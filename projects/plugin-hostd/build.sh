#!/bin/bash -eu
# Copyright 2026 Pau Aliagas <linuxnow@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Builds plugin-hostd's two fuzz targets (fuzz/fuzz_*.c in the plugin-hostd repository) into $OUT.
# plugin-hostd's own Makefile builds them with a native clang and libFuzzer against the installed plugin-hostd-protocol
# and plugin-db; this script makes the same harnesses into static riscv64 programs from the checkouts the sources file
# pins, laid out in $SRC by the Dockerfile: plugin-hostd-protocol (its headers, mod-host's protocol headers among them,
# the two functions of its library the harnesses call, and the JSON of the protocol) and plugin-db (its headers; the
# harnesses include plugin_db_constants.h, which includes nothing, and no OpenSSL).
protocol="$SRC/plugin-hostd-protocol"
plugin_db="$SRC/plugin-db"
flags=(-std=c11 -D_GNU_SOURCE -Iinclude -Isrc -Ifuzz -I"$protocol/include" -I"$plugin_db/include")

# The error words of the protocol's refusals, which plugin-hostd's Makefile writes at build time and never commits
# (src/reply_words.h, read by src/session.c), from the protocol's JSON.
python3 tools/reply-words.py "$protocol/protocol/plugin-hostd-protocol.json" > src/reply_words.h

# The protocol library's part the harnesses call: the socket's send (socket_send) and the word splitter (strarr_split).
mkdir -p "$WORK/obj"
for f in socket utils; do
  $CC $CFLAGS -std=c11 -D_GNU_SOURCE -I"$protocol/include" -I"$protocol/src" -c "$protocol/src/$f.c" -o "$WORK/obj/protocol-$f.o"
done
$AR rcs "$WORK/libplugin-hostd-protocol.a" "$WORK/obj/protocol-socket.o" "$WORK/obj/protocol-utils.o"

# The library: the daemon's command parser and dispatcher, src/verbs.c, the code fuzz_command drives, with what it is
# built from in plugin-hostd's Makefile (FUZZ_SRC_command): the session, the word reader, the pin words, the writer.
for f in verbs session words pin_words writer fsutil; do
  $CC $CFLAGS "${flags[@]}" -c "src/$f.c" -o "$WORK/obj/$f.o"
done
$AR rcs "$WORK/libplugin-hostd.a" "$WORK"/obj/{verbs,session,words,pin_words,writer,fsutil}.o

# fuzz_command: the library, with everything below it (the supervisor, the pins, the descriptors, the socket's send)
# answered by the harness's recorder, fuzz/recorder.c.
$CC $CFLAGS "${flags[@]}" -c fuzz/fuzz_command.c -o "$WORK/fuzz_command.o"
$CC $CFLAGS "${flags[@]}" -c fuzz/recorder.c -o "$WORK/recorder.o"
$CC $CFLAGS "$WORK/fuzz_command.o" "$WORK/recorder.o" -o "$OUT/fuzz_command" $LIB_FUZZING_ENGINE \
  "$WORK/libplugin-hostd.a" "$WORK/libplugin-hostd-protocol.a"

# fuzz_reply: the relay of the workers' feedback, src/relay.c. The harness includes the file itself, with its socket
# calls renamed to the harness's own and a line limit of 6000 bytes, as plugin-hostd's Makefile builds it; so the
# relay is compiled into the harness's object.
$CC $CFLAGS "${flags[@]}" -c fuzz/fuzz_reply.c -o "$WORK/fuzz_reply.o"
$CC $CFLAGS "$WORK/fuzz_reply.o" -o "$OUT/fuzz_reply" $LIB_FUZZING_ENGINE "$WORK/libplugin-hostd-protocol.a"
