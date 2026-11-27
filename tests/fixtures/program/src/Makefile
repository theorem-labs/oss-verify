# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The program's own build. It takes CC and CFLAGS from the environment when they are set, as a build system does.
# Else it uses its own. Its CC is the toolchain's clang for static riscv64 musl programs: /opt/asan-static/musl.cfg is
# the config of the builder's plain compiler shim, and it links with -static, so the program is static and not PIE
# (ET_EXEC). Its CFLAGS: -march=rv64g has no compressed instruction, which the ELF check refuses; -g puts the path of
# the build in the bytes. The CFLAGS of a fuzz build define FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION and its own do
# not, so hello.c prints another string and the CFLAGS of a fuzz build give other bytes (-Os and -O2 alone do not). The
# link takes LDFLAGS and writes the link map hello.map. The program is hello, in this directory.
ifeq ($(origin CC),default)
CC = clang --config=/opt/asan-static/musl.cfg
endif
CFLAGS ?= -march=rv64g -mabi=lp64d -O2 -g
LDFLAGS ?=

hello: hello.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-Map=hello.map -o hello hello.o

hello.o: hello.c
	$(CC) $(CFLAGS) -c -o hello.o hello.c
