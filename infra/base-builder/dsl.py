#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The renames and the gates of a DSL fuzz target's link (docs/build-contract.md, "DSL fuzz targets").

    python3 dsl.py rename --work DIR -- ARGUMENT...
    python3 dsl.py trace --work DIR LOG

link-fuzz-target runs both for a link that names $LIB_DSL_ENGINE. The fuzz target's block declares its driver in the
environment (each list is absolute paths, separated by spaces):

    OV_DSL_DRIVER            the target's driver objects: they define target_name, target_alloc_init,
                             target_alloc_count and target_run, which cli.c calls. Each <name>.o may have its quiet
                             build beside it, <name>-quiet.o. Required.
    OV_DSL_REDEFS            rename maps for the library and the driver objects.
    OV_DSL_LIBRARY_REDEFS    rename maps for the library alone. The driver objects must not name either side of a pair.
    OV_DSL_TRAMPOLINES       objects that define the new names. They are linked as they are, after the link's own
                             arguments, and the record counts them as the driver's: compiled with no sanitizer.
    OV_DSL_ALLOW             with OV_DSL_LIBRARY_REDEFS, required: the census allow list (below).

At least one map. A map has one pair `<old> <new>` a line; `#` starts a comment, and a blank line is nothing. No name
is the old name of two pairs, or the new name of two, or both an old and a new name.

rename takes the link's own arguments. The library is each archive among them whose real path is not under /opt/ (the
toolchain image's libraries, which are never renamed); at least one. An object file among them, such as a seal, is
linked as it is. It refuses an argument that could hide an input from the renames: a source file, a response file
(@file), -l, -Xlinker, --for-linker, --config, and -Wl, other than -Wl,--wrap=<name> of a seal's function (SEALS:
getenv, getpid, getppid, mkstemp, mkostemp, mkstemps, mkostemps), none of which a map may name. A wrap of any other
name would send calls past the trampolines unseen: the linker writes its -y trace before it applies --wrap. Before the
renames it refuses a library that defines an old name of a map (it has its own <name>), and a library or a driver
object that names a new name already. It refuses a driver object, loud or quiet, that names a name of a library map.
It copies each library archive and each driver object, and renames the copies with llvm-objcopy --redefine-syms: the
library with every map, the driver objects with the OV_DSL_REDEFS maps. Then the gates, each of which stops the link:

    conservation   for each pair, in the library copies and in each driver object's copy, the references (llvm-nm, U)
                   to the new name are as many as there were to the old name, and none to the old name is left; the
                   number of undefined symbols does not change.
    each map       renames at least one reference: a map over nothing would schedule nothing.
    census         with OV_DSL_ALLOW: each name that the library copies leave undefined is defined by the library, is
                   a new name, is a sanitizer's (__asan_, __ubsan_, __sanitizer_, or __start_ and __stop_, the bounds
                   of a section, which the linker makes), or is a line of the allow list. So a library call that no
                   map answers, and that can reach the kernel, is named in a file that a review reads.

It writes in DIR: args (the link's own arguments, NUL-separated, with each library archive replaced by its copy),
driver (the driver objects' copies, one a line), quiet (their quiet twins' copies, or empty when one has none),
trampolines, renamed (for the record: <copy> <real path of the original> <its sha256>, one a line), trace-words (an
-Wl,-y,<name> for each new name, which the first link gets) and state.json, which trace reads.

trace reads the linker's -y lines in LOG (`<file>: reference to <name>`, `<file>: definition of <name>`) and stops the
link unless, for each new name: no file but a trampoline defines it, and one does when it is referenced; each
reference is from a library copy (an archive member of one), a driver object's copy or a trampoline; and, for a new
name of a library map, a reference from a library copy is not a reference from a driver object. For each library map,
the link takes at least one reference from a library copy to one of its new names.
"""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

SANITIZER_PREFIXES = ("__asan_", "__ubsan_", "__sanitizer_", "__start_", "__stop_")
# The functions the driver's seals wrap (docs/build-contract.md, "Functions that the AddressSanitizer runtime wraps"):
# the only -Wl,--wrap=<name> a DSL link takes.
SEALS = ("getenv", "getpid", "getppid", "mkstemp", "mkostemp", "mkstemps", "mkostemps")
SOURCES = (".c", ".cc", ".cpp", ".cxx", ".c++", ".C", ".m", ".mm", ".s", ".S")
TRACE = re.compile(r"^(.*): (reference to|definition of|common definition of|lazy definition of|"
                   r"shared definition of) (\S+)$")


class Refused(Exception):
    pass


def paths(name, required=False):
    """The absolute paths of the environment variable `name`, a list separated by spaces."""
    value = os.environ.get(name, "")
    words = value.split()
    if required and not words:
        raise Refused(f"{name} must name at least one file")
    for word in words:
        if not word.startswith("/"):
            raise Refused(f"{name}: {word} is not an absolute path")
        if any(ord(c) < 32 or ord(c) == 127 for c in word):
            raise Refused(f"{name}: {word!r} holds a control character")
        if not os.path.isfile(word):
            raise Refused(f"{name}: there is no file {word}")
    if len(set(words)) != len(words):
        raise Refused(f"{name} names a file twice")
    return words


def read_map(path):
    """[(old, new)] of a map file."""
    pairs = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            words = line.split("#", 1)[0].split()
            if not words:
                continue
            if len(words) != 2:
                raise Refused(f"{path}:{number}: a pair is two names, `<old> <new>`, not {line.strip()!r}")
            pairs.append((words[0], words[1]))
    if not pairs:
        raise Refused(f"{path}: the map has no pair")
    return pairs


def check_maps(maps):
    olds = collections.Counter(old for _, pairs in maps for old, _ in pairs)
    news = collections.Counter(new for _, pairs in maps for _, new in pairs)
    for name, count in sorted((olds + news).items()):
        if olds[name] > 1:
            raise Refused(f"the maps rename {name} {olds[name]} times")
        if news[name] > 1:
            raise Refused(f"the maps rename {news[name]} names to {name}")
        if olds[name] and news[name]:
            raise Refused(f"the maps name {name} as an old name and as a new name")
        if name in SEALS or name in {f"__wrap_{s}" for s in SEALS} or name in {f"__real_{s}" for s in SEALS}:
            raise Refused(f"the maps name {name}, of a seal: the seals' wraps would act on it")


def symbols(path):
    """[(name, type)] that llvm-nm -P lists for an object or an archive (each member's symbols)."""
    done = subprocess.run(["llvm-nm", "-P", path], capture_output=True, text=True)
    if done.returncode != 0:
        raise Refused(f"llvm-nm cannot read {path}: {done.stderr.strip()}")
    found = []
    for line in done.stdout.splitlines():
        fields = line.split()
        # A member's header is one word ending in ":"; a symbol is <name> <type> [<value> <size>].
        if len(fields) >= 2 and len(fields[1]) == 1:
            found.append((fields[0], fields[1]))
    return found


def undefined(found):
    return collections.Counter(name for name, kind in found if kind == "U")


def defined(found):
    """The names that a global or weak symbol defines (an upper-case type but U)."""
    return {name for name, kind in found if kind.isupper() and kind != "U"}


def selected(arguments):
    """(each argument, the indices of the library archives among them). Refuses the forms that could hide an input."""
    library = []
    for index, word in enumerate(arguments):
        if word.startswith("-Wl,"):
            wrap = re.fullmatch(r"-Wl,--wrap=([A-Za-z_][A-Za-z0-9_.$]*)", word)
            if not wrap or wrap.group(1) not in SEALS:
                raise Refused(f"{word}: a DSL fuzz target's link takes no linker option but the seals' "
                              f"-Wl,--wrap=<name> ({', '.join(SEALS)})")
            continue
        if word.startswith("-l") or word in ("-Xlinker", "--config") or word.startswith(("--for-linker", "--config=")):
            raise Refused(f"{word}: name a DSL fuzz target's archives directly, without -l, linker forwarding or a "
                          "configuration file")
        if word.startswith("@"):
            raise Refused(f"{word}: name a DSL fuzz target's objects and archives on the command line")
        if word.startswith("-"):
            continue
        if word.endswith(SOURCES):
            raise Refused(f"{word}: compile a DSL fuzz target's sources first, and link the objects")
        if not os.path.isfile(word):
            continue
        with open(word, "rb") as handle:
            head = handle.read(8)
        if head.startswith(b"\x7fELF"):
            continue
        if head == b"!<arch>\n":
            if not os.path.realpath(word).startswith("/opt/"):
                library.append(index)
            continue
        if head.startswith(b"BC\xc0\xde"):
            raise Refused(f"{word}: LLVM bitcode; a DSL fuzz target needs object code (no LTO)")
        raise Refused(f"{word}: a DSL fuzz target's link takes object files and archives, not linker scripts or "
                      "other inputs")
    if not library:
        raise Refused("the link names no archive of the library: the maps would rename nothing")
    return library


def sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def objcopy(maps, source, copy):
    command = ["llvm-objcopy", *(f"--redefine-syms={path}" for path in maps), source, copy]
    done = subprocess.run(command, capture_output=True, text=True)
    if done.returncode != 0:
        raise Refused(f"llvm-objcopy failed on {source}: {done.stderr.strip()}")


def conserve(label, pairs, before, after):
    """Refuses unless each pair's references moved from the old name to the new one. Returns the count per pair."""
    if sum(before.values()) != sum(after.values()):
        raise Refused(f"conservation: {label}: {sum(before.values())} undefined symbols before the renames, "
                      f"{sum(after.values())} after")
    counts = {}
    for old, new in pairs:
        if before[old] != after[new] or after[old]:
            raise Refused(f"conservation: {label}: U {old} before {before[old]}, U {new} after {after[new]}, "
                          f"U {old} left after {after[old]}")
        counts[old] = before[old]
    return counts


def rename(work, arguments):
    work = pathlib.Path(work)
    driver = paths("OV_DSL_DRIVER", required=True)
    both = paths("OV_DSL_REDEFS")
    library_maps = paths("OV_DSL_LIBRARY_REDEFS")
    trampolines = paths("OV_DSL_TRAMPOLINES")
    allow_path = paths("OV_DSL_ALLOW")
    if len(allow_path) > 1:
        raise Refused("OV_DSL_ALLOW names one file")
    if not both and not library_maps:
        raise Refused("a DSL fuzz target names at least one map, in OV_DSL_REDEFS or OV_DSL_LIBRARY_REDEFS")
    if library_maps and not allow_path:
        raise Refused("OV_DSL_LIBRARY_REDEFS needs OV_DSL_ALLOW: the census of the names the library still calls")
    for path in driver + trampolines:
        with open(path, "rb") as handle:
            if not handle.read(4) == b"\x7fELF":
                raise Refused(f"{path}: not an object file")
    maps = [("both", (path, read_map(path))) for path in both] + \
           [("library", (path, read_map(path))) for path in library_maps]
    check_maps([entry for _, entry in maps])
    pairs_of = {"both": [p for kind, (_, pairs) in maps if kind == "both" for p in pairs],
                "library": [p for kind, (_, pairs) in maps if kind == "library" for p in pairs]}
    every_pair = pairs_of["both"] + pairs_of["library"]
    olds = {old for old, _ in every_pair}
    news = {new for _, new in every_pair}
    library_names = {name for pair in pairs_of["library"] for name in pair}
    allow = set()
    if allow_path:
        with open(allow_path[0], encoding="utf-8") as handle:
            allow = {line.split("#", 1)[0].strip() for line in handle} - {""}
    # The maps as llvm-objcopy reads them: the pairs alone, one a line.
    normal = {}
    for kind, (path, pairs) in maps:
        out = work / f"map{len(normal)}.redefs"
        out.write_text("".join(f"{old} {new}\n" for old, new in pairs))
        normal[path] = (kind, str(out))
    every_map = [out for _, out in normal.values()]
    both_maps = [out for kind, out in normal.values() if kind == "both"]

    arguments = list(arguments)
    library = selected(arguments)
    renamed_rows, lines = [], []
    before_all, after_all, defined_all = collections.Counter(), collections.Counter(), set()
    for index in library:
        original = arguments[index]
        found = symbols(original)
        names = defined(found)
        own = sorted(olds & names)
        if own:
            raise Refused(f"{original} defines {', '.join(own)} itself: a library with its own "
                          f"{own[0]} cannot be scheduled by renaming its calls")
        early = sorted(news & (names | set(undefined(found))))
        if early:
            raise Refused(f"{original} already names {', '.join(early)}, a new name of a map")
        copy = work / f"{index}-{os.path.basename(original)}"
        objcopy(every_map, original, str(copy))
        after = symbols(str(copy))
        counts = conserve(original, every_pair, undefined(found), undefined(after))
        for old, count in counts.items():
            lines.append(f"dsl.py: {original}: U {old} {count}")
        before_all.update(undefined(found))
        after_all.update(undefined(after))
        defined_all |= defined(after)
        renamed_rows.append((str(copy), os.path.realpath(original), sha256(original)))
        arguments[index] = str(copy)

    copies, quiet = [], []
    for number, original in enumerate(driver):
        twin = original[:-2] + "-quiet.o" if original.endswith(".o") else None
        for path, out in ((original, copies), (twin, quiet)):
            if path is None or not os.path.isfile(path):
                continue
            found = symbols(path)
            named = set(undefined(found)) | defined(found)
            bad = sorted(library_names & named)
            if bad:
                raise Refused(f"{path} names {', '.join(bad)}, of a library map: the driver reaches what the library "
                              "map renames only through the trampolines' own functions")
            early = sorted(news & named)
            if early:
                raise Refused(f"{path} already names {', '.join(early)}, a new name of a map")
            copy = work / f"d{number}-{os.path.basename(path)}"
            if both_maps:
                objcopy(both_maps, path, str(copy))
            else:
                copy.write_bytes(pathlib.Path(path).read_bytes())
            after = symbols(str(copy))
            counts = conserve(path, pairs_of["both"], undefined(found), undefined(after))
            if path == original:
                before_all.update({old: counts[old] for old in counts})
                for old, count in counts.items():
                    if count:
                        lines.append(f"dsl.py: {path}: U {old} {count}")
            renamed_rows.append((str(copy), os.path.realpath(path), sha256(path)))
            out.append(str(copy))
    if len(quiet) != len(copies):
        quiet = []

    for path, (kind, _) in normal.items():
        pairs = dict(read_map(path))
        if not any(before_all[old] for old in pairs):
            raise Refused(f"{path} renames no reference of the library{' or the driver' if kind == 'both' else ''}: "
                          "a map over nothing schedules nothing")

    if allow_path:
        left = sorted(name for name in after_all
                      if name not in defined_all and name not in news and name not in allow
                      and not name.startswith(SANITIZER_PREFIXES))
        if left:
            raise Refused(f"census: the library copies call {', '.join(left)}, which they do not define, which is no "
                          f"new name of a map and no sanitizer's, and which {allow_path[0]} does not list")
        lines.append(f"dsl.py: census: {len(set(after_all))} names left undefined, each accounted for")

    (work / "args").write_bytes(b"".join(word.encode() + b"\0" for word in arguments))
    (work / "driver").write_text("".join(f"{c}\n" for c in copies))
    (work / "quiet").write_text("".join(f"{c}\n" for c in quiet))
    (work / "trampolines").write_text("".join(f"{t}\n" for t in trampolines))
    (work / "renamed").write_text("".join("\t".join(row) + "\n" for row in renamed_rows))
    (work / "trace-words").write_text("".join(f"-Wl,-y,{new}\n" for new in sorted(news)))
    (work / "state.json").write_text(json.dumps({
        "library": [row[0] for row in renamed_rows if row[0] not in copies + quiet],
        "driver": copies, "trampolines": trampolines,
        "library_maps": [[new for _, new in read_map(path)] for path, (kind, _) in normal.items() if kind == "library"],
        "both_news": [new for _, new in pairs_of["both"]],
    }))
    for line in lines:
        print(line, file=sys.stderr)


def trace(work, log):
    state = json.loads((pathlib.Path(work) / "state.json").read_text())
    library, driver, trampolines = set(state["library"]), set(state["driver"]), set(state["trampolines"])
    library_news = {new for names in state["library_maps"] for new in names}
    news = library_news | set(state["both_news"])

    def from_library(file):
        member = re.fullmatch(r"(.*)\((.*)\)", file)
        return (member.group(1) if member else file) in library

    definitions, references = collections.defaultdict(list), collections.defaultdict(list)
    for line in pathlib.Path(log).read_text(errors="replace").splitlines():
        found = TRACE.match(line.strip())
        if not found or found.group(3) not in news:
            continue
        file, kind, name = found.groups()
        # GNU ld writes its own name first ("/usr/bin/ld: <file>: reference to ..."); lld does not.
        file = file.rsplit(": ", 1)[-1]
        if kind == "reference to":
            references[name].append(file)
        elif kind != "lazy definition of":
            definitions[name].append(file)
    problems = []
    for name in sorted(news):
        wrong = [f for f in definitions[name] if f not in trampolines]
        if wrong:
            problems.append(f"{name} is defined by {', '.join(wrong)}, which is no trampoline")
        if references[name] and len(definitions[name]) != 1:
            problems.append(f"{name} is referenced, and defined {len(definitions[name])} times")
        for file in references[name]:
            if from_library(file):
                continue
            if name in library_news or (file not in driver and file not in trampolines):
                problems.append(f"{file} references {name}")
    for names in state["library_maps"]:
        if not any(from_library(file) for name in names for file in references[name]):
            problems.append(f"the link takes no reference from the library to any of {', '.join(names)}")
    if problems:
        raise Refused("the link's trace: " + "; ".join(problems))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dsl.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    rename_parser = commands.add_parser("rename")
    rename_parser.add_argument("--work", required=True)
    rename_parser.add_argument("arguments", nargs="*")
    trace_parser = commands.add_parser("trace")
    trace_parser.add_argument("--work", required=True)
    trace_parser.add_argument("log")
    options = parser.parse_args(argv)
    try:
        if options.command == "rename":
            rename(options.work, options.arguments)
        else:
            trace(options.work, options.log)
    except Refused as error:
        print(f"link-fuzz-target: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
