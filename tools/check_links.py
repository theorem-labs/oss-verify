# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""What each link of a fuzz target took, and which of that code no sanitizer instruments: a check of
`tools/check --checks`.

compile records each link of a fuzz target when tools/check asks (infra/base-builder/link-fuzz-target, "the record of
this link"): the linker's map, each file the map names with its real path and SHA-256, the driver's objects, the
copies an allocation-failure link made, and a copy of every input. It also records each compile that runs a compiler
shim (infra/base-builder/record-compile), one line of $OUT/.records/compiles.jsonl for each object a compile wrote: the
SHA-256 of its bytes, its source, the SHA-256 of the source's bytes, that source's language, the no_sanitize attributes
of the preprocessed source and the SHA-256 of the object compiled with them taken out ($OUT/.records/nosan/), and every
argument the build gave the compiler; and the build's own sanitizer flags, by language, in $OUT/.records/flags.json
(infra/base-builder/compile). This module reads those records, with no Docker, and gives each build of each fuzz
target two results:

1. The uninstrumented list, in the shape of the proofs repository's harness.yaml (builds.<build>.uninstrumented):
   each file of the toolchain image whose code is in the binary: an object, or an archive at least one of whose
   members has an input section that the linker's map puts in a loaded section (one that --gc-sections kept; an
   archive whose members left only debug information is not listed). The map is required: a link with none has no
   list. No sanitizer instruments these files in any build, as in OSS-Fuzz's
   sanitizer builds: {name: <file name>, kind: libc | compiler-rt | sanitizer-runtime | cxx-runtime | fortran-runtime
   | image-library, sha256}, sorted by the file's path in the image. A file is the toolchain image's when its path is
   under /opt and the toolchain image has those bytes at that path (tools/check reads them from the image). In an
   AddressSanitizer build, an uninstrumented object is listed too, as {name, kind: assembly | fortran, source}, as
   OSS-Fuzz allows, when its DWARF says it is assembly or Fortran and names a source in a checkout of the project
   image, or, for one assembled without DWARF, when a source of the project carries its name and names every global it
   defines. A ported build assembles a build directory's copy of the checkout, so the DWARF names the copy: such an
   object is listed with the checkout's file when a recorded compile that wrote its bytes, with the build's own
   sanitizer flags, read a copy of that file with the same bytes (copied_sources). Wherever its source is, an assembly
   object whose recorded compiles all lack the build's own sanitizer flags is a finding (unflagged_assembly); one with
   no record is judged as before. The driver (cli.o, the adapter and the seals) is compiled without a sanitizer in
   every build, by design, and is not listed.

2. Whether the project's own code is instrumented, in each sanitizer build. The project's code is every object and
   archive member the link took, with code in a loaded section of the binary (parse_map), that is neither the
   driver's nor the toolchain image's. In the AddressSanitizer
   builds (asan, asan-ubsan), each one with code must refer to __asan_init or __asan_version_mismatch_check_*, as the
   constructor that AddressSanitizer adds to each instrumented object does. rustc's allocator shim, an object that only
   forwards __rust_alloc and its siblings to the standard library, is the one exception (at most one such member), as
   it makes no memory access for AddressSanitizer to check. The UndefinedBehaviorSanitizer runs in trap mode and
   leaves no symbol: its checks are trap instructions (`unimp`), and rustc's UB checks are precondition_check
   functions; and code with nothing to check compiles to the same bytes with its flags as without them. So in the
   ubsan and asan-ubsan builds, each object and archive member is judged first by the recorded compiles that wrote
   its bytes (by their SHA-256): instrumented if one of them carried the build's UBSan flags for its language (each of
   them, but the -fno-sanitize= ones, among its arguments; no -fno-sanitize= argument that turns off a check the
   build's own flags keep; and no ignorelist, -fno-sanitize-trap, -fsanitize-recover or -ftrap-function argument,
   which take checks away or turn traps into calls, that the build's own flags do not have; the last
   -fstrict-flex-arrays= that the driver reads gives no lower level than theirs, since clang keeps the last one, and
   no -fstrict-flex-arrays= that it hands on to the front end gives a lower one, wherever it stands; a word that the
   driver hands on to the front end through -Xclang, -Xclang=, -Xpreprocessor or -Wp, counts as the bare word, and a
   -fstrict-flex-arrays= so handed on counts only against the compile), whatever its
   traps (but bytes with no check, out of which the compile's no_sanitize attributes took checks, are not
   instrumented: they fail; record-compile compiles such a source again with the attributes taken out, and that
   object has checks. Bytes with no check whose record cannot say so are not decided by that compile); not
   instrumented (fail) if none did, whatever its traps. A compile of a language that the sanitizer does not
   instrument (assembly), one whose arguments are in a response file, or one with an option whose effect the record
   does not show (an -mllvm option, --config, --config-user-dir, --config-system-dir, -resource-dir) that the build's
   own flags do not have, decides nothing; a compile run with CCC_OVERRIDE_OPTIONS has no record. Nor does any compile
   decide in a language whose recorded UBSan flags turn on no check (no -fsanitize= word: flags that every compile
   carries); the result notes it, as it notes a build with no compile records. The code that no recorded compile
   decides is judged by its checks: each archive that holds some of it must hold more of them than the same archive in
   the plain build, and so must the project's code as a whole; a build with no compile records is judged by its checks
   alone, as before.

The plain build instruments nothing, by design; its result is "plain" when its record is complete, and "error"
when it has no record or an incomplete one. A Go program has no record (Go's linker writes no map): its result is
"plain" when its own build information says Go's linker linked it with no cgo, and its function table gives every
function of its code a line table, as Go's compiler and assembler do (a .syso file's C code has none), and "error"
otherwise.

What this catches: a build whose sanitizer flags did not reach some of its code, by mistake; with the compile
records, also a member compiled without the flags whose archive's other members hold checks, and a member with no
check whose source's no_sanitize attributes took its checks out. A member that has nothing to check passes when its
recorded compile carried the flags and its attributes took nothing out of it. What it misses: code that no recorded
compile wrote (a compiler run by its own name, not through a shim; an object changed after its compile, such as an
allocation-failure link's renamed copy; a prebuilt object), and a member with no check whose record cannot say what
its attributes took out (record-compile), are judged by their checks only, as before, and a member with nothing to
check then fails with its archive. The records are written inside the build's own container, so a build.sh
that sets out to deceive the check can; the review of the pull request is what stands against that.
"""
import array
import dataclasses
import hashlib
import json
import os
import pathlib
import posixpath
import re
import stat
import struct
import sys

import binary_isa

# The kinds of the toolchain's runtimes, by file name, as the toolchain's driver links them. Every other archive in a
# sysroot's usr/lib is a library of the toolchain image: kind image-library.
CXX_RUNTIME = re.compile(r"libc\+\+\.a|libc\+\+abi\.a|libunwind\.a|libc\+\+experimental\.a")
COMPILER_RT = re.compile(r"libclang_rt\.builtins.*\.a|clang_rt\.crt(begin|end).*\.o")
SANITIZER_RUNTIME = re.compile(r"libclang_rt\..*\.a")
# The Fortran runtime, which a toolchain image with a Fortran compiler links beside the others: LLVM's flang and
# GCC's gfortran name theirs differently.
FORTRAN_RUNTIME = re.compile(r"lib(Fortran[A-Za-z]*|flang[A-Za-z_.]*|gfortran|quadmath)\.a")
# musl's C library: its start files, libc.a, its empty stub archives, and libssp_nonshared.a.
LIBC = re.compile(r"(crt1|crti|crtn|Scrt1|rcrt1)\.o|lib(c|m|rt|pthread|crypt|util|xnet|resolv|dl|ssp_nonshared)\.a")
SYSROOT_LIB = re.compile(r"/opt/[^/]+(/[^/]+)*/usr/lib/[^/]+\.a")
# rustc's allocator shim defines only these, and forwards each to the standard library.
RUST_ALLOCATOR_SHIM = re.compile(r"__rust_(alloc|dealloc|realloc|alloc_zeroed|alloc_error_handler|"
                                 r"no_alloc_shim_is_unstable)")
# The symbols that AddressSanitizer's module constructor, in every object it instruments, refers to.
ASAN_MODULE = re.compile(r"__asan_init|__asan_version_mismatch_check_v[0-9]+")
TRAP = 0xC0001073  # `unimp`, the word a trap-mode UndefinedBehaviorSanitizer check executes on riscv64
SANITIZER_BUILDS = ("ubsan", "asan", "asan-ubsan")
ASAN_BUILDS = ("asan", "asan-ubsan")
UBSAN_BUILDS = ("ubsan", "asan-ubsan")
# The languages of a recorded compile (infra/base-builder/record-compile) that the UndefinedBehaviorSanitizer
# instruments, by the language whose flags (the build's flags.json) a compile of it gets.
UBSAN_LANGUAGES = {"c": "c", "cpp-output": "c", "c-header": "c", "objective-c": "c", "objective-c-cpp-output": "c",
                   "c++": "c++", "c++-cpp-output": "c++", "c++-header": "c++", "objective-c++": "c++",
                   "objective-c++-cpp-output": "c++"}
NO_SANITIZE = "-fno-sanitize="
# The arguments that take a check away from a compile, or turn its trap into a call, while its -fsanitize= flags stay:
# an ignorelist (and clang's older spelling, blacklist; the system ones too), -fno-sanitize-trap and -fsanitize-recover,
# with or without =<checks> (and clang's older spelling of -fno-sanitize-trap=undefined), and -ftrap-function, which
# makes each trap a call of the function it names. A compile that has one the build's own flags do not have did not
# carry the build's flags.
UNDO_CHECKS = re.compile(r"-fsanitize-(system-)?(ignorelist|blacklist)=.*|-fno-sanitize-trap(=.*)?"
                         r"|-fsanitize-recover(=.*)?|-fno-sanitize-undefined-trap-on-error|-ftrap-function(=.*)?")
# The sanitizers that a no_sanitize attribute can name that are not the UndefinedBehaviorSanitizer's: an attribute
# that names only these leaves its checks on. Every other name, a check or group of it ("undefined", "shift",
# "signed-integer-overflow", ...) or one this does not know, turns a UBSan check off.
NOT_UBSAN = {"address", "hwaddress", "kernel-address", "kernel-hwaddress", "memory", "kernel-memory", "thread",
             "memtag", "memtag-stack", "memtag-heap", "memtag-globals", "safe-stack", "shadow-call-stack", "dataflow",
             "leak", "kcfi", "scudo", "fuzzer", "fuzzer-no-link", "realtime", "numerical", "type"}
NO_SANITIZE_ATTRIBUTE = re.compile(r"(?:__)?(no_sanitize[a-z_]*?)(?:__)?\s*(\((.*)\))?$", re.S)


def turns_ubsan_off(attribute):
    """Whether one no_sanitize attribute that record-compile read from a source (`no_sanitize_undefined`,
    `no_sanitize("undefined")`, `__no_sanitize__("shift", "address")`, ...) turns a UBSan check off: one that names
    a sanitizer outside NOT_UBSAN (no cfi- one) does, and so does one whose arguments name nothing this reads.
    no_sanitize_address, no_sanitize_memory and no_sanitize_thread do not; nor does a bare `no_sanitize` with no
    arguments, which is no attribute (an identifier of the code, or the name in __has_attribute)."""
    m = NO_SANITIZE_ATTRIBUTE.fullmatch(attribute.strip())
    if not m:
        return True
    name, arguments = m.group(1), m.group(3)
    if name == "no_sanitize_undefined":
        return True
    if name != "no_sanitize":
        return False
    if m.group(2) is None:
        return False
    names = [n.strip() for s in re.findall(r'"([^"]*)"', arguments or "") for n in s.split(",")]
    return not names or any(n not in NOT_UBSAN and not n.startswith("cfi") for n in names)


# The options whose effect the record does not show, each as <option> <value> or <option>=<value>: LLVM's own options,
# which can take every check away; and those that make clang read flags or an ignorelist from a file: a configuration
# file, the directories clang looks for its default configuration file in, and the resource directory, whose
# share/ubsan_ignorelist.txt the driver applies. A compile that gives one a value that the build's own flags do not
# give it decides nothing. The compiler shims' own --config is not in a record: the record holds the arguments the
# build gave the shim.
UNSEEN = ("-mllvm", "--config", "--config-user-dir", "--config-system-dir", "-resource-dir")
# -fstrict-flex-arrays=<level>: which trailing arrays of a struct array-bounds checks (infra/base-builder/toolchain.sh).
# clang keeps only the last one the driver gets, so a compile whose last one gives a lower level than the build's
# takes that check away while each of the build's words stays among its arguments (lower_flex_levels).
STRICT_FLEX_ARRAYS = "-fstrict-flex-arrays="
C_FAMILY = re.compile(r"\.(c|cc|cp|cpp|cxx|c\+\+|C|CPP|m|mm|h|hh|hpp|hxx|inc|ii|i)$")
ASSEMBLY = re.compile(r"\.(S|s|sx|asm)$")
FORTRAN = re.compile(r"\.(f|for|ftn|fpp|f77|f90|f95|f03|f08|f18)$", re.I)
# The DWARF language of an object assembled from a .S or .s file, and of one compiled from Fortran.
ASSEMBLER_LANGUAGE = "DW_LANG_Mips_Assembler"
FORTRAN_LANGUAGE = re.compile(r"DW_LANG_Fortran\w*")
# What an uninstrumented entry's name and source may hold (the facts' schema for builds.<b>.uninstrumented).
NAME = re.compile(r"[A-Za-z0-9._+-]{1,120}")
SOURCE = re.compile(r"[A-Za-z0-9._+/-]{1,200}")
MAP_COLUMNS = re.compile(r"^ *([0-9a-f]+) +[0-9a-f]+ +([0-9a-f]+) +[0-9]+ ")
# An allocation-failure link's copy of an archive or object is named <position>-<the original's name>.
COPY_PREFIX = re.compile(r"^[0-9]+-")
MAX_LISTED = 40
# The most bytes read from one file of a record: a linker map, or an archive the link took.
MAX_RECORD_BYTES = 1 << 30
# The driver's seals: infra/base-builder/driver/wrap_*.c. A recipe that wraps a C library call itself compiles one of
# them with the driver's compiler and no sanitizer (infra/base-builder/recipes.sh, oft_seal_getenv and its siblings),
# as compile does. Such an object names the seal's source in its STT_FILE symbol and defines only __wrap_ functions,
# each of which stands in for a C library call.
DRIVER_SEALS = frozenset(path.name for path in
                         (pathlib.Path(__file__).resolve().parent.parent / "infra" / "base-builder" / "driver")
                         .glob("wrap_*.c"))

SHT_SYMTAB, SHT_NOBITS = 2, 8
SHF_EXECINSTR = 0x4
STT_FILE = 4
SHN_UNDEF = 0
SHN_LORESERVE, SHN_XINDEX = 0xFF00, 0xFFFF


class RecordError(Exception):
    """A record, or a file of it, that is not there or cannot be read."""


# ── reading files that a build wrote ─────────────────────────────────────────────────────────────────────────────────

def below(base, *parts):
    """base/parts..., where no part is a symbolic link: a build (or a run) writes these directories, and the host must
    never follow a link it planted. Raise RecordError if a part is missing or is a link."""
    path = pathlib.Path(base)
    for part in parts:
        if "/" in part or part in ("", ".", ".."):
            raise RecordError(f"{part!r} is not a file name")
        path = path / part
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            raise RecordError(f"{part} is not there") from None
        if stat.S_ISLNK(mode):
            raise RecordError(f"{part} is a symbolic link")
    return path


def read_regular(path, limit=MAX_RECORD_BYTES):
    """The bytes of the regular file `path`, opened without following a link, without blocking on a FIFO, and at most
    `limit` bytes long. Raise RecordError otherwise."""
    try:
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise RecordError(f"{pathlib.Path(path).name}: {error.strerror}") from None
    try:
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode):
            raise RecordError(f"{pathlib.Path(path).name} is not a regular file")
        if info.st_size > limit:
            raise RecordError(f"{pathlib.Path(path).name} is larger than {limit} bytes")
        chunks, left = [], limit + 1
        while left > 0 and (chunk := os.read(handle, min(left, 1 << 20))):
            chunks.append(chunk)
            left -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise RecordError(f"{pathlib.Path(path).name} is larger than {limit} bytes")
        return data
    finally:
        os.close(handle)


# ── the record ───────────────────────────────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class Record:
    """One link's record (link-fuzz-target): the map's input sections, the files they came from, and the driver."""

    taken: list  # [(file as the map names it, member or None, section, size)]
    inputs: dict  # {file as the map names it: (real path, sha256, bytes)}
    driver: set  # the paths of the driver's objects
    renamed: dict  # {real path of an allocation-failure link's copy: (real path of the original, its sha256)}
    raw: pathlib.Path  # the build's $OUT, whose .records/store holds the bytes of the inputs
    quiet: pathlib.Path | None  # the quiet twin, if the link made one
    compiles: "Compiles | None" = None  # the build's compile records, if it has them

    def store(self, sha256):
        """The bytes of the input with this SHA-256, checked. Raise RecordError if they were not kept."""
        data = read_regular(below(self.raw, ".records", "store", sha256))
        if hashlib.sha256(data).hexdigest() != sha256:
            raise RecordError(f"the kept copy of {sha256[:16]} has other bytes")
        return data


@dataclasses.dataclass
class Compile:
    """One recorded compile of an object (infra/base-builder/record-compile)."""

    file: str  # its source
    language: str  # clang's name for the source's language
    arguments: list  # the arguments the build gave the compiler shim
    directory: str = ""  # the working directory of the compile, which a relative `file` is relative to
    source_sha256: str | None = None  # the SHA-256 of the source's bytes, if the record has it
    # the no_sanitize attributes of its preprocessed source, or None when the record cannot say
    no_sanitize: list | None = None
    # the UBSan traps and UB checks of the object compiled with those attributes taken out, or None when the record
    # has no such object or it cannot be read
    no_sanitize_checks: int | None = None


@dataclasses.dataclass
class Compiles:
    """A build's compile records (infra/base-builder/compile, record-compile): its own sanitizer flags, by language,
    and each recorded compile, by the SHA-256 of the object it wrote."""

    build: str  # the build the flags are of
    sanitizer: dict  # {"c": [word], "c++": [word]}: the build's own sanitizer flags
    ubsan: dict  # the same, the UndefinedBehaviorSanitizer's only
    objects: dict  # {sha256: [Compile]}


def read_compiles(raw):
    """The compile records in the build's $OUT `raw` (.records/flags.json and .records/compiles.jsonl), or None if it
    has none or they cannot be read: each object is then judged as one with no record. A line that is not a record is
    left out, and its object has no record."""
    try:
        flags = json.loads(read_regular(below(raw, ".records", "flags.json")))
        lines = read_regular(below(raw, ".records", "compiles.jsonl")).decode("utf-8", "surrogateescape")
    except (RecordError, ValueError, RecursionError):
        return None

    def words(value):
        return (isinstance(value, dict)
                and all(isinstance(value.get(language), list) and all(isinstance(w, str) for w in value[language])
                        for language in ("c", "c++")))

    if not (isinstance(flags, dict) and isinstance(flags.get("build"), str) and words(flags.get("sanitizer"))
            and words(flags.get("ubsan"))):
        return None
    objects = {}
    for line in lines.split("\n"):
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not (isinstance(entry, dict) and isinstance(entry.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) and isinstance(entry.get("file"), str)
                and isinstance(entry.get("language"), str) and isinstance(entry.get("arguments"), list)
                and all(isinstance(a, str) for a in entry["arguments"])):
            continue
        directory = entry.get("directory") if isinstance(entry.get("directory"), str) else ""
        source = entry.get("source_sha256")
        source = source if isinstance(source, str) and re.fullmatch(r"[0-9a-f]{64}", source) else None
        attributes = entry.get("no_sanitize")
        attributes = (attributes if isinstance(attributes, list) and all(isinstance(a, str) for a in attributes)
                      else None)
        # The object without the attributes, saved by its SHA-256 (record-compile): its checks, if it is that object.
        stripped, checks = entry.get("no_sanitize_object"), None
        if isinstance(stripped, str) and re.fullmatch(r"[0-9a-f]{64}", stripped):
            try:
                data = read_regular(below(raw, ".records", "nosan", stripped))
            except RecordError:
                data = None
            facts = object_facts(data) if data is not None and hashlib.sha256(data).hexdigest() == stripped else None
            if facts is not None and not facts.bitcode:
                checks = facts.traps + facts.ub_checks
        objects.setdefault(entry["sha256"], []).append(
            Compile(entry["file"], entry["language"], entry["arguments"], directory, source, attributes, checks))
    return Compiles(flags["build"], flags["sanitizer"], flags["ubsan"], objects)


@dataclasses.dataclass
class GoProgram:
    """A program that Go's own linker linked from Go code only, as the program's build information and its function
    table say. Go's linker writes no map, so such a link has no Record; this stands in for it."""

    version: str  # the Go release, as the build information names it
    settings: dict  # the build information's `build` lines: {key: value}


# The build information that Go writes into each program it builds (.go.buildinfo, read by `go version -m`;
# src/debug/buildinfo/buildinfo.go): a 32-byte header that starts with this magic, then, when bit 1 of its flags byte
# is set, the Go version and the module information, each a uvarint length and the bytes. The module information is
# framed by 16 bytes on each side.
GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
# The settings of a program that takes no file of the toolchain image that a sanitizer could instrument: no cgo (so no
# C library and no C compiler's runtime), Go's own compiler, an executable, for linux/riscv64. The race detector and
# Go's -msan and -asan modes link C runtimes, and an external link runs the C toolchain's linker.
GO_ONLY_SETTINGS = {"CGO_ENABLED": "0", "-compiler": "gc", "-buildmode": "exe", "GOOS": "linux", "GOARCH": "riscv64"}
GO_C_RUNTIMES = ("-race", "-msan", "-asan")


def _uvarint(data, at):
    """The uvarint at data[at:] and the offset after it. Raise ValueError if it runs past the end or past 64 bits."""
    value = shift = 0
    while shift < 64:
        if at >= len(data):
            raise ValueError("a length runs past the end of the section")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, at
        shift += 7
    raise ValueError("a length is longer than 64 bits")


# Go's function table (.gopclntab; src/runtime/symtab.go pcHeader, src/debug/gosym/pclntab.go) of Go 1.18 and later:
# a header of the magic, two zero bytes, minLC, ptrSize, then nfunc, nfiles, textStart and the offsets of funcnametab,
# cutab, filetab, pctab and pclntab, each ptrSize bytes; at pclntab, nfunc + 1 pairs of uint32 (entry offset from
# textStart, offset of the _func), the last one's entry being the end of the code. Each _func (runtime/runtime2.go)
# starts entryOff, nameOff, args, deferreturn, pcsp, pcfile, pcln, npcdata, cuOffset: GO_FUNC.
GO_PCLNTAB_MAGICS = (0xFFFFFFF0, 0xFFFFFFF1)
GO_FUNC = struct.Struct("<IiiIIIIII")
NO_CU = 0xFFFFFFFF
NAME_MAX_GO = 120  # the most bytes of a function's name read: the name only names the function in a message


def go_functions(data, sections):
    """[(start, end, name, has a line table)] of every function in the executable's Go function table, in address
    order, as offsets from the start of .text, or the reason it cannot be read (str). (Go 1.27.1 writes textStart as 0;
    its offsets are from .text's start.) A function has a line table when its pcfile and pcln are not 0 and its
    cuOffset names a compilation unit, as Go's compiler and assembler write for every function they make. The name is
    read only for a function with no line table, and only its first NAME_MAX_GO bytes, so the work is linear in the
    table; it is None for the others.

    Go's linker lists a host object's (a .syso file's) global symbols here, with no line table, but not its local
    `.L` labels or its sections' containers on riscv64 (cmd/link/internal/ld/pcln.go): such code is counted in the
    function before it, or lies before the first one (foreign_code's start rule). A .syso symbol that an empty Go
    assembly TEXT also defines carries that TEXT's line table, and is listed a second time out of address order, which
    the order rule here refuses."""
    found = [s for s in sections if s["name"] == ".gopclntab" and s["type"] != SHT_NOBITS]
    if len(found) != 1:
        return f"{len(found)} .gopclntab sections, not one"
    tab = data[found[0]["off"]:found[0]["off"] + found[0]["size"]]
    if len(tab) < 72 or struct.unpack_from("<I", tab, 0)[0] not in GO_PCLNTAB_MAGICS or tab[4:6] != b"\0\0" \
            or tab[7] != 8:
        return "its .gopclntab is not Go 1.18's function table for a 64-bit target"
    nfunc, _, text_start, names_at, cu_at, _, _, pcln_at = struct.unpack_from("<8Q", tab, 8)
    if text_start != 0:
        return f"its .gopclntab's textStart is {text_start:#x}, not the 0 that Go 1.27.1 writes"
    if pcln_at + (nfunc + 1) * 8 > len(tab) or not names_at <= cu_at <= len(tab):
        return "its .gopclntab's function table runs past the end of the section"
    functions = []
    for i in range(nfunc):
        entry, func = struct.unpack_from("<II", tab, pcln_at + i * 8)
        end = struct.unpack_from("<I", tab, pcln_at + (i + 1) * 8)[0]
        if end < entry:
            where = f"the code ends before function {i}" if i + 1 == nfunc else f"function {i + 1} starts before {i}"
            return f"its .gopclntab's functions are not in address order ({where})"
        if pcln_at + func + GO_FUNC.size > len(tab):
            return f"its .gopclntab's function {i} runs past the end of the section"
        if entry % 2:
            # Go's compiler, assembler and linker start every function at an even offset (a multiple of 4: none of
            # 3.5 million measured is not); a jump cannot land on an odd one (jalr clears bit 0).
            return f"its .gopclntab's function {i} starts at the odd offset {entry:#x}"
        _, name_off, _, _, _, pcfile, pcln, _, cu = GO_FUNC.unpack_from(tab, pcln_at + func)
        at = names_at + name_off
        if name_off < 0 or at >= cu_at:
            return f"its .gopclntab's function {i} has no name in funcnametab"
        lines = bool(pcfile and pcln and cu != NO_CU)
        name = None
        if not lines:
            limit = min(cu_at, at + NAME_MAX_GO)
            stop = tab.find(b"\0", at, limit)
            name = (tab[at:stop] if stop >= 0 else tab[at:limit] + b"...").decode("latin1")
        functions.append((entry, end, name, lines))
    return functions


# The functions Go's linker makes itself, which have no line table: a trampoline `<target>-tramp<N>` to a function
# too far for a direct jump, which is `auipc x31, hi` and `jalr x0, lo(x31)` to the entry of that function, then zero
# padding (cmd/link/internal/riscv64/asm.go genCallTramp); and the FIPS markers `go:textfipsstart` and
# `go:textfipsend`, which are zero bytes. They are told by their bytes, not their names: the author of a .syso picks
# its symbols' names, and a name can be longer than the bytes read of it (a trampoline to a generic function). A
# trampoline must jump to the entry of a listed function, which the table judges on its own (every entry is even,
# and the machine's target is the sum with bit 0 cleared): one that jumps anywhere else (into the middle of another
# stub, where its bytes decode as a compressed instruction of the author's choice) is not the linker's.


def linker_function(body, start, entries):
    """Whether a function with no line table, of these bytes, at offset `start` of .text, is one that Go's linker
    makes itself; `entries` is the set of the table's function entries."""
    if not any(body):
        return True
    if len(body) >= 8:
        auipc, jalr = struct.unpack_from("<II", body, 0)
        if auipc & 0xFFF != 0xF97 or jalr & 0xFFFFF != 0xF8067 or any(body[8:]):
            return False
        high = (auipc & 0xFFFFF000) - ((auipc & 0x80000000) << 1)      # sign-extended U-immediate
        low = (jalr >> 20) - ((jalr & 0x80000000) >> 19)                 # sign-extended I-immediate
        return (start + high + low) & ~1 in entries     # jalr clears bit 0 of the target
    return False


def foreign_code(data, sections):
    """Why the Go program's code may hold code that Go did not compile, or None. Go's function table must start at
    .text's start and end at its end, up to zero padding, and every function in it must have the line table that Go's
    compiler and assembler write, or be one of the linker's own (linker_function). A .syso file's code (linked with
    CGO_ENABLED=0, which the build information does not show) has no line table, or lies outside every function, or is
    listed out of order (go_functions)."""
    text = [s for s in sections if s["name"] == ".text" and s["type"] != SHT_NOBITS]
    if len(text) != 1:
        return f"{len(text)} .text sections, not one"
    functions = go_functions(data, sections)
    if isinstance(functions, str):
        return functions
    if not functions or functions[0][0] != 0:
        return "its function table does not start at .text's start"
    base, size = text[0]["off"], text[0]["size"]
    end = functions[-1][1]
    if end > size or any(data[base + end:base + size]):
        return f"its function table ends at {end:#x} of .text's {size:#x} bytes, and the rest is not zero padding"
    entries = {start for start, _, _, _ in functions}
    foreign = [name for start, stop, name, lines in functions
               if not lines and not linker_function(data[base + start:base + stop], start, entries)]
    if foreign:
        return ("functions with no line table, so code that Go did not compile (a .syso file, for one): "
                + ", ".join(listed(sorted(set(foreign)))))
    return None


def go_program(data):
    """The GoProgram that the executable `data` is, from its .go.buildinfo section, or the reason it is not one
    (str): no such section, build information this cannot read, or a setting that lets the link take C code."""
    try:
        _, sections, _ = binary_isa.parse_elf(data)
    except binary_isa.Unexamined as error:
        return f"not a RISC-V ELF file: {error}"
    found = [s for s in sections if s["name"] == ".go.buildinfo" and s["type"] != SHT_NOBITS]
    if len(found) != 1:
        return f"{len(found)} .go.buildinfo sections, not one: not a program that Go built"
    body = data[found[0]["off"]:found[0]["off"] + found[0]["size"]]
    if len(body) < 32 or not body.startswith(GO_BUILDINFO_MAGIC) or not body[15] & 2:
        return "its .go.buildinfo is not the build information of Go 1.18 or later"
    try:
        strings, at = [], 32
        for _ in range(2):
            size, at = _uvarint(body, at)
            if at + size > len(body):
                raise ValueError("a string runs past the end of the section")
            strings.append(body[at:at + size])
            at += size
        version, module = strings
        if len(module) >= 33 and module[-17:-16] == b"\n":
            module = module[16:-16]
        version, module = version.decode("ascii"), module.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        return f"its .go.buildinfo cannot be read: {error}"
    if not version.startswith("go"):
        return f"its .go.buildinfo names no Go release: {version[:40]!r}"
    settings = {}
    for line in module.split("\n"):
        if line.startswith("build\t"):
            key, _, value = line[len("build\t"):].partition("=")
            settings[key] = value
    wrong = [f"{key}={settings.get(key, '(none)')}, not {value}" for key, value in GO_ONLY_SETTINGS.items()
             if settings.get(key) != value]
    wrong += [f"{key}={settings[key]}" for key in GO_C_RUNTIMES if settings.get(key, "false") != "false"]
    if "linkmode" in settings.get("-ldflags", "") or "extld" in settings.get("-ldflags", ""):
        wrong.append(f"-ldflags={settings['-ldflags']} chooses the linker")
    if wrong:
        return f"a Go program ({version}) whose build information lets its link take C code: " + "; ".join(wrong)
    # The build information does not show a .syso file, which Go's own linker takes with no cgo: the function table
    # does.
    foreign = foreign_code(data, sections)
    if foreign:
        return f"a Go program ({version}) whose code Go's function table does not account for: {foreign}"
    return GoProgram(version, settings)


def parse_map(text):
    """The input sections of an lld map that reach the binary: [(file, member or None, section, size)]. An output
    section is a line whose text follows the four columns of numbers with no indent; an input section is a line whose
    text is indented by eight blanks and reads <file>:(<section>) or <archive>(<member>):(<section>), and belongs to
    the output section above it. Only input sections of an output section at a non-zero address are kept: lld gives
    a section that is not loaded (debug information, .comment, which the published binary's --strip-all removes) the
    address 0, and its input sections their offsets in it, which are not 0 past the first. So an archive whose
    members only have debug information left after --gc-sections is not taken. The linker's own sections
    (<internal>) are left out."""
    taken = []
    loaded = False
    for line in text.splitlines():
        found = MAP_COLUMNS.match(line)
        if not found:
            continue
        rest = line[found.end():]
        if rest[:1] not in ("", " "):
            loaded = int(found.group(1), 16) != 0
            continue
        if not loaded or not rest.startswith(" " * 8) or rest[8:9] in ("", " "):
            continue
        rest = rest[8:]
        at = rest.rfind(":(")
        if at <= 0 or not rest.endswith(")"):
            continue
        file, section = rest[:at], rest[at + 2:-1]
        if file == "<internal>":
            continue
        member = None
        if file.endswith(")") and "(" in file:
            open_at = file.rindex("(")
            file, member = file[:open_at], file[open_at + 1:-1]
        taken.append((file, member, section, int(found.group(2), 16)))
    return taken


def read_record(raw, sha256, compiles=None):
    """The record of the link whose unstripped output has this SHA-256, in the build's $OUT `raw`
    ($OUT/.records/<sha256>/), with the build's compile records `compiles` (read_compiles). Raise RecordError if it is
    not there, is incomplete, or holds a symbolic link."""
    directory = below(raw, ".records", sha256)

    def text(name):
        return read_regular(below(directory, name)).decode("utf-8", "replace")

    try:
        mapping, rows, driver = text("map"), text("inputs.tsv").splitlines(), text("driver").split()
        renamed_rows = text("renamed").splitlines() if os.path.lexists(directory / "renamed") else []
    except RecordError as error:
        raise RecordError(f"the link record is incomplete: {error}") from None
    inputs, renamed = {}, {}
    for row in rows:
        fields = row.split("\t")
        if len(fields) == 4 and re.fullmatch(r"[0-9a-f]{64}", fields[2]) and fields[3].isdigit():
            inputs[fields[0]] = (fields[1], fields[2], int(fields[3]))
    for row in renamed_rows:
        fields = row.split("\t")
        if len(fields) == 3 and re.fullmatch(r"[0-9a-f]{64}", fields[2]):
            renamed[fields[0]] = (fields[1], fields[2])
    quiet = None
    try:
        quiet = below(directory, "quiet")
        if not stat.S_ISREG(os.lstat(quiet).st_mode):
            quiet = None
    except RecordError:
        quiet = None
    return Record(parse_map(mapping), inputs, set(driver), renamed, pathlib.Path(raw), quiet, compiles)


def runtime_kind(path):
    """The kind of a file of the toolchain image, for the uninstrumented list, or None if no rule names it."""
    name = path.rsplit("/", 1)[-1]
    if CXX_RUNTIME.fullmatch(name):
        return "cxx-runtime"
    if COMPILER_RT.fullmatch(name):
        return "compiler-rt"
    if SANITIZER_RUNTIME.fullmatch(name):
        return "sanitizer-runtime"
    if FORTRAN_RUNTIME.fullmatch(name):
        return "fortran-runtime"
    if "/usr/lib/" in path and LIBC.fullmatch(name):
        return "libc"
    if SYSROOT_LIB.fullmatch(path):
        return "image-library"
    return None


# ── archives and objects ─────────────────────────────────────────────────────────────────────────────────────────────

def ar_members(data):
    """The members of a System V or GNU ar archive: [(name, bytes)]. A thin archive holds no member bytes: []."""
    if not data.startswith(b"!<arch>\n"):
        return []
    members, names, at = [], b"", 8
    while at + 60 <= len(data):
        header = data[at:at + 60]
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            break
        if size < 0:  # a header that would move the walk backwards
            break
        body = data[at + 60:at + 60 + size]
        at += 60 + size + (size & 1)
        name = header[:16].decode("latin-1").rstrip()
        if name == "//":
            names = body
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        if name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            end = names.find(b"\n", start)
            name = names[start:end if end >= 0 else len(names)].decode("latin-1")
        members.append((name.rstrip("/"), body))
    return members


@dataclasses.dataclass
class ObjectFacts:
    """What an ELF relocatable object says about its code."""

    code: int  # bytes of executable sections
    asan: bool  # it refers to AddressSanitizer's module constructor symbols (ASAN_MODULE)
    traps: int  # `unimp` words in its executable sections
    ub_checks: int  # precondition_check functions it defines (rustc's UB checks)
    defined: list  # the global functions it defines
    files: list  # the names of its STT_FILE symbols
    compiled: bool  # a compiler's .comment or .llvm_addrsig: it was compiled from C, C++ or another language
    bitcode: bool  # LLVM bitcode, which this cannot read


def words(body):
    """The little-endian 32-bit words of `body`, from its first byte: riscv64 code without compressed instructions is
    a sequence of them."""
    table = array.array("I", body[:len(body) // 4 * 4])
    if sys.byteorder == "big":
        table.byteswap()
    return table


def object_facts(data):
    """The facts of one object file's bytes, or None if it is not a 64-bit little-endian ELF file or LLVM bitcode."""
    if data[:4] == b"BC\xc0\xde":
        return ObjectFacts(0, False, 0, 0, [], [], True, True)
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    shoff, = struct.unpack_from("<Q", data, 40)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if shoff == 0 or shentsize < 64 or shoff + 64 > len(data):
        return None
    first = struct.unpack_from("<IIQQQQIIQQ", data, shoff)
    # Extended numbering: with 0xff00 sections or more, the count is section 0's sh_size, and the index of the section
    # names is its sh_link.
    if shnum == 0:
        shnum = first[5]
    if shstrndx == SHN_XINDEX:
        shstrndx = first[6]
    if shoff + shnum * shentsize > len(data):
        return None
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]

    def raw(index):
        _, kind, _, _, offset, size, *_ = sections[index]
        return b"" if kind == SHT_NOBITS else data[offset:offset + size]

    names = raw(shstrndx) if shstrndx < shnum else b""

    def name_of(offset):
        end = names.find(b"\0", offset)
        return names[offset:end if end >= 0 else len(names)].decode("latin-1")

    code = traps = 0
    compiled = False
    for index, (name, kind, flags, _, _, size, *_) in enumerate(sections):
        section = name_of(name)
        if section in (".comment", ".llvm_addrsig"):
            compiled = True
        if flags & SHF_EXECINSTR and kind != SHT_NOBITS and size:
            body = raw(index)
            code += len(body)
            traps += words(body).count(TRAP)
    asan, defined, files, ub_checks = False, [], [], 0
    for index, (_, kind, _, _, _, _, link, _, _, entsize) in enumerate(sections):
        if kind != SHT_SYMTAB or entsize < 24 or link >= shnum:
            continue
        table, strings = raw(index), raw(link)
        for at in range(0, len(table) - 23, entsize):
            name, info, _, shndx = struct.unpack_from("<IBBH", table, at)
            end = strings.find(b"\0", name)
            text = strings[name:end if end >= 0 else len(strings)].decode("latin-1")
            if (info & 0xF) == STT_FILE:
                files.append(text)
            elif shndx == SHN_UNDEF:
                asan = asan or bool(ASAN_MODULE.fullmatch(text))
            elif (info & 0xF) == 2:  # a function this object defines
                # rustc's UB checks: a precondition_check function, of any binding.
                ub_checks += "precondition_check" in text
                if (info >> 4) in (1, 2):  # global or weak
                    defined.append(text)
    return ObjectFacts(code, asan, traps, ub_checks, defined, files, compiled, False)


# ── one target ───────────────────────────────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class Code:
    """One object or archive member of the project's code that a link took."""

    label: str  # archive(member) or object, by the original's file name
    facts: ObjectFacts | None
    archive: str | None  # the archive it is a member of, by file name, or None for an object linked on its own
    data: bytes = b""


def is_seal(facts):
    """Whether an object is one of the driver's seals that a recipe compiled (DRIVER_SEALS)."""
    return (facts is not None and facts.defined and facts.files
            and all(pathlib.PurePosixPath(name).name in DRIVER_SEALS for name in facts.files)
            and all(name.startswith("__wrap_") for name in facts.defined))


def project_code(record, image):
    """The project's code that a link took ([Code]), the files that the toolchain image provides ([(real path,
    sha256)]), and problems ([text]). `image` maps a real path under /opt to the toolchain image's sha256 of it."""
    code, provided, problems = [], [], []
    members = {}
    for file, member, _, _ in record.taken:
        members.setdefault(file, set())
        if member is not None:
            members[file].add(member)
    for file, wanted in sorted(members.items()):
        if file not in record.inputs:
            problems.append(f"the link took {file}, which its record does not describe")
            continue
        real, sha256, _ = record.inputs[file]
        if file in record.driver or real in record.driver:
            continue
        # An allocation-failure link's copy stands for its original, whose allocator calls it renames.
        original, original_sha256 = record.renamed.get(real, (real, sha256))
        if original.startswith("/opt/") and image.get(original) == original_sha256:
            provided.append((original, original_sha256))
            continue
        try:
            data = record.store(sha256)
        except RecordError as error:
            problems.append(f"{file}: {error}")
            continue
        name = COPY_PREFIX.sub("", pathlib.PurePosixPath(original).name)
        if data.startswith(b"!<thin>\n"):
            problems.append(f"{name}: a thin archive, whose members this cannot read")
        elif data.startswith(b"!<arch>\n"):
            parts = ar_members(data)
            found = {member for member, _ in parts}
            for member, body in parts:
                if member in wanted:
                    code.append(Code(f"{name}({member})", object_facts(body), name, body))
            for member in sorted(wanted - found):
                problems.append(f"the link took {name}({member}), which this does not find in the archive")
        else:
            code.append(Code(name, object_facts(data), None, data))
    return [c for c in code if not is_seal(c.facts)], provided, problems


def listed(items):
    return items[:MAX_LISTED] + ([f"and {len(items) - MAX_LISTED} more"] if len(items) > MAX_LISTED else [])


def ub_count(code):
    """The UBSan traps and rustc UB checks of some code, by the archive it is a member of, and by name for an object
    the link took on its own: {archive or object name: count}."""
    counts = {}
    for c in code:
        if c.facts is not None and not c.facts.bitcode:
            where = c.archive or c.label
            counts[where] = counts.get(where, 0) + c.facts.traps + c.facts.ub_checks
    return counts


def driver_words(arguments):
    """`arguments`, with each word that the driver hands on to clang's front end as a bare word: -Xclang=<word> and
    -Wp,<word>,<word>... as the words, and each -Xclang or -Xpreprocessor before a word left out."""
    words = []
    for a in arguments:
        if a in ("-Xclang", "-Xpreprocessor"):
            continue
        if a.startswith("-Xclang="):
            words.append(a[len("-Xclang="):])
        elif a.startswith("-Wp,"):
            words += a[len("-Wp,"):].split(",")
        else:
            words.append(a)
    return words


def option_values(words, option):
    """The values that `option` has among `words` (driver_words): <option> <value> and <option>=<value>."""
    return [words[i + 1] if w == option else w[len(option) + 1:] for i, w in enumerate(words)
            if w == option and i + 1 < len(words) or w.startswith(option + "=")]


def flex_levels(arguments):
    """The -fstrict-flex-arrays= values among `arguments`: (those the driver reads itself, in order; those it hands on
    to clang's front end, as driver_words reads them)."""
    driver, forwarded = [], []
    handed_on = False
    for a in arguments:
        if handed_on:
            forwarded.append(a)
            handed_on = False
        elif a in ("-Xclang", "-Xpreprocessor"):
            handed_on = True
        elif a.startswith("-Xclang="):
            forwarded.append(a[len("-Xclang="):])
        elif a.startswith("-Wp,"):
            forwarded += a[len("-Wp,"):].split(",")
        else:
            driver.append(a)
    return ([w[len(STRICT_FLEX_ARRAYS):] for w in driver if w.startswith(STRICT_FLEX_ARRAYS)],
            [w[len(STRICT_FLEX_ARRAYS):] for w in forwarded if w.startswith(STRICT_FLEX_ARRAYS)])


def lower_flex_levels(wanted, arguments):
    """The -fstrict-flex-arrays= words of a compile's `arguments` that give a lower level than the build's UBSan flags
    `wanted` do (the last of theirs), or none when those flags have none: the last one the driver reads, and each one
    it hands on to the front end, which counts against the compile and never for it. A build level that is not decimal
    digits cannot be compared, so each compile then counts as giving a lower level: the build's own word."""
    build = flex_levels(wanted)[0]
    if not build:
        return []
    if not re.fullmatch("[0-9]+", build[-1]):
        return [STRICT_FLEX_ARRAYS + build[-1]]
    driver, forwarded = flex_levels(arguments)
    return [STRICT_FLEX_ARRAYS + level for level in driver[-1:] + forwarded
            if not (re.fullmatch("[0-9]+", level) and int(level) >= int(build[-1]))]


def wants_checks(compiles, language):
    """Whether the build's UBSan flags for `language` ("c" or "c++") turn on a check: hold a -fsanitize= word. Flags
    that turn on none (an empty list, or only -fno-sanitize-recover and the like) are carried by any compile, and so
    show nothing: such a build's compile records decide nothing for that language."""
    return any(w.startswith("-fsanitize=") for w in compiles.ubsan[language])


def ubsan_compile(compiles, compile):
    """Whether one recorded compile carried the build's UndefinedBehaviorSanitizer flags for its language: (True,
    ""), (False, why), or (None, "") when its record cannot say: for a language the sanitizer does not instrument
    (assembly), a build whose UBSan flags for that language turn on no check (no -fsanitize= word: wants_checks),
    arguments it read from a response file (@file), or an option of UNSEEN (an LLVM option, or one that makes clang
    read flags or an ignorelist from a file the record does not hold) with a value that the build's own flags do not
    give it. It carried them when each of the build's UBSan flags for that language is one of its arguments, but the
    -fno-sanitize= ones; each check that a -fno-sanitize= argument of it turns off is one that the build's own
    sanitizer flags for that language turn off (a check that the build turns off is the build's choice, one the
    compile adds is not); and it has no ignorelist, -fno-sanitize-trap, -fsanitize-recover or -ftrap-function argument
    (UNDO_CHECKS) that the build's own flags do not have, and, when the build's UBSan flags give -fstrict-flex-arrays=,
    the last one that the driver reads gives no lower level, and none that it hands on to the front end gives a lower
    level, wherever it stands (lower_flex_levels). A word that the driver hands on to the front end
    (-Xclang, -Xclang=, -Xpreprocessor, -Wp,) counts against the compile as the bare word does, and never for it."""
    language = UBSAN_LANGUAGES.get(compile.language)
    wanted = [w for w in compiles.ubsan[language] if not w.startswith(NO_SANITIZE)] if language else []
    if not language or not wants_checks(compiles, language) or any(a.startswith("@") for a in compile.arguments):
        return None, ""
    own = set(compiles.sanitizer[language])
    words, own_words = driver_words(compile.arguments), driver_words(compiles.sanitizer[language])
    if any(not set(option_values(words, option)) <= set(option_values(own_words, option)) for option in UNSEEN):
        return None, ""
    have = set(compile.arguments)
    allowed = {check for w in compiles.sanitizer[language] if w.startswith(NO_SANITIZE)
               for check in w[len(NO_SANITIZE):].split(",")}
    missing = [w for w in wanted if w not in have]
    extra = sorted({a for a in words
                    if a.startswith(NO_SANITIZE) and not set(a[len(NO_SANITIZE):].split(",")) <= allowed
                    or UNDO_CHECKS.fullmatch(a) and a not in own} | set(lower_flex_levels(wanted, compile.arguments)))
    if not missing and not extra:
        return True, ""
    return False, (f"{compile.file}: " + ", ".join((["without " + " ".join(missing)] if missing else [])
                                                   + (["with " + " ".join(extra)] if extra else [])))


# What ubsan_record says of bytes with no check whose compile's source took UBSan checks out of them.
TURNED_OFF = "no UBSan check, and its source's no_sanitize attributes took UBSan checks out of it"


def ubsan_record(compiles, data, checks):
    """What the build's compile records say of an object's bytes `data`, which hold `checks` UBSan traps and UB
    checks: (True, ""), when a recorded compile that wrote these bytes carried the build's UBSan flags (the bytes are
    the same whichever one made them); (False, why), when compiles wrote them and none carried the flags; (None, "")
    when no record decides.

    Code with nothing to check has no trap, and so has code whose source turns the checks off (a no_sanitize
    attribute, turns_ubsan_off): the bytes do not tell the two apart, so a compile shows bytes with no check
    instrumented only when its record shows that its source's attributes took no check out of them. That is so when
    the source has no attribute that turns a UBSan check off, or when the object that record-compile compiled with the
    attributes taken out has no check either. When that object has checks, the attributes took them out of these
    bytes, and the compile says they were not instrumented. A record that cannot say (no_sanitize null, or no such
    object) decides nothing for bytes with no check."""
    if compiles is None:
        return None, ""
    verdicts = []
    for compile in compiles.objects.get(hashlib.sha256(data).hexdigest(), []):
        verdict, why = ubsan_compile(compiles, compile)
        if verdict and not checks:
            off = None if compile.no_sanitize is None else [a for a in compile.no_sanitize if turns_ubsan_off(a)]
            if off is None or off and compile.no_sanitize_checks is None:
                verdict = None
            elif off and compile.no_sanitize_checks:
                verdict, why = False, (f"{compile.file}: {TURNED_OFF} ({compile.no_sanitize_checks} without "
                                       + ", ".join(off) + ")")
        verdicts.append((verdict, why))
    if any(verdict for verdict, _ in verdicts):
        return True, ""
    against = [why for verdict, why in verdicts if verdict is False]
    return (False, against[0]) if against else (None, "")


def relative_source(path, checkouts):
    """`path` relative to the git checkout of the image that holds it, or None."""
    path = posixpath.normpath(path)
    for checkout in sorted(checkouts, key=len, reverse=True):
        checkout = posixpath.normpath(checkout)
        if path.startswith(checkout + "/"):
            return path[len(checkout) + 1:]
    return None


def assembly_records(compiles, c):
    """The recorded compiles of assembly that wrote the bytes of the object `c` (Code), but those whose arguments are
    in a response file, which the record does not show."""
    return [k for k in compiles.objects.get(hashlib.sha256(c.data).hexdigest(), [])
            if k.language in ("assembler", "assembler-with-cpp") and not any(a.startswith("@") for a in k.arguments)]


def assembly_flags(compiles):
    """The build's own sanitizer flags that a compile of assembly must carry: each of them but the -fno-sanitize=
    ones, for C and C++ alike."""
    return [w for w in compiles.sanitizer["c"] if not w.startswith(NO_SANITIZE) and w in compiles.sanitizer["c++"]]


def unflagged_assembly(c, compiles):
    """The problem of an assembly object (Code) whose recorded compiles (assembly_records) all lack the build's own
    sanitizer flags (assembly_flags), wherever its source is: the build's flags did not reach it. It names the object
    and the flags. None when one of them carried the flags, or there is no record (the object is judged as before)."""
    if compiles is None:
        return None
    recorded, flags = assembly_records(compiles, c), assembly_flags(compiles)
    if not recorded or any(all(w in k.arguments for w in flags) for k in recorded):
        return None
    missing = [w for w in flags if w not in recorded[0].arguments]
    return f"{c.label}: assembled without the build's sanitizer flags ({recorded[0].file}: without {' '.join(missing)})"


def copied_sources(objects, compiles, checkouts, checkout_files):
    """For each assembly object of `objects` ([Code]) whose DWARF names a source outside every checkout: the
    checkout's file that the build's compile records `compiles` show it was assembled from, relative to its checkout,
    or None. A ported build copies the source tree into a build directory and assembles the copy there
    (infra/base-builder/release-target.sh, BUILDDIR), so the object's DWARF names the copy. A recorded compile of an
    assembly source that wrote the object's bytes, with the build's own sanitizer flags (assembly_flags), names the
    copy too (its directory and file), and the SHA-256 of the source it read (source_sha256): the source is the
    checkout's file at <checkout>/<the copy's path less some of its leading directories>, the longest such path, when
    that file has the same bytes (`checkout_files(paths)` gives {path: sha256} of the project image's files). No such
    record, or no checkout file with those bytes: None, and the object is judged as before."""
    results = [None] * len(objects)
    if compiles is None or not checkouts:
        return results
    flags = assembly_flags(compiles)
    plans, paths = [], set()
    for n, c in enumerate(objects):
        candidates = []
        for k in assembly_records(compiles, c):
            if not all(w in k.arguments for w in flags) or k.source_sha256 is None or not k.directory.startswith("/"):
                continue
            parts = [p for p in posixpath.normpath(posixpath.join(k.directory, k.file)).split("/") if p]
            for i in range(1, len(parts)):
                tail = "/".join(parts[i:])
                if SOURCE.fullmatch(tail) and ASSEMBLY.search(tail):
                    for checkout in checkouts:
                        path = posixpath.join(posixpath.normpath(checkout), tail)
                        candidates.append((len(parts) - i, path, tail, k.source_sha256))
                        paths.add(path)
        plans.append((n, sorted(candidates, key=lambda x: -x[0])))
    hashes = checkout_files(sorted(paths)) if paths and checkout_files else {}
    for n, candidates in plans:
        for _, path, tail, sha256 in candidates:
            if hashes.get(path) == sha256:
                results[n] = tail
                break
    return results


def dwarf_source(unit, checkouts):
    """The source that a DWARF compile unit (language, name, compilation directory) names, relative to the checkout
    of the project image that holds it, or None."""
    if not unit or not unit[1]:
        return None
    return relative_source(unit[1] if unit[1].startswith("/") else posixpath.join(unit[2] or "", unit[1]), checkouts)


def source_entry(c, unit, checkouts, named=None, copied=None):
    """The uninstrumented entry of an object with no mark of a C or C++ compiler: (entry, problem or None). A
    compiler adds no sanitizer check to hand-written assembly or to Fortran, and OSS-Fuzz allows both uninstrumented,
    listed by name with the source they came from; the facts' schema asks for that source. Three things can name it:
    the object's DWARF compile unit (language, name, compilation directory), which the toolchain writes with -g and
    which also says the language; for an assembly object whose DWARF names a copy of a checkout's file in a build
    directory, its compile record (`copied`, from copied_sources); and, for an assembly object with no DWARF at all, a
    source of the project that carries the object's name and names every global the object defines (`named`, from
    assembly_sources). An object assembled without -g carries no mark of any kind, so without the last rule an honest
    build would fail."""
    name = c.label.rsplit("(", 1)[-1].rstrip(")")
    language = unit[0] if unit else ""
    kind = "assembly" if language == ASSEMBLER_LANGUAGE else "fortran" if FORTRAN_LANGUAGE.fullmatch(language) else ""
    entry = {"name": name, "kind": kind or "assembly"}
    if not NAME.fullmatch(name):
        return entry, f"{c.label}: its name is not one the facts can hold"
    if not kind:
        if language:
            return entry, (f"{c.label}: uninstrumented code with no mark of a C or C++ compiler, and its DWARF says "
                           f"{language}, not assembly or Fortran")
        if not named or not SOURCE.fullmatch(named):
            return entry, (f"{c.label}: uninstrumented code with no mark of a compiler and no DWARF, and no assembly "
                           "source of the project both carries its name and names every function it defines")
        entry["source"] = named
        return entry, None
    source = dwarf_source(unit, checkouts)
    if not source and kind == "assembly":
        source = copied
    if not source or not SOURCE.fullmatch(source) or not (ASSEMBLY if kind == "assembly" else FORTRAN).search(source):
        return entry, (f"{c.label}: its {kind} source {unit[1] or '(not named)'} is in no checkout of the project "
                       "image" + (", and no compile record of it shows the checkout's file with the same bytes"
                                  if kind == "assembly" else ""))
    entry["source"] = source
    return entry, None


def analyse(records, image, dwarf_units=None, checkouts=(), assembly_sources=None, checkout_files=None):
    """The results for one fuzz target: {build: {"uninstrumented": [...] or None, "instrumented": {"result",
    "detail"}}}. `records` maps a build to its Record, to a GoProgram, or to the reason it has neither; `image` maps
    real paths under /opt to the toolchain image's sha256. `dwarf_units(objects)` gives each object's DWARF compile
    unit (language, name, compilation directory) or None; `checkouts` are the checkouts of the project image, which a
    source is named relative to; `assembly_sources([(object name, [the functions it defines])])` gives, for an object
    with no DWARF, the assembly source of the project that carries its name and names every one of them, or None;
    `checkout_files(paths)` gives {path: sha256} of the files of the project image at `paths` (copied_sources)."""
    results, scanned, problems_of = {}, {}, {}
    for build, record in records.items():
        if isinstance(record, GoProgram):
            # Go's linker writes no map, and the program's own build information says what it linked: Go code only,
            # with no C library and no file of a C toolchain. No list is written: what it takes from the toolchain
            # image is Go's runtime and standard library, which no file list of the facts' schema names. Go has the
            # plain build only (infra/base-builder/go/compile-go), and no sanitizer instruments Go code.
            plain = build not in SANITIZER_BUILDS
            results[build] = {"uninstrumented": None, "instrumented": {
                "result": "plain" if plain else "error",
                "detail": (f"a Go program ({record.version}), linked by Go's own linker from Go code only (its build "
                           "information: " + ", ".join(f"{k}={record.settings[k]}" for k in GO_ONLY_SETTINGS)
                           + "), which writes no map; no uninstrumented list, as it links no C library or other file "
                           "of a C toolchain" + ("; the plain build instruments nothing, by design" if plain
                                                 else "; no sanitizer instruments Go code"))}}
            continue
        if not isinstance(record, Record):
            # With no record, nothing says what the link took, in the plain build as in the others.
            results[build] = {"uninstrumented": None,
                              "instrumented": {"result": "error", "detail": f"no link record: {record}"}}
            continue
        code, provided, problems = project_code(record, image)
        scanned[build] = code
        # A list that leaves a file out is worse than no list: the facts would then say that the build links less
        # uninstrumented code than it does. So a file the record does not describe or this cannot read, one file
        # without a kind, or an empty list, leaves the build with no list and an error, in the plain build as in the
        # others. Every static link takes the C library, so an empty list means the record named nothing; the facts'
        # schema asks for at least one entry too.
        listing, unknown = [], []
        for real, sha256 in sorted(provided):
            kind = runtime_kind(real)
            if kind is None:
                unknown.append(f"{real}: a file of the toolchain image that no kind names (tools/check_links.py, "
                               "runtime_kind)")
                continue
            listing.append({"name": real.rsplit("/", 1)[-1], "kind": kind, "sha256": sha256})
        if not listing:
            unknown.append("the link took no file of the toolchain image, and every static link takes its C library")
        unknown = problems + unknown
        results[build] = {"uninstrumented": None if unknown else listing, "incomplete": unknown}
        problems_of[build] = list(unknown)

    for build, problems in problems_of.items():
        result, code = results[build], scanned[build]
        if build not in SANITIZER_BUILDS:
            detail = "the plain build instruments nothing, by design"
            if problems:
                detail += "; " + "; ".join(listed(problems))
            result["instrumented"] = {"result": "error" if result.pop("incomplete") else "plain", "detail": detail}
            continue
        incomplete = result.pop("incomplete")
        with_code = [c for c in code if c.facts is not None and (c.facts.code or c.facts.bitcode)]
        unreadable = [c.label for c in code if c.facts is None]
        bitcode = [c.label for c in with_code if c.facts.bitcode]
        found = []
        # The build's compile records, if it has them and they are of this build.
        compiles = records[build].compiles
        if compiles is not None and compiles.build != build:
            compiles = None
        if build in ASAN_BUILDS:
            plain_c, shims, assembly = [], [], []
            for c in with_code:
                if c.facts.bitcode or c.facts.asan:
                    continue
                if c.facts.defined and all(RUST_ALLOCATOR_SHIM.fullmatch(n) for n in c.facts.defined):
                    shims.append(c.label)
                elif not c.facts.compiled and not any(C_FAMILY.search(n) for n in c.facts.files):
                    assembly.append(c)
                else:
                    plain_c.append(c.label)
            if assembly:
                units = dwarf_units([c.data for c in assembly]) if dwarf_units else [None] * len(assembly)
                # An object with no DWARF at all: the project's own assembly sources are asked for its name.
                wanted = [(c.label.rsplit("(", 1)[-1].rstrip(")"), c.facts.defined)
                          for c, unit in zip(assembly, units) if unit is None]
                found_sources = iter(assembly_sources(wanted) if assembly_sources and wanted else [None] * len(wanted))
                # An assembly object whose DWARF names a source outside every checkout: its compile record may show
                # that it is a build directory's copy of a checkout's file.
                outside = [n for n, unit in enumerate(units)
                           if unit and unit[0] == ASSEMBLER_LANGUAGE and dwarf_source(unit, checkouts) is None]
                copied = dict(zip(outside, copied_sources([assembly[n] for n in outside], compiles, checkouts,
                                                          checkout_files)))
                for n, (c, unit) in enumerate(zip(assembly, units)):
                    entry, problem = source_entry(c, unit, checkouts, next(found_sources) if unit is None else None,
                                                  copied.get(n))
                    # Wherever its source is, an assembly object whose recorded compiles lack the build's sanitizer
                    # flags is one the build's flags did not reach: a finding.
                    problem = unflagged_assembly(c, compiles) or problem
                    if problem:
                        # Code not shown to be assembly or Fortran is a finding (fail), and the list, which could not
                        # hold its entry, is not written either: never shorter than what the link took.
                        problems.append(problem)
                        result["uninstrumented"] = None
                    elif result["uninstrumented"] is not None:
                        result["uninstrumented"].append(entry)
            plain_c += shims[1:]
            if plain_c:
                found.append(f"{len(plain_c)} of {len(with_code)} objects with code refer to no AddressSanitizer "
                             "constructor: " + ", ".join(listed(plain_c)))
        notes, shown = [], 0
        if build in UBSAN_BUILDS:
            # Each object and archive member is judged first by the compile that wrote its bytes, when the build
            # recorded one: one that carried the build's UBSan flags is instrumented, whatever its traps (code with
            # nothing to check has none), unless it has none and its source turns a UBSan check off (ubsan_record);
            # one without them is not, whatever its traps.
            # A build whose records cannot decide says so in its cell: its code is then judged by its traps alone.
            if compiles is None:
                notes.append("the build has no compile records that this reads (flags.json or compiles.jsonl is not "
                             "there, cannot be read, or is another build's), so its code is judged by its UBSan "
                             "traps")
            else:
                none_on = [language for language in ("c", "c++") if not wants_checks(compiles, language)]
                if none_on:
                    notes.append("the build's recorded UndefinedBehaviorSanitizer flags for "
                                 + " and ".join("C" if language == "c" else "C++" for language in none_on)
                                 + " turn on no check (no -fsanitize= word), so its compile records decide nothing "
                                 "for that code, which is judged by its UBSan traps")
            without, turned_off, undecided = [], [], []
            for c in with_code:
                verdict, why = (ubsan_record(compiles, c.data, c.facts.traps + c.facts.ub_checks)
                                if not c.facts.bitcode else (None, ""))
                if verdict:
                    shown += 1
                elif verdict is False:
                    (turned_off if TURNED_OFF in why else without).append(f"{c.label} ({why})")
                else:
                    undecided.append(c)
            if without:
                found.append(f"{len(without)} objects were compiled without the build's UndefinedBehaviorSanitizer "
                             "flags: " + "; ".join(listed(without)))
            if turned_off:
                found.append(f"{len(turned_off)} objects have no UndefinedBehaviorSanitizer check because the "
                             "no_sanitize attributes of their source took the checks out: "
                             + "; ".join(listed(turned_off)))
            # The code that no record decides (a prebuilt object, a compile that ran no shim, a build without records)
            # is judged by its checks: each archive that holds some of it must hold more checks than the same archive
            # in the plain build, and so must the project's code as a whole. An object the link took on its own is
            # named when it holds none, and does not fail the build: one can genuinely have nothing to check (the
            # example fixture's own fuzz target object has no check in either build), and nothing in the object tells
            # the two apart. The enrollment's review reads that line. Without a plain build there is nothing to
            # compare, and the check decides nothing. A build without records is judged by its checks alone.
            by_checks = compiles is None or bool(undecided)
            if by_checks and "plain" not in scanned:
                incomplete = incomplete + ["no plain build to compare the UndefinedBehaviorSanitizer's checks with"]
                found.append(incomplete[-1])
            counts, baseline = ub_count(with_code), ub_count(scanned.get("plain", []))
            archives = {c.archive for c in with_code if c.archive}
            judged = {c.archive or c.label for c in undecided}
            short, quiet = [], []
            for where, count in sorted(counts.items()):
                before = baseline.get(where)
                if where not in judged or count and (before is None or count > before):
                    continue
                text = (f"{where}: {count} UBSan traps and UB checks"
                        + (f", the plain build's {before}" if before is not None else ""))
                (short if where in archives else quiet).append(text)
            total, before = sum(counts.values()), sum(baseline.values())
            if by_checks and (total == 0 or (baseline and total <= before)):
                short.append(f"the project's code as a whole: {total} UBSan traps and UB checks"
                             + (f", the plain build's {before}" if baseline else ""))
            if short:
                found.append("the UndefinedBehaviorSanitizer did not reach " + "; ".join(listed(short)))
            if quiet:
                notes.append("objects with no UndefinedBehaviorSanitizer check, which may have nothing to check: "
                             + "; ".join(listed(quiet)))
        if bitcode:
            found.append(f"{len(bitcode)} objects are LLVM bitcode, which this does not read: "
                         + ", ".join(listed(bitcode)))
        if unreadable:
            found.append(f"{len(unreadable)} objects are not 64-bit ELF files: " + ", ".join(listed(unreadable)))
        if not with_code:
            found.append("the link took no object of the project's code (examined nothing)")
        found += problems
        if incomplete:
            # The build's code may be instrumented, but the list of what it links uninstrumented is not there.
            result["instrumented"] = {"result": "error", "detail": "; ".join(found + notes)}
        elif found:
            result["instrumented"] = {"result": "fail", "detail": "; ".join(found + notes)}
        else:
            result["instrumented"] = {"result": "pass", "detail": "; ".join(
                [f"{len(with_code)} objects with code, all instrumented"
                 + (f", {shown} of them by the compile that wrote them, which carried the build's "
                    "UndefinedBehaviorSanitizer flags" if shown else "")] + notes)}
    return results


def parse_dwarfdump(text):
    """The first compile unit of each object in the output of
    `for f in ...; do echo "== $f"; llvm-dwarfdump --debug-info "$f"; done`: {file: (language, name, directory)}."""
    units, current, unit = {}, None, None

    def keep():
        if current is not None and unit is not None and current not in units:
            units[current] = tuple(unit)

    for line in text.splitlines():
        if line.startswith("== "):
            keep()
            current, unit = line[3:], None
        elif current is None or current in units:
            continue
        elif re.match(r"^0x[0-9a-f]+:\s+DW_TAG_", line):
            if unit is not None:
                keep()  # the compile unit's attributes end at the next entry
            elif "DW_TAG_compile_unit" in line:
                unit = ["", "", ""]
        elif unit is not None:
            found = re.search(r'DW_AT_(language|name|comp_dir)\s+\((?:"(.*)"|(DW_LANG_\w+))\)', line)
            if found:
                unit[{"language": 0, "name": 1, "comp_dir": 2}[found.group(1)]] = found.group(2) or found.group(3)
    keep()
    return units
