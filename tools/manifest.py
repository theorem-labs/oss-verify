# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Fuzz targets, the build manifest, and locks: the parts of tools/check that need no Docker.

A fuzz target is an executable in a build's $OUT whose ELF symbol table defines LLVMFuzzerTestOneInput. This is
OSS-Fuzz's rule (infra/utils.py, is_fuzz_target_local), reading the symbol table instead of searching the bytes. A Go
program has no such symbol, so `compile` lists the Go fuzz targets in $OUT/.go-fuzz-targets.
`compile` saves the stripped twin of each one as $OUT/.stripped/<sha256 of the executable>, and those stripped bytes
are what is collected, published and pinned.

The manifest's targets.<target>.builds section has the shape of the builds: section of an oss-fuzz-theorems
harness.yaml (file, bytes, sha256 for each build), so that the lock in the proofs repository can take it as it is.
Its layout section gives each binary's .text size and whether it is statically linked, apart from that harness shape.
With --twice, its rebuild block records the second build in the same shape, and whether the two are identical.
"""
import hashlib
import os
import pathlib
import shutil
import struct

import yaml

# The schema tag and the field "oss_verifier" keep the project's old name: the tools that read manifests use them.
MANIFEST_SCHEMA = "oss-verifier/build-manifest/1"
HARNESS_SCHEMA = "oss-fuzz-theorems/harness/1"
ENTRY = b"LLVMFuzzerTestOneInput"
STRIPPED = ".stripped"
GO_TARGETS = ".go-fuzz-targets"

SHT_SYMTAB = 2
SHN_UNDEF = 0
SHN_XINDEX = 0xFFFF
STT_FUNC = 2
STB_GLOBAL, STB_WEAK = 1, 2
ET_EXEC, ET_DYN = 2, 3
PT_DYNAMIC, PT_INTERP = 2, 3
PN_XNUM = 0xFFFF
TEXT = b".text\0"
MAX_ELF_BYTES = 4 << 30


class LockError(Exception):
    """A lock file that cannot be read or is not of a known kind."""


def sha256_of(path):
    """The SHA-256 of a file, in hex."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_elf(path):
    """Return (header fields, section headers) of an ELF file, or None if it is not one we can read.

    The header fields are type, wide, order, phoff, phentsize, phnum and shstrndx. Each section header is (type,
    offset, size, link, entsize, name), where name is the offset of its name in the section-header string table.
    Reads only the headers and what they point to; a malformed file is not an error, just not an ELF file.
    """
    try:
        with open(path, "rb") as handle:
            ident = handle.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF" or ident[4] not in (1, 2) or ident[5] not in (1, 2):
                return None
            wide, order = ident[4] == 2, "<" if ident[5] == 1 else ">"
            header = handle.read(48 if wide else 36)
            layout = order + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH")
            if len(header) < struct.calcsize(layout):
                return None
            (e_type, _, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack(layout, header)
            fields = {"type": e_type, "wide": wide, "order": order, "phoff": e_phoff, "phentsize": e_phentsize,
                      "phnum": e_phnum, "shstrndx": e_shstrndx}
            entry = order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
            if e_shoff == 0 or e_shnum == 0 or e_shentsize < struct.calcsize(entry) or e_shnum > 65535:
                return fields, []
            sections = []
            for index in range(e_shnum):
                handle.seek(e_shoff + index * e_shentsize)
                raw = handle.read(struct.calcsize(entry))
                if len(raw) < struct.calcsize(entry):
                    return None
                values = struct.unpack(entry, raw)
                # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
                sections.append((values[1], values[4], values[5], values[6], values[9], values[0]))
            return fields, sections
    except (OSError, ValueError):  # ValueError: an offset larger than any file
        return None


def binary_layout(path):
    """Return {"text_bytes", "static"} of an ELF file, or None if it is not one we can read.

    text_bytes is the size of the section named .text in the section-header string table (e_shstrndx), or None if the
    file has no such section. static is True if no program header is PT_INTERP or PT_DYNAMIC. Reads only the headers,
    four bytes of each program header and six bytes of each section's name; a malformed file is not an error.
    """
    parsed = read_elf(path)
    if parsed is None:
        return None
    header, sections = parsed
    try:
        with open(path, "rb") as handle:
            kinds = program_header_types(handle, header)
            if kinds is None:
                return None
            return {"text_bytes": section_size(handle, sections, header["shstrndx"], TEXT),
                    "static": not ({PT_INTERP, PT_DYNAMIC} & kinds)}
    except (OSError, ValueError):  # ValueError: an offset larger than any file
        return None


def program_header_types(handle, header):
    """The p_type of every program header, or None if they cannot be read."""
    count, size = header["phnum"], header["phentsize"]
    if count == 0:
        return set()
    if count == PN_XNUM or size < (56 if header["wide"] else 32):  # PN_XNUM: the count is in section 0
        return None
    kinds = set()
    for index in range(count):
        handle.seek(header["phoff"] + index * size)
        raw = handle.read(4)
        if len(raw) < 4:
            return None
        kinds.add(struct.unpack(header["order"] + "I", raw)[0])
    return kinds


def section_size(handle, sections, names, wanted):
    """The size of the first section whose name, with its NUL, is `wanted`, or None if there is none."""
    if names == SHN_XINDEX and sections:
        names = sections[0][3]  # the index is in section 0's sh_link
    if names == SHN_UNDEF or names >= len(sections):
        return None
    _, offset, size, *_ = sections[names]
    for _, _, section_bytes, _, _, name in sections:
        if name <= size - len(wanted):
            handle.seek(offset + name)
            if handle.read(len(wanted)) == wanted:
                return section_bytes
    return None


def defined_symbols(path, wanted):
    """Return the names in `wanted` that the ELF file's symbol table defines as a global or weak function."""
    parsed = read_elf(path)
    if parsed is None:
        return set()
    header, sections = parsed
    wide, order = header["wide"], header["order"]
    symbol = order + ("IBBHQQ" if wide else "IIIBBH")
    found = set()
    with open(path, "rb") as handle:
        for kind, offset, size, link, entsize, _ in sections:
            if kind != SHT_SYMTAB or entsize < struct.calcsize(symbol) or link >= len(sections):
                continue
            _, str_offset, str_size, *_ = sections[link]
            if size > MAX_ELF_BYTES or str_size > MAX_ELF_BYTES:
                continue
            handle.seek(str_offset)
            strings = handle.read(str_size)
            handle.seek(offset)
            table = handle.read(size)
            for start in range(0, len(table) - entsize + 1, entsize):
                fields = struct.unpack_from(symbol, table, start)
                if wide:
                    name, info, _, shndx = fields[0], fields[1], fields[2], fields[3]
                else:
                    name, info, shndx = fields[0], fields[3], fields[5]
                if shndx == SHN_UNDEF or (info & 0xF) != STT_FUNC or (info >> 4) not in (STB_GLOBAL, STB_WEAK):
                    continue
                end = strings.find(b"\0", name)
                text = strings[name:end if end >= 0 else len(strings)]
                if text in wanted:
                    found.add(text)
    return found


def has_symbol_table(path):
    """Return True if the ELF file has a symbol table (a stripped one has none)."""
    parsed = read_elf(path)
    return parsed is not None and any(kind == SHT_SYMTAB for kind, *_ in parsed[1])


def is_executable(path):
    """Return True if `path` is an executable ELF file (not a link to one)."""
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        return False
    parsed = read_elf(path)
    return parsed is not None and parsed[0]["type"] in (ET_EXEC, ET_DYN)


def is_fuzz_target(path):
    """Return True if `path` is an executable ELF file whose symbol table defines LLVMFuzzerTestOneInput."""
    return is_executable(path) and ENTRY in defined_symbols(path, {ENTRY})


def go_fuzz_targets(out):
    """The Go fuzz targets that `compile` lists in $OUT/.go-fuzz-targets, one name on each line: {name: path}."""
    listing = pathlib.Path(out) / GO_TARGETS
    if listing.is_symlink() or not listing.is_file():
        return {}
    names = listing.read_text(encoding="utf-8", errors="replace").split()
    return {name: pathlib.Path(out) / name for name in names
            if "/" not in name and name not in (".", "..") and is_executable(pathlib.Path(out) / name)}


def discover(out):
    """The fuzz targets in one build's $OUT: {name: path}, by the symbol table rule, and the Go fuzz targets."""
    out = pathlib.Path(out)
    found = {path.name: path for path in out.iterdir() if is_fuzz_target(path)}
    found.update(go_fuzz_targets(out))
    return dict(sorted(found.items()))


def published(out, path):
    """The stripped twin `compile` saved for the executable at `path` in `out`, or None if there is none."""
    twin = pathlib.Path(out) / STRIPPED / sha256_of(path)
    return twin if twin.is_file() and not twin.is_symlink() else None


def resolve_targets(found, wanted=None):
    """Decide which fuzz targets a check covers. `found` maps each build to the targets discovered in it; `wanted` is
    project.yaml's fuzz_targets, or None for all of them. Return (targets, problems)."""
    builds = list(found)
    common = set.intersection(*(set(found[build]) for build in builds)) if builds else set()
    problems = []
    for build in builds:
        for name in sorted(set(found[build]) - common):
            missing = [other for other in builds if name not in found[other]]
            problems.append(f"fuzz target {name} is in the {build} build but not in the {', '.join(missing)} build")
    if wanted is None:
        targets = sorted(common)
        if not targets and not problems:
            problems.append(
                "the build produced no fuzz target: no executable in $OUT defines LLVMFuzzerTestOneInput "
                "(link each one with $LIB_FUZZING_ENGINE)"
            )
        return targets, problems
    for name in wanted:
        if name not in common and not any(name in found[build] for build in builds):
            problems.append(f"fuzz target {name}, which project.yaml lists, is not in any build")
    return [name for name in wanted if name in common], problems


def collect(raw, targets, out):
    """Copy each target's published bytes from raw[<build>] (a build's $OUT) to out/<target>/<target>.<build>.

    Return ({target: {build: {file, bytes, sha256}}}, problems).
    """
    out = pathlib.Path(out)
    if out.exists():
        shutil.rmtree(out)
    entries, problems = {}, []
    for target in targets:
        (out / target).mkdir(parents=True)
        entries[target] = {}
        for build, directory in raw.items():
            twin = published(directory, pathlib.Path(directory) / target)
            if twin is None:
                problems.append(
                    f"{target} in the {build} build has no stripped twin: it was not linked through $CC or $CXX "
                    "with $LIB_FUZZING_ENGINE, or build.sh changed it after the link"
                )
                continue
            if has_symbol_table(twin):
                problems.append(f"the stripped twin of {target} in the {build} build has a symbol table")
                continue
            name = f"{target}.{build}"
            shutil.copyfile(twin, out / target / name)
            os.chmod(out / target / name, 0o755)
            entries[target][build] = {
                "file": name, "bytes": (out / target / name).stat().st_size, "sha256": sha256_of(out / target / name),
            }
    return entries, problems


def layouts(out, entries):
    """The layout of each binary that collect() copied to `out`: {target: {build: {text_bytes, static}}}, with None
    for each value that cannot be read."""
    out = pathlib.Path(out)
    return {target: {build: binary_layout(out / target / entry["file"]) or {"text_bytes": None, "static": None}
                     for build, entry in builds.items()}
            for target, builds in entries.items()}


def manifest(*, project, repo, ref, commit, oss_verify, builder, sources, builds, targets, entries, layouts):
    """The build manifest of one check, as a mapping ready for YAML."""
    return {
        "schema": MANIFEST_SCHEMA,
        "project": project,
        "repo": repo,
        "ref": ref,
        "commit": commit,
        "oss_verifier": oss_verify,
        "builder": builder,
        "sources": sources,
        "builds": builds,
        "fuzz_targets": targets,
        "targets": {target: {"builds": entries[target]} for target in targets},
        "layout": {target: layouts[target] for target in targets},
    }


def rebuild(first, second, targets, *, host, at, builder, builds):
    """The rebuild block that tools/check --twice adds to a manifest once it has compared its second build with the
    first: where and when the second build ran, its builder, each binary that it made (as the top level's targets
    section), and whether every binary has the first build's bytes. `first` and `second` are collect()'s entries.

    Return (block, differences, matched): a difference is a binary that one build made and the other did not, or made
    with other bytes; matched counts the binaries whose bytes are identical."""
    pins = {(target, build): entry for target in first for build, entry in first[target].items()}
    differences, extras, matched = compare(second, pins, builds)
    differences += extras
    block = {
        "kind": "same-host",
        "host": host,
        "at": at,
        "builder": builder,
        "builds": builds,
        "targets": {target: {"builds": second[target]} for target in targets},
        "result": "differs" if differences else "identical",
    }
    return block, differences, matched


def write_manifest(path, data):
    """Write a manifest as YAML, marked as generated."""
    text = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=120)
    pathlib.Path(path).write_text("# Generated by tools/check; do not edit.\n" + text, encoding="utf-8")


def load_lock(path):
    """Read a lock: a manifest from tools/check, or an oss-fuzz-theorems harness.yaml.

    Return (commit or None, {(target, build): {"file", "bytes", "sha256"}}, toolchain image or None). A manifest names
    its toolchain; a harness.yaml's is the builder its project.yaml, two directories up, names. Raise LockError if it
    is neither.
    """
    try:
        data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise LockError(f"cannot read {path}: {error}") from None
    if not isinstance(data, dict):
        raise LockError(f"{path} is not a mapping")
    pins, toolchain = {}, None
    if data.get("schema") == MANIFEST_SCHEMA or isinstance(data.get("targets"), dict):
        for target, entry in (data.get("targets") or {}).items():
            for build, pin in ((entry or {}).get("builds") or {}).items():
                pins[(str(target), str(build))] = pin
        commit = data.get("commit")
        toolchain = (data.get("builder") or {}).get("toolchain") if isinstance(data.get("builder"), dict) else None
    elif data.get("schema") == HARNESS_SCHEMA or (isinstance(data.get("builds"), dict) and data.get("harness")):
        for build, pin in (data.get("builds") or {}).items():
            pins[(str(data["harness"]), str(build))] = pin
        commit = (data.get("library") or {}).get("commit")
        project_file = pathlib.Path(path).resolve().parent.parent / "project.yaml"
        try:
            project = yaml.safe_load(project_file.read_text(encoding="utf-8")) if project_file.is_file() else None
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            project = None
        if isinstance(project, dict) and isinstance(project.get("build"), dict):
            toolchain = project["build"].get("builder")
    else:
        raise LockError(f"{path} is neither a tools/check manifest nor an oss-fuzz-theorems harness.yaml")
    for key, pin in pins.items():
        if not (isinstance(pin, dict) and isinstance(pin.get("sha256"), str)):
            raise LockError(f"{path}: the pin of {key[0]}.{key[1]} has no sha256")
    return (commit if isinstance(commit, str) else None), pins, (toolchain if isinstance(toolchain, str) else None)


def compare(entries, pins, builds):
    """Compare a fresh build with a lock. Return (differences, extras, matched): a difference is a binary the lock pins
    that this build does not reproduce; an extra is a binary this build made that the lock does not pin; matched
    counts the binaries whose bytes are identical. Only the builds in `builds` are compared."""
    differences, extras, matched = [], [], 0
    for (target, build), pin in sorted(pins.items()):
        if build not in builds:
            continue
        fresh = entries.get(target, {}).get(build)
        if fresh is None:
            differences.append(f"{target}.{build}: in the lock, not in this build")
        elif fresh["sha256"] != pin["sha256"]:
            differences.append(
                f"{target}.{build}: sha256 {fresh['sha256']} ({fresh['bytes']} bytes), the lock has "
                f"{pin['sha256']} ({pin.get('bytes', '?')} bytes)"
            )
        else:
            matched += 1
    for target, by_build in sorted(entries.items()):
        for build in sorted(by_build):
            if (target, build) not in pins:
                extras.append(f"{target}.{build}: in this build, not in the lock")
    return differences, extras, matched
