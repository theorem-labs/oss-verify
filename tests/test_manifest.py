# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for src/oss_verify/manifest.py:  uv run pytest"""
import hashlib
import os
import struct

import pytest
import yaml

from oss_verify import manifest


def elf(symbols=(), e_type=2, symtab=True, wide=True, sections=(), segments=()):
    """A minimal little-endian ELF file. `symbols` is a list of (name, info, shndx), `sections` a list of (name, size)
    of more sections, and `segments` a list of program header types."""
    strtab = b"\0" + b"".join(name.encode() + b"\0" for name, _, _ in symbols)
    entries, offset = [], 1
    for name, info, shndx in symbols:
        if wide:
            entries.append(struct.pack("<IBBHQQ", offset, info, 0, shndx, 0, 0))
        else:
            entries.append(struct.pack("<IIIBBH", offset, 0, 0, info, 0, shndx))
        offset += len(name) + 1
    table = (struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0) if wide else struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)) + b"".join(entries)
    header_size, section_size, symbol_size, segment_size = (64, 64, 24, 56) if wide else (52, 40, 16, 32)
    names = ([".symtab", ".strtab"] if symtab else []) + [name for name, _ in sections] + [".shstrtab"]
    shstrtab, name_offsets = b"\0", []
    for name in names:
        name_offsets.append(len(shstrtab))
        shstrtab += name.encode() + b"\0"
    body = table + strtab + shstrtab
    segments_at = header_size + len(body)
    segment_layout = "<IIQQQQQQ" if wide else "<IIIIIIII"

    def segment(item):
        # a program header type, or (type, flags, memsz)
        kind, flags, memsz = (item, 0, 0) if isinstance(item, int) else item
        if wide:
            return struct.pack(segment_layout, kind, flags, 0, 0, 0, 0, memsz, 0)
        return struct.pack(segment_layout, kind, 0, 0, 0, 0, memsz, flags, 0)

    program = b"".join(segment(item) for item in segments)
    sections_at = segments_at + len(program)
    section_layout = "<IIQQQQIIQQ" if wide else "<IIIIIIIIII"

    def section(name, kind, offset=0, size=0, link=0, info=0, align=1, entsize=0):
        return struct.pack(section_layout, name, kind, 0, 0, offset, size, link, info, align, entsize)

    headers = [section(0, 0, align=0)]
    if symtab:
        headers += [section(name_offsets[0], 2, header_size, len(table), 2, 1, 8 if wide else 4, symbol_size),
                    section(name_offsets[1], 3, header_size + len(table), len(strtab))]
    headers += [section(name_offsets[len(headers) - 1 + index], 1, size=size) for index, (_, size) in enumerate(sections)]
    headers.append(section(name_offsets[-1], 3, header_size + len(table) + len(strtab), len(shstrtab)))
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1, 1]) + bytes(9)
    fields = (e_type, 243, 1, 0, segments_at if segments else 0, sections_at, 0, header_size,
              segment_size if segments else 0, len(segments), section_size, len(headers), len(headers) - 1)
    header = ident + struct.pack("<HHIQQQIHHHHHH" if wide else "<HHIIIIIHHHHHH", *fields)
    return header + body + program + b"".join(headers)


GLOBAL_FUNC, LOCAL_FUNC, GLOBAL_OBJECT, WEAK_FUNC = 0x12, 0x02, 0x11, 0x22
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
ENTRY = "LLVMFuzzerTestOneInput"


class Scratch:
    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.dir = tmp_path

    def write(self, relative, data, mode=0o755):
        path = self.dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, mode)
        return path


class TestDiscovery(Scratch):
    def test_the_symbol_table_rule(self):
        cases = {
            "target": (elf([(ENTRY, GLOBAL_FUNC, 1)]), 0o755, True),
            "weak": (elf([(ENTRY, WEAK_FUNC, 1)]), 0o755, True),
            "pie": (elf([(ENTRY, GLOBAL_FUNC, 1)], e_type=3), 0o755, True),
            "elf32": (elf([(ENTRY, GLOBAL_FUNC, 1)], wide=False), 0o755, True),
            "undefined": (elf([(ENTRY, GLOBAL_FUNC, 0)]), 0o755, False),
            "local": (elf([(ENTRY, LOCAL_FUNC, 1)]), 0o755, False),
            "object": (elf([(ENTRY, GLOBAL_OBJECT, 1)]), 0o755, False),
            "other": (elf([("main", GLOBAL_FUNC, 1)]), 0o755, False),
            "stripped": (elf(symtab=False), 0o755, False),
            "relocatable": (elf([(ENTRY, GLOBAL_FUNC, 1)], e_type=1), 0o755, False),
            "not-executable": (elf([(ENTRY, GLOBAL_FUNC, 1)]), 0o644, False),
            "script": (b"#!/bin/sh\necho LLVMFuzzerTestOneInput\n", 0o755, False),
            "truncated": (elf([(ENTRY, GLOBAL_FUNC, 1)])[:70], 0o755, False),
        }
        for name, (data, mode, expected) in cases.items():
            path = self.write(f"out/{name}", data, mode)
            assert manifest.is_fuzz_target(path) == expected, name
        os.symlink(self.dir / "out/target", self.dir / "out/link")
        (self.dir / "out/.stripped").mkdir()
        found = manifest.discover(self.dir / "out")
        assert sorted(found) == ["elf32", "pie", "target", "weak"]
        assert manifest.has_symbol_table(self.dir / "out/target")
        assert not manifest.has_symbol_table(self.dir / "out/stripped")

    def test_a_symbol_table_past_any_file_is_no_symbol_table(self):
        """The build writes $OUT, so the pull request chooses every byte of each file there. A symbol table, or its
        strings, at an offset no file can reach is no symbol table: discover() goes on, rather than end oss-verify check
        with a traceback that build.yaml reports as "does not build"."""
        data = elf([(ENTRY, GLOBAL_FUNC, 1)])
        headers = len(data) - 4 * 64  # the section headers: none, .symtab, .strtab, .shstrtab
        for index, offset in ((2, 2 ** 63), (1, 2 ** 64 - 1)):
            far = bytearray(data)
            far[headers + index * 64 + 24:headers + index * 64 + 32] = offset.to_bytes(8, "little")  # sh_offset
            assert not manifest.is_fuzz_target(self.write(f"out/far{index}", bytes(far), 0o755)), index
        self.write("out/target", data, 0o755)
        assert list(manifest.discover(self.dir / "out")) == ["target"]

    def test_the_go_fuzz_targets_compile_lists(self):
        self.write("out/a", elf(symtab=False))
        self.write("out/b", elf(symtab=False))
        self.write("out/notes", b"text", 0o644)
        self.write("out/c", elf([(ENTRY, GLOBAL_FUNC, 1)]))
        (self.dir / "out/.go-fuzz-targets").write_text("a\nnotes\n../c\nmissing\n")
        assert sorted(manifest.discover(self.dir / "out")) == ["a", "c"]
        assert sorted(manifest.go_fuzz_targets(self.dir / "out")) == ["a"]
        (self.dir / "out/.go-fuzz-targets").unlink()
        assert sorted(manifest.discover(self.dir / "out")) == ["c"]

    def test_the_dsl_fuzz_targets_compile_lists(self):
        """A DSL fuzz target defines no LLVMFuzzerTestOneInput; compile lists it in $OUT/.dsl-fuzz-targets, as it
        lists a Go fuzz target, and the same names are refused."""
        self.write("out/api", elf())
        self.write("out/notes", b"text", 0o644)
        self.write("out/c", elf([(ENTRY, GLOBAL_FUNC, 1)]))
        (self.dir / "out/.dsl-fuzz-targets").write_text("api\nnotes\n../c\nmissing\n")
        assert sorted(manifest.discover(self.dir / "out")) == ["api", "c"]
        assert sorted(manifest.listed_fuzz_targets(self.dir / "out", manifest.DSL_TARGETS)) == ["api"]

    def test_resolve_targets(self):
        found = {"plain": {"a": 1, "b": 1}, "asan": {"a": 1, "b": 1}}
        assert manifest.resolve_targets(found) == (["a", "b"], [])
        assert manifest.resolve_targets(found, ["b"]) == (["b"], [])
        targets, problems = manifest.resolve_targets({"plain": {"a": 1, "b": 1}, "asan": {"a": 1}})
        assert targets == ["a"]
        assert problems == ["fuzz target b is in the plain build but not in the asan build"]
        targets, problems = manifest.resolve_targets(found, ["a", "c"])
        assert targets == ["a"]
        assert "fuzz target c, which project.yaml lists, is not in any build" in problems
        targets, problems = manifest.resolve_targets({"plain": {}})
        assert targets == []
        assert problems and "no fuzz target" in problems[0]


class TestCollection(Scratch):
    def test_collect_takes_the_stripped_twin(self):
        unstripped = elf([(ENTRY, GLOBAL_FUNC, 1)])
        twin = elf(symtab=False) + b"twin"
        for build in ("plain", "asan"):
            self.write(f"raw/{build}/fuzzer", unstripped)
            self.write(f"raw/{build}/.stripped/{hashlib.sha256(unstripped).hexdigest()}", twin)
        raw = {build: self.dir / "raw" / build for build in ("plain", "asan")}
        entries, problems = manifest.collect(raw, ["fuzzer"], self.dir / "out")
        assert problems == []
        assert (self.dir / "out/fuzzer/fuzzer.asan").read_bytes() == twin
        assert entries["fuzzer"]["plain"] == {
            "file": "fuzzer.plain", "bytes": len(twin), "sha256": hashlib.sha256(twin).hexdigest(),
        }

    def test_collect_needs_a_twin_without_symbols(self):
        unstripped = elf([(ENTRY, GLOBAL_FUNC, 1)])
        self.write("raw/plain/a", unstripped)
        self.write("raw/plain/b", unstripped + b"b")
        self.write(f"raw/plain/.stripped/{hashlib.sha256(unstripped + b'b').hexdigest()}", unstripped)
        _, problems = manifest.collect({"plain": self.dir / "raw/plain"}, ["a", "b"], self.dir / "out")
        assert len(problems) == 2
        assert "a in the plain build has no stripped twin" in problems[0]
        assert "the stripped twin of b in the plain build has a symbol table" in problems[1]


class TestLayout(Scratch):
    def test_text_size_is_read_by_name(self):
        sections = [(".text.startup", 11), (".rodata", 23), (".text", 4567), (".data", 89)]
        for wide in (True, False):
            path = self.write(f"target-{wide}", elf(symtab=False, wide=wide, sections=sections, segments=[PT_LOAD]))
            assert manifest.binary_layout(path)["text_bytes"] == 4567
        path = self.write("no-text", elf(symtab=False, sections=[(".data", 1)], segments=[PT_LOAD]))
        assert manifest.binary_layout(path)["text_bytes"] is None

    def test_static_means_no_interpreter_and_no_dynamic_segment(self):
        cases = {
            "static": ([PT_LOAD], True),
            "interpreter": ([PT_LOAD, PT_INTERP], False),
            "dynamic": ([PT_LOAD, PT_DYNAMIC], False),
        }
        for name, (segments, static) in cases.items():
            path = self.write(name, elf(symtab=False, sections=[(".text", 1)], segments=segments))
            assert manifest.binary_layout(path)["static"] is static, name

    def test_executable_bytes_sum_the_executable_loaded_segments(self):
        segments = [(PT_LOAD, 5, 3000), (PT_LOAD, 4, 9000), (PT_LOAD, 7, 400), (PT_DYNAMIC, 1, 77)]
        for wide in (True, False):
            # .text says 10 bytes; the loader maps 3,400 executable bytes, and that is what is counted
            path = self.write(f"exec-{wide}", elf(symtab=False, wide=wide, sections=[(".text", 10)], segments=segments))
            assert manifest.executable_bytes(path) == 3400, wide
            assert manifest.binary_layout(path)["text_bytes"] == 10, wide

    def test_executable_bytes_of_a_file_that_cannot_be_read(self):
        data = elf(symtab=False, sections=[(".text", 1)], segments=[(PT_LOAD, 5, 8)])
        assert manifest.executable_bytes(self.write("truncated-exec", data[:len(data) - 200])) is None
        assert manifest.executable_bytes(self.write("not-elf", b"#!/bin/sh\n")) is None
        assert manifest.executable_bytes(self.write("no-segments", elf(symtab=False))) == 0
        # e_phentsize smaller than one entry, and the PN_XNUM count: the program headers cannot be read
        for offset, value in ((54, 8), (56, 0xFFFF)):
            bad = data[:offset] + struct.pack("<H", value) + data[offset + 2:]
            assert manifest.executable_bytes(self.write(f"phdr-{offset}", bad)) is None, offset

    def test_a_truncated_file_is_not_read(self):
        data = elf(symtab=False, sections=[(".text", 1)], segments=[PT_LOAD, PT_INTERP])
        for size in (0, 20, 63, len(data) - 1):
            assert manifest.binary_layout(self.write(f"truncated-{size}", data[:size])) is None, size

    def test_an_offset_past_any_file_is_not_read(self):
        data = elf(symtab=False, sections=[(".text", 1)], segments=[PT_LOAD])
        for start in (32, 40):  # e_phoff, e_shoff
            path = self.write(f"offset-{start}", data[:start] + struct.pack("<Q", 2**64 - 1) + data[start + 8:])
            assert not manifest.has_symbol_table(path), start
            assert manifest.binary_layout(path) is None, start


class TestLocks(Scratch):
    ENTRIES = {"fuzzer": {"plain": {"file": "fuzzer.plain", "bytes": 3, "sha256": "aa"},
                          "asan": {"file": "fuzzer.asan", "bytes": 4, "sha256": "bb"}}}

    def test_manifest_round_trip(self):
        layouts = {"fuzzer": {"plain": {"text_bytes": 10, "static": True},
                              "asan": {"text_bytes": 20, "static": False}}}
        data = manifest.manifest(
            project="p", repo="https://x/y", ref="v1", commit="c" * 40, oss_verify=None,
            builder={"toolchain": "example.org/toolchain@sha256:" + "1" * 64},
            sources={}, builds=["plain", "asan"], targets=["fuzzer"], entries=self.ENTRIES, layouts=layouts,
        )
        manifest.write_manifest(self.dir / "manifest.yaml", data)
        text = (self.dir / "manifest.yaml").read_text()
        assert text.startswith("# Generated by oss-verify check; do not edit.\n")
        assert yaml.safe_load(text)["layout"] == layouts
        assert yaml.safe_load(text)["targets"] == {"fuzzer": {"builds": self.ENTRIES["fuzzer"]}}
        commit, pins, toolchain = manifest.load_lock(self.dir / "manifest.yaml")
        assert commit == "c" * 40
        assert toolchain == "example.org/toolchain@sha256:" + "1" * 64
        assert pins[("fuzzer", "asan")]["sha256"] == "bb"
        assert manifest.compare(self.ENTRIES, pins, ["plain", "asan"]) == ([], [], 2)

    def test_harness_yaml(self):
        harness = {"schema": "oss-fuzz-theorems/harness/1", "harness": "fuzzer",
                   "library": {"commit": "d" * 40},
                   "builds": {"plain": {"file": "fuzzer.plain", "bytes": 3, "sha256": "aa"},
                              "ubsan": {"file": "fuzzer.ubsan", "bytes": 5, "sha256": "cc"},
                              "asan": {"file": "fuzzer.asan", "bytes": 4, "sha256": "00"}}}
        (self.dir / "harness.yaml").write_text(yaml.safe_dump(harness))
        commit, pins, toolchain = manifest.load_lock(self.dir / "harness.yaml")
        assert commit == "d" * 40
        assert toolchain is None  # no project.yaml two directories up
        # The release's harness.yaml is projects/<name>/<harness>/harness.yaml; its project.yaml names the builder.
        harness_dir = self.dir / "projects" / "p" / "fuzzer"
        harness_dir.mkdir(parents=True)
        (harness_dir / "harness.yaml").write_text(yaml.safe_dump(harness))
        (harness_dir.parent / "project.yaml").write_text("build:\n  builder: example.org/tc@sha256:" + "2" * 64 + "\n")
        assert manifest.load_lock(harness_dir / "harness.yaml")[2] == "example.org/tc@sha256:" + "2" * 64
        (harness_dir.parent / "project.yaml").write_text("at: 2024-13-45\n")
        assert manifest.load_lock(harness_dir / "harness.yaml")[2] is None
        differences, extras, matched = manifest.compare(self.ENTRIES, pins, ["plain", "asan"])
        assert matched == 1
        assert extras == []
        assert len(differences) == 1
        assert "fuzzer.asan: sha256 bb" in differences[0]
        differences, extras, matched = manifest.compare(self.ENTRIES, pins, ["plain", "ubsan", "asan"])
        assert "fuzzer.ubsan: in the lock, not in this build" in differences

    @pytest.mark.parametrize("text", [
        pytest.param("- a\n", id="a-list"),
        pytest.param("schema: something/else\n", id="another-schema"),
        pytest.param("harness: x\nbuilds: {plain: {bytes: 1}}\n", id="a-build-with-no-sha256"),
        pytest.param("a: [\n", id="no-yaml"),
        pytest.param("at: 2024-13-45\n", id="a-date-that-does-not-exist"),
        pytest.param("created: 2024-01-01T25:00:00\n", id="a-time-that-does-not-exist"),
    ])
    def test_extras_and_bad_locks(self, text):
        _, extras, _ = manifest.compare(self.ENTRIES, {("fuzzer", "plain"): {"sha256": "aa"}}, ["plain", "asan"])
        assert extras == ["fuzzer.asan: in this build, not in the lock"]
        (self.dir / "lock.yaml").write_text(text)
        with pytest.raises(manifest.LockError):
            manifest.load_lock(self.dir / "lock.yaml")

    HARNESS = "schema: oss-fuzz-theorems/harness/1\n"

    @pytest.mark.parametrize("text", [
        pytest.param("targets: {f: [1, 2]}\n", id="a-target-that-is-not-a-mapping"),
        pytest.param("targets: {f: {builds: [plain]}}\n", id="builds-that-are-not-a-mapping"),
        pytest.param(f"schema: {manifest.MANIFEST_SCHEMA}\ntargets: [f]\n", id="targets-that-are-not-a-mapping"),
        pytest.param(HARNESS + "builds: {plain: {sha256: aa}}\n", id="no-harness"),
        pytest.param(HARNESS + "harness: {a: b}\nbuilds: {plain: {sha256: aa}}\n", id="a-harness-that-is-a-mapping"),
        pytest.param(HARNESS + "harness: f\nbuilds: [1]\n", id="harness-builds-that-are-not-a-mapping"),
        pytest.param("harness: f\nbuilds: {plain: {sha256: aa}}\nlibrary: x\n", id="a-library-that-is-not-a-mapping"),
    ])
    def test_a_lock_of_the_wrong_shape_is_a_lock_error(self, text):
        """Every shape that is not a lock is refused with LockError, which oss-verify check reports as a message, never
        an AttributeError or KeyError that ends it with a traceback."""
        (self.dir / "lock.yaml").write_text(text)
        with pytest.raises(manifest.LockError):
            manifest.load_lock(self.dir / "lock.yaml")
        # Still a lock: a harness named by a number, and a manifest whose target has no builds yet.
        (self.dir / "lock.yaml").write_text(self.HARNESS + "harness: 7\nbuilds: {plain: {sha256: aa}}\n")
        assert list(manifest.load_lock(self.dir / "lock.yaml")[1]) == [("7", "plain")]
        (self.dir / "lock.yaml").write_text("targets: {f: {builds: }}\n")
        assert manifest.load_lock(self.dir / "lock.yaml")[1] == {}
