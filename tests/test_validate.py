# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for oss-verify validate:  uv run pytest"""
import contextlib
import functools
import io
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import tracemalloc
import zipfile

import pytest

from oss_verify import validate

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"

KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBF...\n-----END PGP PUBLIC KEY BLOCK-----\n"
CONTACT = "security@libexample.dev"
MINIMAL = f"repo: https://github.com/example/project#v1.0\nprimary_contact: {CONTACT}\nlanguage: c\n"


class ProjectDir:
    """A projects/<name>/ directory in a temporary directory, removed afterwards."""

    def __init__(self, files, name="example"):
        self.scratch = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.scratch.name) / name
        self.path.mkdir()
        for file, content in files.items():
            target = self.path / file
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        self.scratch.cleanup()


def check(yaml_text, files=None, name="example"):
    """Run check_project on a directory holding project.yaml and `files` (default: a Dockerfile and a build.sh)."""
    if files is None:
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
    with ProjectDir({"project.yaml": yaml_text, **files}, name) as directory:
        return validate.check_project(directory)


class TestValidProjects:
    def test_minimal(self):
        problems, warnings, summary = check(MINIMAL)
        assert problems == []
        assert warnings == []
        assert "builds: plain ubsan asan asan-ubsan" in summary
        assert "fuzz targets: all" in summary

    def test_every_field(self):
        text = (
            "repo: https://github.com/example/project#0123456789abcdef0123456789abcdef01234567\n"
            f"primary_contact: {CONTACT}\nhomepage: https://example.org\nlanguage: c++\n"
            "disabled: false\nsanitizers: [address]\nfuzz_targets: [a_fuzzer, b-fuzzer.x]\npublish: eager\n"
            "budgets:\n  halts: 16GiB\n  agrees:\n    address: [2GiB, 512GiB]\n"
            "proofs:\n  repo: https://github.com/example/proofs#main\n  path: projects/example\n"
            f"pgp: |\n  {KEY.replace(chr(10), chr(10) + '  ')}\n"
        )
        files = {
            "Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n", "patch_style.md": "# Patches\n", "sources": "# none\n",
            "driver.c": "int x;\n", "driver.h": "", "more.cpp": "", "0001-static.patch": "--- a\n+++ b\n",
            "series": "# order\n0001-static.patch\n",
        }
        problems, warnings, summary = check(text, files)
        assert problems == []
        assert warnings == []
        assert "builds: plain asan" in summary
        assert "fuzz targets: a_fuzzer, b-fuzzer.x" in summary

    def test_dockerfile_in_repository(self):
        problems, _, summary = check(MINIMAL + "dockerfile: .oss-verify/Dockerfile\n", {"patch_style.md": "x"})
        assert problems == []
        assert "in the repository at .oss-verify/Dockerfile" in summary

    def test_seeded_project_warns(self):
        problems, warnings, _ = check(MINIMAL.replace(CONTACT, "n/a"))
        assert problems == []
        assert any("primary_contact is n/a" in warning for warning in warnings)

    def test_seeded_project_without_build_files_warns(self):
        problems, warnings, summary = check(MINIMAL.replace(CONTACT, "n/a"), {})
        assert problems == []
        assert any("no build files yet" in warning for warning in warnings)
        assert "Dockerfile: none yet" in summary

    def test_files_the_sources_file_copies_may_have_any_name(self):
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/sh\n", "list.sha256": "00  x\n",
                 "sources": "copy\ttargets/t/list.sha256\tlist.sha256\n"}
        problems, _, _ = check(MINIMAL, files)
        assert problems == []
        problems, _, _ = check(MINIMAL, {**files, "sources": "# copies nothing\n"})
        assert any("list.sha256: only project.yaml" in problem for problem in problems), problems

    def test_dockerfile_without_build_sh_warns(self):
        problems, warnings, _ = check(MINIMAL, {"Dockerfile": "FROM x\n"})
        assert problems == []
        assert any("no build.sh" in warning for warning in warnings)

    def test_short_commit_warns(self):
        problems, warnings, _ = check(MINIMAL.replace("#v1.0", "#abc1234"))
        assert problems == []
        assert any("shortened commit" in warning for warning in warnings)

    def test_placeholder_address_warns(self):
        for address in ("dry-run@example.invalid", "security@example.org", "a@mail.example.com", "x@host.test"):
            problems, warnings, _ = check(MINIMAL.replace(CONTACT, address))
            assert problems == []
            assert any(f"{address} is a placeholder" in warning for warning in warnings), warnings
        _, warnings, _ = check(MINIMAL + "auto_ccs: [team@example.net]\n")
        assert any("team@example.net is a placeholder" in warning for warning in warnings), warnings
        # Aliases of one address give one warning, not one for each place.
        _, warnings, _ = check(MINIMAL + "auto_ccs: [&cc team@example.net" + ", *cc" * 1999 + "]\n")
        assert warnings == ["team@example.net is a placeholder: its domain is reserved for examples, so no report "
                            "reaches it"]
        # A real domain that only contains "example" is not one.
        assert check(MINIMAL.replace(CONTACT, "security@myexample.org"))[1] == []


class TestBuilds:
    def test_builds_follow_sanitizers(self):
        assert validate.builds_of({}) == ["plain", "ubsan", "asan", "asan-ubsan"]
        assert validate.builds_of({"sanitizers": ["undefined", "address"]}) == ["plain", "ubsan", "asan", "asan-ubsan"]
        assert validate.builds_of({"sanitizers": ["address"]}) == ["plain", "asan"]
        assert validate.builds_of({"sanitizers": ["undefined"]}) == ["plain", "ubsan"]
        assert validate.builds_of({"sanitizers": []}) == ["plain"]

    def test_sizes(self):
        assert validate.size_in_bytes("16GiB") == 16 << 30
        assert validate.size_in_bytes("512GiB") == 512 << 30
        assert validate.size_in_bytes(1024) == 1024
        for bad in ("0", "16GB", "-1", "1.5GiB", True, 0, None, "", "16 GiB"):
            assert validate.size_in_bytes(bad) is None, bad


class TestLanguages:
    def test_oss_fuzz_names(self):
        for language in ("c", "c++", "rust", "python", "go", "jvm", "javascript"):
            problems, _, _ = check(MINIMAL.replace("language: c", f"language: {language}"))
            assert problems == [], language
        for language in ("ruby", "lua", "swift", "C", "java"):
            problems, _, _ = check(MINIMAL.replace("language: c", f"language: {language}"))
            assert any("language must be one of" in problem for problem in problems), language

    def test_the_languages_built_today(self):
        assert check(MINIMAL)[1] == []
        assert check(MINIMAL.replace("language: c", "language: rust"))[1] == []
        assert check(MINIMAL.replace("language: c", "language: python"))[1] == []
        _, warnings, _ = check(MINIMAL.replace("language: c", "language: javascript"))
        assert any("the builder cannot build it yet" in warning for warning in warnings), warnings
        # A language is built today if, and only if, a toolchain in infra/toolchains.tsv builds it.
        listed = {language for _, _, _, languages in validate.check_build.toolchains() for language in languages}
        assert set(validate.BUILT_TODAY) == listed

    def test_ubsan_checks_are_for_c_and_cxx(self):
        changes = "ubsan_checks: {remove: [shift], reason: shifts of negative values are intended}\n"
        problems, _, _ = check(MINIMAL.replace("language: c", "language: rust") + changes)
        assert any("applies only to C, C++ and Python" in problem for problem in problems), problems
        for language in ("c", "python"):
            problems, _, _ = check(MINIMAL.replace("language: c", f"language: {language}") + changes)
            assert not any("applies only to" in problem for problem in problems), problems

    def test_go_and_jvm_have_the_plain_build_only(self):
        for language in ("go", "jvm"):
            text = MINIMAL.replace("language: c", f"language: {language}")
            assert "builds: plain;" in check(text)[2]
            assert "builds: plain;" in check(text + "sanitizers: []\n")[2]
            problems, _, _ = check(text + "sanitizers: [address]\n")
            assert any("plain build only" in problem for problem in problems), problems
        assert validate.builds_of({"language": "go"}) == ["plain"]
        assert validate.builds_of({"language": "rust"}) == ["plain", "ubsan", "asan", "asan-ubsan"]

    def test_harness_suffixes_follow_the_language(self):
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n", "fuzz_parse.rs": "fn main() {}\n",
                 "shim.c": "int x;\n"}
        assert check(MINIMAL.replace("language: c", "language: rust"), files)[0] == []
        problems, _, _ = check(MINIMAL, files)
        assert any(problem.startswith("fuzz_parse.rs: only") for problem in problems), problems
        assert validate.limit_for("fuzz.py", validate.source_suffixes({"language": "python"})) == \
            validate.MAX_SOURCE_BYTES
        assert validate.limit_for("fuzz.py", validate.source_suffixes({"language": "c"})) == \
            validate.MAX_FILE_BYTES


def corpus(inputs):
    """A seed corpus: a zip file of these {name: bytes} inputs."""
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in inputs.items():
            archive.writestr(name, content)
    return data.getvalue()


class TestSeedCorpora:
    BUILD = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}

    def problems(self, data, text=MINIMAL, name="a_fuzzer_seed_corpus.zip", files=None):
        return check(text, {**(self.BUILD if files is None else files), name: data})[0]

    def test_a_seed_corpus(self):
        assert self.problems(corpus({"empty": b"", "one": b"\x01\x02"})) == []
        assert self.problems(corpus({"x": b"1"}), MINIMAL + "fuzz_targets: [a_fuzzer]\n") == []
        # It may stay beside project.yaml when the repository holds the build files.
        in_repo = MINIMAL + "dockerfile: .oss-verify/Dockerfile\n"
        assert self.problems(corpus({"x": b"1"}), in_repo, files={}) == []

    def test_bad_seed_corpora(self):
        def has(fragment, problems):
            assert any(fragment in problem for problem in problems), f"{fragment!r} not in {problems}"
        has("is not a zip file", self.problems(b"not a zip"))
        has("holds no input", self.problems(corpus({})))
        has("is not a file at the top level", self.problems(corpus({"dir/x": b"1"})))
        has("is not a file at the top level", self.problems(corpus({"../x": b"1"})))
        has("which fuzz_targets does not list", self.problems(corpus({"x": b"1"}), MINIMAL + "fuzz_targets: [b]\n"))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(validate, "MAX_CORPUS_INPUTS", 2)
            has("more than 2 inputs", self.problems(corpus({"x": b"1", "y": b"2", "z": b"3"})))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(validate, "MAX_CORPUS_EXPANDED", 1 << 20)
            has("expands to more than 1 MiB", self.problems(corpus({"zeros": bytes(2 << 20)})))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(validate, "MAX_CORPUS_BYTES", 10)
            has("is larger than 0 KiB", self.problems(corpus({"x": b"1"})))
        # Any other zip file name is refused.
        has("only project.yaml", self.problems(corpus({"x": b"1"}), name="inputs.zip"))


class TestUbsanChecks:
    """ubsan_checks, in its provisional format: changes to the default, with the reason."""

    def has(self, fragment, texts):
        assert any(fragment in text for text in texts), f"{fragment!r} not in {texts}"

    def test_changes_with_a_reason(self):
        added = "ubsan_checks:\n  add: [alignment]\n  reason: the decoder must not read packed structures misaligned\n"
        problems, warnings, _ = check(MINIMAL + added)
        assert problems == []
        self.has("has no effect yet", warnings)
        cxx = MINIMAL.replace("language: c", "language: c++")
        removed = "ubsan_checks: {remove: [function], reason: callbacks are called through a void pointer type}\n"
        assert check(cxx + removed)[0] == []
        default = validate.DEFAULT_UBSAN_CHECKS
        assert validate.ubsan_checks_in_effect(yaml_of(MINIMAL + added)) == [*default["c"], "alignment"]
        assert validate.ubsan_checks_in_effect(yaml_of(cxx + removed)) == \
            [check for check in default["c++"] if check != "function"]
        assert validate.ubsan_checks_in_effect(yaml_of(MINIMAL)) == default["c"]
        assert validate.ubsan_checks_in_effect(yaml_of(cxx)) == default["c++"]
        # A c project's default has no function to remove.
        self.has("function is not in the default", check(MINIMAL + removed)[1])

    def test_the_defaults(self):
        """OSS-Fuzz's -fno-sanitize-recover list, less vptr (trap mode cannot make it); C and Python drop function,
        as OSS-Fuzz drops it from C compiles and from a Python project's native code."""
        default = validate.DEFAULT_UBSAN_CHECKS
        assert default["c"] == [check for check in default["c++"]
                                if check not in ("function", "vptr", "libcxx-hardening")]
        # strict-flex-arrays is about C as much as C++: every default has it.
        for checks in default.values():
            assert "strict-flex-arrays" in checks
        assert default["python"] == default["c"]
        for checks in default.values():
            assert "unsigned-integer-overflow" not in checks

    def test_bad_changes(self):
        def problems(text):
            return check(MINIMAL + text)[0]
        self.has("must be a mapping", problems("ubsan_checks: [null, bool]\n"))
        self.has("unknown field 'only'", problems("ubsan_checks: {only: [null], reason: x}\n"))
        self.has("'made-up' is not a UBSan check", problems("ubsan_checks: {add: [made-up], reason: x}\n"))
        self.has("'objc-cast' is not a UBSan check", problems("ubsan_checks: {add: [objc-cast], reason: x}\n"))
        self.has("ubsan_checks.add must be a list", problems("ubsan_checks: {add: alignment, reason: x}\n"))
        self.has("names a check twice", problems("ubsan_checks: {remove: [enum, enum], reason: x}\n"))
        self.has("adds and removes the same check", problems("ubsan_checks: {add: [enum], remove: [enum], reason: x}\n"))
        self.has("changes nothing", problems("ubsan_checks: {add: [], reason: x}\n"))
        self.has("must say why", problems("ubsan_checks: {add: [alignment]}\n"))
        self.has("must say why", problems("ubsan_checks: {add: [alignment], reason: ' '}\n"))
        self.has("sanitizers must contain undefined",
                 problems("sanitizers: [address]\nubsan_checks: {add: [alignment], reason: x}\n"))
        self.has("libcxx-hardening applies only to a c++ project",
                 problems("ubsan_checks: {add: [libcxx-hardening], reason: x}\n"))

    def test_cxx_opts_out_of_vptr_and_hardening(self):
        cxx = MINIMAL.replace("language: c\n", "language: c++\n")
        assert cxx != MINIMAL
        out = cxx + "ubsan_checks: {remove: [vptr, libcxx-hardening], reason: the library is built without RTTI}\n"
        assert check(out)[0] == []
        assert validate.ubsan_checks_in_effect(yaml_of(out)) == \
            [c for c in validate.DEFAULT_UBSAN_CHECKS["c++"] if c not in ("vptr", "libcxx-hardening")]

    def test_a_project_opts_out_of_strict_flex_arrays(self):
        out = MINIMAL + ("ubsan_checks: {remove: [strict-flex-arrays], reason: 'the packet header is read past its "
                         "trailing options[4], into the room allocated for it'}\n")
        problems, warnings, _ = check(out)
        assert problems == []
        assert not any("strict-flex-arrays" in warning for warning in warnings), warnings
        assert validate.ubsan_checks_in_effect(yaml_of(out)) == \
            [c for c in validate.DEFAULT_UBSAN_CHECKS["c"] if c != "strict-flex-arrays"]
        # Without array-bounds it adds no check, which is worth a warning, not a refusal.
        alone = MINIMAL + "ubsan_checks: {remove: [array-bounds], reason: x}\n"
        assert check(alone)[0] == []
        self.has("strict-flex-arrays adds no check without array-bounds, which the checks leave out; it still changes "
                 "how clang optimizes the code of the two UBSan builds", check(alone)[1])

    def test_warnings(self):
        warnings = check(MINIMAL + "ubsan_checks: {add: [vptr, enum], remove: [alignment], reason: x}\n")[1]
        self.has("vptr: only the ubsan build makes it, through the toolchain's trap-only handler", warnings)
        self.has("enum is in the default already", warnings)
        self.has("alignment is not in the default", warnings)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(validate, "newest_toolchain_applies_ubsan_checks", lambda *args, **kwargs: True)
            warnings = check(MINIMAL + "ubsan_checks: {add: [alignment], reason: x}\n")[1]
        assert not any("has no effect yet" in warning for warning in warnings), warnings

    def test_a_bare_null_is_the_check_null(self):
        assert validate.ubsan_changes_of({"ubsan_checks": {"remove": [None]}}) == {"remove": ["null"]}
        assert validate.ubsan_changes_of({}) is None


def yaml_of(text):
    return validate.yaml.safe_load(text)


# The SHA-256 that a program's entry pins in the tests: 64 hex digits, lower case.
PIN = "0123456789abcdef" * 4
# A file name of 101 characters: one more than a program's file name may have.
LONG = "h" * 101


def programs(*entries):
    """MINIMAL's project.yaml with a programs list of these entries, each one a mapping in YAML's flow style."""
    return MINIMAL + "programs:\n" + "".join(f"  - {entry}\n" for entry in entries)


def nested_list(levels):
    """A YAML flow list of 9 ** (levels + 1) strings, in a few bytes for each level: l0 is a list of 9 strings, and each
    l<k> is a list of 9 aliases of l<k-1> (the first one defines it)."""
    text = "[" + ", ".join("abcdefghi") + "]"
    for level in range(levels):
        text = f"[&l{level} {text}" + f", *l{level}" * 8 + "]"
    return text


HELLO = programs(f"{{file: hello, sha256: {PIN}, link_map: hello.map}}")


class TestPrograms:
    """programs: the whole programs that build.sh writes, which a project names in place of fuzz targets. Such a
    project has the plain build alone, and no fuzz target, mutants or seed corpus."""

    BUILD = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}

    def refused(self, text, fragment, files=None):
        """Check that validate refuses the project, with a problem that holds `fragment`."""
        problems, _, summary = check(text, files)
        assert summary is None
        assert any(fragment in problem for problem in problems), f"{fragment!r} not in {problems}"

    def test_a_program_port(self):
        problems, warnings, summary = check(HELLO)
        assert (problems, warnings) == ([], [])
        assert "builds: plain; programs: hello)" in summary
        assert validate.builds_of(yaml_of(HELLO)) == ["plain"]
        # The language is not restricted.
        for language in validate.BUILT_TODAY:
            assert check(HELLO.replace("language: c\n", f"language: {language}\n"))[0] == [], language

    def test_a_program_port_with_an_empty_sanitizers_list(self):
        problems, _, summary = check(HELLO + "sanitizers: []\n")
        assert problems == []
        assert "builds: plain; programs: hello)" in summary

    def test_two_programs(self):
        text = programs(f"{{file: hello, sha256: {PIN}, link_map: hello.map}}",
                        f"{{file: server, sha256: {'f' * 64}, link_map: server.map}}")
        problems, _, summary = check(text)
        assert problems == []
        assert "builds: plain; programs: hello, server)" in summary

    def test_a_program_port_lists_no_fuzz_target(self):
        self.refused(HELLO + "fuzz_targets: [hello]\n", "programs and fuzz_targets together are not supported")

    @pytest.mark.parametrize("sanitizers", ["[address]", "[undefined]", "[address, undefined]"])
    def test_a_program_port_has_no_sanitizer_build(self, sanitizers):
        self.refused(HELLO + f"sanitizers: {sanitizers}\n",
                     "a project with programs has the plain build only: give sanitizers: [] or leave it out")

    def test_a_program_port_has_no_ubsan_checks(self):
        self.refused(HELLO + "ubsan_checks: {add: [alignment], reason: x}\n",
                     "ubsan_checks applies only to the UBSan builds: sanitizers must contain undefined")

    def test_a_program_port_has_no_mutants(self):
        self.refused(HELLO + "mutants: breakages\n", "mutants applies only to fuzz targets")

    def test_a_program_port_has_no_seed_corpus(self):
        files = {**self.BUILD, "hello_seed_corpus.zip": corpus({"x": b"1"})}
        # The same seed corpus is valid beside a project of fuzz targets.
        assert check(MINIMAL, files)[0] == []
        self.refused(HELLO, "hello_seed_corpus.zip: a project with programs has no seed corpus", files)

    def test_a_program_port_keeps_the_halts_budget(self):
        assert check(HELLO + "budgets: {halts: 16GiB}\n")[0] == []
        self.refused(HELLO + "budgets: {agrees: {address: [2GiB, 512GiB]}}\n",
                     "budgets.agrees.address is set, but address is not one of this project's sanitizers")

    @pytest.mark.parametrize("text, fragment", [
        (MINIMAL + "programs: hello\n", "programs must be a non-empty list"),
        (MINIMAL + "programs: []\n", "programs must be a non-empty list"),
        (MINIMAL + "programs: [hello]\n", "programs: entry 1 must be a mapping"),
        (programs(f"{{file: hello, sha256: {PIN}, name: hello}}"), "programs: entry 1: unknown field 'name'"),
        (programs(f"{{sha256: {PIN}}}"), "programs: entry 1: missing file"),
        (programs("{file: hello}"), "programs: entry 1: missing sha256"),
        (programs(f"{{file: bin/hello, sha256: {PIN}}}"), "programs: entry 1: file 'bin/hello' is not a file name"),
        (programs(f"{{file: .hello, sha256: {PIN}}}"), "programs: entry 1: file '.hello' is not a file name"),
        (programs(f"{{file: {LONG}, sha256: {PIN}}}"), f"programs: entry 1: file '{LONG}' is not a file name"),
        (programs(f"{{file: hello, sha256: {PIN.upper()}}}"), "programs: entry 1: sha256 must be"),
        (programs(f"{{file: hello, sha256: {PIN[:63]}}}"), "programs: entry 1: sha256 must be"),
        (programs(f"{{file: hello, sha256: {PIN}, link_map: maps/hello.map}}"),
         "programs: entry 1: link_map 'maps/hello.map' is not a file name"),
        (programs(f"{{file: hello, sha256: {PIN}, link_map: hello}}"),
         "programs: entry 1: link_map 'hello' is also the file of a program"),
        (programs(f"{{file: hello, sha256: {PIN}, link_map: server}}", f"{{file: server, sha256: {PIN}}}"),
         "programs: entry 1: link_map 'server' is also the file of a program"),
        (programs(f"{{file: hello, sha256: {PIN}}}", f"{{file: hello, sha256: {PIN}}}"),
         "programs names the file 'hello' twice"),
        (programs(f"{{file: hello, sha256: {PIN}, link_map: out.map}}",
                  f"{{file: server, sha256: {PIN}, link_map: out.map}}"),
         "programs names the link map 'out.map' twice"),
    ], ids=["not a list", "an empty list", "an entry that is not a mapping", "an unknown key", "no file", "no sha256",
            "a file with a slash", "a file that starts with a dot", "a file of 101 characters",
            "a sha256 in upper case", "a sha256 of 63 digits", "a link map with a slash",
            "a link map that is its own file", "a link map that is the file of another program", "one file twice",
            "two programs with one link map"])
    def test_bad_program_entries(self, text, fragment):
        self.refused(text, fragment)

    def test_a_file_that_aliases_make_a_large_list(self):
        """A value of file that is not a string is named by its type. Its repr would hold each string of the list: for
        6 levels, 4,782,969 strings in 25 MB, from a project.yaml of 500 bytes."""
        start = time.monotonic()
        problems, _, summary = check(programs(f"{{file: {nested_list(6)}, sha256: {PIN}}}"))
        assert time.monotonic() - start < 10
        assert sum(len(problem) for problem in problems) < 2000
        assert summary is None
        assert any(problem.startswith("programs: ") and "(it is a list)" in problem for problem in problems), problems

    def test_an_entry_that_aliases_repeat_is_checked_once(self):
        """The keys and values of one entry object are checked at its first place alone. Its file and link map still
        count at each place, so that the names given twice are found."""
        unknown = ", ".join(f"k{number}: 1" for number in range(200))
        text = (MINIMAL + f"programs:\n  - &entry {{file: hello, sha256: {PIN}, link_map: hello.map, {unknown}}}\n"
                + "  - *entry\n" * 199)
        problems, _, summary = check(text)
        assert len(problems) < 1000
        assert summary is None
        for number in range(200):
            assert sum(f"unknown field 'k{number}'" in problem for problem in problems) == 1, number
        assert "programs names the file 'hello' twice" in problems
        assert "programs names the link map 'hello.map' twice" in problems

    def test_a_long_string_that_aliases_repeat_is_cut(self):
        """A problem quotes at most the first 200 characters of a string. Through aliases, the entries of a small
        project.yaml can each name one long string: here 1,000 entries, with a file name of 20,000 characters."""
        text = (MINIMAL + f"programs:\n  - {{file: &long {'x' * 20000}, sha256: &pin {PIN}}}\n"
                + "  - {file: *long, sha256: *pin, *long : 1}\n" * 999)
        problems, _, summary = check(text)
        cut = f"'{'x' * 200}'..."
        assert max(len(problem) for problem in problems) < 500
        assert summary is None
        for number in (1, 1000):
            assert any(problem.startswith(f"programs: entry {number}: file {cut} is not a file name")
                       for problem in problems), number
        assert any(problem.startswith(f"programs: entry 1000: unknown field {cut} (allowed: ") for problem in problems)
        assert f"programs names the file {cut} twice" in problems


class TestProblems:
    def expect_problem(self, text, fragment, files=None, name="example"):
        problems, _, summary = check(text, files, name)
        assert summary is None
        assert any(fragment in problem for problem in problems), f"{fragment!r} not in {problems}"

    def test_keys(self):
        self.expect_problem(MINIMAL + "threat_model: x.md\n", "unknown field 'threat_model'")
        self.expect_problem("repo: https://github.com/a/b\nlanguage: c\n", "missing primary_contact")
        self.expect_problem("repo: https://github.com/a/b\nprimary_contact: a@b.cd\n", "missing language")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(validate, "OPERATOR_KEYS", ("budget_usd",))
            self.expect_problem(MINIMAL + "budget_usd: 5\n", "set by the operators")

    def test_types(self):
        self.expect_problem(MINIMAL + "disabled: yes please\n", "disabled must be true or false")
        self.expect_problem(MINIMAL.replace("language: c", "language: [c]"), "language must be a string")
        self.expect_problem(MINIMAL + "budgets: 16GiB\n", "budgets must be a mapping")
        self.expect_problem(MINIMAL + "proofs: [a]\n", "proofs must be a mapping")
        self.expect_problem("- a\n- b\n", "not a mapping")

    def test_urls(self):
        for repo in ("http://github.com/a/b", "[https://github.com/a/b]", "https://", "git@github.com:a/b",
                     "https://github.com/a/b#bad ref", "https://github.com/a/b#x#y"):
            self.expect_problem(MINIMAL.replace("https://github.com/example/project#v1.0", repo), "repo must be")
        self.expect_problem(MINIMAL + "homepage: ftp://example.org\n", "homepage must be")

    def test_addresses(self):
        self.expect_problem(MINIMAL.replace(CONTACT, "nobody"), "bad email")
        self.expect_problem(MINIMAL + "auto_ccs: a@b.cd\n", "auto_ccs must be a list")
        self.expect_problem(MINIMAL + "auto_ccs: [a@b.cd, nope]\n", "bad email 'nope'")

    def test_pgp(self):
        key = KEY.replace("\n", "\n  ")
        self.expect_problem(MINIMAL + f"auto_ccs: [a@b.cd]\npgp: |\n  {key}\n", "pgp and auto_ccs")
        self.expect_problem(MINIMAL + "pgp: '0xDEADBEEF'\n", "pgp must be one armored public key")
        private = key.replace("PUBLIC KEY BLOCK-----\n  mQ", "PUBLIC KEY BLOCK-----\n  PRIVATE KEY mQ")
        self.expect_problem(MINIMAL + f"pgp: |\n  {private}\n", "pgp must be one armored public key")

    def test_build_fields(self):
        self.expect_problem(MINIMAL.replace("language: c", "language: swift"), "language must be one of")
        self.expect_problem(MINIMAL + "sanitizers: address\n", "sanitizers must be a list")
        self.expect_problem(MINIMAL + "sanitizers: [memory]\n", "'memory' is not one of")
        self.expect_problem(MINIMAL + "sanitizers: [address, address]\n", "names a sanitizer twice")
        self.expect_problem(MINIMAL + "fuzz_targets: []\n", "non-empty list")
        self.expect_problem(MINIMAL + "fuzz_targets: [a, a]\n", "names a fuzz target twice")
        self.expect_problem(MINIMAL + "fuzz_targets: ['../x']\n", "is not a fuzz target name")
        self.expect_problem(MINIMAL + "publish: sometimes\n", "publish must be one of")

    @pytest.mark.parametrize("field", ["fuzz_targets", "sanitizers", "auto_ccs", "ubsan_checks.add",
                                       "ubsan_checks.remove", "language", "publish", "primary_contact"])
    def test_a_long_bad_value_gives_short_problems(self, field):
        """A problem quotes at most the first 200 characters of a value, and check_config gives each distinct problem
        once. Through YAML aliases, a list of 32 KB of project.yaml can hold one string of 20,000 characters 2,000
        times: the problems of each item were 40 MB in all."""
        bad = "x" * 20000
        items = f"[&bad {bad}" + ", *bad" * 1999 + "]"
        if field.startswith("ubsan_checks."):
            text = MINIMAL + f"ubsan_checks: {{{field.split('.')[1]}: {items}, reason: x}}\n"
        elif field in ("language", "primary_contact"):
            text = re.sub(rf"^{field}: .*$", f"{field}: {bad}", MINIMAL, flags=re.M)
        elif field == "publish":
            text = MINIMAL + f"publish: {bad}\n"
        else:
            text = MINIMAL + f"{field}: {items}\n"
        problems, _, summary = check(text)
        assert summary is None
        assert sum(len(problem) for problem in problems) < 2000
        assert any(f"'{'x' * 200}'..." in problem for problem in problems), problems

    @pytest.mark.parametrize("key", ["add", "remove"])
    def test_a_ubsan_item_that_aliases_make_a_large_list(self, key):
        """An item of ubsan_checks.add or remove that is not a string is refused by its type, and validate never turns
        it into text. Through aliases, the item here, 257 bytes of YAML, holds 531,441 strings, 2.8 MB as text, and
        each level of about 56 bytes more is 9 times as much: str() of such items made oss-verify validate take 2.3 s
        and 192 MiB for a project.yaml of 600 bytes."""
        text = MINIMAL + f"ubsan_checks: {{{key}: [{nested_list(5)}], reason: x}}\n"
        tracemalloc.start()
        try:
            problems, _, summary = check(text)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert summary is None
        assert f"ubsan_checks.{key} must be a list of UBSan check names" in problems, problems
        assert peak < 2**20, f"validate allocated {peak:,} bytes at the peak for {len(text)} bytes of project.yaml"

    def test_budgets(self):
        self.expect_problem(MINIMAL + "budgets: {oom: 1GiB}\n", "unknown field 'oom'")
        self.expect_problem(MINIMAL + "budgets: {halts: 16GB}\n", "budgets.halts must be a size")
        self.expect_problem(MINIMAL + "budgets: {agrees: [1]}\n", "budgets.agrees must be a mapping")
        self.expect_problem(MINIMAL + "budgets: {agrees: {memory: [1, 2]}}\n", "'memory' is not one of")
        self.expect_problem(MINIMAL + "budgets: {agrees: {address: [2GiB]}}\n", "must be two sizes")
        self.expect_problem(
            MINIMAL + "sanitizers: [undefined]\nbudgets: {agrees: {address: [2GiB, 512GiB]}}\n",
            "is not one of this project's sanitizers",
        )

    def test_budgets_with_a_null_sanitizers_field(self):
        # An empty or null sanitizers: is the default, address and undefined, so their agrees budgets are allowed.
        for empty in ("sanitizers:\n", "sanitizers: null\n", "sanitizers: ~\n"):
            text = MINIMAL + empty + "budgets: {agrees: {address: [2GiB, 512GiB], undefined: [16GiB, 512GiB]}}\n"
            assert check(text)[0] == [], empty

    def test_budget_floor_and_order(self):
        self.expect_problem(MINIMAL + "budgets: {agrees: {undefined: [4095, 5TiB]}}\n", "at least 4096 bytes")
        self.expect_problem(MINIMAL + "budgets: {agrees: {undefined: [5TiB, 2GiB]}}\n", "at least the plain side")
        for ok in ("[4096, 4096]", "[2GiB, 5TiB]", "[16GiB, 512GiB]"):
            assert check(MINIMAL + "budgets: {agrees: {undefined: %s}}\n" % ok)[0] == [], ok

    def test_only_the_default_halts_budget(self):
        for bad in ("8GiB", "32GiB", "17179869185"):
            self.expect_problem(MINIMAL + "budgets: {halts: %s}\n" % bad, "only 16GiB is supported")
        for ok in ("16GiB", "16384MiB", str(16 << 30)):
            assert check(MINIMAL + "budgets: {halts: %s}\n" % ok)[0] == [], ok

    def test_proofs(self):
        self.expect_problem(MINIMAL + "proofs: {branch: x}\n", "unknown field 'branch'")
        self.expect_problem(MINIMAL + "proofs: {repo: 'git://x/y'}\n", "proofs.repo must be")
        self.expect_problem(MINIMAL + "proofs: {path: ../escape}\n", "proofs.path must be")

    def test_dockerfile_placement(self):
        self.expect_problem(MINIMAL, "a Dockerfile is required", {})
        self.expect_problem(MINIMAL + "dockerfile: Dockerfile\n", "one place only")
        self.expect_problem(MINIMAL + "dockerfile: /abs/Dockerfile\n", "relative path inside your repository", {})
        self.expect_problem(MINIMAL + "dockerfile: .oss-verify/Dockerfile\n", "build.sh belongs there",
                            {"build.sh": "x"})
        self.expect_problem(MINIMAL + "dockerfile: d/Dockerfile\n", "x.c belongs there", {"x.c": "int x;"})
        self.expect_problem(MINIMAL + "patch_style: style.md\n", "one place only",
                            {"Dockerfile": "FROM x", "build.sh": "x", "patch_style.md": "x"})

    def test_files(self):
        base = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
        self.expect_problem(MINIMAL, "only project.yaml, Dockerfile", {**base, "notes.txt": "x"})
        self.expect_problem(MINIMAL, "a file name may use only", {**base, "-x.c": "x"})
        self.expect_problem(MINIMAL, "Dockerfile is empty", {**base, "Dockerfile": " \n"})
        self.expect_problem(MINIMAL, "build.sh is empty", {**base, "build.sh": ""})
        self.expect_problem(MINIMAL, "Dockerfile names OFT_FRAME_POINTERS",
                            {**base, "Dockerfile": "FROM x\nENV OFT_FRAME_POINTERS=1\n"})
        self.expect_problem(MINIMAL, "build.sh names OFT_FRAME_POINTERS",
                            {**base, "build.sh": "#!/bin/bash\nexport OFT_FRAME_POINTERS=1\n"})
        self.expect_problem(MINIMAL, "larger than 64 KiB", {**base, "Dockerfile": "x" * (64 * 1024 + 1)})
        self.expect_problem(MINIMAL, "larger than 256 KiB", {**base, "build.sh": "x" * (256 * 1024 + 1)})
        self.expect_problem(MINIMAL, "larger than 256 KiB", {**base, "big.c": "x" * (256 * 1024 + 1)})
        self.expect_problem(MINIMAL, "not UTF-8", {**base, "bad.c": b"\xff\xfe"})
        many = {**base, **{f"f{i}.c": "" for i in range(validate.MAX_FILES)}}
        self.expect_problem(MINIMAL, "at most 64 files", many)

    def test_patches(self):
        base = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
        patch = "--- a/x\n+++ b/x\n"
        self.expect_problem(MINIMAL, "need a series file", {**base, "a.patch": patch})
        self.expect_problem(MINIMAL, "series lists 'b.patch'",
                            {**base, "a.patch": patch, "series": "a.patch\nb.patch\n"})
        self.expect_problem(MINIMAL, "more than once", {**base, "a.patch": patch, "series": "a.patch\na.patch\n"})
        self.expect_problem(MINIMAL, "a.patch is not listed", {**base, "a.patch": patch, "series": "# none\n"})
        # lay-out-sources reads a # after a space as part of a patch name, so validate does too.
        self.expect_problem(MINIMAL, "series lists '# old.patch'",
                            {**base, "a.patch": patch, "series": "a.patch\n  # old.patch\n"})
        problems, warnings, _ = check(MINIMAL, {**base, "a.patch": "not a diff\n", "series": "a.patch\n"})
        assert problems == []
        assert any("does not look like a patch" in warning for warning in warnings)

    def test_directory(self):
        self.expect_problem(MINIMAL, "the directory name must be", name="Bad_Name")
        self.expect_problem("repo: [unclosed\n", "does not parse")
        # PyYAML raises a plain ValueError, not a YAMLError, for a date or a timestamp that does not exist.
        self.expect_problem(MINIMAL + "homepage: 2024-13-45\n", "project.yaml does not parse: ValueError")
        self.expect_problem(MINIMAL + "x: 2024-01-01T25:00:00\n", "project.yaml does not parse: ValueError")
        self.expect_problem(MINIMAL + "#" * (validate.MAX_CONFIG_BYTES + 1) + "\n", "project.yaml is larger than")

    def test_symbolic_links_and_directories(self):
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            os.symlink("/etc/passwd", directory / "harness.c")
            problems, _, _ = validate.check_project(directory)
            assert any("only regular files" in problem for problem in problems), problems
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            (directory / "sub").mkdir()
            problems, _, _ = validate.check_project(directory)
            assert any("only regular files" in problem for problem in problems), problems
        with ProjectDir({"real.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            os.symlink(directory / "real.yaml", directory / "project.yaml")
            problems, _, _ = validate.check_project(directory)
            assert any("project.yaml is one" in problem for problem in problems), problems
        with ProjectDir({"project.yaml": MINIMAL}) as directory:
            link = directory.parent / "linked"
            os.symlink(directory, link)
            problems, _, _ = validate.check_project(link)
            assert any("projects/linked is one" in problem for problem in problems), problems


# The hostile spellings of TestHostileYaml: YAML text that a small project.yaml can give at any place. The largest
# project.yaml of the test has 28,227 bytes. LONG_TEXT is a string of 20,000 characters. HUGE_INT is 4,000 hex digits:
# an integer of 16,000 bits. Python gives no integer of more than 4,300 decimal digits as text, so its repr() raises.
# UNKNOWN_KEYS is a mapping of 200 unknown keys.
LONG_TEXT = "x" * 20000
HUGE_INT = "0x" + "f" * 4000
UNKNOWN_KEYS = "{" + ", ".join(f"k{number}: 1" for number in range(200)) + "}"
# An address of 20,000 characters on a domain reserved for examples. It is valid, and it makes a warning.
LONG_ADDRESS = "x" * (20000 - len("@example.com")) + "@example.com"


def repeated(text):
    """A YAML flow list of `text` and 2,000 aliases of it."""
    return f"[&e {text}" + ", *e" * 2000 + "]"


def flow(*entries):
    """A YAML flow mapping of these entries. Each entry is two YAML texts: a key and a value."""
    return "{" + ", ".join(f"? {key} : {value}" for key, value in entries) + "}"


def with_field(field, value):
    """MINIMAL's project.yaml with `field` set to `value`, YAML text."""
    if field in validate.REQUIRED_KEYS:
        return re.sub(rf"^{field}: .*$", lambda _: f"{field}: {value}", MINIMAL, flags=re.M)
    return MINIMAL + f"{field}: {value}\n"


def in_field(field, *entries):
    """MINIMAL's project.yaml with `field` set to a flow mapping of these entries."""
    return with_field(field, flow(*entries))


# Each spelling in each form that it has: "value", the value of a field; "entry", an entry of a mapping (its key and its
# value); "addresses", the addresses of a valid auto_ccs. A list is not a mapping key (PyYAML refuses it), and a mapping
# holds a key once (the aliases of one key in it give one entry). Thus a nested alias and a repeated alias have no entry
# form. An address is a string. Thus only a long string and a repeated alias have an addresses form.
HOSTILE_SPELLINGS = {
    # 4,782,969 strings, 25 MB as text, in 303 bytes of YAML.
    "a nested alias": {"value": nested_list(6)},
    # Each {<<: *e} makes a new mapping of the 200 keys. A check of the object's id() does not join them.
    "a merge key": {"value": f"[&e {UNKNOWN_KEYS}" + ", {<<: *e}" * 99 + "]", "entry": ("<<", UNKNOWN_KEYS)},
    "an integer key": {"value": flow((HUGE_INT, "1")), "entry": (HUGE_INT, "1")},
    "a long string": {"value": LONG_TEXT, "entry": (LONG_TEXT, "1"), "addresses": f"[{LONG_ADDRESS}]"},
    "a repeated alias": {"value": repeated(LONG_TEXT), "addresses": repeated(LONG_ADDRESS)},
}
# Each place: the form of a spelling that it takes, and a function from that form to a project.yaml.
HOSTILE_PLACES = {
    **{field: ("value", functools.partial(with_field, field)) for field in validate.ALLOWED_KEYS},
    "an unknown field": ("value", functools.partial(with_field, "unknown")),
    "budgets.halts": ("value", lambda value: in_field("budgets", ("halts", value))),
    "budgets.agrees": ("value", lambda value: in_field("budgets", ("agrees", value))),
    "budgets.agrees.address": ("value", lambda value: in_field("budgets", ("agrees", flow(("address", value))))),
    "proofs.repo": ("value", lambda value: in_field("proofs", ("repo", value))),
    "proofs.path": ("value", lambda value: in_field("proofs", ("path", value))),
    "ubsan_checks.add": ("value", lambda value: in_field("ubsan_checks", ("add", value), ("reason", "x"))),
    "ubsan_checks.remove": ("value", lambda value: in_field("ubsan_checks", ("remove", value), ("reason", "x"))),
    "ubsan_checks.reason": ("value", lambda value: in_field("ubsan_checks", ("add", "[alignment]"), ("reason", value))),
    "an entry of programs": ("value", programs),
    "the file of a program": ("value", lambda value: programs(flow(("file", value), ("sha256", PIN)))),
    "the sha256 of a program": ("value", lambda value: programs(flow(("file", "hello"), ("sha256", value)))),
    "the link_map of a program": (
        "value", lambda value: programs(flow(("file", "hello"), ("sha256", PIN), ("link_map", value)))),
    "a key of the top level": ("entry", lambda entry: MINIMAL + "? {}\n: {}\n".format(*entry)),
    "a key of budgets": ("entry", lambda entry: in_field("budgets", entry)),
    "a key of budgets.agrees": ("entry", lambda entry: in_field("budgets", ("agrees", flow(entry)))),
    "a key of proofs": ("entry", lambda entry: in_field("proofs", entry)),
    "a key of ubsan_checks": ("entry", lambda entry: in_field("ubsan_checks", ("add", "[alignment]"), ("reason", "x"),
                                                               entry)),
    "a key of a program": ("entry", lambda entry: programs(flow(("file", "hello"), ("sha256", PIN), entry))),
    # A project.yaml that is valid otherwise: it has no problem, and its addresses make warnings.
    "auto_ccs of a valid project": ("addresses", functools.partial(with_field, "auto_ccs")),
}
HOSTILE_CASES = [(spelling, place) for spelling, forms in HOSTILE_SPELLINGS.items()
                 for place, (form, _) in HOSTILE_PLACES.items() if form in forms]


class TestHostileYaml:
    """Any YAML spelling at any field of project.yaml gives bounded work and output. Through aliases and merge keys, a
    small project.yaml can give a large value, or one value at many places. A mapping key can be an integer whose repr()
    raises. For each spelling at each place, validate raises no exception. It gives at most 101 problems and at most
    101 warnings: 100, then one line that says that more are not shown. Each line has at most 1,000 characters, and all
    the lines together have at most 101,000. validate takes at most 2.25 MiB at the peak."""

    MAX_LINES = 101
    # A line that quotes 200 characters of a value has fewer than 500.
    MAX_LINE = 1000
    MAX_CHARACTERS = MAX_LINES * MAX_LINE
    # Measured with Python 3.12 and PyYAML 6.0.3: yaml.safe_load of these project.yaml files alone takes at most
    # 1.11 MiB at the peak (a merge key as a value: 99 new mappings of 200 keys), and at most 0.26 MiB for each other
    # spelling. The bound is about twice the most.
    MAX_PEAK = int(2.25 * 2**20)

    @pytest.mark.parametrize("spelling, place", HOSTILE_CASES,
                             ids=[f"{spelling} at {place}" for spelling, place in HOSTILE_CASES])
    def test_any_spelling_at_any_place_is_bounded(self, spelling, place):
        form, build = HOSTILE_PLACES[place]
        text = build(HOSTILE_SPELLINGS[spelling][form])
        tracemalloc.start()
        try:
            problems, warnings, _ = check(text)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        if form == "addresses":
            # validate gives warnings only for a valid project.yaml. With a problem, this row would not test them.
            assert problems == [], problems
        assert len(problems) <= self.MAX_LINES, f"{len(problems):,} problems"
        assert len(warnings) <= self.MAX_LINES, f"{len(warnings):,} warnings"
        longest = max((len(line) for line in problems + warnings), default=0)
        assert longest <= self.MAX_LINE, f"a line of {longest:,} characters"
        characters = sum(len(line) for line in problems + warnings)
        assert characters <= self.MAX_CHARACTERS, f"{characters:,} characters of problems and warnings"
        assert peak <= self.MAX_PEAK, f"validate allocated {peak:,} bytes at the peak for {len(text):,} bytes of YAML"


class TestOutput:
    def test_printable(self):
        assert validate.printable("a\x1b[31mb\n\x07") == "a\\x1b[31mb\\x0a\\x07"

    def test_help_names_each_field(self):
        """`oss-verify validate --help`, run as a command, prints the module's docstring, which lists the fields of
        project.yaml, one line for each."""
        done = subprocess.run([sys.executable, "-P", "-m", "oss_verify", "validate", "--help"], capture_output=True,
                              text=True, env=dict(os.environ, PYTHONPATH=str(SRC)), check=False)
        assert (done.returncode, done.stderr) == (0, "")
        for key in validate.ALLOWED_KEYS:
            assert re.search(rf"\n    {key}: ", done.stdout), key

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "argv", ["validate.py", *map(str, args)])
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = validate.main()
        return code, out.getvalue(), err.getvalue()

    def test_main(self):
        with ProjectDir({"project.yaml": MINIMAL.replace(CONTACT, "n/a"),
                         "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            code, out, err = self.run_main(directory)
            assert code == 0
            assert "ok: 1 project(s)" in out
            assert "example: warning: primary_contact is n/a" in out
        with ProjectDir({"project.yaml": "repo: http://x\x1b\n"}, "bad") as directory:
            code, out, err = self.run_main(directory)
            assert code == 1
            assert "bad: " in err
            assert "\x1b" not in err

    def test_main_from_inside_the_project(self):
        """`oss-verify validate .` in projects/<name>/ checks <name>, not the empty name of "." or ".."."""
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            cwd = os.getcwd()
            try:
                os.chdir(directory)
                code, out, err = self.run_main(".")
                assert (code, err) == (0, "")
                assert "example " in out
                (directory / "sub").mkdir()
                os.chdir(directory / "sub")
                code, out, err = self.run_main("..")
                assert code == 1
                assert "example: only regular files are accepted" in err
            finally:
                os.chdir(cwd)

    def test_repository_projects_pass(self):
        """Every project in this repository passes, so a pull request starts from a clean tree."""
        code, out, err = self.run_main()
        assert code == 0, err
