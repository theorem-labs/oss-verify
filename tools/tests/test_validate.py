# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/validate.py:  python3 -m pytest tools/tests"""
import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import validate  # noqa: E402

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


class ValidProjects(unittest.TestCase):
    def test_minimal(self):
        problems, warnings, summary = check(MINIMAL)
        self.assertEqual(problems, [])
        self.assertEqual(warnings, [])
        self.assertIn("builds: plain ubsan asan asan-ubsan", summary)
        self.assertIn("fuzz targets: all", summary)

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
        self.assertEqual(problems, [])
        self.assertEqual(warnings, [])
        self.assertIn("builds: plain asan", summary)
        self.assertIn("fuzz targets: a_fuzzer, b-fuzzer.x", summary)

    def test_dockerfile_in_repository(self):
        problems, _, summary = check(MINIMAL + "dockerfile: .oss-verify/Dockerfile\n", {"patch_style.md": "x"})
        self.assertEqual(problems, [])
        self.assertIn("in the repository at .oss-verify/Dockerfile", summary)

    def test_seeded_project_warns(self):
        problems, warnings, _ = check(MINIMAL.replace(CONTACT, "n/a"))
        self.assertEqual(problems, [])
        self.assertTrue(any("primary_contact is n/a" in warning for warning in warnings))

    def test_seeded_project_without_build_files_warns(self):
        problems, warnings, summary = check(MINIMAL.replace(CONTACT, "n/a"), {})
        self.assertEqual(problems, [])
        self.assertTrue(any("no build files yet" in warning for warning in warnings))
        self.assertIn("Dockerfile: none yet", summary)

    def test_files_the_sources_file_copies_may_have_any_name(self):
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/sh\n", "list.sha256": "00  x\n",
                 "sources": "copy\ttargets/t/list.sha256\tlist.sha256\n"}
        problems, _, _ = check(MINIMAL, files)
        self.assertEqual(problems, [])
        problems, _, _ = check(MINIMAL, {**files, "sources": "# copies nothing\n"})
        self.assertTrue(any("list.sha256: only project.yaml" in problem for problem in problems), problems)

    def test_dockerfile_without_build_sh_warns(self):
        problems, warnings, _ = check(MINIMAL, {"Dockerfile": "FROM x\n"})
        self.assertEqual(problems, [])
        self.assertTrue(any("no build.sh" in warning for warning in warnings))

    def test_short_commit_warns(self):
        problems, warnings, _ = check(MINIMAL.replace("#v1.0", "#abc1234"))
        self.assertEqual(problems, [])
        self.assertTrue(any("shortened commit" in warning for warning in warnings))

    def test_placeholder_address_warns(self):
        for address in ("dry-run@example.invalid", "security@example.org", "a@mail.example.com", "x@host.test"):
            problems, warnings, _ = check(MINIMAL.replace(CONTACT, address))
            self.assertEqual(problems, [])
            self.assertTrue(any(f"{address} is a placeholder" in warning for warning in warnings), warnings)
        _, warnings, _ = check(MINIMAL + "auto_ccs: [team@example.net]\n")
        self.assertTrue(any("team@example.net is a placeholder" in warning for warning in warnings), warnings)
        # A real domain that only contains "example" is not one.
        self.assertEqual(check(MINIMAL.replace(CONTACT, "security@myexample.org"))[1], [])


class Builds(unittest.TestCase):
    def test_builds_follow_sanitizers(self):
        self.assertEqual(validate.builds_of({}), ["plain", "ubsan", "asan", "asan-ubsan"])
        self.assertEqual(validate.builds_of({"sanitizers": ["undefined", "address"]}), ["plain", "ubsan", "asan", "asan-ubsan"])
        self.assertEqual(validate.builds_of({"sanitizers": ["address"]}), ["plain", "asan"])
        self.assertEqual(validate.builds_of({"sanitizers": ["undefined"]}), ["plain", "ubsan"])
        self.assertEqual(validate.builds_of({"sanitizers": []}), ["plain"])

    def test_sizes(self):
        self.assertEqual(validate.size_in_bytes("16GiB"), 16 << 30)
        self.assertEqual(validate.size_in_bytes("512GiB"), 512 << 30)
        self.assertEqual(validate.size_in_bytes(1024), 1024)
        for bad in ("0", "16GB", "-1", "1.5GiB", True, 0, None, "", "16 GiB"):
            self.assertIsNone(validate.size_in_bytes(bad), bad)


class Languages(unittest.TestCase):
    def test_oss_fuzz_names(self):
        for language in ("c", "c++", "rust", "python", "go", "jvm", "javascript"):
            problems, _, _ = check(MINIMAL.replace("language: c", f"language: {language}"))
            self.assertEqual(problems, [], language)
        for language in ("ruby", "lua", "swift", "C", "java"):
            problems, _, _ = check(MINIMAL.replace("language: c", f"language: {language}"))
            self.assertTrue(any("language must be one of" in problem for problem in problems), language)

    def test_the_languages_built_today(self):
        self.assertEqual(check(MINIMAL)[1], [])
        self.assertEqual(check(MINIMAL.replace("language: c", "language: rust"))[1], [])
        self.assertEqual(check(MINIMAL.replace("language: c", "language: python"))[1], [])
        _, warnings, _ = check(MINIMAL.replace("language: c", "language: javascript"))
        self.assertTrue(any("the builder cannot build it yet" in warning for warning in warnings), warnings)
        # A language is built today if, and only if, a toolchain in infra/toolchains.tsv builds it.
        listed = {language for _, _, _, languages in validate.check_build.toolchains() for language in languages}
        self.assertEqual(set(validate.BUILT_TODAY), listed)

    def test_ubsan_checks_are_for_c_and_cxx(self):
        changes = "ubsan_checks: {remove: [shift], reason: shifts of negative values are intended}\n"
        problems, _, _ = check(MINIMAL.replace("language: c", "language: rust") + changes)
        self.assertTrue(any("applies only to C, C++ and Python" in problem for problem in problems), problems)
        for language in ("c", "python"):
            problems, _, _ = check(MINIMAL.replace("language: c", f"language: {language}") + changes)
            self.assertFalse(any("applies only to" in problem for problem in problems), problems)

    def test_go_and_jvm_have_the_plain_build_only(self):
        for language in ("go", "jvm"):
            text = MINIMAL.replace("language: c", f"language: {language}")
            self.assertIn("builds: plain;", check(text)[2])
            self.assertIn("builds: plain;", check(text + "sanitizers: []\n")[2])
            problems, _, _ = check(text + "sanitizers: [address]\n")
            self.assertTrue(any("plain build only" in problem for problem in problems), problems)
        self.assertEqual(validate.builds_of({"language": "go"}), ["plain"])
        self.assertEqual(validate.builds_of({"language": "rust"}), ["plain", "ubsan", "asan", "asan-ubsan"])

    def test_harness_suffixes_follow_the_language(self):
        files = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n", "fuzz_parse.rs": "fn main() {}\n",
                 "shim.c": "int x;\n"}
        self.assertEqual(check(MINIMAL.replace("language: c", "language: rust"), files)[0], [])
        problems, _, _ = check(MINIMAL, files)
        self.assertTrue(any(problem.startswith("fuzz_parse.rs: only") for problem in problems), problems)
        self.assertEqual(validate.limit_for("fuzz.py", validate.source_suffixes({"language": "python"})),
                         validate.MAX_SOURCE_BYTES)
        self.assertEqual(validate.limit_for("fuzz.py", validate.source_suffixes({"language": "c"})),
                         validate.MAX_FILE_BYTES)


def corpus(inputs):
    """A seed corpus: a zip file of these {name: bytes} inputs."""
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in inputs.items():
            archive.writestr(name, content)
    return data.getvalue()


class SeedCorpora(unittest.TestCase):
    BUILD = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}

    def problems(self, data, text=MINIMAL, name="a_fuzzer_seed_corpus.zip", files=None):
        return check(text, {**(self.BUILD if files is None else files), name: data})[0]

    def test_a_seed_corpus(self):
        self.assertEqual(self.problems(corpus({"empty": b"", "one": b"\x01\x02"})), [])
        self.assertEqual(self.problems(corpus({"x": b"1"}), MINIMAL + "fuzz_targets: [a_fuzzer]\n"), [])
        # It may stay beside project.yaml when the repository holds the build files.
        in_repo = MINIMAL + "dockerfile: .oss-verify/Dockerfile\n"
        self.assertEqual(self.problems(corpus({"x": b"1"}), in_repo, files={}), [])

    def test_bad_seed_corpora(self):
        def has(fragment, problems):
            self.assertTrue(any(fragment in problem for problem in problems), f"{fragment!r} not in {problems}")
        has("is not a zip file", self.problems(b"not a zip"))
        has("holds no input", self.problems(corpus({})))
        has("is not a file at the top level", self.problems(corpus({"dir/x": b"1"})))
        has("is not a file at the top level", self.problems(corpus({"../x": b"1"})))
        has("which fuzz_targets does not list", self.problems(corpus({"x": b"1"}), MINIMAL + "fuzz_targets: [b]\n"))
        with mock.patch.object(validate, "MAX_CORPUS_INPUTS", 2):
            has("more than 2 inputs", self.problems(corpus({"x": b"1", "y": b"2", "z": b"3"})))
        with mock.patch.object(validate, "MAX_CORPUS_EXPANDED", 1 << 20):
            has("expands to more than 1 MiB", self.problems(corpus({"zeros": bytes(2 << 20)})))
        with mock.patch.object(validate, "MAX_CORPUS_BYTES", 10):
            has("is larger than 0 KiB", self.problems(corpus({"x": b"1"})))
        # Any other zip file name is refused.
        has("only project.yaml", self.problems(corpus({"x": b"1"}), name="inputs.zip"))


class UbsanChecks(unittest.TestCase):
    """ubsan_checks, in its provisional format: changes to the default, with the reason."""

    def has(self, fragment, texts):
        self.assertTrue(any(fragment in text for text in texts), f"{fragment!r} not in {texts}")

    def test_changes_with_a_reason(self):
        added = "ubsan_checks:\n  add: [alignment]\n  reason: the decoder must not read packed structures misaligned\n"
        problems, warnings, _ = check(MINIMAL + added)
        self.assertEqual(problems, [])
        self.has("has no effect yet", warnings)
        cxx = MINIMAL.replace("language: c", "language: c++")
        removed = "ubsan_checks: {remove: [function], reason: callbacks are called through a void pointer type}\n"
        self.assertEqual(check(cxx + removed)[0], [])
        default = validate.DEFAULT_UBSAN_CHECKS
        self.assertEqual(validate.ubsan_checks_in_effect(yaml_of(MINIMAL + added)), [*default["c"], "alignment"])
        self.assertEqual(validate.ubsan_checks_in_effect(yaml_of(cxx + removed)),
                         [check for check in default["c++"] if check != "function"])
        self.assertEqual(validate.ubsan_checks_in_effect(yaml_of(MINIMAL)), default["c"])
        self.assertEqual(validate.ubsan_checks_in_effect(yaml_of(cxx)), default["c++"])
        # A c project's default has no function to remove.
        self.has("function is not in the default", check(MINIMAL + removed)[1])

    def test_the_defaults(self):
        """OSS-Fuzz's -fno-sanitize-recover list, less vptr (trap mode cannot make it); C and Python drop function,
        as OSS-Fuzz drops it from C compiles and from a Python project's native code."""
        default = validate.DEFAULT_UBSAN_CHECKS
        self.assertEqual(len(default["c++"]), 17)
        self.assertEqual(default["c++"][-3:], ["vptr", "libcxx-hardening", "strict-flex-arrays"])
        self.assertEqual(default["c"], [check for check in default["c++"]
                                        if check not in ("function", "vptr", "libcxx-hardening")])
        # strict-flex-arrays is about C as much as C++: every default has it.
        for checks in default.values():
            self.assertIn("strict-flex-arrays", checks)
        self.assertEqual(default["python"], default["c"])
        self.assertEqual(set(validate.TRAP_EXCEPTIONS), {"vptr"})
        for checks in default.values():
            self.assertNotIn("unsigned-integer-overflow", checks)

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
        self.assertNotEqual(cxx, MINIMAL)
        out = cxx + "ubsan_checks: {remove: [vptr, libcxx-hardening], reason: the library is built without RTTI}\n"
        self.assertEqual(check(out)[0], [])
        self.assertEqual(validate.ubsan_checks_in_effect(yaml_of(out)),
                         [c for c in validate.DEFAULT_UBSAN_CHECKS["c++"] if c not in ("vptr", "libcxx-hardening")])

    def test_a_project_opts_out_of_strict_flex_arrays(self):
        out = MINIMAL + ("ubsan_checks: {remove: [strict-flex-arrays], reason: 'the packet header is read past its "
                         "trailing options[4], into the room allocated for it'}\n")
        problems, warnings, _ = check(out)
        self.assertEqual(problems, [])
        self.assertFalse(any("strict-flex-arrays" in warning for warning in warnings), warnings)
        self.assertEqual(validate.ubsan_checks_in_effect(yaml_of(out)),
                         [c for c in validate.DEFAULT_UBSAN_CHECKS["c"] if c != "strict-flex-arrays"])
        # Without array-bounds it changes nothing, which is worth a warning, not a refusal.
        alone = MINIMAL + "ubsan_checks: {remove: [array-bounds], reason: x}\n"
        self.assertEqual(check(alone)[0], [])
        self.has("strict-flex-arrays does nothing without array-bounds", check(alone)[1])

    def test_warnings(self):
        warnings = check(MINIMAL + "ubsan_checks: {add: [vptr, enum], remove: [alignment], reason: x}\n")[1]
        self.has("vptr: only the ubsan build makes it, through the toolchain's trap-only handler", warnings)
        self.has("enum is in the default already", warnings)
        self.has("alignment is not in the default", warnings)
        with mock.patch.object(validate, "newest_toolchain_applies_ubsan_checks", return_value=True):
            warnings = check(MINIMAL + "ubsan_checks: {add: [alignment], reason: x}\n")[1]
        self.assertFalse(any("has no effect yet" in warning for warning in warnings), warnings)

    def test_a_bare_null_is_the_check_null(self):
        self.assertEqual(validate.ubsan_changes_of({"ubsan_checks": {"remove": [None]}}), {"remove": ["null"]})
        self.assertIsNone(validate.ubsan_changes_of({}))


def yaml_of(text):
    return validate.yaml.safe_load(text)


class Problems(unittest.TestCase):
    def assertProblem(self, text, fragment, files=None, name="example"):
        problems, _, summary = check(text, files, name)
        self.assertIsNone(summary)
        self.assertTrue(any(fragment in problem for problem in problems), f"{fragment!r} not in {problems}")

    def test_keys(self):
        self.assertProblem(MINIMAL + "threat_model: x.md\n", "unknown field 'threat_model'")
        self.assertProblem("repo: https://github.com/a/b\nlanguage: c\n", "missing primary_contact")
        self.assertProblem("repo: https://github.com/a/b\nprimary_contact: a@b.cd\n", "missing language")
        with mock.patch.object(validate, "OPERATOR_KEYS", ("budget_usd",)):
            self.assertProblem(MINIMAL + "budget_usd: 5\n", "set by the operators")

    def test_types(self):
        self.assertProblem(MINIMAL + "disabled: yes please\n", "disabled must be true or false")
        self.assertProblem(MINIMAL.replace("language: c", "language: [c]"), "language must be a string")
        self.assertProblem(MINIMAL + "budgets: 16GiB\n", "budgets must be a mapping")
        self.assertProblem(MINIMAL + "proofs: [a]\n", "proofs must be a mapping")
        self.assertProblem("- a\n- b\n", "not a mapping")

    def test_urls(self):
        for repo in ("http://github.com/a/b", "[https://github.com/a/b]", "https://", "git@github.com:a/b",
                     "https://github.com/a/b#bad ref", "https://github.com/a/b#x#y"):
            self.assertProblem(MINIMAL.replace("https://github.com/example/project#v1.0", repo), "repo must be")
        self.assertProblem(MINIMAL + "homepage: ftp://example.org\n", "homepage must be")

    def test_addresses(self):
        self.assertProblem(MINIMAL.replace(CONTACT, "nobody"), "bad email")
        self.assertProblem(MINIMAL + "auto_ccs: a@b.cd\n", "auto_ccs must be a list")
        self.assertProblem(MINIMAL + "auto_ccs: [a@b.cd, nope]\n", "bad email 'nope'")

    def test_pgp(self):
        key = KEY.replace("\n", "\n  ")
        self.assertProblem(MINIMAL + f"auto_ccs: [a@b.cd]\npgp: |\n  {key}\n", "pgp and auto_ccs")
        self.assertProblem(MINIMAL + "pgp: '0xDEADBEEF'\n", "pgp must be one armored public key")
        private = key.replace("PUBLIC KEY BLOCK-----\n  mQ", "PUBLIC KEY BLOCK-----\n  PRIVATE KEY mQ")
        self.assertProblem(MINIMAL + f"pgp: |\n  {private}\n", "pgp must be one armored public key")

    def test_build_fields(self):
        self.assertProblem(MINIMAL.replace("language: c", "language: swift"), "language must be one of")
        self.assertProblem(MINIMAL + "sanitizers: address\n", "sanitizers must be a list")
        self.assertProblem(MINIMAL + "sanitizers: [memory]\n", "'memory' is not one of")
        self.assertProblem(MINIMAL + "sanitizers: [address, address]\n", "names a sanitizer twice")
        self.assertProblem(MINIMAL + "fuzz_targets: []\n", "non-empty list")
        self.assertProblem(MINIMAL + "fuzz_targets: [a, a]\n", "names a fuzz target twice")
        self.assertProblem(MINIMAL + "fuzz_targets: ['../x']\n", "is not a fuzz target name")
        self.assertProblem(MINIMAL + "publish: sometimes\n", "publish must be one of")

    def test_budgets(self):
        self.assertProblem(MINIMAL + "budgets: {oom: 1GiB}\n", "unknown field 'oom'")
        self.assertProblem(MINIMAL + "budgets: {halts: 16GB}\n", "budgets.halts must be a size")
        self.assertProblem(MINIMAL + "budgets: {agrees: [1]}\n", "budgets.agrees must be a mapping")
        self.assertProblem(MINIMAL + "budgets: {agrees: {memory: [1, 2]}}\n", "'memory' is not one of")
        self.assertProblem(MINIMAL + "budgets: {agrees: {address: [2GiB]}}\n", "must be two sizes")
        self.assertProblem(
            MINIMAL + "sanitizers: [undefined]\nbudgets: {agrees: {address: [2GiB, 512GiB]}}\n",
            "is not one of this project's sanitizers",
        )

    def test_budget_floor_and_order(self):
        self.assertProblem(MINIMAL + "budgets: {agrees: {undefined: [4095, 5TiB]}}\n", "at least 4096 bytes")
        self.assertProblem(MINIMAL + "budgets: {agrees: {undefined: [5TiB, 2GiB]}}\n", "at least the plain side")
        for ok in ("[4096, 4096]", "[2GiB, 5TiB]", "[16GiB, 512GiB]"):
            self.assertEqual(check(MINIMAL + "budgets: {agrees: {undefined: %s}}\n" % ok)[0], [], ok)

    def test_only_the_default_halts_budget(self):
        for bad in ("8GiB", "32GiB", "17179869185"):
            self.assertProblem(MINIMAL + "budgets: {halts: %s}\n" % bad, "only 16GiB is supported")
        for ok in ("16GiB", "16384MiB", str(16 << 30)):
            self.assertEqual(check(MINIMAL + "budgets: {halts: %s}\n" % ok)[0], [], ok)

    def test_proofs(self):
        self.assertProblem(MINIMAL + "proofs: {branch: x}\n", "unknown field 'branch'")
        self.assertProblem(MINIMAL + "proofs: {repo: 'git://x/y'}\n", "proofs.repo must be")
        self.assertProblem(MINIMAL + "proofs: {path: ../escape}\n", "proofs.path must be")

    def test_dockerfile_placement(self):
        self.assertProblem(MINIMAL, "a Dockerfile is required", {})
        self.assertProblem(MINIMAL + "dockerfile: Dockerfile\n", "one place only")
        self.assertProblem(MINIMAL + "dockerfile: /abs/Dockerfile\n", "relative path inside your repository", {})
        self.assertProblem(MINIMAL + "dockerfile: .oss-verify/Dockerfile\n", "build.sh belongs there", {"build.sh": "x"})
        self.assertProblem(MINIMAL + "dockerfile: d/Dockerfile\n", "x.c belongs there", {"x.c": "int x;"})
        self.assertProblem(MINIMAL + "patch_style: style.md\n", "one place only",
                           {"Dockerfile": "FROM x", "build.sh": "x", "patch_style.md": "x"})

    def test_files(self):
        base = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
        self.assertProblem(MINIMAL, "only project.yaml, Dockerfile", {**base, "notes.txt": "x"})
        self.assertProblem(MINIMAL, "a file name may use only", {**base, "-x.c": "x"})
        self.assertProblem(MINIMAL, "Dockerfile is empty", {**base, "Dockerfile": " \n"})
        self.assertProblem(MINIMAL, "build.sh is empty", {**base, "build.sh": ""})
        self.assertProblem(MINIMAL, "larger than 64 KiB", {**base, "Dockerfile": "x" * (64 * 1024 + 1)})
        self.assertProblem(MINIMAL, "larger than 256 KiB", {**base, "build.sh": "x" * (256 * 1024 + 1)})
        self.assertProblem(MINIMAL, "larger than 256 KiB", {**base, "big.c": "x" * (256 * 1024 + 1)})
        self.assertProblem(MINIMAL, "not UTF-8", {**base, "bad.c": b"\xff\xfe"})
        many = {**base, **{f"f{i}.c": "" for i in range(validate.MAX_FILES)}}
        self.assertProblem(MINIMAL, "at most 64 files", many)

    def test_patches(self):
        base = {"Dockerfile": "FROM x\n", "build.sh": "#!/bin/bash\n"}
        patch = "--- a/x\n+++ b/x\n"
        self.assertProblem(MINIMAL, "need a series file", {**base, "a.patch": patch})
        self.assertProblem(MINIMAL, "series lists 'b.patch'", {**base, "a.patch": patch, "series": "a.patch\nb.patch\n"})
        self.assertProblem(MINIMAL, "more than once", {**base, "a.patch": patch, "series": "a.patch\na.patch\n"})
        self.assertProblem(MINIMAL, "a.patch is not listed", {**base, "a.patch": patch, "series": "# none\n"})
        problems, warnings, _ = check(MINIMAL, {**base, "a.patch": "not a diff\n", "series": "a.patch\n"})
        self.assertEqual(problems, [])
        self.assertTrue(any("does not look like a patch" in warning for warning in warnings))

    def test_directory(self):
        self.assertProblem(MINIMAL, "the directory name must be", name="Bad_Name")
        self.assertProblem("repo: [unclosed\n", "does not parse")
        self.assertProblem(MINIMAL + "#" * (validate.MAX_CONFIG_BYTES + 1) + "\n", "project.yaml is larger than")

    def test_symbolic_links_and_directories(self):
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            os.symlink("/etc/passwd", directory / "harness.c")
            problems, _, _ = validate.check_project(directory)
            self.assertTrue(any("only regular files" in problem for problem in problems), problems)
        with ProjectDir({"project.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            (directory / "sub").mkdir()
            problems, _, _ = validate.check_project(directory)
            self.assertTrue(any("only regular files" in problem for problem in problems), problems)
        with ProjectDir({"real.yaml": MINIMAL, "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            os.symlink(directory / "real.yaml", directory / "project.yaml")
            problems, _, _ = validate.check_project(directory)
            self.assertTrue(any("project.yaml is one" in problem for problem in problems), problems)
        with ProjectDir({"project.yaml": MINIMAL}) as directory:
            link = directory.parent / "linked"
            os.symlink(directory, link)
            problems, _, _ = validate.check_project(link)
            self.assertTrue(any("projects/linked is one" in problem for problem in problems), problems)


class Output(unittest.TestCase):
    def test_printable(self):
        self.assertEqual(validate.printable("a\x1b[31mb\n\x07"), "a\\x1b[31mb\\x0a\\x07")

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["validate.py", *map(str, args)]):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = validate.main()
        return code, out.getvalue(), err.getvalue()

    def test_main(self):
        with ProjectDir({"project.yaml": MINIMAL.replace(CONTACT, "n/a"),
                         "Dockerfile": "FROM x", "build.sh": "x"}) as directory:
            code, out, err = self.run_main(directory)
            self.assertEqual(code, 0)
            self.assertIn("ok: 1 project(s)", out)
            self.assertIn("example: warning: primary_contact is n/a", out)
        with ProjectDir({"project.yaml": "repo: http://x\x1b\n"}, "bad") as directory:
            code, out, err = self.run_main(directory)
            self.assertEqual(code, 1)
            self.assertIn("bad: ", err)
            self.assertNotIn("\x1b", err)

    def test_repository_projects_pass(self):
        """Every project in this repository passes, so a pull request starts from a clean tree."""
        code, out, err = self.run_main()
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
