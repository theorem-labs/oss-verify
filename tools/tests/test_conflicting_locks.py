# Copyright 2026 Arunim Shukla
# SPDX-License-Identifier: Apache-2.0
"""A --lock argument must remain a constraint when another --lock follows it."""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import pathlib
import sys
from unittest import mock

import pytest
TOOLS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import check_build
import manifest
from test_manifest import PT_LOAD, elf  # noqa: E402

LOADER = importlib.machinery.SourceFileLoader("check_conflicting_locks", str(TOOLS / "check"))
SPEC = importlib.util.spec_from_loader("check_conflicting_locks", LOADER)
CHECK = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(CHECK)
COMMIT = "a" * 40
TOOLCHAIN = "example.invalid/toolchain@sha256:" + "0" * 64
STATIC = {"text_bytes": 1, "static": True}


@pytest.fixture
def lock_check(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()
    (project / "project.yaml").write_text(
        f"repo: https://example.invalid/demo#{COMMIT}\n"
        "primary_contact: security@example.org\nlanguage: c\nsanitizers: []\n")
    (project / "Dockerfile").write_text("FROM scratch\n")
    (project / "build.sh").write_text("#!/bin/bash\n")
    produced = tmp_path / "produced"
    produced.write_bytes(b"the actual build artifact")
    expected = tmp_path / "expected"
    expected.write_bytes(b"a different expected artifact")

    def entry(path):
        return {"file": "fuzzer.plain", "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    fresh = {"fuzzer": {"plain": entry(produced)}}
    locks = {}
    for name, artifact in (("good", produced), ("bad", expected)):
        path = tmp_path / f"{name}.yaml"
        manifest.write_manifest(path, manifest.manifest(
            project="demo", repo="https://example.invalid/demo", ref=COMMIT, commit=COMMIT,
            oss_verify=None, builder={"toolchain": TOOLCHAIN}, sources={}, builds=["plain"],
            targets=["fuzzer"], entries={"fuzzer": {"plain": entry(artifact)}}, layouts={"fuzzer": {"plain": STATIC}}))
        locks[name] = path
    duplicate = tmp_path / "duplicate.yaml"
    duplicate_data = manifest.manifest(
        project="demo", repo="https://example.invalid/demo", ref=COMMIT, commit=COMMIT,
        oss_verify=None, builder={"toolchain": TOOLCHAIN}, sources={}, builds=["plain"],
        targets=["fuzzer"], entries={"fuzzer": {"plain": {**entry(produced), "file": "renamed.plain"}}},
        layouts={"fuzzer": {"plain": STATIC}})
    manifest.write_manifest(duplicate, duplicate_data)
    locks["duplicate"] = duplicate
    other = tmp_path / "other.yaml"
    manifest.write_manifest(other, manifest.manifest(
        project="demo", repo="https://example.invalid/demo", ref=COMMIT, commit=COMMIT,
        oss_verify=None, builder={"toolchain": TOOLCHAIN}, sources={}, builds=["plain"],
        targets=["other"], entries={"other": {"plain": entry(produced)}}, layouts={"other": {"plain": STATIC}}))
    locks["other"] = other

    def run(order, include_other=False):
        argv = ["tools/check", "--no-shell", "--toolchain", TOOLCHAIN, "--dir", str(tmp_path / "work")]
        for name in order:
            argv.extend(["--lock", str(locks[name])])
        argv.append(str(project))
        output = io.StringIO()
        outputs = {**fresh, **({"other": {"plain": entry(produced)}} if include_other else {})}

        def build_all(*args, **kwargs):
            for target, builds in outputs.items():
                for pin in builds.values():
                    path = tmp_path / "work" / "out" / target / pin["file"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(elf(symtab=False, sections=[(".text", 1)], segments=[PT_LOAD]))
            return "builder", "project", list(outputs), outputs

        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(CHECK, "build_all", side_effect=build_all) as build, \
                mock.patch.object(check_build, "image_id", return_value="sha256:image"), \
                mock.patch.object(check_build, "sources", return_value={}), \
                mock.patch.object(check_build, "oss_verify_state", return_value=None), \
                contextlib.redirect_stdout(output):
            try:
                code = CHECK.main()
            except SystemExit as error:
                return error.code, output.getvalue(), build.call_count
        return code, output.getvalue(), build.call_count

    return run


def test_one_matching_lock_control(lock_check):
    assert lock_check(["good"])[0] == 0


def test_one_mismatching_lock_control(lock_check):
    assert lock_check(["bad"])[0] == CHECK.DIFFERENT


def test_identical_duplicate_locks_control(lock_check):
    assert lock_check(["good", "good"])[0] == 0


def test_equal_hashes_with_different_file_names_are_allowed(lock_check):
    assert lock_check(["good", "duplicate"])[0] == 0


def test_disjoint_locks_are_both_compared(lock_check):
    assert lock_check(["good", "other"], include_other=True)[0] == 0
    assert lock_check(["good", "other"])[0] == CHECK.DIFFERENT


@pytest.mark.parametrize("order", [("bad", "good"), ("good", "bad")])
def test_conflicting_lock_cannot_be_overwritten_by_another_lock(lock_check, order):
    code, output, builds = lock_check(order)
    assert code != 0, output
    assert builds == 0, "conflicting lock constraints should fail before building"
    assert "fuzzer.plain" in str(code)
    assert "sha256" in str(code)
