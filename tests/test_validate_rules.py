# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/validate_rules/, the rules of oss-verify validate for the jobs that hold a token, and
.github/scripts/copy-validate-rules, which writes them from src/oss_verify/:  uv run pytest tests/test_validate_rules.py

One set of rules: the copy must be what copy-validate-rules writes from src/ as it is, so that a change to the rules in
src/ fails here until the copy has it too. And the copy must judge each project as `oss-verify validate` does, as the
workflows run each: python3 -P -m validate_rules.validate with PYTHONPATH naming .github/scripts, and python3 -P -m
oss_verify validate with PYTHONPATH naming src/."""
import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import sys

import pytest

from oss_verify import check_build, validate

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".github" / "scripts"
SOURCE = ROOT / "src" / "oss_verify"
LOADER = importlib.machinery.SourceFileLoader("copy_validate_rules", str(SCRIPTS / "copy-validate-rules"))
copier = importlib.util.module_from_spec(importlib.util.spec_from_loader(LOADER.name, LOADER))
LOADER.exec_module(copier)
# A project that sets ubsan_checks, which no project of projects/ or seeds/ does: its warnings read the newest
# toolchain of infra/toolchains.tsv through check_build.
UBSAN = ("repo: https://github.com/example/project#v1.0\nprimary_contact: security@example.org\nlanguage: c++\n"
         "ubsan_checks:\n  add: [unsigned-integer-overflow, vptr]\n  reason: its arithmetic wraps on purpose\n")


def copied():
    """validate_rules.validate, imported as triage.py imports it: from .github/scripts."""
    saved = list(sys.path)
    sys.path.insert(0, str(SCRIPTS))
    try:
        from validate_rules import validate as rules
    finally:
        sys.path[:] = saved
    return rules


def run(module, path, *arguments):
    """python3 -P -m `module` with PYTHONPATH `path` alone, from the top of the checkout: (status, stdout, stderr)."""
    environment = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
    done = subprocess.run([sys.executable, "-P", "-m", *module.split(), *arguments], cwd=ROOT, capture_output=True,
                          text=True, env={**environment, "PYTHONPATH": str(path)}, stdin=subprocess.DEVNULL)
    return done.returncode, done.stdout, done.stderr


def test_the_copy_is_what_copy_validate_rules_writes_from_src():
    for path, data in copier.copies().items():
        assert path.read_bytes() == data, (
            f"{path.relative_to(ROOT)} is not what .github/scripts/copy-validate-rules writes from src/oss_verify/. "
            "Run python3 -P .github/scripts/copy-validate-rules, and commit what it writes.")


def test_validate_py_is_src_byte_for_byte():
    assert (SCRIPTS / "validate_rules" / "validate.py").read_bytes() == (SOURCE / "validate.py").read_bytes()


def newest(module, language):
    """The newest toolchain for `language` that check_build `module` gives, or the message of its Failed."""
    try:
        return module.newest_toolchain(language)
    except module.Failed as error:
        return f"Failed: {error}"


def test_the_copy_reads_the_toolchains_as_src_does():
    rules = copied()
    assert pathlib.Path(rules.__file__).parent == SCRIPTS / "validate_rules"
    assert pathlib.Path(rules.check_build.__file__).parent == SCRIPTS / "validate_rules"
    assert rules.check_build.ROOT == check_build.ROOT == ROOT
    assert rules.PROJECTS == validate.PROJECTS
    assert rules.check_build.toolchains() == check_build.toolchains()
    for language in validate.LANGUAGES:
        assert newest(rules.check_build, language) == newest(check_build, language), language
    assert rules.newest_toolchain_applies_ubsan_checks() == validate.newest_toolchain_applies_ubsan_checks()


def test_the_copy_judges_each_project_as_src_does(tmp_path):
    rules = copied()
    (tmp_path / "ubsan").mkdir()
    (tmp_path / "ubsan" / "project.yaml").write_text(UBSAN)
    (tmp_path / "ubsan" / "Dockerfile").write_text("FROM base\n")
    (tmp_path / "ubsan" / "build.sh").write_text("#!/bin/bash\n")
    directories = sorted({path.parent for top in ("projects", "seeds", "tests/fixtures")
                          for path in (ROOT / top).glob("*/project.yaml")}) + [tmp_path / "ubsan"]
    assert len(directories) > 100
    for directory in directories:
        assert rules.check_project(directory) == validate.check_project(directory), directory
    problems, warnings, _ = validate.check_project(tmp_path / "ubsan")
    assert problems == [] and any(warning.startswith("ubsan_checks") for warning in warnings), warnings


def test_the_copy_runs_as_oss_verify_validate_and_loads_nothing_from_src(tmp_path):
    # With no directory, each of projects/: the copy's ROOT is the top of the checkout too.
    copy = run("validate_rules.validate", SCRIPTS)
    assert copy == run("oss_verify validate", SOURCE.parent)
    assert copy[0] == 0 and copy[1].startswith("ok: "), copy
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "project.yaml").write_text("repo: http://example.org/x\n")
    copy = run("validate_rules.validate", SCRIPTS, str(tmp_path / "bad"), "projects/bzip2")
    assert copy == run("oss_verify validate", SOURCE.parent, str(tmp_path / "bad"), "projects/bzip2")
    assert copy[0] == 1 and "bad: missing primary_contact" in copy[2], copy
    # What review-gather and triage.py run loads no module of the package oss_verify.
    code = ("import sys\nfrom validate_rules import validate\nvalidate.main(['projects/bzip2'])\n"
            "print(sorted(name for name in sys.modules if name.split('.')[0] == 'oss_verify'))")
    loaded = subprocess.run([sys.executable, "-P", "-c", code], cwd=ROOT, capture_output=True, text=True,
                            env={**os.environ, "PYTHONPATH": str(SCRIPTS)})
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.splitlines()[-1] == "[]"


def changed_source(tmp_path, monkeypatch, file, old, new):
    """Point copy-validate-rules at a copy of src/oss_verify/ whose `file` has `new` in place of `old`."""
    source = tmp_path / "oss_verify"
    source.mkdir()
    for name in ("validate.py", "check_build.py"):
        text = (SOURCE / name).read_text(encoding="utf-8")
        if name == file:
            assert text.count(old) == 1, old
            text = text.replace(old, new)
        (source / name).write_text(text, encoding="utf-8")
    monkeypatch.setattr(copier, "SOURCE", source)


@pytest.mark.parametrize("file, old, new", [
    ("validate.py", "MAX_FILES = 64\n", "MAX_FILES = 65\n"),
    ("check_build.py", 'UBSAN_MODES = ("fixed", "checks")', 'UBSAN_MODES = ("fixed", "checks", "both")'),
    ("check_build.py", "    return images[-1]\n", "    return images[0]\n"),
], ids=["a constant of validate.py", "a constant validate.py reads through toolchains()", "newest_toolchain"])
def test_control_a_change_to_the_rules_in_src_alone_fails(tmp_path, monkeypatch, file, old, new):
    changed_source(tmp_path, monkeypatch, file, old, new)
    with pytest.raises(AssertionError, match="is not what .github/scripts/copy-validate-rules writes"):
        test_the_copy_is_what_copy_validate_rules_writes_from_src()


def test_control_a_change_to_check_build_that_validate_py_does_not_use_changes_no_copy(tmp_path, monkeypatch):
    # The build steps of oss-verify check stay out of the copy, and so out of the jobs that hold a token.
    changed_source(tmp_path, monkeypatch, "check_build.py", 'IMAGES = "images"', 'IMAGES = "built-images"')
    test_the_copy_is_what_copy_validate_rules_writes_from_src()
    assert "IMAGES" not in (SCRIPTS / "validate_rules" / "check_build.py").read_text()


@pytest.mark.parametrize("file, old, new, why", [
    ("validate.py", "from . import check_build\n", "from . import check_build, manifest\n",
     "imports from the package more than its module check_build"),
    ("validate.py", "from . import check_build\n", "from oss_verify import check_build\n",
     "imports the package oss_verify by its name"),
    ("validate.py", "PROJECTS = check_build.ROOT", "build = check_build\nPROJECTS = build.ROOT",
     "uses check_build other than as check_build.<name>"),
    ("check_build.py", "ROOT = pathlib.Path(__file__).resolve().parents[2]",
     "ROOT = pathlib.Path(__file__).resolve().parent.parent.parent", "no longer sets ROOT with"),
    ("check_build.py", 'UBSAN_MODES = ("fixed", "checks")', 'UBSAN_MODES = ("fixed", "checks")\nUBSAN_MODES += ()',
     "binds UBSAN_MODES 2 times"),
    ("check_build.py", 'UBSAN_MODES = ("fixed", "checks")', 'if True:\n    UBSAN_MODES = ("fixed", "checks")',
     "binds UBSAN_MODES in a If statement"),
], ids=["another module", "the package by name", "check_build as a value", "another ROOT", "a name bound twice",
        "a name bound in an if"])
def test_control_copy_validate_rules_refuses_a_shape_it_cannot_copy(tmp_path, monkeypatch, file, old, new, why):
    changed_source(tmp_path, monkeypatch, file, old, new)
    with pytest.raises(copier.Unknown, match=why):
        copier.copies()
