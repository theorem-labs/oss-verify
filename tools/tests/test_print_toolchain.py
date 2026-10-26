# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""tools/check --print-toolchain, the image the Build workflow pulls before tools/check builds:  python3 -m pytest tools/tests

The image it prints must be the one tools/check then builds FROM. Each test runs tools/check's build with its builds
replaced, records the toolchain it builds with, and compares."""
import contextlib
import importlib.machinery
import importlib.util
import io
import pathlib
import subprocess
import sys

import pytest

TOOLS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import check_build  # noqa: E402

LOADER = importlib.machinery.SourceFileLoader("check_tool", str(TOOLS / "check"))
check_tool = importlib.util.module_from_spec(importlib.util.spec_from_loader("check_tool", LOADER))
LOADER.exec_module(check_tool)

PROJECT = "repo: https://github.com/example/project#v1.0\nprimary_contact: security@example.org\nlanguage: {}\n"
BUILD_FILES = ("Dockerfile", "build.sh")


class Stop(Exception):
    """Raised in place of the build, once tools/check has chosen its toolchain."""


def project(tmp_path, text, files=BUILD_FILES):
    directory = tmp_path / "demo"
    directory.mkdir()
    (directory / "project.yaml").write_text(text)
    for name in files:
        (directory / name).write_text("#!/bin/bash\n")
    return directory


def printed(directory, cwd=None):
    """What `tools/check --print-toolchain` prints, and its exit code, run as the workflow runs it."""
    done = subprocess.run([sys.executable, str(TOOLS / "check"), "--print-toolchain", str(directory)],
                          capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                          cwd=cwd, check=False)
    return done.returncode, done.stdout


def built_from(directory, monkeypatch):
    """The toolchain `tools/check --no-shell <directory>` builds FROM, or None if it stops before building."""
    chosen = []

    def build_all(job, commit, work, toolchain, *args, **kwargs):
        chosen.append(toolchain)
        raise Stop

    monkeypatch.setattr(check_tool, "build_all", build_all)
    monkeypatch.setattr(check_build, "resolve", lambda repo, ref: "a" * 40)
    monkeypatch.setattr(sys, "argv", ["tools/check", "--no-shell", "--dir", str(directory.parent / "work"),
                                      str(directory)])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            check_tool.main()
        except Stop:
            pass
        except SystemExit as stop:
            assert stop.code not in (0, None), "tools/check exited 0 without building"
    return chosen[0] if chosen else None


@pytest.mark.parametrize("language", ["c", "c++", "rust", "python", "go"])
def test_it_prints_the_image_tools_check_builds_from(tmp_path, monkeypatch, language):
    directory = project(tmp_path, PROJECT.format(language))
    image = built_from(directory, monkeypatch)
    assert image is not None
    assert printed(directory) == (0, image + "\n")


@pytest.mark.parametrize("text, files", [
    (PROJECT.format("jvm"), BUILD_FILES),
    (PROJECT.format("javascript"), BUILD_FILES),
    (PROJECT.format("rust"), ()),  # no Dockerfile: an enrollment problem
    (PROJECT.format("c").replace("security@example.org", "n/a"), ()),  # a seeded project with no build files yet
    (PROJECT.format("[c]") + "ubsan_checks: {}\n", BUILD_FILES),  # tools/validate.py raised on it
    ("not: [valid\n", BUILD_FILES),
])
def test_a_project_tools_check_refuses_gets_the_newest_c_toolchain_and_exit_0(tmp_path, monkeypatch, text, files):
    # tools/check stops before it builds anything, and the workflow still needs an image to pull and a zero exit, so
    # that tools/check gives its own report in the next step.
    directory = project(tmp_path, text, files)
    assert built_from(directory, monkeypatch) is None
    assert printed(directory) == (0, check_build.newest_toolchain() + "\n")


def test_standard_output_holds_only_the_image(tmp_path):
    # The workflow reads all of standard output as the image: the warnings tools/check prints go to standard error.
    directory = project(tmp_path, PROJECT.format("c").replace("security@example.org", "n/a"))
    code, out = printed(directory)
    assert code == 0
    assert out.count("\n") == 1 and "@sha256:" in out


def test_a_project_named_templates_is_read_from_projects(tmp_path, monkeypatch):
    # The workflow runs tools/check from the checkout's root, which has a templates/project.yaml of its own, and passes
    # projects/<name> to both --print-toolchain and the build. A bare `templates` would read the root's templates/.
    root = tmp_path / "checkout"
    (root / "projects").mkdir(parents=True)
    project(root / "projects", PROJECT.format("c")).rename(root / "projects" / "templates")
    project(root, PROJECT.format("rust")).rename(root / "templates")
    monkeypatch.chdir(root)
    path = pathlib.Path("projects", "templates")
    image = built_from(path, monkeypatch)
    assert image == check_build.newest_toolchain("c")
    assert printed(path, cwd=root) == (0, image + "\n")
    assert built_from(pathlib.Path("templates"), monkeypatch) == check_build.newest_toolchain("rust")
