# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the patch directive of infra/base-builder/lay-out-sources, which need no Docker:  uv run pytest

A patch row applies with `git apply` under `core.symlinks=false`, so a patch cannot make a symbolic link: a link
a patch makes is written as a regular file holding the text of its target.
"""
import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
LOADER = importlib.machinery.SourceFileLoader(
    "lay_out_sources", str(TESTS.parent / "infra" / "base-builder" / "lay-out-sources"))
SPEC = importlib.util.spec_from_loader("lay_out_sources", LOADER)
lay_out_sources = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(lay_out_sources)

ONE = "int one(void) { return 1; }\n"
EDIT = "--- a/one.c\n+++ b/one.c\n@@ -1 +1 @@\n-int one(void) { return 1; }\n+int one(void) { return 2; }\n"
ADD_AND_DELETE = ("diff --git a/two.c b/two.c\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n"
                  "+++ b/two.c\n@@ -0,0 +1 @@\n+int two;\n"
                  "diff --git a/one.c b/one.c\ndeleted file mode 100644\nindex 2222222..0000000\n--- a/one.c\n"
                  "+++ /dev/null\n@@ -1 +0,0 @@\n-int one(void) { return 1; }\n")
EXECUTABLE = "diff --git a/one.c b/one.c\nold mode 100644\nnew mode 100755\n"
# what git diff writes when a file becomes a symbolic link: the file deleted, a link (mode 120000) made at its path
TYPECHANGE = ("diff --git a/one.c b/one.c\ndeleted file mode 100644\nindex 2222222..0000000\n--- a/one.c\n"
              "+++ /dev/null\n@@ -1 +0,0 @@\n-int one(void) { return 1; }\n"
              "diff --git a/one.c b/one.c\nnew file mode 120000\nindex 0000000..48980ad\n--- /dev/null\n"
              "+++ b/one.c\n@@ -0,0 +1 @@\n+/etc/hostname\n\\ No newline at end of file\n")
TO_LINK = "diff --git a/one.c b/one.c\nold mode 100644\nnew mode 120000\n"
# a rename that also makes the file a link: git's summary gives its mode change on a line with no path on it
RENAME_TO_LINK = ("diff --git a/one.c b/two.c\nold mode 100644\nnew mode 120000\nsimilarity index 100%\n"
                  "rename from one.c\nrename to two.c\n")
UP = "--- a/../one.c\n+++ b/../one.c\n@@ -1 +1 @@\n-int one(void) { return 1; }\n+int one(void) { return 9; }\n"
THROUGH_A_LINK = ("--- a/out/one.c\n+++ b/out/one.c\n@@ -1 +1 @@\n-int one(void) { return 1; }\n"
                  "+int one(void) { return 9; }\n")


class TestPatchDirective:
    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.top = tmp_path
        self.root = self.top / "work"
        self.project = self.top / "project"
        self.project.mkdir()
        self.tree = self.root / "ext" / "demo" / "src"
        self.tree.mkdir(parents=True)
        (self.tree / "one.c").write_text(ONE)
        (self.tree / "one.c").chmod(0o644)

    def lay_out(self, text):
        """Run lay-out-sources on a sources file with one patch row of `text` at ext/demo/src."""
        (self.project / "demo.patch").write_text(text)
        (self.project / "series").write_text("demo.patch\n")
        sources = self.project / "sources"
        sources.write_text("patch\text/demo/src\tdemo.patch\n")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "argv", ["lay-out-sources", str(sources), str(self.root)])
            lay_out_sources.main()

    def refused(self, text):
        with pytest.raises(SystemExit) as stopped:
            self.lay_out(text)
        return str(stopped.value.code)

    def test_a_patch_row_written_with_spaces_is_refused_by_its_line(self):
        """A row's fields are separated by tabs. A row with none ended the build with a ValueError traceback that
        named neither the file nor the line."""
        (self.project / "demo.patch").write_text(EDIT)
        (self.project / "series").write_text("demo.patch\n")
        sources = self.project / "sources"
        sources.write_text("# the demo patch\npatch ext/demo/src demo.patch\n")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "argv", ["lay-out-sources", str(sources), str(self.root)])
            with pytest.raises(SystemExit) as stopped:
                lay_out_sources.main()
        assert str(stopped.value.code) == (f"lay-out-sources: {sources}:2: not a directive this tool knows, with "
                                           "these fields: 'patch ext/demo/src demo.patch'")

    def test_a_patch_of_regular_files_applies(self):
        self.lay_out(EDIT)
        assert (self.tree / "one.c").read_text() == "int one(void) { return 2; }\n"

    def test_a_patch_may_add_and_delete_a_file(self):
        self.lay_out(ADD_AND_DELETE)
        assert (self.tree / "two.c").read_text() == "int two;\n"
        assert not os.path.lexists(self.tree / "one.c")

    def test_a_patch_may_make_a_file_executable(self):
        self.lay_out(EXECUTABLE)
        assert os.access(self.tree / "one.c", os.X_OK)

    @pytest.mark.parametrize("text, name", [pytest.param(TYPECHANGE, "one.c", id="TYPECHANGE"),
                                            pytest.param(TO_LINK, "one.c", id="TO_LINK"),
                                            pytest.param(RENAME_TO_LINK, "two.c", id="RENAME_TO_LINK")])
    def test_a_patch_cannot_make_a_symbolic_link(self, text, name):
        """Under core.symlinks=false git writes a link a patch makes as a regular file holding the text of its
        target, so nothing out of the tree is readable through the laid-out file. git refuses some of these forms
        by itself; either way, no link is made."""
        try:
            self.lay_out(text)
        except SystemExit as stopped:
            assert "demo.patch" in str(stopped.code)
        made = self.tree / name
        assert not made.is_symlink()
        if made.exists():
            assert made.read_text() != pathlib.Path("/etc/hostname").read_text()

    def test_a_link_a_patch_makes_is_a_regular_file_holding_its_target(self):
        """The delete-then-add-as-link patch, the form git diff writes when a file becomes a link: the laid-out
        file is a regular file whose text is the target's path, not the machine's /etc/hostname."""
        self.lay_out(TYPECHANGE)
        assert not (self.tree / "one.c").is_symlink()
        assert (self.tree / "one.c").read_text() == "/etc/hostname"

    def test_a_patch_with_a_path_out_of_the_tree_is_refused(self):
        assert "demo.patch" in self.refused(UP)
        assert not os.path.lexists(self.tree.parent / "one.c")
        assert (self.tree / "one.c").read_text() == ONE

    def test_a_patch_that_writes_through_a_link_already_in_the_tree_is_refused(self):
        outside = self.top / "outside"
        outside.mkdir()
        (outside / "one.c").write_text(ONE)
        (self.tree / "out").symlink_to(outside)
        assert "demo.patch" in self.refused(THROUGH_A_LINK)
        assert (outside / "one.c").read_text() == ONE

    def configuration(self, repository):
        """What git reads as the configuration of the repository at `repository`: its own file, and the value of
        core.symlinks (with whether one is set)."""
        local = subprocess.run(["git", "config", "--local", "--list"], cwd=repository, capture_output=True, text=True,
                               check=True).stdout
        symlinks = subprocess.run(["git", "config", "core.symlinks"], cwd=repository, capture_output=True, text=True)
        return local, symlinks.returncode, symlinks.stdout

    # Each its own test, so each has a fresh tree from set_up, whatever the one before it left.
    @pytest.mark.parametrize("where", ["tree", "top"])
    def test_the_apply_leaves_the_configuration_of_a_repository_as_it_was(self, where):
        """core.symlinks=false is for the apply alone: in a clone's config it would make git write the real
        symbolic links of that working tree as files of text. A tree that is a repository, and a tree below one,
        take the patch and keep their configuration."""
        repository = getattr(self, where)
        subprocess.run(["git", "init", "-q", "."], cwd=repository, check=True)
        before = self.configuration(repository)
        self.lay_out(EDIT)
        assert (self.tree / "one.c").read_text() == "int one(void) { return 2; }\n"
        assert self.configuration(repository) == before

    def test_a_repository_above_the_tree_does_not_take_the_patch(self):
        """Why the apply passes GIT_CEILING_DIRECTORIES: inside a repository, git apply reads the paths of a patch
        with a `diff --git` header from the repository's top, and a tree laid out under it gets nothing, with exit
        0."""
        subprocess.run(["git", "init", "-q", "."], cwd=self.top, check=True)
        self.lay_out(ADD_AND_DELETE)
        assert (self.tree / "two.c").read_text() == "int two;\n"
        assert not os.path.lexists(self.tree / "one.c")
