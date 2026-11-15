# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the errors of infra/base-builder/lay-out-sources, which need no Docker:  uv run pytest

A line the tool cannot carry out ends the run with one line, `lay-out-sources: <sources>:<line>: <why>`, never a
traceback.
"""
import importlib.machinery
import importlib.util
import io
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

TESTS = pathlib.Path(__file__).resolve().parent
LOADER = importlib.machinery.SourceFileLoader(
    "lay_out_sources", str(TESTS.parent / "infra" / "base-builder" / "lay-out-sources"))
SPEC = importlib.util.spec_from_loader("lay_out_sources", LOADER)
lay_out_sources = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(lay_out_sources)

SHA256 = "0" * 64


def tar(*members):
    """A tar archive of `members`, each a (name, type, link target) with no bytes."""
    made = io.BytesIO()
    with tarfile.open(fileobj=made, mode="w") as archive:
        for name, kind, target in members:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, target
            archive.addfile(info)
    return made.getvalue()


class Errors(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.top = pathlib.Path(d.name)
        self.sources = self.top / "sources"

    def refused(self, text, data=b""):
        """What lay-out-sources says when it stops on a sources file of `text`, its archive rows downloading
        `data`."""
        self.sources.write_text(text)
        with (mock.patch.object(lay_out_sources, "download", lambda url, sha256: data),
              mock.patch.object(sys, "argv", ["lay-out-sources", str(self.sources), str(self.top / "root")]),
              self.assertRaises(SystemExit) as stopped):
            lay_out_sources.main()
        return str(stopped.exception.code)

    def test_a_hard_link_to_a_member_the_archive_lacks_is_refused_by_its_line(self):
        data = tar(("top/a", tarfile.LNKTYPE, "top/gone"))
        said = self.refused(f"archive\tvendor\thttps://example.com/a.tar\t{SHA256}\t1\n", data)
        self.assertEqual(said, f"lay-out-sources: {self.sources}:1: hard link 'top/a' points to 'top/gone', not a "
                               "file in the archive")

    def test_a_hard_link_to_a_directory_is_refused_by_its_line(self):
        data = tar(("top/dir", tarfile.DIRTYPE, ""), ("top/a", tarfile.LNKTYPE, "top/dir"))
        said = self.refused(f"archive\tvendor\thttps://example.com/a.tar\t{SHA256}\t1\n", data)
        self.assertEqual(said, f"lay-out-sources: {self.sources}:1: hard link 'top/a' points to 'top/dir', not a "
                               "file in the archive")

    def test_a_hard_link_to_a_file_takes_its_bytes(self):
        made = io.BytesIO()
        with tarfile.open(fileobj=made, mode="w") as archive:
            info = tarfile.TarInfo("top/one.c")
            info.size = 4
            archive.addfile(info, io.BytesIO(b"one\n"))
            info = tarfile.TarInfo("top/two.c")
            info.type, info.linkname = tarfile.LNKTYPE, "top/one.c"
            archive.addfile(info)
        self.assertEqual(lay_out_sources.members(made.getvalue(), 1, ()),
                         [("one.c", "file", b"one\n", False), ("two.c", "file", b"one\n", False)])

if __name__ == "__main__":
    unittest.main()
