# Copyright 2026 Arunim Shukla
# SPDX-License-Identifier: Apache-2.0
"""Source pinning with real local Git refs; Docker builds are replaced, as in test_check.py."""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

TOOLS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import check_build  # noqa: E402
import manifest  # noqa: E402
from test_manifest import PT_LOAD, elf  # noqa: E402

LOADER = importlib.machinery.SourceFileLoader("check_source_pinning", str(TOOLS / "check"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
check_tool = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(check_tool)

REPO = "https://example.org/demo"
PIN = {"file": "demo_fuzzer.plain", "bytes": 1, "sha256": "1" * 64}


class GitRepository(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        # git with no configuration from this machine: its hooks, signing and URL rewrites stay out of the fixture,
        # for the fixture's own commits and for the real git ls-remote that resolve() runs.
        home = self.root / "home"
        home.mkdir()
        environment = mock.patch.dict(os.environ, {
            "PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_GLOBAL": str(home / "gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
        }, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.remote = self.root / "remote"
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.remote)], check=True, capture_output=True)
        self.git("commit", "-q", "--allow-empty", "-m", "first")
        self.commit = self.git("rev-parse", "HEAD")
        self.git("branch", "release")
        self.git("tag", "-a", "v1", "-m", "annotated release")
        self.git("tag", "v1-light")
        self.git("commit", "-q", "--allow-empty", "-m", "second")
        self.latest = self.git("rev-parse", "HEAD")
        # Only the transport is redirected: resolve() still runs real git ls-remote.
        transport = mock.patch.object(check_build, "git", self.local_transport)
        transport.start()
        self.addCleanup(transport.stop)

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.remote), "-c", "user.name=Source pinning test",
             "-c", "user.email=test@example.org", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
            text=True, stderr=subprocess.PIPE,
        ).strip()

    def local_transport(self, *args):
        return ["git", "-c", "credential.helper=", "-c", "protocol.allow=never", "-c", "protocol.file.allow=always",
                *(self.remote.as_uri() if arg == REPO else arg for arg in args)]


class Resolve(GitRepository):
    def test_annotated_tag(self):
        self.assertEqual(check_build.resolve(REPO, "v1"), self.commit)
        self.assertEqual(check_build.resolve(REPO, "refs/tags/v1"), self.commit)

    def test_nested_annotated_tag(self):
        self.git("tag", "-a", "nested", "v1", "-m", "tag of a tag")
        self.assertEqual(check_build.resolve(REPO, "nested"), self.commit)
        self.assertEqual(check_build.resolve(REPO, "refs/tags/nested"), self.commit)

    def test_lightweight_tag(self):
        self.assertEqual(check_build.resolve(REPO, "v1-light"), self.commit)
        self.assertEqual(check_build.resolve(REPO, "refs/tags/v1-light"), self.commit)

    def test_explicit_refs_disambiguate_branch_and_tag(self):
        self.git("branch", "v1", self.latest)
        self.assertEqual(check_build.resolve(REPO, "refs/heads/v1"), self.latest)
        self.assertEqual(check_build.resolve(REPO, "refs/tags/v1"), self.commit)
        with self.assertRaisesRegex(check_build.Failed, "both a branch and a tag"):
            check_build.resolve(REPO, "v1")

    def test_branch_and_default(self):
        for ref in ("", "main", "refs/heads/main"):
            with self.subTest(ref=ref):
                self.assertEqual(check_build.resolve(REPO, ref), self.latest)

    def test_missing_ref(self):
        with self.assertRaisesRegex(check_build.Failed, "no branch or tag"):
            check_build.resolve(REPO, "missing")


class LockedBuild(GitRepository):
    def setUp(self):
        super().setUp()
        self.project = self.root / "demo"
        self.project.mkdir()
        (self.project / "project.yaml").write_text(yaml.safe_dump({
            "repo": REPO + "#release", "primary_contact": "security@example.org", "language": "c", "sanitizers": [],
        }))
        (self.project / "Dockerfile").write_text("FROM scratch\n")
        (self.project / "build.sh").write_text("#!/bin/sh\n")
        self.work = self.root / "work"

    def run_check(self, *, use_lock=True, pin_commit=True):
        argv = ["tools/check", "--no-shell", "--toolchain", "test/toolchain:local", "--dir", str(self.work),
                str(self.project)]
        if use_lock:
            lock = {"schema": manifest.MANIFEST_SCHEMA, "targets": {"demo_fuzzer": {"builds": {"plain": PIN}}}}
            if pin_commit:
                lock["commit"] = self.commit
            path = self.root / "lock.yaml"
            path.write_text(yaml.safe_dump(lock))
            argv += ["--lock", str(path)]
        built = []

        def build_all(job, commit, *args, **kwargs):
            built.append(commit)
            path = self.work / "out" / "demo_fuzzer" / PIN["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(elf(symtab=False, sections=[(".text", 1)], segments=[PT_LOAD]))
            return "builder", "project", ["demo_fuzzer"], {"demo_fuzzer": {"plain": dict(PIN)}}

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(check_tool, "build_all", build_all))
            stack.enter_context(mock.patch.object(check_build, "image_id", return_value="sha256:test"))
            stack.enter_context(mock.patch.object(check_build, "sources", return_value={}))
            stack.enter_context(mock.patch.object(check_build, "oss_verify_state", return_value=None))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = check_tool.main()
        path = self.work / "manifest.yaml"
        data = yaml.safe_load(path.read_text()) if path.exists() else None
        return code, built, data

    def test_lock_survives_deleted_ref(self):
        self.git("branch", "-D", "release")
        self.assertEqual(self.git("cat-file", "-t", self.commit), "commit")
        code, built, data = self.run_check()
        self.assertEqual(code, 0)
        self.assertEqual(built, [self.commit])
        self.assertEqual(data["commit"], self.commit)

    def test_lock_survives_ambiguous_ref(self):
        self.git("tag", "release", self.latest)
        code, built, data = self.run_check()
        self.assertEqual(code, 0)
        self.assertEqual(built, [self.commit])
        self.assertEqual(data["commit"], self.commit)

    def test_lock_pins_original_commit_after_ref_moves(self):
        self.git("branch", "-f", "release", self.latest)
        code, built, data = self.run_check()
        self.assertEqual(code, 0)
        self.assertEqual(built, [self.commit])
        self.assertEqual(data["commit"], self.commit)

    def test_lock_without_commit_resolves_live_ref(self):
        self.git("branch", "-f", "release", self.latest)
        code, built, data = self.run_check(pin_commit=False)
        self.assertEqual(code, 0)
        self.assertEqual(built, [self.latest])
        self.assertEqual(data["commit"], self.latest)

    def test_unlocked_build_follows_live_ref(self):
        self.git("branch", "-f", "release", self.latest)
        code, built, data = self.run_check(use_lock=False)
        self.assertEqual(code, 0)
        self.assertEqual(built, [self.latest])
        self.assertEqual(data["commit"], self.latest)

    def test_unlocked_build_rejects_deleted_ref(self):
        self.git("branch", "-D", "release")
        code, built, data = self.run_check(use_lock=False)
        self.assertEqual(code, 1)
        self.assertEqual(built, [])
        self.assertIsNone(data)


if __name__ == "__main__":
    unittest.main()
