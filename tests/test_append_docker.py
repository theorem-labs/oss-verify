# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""oss-verify check --layout-out and --base-layout on tests/fixtures/example: a base build, then an append build of a
copy whose example_run has one case more. Each function whose code did not change keeps its base address, and
example_run moves. Needs Docker and the toolchain image:

    OV_DOCKER_TESTS=1 uv run pytest tests/test_append_docker.py
"""
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from oss_verify import check
from oss_verify import check_build
from oss_verify import validate
from test_binary_checks_docker import docker_ready

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "example"
SCRIPT = check_build.BUILDER_DIR / "layout.py"
layout = check.layout_module()
BUILDS = ["plain", "asan"]
TARGET = "example_fuzzer"
CHANGED = ".text.example_run"
# The copy's example.c gets ADDED after the line of example_run's switch that holds CASE_R. 'p' lies between cases the
# switch already has, so a jump table of the switch keeps its size: the function's code grows, and the read-only data in
# front of .text does not (layout.py's readonly_growth, which would make each link a normal one).
CASE_R = "case 'r': return 1;"
ADDED = "    case 'p': return 2;\n"
# tests/fixtures/example is the builder tests' project, not an enrollment, so oss-verify check takes it with two
# stand-ins: validate refuses its fuzz/ (only regular files may sit beside project.yaml), and its repo,
# https://example.invalid/example, is no repository to resolve. Its Dockerfile copies the build context, so the commit
# only names the image, as "0" * 40 does in the other Docker tests.
COMMIT = "0" * 40


def remove_images(work):
    """Remove the project images of the oss-verify check run with the work directory `work`, which it lists in
    work/images (check_build.record_image). The builder image stays, as the other Docker tests leave it: its tag hashes
    infra/base-builder and the toolchain, and the next run reuses it. Every container of the run is a docker run
    --rm, so none is left."""
    tags = check_build.recorded_images(work / check_build.IMAGES)
    if tags:
        subprocess.run(["docker", "image", "rm", *tags], capture_output=True)


@unittest.skipUnless(os.environ.get("OV_DOCKER_TESTS") == "1" and docker_ready(),
                     "set OV_DOCKER_TESTS=1, with Docker and the toolchain image, to build the fixture")
class Append(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Class cleanups run when setUpClass fails too, unlike tearDownClass: the images of a failed build go as well.
        # They run last first, so each run's images go before the scratch directory that lists them.
        scratch = tempfile.TemporaryDirectory(prefix="ov-test-append.")
        cls.addClassCleanup(scratch.cleanup)
        root = pathlib.Path(scratch.name)
        cls.base, cls.new = root / "base-layout", root / "new-layout"
        changed = root / "example-changed"
        shutil.copytree(FIXTURE, changed)
        source = changed / "example.c"
        text = source.read_text(encoding="utf-8")
        if text.count(CASE_R) != 1:
            raise cls.failureException(f"{source} has not one line with {CASE_R!r} to add {ADDED.strip()!r} after")
        at = text.index("\n", text.index(CASE_R)) + 1
        source.write_text(text[:at] + ADDED + text[at:], encoding="utf-8")
        cls.check("the base build", FIXTURE, root / "base-work", "--layout-out", cls.base)
        cls.check("the append build", changed, root / "new-work", "--layout-out", cls.new, "--base-layout", cls.base)

    @classmethod
    def check(cls, step, project, work, *options):
        """Run oss-verify check on `project` for BUILDS, in the work directory `work`, with `options`. Fail, naming
        `step`, unless it exits 0."""
        cls.addClassCleanup(remove_images, work)
        argv = ["--no-shell", *(word for build in BUILDS for word in ("--build", build)), "--dir", str(work),
                *map(str, options), str(project)]
        with mock.patch.object(validate, "check_project", lambda directory: ([], [], None)), \
                mock.patch.object(check_build, "resolve", lambda repo, ref, token=None: COMMIT):
            try:
                code = check.main(argv)
            except SystemExit as stop:
                code = stop.code
        if code != 0:
            raise cls.failureException(f"{step}: oss-verify check {shlex.join(argv)} exited {code}, not 0 (its output "
                                       "is captured above)")

    def read(self, tree, build):
        return layout.read_layout(tree / build / TARGET)

    def test_the_layout_check_passes_for_every_build_and_target(self):
        done = subprocess.run([sys.executable, str(SCRIPT), "check", str(self.base), str(self.new)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        entries = layout.entries(self.base)
        self.assertEqual(entries, layout.entries(self.new))
        self.assertLessEqual({(build, TARGET) for build in BUILDS}, set(entries))
        self.assertIn(f"layout check: {len(entries)} of {len(entries)} (build, target) pass", done.stdout)

    def test_the_changed_function_moves(self):
        for build in BUILDS:
            base, new = self.read(self.base, build), self.read(self.new, build)
            old, now = ([i for i in tree.inputs if i.section == CHANGED] for tree in (base, new))
            self.assertEqual((len(old), len(now)), (1, 1), f"{build}: the {CHANGED} input sections of {TARGET}")
            old, now = old[0], now[0]
            pairing = layout.pair(base.inputs, new.inputs)
            self.assertEqual(pairing.partner[now.row], old.row, build)
            self.assertFalse(pairing.same[now.row], f"{build}: example_run has the bytes it has at the base")
            self.assertNotEqual(now.address, old.address, f"{build}: example_run is at its base address")

    def test_each_function_that_did_not_change_keeps_its_address(self):
        base, new = self.read(self.base, "plain"), self.read(self.new, "plain")
        self.assertTrue(new.placement, f"plain/{TARGET} of the append build has no placement.tsv: no append link")
        pairing = layout.pair(base.inputs, new.inputs)
        occurrence = layout.occurrences(new.inputs)
        kept, moved = 0, []
        for i in new.inputs:
            if not pairing.same.get(i.row):
                continue
            old = base.inputs[pairing.partner[i.row]]
            if (i.address, i.linked) == (old.address, old.linked):
                kept += 1
                continue
            moved.append(f"{layout.function(i)}: address {old.address:#x} -> {i.address:#x}, linked size "
                         f"{old.linked} -> {i.linked}, placement {new.placement.get(i.key + (occurrence[i.row],))}")
        self.assertEqual(moved, [])
        self.assertGreater(kept, 0, f"plain/{TARGET} has no .text input section with the bytes it has at the base")


if __name__ == "__main__":
    unittest.main()
