# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""tests/test_builder.py's own command, `OV_DOCKER_TESTS=1 uv run pytest`, on a machine with Docker and the base images
but with no frame-pointer image named (OV_FP_TOOLCHAIN_C and OV_FP_TOOLCHAIN_RUST unset): FramePointersC and
FramePointersRust skip, as each other class of that file skips when its image is not here, and the run does not fail.
The jobs that run them with the images (the job docker of .github/workflows/tests.yaml, and toolchain-images.yaml's job
docker-tests) fail on a skipped test by themselves. A docker on PATH that says that each image is here stands in for
Docker and the base images, so this test needs no Docker, and the job suite of tests.yaml runs it:

    uv run pytest tests/test_no_frame_pointer_image.py
"""
import os
import pathlib
import re
import subprocess
import sys

BUILDER_TESTS = pathlib.Path(__file__).resolve().parent / "test_builder.py"


class TestNoFramePointerImage:
    def test_frame_pointers_skips_when_no_frame_pointer_image_is_named(self, tmp_path):
        root = BUILDER_TESTS.parents[1]
        docker = tmp_path / "docker"
        docker.write_text('#!/bin/sh\n[ "$1 $2" = "image inspect" ] && exit 0\necho "docker $*: not here" >&2\n'
                          "exit 1\n")
        docker.chmod(0o755)
        environment = {name: value for name, value in os.environ.items()
                       if name not in ("OV_FP_TOOLCHAIN_C", "OV_FP_TOOLCHAIN_RUST")}
        environment.update(OV_DOCKER_TESTS="1", PATH=f"{tmp_path}{os.pathsep}{environment.get('PATH', '')}")
        done = subprocess.run(
            [sys.executable, "-P", "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider", "-c", "pyproject.toml",
             f"{BUILDER_TESTS}::FramePointersC", f"{BUILDER_TESTS}::FramePointersRust"],
            cwd=root, env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
        assert done.returncode == 0, done.stdout[-4000:] + done.stderr[-2000:]
        # The 7 tests of the two classes, each skipped.
        assert re.search(r"(?m)^7 skipped in ", done.stdout), done.stdout[-4000:]
