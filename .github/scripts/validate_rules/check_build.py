# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the steps of an OSS Verify build (resolve the ref, build the builder and the
# project image, compile each build with no network, list the image's git checkouts) in place of the scanner's. The
# virtual machine backend is not ported.
# Written by .github/scripts/copy-validate-rules from src/oss_verify/check_build.py; do not edit.
"""What validate.py uses of src/oss_verify/check_build.py (.github/scripts/copy-validate-rules)."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOLCHAINS = ROOT / "infra" / "toolchains.tsv"
# How a toolchain's UBSan builds choose their checks: the release's fixed flags, or the project's ubsan_checks.
UBSAN_MODES = ("fixed", "checks")


class Failed(Exception):
    """The build failed. The message says which step failed and why."""


def toolchains():
    """The toolchain images a project can be built with, oldest first (infra/toolchains.tsv): [(name, image, ubsan,
    languages)]. ubsan is how the UBSan builds choose their checks: "fixed" (the release's flags) or "checks"
    (ubsan_checks). languages are the values of project.yaml's language that the image builds."""
    rows = [line.split("\t") for line in TOOLCHAINS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]
    if not rows or any(len(row) < 4 or not row[1] or row[2] not in UBSAN_MODES or not row[3] for row in rows):
        raise Failed(f"{TOOLCHAINS} lists no toolchain, or a row has no image, no ubsan of {', '.join(UBSAN_MODES)} "
                     "or no languages")
    return [(row[0], row[1], row[2], tuple(row[3].split(","))) for row in rows]


def ubsan_mode(image):
    """How the UBSan builds on this toolchain image choose their checks: as its row says, or "fixed" for an image
    that infra/toolchains.tsv does not list."""
    return next((mode for _, listed, mode, _ in toolchains() if listed == image), "fixed")


def newest_toolchain(language="c"):
    """The newest toolchain image for a language: the last row of infra/toolchains.tsv that lists it."""
    images = [image for _, image, _, languages in toolchains() if language in languages]
    if not images:
        raise Failed(f"{TOOLCHAINS} lists no toolchain for {language}")
    return images[-1]
