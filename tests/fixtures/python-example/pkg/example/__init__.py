# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""A library for tests/test_builder.py: each function ends a run in one way."""
import sys


def run(data):
    """Does one thing for each first byte of `data`, as tests/test_builder.py's PYTHON_EXPECTED says."""
    first = data[:1]
    if first == b"e":
        raise ValueError("a failed property")
    if first == b"m":
        raise MemoryError()
    if first == b"x":
        sys.exit(3)
    if first == b"p":
        print("printed")
    return len(data)
