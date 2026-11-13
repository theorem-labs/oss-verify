# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""An atheris harness for tests/test_builder.py."""
import sys

import atheris

with atheris.instrument_imports():
    import example


def TestOneInput(data):
    example.run(data)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
