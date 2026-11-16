# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The oss-verify command. Each of its commands is one module of this package:

    oss-verify check ...       build a project's fuzz targets, check them and write the manifest (oss_verify.check)
    oss-verify validate ...    check the files of project directories (oss_verify.validate)

`oss-verify <command> --help` describes a command."""
import sys

USAGE = "usage: oss-verify {check,validate} ..."


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["check"]:
        from . import check
        return check.run(argv[1:])
    if argv[:1] == ["validate"]:
        from . import validate
        return validate.main(argv[1:])
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    print(f"{USAGE}\n{__doc__}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
