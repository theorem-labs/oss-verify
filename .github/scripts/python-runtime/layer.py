#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""layer.py STAGING OUT_TAR: the layer that .github/scripts/python-runtime/make appends to a Python toolchain image,
the tar of STAGING's opt/oft-py/prebuilt/.

The same files give the same bytes, whatever their times, owners and modes on disk, so that the image made again from
the same runtimes has the same digest. The entries are opt/oft-py/prebuilt and each directory and file under it,
sorted by path, in the ustar format. Each has mtime 0, uid and gid 0, and empty user and group names; a directory has
mode 0755, and a file 0644, or 0755 when any of its execute bits is set. The layer holds no entry for opt/ or
opt/oft-py/, which the toolchain image has: those directories keep the image's own times and modes.

STAGING may hold the directories opt/ and opt/oft-py/ and nothing else beside opt/oft-py/prebuilt/. A symbolic link,
or any other entry that is not a regular file or a directory, is refused. It exits 2 on a usage error, and 1 when it
refuses STAGING or cannot write OUT_TAR. It imports no package but Python's own."""
import os
import stat
import sys
import tarfile

TOP = "opt/oft-py/prebuilt"
# The directories above TOP that STAGING may hold.
ABOVE = {"opt", "opt/oft-py"}


class Refused(Exception):
    pass


def raise_error(error):
    """os.walk's onerror: a directory that cannot be read fails the layer, rather than leaving its entries out."""
    raise error


def entries(staging):
    """[(path relative to STAGING, its lstat)] of TOP and each entry under it, sorted by path."""
    found = []
    for directory, names, files in os.walk(staging, onerror=raise_error):
        for name in names + files:
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, staging).replace(os.sep, "/")
            info = os.lstat(path)
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise Refused(f"{relative} is neither a regular file nor a directory")
            if relative in ABOVE and stat.S_ISDIR(info.st_mode):
                continue
            if relative != TOP and not relative.startswith(TOP + "/"):
                raise Refused(f"{relative} is not under {TOP}")
            found.append((relative, info))
    if not any(relative == TOP and stat.S_ISDIR(info.st_mode) for relative, info in found):
        raise Refused(f"there is no directory {TOP}")
    return sorted(found, key=lambda entry: os.fsencode(entry[0]))


def write(staging, found, out):
    with tarfile.open(out, "w", format=tarfile.USTAR_FORMAT) as tar:
        for relative, info in found:
            member = tarfile.TarInfo(relative)
            member.mtime = 0
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            if stat.S_ISDIR(info.st_mode):
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                tar.addfile(member)
            else:
                member.type = tarfile.REGTYPE
                member.mode = 0o755 if info.st_mode & 0o111 else 0o644
                member.size = info.st_size
                with open(os.path.join(staging, relative), "rb") as source:
                    tar.addfile(member, source)


def main(argv):
    if len(argv) != 3:
        print("usage: layer.py STAGING OUT_TAR", file=sys.stderr)
        return 2
    staging, out = argv[1:]
    try:
        found = entries(staging)
    except (Refused, OSError) as error:
        print(f"layer.py: {staging}: {error}", file=sys.stderr)
        return 1
    try:
        write(staging, found, out)
    except (OSError, ValueError) as error:
        print(f"layer.py: {out}: {error}", file=sys.stderr)
        if os.path.lexists(out):
            os.unlink(out)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
