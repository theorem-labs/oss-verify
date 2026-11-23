# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""seen.py [<directory> ...]: what CPython's configure can see in this container besides its precious variables, which
autoconf compares itself (python/recipes.sh, oft_py_seen and oft_py_configure_from_cache). One line for the package
database (Alpine's, or Debian's), with the SHA-256 of its bytes; then one line for each variable of the environment,
less ENVIRONMENT_LEFT_OUT, sorted by name, with its value; then one line for each entry under the directories and
under each directory on PATH, sorted by path: a file with its permissions, its size and its modification time (in
seconds), a directory with its permissions, a symbolic link with its target, or another kind of entry with its type
and permissions. So a package that a project's Dockerfile installs, a variable that it or build.sh sets (an ENV PATH
that adds a directory of tools, say), or a file that it or build.sh adds, removes, rewrites (apk, pip, make install,
sed -i, cp) or makes executable, changes it. An edit that keeps a file's size and time is not seen, by design: it
takes intent, and reading the bytes of the 3.3 GB of files took 6.6 s a build, 27 s from a cold page cache, where
their metadata takes 0.5 s, 1.5 s cold (the Python builder of 2026.10 on an n2d-standard-4 VM, INFRA-5359). With no
directory given, the package database, the environment, DIRECTORIES and the directories on PATH, those that hold the
headers, libraries, pkg-config files and programs that configure looks for, less LEFT_OUT; with directories, the
environment, those and the directories on PATH (tests/test_python_seen.py). A directory given or on PATH that is a
symbolic link is walked at the directory that it reaches too; a link under one is not followed. The toolchain image's
native Python runs it."""
import hashlib
import os
import stat
import sys

DATABASES = (b"/lib/apk/db/installed", b"/var/lib/dpkg/status")
DIRECTORIES = (b"/opt/musl-sysroot", b"/usr/include", b"/usr/local", b"/usr/lib/pkgconfig", b"/usr/share/pkgconfig",
               b"/bin", b"/sbin", b"/usr/bin", b"/usr/sbin")
# This builder's own files, which hold the answers and change with each build's output (__pycache__); the init that
# `docker run --init` (oss_verify.check_build.compile_build) mounts in each build's container; and the compiler shims
# that compile writes anew in each container from toolchain.sh (SHIM, first on PATH), whose times therefore differ in
# each, and whose compilers are the build's CC and CXX, which autoconf compares itself.
LEFT_OUT = {b"/usr/local/lib/oss-verify", b"/sbin/docker-init", b"/tmp/shim"}
# The variables of the environment that differ from one run to the next whatever a project does, and so are not
# compared. Set anew for each container or shell: the container's name (HOSTNAME), the shell's directories (PWD,
# OLDPWD), its depth (SHLVL) and its last command (_). Set by release-target.sh's ov_target_begin for the target that
# it builds, not for the toolchain: its name (T), its source and build directories (SRCDIR, BUILDDIR) and its prefix
# (OFT_PREFIX); the builder's run of config-cache builds the target oft-py-config. Set by oss-verify check for how it
# builds, not for what: the records of the checks (OV_RECORD, OV_RECORDS, OV_LAYOUT, OV_BASE_LAYOUT), which change no
# byte of a build (tests/test_binary_checks_docker.py, test_records_change_no_byte), and the parallel jobs of make
# (OFT_MAKE_JOBS). Set by config-cache for itself: where it writes the answers (OV_CONFIG_CACHE_DIR).
ENVIRONMENT_LEFT_OUT = {b"HOSTNAME", b"PWD", b"OLDPWD", b"SHLVL", b"_", b"T", b"SRCDIR", b"BUILDDIR", b"OFT_PREFIX",
                        b"OV_RECORD", b"OV_RECORDS", b"OV_LAYOUT", b"OV_BASE_LAYOUT", b"OFT_MAKE_JOBS",
                        b"OV_CONFIG_CACHE_DIR"}


def sha256(path):
    """The SHA-256 of the bytes of the file at `path`, in hex."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest().encode()


def escaped(text):
    """`text` with a backslash and a newline written escaped, so that it takes one line."""
    return text.replace(b"\\", b"\\\\").replace(b"\n", b"\\n")


def described(path):
    """One line for the entry at `path`: its kind, its path, and its permissions (in octal) and a file's size and
    modification time, or its link's target. The time is in whole seconds, the precision that every image layer
    keeps."""
    status = os.lstat(path)
    mode = status.st_mode
    if stat.S_ISREG(mode):
        return b"file %s %o %d %d" % (escaped(path), stat.S_IMODE(mode), status.st_size, int(status.st_mtime))
    if stat.S_ISLNK(mode):
        return b"link %s -> %s" % (escaped(path), escaped(os.readlink(path)))
    if stat.S_ISDIR(mode):
        return b"directory %s %o" % (escaped(path), stat.S_IMODE(mode))
    return b"other %s %o %o" % (escaped(path), stat.S_IFMT(mode), stat.S_IMODE(mode))


def entries(top):
    """(path, line) for `top` and each entry under it, less LEFT_OUT; a symbolic link is not followed."""
    if top in LEFT_OUT or not os.path.lexists(top):
        return
    yield top, described(top)
    if os.path.isdir(top) and not os.path.islink(top):
        for root, directories, files in os.walk(top):
            directories[:] = [name for name in directories if os.path.join(root, name) not in LEFT_OUT]
            for name in directories + files:
                path = os.path.join(root, name)
                if path not in LEFT_OUT:
                    yield path, described(path)


def on_path():
    """The directories on PATH, each once, in the order of PATH; an empty entry, which means the current directory, as
    the current directory. None without PATH, or with an empty one."""
    path = os.environb.get(b"PATH", b"")
    return list(dict.fromkeys(os.path.abspath(entry or b".") for entry in path.split(b":"))) if path else []


def main(arguments):
    tops = [os.fsencode(argument) for argument in arguments]
    lines = []
    if not tops:
        lines += [b"package database %s %s" % (database, sha256(database)) for database in DATABASES
                  if os.path.isfile(database)]
    lines += [b"environment %s=%s" % (escaped(name), escaped(value)) for name, value in sorted(os.environb.items())
              if name not in ENVIRONMENT_LEFT_OUT]
    # Each directory, and the one that it reaches through symbolic links, if it is one: a link on PATH to a directory
    # of tools is walked as that directory is.
    walked = dict.fromkeys(path for top in [*(tops or DIRECTORIES), *on_path()]
                           for path in (top, os.path.realpath(top)))
    seen = dict(item for top in walked for item in entries(top))
    lines += [line for _, line in sorted(seen.items())]
    sys.stdout.buffer.write(b"".join(line + b"\n" for line in lines))


if __name__ == "__main__":
    main(sys.argv[1:])
