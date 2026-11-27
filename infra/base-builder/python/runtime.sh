# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The CPython runtime of a Python fuzz target's build: the patched source tree (oft_py_source) and the build's
# libpython3.11.a with its two bundled archives (oft_py_runtime). python/recipes.sh sources this file, and its other
# steps read the runtime's files from $OFT_PY_RT and the source tree's headers and standard library from $OFT_PY_SRC.
#
# The runtime is addressed by its inputs, and its build reads no other. oft_py_runtime builds it in an environment of
# its own (oft_py_hermetic): no variable but a few of the build's (OFT_PY_ENV_KEPT) and fixed ones, a PATH of the
# compiler shims and the image's own directories, HOME and TMPDIR in its new build directory, its build directory as
# the working directory, and, in a build that runs as root, the user nobody, behind a read boundary (oft_py_boundary):
# each path that the key leaves out, but the container's own and what the build needs there, is closed to that user
# while it builds, so it can read nothing there even when a value that it gets names one. The patched source tree is
# read-only to it, and oft_py_runtime fails if the tree changed. (A mount namespace would hide those paths, as Nix's
# sandbox does; a build's container may not make one.) oft_py_runtime_inputs prints, one per line, what its bytes
# depend on: the build, configure's arguments, make's targets, that environment, the files that its build reads and
# runs, the compiler shims, the patched source tree, and the whole file system, by content, mode and owner, but the
# paths that oft_py_fs_left_out names. Its key is the SHA-256 of those lines. A Python toolchain image derived for this
# (.github/scripts/python-runtime/make) holds, for each of the four builds, the runtime built from those inputs, in
# /opt/oft-py/prebuilt/<flav>-<key>/:
#   runtime/   the files of the runtime that the rest of a build reads (OFT_PY_RT_FILES)
#   records/   the compile records of its build: compiles.jsonl and nosan/, as compile writes them with OV_RECORD=1
#   manifest   the inputs' lines, then `key <key>`, then `made-from <the toolchain image it was made FROM>`
# Every build computes its key and prints it, with the time it took. A build whose key is there takes that runtime,
# and, when it records its compiles, those records, so that the checks of src/oss_verify/check_links.py see what they
# see when the build compiles the runtime itself. Any other build compiles its own, in the same environment as the
# image's build of it, and says which input differs. This file holds the runtime's recipe alone, so that a change of the
# rest of python/recipes.sh changes no key.
#
# oft_py_source and the build in oft_py_runtime are from the build recipe of the oss-fuzz-theorems 2026.10 release
# (tools/python/recipe.sh), in its release mode, as python/recipes.sh says: the same commands, with the same arguments
# and the same values of the variables they read. The environment that holds nothing else, and the shipped runtime,
# are new.

OFT_PY_DIR=/usr/local/lib/oss-verify/python
# The toolchain image's Python: the CPython tarball and a native CPython 3.11.13 built from it.
OFT_PY_OPT=/opt/oft-py
OFT_PY_BPY=$OFT_PY_OPT/native/bin/python3.11
OFT_PY_TARBALL=$OFT_PY_OPT/Python-3.11.13.tar.xz
OFT_PY_TARBALL_SHA256=8fb5f9fbc7609fa822cb31549884575db7fd9657cbffb89510b5d7975963a83a
OFT_PY_PATCHES="$OFT_PY_DIR/patches/0001-signal-assume-default-dispositions.patch"
OFT_PY_CPY_DEFS="-DOFT_SIGNAL_ASSUME_DEFAULT"
# The interpreter's prefix, which libpython and atheris_host.c record. /oft does not exist, so CPython's probes of it
# cost one -ENOENT. The build directory's own files are compiled as /oft/pyrt/build/ (__FILE__).
OFT_PY_PREFIX=/oft/py
OFT_PY_FILE_MAP=/oft/pyrt/build/
# The patched source tree, one for all four builds, at the release's path for it: configure records its own path, and
# the binaries hold it, 237 times in an asan build. The name is the release's hash of the tarball and the patches.
OFT_PY_SRC=/work/build/pyrt/src-64ef29c99f3ea59d

# make's targets in the runtime's build, and the files of a runtime that the rest of a build reads (relative to it):
# what a shipped runtime holds in runtime/.
OFT_PY_RT_TARGETS="libpython3.11.a Modules/expat/libexpat.a Modules/_decimal/libmpdec/libmpdec.a"
OFT_PY_RT_FILES="$OFT_PY_RT_TARGETS pyconfig.h oft-linkvars.txt target-builtins.txt target-frozen.txt"
# Where a derived Python toolchain image holds its runtimes: one directory for each build and key, <flav>-<key>.
OFT_PY_PREBUILT=$OFT_PY_OPT/prebuilt
# The environment of the runtime's build (oft_py_hermetic). The build's own values of these variables, which the
# runtime's build reads (one that is unset stays unset):
#   CC CXX CFLAGS                      configure's compilers (CC and CFLAGS are its arguments too), and the CFLAGS that
#                                      CPython's Makefile adds to its own
#   PKG_CONFIG_LIBDIR PKG_CONFIG_PATH  where configure's pkg-config looks: the musl sysroot's .pc files
#   SOURCE_DATE_EPOCH                  the time that clang gives __DATE__ and __TIME__ (Modules/getbuildinfo.c)
OFT_PY_ENV_KEPT="CC CXX CFLAGS PKG_CONFIG_LIBDIR PKG_CONFIG_PATH SOURCE_DATE_EPOCH"
# And these, the same in every build: PATH, below; HOME and TMPDIR, two directories in the runtime's build directory,
# which oft_py_runtime makes anew; CONFIG_SITE, empty, so that configure reads no site file; PYTHONNOUSERSITE=1 and
# PYTHONDONTWRITEBYTECODE=1, so that the native Python that CPython's make runs reads no user site directory and writes
# no bytecode. That make runs it with PYTHONPATH and _PYTHON_SYSCONFIGDATA_NAME, the settings of a cross build, which
# -I would ignore; every other run of the native Python here has -I.
# PATH: the compiler shims, which toolchain.sh writes in /tmp/shim, and the image's own directories, as the build has
# it. The key reads each of them.
OFT_PY_PATH=/tmp/shim:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# The user that the runtime's build runs as when the build runs as root: nobody. oft_py_runtime gives it the build
# directory and compile's records directory, and it can write no other file of the image.
OFT_PY_UID=65534
# The file system that the runtime's build can read, which oft_py_runtime_inputs keys by content: one tree line for each
# entry of OFT_PY_FS, and for each entry of the directories of OFT_PY_FS_SPLIT (relative to it) in place of a line for
# the directory, but the paths that oft_py_fs_left_out names; one for the patched source tree; and one for what each
# symbolic link of those trees leads to outside them, but into the paths of oft_py_fs_unfollowed. A project that
# changes any other file builds its own runtime.
OFT_PY_FS=/
OFT_PY_FS_SPLIT="usr opt var tmp"
# The program that the native Python runs to print `<prefix> <word>` for each word after the prefix, one line each. A
# backslash in a word is written \\ and a newline \n, so that each word is one line.
OFT_PY_LINES='import os, sys
for word in sys.argv[2:]:
    sys.stdout.buffer.write(os.fsencode(sys.argv[1]) + b" "
                            + os.fsencode(word).replace(b"\\", b"\\\\").replace(b"\n", b"\\n") + b"\n")'
# The program that oft_py_hermetic runs. Its arguments: a directory, a user, the names of OFT_PY_ENV_KEPT, the fixed
# variables as NAME=value, then, after --, a command. It runs the command from that directory, as that user when that
# is not this process's own, with those variables and no other: each of OFT_PY_ENV_KEPT as this process has it, and the
# fixed ones. With no --, it prints that environment instead, sorted by name, as `env NAME=value` lines, each value
# written as OFT_PY_LINES writes a word, and then `user <user>`.
OFT_PY_HERMETIC='import os, sys
args = [os.fsencode(arg) for arg in sys.argv[1:]]
end = args.index(b"--") if b"--" in args else len(args)
directory, user, kept = args[0], int(args[1]), args[2].split()
env = {name: os.environb[name] for name in kept if name in os.environb}
env.update(word.split(b"=", 1) for word in args[3:end])
if end == len(args):
    out = sys.stdout.buffer
    for name in sorted(env):
        out.write(b"env " + name + b"=" + env[name].replace(b"\\", b"\\\\").replace(b"\n", b"\\n") + b"\n")
    out.write(b"user %d\n" % user)
else:
    os.chdir(directory)
    if os.getuid() != user:
        os.setgroups([])
        os.setgid(user)
        os.setuid(user)
    os.execve(args[end + 1], args[end + 1:], env)'

# The script of the runtime's build, which oft_py_runtime runs with sh, in the runtime's environment: it reads this file
# again and runs oft_py_build_here. Its arguments: this file, make's -j, and configure's arguments.
# shellcheck disable=SC2016 # the script's own $1 and $@
OFT_PY_BUILD='. "$1" || exit 1
jobs=$2
shift 2
oft_py_build_here "$jobs" "$@"'

# The program of the runtime's read boundary (oft_py_boundary), which runs as root:
#   close <state> <user> <grants> <left out> <needed>   each argument after the user is paths, one per line
#   open <state>
# close writes to <state> what it will change, as it is (each entry's mode, owner, group, device and inode), then
# changes it: each entry of the trees of <grants> goes to the user; and each path of <left out> that is no symbolic
# link and holds no path of <needed> goes to root with no access for its group and others, while a directory that holds
# one is not changed and each entry in it is closed so too. The paths of <needed>, and what is under them, are not
# changed. Nor is a mount point (/proc/self/mountinfo) that is a directory, whose owner and mode the host sets (the
# build's /out), or that is mounted read-only (the make script's /src/build.sh); a file that Docker mounts writable for
# each container (its /etc/hosts) is closed as any other.
# open first stops each process of the user, when this runs as root: in the build's container, whose process
# namespace holds its own processes alone, and where nothing but the runtime's build runs as that user. Then it gives
# back each entry that <state> names, its mode and owner; and each entry of the trees of <grants> that the build made or
# put in place of one, to this process's user. It goes on after an entry that it cannot give back, and then fails,
# naming each, as it does when an entry is not as it was (or, for one that the build made, not this user's).
# Both reach each entry from / one directory at a time, by its descriptor, with no symbolic link followed, and the
# walk of a grant enters no mount point (/proc/self/mountinfo): a link that the build put in place of a directory leads
# nowhere, and close refuses a grant that is a mount point itself.
OFT_PY_BOUNDARY='import json, os, re, signal, stat, sys, time
PROC = "/proc"
def paths(arg):
    return [p for p in os.fsencode(arg).split(b"\n") if p]
def under(path, directory):
    return path == directory or path.startswith(directory.rstrip(b"/") + b"/")
def parent(path):
    # A descriptor of the directory that holds path, and the last component.
    parts = [p for p in path.split(b"/") if p]
    fd = os.open(b"/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]
def info(path):
    fd, name = parent(path)
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    finally:
        os.close(fd)
def seen(found):
    mode = None if stat.S_ISLNK(found.st_mode) else stat.S_IMODE(found.st_mode)
    return [mode, found.st_uid, found.st_gid, found.st_dev, found.st_ino]
def change(path, was, uid, gid, mode):
    # Give path, when it is still the entry that was (device and inode), uid, gid and mode (None: its own).
    fd, name = parent(path)
    try:
        found = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if was is not None and [found.st_dev, found.st_ino] != was:
            raise OSError("it is another entry than the one that close changed")
        os.chown(name, uid, gid, dir_fd=fd, follow_symlinks=False)
        if mode is not None and not stat.S_ISLNK(found.st_mode):
            os.chmod(name, mode, dir_fd=fd)
    finally:
        os.close(fd)
def mounts():
    # Each mount point of this process, and whether it is mounted read-only.
    found = {}
    with open(os.path.join(PROC, "self/mountinfo"), "rb") as f:
        for line in f:
            fields = line.split()
            point = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8)]), fields[4])
            found[point] = b"ro" in fields[5].split(b",")
    return found
MOUNTS = mounts()
def tree(top):
    # top and each entry under it, as (path, stat), with no symbolic link followed and no mount point entered: one
    # is not given, nor anything under it, whether its device is that of top or not.
    try:
        here = info(top)
    except FileNotFoundError:
        return
    yield top, here
    if not stat.S_ISDIR(here.st_mode):
        return
    fd, name = parent(top)
    try:
        for directory, dirs, files, dfd in os.fwalk(name, dir_fd=fd, follow_symlinks=False):
            base = os.path.join(os.path.dirname(top.rstrip(b"/")), directory)
            for entry in sorted(dirs + files):
                path = os.path.join(base, entry)
                found = os.stat(entry, dir_fd=dfd, follow_symlinks=False)
                if path not in MOUNTS and found.st_dev == here.st_dev:
                    yield path, found
            dirs[:] = [d for d in dirs if os.path.join(base, d) not in MOUNTS
                       and os.stat(d, dir_fd=dfd, follow_symlinks=False).st_dev == here.st_dev]
    finally:
        os.close(fd)
def stop(user):
    # Stop each process of user (real, effective, saved or file-system user id), as root, but this one.
    for _ in range(200):
        left = []
        for pid in os.listdir(PROC):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            try:
                with open(os.path.join(PROC, pid, "status")) as f:
                    status = dict(line.split(":", 1) for line in f if ":" in line)
            except OSError:
                continue
            if status.get("State", "").split()[:1] == ["Z"] or user not in map(int, status["Uid"].split()):
                continue
            left.append(int(pid))
            try:
                os.kill(int(pid), signal.SIGKILL)
                print("oft-py: the boundary stopped process %s of user %d" % (pid, user), file=sys.stderr)
            except ProcessLookupError:
                pass
        if not left:
            return []
        time.sleep(0.05)
    return ["process %d of user %d still runs" % (pid, user) for pid in left]
state = sys.argv[2]
if sys.argv[1] == "close":
    user = int(sys.argv[3])
    grants, left_out, needed = paths(sys.argv[4]), paths(sys.argv[5]), paths(sys.argv[6])
    # Each path with the links of its parent resolved, as the walk from / reaches it (parent).
    def real(path):
        return os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
    needed, grants = [real(p) for p in needed], [real(p) for p in grants]
    for top in grants:
        if top in MOUNTS:
            sys.exit("oft-py: the grant " + os.fsdecode(top) + " is a mount point: the boundary changes nothing")
    mounts = MOUNTS
    closed = []
    def close(path):
        try:
            found = info(path)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(found.st_mode) or path == os.fsencode(state) or any(under(path, n) for n in needed):
            return
        if path in mounts and (mounts[path] or stat.S_ISDIR(found.st_mode)):
            return
        if stat.S_ISDIR(found.st_mode) and any(under(n, path) for n in needed):
            for name in sorted(os.listdir(path)):
                close(os.path.join(path, name))
            return
        closed.append((path, found))
    for path in left_out:
        close(real(path))
    granted = [entry for top in grants for entry in tree(top)]
    record = {"user": user, "grants": [os.fsdecode(p) for p in grants],
              "granted": [[os.fsdecode(p)] + seen(found) for p, found in granted],
              "closed": [[os.fsdecode(p)] + seen(found) for p, found in closed]}
    with open(state, "w") as f:
        json.dump(record, f)
        f.flush()
        os.fsync(f.fileno())
    for path, found in granted:
        change(path, [found.st_dev, found.st_ino], user, user, None)
    for path, found in closed:
        change(path, [found.st_dev, found.st_ino], 0, 0, stat.S_IMODE(found.st_mode) & 0o700)
else:
    with open(state) as f:
        record = json.load(f)
    failed = stop(record["user"]) if os.getuid() == 0 and record["user"] != 0 else []
    me = [os.getuid(), os.getgid()]
    granted = {os.fsencode(p): rest for p, *rest in record["granted"]}
    given = []
    def give(path, rest, gone):
        # Give path back as rest says; a path that is gone is a failure unless gone says it may be.
        mode, uid, gid, dev, ino = rest
        try:
            change(path, [dev, ino], uid, gid, mode)
            given.append((path, rest))
        except FileNotFoundError:
            if not gone:
                failed.append("%s is gone" % os.fsdecode(path))
        except OSError as error:
            failed.append("%s cannot be given back: %s" % (os.fsdecode(path), error))
    reached, made = set(), []
    for top in record["grants"]:
        for path, found in tree(os.fsencode(top)):
            reached.add(path)
            rest = granted.get(path)
            if rest is not None and [found.st_dev, found.st_ino] == rest[3:]:
                give(path, rest, True)
                continue
            try:
                change(path, [found.st_dev, found.st_ino], me[0], me[1], None)
                made.append(path)
            except OSError as error:
                failed.append("%s, which the build made, cannot be given back: %s" % (os.fsdecode(path), error))
    # An entry of the grants that the walk did not reach: gone (the build may remove what it was given), or behind
    # what the build put in place of a directory, which give does not follow.
    for path, rest in granted.items():
        if path not in reached:
            give(path, rest, True)
    for p, *rest in record["closed"]:
        give(os.fsencode(p), rest, False)
    for path, rest in given:
        try:
            now = seen(info(path))
        except OSError as error:
            failed.append("%s cannot be read again: %s" % (os.fsdecode(path), error))
            continue
        if now != rest:
            failed.append("%s is not as it was before the build: mode, owner, group, device and inode %s, not %s"
                          % (os.fsdecode(path), now, rest))
    for path in made:
        try:
            now = seen(info(path))
        except OSError as error:
            failed.append("%s cannot be read again: %s" % (os.fsdecode(path), error))
            continue
        if now[1:3] != me:
            failed.append("%s, which the build made, is not root\x27s" % os.fsdecode(path))
    if failed:
        sys.exit("oft-py: " + "\noft-py: ".join(failed))'

# The program that prints one line `tree <path> <SHA-256>` for each tree, in one pass of a process pool. Argument 1 is
# the paths to leave out, one per line; argument 2 the directories to split, separated by spaces; argument 3 the paths
# whose content no link leads to (oft_py_fs_unfollowed), one per line; each argument after them is a tree, or, when it
# is a directory to split, the entries in it (but those left out), each split again when it is one of them. The lines
# of each argument are sorted by path. Then a line for what each symbolic link of those trees leads to (its path, with
# every link in it resolved) when that exists, is not in them (it is outside each tree, or under a path that is left
# out of the tree it is in), and is not under one of the paths of argument 3: a tree of its own, whose links are
# followed so too, with no path left out. Those lines come in the order that the links are found, each round of them
# sorted by path. A tree's SHA-256 is that of the sorted lines (as bytes) of a listing of it and of each entry under it
# but those left out, each line ending with a newline:
#   <path> d <mode> <uid>:<gid>                           a directory
#   <path> f <SHA-256 of its bytes> <mode> <uid>:<gid>    a regular file
#   <path> l '<path>' -> '<target>'                       a symbolic link, which it does not follow (stat's %n l %N)
#   <path> o <mode> <uid>:<gid>                           any other entry
# The mode is the permission bits in octal, as stat's %a writes them: the runtime's build runs as another user than the
# key (oft_py_hermetic), so which files it may read and run depends on them, and on the owner. A time is not keyed.
# A path or a target of printable ASCII other than \ and ' is written as it is (a link's in its quotes); any other is
# written $'...', with \\ for \, \' for ' and \xHH for each other byte that is not printable ASCII, so that each entry is
# one line and no two are written alike. The files of all the trees are hashed in one process pool, one process for
# each processor that this process may run on (but no more processes than files), each reading into one buffer of its
# own: with a new buffer for each read (hashlib.file_digest, or read()), the sysroot of the Python toolchain image took
# 5.2 s on one processor, against 2.4 s. For a tree whose paths and targets are all printable ASCII other than \ and ',
# the SHA-256 is that of the same listing made by find, sha256sum, stat and sort one file after another, as oft_py_tree
# was before (tests/test_python_prebuilt.py compares the two).
OFT_PY_TREE='import hashlib, multiprocessing, os, stat, sys
PRINTABLE = frozenset(range(0x20, 0x7f)) - {0x5c, 0x27}
def written(path, quote=b""):
    if all(c in PRINTABLE for c in path):
        return quote + path + quote
    return b"$\x27" + b"".join(b"\\\\" if c == 0x5c else b"\\\x27" if c == 0x27 else bytes((c,)) if c in PRINTABLE
                                else b"\\x%02x" % c for c in path) + b"\x27"
BUFFER = bytearray(1 << 18)
VIEW = memoryview(BUFFER)
def digest(path):
    sha = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while n := f.readinto(BUFFER):
            sha.update(VIEW[:n])
    return sha.hexdigest().encode()
def join(directory, name):
    return directory.rstrip(b"/") + b"/" + name
def under(path, directory):
    return path == directory or path.startswith(directory.rstrip(b"/") + b"/")
def walk(top, left_out, lines, files, index, links):
    pending = []
    def meta(info):
        return b" %o %d:%d" % (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
    def entry(path, info):
        if stat.S_ISDIR(info.st_mode):
            lines.append(written(path) + b" d" + meta(info))
            pending.append(path)
        elif stat.S_ISREG(info.st_mode):
            files.append((info.st_size, path, index, meta(info)))
        elif stat.S_ISLNK(info.st_mode):
            lines.append(written(path) + b" l " + written(path, b"\x27") + b" -> "
                         + written(os.readlink(path), b"\x27"))
            links.append(path)
        else:
            lines.append(written(path) + b" o" + meta(info))
    entry(top, os.lstat(top))
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for e in entries:
                path = join(directory, e.name)
                if path not in left_out:
                    entry(path, e.stat(follow_symlinks=False))
def main(left_out, split, own, tops):
    def expand(path):
        if path in split and stat.S_ISDIR(os.lstat(path).st_mode):
            with os.scandir(path) as entries:
                children = [join(path, e.name) for e in entries]
            for child in children:
                if child not in left_out:
                    yield from expand(child)
        else:
            yield path
    def inside(path):
        return any(under(path, top) and not any(under(path, out) and under(out, top) for out in left_out)
                   for top in tops)
    trees = [path for top in tops for path in sorted(expand(top))]
    listings, files, links = [[] for _ in trees], [], []
    for index, top in enumerate(trees):
        walk(top, left_out, listings[index], files, index, links)
    followed = set()
    while links:
        found = {target for target in map(os.path.realpath, links) if target not in followed
                 and os.path.lexists(target) and not inside(target) and not any(under(target, p) for p in own)}
        links = []
        for target in sorted(found):
            followed.add(target)
            trees.append(target)
            listings.append([])
            walk(target, set(), listings[-1], files, len(trees) - 1, links)
    files.sort(reverse=True)
    workers = min(len(os.sched_getaffinity(0)), len(files))
    if workers > 1:
        with multiprocessing.get_context("fork").Pool(workers) as pool:
            sums = pool.map(digest, [path for _, path, _, _ in files], chunksize=4)
    else:
        sums = [digest(path) for _, path, _, _ in files]
    for (_, path, index, meta), hexed in zip(files, sums):
        listings[index].append(written(path) + b" f " + hexed + meta)
    for top, lines in zip(trees, listings):
        sha = hashlib.sha256(b"".join(line + b"\n" for line in sorted(lines))).hexdigest().encode()
        sys.stdout.buffer.write(b"tree " + written(top) + b" " + sha + b"\n")
def paths(arg):
    return set(os.fsencode(arg).split(b"\n")) - {b""}
try:
    main(paths(sys.argv[1]), set(os.fsencode(sys.argv[2]).split()), paths(sys.argv[3]),
         [os.fsencode(top) for top in sys.argv[4:]])
except OSError as error:
    sys.exit("oft-py: a tree cannot be read: " + str(error))'

# The program that prints the `meta` lines of oft_py_runtime_inputs. Argument 1 is the file system's root (OFT_PY_FS);
# each argument after it, up to --shims, is a path: one line for it and for each directory above it up to the root,
# each once, sorted by path. After --shims, three arguments for each compiler shim: its name, the file that the build
# runs, and the file that holds its text. A mode and owner is the mode in octal and <uid>:<gid>, after `l` for a
# symbolic link (whose mode means nothing), or `missing`. A shim's line has the read and run bits alone of the file
# that runs, of the file that holds its text, and of the directory that holds that file ($SHIM, or $SHIM/.recorded
# behind a front, which no tree line holds): record-compile writes a front 0755 in a directory that it makes, and
# copies the shim there with its own mode, and whether the build may write either changes nothing that it reads (the
# inputs are read again after the build: oft_py_prebuilt_stage).
OFT_PY_META='import os, stat, sys
args = [os.fsencode(arg) for arg in sys.argv[1:]]
root = args[0].rstrip(b"/") or b"/"
end = args.index(b"--shims") if b"--shims" in args else len(args)
def under(path):
    return root == b"/" or path == root or path.startswith(root + b"/")
def meta(path, bits=0o7777):
    try:
        found = os.lstat(path)
    except FileNotFoundError:
        return b"missing"
    kind = b"l " if stat.S_ISLNK(found.st_mode) else b""
    return kind + b"%o %d:%d" % (stat.S_IMODE(found.st_mode) & bits, found.st_uid, found.st_gid)
found = set()
for path in args[1:end]:
    found.add(path)
    while path not in (b"/", root) and under(path):
        path = os.path.dirname(path)
        found.add(path)
out = sys.stdout.buffer
for path in sorted(found):
    out.write(b"meta " + path + b" " + meta(path) + b"\n")
shims = args[end + 1:]
for i in range(0, len(shims) - 2, 3):
    name, runs, text = shims[i:i + 3]
    out.write(b"meta shim " + name + b" " + meta(runs, 0o555) + b", its text " + meta(text, 0o555) + b" in "
              + meta(os.path.dirname(text), 0o555) + b"\n")'

oft_py_source() {
  [ ! -f "$OFT_PY_SRC/.oft-src-ok" ] || return 0
  [ -f "$OFT_PY_TARBALL" ] || { oft_py_fail "no $OFT_PY_TARBALL: this is not the Python toolchain image"; return 1; }
  [ "$(sha256sum "$OFT_PY_TARBALL" | cut -d' ' -f1)" = "$OFT_PY_TARBALL_SHA256" ] \
    || { oft_py_fail "$OFT_PY_TARBALL is not CPython 3.11.13's tarball"; return 1; }
  rm -rf "$OFT_PY_SRC"
  mkdir -p "$OFT_PY_SRC"
  tar -C "$OFT_PY_SRC" --strip-components=1 -xJf "$OFT_PY_TARBALL" || return 1
  # shellcheck disable=SC2086 # a list of patches
  "$OFT_PY_BPY" -I "$OFT_PY_DIR/patches/apply.py" "$OFT_PY_SRC" $OFT_PY_PATCHES || return 1
  : > "$OFT_PY_SRC/.oft-src-ok"
}

# oft_py_configure <command> [<word> ...]: run the command with configure's arguments for the runtime in $rt.
# oft_py_runtime runs configure so, in the runtime's environment, and oft_py_runtime_inputs prints the arguments so.
#
# A cross build, out of the source tree. The two ac_cv_file values are what configure asks for in a cross build; ipv6
# needs a run-time getaddrinfo probe that a cross build cannot run. CFLAGS are a library's, the runtime's define, and a
# prefix map that gives the build directory's own files one __FILE__ spelling.
oft_py_configure() {
  "$@" \
    --host="$CHOST" --build=x86_64-pc-linux-gnu \
    --with-build-python="$OFT_PY_BPY" --prefix="$OFT_PY_PREFIX" \
    --disable-shared --without-ensurepip --disable-test-modules --disable-ipv6 \
    ac_cv_file__dev_ptmx=no ac_cv_file__dev_ptc=no \
    CC="$CC" CFLAGS="$BASE_CFLAGS $SAN $OFT_PY_CPY_DEFS -fmacro-prefix-map=$rt/=$OFT_PY_FILE_MAP -fmacro-prefix-map=/src/repo${rt#/work}/=$OFT_PY_FILE_MAP" \
    CPPFLAGS= LDFLAGS=
}

# oft_py_file <path>: `file <path> <SHA-256 of its bytes>`, or `file <path> missing`.
oft_py_file() {
  if [ -f "$1" ]; then
    sum=$(sha256sum < "$1") || return 1
    echo "file $1 ${sum%% *}"
  else
    echo "file $1 missing"
  fi
}

# oft_py_fs <path> ...: each path, relative to OFT_PY_FS, as an absolute path, one per line.
oft_py_fs() {
  for p; do printf '%s\n' "${OFT_PY_FS%/}/$p"; done
}

# oft_py_fs_own: the paths that the read boundary (oft_py_boundary) leaves open, which every container gives its build
# and no image holds: the kernel's, and what the host mounts. The key reads none of them, and follows no link into them.
# The runtime's build reads the kernel's as every program does (/dev/null, /proc/self); closing a host's directory from
# a container could lock the host out of it. They are what Nix's sandbox, too, gives a build: the kernel's /proc and a
# few devices, and the build's output directory. The runtime's build takes no input from them: the key holds every name
# that it gets (the variables that it keeps, configure's arguments, and the bytes of each file that it reads), so a
# build whose key is that of a shipped runtime gets the names that the shipped one got, and none of them is under these
# paths. They are /proc, /sys and /dev; the mounts of compile_build (src/oss_verify/check_build.py): $OUT, and the base
# layout of a development build, which only OV_BASE_LAYOUT names (not kept); and Docker's init, which it mounts
# read-only. Two builds of the derived image on two machines, with their own hostnames, made the same bytes
# (INFRA-5359).
oft_py_fs_own() {
  oft_py_fs proc sys dev out ov-base-layout sbin/docker-init
}

# oft_py_fs_container: what Docker writes in each container, and so no image holds, which the read boundary closes:
# /run, its files of name lookups (a build with no network makes none), and its mark /.dockerenv. The key reads none of
# them, and follows no link into them.
oft_py_fs_container() {
  oft_py_fs run etc/hostname etc/hosts etc/resolv.conf .dockerenv
}

# oft_py_fs_unfollowed: the paths left out whose content the key reads through no link either: the container's own
# (oft_py_fs_own and oft_py_fs_container), and the Java keystore (oft_py_fs_left_out), to which the Java runtime's own
# keystore in /usr/lib/jvm is a link. Only Java reads it, through that link too, and the runtime's build runs no Java.
# The link itself is in its tree's line.
oft_py_fs_unfollowed() {
  oft_py_fs_own
  oft_py_fs_container
  oft_py_fs etc/ssl/certs/java/cacerts
}

# oft_py_fs_left_out: the paths of the file system that the key leaves out, one per line: the container's own, then
# each of the others for the reason above it, that the runtime's build reads nothing there: but for what it needs,
# which has a line of its own, the read boundary closes each of them, and those of oft_py_fs_container, to the build
# while it builds (oft_py_boundary). The manifest lists them (`excluded <path>`), so that an audit sees what the key
# does not cover.
oft_py_fs_left_out() {
  oft_py_fs_own
  oft_py_fs_container
  # compile's scratch, which it writes anew in each container: the driver's objects, the links' settings, and the
  # records, where the fronts of the compiler shims (record-compile) write those of the runtime's build.
  oft_py_fs tmp/ov
  # The project's own sources, and the neutral names that release-target.sh links to a target's directories. The
  # runtime's build reads its source tree through one of them, /src/repo, which has a line of its own.
  oft_py_fs src
  # The build's own trees. The runtime's source tree has a tree line of its own, and oft_py_runtime makes the runtime's
  # build directory anew.
  oft_py_fs work
  # Caches and temporary files: HOME and TMPDIR are in the runtime's build directory, which runs no pip and no apk.
  oft_py_fs root/.cache var/tmp var/cache
  # The shipped runtimes themselves, which only an image derived for them has, and which oft_py_shipped copies.
  oft_py_fs opt/oft-py/prebuilt
  # The builder's scripts, which change with python/recipes.sh. Those that the runtime's build runs, and the files it
  # reads, have file lines of their own: runtime.sh, patches/apply.py, the patches, Setup.local and record-compile; so
  # do release-target.sh and toolchain.sh, which write the compiler shims and their configuration, and compile.
  oft_py_fs usr/local/lib/oss-verify
  # The Java keystore, which each build of the builder writes anew (distrust-roots.py runs update-ca-certificates,
  # whose Java hook makes the store again), with other random salts each time: two builds of the builder from one
  # toolchain image gave other bytes for it, and no other file (INFRA-5359). Only Java reads it, and the runtime's
  # build runs no Java.
  oft_py_fs etc/ssl/certs/java/cacerts
}

# The install prefix of each target, /opt/oft/<target>: a symbolic link to its build directory under /work, which
# release-target.sh makes (oft_link_prefix) and which names the target, so that each project has others. The runtime's
# build reads no target's prefix. Each such link is left out of the tree of /opt/oft; the rest of /opt/oft, the
# toolchain's, is keyed. The manifest says so in this one line, the same for any target.
OFT_PY_PREFIX_LINKS='excluded /opt/oft/<target>, each link to a directory under /work (a target'"'"'s install prefix)'

# oft_py_prefix_links: the target prefixes of /opt/oft (above), one per line.
oft_py_prefix_links() {
  for e in /opt/oft/*; do
    if [ -L "$e" ]; then
      case $(readlink "$e") in /work/*) printf '%s\n' "$e" ;; esac
    fi
  done
}

# The names of the four compiler shims that release-target.sh writes in $SHIM for a target (ov_release_shims), and
# that name the targets of its layout. oft_py_shims compares them with the text that release-target.sh writes.
oft_py_shim_names() {
  for s in clang-plain clang++-plain clang-sealed clang++-sealed; do echo "$CHOST-$s"; done
}

# oft_py_shims: a line for each compiler shim of the release layout in $SHIM. When the shim is the text that
# ov_release_shims writes from the layout of this build's targets ($DEPS and $T, as ov_target_begin lays them out, in
# its LIBREL, build/lib/<flav>), with variables that ov_release_variables sets anew here, or, when compile records the
# build, the front that record-compile --front writes before that text (in $SHIM/.recorded): `shim <name> as
# release-target.sh writes it, for no target <SHA-256>`, the SHA-256 of the text that ov_release_shims writes, in this
# build's shell, for a layout of no target. That text holds all that the shim's text depends on but the targets'
# names: OV_PATH_REWRITE, which a build may set unexported, CHOST, and release-target.sh's code. A target's name gives
# only the path pairs of /work/build/lib/<flav>/<name>, /work/ext/<name>, /work/targets/<name> and /src/<name>,
# /src/vendor/<name>, /src/ext/<name>, /src/ext-vendor/<name>, /src/harness/<name>. When each name is plain (letters,
# digits and . _ + -, no slash, not . or ..), none of them is a prefix of a path of the runtime's build, whose trees
# are /work/build/pyrt/... and /src/repo/build/pyrt/... (release-target.sh refuses the name repo), so the line is the
# same for any plain target names, and with records or without. A shim of any other text, or of a layout with a name
# that is not plain, gives `shim <name> <SHA-256 of its text>` (or missing). Then `shim-extra .recorded/<name>
# <SHA-256>` for any other entry of $SHIM/.recorded. The rest of $SHIM, which toolchain.sh writes (the tool wrappers,
# the headers it adds, the link script), has a tree line. With no ov_release_variables (a build that did not source
# release-target.sh), it prints nothing, and the tree line keys the whole of $SHIM.
oft_py_shims() {
  command -v ov_release_variables > /dev/null 2>&1 || return 0
  d=$(mktemp -d) || return 1
  mkdir "$d/none" || { rm -rf "$d"; return 1; }
  # DEPS is the dependencies' names, one space between each (ov_target_begin), so a name has no space.
  case " ${DEPS:-} ${T:-} " in
    *[!A-Za-z0-9._+\ -]*|*" . "*|*" .. "*) plain=0 ;;
    *) plain=1 ;;
  esac
  # In subshells: the layout's variables and SHIM stay as they are, and ov_neutral makes no link (they are made).
  # shellcheck disable=SC2086,SC2329,SC2034 # DEPS is the list of the dependencies' names, as ov_target_begin sets it;
  # the ov_neutral and the LIBREL of the subshell are the ones that ov_release_variables reads
  if [ "$plain" = 1 ]; then
    ( ov_neutral() { :; }; LIBREL=build/lib/$FLAV; ov_release_variables ${DEPS:-} ${T:+"$T"} &&
      ov_release_shims "$d" ) || { rm -rf "$d"; return 1; }
  fi
  # shellcheck disable=SC2329 # as above
  ( ov_neutral() { :; }; ov_release_variables && ov_release_shims "$d/none" ) || { rm -rf "$d"; return 1; }
  self=/usr/local/lib/oss-verify/record-compile
  self=$(readlink -f "$self" 2> /dev/null) || self=/usr/local/lib/oss-verify/record-compile
  for n in $(oft_py_shim_names); do
    s=$SHIM/$n
    none=$(sha256sum < "$d/none/$n") || { rm -rf "$d"; return 1; }
    if [ -f "$s" ] && [ "$(sed -n 2p "$s")" = "# record-compile front" ]; then
      printf '#!/bin/sh\n# record-compile front\nexec %s %s %s "$@"\n' "$self" "${OV_RECORDS:-}" "$SHIM/.recorded/$n" \
        > "$d/.front"
      if cmp -s "$s" "$d/.front" && cmp -s "$SHIM/.recorded/$n" "$d/$n"; then
        echo "shim $n as release-target.sh writes it, for no target ${none%% *}"; continue
      fi
      sum=$(cat "$s" "$SHIM/.recorded/$n" 2> /dev/null | sha256sum) || { rm -rf "$d"; return 1; }
      echo "shim $n ${sum%% *} (a front)"
    elif [ -f "$s" ] && cmp -s "$s" "$d/$n"; then
      echo "shim $n as release-target.sh writes it, for no target ${none%% *}"
    elif [ -f "$s" ]; then
      sum=$(sha256sum < "$s") || { rm -rf "$d"; return 1; }
      echo "shim $n ${sum%% *}"
    else
      echo "shim $n missing"
    fi
  done
  rm -rf "$d"
  if [ -d "$SHIM/.recorded" ]; then
    for e in "$SHIM/.recorded"/* "$SHIM/.recorded"/.[!.]*; do
      [ -e "$e" ] || [ -L "$e" ] || continue
      case " $(oft_py_shim_names | tr '\n' ' ') " in *" ${e##*/} "*) continue ;; esac
      if [ -f "$e" ] && [ ! -L "$e" ]; then
        sum=$(sha256sum < "$e") || return 1
        echo "shim-extra .recorded/${e##*/} ${sum%% *}"
      else
        if [ -L "$e" ]; then
          echo "shim-extra .recorded/${e##*/} link -> $(readlink "$e")"
        else
          echo "shim-extra .recorded/${e##*/} not a file"
        fi
      fi
    done
  fi
}

# oft_py_repo_link: the neutral name /src/repo, through which the runtime's build runs configure and the shims give its
# compiles their paths (/src/repo/build/pyrt/... for /work/build/pyrt/...): `link /src/repo -> <its target>`, or, when
# it is no symbolic link, a tree of it (OFT_PY_REPO_TREE), or `link /src/repo missing`.
oft_py_repo_link() {
  OFT_PY_REPO_TREE=""
  r=/src/repo
  if [ -L "$r" ]; then
    echo "link $r -> $(readlink "$r")"
  elif [ -e "$r" ]; then
    echo "link $r is no symbolic link: a tree line keys it"
    OFT_PY_REPO_TREE=$r
  else
    echo "link $r missing"
  fi
}

# oft_py_clock: the time since the machine started, in hundredths of a second (/proc/uptime), else, with no
# /proc/uptime, the time in whole seconds (date), in hundredths. oft_py_shipped measures the key with it.
oft_py_clock() {
  if read -r up _ 2> /dev/null < /proc/uptime; then
    echo $(( ${up%.*} * 100 + 1${up#*.} - 100 ))
  else
    echo $(( $(date +%s) * 100 ))
  fi
}

# oft_py_runtime_inputs: the inputs of this build's runtime, one per line, in this order:
#   flav <FLAV>
#   configure <argument>        each argument of configure (oft_py_configure)
#   make <target>               each target of make
#   env <NAME>=<value>          the runtime's environment (oft_py_hermetic), sorted by name
#   user <user>                 the user that the runtime's build runs as
#   file <path> <SHA-256>       the tarball, the patches, Setup.local, the native Python, and the scripts that the
#                               runtime's build runs, or that write what it reads: this file, patches/apply.py,
#                               release-target.sh (the compiler shims), toolchain.sh (the build's flags, and the
#                               headers and the sealed configuration that the shims give the compilers), compile, and
#                               record-compile (the records)
#   packages <SHA-256>          of the package database, /lib/apk/db/installed, when there is one
#   meta <path> <mode> <uid>:<gid>
#                               the mode and owner of each file above, of each directory above them, above the patched
#                               source tree, /src/repo and $SHIM, and of / and the directories that the tree lines
#                               split (OFT_PY_META): what the runtime's user may read, run and reach, which the tree
#                               lines do not say for these. Then, for each compiler shim, `meta shim <name> <mode and
#                               owner of the file that the build runs>, its text <of the file that holds its text>`:
#                               the shim itself, or, behind a front, the front and its copy in $SHIM/.recorded
#   excluded <path>             each path that the trees below leave out (oft_py_fs_left_out), then one line for the
#                               targets' install prefixes (OFT_PY_PREFIX_LINKS)
#   shim <name> ...             each compiler shim that release-target.sh writes in $SHIM (oft_py_shims)
#   link /src/repo ...          the neutral name through which the build reads its source tree (oft_py_repo_link)
#   tree <path> <SHA-256>       the patched source tree, then each entry of / and of /usr, /opt, /var and /tmp (where
#                               $SHIM is), sorted by path, by content (OFT_PY_TREE), but the paths left out; then what
#                               a link of those trees leads to outside them
# The lines that name one file come first, so that the first line that differs names it; a tree line names a directory
# of / otherwise. The same function prints them where the runtime is made (oft_py_prebuilt_stage) and where it is used
# (oft_py_shipped), after oft_py_source. It fails when a line cannot be printed.
# The runtime's build runs in a shell of its own, which reads this file again: what it runs is what the file says. The
# key reads release-target.sh and the other scripts by their bytes too, and assumes that the build's shell runs their
# functions as those files define them, where the key runs them (oft_py_configure, and ov_release_variables in
# oft_py_shims): a build.sh that defines one of them again, after it sources them, is not seen (the shell cannot print a
# function's body).
oft_py_runtime_inputs() {
  rt=/work/build/pyrt/$FLAV
  echo "flav $FLAV"
  oft_py_configure "$OFT_PY_BPY" -I -S -c "$OFT_PY_LINES" configure || return 1
  # shellcheck disable=SC2086 # a list of targets
  "$OFT_PY_BPY" -I -S -c "$OFT_PY_LINES" make $OFT_PY_RT_TARGETS || return 1
  oft_py_hermetic || return 1
  oft_py_file "$OFT_PY_TARBALL" || return 1
  files="$OFT_PY_TARBALL $OFT_PY_PATCHES $OFT_PY_DIR/Setup.local $OFT_PY_BPY $OFT_PY_DIR/runtime.sh
$OFT_PY_DIR/patches/apply.py /usr/local/lib/oss-verify/release-target.sh /usr/local/lib/oss-verify/toolchain.sh
/usr/local/bin/compile /usr/local/lib/oss-verify/record-compile"
  for p in $files; do
    [ "$p" = "$OFT_PY_TARBALL" ] || oft_py_file "$p" || return 1
  done
  if [ -f /lib/apk/db/installed ]; then
    p=$(sha256sum < /lib/apk/db/installed) || return 1
    echo "packages ${p%% *}"
  fi
  set -- --shims
  if [ -n "${SHIM:-}" ] && command -v ov_release_variables > /dev/null 2>&1; then
    for n in $(oft_py_shim_names); do
      if [ -f "$SHIM/$n" ] && [ "$(sed -n 2p "$SHIM/$n")" = "# record-compile front" ]; then
        set -- "$@" "$n" "$SHIM/$n" "$SHIM/.recorded/$n"
      else
        set -- "$@" "$n" "$SHIM/$n" "$SHIM/$n"
      fi
    done
  fi
  split=$OFT_PY_FS
  for p in $OFT_PY_FS_SPLIT; do split="$split $(oft_py_fs "$p")"; done
  # shellcheck disable=SC2086 # lists of paths
  "$OFT_PY_BPY" -I -S -c "$OFT_PY_META" "$OFT_PY_FS" $files "$OFT_PY_SRC" /src/repo ${SHIM:+"$SHIM"} $split "$@" \
    || return 1
  left=$(oft_py_fs_left_out)
  for p in $left; do echo "excluded $p"; done
  echo "$OFT_PY_PREFIX_LINKS"
  oft_py_shims || return 1
  oft_py_repo_link
  left="$left
$(oft_py_prefix_links)"
  # The shims that oft_py_shims compared, and record-compile's copies of them.
  if [ -n "${SHIM:-}" ] && command -v ov_release_variables > /dev/null 2>&1; then
    left="$left
$(oft_py_shim_names | sed "s|^|$SHIM/|")
$SHIM/.recorded"
  fi
  set -- "$OFT_PY_SRC"
  if [ -n "$OFT_PY_REPO_TREE" ]; then set -- "$@" "$OFT_PY_REPO_TREE"; fi
  "$OFT_PY_BPY" -I -S -c "$OFT_PY_TREE" "$left" "$split" "$(oft_py_fs_unfollowed)" "$@" "$OFT_PY_FS" || return 1
}

# oft_py_hermetic [<command> [<word> ...]]: run the command in the runtime's environment (OFT_PY_HERMETIC): from the
# runtime's build directory $rt, with the variables of OFT_PY_ENV_KEPT as this build has them, PATH=$OFT_PY_PATH, HOME
# and TMPDIR in $rt, CONFIG_SITE empty, PYTHONNOUSERSITE=1 and PYTHONDONTWRITEBYTECODE=1, and no other variable, as the
# user OFT_PY_UID when this runs as root. With no command, print that environment and the user.
oft_py_hermetic() {
  user=$(id -u) || return 1
  [ "$user" != 0 ] || user=$OFT_PY_UID
  if [ $# -gt 0 ]; then set -- -- "$@"; fi
  "$OFT_PY_BPY" -I -S -c "$OFT_PY_HERMETIC" "$rt" "$user" "$OFT_PY_ENV_KEPT" "PATH=$OFT_PY_PATH" "HOME=$rt/.home" \
    "TMPDIR=$rt/.tmp" CONFIG_SITE= PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 "$@"
}

# oft_py_tree_of <path>: the tree line of <path> alone, with nothing left out (OFT_PY_TREE).
oft_py_tree_of() {
  "$OFT_PY_BPY" -I -S -c "$OFT_PY_TREE" "" "" "" "$1"
}

# oft_py_runtime_manifest <file>: write this build's manifest to <file>: the lines of oft_py_runtime_inputs, then
# `key <the SHA-256 of those lines>`. OFT_PY_KEY is the key. The inputs are read in a subshell with the runtime's PATH
# and LC_ALL=C, so that the tools that read them are the ones that the runtime's build finds.
oft_py_runtime_manifest() {
  if ! ( PATH=$OFT_PY_PATH LC_ALL=C; export PATH LC_ALL; oft_py_runtime_inputs ) > "$1.inputs"; then
    rm -f "$1.inputs"
    oft_py_fail "the inputs of the $FLAV runtime cannot be read"; return 1
  fi
  OFT_PY_KEY=$(sha256sum < "$1.inputs" | cut -d' ' -f1)
  { cat "$1.inputs" && echo "key $OFT_PY_KEY"; } > "$1" && rm -f "$1.inputs"
}

# oft_py_difference <shipped manifest> <this build's manifest>: `built with <line>, this build has <line>`: the first
# line, up to the key, where the two differ, a line that one has and the other has not as `nothing`. The shipped
# manifest's lines after its key (made-from) are not compared.
oft_py_difference() {
  awk 'BEGIN { here = ARGV[2]; ARGV[2] = "" }
    { shipped[++s] = $0; if ($0 ~ /^key /) exit }
    END {
      while ((getline line < here) > 0) mine[++m] = line
      for (i = 1; i <= s || i <= m; i++) {
        a = i <= s ? shipped[i] : "nothing"
        b = i <= m ? mine[i] : "nothing"
        if (a != b) { print "built with " a ", this build has " b; exit }
      }
      # The same lines, in other bytes: a line end, or a NUL, that awk does not see.
      print "built with these lines in other bytes, this build has the same lines"
    }' "$1" "$2"
}

# oft_py_shipped: the key of this build's inputs (/work/build/pyrt/<flav>.manifest), and how long it took, in one line:
#     oft-py: runtime <flav>: key <its first 12 hex digits> in <seconds, to a tenth> s
# or, when the inputs cannot be read, `oft-py: runtime <flav>: no key, in <seconds> s: ...`. Then, when the toolchain
# image ships the runtime of this key, take it into $rt (OFT_PY_TOOK=1), with its records when the build records its
# compiles. Else say why this build compiles its own: its inputs cannot be read, the image ships none for this build, or
# the first input where its own differs (OFT_PY_TOOK empty). The image's runtime is taken only when its manifest, up to
# its key, is this build's, byte for byte. Every build computes the key, so that a build on any toolchain image says
# what the key costs. This fails only when the runtime of this key is not whole.
oft_py_shipped() {
  OFT_PY_TOOK=""
  m=$rt.manifest
  k0=$(oft_py_clock)
  if ! oft_py_runtime_manifest "$m"; then
    k0=$(( ($(oft_py_clock) - k0 + 5) / 10 ))
    rm -f "$m"
    echo "oft-py: runtime $FLAV: no key, in $((k0 / 10)).$((k0 % 10)) s: the inputs of this build cannot be read"
    echo "oft-py: runtime $FLAV: built here: the inputs of this build cannot be read (oft_py_runtime_inputs failed)"
    return 0
  fi
  k0=$(( ($(oft_py_clock) - k0 + 5) / 10 ))
  echo "oft-py: runtime $FLAV: key $(printf %.12s "$OFT_PY_KEY") in $((k0 / 10)).$((k0 % 10)) s"
  shipped=""
  for d in "$OFT_PY_PREBUILT/$FLAV"-*; do
    if [ -d "$d" ]; then shipped=$d; break; fi
  done
  if [ -z "$shipped" ]; then
    echo "oft-py: runtime $FLAV: built here: this toolchain image ships no prebuilt runtime ($OFT_PY_PREBUILT/$FLAV-*)"
    return 0
  fi
  d=$OFT_PY_PREBUILT/$FLAV-$OFT_PY_KEY
  if [ -f "$d/manifest" ] && head -n "$(($(wc -l < "$m")))" "$d/manifest" | cmp -s - "$m"; then
    rm -rf "$rt"
    if ! { mkdir -p "$rt" && cp -R "$d/runtime/." "$rt/"; }; then
      oft_py_fail "cannot copy $d/runtime to $rt"; return 1
    fi
    for f in $OFT_PY_RT_FILES; do
      [ -s "$rt/$f" ] || { oft_py_fail "the shipped runtime $d has no $f"; return 1; }
    done
    # The records, when compile records the build's compiles (OV_RECORD=1): the runtime's compile records as one file,
    # under a name that no record of record-compile has (mktemp's ten letters and digits), which compile gathers into
    # $OUT/.records/compiles.jsonl with the build's own, and the objects without their sources' no_sanitize attributes
    # that they name.
    if [ -n "${OV_RECORDS:-}" ]; then
      [ -f "$d/records/compiles.jsonl" ] || { oft_py_fail "the shipped runtime $d has no records"; return 1; }
      if ! { mkdir -p "$OV_RECORDS/compiles" \
             && cp "$d/records/compiles.jsonl" "$OV_RECORDS/compiles/oft-py-runtime-$FLAV.jsonl"; }; then
        oft_py_fail "cannot copy the records of $d to $OV_RECORDS"; return 1
      fi
      if [ -d "$d/records/nosan" ] && ! { mkdir -p "$OV_RECORDS/nosan" \
                                          && cp -R "$d/records/nosan/." "$OV_RECORDS/nosan/"; }; then
        oft_py_fail "cannot copy the records of $d to $OV_RECORDS"; return 1
      fi
    fi
    : > "$rt/.oft-built"
    OFT_PY_TOOK=1
    echo "oft-py: runtime $FLAV: took the shipped runtime ($d); ran no CPython configure or make"
    return 0
  fi
  [ -f "$d/manifest" ] || d=$shipped
  echo "oft-py: runtime $FLAV: built here: the shipped runtime was $(oft_py_difference "$d/manifest" "$m") ($d/manifest)"
}

# oft_py_boundary close <state> | open <state>: the runtime's read boundary (OFT_PY_BOUNDARY), which oft_py_runtime takes
# as root around the runtime's build alone. close gives the runtime's user the new build directory $rt and compile's
# records directory, and takes the access of its group and of others off each path that the key leaves out but the
# container's own (oft_py_fs_left_out, but oft_py_fs_own): so the build can read nothing there, though a value that
# it gets names it. It keeps what the build reads there: the patched source tree, through /src/repo, its build
# directory, the records directory, runtime.sh, which its shell reads again, and record-compile, which the shims'
# fronts run. open gives it all back, and fails unless each entry is as it was.
oft_py_boundary() {
  if [ "$1" = close ]; then
    rm -f "$2"
    own=$(oft_py_fs_own)
    self=$(readlink -f /usr/local/lib/oss-verify/record-compile 2> /dev/null) || self=/usr/local/lib/oss-verify/record-compile
    "$OFT_PY_BPY" -I -S -c "$OFT_PY_BOUNDARY" close "$2" "$OFT_PY_UID" "$rt
${OV_RECORDS:-}" "$(oft_py_fs_left_out | grep -vxF "$own")" "$OFT_PY_SRC
$rt
${OV_RECORDS:-}
/src/repo
$OFT_PY_DIR/runtime.sh
$self"
  else
    # close writes the state before it changes anything: with none, it changed nothing.
    [ -f "$2" ] || return 0
    "$OFT_PY_BPY" -I -S -c "$OFT_PY_BOUNDARY" open "$2" && rm -f "$2"
  fi
}

# oft_py_runtime: the build's libpython3.11.a, in /work/build/pyrt/<flav>, made once in a container: taken from the
# toolchain image when it ships the runtime of this build's inputs (oft_py_shipped), else built here, in the runtime's
# environment (oft_py_hermetic, oft_py_build_here). In a build that runs as root, the build runs as the runtime's user,
# behind the read boundary (oft_py_boundary), which a trap gives back on every way out of the subshell that took it; a
# boundary that cannot be given back as it was fails the build. It fails when the build changed the patched source
# tree.
oft_py_runtime() {
  oft_py_source || return 1
  rt=/work/build/pyrt/$FLAV
  if [ ! -f "$rt/.oft-built" ]; then
    oft_py_shipped || return 1
    if [ -n "$OFT_PY_TOOK" ]; then OFT_PY_RT=$rt; return 0; fi
    rm -rf "$rt"
    mkdir -p "$rt/Modules" "$rt/.home" "$rt/.tmp"
    cp "$OFT_PY_DIR/Setup.local" "$rt/Modules/Setup.local"
    src=$(oft_py_tree_of "$OFT_PY_SRC") || return 1
    t0=$(date +%s)
    if [ "$(id -u)" = 0 ]; then
      ( b=$rt.boundary
        trap 'oft_py_boundary open "$b" || { oft_py_fail "the read boundary cannot be given back ($b)"; exit 3; }' EXIT
        trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
        oft_py_boundary close "$b" || { oft_py_fail "the read boundary cannot be taken"; exit 1; }
        oft_py_configure oft_py_hermetic /bin/sh -c "$OFT_PY_BUILD" sh "$OFT_PY_DIR/runtime.sh" "$(oft_jobs)"
      ) || return 1
    else
      oft_py_configure oft_py_hermetic /bin/sh -c "$OFT_PY_BUILD" sh "$OFT_PY_DIR/runtime.sh" "$(oft_jobs)" || return 1
    fi
    [ "$(oft_py_tree_of "$OFT_PY_SRC")" = "$src" ] \
      || { oft_py_fail "the runtime's build changed the patched source tree $OFT_PY_SRC"; return 1; }
    if [ ! -s "$rt/target-builtins.txt" ] || [ ! -s "$rt/target-frozen.txt" ]; then
      oft_py_fail "empty inittab or frozen list for $rt"; return 1
    fi
    for a in $OFT_PY_RT_TARGETS; do
      [ -s "$rt/$a" ] || { oft_py_fail "the runtime build made no $a"; return 1; }
    done
    echo "oft-py: runtime $FLAV built in $(( $(date +%s) - t0 )) s ($(wc -l < "$rt/target-builtins.txt") builtin modules)"
    : > "$rt/.oft-built"
  else
    echo "oft-py: runtime $FLAV built already ($rt)"
  fi
  OFT_PY_RT=$rt
}

# oft_py_build_here <jobs> <configure argument> ...: the runtime's build, from its build directory, in the runtime's
# environment (oft_py_runtime runs it so, in a shell that reads this file again): configure, through the path that the
# compiler shims give the source tree (/src/repo/... for /work/...), which it records; make, with <jobs> jobs; and the
# lists that the rest of a build reads beside the archives: what the static program links besides libpython (the
# Makefile's own answer), the target's builtin modules (the cross build's inittab), and CPython's own frozen modules.
oft_py_build_here() {
  jobs=$1
  shift
  if ! "/src/repo${OFT_PY_SRC#/work}/configure" "$@" > configure.log 2>&1; then
    tail -40 configure.log >&2
    [ ! -f config.log ] || { echo "oft-py: the end of config.log:"; tail -20 config.log; } >&2
    return 1
  fi
  # shellcheck disable=SC2086 # a list of targets
  if ! make -j"$jobs" $OFT_PY_RT_TARGETS > make.log 2>&1; then
    grep -n -m20 -E 'error|Error' make.log >&2; tail -30 make.log >&2; return 1
  fi
  # shellcheck disable=SC2016 # the make rule's own $($*)
  printf 'print-%%:\n\t@echo $($*)\n' > oft-print.mk
  for v in LIBS MODLIBS SYSLIBS OPT; do
    printf '%s=' "$v"
    make -s -f Makefile -f oft-print.mk "print-$v" || return 1
  done > oft-linkvars.txt
  { sed -n 's/^ *{"\([A-Za-z0-9_]*\)", *[A-Za-z0-9_]*},.*/\1/p' Modules/config.c
    printf '%s\n' marshal _imp _ast _tokenize builtins sys gc _warnings _string __main__; } | sort -u > target-builtins.txt
  "$OFT_PY_BPY" -I -c 'import _imp; print("\n".join(_imp._frozen_module_names()))' | sort -u > target-frozen.txt
}

# oft_py_prebuilt_stage <dir>: for .github/scripts/python-runtime/make, after oft_py_runtime built the runtime here (a
# runtime taken from the image is refused): the runtime's files in <dir>/runtime/, and in <dir>/manifest the manifest
# that oft_py_runtime wrote before the build, which is where a build that uses the runtime computes its own. It fails
# when the inputs read again now differ from those, the patched source tree among them: a build whose inputs change as
# it runs could never take the runtime. The make script adds the records, and the manifest's made-from line.
oft_py_prebuilt_stage() {
  if [ -z "${OFT_PY_RT:-}" ] || [ ! -f "$OFT_PY_RT/.oft-built" ] || [ ! -f "$OFT_PY_RT/configure.log" ]; then
    oft_py_fail "oft_py_prebuilt_stage: no runtime built here (run oft_py_runtime first, in an image that ships none)"
    return 1
  fi
  if [ ! -f "$OFT_PY_RT.manifest" ]; then
    oft_py_fail "oft_py_prebuilt_stage: oft_py_runtime could not read the inputs ($OFT_PY_RT.manifest)"; return 1
  fi
  for f in $OFT_PY_RT_FILES; do
    case "$f" in */*) mkdir -p "$1/runtime/${f%/*}" || return 1 ;; *) mkdir -p "$1/runtime" || return 1 ;; esac
    cp "$OFT_PY_RT/$f" "$1/runtime/$f" || return 1
  done
  oft_py_runtime_manifest "$1/manifest.now" || return 1
  for m in "$OFT_PY_RT.manifest" "$1/manifest.now"; do
    sed '/^key /d' "$m" > "$m.read-again" || return 1
  done
  if ! cmp -s "$OFT_PY_RT.manifest.read-again" "$1/manifest.now.read-again"; then
    oft_py_fail "oft_py_prebuilt_stage: the inputs of the $FLAV runtime changed while it was built: it was" \
      "$(oft_py_difference "$OFT_PY_RT.manifest.read-again" "$1/manifest.now.read-again")"
    return 1
  fi
  rm -f "$1/manifest.now" "$1/manifest.now.read-again" "$OFT_PY_RT.manifest.read-again" \
    && cp "$OFT_PY_RT.manifest" "$1/manifest"
}
