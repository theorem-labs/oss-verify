#!/usr/bin/env python3
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: the steps of an OSS Verify build (resolve the ref, build the builder and the
# project image, compile each build with no network, list the image's git checkouts) in place of the scanner's. The
# virtual machine backend is not ported.
"""The build steps of tools/check: resolve the commit, build the images, compile each build with no network.

tools/check imports this module; it is not run on its own.
"""
import codecs
import dataclasses
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILDER_DIR = ROOT / "infra" / "base-builder"
CACHE = pathlib.Path(os.environ.get("XDG_CACHE_HOME") or "~/.cache").expanduser() / "oss-verify-check"
FULL_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
TOOLCHAIN_ARG = re.compile(r"^ARG TOOLCHAIN=(\S+)$", re.M)
TOOLCHAINS = ROOT / "infra" / "toolchains.tsv"
# How a toolchain's UBSan builds choose their checks: the release's fixed flags, or the project's ubsan_checks.
UBSAN_MODES = ("fixed", "checks")
# In a tools/check work directory: the tags of the project images that run built, one a line (record_image).
IMAGES = "images"
# The label on every container a tools/check run starts: its work directory (work_label).
WORK_LABEL = "oss-verify-check.work"
# The git checkouts under $SRC in a project image, and their commits, for the manifest.
LIST_SOURCES = (
    'find "$SRC" -maxdepth 4 -name .git 2>/dev/null | sort | while read -r g; do d=${g%/.git}; '
    'c=$(git -C "$d" rev-parse HEAD 2>/dev/null) && printf "%s %s\\n" "$d" "$c"; done'
)


class Failed(Exception):
    """The build failed. The message says which step failed and why."""


@dataclasses.dataclass
class Job:
    """One project's build settings, from its project.yaml and the command line."""

    name: str
    directory: pathlib.Path  # projects/<name>
    repo: str  # without the #ref
    ref: str  # branch, tag or commit; "" means the repository's default branch
    dockerfile: str  # path in the repository; "" if it is kept next to project.yaml
    builds: list
    fuzz_targets: list | None  # None: every fuzz target the build produces
    ubsan_checks: list | None = None  # the UBSan checks in effect if the project changes them; None: the default
    language: str = "c"  # project.yaml's language, which chooses the toolchain


_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def terminal_safe(text):
    """Text from the project (its commits, its build output) for the terminal: control characters other than tab, newline
    and carriage return (escape sequences, BEL, ...) are shown as \\xNN, never sent raw."""
    return _UNSAFE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def say(text=""):
    """Print a line and flush right away, so output stays in order with subprocess output. Everything goes through
    terminal_safe(): much of what is printed (names, URLs, logs) comes from the project."""
    print(terminal_safe(str(text)), flush=True)


def step(text):
    """Print a timestamped heading for the next build step."""
    say(f"\n[{time.strftime('%H:%M:%S')}] {text}")


def run(*argv, quiet=False):
    """Run a command and return its exit code.

    `quiet` hides its output. Otherwise its output (the project's build, its git server's messages) reaches the
    terminal through terminal_safe(), never raw. The command never reads what was piped into tools/check.
    """
    if quiet:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def copy():
        decode = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while chunk := os.read(proc.stdout.fileno(), 65536):
            sys.stdout.write(terminal_safe(decode.decode(chunk)))
            sys.stdout.flush()

    reader = threading.Thread(target=copy, daemon=True)
    reader.start()
    code = proc.wait()
    reader.join(timeout=5)
    proc.stdout.close()
    return code


def output(*argv):
    """Run a command quietly and return its standard output, or raise Failed with its error output."""
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
    if done.returncode != 0:
        raise Failed(f"{' '.join(argv[:3])} ... exited {done.returncode}: {done.stderr.strip()[-1500:]}")
    return done.stdout


def git(*args):
    """git, anonymous and over https only, even if a URL or a server redirect asks for another protocol."""
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    return ["git", "-c", "credential.helper=", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args]


def resolve(repo, ref):
    """The full commit id that `repo#ref` names now: a branch, a tag (annotated tags are followed to their commit), a
    full commit id (taken as it is), or "" for the default branch."""
    if FULL_COMMIT.fullmatch(ref):
        return ref
    if ref.startswith("refs/"):
        names = [ref, f"{ref}^{{}}"]
    else:
        names = [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"]
    listing = output(*git("ls-remote", "--", repo, *(names if ref else ["HEAD"])))
    refs = dict(reversed(line.split("\t", 1)) for line in listing.splitlines() if "\t" in line)
    if not ref:
        found = {refs["HEAD"]} if "HEAD" in refs else set()
    elif ref.startswith("refs/"):
        # A qualified annotated tag names a tag object; use its peeled commit.
        commit = refs.get(f"{ref}^{{}}") or refs.get(ref)
        found = {commit} if commit else set()
    else:
        tag = refs.get(f"refs/tags/{ref}^{{}}") or refs.get(f"refs/tags/{ref}")
        found = {commit for commit in (refs.get(f"refs/heads/{ref}"), tag, refs.get(ref)) if commit}
    if len(found) > 1:
        raise Failed(f"#{ref} is both a branch and a tag of {repo}, at different commits: name a commit instead")
    if not found:
        raise Failed(f"{repo} has no branch or tag {ref!r}" if ref else f"{repo} has no default branch")
    return found.pop()


def clone(repo, commit, checkout):
    """Check out `repo` at `commit` into `checkout`, anonymously, over https."""
    shutil.rmtree(checkout, ignore_errors=True)
    checkout.mkdir(parents=True)
    for args in (["init", "-q", str(checkout)], ["-C", str(checkout), "fetch", "-q", "--depth", "1", "--", repo, commit],
                 ["-C", str(checkout), "checkout", "-q", "--detach", "FETCH_HEAD"]):
        if run(*git(*args)) != 0:
            raise Failed(f"cannot fetch {commit} from {repo}")


def in_checkout(checkout, path):
    """Return checkout/path. Raise Failed if a symbolic link makes it point outside the checkout."""
    if not (checkout / path).resolve().is_relative_to(checkout.resolve()):
        raise Failed(f"{path} resolves to a place outside the repository and is not used")
    return checkout / path


def tree_hash(directory):
    """A hash of every file under `directory` (less Python's bytecode caches): its relative path, its mode and its
    bytes."""
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file() and "__pycache__" not in path.relative_to(directory).parts:
            digest.update(f"{path.relative_to(directory)}\0{path.stat().st_mode & 0o111:o}\0".encode())
            digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def toolchain():
    """The toolchain image infra/base-builder/Dockerfile builds FROM when given none (its ARG TOOLCHAIN default)."""
    match = TOOLCHAIN_ARG.search((BUILDER_DIR / "Dockerfile").read_text(encoding="utf-8"))
    if not match:
        raise Failed("infra/base-builder/Dockerfile pins no toolchain (ARG TOOLCHAIN=...)")
    return match.group(1)


def toolchains():
    """The toolchain images a project can be built with, oldest first (infra/toolchains.tsv): [(name, image, ubsan,
    languages)]. ubsan is how the UBSan builds choose their checks: "fixed" (the release's flags) or "checks"
    (ubsan_checks). languages are the values of project.yaml's language that the image builds."""
    rows = [line.split("\t") for line in TOOLCHAINS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]
    if not rows or any(len(row) < 4 or row[2] not in UBSAN_MODES or not row[3] for row in rows):
        raise Failed(f"{TOOLCHAINS} lists no toolchain, or a row has no image, no ubsan of {', '.join(UBSAN_MODES)} "
                     "or no languages")
    return [(row[0], row[1], row[2], tuple(row[3].split(","))) for row in rows]


def ubsan_mode(image):
    """How the UBSan builds on this toolchain image choose their checks: as its row says, or "fixed" for an image
    that infra/toolchains.tsv does not list."""
    return next((mode for _, listed, mode, _ in toolchains() if listed == image), "fixed")


def languages_of(image):
    """The languages that a toolchain image builds, as its row says, or None for an image that infra/toolchains.tsv
    does not list."""
    return next((languages for _, listed, _, languages in toolchains() if listed == image), None)


def newest_toolchain(language="c"):
    """The newest toolchain image for a language: the last row of infra/toolchains.tsv that lists it."""
    images = [image for _, image, _, languages in toolchains() if language in languages]
    if not images:
        raise Failed(f"{TOOLCHAINS} lists no toolchain for {language}")
    return images[-1]


def toolchain_id(image):
    """A short name for a toolchain image, for a builder's tag: the start of its digest, or its name made tag-safe."""
    digest = image.partition("@sha256:")[2]
    return digest[:12] if digest else re.sub(r"[^A-Za-z0-9_.-]", "-", image)[-40:]


def image_id(tag):
    """The local id of an image."""
    return output("docker", "image", "inspect", "--format", "{{.Id}}", tag).strip()


def require_buildkit():
    """Refuse to start when `docker build` refuses `--progress=plain`, which tools/check gives each build. Docker 23 and
    later refuse it with the legacy builder: without the buildx plugin (Ubuntu's docker.io package alone), or with
    DOCKER_BUILDKIT set to a false value. The probe asks for the help text, so it builds nothing."""
    if run("docker", "build", "--progress=plain", "--help", quiet=True) != 0:
        raise Failed("tools/check needs Docker with BuildKit, and `docker build --progress=plain --help` fails. "
                     "Install the buildx plugin (on Ubuntu, `apt install docker-buildx`; from Docker's own "
                     "repository, `docker-buildx-plugin`), unset DOCKER_BUILDKIT, then run tools/check again.")


def build_builder(image=None, suffix="", no_cache=False):
    """Build the builder image from infra/base-builder, FROM the toolchain `image` (the newest for C if None). Return
    its tag."""
    image = image or newest_toolchain()
    tag = f"oss-verify-base-builder:{tree_hash(BUILDER_DIR)[:16]}-{toolchain_id(image)}{suffix}"
    require_buildkit()
    step(f"docker build: the builder ({tag}), FROM {image}")
    cache = ["--no-cache"] if no_cache else []
    if run("docker", "build", "--progress=plain", *cache, "--build-arg", f"TOOLCHAIN={image}", "-t", tag,
           str(BUILDER_DIR)) != 0:
        raise Failed("the builder image does not build (is the toolchain image available?)")
    return tag


def project_tag(job, commit, builder, home, suffix=""):
    """The tag of the project image: the upstream commit, and a hash of what this repository puts into the image (the
    project's directory, and the builder it is built FROM, whose tag hashes infra/base-builder and the toolchain) and
    of the run's work directory `home`. So no two runs on one Docker host share a tag, and removing one run's tag never
    takes another's image; the same inputs still reuse docker's layer cache."""
    inputs = hashlib.sha256(f"{tree_hash(job.directory)}\0{builder}\0{home}".encode()).hexdigest()
    return f"oss-verify-check/{job.name}:{commit[:12]}-{inputs[:12]}{suffix}"


def work_label(home):
    """The label every container that the run with work directory `home` starts carries, so that a caller stops that
    run's containers and no other's."""
    return ["--label", f"{WORK_LABEL}={home}"]


def record_image(record, tag):
    """Add `tag` to the file `record`, one tag a line, before the image is built: the project images this run makes,
    for a caller to remove those and no other run's."""
    with open(record, "a", encoding="utf-8") as handle:
        handle.write(f"{tag}\n")


def recorded_images(record):
    """The tags that record_image() wrote to `record`, in order, each once; [] if the file is not there."""
    try:
        return list(dict.fromkeys(record.read_text(encoding="utf-8").split()))
    except FileNotFoundError:
        return []


def build_project(job, commit, builder, tag, work, no_cache=False):
    """Build the project's Dockerfile on the builder, with network access, into image `tag`."""
    args = ["--build-arg", f"BASE_BUILDER={builder}", "--build-arg", f"REPO={job.repo}", "--build-arg", f"COMMIT={commit}"]
    if job.dockerfile:
        checkout = work / "src"
        step(f"clone {job.repo} at {commit}")
        clone(job.repo, commit, checkout)
        dockerfile = in_checkout(checkout, job.dockerfile)
        if not dockerfile.is_file():
            raise Failed(f"no Dockerfile at {job.dockerfile} in the repository")
        if not (dockerfile.parent / "build.sh").is_file():
            say(f"note: no build.sh beside {job.dockerfile}: the Dockerfile must create $SRC/build.sh itself")
        where = ["-f", str(dockerfile), str(checkout)]
        say(f"Dockerfile: the repository's own, {job.dockerfile}; the build context is the repository")
    else:
        where = ["-f", str(job.directory / "Dockerfile"), str(job.directory)]
        say(f"Dockerfile: the one beside project.yaml; the build context is projects/{job.name}/")
    step(f"docker build: the project ({tag}); the network is available")
    cache = ["--no-cache"] if no_cache else []
    if run("docker", "build", "--progress=plain", *cache, *args, "-t", tag, *where) != 0:
        raise Failed("docker build of the project's Dockerfile failed")


def sources(tag, *, labels):
    """The git checkouts under $SRC in the project image: {path: commit}. `labels`: docker run arguments, work_label()."""
    listing = output("docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "sh", tag, "-c", LIST_SOURCES)
    return dict(line.split(" ", 1) for line in listing.splitlines() if " " in line)


def empty_directory(path, tag, *, labels):
    """Make `path` an empty directory, removing what an earlier root-owned run may have left in it."""
    if path.exists():
        try:
            shutil.rmtree(path)
        except PermissionError:
            run("docker", "run", "--rm", "--network=none", *labels, "-v", f"{path.parent}:/parent", "--entrypoint", "rm",
                tag, "-rf", f"/parent/{path.name}", quiet=True)
    path.mkdir(parents=True)


# The status docker run exits with when it cannot run the container at all.
DOCKER_FAILED = 125


def compile_build(tag, build, sanitizer, out, ubsan=None, *, labels):
    """Run `compile` for one build in a fresh container with no network, its $OUT mounted at `out`. `ubsan`, if given,
    is (checks, left out[, left out of C compiles]): the UBSan checks of the build, those that trap mode leaves out,
    and those that its C compiles leave out. `labels`: docker run arguments for the container, work_label()."""
    step(f"compile: the {build} build (SANITIZER={sanitizer}), with no network")
    empty_directory(out, tag, labels=labels)
    owner = f"{os.getuid()}:{os.getgid()}"
    # The number of parallel jobs, if set here, for recipes that read it; it does not change the bytes.
    jobs = ["-e", "OFT_MAKE_JOBS"] if os.environ.get("OFT_MAKE_JOBS") else []
    checks = []
    if ubsan and "undefined" in sanitizer:
        checks = ["-e", f"OV_UBSAN_CHECKS={','.join(ubsan[0])}", "-e", f"OV_UBSAN_EXCLUDE={','.join(ubsan[1])}"]
        if len(ubsan) > 2 and ubsan[2]:
            checks += ["-e", f"OV_UBSAN_C_EXCLUDE={','.join(ubsan[2])}"]
    command = ["docker", "run", "--rm", "--init", "--network=none", *labels, "-e", f"SANITIZER={sanitizer}",
               "-e", f"OV_OWNER={owner}", *jobs, *checks, "-v", f"{out}:/out", tag, "compile"]
    code = run(*command)
    if code == DOCKER_FAILED:
        # docker run itself failed (the daemon could not start the container), not the build: once more, afresh.
        say(f"docker run exited {DOCKER_FAILED}: starting the {build} build again")
        empty_directory(out, tag, labels=labels)
        code = run(*command)
    if code != 0:
        raise Failed(f"compile exited {code} in the {build} build")


def oss_verify_state(job):
    """This repository's commit, and whether what decides the bytes (tools/, infra/, the project's directory) differs
    from it. None outside a git checkout."""
    inside = job.directory.is_relative_to(ROOT)
    try:
        commit = output("git", "-C", str(ROOT), "rev-parse", "HEAD").strip()
        paths = ["tools", "infra", *([str(job.directory.relative_to(ROOT))] if inside else [])]
        changed = output("git", "-C", str(ROOT), "status", "--porcelain", "--", *paths).strip()
    except (Failed, OSError):
        return None
    # A project directory outside this repository is not part of its commit.
    return {"commit": commit, "modified": bool(changed) or not inside}
