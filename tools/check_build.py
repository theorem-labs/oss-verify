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
import concurrent.futures
import contextlib
import dataclasses
import hashlib
import os
import pathlib
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILDER_DIR = ROOT / "infra" / "base-builder"
CACHE = pathlib.Path(os.environ.get("XDG_CACHE_HOME") or "~/.cache").expanduser() / "oss-verify-check"
FULL_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
TOOLCHAINS = ROOT / "infra" / "toolchains.tsv"
# How a toolchain's UBSan builds choose their checks: the release's fixed flags, or the project's ubsan_checks.
UBSAN_MODES = ("fixed", "checks")
# In a tools/check work directory: the tags of the project images that run built, one a line (record_image).
IMAGES = "images"
# The label on every container a tools/check run starts: its work directory (work_label).
WORK_LABEL = "oss-verify-check.work"
# The label on every container this process starts, whatever its work directory (work_label): stop_containers() stops
# this process's containers, and not those of another run, even one in the same work directory.
RUN_LABEL = "oss-verify-check.run"
RUN = uuid.uuid4().hex
# The git checkouts under $SRC in a project image, and their commits, for the manifest.
LIST_SOURCES = (
    'find "$SRC" -maxdepth 4 -name .git 2>/dev/null | sort | while read -r g; do d=${g%/.git}; '
    'c=$(git -C "$d" rev-parse HEAD 2>/dev/null) && printf "%s %s\\n" "$d" "$c"; done'
)
# The libraries a build fetches with a credential, one repository a row, and nothing else (private_libraries()).
PRIVATE_LIBRARIES = ROOT / "infra" / "private-libraries.tsv"
# The command that prints a read-only token for one repository, run with <owner> <repo>; OSS_VERIFY_GIT_TOKEN_COMMAND
# replaces it (infra/github-read-token).
TOKEN_COMMAND = ROOT / "infra" / "github-read-token"
TOKEN_COMMAND_ENV = "OSS_VERIFY_GIT_TOKEN_COMMAND"
# The BuildKit secret that carries that token into the build, and the host environment variable `docker build
# --secret env=` reads it from. A secret is a tmpfs file in the RUN step that mounts it: it is in no layer, in no
# image history and in no build argument. The project's Dockerfile must ask for it (build_project).
GIT_TOKEN_SECRET = "oss-verify-git-token"
GIT_TOKEN_ENV = "OSS_VERIFY_GIT_TOKEN"
SECRET_MOUNT = f"--mount=type=secret,id={GIT_TOKEN_SECRET}"
# How git reads that token on the host: the same helper the builder image installs, by its path here, with the token
# in the environment of the git process alone (infra/base-builder/git-credential-oss-verify).
CREDENTIAL_HELPER = BUILDER_DIR / "git-credential-oss-verify"
# A GitHub token, for the one case where a message this file did not write may hold one: the standard error of a
# token command, which is read before there is a token to compare against.
TOKEN_SHAPE = re.compile(r"gh[a-z]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}")
# What stands in a message for a credential that was wrong or missing, rather than for a request that never arrived.
UNAUTHORISED = ("could not read username", "authentication failed", "repository not found", "terminal prompts "
                "disabled", "403 forbidden", "invalid username or token", "remote: not found")


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
    mutants: str | None = None  # project.yaml's mutants: the directory of breakage patches, from the image's WORKDIR


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


def redacted(text, token):
    """`text` with every copy of `token` replaced, and with anything else shaped like a GitHub token replaced too.
    With no token, only the shape is matched: a token command's standard error is read before there is a value to
    compare against."""
    if token:
        text = text.replace(token, "<redacted>")
    return TOKEN_SHAPE.sub("<redacted>", text)


def run(*argv, quiet=False, env=None, token=None):
    """Run a command and return its exit code.

    `quiet` hides its output. Otherwise its output (the project's build, its git server's messages) reaches the
    terminal through terminal_safe(), never raw. `env` replaces the command's whole environment. `token`, the
    read-only token of a private library, is replaced wherever it appears in that output, across chunk boundaries
    too: the build log is one of the four places a token must never end up, and what a git server or a failing
    fetch writes is not this program's text. The command never reads what was piped into tools/check.
    """
    if quiet:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=env).returncode
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    def copy():
        decode = codecs.getincrementaldecoder("utf-8")(errors="replace")
        # With no token this is the stream as it always was: a public build's log is not filtered at all. With one,
        # the buffer is redacted before any of it is written, and the last len(token)-1 characters are held back
        # until the next chunk (or the end) says whether they begin a copy of it: a filter that looks at one chunk
        # at a time lets through a token that straddles two reads.
        clean = (lambda text: redacted(text, token)) if token else (lambda text: text)
        keep = len(token) - 1 if token else 0
        held = ""

        def write(text):
            if text:
                sys.stdout.write(terminal_safe(text))
                sys.stdout.flush()

        while chunk := os.read(proc.stdout.fileno(), 65536):
            held = clean(held + decode.decode(chunk))
            if len(held) > keep:
                write(held[:len(held) - keep])
                held = held[len(held) - keep:]
        write(clean(held))

    reader = threading.Thread(target=copy, daemon=True)
    reader.start()
    code = proc.wait()
    reader.join(timeout=5)
    proc.stdout.close()
    return code


def output(*argv, env=None, token=None):
    """Run a command quietly and return its standard output, or raise Failed with its error output. `env` replaces
    the command's whole environment; `token` is kept out of the message, as run() keeps it out of the log."""
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", env=env)
    if done.returncode != 0:
        raise Failed(f"{' '.join(argv[:3])} ... exited {done.returncode}: "
                     f"{redacted(done.stderr.strip()[-1500:], token)}")
    return done.stdout


def git(*args, token=False):
    """git, over https only, even if a URL or a server redirect asks for another protocol.

    Anonymous, which is what a public library is fetched with and what keeps a build off whatever credential the
    host happens to have. With `token`, one credential helper is put in place of that empty list: the builder's own,
    which reads the token from OSS_VERIFY_GIT_TOKEN in the environment of this git process (git_environment()). The
    token itself is in no command line.
    """
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    helper = ["-c", "credential.helper="]
    if token:
        helper += ["-c", f"credential.helper=!{shlex.quote(str(CREDENTIAL_HELPER))}"]
    return ["git", *helper, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args]


def git_environment(token):
    """The environment of a git process that fetches with `token`: this one, with the token added for the credential
    helper to read. None without a token, which leaves the process this one's environment as before."""
    return {**os.environ, GIT_TOKEN_ENV: token} if token else None


def private_libraries():
    """The libraries a build fetches with a credential: {repository URL: why}, from infra/private-libraries.tsv.
    Every other library is fetched with none. A missing file is an empty list, not an error: a checkout that has
    removed it has no private library."""
    try:
        text = PRIVATE_LIBRARIES.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    rows = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        repo, _, why = line.partition("\t")
        rows[normalised_repo(repo)] = why.strip()
    return rows


def normalised_repo(repo):
    """A repository URL as it is compared with infra/private-libraries.tsv: without its #ref, a trailing .git or a
    trailing slash, so that one repository written three ways is one row and not three."""
    return repo.strip().partition("#")[0].rstrip("/").removesuffix(".git").rstrip("/")


def private_reason(repo):
    """Why `repo` is fetched with a token, or None when it is fetched with none."""
    return private_libraries().get(normalised_repo(repo))


def owner_and_name(repo):
    """The GitHub account and repository name in an https URL, for the token command."""
    parts = normalised_repo(repo).split("/")
    if len(parts) < 2:
        raise Failed(f"{repo} is not <host>/<owner>/<name>, so there is no repository to narrow a token to")
    return parts[-2], parts[-1]


def mint_token(repo):
    """A token that may read `repo` and nothing else, minted for this build by the token command (TOKEN_COMMAND, or
    OSS_VERIFY_GIT_TOKEN_COMMAND). It is returned, never printed, never written to a file here, and never put in a
    build argument; build_project() hands it to docker as a BuildKit secret.

    Raise Failed if there is no token. The message holds the command and its standard error with anything
    token-shaped taken out: a credential command's error text can quote what it was given.
    """
    owner, name = owner_and_name(repo)
    command = os.environ.get(TOKEN_COMMAND_ENV, "").strip()
    argv = [*shlex.split(command), owner, name] if command else [str(TOKEN_COMMAND), owner, name]
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
    except OSError as error:
        raise Failed(f"the token command {argv[0]} for {owner}/{name} did not run: {error.strerror}") from None
    token = done.stdout.strip()
    if done.returncode != 0 or not token:
        why = "printed no token" if done.returncode == 0 else f"exited {done.returncode}"
        raise Failed(f"no read-only token for {owner}/{name}: {argv[0]} {why}. It said: "
                     f"{redacted(done.stderr.strip()[-1000:], None) or '(nothing)'}")
    if len(token.splitlines()) != 1:
        raise Failed(f"the token command {argv[0]} printed more than one line for {owner}/{name}; a token is one line")
    return token


def resolve(repo, ref, token=None):
    """The full commit id that `repo#ref` names now: a branch, a tag (annotated tags are followed to their commit), a
    full commit id (taken as it is), or "" for the default branch. `token`, for a private library, is read by the
    credential helper out of this git process's environment and is in no command line."""
    if FULL_COMMIT.fullmatch(ref):
        return ref
    if ref.startswith("refs/"):
        names = [ref, f"{ref}^{{}}"]
    else:
        names = [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"]
    try:
        listing = output(*git("ls-remote", "--", repo, *(names if ref else ["HEAD"]), token=bool(token)),
                         env=git_environment(token), token=token)
    except Failed as failure:
        # A refused credential, and a repository the server will not admit exists, read alike; a bad host or no
        # network does not, and keeps git's own message rather than being called an authorisation failure.
        if not any(marker in str(failure).lower() for marker in UNAUTHORISED):
            raise
        raise Failed(unreadable(repo, token, str(failure))) from None
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


def unreadable(repo, token, said):
    """What to say when git could not even list a repository's refs. A server that refuses a credential and one that
    has no such repository answer alike, so this names what the build tried rather than claiming which it was; what
    git said comes after it, so a failure that is neither (no network, a bad host) is still readable."""
    with_what = ("with a read-only token minted for this build" if token else
                 "with no credential, which is how every public library is fetched")
    private = "" if private_reason(repo) else (
        f" {normalised_repo(repo)} is not in infra/private-libraries.tsv, so no token was minted for it; a private "
        "repository of ours needs a row there.")
    return (f"cannot read {repo}: it is private, it does not exist, or the build may not read it. The build asked "
            f"{with_what}, and the server listed no refs, so no commit of it was looked up: this is not a missing "
            f"commit.{private} git said: {said}")


def clone(repo, commit, checkout, token=None):
    """Check out `repo` at `commit` into `checkout`, over https. Anonymously, unless `token` is the read-only token
    of a private library, which the credential helper reads out of the git process's environment."""
    shutil.rmtree(checkout, ignore_errors=True)
    checkout.mkdir(parents=True)
    environment = git_environment(token)
    for args in (["init", "-q", str(checkout)], ["-C", str(checkout), "fetch", "-q", "--depth", "1", "--", repo, commit],
                 ["-C", str(checkout), "checkout", "-q", "--detach", "FETCH_HEAD"]):
        if run(*git(*args, token=bool(token)), env=environment, token=token) != 0:
            raise Failed(f"cannot fetch {commit} from {repo}")


def in_checkout(checkout, path):
    """Return checkout/path. Raise Failed if a symbolic link makes it point outside the checkout."""
    if not (checkout / path).resolve().is_relative_to(checkout.resolve()):
        raise Failed(f"{path} resolves to a place outside the repository and is not used")
    return checkout / path


def tree_hash(directory):
    """A hash of every file under `directory` (less Python's bytecode caches): its relative path, its mode and its
    bytes. A symbolic link counts as the text of the link, not what it points to, as `docker build` sends it. Each
    field goes in with its length in front, so no two trees give one stream (a file whose bytes look like the next
    file's path cannot pass for two files), and a file's bytes go in by their own SHA-256, read in chunks."""
    digest = hashlib.sha256()

    def field(data):
        digest.update(len(data).to_bytes(8, "big") + data)

    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            for data in (b"link", os.fsencode(relative), os.fsencode(os.readlink(path))):
                field(data)
        elif path.is_file():
            content = hashlib.sha256()
            with open(path, "rb") as handle:
                while chunk := handle.read(1 << 20):
                    content.update(chunk)
            for data in (b"file", os.fsencode(relative), f"{path.stat().st_mode & 0o111:o}".encode(),
                         content.digest()):
                field(data)
    return digest.hexdigest()


@contextlib.contextmanager
def cache_lock(entry):
    """Hold an exclusive lock for the cache entry `entry` (a path in the cache) while a run fills or reads it, through
    the file <entry>.lock beside it: a second tools/check on this host that fills the same entry waits, rather than
    removing what the first is writing."""
    # Imported here, not at the top: fcntl is POSIX only, and tools/validate.py (with the triage preview that
    # CONTRIBUTING.md gives) imports this module, and must still run where there is none, as on Windows.
    import fcntl
    entry = pathlib.Path(entry)
    entry.parent.mkdir(parents=True, exist_ok=True)
    with open(entry.parent / f"{entry.name}.lock", "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


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
    """The docker run options of every container that the run with work directory `home` starts: the label of that
    work directory, so that a caller stops that run's containers and no other's; the label of this process, for
    stop_containers(); and no log. Docker keeps a container's log on the host for as long as the container writes,
    read or not, so one that writes forever after its client is gone would fill the host's disk. docker run still
    passes on all that its container writes."""
    return ["--label", f"{WORK_LABEL}={home}", "--label", f"{RUN_LABEL}={RUN}", "--log-driver=none"]


def _docker(*argv):
    """Run a docker command quietly, for at most a minute, and return its standard output: "" if it fails, or there
    is no docker."""
    try:
        return subprocess.run(["docker", *argv], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def remove_containers(*names):
    """Kill and remove these containers (docker rm -f), quietly: one already gone is no error."""
    if names:
        _docker("rm", "-f", *names)


def stop_containers():
    """Kill and remove every container that this process started and that is still there (by its RUN_LABEL). A
    container outlives its docker run client: if the client ends first (it is killed, or tools/check ends and leaves it
    behind), the container runs on to its own end, or forever."""
    remove_containers(*_docker("ps", "-aq", "--filter", f"label={RUN_LABEL}={RUN}").split())


def abandon(pool):
    """For a thread pool of docker runs whose caller is ending (Ctrl-C, or SIGTERM or SIGHUP in containers_stopped()):
    start none of its jobs that have not started, and stop the containers of those that have. Else the pool's threads
    would run every job to its time limit before tools/check could end."""
    pool.shutdown(wait=False, cancel_futures=True)
    stop_containers()


def in_threads(function, items, workers):
    """function(item) for each of `items`, at most `workers` at once, each in a thread of its own: what each call
    returned, or the exception it raised, in the order of `items`. If Ctrl-C, or a signal of containers_stopped(),
    stops the wait, the calls are abandoned (abandon()) and it is raised again. Each pool of docker runs runs here."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(function, item) for item in items]
        try:
            concurrent.futures.wait(futures)
        except (KeyboardInterrupt, SystemExit):
            abandon(pool)
            raise
    outcomes = []
    for future in futures:
        error = future.exception()
        outcomes.append(error if error is not None else future.result())
    return outcomes


def _end(number, frame):
    raise SystemExit(128 + number)


@contextlib.contextmanager
def containers_stopped():
    """Around a whole tools/check run, in the main thread: when it ends, however it ends (its result, an error, Ctrl-C,
    or SIGTERM or SIGHUP, which end it with the exit status 128 + the signal's number, as they would a shell), stop
    the containers that it started (stop_containers()). No signal cuts that short. A signal that is ignored when the
    run starts stays ignored, as a shell leaves it: under nohup, a SIGHUP does not end the run."""
    caught = [getattr(signal, name) for name in ("SIGTERM", "SIGHUP")
              if hasattr(signal, name) and signal.getsignal(getattr(signal, name)) is not signal.SIG_IGN]
    before = {number: signal.signal(number, _end) for number in caught}
    try:
        yield
    finally:
        held = {number: signal.signal(number, signal.SIG_IGN) for number in (signal.SIGINT, *caught)}
        try:
            stop_containers()
        finally:
            for number, handler in {**held, **before}.items():
                if handler is not None:  # None: a handler that Python did not install, which it cannot put back
                    signal.signal(number, handler)


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


def check_secret_mount(dockerfile, text, token, where):
    """Refuse a build whose Dockerfile and whose library disagree about the token.

    A private library whose Dockerfile does not mount the secret would fetch with no credential and fail with "not
    authorised", one step away from the message this whole path exists to remove. A library that is NOT private
    whose Dockerfile asks for the mount is the other mistake: a project that asks a build for a credential it was
    never meant to have. BuildKit gives such a RUN an empty mount and says nothing, so neither is caught by docker.
    """
    asks = SECRET_MOUNT in text
    if token and not asks:
        raise Failed(f"{where} is in infra/private-libraries.tsv, so this build minted a read-only token for it, but "
                     f"{dockerfile} never mounts it, so the fetch would get no credential. Put the mount on the "
                     f"fetch step:\n    RUN {SECRET_MOUNT} fetch-commit $SRC/<name>")
    if asks and not token:
        raise Failed(f"{dockerfile} asks for {SECRET_MOUNT}, but {where} is not in infra/private-libraries.tsv, so "
                     "no token is minted for it and no build of it gets a credential. A public library is fetched "
                     "with none: take the mount off.")


def build_project(job, commit, builder, tag, work, no_cache=False, token=None):
    """Build the project's Dockerfile on the builder, with network access, into image `tag`.

    `token`, for a library in infra/private-libraries.tsv, goes to docker as the BuildKit secret oss-verify-git-token
    and never as a build argument: a build argument is in `docker history`, a secret is a tmpfs file that exists
    only while the RUN step that mounts it runs. docker reads it out of this process's environment, so it is in no
    file of ours and in no command line either.
    """
    args = ["--build-arg", f"BASE_BUILDER={builder}", "--build-arg", f"REPO={job.repo}", "--build-arg", f"COMMIT={commit}"]
    environment = None
    if token:
        args += ["--secret", f"id={GIT_TOKEN_SECRET},env={GIT_TOKEN_ENV}"]
        environment = {**os.environ, GIT_TOKEN_ENV: token}
    if job.dockerfile:
        checkout = work / "src"
        step(f"clone {job.repo} at {commit}")
        clone(job.repo, commit, checkout, token)
        dockerfile = in_checkout(checkout, job.dockerfile)
        if not dockerfile.is_file():
            raise Failed(f"no Dockerfile at {job.dockerfile} in the repository")
        if not (dockerfile.parent / "build.sh").is_file():
            say(f"note: no build.sh beside {job.dockerfile}: the Dockerfile must create $SRC/build.sh itself")
        where = ["-f", str(dockerfile), str(checkout)]
        say(f"Dockerfile: the repository's own, {job.dockerfile}; the build context is the repository")
    else:
        dockerfile = job.directory / "Dockerfile"
        where = ["-f", str(dockerfile), str(job.directory)]
        say(f"Dockerfile: the one beside project.yaml; the build context is projects/{job.name}/")
    check_secret_mount(dockerfile, dockerfile.read_text(encoding="utf-8", errors="replace"), token, job.repo)
    step(f"docker build: the project ({tag}); the network is available")
    cache = ["--no-cache"] if no_cache else []
    if run("docker", "build", "--progress=plain", *cache, *args, "-t", tag, *where,
           env=environment, token=token) != 0:
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


def compile_build(tag, build, sanitizer, out, ubsan=None, *, labels, record=False):
    """Run `compile` for one build in a fresh container with no network, its $OUT mounted at `out`. `ubsan`, if given,
    is (checks, left out[, left out of C compiles]): the UBSan checks of the build, those that trap mode leaves out,
    and those that its C compiles leave out. `labels`: docker run arguments for the container, work_label(). With
    `record`, compile records each fuzz target's link in $OUT/.records/ for the checks of the binaries
    (tools/check_links.py); the binaries are the same."""
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
    if record:
        checks += ["-e", "OV_RECORD=1"]
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
