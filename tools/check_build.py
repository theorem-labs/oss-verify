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
# An explicit HTTP status in what git said, both ways git writes one: its own `The requested URL returned error:
# 503`, and `503 Service Unavailable` from the remote. **The status is read before any body text**, because a
# server fault can carry whatever words it likes in its body -- a review measured a 503 whose body said
# `upstream connection permission denied`, and another whose body said `repository not found`. A status decides;
# a body only speaks when there is no status.
HTTP_STATUS = re.compile(r"returned error:\s*(\d{3})|\b(4\d\d|5\d\d)\s+[A-Za-z]")
# The statuses that mean the server answered and would not let this build read the repository. Every other
# status is the server failing, not refusing: 429 and the whole 5xx range are transport.
DENIED_STATUS = ("401", "403", "404")
# What stands in a message with NO HTTP status for a credential that was wrong or missing, or a repository the
# server will not admit exists. Each is a phrase git or the remote writes in that situation and in no other: a
# bare `permission denied` is not here, because a server fault's body can say it, and `remote error: access
# denied` is, because that is git's protocol refusal and carries its own context.
UNAUTHORISED = ("could not read username", "authentication failed", "terminal prompts disabled",
                "invalid username or token", "repository not found", "remote: not found",
                "remote error: access denied", "remote: access denied", "remote error: permission denied",
                "remote: permission denied", "403 forbidden", "401 unauthorized")


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
    compare against. For a stream, use stream_redacted(), which never replaces part of a token it has not seen the
    end of."""
    if token:
        text = text.replace(token, "<redacted>")
    return TOKEN_SHAPE.sub("<redacted>", text)


def held_back(text, token):
    """How many characters at the end of `text` must be kept until more of the stream arrives: the length of the
    longest suffix of `text` that is the beginning of `token`, and so may turn into a copy of it. Only the token
    itself is matched, never TOKEN_SHAPE: a shape matches the first 24 characters of a 44-character token, so
    replacing by shape as the bytes arrive would turn the first half into <redacted> and print the second half
    (a 20-character suffix of a real token, measured in review)."""
    for length in range(min(len(token), len(text) + 1) - 1, 0, -1):
        if token.startswith(text[-length:]):
            return length
    return 0


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
        # With no token this is the stream as it always was: a public build's log is not filtered at all.
        #
        # With one: every whole copy of the token in what has arrived is replaced, and the tail that could still
        # become one -- the longest suffix of the buffer that is a beginning of the token -- is held back until the
        # next read, or the end of the stream, settles it. Only the token's own characters are matched here, and
        # the tail is taken from the text as it arrived: a filter that replaced by shape as the bytes came in would
        # turn a token's first half into <redacted> and then print its second half.
        held = ""

        def write(text):
            if text:
                sys.stdout.write(terminal_safe(text))
                sys.stdout.flush()

        while chunk := os.read(proc.stdout.fileno(), 65536):
            held += decode.decode(chunk)
            if not token:
                write(held)
                held = ""
                continue
            keep = held_back(held.replace(token, "\0" * len(token)), token)
            write(redacted(held[:len(held) - keep], token))
            held = held[len(held) - keep:]
        write(redacted(held, token) if token else held)

    reader = threading.Thread(target=copy, daemon=True)
    reader.start()
    code = proc.wait()
    reader.join(timeout=5)
    proc.stdout.close()
    return code


def output(*argv, env=None, token=None):
    """Run a command quietly and return its standard output, or raise Failed with its error output. `env` replaces
    the command's whole environment; `token` is kept out of the message, as run() keeps it out of the log.

    The error is redacted BEFORE it is cut to its last characters: cutting first leaves whatever of the token was
    in the last 1500 characters, with no replacement to show for it, which a review measured.
    """
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", env=env)
    if done.returncode != 0:
        raise Failed(f"{redacted(' '.join(map(str, argv[:3])), token)} ... exited {done.returncode}: "
                     f"{redacted(done.stderr.strip(), token)[-1500:]}")
    return done.stdout


# What turns git's own tracing off on the command line, where it outranks any configuration file. The environment
# is cleared too (GIT_TRACING), but that is not enough on its own: trace2's targets are configuration, and
# `trace2.envVars` names environment variables to WRITE INTO the trace, which GIT_TRACE_REDACT does not redact. A
# review measured a whole token in a trace file that way.
NO_TRACING = ("trace2.eventTarget=", "trace2.normalTarget=", "trace2.perfTarget=", "trace2.envVars=",
              "trace2.configParams=")


def git(*args, token=False):
    """git, over https only, even if a URL or a server redirect asks for another protocol.

    Anonymous, which is what a public library is fetched with and what keeps a build off whatever credential the
    host happens to have. With `token`: one credential helper in place of that empty list, the builder's own, which
    reads the token from OSS_VERIFY_GIT_TOKEN in the environment of this git process (git_environment()) and
    answers for one repository; `credential.useHttpPath` so the request carries the path the helper matches on,
    without which the helper can only match the host and answers for every repository on it; and every trace
    target emptied. The token itself is in no command line.
    """
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    helper = ["-c", "credential.helper="]
    if token:
        helper += ["-c", f"credential.helper=!{shlex.quote(str(CREDENTIAL_HELPER))}",
                   "-c", "credential.useHttpPath=true"]
        helper += [argument for setting in NO_TRACING for argument in ("-c", setting)]
    return ["git", *helper, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args]


# git's own tracing writes what it sends: GIT_TRACE_CURL with GIT_TRACE_REDACT=0 puts the Authorization header in a
# file that outlives the build. Whatever the caller set, a fetch with a token does not trace.
# A trace variable git reads as a false/true word: 0 turns it off, and 0 OVERRIDES a configured target, which
# removing it would not.
GIT_TRACING = ("GIT_TRACE", "GIT_TRACE_CURL", "GIT_TRACE_PACKET", "GIT_TRACE_CURL_NO_DATA",
               "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF", "GIT_TRACE_SETUP", "GIT_TRACE_SHALLOW",
               "GIT_TRACE_PERFORMANCE", "GIT_TRACE_REFS", "GIT_TRACE_PACK_ACCESS", "GIT_TRACE_FSMONITOR")
# A trace variable whose mere presence turns it on, or whose value is a file name. `GIT_CURL_VERBOSE=0` ENABLES
# curl's tracing, and `GIT_TRACE_PACKFILE=0` writes a packfile to a file called 0. These are removed instead; a
# review measured the first, which this file had set to 0 and so turned ON.
GIT_TRACING_REMOVED = ("GIT_CURL_VERBOSE", "GIT_TRACE_PACKFILE")


def git_environment(token, repo=None):
    """The environment of a git process that fetches `repo` with `token`: this one, with the token added for the
    credential helper to read, the repository the helper may answer for, and git's tracing off. None without a
    token, which leaves the process this one's environment as before."""
    if not token:
        return None
    # Each is SET to 0, not removed: git reads trace2's targets from configuration as well, before `-c` is
    # applied, and `trace2.envVars` names environment variables to write INTO the trace, which GIT_TRACE_REDACT
    # does not redact. An environment variable of 0 turns that target off whatever the configuration says.
    environment = {key: value for key, value in os.environ.items() if key not in GIT_TRACING_REMOVED}
    environment.update({name: "0" for name in GIT_TRACING})
    environment["GIT_TRACE2_ENV_VARS"] = ""
    environment[GIT_TOKEN_ENV] = token
    environment["GIT_TRACE_REDACT"] = "1"
    if repo:
        # The helper answers for this repository alone: a submodule on another server must not be offered it.
        environment["OSS_VERIFY_TOKEN_REPO"] = normalised_repo(repo).partition("://")[2]
    return environment


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
        # Redacted first and cut after: cutting first leaves whatever of a token fell inside the last 1000
        # characters, with no marker to show for it.
        raise Failed(f"no read-only token for {owner}/{name}: {argv[0]} {why}. It said: "
                     f"{redacted(done.stderr.strip(), None)[-1000:] or '(nothing)'}")
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
                         env=git_environment(token, repo), token=token)
    except Failed as failure:
        # A refused credential, and a repository the server will not admit exists, read alike; a bad host, no
        # network, a rate limit and a server fault do not, and keep git's own message rather than being called an
        # authorisation failure.
        if not refused(str(failure)):
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


def refused(said):
    """Did the server answer and refuse, rather than fail to answer? An explicit HTTP status decides on its own:
    401, 403 and 404 are a refusal, and every other status -- 429, 500, 502, 503 -- is the server failing,
    whatever its body says. Only a message with no status at all is read for one of the phrases above."""
    lowered = said.lower()
    found = HTTP_STATUS.search(lowered)
    if found:
        return (found.group(1) or found.group(2)) in DENIED_STATUS
    return any(marker in lowered for marker in UNAUTHORISED)


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
    of a private library, which the credential helper reads out of the git process's environment.

    A fetch that fails is told apart the way fetch-commit tells it apart in the container: the refs are asked for,
    which needs the fetch's authorisation and nothing about the commit. No refs and a refusal means the build may
    not read the repository; no refs and anything else is the transport failure it is. Refs listed means the
    build MAY read it, and no more than that: the objects can still fail to arrive, so that case names both
    possibilities rather than calling the commit missing (why_the_fetch_failed).
    """
    shutil.rmtree(checkout, ignore_errors=True)
    checkout.mkdir(parents=True)
    environment = git_environment(token, repo)
    for args in (["init", "-q", str(checkout)], ["-C", str(checkout), "fetch", "-q", "--depth", "1", "--", repo, commit],
                 ["-C", str(checkout), "checkout", "-q", "--detach", "FETCH_HEAD"]):
        if run(*git(*args, token=bool(token)), env=environment, token=token) != 0:
            raise Failed(why_the_fetch_failed(repo, commit, token))


def why_the_fetch_failed(repo, commit, token):
    """Which of the three it was, after a fetch of `commit` from `repo` failed: the repository cannot be read, it
    can be read and has no such commit, or it could not be reached at all."""
    try:
        output(*git("ls-remote", "--", repo, token=bool(token)), env=git_environment(token, repo), token=token)
    except Failed as failure:
        if refused(str(failure)):
            return unreadable(repo, token, str(failure))
        return (f"could not reach {repo} to list its refs, so nothing is known about {commit} yet: this is neither "
                f"an authorisation failure nor a missing commit. git said: {failure}")
    return (f"could not fetch {commit} from {repo}, although the server listed its refs for this build: this is "
            "not an authorisation failure. Either the commit is not in the repository (deleted, never pushed, or "
            "a branch force-pushed since it was recorded), or the objects did not come (upload-pack refused, a "
            "server fault, a transfer that broke). A successful ref listing says the build may read the "
            "repository and nothing about the transfer; git's own message for the fetch is above.")


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


# `<<EOT`, `<<"EOT"`, `<<-EOT`: what ends a heredoc body. The body is the content of a file or of a script and
# holds no instruction of its own.
HEREDOC = re.compile(r"<<-?\s*([\"']?[A-Za-z_][A-Za-z0-9_]*[\"']?)")


def instructions(text):
    r"""The Dockerfile's instructions, one a string, as a Dockerfile parser reads it: the `escape` directive chooses
    the continuation character, a `#` line is a comment wherever it is (including in the middle of a continued
    instruction), and a line ending in that character continues into the next.

    A continuation takes away the escape character and the newline and NOTHING ELSE: what was before it stays, and
    the next line arrives with its own indentation. So `fetch-\` + `commit` is one word and `--mount=… \` +
    `    fetch-commit` is two, with no rule about commas -- the whitespace that is there decides, and the squeeze
    below only collapses runs of it. Measured against real BuildKit on the third review's cases
    `continued-word`, `continued-field-value`, `continued-fields` and `escape-backtick`.
    """
    text = text.replace("\r\n", "\n")
    escape = "\\"
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            found = re.fullmatch(r"#\s*escape\s*=\s*(.)\s*", line.strip())
            if found:
                escape = found.group(1)
            continue
        break  # a parser directive comes before the first instruction and nowhere else
    joined, carry, ending = [], "", []
    for line in text.splitlines():
        if ending:
            # Inside a heredoc body: these lines are the content of a file or a script, not instructions. A
            # review measured a COPY heredoc whose body quoted a mounted RUN, which read as a real mount and
            # refused a public Dockerfile that mounts nothing.
            if line.strip() == ending[0] or (ending[0].startswith("-") and line.strip() == ending[0][1:]):
                ending.pop(0)
            continue
        if line.lstrip().startswith("#"):
            continue
        stripped = line.rstrip()
        if stripped.endswith(escape):
            carry += stripped[:-1]
            continue
        carry += line
        if carry.strip():
            instruction = " ".join(carry.split())
            joined.append(instruction)
            ending = [word.strip("\"'") for word in HEREDOC.findall(instruction)]
        carry = ""
    if carry.strip():
        joined.append(" ".join(carry.split()))
    return joined


def after_assignment(line, variables):
    """`variables` as they are after one ARG or ENV instruction, unchanged for anything else.

    Every value on one instruction is expanded against the variables as they were BEFORE it, not against each
    other left to right: in `ENV FIRST=new SID=$FIRST`, BuildKit gives SID the OLD value of FIRST. A review
    measured that, and the sequential reading accepted a private build whose fetch gets nothing.
    """
    words = words_of(line) or []
    if not words or words[0].upper() not in ("ARG", "ENV"):
        return variables
    rest = words[1:]
    if words[0].upper() == "ENV" and len(rest) >= 2 and "=" not in rest[0]:
        # The old `ENV KEY value...` form: everything after the name is the value.
        return {**variables, rest[0]: expanded(" ".join(rest[1:]), variables)}
    added = {}
    for pair in rest:
        name, equals, value = pair.partition("=")
        if equals:
            added[name] = expanded(value, variables)
        elif words[0].upper() == "ARG" and name not in variables:
            added[name] = ""  # an ARG with no default is empty unless the build gives one
    return {**variables, **added}


def mounts_and_fetches(text):
    """Walk a Dockerfile once and return [(instruction, the secret ids it mounts, whether it fetches)], with each
    instruction's variables as they are AT it, not at the end of the file: a mount is expanded with what was set
    above it, and a later ENV of the same name does not reach back. `whether it fetches` is True, False, or None
    for a form this does not parse (runs_fetch_commit)."""
    rows, variables = [], {}
    for line in instructions(text):
        rows.append((line, secret_mounts(line, variables), runs_fetch_commit(line)))
        variables = after_assignment(line, variables)
    return rows


def expanded(word, variables):
    """`word` with `$NAME` and `${NAME}` replaced, an unset name by nothing, as BuildKit expands a mount option."""
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                  lambda found: variables.get(found.group(1) or found.group(2), ""), word)


# A command that runs another command: what follows is a shell string, and whether it fetches cannot be read from
# the words of the RUN.
SHELL_WRAPPERS = ("sh", "bash", "ash", "dash", "env", "eval", "xargs", "/bin/sh", "/bin/bash", "/usr/bin/env")


def words_of(instruction):
    """An instruction's words as a shell would split them, or None when it cannot be split (an unmatched quote) or
    carries a heredoc, which this does not parse. A caller that cannot read an instruction must not conclude that
    it does nothing."""
    if "<<" in instruction:
        return None
    try:
        return shlex.split(instruction, comments=False, posix=True)
    except ValueError:
        return None


def secret_mounts(instruction, variables=None):
    """The ids of the BuildKit secrets one instruction mounts: every `--mount=` option of a RUN whose fields say
    `type=secret`, by the value of its `id=` field. The fields of a mount are comma-separated and in any order, and
    an id is matched whole, so `id=oss-verify-git-token-other` is another secret and not this one. A RUN carries
    other options too (`--network=`), so an option that is not a mount is stepped over rather than ending the
    search; the options end at the first word that is not one.

    An instruction that cannot be split is read for the mount by its text, which over-reports rather than under-
    reports: the two callers both want the safe side of that.
    """
    words = words_of(instruction)
    if words is None:
        return re.findall(r"--mount=(?=[^\s]*type=secret)[^\s]*?id=([A-Za-z0-9._-]+)",
                          expanded(instruction or "", variables or {}))
    if not words or words[0].upper() != "RUN":
        return []
    ids = []
    for word in words[1:]:
        if not word.startswith("--"):
            break  # the options end here; what follows is the command the step runs
        if not word.startswith("--mount="):
            continue  # another RUN option, such as --network=
        option = expanded(word[len("--mount="):], variables or {})
        fields = dict(field.partition("=")[::2] for field in option.split(","))
        if fields.get("type") == "secret" and fields.get("id"):
            ids.append(fields["id"])
    return ids


def runs_fetch_commit(instruction):
    """Whether this instruction runs fetch-commit: True, False, or None for "cannot be read".

    The command's own first word decides, so `echo "fetch-commit"` is not a fetch and `/usr/local/bin/fetch-commit`
    is. None is for the forms this does not parse and must not guess at: an instruction that cannot be split or
    carries a heredoc, and a command that runs another command (`sh -c "... fetch-commit ..."`), where whether a
    fetch happens is inside a shell string. A review measured five valid Dockerfiles of those shapes whose real
    fetch ran with no secret while the guard said they were mounted, so None is refused rather than assumed.
    """
    words = words_of(instruction)
    if words is None:
        return None if "fetch-commit" in (instruction or "") else False
    if not words or words[0].upper() != "RUN":
        return False
    rest = [word for word in words[1:] if not word.startswith("--")]
    if not rest:
        return False
    program = rest[0]
    if program.startswith("["):
        # RUN ["fetch-commit", "/src/x"]: the exec form, whose first element is the program and which no shell
        # reads. A review measured an unmounted fetch written this way that the word test missed. The quotes are
        # already gone -- words_of splits as a shell does -- so what is left is `[fetch-commit,`.
        program = program.lstrip("[").strip().strip('",')
    if program in SHELL_WRAPPERS or program.rsplit("/", 1)[-1] in SHELL_WRAPPERS:
        return None if "fetch-commit" in instruction else False
    return program == "fetch-commit" or program.endswith("/fetch-commit")


def fetch_steps(text):
    """The instructions of a Dockerfile that run fetch-commit, with the secret ids each mounts."""
    return [(line, ids) for line, ids, fetches in mounts_and_fetches(text) if fetches]


def unreadable_steps(text):
    """The instructions this cannot read: a heredoc, an unmatched quote, or a command that runs another command,
    where whether a fetch happens and whether it gets the secret are inside a shell string. They are listed, not
    guessed at: a review measured five valid Dockerfiles of those shapes whose real fetch ran with no secret.

    A heredoc is judged on the whole file, because its body is lines of its own: the `RUN … <<EOT` carries the
    mount and the body carries the command, and neither instruction on its own says a fetch is happening. A `<<`
    in a comment is not a heredoc and does not count -- comments are gone by the time instructions() returns.
    """
    lines = instructions(text)
    unreadable = [line for line, _, fetches in mounts_and_fetches(text) if fetches is None]
    # A heredoc BODY is skipped when the instructions are read, so a fetch written inside one appears in no
    # instruction at all. The raw text is what says it is there, and the instruction that opened the heredoc is
    # what to name.
    heredocs = [line for line in lines if "<<" in line]
    if heredocs and "fetch-commit" in text:
        unreadable = list(dict.fromkeys(unreadable + heredocs))
    return unreadable


def check_secret_mount(dockerfile, text, token, where):
    """Refuse a build whose Dockerfile and whose library disagree about the token.

    A private library whose fetch step does not mount the secret would fetch with no credential and fail with "not
    authorised", one step away from the message this whole path exists to remove. A library that is NOT private
    whose Dockerfile asks for the mount is the other mistake: a project that asks a build for a credential it was
    never meant to have. BuildKit gives such a RUN an empty mount and says nothing, so neither shows itself.

    The Dockerfile is parsed, not searched: a mention of the mount in a comment is not a mount, `echo
    "fetch-commit"` is not a fetch, a mount on another step does not put the token on the fetch, an id that merely
    starts with ours is another secret, and a mount whose fields are reordered or whose line is continued is still
    a mount. EVERY fetch step must have it, not one of them: a Dockerfile with a mounted fetch and an unmounted
    one would fetch the second with no credential.
    """
    steps = fetch_steps(text)
    bare = [step for step, ids in steps if GIT_TOKEN_SECRET not in ids]
    unreadable = unreadable_steps(text)
    # Parsed mounts only. Looking for the id in the text as well refused three valid public Dockerfiles that
    # mount nothing: one whose heredoc BODY quotes a mount, one that mounts `…-token-other`, and one that names
    # the mount in a comment. A heredoc body is a shell script; a mount is on the RUN line, which is parsed.
    asks = any(GIT_TOKEN_SECRET in ids for _, ids, _ in mounts_and_fetches(text))
    if token and unreadable:
        raise Failed(f"{where} is in infra/private-libraries.tsv, so its fetch must mount the token, and "
                     f"{dockerfile} writes a step this check cannot read:\n    {unreadable[0][:160]}\n"
                     "A heredoc, an unmatched quote, and a command that runs another command (`sh -c \"…\"`) all "
                     "put the fetch inside a string, and whether BuildKit gives THAT fetch the secret cannot be "
                     "read from the instruction. Write the fetch as its own step:\n"
                     f"    RUN {SECRET_MOUNT} fetch-commit $SRC/<name>")
    if token and (bare or not steps):
        why = (f"{dockerfile} has no fetch-commit step at all" if not steps else
               f"a fetch step in {dockerfile} does not mount it: {bare[0][:120]}" if asks else
               f"the fetch step in {dockerfile} does not mount it")
        raise Failed(f"{where} is in infra/private-libraries.tsv, so this build minted a read-only token for it, but "
                     f"{why}, so that fetch would get no credential. Put the mount on every fetch step:\n"
                     f"    RUN {SECRET_MOUNT} fetch-commit $SRC/<name>")
    if asks and not token:
        raise Failed(f"{dockerfile} mounts the secret {GIT_TOKEN_SECRET}, but {where} is not in "
                     "infra/private-libraries.tsv, so no token is minted for it and no build of it gets a "
                     "credential. A public library is fetched with none: take the mount off.")


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
