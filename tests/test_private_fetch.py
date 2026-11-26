# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""How a build reads a private library of ours, and how it fails when it cannot.

The git half runs against a git server started here, over the loopback interface: `git http-backend`, with one
repository it serves to anyone and two it serves only to a request that carries the right token, one of which names
the other as a submodule. No network and no Docker. fetch-commit is run as the builder image runs it, with REPO and
COMMIT in its environment.

    uv run pytest tests/test_private_fetch.py
"""
import base64
import contextlib
import http.server
import io
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import urllib.parse

import pytest

from oss_verify import check_build
from oss_verify.check_build import Failed, Job

ROOT = pathlib.Path(__file__).resolve().parents[1]
FETCH_COMMIT = ROOT / "infra" / "base-builder" / "fetch-commit"
HELPER = ROOT / "infra" / "base-builder" / "git-credential-oss-verify"
# A token of the shape GitHub gives an App installation. Nothing here reaches GitHub; the server below checks it.
TOKEN = "ghs_" + "T0kenF0rTheBuildOnly" * 2
OTHER_TOKEN = "ghs_" + "AnotherT0kenEntirely" * 2
# The repository the test URLs name. fetch-commit takes https:// only, so git rewrites this to the test server.
HOST = "https://private.test/"
GIT = ("git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false",
       "-c", "init.defaultBranch=main")


def git(*args, cwd=None):
    """Run git here, with no signing and no user configuration of the machine."""
    environment = {**os.environ, "HOME": str(cwd or ROOT), "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_CONFIG_SYSTEM": "/dev/null"}
    done = subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, env=environment)
    if done.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {done.stderr}")
    return done.stdout.strip()


class GitServer(http.server.ThreadingHTTPServer):
    """A git server on the loopback interface. `private` names the repositories it serves only to a request that
    carries `token` as a Basic password; it answers any other request for one of them with 401, as GitHub answers an
    unauthenticated request with a refusal rather than the repository. With `broken` set, every transfer of objects
    stops halfway, as a transfer that broke does."""

    protocol_version = "HTTP/1.0"
    allow_reuse_address = True

    def __init__(self, root, private, token):
        super().__init__(("127.0.0.1", 0), Handler)
        self.root, self.private, self.token = str(root), set(private), token
        self.seen = []  # one (repository, Authorization header or None) for each request, for the tests to read
        self.broken = False


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.serve()

    def do_POST(self):
        self.serve()

    def serve(self):
        parsed = urllib.parse.urlparse(self.path)
        name = parsed.path.lstrip("/").split("/")[0]
        authorization = self.headers.get("Authorization")
        self.server.seen.append((name, authorization))
        if name in self.server.private and not self.authorised(authorization):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="git"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        environment = {
            "PATH": os.environ["PATH"],
            "GIT_PROJECT_ROOT": self.server.root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": parsed.path,
            "QUERY_STRING": parsed.query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
            "REMOTE_USER": "test",
            "REMOTE_ADDR": "127.0.0.1",
        }
        done = subprocess.run(["git", "http-backend"], input=body, capture_output=True, env=environment)
        head, _, payload = done.stdout.partition(b"\r\n\r\n")
        status, headers = 200, []
        for line in head.decode("utf-8", "replace").splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() == "status":
                status = int(value.strip().split()[0])
            elif key.strip():
                headers.append((key.strip(), value.strip()))
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.server.broken and self.command == "POST":
            # The refs are a GET and come whole; the objects are a POST, and half of them comes before the
            # connection closes, short of the length just sent.
            payload = payload[:len(payload) // 2]
        self.wfile.write(payload)

    def authorised(self, authorization):
        if not authorization or not authorization.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(authorization.split(" ", 1)[1]).decode("utf-8", "replace")
        except ValueError:
            return False
        return decoded.partition(":")[2] == self.server.token


class TestFetchCommit:
    """fetch-commit, run as the builder image runs it, against the server above."""

    @pytest.fixture(scope="class", autouse=True)
    def set_up_class(self, request, tmp_path_factory):
        cls = request.cls
        root = tmp_path_factory.mktemp("fetch-commit")
        cls.served = root / "served"
        cls.served.mkdir()
        cls.commits = {}
        for name in ("public", "secret", "outer"):
            work = root / name
            work.mkdir()
            git("init", "-q", str(work))
            (work / "README").write_text(f"{name}\n", encoding="utf-8")
            git("add", "-A", cwd=work)
            if name == "outer":
                # A private library whose tree names secret.git, beside it on the same server, as a submodule: the
                # sibling that fetch-commit --submodules reaches with the helper it set up for outer.git.
                (work / ".gitmodules").write_text('[submodule "sibling"]\n\tpath = sibling\n\turl = ../secret.git\n',
                                                  encoding="utf-8")
                git("add", ".gitmodules", cwd=work)
                git("update-index", "--add", "--cacheinfo", f"160000,{cls.commits['secret']},sibling", cwd=work)
            git("commit", "-qm", "first", cwd=work)
            cls.commits[name] = git("rev-parse", "HEAD", cwd=work)
            # A bare copy for the server, which may serve any commit by its id, so the shallow fetch of one commit
            # works as it does against GitHub.
            bare = cls.served / f"{name}.git"
            git("clone", "-q", "--bare", str(work), str(bare))
            git("-C", str(bare), "config", "uploadpack.allowAnySHA1InWant", "true")
            git("-C", str(bare), "config", "uploadpack.allowTipSHA1InWant", "true")
        cls.server = GitServer(cls.served, {"secret.git", "outer.git"}, TOKEN)
        request.addfinalizer(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # Registered once the server serves: shutdown() waits for serve_forever() to end, and runs before
        # server_close().
        request.addfinalizer(cls.server.shutdown)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.tmp_path, self.directories = tmp_path, 0

    def new_directory(self):
        """A new empty directory in this test's tmp_path, so that each fetch starts with none of another's files."""
        self.directories += 1
        directory = self.tmp_path / f"scratch-{self.directories}"
        directory.mkdir()
        return directory

    def fetch(self, repository, commit, token=None, changes=None, submodules=False):
        """Run fetch-commit for one repository and commit, with `token` in a file as the secret mount holds it,
        `changes` made to its environment (None removes a variable), and --submodules if `submodules`. Return (exit
        code, everything it wrote, the commit checked out)."""
        self.server.seen.clear()
        work = self.new_directory()
        environment = {
            # The builder image installs the credential helper in /usr/local/bin; here it is where it lives.
            "PATH": f"{HELPER.parent}:{os.environ['PATH']}",
            "HOME": str(work),
            "REPO": HOST + repository,
            "COMMIT": commit,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            # The server is on http, and fetch-commit takes https:// only, so git rewrites the URL. A specific
            # protocol.<name>.allow outranks the protocol.allow=never that fetch-commit itself passes, so this
            # changes the transport and nothing else about what is being tested.
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "protocol.http.allow",
            "GIT_CONFIG_VALUE_0": "always",
            "GIT_CONFIG_KEY_1": f"url.{self.base}.insteadOf",
            "GIT_CONFIG_VALUE_1": HOST,
            # git rewrites the URL, so the repository the credential helper is told to answer for must be the
            # one it is really asked about. A build sets neither this nor the token file: fetch-commit derives
            # the scope from REPO, and nothing rewrites a build's URL.
            "OSS_VERIFY_TOKEN_REPO": f"{self.base.partition('//')[2].rstrip('/')}/{repository}",
        }
        if token is not None:
            secret = work / "token"
            secret.write_text(token, encoding="utf-8")
            secret.chmod(0o600)
            environment["OSS_VERIFY_TOKEN_FILE"] = str(secret)
        else:
            # Point the default at a path that is not there: a host running the tests has no secret mount, and
            # this says so rather than depending on that.
            environment["OSS_VERIFY_TOKEN_FILE"] = str(work / "no-token")
        for name, value in (changes or {}).items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        checkout = work / "checkout"
        done = subprocess.run(["sh", str(FETCH_COMMIT), *(["--submodules"] if submodules else []), str(checkout)],
                              capture_output=True, text=True, env=environment)
        head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip()
        return done.returncode, done.stdout + done.stderr, head

    def test_a_public_library_is_fetched_with_no_credential(self):
        code, said, head = self.fetch("public.git", self.commits["public"])
        assert code == 0, said
        assert head == self.commits["public"]
        assert [authorization for _, authorization in self.server.seen if authorization] == [], \
            "a public library's fetch sent a credential"

    def test_a_private_library_with_no_token_says_it_was_not_authorised(self):
        code, said, _ = self.fetch("secret.git", self.commits["secret"])
        assert code == 1
        assert "not authorised to read" in said
        assert "with no credential" in said
        assert "has no commit" not in said

    def test_a_private_library_with_the_token_is_fetched(self):
        code, said, head = self.fetch("secret.git", self.commits["secret"], TOKEN)
        assert code == 0, said
        assert head == self.commits["secret"]
        assert any(authorization for _, authorization in self.server.seen), \
            "the fetch of a private library sent no credential"

    def test_the_token_is_in_nothing_the_fetch_writes(self):
        for name, commit, token, ok in (("secret.git", self.commits["secret"], TOKEN, True),
                                        ("secret.git", self.commits["secret"], OTHER_TOKEN, False),
                                        ("secret.git", "f" * 40, TOKEN, False)):
            case = f"name={name}, commit={commit}, ok={ok}"
            code, said, _ = self.fetch(name, commit, token)
            assert (code == 0) == ok, f"{case}: {said}"
            assert token not in said, case
            assert token[4:] not in said, case

    @pytest.mark.parametrize("target", ["eventTarget", "normalTarget", "perfTarget"])
    def test_a_trace_a_configuration_file_sets_is_not_written(self, tmp_path, target):
        # trace2's targets can be set in a configuration file. fetch-commit sets each target's variable to 0, and that
        # alone stops it: `-c trace2.eventTarget=` and the like did not (measured on git 2.43).
        trace = tmp_path / "trace"
        config = tmp_path / "gitconfig"
        config.write_text(f"[trace2]\n\t{target} = {trace}\n\tenvVars = OSS_VERIFY_TOKEN_FILE\n",
                          encoding="utf-8")
        code, said, _ = self.fetch("secret.git", self.commits["secret"], TOKEN,
                                   changes={"GIT_CONFIG_GLOBAL": str(config)})
        assert code == 0, said
        written = trace.read_text(encoding="utf-8", errors="replace") if trace.exists() else ""
        assert TOKEN not in written
        assert not trace.exists(), written[:500]

    def test_a_wrong_token_says_it_was_not_authorised_and_names_the_token(self):
        code, said, _ = self.fetch("secret.git", self.commits["secret"], OTHER_TOKEN)
        assert code == 1
        assert "not authorised to read" in said
        assert "a read-only token minted for this build" in said
        assert "has no commit" not in said

    @pytest.mark.parametrize("name, token", [pytest.param("public.git", None, id="public.git"),
                                             pytest.param("secret.git", TOKEN, id="secret.git")])
    def test_a_commit_that_is_not_there_is_not_an_authorisation_failure(self, name, token):
        code, said, _ = self.fetch(name, "f" * 40, token)
        assert code == 1
        assert "has no commit" in said
        assert "neither an authorisation failure nor a transfer that broke" in said
        assert "not authorised to read" not in said

    def test_a_repository_that_is_not_there_reads_as_unreadable(self):
        code, said, _ = self.fetch("absent.git", self.commits["public"])
        assert code == 1
        assert "not authorised to read" in said
        assert "has no commit" not in said

    def test_the_checkout_keeps_no_credential(self, tmp_path):
        secret = tmp_path / "token"
        secret.write_text(TOKEN, encoding="utf-8")
        checkout = tmp_path / "checkout"
        environment = {
            "PATH": f"{HELPER.parent}:{os.environ['PATH']}", "HOME": str(tmp_path), "REPO": HOST + "secret.git",
            "COMMIT": self.commits["secret"], "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "OSS_VERIFY_TOKEN_FILE": str(secret),
            "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "protocol.http.allow",
            "GIT_CONFIG_VALUE_0": "always", "GIT_CONFIG_KEY_1": f"url.{self.base}.insteadOf",
            "GIT_CONFIG_VALUE_1": HOST,
            "OSS_VERIFY_TOKEN_REPO": f"{self.base.partition('//')[2].rstrip('/')}/secret.git",
        }
        done = subprocess.run(["sh", str(FETCH_COMMIT), str(checkout)], capture_output=True, text=True,
                              env=environment)
        assert done.returncode == 0, done.stderr
        # Everything the fetch left behind: the remote is REPO as it was given, and no file of the checkout
        # holds the token.
        assert git("-C", str(checkout), "remote", "get-url", "origin") == HOST + "secret.git"
        holding = [str(path) for path in checkout.rglob("*")
                   if path.is_file() and TOKEN.encode() in path.read_bytes()]
        assert holding == []

    def recorded(self, repository, commit, token, changes):
        """fetch() with a stand-in git first on PATH, which writes down the arguments and the environment of each
        call and then runs the real git with them. Return (exit code, everything fetch-commit wrote, one (arguments,
        environment) for each call of git)."""
        directory = self.new_directory()
        stand_in, calls = directory / "bin", directory / "calls"
        stand_in.mkdir()
        calls.mkdir()
        (stand_in / "git").write_text(f"#!/bin/sh\ncall=$(mktemp -d {shlex.quote(str(calls))}/XXXXXX)\n"
                                      "printf '%s\\0' \"$@\" > \"$call/argv\"\nenv -0 > \"$call/env\"\n"
                                      f"exec {shlex.quote(shutil.which('git'))} \"$@\"\n", encoding="utf-8")
        (stand_in / "git").chmod(0o755)
        code, said, _ = self.fetch(repository, commit, token,
                                   {"PATH": f"{stand_in}:{HELPER.parent}:{os.environ['PATH']}", **changes})
        ran = [((call / "argv").read_text(encoding="utf-8").split("\0")[:-1],
                dict(entry.partition("=")[::2]
                     for entry in (call / "env").read_text(encoding="utf-8").split("\0")[:-1]))
               for call in calls.iterdir()]
        return code, said, ran

    def test_with_no_repository_given_the_helper_answers_for_repo_alone(self):
        # A build sets no OSS_VERIFY_TOKEN_REPO, so fetch-commit derives it from REPO, and asks for the path the
        # helper matches on. git is sent to this server in place of REPO's host, which makes this server the other
        # host a submodule could name: it must get no credential, and the fetch fails as an unauthorised one.
        code, said, ran = self.recorded("secret.git", self.commits["secret"], TOKEN, {"OSS_VERIFY_TOKEN_REPO": None})
        reaching = [(argv, environment) for argv, environment in ran if "credential.helper=oss-verify" in argv]
        assert reaching, f"fetch-commit ran no git that reaches the server: {ran}"
        for argv, environment in reaching:
            assert environment.get("OSS_VERIFY_TOKEN_REPO") == "private.test/secret.git", argv
            assert "credential.useHttpPath=true" in argv
        assert [authorization for _, authorization in self.server.seen if authorization] == [], \
            "the helper answered for a server that is not REPO's"
        assert code == 1, said
        assert "not authorised to read" in said

    def test_on_repos_own_host_the_helper_answers_for_repo_and_not_for_a_sibling(self):
        # REPO is named by this server's own host and no OSS_VERIFY_TOKEN_REPO is set, so the scope is the one
        # fetch-commit derives. outer.git's submodule is secret.git, on the same host and served only with the
        # token, so --submodules asks the same helper for both: it must answer for REPO's path and not for the
        # sibling's. Only the same host tells a helper that matches the path from one that matches the host alone.
        host = self.base.partition("//")[2]
        code, said, head = self.fetch("outer.git", self.commits["outer"], TOKEN,
                                      {"REPO": f"https://{host}outer.git", "GIT_CONFIG_VALUE_1": f"https://{host}",
                                       "OSS_VERIFY_TOKEN_REPO": None}, submodules=True)
        sent = {name: [authorization for seen, authorization in self.server.seen if seen == name]
                for name in ("outer.git", "secret.git")}
        assert head == self.commits["outer"], said
        assert any(sent["outer.git"]), f"the helper gave REPO no credential: {said}"
        assert sent["secret.git"], f"the fetch never reached the sibling: {said}"
        assert [authorization for authorization in sent["secret.git"] if authorization] == [], \
            "the helper gave REPO's token to another repository on its host"
        assert code != 0, said

    def test_a_fetch_with_a_token_runs_every_git_with_its_tracing_off(self):
        # Whatever tracing the caller set: each GIT_TRACE* set to 0, the two that 0 turns on removed, and the trace
        # redacted and naming no variable. The host's lists are the container's. The tracing set here writes text to
        # standard error, and the packfile to nowhere, so a fetch that kept it still ends and says what it kept.
        changes = {**{name: "1" for name in check_build.GIT_TRACING}, "GIT_CURL_VERBOSE": "1",
                   "GIT_TRACE_PACKFILE": os.devnull, "GIT_TRACE2_ENV_VARS": "OSS_VERIFY_TOKEN_FILE",
                   "GIT_TRACE_REDACT": "0"}
        code, said, ran = self.recorded("secret.git", self.commits["secret"], TOKEN, changes)
        assert ran, "fetch-commit ran no git"
        for argv, environment in ran:
            for name in check_build.GIT_TRACING:
                assert environment.get(name) == "0", f"{name} of git {argv}"
            for name in check_build.GIT_TRACING_REMOVED:
                assert name not in environment, argv
            assert environment.get("GIT_TRACE2_ENV_VARS") == "", argv
            assert environment.get("GIT_TRACE_REDACT") == "1", argv
        assert code == 0, said

    @pytest.mark.parametrize("name, token", [pytest.param("public", None, id="public"),
                                             pytest.param("secret", TOKEN, id="secret")])
    def test_a_transfer_that_broke_is_not_a_missing_commit(self, monkeypatch, name, token):
        # The second review measured a server that listed its refs and then failed the fetch. The listing says the
        # build may read the repository and nothing about the transfer, so a clone that broke after it is not a
        # repository without the commit.
        monkeypatch.setattr(self.server, "broken", True)
        code, said, _ = self.fetch(f"{name}.git", self.commits[name], token)
        assert code == 1, said
        assert "although the server listed its refs for this build" in said
        assert "has no commit" not in said
        assert "not authorised to read" not in said
        assert "could not reach" not in said


class TestCredentialHelper:
    """git-credential-oss-verify: the one place the token is read."""

    def answer(self, request="protocol=https\nhost=github.com\n\n", **environment):
        done = subprocess.run(["sh", str(HELPER), "get"], input=request, capture_output=True, text=True,
                              env={"PATH": os.environ["PATH"], **environment})
        return done.returncode, done.stdout

    def test_it_reads_the_token_from_the_environment(self):
        code, said = self.answer(OSS_VERIFY_GIT_TOKEN=TOKEN)
        assert code == 0
        assert said == f"username=x-access-token\npassword={TOKEN}\n"

    def test_it_reads_the_token_from_the_secret_mount(self, tmp_path):
        secret = tmp_path / "secret.token"
        secret.write_text(TOKEN, encoding="utf-8")
        code, said = self.answer(OSS_VERIFY_TOKEN_FILE=str(secret))
        assert code == 0
        assert f"password={TOKEN}" in said

    def test_with_no_token_it_answers_nothing_rather_than_prompting(self):
        code, said = self.answer()
        assert (code, said) == (0, "")

    def test_it_stores_nothing(self):
        for operation in ("store", "erase"):
            done = subprocess.run(["sh", str(HELPER), operation], input="protocol=https\nhost=github.com\n\n",
                                  capture_output=True, text=True,
                                  env={"PATH": os.environ["PATH"], "OSS_VERIFY_GIT_TOKEN": TOKEN})
            assert (done.returncode, done.stdout) == (0, ""), operation


class TestTheList:
    """infra/private-libraries.tsv: the only thing that makes a build ask for a token."""

    def test_a_public_library_is_not_in_it(self):
        assert check_build.private_reason("https://github.com/DaveGamble/cJSON") is None
        assert check_build.private_reason("https://github.com/theorem-labs/oss-verify") is None

    def test_one_repository_written_three_ways_is_one_row(self):
        for written in ("https://github.com/theorem-labs/theorem-cli",
                        "https://github.com/theorem-labs/theorem-cli.git",
                        "https://github.com/theorem-labs/theorem-cli/",
                        "https://github.com/theorem-labs/theorem-cli#main"):
            assert check_build.private_reason(written) is not None, written

    def test_every_row_is_a_repository_with_a_reason(self):
        text = check_build.PRIVATE_LIBRARIES.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            repository, tab, why = line.partition("\t")
            assert tab == "\t", f"{line!r} has no tab"
            assert re.search(r"\Ahttps://[^\s]+/[^\s/]+\Z", repository)
            assert why.strip(), f"{repository} has no reason"

    def test_the_owner_and_name_are_what_a_token_is_narrowed_to(self):
        assert check_build.owner_and_name("https://github.com/theorem-labs/theorem-cli.git") == \
            ("theorem-labs", "theorem-cli")


class TestMinting:
    """mint_token: one token for one repository and one build, and no value of it in a message."""

    @contextlib.contextmanager
    def command(self, script):
        """Point OSS_VERIFY_GIT_TOKEN_COMMAND at a shell script while the block runs."""
        path = self.directory / "token-command"
        path.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
        path.chmod(0o755)
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv(check_build.TOKEN_COMMAND_ENV, str(path))
            yield

    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path):
        self.directory = tmp_path

    def test_it_runs_the_command_with_the_owner_and_the_name(self):
        with self.command(f'echo "$1/$2 {TOKEN}"'):
            assert check_build.mint_token("https://github.com/theorem-labs/theorem-cli") == \
                f"theorem-labs/theorem-cli {TOKEN}"

    def test_a_command_that_fails_says_so_without_quoting_a_token(self):
        with self.command(f'echo "refused, the token was {TOKEN}" >&2; exit 1'):
            with pytest.raises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        assert "exited 1" in str(refused.value)
        assert TOKEN not in str(refused.value)
        assert "<redacted>" in str(refused.value)

    def test_a_command_that_prints_nothing_is_not_a_token(self):
        with self.command("exit 0"):
            with pytest.raises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        assert "printed no token" in str(refused.value)

    def test_a_command_that_is_not_there_says_which(self):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv(check_build.TOKEN_COMMAND_ENV, "/nonexistent/mint")
            with pytest.raises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        assert "/nonexistent/mint" in str(refused.value)


class TestWhereTheTokenIsNot:
    """The places a token must not reach: a command line, a build argument, the log, a message."""

    def test_a_public_fetch_takes_the_same_git_it_always_did(self):
        assert check_build.git("ls-remote", "--", "https://example.invalid/x") == \
            ["git", "-c", "credential.helper=", "-c", "protocol.allow=never",
             "-c", "protocol.https.allow=always", "ls-remote", "--", "https://example.invalid/x"]
        assert check_build.git_environment(None) is None

    def test_a_token_is_in_the_environment_and_not_the_command_line(self):
        argv = check_build.git("ls-remote", "--", "https://example.invalid/x", token=True)
        assert TOKEN not in " ".join(argv)
        assert f"credential.helper=!{check_build.CREDENTIAL_HELPER}" in argv
        # The empty helper still comes first, so a helper the host configured is not used.
        assert argv[1:3] == ["-c", "credential.helper="]
        assert check_build.git_environment(TOKEN)[check_build.GIT_TOKEN_ENV] == TOKEN

    def test_the_log_of_a_build_has_the_token_replaced_even_across_a_read(self):
        # The token straddles the boundary of the 64 KiB reads that run() makes, which is where a filter that looks
        # at one chunk at a time lets it through.
        script = f"import sys; sys.stdout.write('x' * 65534 + {TOKEN!r} + 'y')"
        printed = Printed()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "stdout", printed)
            code = check_build.run(sys.executable, "-c", script, token=TOKEN)
        assert code == 0
        assert TOKEN not in printed.text
        assert "<redacted>" in printed.text

    def test_the_log_of_a_public_build_is_not_filtered(self):
        printed = Printed()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "stdout", printed)
            check_build.run(sys.executable, "-c", "print('ordinary output')")
        assert printed.text.strip() == "ordinary output"

    def test_anything_token_shaped_is_replaced_even_with_no_token_to_compare(self):
        assert check_build.redacted(f"said {TOKEN} loudly", None) == "said <redacted> loudly"
        assert check_build.redacted("github_pat_" + "a" * 30, None) == "<redacted>"
        assert check_build.redacted("nothing to hide", None) == "nothing to hide"

    def test_the_build_of_a_private_library_passes_a_secret_and_no_build_argument(self, tmp_path):
        argv, environment = self.build(tmp_path, private=True, mount=True)
        assert "--secret" in argv
        assert f"id={check_build.GIT_TOKEN_SECRET},env={check_build.GIT_TOKEN_ENV}" in argv
        assert TOKEN not in " ".join(argv)
        assert environment[check_build.GIT_TOKEN_ENV] == TOKEN
        assert [argument for argument in argv if argument.startswith("--build-arg")] == ["--build-arg"] * 3

    def test_the_build_of_a_public_library_passes_no_secret_and_no_environment(self, tmp_path):
        argv, environment = self.build(tmp_path, private=False, mount=False)
        assert "--secret" not in argv
        assert environment is None

    def build(self, directory, *, private, mount):
        """Run build_project in `directory` with docker stubbed out, and return the argv and environment it would
        have used."""
        fetch = f"RUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x" if mount else "RUN fetch-commit $SRC/x"
        (directory / "Dockerfile").write_text(f"FROM ${{BASE_BUILDER}}\nARG REPO\nARG COMMIT\n{fetch}\n",
                                              encoding="utf-8")
        job = Job(name="x", directory=directory, repo="https://github.com/theorem-labs/theorem-cli", ref="",
                  dockerfile="", builds=["plain"], fuzz_targets=None)
        seen = {}

        def stub(*argv, quiet=False, env=None, token=None):
            seen["argv"], seen["env"] = list(argv), env
            return 0

        with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()):
            patch.setattr(check_build, "run", stub)
            check_build.build_project(job, "a" * 40, "builder", "tag", directory, token=TOKEN if private else None)
        return seen["argv"], seen["env"]


class TestTheMountAndTheList:
    """A build is refused when the Dockerfile and infra/private-libraries.tsv disagree. The Dockerfile is parsed,
    not searched: before it was, a comment counted as a mount, an id that merely started with ours counted, a
    mount on another step counted, and a reordered or continued one did not count at all."""

    PRIVATE = "https://github.com/theorem-labs/theorem-cli"
    PUBLIC = "https://github.com/DaveGamble/cJSON"
    MOUNTED = f"FROM x\nRUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x\n"

    def refuses(self, text, token, where):
        with pytest.raises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, token, where)
        assert TOKEN not in str(refused.value)
        return str(refused.value)

    def test_a_private_library_whose_fetch_step_does_not_mount_the_secret_is_refused(self):
        said = self.refuses("FROM x\nRUN fetch-commit $SRC/x\n", TOKEN, self.PRIVATE)
        assert "does not mount it" in said
        assert check_build.SECRET_MOUNT in said

    def test_a_library_that_is_not_private_may_not_mount_the_secret(self):
        assert "is not in infra/private-libraries.tsv" in self.refuses(self.MOUNTED, None, self.PUBLIC)

    def test_the_two_that_agree_are_allowed(self):
        check_build.check_secret_mount("Dockerfile", "FROM x\nRUN fetch-commit $SRC/x\n", None, self.PUBLIC)
        check_build.check_secret_mount("Dockerfile", self.MOUNTED, TOKEN, self.PRIVATE)

    def test_a_comment_is_not_a_mount(self):
        # Both directions: a public Dockerfile may say in a comment what the mount would be, and a private one
        # that only says it in a comment has no mount.
        documented = f"FROM x\n# RUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x\nRUN fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", documented, None, self.PUBLIC)
        assert "does not mount it" in self.refuses(documented, TOKEN, self.PRIVATE)

    def test_another_secret_whose_id_begins_with_ours_is_another_secret(self):
        text = f"FROM x\nRUN --mount=type=secret,id={check_build.GIT_TOKEN_SECRET}-other fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, None, self.PUBLIC)
        assert "does not mount it" in self.refuses(text, TOKEN, self.PRIVATE)

    def test_a_mount_on_another_step_does_not_put_it_on_the_fetch(self):
        text = (f"FROM x\nRUN {check_build.SECRET_MOUNT} true\nRUN fetch-commit $SRC/x\n")
        assert "a fetch step in Dockerfile does not mount it" in self.refuses(text, TOKEN, self.PRIVATE)
        # It is still a mount, so a public library may not have it either.
        assert "is not in infra/private-libraries.tsv" in self.refuses(text, None, self.PUBLIC)

    @pytest.mark.parametrize("text", [
        pytest.param(f"FROM x\nRUN --mount=id={check_build.GIT_TOKEN_SECRET},type=secret fetch-commit $SRC/x\n",
                     id="id-before-type"),
        pytest.param(f"FROM x\nRUN {check_build.SECRET_MOUNT} \\\n    fetch-commit $SRC/x\n",
                     id="continued-after-the-mount"),
        pytest.param(f"FROM x\nRUN \\\n  {check_build.SECRET_MOUNT} \\\n  fetch-commit $SRC/x\n",
                     id="continued-around-the-mount"),
        pytest.param(f"FROM x\nRUN {check_build.SECRET_MOUNT},required=true fetch-commit $SRC/x\n",
                     id="with-required-true"),
    ])
    def test_a_reordered_or_continued_mount_is_still_a_mount(self, text):
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        assert "is not in infra/private-libraries.tsv" in self.refuses(text, None, self.PUBLIC)

    def test_a_comment_between_the_lines_of_a_continued_instruction_is_a_comment(self):
        text = f"FROM x\nRUN {check_build.SECRET_MOUNT} \\\n# a comment docker skips\n    fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_private_dockerfile_with_no_fetch_step_at_all_says_so(self):
        assert "no fetch-commit step at all" in self.refuses("FROM x\nRUN true\n", TOKEN, self.PRIVATE)

    def test_no_project_in_this_repository_mounts_the_secret(self):
        # Every library enrolled here is public, so none of their Dockerfiles may ask for a credential.
        asking = [str(path.relative_to(ROOT)) for path in (ROOT / "projects").rglob("Dockerfile")
                  if any(check_build.GIT_TOKEN_SECRET in check_build.secret_mounts(line)
                         for line in check_build.instructions(path.read_text(encoding="utf-8", errors="replace")))
                  and check_build.private_reason(repo_of(path)) is None]
        assert asking == []


class TestTheScopeOfTheHelper:
    """The helper answers for one repository. git asks a helper for every server it reaches, and
    `git submodule update --recursive` reaches whatever servers the tree names."""

    def answer(self, request, **environment):
        done = subprocess.run(["sh", str(HELPER), "get"], input=request, capture_output=True, text=True,
                              env={"PATH": os.environ["PATH"], "OSS_VERIFY_GIT_TOKEN": TOKEN, **environment})
        return done.returncode, done.stdout

    def request(self, host, path=None):
        return f"protocol=https\nhost={host}\n" + (f"path={path}\n" if path is not None else "") + "\n"

    @pytest.mark.parametrize("path", ["theorem-labs/theorem-cli", "theorem-labs/theorem-cli.git",
                                      "/theorem-labs/theorem-cli"])
    def test_it_answers_for_the_repository_it_was_given(self, path):
        code, said = self.answer(self.request("github.com", path),
                                 OSS_VERIFY_TOKEN_REPO="github.com/theorem-labs/theorem-cli")
        assert code == 0
        assert f"password={TOKEN}" in said

    @pytest.mark.parametrize("host, path", [
        pytest.param("github.com", "theorem-labs/something-else", id="another-repository"),
        pytest.param("github.com", "someone/theorem-cli", id="another-owner"),
        pytest.param("gitlab.example.invalid", "theorem-labs/theorem-cli", id="another-host"),
    ])
    def test_it_answers_nothing_for_another_repository_or_another_host(self, host, path):
        code, said = self.answer(self.request(host, path),
                                 OSS_VERIFY_TOKEN_REPO="github.com/theorem-labs/theorem-cli")
        assert (code, said) == (0, "")

    def test_with_no_path_the_host_alone_decides(self):
        # credential.useHttpPath off at the caller: there is nothing more to match on, and refusing every request
        # would leave no way to fetch at all.
        code, said = self.answer(self.request("github.com"), OSS_VERIFY_TOKEN_REPO="github.com")
        assert f"password={TOKEN}" in said


class TestNoTracing:
    """git's own tracing writes what it sends. GIT_TRACE_CURL with GIT_TRACE_REDACT=0 puts the Authorization
    header in a file that outlives the build, so a fetch with a token does not trace, whatever the caller set."""

    def test_the_host_environment_has_no_tracing_and_redacts(self):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("GIT_TRACE_CURL", "/tmp/trace")
            patch.setenv("GIT_TRACE", "1")
            patch.setenv("GIT_TRACE_REDACT", "0")
            patch.setenv("GIT_CURL_VERBOSE", "1")
            patch.setenv("GIT_TRACE_PACKFILE", "/tmp/pack")
            environment = check_build.git_environment(TOKEN, "https://github.com/theorem-labs/theorem-cli")
        # Set to 0, not removed: git reads trace2's targets from configuration too, and an environment variable
        # of 0 turns a target off whatever the configuration says.
        for name in check_build.GIT_TRACING:
            assert environment[name] == "0", name
        # GIT_CURL_VERBOSE=0 ENABLES curl's tracing and GIT_TRACE_PACKFILE=0 writes a packfile to a file called 0,
        # so those two are removed instead of set.
        for name in check_build.GIT_TRACING_REMOVED:
            assert name not in environment
        assert environment["GIT_TRACE2_ENV_VARS"] == ""
        assert environment["GIT_TRACE_REDACT"] == "1"
        assert environment["OSS_VERIFY_TOKEN_REPO"] == "github.com/theorem-labs/theorem-cli"

    def test_a_public_fetch_keeps_the_environment_it_had(self):
        assert check_build.git_environment(None) is None


class TestEverySplit:
    """A token that arrives in two reads is still redacted, at every place it can be cut. The first filter replaced
    the buffer by TOKEN_SHAPE before holding the tail back, and that shape matches a 44-character token's first 24
    characters, so the first half became <redacted> and the second half was printed."""

    def printed(self, first, second):
        """What run() prints of a command that writes `first` and then `second`, in two reads: the command is a pipe
        that this process writes, and `second` is written only once run()'s reader has printed what it made of
        `first`, the text before the token's beginning, which it does not hold back. No process is started, and
        nothing sleeps."""
        reading, writing = os.pipe()
        output, command = os.fdopen(reading, "rb"), os.fdopen(writing, "wb", buffering=0)
        first_printed = threading.Event()

        class Stdout(Printed):
            def write(self, text):
                super().write(text)
                first_printed.set()

        class Command:
            """run()'s Popen, whose output is the pipe. run() starts its reader and then waits for the command."""

            def __init__(self, argv, **options):
                self.stdout = output

            def wait(self):
                command.write(first.encode())
                # Written before the reader has read the first half, the second could arrive in the same read, and
                # the split would not be tested at all.
                if not first_printed.wait(timeout=20):
                    raise AssertionError("run() printed nothing of the first read")
                command.write(second.encode())
                command.close()
                return 0

        printed = Stdout()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "stdout", printed)
            patch.setattr(check_build.subprocess, "Popen", Command)
            try:
                assert check_build.run("command", token=TOKEN) == 0
            finally:
                command.close()
                output.close()
        return printed.text

    def test_no_split_of_a_token_across_two_writes_leaks_any_of_it(self):
        for split in range(1, len(TOKEN)):
            assert self.printed("x" * 10 + TOKEN[:split], TOKEN[split:] + "|end") == \
                "x" * 10 + "<redacted>|end", f"split={split}"
        # The first split and the middle one also from a real command: the two halves are two writes of another
        # process.
        for split in (1, len(TOKEN) // 2):
            script = (f"import sys, time; sys.stdout.write('x' * 10 + {TOKEN[:split]!r}); sys.stdout.flush(); "
                      f"time.sleep(0.02); sys.stdout.write({TOKEN[split:]!r} + '|end')")
            printed = Printed()
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(sys, "stdout", printed)
                check_build.run(sys.executable, "-c", script, token=TOKEN)
            assert printed.text == "x" * 10 + "<redacted>|end", f"split={split}, command={sys.executable}"

    def test_held_back_is_the_longest_beginning_of_the_token(self):
        assert check_build.held_back("nothing here", TOKEN) == 0
        assert check_build.held_back("xx" + TOKEN[:7], TOKEN) == 7
        # A whole token is replaced before the tail is measured, which is what run() does with it: what is left
        # cannot be the beginning of another one.
        assert check_build.held_back("xx" + "\0" * len(TOKEN), TOKEN) == 0

    def test_a_public_build_is_not_filtered_at_all(self):
        printed = Printed()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "stdout", printed)
            check_build.run(sys.executable, "-c", f"print({TOKEN!r})")
        assert printed.text.strip() == TOKEN


class TestWhichFailure:
    """A cause reported as a different cause is the bug this change exists to remove, so a host that cannot be
    reached must not read as a host that refused."""

    def test_refs_listed_is_not_proof_that_the_commit_is_missing(self):
        # The refs listing says the build may read the repository. It says nothing about whether the objects came,
        # so the message names both and does not pick one.
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "output", lambda *args, **kwargs: "deadbeef\trefs/heads/main\n")
            message = check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli", "a" * 40, TOKEN)
        assert "could not fetch" in message
        assert "not an authorisation failure" in message
        assert "the objects did not come" in message

    def test_the_container_tells_a_connection_failure_from_a_refusal(self, tmp_path):
        # A port nothing listens on: ls-remote fails, and the message must not say "not authorised".
        with closed_port() as port:
            secret = tmp_path / "token"
            secret.write_text(TOKEN, encoding="utf-8")
            environment = {
                "PATH": f"{HELPER.parent}:{os.environ['PATH']}", "HOME": str(tmp_path),
                "REPO": "https://private.test/secret.git", "COMMIT": "a" * 40,
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                "OSS_VERIFY_TOKEN_FILE": str(secret), "OSS_VERIFY_TOKEN_REPO": "127.0.0.1/secret.git",
                "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "protocol.http.allow",
                "GIT_CONFIG_VALUE_0": "always",
                "GIT_CONFIG_KEY_1": f"url.http://127.0.0.1:{port}/.insteadOf",
                "GIT_CONFIG_VALUE_1": "https://private.test/",
            }
            done = subprocess.run(["sh", str(FETCH_COMMIT), str(tmp_path / "checkout")],
                                  capture_output=True, text=True, env=environment)
        said = done.stdout + done.stderr
        assert done.returncode == 1
        assert "could not reach" in said
        assert "not authorised to read" not in said
        assert "has no commit" not in said
        assert TOKEN not in said


class TestUnreadable:
    """What the host says when it cannot list a repository's refs."""

    def test_it_names_authorisation_and_not_a_missing_commit(self):
        said = check_build.unreadable("https://github.com/theorem-labs/theorem-cli", TOKEN, "remote: Not Found")
        assert "read-only token minted for this build" in said
        assert "this is not a missing commit" in said
        assert TOKEN not in said

    def test_it_says_when_the_repository_is_not_on_the_list(self):
        said = check_build.unreadable("https://github.com/theorem-labs/not-listed", None, "remote: Not Found")
        assert "with no credential" in said
        assert "not in infra/private-libraries.tsv" in said

    def test_a_failure_that_is_not_an_authorisation_one_keeps_gits_own_message(self):
        def fails(*args, **kwargs):
            raise Failed("could not resolve host: example.invalid")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "output", fails)
            with pytest.raises(Failed) as refused:
                check_build.resolve("https://example.invalid/x", "main")
        assert str(refused.value) == "could not resolve host: example.invalid"

    def test_an_authorisation_failure_is_rewritten(self):
        def fails(*args, **kwargs):
            raise Failed("remote: Repository not found.\nfatal: repository not found")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "output", fails)
            with pytest.raises(Failed) as refused:
                check_build.resolve("https://github.com/theorem-labs/theorem-cli", "main")
        assert "cannot read" in str(refused.value)
        assert "this is not a missing commit" in str(refused.value)


class TestTheSecondReview:
    """What the second non-author review measured at 1eb1c2a, and what this change does about it."""

    @pytest.mark.parametrize("target", ["eventTarget", "normalTarget", "perfTarget"])
    def test_a_trace_a_configuration_file_sets_is_not_written(self, tmp_path, target):
        # trace2's targets can be set in a configuration file, where trace2.envVars can name the variable that holds
        # the token, which GIT_TRACE_REDACT does not redact. git_environment() sets each target's variable to 0, and
        # that alone stops it: `-c trace2.eventTarget=` and the like did not (measured on git 2.43).
        trace = tmp_path / "trace"
        config = tmp_path / "gitconfig"
        config.write_text(f"[trace2]\n\t{target} = {trace}\n\tenvVars = {check_build.GIT_TOKEN_ENV}\n",
                          encoding="utf-8")
        argv = check_build.git("ls-remote", "--", "https://127.0.0.1:1/x", token=True)
        environment = {**check_build.git_environment(TOKEN, "https://127.0.0.1/x"),
                       "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_SYSTEM": "/dev/null"}
        subprocess.run(argv, capture_output=True, text=True, env=environment)
        written = trace.read_text(encoding="utf-8", errors="replace") if trace.exists() else ""
        assert TOKEN not in written
        assert not trace.exists(), written[:500]

    def test_the_host_sends_the_path_so_the_helper_can_match_on_it(self):
        # Without credential.useHttpPath the request carries no path, the helper can only match the host, and it
        # answers for every repository on it.
        assert "credential.useHttpPath=true" in check_build.git("ls-remote", token=True)
        assert "credential.useHttpPath=true" not in check_build.git("ls-remote")

    def test_a_tail_of_an_error_is_cut_after_the_token_is_taken_out_of_it(self, tmp_path):
        # Cutting first left whatever of the token fell inside the last 1500 characters, with no marker for it.
        # The token is read from a file, so it is not in the command line either: what is being measured is the
        # cut of the error text, not the echo of the command.
        secret = tmp_path / "token"
        secret.write_text(TOKEN + "y" * 1400, encoding="utf-8")
        script = tmp_path / "say.py"
        script.write_text(f"import sys; sys.stderr.write(open({str(secret)!r}).read()); raise SystemExit(1)",
                          encoding="utf-8")
        with pytest.raises(Failed) as refused:
            check_build.output(sys.executable, str(script), token=TOKEN)
        assert TOKEN not in str(refused.value)
        assert TOKEN[-100:] not in str(refused.value)

    def test_a_failed_token_command_is_redacted_before_its_message_is_cut(self, tmp_path):
        command = tmp_path / "mint"
        command.write_text(f"#!/bin/sh\nprintf '%s' '{TOKEN}'>&2\nprintf 'y%.0s' $(seq 1 1400) >&2\nexit 1\n",
                           encoding="utf-8")
        command.chmod(0o755)
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv(check_build.TOKEN_COMMAND_ENV, str(command))
            with pytest.raises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        assert TOKEN not in str(refused.value)
        assert TOKEN[-100:] not in str(refused.value)

    def test_a_run_option_before_the_mount_does_not_hide_it(self):
        text = f"FROM x\nRUN --network=default {check_build.SECRET_MOUNT} fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")

    def test_a_continuation_inside_the_comma_fields_is_still_one_mount(self):
        # The next line starts at column 0, which is the form real BuildKit accepts: a continuation removes the
        # escape and the newline and nothing else, so an INDENTED next line would make `id=...` a separate word
        # and the mount only `type=secret,`. This test asserted the indented form until the third review's
        # measurements showed BuildKit does not read it that way either.
        text = f"FROM x\nRUN --mount=type=secret,\\\nid={check_build.GIT_TOKEN_SECRET} fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")
        indented = f"FROM x\nRUN --mount=type=secret,\\\n    id={check_build.GIT_TOKEN_SECRET} fetch-commit $SRC/x\n"
        with pytest.raises(Failed):
            check_build.check_secret_mount("Dockerfile", indented, TOKEN, "https://x/y/z")

    def test_the_escape_directive_chooses_the_continuation_character(self):
        text = f"# escape=`\nFROM x\nRUN {check_build.SECRET_MOUNT} `\n    fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")

    def test_an_escape_directive_after_a_blank_or_a_comment_line_is_a_comment(self):
        # BuildKit reads directives from the first lines only. Taking this backtick as the escape split the
        # continued, mounted fetch below in two.
        for before in ("\n", "# a comment\n", "# unknown=directive\n", "FROM x\n"):
            text = f"{before}# escape=`\nFROM x\nRUN {check_build.SECRET_MOUNT} \\\n    fetch-commit /src/x\n"
            assert [ids for _, ids in check_build.fetch_steps(text)] == [[check_build.GIT_TOKEN_SECRET]], \
                f"before={before!r}"
        # Directives may come in any order, their names in any case, and after spaces.
        for directives in ("# syntax=docker/dockerfile:1\n# ESCAPE=`\n", "  # escape=`\n"):
            text = f"{directives}FROM x\nRUN {check_build.SECRET_MOUNT} `\n    fetch-commit /src/x\n"
            assert [ids for _, ids in check_build.fetch_steps(text)] == [[check_build.GIT_TOKEN_SECRET]], \
                f"directives={directives!r}"

    def test_echoing_the_name_is_not_running_the_program(self):
        # `RUN --mount=… echo "fetch-commit"` beside a real unmounted fetch passed the guard, and the real fetch
        # then ran with no credential.
        text = f"FROM x\nRUN {check_build.SECRET_MOUNT} echo \"fetch-commit\"\nRUN fetch-commit $SRC/x\n"
        with pytest.raises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")
        assert "does not mount it" in str(refused.value)
        assert not check_build.runs_fetch_commit('RUN echo "fetch-commit"')
        assert check_build.runs_fetch_commit("RUN fetch-commit $SRC/x")
        assert check_build.runs_fetch_commit("RUN /usr/local/bin/fetch-commit $SRC/x")

    def test_every_fetch_step_must_have_the_mount_not_one_of_them(self):
        text = f"FROM x\nRUN {check_build.SECRET_MOUNT} fetch-commit $SRC/a\nRUN fetch-commit $SRC/b\n"
        with pytest.raises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")
        assert "$SRC/b" in str(refused.value)

    def test_a_fetch_the_guard_cannot_read_is_refused_for_a_private_library(self):
        # This test asserted the opposite until the fourth review measured five valid Dockerfiles of these
        # shapes whose real fetch ran with NO secret while the guard said they were mounted. There is no safe
        # side to read them on: the guard refuses and says to write the fetch as its own step.
        heredoc = f"FROM x\nRUN {check_build.SECRET_MOUNT} <<EOT\nfetch-commit $SRC/x\nEOT\n"
        with pytest.raises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", heredoc, TOKEN, "https://x/y/z")
        assert "cannot read" in str(refused.value)
        # A public library is refused only for mounting the secret, and this one does mount it.
        with pytest.raises(Failed):
            check_build.check_secret_mount("Dockerfile", heredoc, None, "https://x/y/z")
        assert check_build.words_of('RUN "unmatched') is None


class TestAServerFault:
    """An HTTP 503 whose body happens to say "permission denied" must not read as a refusal. A review measured
    exactly that text from a real server (`remote: upstream connection permission denied`), and the two markers
    that turned it into one are gone from both copies of the list (TestBothClassifiersAgree gives both a message with
    each word and no status). This drives the whole script against a server that answers that way, not the markers
    on their own."""

    @pytest.fixture(scope="class", autouse=True)
    def set_up_class(self, request):
        cls = request.cls

        class Faulty(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_GET(self):
                body = b"remote: upstream connection permission denied\n"
                self.send_response(503)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Faulty)
        request.addfinalizer(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # Registered once the server serves: shutdown() waits for serve_forever() to end, and runs before
        # server_close().
        request.addfinalizer(cls.server.shutdown)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"

    def test_the_container_calls_it_a_server_it_could_not_reach(self, tmp_path):
        secret = tmp_path / "token"
        secret.write_text(TOKEN, encoding="utf-8")
        environment = {
            "PATH": f"{HELPER.parent}:{os.environ['PATH']}", "HOME": str(tmp_path),
            "REPO": HOST + "secret.git", "COMMIT": "a" * 40,
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
            "OSS_VERIFY_TOKEN_FILE": str(secret),
            "OSS_VERIFY_TOKEN_REPO": f"{self.base.partition('//')[2].rstrip('/')}/secret.git",
            "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "protocol.http.allow",
            "GIT_CONFIG_VALUE_0": "always", "GIT_CONFIG_KEY_1": f"url.{self.base}.insteadOf",
            "GIT_CONFIG_VALUE_1": HOST,
        }
        done = subprocess.run(["sh", str(FETCH_COMMIT), str(tmp_path / "checkout")],
                              capture_output=True, text=True, env=environment)
        said = done.stdout + done.stderr
        assert done.returncode == 1, said
        assert "could not reach" in said
        assert "not authorised to read" not in said
        assert "has no commit" not in said
        assert TOKEN not in said


class TestTheParserAgainstBuildKit:
    """The forms real BuildKit accepts, from the third review's 24 cases. Both directions: a guard that refuses a
    file BuildKit really mounts stops a build that should run, and one that accepts a file BuildKit leaves
    unmounted lets a fetch go out with no credential."""

    MOUNT = check_build.SECRET_MOUNT
    PRIVATE = "https://github.com/theorem-labs/theorem-cli"

    def mounts(self, text):
        return [ids for _, ids in check_build.fetch_steps(text)]

    def test_a_continuation_inside_a_word_joins_it(self):
        # `fetch-\` + `commit` is one word to BuildKit, and the step really ran fetch-commit.
        text = f"FROM x\nRUN {self.MOUNT} fetch-\\\ncommit /src/x\n"
        assert self.mounts(text) == [[check_build.GIT_TOKEN_SECRET]]
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_continuation_inside_a_field_value_joins_it(self):
        text = "FROM x\nRUN --mount=type=secret,id=oss-verify-\\\ngit-token fetch-commit /src/x\n"
        assert self.mounts(text) == [[check_build.GIT_TOKEN_SECRET]]
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_continuation_before_an_indented_line_keeps_the_two_words_apart(self):
        text = f"FROM x\nRUN {self.MOUNT} \\\n    fetch-commit /src/x\n"
        assert self.mounts(text) == [[check_build.GIT_TOKEN_SECRET]]

    def test_a_blank_line_inside_a_continued_instruction_does_not_end_it(self):
        # BuildKit joins across it (and warns NoEmptyContinuation); ending the RUN there lost the mounted fetch,
        # and the guard said there was no fetch-commit step at all.
        for blank in ("", "   ", "\t"):
            text = f"FROM x\nRUN {self.MOUNT} \\\n{blank}\n    fetch-commit /src/x\n"
            assert self.mounts(text) == [[check_build.GIT_TOKEN_SECRET]], f"blank={blank!r}"
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        # Python calls a line of U+001C, U+001D, U+001E or U+001F alone blank, and splitlines() ends a line at the
        # first three. BuildKit does neither: that line ends the RUN, and the fetch below it runs with no mount.
        for character in ("\x1c", "\x1d", "\x1e", "\x1f"):
            text = (f"FROM x\nRUN {self.MOUNT} true \\\n{character}\nRUN fetch-commit /src/y\n"
                    f"RUN {self.MOUNT} fetch-commit /src/x\n")
            with pytest.raises(Failed) as refused:
                check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
            assert "does not mount it: RUN fetch-commit /src/y" in str(refused.value), f"character={character!r}"

    def test_an_escaped_escape_at_the_end_of_a_line_continues_nothing(self):
        # `C:\\` ends its instruction in BuildKit. Read as a continuation, it joined the mounted fetch below into
        # the echo.
        text = f"FROM x\nRUN echo C:\\\\\nRUN {self.MOUNT} fetch-commit /src/x\n"
        assert check_build.instructions(text)[1:] == ["RUN echo C:\\\\", f"RUN {self.MOUNT} fetch-commit /src/x"]
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    @pytest.mark.parametrize("setting", [
        "ARG SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=$SECRET_ID",
        "ENV SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=${SECRET_ID}",
        "ENV SECRET_ID oss-verify-git-token\nRUN --mount=type=secret,id=${SECRET_ID}",
    ], ids=lambda setting: setting.splitlines()[0])
    def test_the_secret_id_may_come_from_an_arg_or_an_env(self, setting):
        # BuildKit expands these and the step really gets the secret, so a guard that reads the literal
        # `$SECRET_ID` refuses a working private build and lets a public one carry a real mount.
        text = f"FROM x\n{setting} fetch-commit /src/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        with pytest.raises(Failed):
            check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")

    def test_an_unset_variable_names_no_secret(self):
        assert self.mounts("FROM x\nRUN --mount=type=secret,id=$NOT_SET fetch-commit /src/x\n") == [[]]

    def test_a_here_string_or_a_shift_opens_no_heredoc(self):
        # A private library's correctly mounted fetch was refused as unreadable for `<<<` or `1<<4` elsewhere.
        for line in ('RUN read -r v <<< "$X"', "RUN read -r v <<<EOT", "RUN echo $((1<<4))", "RUN cat<<EOT"):
            text = f"FROM x\n{line}\nRUN {self.MOUNT} fetch-commit /src/x\nRUN echo EOT\n"
            assert check_build.unreadable_steps(text) == [], f"line={line!r}"
            assert self.mounts(text) == [[check_build.GIT_TOKEN_SECRET]], f"line={line!r}"
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        # A heredoc is still one, with a file descriptor or a dash before its word.
        for opener, word in (("<<EOT", "EOT"), ("<<-EOT", "EOT"), ("2<<EOT", "EOT"), ('<<"EOT"', "EOT"),
                             ("<<1EOT", "1EOT"), ("<<.EOT", ".EOT"), ("<<'9'", "9"), ("<< EOT", "EOT"),
                             ("sh $X<<EOT", "EOT"), ("sh ${X}2<<EOT", "EOT"), ("sh ${X:-${Y}}<<EOT", "EOT")):
            text = f"FROM x\nRUN {self.MOUNT} {opener}\nfetch-commit /src/x\n{word}\n"
            with pytest.raises(Failed) as refused:
                check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
            assert "cannot read" in str(refused.value), f"opener={opener!r}"
        # A heredoc named by U+001F, which Go counts as no space and Python's split() takes away: BuildKit runs its
        # body, here a fetch with no mount, so the RUN that opens it is refused and named.
        text = f"FROM x\nRUN {self.MOUNT} fetch-commit /src/x\nRUN sh <<\x1f\nfetch-commit /src/y\n\x1f\n"
        with pytest.raises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        assert "cannot read" in str(refused.value)
        assert "RUN sh <<" in str(refused.value)
        # BuildKit reads no heredoc from an empty word, so a bare `<<` or `2<<` at the end of a RUN opens none: the
        # RUN after it is an instruction, and its mount is refused for a public library.
        for opener in ("<<", "2<<"):
            text = f"FROM x\nRUN cat {opener}\nRUN {self.MOUNT} true\n"
            with pytest.raises(Failed) as refused:
                check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")
            assert "take the mount off" in str(refused.value), f"empty_word={opener!r}"
        # Nor from a word that starts with expansions, which it keeps as they are: the lines after `$X<<EOT` are
        # instructions too, so a mount there is refused for a public library, even when a `#` line could end a body.
        for opener in ("cat $X<<EOT", 'echo " $X<<#"'):
            text = f"FROM x\nRUN {opener}\nRUN {self.MOUNT} true\n#\n"
            with pytest.raises(Failed) as refused:
                check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")
            assert "take the mount off" in str(refused.value), f"expansions={opener!r}"

    @pytest.mark.parametrize("text", [
        pytest.param(f"FROM x\nRUN {MOUNT} fetch-commit /src/x\n", id="mount-then-fetch"),
        pytest.param(f"FROM x\nRUN --network=default {MOUNT} fetch-commit /src/x\n", id="option-before-the-mount"),
        pytest.param(f"FROM x\nRUN {MOUNT} --network=default fetch-commit /src/x\n", id="option-after-the-mount"),
        pytest.param(f"# escape=`\nFROM x\nRUN {MOUNT} `\n    fetch-commit /src/x\n", id="backtick-escape"),
        pytest.param(f"FROM x\r\nRUN {MOUNT} \\\r\n    fetch-commit /src/x\r\n", id="crlf-line-ends"),
        pytest.param(f'FROM x\nRUN {MOUNT} "fetch-commit" /src/x\n', id="quoted-program"),
    ])
    def test_the_forms_that_already_worked_still_do(self, text):
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)


class TestBothClassifiersAgree:
    """The host's refused() and the container's denied() are the same rule in two languages. A review found them
    apart -- the host corrected, the shell not -- so they are given the same messages here and must answer alike.
    Each message is one a real server produced in that review, or one of its lookalikes."""

    # (what git said, whether the server answered and refused)
    MESSAGES = (
        pytest.param("error: The requested URL returned error: 401", True, id="status-401"),
        pytest.param("error: The requested URL returned error: 403", True, id="status-403"),
        pytest.param("error: The requested URL returned error: 404", True, id="status-404"),
        # A 404 with an empty body: git puts the URL between `repository` and `not found`, and writes no status.
        pytest.param("fatal: repository 'http://127.0.0.1:45677/secret.git/' not found", True,
                     id="404-with-an-empty-body"),
        pytest.param("remote: Repository not found.\nfatal: repository not found", True, id="repository-not-found"),
        pytest.param("fatal: Authentication failed for 'http://127.0.0.1/x.git/'", True, id="authentication-failed"),
        pytest.param("fatal: could not read Username for 'https://github.com': terminal prompts disabled", True,
                     id="username-prompt-disabled"),
        pytest.param("fatal: remote error: access denied", True, id="remote-access-denied"),
        pytest.param("fatal: remote error: permission denied", True, id="remote-permission-denied"),
        # A refusal whose text happens to carry three digits: `\d{3} [A-Za-z]` called these server faults.
        pytest.param("fatal: remote error: access denied after 503 bytes", True, id="access-denied-after-503-bytes"),
        pytest.param("fatal: remote error: access denied on port 500 today", True, id="access-denied-on-port-500"),
        pytest.param("fatal: remote error: access denied on 2026-11-12", True, id="access-denied-on-a-date"),
        pytest.param("error: RPC failed; HTTP 404 curl 22", True, id="rpc-failed-404"),
        pytest.param("error: The requested URL returned error: 429", False, id="status-429"),
        pytest.param("error: The requested URL returned error: 500", False, id="status-500"),
        pytest.param("error: The requested URL returned error: 502", False, id="status-502"),
        pytest.param("error: The requested URL returned error: 503", False, id="status-503"),
        # A server fault may say anything in its body; the status outranks it.
        pytest.param("remote: upstream connection permission denied\nerror: The requested URL returned error: 503",
                     False, id="503-saying-permission-denied"),
        pytest.param("remote: repository not found\nerror: The requested URL returned error: 503", False,
                     id="503-saying-not-found"),
        pytest.param("remote: repository not found; 404 bytes retained\nerror: The requested URL returned error: 503",
                     False, id="503-saying-404-bytes"),
        pytest.param("error: RPC failed; HTTP/1.1 503 curl 22", False, id="rpc-failed-503"),
        pytest.param("fatal: unable to access 'http://127.0.0.1:44037/x.git/': Failed to connect to 127.0.0.1 "
                     "port 44037 after 0 ms: Connection refused", False, id="connection-refused"),
        pytest.param("fatal: unable to access: Could not resolve host: not-a-real-host.invalid", False,
                     id="unresolved-host"),
        # The LAST status is git's own; a body can quote the status of an earlier request.
        pytest.param("remote: your earlier request returned error: 403\nerror: The requested URL returned error: 503",
                     False, id="503-after-a-quoted-403"),
        pytest.param("remote: a previous call returned error: 503\nerror: The requested URL returned error: 403",
                     True, id="403-after-a-quoted-503"),
        # A status outside any list of codes is still a status: enumerating them left 505 and 507 to fall
        # through to the phrases, so a server fault whose body said `access denied` read as a refusal.
        pytest.param("error: The requested URL returned error: 505", False, id="status-505"),
        pytest.param("remote: access denied\nerror: The requested URL returned error: 507", False,
                     id="507-saying-access-denied"),
        # Three digits in a URL are not a status.
        pytest.param("fatal: unable to access 'http://127.0.0.1/404/x.git/': Could not resolve host", False,
                     id="404-in-a-url"),
        # No status, and a word that alone is not a refusal: a connection the machine itself blocked, for which
        # curl writes the system's `Permission denied`, and a server that hung up after a body like the review's
        # 503 one. A bare `permission denied` or `access denied` in either list called these refusals.
        pytest.param("fatal: unable to access 'https://github.com/x/y/': Failed to connect to github.com port 443: "
                     "Permission denied", False, id="connect-permission-denied"),
        pytest.param("remote: upstream connection access denied\nfatal: the remote end hung up unexpectedly", False,
                     id="hung-up-after-access-denied"),
    )

    def container(self, said):
        """The container's denied(), read out of fetch-commit and run on its own."""
        source = FETCH_COMMIT.read_text(encoding="utf-8")
        start = source.index("denied() {")
        body = source[start:source.index("\n}\n", start) + 3]
        script = f"refs_said=$(cat)\n{body}\nif denied; then echo refusal; else echo transport; fi\n"
        done = subprocess.run(["sh", "-c", script], input=said, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return done.stdout.strip()

    @pytest.mark.parametrize("said, refusal", MESSAGES)
    def test_the_two_answer_alike_and_answer_rightly(self, said, refusal):
        want = "refusal" if refusal else "transport"
        assert ("refusal" if check_build.refused(said) else "transport") == want, "the host"
        assert self.container(said) == want, "the container"


class TestTheStatusDecides:
    """Which failure it was is read from the HTTP status first, and from the words only when there is none. A
    body can say anything: the fourth review measured a 503 saying `upstream connection permission denied` and
    another saying `repository not found`, and the round before it a real protocol refusal with no status at
    all. Reading the words first gets one of those wrong whichever words are in the list."""

    def because(self, said):
        def fails(*args, **kwargs):
            raise Failed(said)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(check_build, "output", fails)
            return check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli", "a" * 40, TOKEN)

    @pytest.mark.parametrize("said", [
        pytest.param("remote: upstream connection permission denied\nerror: The requested URL returned error: 503",
                     id="503-saying-permission-denied"),
        pytest.param("remote: repository not found\nerror: The requested URL returned error: 503",
                     id="503-saying-not-found"),
        pytest.param("error: The requested URL returned error: 503", id="status-503"),
        pytest.param("error: The requested URL returned error: 429", id="status-429"),
        pytest.param("fatal: unable to access: 502 Bad Gateway", id="502-bad-gateway"),
    ])
    def test_a_status_outranks_the_body(self, said):
        assert "could not reach" in self.because(said)
        assert not check_build.refused(said)

    @pytest.mark.parametrize("said", [
        pytest.param("error: The requested URL returned error: 403", id="status-403"),
        pytest.param("error: The requested URL returned error: 401", id="status-401"),
        pytest.param("error: The requested URL returned error: 404", id="status-404"),
        pytest.param("fatal: unable to access: 403 Forbidden", id="403-forbidden"),
    ])
    def test_a_refusing_status_is_a_refusal_whatever_the_body(self, said):
        assert "cannot read" in self.because(said)
        assert check_build.refused(said)

    @pytest.mark.parametrize("said", [
        pytest.param("fatal: remote error: access denied", id="remote-access-denied"),
        pytest.param("remote: access denied\nfatal: the remote end hung up unexpectedly",
                     id="access-denied-then-hung-up"),
        pytest.param("fatal: remote error: permission denied", id="remote-permission-denied"),
        pytest.param("remote: Repository not found.", id="repository-not-found"),
        pytest.param("remote: Invalid username or token.", id="invalid-username-or-token"),
        pytest.param("fatal: Authentication failed for 'https://github.com/x/y'", id="authentication-failed"),
        pytest.param("fatal: could not read Username for 'https://github.com'", id="could-not-read-username"),
        pytest.param("fatal: could not read Username for 'https://github.com': terminal prompts disabled",
                     id="username-prompt-disabled"),
    ])
    def test_a_protocol_refusal_with_no_status_is_still_a_refusal(self, said):
        # git's own wording when the server refuses over the protocol rather than over HTTP. Dropping the bare
        # `access denied` marker made these read as a server that did not answer.
        assert check_build.refused(said), said
        assert "cannot read" in self.because(said)

    @pytest.mark.parametrize("said", [
        pytest.param("fatal: unable to access: Could not resolve host: github.com", id="unresolved-host"),
        pytest.param("fatal: unable to access: Failed to connect to github.com port 443: Connection refused",
                     id="connection-refused"),
        pytest.param("fatal: unable to access 'https://github.com/x/y': Failed to connect to github.com port 443: "
                     "Connection refused", id="connection-refused-for-a-url"),
    ])
    def test_a_message_that_is_neither_keeps_being_neither(self, said):
        assert not check_build.refused(said)
        assert "could not reach" in self.because(said)


class TestWhatTheGuardWillNotRead:
    """The forms where whether a fetch happens, and whether it gets the secret, are inside a string. The fourth
    review measured five valid Dockerfiles of these shapes whose real fetch ran with no credential while the
    guard said they were mounted. They are refused for a private library and named, not guessed at."""

    MOUNT = check_build.SECRET_MOUNT
    PRIVATE = "https://github.com/theorem-labs/theorem-cli"

    def refuses(self, text):
        with pytest.raises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        return str(refused.value)

    def test_a_fetch_inside_a_heredoc_body_is_not_read(self):
        assert "cannot read" in self.refuses(f"FROM x\nRUN {self.MOUNT} <<EOT\nfetch-commit /src/x\nEOT\n")

    @pytest.mark.parametrize("command", ['sh -c "fetch-commit /src/x"', "env fetch-commit /src/x",
                                         '/bin/sh -c "fetch-commit /src/x"', 'bash -c "fetch-commit /src/x"'])
    def test_a_fetch_behind_a_command_that_runs_a_command_is_not_read(self, command):
        assert "cannot read" in self.refuses(f"FROM x\nRUN {self.MOUNT} {command}\n")

    def test_the_exec_form_is_read_as_the_program_it_names(self):
        # RUN ["fetch-commit", "/src/y"] is a fetch; a mounted fetch beside it does not excuse it.
        assert check_build.runs_fetch_commit('RUN ["fetch-commit", "/src/y"]')
        assert not check_build.runs_fetch_commit('RUN ["echo", "fetch-commit"]')
        text = f'FROM x\nRUN {self.MOUNT} fetch-commit /src/x\nRUN ["fetch-commit", "/src/y"]\n'
        assert "does not mount it" in self.refuses(text)

    def test_a_double_angle_in_a_comment_is_not_a_heredoc(self):
        text = f"# << not a heredoc\n# RUN {self.MOUNT} fetch-commit /src/x\nFROM x\nRUN fetch-commit /src/y\n"
        assert "does not mount it" in self.refuses(text)
        check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")  # and it mounts nothing

    @pytest.mark.parametrize("text", [
        pytest.param(f"FROM x\nCOPY <<EOF /example\nRUN {MOUNT} fetch-commit /src/x\nEOF\nRUN fetch-commit /src/x\n",
                     id="mount-in-a-heredoc-body"),
        pytest.param("FROM x\nRUN --mount=type=secret,id=oss-verify-git-token-other fetch-commit /src/x\n",
                     id="id-beginning-with-ours"),
        pytest.param(f"# RUN {MOUNT} fetch-commit /src/x\nFROM x\nRUN fetch-commit /src/y\n", id="mount-in-a-comment"),
    ])
    def test_a_public_library_is_refused_only_for_a_mount_it_really_has(self, text):
        # Three valid public Dockerfiles that mount nothing: a heredoc BODY quoting a mount, an id that merely
        # begins with ours, and a mount named in a comment. Looking for the id in the text refused all three.
        check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")


class TestVariablesAsOfTheInstruction:
    """BuildKit expands a mount with the values set ABOVE it, and every value of one ENV against what was set
    before that ENV. One dictionary for the whole file gets both wrong, and the fourth review measured a file
    where that difference decided whether the fetch got a token."""

    PRIVATE = "https://github.com/theorem-labs/theorem-cli"

    def test_one_env_does_not_see_its_own_assignments(self):
        # BuildKit gives SID the OLD value of FIRST, so this fetch gets nothing and must be refused.
        text = ("FROM x\nENV FIRST=old\nENV FIRST=oss-verify-git-token SID=$FIRST\n"
                "RUN --mount=type=secret,id=$SID fetch-commit /x\n")
        with pytest.raises(Failed):
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")

    def test_a_later_assignment_does_not_reach_back(self):
        text = ("FROM x\nENV SID=oss-verify-git-token\nRUN --mount=type=secret,id=$SID fetch-commit /x\n"
                "ENV SID=other\n")
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_an_arg_with_no_default_names_no_secret(self):
        text = "FROM x\nARG SID\nRUN --mount=type=secret,id=$SID fetch-commit /x\n"
        assert [ids for _, ids in check_build.fetch_steps(text)] == [[]]

    def test_the_old_env_form_takes_the_rest_of_the_line(self):
        text = "FROM x\nENV SID oss-verify-git-token\nRUN --mount=type=secret,id=${SID} fetch-commit /x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_chain_of_assignments_reads_in_order(self):
        text = ("FROM x\nENV A=oss-verify-git-token\nENV B=$A\nRUN --mount=type=secret,id=$B fetch-commit /x\n")
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)



class Printed:
    """Stands in for sys.stdout and keeps what was written."""

    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass


def repo_of(dockerfile):
    """The repository of the project a Dockerfile belongs to, from its project.yaml, or "" if there is none."""
    config = dockerfile.parent / "project.yaml"
    if not config.is_file():
        return ""
    found = re.search(r"^repo:\s*(\S+)", config.read_text(encoding="utf-8", errors="replace"), re.MULTILINE)
    return found.group(1) if found else ""


@contextlib.contextmanager
def closed_port():
    """A loopback port nothing listens on, while the block runs: a socket holds it bound and does not listen, so a
    connection to it is refused. The socket stays bound until the block ends, so no other process can take the port
    in the meantime, such as a test server in another pytest-xdist worker, whose answer would replace the refusal."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        yield probe.getsockname()[1]
