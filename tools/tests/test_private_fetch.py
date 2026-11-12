# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""How a build reads a private library of ours, and how it fails when it cannot.

The git half runs against a git server started here, over the loopback interface: `git http-backend`, with one
repository it serves to anyone and one it serves only to a request that carries the right token. No network and no
Docker. fetch-commit is run as the builder image runs it, with REPO and COMMIT in its environment.

    python3 -m pytest tools/tests/test_private_fetch.py
"""
import base64
import contextlib
import http.server
import io
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_build  # noqa: E402
from check_build import Failed, Job  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
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
    unauthenticated request with a refusal rather than the repository."""

    protocol_version = "HTTP/1.0"
    allow_reuse_address = True

    def __init__(self, root, private, token):
        super().__init__(("127.0.0.1", 0), Handler)
        self.root, self.private, self.token = str(root), set(private), token
        self.seen = []  # one (repository, Authorization header or None) for each request, for the tests to read


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
        self.wfile.write(payload)

    def authorised(self, authorization):
        if not authorization or not authorization.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(authorization.split(" ", 1)[1]).decode("utf-8", "replace")
        except ValueError:
            return False
        return decoded.partition(":")[2] == self.server.token


class FetchCommit(unittest.TestCase):
    """fetch-commit, run as the builder image runs it, against the server above."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.temporary.name)
        cls.served = root / "served"
        cls.served.mkdir()
        cls.commits = {}
        for name in ("public", "secret"):
            work = root / name
            work.mkdir()
            git("init", "-q", str(work))
            (work / "README").write_text(f"{name}\n", encoding="utf-8")
            git("add", "-A", cwd=work)
            git("commit", "-qm", "first", cwd=work)
            cls.commits[name] = git("rev-parse", "HEAD", cwd=work)
            # A bare copy for the server, which may serve any commit by its id, so the shallow fetch of one commit
            # works as it does against GitHub.
            bare = cls.served / f"{name}.git"
            git("clone", "-q", "--bare", str(work), str(bare))
            git("-C", str(bare), "config", "uploadpack.allowAnySHA1InWant", "true")
            git("-C", str(bare), "config", "uploadpack.allowTipSHA1InWant", "true")
        cls.server = GitServer(cls.served, {"secret.git"}, TOKEN)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temporary.cleanup()

    def fetch(self, repository, commit, token=None):
        """Run fetch-commit for one repository and commit, with `token` in a file as the secret mount holds it.
        Return (exit code, everything it wrote)."""
        self.server.seen.clear()
        with tempfile.TemporaryDirectory() as work:
            environment = {
                # The builder image installs the credential helper in /usr/local/bin; here it is where it lives.
                "PATH": f"{HELPER.parent}:{os.environ['PATH']}",
                "HOME": work,
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
                secret = pathlib.Path(work) / "token"
                secret.write_text(token, encoding="utf-8")
                secret.chmod(0o600)
                environment["OSS_VERIFY_TOKEN_FILE"] = str(secret)
            else:
                # Point the default at a path that is not there: a host running the tests has no secret mount, and
                # this says so rather than depending on that.
                environment["OSS_VERIFY_TOKEN_FILE"] = str(pathlib.Path(work) / "no-token")
            done = subprocess.run(["sh", str(FETCH_COMMIT), str(pathlib.Path(work) / "checkout")],
                                  capture_output=True, text=True, env=environment)
            checkout = pathlib.Path(work) / "checkout"
            head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True,
                                  text=True).stdout.strip()
            return done.returncode, done.stdout + done.stderr, head

    def test_a_public_library_is_fetched_with_no_credential(self):
        code, said, head = self.fetch("public.git", self.commits["public"])
        self.assertEqual(code, 0, said)
        self.assertEqual(head, self.commits["public"])
        self.assertEqual([authorization for _, authorization in self.server.seen if authorization], [],
                         "a public library's fetch sent a credential")

    def test_a_private_library_with_no_token_says_it_was_not_authorised(self):
        code, said, _ = self.fetch("secret.git", self.commits["secret"])
        self.assertEqual(code, 1)
        self.assertIn("not authorised to read", said)
        self.assertIn("with no credential", said)
        self.assertNotIn("has no commit", said)

    def test_a_private_library_with_the_token_is_fetched(self):
        code, said, head = self.fetch("secret.git", self.commits["secret"], TOKEN)
        self.assertEqual(code, 0, said)
        self.assertEqual(head, self.commits["secret"])
        self.assertTrue(any(authorization for _, authorization in self.server.seen),
                        "the fetch of a private library sent no credential")

    def test_the_token_is_in_nothing_the_fetch_writes(self):
        for name, commit, token, ok in (("secret.git", self.commits["secret"], TOKEN, True),
                                        ("secret.git", self.commits["secret"], OTHER_TOKEN, False),
                                        ("secret.git", "f" * 40, TOKEN, False)):
            with self.subTest(name=name, ok=ok):
                code, said, _ = self.fetch(name, commit, token)
                self.assertEqual(code == 0, ok, said)
                self.assertNotIn(token, said)
                self.assertNotIn(token[4:], said)

    def test_a_wrong_token_says_it_was_not_authorised_and_names_the_token(self):
        code, said, _ = self.fetch("secret.git", self.commits["secret"], OTHER_TOKEN)
        self.assertEqual(code, 1)
        self.assertIn("not authorised to read", said)
        self.assertIn("a read-only token minted for this build", said)
        self.assertNotIn("has no commit", said)

    def test_a_commit_that_is_not_there_is_not_an_authorisation_failure(self):
        for name, token in (("public.git", None), ("secret.git", TOKEN)):
            with self.subTest(name=name):
                code, said, _ = self.fetch(name, "f" * 40, token)
                self.assertEqual(code, 1)
                self.assertIn("has no commit", said)
                self.assertIn("neither an authorisation failure nor a transfer that broke", said)
                self.assertNotIn("not authorised to read", said)

    def test_a_repository_that_is_not_there_reads_as_unreadable(self):
        code, said, _ = self.fetch("absent.git", self.commits["public"])
        self.assertEqual(code, 1)
        self.assertIn("not authorised to read", said)
        self.assertNotIn("has no commit", said)

    def test_the_checkout_keeps_no_credential(self):
        with tempfile.TemporaryDirectory() as work:
            secret = pathlib.Path(work) / "token"
            secret.write_text(TOKEN, encoding="utf-8")
            checkout = pathlib.Path(work) / "checkout"
            environment = {
                "PATH": f"{HELPER.parent}:{os.environ['PATH']}", "HOME": work, "REPO": HOST + "secret.git",
                "COMMIT": self.commits["secret"], "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null", "OSS_VERIFY_TOKEN_FILE": str(secret),
                "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "protocol.http.allow",
                "GIT_CONFIG_VALUE_0": "always", "GIT_CONFIG_KEY_1": f"url.{self.base}.insteadOf",
                "GIT_CONFIG_VALUE_1": HOST,
                "OSS_VERIFY_TOKEN_REPO": f"{self.base.partition('//')[2].rstrip('/')}/secret.git",
            }
            done = subprocess.run(["sh", str(FETCH_COMMIT), str(checkout)], capture_output=True, text=True,
                                  env=environment)
            self.assertEqual(done.returncode, 0, done.stderr)
            # Everything the fetch left behind: the remote is REPO as it was given, and no file of the checkout
            # holds the token.
            self.assertEqual(git("-C", str(checkout), "remote", "get-url", "origin"), HOST + "secret.git")
            holding = [str(path) for path in checkout.rglob("*")
                       if path.is_file() and TOKEN.encode() in path.read_bytes()]
            self.assertEqual(holding, [])


class CredentialHelper(unittest.TestCase):
    """git-credential-oss-verify: the one place the token is read."""

    def answer(self, request="protocol=https\nhost=github.com\n\n", **environment):
        done = subprocess.run(["sh", str(HELPER), "get"], input=request, capture_output=True, text=True,
                              env={"PATH": os.environ["PATH"], **environment})
        return done.returncode, done.stdout

    def test_it_reads_the_token_from_the_environment(self):
        code, said = self.answer(OSS_VERIFY_GIT_TOKEN=TOKEN)
        self.assertEqual(code, 0)
        self.assertEqual(said, f"username=x-access-token\npassword={TOKEN}\n")

    def test_it_reads_the_token_from_the_secret_mount(self):
        with tempfile.NamedTemporaryFile("w", suffix=".token") as secret:
            secret.write(TOKEN)
            secret.flush()
            code, said = self.answer(OSS_VERIFY_TOKEN_FILE=secret.name)
        self.assertEqual(code, 0)
        self.assertIn(f"password={TOKEN}", said)

    def test_with_no_token_it_answers_nothing_rather_than_prompting(self):
        code, said = self.answer()
        self.assertEqual((code, said), (0, ""))

    def test_it_stores_nothing(self):
        for operation in ("store", "erase"):
            done = subprocess.run(["sh", str(HELPER), operation], input="protocol=https\nhost=github.com\n\n",
                                  capture_output=True, text=True,
                                  env={"PATH": os.environ["PATH"], "OSS_VERIFY_GIT_TOKEN": TOKEN})
            self.assertEqual((done.returncode, done.stdout), (0, ""), operation)


class TheList(unittest.TestCase):
    """infra/private-libraries.tsv: the only thing that makes a build ask for a token."""

    def test_it_lists_the_two_private_libraries(self):
        listed = check_build.private_libraries()
        for repository in ("https://github.com/theorem-labs/cjson-ossv267",
                           "https://github.com/theorem-labs/theorem-cli"):
            self.assertIn(repository, listed)
            self.assertTrue(listed[repository], f"{repository} has no reason beside it")

    def test_a_public_library_is_not_in_it(self):
        self.assertIsNone(check_build.private_reason("https://github.com/DaveGamble/cJSON"))
        self.assertIsNone(check_build.private_reason("https://github.com/theorem-labs/oss-verify"))

    def test_one_repository_written_three_ways_is_one_row(self):
        for written in ("https://github.com/theorem-labs/theorem-cli",
                        "https://github.com/theorem-labs/theorem-cli.git",
                        "https://github.com/theorem-labs/theorem-cli/",
                        "https://github.com/theorem-labs/theorem-cli#main"):
            self.assertIsNotNone(check_build.private_reason(written), written)

    def test_every_row_is_a_repository_with_a_reason(self):
        text = check_build.PRIVATE_LIBRARIES.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            repository, tab, why = line.partition("\t")
            self.assertEqual(tab, "\t", f"{line!r} has no tab")
            self.assertRegex(repository, r"\Ahttps://[^\s]+/[^\s/]+\Z")
            self.assertTrue(why.strip(), f"{repository} has no reason")

    def test_the_owner_and_name_are_what_a_token_is_narrowed_to(self):
        self.assertEqual(check_build.owner_and_name("https://github.com/theorem-labs/theorem-cli.git"),
                         ("theorem-labs", "theorem-cli"))


class Minting(unittest.TestCase):
    """mint_token: one token for one repository and one build, and no value of it in a message."""

    def command(self, script):
        """Point OSS_VERIFY_GIT_TOKEN_COMMAND at a shell script, and return the environment patcher."""
        path = pathlib.Path(self.temporary.name) / "token-command"
        path.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
        path.chmod(0o755)
        return mock.patch.dict(os.environ, {check_build.TOKEN_COMMAND_ENV: str(path)})

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def test_it_runs_the_command_with_the_owner_and_the_name(self):
        with self.command(f'echo "$1/$2 {TOKEN}"'):
            self.assertEqual(check_build.mint_token("https://github.com/theorem-labs/theorem-cli"),
                             f"theorem-labs/theorem-cli {TOKEN}")

    def test_a_command_that_fails_says_so_without_quoting_a_token(self):
        with self.command(f'echo "refused, the token was {TOKEN}" >&2; exit 1'):
            with self.assertRaises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        self.assertIn("exited 1", str(refused.exception))
        self.assertNotIn(TOKEN, str(refused.exception))
        self.assertIn("<redacted>", str(refused.exception))

    def test_a_command_that_prints_nothing_is_not_a_token(self):
        with self.command("exit 0"):
            with self.assertRaises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        self.assertIn("printed no token", str(refused.exception))

    def test_a_command_that_is_not_there_says_which(self):
        with mock.patch.dict(os.environ, {check_build.TOKEN_COMMAND_ENV: "/nonexistent/mint"}):
            with self.assertRaises(Failed) as refused:
                check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        self.assertIn("/nonexistent/mint", str(refused.exception))


class WhereTheTokenIsNot(unittest.TestCase):
    """The places a token must not reach: a command line, a build argument, the log, a message."""

    def test_a_public_fetch_takes_the_same_git_it_always_did(self):
        self.assertEqual(check_build.git("ls-remote", "--", "https://example.invalid/x"),
                         ["git", "-c", "credential.helper=", "-c", "protocol.allow=never",
                          "-c", "protocol.https.allow=always", "ls-remote", "--", "https://example.invalid/x"])
        self.assertIsNone(check_build.git_environment(None))

    def test_a_token_is_in_the_environment_and_not_the_command_line(self):
        argv = check_build.git("ls-remote", "--", "https://example.invalid/x", token=True)
        self.assertNotIn(TOKEN, " ".join(argv))
        self.assertIn(f"credential.helper=!{check_build.CREDENTIAL_HELPER}", argv)
        # The empty helper still comes first, so a helper the host configured is not used.
        self.assertEqual(argv[1:3], ["-c", "credential.helper="])
        self.assertEqual(check_build.git_environment(TOKEN)[check_build.GIT_TOKEN_ENV], TOKEN)

    def test_the_log_of_a_build_has_the_token_replaced_even_across_a_read(self):
        # The token straddles the boundary of the 64 KiB reads that run() makes, which is where a filter that looks
        # at one chunk at a time lets it through.
        script = f"import sys; sys.stdout.write('x' * 65534 + {TOKEN!r} + 'y')"
        with mock.patch("sys.stdout", new_callable=Printed) as printed:
            code = check_build.run(sys.executable, "-c", script, token=TOKEN)
        self.assertEqual(code, 0)
        self.assertNotIn(TOKEN, printed.text)
        self.assertIn("<redacted>", printed.text)

    def test_the_log_of_a_public_build_is_not_filtered(self):
        with mock.patch("sys.stdout", new_callable=Printed) as printed:
            check_build.run(sys.executable, "-c", "print('ordinary output')")
        self.assertEqual(printed.text.strip(), "ordinary output")

    def test_anything_token_shaped_is_replaced_even_with_no_token_to_compare(self):
        self.assertEqual(check_build.redacted(f"said {TOKEN} loudly", None), "said <redacted> loudly")
        self.assertEqual(check_build.redacted("github_pat_" + "a" * 30, None), "<redacted>")
        self.assertEqual(check_build.redacted("nothing to hide", None), "nothing to hide")

    def test_the_build_of_a_private_library_passes_a_secret_and_no_build_argument(self):
        argv, environment = self.build(private=True, mount=True)
        self.assertIn("--secret", argv)
        self.assertIn(f"id={check_build.GIT_TOKEN_SECRET},env={check_build.GIT_TOKEN_ENV}", argv)
        self.assertNotIn(TOKEN, " ".join(argv))
        self.assertEqual(environment[check_build.GIT_TOKEN_ENV], TOKEN)
        self.assertEqual([argument for argument in argv if argument.startswith("--build-arg")], ["--build-arg"] * 3)

    def test_the_build_of_a_public_library_passes_no_secret_and_no_environment(self):
        argv, environment = self.build(private=False, mount=False)
        self.assertNotIn("--secret", argv)
        self.assertIsNone(environment)

    def build(self, *, private, mount):
        """Run build_project with docker stubbed out, and return the argv and environment it would have used."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = pathlib.Path(temporary.name)
        fetch = f"RUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x" if mount else "RUN fetch-commit $SRC/x"
        (directory / "Dockerfile").write_text(f"FROM ${{BASE_BUILDER}}\nARG REPO\nARG COMMIT\n{fetch}\n",
                                              encoding="utf-8")
        job = Job(name="x", directory=directory, repo="https://github.com/theorem-labs/theorem-cli", ref="",
                  dockerfile="", builds=["plain"], fuzz_targets=None)
        seen = {}

        def stub(*argv, quiet=False, env=None, token=None):
            seen["argv"], seen["env"] = list(argv), env
            return 0

        with mock.patch.object(check_build, "run", stub), contextlib.redirect_stdout(io.StringIO()):
            check_build.build_project(job, "a" * 40, "builder", "tag", directory, token=TOKEN if private else None)
        return seen["argv"], seen["env"]


class TheMountAndTheList(unittest.TestCase):
    """A build is refused when the Dockerfile and infra/private-libraries.tsv disagree. The Dockerfile is parsed,
    not searched: before it was, a comment counted as a mount, an id that merely started with ours counted, a
    mount on another step counted, and a reordered or continued one did not count at all."""

    PRIVATE = "https://github.com/theorem-labs/theorem-cli"
    PUBLIC = "https://github.com/DaveGamble/cJSON"
    MOUNTED = f"FROM x\nRUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x\n"

    def refuses(self, text, token, where):
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, token, where)
        self.assertNotIn(TOKEN, str(refused.exception))
        return str(refused.exception)

    def test_a_private_library_whose_fetch_step_does_not_mount_the_secret_is_refused(self):
        said = self.refuses("FROM x\nRUN fetch-commit $SRC/x\n", TOKEN, self.PRIVATE)
        self.assertIn("does not mount it", said)
        self.assertIn(check_build.SECRET_MOUNT, said)

    def test_a_library_that_is_not_private_may_not_mount_the_secret(self):
        self.assertIn("is not in infra/private-libraries.tsv", self.refuses(self.MOUNTED, None, self.PUBLIC))

    def test_the_two_that_agree_are_allowed(self):
        check_build.check_secret_mount("Dockerfile", "FROM x\nRUN fetch-commit $SRC/x\n", None, self.PUBLIC)
        check_build.check_secret_mount("Dockerfile", self.MOUNTED, TOKEN, self.PRIVATE)

    def test_a_comment_is_not_a_mount(self):
        # Both directions: a public Dockerfile may say in a comment what the mount would be, and a private one
        # that only says it in a comment has no mount.
        documented = f"FROM x\n# RUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x\nRUN fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", documented, None, self.PUBLIC)
        self.assertIn("does not mount it", self.refuses(documented, TOKEN, self.PRIVATE))

    def test_another_secret_whose_id_begins_with_ours_is_another_secret(self):
        text = f"FROM x\nRUN --mount=type=secret,id={check_build.GIT_TOKEN_SECRET}-other fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, None, self.PUBLIC)
        self.assertIn("does not mount it", self.refuses(text, TOKEN, self.PRIVATE))

    def test_a_mount_on_another_step_does_not_put_it_on_the_fetch(self):
        text = (f"FROM x\nRUN {check_build.SECRET_MOUNT} true\nRUN fetch-commit $SRC/x\n")
        self.assertIn("a fetch step in Dockerfile does not mount it", self.refuses(text, TOKEN, self.PRIVATE))
        # It is still a mount, so a public library may not have it either.
        self.assertIn("is not in infra/private-libraries.tsv", self.refuses(text, None, self.PUBLIC))

    def test_a_reordered_or_continued_mount_is_still_a_mount(self):
        for text in (f"FROM x\nRUN --mount=id={check_build.GIT_TOKEN_SECRET},type=secret fetch-commit $SRC/x\n",
                     f"FROM x\nRUN {check_build.SECRET_MOUNT} \\\n    fetch-commit $SRC/x\n",
                     f"FROM x\nRUN \\\n  {check_build.SECRET_MOUNT} \\\n  fetch-commit $SRC/x\n",
                     f"FROM x\nRUN {check_build.SECRET_MOUNT},required=true fetch-commit $SRC/x\n"):
            with self.subTest(text=text):
                check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
                self.assertIn("is not in infra/private-libraries.tsv", self.refuses(text, None, self.PUBLIC))

    def test_a_comment_between_the_lines_of_a_continued_instruction_is_a_comment(self):
        text = f"FROM x\nRUN {check_build.SECRET_MOUNT} \\\n# a comment docker skips\n    fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_private_dockerfile_with_no_fetch_step_at_all_says_so(self):
        self.assertIn("no fetch-commit step at all", self.refuses("FROM x\nRUN true\n", TOKEN, self.PRIVATE))

    def test_no_project_in_this_repository_mounts_the_secret(self):
        # Every library enrolled here is public, so none of their Dockerfiles may ask for a credential.
        asking = [str(path.relative_to(ROOT)) for path in (ROOT / "projects").rglob("Dockerfile")
                  if any(check_build.GIT_TOKEN_SECRET in check_build.secret_mounts(line)
                         for line in check_build.instructions(path.read_text(encoding="utf-8", errors="replace")))
                  and check_build.private_reason(repo_of(path)) is None]
        self.assertEqual(asking, [])


class TheScopeOfTheHelper(unittest.TestCase):
    """The helper answers for one repository. git asks a helper for every server it reaches, and
    `git submodule update --recursive` reaches whatever servers the tree names."""

    def answer(self, request, **environment):
        done = subprocess.run(["sh", str(HELPER), "get"], input=request, capture_output=True, text=True,
                              env={"PATH": os.environ["PATH"], "OSS_VERIFY_GIT_TOKEN": TOKEN, **environment})
        return done.returncode, done.stdout

    def request(self, host, path=None):
        return f"protocol=https\nhost={host}\n" + (f"path={path}\n" if path is not None else "") + "\n"

    def test_it_answers_for_the_repository_it_was_given(self):
        for path in ("theorem-labs/theorem-cli", "theorem-labs/theorem-cli.git", "/theorem-labs/theorem-cli"):
            with self.subTest(path=path):
                code, said = self.answer(self.request("github.com", path),
                                         OSS_VERIFY_TOKEN_REPO="github.com/theorem-labs/theorem-cli")
                self.assertEqual(code, 0)
                self.assertIn(f"password={TOKEN}", said)

    def test_it_answers_nothing_for_another_repository_or_another_host(self):
        for host, path in (("github.com", "theorem-labs/something-else"),
                           ("github.com", "someone/theorem-cli"),
                           ("gitlab.example.invalid", "theorem-labs/theorem-cli")):
            with self.subTest(host=host, path=path):
                code, said = self.answer(self.request(host, path),
                                         OSS_VERIFY_TOKEN_REPO="github.com/theorem-labs/theorem-cli")
                self.assertEqual((code, said), (0, ""))

    def test_with_no_path_the_host_alone_decides(self):
        # credential.useHttpPath off at the caller: there is nothing more to match on, and refusing every request
        # would leave no way to fetch at all.
        code, said = self.answer(self.request("github.com"), OSS_VERIFY_TOKEN_REPO="github.com")
        self.assertIn(f"password={TOKEN}", said)

    def test_fetch_commit_scopes_the_helper_to_its_own_repository(self):
        said = FETCH_COMMIT.read_text(encoding="utf-8")
        self.assertIn("OSS_VERIFY_TOKEN_REPO=${OSS_VERIFY_TOKEN_REPO:-${REPO#https://}}", said)
        self.assertIn("credential.useHttpPath=true", said)


class NoTracing(unittest.TestCase):
    """git's own tracing writes what it sends. GIT_TRACE_CURL with GIT_TRACE_REDACT=0 puts the Authorization
    header in a file that outlives the build, so a fetch with a token does not trace, whatever the caller set."""

    def test_the_host_environment_has_no_tracing_and_redacts(self):
        with mock.patch.dict(os.environ, {"GIT_TRACE_CURL": "/tmp/trace", "GIT_TRACE": "1",
                                          "GIT_TRACE_REDACT": "0", "GIT_CURL_VERBOSE": "1",
                                          "GIT_TRACE_PACKFILE": "/tmp/pack"}):
            environment = check_build.git_environment(TOKEN, "https://github.com/theorem-labs/theorem-cli")
        # Set to 0, not removed: git reads trace2's targets from configuration too, and an environment variable
        # of 0 turns a target off whatever the configuration says.
        for name in check_build.GIT_TRACING:
            self.assertEqual(environment[name], "0", name)
        # GIT_CURL_VERBOSE=0 ENABLES curl's tracing and GIT_TRACE_PACKFILE=0 writes a packfile to a file called 0,
        # so those two are removed instead of set.
        for name in check_build.GIT_TRACING_REMOVED:
            self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_TRACE2_ENV_VARS"], "")
        self.assertEqual(environment["GIT_TRACE_REDACT"], "1")
        self.assertEqual(environment["OSS_VERIFY_TOKEN_REPO"], "github.com/theorem-labs/theorem-cli")

    def test_a_public_fetch_keeps_the_environment_it_had(self):
        self.assertIsNone(check_build.git_environment(None))

    def test_fetch_commit_clears_them_too(self):
        said = FETCH_COMMIT.read_text(encoding="utf-8")
        self.assertIn("for name in GIT_TRACE GIT_TRACE_CURL", said)
        self.assertIn('eval "$name=0; export $name"', said)
        self.assertIn("unset GIT_CURL_VERBOSE GIT_TRACE_PACKFILE", said)
        self.assertIn("GIT_TRACE2_ENV_VARS=", said)
        self.assertIn("GIT_TRACE_REDACT=1", said)


class EverySplit(unittest.TestCase):
    """A token that arrives in two reads is still redacted, at every place it can be cut. The first filter replaced
    the buffer by TOKEN_SHAPE before holding the tail back, and that shape matches a 44-character token's first 24
    characters, so the first half became <redacted> and the second half was printed."""

    def test_no_split_of_a_token_across_two_writes_leaks_any_of_it(self):
        for split in range(1, len(TOKEN)):
            with self.subTest(split=split):
                script = (f"import sys, time; sys.stdout.write('x' * 10 + {TOKEN[:split]!r}); sys.stdout.flush(); "
                          f"time.sleep(0.02); sys.stdout.write({TOKEN[split:]!r} + '|end')")
                printed = Printed()
                with mock.patch("sys.stdout", printed):
                    check_build.run(sys.executable, "-c", script, token=TOKEN)
                self.assertEqual(printed.text, "x" * 10 + "<redacted>|end")

    def test_held_back_is_the_longest_beginning_of_the_token(self):
        self.assertEqual(check_build.held_back("nothing here", TOKEN), 0)
        self.assertEqual(check_build.held_back("xx" + TOKEN[:7], TOKEN), 7)
        # A whole token is replaced before the tail is measured, which is what run() does with it: what is left
        # cannot be the beginning of another one.
        self.assertEqual(check_build.held_back("xx" + "\0" * len(TOKEN), TOKEN), 0)

    def test_a_public_build_is_not_filtered_at_all(self):
        printed = Printed()
        with mock.patch("sys.stdout", printed):
            check_build.run(sys.executable, "-c", f"print({TOKEN!r})")
        self.assertEqual(printed.text.strip(), TOKEN)


class WhichFailure(unittest.TestCase):
    """A cause reported as a different cause is the bug this change exists to remove, so a host that cannot be
    reached must not read as a host that refused."""

    def failed(self, said):
        return mock.patch.object(check_build, "output", side_effect=Failed(said))

    def test_a_refused_credential_or_an_absent_repository_is_an_authorisation_failure(self):
        for said in ("remote: Repository not found.", "fatal: Authentication failed for 'https://github.com/x/y'",
                     "remote: Invalid username or token.", "fatal: could not read Username for 'https://github.com'",
                     "error: The requested URL returned error: 403",
                     "error: The requested URL returned error: 401"):
            with self.subTest(said=said):
                with self.failed(said):
                    message = check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli",
                                                               "a" * 40, TOKEN)
                self.assertIn("cannot read", message)
                self.assertNotIn("has no commit", message)

    def test_a_host_that_cannot_be_reached_is_not_called_an_authorisation_failure(self):
        for said in ("fatal: unable to access 'https://github.com/x/y': Failed to connect to github.com port 443: "
                     "Connection refused",
                     "error: The requested URL returned error: 429",
                     "error: The requested URL returned error: 503",
                     "fatal: unable to access: Could not resolve host: github.com"):
            with self.subTest(said=said):
                with self.failed(said):
                    message = check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli",
                                                               "a" * 40, TOKEN)
                self.assertIn("could not reach", message)
                self.assertNotIn("cannot read", message)
                self.assertNotIn("has no commit", message)

    def test_refs_listed_is_not_proof_that_the_commit_is_missing(self):
        # The refs listing says the build may read the repository. It says nothing about whether the objects came,
        # so the message names both and does not pick one.
        with mock.patch.object(check_build, "output", return_value="deadbeef\trefs/heads/main\n"):
            message = check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli", "a" * 40, TOKEN)
        self.assertIn("could not fetch", message)
        self.assertIn("not an authorisation failure", message)
        self.assertIn("the objects did not come", message)

    def test_the_container_tells_a_connection_failure_from_a_refusal(self):
        # A port nothing listens on: ls-remote fails, and the message must not say "not authorised".
        with tempfile.TemporaryDirectory() as work:
            secret = pathlib.Path(work) / "token"
            secret.write_text(TOKEN, encoding="utf-8")
            environment = {
                "PATH": f"{HELPER.parent}:{os.environ['PATH']}", "HOME": work,
                "REPO": "https://private.test/secret.git", "COMMIT": "a" * 40,
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                "OSS_VERIFY_TOKEN_FILE": str(secret), "OSS_VERIFY_TOKEN_REPO": "127.0.0.1/secret.git",
                "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "protocol.http.allow",
                "GIT_CONFIG_VALUE_0": "always",
                "GIT_CONFIG_KEY_1": f"url.http://127.0.0.1:{closed_port()}/.insteadOf",
                "GIT_CONFIG_VALUE_1": "https://private.test/",
            }
            done = subprocess.run(["sh", str(FETCH_COMMIT), str(pathlib.Path(work) / "checkout")],
                                  capture_output=True, text=True, env=environment)
        said = done.stdout + done.stderr
        self.assertEqual(done.returncode, 1)
        self.assertIn("could not reach", said)
        self.assertNotIn("not authorised to read", said)
        self.assertNotIn("has no commit", said)
        self.assertNotIn(TOKEN, said)


class Unreadable(unittest.TestCase):
    """What the host says when it cannot list a repository's refs."""

    def test_it_names_authorisation_and_not_a_missing_commit(self):
        said = check_build.unreadable("https://github.com/theorem-labs/theorem-cli", TOKEN, "remote: Not Found")
        self.assertIn("read-only token minted for this build", said)
        self.assertIn("this is not a missing commit", said)
        self.assertNotIn(TOKEN, said)

    def test_it_says_when_the_repository_is_not_on_the_list(self):
        said = check_build.unreadable("https://github.com/theorem-labs/not-listed", None, "remote: Not Found")
        self.assertIn("with no credential", said)
        self.assertIn("not in infra/private-libraries.tsv", said)

    def test_a_failure_that_is_not_an_authorisation_one_keeps_gits_own_message(self):
        with mock.patch.object(check_build, "output", side_effect=Failed("could not resolve host: example.invalid")):
            with self.assertRaises(Failed) as refused:
                check_build.resolve("https://example.invalid/x", "main")
        self.assertEqual(str(refused.exception), "could not resolve host: example.invalid")

    def test_an_authorisation_failure_is_rewritten(self):
        with mock.patch.object(check_build, "output",
                               side_effect=Failed("remote: Repository not found.\nfatal: repository not found")):
            with self.assertRaises(Failed) as refused:
                check_build.resolve("https://github.com/theorem-labs/theorem-cli", "main")
        self.assertIn("cannot read", str(refused.exception))
        self.assertIn("this is not a missing commit", str(refused.exception))


class TheSecondReview(unittest.TestCase):
    """What the second non-author review measured at 1eb1c2a, and what this change does about it."""

    def test_a_configured_trace_target_is_emptied_on_the_command_line(self):
        # Clearing GIT_TRACE* is not enough: trace2's targets are configuration, and trace2.envVars names
        # environment variables to write INTO the trace, which GIT_TRACE_REDACT does not redact.
        argv = check_build.git("ls-remote", "--", "https://example.invalid/x", token=True)
        for setting in check_build.NO_TRACING:
            self.assertIn(setting, argv)
        self.assertNotIn("trace2.eventTarget=", check_build.git("ls-remote", "--", "https://example.invalid/x"))
        said = FETCH_COMMIT.read_text(encoding="utf-8")
        self.assertIn("for name in GIT_TRACE ", said)
        self.assertIn("trace2.eventTarget=", said)

    def test_a_real_configured_trace_holds_no_token(self):
        with tempfile.TemporaryDirectory() as work:
            trace = pathlib.Path(work) / "trace.json"
            config = pathlib.Path(work) / "gitconfig"
            config.write_text(f"[trace2]\n\teventTarget = {trace}\n\tenvVars = {check_build.GIT_TOKEN_ENV}\n",
                              encoding="utf-8")
            argv = check_build.git("ls-remote", "--", "https://127.0.0.1:1/x", token=True)
            environment = {**check_build.git_environment(TOKEN, "https://127.0.0.1/x"),
                           "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_SYSTEM": "/dev/null"}
            subprocess.run(argv, capture_output=True, text=True, env=environment)
            written = trace.read_text(encoding="utf-8", errors="replace") if trace.exists() else ""
        self.assertNotIn(TOKEN, written)

    def test_the_host_sends_the_path_so_the_helper_can_match_on_it(self):
        # Without credential.useHttpPath the request carries no path, the helper can only match the host, and it
        # answers for every repository on it.
        self.assertIn("credential.useHttpPath=true", check_build.git("ls-remote", token=True))
        self.assertNotIn("credential.useHttpPath=true", check_build.git("ls-remote"))

    def test_a_tail_of_an_error_is_cut_after_the_token_is_taken_out_of_it(self):
        # Cutting first left whatever of the token fell inside the last 1500 characters, with no marker for it.
        # The token is read from a file, so it is not in the command line either: what is being measured is the
        # cut of the error text, not the echo of the command.
        with tempfile.TemporaryDirectory() as work:
            secret = pathlib.Path(work) / "token"
            secret.write_text(TOKEN + "y" * 1400, encoding="utf-8")
            script = pathlib.Path(work) / "say.py"
            script.write_text(f"import sys; sys.stderr.write(open({str(secret)!r}).read()); raise SystemExit(1)",
                              encoding="utf-8")
            with self.assertRaises(Failed) as refused:
                check_build.output(sys.executable, str(script), token=TOKEN)
        self.assertNotIn(TOKEN, str(refused.exception))
        self.assertNotIn(TOKEN[-100:], str(refused.exception))

    def test_a_failed_token_command_is_redacted_before_its_message_is_cut(self):
        with tempfile.TemporaryDirectory() as work:
            command = pathlib.Path(work) / "mint"
            command.write_text(f"#!/bin/sh\nprintf '%s' '{TOKEN}'>&2\nprintf 'y%.0s' $(seq 1 1400) >&2\nexit 1\n",
                               encoding="utf-8")
            command.chmod(0o755)
            with mock.patch.dict(os.environ, {check_build.TOKEN_COMMAND_ENV: str(command)}):
                with self.assertRaises(Failed) as refused:
                    check_build.mint_token("https://github.com/theorem-labs/theorem-cli")
        self.assertNotIn(TOKEN, str(refused.exception))
        self.assertNotIn(TOKEN[-100:], str(refused.exception))

    def test_a_server_fault_whose_text_says_permission_denied_is_still_a_server_fault(self):
        said = "remote: upstream connection permission denied\nerror: The requested URL returned error: 503"
        with mock.patch.object(check_build, "output", side_effect=Failed(said)):
            message = check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli", "a" * 40, TOKEN)
        self.assertIn("could not reach", message)
        self.assertNotIn("cannot read", message)

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
        with self.assertRaises(Failed):
            check_build.check_secret_mount("Dockerfile", indented, TOKEN, "https://x/y/z")

    def test_the_escape_directive_chooses_the_continuation_character(self):
        text = f"# escape=`\nFROM x\nRUN {check_build.SECRET_MOUNT} `\n    fetch-commit $SRC/x\n"
        check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")

    def test_echoing_the_name_is_not_running_the_program(self):
        # `RUN --mount=… echo "fetch-commit"` beside a real unmounted fetch passed the guard, and the real fetch
        # then ran with no credential.
        text = f"FROM x\nRUN {check_build.SECRET_MOUNT} echo \"fetch-commit\"\nRUN fetch-commit $SRC/x\n"
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")
        self.assertIn("does not mount it", str(refused.exception))
        self.assertFalse(check_build.runs_fetch_commit('RUN echo "fetch-commit"'))
        self.assertTrue(check_build.runs_fetch_commit("RUN fetch-commit $SRC/x"))
        self.assertTrue(check_build.runs_fetch_commit("RUN /usr/local/bin/fetch-commit $SRC/x"))

    def test_every_fetch_step_must_have_the_mount_not_one_of_them(self):
        text = f"FROM x\nRUN {check_build.SECRET_MOUNT} fetch-commit $SRC/a\nRUN fetch-commit $SRC/b\n"
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, "https://x/y/z")
        self.assertIn("$SRC/b", str(refused.exception))

    def test_a_fetch_the_guard_cannot_read_is_refused_for_a_private_library(self):
        # This test asserted the opposite until the fourth review measured five valid Dockerfiles of these
        # shapes whose real fetch ran with NO secret while the guard said they were mounted. There is no safe
        # side to read them on: the guard refuses and says to write the fetch as its own step.
        heredoc = f"FROM x\nRUN {check_build.SECRET_MOUNT} <<EOT\nfetch-commit $SRC/x\nEOT\n"
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", heredoc, TOKEN, "https://x/y/z")
        self.assertIn("cannot read", str(refused.exception))
        # A public library is refused only for mounting the secret, and this one does mount it.
        with self.assertRaises(Failed):
            check_build.check_secret_mount("Dockerfile", heredoc, None, "https://x/y/z")
        self.assertIsNone(check_build.words_of('RUN "unmatched'))

    def test_a_transfer_that_broke_is_not_a_missing_commit(self):
        said = FETCH_COMMIT.read_text(encoding="utf-8")
        self.assertIn('net clone -q --no-checkout "$REPO" "$dir" || transfer_failed', said)
        self.assertIn("it the whole repository", said)


class AServerFault(unittest.TestCase):
    """An HTTP 503 whose body happens to say "permission denied" must not read as a refusal. A review measured
    exactly that text from a real server (`remote: upstream connection permission denied`), and the two markers
    that turned it into one are gone from both copies of the list. This drives the whole script against a server
    that answers that way, not the markers on their own."""

    @classmethod
    def setUpClass(cls):
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
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_the_container_calls_it_a_server_it_could_not_reach(self):
        with tempfile.TemporaryDirectory() as work:
            secret = pathlib.Path(work) / "token"
            secret.write_text(TOKEN, encoding="utf-8")
            environment = {
                "PATH": f"{HELPER.parent}:{os.environ['PATH']}", "HOME": work,
                "REPO": HOST + "secret.git", "COMMIT": "a" * 40,
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                "OSS_VERIFY_TOKEN_FILE": str(secret),
                "OSS_VERIFY_TOKEN_REPO": f"{self.base.partition('//')[2].rstrip('/')}/secret.git",
                "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "protocol.http.allow",
                "GIT_CONFIG_VALUE_0": "always", "GIT_CONFIG_KEY_1": f"url.{self.base}.insteadOf",
                "GIT_CONFIG_VALUE_1": HOST,
            }
            done = subprocess.run(["sh", str(FETCH_COMMIT), str(pathlib.Path(work) / "checkout")],
                                  capture_output=True, text=True, env=environment)
        said = done.stdout + done.stderr
        self.assertEqual(done.returncode, 1, said)
        self.assertIn("could not reach", said)
        self.assertNotIn("not authorised to read", said)
        self.assertNotIn("has no commit", said)
        self.assertNotIn(TOKEN, said)

    def test_neither_list_carries_the_two_words_any_more(self):
        for marker in ("permission denied", "access denied"):
            self.assertNotIn(marker, check_build.UNAUTHORISED)
            self.assertNotIn(f'*"{marker}"*', FETCH_COMMIT.read_text(encoding="utf-8"))


class TheParserAgainstBuildKit(unittest.TestCase):
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
        self.assertEqual(self.mounts(text), [[check_build.GIT_TOKEN_SECRET]])
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_continuation_inside_a_field_value_joins_it(self):
        text = "FROM x\nRUN --mount=type=secret,id=oss-verify-\\\ngit-token fetch-commit /src/x\n"
        self.assertEqual(self.mounts(text), [[check_build.GIT_TOKEN_SECRET]])
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_a_continuation_before_an_indented_line_keeps_the_two_words_apart(self):
        text = f"FROM x\nRUN {self.MOUNT} \\\n    fetch-commit /src/x\n"
        self.assertEqual(self.mounts(text), [[check_build.GIT_TOKEN_SECRET]])

    def test_the_secret_id_may_come_from_an_arg_or_an_env(self):
        # BuildKit expands these and the step really gets the secret, so a guard that reads the literal
        # `$SECRET_ID` refuses a working private build and lets a public one carry a real mount.
        for setting in ("ARG SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=$SECRET_ID",
                        "ENV SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=${SECRET_ID}",
                        "ENV SECRET_ID oss-verify-git-token\nRUN --mount=type=secret,id=${SECRET_ID}"):
            with self.subTest(setting=setting.splitlines()[0]):
                text = f"FROM x\n{setting} fetch-commit /src/x\n"
                check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
                with self.assertRaises(Failed):
                    check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")

    def test_an_unset_variable_names_no_secret(self):
        self.assertEqual(self.mounts("FROM x\nRUN --mount=type=secret,id=$NOT_SET fetch-commit /src/x\n"), [[]])

    def test_the_forms_that_already_worked_still_do(self):
        for text in (f"FROM x\nRUN {self.MOUNT} fetch-commit /src/x\n",
                     f"FROM x\nRUN --network=default {self.MOUNT} fetch-commit /src/x\n",
                     f"FROM x\nRUN {self.MOUNT} --network=default fetch-commit /src/x\n",
                     f"# escape=`\nFROM x\nRUN {self.MOUNT} `\n    fetch-commit /src/x\n",
                     f"FROM x\r\nRUN {self.MOUNT} \\\r\n    fetch-commit /src/x\r\n",
                     f'FROM x\nRUN {self.MOUNT} "fetch-commit" /src/x\n'):
            with self.subTest(text=text.splitlines()[-1]):
                check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)


class BothClassifiersAgree(unittest.TestCase):
    """The host's refused() and the container's denied() are the same rule in two languages. A review found them
    apart -- the host corrected, the shell not -- so they are given the same messages here and must answer alike.
    Each message is one a real server produced in that review, or one of its lookalikes."""

    # (what git said, whether the server answered and refused)
    MESSAGES = (
        ("error: The requested URL returned error: 401", True),
        ("error: The requested URL returned error: 403", True),
        ("error: The requested URL returned error: 404", True),
        # A 404 with an empty body: git puts the URL between `repository` and `not found`, and writes no status.
        ("fatal: repository 'http://127.0.0.1:45677/secret.git/' not found", True),
        ("remote: Repository not found.\nfatal: repository not found", True),
        ("fatal: Authentication failed for 'http://127.0.0.1/x.git/'", True),
        ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", True),
        ("fatal: remote error: access denied", True),
        ("fatal: remote error: permission denied", True),
        # A refusal whose text happens to carry three digits: `\d{3} [A-Za-z]` called these server faults.
        ("fatal: remote error: access denied after 503 bytes", True),
        ("fatal: remote error: access denied on port 500 today", True),
        ("fatal: remote error: access denied on 2026-11-12", True),
        ("error: RPC failed; HTTP 404 curl 22", True),
        ("error: The requested URL returned error: 429", False),
        ("error: The requested URL returned error: 500", False),
        ("error: The requested URL returned error: 502", False),
        ("error: The requested URL returned error: 503", False),
        # A server fault may say anything in its body; the status outranks it.
        ("remote: upstream connection permission denied\nerror: The requested URL returned error: 503", False),
        ("remote: repository not found\nerror: The requested URL returned error: 503", False),
        ("remote: repository not found; 404 bytes retained\nerror: The requested URL returned error: 503", False),
        ("error: RPC failed; HTTP/1.1 503 curl 22", False),
        ("fatal: unable to access 'http://127.0.0.1:44037/x.git/': Failed to connect to 127.0.0.1 port 44037 "
         "after 0 ms: Connection refused", False),
        ("fatal: unable to access: Could not resolve host: not-a-real-host.invalid", False),
    )

    def container(self, said):
        """The container's denied(), read out of fetch-commit and run on its own."""
        source = FETCH_COMMIT.read_text(encoding="utf-8")
        start = source.index("denied() {")
        body = source[start:source.index("\n}\n", start) + 3]
        script = f"refs_said=$(cat)\n{body}\nif denied; then echo refusal; else echo transport; fi\n"
        done = subprocess.run(["sh", "-c", script], input=said, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def test_the_two_answer_alike_and_answer_rightly(self):
        for said, refusal in self.MESSAGES:
            with self.subTest(said=said.splitlines()[-1][:60]):
                want = "refusal" if refusal else "transport"
                self.assertEqual("refusal" if check_build.refused(said) else "transport", want, "the host")
                self.assertEqual(self.container(said), want, "the container")


class TheStatusDecides(unittest.TestCase):
    """Which failure it was is read from the HTTP status first, and from the words only when there is none. A
    body can say anything: the fourth review measured a 503 saying `upstream connection permission denied` and
    another saying `repository not found`, and the round before it a real protocol refusal with no status at
    all. Reading the words first gets one of those wrong whichever words are in the list."""

    def because(self, said):
        with mock.patch.object(check_build, "output", side_effect=Failed(said)):
            return check_build.why_the_fetch_failed("https://github.com/theorem-labs/theorem-cli", "a" * 40, TOKEN)

    def test_a_status_outranks_the_body(self):
        for said in ("remote: upstream connection permission denied\nerror: The requested URL returned error: 503",
                     "remote: repository not found\nerror: The requested URL returned error: 503",
                     "error: The requested URL returned error: 429",
                     "fatal: unable to access: 502 Bad Gateway"):
            with self.subTest(said=said.splitlines()[-1]):
                self.assertIn("could not reach", self.because(said))
                self.assertFalse(check_build.refused(said))

    def test_a_refusing_status_is_a_refusal_whatever_the_body(self):
        for said in ("error: The requested URL returned error: 403",
                     "error: The requested URL returned error: 401",
                     "error: The requested URL returned error: 404",
                     "fatal: unable to access: 403 Forbidden"):
            with self.subTest(said=said):
                self.assertIn("cannot read", self.because(said))
                self.assertTrue(check_build.refused(said))

    def test_a_protocol_refusal_with_no_status_is_still_a_refusal(self):
        # git's own wording when the server refuses over the protocol rather than over HTTP. Dropping the bare
        # `access denied` marker made these read as a server that did not answer.
        for said in ("fatal: remote error: access denied",
                     "remote: access denied\nfatal: the remote end hung up unexpectedly",
                     "fatal: remote error: permission denied",
                     "remote: Repository not found.",
                     "fatal: Authentication failed for 'https://github.com/x/y'",
                     "fatal: could not read Username for 'https://github.com': terminal prompts disabled"):
            with self.subTest(said=said.splitlines()[0]):
                self.assertTrue(check_build.refused(said), said)
                self.assertIn("cannot read", self.because(said))

    def test_a_message_that_is_neither_keeps_being_neither(self):
        for said in ("fatal: unable to access: Could not resolve host: github.com",
                     "fatal: unable to access: Failed to connect to github.com port 443: Connection refused"):
            with self.subTest(said=said):
                self.assertFalse(check_build.refused(said))
                self.assertIn("could not reach", self.because(said))


class WhatTheGuardWillNotRead(unittest.TestCase):
    """The forms where whether a fetch happens, and whether it gets the secret, are inside a string. The fourth
    review measured five valid Dockerfiles of these shapes whose real fetch ran with no credential while the
    guard said they were mounted. They are refused for a private library and named, not guessed at."""

    MOUNT = check_build.SECRET_MOUNT
    PRIVATE = "https://github.com/theorem-labs/theorem-cli"

    def refuses(self, text):
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        return str(refused.exception)

    def test_a_fetch_inside_a_heredoc_body_is_not_read(self):
        self.assertIn("cannot read", self.refuses(f"FROM x\nRUN {self.MOUNT} <<EOT\nfetch-commit /src/x\nEOT\n"))

    def test_a_fetch_behind_a_command_that_runs_a_command_is_not_read(self):
        for command in ('sh -c "fetch-commit /src/x"', "env fetch-commit /src/x",
                        '/bin/sh -c "fetch-commit /src/x"', 'bash -c "fetch-commit /src/x"'):
            with self.subTest(command=command):
                self.assertIn("cannot read", self.refuses(f"FROM x\nRUN {self.MOUNT} {command}\n"))

    def test_the_exec_form_is_read_as_the_program_it_names(self):
        # RUN ["fetch-commit", "/src/y"] is a fetch; a mounted fetch beside it does not excuse it.
        self.assertTrue(check_build.runs_fetch_commit('RUN ["fetch-commit", "/src/y"]'))
        self.assertFalse(check_build.runs_fetch_commit('RUN ["echo", "fetch-commit"]'))
        text = f'FROM x\nRUN {self.MOUNT} fetch-commit /src/x\nRUN ["fetch-commit", "/src/y"]\n'
        self.assertIn("does not mount it", self.refuses(text))

    def test_a_double_angle_in_a_comment_is_not_a_heredoc(self):
        text = f"# << not a heredoc\n# RUN {self.MOUNT} fetch-commit /src/x\nFROM x\nRUN fetch-commit /src/y\n"
        self.assertIn("does not mount it", self.refuses(text))
        check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")  # and it mounts nothing

    def test_a_public_library_is_refused_only_for_a_mount_it_really_has(self):
        # Three valid public Dockerfiles that mount nothing: a heredoc BODY quoting a mount, an id that merely
        # begins with ours, and a mount named in a comment. Looking for the id in the text refused all three.
        for text in (f"FROM x\nCOPY <<EOF /example\nRUN {self.MOUNT} fetch-commit /src/x\nEOF\nRUN fetch-commit /src/x\n",
                     "FROM x\nRUN --mount=type=secret,id=oss-verify-git-token-other fetch-commit /src/x\n",
                     f"# RUN {self.MOUNT} fetch-commit /src/x\nFROM x\nRUN fetch-commit /src/y\n"):
            with self.subTest(text=text.splitlines()[0]):
                check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")


class VariablesAsOfTheInstruction(unittest.TestCase):
    """BuildKit expands a mount with the values set ABOVE it, and every value of one ENV against what was set
    before that ENV. One dictionary for the whole file gets both wrong, and the fourth review measured a file
    where that difference decided whether the fetch got a token."""

    PRIVATE = "https://github.com/theorem-labs/theorem-cli"

    def test_one_env_does_not_see_its_own_assignments(self):
        # BuildKit gives SID the OLD value of FIRST, so this fetch gets nothing and must be refused.
        text = ("FROM x\nENV FIRST=old\nENV FIRST=oss-verify-git-token SID=$FIRST\n"
                "RUN --mount=type=secret,id=$SID fetch-commit /x\n")
        with self.assertRaises(Failed):
            check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)
        check_build.check_secret_mount("Dockerfile", text, None, "https://x/y/z")

    def test_a_later_assignment_does_not_reach_back(self):
        text = ("FROM x\nENV SID=oss-verify-git-token\nRUN --mount=type=secret,id=$SID fetch-commit /x\n"
                "ENV SID=other\n")
        check_build.check_secret_mount("Dockerfile", text, TOKEN, self.PRIVATE)

    def test_an_arg_with_no_default_names_no_secret(self):
        text = "FROM x\nARG SID\nRUN --mount=type=secret,id=$SID fetch-commit /x\n"
        self.assertEqual([ids for _, ids in check_build.fetch_steps(text)], [[]])

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


def closed_port():
    """A loopback port nothing listens on: bound and closed, so a connection to it is refused."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


if __name__ == "__main__":
    unittest.main()
