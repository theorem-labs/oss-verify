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
                self.assertIn("not an authorisation failure", said)
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
    """A build is refused when the Dockerfile and infra/private-libraries.tsv disagree."""

    def test_a_private_library_whose_dockerfile_does_not_mount_the_secret_is_refused(self):
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", "RUN fetch-commit $SRC/x\n", TOKEN,
                                           "https://github.com/theorem-labs/theorem-cli")
        self.assertIn("never mounts it", str(refused.exception))
        self.assertIn(check_build.SECRET_MOUNT, str(refused.exception))
        self.assertNotIn(TOKEN, str(refused.exception))

    def test_a_library_that_is_not_private_may_not_ask_for_the_mount(self):
        with self.assertRaises(Failed) as refused:
            check_build.check_secret_mount("Dockerfile", f"RUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x\n",
                                           None, "https://github.com/DaveGamble/cJSON")
        self.assertIn("is not in infra/private-libraries.tsv", str(refused.exception))

    def test_the_two_that_agree_are_allowed(self):
        check_build.check_secret_mount("Dockerfile", "RUN fetch-commit $SRC/x\n", None, "https://x/y/z")
        check_build.check_secret_mount("Dockerfile", f"RUN {check_build.SECRET_MOUNT} fetch-commit $SRC/x\n", TOKEN,
                                       "https://x/y/z")

    def test_no_project_in_this_repository_asks_for_the_mount(self):
        # Every library enrolled here is public, so none of their Dockerfiles may ask for a credential.
        asking = [str(path.relative_to(ROOT)) for path in (ROOT / "projects").rglob("Dockerfile")
                  if check_build.SECRET_MOUNT in path.read_text(encoding="utf-8", errors="replace")
                  and check_build.private_reason(repo_of(path)) is None]
        self.assertEqual(asking, [])


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


if __name__ == "__main__":
    unittest.main()
