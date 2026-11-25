# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/review-gather KIND=setup, the review of a setup pull request on an owner's repository:
uv run pytest tests/test_review_gather_setup.py

The script reads only the fetch job's folder of the form setup-fetch/1, here tests/fixtures/setup-fetch/ (its README.md
says where each file comes from), and the file LAST_REVIEW. Each test runs the real script with no GH_TOKEN, with a gh,
git, curl and wget on PATH that record each call and exit 1, and in a checkout whose triage.py and rules of
validate_rules/ record that they ran. No test uses the network."""
import gzip
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "review-gather"
FIXTURE = ROOT / "tests" / "fixtures" / "setup-fetch"
# Each file and folder of the form setup-fetch/1 but the optional since-last-review.diff.
FORM = ("pr.json", "pr.diff", "review-comments.txt", "review-comment-authors.txt", "theorem", "source.tar",
        "setup.json", "setup.txt", "record.json", "repository.json", "contributors.json", "last-review-head.txt")
# The commands that could read the network. Each stand-in records its call and fails.
NETWORK = ("gh", "git", "curl", "wget")
# The variables of the job's environment that the script must not need.
UNSET = ("GH_TOKEN", "GITHUB_TOKEN", "KIND", "FETCHED", "LAST_REVIEW", "GITHUB_OUTPUT", "REPO", "PR", "NAME", "COMMIT",
         "HEAD_SHA", "ISSUE")
# The top folder of the fixture's tarball, as GitHub names it: <owner>-<name>-<commit>.
TOP = "FreeREAC-libreac-4e09c7d"
SESSION = "09227178-7bbf-4e5f-86db-8736e530ef01"
HEAD, OTHER = "b" * 40, "c" * 40


def member(name, kind=tarfile.REGTYPE, link="", data=None):
    """A member for SetupGather.tar: its header and its bytes (None for a member that holds none)."""
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.size = kind, link, len(data or b"")
    return info, data


def tree(folder):
    """{the path of each regular file under `folder`, from `folder`: its bytes}."""
    return {path.relative_to(folder).as_posix(): path.read_bytes() for path in sorted(folder.rglob("*"))
            if path.is_file() and not path.is_symlink()}


def kept(text):
    """The text of a file that keep() wrote, without its last line, and the exit status on that line."""
    body, _, last = text.rstrip("\n").rpartition("\n")
    status = re.fullmatch(r"\(exit status (\d+)\)", last)
    return body, int(status.group(1)) if status else None


@unittest.skipUnless(shutil.which("jq") and shutil.which("unzip"), "needs jq and unzip, which the script runs")
class SetupGather(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="review-gather-setup-")
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        self.fetched = self.root / "fetched"
        shutil.copytree(FIXTURE, self.fetched, symlinks=True, ignore=shutil.ignore_patterns("README.md"))
        # The review's folder is one level down, so that a path that leaves it is found in work/.
        self.work = self.root / "work"
        self.work.mkdir()
        self.out = self.work / "review"
        self.calls = self.root / "calls"
        self.output = self.root / "output"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in NETWORK:
            stub = self.bin / name
            stub.write_text(f'#!/bin/sh\necho "{name} $*" >> {shlex.quote(str(self.calls))}\nexit 1\n')
            stub.chmod(0o755)
        # The checkout the job runs the script from: its triage.py and its rules of validate_rules/ only record that
        # they ran.
        self.checkout = self.root / "checkout"
        scripts = self.checkout / ".github" / "scripts"
        (scripts / "validate_rules").mkdir(parents=True)
        ran = f"open({str(self.calls)!r}, 'a').write('ran ' + __file__ + '\\n')\n"
        for path in ("triage.py", "validate_rules/__init__.py", "validate_rules/validate.py"):
            (scripts / path).write_text(ran)

    def gather(self, **env):
        """Run review-gather KIND=setup on self.fetched into self.out, with `env` over the job's environment."""
        environment = {name: value for name, value in os.environ.items() if name not in UNSET}
        environment.update({"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "KIND": "setup",
                            "FETCHED": str(self.fetched), "GITHUB_OUTPUT": str(self.output), **env})
        return subprocess.run([str(SCRIPT), str(self.out)], cwd=self.checkout, env=environment, capture_output=True,
                              text=True)

    def tar(self, *extra):
        """Make source.tar the fixture's tarball with the members `extra` after its own, compressed as GitHub's is."""
        raw = io.BytesIO()
        with tarfile.open(FIXTURE / "source.tar") as given, tarfile.open(
                fileobj=raw, mode="w", format=tarfile.PAX_FORMAT, pax_headers=given.pax_headers) as made:
            for info in given:
                made.addfile(info, given.extractfile(info) if info.isfile() else None)
            for info, data in extra:
                made.addfile(info, None if data is None else io.BytesIO(data))
        (self.fetched / "source.tar").write_bytes(gzip.compress(raw.getvalue()))

    def no_network(self):
        """Nothing called a network command, triage.py or the rules of validate_rules/."""
        self.assertFalse(self.calls.exists(), self.calls.read_text() if self.calls.exists() else "")

    def written(self):
        """What the script wrote to GITHUB_OUTPUT."""
        return self.output.read_text() if self.output.exists() else ""

    def test_it_writes_each_file_the_review_reads_with_no_token_and_no_network(self):
        """With no token, and also with one in the environment: the script calls no network command."""
        pr = json.loads((FIXTURE / "pr.json").read_text())
        for env in ({}, {"GH_TOKEN": "ghs_" + "Q" * 36, "REPO": "FreeREAC/libreac", "PR": "1"}):
            with self.subTest(token="GH_TOKEN" in env):
                shutil.rmtree(self.out, ignore_errors=True)
                run = self.gather(**env)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.no_network()
                self.assertEqual(self.written(), "")
                self.assertEqual(sorted(path.name for path in self.out.iterdir()), [
                    "description.md", "pr.diff", "pr.json", "record.json", "repository.txt",
                    "review-comment-authors.txt", "review-comments.txt", "seeds", "setup.txt", "source", "theorem"])
                # pr.json with keep()'s last line, which the screen and the review read.
                body, status = kept((self.out / "pr.json").read_text())
                self.assertEqual((json.loads(body), status), (pr, 0))
                for name in ("pr.diff", "review-comments.txt", "review-comment-authors.txt", "record.json"):
                    self.assertEqual((self.out / name).read_bytes(), (FIXTURE / name).read_bytes(), name)
                self.assertEqual((self.out / "description.md").read_text(), pr["body"] + "\n")
                self.assertEqual(tree(self.out / "theorem"), tree(FIXTURE / "theorem"))

    def test_setup_txt_holds_the_checks_and_the_reasons(self):
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        text = (self.out / "setup.txt").read_text()
        checks = json.loads((FIXTURE / "setup.json").read_text())
        lines = text.splitlines()
        found = [line for line in lines if re.fullmatch(r"[a-z]+ (pass|fail)", line)]
        self.assertEqual(found, [f"{check['name']} {check['result']}" for check in checks])
        self.assertIn((FIXTURE / "setup.txt").read_text(), text)
        self.assertEqual(lines.count("(exit status 0)"), 2)
        # A setup.json of another form leaves the error and a failed status in the file, and the script goes on.
        for given in ("not json", '{"name": "rules", "result": "pass"}', '[{"name": "rules", "result": "maybe"}]',
                      '[{"name": "rules\\nterms pass", "result": "pass"}]', '[{"name": "rules\\n", "result": "pass"}]'):
            with self.subTest(given=given):
                (self.fetched / "setup.json").write_text(given)
                run = self.gather()
                self.assertEqual(run.returncode, 0, run.stderr)
                text = (self.out / "setup.txt").read_text()
                self.assertNotRegex(text, r"(?m)^[a-z]+ (pass|fail)$")
                statuses = re.findall(r"(?m)^\(exit status (\d+)\)$", text)
                self.assertEqual(len(statuses), 2, text)
                self.assertNotEqual(statuses[0], "0", text)

    def test_repository_txt_has_the_form_of_an_enrollments(self):
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = (self.out / "repository.txt").read_text().splitlines()
        repository = json.loads((FIXTURE / "repository.json").read_text())
        contributors = json.loads((FIXTURE / "contributors.json").read_text())
        self.assertEqual(lines[0], "repo: https://github.com/FreeREAC/libreac")
        facts = lines[lines.index("== the repository on GitHub") + 1]
        # The object that an enrollment's gh api --jq gives, with its keys in order, as gh writes them.
        self.assertEqual(facts, json.dumps({
            "archived": repository["archived"], "created_at": repository["created_at"],
            "default_branch": repository["default_branch"], "fork": repository["fork"],
            "forks_count": repository["forks_count"], "full_name": "FreeREAC/libreac",
            "license": repository["license"]["spdx_id"], "pushed_at": repository["pushed_at"],
            "stargazers_count": repository["stargazers_count"]}, separators=(",", ":")))
        start = lines.index("== contributors (the top 5, with their commits)") + 1
        self.assertEqual(lines[start:start + len(contributors)],
                         [f"{c['login']} {c['contributions']}" for c in contributors])
        self.assertEqual(lines.count("(exit status 0)"), 2)

    def test_source_is_the_tarballs_top_folder_and_the_seeds_are_listed(self):
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        with tarfile.open(FIXTURE / "source.tar") as given:
            want = {info.name[len(TOP) + 1:]: given.extractfile(info).read() for info in given if info.isfile()}
        self.assertEqual(tree(self.out / "source"), want)
        self.assertIn("NOTICE", want)
        # The seed listings, as for an enrollment: unzip -l, and the first bytes of each input in hexadecimal.
        listing, status = kept((self.out / "seeds" / "fuzz_knock.listing.txt").read_text())
        self.assertEqual(status, 0)
        hexed = (self.out / "seeds" / "fuzz_knock.hex.txt").read_text().splitlines()
        with zipfile.ZipFile(FIXTURE / "theorem" / "fuzz_knock_seed_corpus.zip") as corpus:
            inputs = corpus.infolist()
        for info in inputs:
            self.assertIn(info.filename, listing)
        self.assertEqual([line for line in hexed if line.startswith("== ")],
                         [f"== {info.filename!r}: {info.file_size} bytes" for info in inputs])
        self.assertEqual(sorted(path.name for path in (self.out / "seeds").iterdir()),
                         ["fuzz_knock.hex.txt", "fuzz_knock.listing.txt"])

    def test_a_missing_file_of_the_form_stops_it_and_is_named(self):
        for name in FORM:
            with self.subTest(name=name):
                self.setUp()
                path = self.fetched / name
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                run = self.gather()
                self.assertEqual(run.returncode, 2, run.stdout)
                self.assertIn(f"FETCHED has no {name}", run.stderr)
                self.assertFalse(self.out.exists())
                self.no_network()
        # A symbolic link in the place of a file, a file in the place of theorem/, and no FETCHED.
        self.setUp()
        (self.fetched / "record.json").unlink()
        (self.fetched / "record.json").symlink_to(FIXTURE / "record.json")
        self.assertEqual(self.gather().returncode, 2)
        self.setUp()
        shutil.rmtree(self.fetched / "theorem")
        (self.fetched / "theorem").write_text("")
        self.assertEqual(self.gather().returncode, 2)
        for fetched in ("", str(self.root / "none")):
            self.assertEqual(self.gather(FETCHED=fetched).returncode, 2)
        self.assertFalse(self.out.exists())

    def test_a_link_in_the_tarball_is_not_taken_and_nothing_is_written_outside(self):
        """A symbolic link that leads out of the folder, a file whose path goes through it, a hard link, a device and
        a FIFO. Only the file is taken, under its own path in source/, which is a real folder."""
        self.tar(member(f"{TOP}/up", tarfile.SYMTYPE, "../../.."), member(f"{TOP}/up/escaped", data=b"ESCAPED\n"),
                 member(f"{TOP}/etc", tarfile.SYMTYPE, "/etc"), member(f"{TOP}/hard", tarfile.LNKTYPE, "/etc/passwd"),
                 member(f"{TOP}/inside", tarfile.LNKTYPE, f"{TOP}/NOTICE"), member(f"{TOP}/fifo", tarfile.FIFOTYPE),
                 member(f"{TOP}/null", tarfile.CHRTYPE))
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        source = self.out / "source"
        self.assertEqual([path for path in source.rglob("*") if not (path.is_file() or path.is_dir())
                          or path.is_symlink()], [])
        for name in ("etc", "hard", "inside", "fifo", "null"):
            self.assertFalse(os.path.lexists(source / name), name)
            self.assertIn(f"not taken: '{TOP}/{name}'", run.stderr)
        self.assertIn(f"not taken: '{TOP}/up'", run.stderr)
        self.assertEqual((source / "up" / "escaped").read_bytes(), b"ESCAPED\n")
        self.assertEqual([path for path in self.root.rglob("escaped")], [source / "up" / "escaped"])
        self.assertEqual(list(self.work.iterdir()), [self.out])
        self.assertIn("NOTICE", tree(source))
        self.no_network()

    def test_a_sparse_file_in_the_tarball_is_not_taken(self):
        """A PAX header makes a member of the type of a regular file sparse, with a hole of 1 GiB that the tar holds no
        byte of. It is not taken, and nothing large is written."""
        sparse = tarfile.TarInfo(f"{TOP}/sparse")
        sparse.pax_headers = {"GNU.sparse.map": "0,0", "GNU.sparse.size": str(1 << 30)}
        self.tar((sparse, None))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertTrue(given.getmember(f"{TOP}/sparse").issparse())
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(os.path.lexists(self.out / "source" / "sparse"))
        self.assertIn(f"not taken: '{TOP}/sparse': it is a sparse file", run.stderr)
        self.assertLess(sum(path.lstat().st_size for path in self.root.rglob("*") if path.is_file()), 1 << 20)
        self.assertIn("NOTICE", tree(self.out / "source"))
        self.no_network()

    def test_a_path_that_leaves_the_folder_is_not_taken(self):
        outside = self.root / "absolute"
        self.tar(member(f"{TOP}/../../dotdot", data=b"x"), member(f"{TOP}/debian/../../../dotdot", data=b"x"),
                 member(str(outside), data=b"x"), member("other-top/file", data=b"x"))
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(outside.exists())
        self.assertEqual(list(self.root.rglob("dotdot")) + list(self.root.rglob("other-top")), [])
        self.assertEqual(list(self.work.iterdir()), [self.out])
        for name in (f"{TOP}/../../dotdot", f"{TOP}/debian/../../../dotdot", str(outside), "other-top/file"):
            self.assertIn(f"not taken: {name!r}", run.stderr)
        with tarfile.open(FIXTURE / "source.tar") as given:
            want = {info.name[len(TOP) + 1:] for info in given if info.isfile()}
        self.assertEqual(set(tree(self.out / "source")), want)

    def test_instructions_for_claude_and_links_are_taken_out(self):
        theorem = self.fetched / "theorem"
        (theorem / "CLAUDE.md").write_text("x")
        (theorem / "agents.override.md").write_text("x")
        (theorem / ".claude").mkdir()
        (theorem / ".claude" / "settings.json").write_text("{}")
        (theorem / "link").symlink_to("/etc/passwd")
        os.mkfifo(theorem / "fifo")
        self.tar(member(f"{TOP}/CLAUDE.md", data=b"x"), member(f"{TOP}/docs/AGENTS.md", data=b"x"),
                 member(f"{TOP}/sub/.claude/settings.json", data=b"{}"))
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(tree(self.out / "theorem"), tree(FIXTURE / "theorem"))
        self.assertEqual(sorted(path.name for path in (self.out / "theorem").iterdir()),
                         sorted(path.name for path in (FIXTURE / "theorem").iterdir()))
        source = tree(self.out / "source")
        self.assertEqual([path for path in source if re.search(r"(?i)claude|agents", path)], [])
        self.assertIn("NOTICE", source)

    def test_a_tarball_that_cannot_be_read_gives_no_source(self):
        (self.fetched / "source.tar").write_bytes(b"not a tar file\n")
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse((self.out / "source").exists())
        self.assertIn("there is no source to read", (self.out / "source.txt").read_text())
        self.assertTrue((self.out / "setup.txt").exists())

    def test_a_session_kept_for_the_reviewed_head_is_resumed(self):
        diff = "diff --git a/.theorem/config.yml b/.theorem/config.yml\n+sanitizers: [address]\n"
        (self.fetched / "last-review-head.txt").write_text(HEAD + "\n")
        (self.fetched / "since-last-review.diff").write_text(diff)
        (self.root / "last-review").write_text(f"session={SESSION} head={HEAD}\n")
        run = self.gather(LAST_REVIEW=str(self.root / "last-review"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.written(), f"session={SESSION}\nlast={HEAD}\n")
        self.assertEqual((self.out / "since-last-review.diff").read_text(), diff + "(exit status 0)\n")
        self.assertIn(f"resumes the session {SESSION}", run.stdout)
        self.no_network()

    def test_the_diff_since_the_last_review_keeps_only_the_sections_of_theorem(self):
        """A merge of the default branch into theorem/setup puts each change of that branch in the fetched diff: the
        review gets only the sections of .theorem/, and it still resumes the session."""
        theorem = ("diff --git a/.theorem/config.yml b/.theorem/config.yml\n--- a/.theorem/config.yml\n"
                   "+++ b/.theorem/config.yml\n@@ -1 +1,2 @@\n sanitizers:\n+  - address\n")
        other = "diff --git a/src/x.c b/src/x.c\n--- a/src/x.c\n+++ b/src/x.c\n@@ -1 +1 @@\n-int x;\n+int y;\n"
        (self.fetched / "last-review-head.txt").write_text(HEAD + "\n")
        (self.fetched / "since-last-review.diff").write_text(theorem + other)
        (self.root / "last-review").write_text(f"session={SESSION} head={HEAD}\n")
        run = self.gather(LAST_REVIEW=str(self.root / "last-review"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.out / "since-last-review.diff").read_text(), theorem + "(exit status 0)\n")
        self.assertEqual(self.written(), f"session={SESSION}\nlast={HEAD}\n")
        self.assertIn(f"resumes the session {SESSION}", run.stdout)
        self.no_network()

    def test_no_session_for_another_head_or_without_the_diff(self):
        diff = "diff --git a/.theorem/config.yml b/.theorem/config.yml\n+sanitizers: [address]\n"
        # Each case: the head of the review comment, the head that the cache's session was kept for, whether FETCHED
        # holds the diff, and whether the script says that the session was kept for another head. A head that is not
        # one commit id is no head, so the script does not compare the cache's head with it.
        for why, head, kept_for, with_diff, another in (
                ("the cache's session is another head's", HEAD, OTHER, True, True),
                ("no diff: the head is not an ancestor", HEAD, HEAD, False, False),
                ("no review comment", "", HEAD, True, False),
                ("a head that is not a commit id", "main", HEAD, True, False),
                ("a head of capitals", HEAD.upper(), HEAD, True, False)):
            with self.subTest(why=why):
                self.setUp()
                (self.fetched / "last-review-head.txt").write_text(head + "\n" if head else "")
                if with_diff:
                    (self.fetched / "since-last-review.diff").write_text(diff)
                (self.root / "last-review").write_text(f"session={SESSION} head={kept_for}\n")
                run = self.gather(LAST_REVIEW=str(self.root / "last-review"))
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(self.written(), "")
                # The diff is still the review's to read when the folder holds it.
                self.assertEqual((self.out / "since-last-review.diff").exists(), with_diff)
                said = [line for line in run.stdout.splitlines() if "kept for" in line]
                self.assertEqual(bool(said), another, run.stdout)
        # The cache's file of another shape, or none.
        self.setUp()
        (self.fetched / "last-review-head.txt").write_text(HEAD + "\n")
        (self.fetched / "since-last-review.diff").write_text(diff)
        for last in (f"session=x head={HEAD}\n", f"session={SESSION} head={HEAD} extra\n", None):
            with self.subTest(last=last):
                if last is not None:
                    (self.root / "last-review").write_text(last)
                run = self.gather(LAST_REVIEW=str(self.root / "last-review") if last is not None else "")
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(self.written(), "")


if __name__ == "__main__":
    unittest.main()
