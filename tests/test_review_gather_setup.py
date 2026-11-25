# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for .github/scripts/review-gather KIND=setup, the review of a setup pull request on an owner's repository:
uv run pytest tests/test_review_gather_setup.py

The script reads only the fetch job's folder of the form setup-fetch/1, here tests/fixtures/setup-fetch/ (its README.md
says where each file comes from), and the file LAST_REVIEW. Each test runs the real script with no GH_TOKEN, with a gh,
git, curl and wget on PATH that record each call and exit 1, and in a checkout whose triage.py and rules of
validate_rules/ record that they ran. No test uses the network."""
import errno
import gzip
import io
import json
import os
import pathlib
import re
import resource
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
# The commit that the global PAX header of the fixture's tarball holds (comment), as git archive writes it.
COMMIT = "4e09c7d811313828e0aa9ed4d21215cf1c851689"
# The real git, found before a test puts its stand-in on PATH, for a tarball that git archive writes.
GIT = shutil.which("git")
# PAX records that tarfile cannot read, and finds that out only after it read the header of the member after them:
# GNU.sparse.size makes it read GNU.sparse.offset as a number, and abc is none.
BAD_PAX = {"GNU.sparse.size": "10", "GNU.sparse.offset": "abc"}
# The reasons that the script gives for a tar that is not of the shape that git archive writes, each with the byte
# offset of the header that it refuses: a member of a type other than a folder, a regular file and a symbolic link; a
# checksum that is not the sum of the bytes of the header; a keyword other than comment in a global PAX header, or other
# than path, linkpath and size in an extended one; and a size that is not 1 to 20 ASCII digits.
TYPE = ("ShapeError: the header at byte {} is of the tar type {!r}, not a folder (5), a regular file (0) or a symbolic"
        " link (2)")
CHECKSUM = "ShapeError: the header at byte {} has the checksum {!r}, which is not the sum of its bytes"
GLOBAL_KEYWORD = "ShapeError: the global PAX header at byte {} holds the keyword {!r}, which is not comment"
EXTENDED_KEYWORD = ("ShapeError: the extended PAX header at byte {} holds the keyword {!r}, which is not path, linkpath"
                    " or size")
NOT_DIGITS = "ShapeError: the extended PAX header at byte {} holds a size that is not 1 to 20 ASCII digits: {!r}"


def member(name, kind=tarfile.REGTYPE, link="", data=None, pax_headers=None):
    """A member for SetupGather.tar: its header, with the PAX records `pax_headers`, and its bytes (None for a member
    that holds none)."""
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.size = kind, link, len(data or b"")
    info.pax_headers = dict(pax_headers or {})
    return info, data


def pax_header(kind, record):
    """A PAX header for SetupGather.tar, extended (tarfile.XHDTYPE) or global (tarfile.XGLTYPE), whose data is
    `record`, the bytes of its records (pax_record())."""
    info = tarfile.TarInfo("pax_global_header" if kind == tarfile.XGLTYPE else "././@PaxHeader")
    info.type, info.size = kind, len(record)
    return info, record


def pax_record(keyword, value):
    """The PAX record "<length> <keyword>=<value>\\n", whose length counts the whole record, its own digits too."""
    field = f" {keyword}={value}\n".encode()
    digits = 1
    while len(str(len(field) + digits)) != digits:
        digits += 1
    return str(len(field) + digits).encode() + field


def headers(raw):
    """[(offset, header)] of each header of the tar `raw`, not compressed, up to its first block of zero bytes: after
    each header, its data of the size that the header gives."""
    found, at = [], 0
    while raw[at:at + tarfile.BLOCKSIZE].strip(b"\x00"):
        header = raw[at:at + tarfile.BLOCKSIZE]
        found.append((at, header))
        size = int(header[124:136].split(b"\x00")[0] or b"0", 8)
        at += tarfile.BLOCKSIZE + -(-size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
    return found


def x_hides_z(pax_headers):
    """Two members for SetupGather.tar: X, with the PAX records `pax_headers`, whose header gives it 512 bytes, which
    hold the header of Y, of 1024 bytes, which hold the header and the data of Z; and Z. A tarfile that reads X as
    empty reads the header of Y in its data, and Z is in the data of Y, so it does not read Z."""
    y = tarfile.TarInfo(f"{TOP}/Y")
    y.size = 2 * tarfile.BLOCKSIZE
    return (member(f"{TOP}/X", data=y.tobuf(tarfile.USTAR_FORMAT), pax_headers=pax_headers),
            member(f"{TOP}/Z", data=b"z\n"))


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

    def gather(self, limit=None, **env):
        """Run review-gather KIND=setup on self.fetched into self.out, with `env` over the job's environment, and with
        `limit`, when it is given, as the most bytes that it and its commands can write to one file (RLIMIT_FSIZE)."""
        environment = {name: value for name, value in os.environ.items() if name not in UNSET}
        environment.update({"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "KIND": "setup",
                            "FETCHED": str(self.fetched), "GITHUB_OUTPUT": str(self.output), **env})

        def limited():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, resource.RLIM_INFINITY))
        return subprocess.run([str(SCRIPT), str(self.out)], cwd=self.checkout, env=environment, capture_output=True,
                              text=True, preexec_fn=limited if limit else None)

    def tar(self, *extra, first=(), global_records=None):
        """Make source.tar the fixture's tarball with the members `extra` after its own, in the shape of git archive
        and compressed as GitHub's is: the fixture's global PAX header at byte 0, with the records `global_records` in
        the place of its own when they are given, then each member with no PAX record of its own but those it is given,
        so that PAX_FORMAT writes an extended header only for a member that is given records or whose field needs one
        (a long path). The members `first` come before the fixture's own, in the place of its global PAX header, so
        that the first of them starts the tar."""
        raw = io.BytesIO()
        with tarfile.open(FIXTURE / "source.tar") as given, tarfile.open(
                fileobj=raw, mode="w", format=tarfile.PAX_FORMAT,
                pax_headers=None if first else global_records or given.pax_headers) as made:
            for info, data in first:
                made.addfile(info, None if data is None else io.BytesIO(data))
            for info in given:
                # tarfile gives each member the records of the global header, which git archive writes there alone.
                info.pax_headers = {}
                made.addfile(info, given.extractfile(info) if info.isfile() else None)
            for info, data in extra:
                made.addfile(info, None if data is None else io.BytesIO(data))
        (self.fetched / "source.tar").write_bytes(gzip.compress(raw.getvalue()))

    def raw(self):
        """The tar of self.fetched's source.tar, not compressed."""
        return gzip.decompress((self.fetched / "source.tar").read_bytes())

    def added(self):
        """[(offset, type)] of each header of source.tar after those of the fixture's tarball: those of the members
        `extra` of tar()."""
        fixture = headers(gzip.decompress((FIXTURE / "source.tar").read_bytes()))
        return [(at, header[156:157]) for at, header in headers(self.raw())[len(fixture):]]

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

    def test_the_fixture_and_tar_have_the_shape_of_git_archive(self):
        """git archive writes GitHub's tarball: a global PAX header at byte 0 that holds the commit, then each member
        with its ustar header alone, and an extended header only where a field needs one. The fixture has that shape,
        and tar() writes it again, with the same header for each member, and an extended header for a member of its
        own only when the member needs one (here a name longer than 100 bytes)."""
        fixture = gzip.decompress((FIXTURE / "source.tar").read_bytes())
        found = headers(fixture)
        self.assertEqual([(at, header[156:157]) for at, header in found[:1]], [(0, tarfile.XGLTYPE)])
        self.assertEqual(fixture[tarfile.BLOCKSIZE:tarfile.BLOCKSIZE * 2].rstrip(b"\x00"),
                         pax_record("comment", COMMIT))
        self.assertEqual({header[156:157] for _, header in found[1:]}, {tarfile.DIRTYPE, tarfile.REGTYPE})
        self.assertEqual({header[257:265] for _, header in found}, {b"ustar\x0000"})
        self.tar(member(f"{TOP}/short", data=b"short\n"), member(f"{TOP}/{'l' * 120}", data=b"long\n"))
        written = headers(self.raw())
        self.assertEqual([(at, header[156:157]) for at, header in written[:1]], [(0, tarfile.XGLTYPE)])
        self.assertEqual(written[1:len(found)], found[1:])
        self.assertEqual([header[156:157] for _, header in written[len(found):]],
                         [tarfile.REGTYPE, tarfile.XHDTYPE, tarfile.REGTYPE])
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.pax_headers, {"comment": COMMIT})

    def test_a_link_in_the_tarball_is_not_taken_and_nothing_is_written_outside(self):
        """A symbolic link that leads out of the folder, a file whose path goes through it, and a link to /etc. Each
        link alone is not taken, with its reason, and the file is taken, under its own path in source/, which is a real
        folder."""
        self.tar(member(f"{TOP}/up", tarfile.SYMTYPE, "../../.."), member(f"{TOP}/up/escaped", data=b"ESCAPED\n"),
                 member(f"{TOP}/etc", tarfile.SYMTYPE, "/etc"))
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        source = self.out / "source"
        self.assertEqual([path for path in source.rglob("*") if not (path.is_file() or path.is_dir())
                          or path.is_symlink()], [])
        self.assertFalse(os.path.lexists(source / "etc"))
        for name in ("up", "etc"):
            self.assertIn(f"not taken: '{TOP}/{name}': it is a symbolic link", run.stderr)
        self.assertEqual((source / "up" / "escaped").read_bytes(), b"ESCAPED\n")
        self.assertEqual([path for path in self.root.rglob("escaped")], [source / "up" / "escaped"])
        self.assertEqual(list(self.work.iterdir()), [self.out])
        self.assertIn("NOTICE", tree(source))
        self.no_network()

    def test_a_member_of_a_type_that_git_archive_does_not_write_gives_no_source(self):
        """git archive writes folders, regular files and symbolic links alone. A hard link, a character or a block
        device, a FIFO, a contiguous file, a regular file of the old type NUL, a GNU long name or long link, or a type
        that tarfile does not know, gives no source, and the reason names its header and its type."""
        for kind, link, data in ((tarfile.LNKTYPE, f"{TOP}/NOTICE", None), (tarfile.CHRTYPE, "", None),
                                 (tarfile.BLKTYPE, "", None), (tarfile.FIFOTYPE, "", None),
                                 (tarfile.CONTTYPE, "", b"c\n"), (tarfile.AREGTYPE, "", b"a\n"),
                                 (tarfile.GNUTYPE_LONGNAME, "", f"{TOP}/{'n' * 120}\x00".encode()),
                                 (tarfile.GNUTYPE_LONGLINK, "", f"{'t' * 120}\x00".encode()), (b"Z", "", b"z\n")):
            with self.subTest(kind=kind):
                self.setUp()
                self.tar(member(f"{TOP}/odd", kind, link, data), member(f"{TOP}/after", data=b"after\n"))
                at, written = self.added()[0]
                self.assertEqual(written, kind)
                self.gives_no_source(TYPE.format(at, kind))

    def test_a_sparse_file_in_the_tarball_gives_no_source(self):
        """A GNU sparse header (type S) makes a member sparse, with a hole of 1 GiB that the tar holds no byte of: its
        size of 1 GiB is in the 12 bytes at 483 of the header, set here, with the checksum of the header made again.
        git archive writes no such header: the tar gives no source, and nothing large is written."""
        self.tar(member(f"{TOP}/sparse", tarfile.GNUTYPE_SPARSE))
        raw = bytearray(self.raw())
        with tarfile.open(fileobj=io.BytesIO(raw)) as given:
            at = given.getmember(f"{TOP}/sparse").offset
        raw[at + 483:at + 495] = b"%011o\x00" % (1 << 30)
        raw[at + 148:at + 156] = b" " * 8
        raw[at + 148:at + 156] = b"%06o\x00 " % sum(raw[at:at + tarfile.BLOCKSIZE])
        (self.fetched / "source.tar").write_bytes(gzip.compress(bytes(raw)))
        with tarfile.open(self.fetched / "source.tar") as given:
            sparse = given.getmember(f"{TOP}/sparse")
            self.assertEqual((sparse.issparse(), sparse.size, sparse.pax_headers), (True, 1 << 30, {}))
        self.gives_no_source(TYPE.format(at, tarfile.GNUTYPE_SPARSE))
        self.assertLess(sum(path.lstat().st_size for path in self.root.rglob("*") if path.is_file()), 1 << 20)

    def test_a_folder_or_a_link_with_a_size_gives_no_source(self):
        """git archive writes the size 0 for a folder and for a symbolic link. tarfile skips no data after either, so
        it reads the 512 bytes of data here as a header, of a member hidden. The tar gives no source."""
        hidden = tarfile.TarInfo(f"{TOP}/hidden").tobuf(tarfile.USTAR_FORMAT)
        for kind, link in ((tarfile.DIRTYPE, ""), (tarfile.SYMTYPE, "NOTICE")):
            with self.subTest(kind=kind):
                self.setUp()
                self.tar(member(f"{TOP}/sized", kind, link, hidden), member(f"{TOP}/after", data=b"after\n"))
                with tarfile.open(self.fetched / "source.tar") as given:
                    self.assertIn(f"{TOP}/hidden", given.getnames())
                at, _ = self.added()[0]
                self.gives_no_source(f"ShapeError: the header at byte {at} is of a folder or a symbolic link, and has "
                                     f"the size {tarfile.BLOCKSIZE}, not 0")

    def test_a_pax_record_for_a_member_of_another_type_gives_no_source(self):
        """git archive writes the PAX record size only for a regular file, and linkpath only for a symbolic link."""
        for kind, records, why in (
                (tarfile.DIRTYPE, {"size": "0"}, "gives a size to the header at byte {}, which is not of a regular file"),
                (tarfile.REGTYPE, {"linkpath": "NOTICE"},
                 "gives a link target to the header at byte {}, which is not of a symbolic link")):
            with self.subTest(kind=kind):
                self.setUp()
                self.tar(member(f"{TOP}/other", kind, pax_headers=records))
                (at, extended), (after, written) = self.added()
                self.assertEqual((extended, written), (tarfile.XHDTYPE, kind))
                self.gives_no_source(f"ShapeError: the extended PAX header at byte {at} {why.format(after)}")

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

    def test_a_member_that_cannot_be_written_is_not_taken_and_the_others_are(self):
        """A member whose path has a part of 300 bytes, more than a file system takes in one name (255 bytes): it alone
        is not taken, with the file system's reason, and source/ gets each other member, the one after it too."""
        long = f"{TOP}/{'a' * 300}"
        self.tar(member(long, data=b"long\n"), member(f"{TOP}/after", data=b"after\n"))
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        with tarfile.open(FIXTURE / "source.tar") as given:
            want = {info.name[len(TOP) + 1:]: given.extractfile(info).read() for info in given if info.isfile()}
        self.assertEqual(tree(self.out / "source"), {**want, "after": b"after\n"})
        self.assertFalse((self.out / "source.txt").exists())
        self.assertIn(f"not taken: {long!r}: it cannot be written here: File name too long", run.stderr)
        self.no_network()

    def test_a_member_whose_data_cannot_be_copied_is_not_taken_and_its_part_is_gone(self):
        """A member of 2 MiB, with a limit of 1 MiB on each file that the script writes (RLIMIT_FSIZE): the copy of its
        data fails with EFBIG after it wrote 1 MiB of the file. That member alone is not taken, with the error, the
        part of its file that was written is gone, and source/ gets each other member, the one after it too. No tar
        has a read of a member's data that fails and a next header that can then be read: a plain tar fails there only
        when it is cut short, and gzip, GitHub's form, decompresses in order, so an error in a member's data stops the
        read of each header after it too, and then there is no source, as in
        test_a_tarball_that_cannot_be_read_gives_no_source."""
        large = f"{TOP}/large"
        self.tar(member(large, data=b"x" * (2 << 20)), member(f"{TOP}/after", data=b"after\n"))
        run = self.gather(limit=1 << 20)
        self.assertEqual(run.returncode, 0, run.stderr)
        with tarfile.open(FIXTURE / "source.tar") as given:
            want = {info.name[len(TOP) + 1:]: given.extractfile(info).read() for info in given if info.isfile()}
        self.assertEqual(tree(self.out / "source"), {**want, "after": b"after\n"})
        self.assertFalse(os.path.lexists(self.out / "source" / "large"))
        self.assertFalse((self.out / "source.txt").exists())
        self.assertIn(f"not taken: {large!r}: its data cannot be copied: OSError: [Errno {errno.EFBIG}] "
                      f"{os.strerror(errno.EFBIG)}", run.stderr)
        self.no_network()

    def test_a_member_whose_name_holds_a_nul_byte_is_not_taken_and_the_others_are(self):
        """A PAX header can give a member a name that holds a NUL byte, which no path of the file system can hold:
        os.open() refuses it with ValueError. That member alone is not taken, with its own reason, and source/ gets
        each other member, the one before it and the one after it too. tarfile's writer cuts a name at its NUL, so the
        PAX record is made here."""
        name = f"{TOP}/b\x00c"
        self.tar(member(f"{TOP}/before", data=b"before\n"), pax_header(tarfile.XHDTYPE, pax_record("path", name)),
                 member(f"{TOP}/bxc", data=b"nul\n"), member(f"{TOP}/after", data=b"after\n"))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertIn(name, given.getnames())
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        with tarfile.open(FIXTURE / "source.tar") as given:
            want = {info.name[len(TOP) + 1:]: given.extractfile(info).read() for info in given if info.isfile()}
        self.assertEqual(tree(self.out / "source"), {**want, "before": b"before\n", "after": b"after\n"})
        self.assertFalse((self.out / "source.txt").exists())
        self.assertIn(f"not taken: {name!r}: its name holds a NUL byte", run.stderr)
        self.no_network()

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

    @unittest.skipUnless(GIT, "needs git, to write a tarball with git archive")
    def test_a_tarball_that_git_archive_writes_gives_each_file_whole(self):
        """git archive --format=tar.gz, which writes GitHub's tarball, of a commit with a short path, a path that needs
        the prefix field of ustar, a name longer than 100 bytes and a path longer than 255 bytes, which need an
        extended header with path, a symbolic link, one whose target needs an extended header with linkpath, and a
        submodule, which git archive writes as an empty folder. source/ gets each file whole and the empty folder, and
        each link alone is not taken."""
        repo = self.root / "repo"
        prefixed, deep = f"{'p' * 70}/{'q' * 40}.txt", "/".join(["s" * 60] * 4) + "/deep.txt"
        files = {"short.txt": b"short\n", "sub/file.txt": b"sub\n", prefixed: b"prefix\n", "r" * 120: b"long name\n",
                 deep: b"deep\n"}
        for path, data in files.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(data)
        (repo / "link").symlink_to("short.txt")
        (repo / "longlink").symlink_to("t" * 120)
        environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@example.com", "GIT_COMMITTER_NAME": "a",
                       "GIT_COMMITTER_EMAIL": "a@example.com"}

        def git(*args):
            return subprocess.run([GIT, "-C", str(repo), *args], env=environment, check=True, capture_output=True,
                                  text=True).stdout.strip()
        git("init", "-q")
        git("add", "-A")
        git("update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},empty")
        commit = git("commit-tree", git("write-tree"), "-m", "head")
        top = f"owner-repo-{commit[:7]}"
        git("archive", "--format=tar.gz", f"--prefix={top}/", "-o", str(self.fetched / "source.tar"), commit)
        raw = self.raw()
        with tarfile.open(self.fetched / "source.tar") as given:
            # The members whose header comes after an extended header, and those whose header holds a prefix.
            extended = {info.name for info in given if info.offset != info.offset_data - tarfile.BLOCKSIZE}
            prefix = {info.name for info in given if raw[info.offset_data - 167:info.offset_data - 12].strip(b"\x00")}
            self.assertEqual((given.pax_headers, given.getmember(f"{top}/empty").type),
                             ({"comment": commit}, tarfile.DIRTYPE))
        self.assertEqual(headers(raw)[0][1][156:157], tarfile.XGLTYPE)
        self.assertLessEqual({f"{top}/{'r' * 120}", f"{top}/{deep}", f"{top}/longlink"}, extended)
        self.assertIn(f"{top}/{prefixed}", prefix - extended)
        self.assertNotIn(f"{top}/short.txt", extended | prefix)
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse((self.out / "source.txt").exists())
        self.assertEqual(tree(self.out / "source"), files)
        self.assertTrue((self.out / "source" / "empty").is_dir())
        self.assertEqual([line for line in run.stderr.splitlines() if "not taken" in line],
                         [f"review-gather: source.tar: not taken: '{top}/{name}': it is a symbolic link"
                          for name in ("link", "longlink")])
        self.assertFalse(os.path.lexists(self.out / "source" / "link"))
        self.no_network()

    def gives_no_source(self, reason):
        """Run the script on the source.tar of self.fetched: as for any tar that it cannot read, it gives no source/,
        source.txt says that there is no source to read, and its standard error has the line of `reason`."""
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(os.path.lexists(self.out / "source"), run.stderr)
        self.assertIn("there is no source to read", (self.out / "source.txt").read_text())
        self.assertIn(f"review-gather: source.tar is not a tar file that can be read: {reason}",
                      run.stderr.splitlines())
        self.no_network()

    def test_a_tarball_that_cannot_be_read_gives_no_source(self):
        (self.fetched / "source.tar").write_bytes(b"not a tar file\n")
        self.gives_no_source("ShapeError: the tar ends at byte 15, in the header at byte 0")
        self.assertTrue((self.out / "setup.txt").exists())

    def test_a_tarball_cut_short_gives_no_source(self):
        """A tar that ends inside a header, inside the data of a member, or before the block of zero bytes that ends
        it gives no source."""
        self.tar(member(f"{TOP}/after", data=b"after\n"))
        raw = self.raw()
        [(at, _)] = self.added()
        for cut, where in ((at + 100, f"in the header at byte {at}"),
                           (at + tarfile.BLOCKSIZE + 3, f"in the data of the header at byte {at}"),
                           (at + 2 * tarfile.BLOCKSIZE, "with no block of zero bytes to end it")):
            with self.subTest(cut=cut):
                (self.fetched / "source.tar").write_bytes(gzip.compress(raw[:cut]))
                self.gives_no_source(f"ShapeError: the tar ends at byte {cut}, {where}")

    def test_a_tarball_with_a_bad_header_after_the_first_gives_no_source(self):
        """tarfile takes a header that it cannot read after the first one (here the last one, whose checksum is
        broken) for the end of the tar, and raises nothing. The walk checks the checksum of each header, and the tar
        gives no source."""
        self.tar(member(f"{TOP}/after", data=b"after\n"))
        raw = bytearray(self.raw())
        with tarfile.open(fileobj=io.BytesIO(raw)) as given:
            at = given.getmember(f"{TOP}/after").offset
        raw[at + 148:at + 156] = b"0000000\x00"
        (self.fetched / "source.tar").write_bytes(gzip.compress(bytes(raw)))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertNotIn(f"{TOP}/after", given.getnames())
        self.gives_no_source(CHECKSUM.format(at, b"0000000\x00"))

    def test_a_header_that_is_not_of_ustar_gives_no_source(self):
        """git archive writes each header with the magic and version of ustar, and its size in octal digits. A header
        with the magic of GNU tar, or with a size in base 256, here the same size, 6, gives no source."""
        for start, field, why in ((257, b"ustar  \x00", "has the magic and version {!r}, not those of ustar"),
                                  (124, b"\x80" + bytes(10) + b"\x06", "has the size {!r}, which is not octal digits")):
            with self.subTest(field=field):
                self.tar(member(f"{TOP}/after", data=b"after\n"))
                raw = bytearray(self.raw())
                [(at, _)] = self.added()
                raw[at + start:at + start + len(field)] = field
                raw[at + 148:at + 156] = b" " * 8
                raw[at + 148:at + 156] = b"%06o\x00 " % sum(raw[at:at + tarfile.BLOCKSIZE])
                (self.fetched / "source.tar").write_bytes(gzip.compress(bytes(raw)))
                with tarfile.open(self.fetched / "source.tar") as given:
                    self.assertEqual(given.getmember(f"{TOP}/after").size, 6)
                self.gives_no_source(f"ShapeError: the header at byte {at} {why.format(field)}")

    def test_a_pax_header_whose_records_are_not_of_their_form_gives_no_source(self):
        """Each record of a PAX header is "<length> <keyword>=<value>\\n", whose length has no leading zero and counts
        the whole record, and the records fill the data of the header exactly, in at most 64 KiB, with no keyword
        twice. A length too large, a leading zero, a record with no newline at its end, bytes after the last record, a
        keyword twice, and 1 byte more than 64 KiB each give no source."""
        record = pax_record("path", f"{TOP}/r")
        large = pax_record("path", "a" * (65537 - 12))
        self.assertEqual(len(large), 65537)
        form = "has a record at byte {} that is not of the form '<length> <keyword>=<value>\\n'"
        for data, at_record, why in ((b"1" + record, 0, form), (b"0" + record, 0, form),
                                     (record[:-1] + b"x", 0, form), (record + b"xyz", len(record), form),
                                     (record + record, None, "holds the keyword 'path' twice"),
                                     (large, None, "holds 65537 bytes, more than 64 KiB")):
            with self.subTest(data=data[:40], length=len(data)):
                self.tar(pax_header(tarfile.XHDTYPE, data), member(f"{TOP}/m", data=b"m\n"))
                at, _ = self.added()[0]
                if at_record is not None:
                    why = why.format(at + tarfile.BLOCKSIZE + at_record)
                self.gives_no_source(f"ShapeError: the extended PAX header at byte {at} {why}")

    def test_a_header_that_tarfile_cannot_read_gives_no_source(self):
        """The header of bad has the mtime abc, which is not a number, and a checksum that is its sum. The walk does
        not read the mtime, but tarfile cannot read that header, takes it for the end of the tar and raises nothing,
        so it reads neither bad nor after. tarfile does not read the members that the walk read, and the tar gives no
        source."""
        self.tar(member(f"{TOP}/bad", data=b"bad\n"), member(f"{TOP}/after", data=b"after\n"))
        raw = bytearray(self.raw())
        (at, _), _ = self.added()
        raw[at + 136:at + 148] = b"abc" + bytes(9)
        raw[at + 148:at + 156] = b" " * 8
        raw[at + 148:at + 156] = b"%06o\x00 " % sum(raw[at:at + tarfile.BLOCKSIZE])
        (self.fetched / "source.tar").write_bytes(gzip.compress(bytes(raw)))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-1], f"{TOP}/fuzz/corpus/boxreg/find-absent")
        self.gives_no_source(f"ShapeError: tarfile reads no member, and the walk reads the member at byte {at} (its "
                             f"data at byte {at + tarfile.BLOCKSIZE}, 4 bytes, tar type b'0')")

    def test_a_tarball_with_a_bad_pax_header_on_the_last_member_gives_no_source(self):
        """For a PAX header, tarfile reads the header of the member after it first, which moves its offset past the
        data of that member, and then finds that it cannot read the PAX records (BAD_PAX): it takes the tar to end
        there and raises nothing. An extended header holds only path, linkpath and size, and the tar gives no
        source."""
        self.tar(member(f"{TOP}/a", data=b"a\n"), member(f"{TOP}/s", data=b"s\n", pax_headers=BAD_PAX))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-1], f"{TOP}/a")
            # The PAX header of s is in the block after the data of a, which is one block.
            at = given.getmember(f"{TOP}/a").offset_data + tarfile.BLOCKSIZE
        self.gives_no_source(EXTENDED_KEYWORD.format(at, "GNU.sparse.size"))

    def test_a_tarball_with_a_bad_pax_header_on_the_first_member_gives_no_source(self):
        """The same member first in the tar, before the top folder: tarfile.open() reads it with the first next(),
        from byte 0, takes the tar to end there and raises nothing, and the tar has no member. The tar gives no
        source."""
        self.tar(first=[member(f"{TOP}/s", data=b"s\n", pax_headers=BAD_PAX)])
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames(), [])
        self.gives_no_source(EXTENDED_KEYWORD.format(0, "GNU.sparse.size"))

    def test_a_tarball_whose_gzip_crc_is_not_its_datas_gives_no_source(self):
        """gzip checks the CRC that GitHub's tarball holds (the 4 bytes before its last 4) against its data only at the
        end of the data, after the zero block where tarfile ends the tar. The walk reads the tar to its end, so gzip
        checks it, and the tar gives no source."""
        gz = bytearray((self.fetched / "source.tar").read_bytes())
        crc = int.from_bytes(gz[-8:-4], "little")
        gz[-8:-4] = (crc ^ 1).to_bytes(4, "little")
        (self.fetched / "source.tar").write_bytes(gz)
        self.gives_no_source(f"BadGzipFile: CRC check failed {hex(crc ^ 1)} != {hex(crc)}")

    def test_a_tarball_whose_gzip_length_is_not_its_datas_gives_no_source(self):
        """The same for the length of the data (the last 4 bytes)."""
        gz = bytearray((self.fetched / "source.tar").read_bytes())
        length = int.from_bytes(gz[-4:], "little")
        gz[-4:] = (length + 1).to_bytes(4, "little")
        (self.fetched / "source.tar").write_bytes(gz)
        self.gives_no_source("BadGzipFile: Incorrect length of data produced")

    def test_a_tarball_with_data_after_its_end_blocks_gives_no_source(self):
        """tarfile ends the tar at the first of the two zero blocks that end it, and reads no byte after them. POSIX
        lets a tar hold any bytes there, but GitHub's tarball holds zero bytes alone there: a block that is not zero
        after them gives no source."""
        self.tar(member(f"{TOP}/after", data=b"after\n"))
        raw = self.raw()
        with tarfile.open(fileobj=io.BytesIO(raw)) as given:
            # The zero blocks are in the block after the data of after, which is one block.
            end = given.getmember(f"{TOP}/after").offset_data + tarfile.BLOCKSIZE
        (self.fetched / "source.tar").write_bytes(gzip.compress(raw + bytes(tarfile.BLOCKSIZE - 1) + b"\x01"))
        self.gives_no_source(f"ShapeError: the tar ends with the block of zero bytes at byte {end}, and the byte at "
                             f"{len(raw) + tarfile.BLOCKSIZE - 1} after it is not zero")

    def test_a_tarball_with_a_pax_size_that_is_not_a_number_gives_no_source(self):
        """tarfile reads a PAX size that is not a number as 0. Here the record size=abc is on X (x_hides_z()): tarfile
        reads X as empty and the header of Y in its data, and does not read Z. GNU tar refuses such a record, and the
        tar gives no source."""
        self.tar(*x_hides_z({"size": "abc"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-2:], [f"{TOP}/X", f"{TOP}/Y"])
        self.gives_no_source(NOT_DIGITS.format(self.added()[0][0], b"abc"))

    def test_a_tarball_with_a_pax_size_under_another_extended_header_gives_no_source(self):
        """An extended header with comment=hi, then the one of X with size=abc (x_hides_z()). tarfile applies the inner
        one to X first: it reads the size as 0, and the header of Y in the data of X. Then the outer one replaces the
        pax_headers of X with its own records, which hold no size. An extended header holds no comment, and the tar
        gives no source."""
        self.tar(pax_header(tarfile.XHDTYPE, b"14 comment=hi\n"), *x_hides_z({"size": "abc"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-2:], [f"{TOP}/X", f"{TOP}/Y"])
            self.assertEqual(given.getmember(f"{TOP}/X").pax_headers, {"comment": "hi"})
        self.gives_no_source(EXTENDED_KEYWORD.format(self.added()[0][0], "comment"))

    def test_a_tarball_with_a_global_pax_size_after_an_extended_header_gives_no_source(self):
        """An extended header with comment=hi, then a global one with size=abc, then the last member. tarfile applies
        the global records to the member first, and reads its size as 0; then the extended one replaces its pax_headers
        with its own records, which hold no size. The offset stays on the size in the header of the member, so tarfile
        reads the tar on in its place, and the member as empty. An extended header holds no comment, and the tar gives
        no source."""
        self.tar(pax_header(tarfile.XHDTYPE, b"14 comment=hi\n"), pax_header(tarfile.XGLTYPE, b"12 size=abc\n"),
                 member(f"{TOP}/last", data=b"last\n"))
        with tarfile.open(self.fetched / "source.tar") as given:
            last = given.getmembers()[-1]
            self.assertEqual((last.name, last.size, last.pax_headers), (f"{TOP}/last", 0, {"comment": "hi"}))
        self.gives_no_source(EXTENDED_KEYWORD.format(self.added()[0][0], "comment"))

    def test_a_tarball_with_a_pax_size_of_more_than_20_digits_gives_no_source(self):
        """The PAX size 512, the size of X (x_hides_z()), in 4301 digits: int() refuses more than 4300 digits, so
        tarfile reads it as 0. A size is at most 20 digits, as many as 2**64 has, and the tar gives no source."""
        size = "0" * 4298 + "512"
        self.tar(*x_hides_z({"size": size}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-2:], [f"{TOP}/X", f"{TOP}/Y"])
        self.gives_no_source(NOT_DIGITS.format(self.added()[0][0], size[:40].encode()))

    def test_a_tarball_with_a_pax_size_in_the_digits_of_another_script_gives_no_source(self):
        """The PAX size U+0660, ARABIC-INDIC DIGIT ZERO, on X (x_hides_z()): str.isdigit() takes it for a digit, and
        int() reads it as 0. A size is ASCII digits alone, and the tar gives no source."""
        self.tar(*x_hides_z({"size": "\u0660"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-2:], [f"{TOP}/X", f"{TOP}/Y"])
        self.gives_no_source(NOT_DIGITS.format(self.added()[0][0], "\u0660".encode()))

    def test_a_tarball_with_a_global_pax_size_that_is_not_a_number_gives_no_source(self):
        """A global PAX header gives its records to each member after it, so tarfile reads size=abc there as 0 for each
        one. A global header holds only comment, and the tar gives no source."""
        self.tar(first=[pax_header(tarfile.XGLTYPE, b"12 size=abc\n")])
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.pax_headers, {"size": "abc"})
        self.gives_no_source(GLOBAL_KEYWORD.format(0, "size"))

    def test_a_tarball_with_a_global_pax_size_and_no_extended_header_gives_no_source(self):
        """The shape of git archive, with size=abc in the global PAX header too. tarfile takes the offset after each
        member from the size in its header before it applies the global records, so it reads each member in its
        place, with the size 0. A global header holds only comment, and the tar gives no source."""
        self.tar(global_records={"comment": COMMIT, "size": "abc"})
        self.assertEqual([header[156:157] for _, header in headers(self.raw())
                          if header[156:157] in (tarfile.XHDTYPE, tarfile.XGLTYPE)], [tarfile.XGLTYPE])
        with tarfile.open(self.fetched / "source.tar") as given, tarfile.open(FIXTURE / "source.tar") as fixture:
            self.assertEqual(given.getnames(), fixture.getnames())
            self.assertEqual({info.size for info in given}, {0})
        self.gives_no_source(GLOBAL_KEYWORD.format(0, "size"))

    def test_a_tarball_with_a_decimal_global_pax_size_gives_no_source(self):
        """The shape of git archive, with size=1 in the global PAX header too, a decimal size. tarfile reads each
        member in its place, as above, with the size 1, so each file would hold its first byte alone. A global header
        holds only comment, and the tar gives no source."""
        self.tar(global_records={"comment": COMMIT, "size": "1"})
        with tarfile.open(self.fetched / "source.tar") as given, tarfile.open(FIXTURE / "source.tar") as fixture:
            self.assertEqual(given.getnames(), fixture.getnames())
            self.assertEqual({info.size for info in given}, {1})
            self.assertEqual(given.extractfile(f"{TOP}/NOTICE").read(),
                             fixture.extractfile(f"{TOP}/NOTICE").read()[:1])
        self.gives_no_source(GLOBAL_KEYWORD.format(0, "size"))

    def test_a_tarball_with_a_pax_size_that_int_reads_but_is_not_decimal_gives_no_source(self):
        """int() reads the PAX size 0_2 as 2, the size of the member, but a decimal number is ASCII digits alone, as for
        GNU tar, which refuses 0_2: the tar gives no source."""
        self.tar(member(f"{TOP}/u", data=b"u\n", pax_headers={"size": "0_2"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getmember(f"{TOP}/u").size, 2)
        self.gives_no_source(NOT_DIGITS.format(self.added()[0][0], b"0_2"))

    def test_a_tarball_with_a_pax_sparse_length_after_a_decimal_size_gives_no_source(self):
        """One extended header on X (x_hides_z()) with size=512, its size, then GNU.sparse.realsize=0: tarfile applies
        the records in their order, so the second makes the size of X 0. An extended header holds no GNU.sparse.*
        record, and the tar gives no source."""
        self.tar(*x_hides_z({"size": "512", "GNU.sparse.realsize": "0"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-2:], [f"{TOP}/X", f"{TOP}/Y"])
            self.assertEqual(list(given.getmember(f"{TOP}/X").pax_headers)[-2:], ["size", "GNU.sparse.realsize"])
        self.gives_no_source(EXTENDED_KEYWORD.format(self.added()[0][0], "GNU.sparse.realsize"))

    def test_a_tarball_with_a_pax_sparse_size_gives_no_source(self):
        """A decimal GNU.sparse.size alone: tarfile makes the member sparse, of that size. The tar gives no source."""
        self.tar(member(f"{TOP}/s", data=b"s\n", pax_headers={"GNU.sparse.size": "2"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertTrue(given.getmember(f"{TOP}/s").issparse())
        self.gives_no_source(EXTENDED_KEYWORD.format(self.added()[0][0], "GNU.sparse.size"))

    def test_a_tarball_with_a_pax_sparse_realsize_gives_no_source(self):
        """A decimal GNU.sparse.realsize alone: tarfile takes it for the size of the member, here 1 of its 2 bytes, and
        the member is not sparse. The tar gives no source."""
        self.tar(member(f"{TOP}/r", data=b"r\n", pax_headers={"GNU.sparse.realsize": "1"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            r = given.getmember(f"{TOP}/r")
            self.assertEqual((r.issparse(), r.size), (False, 1))
        self.gives_no_source(EXTENDED_KEYWORD.format(self.added()[0][0], "GNU.sparse.realsize"))

    def test_a_tarball_with_a_comment_in_an_extended_header_gives_no_source(self):
        """git archive writes comment in the global header alone: an extended header with it gives no source."""
        self.tar(pax_header(tarfile.XHDTYPE, pax_record("comment", "hi")), member(f"{TOP}/c", data=b"c\n"))
        self.gives_no_source(EXTENDED_KEYWORD.format(self.added()[0][0], "comment"))

    def test_a_tarball_with_a_global_header_after_the_first_member_gives_no_source(self):
        """git archive writes one global header, the first header of the tar. Another one after a member, which
        tarfile reads, gives no source."""
        self.tar(pax_header(tarfile.XGLTYPE, pax_record("comment", COMMIT)), member(f"{TOP}/g", data=b"g\n"))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-1], f"{TOP}/g")
        at, kind = self.added()[0]
        self.assertEqual(kind, tarfile.XGLTYPE)
        self.gives_no_source(f"ShapeError: the global PAX header at byte {at} is not the first header of the tar")

    def test_a_tarball_with_an_extended_header_after_another_gives_no_source(self):
        """Two extended headers in a row, each with a path, which git archive does not write: tarfile gives the member
        the path of the first. The tar gives no source."""
        self.tar(pax_header(tarfile.XHDTYPE, pax_record("path", f"{TOP}/one")),
                 pax_header(tarfile.XHDTYPE, pax_record("path", f"{TOP}/two")), member(f"{TOP}/three", data=b"3\n"))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getnames()[-1], f"{TOP}/one")
        (first, _), (second, _), _ = self.added()
        self.gives_no_source(f"ShapeError: the extended PAX header at byte {first} is followed by a header of the tar "
                             f"type b'x', at byte {second}, not by the header of a member")

    def test_a_tarball_with_an_extended_header_before_its_end_gives_no_source(self):
        """An extended header is for the member after it: one right before the end of the tar gives no source."""
        self.tar(pax_header(tarfile.XHDTYPE, pax_record("path", f"{TOP}/none")))
        [(at, _)] = self.added()
        self.gives_no_source(f"ShapeError: the extended PAX header at byte {at} is followed by the end of the tar, at "
                             f"byte {at + 2 * tarfile.BLOCKSIZE}")

    def test_a_tarball_with_a_pax_record_after_the_records_of_a_header_gives_no_source(self):
        """tarfile reads the records of a PAX header on past its size, to the end of its last block, up to a NUL byte.
        Here a record GNU.sparse.map=0,1 after the path of the extended header makes q sparse, with its first byte
        alone and then zero bytes, at the same offsets and of the same size. The bytes of a PAX header after its records
        are zero, and the tar gives no source."""
        record = pax_record("path", f"{TOP}/q")
        self.tar(pax_header(tarfile.XHDTYPE, record), member(f"{TOP}/p", data=b"secret\n"))
        raw = bytearray(self.raw())
        (at, _), _ = self.added()
        hidden = pax_record("GNU.sparse.map", "0,1")
        start = at + tarfile.BLOCKSIZE + len(record)
        raw[start:start + len(hidden)] = hidden
        (self.fetched / "source.tar").write_bytes(gzip.compress(bytes(raw)))
        with tarfile.open(self.fetched / "source.tar") as given:
            q = given.getmember(f"{TOP}/q")
            self.assertEqual((q.sparse, q.size, given.extractfile(q).read()), ([(0, 1)], 7, b"s" + bytes(6)))
        self.gives_no_source(f"ShapeError: the extended PAX header at byte {at} has a byte that is not zero after its "
                             "records, in its last block")

    def test_a_member_with_a_decimal_pax_size_is_taken(self):
        """A PAX size of ASCII digits alone, the size of the member: the script takes the member whole, beside each
        other member."""
        self.tar(member(f"{TOP}/d", data=b"d\n", pax_headers={"size": "2"}))
        with tarfile.open(self.fetched / "source.tar") as given:
            self.assertEqual(given.getmember(f"{TOP}/d").pax_headers["size"], "2")
        run = self.gather()
        self.assertEqual(run.returncode, 0, run.stderr)
        with tarfile.open(FIXTURE / "source.tar") as given:
            want = {info.name[len(TOP) + 1:]: given.extractfile(info).read() for info in given if info.isfile()}
        self.assertEqual(tree(self.out / "source"), {**want, "d": b"d\n"})
        self.assertFalse((self.out / "source.txt").exists())
        self.assertNotIn(f"not taken: '{TOP}/d'", run.stderr)
        self.no_network()

    def gather_since(self, diff):
        """Run the script with `diff` as the fetched since-last-review.diff from HEAD, the head of the review comment,
        and a session kept for HEAD. Return the run, after checking that the review's folder has the diff whole."""
        (self.fetched / "last-review-head.txt").write_text(HEAD + "\n")
        (self.fetched / "since-last-review.diff").write_text(diff)
        (self.root / "last-review").write_text(f"session={SESSION} head={HEAD}\n")
        run = self.gather(LAST_REVIEW=str(self.root / "last-review"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.out / "since-last-review.diff").read_text(), diff + "(exit status 0)\n")
        self.no_network()
        return run

    def test_a_diff_of_theorem_alone_resumes(self):
        """A change, a new file, a rename and a deletion, each under .theorem/."""
        diff = ("diff --git a/.theorem/config.yml b/.theorem/config.yml\n--- a/.theorem/config.yml\n"
                "+++ b/.theorem/config.yml\n@@ -1 +1,2 @@\n sanitizers:\n+  - address\n"
                "diff --git a/.theorem/fuzz_new.c b/.theorem/fuzz_new.c\nnew file mode 100644\n--- /dev/null\n"
                "+++ b/.theorem/fuzz_new.c\n@@ -0,0 +1 @@\n+int x;\n"
                "diff --git a/.theorem/old.sh b/.theorem/build.sh\nsimilarity index 100%\nrename from .theorem/old.sh\n"
                "rename to .theorem/build.sh\n"
                "diff --git a/.theorem/gone.txt b/.theorem/gone.txt\ndeleted file mode 100644\n--- a/.theorem/gone.txt\n"
                "+++ /dev/null\n@@ -1 +0,0 @@\n-x\n")
        run = self.gather_since(diff)
        self.assertEqual(self.written(), f"session={SESSION}\nlast={HEAD}\n")
        self.assertIn(f"the setup review resumes the session {SESSION}, with the diff from {HEAD}", run.stdout)

    def test_a_diff_of_theorem_alone_with_a_mode_a_binary_file_and_no_newline_at_the_end_resumes(self):
        """git diff of two commits writes a change of mode with no hunk, a binary file as one line Binary files ...
        differ, and the line \\ No newline at end of file after a hunk line: each is of a plain diff."""
        diff = ("diff --git a/.theorem/build.sh b/.theorem/build.sh\nold mode 100755\nnew mode 100644\n"
                "diff --git a/.theorem/seed.zip b/.theorem/seed.zip\nindex 20a6b40..213ab45 100644\n"
                "Binary files a/.theorem/seed.zip and b/.theorem/seed.zip differ\n"
                "diff --git a/.theorem/fuzz.c b/.theorem/fuzz.c\nindex 1039088..2a1d3c4 100644\n--- a/.theorem/fuzz.c\n"
                "+++ b/.theorem/fuzz.c\n@@ -1,2 +1,2 @@\n #include <stdint.h>\n-int x;\n"
                "\\ No newline at end of file\n+int y;\n\\ No newline at end of file\n")
        run = self.gather_since(diff)
        self.assertEqual(self.written(), f"session={SESSION}\nlast={HEAD}\n")
        self.assertIn(f"the setup review resumes the session {SESSION}, with the diff from {HEAD}", run.stdout)

    def test_a_diff_that_changes_a_file_outside_theorem_is_whole_and_the_review_is_fresh(self):
        """A merge of the default branch into theorem/setup puts each change of that branch in the fetched diff, and a
        fuzz target or a Dockerfile can stay outside .theorem/: the review reads the diff whole, and it is fresh."""
        theorem = ("diff --git a/.theorem/config.yml b/.theorem/config.yml\n--- a/.theorem/config.yml\n"
                   "+++ b/.theorem/config.yml\n@@ -1 +1,2 @@\n sanitizers:\n+  - address\n")
        other = "diff --git a/src/x.c b/src/x.c\n--- a/src/x.c\n+++ b/src/x.c\n@@ -1 +1 @@\n-int x;\n+int y;\n"
        for why, diff in (
                ("a section of .theorem/ and one of src/x.c", theorem + other),
                ("src/x.c first", other + theorem),
                ("a rename out of .theorem/", theorem + "diff --git a/.theorem/fuzz.c b/fuzz.c\nsimilarity index 100%\n"
                 "rename from .theorem/fuzz.c\nrename to fuzz.c\n"),
                ("a rename into .theorem/", "diff --git a/Dockerfile b/.theorem/Dockerfile\nsimilarity index 100%\n"
                 "rename from Dockerfile\nrename to .theorem/Dockerfile\n"),
                # From .theorem/x b/.theorem/y to src/z, or from .theorem/x to .theorem/y b/src/z: the line does not
                # say which.
                ("a path that holds ' b/'", "diff --git a/.theorem/x b/.theorem/y b/src/z\nsimilarity index 100%\n"
                 "rename from .theorem/x b/.theorem/y\nrename to src/z\n")):
            with self.subTest(why=why):
                self.setUp()
                run = self.gather_since(diff)
                self.assertEqual(self.written(), "")
                self.assertIn(f"review-gather: the diff from {HEAD} changes a file outside .theorem/: the review is "
                              "fresh", run.stdout.splitlines())
                self.assertNotIn("resumes", run.stdout)

    def test_a_diff_with_a_line_that_is_not_of_a_plain_diff_is_whole_and_the_review_is_fresh(self):
        """Only the forms of lines that git diff writes for two commits resume. git diff --submodule=log writes a
        submodule that changed as Submodule <path> <old>..<new>: and a line for each of its commits, with no diff --git
        line; git diff --binary writes GIT binary patch and its data, which hold empty lines; and an empty line is of
        no section. The review reads the diff whole, and it is fresh."""
        theorem = ("diff --git a/.theorem/config.yml b/.theorem/config.yml\n--- a/.theorem/config.yml\n"
                   "+++ b/.theorem/config.yml\n@@ -1 +1,2 @@\n sanitizers:\n+  - address\n")
        for why, diff in (
                ("a submodule's log after a section of .theorem/",
                 theorem + "Submodule lib 025e3a3..4f0d847:\n  > two\n"),
                ("a binary patch of .theorem/", "diff --git a/.theorem/seed.zip b/.theorem/seed.zip\n"
                 "index 20a6b40ed53634d558b7e3c3db33b1139173c4b2..213ab45af4e73441335d80e131802e59f0e2b674 100644\n"
                 "GIT binary patch\nliteral 7\nOcmWIWW@cevU<UvM9{{QV\n\nliteral 6\nNcmWIWW@cez0ssSf0Hy!{\n\n"),
                ("an empty line between two sections of .theorem/",
                 theorem + "\n" + theorem.replace("config.yml", "build.yml"))):
            with self.subTest(why=why):
                self.setUp()
                run = self.gather_since(diff)
                self.assertEqual(self.written(), "")
                self.assertIn(f"review-gather: the diff from {HEAD} holds a line that is not of a plain diff: the "
                              "review is fresh", run.stdout.splitlines())
                self.assertNotIn("resumes", run.stdout)

    def combined_section_gives_a_fresh_review(self, header):
        """A section of .theorem/, then a section of a merge's combined diff that `header` starts: git diff --cc and
        git diff --combined start no section with diff --git, so the script does not read its paths. The review reads
        the diff whole, and it is fresh."""
        theorem = ("diff --git a/.theorem/config.yml b/.theorem/config.yml\n--- a/.theorem/config.yml\n"
                   "+++ b/.theorem/config.yml\n@@ -1 +1,2 @@\n sanitizers:\n+  - address\n")
        combined = (f"{header}\nindex 1111111,2222222..3333333\n--- a/src/x.c\n+++ b/src/x.c\n"
                    "@@@ -1,1 -1,1 +1,1 @@@\n- int x;\n -int y;\n++int z;\n")
        run = self.gather_since(theorem + combined)
        self.assertEqual(self.written(), "")
        self.assertIn(f"review-gather: the diff from {HEAD} holds a section that is not of diff --git: the review is "
                      "fresh", run.stdout.splitlines())
        self.assertNotIn("resumes", run.stdout)

    def test_a_diff_cc_section_after_theorem_gives_a_fresh_review(self):
        self.combined_section_gives_a_fresh_review("diff --cc src/x.c")

    def test_a_diff_combined_section_after_theorem_gives_a_fresh_review(self):
        self.combined_section_gives_a_fresh_review("diff --combined src/x.c")

    def test_a_fetched_file_of_error_text_gives_a_fresh_review(self):
        """The fetch job wrote the error of a diff that failed in the place of the diff."""
        run = self.gather_since(f"fatal: bad object {HEAD}\n")
        self.assertEqual(self.written(), "")
        self.assertIn(f"review-gather: the diff from {HEAD} does not start with diff --git: the review is fresh",
                      run.stdout.splitlines())
        self.assertNotIn("resumes", run.stdout)

    def test_an_empty_fetched_diff_gives_a_fresh_review(self):
        run = self.gather_since("")
        self.assertEqual(self.written(), "")
        self.assertIn(f"review-gather: the diff from {HEAD} is empty: the review is fresh", run.stdout.splitlines())
        self.assertNotIn("resumes", run.stdout)

    def test_no_session_for_another_head_or_without_the_diff(self):
        diff = "diff --git a/.theorem/config.yml b/.theorem/config.yml\n@@ -0,0 +1 @@\n+sanitizers: [address]\n"
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
