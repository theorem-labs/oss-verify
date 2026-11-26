# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The read of one file of an artifact of a Build run (read_member), the exceptions that read_member does not catch
(UNREADABLE), the class that reads GitHub's REST API (Api), the check of a whole number of JSON (whole), and the runs
of a workflow file at a head (runs_at) and the one of them that gives its check (deciding_run).
take-build-results, enroll-dispatch and required-check import them from this directory, as they import steering.py:

    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    from artifact import Api, read_member, whole
    data, why = read_member(Api(), repo, run, "build-results", "results.json", 1 << 20)

read_member gives the bytes of the file and '', or None and why not. The reason names no text of the artifact. A zip,
or a file in it, that zipfile cannot read raises one of the exceptions of UNREADABLE. A call of gh that fails raises
subprocess.CalledProcessError. Each caller handles them in its own way. This reads the zip in memory and writes no
file.
"""
from __future__ import annotations

import io
import json
import subprocess
import zipfile
import zlib
from urllib.parse import quote

# The exceptions that read_member does not catch, for a zip, or a file in it, that zipfile cannot read:
# zipfile.BadZipFile (for example, a file whose bytes do not match its header), EOFError (a cut file), zlib.error (a
# broken deflate stream), NotImplementedError (a flag bit or a zip version that zipfile cannot read), and ValueError (a
# file name that is not UTF-8).
UNREADABLE = (zipfile.BadZipFile, EOFError, zlib.error, NotImplementedError, ValueError)


class Api:
    """GitHub's REST API through the gh command-line tool, which reads GH_TOKEN."""

    def run(self, path: str, *flags: str) -> bytes:
        return subprocess.run(["gh", "api", *flags, "--", path], check=True, capture_output=True).stdout

    def get(self, path: str):
        return json.loads(self.run(path))

    def pages(self, path: str) -> list:
        """Every page of a paginated answer, as a list of pages."""
        return json.loads(self.run(path, "--paginate", "--slurp"))

    def raw(self, path: str) -> bytes:
        return self.run(path, "-H", "Accept: application/vnd.github.raw")


def whole(value: object) -> bool:
    """Whether `value` is a whole number of JSON: an int that is not a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def deciding_run(runs: list[dict]) -> dict | None:
    """Of the runs of a required check's workflow file at one head commit of one pull request's head, the run whose job
    gives the check: the newest (by id), or None for no run. But when GitHub cancelled the newest, and another run of
    the same file, event and head commit was created in the same second and ended otherwise, the newest such run. Of
    two runs that start in the same second in one concurrency group, GitHub can cancel the newer and keep the older (on
    #317, Terms runs 45815765694 and 45815765408), and runs of one head created in the same second judge one merge
    commit. A run created in an earlier second never stands in for a cancelled newer one: it can have read an older
    input, such as a Terms run the description before an edit. required-check and enroll-dispatch both decide by it,
    so they agree."""
    newest = max(runs, key=lambda r: r["id"], default=None)
    if newest is None or (newest.get("status"), newest.get("conclusion")) != ("completed", "cancelled"):
        return newest
    twin = (newest.get("path"), newest.get("event"), newest.get("head_sha"), newest.get("created_at"))
    kept = [r for r in runs if isinstance(twin[3], str) and twin[3]
            and (r.get("path"), r.get("event"), r.get("head_sha"), r.get("created_at")) == twin
            and r.get("status") == "completed" and r.get("conclusion") != "cancelled"]
    return max(kept, key=lambda r: r["id"], default=newest)


def runs_at(api: Api, repo: str, path: str, event: str, sha: str, head: tuple[object, object]) -> list[dict]:
    """The runs of the workflow file `path` on `event` at the head commit `sha`, of a pull request from `head` (its
    repository and branch), as GitHub lists them, each with a whole id and run_attempt. A run of another file that
    GitHub lists under the same workflow does not count."""
    workflow = quote(path.rsplit("/", 1)[1], safe="")
    return [r for page in api.pages(f"repos/{repo}/actions/workflows/{workflow}/runs?event={event}&head_sha={sha}"
                                    "&per_page=100")
            for r in page.get("workflow_runs") or []
            if r.get("path") == path and r.get("event") == event and r.get("head_sha") == sha
            and ((r.get("head_repository") or {}).get("full_name"), r.get("head_branch")) == head
            and whole(r.get("id")) and whole(r.get("run_attempt"))]


def read_member(api: Api, repo: str, run: int, name: str, member: str, limit: int) -> tuple[bytes | None, str]:
    """The bytes of `member`, the one file of the artifact `name` of the Build run `run`, and ''; or None and why not.
    The run must have exactly one unexpired artifact of that name. The API must give its id and its size_in_bytes as
    whole numbers. That size and the size of the download must be at most `limit` bytes. The zip must hold `member`
    once, and no other file. That file must be stored or deflated, and of at most `limit` bytes by its header. It must
    not be encrypted. A read with a size stops at the header's size for such a file.
    zipfile raises an exception of UNREADABLE for a zip, or a file in it, that it cannot read, and this does not catch
    it. An answer of the API that is not JSON raises ValueError, one of UNREADABLE, too. A call of gh that fails raises
    subprocess.CalledProcessError."""
    found = [a for page in api.pages(f"repos/{repo}/actions/runs/{run}/artifacts?name={name}&per_page=100")
             for a in page.get("artifacts") or [] if a.get("name") == name and not a.get("expired")]
    if len(found) != 1:
        return None, f"Build run {run} has {len(found)} unexpired {name} artifacts, not one"
    if not whole(found[0].get("id")) or not whole(found[0].get("size_in_bytes")):
        return None, f"the API gave Build run {run}'s {name} with no id or size"
    if found[0]["size_in_bytes"] > limit:
        return None, f"Build run {run}'s {name} is larger than {limit} bytes"
    data = api.raw(f"repos/{repo}/actions/artifacts/{found[0]['id']}/zip")
    if len(data) > limit:
        return None, f"Build run {run}'s {name} is larger than {limit} bytes"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.namelist() != [member] or (info := archive.getinfo(member)).file_size > limit:
            return None, f"Build run {run}'s {name} does not hold {member} alone"
        # read() with no size decompresses the whole member before it cuts the member to the header's size. A read
        # with a size stops at the header's size for a stored or deflated member, and the read of a member whose bytes
        # do not match its header fails (BadZipFile). zipfile decompresses bzip2 and lzma with no bound, also for a
        # read with a size. So this reads only a stored or deflated member.
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            return None, (f"Build run {run}'s {member} has the compression method {info.compress_type}, not stored or "
                          "deflated")
        # ZipFile.open raises RuntimeError for an encrypted file, because this gives no password. Bit 0x1 of the
        # general purpose bit flag marks an encrypted file.
        if info.flag_bits & 0x1:
            return None, f"Build run {run}'s {member} is encrypted"
        with archive.open(info) as opened:
            return opened.read(limit), ""
