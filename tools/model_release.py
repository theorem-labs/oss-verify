# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The process model that the binary checks hold a binary against: the version that the published proofs use.

The proofs repository's release.yaml names the model (its `semantics:` block: the repository and the commit). The
binary checks read that file from the proofs repository's default branch, fetch the model's files at that commit with
git, anonymously, over https, and keep them in the cache. Nothing here copies the model.

Two checks read the model's code by hand-written rules: tools/binary_isa.py (the instruction decoder, theories/Riscv)
and tools/syscall_shapes.py (the system calls and their arguments, theories/LinuxProcessSem). Each one names the model
commit its rules were checked against and the SHA-256 of each model file it reads, with the file's comments removed
(code_sha256). When the release names a model whose code differs in one of those files, the rules may no longer be
the model's, and the check says so instead of a verdict (stale()). A change to a comment changes no verdict.
"""
import hashlib
import pathlib
import re
import urllib.request

import yaml

import check_build
from check_build import Failed

# The release.yaml of the published proofs, on the default branch of the public repository.
RELEASE_YAML = "https://raw.githubusercontent.com/theorem-labs/oss-verify-proofs/main/release.yaml"
PUBLIC_REPOSITORY = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")


def release_model(url=RELEASE_YAML, text=None):
    """The model that the release names: {"release", "name", "repository", "commit", "from"}. `text` is the
    release.yaml's text, for a caller that has it; otherwise it is downloaded from `url`. Raise Failed if it cannot be
    read or names no public model at a full commit id."""
    if text is None:
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                text = response.read(1 << 20).decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise Failed(f"cannot read {url}: {error}") from error
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise Failed(f"{url} is not YAML: {error}") from error
    semantics = data.get("semantics") if isinstance(data, dict) else None
    if not isinstance(semantics, dict):
        raise Failed(f"{url} has no semantics: block, which names the model")
    repository, commit = semantics.get("repository"), semantics.get("commit")
    if not (isinstance(repository, str) and PUBLIC_REPOSITORY.fullmatch(repository)):
        raise Failed(f"{url}: semantics.repository is not a GitHub repository URL: {repository!r}")
    if not (isinstance(commit, str) and COMMIT.fullmatch(commit)):
        raise Failed(f"{url}: semantics.commit is not a full commit id: {commit!r}")
    return {"release": str(data.get("release", "")), "name": str(semantics.get("name", "")),
            "repository": repository, "commit": commit, "from": url}


def fetch(repository, commit, cache=None):
    """A checkout of the model at `commit`, fetched once into the cache: its directory. git checks every object
    against the commit id, so the files are the commit's."""
    home = (cache or check_build.CACHE) / "model" / commit
    # Under the entry's lock: a second run that fetches the same commit at the same time waits, then finds it fetched,
    # instead of removing the first run's checkout while git writes it (clone() starts by removing the directory).
    with check_build.cache_lock(home):
        if (home / ".fetched").is_file():
            return home
        check_build.clone(repository, commit, home)
        (home / ".fetched").write_text(f"{repository} {commit}\n", encoding="utf-8")
    return home


def rocq_code(text):
    """The code of a Rocq file: its comments removed (they nest; a string, where "" is a quote, is kept whole), each
    line's runs of blanks made one blank, and blank lines dropped."""
    out, depth, i, n = [], 0, 0, len(text)
    while i < n:
        if text[i] == '"':
            j = i + 1
            while True:
                j = text.find('"', j)
                if j == -1:
                    j = n - 1
                    break
                if j + 1 < n and text[j + 1] == '"':
                    j += 2
                    continue
                break
            if depth == 0:
                out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("(*", i):
            depth += 1
            i += 2
        elif depth and text.startswith("*)", i):
            depth -= 1
            i += 2
        else:
            if depth == 0:
                out.append(text[i])
            i += 1
    lines = (re.sub(r"\s+", " ", line).strip() for line in "".join(out).split("\n"))
    return [line for line in lines if line]


def code_sha256(text):
    """The SHA-256 of a Rocq file's code (rocq_code), in hex: the same for two files that differ only in comments and
    blanks."""
    return hashlib.sha256("\n".join(rocq_code(text)).encode("utf-8")).hexdigest()


def stale(root, files):
    """The files of `files` ({path in the model repository: code_sha256 the rules were checked against}) whose code
    in the checkout `root` differs, or that it does not have: [path]. [] means the rules read the model as it is."""
    root = pathlib.Path(root)
    changed = []
    for path, expected in sorted(files.items()):
        file = root / path
        if not file.is_file() or code_sha256(file.read_text(encoding="utf-8", errors="replace")) != expected:
            changed.append(path)
    return changed
