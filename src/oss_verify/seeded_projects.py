# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Write docs/seeded-projects.tsv: each project of OSS-Fuzz at the commit of the oss-fuzz-theorems 2026.10 release,
whether we seeded it, what oss-verify check found of its seeded build, and why we did not seed it.

    uv run python3 -m oss_verify.seeded_projects    write docs/seeded-projects.tsv

The table holds no fact of its own. It is made from these files only:
  - seeds/oss-fuzz-projects.tsv: each project of OSS-Fuzz at that commit, and what the release's data says of
    it: why we did not seed it, or notes on what we took.
  - seeds/languages.tsv: the projects in another language than C and C++ that we seeded from the release's
    build of that language. The notes on each come from its row.
  - seeds/builds.tsv: the projects that we seeded, one row each, with what oss-verify check found of its build.
  - seeds/checked-patches.tsv: the patches that the check of each seed port applied, with their sha256.
  - the port of each seeded project, projects/<name>/ or else seeds/<name>/: its series, the patch files that
    series lists, its sources and its build.sh.
A seeded project's fuzz targets are in its project.yaml (seeds/<name>/, or projects/<name>/ for one whose
proofs we publish), and not in the table: a maintainer who adopts a project in projects/ changes that file.

The build notes of a seeded project give the detail of its check. They also name each patch that the port applies
since that check, new or in other bytes. They also name each patch of the check that the port no longer applies.
The sources and build.sh of the port give the fuzz targets that a patch changes. Each ov_target_begin block reads
the trees ext/<key>, ext/<key>/src and targets/<key> of its key and of each dependency key. It also reads each tree
that a link inside a tree that it reads points to. A patch changes the fuzz targets of the block when the patched
tree is one of these trees, is in one, or holds one. The table follows the links of sources to find these trees, as
lay-out-sources lays the links out and as Linux follows them. lay-out-sources reads the lines of sources in order,
and it makes the parent of a link through the links before it. Linux follows at most 40 links in one path. When
those files do not show all the targets, the notes say that the table cannot name them. The table also cannot name
them when sources shows that lay-out-sources cannot lay out the port:
  - a line without a path, or a link or patch line without exactly one field after its path
  - a path or a link target that is empty or absolute, or that holds ..
  - a link at a path that is there already: a path that the lines before it lay out, or the link's own target, is
    at that path or in it
  - a path that follows more than 40 links
It also cannot name them when the sources and the build.sh of the port take more than 1,000,000 steps (STEPS) to
read. When the check found that the binaries match the release's, the notes also say which binaries differ, or may
differ. No content of a port stops the table: a port file that is missing or that cannot be read counts as absent.

tests/test_seeded_projects.py fails when docs/seeded-projects.tsv is not what this writes. The workflow
.github/workflows/tests.yaml runs its test Committed for a change to this file, src/oss_verify/validate.py, a file
under seeds/, docs/seeded-projects.tsv or tests/test_seeded_projects.py. The top of that workflow lists these paths.
A pull request that changes one of them runs this and commits docs/seeded-projects.tsv. After any other change,
such as a change to a port, .github/workflows/seeded-projects.yml fails on the push to main until a pull request
commits the table.
"""
import argparse
import dataclasses
import functools
import hashlib
import pathlib
import re
import sys

from . import validate

ROOT = pathlib.Path(__file__).resolve().parents[2]
SEEDS = ROOT / "seeds"
PROJECTS = ROOT / "projects"
TABLE = ROOT / "docs" / "seeded-projects.tsv"

HEADER = ("# Written by src/oss_verify/seeded_projects.py; do not edit. Every OSS-Fuzz project at the commit of the "
          "oss-fuzz-theorems 2026.10 release: whether we seeded it, and why not. For a seeded project, build is what "
          "the check of its seed port found (seeds/builds.tsv). Its build notes also name each patch that the port "
          "applies since that check, or no longer applies (seeds/checked-patches.tsv). A seeded project's fuzz "
          "targets are in its project.yaml, in seeds/<name>/ or projects/<name>/.")
COLUMNS = ("project", "seedable", "build", "build notes", "reason or notes")
RELEASE_COLUMNS = ("project", "reason or notes")
LANGUAGE_COLUMNS = ("project", "oss_fuzz", "language", "repo", "commit", "homepage", "sanitizers", "fuzz_targets",
                    "release_targets", "held")
BUILD_COLUMNS = ("project", "result", "detail")
CHECKED_COLUMNS = ("project", "patch", "sha256")
SHA256 = re.compile("[0-9a-f]{64}")
# The trees that an ov_target_begin block reads for its key and for each dependency key.
KEY_TREES = ("ext/{}", "ext/{}/src", "targets/{}")
# Linux follows at most this many links in one path (MAXSYMLINKS), so lay-out-sources and a build do too.
MAXSYMLINKS = 40
# The most steps that the table takes on the sources and build.sh of one port, for all of its patches. A step is one
# unit of work whose count grows with the content of the port:
#   - a character or a line of sources or of build.sh
#   - a path component that a walk reads, or a component of the target of a link that a walk follows (two steps)
#   - a component of a path that the table adds as a directory, or a tree that it adds to its trie or finds there,
#     and each component of the tree
#   - a key of an ov_target_begin line, and each character of the key: when the table reads the trees of the key, and
#     when it searches the other lines of build.sh for the key
#   - a tree of a key that a block reads
#   - a component of a path, or a node of the trie, that the search for the trees that meet the path reads
#   - a tree that the search for the trees that a patch reaches finds, and each link or block that the tree leads to
#   - a fuzz target that the search names, and each character of it
#   - for a key with other characters than those of WORD, a character of build.sh that the search for the key reads
# A key that the table reads for the first time takes KEY_STEPS more. Each other operation goes over a text, a list or
# a path that took these steps, a fixed number of times. Only the sort of the fuzz targets compares each of them more
# times: about log2 of their number, which is less than 20. The table keeps one str for each path component (see
# components), so a dict lookup that finds a component compares no characters. The table reads each of the two files
# whole before it counts their characters, and validate.py lets sources have 64 KiB and build.sh 256 KiB.
# A probe at a tree of a real port takes fewer than 80,000 steps (projects/openssl), and the fan of 2400 blocks in
# tests/test_seeded_projects.py takes about 425,000. On the machine where we measured, the steps of keys that the
# table reads for the first time take the most CPU time: 12,000 such keys on one line take 864,000 steps and 0.25 to
# 0.5 seconds. Thus a port that takes all the steps takes less than a second of CPU time, whatever its content.
STEPS = 1_000_000
# The steps that a key takes in addition when the table reads it for the first time. For each such key, the table
# makes its three trees (KEY_TREES) from the characters of the key, and starts a walk and a lookup in its trie for
# each tree. On the machine where we measured, this work takes as much CPU time as about 40 other steps.
KEY_STEPS = 40
# A whole word of a line of build.sh: a run of word characters, dots and dashes that is as long as it can be.
WORD = re.compile(r"[\w.-]+")
LANGUAGE_NAMES = {"rust": "Rust", "python": "Python", "go": "Go", "javascript": "JavaScript", "jvm": "JVM"}


class Error(Exception):
    """An input from which the table cannot be made."""


def tsv_fields(path, columns):
    """The fields of each row of a TSV file, one value for each of `columns`, without its comment lines (#) and its
    line of column names."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or line == "\t".join(columns):
            continue
        fields = line.split("\t")
        if len(fields) != len(columns) or not all(fields):
            raise Error(f"{path}: a row without a value in each of its {len(columns)} columns: {line!r}")
        if fields[0] == "project":
            raise Error(f"{path}: its line of column names is not {chr(9).join(columns)!r}: {line!r}")
        yield fields


def read_rows(path, columns):
    """The rows of a TSV file, {project: {column: value}}, without its comment lines (#) and its line of column
    names. Each row has a value in each of `columns`, and names a project that no other row names."""
    rows = {}
    for fields in tsv_fields(path, columns):
        if fields[0] in rows:
            raise Error(f"{path}: two rows for {fields[0]}")
        rows[fields[0]] = dict(zip(columns, fields))
    return rows


def language_notes(row):
    """The notes on a project that we seeded from its row of seeds/languages.tsv."""
    language = LANGUAGE_NAMES.get(row["language"], row["language"])
    notes = [f"the release built it in its {language} build, which it did not publish"]
    if row["oss_fuzz"] != row["project"]:
        notes.append(f"one of the repositories of OSS-Fuzz's project {row['oss_fuzz']}, each a project here")
    if row["held"] != "-":
        notes.append(f"the release held back these builds: {row['held']}")
    return "; ".join(notes)


def checked_patches(path):
    """The patches that the check of each seed port applied, from seeds/checked-patches.tsv: {project: {patch:
    sha256}}, the patches of a project in the order of its rows."""
    record = {}
    for project, patch, sha256 in tsv_fields(path, CHECKED_COLUMNS):
        if patch in record.get(project, {}):
            raise Error(f"{path}: two rows for {patch} of {project}")
        if not SHA256.fullmatch(sha256):
            raise Error(f"{path}: the sha256 of {patch} of {project} is not 64 lower-case hex digits: {sha256!r}")
        record.setdefault(project, {})[patch] = sha256
    return record


def port_directory(name, seeds, projects):
    """The port of the seeded project `name`: projects/<name>/ if it is a directory, else seeds/<name>/ if it is a
    directory, else None."""
    return next((path for path in (projects / name, seeds / name) if path.is_dir()), None)


def relative(text):
    """The components of the path `text`, which is relative to a root: the parts between its slashes, without the
    empty parts and the parts that are a dot, as pathlib.PurePosixPath gives them. None if the path has no
    components, starts with a slash (it is absolute) or holds .. (lay-out-sources refuses such a path)."""
    parts = text.split("/")
    if "" in parts or "." in parts:
        parts = [part for part in parts if part and part != "."]
    if not parts or text.startswith("/") or ".." in parts:
        return None
    return tuple(parts)


def port_bytes(port, name):
    """The bytes of the file `name` of `port`, or None if the port has no such file or it cannot be read. A name
    that is absolute or holds .. names no file of the port."""
    path = relative(name)
    if port is None or path is None:
        return None
    try:
        return port.joinpath(*path).read_bytes()
    except (OSError, ValueError):
        return None


def port_text(port, name):
    """The text of the file `name` of `port`, read as UTF-8 with each byte that is not UTF-8 replaced, or "" if the
    port has no such file or it cannot be read."""
    data = port_bytes(port, name)
    return "" if data is None else data.decode("utf-8", errors="replace")


class Steps:
    """The steps that the table can still take on one port: STEPS at first."""

    def __init__(self):
        self.left = STEPS

    def take(self, count=1):
        """Whether `count` more steps fit in the steps that are left. It takes them from those steps."""
        self.left -= count
        return self.left >= 0


def walk(root, path, steps):
    """The path that `path` names after the links in `root` (from lay_out), as Linux follows them. The walk reads
    the components of `path` in turn, one step for each, which it takes first. At a link, also at the last component,
    it goes on from the root: first with the components of the link's target, then with the components that are left.
    When it follows the link, it takes two steps for each component of the target: one because the walk can stop
    before it reads them, and one for the read. None if the walk follows more than MAXSYMLINKS links, or if `steps`
    run out."""
    if not steps.take(len(path)):
        return None
    node, walked, rest, followed = root, [], list(reversed(path)), 0
    while rest:
        name = rest.pop()
        child = None if node is None else node.get(name)
        if isinstance(child, tuple):
            followed += 1
            if followed > MAXSYMLINKS or not steps.take(2 * len(child)):
                return None
            node, walked = root, []
            rest += reversed(child)
        else:
            node = child
            walked.append(name)
    return tuple(walked)


def directory(root, path, steps):
    """The dict of the directory `path` in `root` (from lay_out). It adds the directory, and each directory that holds
    it, where they are not there yet, as mkdir -p does. `path` goes through no link: it is a path after the links. It
    takes one step for each component of `path`. None if `steps` run out."""
    if not steps.take(len(path)):
        return None
    node = root
    for name in path:
        node = node.setdefault(name, {})
    return node


def link(root, path, target, steps):
    """The (location, end) of the link at `path` to `target` (path components), which lay-out-sources makes after the
    links in `root` (from lay_out). It adds the link to `root`. The location is the path of the link: its parent after
    those links, then its own name. The end is `target` after those links. lay-out-sources also needs the target to be
    there, but the sources file does not show each directory that a tree, git or archive line lays out. So this adds
    the end where it is not there yet. None if a walk or a directory gives None, or if lay-out-sources cannot make the
    link because something is at the location: a path laid out before the link, or the target, is at the location or
    in it."""
    parent, end = walk(root, path[:-1], steps), walk(root, target, steps)
    if parent is None or end is None or directory(root, end, steps) is None:
        return None
    node = directory(root, parent, steps)
    if node is None or path[-1] in node:
        return None
    node[path[-1]] = target
    return parent + path[-1:], end


def components(text, names):
    """The components of the path `text` (from relative). Each is the str of `names` that has the same characters: this
    adds to `names` each component that is not in it yet. So the table has one str for each component, and a dict
    lookup that finds a component compares no characters. None if relative gives None."""
    path = relative(text)
    return None if path is None else tuple([names.setdefault(name, name) for name in path])


def text_lines(text, steps):
    """The lines of `text` (str.splitlines). It takes one step for each character of the text, before it splits the
    text, and one step for each line. The table reads each line, and splits it into fields and words, a fixed number
    of times. None if `steps` run out."""
    if not steps.take(len(text)):
        return None
    lines = text.splitlines()
    return lines if steps.take(len(lines)) else None


def lay_out(sources, names, steps):
    """What lay-out-sources lays out from the text of a sources file, line by line, as far as the text shows it:
    (root, links, patched).
      - root: the dict of the root directory. The dict of a directory maps the name of each directory in it to the
        directory's dict, and the name of each link in it to the components of the link's target.
      - links: the (location, end) of each link (from link).
      - patched: {patch: [each path that a patch line applies it to, after the links before that line]}
    Each path component is a str of `names` (see components). None if lay-out-sources cannot lay out the text (see
    the module's docstring), or if `steps` run out."""
    lines = text_lines(sources, steps)
    if lines is None:
        return None
    root, links, patched = {}, [], {}
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        kind, *fields = line.split("\t")
        path = components(fields[0], names) if fields else None
        if path is None or (kind in ("link", "patch") and len(fields) != 2):
            return None
        if kind == "link":
            target = components(fields[1], names)
            placed = None if target is None else link(root, path, target, steps)
            if placed is None:
                return None
            links.append(placed)
            continue
        walked = walk(root, path, steps)
        if walked is None or directory(root, walked, steps) is None:
            return None
        if kind == "patch":
            patched.setdefault(fields[1], []).append(walked)
    return root, links, patched


def key_trees(root, blocks, names, steps):
    """The trees that `blocks` (from target_blocks) read for each of their keys (KEY_TREES), after the links in `root`
    (from lay_out): {key: [tree]}, each key once, in the order in which the blocks first name it. Each key of each
    block takes one step, and one step for each of its characters, because the lookup of the key reads them. This is
    also true for a key that it read before. A key that it did not read before takes KEY_STEPS more, and the steps of
    the walks of its trees. Each path component is a str of `names` (see components). None at the first key with a
    tree that holds .. or whose walk gives None, or if `steps` run out."""
    trees = {}
    for key in (key for keys, _ in blocks for key in keys):
        if not steps.take(1 + len(key)):
            return None
        if key in trees:
            continue
        if not steps.take(KEY_STEPS):
            return None
        trees[key] = []
        for tree in KEY_TREES:
            path = components(tree.format(key), names)
            walked = None if path is None else walk(root, path, steps)
            if walked is None:
                return None
            trees[key].append(walked)
    return trees


def tree_number(index, readable, tree, steps):
    """The number of `tree` in `index`, the trie of the trees `readable`: [children, number]. children maps each next
    path component to the trie of the trees that go on with it. number is that of the tree that ends there (its index
    in `readable`), or None. A tree that is not in the trie yet gets the next number: this adds it to the trie and to
    `readable`. It takes one step for the tree and one step for each of its components. None if `steps` run out."""
    if not steps.take(1 + len(tree)):
        return None
    node = index
    for name in tree:
        child = node[0].get(name)
        if child is None:
            child = node[0][name] = [{}, None]
        node = child
    if node[1] is None:
        node[1] = len(readable)
        readable.append(tree)
    return node[1]


def meeting(index, path, steps):
    """The numbers of the trees in `index` (from tree_number) that meet `path`: each tree that holds it, is it, or is
    in it. None if `steps` run out."""
    met, node = [], index
    for name in path:
        if not steps.take():
            return None
        if node[1] is not None:
            met.append(node[1])
        node = node[0].get(name)
        if node is None:
            return met
    nodes = [node]
    while nodes:
        if not steps.take():
            return None
        node = nodes.pop()
        if node[1] is not None:
            met.append(node[1])
        nodes += node[0].values()
    return met


def target_blocks(build, steps):
    """What the table reads of the text of a build.sh, without its comment lines (whose first character that is not
    blank is #): (blocks, other).
      - blocks: [(keys, fuzz targets)] for each ov_target_begin line: the block's key and dependency keys, each once,
        and the fuzz targets that the ov_target_build lines after it name.
      - other: the text of the lines that are not ov_target_begin lines, with a newline between two lines.
    None if `steps` run out (see text_lines)."""
    lines = text_lines(build, steps)
    if lines is None:
        return None
    blocks, other = [], []
    for line in lines:
        words = line.split()
        if words[:1] == ["ov_target_begin"]:
            blocks.append((list(dict.fromkeys(words[1:])), []))
        elif not words or not words[0].startswith("#"):
            if words[:1] == ["ov_target_build"] and words[1:] and blocks:
                blocks[-1][1].append(words[1])
            other.append(line)
    return blocks, "\n".join(other)


def whole_word(key, padded):
    """Whether `padded`, a text with a space at its start and at its end, names `key`, which holds no blank, as a whole
    word: the character just before it and the character just after it are not characters of WORD. re's \\w is a
    character for which str.isalnum() is true, or _."""
    start = padded.find(key)
    while start >= 0:
        before, after = padded[start - 1], padded[start + len(key)]
        if not (before.isalnum() or before in "_.-" or after.isalnum() or after in "_.-"):
            return True
        start = padded.find(key, start + 1)
    return False


def named_elsewhere(keys, other, steps):
    """The `keys` that `other`, the text of the lines of build.sh that are not ov_target_begin lines (from
    target_blocks), names as a whole word (WORD). Another block can then read what the block of such a key builds (as
    $LIBROOT/<key>). Each key takes one step, and one step for each of its characters. A key with other characters
    than those of WORD takes one more step for each character of `other`, which the search for the key reads. None if
    `steps` run out."""
    words = set(WORD.findall(other))
    padded = f" {other} "
    named = set()
    for key in keys:
        if not steps.take(1 + len(key)):
            return None
        if WORD.fullmatch(key):
            if key in words:
                named.add(key)
        elif not steps.take(len(other)):
            return None
        elif whole_word(key, padded):
            named.add(key)
    return named


@dataclasses.dataclass
class Layout:
    """What fuzz_targets reads of a port, which port_layout makes once from its sources and build.sh. A tree that a
    build can read is a tree of a key of build.sh or the end of a link, after the links. Each has a number.
      - patched: {patch: [each path that sources applies it to, after the links]}
      - index: the trie of the trees (see tree_number)
      - holders: for each tree, the trees that hold the location of a link to it
      - readers: for each tree, the blocks of build.sh that read it (their numbers in targets)
      - named: for each tree, whether it is a tree of a key that build.sh names elsewhere (named_elsewhere)
      - targets: for each block of build.sh, the fuzz targets that it builds
      - steps: the steps that the table can still take on the port"""
    patched: dict
    index: list
    holders: list
    readers: list
    named: list
    targets: list
    steps: Steps


def port_layout(port):
    """The Layout of `port`, from its sources and build.sh. None if the table cannot name the fuzz targets of any
    patch of the port (see the module's docstring)."""
    steps, names = Steps(), {}
    laid = lay_out(port_text(port, validate.SOURCES), names, steps)
    read = None if laid is None else target_blocks(port_text(port, "build.sh"), steps)
    if read is None:
        return None
    (root, links, patched), (blocks, other) = laid, read
    trees = key_trees(root, blocks, names, steps)
    elsewhere = None if trees is None else named_elsewhere(trees, other, steps)
    if elsewhere is None:
        return None
    # The trees of each key and the end of each link get their numbers once. tree_number gives None only when the
    # steps run out.
    index, readable = [{}, None], []
    numbers = {key: [tree_number(index, readable, tree, steps) for tree in paths] for key, paths in trees.items()}
    ends = [tree_number(index, readable, end, steps) for _, end in links]
    if steps.left < 0:
        return None
    holders, readers, named = [[] for _ in readable], [[] for _ in readable], [False] * len(readable)
    for (location, _), end in zip(links, ends):
        # No tree is at the location of a link or in it: each is a path after the links. So a tree that meets the
        # location holds it.
        held = meeting(index, location, steps)
        if held is None:
            return None
        holders[end] += held
    for key in elsewhere:
        for tree in numbers[key]:
            named[tree] = True
    # A block names each of its keys once (target_blocks). Each tree of each key of a block takes one step.
    for block, (keys, _) in enumerate(blocks):
        if not steps.take(len(KEY_TREES) * len(keys)):
            return None
        for key in keys:
            for tree in numbers[key]:
                readers[tree].append(block)
    return Layout(patched, index, holders, readers, named, [targets for _, targets in blocks], steps)


def reached_trees(layout, paths):
    """The numbers of the trees of `layout` (from port_layout) through which a build reads one of the patched
    `paths`: each tree that meets one of them, and each tree that holds the location of a link to such a tree. None
    if the steps of the port run out."""
    new = []
    for path in paths:
        met = meeting(layout.index, path, layout.steps)
        if met is None:
            return None
        new += met
    found = set()
    while new:
        tree = new.pop()
        if tree not in found:
            found.add(tree)
            if not layout.steps.take(1 + len(layout.holders[tree]) + len(layout.readers[tree])):
                return None
            new += layout.holders[tree]
    return found


def fuzz_targets(layout, patch):
    """The sorted fuzz targets whose builds read a tree that the sources of a port apply `patch` to, from the port's
    `layout` (from port_layout). None if its sources and build.sh do not show them all (see the module's
    docstring)."""
    found = None if layout is None or patch not in layout.patched else reached_trees(layout, layout.patched[patch])
    if found is None or any(layout.named[tree] for tree in found):
        return None
    targets = [layout.targets[block] for block in {block for tree in found for block in layout.readers[tree]}]
    if not targets or not all(targets):
        return None
    # Each fuzz target of each block takes one step, and one step for each of its characters, which the set and the
    # sort of the fuzz targets compare.
    if not layout.steps.take(sum(len(names) + sum(map(len, names)) for names in targets)):
        return None
    return sorted({name for names in targets for name in names})


def applied(patch, other_bytes, targets):
    """The words that name `patch`, which the port applies since the check of its seed port (in bytes other than
    that check's, if `other_bytes`), and its fuzz `targets` (None if the table cannot name them)."""
    other = " in bytes other than that check's" if other_bytes else ""
    if targets is None:
        return f"applies {patch}{other}, whose fuzz targets this table cannot name"
    return f"applies {patch}{other}{',' if other_bytes else ''} to {', '.join(targets)}"


def port_changes(port, checked):
    """What `port` applies since the check of its seed port, which applied `checked` ({patch: sha256}): [(words,
    fuzz targets or None)], first each patch applied since that check in series order, then each patch of
    `checked` that the port no longer applies."""
    listed = dict.fromkeys(validate.series_entries(port_text(port, validate.SERIES)))
    # The layout of the port, made once, for the first patch whose fuzz targets are wanted.
    layout = functools.cache(lambda: port_layout(port))
    changes = []
    for patch in listed:
        data = port_bytes(port, patch)
        if data is not None and checked.get(patch) == hashlib.sha256(data).hexdigest():
            continue
        targets = None if data is None else fuzz_targets(layout(), patch)
        changes.append((applied(patch, patch in checked, targets), targets))
    return changes + [(f"no longer applies {patch}", None) for patch in checked if patch not in listed]


def build_notes(build, changes):
    """The build notes of a seeded project, from its row of seeds/builds.tsv and what its port applies since that
    check (`changes`, from port_changes)."""
    if not changes:
        return build["detail"]
    notes = f"the seed port's check: {build['detail']}; since that check the port {'; '.join(w for w, _ in changes)}"
    if build["result"] != "reproduces":
        return notes
    named = ", ".join(sorted({name for _, targets in changes for name in targets or ()}))
    if all(targets is not None for _, targets in changes):
        return f"{notes}: the binaries of {named} differ from the release's"
    if named:
        return f"{notes}: the binaries of {named} differ from the release's, and others may"
    return f"{notes}: some of its binaries may differ from the release's"


def table(seeds=SEEDS, projects=PROJECTS):
    """The text of docs/seeded-projects.tsv, from the files in `seeds` and the port of each seeded project, in
    `projects` or else in `seeds`."""
    release = read_rows(seeds / "oss-fuzz-projects.tsv", RELEASE_COLUMNS)
    languages = read_rows(seeds / "languages.tsv", LANGUAGE_COLUMNS)
    builds = read_rows(seeds / "builds.tsv", BUILD_COLUMNS)
    checked = checked_patches(seeds / "checked-patches.tsv")
    unknown = sorted(set(builds) - set(release) - set(languages))
    if unknown:
        raise Error(f"seeds/builds.tsv has rows for projects that neither oss-fuzz-projects.tsv nor "
                    f"languages.tsv names: {', '.join(unknown)}")
    unchecked = sorted(set(checked) - set(builds))
    if unchecked:
        raise Error(f"seeds/checked-patches.tsv has rows for projects that seeds/builds.tsv has no row for: "
                    f"{', '.join(unchecked)}")
    # An OSS-Fuzz project whose fuzz targets are in more than one repository: the projects we seeded, one for each.
    split = {}
    for row in languages.values():
        if row["oss_fuzz"] not in release:
            raise Error(f"seeds/languages.tsv seeds {row['project']} from OSS-Fuzz's project {row['oss_fuzz']}, "
                        "which seeds/oss-fuzz-projects.tsv does not name")
        if row["oss_fuzz"] != row["project"]:
            split.setdefault(row["oss_fuzz"], []).append(row["project"])
    lines = [HEADER, "\t".join(COLUMNS)]
    for name in sorted(set(release) | set(languages)):
        notes = release[name]["reason or notes"] if name in release else "-"
        if (name in languages or name in split) and notes != "-":
            raise Error(f"seeds/oss-fuzz-projects.tsv has notes on {name}, whose notes come from "
                        "seeds/languages.tsv: give -")
        if name in split and name in builds:
            raise Error(f"seeds/builds.tsv has a row for {name}, which we seeded as "
                        f"{', '.join(sorted(split[name]))}: one project for each of its repositories")
        if name in split and name not in languages:
            lines.append(f"{name}\tno\t-\t-\tseeded as {', '.join(sorted(split[name]))}: one project for each of its "
                         "repositories")
        elif name in builds:
            notes = language_notes(languages[name]) if name in languages else notes
            changes = port_changes(port_directory(name, seeds, projects), checked.get(name, {}))
            lines.append("\t".join((name, "yes", builds[name]["result"], build_notes(builds[name], changes), notes)))
        elif name in languages:
            raise Error(f"seeds/languages.tsv seeds {name}, but seeds/builds.tsv has no row for it")
        elif notes == "-":
            raise Error(f"seeds/oss-fuzz-projects.tsv gives no reason why {name} is not seeded")
        else:
            lines.append(f"{name}\tno\t-\t-\t{notes}")
    return "\n".join(lines) + "\n"


def main():
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    try:
        text = table()
    except (Error, OSError, UnicodeDecodeError) as error:
        sys.exit(f"src/oss_verify/seeded_projects.py: {error}")
    TABLE.write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
