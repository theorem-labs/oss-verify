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
the trees ext/<key>, ext/<key>/src and targets/<key> of its key and of each dependency key. A patch changes the
fuzz targets of the block when the patched tree is one of these trees, is in one, or holds one, after the links of
sources. When those files do not show all the targets, the notes say that the table cannot name them. When the
check found that the binaries match the release's, the notes also say which binaries differ, or may differ. No
content of a port stops the table: a port file that is missing or that cannot be read counts as absent.

tests/test_seeded_projects.py fails when docs/seeded-projects.tsv is not what this writes. The workflow
.github/workflows/tests.yaml runs its test Committed for a change to this file, src/oss_verify/validate.py, a file
under seeds/, docs/seeded-projects.tsv or tests/test_seeded_projects.py. The top of that workflow lists these paths.
A pull request that changes one of them runs this and commits docs/seeded-projects.tsv. After any other change,
such as a change to a port, .github/workflows/seeded-projects.yml fails on the push to main until a pull request
commits the table.
"""
import argparse
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


def port_bytes(port, name):
    """The bytes of the file `name` of `port`, or None if the port has no such file or it cannot be read. A name
    that is absolute or holds .. names no file of the port."""
    path = pathlib.PurePosixPath(name)
    if port is None or not path.parts or path.is_absolute() or ".." in path.parts:
        return None
    try:
        return port.joinpath(*path.parts).read_bytes()
    except (OSError, ValueError):
        return None


def port_text(port, name):
    """The text of the file `name` of `port`, read as UTF-8 with each byte that is not UTF-8 replaced, or "" if the
    port has no such file or it cannot be read."""
    data = port_bytes(port, name)
    return "" if data is None else data.decode("utf-8", errors="replace")


def directives(sources, kind):
    """The (path, argument) of each `kind` line (link or patch) of the text of a sources file, each path a tuple of
    its components."""
    found = []
    for line in sources.splitlines():
        fields = line.split("\t")
        if not line.startswith("#") and len(fields) == 3 and fields[0] == kind:
            found.append((pathlib.PurePosixPath(fields[1]).parts, fields[2]))
    return found


def resolved(path, links):
    """`path` after the links of sources ({path: target}): the longest link that holds it replaced by its target,
    again until no link holds it. None if a link still holds it after one step more than there are links."""
    for _ in range(len(links) + 2):
        link = next((path[:n] for n in range(len(path), -1, -1) if path[:n] in links), None)
        if link is None:
            return path
        path = links[link] + path[len(link):]
    return None


def meets(path, tree):
    """Whether `path` is the path `tree`, is in it, or holds it."""
    return path[:len(tree)] == tree or tree[:len(path)] == path


def build_lines(build):
    """The lines of the text of a build.sh that are not comments (whose first character that is not blank is #)."""
    return [line for line in build.splitlines() if not line.lstrip().startswith("#")]


def target_blocks(lines):
    """The blocks of build.sh lines that each ov_target_begin line starts: [(keys, fuzz targets)], with the block's
    key and dependency keys, and the fuzz targets that its ov_target_build lines name."""
    blocks = []
    for words in map(str.split, lines):
        if words[:1] == ["ov_target_begin"]:
            blocks.append((words[1:], []))
        elif words[:1] == ["ov_target_build"] and words[1:] and blocks:
            blocks[-1][1].append(words[1])
    return blocks


def named_elsewhere(key, lines):
    """Whether `key` is a whole word of one of the build.sh `lines` that is not an ov_target_begin line. Another
    block can then read what the block of `key` builds (as $LIBROOT/<key>)."""
    word = re.compile(rf"(?<![\w.-]){re.escape(key)}(?![\w.-])")
    return any(word.search(line) for line in lines if line.split()[:1] != ["ov_target_begin"])


def fuzz_targets(port, patch):
    """The sorted fuzz targets whose builds read the tree that the sources of `port` applies `patch` to, from its
    sources and build.sh. None if those files do not show them all (see the module's docstring)."""
    sources = port_text(port, validate.SOURCES)
    links = {path: pathlib.PurePosixPath(target).parts for path, target in directives(sources, "link")}
    patched = [resolved(path, links) for path, name in directives(sources, "patch") if name == patch]
    if not patched or None in patched:
        return None
    lines = build_lines(port_text(port, "build.sh"))
    blocks = target_blocks(lines)
    trees = {key: [resolved(pathlib.PurePosixPath(tree.format(key)).parts, links) for tree in KEY_TREES]
             for keys, _ in blocks for key in keys}
    if any(None in paths for paths in trees.values()):
        return None
    reached = {key for key, paths in trees.items() if any(meets(path, tree) for path in patched for tree in paths)}
    targets = [names for keys, names in blocks if reached.intersection(keys)]
    if not targets or not all(targets) or any(named_elsewhere(key, lines) for key in reached):
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
    changes = []
    for patch in listed:
        data = port_bytes(port, patch)
        if data is not None and checked.get(patch) == hashlib.sha256(data).hexdigest():
            continue
        targets = None if data is None else fuzz_targets(port, patch)
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
