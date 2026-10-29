#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Write docs/seeded-projects.tsv: each project of OSS-Fuzz at the commit of the oss-fuzz-theorems 2026.10 release,
whether we seeded it, what tools/check found of its seeded build, and why we did not seed it.

    tools/seeds/seeded_projects.py    write docs/seeded-projects.tsv

The table holds no fact of its own. It is made from these files only:
  - tools/seeds/oss-fuzz-projects.tsv: each project of OSS-Fuzz at that commit, and what the release's data says of
    it: why we did not seed it, or notes on what we took;
  - tools/seeds/languages.tsv: the projects in another language than C and C++ that we seeded from the release's
    build of that language; the notes on each come from its row;
  - tools/seeds/builds.tsv: the projects that we seeded, one row each, with what tools/check found of its build.
A seeded project's fuzz targets are in its project.yaml (tools/seeds/<name>/, or projects/<name>/ for one whose
proofs we publish), and not in the table: a maintainer who adopts a project in projects/ changes that file.

tools/tests/test_seeded_projects.py fails when docs/seeded-projects.tsv is not what this writes. After a change to
one of those files, run this, and commit docs/seeded-projects.tsv with the change.
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SEEDS = ROOT / "tools" / "seeds"
TABLE = ROOT / "docs" / "seeded-projects.tsv"

HEADER = ("# Written by tools/seeds/seeded_projects.py; do not edit. Every OSS-Fuzz project at the commit of the "
          "oss-fuzz-theorems 2026.10 release: whether we seeded it, whether its seeded build reproduces the release's "
          "binaries (tools/seeds/builds.tsv), and why not. A seeded project's fuzz targets are in its project.yaml, in "
          "tools/seeds/<name>/ or projects/<name>/.")
COLUMNS = ("project", "seedable", "build", "build notes", "reason or notes")
RELEASE_COLUMNS = ("project", "reason or notes")
LANGUAGE_COLUMNS = ("project", "oss_fuzz", "language", "repo", "commit", "homepage", "sanitizers", "fuzz_targets",
                    "release_targets", "held")
BUILD_COLUMNS = ("project", "result", "detail")
LANGUAGE_NAMES = {"rust": "Rust", "python": "Python", "go": "Go", "javascript": "JavaScript", "jvm": "JVM"}


class Error(Exception):
    """An input from which the table cannot be made."""


def read_rows(path, columns):
    """The rows of a TSV file, {project: {column: value}}, without its comment lines (#) and its line of column
    names. Each row has a value in each of `columns`, and names a project that no other row names."""
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or line == "\t".join(columns):
            continue
        fields = line.split("\t")
        if len(fields) != len(columns) or not all(fields):
            raise Error(f"{path}: a row without a value in each of its {len(columns)} columns: {line!r}")
        if fields[0] == "project":
            raise Error(f"{path}: its line of column names is not {chr(9).join(columns)!r}: {line!r}")
        if fields[0] in rows:
            raise Error(f"{path}: two rows for {fields[0]}")
        rows[fields[0]] = dict(zip(columns, fields))
    return rows


def language_notes(row):
    """The notes on a project that we seeded from its row of tools/seeds/languages.tsv."""
    language = LANGUAGE_NAMES.get(row["language"], row["language"])
    notes = [f"the release built it in its {language} build, which it did not publish"]
    if row["oss_fuzz"] != row["project"]:
        notes.append(f"one of the repositories of OSS-Fuzz's project {row['oss_fuzz']}, each a project here")
    if row["held"] != "-":
        notes.append(f"the release held back these builds: {row['held']}")
    return "; ".join(notes)


def table(seeds=SEEDS):
    """The text of docs/seeded-projects.tsv, from the files in `seeds`."""
    release = read_rows(seeds / "oss-fuzz-projects.tsv", RELEASE_COLUMNS)
    languages = read_rows(seeds / "languages.tsv", LANGUAGE_COLUMNS)
    builds = read_rows(seeds / "builds.tsv", BUILD_COLUMNS)
    unknown = sorted(set(builds) - set(release) - set(languages))
    if unknown:
        raise Error(f"tools/seeds/builds.tsv has rows for projects that neither oss-fuzz-projects.tsv nor "
                    f"languages.tsv names: {', '.join(unknown)}")
    # An OSS-Fuzz project whose fuzz targets are in more than one repository: the projects we seeded, one for each.
    split = {}
    for row in languages.values():
        if row["oss_fuzz"] not in release:
            raise Error(f"tools/seeds/languages.tsv seeds {row['project']} from OSS-Fuzz's project {row['oss_fuzz']}, "
                        "which tools/seeds/oss-fuzz-projects.tsv does not name")
        if row["oss_fuzz"] != row["project"]:
            split.setdefault(row["oss_fuzz"], []).append(row["project"])
    lines = [HEADER, "\t".join(COLUMNS)]
    for name in sorted(set(release) | set(languages)):
        notes = release[name]["reason or notes"] if name in release else "-"
        if (name in languages or name in split) and notes != "-":
            raise Error(f"tools/seeds/oss-fuzz-projects.tsv has notes on {name}, whose notes come from "
                        "tools/seeds/languages.tsv: give -")
        if name in split and name in builds:
            raise Error(f"tools/seeds/builds.tsv has a row for {name}, which we seeded as "
                        f"{', '.join(sorted(split[name]))}: one project for each of its repositories")
        if name in split and name not in languages:
            lines.append(f"{name}\tno\t-\t-\tseeded as {', '.join(sorted(split[name]))}: one project for each of its "
                         "repositories")
        elif name in builds:
            notes = language_notes(languages[name]) if name in languages else notes
            lines.append("\t".join((name, "yes", builds[name]["result"], builds[name]["detail"], notes)))
        elif name in languages:
            raise Error(f"tools/seeds/languages.tsv seeds {name}, but tools/seeds/builds.tsv has no row for it")
        elif notes == "-":
            raise Error(f"tools/seeds/oss-fuzz-projects.tsv gives no reason why {name} is not seeded")
        else:
            lines.append(f"{name}\tno\t-\t-\t{notes}")
    return "\n".join(lines) + "\n"


def main():
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    try:
        text = table()
    except (Error, OSError, UnicodeDecodeError) as error:
        sys.exit(f"tools/seeds/seeded_projects.py: {error}")
    TABLE.write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
