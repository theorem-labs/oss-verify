# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""infra/base-builder/link-fuzz-target's append mode, and its rule that a link with no base layout is a normal link,
which runs the commands that the script ran at commit 889360251058, argument for argument (normal_links):
uv run pytest tests/test_append_link.py

No linker runs here. The script runs as tests/test_allocation_library_links.py runs it: a copy, with /tmp/ov/ replaced
by a scratch directory. The compiler is a stand-in that logs each command and writes the output and the map it is
asked for. Beside the copy, layout.py is a stand-in that logs its command and writes what layout.py append writes."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINKER = ROOT / "infra/base-builder/link-fuzz-target"

# What the stand-in compiler writes to each -o file, and so the sha256 that names the stripped twin and the record.
OUTPUT = b"\x7fELF linked\n"
SUM = hashlib.sha256(OUTPUT).hexdigest()
# The map it writes for -Wl,-Map=<file>: one input section, as lld writes the line.
MAP = (f"{'VMA':>16} {'LMA':>16} {'Size':>8} {'Align':>5} Out     In      Symbol\n"
       f"{0x11000:>16x} {0x11000:>16x} {0x20:>8x} {4:>5}         fuzzer.o:(.text.LLVMFuzzerTestOneInput)\n")
# What the stand-in layout.py writes.
SCRIPT = ("SECTIONS { .text 0x11000 : { . = 0x11000; \"fuzzer.o\"(.text.LLVMFuzzerTestOneInput) } }"
          " INSERT BEFORE .fini;\n")
PLACEMENT = ("fuzzer.o\t-\t.text.LLVMFuzzerTestOneInput\t0\tfuzzer.o\t-\t.text.LLVMFuzzerTestOneInput\t0\t"
             "kept\t0x11000\t-\t-\n")
WRAPS = "getenv\ngetpid\n"

COMPILER = r'''#!/usr/bin/env python3
"""A stand-in for the compiler: it logs its command, writes OUTPUT to its -o file and MAP to its -Wl,-Map= file."""
import json
import os
import sys

with open(os.environ["FAKE_CC_LOG"], "a") as log:
    log.write(json.dumps(sys.argv) + "\n")
words = sys.argv[1:]
for k, word in enumerate(words):
    if word == "-o":
        with open(words[k + 1], "wb") as out:
            out.write(@OUTPUT@)
    elif word.startswith("-Wl,-Map="):
        with open(word[len("-Wl,-Map="):], "w") as out:
            out.write(@MAP@)
'''.replace("@OUTPUT@", repr(OUTPUT)).replace("@MAP@", repr(MAP))

LAYOUT = r'''"""A stand-in for layout.py: it logs its command, its working directory and the renamed file that append is
given. For wraps it prints WRAPS. For append it writes the script ($STUB_SCRIPT: pins, empty, or absent for none),
placement.tsv and wraps where it is told to, and exits with $STUB_STATUS."""
import json
import os
import sys

argv = sys.argv[1:]
end = argv.index("--")
options = dict(zip(argv[1:end:2], argv[2:end:2]))
renamed = None
if "--renamed" in options:
    with open(options["--renamed"]) as f:
        renamed = f.read()
with open(os.environ["FAKE_LAYOUT_LOG"], "a") as log:
    log.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "renamed": renamed}) + "\n")
if argv[0] == "wraps":
    sys.stdout.write(@WRAPS@)
    sys.exit(0)
if os.environ["STUB_SCRIPT"] != "absent":
    with open(options["--script"], "w") as f:
        f.write(@SCRIPT@ if os.environ["STUB_SCRIPT"] == "pins" else "")
with open(options["--placement"], "w") as f:
    f.write(@PLACEMENT@)
with open(options["--wraps"], "w") as f:
    f.write(@WRAPS@)
sys.exit(int(os.environ["STUB_STATUS"]))
'''.replace("@WRAPS@", repr(WRAPS)).replace("@SCRIPT@", repr(SCRIPT)).replace("@PLACEMENT@", repr(PLACEMENT))

SILENT = "-Wl,--defsym=__sanitizer_silent_reports=1"
SEALS = ["wrap_getenv.o", "-Wl,--wrap=getenv", "wrap_getpid.o", "-Wl,--wrap=getpid"]
# The driver and the quiet driver of each engine.
DRIVERS = {
    "normal-engine": (["cli.o", "adapter.o"], ["cli-quiet.o", "adapter-quiet.o"]),
    "failure-engine": (["cli.o", "af.o"], ["cli-quiet.o", "af-quiet.o"]),
    "counting-engine": (["cli.o", "count.o"], ["cli-quiet.o", "count-quiet.o"]),
}
# The files of a record that a normal link writes for the link below.
NORMAL_RECORD = ["driver", "inputs.tsv", "map", "quiet"]


@pytest.fixture
def t(tmp_path):
    tools, ov, build, base = (tmp_path / name for name in ("tools", "ov", "build", "base"))
    twins, records = ov / "twins", ov / "records"
    for directory in (tools, build, twins, records):
        directory.mkdir(parents=True)
    # A base layout tree with an entry for another build of the target and one for another target of the build, and
    # none for this link (target, asan) until a test makes it.
    (base / "plain" / "target").mkdir(parents=True)
    (base / "asan" / "other").mkdir(parents=True)
    script = tools / "link-fuzz-target"
    script.write_text(LINKER.read_text().replace("/tmp/ov/", f"{ov}/"))
    script.chmod(0o755)
    (tools / "layout.py").write_text(LAYOUT)
    cc = tools / "cc"
    cc.write_text(COMPILER)
    cc.chmod(0o755)
    objcopy = tools / "llvm-objcopy"
    objcopy.write_text("#!/bin/sh\nexit 0\n")
    objcopy.chmod(0o755)
    for name in ("fuzzer.o", "cli.o", "adapter.o", "af.o", "count.o", "wrap_getenv.o", "wrap_getpid.o",
                 "cli-quiet.o", "adapter-quiet.o", "af-quiet.o", "count-quiet.o"):
        (build / name).write_bytes(b"\x7fELF " + name.encode() + b"\n")
    (build / "libfixture.a").write_bytes(b"!<arch>\nlibfixture\n")
    cc_log, layout_log = tmp_path / "cc.jsonl", tmp_path / "layout.jsonl"

    def run(engine="normal-engine", records=False, layout=False, base_layout=None, script_kind="pins", status=0):
        """link-fuzz-target <cc> fuzzer.o <engine> -pthread -o target libfixture.a, in build/, in the asan build;
        `base_layout` None leaves OV_BASE_LAYOUT unset."""
        (ov / "link.env").write_text(
            "OV_LFE='normal-engine'\nOV_DRIVER='cli.o adapter.o'\nOV_CLI='cli.o'\n"
            f"OV_SILENT_LD='{SILENT}'\nOV_SEALS='{' '.join(SEALS)}'\nOV_TWINS='{twins}'\n"
            "OV_AFE='failure-engine'\nOV_AF_DRIVER='cli.o af.o'\n"
            "OV_AFC='counting-engine'\nOV_AFC_DRIVER='cli.o count.o'\n"
            f"OV_RECORDS='{records if records else ''}'\n"
            "OV_AF_RENAME='--redefine-sym malloc=__ov_malloc'\nOV_BUILD='asan'\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("OV_")}
        env.update(PATH=f"{tools}:{os.environ['PATH']}", FAKE_CC_LOG=str(cc_log), FAKE_LAYOUT_LOG=str(layout_log),
                   STUB_SCRIPT=script_kind, STUB_STATUS=str(status))
        if layout:
            env["OV_LAYOUT"] = "1"
        if base_layout is not None:
            env["OV_BASE_LAYOUT"] = str(base_layout)
        return subprocess.run([str(script), str(cc), "fuzzer.o", engine, "-pthread", "-o", "target", "libfixture.a"],
                              cwd=build, env=env, capture_output=True, text=True, timeout=30)

    def compiles():
        """Each command the compiler got, with the process id in the map's name written $$."""
        if not cc_log.exists():
            return []
        return [[re.sub(r"^(-Wl,-Map=.*/map\.)[0-9]+$", r"\1$$", word) for word in json.loads(line)]
                for line in cc_log.read_text().splitlines()]

    def layout_calls():
        if not layout_log.exists():
            return []
        return [json.loads(line) for line in layout_log.read_text().splitlines()]

    def only(pattern):
        found = sorted(ov.glob(pattern))
        assert len(found) == 1, found
        return found[0]

    return SimpleNamespace(run=run, compiles=compiles, layout_calls=layout_calls, only=only, cc=str(cc), ov=ov,
                           twins=twins, records=records, build=build, base=base, entry=base / "asan" / "target")


def inputs(t, engine):
    """The link's own arguments as link-fuzz-target passes them on: an allocation-failure link's copies in place of the
    object file and the archive."""
    if engine == "normal-engine":
        return ["fuzzer.o", "-pthread", "libfixture.a"]
    copies = t.only("af.*")
    return [f"{copies}/0-fuzzer.o", "-pthread", f"{copies}/2-libfixture.a"]


def normal_links(t, engine, records):
    """The compiler's commands of a normal link for the link of `run`, argument for argument, as link-fuzz-target ran
    them at 889360251058: the output link, with OV_RECORDS the map argument last; the stripped twin into OV_TWINS; and
    with OV_RECORDS the quiet twin, with the quiet driver."""
    driver, quiet = DRIVERS[engine]
    own = inputs(t, engine)
    links = [
        [t.cc, "-static", "-no-pie", "-Wl,--gc-sections", "-o", "target", *driver, SILENT, *own, *SEALS]
        + ([f"-Wl,-Map={t.records}/map.$$"] if records else []),
        [t.cc, "-static", "-no-pie", "-Wl,--gc-sections", "-Wl,--strip-all", "-o", f"{t.twins}/{SUM}.tmp", *driver,
         SILENT, *own, *SEALS],
    ]
    if records:
        links.append([t.cc, "-static", "-no-pie", "-Wl,--gc-sections", "-Wl,--strip-all", "-o",
                      f"{t.records}/{SUM}/quiet", *quiet, SILENT, *own, *SEALS])
    return links


def link_command(t, engine):
    """The link's command that layout.py gets after --: the words link() gives the compiler, with no -o, no map and no
    script."""
    return [t.cc, "-static", "-no-pie", "-Wl,--gc-sections", *DRIVERS[engine][0], SILENT, *inputs(t, engine), *SEALS]


def with_script(t, links):
    """`links` (normal_links) with the append mode's script: after the seals and before the map argument on the output
    link, last on the stripped twin, and none on the quiet twin."""
    script = f"-Wl,-T,{t.only('append.*')}/append.ld"
    first = links[0][:-1] + [script, links[0][-1]] if links[0][-1].startswith("-Wl,-Map=") else links[0] + [script]
    return [first, links[1] + [script], *links[2:]]


def record_files(t):
    return sorted(p.name for p in (t.records / SUM).iterdir())


@pytest.mark.parametrize("engine", ["normal-engine", "failure-engine"])
@pytest.mark.parametrize("records", [False, True], ids=["no-records", "records"])
@pytest.mark.parametrize("base", ["unset", "empty", "no-entry"])
def test_no_base_layout_runs_the_normal_link_commands(t, base, records, engine):
    """With no base layout, or one with no entry for this link, the compiler's commands are the normal link's,
    argument for argument; with OV_RECORDS alone (the --checks path) too, with no layout.py call and no wraps in the
    record. Only a base layout with no entry adds its one line on standard error."""
    done = t.run(engine, records=t.records if records else False,
                 base_layout={"unset": None, "empty": "", "no-entry": t.base}[base])
    assert done.returncode == 0, done.stderr
    assert t.compiles() == normal_links(t, engine, records)
    assert t.layout_calls() == []
    assert not list(t.ov.glob("append.*"))
    if base == "no-entry":
        lines = done.stderr.splitlines()
        assert len(lines) == 1, done.stderr
        assert lines[0].startswith("link-fuzz-target: target (asan): ")
        assert f"{t.base}/asan/target" in lines[0] and "normal" in lines[0]
    else:
        assert done.stderr == ""
    assert (t.build / "target").read_bytes() == OUTPUT
    assert (t.twins / SUM).read_bytes() == OUTPUT
    if records:
        assert record_files(t) == sorted(NORMAL_RECORD + ([] if engine == "normal-engine" else ["renamed"]))
    else:
        assert not (t.records / SUM).exists()
        if engine != "normal-engine":
            assert not (t.only("af.*") / "renamed").exists()


@pytest.mark.parametrize("base", ["unset", "no-entry"])
def test_layout_without_an_entry_records_the_wraps(t, base):
    """OV_LAYOUT=1 with no entry: the links are normal ones, and the record holds the wraps that layout.py wraps prints
    for the link's command."""
    done = t.run(records=t.records, layout=True, base_layout=None if base == "unset" else t.base)
    assert done.returncode == 0, done.stderr
    assert t.compiles() == normal_links(t, "normal-engine", True)
    assert t.layout_calls() == [{"argv": ["wraps", "--", *link_command(t, "normal-engine")],
                                 "cwd": os.path.realpath(t.build), "renamed": None}]
    assert record_files(t) == sorted(NORMAL_RECORD + ["wraps"])
    assert (t.records / SUM / "wraps").read_text() == WRAPS


@pytest.mark.parametrize("records", [False, True], ids=["no-records", "records"])
def test_an_entry_takes_the_append_mode(t, records):
    """With an entry: layout.py append once, in the link's working directory, with the link's command; then the output
    link and its stripped twin with the script after the seals and before the map argument, and the quiet twin with no
    script. With OV_RECORDS and OV_LAYOUT=1, the record holds the placement and the wraps that append wrote."""
    t.entry.mkdir()
    done = t.run(records=t.records if records else False, layout=records, base_layout=t.base)
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    work = t.only("append.*")
    assert t.layout_calls() == [{
        "argv": ["append", "--base", str(t.entry), "--work", str(work), "--script", f"{work}/append.ld",
                 "--placement", f"{work}/placement.tsv", "--wraps", f"{work}/wraps", "--",
                 *link_command(t, "normal-engine")],
        "cwd": os.path.realpath(t.build), "renamed": None}]
    links = with_script(t, normal_links(t, "normal-engine", records))
    assert t.compiles() == links
    if records:
        assert links[0][-2:] == [f"-Wl,-T,{work}/append.ld", f"-Wl,-Map={t.records}/map.$$"]
        assert not any(word.startswith("-Wl,-T,") for word in links[2])
        assert record_files(t) == sorted(NORMAL_RECORD + ["placement.tsv", "wraps"])
        assert (t.records / SUM / "placement.tsv").read_text() == PLACEMENT
        assert (t.records / SUM / "wraps").read_text() == WRAPS
    else:
        assert not (t.records / SUM).exists()
    assert (t.twins / SUM).read_bytes() == OUTPUT


@pytest.mark.parametrize("script_kind", ["empty", "absent"])
def test_readonly_growth_links_with_no_script(t, script_kind):
    """When layout.py append writes an empty script, or none (the read-only data grew past its room, and it linked
    normally), the two links have no script: they are the normal link's. The record still holds the placement."""
    t.entry.mkdir()
    done = t.run(records=t.records, layout=True, base_layout=t.base, script_kind=script_kind)
    assert done.returncode == 0, done.stderr
    assert [call["argv"][0] for call in t.layout_calls()] == ["append"]
    assert t.compiles() == normal_links(t, "normal-engine", True)
    assert record_files(t) == sorted(NORMAL_RECORD + ["placement.tsv", "wraps"])


@pytest.mark.parametrize("status", [1, 2])
def test_a_failed_append_stops_the_link(t, status):
    """When layout.py append fails, the link fails with its exit status, before the compiler runs: no binary, no twin
    and no record are left as if it had linked."""
    t.entry.mkdir()
    done = t.run(records=t.records, layout=True, base_layout=t.base, status=status)
    assert done.returncode == status
    assert [call["argv"][0] for call in t.layout_calls()] == ["append"]
    assert t.compiles() == []
    assert not (t.build / "target").exists()
    assert list(t.twins.iterdir()) == []
    assert not (t.records / SUM).exists()


@pytest.mark.parametrize("engine", ["failure-engine", "counting-engine"])
def test_an_allocation_failure_link_takes_the_append_mode(t, engine):
    """An allocation-failure or allocation-counting link with an entry and no OV_RECORDS takes the append mode: it
    writes renamed, which maps each copy to its original, and passes it to layout.py append."""
    t.entry.mkdir()
    done = t.run(engine, base_layout=t.base)
    assert done.returncode == 0, done.stderr
    copies, work = t.only("af.*"), t.only("append.*")

    def line(index, name):
        original = t.build / name
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        return f"{copies}/{index}-{name}\t{os.path.realpath(original)}\t{digest}\n"

    renamed = line(0, "fuzzer.o") + line(2, "libfixture.a")
    assert (copies / "renamed").read_text() == renamed
    assert t.layout_calls() == [{
        "argv": ["append", "--base", str(t.entry), "--work", str(work), "--renamed", f"{copies}/renamed",
                 "--script", f"{work}/append.ld", "--placement", f"{work}/placement.tsv", "--wraps", f"{work}/wraps",
                 "--", *link_command(t, engine)],
        "cwd": os.path.realpath(t.build), "renamed": renamed}]
    assert t.compiles() == with_script(t, normal_links(t, engine, False))
