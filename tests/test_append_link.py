# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""infra/base-builder/link-fuzz-target's append mode, and its rule that a link with no base layout is a normal link,
which runs the commands that the script ran at commit 889360251058, argument for argument (normal_links):
uv run pytest tests/test_append_link.py

No linker runs here. The script runs as tests/test_allocation_library_links.py runs it: a copy, with /tmp/ov/ replaced
by a scratch directory. The compiler is a stand-in that logs each command and writes the output and the map it is
asked for; for the tests of links that make the same bytes at the same time, it can also wait, fail, or run a second
link (COMPILER). Beside the copy, layout.py is a stand-in that logs its command and writes what layout.py append
writes, and llvm-objcopy one that logs the file it is given. The script removes the directories it makes in /tmp/ov/
when it ends: a test takes their names from those logs (gone).

It also tests the settings that the build of one fuzz target can give its link, against the same commands:
OV_MAX_INPUT_LOG2, the driver's input limit, and OV_LIBC, the C library that the build declares."""
import hashlib
import json
import os
import pathlib
import re
import shutil
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
"""A stand-in for the compiler: it logs its command, writes OUTPUT to its -o file and MAP to its -Wl,-Map= file.

A compile is of one of three kinds: quiet, the quiet twin (a driver object named *-quiet.o); twin, the stripped twin
(-Wl,--strip-all); output, any other. Three settings change what a compile does:
  FAKE_CC_FAIL   the compile of this kind writes nothing and exits with 1.
  FAKE_CC_SLEEP  each compile waits this number of seconds after it has written its files.
  FAKE_CC_NEST   {"at": <kind>, "argv": <command>, "env": <variables>, "result": <file>}: after it has written its
                 files, the compile of the kind at runs a whole second link, argv, in the same directory, with the
                 environment of this compile, with no FAKE_CC_NEST, and with env. It writes the exit status and the
                 standard error of that link to result."""
import json
import os
import subprocess
import sys
import time

with open(os.environ["FAKE_CC_LOG"], "a") as log:
    log.write(json.dumps(sys.argv) + "\n")
words = sys.argv[1:]
if any(word.endswith("-quiet.o") for word in words):
    kind = "quiet"
elif "-Wl,--strip-all" in words:
    kind = "twin"
else:
    kind = "output"
if os.environ.get("FAKE_CC_FAIL") == kind:
    sys.exit(1)
for k, word in enumerate(words):
    if word == "-o":
        with open(words[k + 1], "wb") as out:
            out.write(@OUTPUT@)
    elif word.startswith("-Wl,-Map="):
        with open(word[len("-Wl,-Map="):], "w") as out:
            out.write(@MAP@)
if os.environ.get("FAKE_CC_SLEEP"):
    time.sleep(float(os.environ["FAKE_CC_SLEEP"]))
nest = json.loads(os.environ.get("FAKE_CC_NEST") or "null")
if nest and nest["at"] == kind:
    env = {name: value for name, value in os.environ.items() if name != "FAKE_CC_NEST"}
    env.update(nest["env"])
    done = subprocess.run(nest["argv"], env=env, capture_output=True, text=True, timeout=30)
    with open(nest["result"], "w") as result:
        json.dump({"returncode": done.returncode, "stderr": done.stderr}, result)
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

OBJCOPY = r'''#!/bin/sh
# A stand-in for llvm-objcopy: it logs the file it is given, its last argument, and leaves the file as it is.
for file; do :; done
printf '%s\n' "$file" >> "$FAKE_OBJCOPY_LOG"
'''

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
    objcopy.write_text(OBJCOPY)
    objcopy.chmod(0o755)
    for name in ("fuzzer.o", "cli.o", "adapter.o", "af.o", "count.o", "wrap_getenv.o", "wrap_getpid.o",
                 "cli-quiet.o", "adapter-quiet.o", "af-quiet.o", "count-quiet.o"):
        (build / name).write_bytes(b"\x7fELF " + name.encode() + b"\n")
    (build / "libfixture.a").write_bytes(b"!<arch>\nlibfixture\n")
    cc_log, layout_log, objcopy_log = tmp_path / "cc.jsonl", tmp_path / "layout.jsonl", tmp_path / "objcopy.log"

    def environment(records=False, layout=False, base_layout=None, script_kind="pins", status=0, extra=None):
        """Writes link.env, and returns the environment of the script, for the asan build; `base_layout` None leaves
        OV_BASE_LAYOUT unset. `extra` holds more environment variables for the script."""
        (ov / "link.env").write_text(
            "OV_LFE='normal-engine'\nOV_DRIVER='cli.o adapter.o'\nOV_CLI='cli.o'\n"
            f"OV_SILENT_LD='{SILENT}'\nOV_SEALS='{' '.join(SEALS)}'\nOV_TWINS='{twins}'\n"
            "OV_AFE='failure-engine'\nOV_AF_DRIVER='cli.o af.o'\n"
            "OV_AFC='counting-engine'\nOV_AFC_DRIVER='cli.o count.o'\n"
            f"OV_RECORDS='{records if records else ''}'\n"
            "OV_AF_RENAME='--redefine-sym malloc=__ov_malloc'\nOV_BUILD='asan'\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("OV_")}
        env.update(PATH=f"{tools}:{os.environ['PATH']}", FAKE_CC_LOG=str(cc_log), FAKE_LAYOUT_LOG=str(layout_log),
                   FAKE_OBJCOPY_LOG=str(objcopy_log), STUB_SCRIPT=script_kind, STUB_STATUS=str(status))
        if layout:
            env["OV_LAYOUT"] = "1"
        if base_layout is not None:
            env["OV_BASE_LAYOUT"] = str(base_layout)
        env.update(extra or {})
        return env

    def command(engine="normal-engine"):
        """link-fuzz-target <cc> fuzzer.o <engine> -pthread -o target libfixture.a."""
        return [str(script), str(cc), "fuzzer.o", engine, "-pthread", "-o", "target", "libfixture.a"]

    def run(engine="normal-engine", records=False, layout=False, base_layout=None, script_kind="pins", status=0,
            extra=None):
        """The command, in build/, in the environment (above)."""
        env = environment(records, layout, base_layout, script_kind, status, extra)
        return subprocess.run(command(engine), cwd=build, env=env, capture_output=True, text=True, timeout=30)

    # The directory that a link makes for its stripped twin in OV_TWINS, or for its record in OV_RECORDS.
    own = re.compile(rf"^({re.escape(str(twins))}|{re.escape(str(records))})/\.link\.[0-9A-Za-z]{{6}}/")

    def compiles():
        """Each command the compiler got, with the process id in the map's name written $$, and the random part of the
        name of a link's own directory in OV_TWINS or OV_RECORDS (own) written XXXXXX."""
        if not cc_log.exists():
            return []
        return [[own.sub(r"\1/.link.XXXXXX/", re.sub(r"^(-Wl,-Map=.*/map\.)[0-9]+$", r"\1$$", word))
                 for word in json.loads(line)]
                for line in cc_log.read_text().splitlines()]

    def layout_calls():
        if not layout_log.exists():
            return []
        return [json.loads(line) for line in layout_log.read_text().splitlines()]

    def gone(prefix):
        """The directory /tmp/ov/<prefix>.XXXXXX that the run made, as the tool it was made for got it: for "af", an
        allocation-failure link's copies, the files llvm-objcopy got; for "append", the append mode's, layout.py
        append's --work. Check first that link-fuzz-target removed it when it ended."""
        assert not list(ov.glob(f"{prefix}.*"))
        if prefix == "af":
            found = {pathlib.Path(copy).parent for copy in objcopy_log.read_text().splitlines()}
        else:
            found = {pathlib.Path(call["argv"][call["argv"].index("--work") + 1]) for call in layout_calls()
                     if call["argv"][0] == "append"}
        assert len(found) == 1, found
        directory = found.pop()
        assert directory.parent == ov and re.fullmatch(rf"{prefix}\.\w{{6}}", directory.name), directory
        return directory

    return SimpleNamespace(run=run, environment=environment, command=command, compiles=compiles,
                           layout_calls=layout_calls, gone=gone, cc=str(cc), ov=ov, twins=twins, records=records,
                           build=build, base=base, entry=base / "asan" / "target")


def inputs(t, engine):
    """The link's own arguments as link-fuzz-target passes them on: an allocation-failure link's copies in place of the
    object file and the archive."""
    if engine == "normal-engine":
        return ["fuzzer.o", "-pthread", "libfixture.a"]
    copies = t.gone("af")
    return [f"{copies}/0-fuzzer.o", "-pthread", f"{copies}/2-libfixture.a"]


def normal_links(t, engine, records):
    """The compiler's commands of a normal link for the link of `run`, argument for argument, as link-fuzz-target ran
    them at 889360251058: the output link, with OV_RECORDS the map argument last; the stripped twin into OV_TWINS; and
    with OV_RECORDS the quiet twin, with the quiet driver. Only the -o files of the two twins are not those of
    889360251058: each is in a directory of the link's own (compiles), from which the link renames it."""
    driver, quiet = DRIVERS[engine]
    own = inputs(t, engine)
    links = [
        [t.cc, "-static", "-no-pie", "-Wl,--gc-sections", "-o", "target", *driver, SILENT, *own, *SEALS]
        + ([f"-Wl,-Map={t.records}/map.$$"] if records else []),
        [t.cc, "-static", "-no-pie", "-Wl,--gc-sections", "-Wl,--strip-all", "-o", f"{t.twins}/.link.XXXXXX/{SUM}",
         *driver, SILENT, *own, *SEALS],
    ]
    if records:
        links.append([t.cc, "-static", "-no-pie", "-Wl,--gc-sections", "-Wl,--strip-all", "-o",
                      f"{t.records}/.link.XXXXXX/{SUM}/quiet", *quiet, SILENT, *own, *SEALS])
    return links


def link_command(t, engine):
    """The link's command that layout.py gets after --: the words link() gives the compiler, with no -o, no map and no
    script."""
    return [t.cc, "-static", "-no-pie", "-Wl,--gc-sections", *DRIVERS[engine][0], SILENT, *inputs(t, engine), *SEALS]


def with_script(t, links):
    """`links` (normal_links) with the append mode's script: after the seals and before the map argument on the output
    link, last on the stripped twin, and none on the quiet twin."""
    script = f"-Wl,-T,{t.gone('append')}/append.ld"
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
    record. Only a base layout with no entry adds its one line on standard error. An allocation-failure link's copies
    are gone once it has ended."""
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
        assert f"{t.base}/asan/target" in lines[0]
    else:
        assert done.stderr == ""
    assert (t.build / "target").read_bytes() == OUTPUT
    assert (t.twins / SUM).read_bytes() == OUTPUT
    if records:
        assert record_files(t) == sorted(NORMAL_RECORD + ([] if engine == "normal-engine" else ["renamed"]))
    else:
        assert not (t.records / SUM).exists()
    if engine != "normal-engine":
        t.gone("af")


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
    script. With OV_RECORDS and OV_LAYOUT=1, the record holds the placement and the wraps that append wrote. The append
    mode's directory is gone once the link has ended, with or without the record."""
    t.entry.mkdir()
    done = t.run(records=t.records if records else False, layout=records, base_layout=t.base)
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    work = t.gone("append")
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
    t.gone("append")


@pytest.mark.parametrize("status", [1, 2])
def test_a_failed_append_stops_the_link(t, status):
    """When layout.py append fails, the link fails with its exit status, before the compiler runs: no binary, no twin
    and no record are left as if it had linked, and the append mode's directory is gone."""
    t.entry.mkdir()
    done = t.run(records=t.records, layout=True, base_layout=t.base, status=status)
    assert done.returncode == status
    assert [call["argv"][0] for call in t.layout_calls()] == ["append"]
    assert t.compiles() == []
    assert not (t.build / "target").exists()
    assert list(t.twins.iterdir()) == []
    assert not (t.records / SUM).exists()
    t.gone("append")


@pytest.mark.parametrize("engine", ["failure-engine", "counting-engine"])
def test_an_allocation_failure_link_takes_the_append_mode(t, engine):
    """An allocation-failure or allocation-counting link with an entry and no OV_RECORDS takes the append mode: it
    writes renamed, which maps each copy to its original, and passes it to layout.py append. The copies and the append
    mode's directory are gone once the link has ended."""
    t.entry.mkdir()
    done = t.run(engine, base_layout=t.base)
    assert done.returncode == 0, done.stderr
    copies, work = t.gone("af"), t.gone("append")

    def line(index, name):
        original = t.build / name
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        return f"{copies}/{index}-{name}\t{os.path.realpath(original)}\t{digest}\n"

    renamed = line(0, "fuzzer.o") + line(2, "libfixture.a")
    assert t.layout_calls() == [{
        "argv": ["append", "--base", str(t.entry), "--work", str(work), "--renamed", f"{copies}/renamed",
                 "--script", f"{work}/append.ld", "--placement", f"{work}/placement.tsv", "--wraps", f"{work}/wraps",
                 "--", *link_command(t, engine)],
        "cwd": os.path.realpath(t.build), "renamed": renamed}]
    assert t.compiles() == with_script(t, normal_links(t, engine, False))


# The input limit that the tests below set (OV_MAX_INPUT_LOG2).
LIMIT = 29


def limit_objects(t):
    """Stand-ins for the driver objects that compile makes for LIMIT, in the relocated /tmp/ov. Returns the map from
    each default driver object to the object that takes its place."""
    swap = {}
    for default, name in (("cli.o", f"cli-limit{LIMIT}.o"), ("cli-quiet.o", f"cli-limit{LIMIT}-quiet.o")):
        (t.ov / name).write_bytes(b"\x7fELF " + name.encode() + b"\n")
        swap[default] = f"{t.ov}/{name}"
    return swap


def swapped(swap, words):
    """`words` with each word that `swap` holds replaced by its value."""
    return [swap.get(word, word) for word in words]


@pytest.mark.parametrize("form", ["normal-engine", "failure-engine", "counting-engine", "own-adapter"])
@pytest.mark.parametrize("records", [False, True], ids=["no-records", "records"])
def test_the_input_limit_takes_its_driver_in_each_driver_form(t, form, records):
    """With OV_MAX_INPUT_LOG2=29, each form of the driver (each engine, and a recipe's own adapter in OV_ADAPTER) links
    cli-limit29.o in place of cli.o, in the output and in the stripped twin. The quiet twin links cli-limit29-quiet.o
    in place of cli-quiet.o. Every other argument is the normal link's. The record's driver file names cli-limit29.o.
    An allocation-failure link still makes its renamed copies and links them (inputs)."""
    engine = "normal-engine" if form == "own-adapter" else form
    swap = limit_objects(t)
    extra = {"OV_MAX_INPUT_LOG2": str(LIMIT)}
    if form == "own-adapter":
        for name in ("own-adapter.o", "own-adapter-quiet.o"):
            (t.build / name).write_bytes(b"\x7fELF " + name.encode() + b"\n")
        extra.update(OV_ADAPTER="own-adapter.o", OV_ADAPTER_QUIET="own-adapter-quiet.o")
        swap.update({"adapter.o": "own-adapter.o", "adapter-quiet.o": "own-adapter-quiet.o"})
    done = t.run(engine, records=t.records if records else False, extra=extra)
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    assert t.compiles() == [swapped(swap, link) for link in normal_links(t, engine, records)]
    assert (t.build / "target").read_bytes() == OUTPUT
    assert (t.twins / SUM).read_bytes() == OUTPUT
    if records:
        assert record_files(t) == sorted(NORMAL_RECORD + ([] if engine == "normal-engine" else ["renamed"]))
        driver = swapped(swap, DRIVERS[engine][0]) + [word for word in SEALS if word.endswith(".o")]
        assert (t.records / SUM / "driver").read_text().splitlines() == driver
    else:
        assert not (t.records / SUM).exists()


def test_the_input_limit_reaches_the_append_mode(t):
    """With an entry and OV_MAX_INPUT_LOG2=29, the link's command that layout.py append gets (its probe link) and the
    two links with the script name cli-limit29.o in place of cli.o. The quiet twin names cli-limit29-quiet.o."""
    swap = limit_objects(t)
    t.entry.mkdir()
    done = t.run(records=t.records, layout=True, base_layout=t.base, extra={"OV_MAX_INPUT_LOG2": str(LIMIT)})
    assert done.returncode == 0, done.stderr
    assert [call["argv"][call["argv"].index("--") + 1:] for call in t.layout_calls()] == [
        swapped(swap, link_command(t, "normal-engine"))]
    assert t.compiles() == [swapped(swap, link) for link in with_script(t, normal_links(t, "normal-engine", True))]


@pytest.mark.parametrize("value", ["26", "32", "29x", "-1", "", "30"],
                         ids=["26", "32", "29x", "-1", "empty", "30-without-its-object"])
def test_a_bad_input_limit_stops_the_link(t, value):
    """OV_MAX_INPUT_LOG2 set to a value other than 27 to 31 (the empty value too), or set to 30 with no cli-limit30.o,
    stops the link with exit status 1 and a message that names the variable, before any compiler command."""
    limit_objects(t)
    done = t.run(extra={"OV_MAX_INPUT_LOG2": value})
    assert done.returncode == 1
    assert "OV_MAX_INPUT_LOG2" in done.stderr
    if value == "30":
        assert f"{t.ov}/cli-limit30.o" in done.stderr
    assert t.compiles() == []
    assert not (t.build / "target").exists()
    assert list(t.twins.iterdir()) == []


# The files of a C library that a build declares (OV_LIBC), in the order of the record's libc file.
LIBC_FILES = ("libc.a", "crt1.o", "crti.o", "crtn.o")


def libc_files(t, leave_out=None, under="musl"):
    """Stand-ins for a C library that a build made, in <under>/lib/ beside build/: libc.a, an archive, and the start
    files crt1.o, crti.o and crtn.o, each an ELF file. The file `leave_out` is not made. Returns the directory."""
    directory = t.build.parent / under / "lib"
    directory.mkdir(parents=True, exist_ok=True)
    for name in LIBC_FILES:
        if name != leave_out:
            start = b"!<arch>\n" if name == "libc.a" else b"\x7fELF "
            (directory / name).write_bytes(start + name.encode() + b"\n")
    return directory


def libc_rows(directory):
    """The rows that the record's libc file holds for the files in `directory`: <name> <real path> <sha256>."""
    return "".join(f"{name}\t{os.path.realpath(directory / name)}\t"
                   f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}\n" for name in LIBC_FILES)


def libc_directory(t):
    """The one directory that the compiler got in -B<directory>/: libc-<16 hex digits> in the relocated /tmp/ov."""
    found = {word[2:-1] for link in t.compiles() for word in link if word.startswith("-B")}
    assert len(found) == 1, found
    directory = pathlib.Path(found.pop())
    assert directory.parent == t.ov and re.fullmatch(r"libc-[0-9a-f]{16}", directory.name), directory
    return directory


def with_libc(directory, links):
    """`links` (normal_links) with -B<directory>/ and -L<directory> after the link's own options (-o <file> is the last
    of them) and before the driver."""
    words = [f"-B{directory}/", f"-L{directory}"]
    return [link[:link.index("-o") + 2] + words + link[link.index("-o") + 2:] for link in links]


@pytest.mark.parametrize("engine", ["normal-engine", "failure-engine", "counting-engine"])
@pytest.mark.parametrize("records", [False, True], ids=["no-records", "records"])
def test_a_declared_libc_reaches_each_link(t, engine, records):
    """With OV_LIBC, each link gets -B<directory>/ and -L<directory> after its own options and before the driver: the
    output, the stripped twin and the quiet twin. Every other argument is the normal link's. The directory is in
    /tmp/ov and holds a symbolic link to each of the four declared files, and no temporary directory is left. The
    record holds the libc file beside the normal record's files. An allocation-failure link copies its own objects
    and archives only: its renamed file names no libc.a."""
    lib = libc_files(t)
    done = t.run(engine, records=t.records if records else False, extra={"OV_LIBC": str(lib / "libc.a")})
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    directory = libc_directory(t)
    assert t.compiles() == with_libc(directory, normal_links(t, engine, records))
    assert sorted(p.name for p in directory.iterdir()) == sorted(LIBC_FILES)
    for name in LIBC_FILES:
        assert (directory / name).is_symlink(), name
        assert os.path.realpath(directory / name) == os.path.realpath(lib / name), name
    assert [p.name for p in t.ov.glob("libc*")] == [directory.name]
    assert (t.build / "target").read_bytes() == OUTPUT
    assert (t.twins / SUM).read_bytes() == OUTPUT
    if records:
        assert record_files(t) == sorted(NORMAL_RECORD + ["libc"] + ([] if engine == "normal-engine" else ["renamed"]))
        assert (t.records / SUM / "libc").read_text() == libc_rows(lib)
        if engine != "normal-engine":
            originals = [pathlib.Path(row.split("\t")[1]).name
                         for row in (t.records / SUM / "renamed").read_text().splitlines()]
            assert originals == ["fuzzer.o", "libfixture.a"]
    else:
        assert not (t.records / SUM).exists()


def test_the_libc_directory_keeps_its_name(t):
    """A second link with the same OV_LIBC finds the directory and uses it: the same name, the same four links, and
    no directory inside it. A C library with other bytes gets another directory. The stand-in compiler makes the same
    bytes with it, so the record stays the one that the first link wrote
    (test_a_later_link_of_the_same_bytes_keeps_the_record)."""
    lib = libc_files(t)
    for _ in range(2):
        done = t.run(records=t.records, extra={"OV_LIBC": str(lib / "libc.a")})
        assert done.returncode == 0, done.stderr
    directory = libc_directory(t)
    assert t.compiles() == with_libc(directory, normal_links(t, "normal-engine", True)) * 2
    assert sorted(p.name for p in directory.iterdir()) == sorted(LIBC_FILES)
    assert [p.name for p in t.ov.glob("libc*")] == [directory.name]
    rows = libc_rows(lib)
    (lib / "crt1.o").write_bytes(b"\x7fELF another crt1.o\n")
    done = t.run(records=t.records, extra={"OV_LIBC": str(lib / "libc.a")})
    assert done.returncode == 0, done.stderr
    assert len(list(t.ov.glob("libc-*"))) == 2
    assert (t.records / SUM / "libc").read_text() == rows


def test_a_declared_libc_reaches_the_append_mode(t):
    """With an entry and OV_LIBC, the link's command that layout.py append gets (its probe link) has -B<directory>/
    and -L<directory> after -Wl,--gc-sections, and so have the two links with the script and the quiet twin."""
    lib = libc_files(t)
    t.entry.mkdir()
    done = t.run(records=t.records, layout=True, base_layout=t.base, extra={"OV_LIBC": str(lib / "libc.a")})
    assert done.returncode == 0, done.stderr
    directory = libc_directory(t)
    probe = link_command(t, "normal-engine")
    assert [call["argv"][call["argv"].index("--") + 1:] for call in t.layout_calls()] == [
        probe[:4] + [f"-B{directory}/", f"-L{directory}"] + probe[4:]]
    assert t.compiles() == with_script(t, with_libc(directory, normal_links(t, "normal-engine", True)))


def test_a_declared_libc_and_the_input_limit_together(t):
    """OV_LIBC and OV_MAX_INPUT_LOG2 together: each link has both changes, and the record has both."""
    lib = libc_files(t)
    swap = limit_objects(t)
    done = t.run(records=t.records, extra={"OV_LIBC": str(lib / "libc.a"), "OV_MAX_INPUT_LOG2": str(LIMIT)})
    assert done.returncode == 0, done.stderr
    directory = libc_directory(t)
    links = with_libc(directory, normal_links(t, "normal-engine", True))
    assert t.compiles() == [swapped(swap, link) for link in links]
    assert (t.records / SUM / "libc").read_text() == libc_rows(lib)
    assert (t.records / SUM / "driver").read_text().splitlines()[0] == swap["cli.o"]


@pytest.mark.parametrize("case", ["relative", "not-libc.a", "empty", "missing", "not-an-archive", "short-archive",
                                  "no-crt1.o", "no-crti.o", "no-crtn.o", "crt1.o-not-elf"])
def test_a_bad_libc_declaration_stops_the_link(t, case):
    """OV_LIBC that is not the absolute path of a libc.a archive with ELF files crt1.o, crti.o and crtn.o beside it
    stops the link with exit status 1 and a message that names the variable, before any compiler command. The link
    makes no directory for it."""
    lib = libc_files(t, leave_out=case[len("no-"):] if case.startswith("no-") else None)
    value = str(lib / "libc.a")
    if case == "relative":
        value = os.path.relpath(lib / "libc.a", t.build)  # a file that is there, from the link's directory
    elif case == "not-libc.a":
        (lib / "libmusl.a").write_bytes((lib / "libc.a").read_bytes())
        value = str(lib / "libmusl.a")
    elif case == "empty":
        value = ""
    elif case == "missing":
        (lib / "libc.a").unlink()
    elif case == "not-an-archive":
        (lib / "libc.a").write_bytes(b"\x7fELF libc.a\n")
    elif case == "short-archive":
        (lib / "libc.a").write_bytes(b"!<arch>")
    elif case == "crt1.o-not-elf":
        (lib / "crt1.o").write_bytes(b"!<arch>\ncrt1.o\n")
    done = t.run(extra={"OV_LIBC": value})
    assert done.returncode == 1
    assert "OV_LIBC" in done.stderr
    assert t.compiles() == []
    assert not (t.build / "target").exists()
    assert list(t.twins.iterdir()) == []
    assert not list(t.ov.glob("libc*"))


# Links that make the same bytes, and so the same twin and record names, at the same time: build.sh can run two links
# of one output, or of two outputs with the same bytes, in parallel.


def left(directory):
    """The names in `directory`: each link removes its own directory (.link.XXXXXX) in OV_TWINS or OV_RECORDS, and its
    map, when it ends."""
    return sorted(p.name for p in directory.iterdir())


def complete_record(t, build=None):
    """Checks that the record of SUM is the whole record of a normal link in `build` (build/ by default): its map, its
    driver, inputs.tsv for the fuzzer.o of that directory, and the quiet twin."""
    record = t.records / SUM
    fuzzer = (build or t.build) / "fuzzer.o"
    body = fuzzer.read_bytes()
    assert (record / "map").read_text() == MAP.splitlines(keepends=True)[1]
    assert (record / "driver").read_text().splitlines() == (DRIVERS["normal-engine"][0]
                                                             + [word for word in SEALS if word.endswith(".o")])
    assert (record / "inputs.tsv").read_text() == (
        f"fuzzer.o\t{os.path.realpath(fuzzer)}\t{hashlib.sha256(body).hexdigest()}\t{len(body)}\n")
    assert (record / "quiet").read_bytes() == OUTPUT


def nested(t, at, fail=""):
    """The setting of the stand-in compiler (FAKE_CC_NEST) with which its compile `at` ("twin" or "quiet") runs a whole
    second link of the same output, in build/, after it has written its own output and before it returns: the second
    link makes the same bytes while the first one runs. In the second link, the compile `fail` fails. second(t) reads
    what the second link did."""
    return {"FAKE_CC_NEST": json.dumps({"at": at, "argv": t.command(), "env": {"FAKE_CC_FAIL": fail},
                                        "result": str(t.build.parent / "second.json")})}


def second(t):
    """The exit status and the standard error of the second link that nested started."""
    return json.loads((t.build.parent / "second.json").read_text())


@pytest.mark.parametrize("records", [False, True], ids=["no-records", "records"])
def test_a_link_of_the_same_bytes_during_the_stripped_twin(t, records):
    """A second link of the same bytes runs while the first one links its stripped twin, after the compiler has written
    the twin (nested). Each link links its twin in a directory of its own and renames it to OV_TWINS/<sum>, so that
    neither takes the file of the other. At 7f9f4902 both linked to OV_TWINS/<sum>.tmp: the second link moved the
    file, and then the mv of the first failed. Both links exit with 0 and run the normal link's commands. The twin is
    there, with OV_RECORDS the whole record too, and no directory of a link is left."""
    done = t.run(records=t.records if records else False, extra=nested(t, "twin"))
    assert done.returncode == 0, done.stderr
    assert second(t) == {"returncode": 0, "stderr": ""}
    assert done.stderr == ""
    links = normal_links(t, "normal-engine", records)
    assert t.compiles() == links[:2] + links + links[2:]
    assert (t.build / "target").read_bytes() == OUTPUT
    assert (t.twins / SUM).read_bytes() == OUTPUT
    assert left(t.twins) == [SUM]
    if records:
        assert record_files(t) == NORMAL_RECORD
        complete_record(t)
        assert left(t.records) == [SUM, "store"]
    else:
        assert left(t.records) == []


def test_a_failed_record_of_the_same_bytes_removes_no_other_record(t):
    """A second link of the same bytes runs while the first one links its quiet twin, after the compiler has written
    the quiet twin (nested), and the quiet link of the second link fails: the second link cannot write its record, and
    says so. Each link writes its record in a directory of its own and renames it to OV_RECORDS/<sum>, and a link
    whose record failed removes only its own directory and its own map. At 7f9f4902 both wrote in OV_RECORDS/<sum>/,
    and the second link removed it, with the files that the first link had written there. Both links exit with 0. The
    record of the first link is there, whole, and no directory of a link is left."""
    done = t.run(records=t.records, extra=nested(t, "quiet", fail="quiet"))
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    assert second(t) == {"returncode": 0, "stderr": "link-fuzz-target: warning: the record of the link of target "
                                                    "could not be written; its binary checks will say so\n"}
    assert (t.records / SUM).is_dir()
    assert record_files(t) == NORMAL_RECORD
    complete_record(t)
    links = normal_links(t, "normal-engine", True)
    assert t.compiles() == links + links
    assert (t.twins / SUM).read_bytes() == OUTPUT
    assert left(t.twins) == [SUM]
    assert left(t.records) == [SUM, "store"]


def test_a_later_link_of_the_same_bytes_keeps_the_record(t):
    """A second link that makes the same bytes, here with a C library at another path, finds the record that the first
    link wrote and keeps it: a link never removes a record that another link wrote. Both links exit with 0, one whole
    record is there, and no directory of a link is left."""
    first, other = libc_files(t), libc_files(t, under="other-musl")
    for lib in (first, other):
        done = t.run(records=t.records, extra={"OV_LIBC": str(lib / "libc.a")})
        assert done.returncode == 0, done.stderr
        assert done.stderr == ""
    assert record_files(t) == sorted(NORMAL_RECORD + ["libc"])
    assert (t.records / SUM / "libc").read_text() == libc_rows(first)
    complete_record(t)
    assert (t.twins / SUM).read_bytes() == OUTPUT
    assert left(t.twins) == [SUM]
    assert left(t.records) == [SUM, "store"]


# The number of links that test_links_of_the_same_bytes_at_the_same_time runs at the same time.
LINKS = 12


def test_links_of_the_same_bytes_at_the_same_time(t):
    """LINKS links that make the same bytes run at the same time, with OV_RECORDS. Each runs in a build directory of
    its own, whose fuzzer.o has other bytes, and with a C library of its own (OV_LIBC). The stand-in compiler waits 0.2
    seconds after each output, so that the links write their twins and their records at the same time. Each link exits
    with 0. The twin is there, and one whole record, whose inputs.tsv and libc come from one link. No directory of a
    link is left. At 7f9f4902 the mv of a twin failed, and the record was missing, or held the files of two links."""
    env = t.environment(records=t.records, extra={"FAKE_CC_SLEEP": "0.2"})
    builds = []
    for n in range(LINKS):
        build = t.build.parent / f"build{n}"
        shutil.copytree(t.build, build)
        (build / "fuzzer.o").write_bytes(b"\x7fELF fuzzer.o of link %d\n" % n)
        builds.append((build, libc_files(t, under=f"musl{n}")))
    processes = [subprocess.Popen(t.command(), cwd=build, env={**env, "OV_LIBC": str(lib / "libc.a")},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for build, lib in builds]
    ends = [(process.communicate(timeout=60)[1], process.returncode) for process in processes]
    assert [(build.name, stderr, status) for (build, _), (stderr, status) in zip(builds, ends)
            if (stderr, status) != ("", 0)] == []
    assert (t.twins / SUM).read_bytes() == OUTPUT
    assert left(t.twins) == [SUM]
    assert left(t.records) == [SUM, "store"]
    assert record_files(t) == sorted(NORMAL_RECORD + ["libc"])
    real = (t.records / SUM / "inputs.tsv").read_text().split("\t")[1]
    (build, lib), = [(build, lib) for build, lib in builds if os.path.realpath(build / "fuzzer.o") == real]
    complete_record(t, build)
    assert (t.records / SUM / "libc").read_text() == libc_rows(lib)
