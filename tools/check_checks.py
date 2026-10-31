#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The step of `tools/check --checks`: what the checks of a project's fuzz targets catch, on its own seed inputs.

A property of a fuzz target is a check that calls abort() (step 3.2 of .claude/skills/add-project/SKILL.md), and a
proof says no more than its checks. This step measures what steps 3.3 and 3.4 of that skill ask for:

1. Reach. It builds the fuzz targets again with coverage (tools/checks/compile-check), runs each one on each input of
   its seed corpus, and lists each check whose guard (the `if`, `while`, `for` or `switch` that decides whether its
   abort() runs) no seed input reaches. tools/check_records.py reads the checks and their comments.
2. Breakage. Each breakage is a change to the code that should make a check fire: a `mutant:` record in the check's
   comment, with the seed `input:` that must catch it, or a patch in the directory that project.yaml's `mutants`
   names. For each one, it builds the coverage build again with the change, runs the inputs (a record's own input, or
   every seed for a patch), and, if no run failed, builds and runs the project's most checking sanitizer build too. A
   run fails with an exit status other than 0 and 2. A record is met when a run of its input fails, and that input
   passes on the unchanged code. The coverage build also says which checks fired. The breakages build in parallel,
   until a time budget runs out; the rest are listed as not checked.

docs/build-contract.md, "The checks of a fuzz target", says what it measures and what it does not. It works for C and
C++ fuzz targets. It runs the riscv64 binaries with qemu-riscv64-static, inside a container of the project image with
no network. The coverage build needs compiler-rt's source for the toolchain's LLVM version, which it downloads once
and checks.
"""
import bisect
import concurrent.futures
import dataclasses
import difflib
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import time
import urllib.request
import zipfile

import check_build
import check_records
from check_build import Failed, step

TOOLS = pathlib.Path(__file__).resolve().parent
CHECKS_DIR = TOOLS / "checks"
# compiler-rt's source for each LLVM version a toolchain image has: the URL and its SHA-256. The profile runtime must
# be of the same version as the compiler, which writes the profile's format.
COMPILER_RT = {
    "20.1.8": ("https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.8/compiler-rt-20.1.8.src.tar.xz",
               "15277402f6fd63397c0917a5c7171cda82d16d226094b828c1ed0f58f73b9c69"),
}
# The longest a run of a fuzz target on one input may take, in seconds.
RUN_TIMEOUT = 120
# The exit statuses of a run that passes (docs/build-contract.md, "Exit statuses").
PASSES = (0, 2)
# The status of a run that tools/checks/run-seeds stopped at the time limit (SIGKILL). It is neither a pass nor a catch.
KILLED = 137
# The status this step gives an input that did not run before a total time limit stopped the runs.
NOT_RUN = -1
# The driver's header in front of each seed input: no config bytes and no allocation mask (docs/build-contract.md).
HEADER = b"\0" * 6
# The sanitizer builds, the most checking first: a breakage is also run on the first one the project has.
SANITIZER_BUILDS = (("asan-ubsan", "address-undefined"), ("asan", "address"), ("msan", "memory"),
                    ("ubsan", "undefined"))
# The time the breakages may take together, in minutes, by default.
BUDGET_MINUTES = 60
# The most time each run of all the seed inputs on the unchanged code may take, in minutes.
BASELINE_MINUTES = 20
MAX_PATCH_BYTES = 256 * 1024
MAX_PATCHES = 200
MAX_LISTED = 60
LANGUAGES = ("c", "c++")
STATUS_NAMES = {134: "abort()", 132: "a UBSan trap", 139: "a segmentation fault", 77: "exit()",
                78: "a return value other than 0 or -1"}


@dataclasses.dataclass
class Run:
    """The result of running one fuzz target on one seed input: its exit status, or None if it took too long."""

    target: str
    seed: str
    status: int | None
    build: str  # "coverage", or the sanitizer build's name
    index: int = 0  # the input's position in its zip file: two inputs can have one name

    def key(self):
        return (self.build, self.target, self.index)

    def passed(self):
        return self.status in PASSES

    def caught(self):
        return self.status is not None and self.status != NOT_RUN and self.status not in PASSES


@dataclasses.dataclass
class Breakage:
    """One change to the code: a patch of the `mutants` directory, or the change of one or more `mutant:` records."""

    label: str
    patch: bytes | None
    records: list = dataclasses.field(default_factory=list)  # [(check, record)]; empty for a patch of the directory
    problem: str = ""  # why it could not be made, for a record
    # Set by evaluate():
    outcome: str = ""  # "measured", "does not build", "not checked"
    detail: str = ""
    runs: list = dataclasses.field(default_factory=list)
    fired: set = dataclasses.field(default_factory=set)  # (path, line, column) of the checks that fired
    builds: tuple = ()


# ── coverage ─────────────────────────────────────────────────────────────────────────────────────────────────────────

class Coverage:
    """The counts of llvm-cov's segments, by file, summed over the fuzz targets: how many times each region ran."""

    def __init__(self):
        self.segments = {}
        self._keys = {}

    def add(self, export):
        """Add the counts of one `llvm-cov export -format=text` (a fuzz target's runs) to these."""
        self._keys.clear()
        for data in export.get("data", []):
            for entry in data.get("files", []):
                mine = self.segments.setdefault(entry["filename"], {})
                for line, column, count, has_count, *_ in entry.get("segments", []):
                    if has_count:
                        mine[(line, column)] = (mine.get((line, column)) or 0) + count
                    else:
                        mine.setdefault((line, column), None)

    def count(self, path, line, column):
        """How many times the code at (line, column) of `path` ran, or None if no target's coverage maps it."""
        mine = self.segments.get(path)
        if not mine:
            return None
        if path not in self._keys:
            self._keys[path] = sorted(mine)
        keys = self._keys[path]
        at = bisect.bisect_right(keys, (line, column)) - 1
        return mine[keys[at]] if at >= 0 else None


def fuzz_target_files(export):
    """The source files that define LLVMFuzzerTestOneInput in one llvm-cov export."""
    return {name for data in export.get("data", []) for function in data.get("functions", [])
            if function.get("name") == "LLVMFuzzerTestOneInput" for name in function.get("filenames", [])[:1]}


def files_of(export):
    """The source files that one llvm-cov export maps."""
    return {entry["filename"] for data in export.get("data", []) for entry in data.get("files", [])}


def hunk_shifts(patch, workdir):
    """{path in the image: [(old line, +1 or -1)]}: each line that a unified diff adds (before that old line) or removes
    (that old line), so that a check's line in the unchanged file can be moved to its line in the changed one."""
    shifts, path, old, left = {}, None, None, 0
    for line in patch.decode("utf-8", "replace").split("\n"):
        if line.startswith("diff --git "):
            path, old = None, None
        elif (old is None or left <= 0) and line.startswith("+++ "):
            name = line[4:].strip().split("\t")[0]
            path = None if name == "/dev/null" else str(pathlib.PurePosixPath(workdir) / name.removeprefix("b/"))
            old = None
        elif path and (found := re.match(r"@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@", line)):
            old = int(found[1])
            left = int(found[2] or 1) + int(found[3] or 1)
        elif path and old is not None and left > 0 and line[:1] in ("-", "+", " "):
            left -= 1 if line[0] != " " else 2
            if line[0] == "-":
                shifts.setdefault(path, []).append((old, -1))
                old += 1
            elif line[0] == "+":
                shifts.setdefault(path, []).append((old, +1))
            else:
                old += 1
    return shifts


def moved(check, shifts):
    """The line of `check` in the changed file."""
    return check.line + sum(d for at, d in shifts.get(check.path, []) if at < check.line or (d > 0 and at == check.line))


# ── running ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def qemu():
    """The path of a static qemu-riscv64, which runs inside the project image too, or raise Failed."""
    found = shutil.which("qemu-riscv64-static")
    if not found:
        raise Failed("--checks runs the riscv64 binaries with qemu-riscv64-static, which is not on PATH. The check "
                     "of system calls reads the runs of qemu 10.0.11 only: take qemu-user 1:10.0.11 out of Debian 13's "
                     "package without installing it (installing registers qemu with the kernel), with dpkg-deb -x "
                     "<the .deb> <directory> and ln -s qemu-riscv64 <directory>/usr/bin/qemu-riscv64-static, then put "
                     "<directory>/usr/bin on PATH (docs/build-contract.md, \"The checks of a fuzz target\")")
    return pathlib.Path(found).resolve()


def write_seeds(directory, targets, inputs):
    """Write each target's seed inputs, from projects/<name>/<target>_seed_corpus.zip, to inputs/<target>/<n>, each
    with the driver's header in front. Return {target: [the name of input n in its zip file]}; a target with no corpus
    has no entry."""
    shutil.rmtree(inputs, ignore_errors=True)
    names = {}
    for target in targets:
        corpus = directory / f"{target}_seed_corpus.zip"
        if not corpus.is_file():
            continue
        (inputs / target).mkdir(parents=True)
        names[target] = []
        with zipfile.ZipFile(corpus) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    (inputs / target / str(len(names[target]))).write_bytes(HEADER + archive.read(info))
                    names[target].append(info.filename)
    return names


def subset(inputs, names, wanted, directory):
    """A directory of inputs with only the (target, seed name) pairs of `wanted`, linked from `inputs`. Return its
    names, as write_seeds() does."""
    shutil.rmtree(directory, ignore_errors=True)
    chosen = {}
    for target, seed in sorted(wanted):
        if seed in names.get(target, []):
            n = names[target].index(seed)
            (directory / target).mkdir(parents=True, exist_ok=True)
            os.link(inputs / target / str(n), directory / target / str(n))
            chosen.setdefault(target, {})[n] = seed
    return chosen


def run_all(tag, binaries, inputs, names, build, results, *, labels, total=0):
    """Run each fuzz target in the directory `binaries` on each of its seed inputs, in a container of the project image
    with no network (tools/checks/run-seeds). `names` maps a target to its seed names, as a list (input n is the n-th)
    or a dict {n: name}. Keep each run's status and profile in `results`. With `total`, stop all runs after that many
    seconds: an input that did not run has no status, as one stopped at the time limit. Return [Run]."""
    check_build.empty_directory(results, tag, labels=labels)
    command = ["docker", "run", "--rm", "--init", "--network=none", *labels, "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}",
               "-v", f"{qemu()}:/ovc-qemu:ro", "-v", f"{CHECKS_DIR}:/ovc:ro", "-v", f"{binaries}:/bins:ro",
               "-v", f"{inputs}:/inputs:ro", "-v", f"{results}:/results", "--entrypoint", "/ovc/run-seeds", tag,
               str(os.cpu_count() or 2), str(RUN_TIMEOUT), str(max(0, int(total)))]
    if check_build.run(*command, quiet=True) != 0:
        raise Failed(f"could not run the fuzz targets of the {build} build on their seed inputs")
    runs = []
    for target in sorted(names):
        if not (binaries / target).is_file():
            continue
        numbered = names[target] if isinstance(names[target], dict) else dict(enumerate(names[target]))
        for n, seed in sorted(numbered.items()):
            status = results / target / f"{n}.status"
            if not status.is_file() or status.is_symlink():
                runs.append(Run(target, seed, NOT_RUN, build, n))
                continue
            text = status.read_text()[:16].strip()
            runs.append(Run(target, seed, int(text) if text.isdigit() and text != str(KILLED) else None, build, n))
    return runs


# ── the builds ───────────────────────────────────────────────────────────────────────────────────────────────────────

def llvm_version(tag, labels):
    """The version of the toolchain's clang, for example 20.1.8."""
    text = check_build.output("docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "clang", tag,
                              "--version")
    found = re.search(r"clang version (\d+\.\d+\.\d+)", text)
    if not found:
        raise Failed("cannot read the toolchain's clang version")
    return found.group(1)


def compiler_rt(version):
    """compiler-rt's source for this LLVM version, downloaded once into the cache and checked. Return its directory."""
    if version not in COMPILER_RT:
        raise Failed(f"--checks has no compiler-rt source for LLVM {version} (tools/check_checks.py, COMPILER_RT)")
    url, sha256 = COMPILER_RT[version]
    home = check_build.CACHE / f"compiler-rt-{version}"
    source = home / f"compiler-rt-{version}.src"
    if (source / "lib" / "profile").is_dir():
        return source
    step(f"download compiler-rt {version}'s source, for the coverage build")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
    except OSError as error:
        raise Failed(f"cannot download {url}: {error}") from error
    if hashlib.sha256(data).hexdigest() != sha256:
        raise Failed(f"{url} does not have the SHA-256 {sha256}")
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
        archive.extractall(home, filter="data")
    return source


def compile_check(tag, out, sanitizer, targets, *, labels, patch=None, runtime=None, ubsan=None, seconds=0):
    """Build into `out` with tools/checks/compile-check: the build `sanitizer` names, with the coverage changes if
    `runtime` (compiler-rt's source) is given, and with the breakage `patch` applied if given. `ubsan` is as for
    check_build.compile_build. With `seconds`, the build is stopped after that time. Return None if it built each of
    `targets`, else why not, with the end of its output."""
    check_build.empty_directory(out, tag, labels=labels)
    mounts = ["-v", f"{CHECKS_DIR}:/ovc:ro", "-v", f"{out}:/out", "-e", f"OVC_SECONDS={max(0, int(seconds))}"]
    if patch is not None:
        mounts += ["-v", f"{patch}:/ovc-mutant.patch:ro"]
    if runtime is not None:
        mounts += ["-v", f"{runtime}:/ovc-rt:ro", "-e", "OVC_COVERAGE=1"]
    if ubsan and "undefined" in sanitizer:
        mounts += ["-e", f"OV_UBSAN_CHECKS={','.join(ubsan[0])}", "-e", f"OV_UBSAN_EXCLUDE={','.join(ubsan[1])}"]
        if len(ubsan) > 2 and ubsan[2]:
            mounts += ["-e", f"OV_UBSAN_C_EXCLUDE={','.join(ubsan[2])}"]
    command = ["docker", "run", "--rm", "--init", "--network=none", *labels, "-e", f"SANITIZER={sanitizer}",
               "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}", *mounts, "--entrypoint", "/ovc/compile-check", tag]
    done = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True)
    tail = "\n".join(done.stdout.decode("utf-8", "replace").splitlines()[-20:]
                     + done.stderr.decode("utf-8", "replace").splitlines()[-10:])
    if done.returncode != 0:
        return f"the build exited {done.returncode}: {tail}"
    missing = [target for target in targets if not (out / target).is_file() or (out / target).is_symlink()]
    return f"the build made no {', '.join(missing)}" if missing else None


def export_coverage(tag, binaries, profiles, *, labels):
    """Merge each target's profiles and export its coverage with llvm-cov, in the project image. Return {target:
    export}; a target with no profile has none."""
    exports = {}
    for target, binary in sorted(binaries.items()):
        mine = profiles / target
        if not mine.is_dir() or not any(mine.glob("*.profraw")):
            continue
        script = ('llvm-profdata merge -sparse -o /tmp/merged.profdata /profiles/*.profraw && '
                  'llvm-cov export -format=text -instr-profile=/tmp/merged.profdata /binary')
        text = check_build.output("docker", "run", "--rm", "--network=none", *labels, "-v", f"{mine}:/profiles:ro",
                                  "-v", f"{binary}:/binary:ro", "--entrypoint", "sh", tag, "-c", script)
        try:
            exports[target] = json.loads(text)
        except ValueError as error:
            raise Failed(f"llvm-cov export of {target} is not JSON: {error}") from error
    return exports


def image_files(tag, paths, *, labels):
    """The bytes of these regular files of the project image: {path: bytes}. A path that is missing is left out."""
    if not paths:
        return {}
    done = subprocess.run(["docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "tar", tag, "-cf", "-",
                           "--", *sorted(paths)], stdin=subprocess.DEVNULL, capture_output=True)
    files = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(done.stdout)) as archive:
            for member in archive.getmembers():
                if member.isfile() and member.size <= 16 << 20:
                    files["/" + member.name.lstrip("/")] = archive.extractfile(member).read()
    except tarfile.TarError:
        pass
    return files


def workdir_of(tag):
    return check_build.output("docker", "image", "inspect", "--format", "{{.Config.WorkingDir}}", tag).strip() or "/"


def mutant_patches(tag, directory, workdir, *, labels):
    """The breakage patches in `directory` of the project image (relative to its WORKDIR): {name: bytes}, each regular
    file named *.patch at its top level. Raise Failed if the directory is not there."""
    script = 'cd -- "$1" || exit 3; for f in *.patch; do [ -f "$f" ] && [ ! -L "$f" ] && printf "%s\\0" "$f"; done; exit 0'
    done = subprocess.run(["docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "sh", tag, "-c", script,
                           "sh", directory], stdin=subprocess.DEVNULL, capture_output=True)
    if done.returncode != 0:
        raise Failed(f"mutants: {directory} is not a directory of the project image")
    names = sorted(name.decode("utf-8", "replace") for name in done.stdout.split(b"\0") if name)[:MAX_PATCHES]
    base = pathlib.PurePosixPath(workdir) / directory
    files = image_files(tag, [str(base / name) for name in names], labels=labels)
    return {name: files[str(base / name)][:MAX_PATCH_BYTES] for name in names if str(base / name) in files}


def diff_lines(data):
    """The lines of a file for difflib, split on \n only (bytes.splitlines would also split at \r). A last line with no
    newline ends with the marker that a unified diff gives it."""
    lines = [line + b"\n" for line in data.split(b"\n")]
    if data.endswith(b"\n") or not data:
        lines.pop()
    else:
        lines[-1] += b"\\ No newline at end of file\n"
    return lines


def record_breakages(checks, tag, workdir, *, labels):
    """One Breakage for each distinct change that the `mutant:` records of `checks` ask for, as a patch made from the
    image's file."""
    by_change = {}
    for check in checks:
        for record in check.records:
            by_change.setdefault(record.mutant(), []).append((check, record))
    paths = {path for path, *_ in by_change if check_records.safe_path(path)}
    files = image_files(tag, [str(pathlib.PurePosixPath(workdir) / path) for path in paths], labels=labels)
    breakages = []
    for (path, line, old, new), records in by_change.items():
        label = f"{path}:{line} `{old}` -> `{new}`"
        if not check_records.safe_path(path):
            breakages.append(Breakage(label, None, records, problem=f"{path} is not a path inside the WORKDIR"))
            continue
        data = files.get(str(pathlib.PurePosixPath(workdir) / path))
        if data is None:
            breakages.append(Breakage(label, None, records, problem=f"{path} is not a file of the project image"))
            continue
        changed, why = check_records.mutate(data, records[0][1])
        if changed is None:
            breakages.append(Breakage(label, None, records, problem=why))
            continue
        before, after = diff_lines(data), diff_lines(changed)
        diff = b"".join(difflib.diff_bytes(difflib.unified_diff, before, after, f"a/{path}".encode(),
                                           f"b/{path}".encode()))
        breakages.append(Breakage(label, f"diff --git a/{path} b/{path}\n".encode() + diff, records))
    return breakages


# ── the report ───────────────────────────────────────────────────────────────────────────────────────────────────────

_SAFE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def code(text, limit=120):
    """`text` from the project as Markdown code: control characters removed, at most `limit` characters, in a code
    span that no backtick in it can end."""
    text = _SAFE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def cell(text, limit=60):
    """`text` from the project as Markdown code in a table cell, where a | would end the cell."""
    return code(text, limit).replace("|", "\\|")


def shown(path):
    """A path of the project image as the report shows it: without the leading /src/."""
    return path.removeprefix("/src/")


def where(check):
    return f"{shown(check.path)}:{check.line}"


def describe(run):
    """What a failed run did, in words."""
    if run.status is None:
        return f"did not end within {RUN_TIMEOUT} seconds"
    if run.status == NOT_RUN:
        return "did not run before the time limit of the step"
    return f"exit status {run.status}" + (f" ({STATUS_NAMES[run.status]})" if run.status in STATUS_NAMES else "")


def lines_by_file(checks):
    """Checks as `file`: lines 1, 2, 3, one entry per file."""
    files = {}
    for check in checks:
        files.setdefault(shown(check.path), []).append(check.line)
    return [f"{code(path)}: line{'s' if len(lines) > 1 else ''} {', '.join(map(str, sorted(lines)))}"
            for path, lines in sorted(files.items())]


def listed(items, limit=MAX_LISTED):
    """At most `limit` list items, and a line that counts the rest."""
    return items[:limit] + ([f"  - and {len(items) - limit} more"] if len(items) > limit else [])


# ── the step ─────────────────────────────────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class Context:
    """What each breakage's evaluation needs."""
    tag: str
    labels: list
    home: pathlib.Path
    targets: list
    inputs: pathlib.Path
    seeds: dict
    runtime: pathlib.Path
    sanitizer: tuple | None
    ubsan: tuple | None
    workdir: str
    checks: list
    passing: set
    deadline: float


def measure(ctx, binaries, inputs, names, results, total=0):
    """Run the coverage build's binaries on the inputs. Return (runs, Coverage, exports)."""
    runs = run_all(ctx.tag, binaries, inputs, names, "coverage", results, labels=ctx.labels, total=total)
    exports = export_coverage(ctx.tag, {target: binaries / target for target in names if (binaries / target).is_file()},
                              results, labels=ctx.labels)
    coverage = Coverage()
    for export in exports.values():
        coverage.add(export)
    return runs, coverage, exports


def evaluate(ctx, number, breakage, record_targets):
    """Build and run one breakage, and fill in its outcome."""
    if time.monotonic() > ctx.deadline:
        breakage.outcome = "not checked"
        return breakage
    home = ctx.home / "breakages" / str(number)
    try:
        shutil.rmtree(home, ignore_errors=True)
        home.mkdir(parents=True)
        patch = home / "change.patch"
        patch.write_bytes(breakage.patch)
        if breakage.records:
            wanted = {(target, record.input) for check, record in breakage.records
                      for target in record_targets.get(check.path, ())}
            inputs, names = home / "inputs", subset(ctx.inputs, ctx.seeds, wanted, home / "inputs")
        else:
            inputs, names = ctx.inputs, ctx.seeds
        targets = [target for target in ctx.targets if target in names]
        if not targets:
            breakage.outcome, breakage.detail = "measured", "no seed input to run"
            return breakage
        why = compile_check(ctx.tag, home / "coverage", "none", ctx.targets, labels=ctx.labels, patch=patch,
                            runtime=ctx.runtime, seconds=max(60, ctx.deadline - time.monotonic()))
        if why and time.monotonic() > ctx.deadline:
            breakage.outcome = "not checked"
            return breakage
        if why:
            breakage.outcome, breakage.detail = "does not build", why
            return breakage
        runs, coverage, _ = measure(ctx, home / "coverage", inputs, names, home / "results",
                                    max(60, ctx.deadline - time.monotonic()))
        shifts = {} if breakage.records else hunk_shifts(breakage.patch, ctx.workdir)
        breakage.fired = {(check.path, check.line, check.column) for check in ctx.checks
                          if coverage.count(check.path, moved(check, shifts), check.column)}
        breakage.builds = ("coverage",)
        caught = any(run.caught() and run.key() in ctx.passing for run in runs)
        late = False
        if ctx.sanitizer and not caught and time.monotonic() > ctx.deadline:
            late = True
        elif ctx.sanitizer and not caught:
            why = compile_check(ctx.tag, home / ctx.sanitizer[0], ctx.sanitizer[1], ctx.targets, labels=ctx.labels,
                                patch=patch, ubsan=ctx.ubsan, seconds=max(60, ctx.deadline - time.monotonic()))
            late = bool(why) and time.monotonic() > ctx.deadline
            if why:
                breakage.detail = f"the {ctx.sanitizer[0]} build: {why}"
            else:
                runs += run_all(ctx.tag, home / ctx.sanitizer[0], inputs, names, ctx.sanitizer[0], home / "results-san",
                                labels=ctx.labels, total=max(60, ctx.deadline - time.monotonic()))
                breakage.builds += (ctx.sanitizer[0],)
        breakage.runs = runs
        unrun = any(run.status == NOT_RUN for run in runs)
        caught = any(run.caught() and run.key() in ctx.passing for run in runs)
        breakage.outcome = "not checked" if (unrun or late) and not caught else "measured"
    except Failed as failure:
        breakage.outcome, breakage.detail = "does not build", str(failure)
    finally:
        check_build.empty_directory(home, ctx.tag, labels=ctx.labels)
    return breakage


def catches(breakage, passing, target=None, seed=None):
    """The runs of `breakage` that failed where the unchanged code passes: of one target and seed, if given."""
    return [run for run in breakage.runs if run.caught() and run.key() in passing
            and (target is None or run.target == target) and (seed is None or run.seed == seed)]


def checks(job, tag, targets, work, raw, *, labels, ubsan=None, budget=BUDGET_MINUTES):
    """Run the step, and return its report as Markdown."""
    lines = ["### The checks of the fuzz targets", ""]
    if job.language not in LANGUAGES:
        return "\n".join(lines + [f"`--checks` measures C and C++ fuzz targets only; this project is in "
                                  f"{job.language}.", ""])
    home = work / "checks"
    home.mkdir(parents=True, exist_ok=True)
    inputs = home / "inputs"
    seeds = write_seeds(job.directory, targets, inputs)
    runtime = compiler_rt(llvm_version(tag, labels))
    workdir = workdir_of(tag)

    step("--checks: the coverage build, and each fuzz target on each seed input")
    why = compile_check(tag, home / "coverage", "none", targets, labels=labels, runtime=runtime)
    if why:
        raise Failed(f"the coverage build failed: {why}")
    ctx = Context(tag, labels, home, targets, inputs, seeds, runtime, None, ubsan, workdir, [], set(), 0.0)
    base_runs, base, exports = measure(ctx, home / "coverage", inputs, seeds, home / "results", BASELINE_MINUTES * 60)

    # The checks: the abort() calls in each file that defines LLVMFuzzerTestOneInput, and in the other files of its
    # directory that the coverage build compiled.
    defining = set().union(*(fuzz_target_files(export) for export in exports.values())) if exports else set()
    directories = {str(pathlib.PurePosixPath(path).parent) for path in defining}
    harness = sorted(path for path in base.segments if str(pathlib.PurePosixPath(path).parent) in directories)
    sources = image_files(tag, harness, labels=labels)
    found = [check for path in harness
             for check in check_records.find_checks(sources.get(path, b"").decode("latin-1"), path)]
    notes = [check for check in found if check.note]
    exempt = [check for check in found if not check.note and check.not_property is not None and not check.problems]
    properties = [check for check in found if not check.note and check not in exempt]
    badly_written = [check for check in found if check.problems]
    unreached = [check for check in properties if base.count(check.path, *check.guard_at) == 0]
    unmapped = [check for check in properties if base.count(check.path, *check.guard_at) is None]
    record_targets = {}
    for target, export in exports.items():
        for path in files_of(export):
            record_targets.setdefault(path, set()).add(target)

    sanitizer = next(((build, value) for build, value in SANITIZER_BUILDS if build in job.builds), None)
    sanitizer_base = (run_all(tag, raw / sanitizer[0], inputs, seeds, sanitizer[0], home / "results-sanitizer",
                              labels=labels, total=BASELINE_MINUTES * 60) if sanitizer else [])
    unrun = [run for run in base_runs + sanitizer_base if run.status == NOT_RUN]
    failing = [run for run in base_runs + sanitizer_base if not run.passed() and run.status != NOT_RUN]
    # A run stopped at a time limit is listed as failing, with "did not end": its seed then counts as no catch.
    passing = {run.key() for run in base_runs + sanitizer_base if run.passed()}

    no_corpus = [target for target in targets if target not in seeds]
    lines.append(f"Each fuzz target ran on each input of its seed corpus ({sum(map(len, seeds.values()))} inputs), "
                 "in a coverage build" + (f" and in the {sanitizer[0]} build" if sanitizer else "") +
                 ". docs/build-contract.md, \"The checks of a fuzz target\", says how this works.")
    lines.append("")
    if no_corpus:
        lines.append(f"- **No seed corpus:** {', '.join(code(t) for t in no_corpus)}. Step 3.3 of the add-project "
                     "skill asks for one for each fuzz target.")
    if unrun:
        lines.append(f"- **Not measured:** {len(unrun)} runs of seed inputs did not start before the time limit of "
                     f"{BASELINE_MINUTES} minutes, so a check that only they reach shows as not reached.")
    if failing:
        lines.append(f"- **Seed inputs that fail on the unchanged code:** {len(failing)}.")
        lines += listed([f"  - {code(run.target)} on {code(run.seed, 60)}, {run.build} build: {describe(run)}"
                         for run in failing], 20)
    lines.append(f"- **Checks:** {len(properties)} property checks in "
                 f"{', '.join(code(shown(path)) for path in harness) or 'no file'}"
                 + (f", and {len(exempt)} stops marked `not a property`" if exempt else "") + ".")
    if unreached:
        lines.append(f"- **Checks that no seed input reaches:** {len(unreached)}. Step 3.3 asks for an input that "
                     "reaches each check. Add one to the seed corpus.")
        lines += listed([f"  - {code(where(c))}, under {code(c.text, 90)}" for c in unreached])
    else:
        lines.append("- **Checks that no seed input reaches:** none.")
    if unmapped:
        lines.append(f"- **Not measured:** {len(unmapped)} checks that the coverage build did not compile: "
                     + "; ".join(lines_by_file(unmapped)) + ".")
    if notes:
        lines.append(f"- **Not read as checks:** {len(notes)} `abort()` calls.")
        lines += listed([f"  - {code(where(c))}: {c.note}" for c in notes], 20)
    if badly_written:
        lines.append(f"- **Comments whose records cannot be read:** {len(badly_written)}. The record format is in "
                     "docs/build-contract.md, \"The checks of a fuzz target\".")
        lines += listed([f"  - {code(where(c))}: {code('; '.join(c.problems), 200)}" for c in badly_written], 30)
    if exempt:
        lines.append(f"- **Marked `not a property`:** {len(exempt)}, which need no input and no breakage. The review "
                     "reads each reason.")
        lines += listed([f"  - {code(where(c))}: {code(c.not_property, 90)}" for c in exempt], 30)

    # The breakages.
    try:
        breakages = record_breakages(properties, tag, workdir, labels=labels)
        patches = mutant_patches(tag, job.mutants, workdir, labels=labels) if job.mutants else {}
        breakages += [Breakage(name, body) for name, body in patches.items()]
        ctx = Context(tag, labels, home, targets, inputs, seeds, runtime, sanitizer, ubsan, workdir, found, passing,
                      time.monotonic() + budget * 60)
        buildable = [b for b in breakages if b.patch is not None]
        step(f"--checks: {len(buildable)} breakages, at most {budget} minutes")
        jobs = max(1, int(os.environ.get("OVC_JOBS") or (os.cpu_count() or 2)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            list(pool.map(lambda pair: evaluate(ctx, pair[0], pair[1], record_targets), enumerate(buildable)))
    except Failed as failure:
        lines += [f"- **Breakages:** not measured: {code(str(failure), 1500)}", ""]
        return "\n".join(lines)

    # The records, check by check.
    met, problems, made_fire = 0, [], set()
    for breakage in breakages:
        made_fire |= breakage.fired if breakage.outcome == "measured" else set()
        for check, record in breakage.records:
            label = f"{code(where(check))}: {code(str(record), 110)}"
            if breakage.problem:
                problems.append(f"  - {label}: **bad mutant record**: {code(breakage.problem, 200)}")
            elif not any(record.input in seeds.get(t, []) for t in record_targets.get(check.path, ())):
                problems.append(f"  - {label}: **no such input** in the seed corpus of the fuzz targets that "
                                "compile this file")
            elif breakage.outcome == "not checked":
                problems.append(f"  - {label}: not checked: the time budget of {budget} minutes ran out")
            elif breakage.outcome == "does not build":
                problems.append(f"  - {label}: **the mutant does not build**: {code(breakage.detail, 300)}")
            elif not any(catches(breakage, passing, t, record.input) for t in record_targets.get(check.path, ())):
                statuses = ", ".join(f"{run.build} {run.status if run.status is not None else 'time limit'}"
                                     for run in breakage.runs if run.seed == record.input) or "no run"
                problems.append(f"  - {label}: **mutant not met**: the input passes ({statuses})"
                                + (f"; {code(breakage.detail, 300)}" if breakage.detail else ""))
            else:
                met += 1
                if (check.path, check.line, check.column) not in breakage.fired:
                    caught = catches(breakage, passing, None, record.input)[0]
                    problems.append(f"  - {label}: met, but not by this check: {caught.build} build, "
                                    f"{describe(caught)}")
    records = sum(len(b.records) for b in breakages)
    if records:
        lines.append(f"- **Mutant records:** {records} in the comments of the checks, of which {met} are met. "
                     "Step 3.4 asks that each record's input makes its check fire.")
        lines += listed(problems)

    # The patches of the `mutants` directory.
    directory = [b for b in breakages if not b.records]
    if job.mutants:
        uncaught = [b for b in directory if b.outcome == "measured" and not catches(b, passing)]
        broken = [b for b in directory if b.outcome == "does not build"]
        late = [b for b in directory if b.outcome == "not checked"]
        lines.append(f"- **Breakage patches** in {code(job.mutants)}: {len(directory)}. No seed input catches "
                     f"{len(uncaught)}: step 3.4 asks for an input that catches each one, in the seed corpus."
                     + (f" {len(broken)} do not apply or build: correct the patch." if broken else "")
                     + (f" {len(late)} were not checked in the time budget." if late else ""))
        if directory:
            lines += ["", "  | patch | result | checks that fired |", "  |---|---|---|"]
            for b in directory:
                if b.outcome != "measured":
                    result = ("not checked: the time budget ran out" if b.outcome == "not checked"
                              else f"does not apply or build: {cell(b.detail, 200)}")
                elif caught := catches(b, passing):
                    result = (f"caught: {cell(caught[0].target)} on {cell(caught[0].seed)}, {caught[0].build} "
                              f"build, {describe(caught[0])}")
                else:
                    result = f"**not caught** by any seed input ({' and '.join(b.builds)} builds)" + (
                        f"; {cell(b.detail, 200)}" if b.detail else "")
                fired = [check for check in found if (check.path, check.line, check.column) in b.fired]
                lines.append(f"  | {cell(b.label)} | {result} | "
                             f"{', '.join(cell(where(c)) for c in fired) or 'none'} |")
            lines.append("")
    never = [check for check in properties if (check.path, check.line, check.column) not in made_fire]
    if never:
        lines.append(f"- **Checks that no breakage makes fire:** {len(never)} of {len(properties)}. Step 3.4 asks for "
                     "a one-line breakage for each check, and a seed input on which it fires: "
                     + "; ".join(lines_by_file(never)) + ".")
    lines.append("")
    return "\n".join(lines)
