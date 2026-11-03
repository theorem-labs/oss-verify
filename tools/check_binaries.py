# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The checks of the binaries, a step of `tools/check --checks`: four checks on every build of every fuzz target.

1. ELF and instructions (tools/binary_isa.py): the binary is a 64-bit RISC-V executable at fixed addresses (ET_EXEC),
   it holds no compressed instruction, and every 32-bit word of its code is one that the process model's decoder
   accepts and executes.
2. System calls (tools/syscall_shapes.py): every system call that the binary makes on its inputs, and the arguments it
   makes it with, are ones the process model covers. The binary runs under qemu-riscv64 -strace on each input, and
   each trace is read against the model's system call table and the rules of its arguments, under the abort stance
   "off": the statements' default (`abort: error`), in which an abort is not a modeled end.
3. Quiet and loud (here): the quiet twin, the same link with the driver compiled with -DHARNESS_QUIET
   (infra/base-builder/link-fuzz-target), writes nothing and exits with the binary's status on each input. So what the
   binary writes changes neither which code runs nor how it ends.
4. Uninstrumented code (tools/check_links.py): which code each link took that no sanitizer instruments (the files of
   the toolchain image), written in the shape of the proofs repository's harness.yaml; and, in the sanitizer builds,
   whether all of the project's own code is instrumented.

The process model is the one the published proofs use: the proofs repository's release.yaml names it, and it is
fetched at that commit (tools/model_release.py). Checks 1 and 2 read the model by rules written against one commit;
when the release names a model whose code differs in a file they read, their result is "stale", not a verdict.

The inputs of checks 2 and 3 are the empty input (the driver's six-byte header and no payload) and the first
MAX_SEEDS inputs of the fuzz target's seed corpus, each with the header in front. Each binary runs in a fresh
container of the toolchain image with no network (tools/checks/run-binaries), its runs one after the other, each in an
empty working directory with an empty /tmp and an /etc of three fixed files, as the model's environment has it, with
no environment, as an unprivileged user, and named by the fuzz target's name. The binary and its quiet twin run in
the same way. All runs together stop after BUDGET_MINUTES; a run that did not start decides nothing.

Each result is pass, fail, error (the check could not decide), stale (above), plain (check 4 of the plain build), or
for check 3, not-run (no quiet twin). What the step finds changes no exit status of tools/check. Its results go into
the build manifest and its report into the --checks file.
"""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

import binary_isa
import check_build
import check_checks
import check_links
import model_release
import syscall_shapes
from check_build import Failed, step

# The most seed inputs each fuzz target runs on, besides the empty input; the longest one run may take, in seconds; and
# the most time all runs of the step may take together, in minutes.
MAX_SEEDS = 8
RUN_SECONDS = 60
BUDGET_MINUTES = 30
EMPTY = "(the empty input)"
HEADER = check_checks.HEADER
STOPPED = 137  # run-binaries' status for a run stopped at the time limit (SIGKILL)
CHECKS_DIR = check_checks.CHECKS_DIR
MAX_LISTED = 20
STANCE = "off"
# A trace decides something only with this many calls at least, and with the input opened (system_calls).
MIN_CALLS = 8
INPUT_OPEN = re.compile(r'^\d+ openat\(AT_FDCWD,"input\.bin",O_RDONLY[^)]*\) = [0-9]+$', re.M)
# The one qemu release whose -strace formats and host calls tools/syscall_shapes.py reads (measured: Debian 13's
# qemu-user 10.0.11, which CI and the collection's runner install; 10.0.0 prints read's and write's buffer in 32 bits,
# 10.0.11 in full). A run of any other release leaves check 2 not decided.
QEMU_VERSIONS = re.compile(r"qemu-riscv64 version 10\.0\.11\b")
MAX_RESULT_BYTES = 256 << 20


def seed_inputs(directory, target):
    """The inputs a fuzz target runs on: [(name, bytes)], the empty input first, then the first MAX_SEEDS inputs of
    projects/<name>/<target>_seed_corpus.zip, each with the driver's header in front."""
    inputs = [(EMPTY, HEADER)]
    corpus = pathlib.Path(directory) / f"{target}_seed_corpus.zip"
    if corpus.is_file():
        with zipfile.ZipFile(corpus) as archive:
            for info in archive.infolist():
                if len(inputs) > MAX_SEEDS:
                    break
                if not info.is_dir():
                    inputs.append((info.filename, HEADER + archive.read(info)))
    return inputs


def image_hashes(image, paths, *, labels):
    """The SHA-256 of each of `paths` in the image `image`, as {path: sha256}; a path the image does not have as a
    regular file is left out."""
    if not paths:
        return {}
    script = 'for f; do if [ -f "$f" ] && [ ! -L "$f" ]; then sha256sum -- "$f"; fi; done'
    text = check_build.output("docker", "run", "--rm", "--network=none", *labels, "--entrypoint", "sh", image, "-c",
                              script, "sh", *sorted(paths))
    hashes = {}
    for line in text.splitlines():
        digest, _, path = line.partition("  ")
        if len(digest) == 64 and path:
            hashes[path] = digest
    return hashes


def dwarf_reader(image, labels):
    """dwarf_units for check_links.analyse: each object's first DWARF compile unit, read with the toolchain image's
    llvm-dwarfdump in a container with no network."""
    def units(objects):
        with tempfile.TemporaryDirectory(prefix="ov-dwarf.") as scratch:
            for n, data in enumerate(objects):
                pathlib.Path(scratch, f"{n}.o").write_bytes(data)
            script = 'for f in /objects/*.o; do echo "== $f"; llvm-dwarfdump --debug-info "$f"; done'
            done = subprocess.run(["docker", "run", "--rm", "--network=none", *labels, "-v", f"{scratch}:/objects:ro",
                                   "--entrypoint", "sh", image, "-c", script], stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, errors="replace")
            found = check_links.parse_dwarfdump(done.stdout)
            return [found.get(f"/objects/{n}.o") for n in range(len(objects))]
    return units


def assembly_reader(tag, checkouts, labels):
    """assembly_sources for check_links.analyse: for each (object name, the functions it defines), the project's own
    assembly source that carries the object's name and names every one of them, relative to its checkout, or None.
    An object assembled without -g carries no DWARF and no other mark, so its source is what says it is assembly.
    The search runs in a container of the project image with no network, over the checkouts the build left."""
    def sources(wanted):
        if not wanted or not checkouts:
            return [None] * len(wanted)
        job = "".join(f"{name}\t{pathlib.PurePosixPath(name).stem}\t{' '.join(sorted(set(defined)))}\n"
                      for name, defined in wanted)
        script = (
            'while IFS="\t" read -r name stem globals; do\n'
            '  hit=""\n'
            '  [ -n "$globals" ] || { printf "%s\\t\\n" "$name"; continue; }\n'
            '  for root in "$@"; do\n'
            '    for source in $(find "$root" -type f \\( -name "$stem.S" -o -name "$stem.s" -o -name "$stem.sx" '
            '-o -name "$stem.asm" \\) 2>/dev/null | head -20); do\n'
            '      ok=1\n'
            '      for g in $globals; do grep -qw -- "$g" "$source" || { ok=0; break; }; done\n'
            '      [ "$ok" = 1 ] && { hit=$source; break; }\n'
            '    done\n'
            '    [ -z "$hit" ] || break\n'
            '  done\n'
            '  printf "%s\\t%s\\n" "$name" "$hit"\n'
            'done\n')
        done = subprocess.run(["docker", "run", "--rm", "-i", "--network=none", *labels, "--entrypoint", "sh", tag,
                               "-c", script, "sh", *checkouts], input=job, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, errors="replace")
        found = {}
        for line in done.stdout.splitlines():
            name, _, path = line.partition("\t")
            if path:
                found[name] = check_links.relative_source(path, checkouts)
        return [found.get(name) for name, _ in wanted]
    return sources


def record_of(raw, target, compiles=None):
    """The link record of a fuzz target in one build's $OUT `raw`, with the build's compile records `compiles`
    (check_links.read_compiles): a check_links.Record, a check_links.GoProgram (a program that Go's linker linked,
    which has no map), or the reason there is neither. Also its quiet twin's bytes, or None."""
    try:
        executable = check_links.read_regular(check_links.below(raw, target))
    except check_links.RecordError as error:
        return f"{target}: {error}", None
    digest = hashlib.sha256(executable).hexdigest()
    quiet = None
    if os.path.lexists(raw / ".records" / digest):
        try:
            quiet = check_links.read_regular(check_links.below(raw, ".records", digest, "quiet"))
        except check_links.RecordError:
            pass
        if os.path.lexists(raw / ".records" / digest / "map"):
            try:
                return check_links.read_record(raw, digest, compiles), quiet
            except check_links.RecordError as error:
                return str(error), quiet
        why = "its link has no map"
    else:
        why = "compile recorded no link of it (a link that did not go through $CC or $CXX)"
    # Go's linker writes no map: a Go program says what it linked in its own build information. A binary that this
    # cannot read gives that binary an error, never the whole step.
    try:
        program = check_links.go_program(executable)
    except Exception as failure:
        program = f"its Go build information could not be read: {type(failure).__name__}: {failure}"
    if isinstance(program, check_links.GoProgram):
        return program, quiet
    return f"{why}, and it is not a Go program linked from Go code only ({program})", quiet


# ── running the binaries ─────────────────────────────────────────────────────────────────────────────────────────────

def qemu_version(qemu):
    """The first line of `qemu-riscv64-static --version` (our own qemu, on the host: it runs no binary)."""
    done = subprocess.run([str(qemu), "--version"], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          errors="replace")
    return (done.stdout.splitlines() or [""])[0].strip()


def run_job(job_dir, image, qemu, labels, seconds):
    """Run one binary's runs (job_dir/job/runs) in a container of the toolchain image `image`, for at most `seconds` in
    all. Return job_dir/results."""
    results = job_dir / "results"
    check_build.empty_directory(results, image, labels=labels)
    command = ["docker", "run", "--rm", "--init", "--network=none", *labels,
               "-e", f"OV_OWNER={os.getuid()}:{os.getgid()}", "-v", f"{qemu}:/ovc-qemu:ro",
               "-v", f"{CHECKS_DIR}:/ovc:ro", "-v", f"{job_dir / 'job'}:/job:ro", "-v", f"{results}:/results",
               "--entrypoint", "/ovc/run-binaries", image, str(RUN_SECONDS), str(max(1, int(seconds)))]
    if check_build.run(*command, quiet=True) != 0:
        raise Failed(f"could not run {job_dir.name}")
    return results


def read_result(results, name, limit=MAX_RESULT_BYTES):
    """A results file as text, or None if it is not there or is not a regular file."""
    try:
        return check_links.read_regular(check_links.below(results, name), limit).decode("utf-8", "replace")
    except check_links.RecordError:
        return None


def read_number(results, name):
    """The integer a results file holds, or None if it is not there."""
    text = read_result(results, name, 64)
    try:
        return int(text.strip()) if text is not None else None
    except ValueError:
        return None


def describe_status(status):
    if status is None:
        return "did not run in the time budget"
    if status == STOPPED:
        return f"did not end within {RUN_SECONDS} seconds"
    return f"exit status {status}"


def system_calls(model, stale, qemu, binary, inputs, results):
    """Check 2 for one binary from its traces. Return its result.

    Besides the model's rules (tools/syscall_shapes.py), a trace decides something only when it is a whole run of the
    input: the host-side log shows the run started, the trace ends with the run's exit, it holds at least MIN_CALLS
    calls, and it opens input.bin and reads it. A run that died before it reached its input made few calls, all of
    them modeled, and says nothing about the input."""
    if isinstance(model, str):
        return {"result": "error", "detail": model}
    if not QEMU_VERSIONS.match(qemu):
        return {"result": "error", "detail": f"{qemu or 'no qemu version'}: check 2 reads the runs of qemu 10.0.11 "
                                             "only (tools/syscall_shapes.py reads its -strace formats and host calls; "
                                             "qemu 8.2 hands the host 0 for every anonymous mmap's offset, so its runs "
                                             "cannot show one). docs/build-contract.md, \"The checks of a fuzz "
                                             "target\", says how to get qemu-user 10.0.11"}
    statuses, unmodeled, undecided, calls, whole = {}, {}, [], 0, set()
    for n, (name, data) in enumerate(inputs):
        status = read_number(results, f"l{n}.status")
        statuses[name] = status
        text, log = read_result(results, f"l{n}.trace"), read_result(results, f"l{n}.calls")
        if status is None or text is None:
            undecided.append(f"{name}: {describe_status(status)}" if status is None else f"{name}: no trace")
            continue
        try:
            # The run's input.bin holds the input's bytes (tools/checks/run-binaries), so its reads have one answer.
            verdict = syscall_shapes.check_trace(model, text, stance=STANCE, require_exit=True,
                                                 binary=str(binary), lengths=log, inputs={"input.bin": data})
        # One trace must not take the step's other results with it.
        except Exception as failure:
            return {"result": "error", "detail": f"{name}: the trace could not be read: "
                                                 f"{type(failure).__name__}: {failure}"}
        calls += verdict["calls"]
        for item in verdict["unmodeled"]:
            unmodeled.setdefault((item["call"], item["why"]), []).append(name)
        # A call whose answer depends on a value that neither qemu's log nor the host's call shows.
        undecided += [f"{name}: {item['call']}: {item['why']}" for item in verdict.get("undecided", [])]
        if verdict.get("host_log") == "missing":
            undecided.append(f"{name}: {describe_status(status)}, and the host-side log of its calls is missing")
        elif not verdict["exited"]:
            undecided.append(f"{name}: {describe_status(status)}, and its trace holds no end of the run")
        elif verdict["calls"] < MIN_CALLS:
            undecided.append(f"{name}: its trace holds {verdict['calls']} calls, fewer than {MIN_CALLS}")
        elif not INPUT_OPEN.search(text) or "read" not in verdict["names"]:
            undecided.append(f"{name}: {describe_status(status)}, and its trace does not open and read input.bin")
        else:
            whole.add(name)
    result = {"stance": STANCE, "qemu": qemu, "statuses": statuses, "calls": calls, "whole": sorted(whole),
              "unmodeled": [{"call": call, "why": reason, "inputs": names}
                            for (call, reason), names in unmodeled.items()]}
    if stale:
        result.update(result="stale", detail=stale)
    elif unmodeled:
        result.update(result="fail", detail=f"{len(unmodeled)} calls or argument shapes the model does not cover: "
                      + "; ".join(f"{call}: {reason}" for call, reason in list(unmodeled)[:MAX_LISTED]))
    elif undecided:
        result.update(result="error", detail="; ".join(undecided[:MAX_LISTED]))
    else:
        result.update(result="pass", detail=f"{calls} calls on {len(inputs)} inputs, all covered")
    if undecided and result["result"] != "error":
        result["detail"] += "; not decided: " + "; ".join(undecided[:MAX_LISTED])
    return result


def quiet_loud(has_quiet, why_none, inputs, results, whole=None, unknown=None):
    """Check 3 for one binary from its runs. `whole` holds the names of the inputs whose loud run was a whole run of
    that input (system_calls); None means every run counts. A run that died before it reached its input writes
    nothing either, so it decides nothing here. `unknown`, if given, is why check 2 could not tell which runs were
    whole at all (its detail): then no run was shown to be whole, and the result says that, not that each run fell
    short of its input."""
    if not has_quiet:
        return {"result": "not-run", "detail": f"no quiet twin: {why_none}"}
    differ, noisy, undecided, agreed = [], [], [], 0
    for n, (name, _) in enumerate(inputs):
        loud, silent = read_number(results, f"l{n}.status"), read_number(results, f"q{n}.status")
        out, err = read_number(results, f"q{n}.out"), read_number(results, f"q{n}.err")
        # host-calls logs `exec` once the program has started; without it, the status is host-calls' own.
        started = all("exec" in (read_result(results, f"{kind}{n}.calls") or "").split("\n") for kind in "lq")
        if loud is None or silent is None or STOPPED in (loud, silent) or not started or out is None or err is None:
            undecided.append(f"{name}: the binary {describe_status(loud)}, the quiet twin {describe_status(silent)}"
                             + ("" if started else ", and a run did not start")
                             + ("" if out is not None and err is not None else ", and the count of what the quiet "
                                                                               "twin wrote is missing"))
            continue
        written = out + err
        if loud != silent:
            differ.append(f"{name}: the binary exits {loud}, the quiet twin {silent}")
        if written:
            noisy.append(f"{name}: the quiet twin wrote {written} bytes")
        if whole is not None and name not in whole:
            undecided.append(f"{name}: " + ("check 2 could not tell whether the binary's run reached its input"
                                            if unknown else "the binary's run was not a whole run of the input"))
        elif loud == silent and not written:
            agreed += 1
    if differ or noisy:
        return {"result": "fail", "detail": "; ".join((differ + noisy)[:MAX_LISTED])}
    if not agreed:
        detail = "no input decided: " + "; ".join(undecided[:MAX_LISTED])
        if unknown:
            detail += f" (check 2: {unknown})"
        return {"result": "error", "detail": detail}
    detail = f"the same status on {agreed} inputs, and the quiet twin wrote nothing"
    if undecided:
        detail += "; not decided: " + "; ".join(undecided[:MAX_LISTED])
    return {"result": "pass", "detail": detail}


def whole_runs(calls):
    """What check 3 takes from check 2's result `calls`: (the inputs whose loud run was a whole run, why check 2 could
    not tell or None). system_calls() lists the whole runs, perhaps none, in each result it reads the runs for: a pass,
    a failure, a stale model, runs that decide nothing. It lists none when it could not read the runs at all (no model,
    another qemu, a trace it could not read) or raised (guarded()), and then its detail is the reason."""
    if "whole" in calls:
        return set(calls["whole"]), None
    return set(), calls.get("detail") or "it gave no reason"


def guarded(check, *arguments):
    """One check's result, or an error that names what went wrong: a binary or a trace that a check cannot read gives
    that binary an error, and the step's other results stand."""
    try:
        return check(*arguments)
    except Exception as failure:
        return {"result": "error", "detail": f"{check.__name__}: {type(failure).__name__}: {failure}"}


def elf_check(binary, stale):
    """Check 1 for one binary. With a stale model there is no verdict either way: the rules that say which
    instructions the model executes may not be the release's."""
    result = binary_isa.check(str(binary))
    if stale and result["result"] in ("pass", "fail"):
        result = {**result, "result": "stale", "detail": f"{result['detail']}; {stale}"}
    return result


# ── the step ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def staleness(root, module, release):
    """Why a module's rules may not be the release's model ("" if they are)."""
    changed = model_release.stale(root, module.MODEL_FILES)
    if not changed:
        return ""
    return (f"its rules were checked against model commit {module.MODEL_COMMIT[:12]}, and at {release['commit'][:12]}, "
            f"the release's, the code of {', '.join(changed)} differs")


def binary_checks(job, tag, toolchain, targets, entries, sources, work, *, labels):
    """Run the four checks on every binary. `tag` is the project image, whose checkouts `sources` names (the
    manifest's sources); the runs are in the toolchain image. Return (the manifest's binary_checks block, {target:
    {build: uninstrumented list or None}})."""
    home = work / "binaries"
    check_build.empty_directory(home, toolchain, labels=labels)

    step("--checks: the model the published proofs use (their release.yaml)")
    release, root, model = None, None, "the model's version could not be read"
    try:
        release = model_release.release_model()
        root = model_release.fetch(release["repository"], release["commit"])
        model = syscall_shapes.Model.load(root)
        check_build.say(f"{release['name']} at {release['commit']}, from {release['from']}")
    except (Failed, OSError, ValueError) as failure:
        model = f"the model could not be read: {failure}"
        check_build.say(model)
    unknown = "the release's model could not be read, so which model the rules match is not known"
    isa_stale = staleness(root, binary_isa, release) if root is not None else unknown
    shape_stale = staleness(root, syscall_shapes, release) if root is not None else unknown

    step("--checks: the links of each binary")
    records, quiet = {}, {}
    # The compile records are the build's, and every target of it reads them.
    compiles = {build: check_links.read_compiles(work / "raw" / build) for build in job.builds}
    for target in targets:
        for build in job.builds:
            records[(target, build)], quiet[(target, build)] = record_of(work / "raw" / build, target,
                                                                         compiles[build])
    wanted = set()
    for record in records.values():
        if isinstance(record, check_links.Record):
            wanted |= {real for real, _, _ in record.inputs.values() if real.startswith("/opt/")}
            wanted |= {original for original, _ in record.renamed.values() if original.startswith("/opt/")}
    image = image_hashes(toolchain, wanted, labels=labels)
    # The project image's files at the paths a compile record names, by SHA-256: a build directory's copy of an
    # assembly source is shown to be the checkout's file by its bytes (check_links.copied_sources). If the image cannot
    # be read, no copy is shown, and those objects are judged as before.
    def checkout_files(paths):
        try:
            return image_hashes(tag, paths, labels=labels)
        except Failed:
            return {}

    links = {target: check_links.analyse({build: records[(target, build)] for build in job.builds}, image,
                                         dwarf_reader(toolchain, labels), sorted(sources),
                                         assembly_reader(tag, sorted(sources), labels), checkout_files)
             for target in targets}

    step(f"--checks: each binary on its inputs, under qemu-riscv64 (at most {RUN_SECONDS} seconds a run, "
         f"{BUDGET_MINUTES} minutes in all)")
    inputs = {target: seed_inputs(job.directory, target) for target in targets}
    jobs = {}
    for target in targets:
        for build in job.builds:
            job_dir = home / f"{target}.{build}"
            files = job_dir / "job"
            (files / "inputs").mkdir(parents=True)
            shutil.copyfile(work / "out" / target / entries[target][build]["file"], files / "binary")
            os.chmod(files / "binary", 0o755)
            runs = []
            for n, (_, data) in enumerate(inputs[target]):
                (files / "inputs" / str(n)).write_bytes(data)
                runs.append(f"l{n} binary inputs/{n} {target}")
            if quiet[(target, build)] is not None:
                (files / "quiet").write_bytes(quiet[(target, build)])
                os.chmod(files / "quiet", 0o755)
                runs += [f"q{n} quiet inputs/{n} {target}" for n in range(len(inputs[target]))]
            (files / "runs").write_text("".join(f"{run}\n" for run in runs), encoding="utf-8")
            jobs[(target, build)] = job_dir
    results, failures, version = {}, {}, ""
    deadline = time.monotonic() + BUDGET_MINUTES * 60
    try:
        qemu = check_checks.qemu()
        version = qemu_version(qemu)
        keys = list(jobs)
        outcomes = check_build.in_threads(
            lambda key: run_job(jobs[key], toolchain, qemu, labels, deadline - time.monotonic()), keys,
            max(1, os.cpu_count() or 2))
        for key, outcome in zip(keys, outcomes):
            if isinstance(outcome, Failed):
                failures[key] = str(outcome)
            elif isinstance(outcome, BaseException):
                raise outcome
            else:
                results[key] = outcome
    except Failed as failure:
        failures = {key: str(failure) for key in jobs}

    block = {"model": release or {"error": model}, "qemu": version,
             "inputs": {t: [name for name, _ in inputs[t]] for t in targets}, "targets": {}}
    uninstrumented = {}
    for target in targets:
        block["targets"][target] = {}
        uninstrumented[target] = {}
        for build in job.builds:
            binary = work / "out" / target / entries[target][build]["file"]
            record = records[(target, build)]
            why_none = ("one of the driver's objects has no quiet build" if isinstance(record, check_links.Record)
                        else "the Go helper kept no quiet program" if isinstance(record, check_links.GoProgram)
                        else record)
            # A check that cannot read one binary gives that binary an error, never the whole step.
            if (target, build) in results:
                calls = guarded(system_calls, model, shape_stale, version, binary, inputs[target],
                                results[(target, build)])
                agreement = guarded(quiet_loud, quiet[(target, build)] is not None, why_none, inputs[target],
                                    results[(target, build)], *whole_runs(calls))
            else:
                why = failures.get((target, build), "not run")
                calls = {"result": "error", "detail": why}
                agreement = {"result": "error", "detail": why}
            link = links[target][build]
            uninstrumented[target][build] = link["uninstrumented"]
            block["targets"][target][build] = {
                "elf": guarded(elf_check, binary, isa_stale),
                "system_calls": calls,
                "quiet_loud": agreement,
                "instrumented": link["instrumented"],
            }
    return block, uninstrumented


# ── the report ───────────────────────────────────────────────────────────────────────────────────────────────────────

# A check that did not run decided nothing, so it reads as such: only pass and the plain build's "nothing to
# instrument" are results a reader may take as good.
RESULT_WORDS = {"pass": "pass", "fail": "**fail**", "error": "**not decided**", "stale": "**stale model**",
                "not-run": "**not decided** (not run)", "plain": "not instrumented (plain)"}


def report(block, uninstrumented, builds):
    """The Markdown report of the step."""
    code = check_checks.code
    lines = ["### The checks of the binaries", ""]
    model = block["model"]
    if "commit" in model:
        lines.append(f"Against the process model the published proofs use: {code(model['name'])} at "
                     f"{code(model['commit'][:12])} (release {code(model['release'])}, from its release.yaml).")
    else:
        lines.append(f"The process model could not be read: {code(model.get('error', ''), 300)}.")
    counts = {target: len(names) for target, names in block["inputs"].items()}
    lines += [f"Each fuzz target ran on the empty input and up to {MAX_SEEDS} seed inputs ("
              + ", ".join(f"{code(t)}: {n}" for t, n in counts.items()) + "). docs/build-contract.md, \"The checks of "
              "the binaries\", says what each check proves.", "",
              "| binary | ELF and instructions | system calls | quiet and loud | instrumented | uninstrumented code |",
              "|---|---|---|---|---|---|"]
    problems = []
    for target, by_build in block["targets"].items():
        for build in builds:
            results = by_build[build]
            listing = uninstrumented[target][build]
            # A plain result with no list is a Go program (check_links.analyse): it links Go code only.
            files = ("no list (Go code only)" if listing is None and results["instrumented"]["result"] == "plain"
                     else "not recorded" if listing is None else f"{len(listing)} files" + (
                         f", {sum(1 for u in listing if u['kind'] == 'assembly')} assembly"
                         if any(u["kind"] == "assembly" for u in listing) else ""))
            cells = [RESULT_WORDS.get(results[key]["result"], results[key]["result"])
                     for key in ("elf", "system_calls", "quiet_loud", "instrumented")]
            name = f"{target}.{build}"
            lines.append(f"| {check_checks.cell(name)} | {' | '.join(cells)} | {files} |")
            for key, title in (("elf", "ELF and instructions"), ("system_calls", "system calls"),
                               ("quiet_loud", "quiet and loud"), ("instrumented", "instrumented")):
                if results[key]["result"] not in ("pass", "plain"):
                    problems.append(f"- {code(name)}, {title}: {code(results[key]['detail'], 600)}")
    lines.append("")
    if problems:
        lines += ["What each failure is:", "", *problems, ""]
    return "\n".join(lines)
