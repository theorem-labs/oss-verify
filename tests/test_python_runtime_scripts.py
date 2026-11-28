# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The scripts of .github/scripts/python-runtime, run as toolchain-images.yaml's job prebuilt runs them, with stand-ins
of docker and crane first on PATH, and no Docker:

    uv run pytest tests/test_python_runtime_scripts.py

make: the stand-in docker's four builds leave in $OUT what build.sh stages there, and print what compile prints. make
must lay out the layer of the four runtimes, append it with the stand-in crane of tests/test_trigger_move.py, and print
last its line `made <repository>@sha256:<digest>`. It must fail, with no made line, on a base image that has
/opt/oft-py/prebuilt already, a build that fails, a build that printed no built line or the key line of another key, a
missing file of a runtime, no compile records, a manifest whose key is not the SHA-256 of its lines or that is of
another build, and a new image whose manifest names the base image's layers in another order or whose last diff ID is
not the layer's.

probe: the stand-in docker's eight builds of the fixture, four on each image, leave the same files in $OUT, and the
probe must pass. It must fail when one file of one build differs, when the $OUT of a build on the base image is empty,
when a build on the base image left no compile record of an object under /work/build/pyrt/, and when a build on the
derived image printed that it built its own runtime.

Each control runs its case on a copy of the scripts, where it passes, and on a copy with one check of the script taken
out, where it must fail. jq is this host's: the scripts run it, as on the runner."""
import base64
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

import test_trigger_move

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".github/scripts/python-runtime"
PROJECT = "tests/fixtures/python-example/project.yaml"
# compile's FLAV of each SANITIZER (infra/base-builder/compile).
FLAVS = {"none": "plain", "undefined": "ubsan", "address": "asan", "address-undefined": "asanubsan"}
# OFT_PY_RT_FILES of infra/base-builder/python/runtime.sh.
RUNTIME_FILES = ["libpython3.11.a", "Modules/expat/libexpat.a", "Modules/_decimal/libmpdec/libmpdec.a", "pyconfig.h",
                 "oft-linkvars.txt", "target-builtins.txt", "target-frozen.txt"]
# The build that a fault changes.
FAULTY = "asan"
BASE_REPOSITORY = "ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain-python"
TARGET_REPOSITORY = "localhost:5000/theorem-labs/oss-fuzz-theorems-toolchain"
TARGET = f"{TARGET_REPOSITORY}:oss-fuzz-theorems-2026.10-python-prebuilt"
CRANE = test_trigger_move.ToolchainPublish.CRANE
digest_of = test_trigger_move.ToolchainPublish.digest_of

# The stand-in docker of make and of the probe. Each call goes to $FAKE_DOCKER/calls, as a JSON list on one line.
# `docker run ... <image> compile` is a build: it writes into the directory mounted at /out the files and the links of
# $FAKE_DOCKER/builds/<kind>-<flav>.json, prints its log, and exits with its status. <flav> is compile's FLAV of the
# run's SANITIZER. <kind> is make for make's builder (oss-verify-python-runtime/builder:<tag>), and else the image's
# tag: base or derived, for the probe's images of the fixture. `docker run ... --entrypoint find ...` prints
# $FAKE_DOCKER/find.txt. `docker run ... --entrypoint sh ...`, make's look for /opt/oft-py/prebuilt in the base image,
# exits 1 when the file $FAKE_DOCKER/prebuilt exists, else 0. pull and build exit 0.
DOCKER = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

home = pathlib.Path(os.environ["FAKE_DOCKER"])
args = sys.argv[1:]
with open(home / "calls", "a") as calls:
    calls.write(json.dumps(args) + "\n")
if args[:1] in (["pull"], ["build"]):
    sys.exit(0)
if args[:1] != ["run"]:
    sys.exit(f"the stand-in docker does not run: docker {' '.join(args)}")
if "--entrypoint" in args:
    if args[args.index("--entrypoint") + 1] == "find":
        sys.stdout.write((home / "find.txt").read_text())
        sys.exit(0)
    sys.exit(1 if (home / "prebuilt").exists() else 0)
if args[-1] != "compile":
    sys.exit(f"the stand-in docker does not run: docker {' '.join(args)}")
env = dict(args[n + 1].split("=", 1) for n, arg in enumerate(args) if arg == "-e")
mounts = {args[n + 1].split(":")[1]: args[n + 1].split(":")[0] for n, arg in enumerate(args) if arg == "-v"}
flav = {"none": "plain", "undefined": "ubsan", "address": "asan", "address-undefined": "asanubsan"}[env["SANITIZER"]]
repository, _, tag = args[-2].rpartition(":")
kind = "make" if repository.endswith("/builder") else tag
build = json.loads((home / "builds" / f"{kind}-{flav}.json").read_text())
out = pathlib.Path(mounts["/out"])
for name, text in build["files"].items():
    (out / name).parent.mkdir(parents=True, exist_ok=True)
    (out / name).write_text(text)
for name, target in build.get("links", {}).items():
    (out / name).parent.mkdir(parents=True, exist_ok=True)
    (out / name).symlink_to(target)
sys.stdout.write(build["log"])
sys.exit(build.get("status", 0))
"""


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture(autouse=True)
def has_jq():
    assert shutil.which("jq"), "jq is not on PATH: make and the probe run it"


def scripts_copy(where, *changes):
    """A copy of what make and the probe read of this tree, in `where`: .github/scripts/python-runtime/ and the
    fixture's project.yaml. Each change is (script, old, new), where old is in the script once. Return the copy's
    .github/scripts/python-runtime."""
    scripts = where / ".github/scripts/python-runtime"
    shutil.copytree(SCRIPTS, scripts, ignore=shutil.ignore_patterns("__pycache__"))
    (where / PROJECT).parent.mkdir(parents=True)
    shutil.copy2(ROOT / PROJECT, where / PROJECT)
    for script, old, new in changes:
        path = scripts / script
        text = path.read_text()
        assert text.count(old) == 1, f"{script}: the text that the control changes: {old!r}"
        path.write_text(text.replace(old, new))
    return scripts


def stand_ins(where, builds, find=""):
    """In `where`: bin/ with the stand-ins docker and crane and python3 as this interpreter, the stand-in docker's
    home with `builds` ({<kind>-<flav>: a build}) and `find`, and a runner temp. Return the environment of a script that
    runs them."""
    bin_dir, docker, runner = where / "bin", where / "docker", where / "runner"
    for directory in (bin_dir, docker / "builds", runner):
        directory.mkdir(parents=True)
    for name, text in (("docker", DOCKER), ("crane", CRANE), ("python3", f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    for name, build in builds.items():
        (docker / "builds" / f"{name}.json").write_text(json.dumps(build))
    (docker / "find.txt").write_text(find)
    (docker / "calls").write_text("")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "RUNNER_", "FAKE_"))}
    return {**env, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_DOCKER": str(docker),
            "RUNNER_TEMP": str(runner)}


def docker_calls(env):
    return [json.loads(line) for line in pathlib.Path(env["FAKE_DOCKER"], "calls").read_text().splitlines()]


# make


def make_build(flav, fault=""):
    """What build.sh stages in $OUT for the build of `flav`, and what compile prints, as the stand-in docker gives
    them, with the fault `fault`: (the build, its key). The manifest is the inputs' lines, then `key <their SHA-256>`;
    compile prints the key line, `oft-py: runtime <flav>: key <12 hex digits> in <seconds> s`, then the built line."""
    lines = f"flav {'plain' if fault == 'a manifest of another build' else flav}\nenv CFLAGS=-Os -fsanitize={flav}\n"
    key = sha256(lines)
    files = {f"prebuilt/runtime/{name}": f"{name} of the {flav} runtime\n" for name in RUNTIME_FILES
             if not (fault == "a missing runtime file" and name == "target-frozen.txt")}
    files["prebuilt/manifest"] = lines + f"key {'0' * 64 if fault == 'a false key' else key}\n"
    record = {"directory": f"/work/build/pyrt/{flav}", "output": "Python/ceval.o", "arguments": ["clang", "-c"]}
    # An empty compiles.jsonl: an absent one fails make at its copy too, with no made line.
    files[".records/compiles.jsonl"] = "" if fault == "no compile records" else json.dumps(record) + "\n"
    files[f".records/nosan/{'2' * 64}.o"] = f"the nosan object of the {flav} runtime\n"
    log = f"oft-py: runtime {flav}: key {'0' * 12 if fault == 'the key line of another key' else key[:12]} in 0.4 s\n"
    if fault != "no built line":
        log += f"oft-py: runtime {flav} built in 600 s\n"
    return {"files": files, "log": log, "status": 1 if fault == "a failed build" else 0}, key


def base_image():
    """The base image as the stand-in crane's registry holds it: (its reference by digest, the image)."""
    config = {"architecture": "amd64", "os": "linux", "config": {"Env": ["PATH=/usr/local/bin:/usr/bin:/bin"]},
              "rootfs": {"type": "layers", "diff_ids": [digest_of(["diff id", n]) for n in range(3)]}}
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 1,
                           "digest": digest_of(config)},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": n + 1,
                            "digest": digest_of(["layer", n])} for n in range(3)]}
    return f"{BASE_REPOSITORY}@{digest_of(manifest)}", {"manifest": manifest, "config": config}


# The faults of the new image (the stand-in crane's FAKE_CRANE_APPEND_FAULT, CRANE_FAULTS) and of the stand-in docker
# (make_build, and a base image that has /opt/oft-py/prebuilt): each, and the message that make fails with.
MAKE_FAULTS = {
    "a base image with a prebuilt runtime": r"^make: \S+ has /opt/oft-py/prebuilt already",
    "a failed build": r"^make: the asan build failed: compile exited 1$",
    "no built line": r"^make: the asan build printed no 'oft-py: runtime asan built in' line$",
    "a missing runtime file": r"^make: the asan build staged no \S+/out/asan/prebuilt/runtime/target-frozen\.txt$",
    "no compile records": r"^make: the asan build wrote no compile records ",
    "a false key": r"^make: the last line of the asan build's manifest is 'key 0{64}', not 'key [0-9a-f]{64}'$",
    "a manifest of another build": r"^make: the asan build's manifest is not of the asan build$",
    "the key line of another key": r"^make: the asan build printed no 'oft-py: runtime asan: key [0-9a-f]{12} in",
    "base layers reordered": r"^make: the new manifest does not name the base image's layers and then one more$",
    "last diff id": r"^make: the new image's last layer has the diff ID sha256:[0-9a-f]{64}, not layer\.tar's",
}
CRANE_FAULTS = ("base layers reordered", "last diff id")


def run_make(where, scripts=SCRIPTS, fault=""):
    """make BASE TARGET of `scripts`, in a new directory `where`, with the stand-ins, on a registry that holds the base
    image. Each build is make_build's, with `fault` in the asan build's (MAKE_FAULTS). Return what it did: its exit
    status, standard output and error, the base image, the builds with their keys, the registry after it, the calls of
    docker and of crane, and what is left in its runner temp."""
    base, image = base_image()
    builds = {flav: make_build(flav, fault if flav == FAULTY else "") for flav in FLAVS.values()}
    env = stand_ins(where, {f"make-{flav}": build for flav, (build, _) in builds.items()})
    crane = where / "crane"
    crane.mkdir()
    (crane / "registry.json").write_text(json.dumps({"images": {base: image}, "tags": {}, "made": {}}))
    env["FAKE_CRANE"] = str(crane)
    if fault in CRANE_FAULTS:
        env["FAKE_CRANE_APPEND_FAULT"] = fault
    if fault == "a base image with a prebuilt runtime":
        (where / "docker" / "prebuilt").touch()
    done = subprocess.run(["bash", str(scripts / "make"), base, TARGET], capture_output=True, text=True, env=env,
                          timeout=300)
    return SimpleNamespace(
        returncode=done.returncode, stdout=done.stdout, stderr=done.stderr, base=base, builds=builds,
        registry=json.loads((crane / "registry.json").read_text()), docker=docker_calls(env),
        crane=[json.loads(line) for line in (crane / "calls").read_text().splitlines()] if (crane / "calls").exists()
        else [], left=sorted(p.name for p in pathlib.Path(env["RUNNER_TEMP"]).iterdir()))


def layer_of(registry, ref):
    """The entries of the last layer of the image `ref` of the stand-in registry: {path: its bytes, or None for a
    directory}."""
    blob = registry["blobs"][registry["images"][ref]["manifest"]["layers"][-1]["digest"]]
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(base64.b64decode(blob)))) as archive:
        return {m.name: None if m.isdir() else archive.extractfile(m).read() for m in archive.getmembers()}


def laid_out(base, builds):
    """The tree of the layer for `builds`, as make's header lays it out: opt/oft-py/prebuilt/<flav>-<key>/ with
    runtime/ from $OUT/prebuilt, records/ from $OUT/.records, and the manifest with the line made-from BASE_IMAGE."""
    tree = {}
    for flav, (build, key) in builds.items():
        top = f"opt/oft-py/prebuilt/{flav}-{key}"
        for name, text in build["files"].items():
            if name == "prebuilt/manifest":
                tree[f"{top}/manifest"] = (text + f"made-from {base}\n").encode()
            elif name.startswith("prebuilt/runtime/"):
                tree[f"{top}/runtime/{name.removeprefix('prebuilt/runtime/')}"] = text.encode()
            else:
                tree[f"{top}/records/{name.removeprefix('.records/')}"] = text.encode()
    for path in list(tree):
        for parent in pathlib.PurePosixPath(path).parents:
            if str(parent).startswith("opt/oft-py/prebuilt"):
                tree[str(parent)] = None
    return tree


def test_make_makes_the_image_of_the_four_runtimes(tmp_path):
    """make runs the four builds in the builder FROM the base image, with no network, OV_RECORD=1 and build.sh at
    /src/build.sh; appends one layer that holds each build's runtime, records and manifest; prints last the line
    `made <repository>@sha256:<digest>` of the image at TARGET; and removes its work directory."""
    done = run_make(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    made = f"{TARGET_REPOSITORY}@{done.registry['tags'].get(TARGET)}"
    assert re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", made), done.registry["tags"]
    assert done.stdout.splitlines()[-1] == f"made {made}"
    assert layer_of(done.registry, made) == laid_out(done.base, done.builds)
    builds = [call for call in done.docker if call[:1] == ["build"]]
    assert len(builds) == 1 and f"TOOLCHAIN={done.base}" in builds[0], done.docker
    builder = builds[0][builds[0].index("-t") + 1]
    runs = [call for call in done.docker if call[-2:] == [builder, "compile"]]
    assert sorted(call[call.index("-e") + 1] for call in runs) == sorted(f"SANITIZER={s}" for s in FLAVS)
    for call in runs:
        assert {"--network=none", "OV_RECORD=1", f"{SCRIPTS}/build.sh:/src/build.sh:ro"} <= set(call), call
    appends = [call for call in done.crane if call[:1] == ["append"]]
    assert [call[:4] + call[5:] for call in appends] == [["append", "-b", done.base, "-f", "-t", TARGET]], done.crane
    assert done.left == [], "make's runner temp after it"


def make_refuses(where, scripts, fault):
    """make fails on `fault`, with no made line, and says why (MAKE_FAULTS)."""
    done = run_make(where, scripts, fault)
    made = [line for line in done.stdout.splitlines() if line.startswith("made ")]
    assert (done.returncode != 0, made) == (True, []), \
        f"make on {fault}: (it fails, its made lines):\n{done.stdout}{done.stderr}"
    assert re.search(MAKE_FAULTS[fault], done.stderr, re.M), f"make on {fault}: its errors:\n{done.stderr}"


@pytest.mark.parametrize("fault", MAKE_FAULTS)
def test_make_refuses(tmp_path, fault):
    make_refuses(tmp_path, SCRIPTS, fault)


# For each fault of MAKE_FAULTS, the check of make that finds it, and the text that takes it out.
MAKE_CHECKS = {
    "a base image with a prebuilt runtime": (
        """if ! docker run --rm --network=none --entrypoint sh "$base" -c '[ ! -e /opt/oft-py/prebuilt ]'; then""",
        "if false; then"),
    "a failed build": ('  if [ "$status" -ne 0 ]; then\n', "  if false; then\n"),
    "no built line": ('  grep -q "^oft-py: runtime $flav built in " "$work/$flav.log" ||\n', "  true ||\n"),
    "a missing runtime file": ('    [ -s "$path" ] ||', "    true ||"),
    "no compile records": ('  [ -s "$out/.records/compiles.jsonl" ] ||\n', "  true ||\n"),
    "a false key": ('  [ "$key" = "key $sum" ] ||\n', "  true ||\n"),
    "a manifest of another build": ('  [ "$(head -n 1 "$out/prebuilt/manifest")" = "flav $flav" ] ||\n',
                                    "  true ||\n"),
    "the key line of another key": (
        '  grep "^oft-py: runtime $flav: key ${sum:0:12} in [0-9]*\\.[0-9] s$" "$work/$flav.log" ||\n', "  true ||\n"),
    "base layers reordered": (" and $n[0].layers[:-1] == $b[0].layers'", "'"),
    "last diff id": ('[ "$diff_id" = "$layer" ] ||\n', "true ||\n"),
}


@pytest.mark.parametrize("fault", MAKE_CHECKS)
def test_control_make_without_its_check(tmp_path, fault):
    """make refuses `fault` from an unchanged copy of the scripts, and makes the image, with a made line, from a copy
    whose make has the check that finds it taken out (MAKE_CHECKS)."""
    old, new = MAKE_CHECKS[fault]
    make_refuses(tmp_path / "unchanged", scripts_copy(tmp_path / "unchanged-tree"), fault)
    with pytest.raises(AssertionError, match=re.escape(f"make on {fault}: (it fails, its made lines)")):
        make_refuses(tmp_path / "changed", scripts_copy(tmp_path / "changed-tree", ("make", old, new)), fault)


# probe

BASE = "ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain-python@sha256:" + "1" * 64
DERIVED = f"{TARGET_REPOSITORY}@sha256:" + "2" * 64
# The key of the runtime of each flav in the derived image.
KEYS = {flav: sha256(f"the key of the {flav} runtime") for flav in FLAVS.values()}


def took(flav):
    return (f"oft-py: runtime {flav}: took the shipped runtime (/opt/oft-py/prebuilt/{flav}-{KEYS[flav]}); ran no "
            "CPython configure or make")


def probe_build(kind, flav, fault=""):
    """What compile leaves in $OUT for the fuzz target of the fixture, on the image `kind` (base or derived), in the
    build of `flav`, and what it prints, with the fault `fault` (PROBE_FAULTS) in the asan builds. The compile records
    name two objects of the runtime: one by its working directory and a relative output, one by an absolute output. With
    no runtime record, they name objects outside /work/build/pyrt/ in the same two ways."""
    records = [{"directory": f"/work/build/pyrt/{flav}", "output": "Python/ceval.o"},
               {"directory": "/work/build/lib", "output": f"/work/build/pyrt/{flav}/Modules/getpath.o"},
               {"directory": f"/work/build/lib/{flav}/fuzz_example", "output": "harness.o"}]
    if fault == "no runtime record":
        records = [{"directory": f"/work/build/pyrt/{flav}", "output": f"/work/build/lib/{flav}/harness.o"},
                   {"directory": "/work/build/lib", "output": "pyrt/Python/ceval.o"}]
    files = {"fuzz_example": f"the fuzz target of {flav}\n", f".stripped/{'3' * 64}": f"its stripped twin, {flav}\n",
             ".records/compiles.jsonl": "".join(json.dumps(record) + "\n" for record in records),
             ".records/flags.json": json.dumps({"build": flav}) + "\n",
             f".records/{'3' * 64}/inputs.tsv": f"the link inputs of {flav}\n",
             ".records/store/liboft.a": f"liboft of {flav}\n", f".records/nosan/{'4' * 64}.o": f"nosan of {flav}\n"}
    links = {".records/store/current": "liboft.a"}
    if fault == "a file differs" and kind == "derived":
        files[".records/store/liboft.a"] += "a byte more\n"
    if fault == "an empty base $OUT" and kind == "base":
        files, links = {}, {}
    if fault == "no flags.json":
        del files[".records/flags.json"]
    if fault == "no stripped fuzz target":
        del files[f".stripped/{'3' * 64}"]
    log = f"oft-py: runtime {flav}: key {KEYS[flav][:12]} in 0.4 s\n"
    log += f"oft-py: runtime {flav} built in 600 s\n" if kind == "base" else took(flav) + "\n"
    if fault == "a derived build that built its own" and kind == "derived":
        # It printed the took line too, so that only the check of the built line sees it.
        log += f"oft-py: runtime {flav} built in 600 s\n"
    return {"files": files, "links": links, "log": log}


def found_prebuilt():
    """What find prints of /opt/oft-py/prebuilt of the derived image: a directory <flav>-<key> of each flav, with
    runtime/libpython3.11.a, records/compiles.jsonl and manifest."""
    lines = []
    for flav, key in KEYS.items():
        top = f"/opt/oft-py/prebuilt/{flav}-{key}"
        lines += [top, f"{top}/runtime", f"{top}/runtime/libpython3.11.a", f"{top}/records",
                  f"{top}/records/compiles.jsonl", f"{top}/manifest"]
    return "".join(line + "\n" for line in lines)


def run_probe(where, scripts=SCRIPTS, fault=""):
    """probe BASE DERIVED of `scripts`, in a new directory `where`, with the stand-in docker, whose builds are
    probe_build's, with `fault`. Return (its exit status, what it printed, the calls of docker)."""
    builds = {f"{kind}-{flav}": probe_build(kind, flav, fault if flav == FAULTY else "")
              for kind in ("base", "derived") for flav in FLAVS.values()}
    env = stand_ins(where, builds, found_prebuilt())
    done = subprocess.run(["bash", str(scripts / "probe"), BASE, DERIVED], capture_output=True, text=True, env=env,
                          timeout=300)
    return done.returncode, done.stdout + done.stderr, docker_calls(env)


def test_the_probe_passes_when_each_build_gives_the_same_files_on_both_images(tmp_path):
    """The probe builds the builder FROM the base image, then FROM the derived image, and passes. Its table has a row
    for each flav: the directory of the shipped runtime, the built line on the base image, the two records of the
    runtime, and every file and link under $OUT the same on both images, by their number."""
    rc, printed, calls = run_probe(tmp_path)
    assert rc == 0, printed
    assert [c[c.index("--build-arg") + 1] for c in calls if c[:1] == ["build"] and "TOOLCHAIN=" in str(c)] == \
        [f"TOOLCHAIN={BASE}", f"TOOLCHAIN={DERIVED}"]
    build = probe_build("base", "plain")
    count = len(build["files"]) + len(build["links"])
    for flav, key in KEYS.items():
        assert f"| {flav} | `{flav}-{key}` | built in 600 s | 2 | same, {count} |" in printed.splitlines(), printed


# The faults of the probe's builds, and the lines that the probe must print for each.
PROBE_FAULTS = {
    "a file differs": [
        "asan: the files under $OUT, by SHA-256, that differ (< base image, > derived image)",
        f"< {sha256('liboft of asan' + chr(10))}  ./.records/store/liboft.a",
        f"> {sha256('liboft of asan' + chr(10) + 'a byte more' + chr(10))}  ./.records/store/liboft.a"],
    "an empty base $OUT": [
        "- asan: the build on the base image left no fuzz_example, or an empty one, in $OUT",
        "- asan: the build on the base image left no .records/compiles.jsonl, or an empty one, in $OUT",
        "- asan: the build on the base image left no .records/flags.json, or an empty one, in $OUT",
        "- asan: the build on the base image left no stripped fuzz target in $OUT/.stripped",
        "- asan: the build on the base image left no compile record of an object under /work/build/pyrt/",
        "asan: the files under $OUT, by SHA-256, that differ (< base image, > derived image)"],
    "no flags.json": [
        "- asan: the build on the base image left no .records/flags.json, or an empty one, in $OUT",
        "- asan: the build on the derived image left no .records/flags.json, or an empty one, in $OUT"],
    "no stripped fuzz target": [
        "- asan: the build on the base image left no stripped fuzz target in $OUT/.stripped"],
    "no runtime record": [
        "- asan: the build on the base image left no compile record of an object under /work/build/pyrt/"],
    "a derived build that built its own": [
        "- asan: the build on the derived image built its own runtime: oft-py: runtime asan built in 600 s"],
}


def probe_refuses(where, scripts, fault):
    """The probe fails on `fault`, and prints each line of PROBE_FAULTS for it."""
    rc, printed, _ = run_probe(where, scripts, fault)
    assert rc != 0, f"probe on {fault}: it fails:\n{printed}"
    lines = printed.splitlines()
    assert [line for line in PROBE_FAULTS[fault] if line not in lines] == [], \
        f"probe on {fault}: the lines it must print that it did not:\n{printed}"


@pytest.mark.parametrize("fault", PROBE_FAULTS)
def test_the_probe_refuses(tmp_path, fault):
    probe_refuses(tmp_path, SCRIPTS, fault)


# Checks of the probe, each with a fault that it alone finds (on both images alike, but for the comparison's) and the
# text that takes it out.
PROBE_CHECKS = {
    "the comparison of every file": ("a file differs", '  part "$flav" files "the files under \\$OUT, by SHA-256,"\n',
                                     '  REPLY="same, 0"\n'),
    "the files that each $OUT must hold": ("no flags.json", '      [ -s "$out/$file" ] ||\n', "      true ||\n"),
    "a stripped fuzz target": ("no stripped fuzz target",
                               """  [ "$(grep -c '  \\./\\.stripped/' "$work/cmp/base-$flav.files" || true)" """
                               """-gt 0 ] ||\n""",
                               "  true ||\n"),
    "a record of the runtime": ("no runtime record", '  [ "$runtime" -gt 0 ] ||\n', "  true ||\n"),
    "the built line on the derived image": (
        "a derived build that built its own",
        '  if grep -E "^oft-py: runtime $flav built in " "$work/log/derived-$flav.txt" > "$work/built.txt"; then\n',
        "  if false; then\n"),
}


@pytest.mark.parametrize("check", PROBE_CHECKS)
def test_control_probe_without_its_check(tmp_path, check):
    """The probe refuses the fault of `check` from an unchanged copy of the scripts, and passes it, exiting 0, from a
    copy whose probe has that check taken out (PROBE_CHECKS): no other check finds that fault."""
    fault, old, new = PROBE_CHECKS[check]
    probe_refuses(tmp_path / "unchanged", scripts_copy(tmp_path / "unchanged-tree"), fault)
    rc, printed, _ = run_probe(tmp_path / "changed", scripts_copy(tmp_path / "changed-tree", ("probe", old, new)), fault)
    assert rc == 0, f"probe without {check}, on {fault}:\n{printed}"
