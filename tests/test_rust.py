# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for infra/base-builder/rust/gen-shim.py, which need no Docker:  python3 -m pytest tests

It writes the static library crate of one cargo-fuzz [[bin]] of tests/fixtures/rust-example's crate.
It also runs the crates line of infra/base-builder/lay-out-sources with a stand-in cargo.
"""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

TESTS = pathlib.Path(__file__).resolve().parent
RUST = TESTS.parent / "infra" / "base-builder" / "rust"
CRATE = TESTS / "fixtures" / "rust-example" / "crate"
LOADER = importlib.machinery.SourceFileLoader("lay_out_sources", str(RUST.parent / "lay-out-sources"))
SPEC = importlib.util.spec_from_loader("lay_out_sources", LOADER)
lay_out_sources = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(lay_out_sources)


def gen_shim(src, out, *more):
    return subprocess.run([sys.executable, str(RUST / "gen-shim.py"), "--src", str(src), "--fuzz-dir", "fuzz",
                           "--bin", "example_fuzzer", "--out", str(out), "--rt", "/tmp/oft-rust/oft-rust-rt", *more],
                          capture_output=True, text=True)


class GenShim(unittest.TestCase):
    def test_the_shim(self):
        with tempfile.TemporaryDirectory() as scratch:
            src, out = pathlib.Path(scratch) / "src", pathlib.Path(scratch) / "shim"
            shutil.copytree(CRATE, src)
            (src / ".oft-scratch-copy").touch()
            done = gen_shim(src, out, "--profile-env", "CARGO_PROFILE_RELEASE_LTO=false")
            self.assertEqual(done.returncode, 0, done.stderr)
            manifest = tomllib.loads((out / "Cargo.toml").read_text())
            # The package names are those of each project's Cargo.lock; the library is "oft", a static library.
            self.assertEqual(manifest["package"]["name"], "oft-rust-shim")
            self.assertEqual(manifest["lib"], {"name": "oft", "crate-type": ["staticlib"],
                                               "path": str(src / "fuzz/fuzz_targets/oft_shim_example_fuzzer.rs"),
                                               "test": False, "doctest": False})
            self.assertEqual(manifest["dependencies"]["oft-rust-rt"], {"path": "/tmp/oft-rust/oft-rust-rt"})
            self.assertEqual(manifest["dependencies"]["example"], {"path": str(src)})
            self.assertEqual(manifest["dependencies"]["libfuzzer-sys"], "=0.4.10")
            self.assertEqual(manifest["profile"]["release"], {"lto": False, "panic": "abort", "debug": False})
            self.assertIn("workspace", manifest)
            # The library's root is the bin's source, without #![no_main], with the adapter's Rust half linked.
            root = (src / "fuzz/fuzz_targets/oft_shim_example_fuzzer.rs").read_text()
            self.assertNotIn("#![no_main]", root)
            self.assertTrue(root.endswith("extern crate oft_rust_rt as _;\n"))
            self.assertTrue(root.startswith((CRATE / "fuzz/fuzz_targets/example_fuzzer.rs").read_text()
                                            .replace("#![no_main]\n", "").rstrip("\n")))
            record = json.loads((out / "shim.json").read_text())
            self.assertEqual((record["bin"], record["no_main_lines"]), ("example_fuzzer", 1))

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as scratch:
            src, out = pathlib.Path(scratch) / "src", pathlib.Path(scratch) / "shim"
            shutil.copytree(CRATE, src)
            # A tree that is not marked as a scratch copy is never written into.
            done = gen_shim(src, out)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("scratch", done.stderr)
            (src / ".oft-scratch-copy").touch()
            done = gen_shim(src, out, "--profile-env", "CARGO_PROFILE_RELEASE_PANIC=unwind")
            self.assertEqual(done.returncode, 3)
            self.assertIn("REFUSED(profile-env-panic)", done.stderr)
            (src / "fuzz" / "build.rs").write_text("fn main() {}\n")
            done = gen_shim(src, out)
            self.assertEqual(done.returncode, 3)
            self.assertIn("REFUSED(fuzz-package-build-script)", done.stderr)


class Crates(unittest.TestCase):
    def test_a_failed_cargo_vendor_says_why(self):
        # lay-out-sources captures what cargo vendor prints, so the reason a vendoring failed (such as a lock that is
        # not the shim package's) reaches the build log only through its error message
        reason = "error: the lock file shim/Cargo.lock needs to be updated but --locked was passed to prevent this"
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            root, bin_dir, sources = scratch / "root", scratch / "bin", scratch / "sources"
            shutil.copytree(CRATE, root / "src")
            shutil.copy(CRATE.parent / "Cargo.lock", root / "Cargo.lock")
            bin_dir.mkdir()
            (bin_dir / "cargo").write_text(f"#!/bin/sh\necho '{reason}' >&2\nexit 101\n")
            (bin_dir / "cargo").chmod(0o755)
            sources.write_text("crates\tvendor\tCargo.lock\tsrc\tfuzz\texample_fuzzer\n")
            with (mock.patch.object(lay_out_sources, "RUST", RUST),
                  mock.patch.object(sys, "argv", ["lay-out-sources", str(sources), str(root)]),
                  mock.patch.dict(os.environ, {"PATH": f"{bin_dir}:{os.environ['PATH']}"}),
                  self.assertRaises(SystemExit) as stopped):
                lay_out_sources.main()
        said = str(stopped.exception.code)
        self.assertTrue(said.startswith(f"lay-out-sources: {sources}:1: "), said)
        self.assertIn("returned non-zero exit status 101.\n" + reason, said)


if __name__ == "__main__":
    unittest.main()
