#!/bin/bash -eu
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# Builds the fixture's one Go fuzz target with OSS-Fuzz's helper for a go-fuzz Fuzz function.
compile_go_fuzzer example.com/example Fuzz example_fuzzer
