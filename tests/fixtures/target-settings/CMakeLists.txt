# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The library of the test project: one static library, which each fuzz target calls.
cmake_minimum_required(VERSION 3.16)
project(fxs C)
add_library(fxs STATIC fxs.c)
