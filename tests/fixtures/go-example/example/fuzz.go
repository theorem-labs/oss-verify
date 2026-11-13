// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

// Package example is a Go fuzz target whose payload's first byte chooses what it does (test_builder.py, GO_EXPECTED).
package example

import "os"

var table map[string]int

func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	switch data[0] {
	case 'p':
		panic("the fixture panics")
	case 'n':
		// A write to a nil map: a runtime error, which panics.
		table["x"] = 1
	case 's':
		// A load through a nil pointer: the runtime installs no signal handler, so a segmentation fault ends the
		// program.
		var p *int
		return *p
	case 'M':
		// More than the runtime's limit for one allocation (1<<48 bytes): a panic, which asks the system for nothing.
		big := make([]byte, 1<<49+int(data[0]))
		return int(big[0])
	case 'x':
		os.Exit(3)
	case 'd':
		// No other goroutine: the runtime stops the program with a fatal error.
		select {}
	case 'r':
		return -1
	}
	return 1
}
