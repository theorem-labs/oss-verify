/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * MAX_INPUT, the input limit of cli.c: the driver refuses an input of MAX_INPUT bytes or more.
 *
 * With no OV_MAX_INPUT_LOG2, MAX_INPUT is 64 MiB, as in the release recipe. A fuzz target's build can set
 * OV_MAX_INPUT_LOG2 to 27, 28, 29, 30 or 31 (docs/build-contract.md). compile then builds cli.c with
 * -DOV_MAX_INPUT_LOG2=<value>, and MAX_INPUT is 2 to the power of that value. cli.c doubles its buffer from 64 KiB,
 * so a limit must be a power of two. 31 is the largest value whose refusal message fits %u.
 */
#ifndef INPUT_LIMIT_H
#define INPUT_LIMIT_H

#ifndef OV_MAX_INPUT_LOG2
#define MAX_INPUT (64u << 20)
#else
#if OV_MAX_INPUT_LOG2 < 27 || OV_MAX_INPUT_LOG2 > 31
#error "OV_MAX_INPUT_LOG2 must be 27, 28, 29, 30 or 31"
#endif
#define MAX_INPUT (1u << OV_MAX_INPUT_LOG2)
#endif

#endif
