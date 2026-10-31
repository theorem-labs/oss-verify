// OSS Verify fuzz target for THORNode's memo parser. build.sh copies this file into ossverify/memo in the THORNode
// checkout.
//
// Copyright (c) THORChain contributors. SPDX-License-Identifier: Apache-2.0
//
// Every inbound transaction carries a memo that its sender writes, and THORChain parses it in consensus. It is
// THORNode's fuzz target FuzzParseMemo (x/thorchain/memo/memo_security_fuzz_test.go), with these changes for OSS
// Verify: it is a go-fuzz function, which needs no testing shim; it gives the version as common.LatestVersion, because
// types.GetCurrentVersion reads the version file through the source path and the build uses -trimpath; a long input returns in place of t.Skip; and it drops the second
// parse, because the OSS Verify runtime is deterministic, so the two parses cannot differ.
package ossverifymemo

import (
	"fmt"
	"strings"

	"gitlab.com/thorchain/thornode/v3/common"
	memo "gitlab.com/thorchain/thornode/v3/x/thorchain/memo"
)

// maxMemo bounds the memo. THORChain refuses a memo of more than 250 bytes on most chains, and of more than 512 on any.
const maxMemo = 512

// panicPrefix is the text of the error that ParseMemo returns when it recovers from a panic of its parsers
// (errMemoPanic, x/thorchain/memo/memo.go): "panicked parsing memo(<memo>), err: <panic>".
const panicPrefix = "panicked parsing memo("

func FuzzParseMemo(data []byte) int {
	if len(data) > maxMemo {
		return 0
	}
	raw := string(data)
	// A reference memo ("reference:<memo>") parses the memo it embeds through the keeper, which ParseMemo does not
	// have: with no keeper, that is a nil pointer load, which the OSS Verify runtime does not recover. THORChain always
	// parses a reference memo with its keeper, so such a memo is outside this target. The type is read as
	// newParser reads it (x/thorchain/memo/memo_parser.go).
	if typ, err := memo.StringToTxType(strings.Split(strings.Split(raw, "|")[0], ":")[0]); err == nil &&
		typ == memo.TxReferenceWriteMemo {
		return 0
	}
	parsed, err := memo.ParseMemo(common.LatestVersion, raw)
	if err != nil {
		// Property: no parser panics. ParseMemo recovers each panic into an error, so a plain "does not panic"
		// statement would hold for a parser that panics on every memo.
		// Mutant: remove the `len(p.parts) <= idx` bound in parser.get (x/thorchain/memo/memo_parser.go); input
		// "SWAP".
		if strings.HasPrefix(err.Error(), panicPrefix+raw+"), err: ") {
			fail("memo parser panicked for %q: %v", raw, err)
		}
		return 0
	}
	// The queries that handlers run on a parsed memo must not panic.
	_ = parsed.String()
	_ = parsed.GetAmount()
	_ = parsed.GetDestination()
	_ = parsed.GetSlipLimit()
	_ = parsed.GetTxID()
	_ = parsed.GetAccAddress()
	_ = parsed.GetBlockHeight()
	_ = parsed.GetDexAggregator()
	_ = parsed.GetDexTargetAddress()
	_ = parsed.GetDexTargetLimit()
	_ = parsed.GetAffiliateTHORName()
	_ = parsed.GetRefundAddress()
	_ = parsed.GetAffiliates()
	_ = parsed.GetAffiliatesBasisPoints()
	return 0
}

// fail stops the fuzz target: a panic, which exits with status 79.
func fail(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}
