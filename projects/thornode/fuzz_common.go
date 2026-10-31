// OSS Verify fuzz targets for THORNode's common package: address parsing, asset parsing and the share arithmetic
// that pool, LP and fee accounting use. build.sh copies this file into ossverify/common in the THORNode checkout.
//
// Copyright (c) THORChain contributors. SPDX-License-Identifier: Apache-2.0
//
// THORNode is a blockchain state machine. Every validator runs the same code on the same input, and a panic in a
// block's BeginBlock or EndBlock halts the chain. These parsers read strings from user-sent memos and from external
// chains, so an attacker controls every byte that reaches them. A failure here is a panic (exit status 79) or a
// failed property (fail, also a panic). A rejected input is the expected outcome for malformed text and ends the
// call normally, with the return value 0.
package ossverifycommon

import (
	"fmt"
	"math/big"
	"strings"

	"gitlab.com/thorchain/thornode/v3/common"
	"gitlab.com/thorchain/thornode/v3/common/cosmos"
)

// maxText bounds the text inputs. THORChain memos are at most a few hundred bytes, and an address or an asset is a
// field of one.
const maxText = 1024

// FuzzNewAddress checks common.NewAddress, which parses the destination and affiliate addresses of every memo, for each
// chain that THORChain supports.
func FuzzNewAddress(data []byte) int {
	if len(data) > maxText {
		return 0
	}
	input := string(data)
	addr, err := common.NewAddress(input)
	if err != nil {
		// Property: a rejected address is the empty address, so that no caller acts on a partly parsed value.
		// Mutant: return Address(address) with the error of NewAddress's alphaNumRegex check; input " T ".
		if addr != common.NoAddress {
			fail("rejected address returned %q", addr)
		}
		return 0
	}
	// Property: an accepted address is the input itself. Consensus stores and compares the text, so a parse that
	// rewrote it would make two spellings of one address unequal.
	// Mutant: return Address(strings.ToLower(address)) in NewAddress's eth.IsHexAddress case; input
	// "0x90F2b1ae50e6018230e90a33f98c7844a0ab635a".
	if addr.String() != input {
		fail("address changed on parse: %q -> %q", input, addr)
	}
	// Property: an accepted address holds only letters, digits, '_' and ':' (the prefix of a CashAddr, as in
	// "bitcoincash:q..."). Memos, logs and events carry addresses as text, so whitespace, a control character or
	// other punctuation must never get through. bech32.Decode alone accepts any printable ASCII in the HRP.
	// Mutant: remove NewAddress's alphaNumRegex check; input "a!b1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvfe0kv".
	if strings.IndexFunc(input, func(r rune) bool {
		return !(r == ':' || r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) >= 0 {
		fail("accepted character outside [:_A-Za-z0-9] in %q", input)
	}
	// The chain queries of an accepted address run on every outbound. They must not panic, whatever the
	// address is.
	for _, chain := range []common.Chain{
		common.THORChain, common.BTCChain, common.ETHChain, common.BCHChain, common.LTCChain, common.DOGEChain,
		common.GAIAChain, common.AVAXChain, common.BSCChain, common.BASEChain, common.TRONChain, common.XRPChain,
		common.SOLChain, common.ZECChain,
	} {
		_ = addr.IsChain(chain)
		_ = addr.GetNetwork(chain)
	}
	return 0
}

// FuzzNewAsset checks common.NewAsset and its short-code form, which parse the asset of every swap, add and withdraw
// memo.
func FuzzNewAsset(data []byte) int {
	if len(data) > maxText {
		return 0
	}
	input := string(data)
	asset, err := common.NewAssetWithShortCodes(common.LatestVersion, input)
	if err != nil {
		// Property: a rejected asset is the empty asset.
		// Mutant: return asset, err in NewAsset's NewTicker check; input "BTC.-" (empty ticker).
		if !asset.Equals(common.EmptyAsset) {
			fail("rejected asset returned %q", asset)
		}
		return 0
	}
	// Property: the text of an accepted asset parses back to the same asset. Pools, vaults and balances are
	// keyed by this text, so a second spelling would split one asset into two.
	// Mutant: write "." for every divider in Asset.String; input "BTC~BTC".
	again, err := common.NewAsset(asset.String())
	if err != nil || !again.Equals(asset) {
		fail("asset %q (from %q) does not parse back: %q, %v", asset, input, again, err)
	}
	// Property: an asset is at most one of synth, trade and secured.
	// Mutant: also set asset.Synth in the "~" case of NewAsset; input "BTC~BTC".
	kinds := 0
	for _, kind := range []bool{asset.Synth, asset.Trade, asset.Secured} {
		if kind {
			kinds++
		}
	}
	if kinds > 1 {
		fail("asset %q is more than one kind", asset)
	}
	// The asset queries that handlers run on a parsed asset must not panic.
	_ = asset.Valid()
	_ = asset.GetLayer1Asset()
	_ = asset.GetSyntheticAsset()
	_ = asset.GetTradeAsset()
	_ = asset.GetSecuredAsset()
	_ = asset.IsGasAsset()
	_ = asset.IsNative()
	_ = asset.ShortCode()
	_ = asset.Chain.GetGasAsset()
	return 0
}

// maxUintBytes is the width of a cosmos.Uint: a value of more than 256 bits panics at its construction.
const maxUintBytes = 32

// takeUint reads a length byte and that many big-endian bytes, and gives a value of at most 256 bits. The decoding is
// total: a short input gives the bytes that are left.
func takeUint(data []byte) (*big.Int, []byte) {
	if len(data) == 0 {
		return new(big.Int), data
	}
	n := int(data[0]) % (maxUintBytes + 1)
	data = data[1:]
	if n > len(data) {
		n = len(data)
	}
	return new(big.Int).SetBytes(data[:n]), data[n:]
}

// share is the reference for GetUncappedShare: allocation * part / total, rounded half up, and 0 when an operand is 0.
func share(part, total, allocation *big.Int) *big.Int {
	if part.Sign() == 0 || total.Sign() == 0 || allocation.Sign() == 0 {
		return new(big.Int)
	}
	num := new(big.Int).Mul(allocation, part)
	num.Add(num, new(big.Int).Rsh(total, 1))
	return num.Quo(num, total)
}

// FuzzShareMath checks GetSafeShare, GetUncappedShare and SafeSub against a math/big reference, for all operands of up
// to 256 bits. These functions divide pools, LP units, fees and rewards in every block, so a wrong result moves funds
// and a panic halts the chain.
func FuzzShareMath(data []byte) int {
	p, data := takeUint(data)
	tot, data := takeUint(data)
	a, _ := takeUint(data)
	part, total, allocation := cosmos.NewUintFromBigInt(p), cosmos.NewUintFromBigInt(tot), cosmos.NewUintFromBigInt(a)

	// Property: GetSafeShare caps part at total, and is then the rounded share. It never panics, and it never
	// gives more than the allocation, for each operand that a cosmos.Uint can hold.
	// Mutant: remove the `part = total` cap in GetSafeShare; input part=2, total=1, allocation=1.
	capped := p
	if p.Cmp(tot) > 0 {
		capped = tot
	}
	safe := common.GetSafeShare(part, total, allocation)
	if want := share(capped, tot, a); safe.BigInt().Cmp(want) != 0 {
		fail("GetSafeShare(%s, %s, %s) = %s, want %s", part, total, allocation, safe, want)
	}
	if safe.GT(allocation) {
		fail("GetSafeShare(%s, %s, %s) = %s, more than the allocation", part, total, allocation, safe)
	}

	// Property: GetUncappedShare is the rounded share whenever that share fits in a cosmos.Uint. A larger share
	// is outside the domain of the property: callers give part <= total or a small ratio.
	// Mutant: add `if part.GT(total) { return allocation }` to GetUncappedShare; input part=2, total=1,
	// allocation=1 (GetSafeShare caps part first, so only this property sees it).
	if want := share(p, tot, a); want.BitLen() <= 8*maxUintBytes {
		if got := common.GetUncappedShare(part, total, allocation); got.BigInt().Cmp(want) != 0 {
			fail("GetUncappedShare(%s, %s, %s) = %s, want %s", part, total, allocation, got, want)
		}
	}

	// Property: SafeSub is a - b, or 0 when b > a. It never panics.
	// Mutant: return input1 in place of cosmos.ZeroUint() in SafeSub; input part=1, total=2.
	want := new(big.Int).Sub(p, tot)
	if want.Sign() < 0 {
		want.SetInt64(0)
	}
	if got := common.SafeSub(part, total); got.BigInt().Cmp(want) != 0 {
		fail("SafeSub(%s, %s) = %s, want %s", part, total, got, want)
	}
	return 0
}

// fail stops the fuzz target: a panic, which exits with status 79.
func fail(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}
