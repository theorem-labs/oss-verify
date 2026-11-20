// OSS Verify fuzz targets for the decoders of external-chain data in THORNode's Bifrost: Zcash transactions and
// addresses, SS58 addresses, and the Solana RPC version field. build.sh copies this file into ossverify/chains in the
// THORNode checkout.
//
// Copyright (c) THORChain contributors. SPDX-License-Identifier: Apache-2.0
//
// Bifrost reads these bytes from external chains and their RPC nodes, and an attacker who sends a transaction to a
// vault controls them. A panic stops the observer or signer of each node that reads the same block, so it halts that
// chain for THORChain. A failure here is a panic (exit status 79) or a failed property (fail, also a panic). A
// rejected input is the expected outcome for malformed data and ends the call normally.
package ossverifychains

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"gitlab.com/thorchain/thornode/v3/bifrost/pkg/chainclients/solana/rpc"
	"gitlab.com/thorchain/thornode/v3/bifrost/pkg/chainclients/utxo/zcash"
	"gitlab.com/thorchain/thornode/v3/common/crypto/ss58"
)

// maxTx bounds a transaction payload. It is larger than each transparent payment that Bifrost signs or observes.
const maxTx = 64 << 10

// maxText bounds an address or an RPC field.
const maxText = 1024

// FuzzZcashParseTx checks zcash.ParseTx, which decodes the raw transparent transactions that Bifrost reads back from
// zcashd and from its own signed checkpoints.
func FuzzZcashParseTx(data []byte) int {
	if len(data) > maxTx {
		return 0
	}
	tx, err := zcash.ParseTx(data)
	if err != nil {
		return 0
	}
	// Property: an accepted transaction serializes to exactly its input. The signer resumes a saved payload by
	// parsing it and serializing it again, so any change would broadcast a different transaction than it signed.
	// Mutant: drop the `bodyReader.Len() != 0` check in ParseTx; input the last v6 vector of
	// bifrost/pkg/chainclients/utxo/zcash/testdata/v6/vectors.json with a 0x00 byte inserted before its
	// four-byte empty-bundle tail (seed corpus file seed08).
	var out bytes.Buffer
	if err := tx.Serialize(&out); err != nil {
		fail("accepted transaction does not serialize: %v", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		fail("transaction changed on round trip:\n in  %x\n out %x", data, out.Bytes())
	}
	// The hashes of an accepted transaction must not panic.
	_ = tx.TxHash()
	return 0
}

// FuzzZcashDecodeAddress checks zcash.DecodeAddress, which validates the ZEC destination of each outbound, for each
// network.
func FuzzZcashDecodeAddress(data []byte) int {
	if len(data) == 0 || len(data) > maxText {
		return 0
	}
	// The first byte selects the network, so that each network's prefixes are explored.
	network := []string{"mainnet", "testnet3", "regtest", "unsupported"}[int(data[0])%4]
	text := string(data[1:])
	addr, err := zcash.DecodeAddress(text, network)
	if err != nil {
		return 0
	}
	// Property: an accepted address has a script, and its canonical text decodes to the same hash and the same
	// script. A TEX address becomes its transparent form, so the hash and the script are what must not change:
	// the signer pays to this script.
	// Mutant: copy(a.hash[:], hash[1:]) in DecodeAddress; input "\x00t1bgJzZzNhbXEgFcRo9XmJHdLadhEAbzFbh".
	again, err := zcash.DecodeAddress(addr.String(), network)
	if err != nil {
		fail("canonical address %q of %q does not decode: %v", addr, text, err)
	}
	if !bytes.Equal(again.ScriptAddress(), addr.ScriptAddress()) {
		fail("address %q changed hash on round trip", text)
	}
	script, err := addr.Script()
	if err != nil {
		fail("accepted address %q has no script: %v", text, err)
	}
	againScript, err := again.Script()
	if err != nil || !bytes.Equal(script, againScript) {
		fail("address %q changed script on round trip", text)
	}
	return 0
}

// FuzzSS58 checks ss58.Decode, which validates SS58 (Polkadot and Bittensor) addresses.
func FuzzSS58(data []byte) int {
	if len(data) > maxText {
		return 0
	}
	text := string(data)
	prefix, pubkey, err := ss58.Decode(text)
	if err != nil {
		return 0
	}
	// Property: an accepted address is the encoding of its prefix and public key. If two texts decoded to one key,
	// two spellings of one destination would compare unequal.
	// Mutant: skip the checksum comparison in Decode; input "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694tz".
	encoded, err := ss58.Encode(prefix, pubkey)
	if err != nil {
		fail("decoded key of %q does not encode: %v", text, err)
	}
	if encoded != text {
		fail("address %q encodes back as %q", text, encoded)
	}
	return 0
}

// FuzzSolanaRPCVersion checks the JSON decoding of the version field in Solana RPC responses. It is the fuzz target
// FuzzRPCVersion of THORNode (bifrost/pkg/chainclients/solana/rpc/rpc_version_fuzz_test.go), with these changes for
// OSS Verify: it is a go-fuzz function, which needs no testing shim, and a long input returns in place of t.Skip.
func FuzzSolanaRPCVersion(raw []byte) int {
	if len(raw) > maxText {
		return 0
	}
	var version rpc.RPCVersion
	err := version.UnmarshalJSON(raw)
	// Property: JSON null is not a version. A null decoded as version 0 would select the legacy transaction
	// format.
	// Mutant: compare with []byte("nul") in place of []byte("null") in RPCVersion.UnmarshalJSON; input "null".
	if string(raw) == "null" && err == nil {
		fail("accepted null RPC version as numeric zero")
	}
	if err != nil {
		return 0
	}
	// Property: an accepted version is the JSON string, or the decimal text of the JSON integer.
	// Mutant: use strconv.Itoa(num + 1) in RPCVersion.UnmarshalJSON; input "42".
	var str string
	if len(raw) > 0 && raw[0] == '"' {
		if json.Unmarshal(raw, &str) != nil || version.Value != str {
			fail("accepted inconsistent string version %q", raw)
		}
		return 0
	}
	var num int
	if json.Unmarshal(raw, &num) != nil || version.Value != strconv.Itoa(num) {
		fail("accepted inconsistent numeric version %q", raw)
	}
	return 0
}

// fail stops the fuzz target: a panic, which exits with status 79.
func fail(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}
