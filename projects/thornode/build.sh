#!/bin/bash -eu
# THORNode's fuzz targets for OSS Verify, in the form of an OSS-Fuzz Go build.sh.
#
# Copyright (c) THORChain contributors. SPDX-License-Identifier: Apache-2.0
#
# The fuzz targets are go-fuzz functions, Fuzz(data []byte) int, in three packages that this script adds to the
# checkout, so that each binary links only the code that its fuzz target calls. compile_go_fuzzer builds them with no
# shim (a testing.F shim makes a temporary directory on each call) and adds no module to THORNode's go.mod. A build
# without tags uses the mainnet variants of the files that have _mainnet and _mocknet forms.

# use_module_with MODULE FILE OLD NEW: build with a copy of MODULE in which FILE has the line NEW in place of the line
# OLD. It stops the build if FILE no longer has the line OLD, so that a new version of MODULE is looked at again.
use_module_with() {
  local module=$1 file=$2 old=$3 new=$4 copy
  copy=ossverify/mod/$(echo "$module" | tr / _)
  if [ ! -d "$copy" ]; then
    go mod download "$module"
    mkdir -p ossverify/mod
    cp -R "$(go list -m -f '{{.Dir}}' "$module")" "$copy"
    chmod -R u+w "$copy"
    go mod edit -replace "$module=./$copy"
  fi
  python3 - "$copy/$file" "$old" "$new" <<'EOF'
import sys
path, old, new = sys.argv[1:]
lines = open(path).read().split("\n")
if lines.count(old) != 1:
    sys.exit(f"build.sh: {path} does not have the line {old!r} exactly once")
lines[lines.index(old)] = new
open(path, "w").write("\n".join(lines))
EOF
}

# The packages that THORNode's consensus code imports probe the machine and the desktop session when the program
# starts, before the fuzz target runs. The model of the proofs has none of these files, devices or services, so each
# probe would leave the run unmodeled. The build takes each probe's answer for a machine without them; no code that a
# fuzz target calls changes.

# golang.org/x/sys/cpu reads /proc/self/auxv and calls riscv_hwprobe to find the CPU's extensions. Without them, every
# extension is absent. This also drops readVLENB's csrr vlenb, an instruction the model does not have.
use_module_with golang.org/x/sys cpu/cpu_linux.go \
  $'\tif err := readHWCAP(); err != nil {' \
  $'\tif true { // build.sh: no /proc/self/auxv and no riscv_hwprobe in the model, so no extension is detected'

# google.golang.org/protobuf/internal/detrand hashes samples of the program's own file (/proc/self/exe), to vary the
# whitespace of its text and JSON output between binaries. The seed 0 is the one it takes when the file cannot be read.
use_module_with google.golang.org/protobuf internal/detrand/rand.go \
  'var randSeed = binaryHash()' \
  'var randSeed = uint64(0) // build.sh: binaryHash reads /proc/self/exe, which the model does not have'

# github.com/99designs/keyring (THORNode's go.mod replaces it with github.com/cosmos/keyring) connects to the D-Bus
# session bus to offer the Secret Service and KWallet backends. They are not offered when there is no bus.
use_module_with github.com/99designs/keyring secretservice.go \
  $'\t_, err := dbus.SessionBus()' \
  $'\terr := dbus.ErrClosed // build.sh: no D-Bus session bus in the model'
use_module_with github.com/99designs/keyring kwallet.go \
  $'\t_, err := dbus.SessionBus()' \
  $'\terr := dbus.ErrClosed // build.sh: no D-Bus session bus in the model'

# github.com/bytedance/sonic writes a warning on standard error when it starts on riscv64, where it uses
# encoding/json. It is the only thing the programs write before the fuzz target runs.
use_module_with github.com/bytedance/sonic internal/compat/warn.go \
  '    fmt.Fprintf(os.Stderr, "WARNING: %s only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json\n", prefix)' \
  '    if false { fmt.Fprintf(os.Stderr, "%s", prefix) } // build.sh: no warning on standard error'

# cosmossdk.io/math/unsafe and github.com/cometbft/cometbft/libs/rand seed a test-helper generator from crypto/rand
# when they start. The first read of crypto/rand starts a one-minute timer (the warning that the read is blocked), and
# the first timer starts the runtime's network poller, whose epoll and eventfd the model does not have. The generators
# take the seed 0.
for module in cosmossdk.io/math:unsafe/rand.go github.com/cometbft/cometbft:libs/rand/random.go; do
  use_module_with "${module%%:*}" "${module#*:}" \
    $'\tbz := cRandBytes(8)' \
    $'\tbz := make([]byte, 8) // build.sh: no crypto/rand read (and so no timer) when the program starts'
done

# github.com/getsentry/sentry-go makes its default hub when it starts, whose scope takes a trace and span ID from
# crypto/rand (and so the timer above). The IDs of a new scope are zero: no event is ever sent.
use_module_with github.com/getsentry/sentry-go scope.go \
  $'\t\tpropagationContext: NewPropagationContext(),' \
  $'\t\tpropagationContext: PropagationContext{}, // build.sh: no crypto/rand read (and so no timer) when the program starts'

# github.com/prometheus/client_golang registers a process collector in its default registry, which checks with
# statfs that /proc is a procfs. The model has no /proc, so the collector is not registered.
use_module_with github.com/prometheus/client_golang prometheus/registry.go \
  $'\tMustRegister(NewProcessCollector(ProcessCollectorOpts{}))' \
  $'\t// build.sh: no process collector, because the model has no /proc'

mkdir -p ossverify/common ossverify/chains ossverify/memo
cp "$SRC/fuzz_common.go" ossverify/common/
cp "$SRC/fuzz_chains.go" ossverify/chains/
cp "$SRC/fuzz_memo.go" ossverify/memo/

# memo: the parser of the memo of every inbound transaction, in consensus.
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/memo FuzzParseMemo fuzz_parse_memo

# common: memo fields (addresses, assets) and the share arithmetic of pools, LPs and fees.
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/common FuzzNewAddress fuzz_new_address
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/common FuzzNewAsset fuzz_new_asset
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/common FuzzShareMath fuzz_share_math

# Bifrost decoders of external-chain data.
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/chains FuzzZcashParseTx fuzz_zcash_parse_tx
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/chains FuzzZcashDecodeAddress fuzz_zcash_decode_address
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/chains FuzzSS58 fuzz_ss58
compile_go_fuzzer gitlab.com/thorchain/thornode/v3/ossverify/chains FuzzSolanaRPCVersion fuzz_solana_rpc_version
