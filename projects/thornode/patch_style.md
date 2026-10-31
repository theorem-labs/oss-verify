<!-- THORNode's report and patch preferences for OSS Verify. Copyright (c) THORChain contributors. SPDX-License-Identifier: Apache-2.0 -->
# Patch style and report preferences

## What we care about
- THORNode is a blockchain state machine. Every validator runs the same code on the same input. A panic in consensus code (`x/`, `common/`, `constants/`) that a transaction, a memo or an observed external-chain transaction can reach in BeginBlock or EndBlock halts the chain. This comes first.
- A wrong result in share, fee or pool arithmetic (`common.GetSafeShare`, `GetUncappedShare`, `SafeSub`) moves funds. Treat it as seriously as a panic.
- In Bifrost (`bifrost/`), a panic or a wrong decode of data from an external chain stops observation or signing for that chain, or makes the signer broadcast a transaction that differs from the one it signed.
- Determinism matters as much as safety: consensus code must not depend on map iteration order, floats, wall-clock time or randomness.

## Which findings to report
- Report every reachable panic, hang and failed property, with a patch when you have one. Also send a finding that has no patch.
- Rate severity on our scale, priority::0 (most severe) to priority::5. A panic or wrong result that an external user can reach on a consensus path (it halts the chain or moves funds) is priority::0 or priority::1. A Bifrost panic that stops one chain is priority::1 or priority::2. A finding that needs a trusted input (node configuration, an operator's own RPC node acting in bad faith) is priority::3 or lower.
- Tell us the entry point: which memo, transaction or RPC response reaches the code, and from which handler or Bifrost scanner.
- Send findings only to primary_contact. A finding that can halt the chain or move funds is a security issue, and we fix it before it is public.

## How to report
- One report for each root cause. Put related findings (one bug, several fuzz targets) into one report.

## Which patches to write
- Bugs that no fuzz target can hit: also report them, and send a patch.
- Behaviour that we do not support: make the fuzz target narrower, and tell us why.
- Documentation: send patches that change only documentation only when the documentation is wrong.
- Refactoring that makes the code easier to verify: only changes that keep the behaviour. Do not change consensus-visible behaviour (results, events, store keys or `gas_used`) in a refactoring.

## Our contribution policy
- We accept AI-generated patches. A person on the THORNode team reviews each one, and merge requests need three approvals from the dev team.

## Patch format
- Go, formatted with gofumpt (not goimports). Follow the conventions in the repository's CLAUDE.md and REVIEW.md.
- Add a unit test that fails without the fix. Use `go test -tags=mocknet` for packages under `x/thorchain`.
- Gate a behaviour change in consensus code behind a Mimir key that is off by default, and say so in the report.
- One commit for each patch, with a subject line under 72 characters.

## Where and how to send patches
- Attach the patch to the report, sent to primary_contact. Do not open a merge request: our repository is on GitLab (https://gitlab.com/thorchain/thornode), and we open the merge request against the develop branch.

## Anything to leave alone
- Generated files: `*.pb.go`, `*.pb.gw.go`, `*.pulsar.go`, `*_gen.go`, `openapi/gen/` and `api/`.
- `bifrost/tss/go-tss`, which is vendored.
