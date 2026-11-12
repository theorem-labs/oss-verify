VERDICT: REQUEST CHANGES at 1eb1c2adcf61ed60f874a6c84367f5b174af9897
Reviewed by model: openai/gpt-6.1-sol

This comment supersedes https://github.com/theorem-labs/oss-verify/pull/186#issuecomment-6813305547. I reviewed the diff against `db31635cc7ceb774951a0495e0eb6c97d19ac981`, including the changes after `9137f1b3c812bd6dbf8a894550670fc7310332ed`. I did not write or change the implementation.

## Runs

The commands use directory variables to omit machine-specific account paths. `WORK` is the supplied checkouts' parent directory:

```sh
H=$WORK/ossv538
B=$WORK/ossv538-base
R=$WORK/ossv538-scratch/review2
P=$WORK/ossv538-scratch/venv/bin/python
```

**Base/base**, cwd `$B`:

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P -m pytest -q -p no:cacheprovider tools/tests
```

Exit 0: `973 passed, 677 skipped, 434 subtests passed in 445.76s`.

**Head/head**, cwd `$H`:

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P -m pytest -q -p no:cacheprovider tools/tests
```

Exit 0: `1029 passed, 677 skipped, 502 subtests passed in 277.52s`. These tests pass despite the counterexamples below.

**Base code + head tests**, cwd `$R/base-code-head-tests`:

I copied the base tree without `.git`, bytecode or pytest caches. I then copied **every** added or changed test file from head: `test_private_fetch.py`, `test_check.py`, `test_print_toolchain.py`, and `test_source_pinning.py`, all under `tools/tests/`. No production file from head entered that copy.

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P -m pytest -q -p no:cacheprovider tools/tests/test_private_fetch.py tools/tests/test_check.py tools/tests/test_print_toolchain.py tools/tests/test_source_pinning.py
```

**Failed**, exit 2: `1 error in 0.57s`. Collection of `test_private_fetch.py` fails at its class-level `check_build.SECRET_MOUNT` reference. The base has no such attribute. The overlay fails as required, but no behavioral assertion runs. The matrix runner `$P $R/run_matrix.py` then exits 1 because its own assertion expected pytest exit 1 rather than exit 2.

I also ran the three files that collect on base:

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P -m pytest -q -p no:cacheprovider tools/tests/test_check.py tools/tests/test_print_toolchain.py tools/tests/test_source_pinning.py
```

Exit 0: `67 passed, 1 skipped, 13 subtests passed in 11.28s`. Thus the full overlay does fail as required. Its observed failure is the absent API, not a measured regression assertion.

**Independent parser, transport, credential and log checks**, cwd `$H`:

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_parser_stream_scope.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_network.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_remaining.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_transport_markers.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_trace_routes.py
env PYTHONDONTWRITEBYTECODE=1 $P -P $R/probe_error_tail.py
env PYTHONDONTWRITEBYTECODE=1 $P -P $R/probe_docker_parser.py
```

Each listed script exits 0 and reports the counterexamples below. The network checks use real Git and a loopback smart-HTTP server. They rewrite only the transport and corresponding credential scope. The Docker parser checks use real BuildKit and a synthetic secret. The fake `fetch-commit` command reports whether that step actually receives the secret. The last Docker run sets a different non-secret environment value per case, so each step executes instead of using another case's cache.

All transport, trace and redaction tests use synthetic tokens. The real tokens appear only in the two private builds and the read-only API scope checks.

The Docker command for each of the 14 cases was:

```sh
REVIEW2_SYNTHETIC_SECRET=synthetic-secret docker build --progress=plain --secret id=oss-verify-git-token,env=REVIEW2_SYNTHETIC_SECRET -f $R/docker-parser/Dockerfile.<case> $R/docker-parser
```

Cases: `normal`, `string-only`, `heredoc-mounted`, `heredoc-text`, `network-first`, `arg-id`, `env-id`, `quoted-option`, `quoted-command`, `after-command`, `continued-fields`, `escape-backtick`, `copy-mount`, `crlf`. Results appear below.

**Public equivalence**, cwd `$H` for the runner:

```sh
$P $R/public_builds.py
```

The successful run invokes this command in `$B` and `$H`, respectively:

```sh
OSS_VERIFY_GIT_TOKEN_COMMAND=/nonexistent/review2-token-command PYTHONDONTWRITEBYTECODE=1 $P tools/check --no-shell --build plain --dir $R/public-<base-or-head> projects/cjson
```

Both exit 0. Neither log contains a mint step or `--secret`. Both produce the same bytes for all three output files. SHA-256 of `plain/cjson_read_fuzzer`: `9491a9ab63bbda4ecc901e0e41df2c2f4ddf315ce731cf05b7a4fb5911183c79`. Both builds fetch `acc76239bee01d8e9c858ae2cab296704e52d916`. Only the verifier commit and builder image identifiers differ in the manifests. The public Git argument lists and the anonymous container `git()` definition are byte-identical to base. The public stream probe preserves its input bytes, including token-shaped text and split UTF-8.

The first invocation of this runner used `$P -P tools/check` and failed before either build: `ModuleNotFoundError: No module named 'check_build'`. I removed `-P` from that script invocation. I did not change product code.

**Two real private builds and secret-absence scans**, cwd `$H`:

```sh
$P $R/private_builds.py
```

Exit 0. The runner calls the default `mint_token` twice for each repository and compares values without printing them. Both pairs differ. It gives one newly minted value to the build through a temporary command that prints an inherited environment variable. It invokes:

```sh
PYTHONDONTWRITEBYTECODE=1 OSS_VERIFY_GIT_TOKEN_COMMAND=$R/build-token-from-env $P tools/check --no-shell --build plain --dir $R/private-cjson-ossv267 $R/private-projects/cjson-ossv267
PYTHONDONTWRITEBYTECODE=1 OSS_VERIFY_GIT_TOKEN_COMMAND=$R/build-token-from-env $P tools/check --no-shell --build plain --dir $R/private-theorem-cli $R/private-projects/theorem-cli
```

The token is an inherited environment value, not a command argument. Both builds exit 0. Their fetch steps execute, rather than report `CACHED`:

- cJSON: requested commit and `/src/cjson` source fact both equal `acc76239bee01d8e9c858ae2cab296704e52d916`.
- theorem-cli: requested commit and `/src/theorem-cli` source fact both equal `b9e7947677f353c26a62980aaf6dffbcc57d1503`.

For each resulting image the runner executes `docker history --no-trunc <image>`, `docker image inspect <image>`, and `docker save <image>`. It scans every saved regular member, decompressing gzip layer blobs before scanning. Each image has 21 scanned members, including 12 gzip layers. It also scans all files in each build's manifest/output directory. There are zero matches for that build's raw token or the base64 of `x-access-token:<token>`, which an authorization header carries. A network-disabled `docker run --rm --init --name ossv538-review2-<project> --entrypoint sh <image>` checks the environment, secret files and Git remotes. Neither image has the token, token environment variable or secret mount. Both retain the expected credential-free remote. These normal builds do not disprove the trace-file and error-tail counterexamples.

I made no enrollment change under `projects/`, no commit, no push, no merge, and no workflow dispatch.

**Live token scope**, cwd `$H`:

```sh
env PYTHONDONTWRITEBYTECODE=1 $P -P $R/probe_actual_token_scope.py
```

Exit 0. For each default-minted token, `GET /installation/repositories` returns 200 and exactly its one expected repository. Its own repository returns 200. The other private repository returns 404. The repository response reports `push: false`. This uses reads only, not attempted writes.

## The five findings

### 1. Minted for the build: partially fixed, not an unconditional guarantee

[`infra/github-read-token`](https://github.com/theorem-labs/oss-verify/blob/1eb1c2adcf61ed60f874a6c84367f5b174af9897/infra/github-read-token) really forces `GH_APP_TOKEN_MIN_LIFETIME=3600`. The dependency receives `agent --owner theorem-labs --repo theorem-cli --read-only`, even when the caller sets the lifetime to 1. With an accurate client clock, the installed `gh-app-token` rejects an ordinary cached one-hour token at this threshold. A controlled run of that dependency produces two mints for two calls at 3600, versus one at 1800. Profiles have separate cache keys. Normal `--twice` calls `mint_token` twice, once per build. Public `--twice` calls it zero times. Reusing the resulting value for resolve, host checkout and Docker inside one build is appropriate.

Two routes still permit reuse:

- **Clock-dependent cache bypass.** With the dependency's client clock 60 seconds behind the mint server, two calls at minimum 3600 make only one mint and return the same cached value. The expiry comparison uses the client's wall clock. The comment that the value cannot ever come from cache is too strong. An explicit fresh-mint operation would establish this requirement without that assumption.
- **Custom token command.** A command that prints the same fixed token on every call is accepted twice. `mint_token` checks output shape, not freshness, repository scope, read-only permissions or expiry. The documentation must identify those properties as obligations of a trusted override, rather than properties checked here.

The new limitations list does honestly disclose the mode-0600 host cache. I measured that mode. Expiry invalidates the credential, not necessarily the cache file's bytes.

### 2. Dockerfile parser: partially fixed, with valid syntax rejected and false fetch matches accepted

The ordinary template, full-line comments, exact secret IDs, reordered comma fields and CRLF continuation work. A mount placed **after** the command is rejected. That placement is not a BuildKit option, so it is not a meaningful bypass. `COPY --mount=...` and a quoted `"--mount=..."` are also invalid BuildKit forms. Rejecting them does not break a valid fetch.

The remaining defects are in [`instructions`, `secret_mounts`, `fetch_steps`, `check_secret_mount`](https://github.com/theorem-labs/oss-verify/blob/1eb1c2adcf61ed60f874a6c84367f5b174af9897/tools/check_build.py#L602-L668):

- **Valid Dockerfiles refused:** a mounted heredoc, `RUN --network=default --mount=... fetch-commit ...`, `# escape=\`` continuation, and a backslash continuation inside the comma fields. Each builds successfully and the fetch command receives the secret. Each fails the private guard. The tokenizer stops at the first option other than `--mount`, inserts a space where BuildKit joins mount fields, and does not parse heredocs or escape directives.
- **Non-fetch text accepted as a fetch:** `RUN --mount=... echo "fetch-commit"` followed by an unmounted real fetch passes the guard. BuildKit then runs the real fetch without a secret. A `COPY` heredoc containing a textual `RUN --mount=... fetch-commit ...` does the same. Matching the substring is not matching the executed command.
- **Only one mounted match is required:** one properly mounted fetch permits another unmounted fetch. This contradicts the description that the guard refuses a fetch without its mount.
- A quoted command name, `"fetch-commit"`, works. The guard also accepts an `ARG`-expanded command when its declaration happens to contain the substring. That is another symptom of text matching, not command parsing.
- BuildKit **does** expand the secret ID in both tested `ARG`/`ENV` forms. Each build executes the fetch with the secret, but the private guard rejects it. The public guard accepts these same secret requests because it sees only `$SECRET_ID`, not the expanded ID. This is another missed diagnostic, not a public-token mint: an unlisted library still gets no token. A normal syntax directive and CRLF work. Unmatched shell quoting produces a bare `ValueError`, rather than a `Failed` diagnostic.

These are defects in the advertised Dockerfile diagnostic. The separate limitation concerning other code in the same mounted `RUN` is now explicit.

### 3. Three-way failure classification: basic cases fixed, two real counterexamples remain

I exercised both container `fetch-commit` and host `clone`/`why_the_fetch_failed`:

| Server or transport behavior | Container | Host |
| --- | --- | --- |
| Refused connection | could not reach | could not reach |
| DNS failure | could not reach | could not reach |
| HTTP 429 | could not reach | could not reach |
| HTTP 503 with empty body | could not reach | could not reach |
| HTTP 401/403 or wrong token | not authorised | cannot read |
| Readable empty repository | no such commit | no such commit |
| Readable repository, absent commit | no such commit | no such commit |
| Lists refs, POST upload-pack returns 503 | **no such commit, incorrectly** | **no such commit, incorrectly** |
| HTTP 503, text body `upstream connection permission denied` | **not authorised, incorrectly** | **cannot read, incorrectly** |

The upload-pack case uses a commit that exists. A successful `ls-remote` establishes ref visibility, not successful object transport and not absence of that object. Preserve and classify the original fetch failure before asserting a missing commit. Both implementations currently lose that distinction.

The 503 body is a real Git diagnostic: `remote: upstream connection permission denied`, followed by `The requested URL returned error: 503`. The broad `permission denied` match overrides the transport status. My separate invalid-CA and DNS-name checks do not cause this false match.

Redirects also disprove the simple classification. An authenticated same-host redirect leaks the authorization to the other path, then fails with HTTP 302. Both classifiers call the existing target commit missing because a later ref listing succeeds. A pre-authentication redirect to another private path is refused by the container scope but succeeds on the host, as described next. A redirect is not itself proof of a missing commit or denied original credential.

### 4. Helper scope: not fixed on the host

[`git()`](https://github.com/theorem-labs/oss-verify/blob/1eb1c2adcf61ed60f874a6c84367f5b174af9897/tools/check_build.py#L195-L207) does not set `credential.useHttpPath=true`. With the normal default off, real `git credential fill` sends no path. The helper's fallback therefore answers for **any repository on the same host**. With scope set to `github.com/theorem-labs/theorem-cli`, a request for `github.com/theorem-labs/some-other-repo` receives the token. Setting `useHttpPath=true` makes that request fail as intended. The container already sets it.

The real server control confirms the consequence: an initial redirect from the scoped repository to another private path succeeds on the host and that other path receives the token. The container refuses it. Separately, after authentication, libcurl forwards authorization across a same-host path redirect even with container path checking. A helper scope check alone is not a guarantee about every redirected request. A redirect to a different port did not receive authorization in my authenticated redirect control.

Other cases:

- A different hostname is refused when scope is set. The helper answers any host when scope is unset. That fallback is used for tests, not the ordinary scoped path.
- Real Git removes trailing slashes from the helper request. Both `repo/` and `repo.git/` work. A hand-written request retaining that slash is refused, but that is not a demonstrated normal Git failure.
- Matching case and an explicit port work when both scope and request contain them. The private-library list does not recognize uppercase host/path or `:443` aliases of its canonical row, so those spellings mint nothing. Case changes after a canonical scope also fail its literal comparison.
- A URL with userinfo fails even when scope derives from that same URL. The scope includes `user@`, while Git places the username in a separate field. This is a refusal, not a demonstrated token escape.
- A submodule on a different repository path receives no main-repository authorization in the tested container flow.

The claim that the helper answers only one repository is false. The default token's repository-narrowed GitHub permissions still limit what it can read.

### 5. Tracing: listed environment routes fixed, configuration route still exposes the whole token

The inherited routes in `GIT_TRACING`, with `GIT_TRACE_REDACT=0`, produce no trace file in either authenticated flow. The code does force redaction back on.

**Blocking token disclosure:** Git also enables trace2 from configuration. I used a global config containing:

```gitconfig
[trace2]
    eventTarget = <scratch trace file>
    envVars = OSS_VERIFY_GIT_TOKEN
```

A real authenticated host clone succeeds and writes the **complete token** into the trace file. The file contains 25,816 bytes in this run. The exception/output filter never sees it. Unsetting `GIT_TRACE2_EVENT` leaves the configured target active. `GIT_TRACE_REDACT=1` does not redact this selected environment value. The corresponding container trace has 26,302 bytes but not the token, because the normal container path keeps its token in a secret file rather than that environment variable.

I also exercised omitted `GIT_TRACE_PACK_ACCESS`, `GIT_TRACE_SETUP`, `GIT_TRACE_SHALLOW`, `GIT_TRACE_PERFORMANCE`, `GIT_TRACE_REFS`, and `GIT_TRACE_FSMONITOR`. Both fetch paths succeed. Setup, shallow, performance and refs traces remain enabled, but contain neither the token nor its Basic encoding in these runs. Pack-access and fsmonitor create no trace in these particular runs. Absence from those runs is not evidence that tracing is disabled.

Disable configured trace targets as well as inherited ones before claiming that tracing is off. The new documented `/proc`, core-dump and same-`RUN` limits do not describe this ordinary Git log-file disclosure.

## Streaming fix and another log defect

**The streaming regression is fixed for the exact token.** I controlled `os.read` boundaries in the real `run()` copy thread. Every split position passes for a 44-character token (43 positions), a 390-character token (389), `redacted` (7), and a token whose own text begins again inside it (6). One-byte reads also produce exactly `prefix|<redacted>|end`. The shell helper redacts both streams for an ordinary token, `redacted`, and metacharacter-containing input.

**Another host output path still exposes token suffixes.** [`output()`](https://github.com/theorem-labs/oss-verify/blob/1eb1c2adcf61ed60f874a6c84367f5b174af9897/tools/check_build.py#L185-L191) slices stderr to its last 1500 characters **before** redaction. A 390-character known token followed by 1400 characters leaves its last 100 characters in the exception, with no redaction marker. The token-command error path does the same with its 1000-character limit. My isolated command reads its synthetic error from a file, so the token is not in argv. Redact the complete captured error before taking its tail. This is separate from the corrected streaming algorithm.

The first suffix probe put the synthetic emitter in `python -c`, which also quoted the token in the displayed command. I corrected the probe to use a script file before accepting the suffix result. The first omitted-trace probe reused a container checkout and failed on the second case. I corrected it to use one checkout per route. The reported route measurements are from the successful corrected run.

## Documentation and tests

`docs/build-contract.md` now states the real limits concerning process environments, core dumps, other code in the same mounted `RUN`, and the host token cache. Those additions are useful and do not need an impossible sandbox promise.

It still overstates fresh minting with an arbitrary override, Dockerfile parsing, one-repository helper scope, all-output filtering, trace suppression, and what successful ref listing proves. The five results and the error-tail result above contradict those claims. The normal private image/facts scans and public byte comparison pass, but they do not close these failures. `tools/tests/test_private_fetch.py` needs these counterexamples, not only green tests for the revised cases.

## Transcript evidence

