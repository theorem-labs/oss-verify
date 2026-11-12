## The six findings from the superseded comment

### 1. Configured trace2: token disclosure closed, trace suppression incomplete

Both real authenticated shell-path fetches succeed with all three configured trace2 targets: `eventTarget`, `normalTarget`, and `perfTarget`. The configuration also selects `OSS_VERIFY_GIT_TOKEN`, `OSS_VERIFY_TOKEN_FILE`, and `OSS_VERIFY_TOKEN_REPO` through `trace2.envVars`. Neither path creates the configured trace file. Neither captured output contains the synthetic token or its Basic authorization encoding. The inherited trace routes tested in the previous review also produce zero file bytes now. A separate real BuildKit fetch with the secret mounted and all three targets configured also succeeds and creates no trace file.

Two trace issues remain in `tools/check_build.py` and `infra/base-builder/fetch-commit`:

- **New verbosity regression:** setting `GIT_CURL_VERBOSE=0` enables curl tracing. Git tests this variable's presence, not its Boolean value. With the generated authenticated Git command, the forced-zero environment produces 5,333 stderr bytes, including HTTP request headers. Removing only `GIT_CURL_VERBOSE` produces zero stderr bytes. Both commands succeed. Authorization remains redacted in this test. Set the Boolean trace variables to `0`, but remove this presence-based variable.
- **Missed route:** inherited `GIT_TRACE_PACKFILE` creates a 204-byte binary trace in each authenticated fetch path. Neither file contains the synthetic token or its Basic encoding. The routes `GIT_TRACE_BARE` and `GIT_TRACE_WORKING_TREE_ENCODING` create no file in these runs. That observation does not prove those routes are disabled.

The original configured-target token leak is fixed. The claim that all Git tracing is off is not yet true. These remaining trace results do not demonstrate another token disclosure.

### 2. Host helper scope: direct request fixed, redirect limit remains

The host now passes `credential.useHttpPath=true`. Real `git credential fill` rejects another repository on the same host with exit 128 and no token. The intended repository succeeds. Git normalizes the tested trailing-slash forms before asking the helper.

An initial redirect to another private path no longer obtains the token on either path. Both fetches fail instead. After authentication, a same-host path redirect still forwards Authorization to the other path in both implementations. A redirect to another port does not forward it in these controls. The host fix therefore closes the missing-path defect, but does not prevent libcurl's reuse of an already obtained same-origin credential. The repository-scoped token limits its authority. Document that redirect limit rather than claim helper scope governs every HTTP request.

### 3. Error tail: not closed

`output()` now redacts the complete error before retaining its last 1,500 characters. The 390-character token plus 1,400-character suffix produces no token suffix in the exception. Its command echo is also redacted.

**`mint_token()` still cuts before redaction at `tools/check_build.py:310`.** A failing command emits a 390-character GitHub-shaped synthetic token followed by 900 ordinary characters. The exception retains the final 100 token characters, with no `<redacted>` marker. The emitter is a script file, so its token is not in the command arguments. Move `[-1000:]` after `redacted(...)` here too. This is a remaining log disclosure, not a demand for a perfect credential sandbox.

The streaming `run()` path and shell `redact()` do not take a diagnostic tail before filtering. Their independent checks pass below.

### 4. Failure markers: not closed

The two broad markers were removed only from Python's `UNAUTHORISED`. Shell `denied()` still contains both `access denied` and `permission denied` at `infra/base-builder/fetch-commit:142`.

These are real Git/server runs, not mocked diagnostic strings:

| Server response | Container classification | Host classification |
| --- | --- | --- |
| HTTP 503, `upstream connection permission denied` | **not authorised, wrong** | transport failure |
| HTTP 503, `upstream connection access denied` | **not authorised, wrong** | transport failure |
| HTTP 503, `repository not found` | **not authorised, wrong** | **cannot read, wrong** |
| HTTP 200 Git error packet, `ERR access denied` | refusal | **transport failure, wrong** |
| HTTP 401/403 or wrong token | refusal | refusal |
| HTTP 429/503 without an ambiguous body | transport failure | transport failure |
| DNS failure or refused connection | transport failure | transport failure |

Removing more words alone cannot classify these cases correctly. Respect the explicit HTTP failure status before ambiguous body text. Preserve a Git protocol refusal as a refusal. The container's original 503 counterexample remains unchanged.

### 5. Listed refs versus missing commit: closed for the reported counterexample

A server lists refs for an existing commit, then returns HTTP 503 to upload-pack. The container now says the objects did not arrive. It does not assert that the commit is missing. The host reports the two actual possibilities: an absent commit or a failed transfer. Its captured fetch output retains the HTTP 503 diagnostic.

For a genuinely absent commit, the container's successful full clone precedes its missing-commit message. A readable empty repository produces the same result. The host deliberately retains its broader diagnosis. Neither result invents an authorization failure.

The new behavior is better than the old inference from `ls-remote`. The old `clone()` docstring still says listed refs imply a missing commit. `docs/build-contract.md:178` also retains that inference after the new limitation at line 173 rejects it. Update both descriptions.

### 6. Dockerfile parser: partially fixed, not closed

Real BuildKit executes 24 cases. A synthetic `fetch-commit` reports whether its own RUN receives the mounted secret. Each case has a distinct non-secret environment value, so the RUN executes instead of reusing another case's cache.

Fixed cases include non-mount options before and after the mount, a continuation after a comma, a continuation between words, a backtick escape directive with the mount on one line, CRLF, and a quoted command name. A plain `echo "fetch-commit"` no longer hides an unmounted fetch. Without heredocs, one mounted direct fetch no longer permits a second unmounted direct fetch. Prefix-only secret IDs are rejected as intended.

**False acceptances remain:**

- A mounted heredoc followed by an unmounted real fetch passes. BuildKit gives the second fetch no secret, and it fails with exit 19.
- A `COPY` heredoc containing only textual `RUN --mount=... fetch-commit ...`, followed by an unmounted real fetch, passes. That real fetch receives no secret.
- Even `# << not a heredoc`, a commented-out mounted fetch, and an unmounted real fetch pass. The whole-file fallback treats `<<` in a comment as a heredoc.
- After a mounted direct fetch, `RUN env fetch-commit ...` and JSON-form `RUN ["fetch-commit", "/src/y"]` are not recognized as fetches. Each guard accepts an unmounted second fetch that BuildKit executes without the secret.

**False refusals remain:**

- `fetch-\` followed by `commit` on the next line executes successfully with its secret in BuildKit, but the private guard rejects it.
- A continuation inside the secret ID value, `id=oss-verify-\` followed by `git-token`, executes successfully with the secret. The private guard rejects it and the public guard misses the secret request.
- Both tested ARG/ENV-expanded secret IDs execute successfully with the secret, but the private guard rejects them. The public guard misses those requests too.

A quoted `"--mount=..."` is an invalid BuildKit option. `COPY --mount=...` is also invalid. Those are not valid-fetch regressions. A mount after the command is only a command argument, not a secret mount. Rejecting it is correct.

The false refusals block valid private builds and need either support or an explicit supported-syntax restriction. The false acceptances defeat the promised early diagnostic. They do **not** mint a token for an unlisted library. The heredoc fallback is not conservative for the private guard: over-reporting a mount permits exactly the unmounted fetch it is meant to refuse. Documenting it as the safe side does not make that true.

## Streaming, public builds, mint assumptions, and coverage

The real `run()` copy thread passes every internal split of tokens with lengths 44, 390, 8, and 7: 43 + 389 + 7 + 6 = **445 split positions**. The short cases include `redacted` and an overlapping-prefix token. One-byte reads pass too. Public output retains the input bytes, including token-shaped text and split UTF-8. The shell redacts both streams for an ordinary token, `redacted`, and shell-metacharacter input.

The public host Git argv and anonymous shell `git()` definition are identical to base. Two actual cJSON `plain` builds, one from each tree, succeed with a nonexistent token command. Each has zero mint lines and zero `--secret` lines. Their published binary is byte-identical, SHA-256 `b40ed189a37beb50da46f04a457ec144b05319a845fa3b0639d7a117ffd1696d`. In the real CLI with only compilation stubbed, public `--twice` calls the mint function zero times. Private `--twice` calls it twice.

The narrowed mint documentation is appropriate. The default wrapper forces minimum lifetime 3600 and passes repository/read-only scope to its dependency. Controlled dependency runs reproduce distinct tokens at 3600, cache reuse at 1800, and reuse with the client clock 60 seconds behind. Cache files have mode 0600. A replacement command that prints the same fixed token is still accepted. `infra/github-read-token` and the new limitation in `docs/build-contract.md` now say those checks belong to the trusted replacement. I do not require a new freshness mechanism for that explicitly stated assumption.

File coverage:

- `tools/check_build.py`: reviewed all changed paths and exercised output, tracing, helper scope, Dockerfile validation, resolve/clone failures, and public argv equivalence.
- `infra/base-builder/fetch-commit`: exercised the real script against authenticated smart HTTP, transport failures, redirects, full-clone fallback, submodule scope, and controlled redaction input.
- `infra/base-builder/git-credential-oss-verify`, `Dockerfile`, `README.md`, `infra/private-libraries.tsv`, and `tools/check`: reviewed helper installation, explicit repository selection, token delivery, and per-build mint call sites. No enrollment change is needed for this PR.
- `infra/github-read-token`: reviewed the clarified clock and replacement-command assumptions and exercised its dependency arguments.
- `docs/build-contract.md`: the host-cache, clock, replacement-command, process-environment, core-dump and same-RUN limits are useful. The tracing, heredoc safety, and missing-commit claims still exceed the measured behavior.
- `tools/tests/test_private_fetch.py`: the new tests pass in the head suite but miss the failing mint tail, shell markers, and heredoc combinations above. Its configured-trace test uses a refused connection, not a completed authenticated fetch. Several new checks inspect source text instead of executing the failure.

I did not edit either supplied tree, enroll either private project, commit, push, merge, or start a workflow. The review uses synthetic credentials for adversarial runs. I did not repeat the previous review's live private-project image/layer scans or live GitHub token-permission calls. Their earlier results are not fresh evidence for this head. The concrete remaining token-tail disclosure and failure-classification defects are why this verdict requests changes, rather than requiring an impossible credential path.

