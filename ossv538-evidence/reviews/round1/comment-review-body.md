VERDICT: REQUEST CHANGES at 9137f1b3c812bd6dbf8a894550670fc7310332ed
Reviewed by model: model-gateway-openai/openai/gpt-6.1-sol

## 1. base/base

Working directory: `/mnt/nvme/sami/clones/ossv538-base`. Its HEAD is `db31635cc7ceb774951a0495e0eb6c97d19ac981`.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P -m pytest -q -p no:cacheprovider tools/tests
```

Exit 0. Output: `973 passed, 677 skipped, 434 subtests passed in 278.45s (0:04:38)`.

## 2. head/head

Working directory: `/mnt/nvme/sami/clones/ossv538`. Its HEAD is `9137f1b3c812bd6dbf8a894550670fc7310332ed`.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P -m pytest -q -p no:cacheprovider tools/tests
```

Exit 0. Output: `1009 passed, 677 skipped, 439 subtests passed in 277.99s (0:04:37)`.

These runs check the tests that executed. They do not establish the properties of the 677 skipped tests or reproduce the image scans in the PR description.

## 3. base code + head tests

The supplied trees are read-only. I copied the base tree into `/mnt/nvme/sami/clones/ossv538-scratch/non-author-review/base-code-head-tests`, without `.git` or Python/pytest caches. I then overlaid all four added or changed test files from head: `test_private_fetch.py`, `test_check.py`, `test_print_toolchain.py`, and `test_source_pinning.py`. No head implementation file entered this copy.

Working directory: that copied base tree.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P -m pytest -q -p no:cacheprovider tools/tests/test_private_fetch.py tools/tests/test_check.py tools/tests/test_print_toolchain.py tools/tests/test_source_pinning.py
```

Exit 1, as required. Output: `34 failed, 72 passed, 1 skipped, 15 subtests passed in 8.13s`.

The failures include the actual authenticated fetch and both container failure-message assertions. For example, the private fetch exits 128 with `terminal prompts disabled` instead of succeeding. Missing/new APIs also fail. The one skipped test requires `git ls-files` in a Git checkout. This does not account for the behavioral failures.

I ran the three commands sequentially through:

```sh
/mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python /mnt/nvme/sami/clones/ossv538-scratch/non-author-review/run_matrix.py
```

The runner exited 0 after recording all three child exit codes above. It does not turn the expected negative-control failure into a passing test result.

## 4. Additional runs

All commands below ran from `/mnt/nvme/sami/clones/ossv538`. They use synthetic credentials only. The Python files and JSON/log receipts remain under the named scratch directory.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P /mnt/nvme/sami/clones/ossv538-scratch/non-author-review/probe_boundaries.py
```

Exit 0. Observed results:

- Anonymous host Git argv equals base. The shell `git()` definition equals base byte-for-byte.
- Public CLI runs for cJSON and the public `theorem-labs/oss-verify` repository, including `--twice`, call `mint_token` zero times. The configured token command does not exist. Builds are replaced in this CLI probe, not executed by Docker.
- The mount guard accepts a private Dockerfile with the mount only in a comment. It rejects a public Dockerfile with that same comment. It misses public mounts with a continued or reordered option. It accepts a private mount whose ID only starts with the expected ID, and a mount on an unrelated RUN.
- Both Dockerfile-selection branches pass the correct file to the guard: the file beside the project record, or the selected file inside the cloned source.
- Of 43 split positions in a 44-character synthetic GitHub-shaped token, 20 leave an unredacted suffix. A split after character 24 leaves 20 credential characters in the output.
- Valid UTF-8 output with no token matches the original bytes in the probe.
- Shell redaction handles the tested glob, quote, dollar, semicolon, backtick, and backslash characters. A synthetic one-line token equal to `redacted` makes the replacement loop exceed the 2-second timeout. A fake Git executable emitting the complete token on stdout bypasses the shell filter.
- An empty repository produces the missing-commit message, correctly. HTTP 429 and 503 produce the authorisation message, incorrectly. A server that lists refs but rejects upload-pack exits 128 with a raw transport error, not either custom message.
- Host `clone()` gives only its generic `cannot fetch` exception for both a wrong token and a missing commit. Git's earlier raw stderr still distinguishes those simple cases.
- The installed default token helper, exercised with a synthetic broker response, mints once across two requests for the same repository. It returns the same token and retains it in a mode-0600 JSON cache file. The requested scope is one repository with contents/metadata read permissions.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P /mnt/nvme/sami/clones/ossv538-scratch/non-author-review/probe_host_failures.py
```

Exit 0. Real HTTP/Git observations: host `resolve()` rewrites HTTP 401, but not Git's normal HTTP 403 diagnostic. It preserves 429/503 as transport errors and identifies an absent ref separately. The credential helper also returns its token for an unrelated host/path request.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P /mnt/nvme/sami/clones/ossv538-scratch/non-author-review/probe_stream_and_trace.py
```

Exit 0. A real subprocess, rather than mocked reads, confirms the 20-character suffix leak. An authenticated local Git request also writes the recoverable Basic credential into an inherited `GIT_TRACE_CURL` file when `GIT_TRACE_REDACT=0`. The trace-file probe uses a synthetic token and deletes its temporary directory.

```sh
env PYTHONDONTWRITEBYTECODE=1 /mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python -P /mnt/nvme/sami/clones/ossv538-scratch/non-author-review/probe_connection_failure.py
```

Exit 0. A real TCP connection refusal produces the container's `not authorised to read` explanation. Its earlier raw error still reports the connection failure. The host preserves the connection error without calling it authorisation failure.

The probe scripts exit 0 when their observations complete. That is not a claim that the implementation meets the requirements.

## Findings

### [P1] The default command reuses and stores a token instead of minting one for each build

[`infra/github-read-token:33-37`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/infra/github-read-token#L33-L37) sets a minimum remaining lifetime of 1800 seconds. That does not request a fresh token. The installed `gh-app-token` first calls `get_cached_token`, keyed by profile, owner, and scope. A token with more than 1800 seconds left is returned immediately. A newly minted narrowed token goes through `write_cache_file` into a persistent JSON file, via a named temporary file.

The synthetic-dependency probe observes two build-equivalent requests, one broker mint, the same returned token, and one cache file holding it. Thus a second build, including `--twice`, can use the first build's credential. The wrapper's comment that this produces a fresh token is incorrect. The token remains repository-scoped and read-only, but it is not unique to the build or storage-free. Use a per-build mint path that does not reuse or persist the credential, and test the default command's behavior rather than only an override.

### [P2] The mount guard checks text, not a Dockerfile mount

[`tools/check_build.py:545-561`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/tools/check_build.py#L545-L561) uses `SECRET_MOUNT in text`. A comment satisfies the private guard. An ID such as `oss-verify-git-token-other` also satisfies it. A valid option with reordered fields or a continuation evades the public guard and fails the private guard. A mount on `RUN ... true` does not mount it on a later fetch.

This breaks both promised refusals. It also adds a false refusal for a public Dockerfile that merely documents the mount. Parse the effective RUN options, including continuations, and compare the exact secret ID. Check the instruction that performs the fetch. Add regression cases for comments, exact IDs, continuations, reordered fields, and unrelated RUN steps.

### [P2] Redaction destroys a partial match before the next read completes it

[`tools/check_build.py:140-154`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/tools/check_build.py#L140-L154) calls `redacted()` before retaining the suffix. `TOKEN_SHAPE` already matches a `ghs_` prefix followed by 20 characters. If a 44-character token arrives in chunks of 24 and 20 characters, the first chunk becomes `<redacted>` before the complete known token can match. The remaining 20 characters are then printed unchanged.

Both the exhaustive split probe and a real subprocess reproduce this. Retain unresolved original input before doing replacements, or use a streaming matcher that does not consume a potential token prefix. Assert exact output at every split, not just absence of the complete token. The current head test can pass while leaking a suffix.

The container filter has separate limits: [`fetch-commit:80-90`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/infra/base-builder/fetch-commit#L80-L90) filters stderr only. Stdout passes through fd 3. This contradicts the claim that everything Git writes is filtered. Its replacement loop also rechecks inserted `<redacted>` text, so the accepted synthetic token `redacted` never terminates. Normal GitHub-shaped tokens do not contain that replacement text.

### [P2] Failure classification is not consistent across the container and host

[`fetch-commit:97-108`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/infra/base-builder/fetch-commit#L97-L108) treats every failing `ls-remote` as authorisation failure. TCP refusal, HTTP 429, and HTTP 503 all produce that explanation in the probes. A successful listing is not proof that upload-pack is allowed. The tested server that refuses upload-pack instead exits through the unclassified clone failure.

On the host, [`UNAUTHORISED`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/tools/check_build.py#L65-L68) contains `403 forbidden`, but Git normally prints `The requested URL returned error: 403`. That case bypasses the explanation. [`clone()`](https://github.com/theorem-labs/oss-verify/blob/9137f1b3c812bd6dbf8a894550670fc7310332ed/tools/check_build.py#L306-L315), used for an in-repository Dockerfile, does not use the new classification at all.

Keep network/rate-limit/transport failures distinct from access failures. Add real-server host tests, including clone, and do not infer missing objects or authorisation from listing status alone. The head tests pin the container's simple wrong-token/missing-commit cases. Host tests pin mocked resolution errors, not both host fetch failures.

## Token path and remaining exposure

- `mint_token` captures stdout in memory. The custom command is a trusted source of scope/lifetime semantics. The default command has the cache problem above.
- `git_environment` makes a child environment containing the token. `git(token=True)` names the helper, not the credential, in argv. `build_project` supplies `--secret id=oss-verify-git-token,env=OSS_VERIFY_GIT_TOKEN`. No changed command places the credential in a build argument or Dockerfile ENV.
- Inside the container, the intended file is the BuildKit secret mount. `fetch-commit` also reads it into shell memory. The helper returns it through a pipe and does nothing for `store` or `erase`. The checkout remote remains the supplied credential-free URL. The successful authenticated test checks the checkout files for the token.
- These paths close the ordinary URL, `.git/config`, `git remote -v`, build-argument, image-ENV, and argv exposures. They do not establish the absolute claim about all logs: see partial redaction, stdout, and the demonstrated inherited trace file.
- `/proc/<pid>/cmdline` does not receive the token through these commands. `/proc/<pid>/environ` on the host does hold it for the child Git/Docker processes, readable by a permitted same-user/root observer. That is a remaining exposure, not an argv leak.
- No changed code disables core dumps or clears inherited Git tracing. A core dump can contain process memory. The trace-file probe shows another durable route. Arbitrary Dockerfile code sharing a secret-mounted RUN can also copy the mount. BuildKit does not prevent that copy.
- The helper ignores the requested protocol, host, and path. It answers an unrelated recipient in the probe. This matters for recursive submodules: the same configured helper can answer another server's challenge. A repository-scoped token limits its permissions, not who receives its bytes.
- I did not execute live private-project builds or rescan their Docker history/layers. The PR's reported scans are the author's evidence, not mine. The exercised tests and source trace do not prove those scans or live token permissions/expiry.

## Public behavior, provenance, and files

- `tools/check`: only a listed repository reaches `mint_token`. The public and `--twice` branches do not require a token command. Both were exercised with builds replaced.
- `tools/check_build.py`: the anonymous Git argv is identical to base. The new guard and failure handling add behavior even for public projects. The extra container `ls-remote` occurs after a failed fetch. The initial successful anonymous fetch still uses the original Git command.
- `infra/base-builder/fetch-commit`: the no-token `git()` command is byte-identical to base, but the failed-fetch path is not unchanged. See the diagnostic finding.
- `infra/base-builder/git-credential-oss-verify` and `infra/github-read-token`: new credential transport and default mint adapter, with the limits above.
- `infra/base-builder/Dockerfile`: installs the helper and introduces no credential ARG/ENV. Its changed input also changes builder/image cache identities for public builds. I did not measure public binary equivalence myself.
- `infra/private-libraries.tsv`: lists the two private repositories. It does not enroll either project. No existing project file changes in this diff.
- `infra/base-builder/README.md` and `docs/build-contract.md`: document the new route. I also read the latter because it is in the actual diff, although the target list omitted it. Their unconditional fresh-token, mount-validation, and all-output-filtering claims need the fixes above.
- `tools/tests/test_private_fetch.py`: adds 36 tests. They detect the change against base, but miss the cache, Dockerfile parsing, partial-redaction, and diagnostic cases above. The three existing test-file changes only extend stub signatures for the new token argument.
- `manifest.py` is unchanged. `tools/check` still passes the fetched commit into the same manifest construction, without a token field. The public CLI probe records the expected commit and no secret-related top-level fields. Actual image IDs and this repository's recorded revision can change. This is not a new manifest schema.
- The enrollment workflow is unchanged. Its build job has no token-command setup and retains `persist-credentials: false`. No workflow run was started by hand.

For ordinary completed subprocesses, one reader thread preserves output order and the probes show no deadlock. Keeping the last `len(token)-1` original characters would protect an exact token boundary. The premature regex replacement breaks that argument here. The five-second reader join and lack of a final incremental-decoder flush are inherited from base. I do not claim an all-input losslessness guarantee for them.
