# project.yaml

This page describes each field of `projects/<name>/project.yaml` and each file in the project directory. It is for a maintainer, or a coding agent, who writes a project directory.

Start from [templates/project.yaml](../templates/project.yaml). `tools/validate.py` checks each rule on this page. We use the same rules when we import a project.

The field names come from OSS Scanner if it has the field, then from OSS-Fuzz. We made new names only for fields that neither has.

## The fields

| field | required | value | default |
|---|---|---|---|
| `repo` | yes | the git repository, with an optional `#<ref>` | the default branch |
| `primary_contact` | yes | the one email address that gets findings and build problems | |
| `language` | yes | the language of the code that we build ([below](#language)) | |
| `dockerfile` | if no `Dockerfile` is in the project directory | the path of the `Dockerfile` in your repository | |
| `auto_ccs` | no | more email addresses, copied on each report | none |
| `homepage` | no | the project's home page | |
| `pgp` | no | your armored OpenPGP public key | |
| `disabled` | no | `true` pauses the project | `false` |
| `sanitizers` | no | the sanitizer builds in addition to `plain` | `[address, undefined]` |
| `ubsan_checks` | no | changes to the UBSan checks of the `ubsan` and `asan-ubsan` builds, with the next toolchain version ([below](#ubsan_checks)) | none: the checks that OSS-Fuzz makes fatal, for the project's language |
| `fuzz_targets` | no | the fuzz targets to verify | each fuzz target that the build makes |
| `mutants` | no | the directory of the breakage patches, from the `WORKDIR` of the `Dockerfile` ([below](#mutants)) | none |
| `patch_style` | no | the path of your `patch_style.md` in your repository ([below](#patch_style)) | |
| `budgets` | no | the memory budgets of the statements | today's values |
| `proofs` | no | where we publish the proofs ([below](#proofs)) | the proofs repository |
| `publish` | no | when we publish the proofs: `eager`, `after_fixes` or `never` ([below](#publish)) | `after_fixes` |

`tools/validate.py` refuses each field that is not in this table.

### repo

Give exactly one git repository, as an `https://` URL. We clone it anonymously.

After `#`, give one of these:

* A branch or a tag. Each build uses the commit that the branch or tag names when the build starts. We do not build again each time the branch moves ([what-gets-proven.md](what-gets-proven.md#when)).
* A full commit id: 40 hexadecimal digits, or 64 for a SHA-256 repository. Each build then uses exactly that commit.

The lock in the proofs repository records the commit of each build. It is the only place that records it. `tools/validate.py` warns you about a ref that looks like a shortened commit id.

### primary_contact, auto_ccs and pgp

These fields work as they do in OSS Scanner.

* `primary_contact` gets each finding and each build problem.
* `auto_ccs` lists more addresses. Each report goes to them too.
* `pgp` holds your armored OpenPGP public key. We then encrypt each report to this key, and send it to `primary_contact` only. Thus you cannot use `pgp` with `auto_ccs`.

The addresses are public. Use an address that you are glad to publish, such as a security alias. We send each finding privately to these addresses ([what-gets-proven.md](what-gets-proven.md#findings)). `tools/validate.py` warns about an address at a domain that is reserved for examples, such as `example.org` or `.invalid`, because no report reaches it.

A seeded project has `primary_contact: n/a` until a maintainer adopts it ([below](#seeded-projects)).

### language

Give the language of the code that we build: the library and its fuzz targets. Use the name that OSS-Fuzz uses.

This table is the only list of languages in these documents. It gives the status of each language today.

| `language` | the code | status | more source suffixes |
|---|---|---|---|
| `c` | C | statements today | |
| `c++` | C++, or C and C++ together | statements today | |
| `rust` | Rust | statements today | `*.rs` |
| `python` | Python | statements today; we start no statements for a new enrollment for now ([README](../README.md#when-the-checks-pass)) | `*.py` |
| `go` | Go | builds today (plain build only, no cgo); our tools do not write theorem statements for Go yet | `*.go` |
| `jvm` | Java, Kotlin and the other JVM languages | halts statements only; JVM binaries are not byte-reproducible yet | `*.java` `*.kt` |
| `javascript` | JavaScript | held | `*.js` `*.mjs` `*.cjs` `*.ts` |
| | Ruby, Lua | in progress: `tools/validate.py` does not accept them yet | |
| | R | pending (likely address-only): `tools/validate.py` does not accept it yet | |
| | Swift | not possible: RISC-V LLVM has no Swift calling convention | |

Our builder builds `c`, `c++`, `rust`, `python` and `go` projects today. `tools/validate.py` warns about the other languages, and `tools/check` refuses them. The builders of the other languages are pending. We add each one to [infra/toolchains.tsv](../infra/toolchains.tsv) after its image is published.

A `rust` project has all four builds. Its `ubsan` build uses rustc's UB checks, not UndefinedBehaviorSanitizer ([build-contract.md](build-contract.md#rust-fuzz-targets)). A `python` project has all four builds: each build compiles CPython with its own flags.

A `go` or `jvm` project has only the plain build. Go has no UndefinedBehaviorSanitizer or AddressSanitizer build, and the Go builder does not support cgo. Our tools do not write theorem statements for Go yet. A `jvm` project has halts statements only. Leave out `sanitizers`, or give `sanitizers: []`. A `go` project's fuzz targets are its OSS-Fuzz Go fuzz targets, which OSS-Fuzz's Go helpers build ([build-contract.md](build-contract.md#go-fuzz-targets)).

A fuzz target source in the project directory has a suffix of C or C++: `*.c` `*.cc` `*.cpp` `*.h` `*.hh` `*.hpp`. Each other language also permits the suffixes that the table gives.

### dockerfile

Use `dockerfile` only if the `Dockerfile` is in your repository. We recommend the path `.oss-verify/Dockerfile`.

* If the `Dockerfile` and `build.sh` are in the project directory, do not set `dockerfile`. The build context is then the project directory.
* If you set `dockerfile`, the build context is your repository at the commit that we build. Put `build.sh` next to the `Dockerfile`, unless the `Dockerfile` makes `$SRC/build.sh`. Then put your fuzz target sources, build patches and `sources` file in your repository too. Only `project.yaml`, `patch_style.md` and seed corpora can then be in the project directory.

A seeded project can have no build files yet. `tools/validate.py` warns about it, and `tools/check` refuses it, because there is nothing to build.

### sanitizers

Each build makes a different set of binaries, with its own statements.

| build | we make it when | sanitizer |
|---|---|---|
| `plain` | always | none |
| `ubsan` | `sanitizers` contains `undefined` | UndefinedBehaviorSanitizer |
| `asan` | `sanitizers` contains `address` | AddressSanitizer |
| `asan-ubsan` | `sanitizers` contains both | both |

[build-contract.md](build-contract.md#the-builds) gives the flags of each build. A `go` or `jvm` project has the plain build only ([above](#language)).

### ubsan_checks

Change the UndefinedBehaviorSanitizer checks of the `ubsan` and `asan-ubsan` builds. Use this field only if `sanitizers` contains `undefined`, and only for a `c`, `c++` or `python` project.

**The format of this field is provisional.** It can change before the next toolchain version applies it.

> **WARNING:** Today's toolchain vintage does not apply this field. Its builds keep the fixed UBSan flags of the release ([build-contract.md](build-contract.md#the-builds)), so that its binaries are the release's. With this vintage, `tools/check` refuses a project that sets the field. The field applies with the next toolchain version.

If you leave out the field, the builds make the checks that OSS-Fuzz makes fatal, which are those of its `-fno-sanitize-recover` list, and for a `c++` project also libc++'s hardening. For a `c++` project, these are the checks:

    array-bounds bool builtin enum function integer-divide-by-zero null object-size return
    returns-nonnull-attribute shift signed-integer-overflow unreachable vla-bound vptr libcxx-hardening

OSS-Fuzz leaves out `function` when it compiles C code, and when it compiles a Python project's native code. Thus a `c` or `python` project's default does not have `function`, and the C files of a `c++` project are compiled without it. `vptr` and `libcxx-hardening` are about C++ code, so a `c` or `python` project's default does not have them either.

* `vptr` needs the UBSan runtime, which trap mode does not have. The `ubsan` build makes it through the toolchain image's trap-only handler (`/opt/ubsan-vptr-trap/libclang_rt.ubsan_vptr_trap.a`), which traps on a mismatch as the other checks do. A compile with `-fno-rtti` has no vptr check: the compiler shim adds `-fno-sanitize=vptr` to it, so a project built without RTTI needs no change. The `asan-ubsan` build leaves `vptr` out.
* `libcxx-hardening` is not a clang check. It is libc++'s extensive hardening mode: the `ubsan` build compiles and links the project's C++ against the toolchain image's hardened libc++ (`/opt/asan-static/musl-hardened.cfg`). libc++ then checks its preconditions, for example an index past the end of a `std::span`, `std::string_view` or `std::vector`, or `*` of an empty `std::optional`, in the headers and in `libc++.a`, and a failed check traps with no output. The other builds keep the default libc++. To leave it out, write `remove: [libcxx-hardening]`, as for any check.
* OSS-Fuzz also instruments `unsigned-integer-overflow`, but it silences the reports (`silence_unsigned_overflow=1`). Trap mode cannot silence a check. Thus the default does not contain it.

The field changes the default, and tells why:

* `add`: the checks to make in addition to the default, as clang names them;
* `remove`: the checks of the default to leave out;
* `reason`: why the project's checks differ from the default. This key is required.

For example:

```yaml
ubsan_checks:
  add: [alignment]
  reason: "the decoder reads packed structures, and must never read them misaligned"
```

`tools/validate.py` refuses a name that clang does not know, a check that the field both adds and removes, and a change without a reason. In these lists, `null` needs no quotes.

### fuzz_targets

Give the names of the fuzz targets that `build.sh` puts in `$OUT`. If you do not give this field, we verify each fuzz target that the build makes. A fuzz target is an executable in `$OUT` whose symbol table defines `LLVMFuzzerTestOneInput`. It must be in each build.

The manifest and the lock record the list that a build used. Thus "each fuzz target" cannot change what a proof is about without a record. A build that does not make a fuzz target in this list fails.

### mutants

Give the directory that holds breakage patches of your fuzz targets: changes to the library or to a fuzz target that make a check fail on an input in the seed corpus. A one-line change is usually a `mutant:` record in the check's comment instead, and a project can use both ([.claude/skills/add-project/SKILL.md](../.claude/skills/add-project/SKILL.md), step 3.4). The path starts at the `WORKDIR` of the `Dockerfile`, where `build.sh` runs. For a `Dockerfile` that fetches your repository into `$SRC/<name>` and works there, it is a directory of your repository, for example `fuzz/mutants`.

Each file in the directory whose name ends in `.patch` is one breakage patch, as `git diff` writes it, with paths from that `WORKDIR`. Before its `diff --git` line, write which check it breaks and the seed input that catches it. `git apply` ignores that text. For example:

```
Breaks the check of fuzz/fuzz_ctrl.c:91 (an 0x8819 frame of 50 bytes or more is parsed as REAC).
Caught by the seed input "breakages" of fuzz_ctrl.

diff --git a/src/reac_ctrlblk.c b/src/reac_ctrlblk.c
...
```

The Build check of each enrollment pull request applies each patch in turn, builds again, and runs each fuzz target on each input of its seed corpus. It reports each patch that no input catches, and each check that no breakage, record or patch, makes fire ([build-contract.md](build-contract.md#the-checks-of-a-fuzz-target)). A breakage patch is never applied to a binary that we prove things about.

### patch_style

Give the path of your `patch_style.md` in your repository. Do not use this field if `patch_style.md` is in the project directory.

`patch_style.md` covers your report preferences and your patch style. It is free text for our AI, which reads it before it sends you a report or writes a patch. Start from [templates/patch_style.md](../templates/patch_style.md). It suggests these topics:

* only security-critical findings, or all of them, and how you rate severity;
* findings that come without a patch, or only findings with a patch;
* other report preferences, for example one report for a group of related findings;
* patches for bugs that no fuzz target can hit, or only for bugs that a fuzz target can hit;
* a narrower fuzz target, or a library that handles behaviour that you do not support, in particular refused allocations;
* patches that change only the documentation;
* refactoring that makes the code easier to verify, and whether it needs a proof that the behaviour does not change;
* your policy on AI-generated contributions, which we follow;
* the code style, tests and commit format of a patch, and Simplified Technical English (ASD-STE100) for its text.

These are suggestions only. Write about the topics that matter to you.

### budgets

The memory budgets of the statements ([what-gets-proven.md](what-gets-proven.md#memory-budgets)). These are the defaults:

```yaml
budgets:
  halts: 16GiB               # each build that runs alone; only 16GiB
  agrees:                    # for each sanitizer: [plain side, sanitizer side]
    address: [2GiB, 512GiB]  # also for asan-ubsan
    undefined: [16GiB, 512GiB]
```

Give a size as a positive number of bytes, or as a number followed by `KiB`, `MiB`, `GiB` or `TiB`. Give a budget under `agrees` only for a sanitizer that the project uses. Give only the values that you want to change. The plain side of a pair must be at least 4096 bytes, and the sanitizer side must be at least the plain side. `halts` can only be 16GiB: a project's own halts budget is not carried into the statements yet.

A statement made under a project's own budgets names both of them. A smaller plain-side budget covers fewer inputs. A larger sanitizer-side budget lets the sanitizer build use more memory before a refusal counts as a difference. So two agrees statements with different budgets claim different things: compare the budgets before you compare the statements.

### proofs

Give the place where we publish the proofs: `repo`, an `https://` URL, with `#<branch>` if it is not the repository's default branch, and `path`, a directory in that repository. Most projects do not use this field. By default, we publish to the main branch of [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs), with the project's statements in `projects/<name>/` and its proofs in `proofs/<name>/`:

```yaml
proofs:
  repo: https://github.com/theorem-labs/oss-verify-proofs
  path: projects/<name>
```

### publish

Tell us when to publish the proofs:

| value | we publish the proofs |
|---|---|
| `after_fixes` (the default) | when each patch that we sent you is public or in your project |
| `eager` | while we work on them |
| `never` | never outside Theorem |

With `never`, we publish neither the proofs nor the theorem statements. With each other value, we publish the theorem statements after the enrollment's checks pass. We hold back each statement that shows a finding that is not public yet. When we have a patch for a finding, or we reported it, we hold back all the statements of the project until the finding is public. A project that was private stays private, also if you change `publish` ([what-gets-proven.md](what-gets-proven.md#publishing)).

## Seeded projects

We seeded some projects ourselves. A project whose proofs we publish in [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs) is in `projects/<name>/`. Each other one is in [tools/seeds/](../tools/seeds/)`<name>/`: its `project.yaml`, and its build files if it has any. We used the build data of the oss-fuzz-theorems 2026.10 release. A seeded project has `primary_contact: n/a`. Its `project.yaml` starts with two comment lines that tell that we seeded it. `tools/validate.py` warns about `n/a`, and the `tools/validate.py` row of the triage comment on a pull request shows that warning.

From [this commit of OSS-Fuzz](https://github.com/google/oss-fuzz/tree/bd2ce21991a94a362b92fb1bf25f86d5a1a60842), we seeded each project that our builder can build and that we can describe honestly. A seeded `project.yaml` gives only what the recorded build data tells, and no guess. [seeded-projects.tsv](seeded-projects.tsv) lists each of the 1,381 projects of OSS-Fuzz at that commit. For a project that we did not seed, it gives the reason.

A core maintainer can adopt a seeded project:

1. Copy its `projects/<name>/`, or its `tools/seeds/<name>/`, to `projects/<name>/` in a branch of your fork.
2. Remove each patch that fixes a bug. The directory of a seeded project whose proofs we publish can hold such a patch, but the directory of an enrolled project cannot ([above](#build-patches)). For each one, delete the patch file, its line in `series`, its `patch` line in `sources`, and its name where the `Dockerfile` or `build.sh` copies or applies it. `lay-out-sources` applies each `patch` line of `sources` in turn, and stops when those lines are not the patches that `series` lists, in the same order. So keep the patches that remain in their order in both files.
3. Set `primary_contact` to the address that gets findings.
4. Remove the two comment lines.
5. Do the steps in the [README](../README.md#enroll-a-project) from step 3.

The build files of a seeded project come from the build recipe of that release. They make that release's binaries again, byte for byte. Keep them, or write your own. If a seeded project has no build files, [seeded-projects.tsv](seeded-projects.tsv) tells why. Add a `Dockerfile` and a `build.sh` before you open the pull request.

## The files in the project directory

| file | when |
|---|---|
| `Dockerfile` | if `dockerfile` is not set |
| `build.sh` | with a `Dockerfile` in the project directory |
| `patch_style.md` | optional, if `patch_style` is not set |
| fuzz target sources | optional: your own fuzz targets and their helpers, with the suffixes of your language ([above](#language)) |
| `*.patch` and `series` | optional: patches ([below](#build-patches)) |
| `sources` | optional: other source trees and files of the build, each pinned by commit or SHA-256 ([build-contract.md](build-contract.md#builds-ported-from-oss-fuzz-theorems)) |
| a file that `sources` copies or reads | optional: a file that the build needs, under any name, for example the `Cargo.lock` of a Rust fuzz target or the `go.lock` of a Go project |
| `<target>_seed_corpus.zip` | optional: example inputs of the fuzz target `<target>` ([below](#seed-corpora)) |

### Seed corpora

A seed corpus is a zip file of example inputs of one fuzz target. Together, its inputs run each API call and each property check of the fuzz target at least once ([.claude/skills/add-project/SKILL.md](../.claude/skills/add-project/SKILL.md), step 3.3). OSS-Fuzz uses the same name. A seed corpus must obey these rules:

* Its name is `<target>_seed_corpus.zip`. If you give `fuzz_targets`, it lists `<target>`.
* Each input is a file at the top level of the zip file. It is an input as libFuzzer takes it, without the six-byte header that the driver reads ([build-contract.md](build-contract.md#the-driver)).
* It holds at most 1,024 inputs.
* Its size is at most 1 MiB, and at most 16 MiB when uncompressed.

The seed corpus of a `python` project is an input of the build of its fuzz target. The build gives the seeds to `pyclosure.py`, which runs the harness on each one, and the modules that these runs reach go into the frozen module set of the binary ([infra/base-builder/python/recipes.sh](../infra/base-builder/python/recipes.sh), `oft_py_freeze`). Thus a change to such a seed corpus can change the bytes of the binaries. For each other language, no build reads the seeds. `tools/check --checks` runs the seeds of a `c` or `c++` project to measure its checks, and that run changes no binary ([build-contract.md](build-contract.md#the-checks-of-a-fuzz-target)).

### Build patches

`series` lists each patch that the build applies, one file name on each line, in order. We ignore empty lines and lines that start with `#`. List each patch exactly once.

A patch of an enrolled project can only change how the project builds. For example, it can make the build static, set up cross-compilation, correct a version stamp or make a generated file. A change that fixes a bug never goes in the directory of your project. We send it to you as a patch, with its finding ([what-gets-proven.md](what-gets-proven.md#findings)). If a proof needed that patch, we publish the patch with the proof ([what-gets-proven.md](what-gets-proven.md#publishing)). Only the directory of a seeded project whose proofs we publish can hold such a patch ([build-contract.md](build-contract.md#build-patches)).

### Rules for each file

Each file must obey these rules:

* It is a regular file. Symbolic links and subdirectories are not permitted.
* Its name uses only `A-Z a-z 0-9 . _ -` and starts with a letter or digit.
* It is UTF-8 text. A seed corpus is the only exception.
* Its size is at most 128 KiB for `project.yaml`.
* Its size is at most 256 KiB for `build.sh`, a fuzz target source, a file that `sources` copies or reads, or a build patch.
* Its size is at most 64 KiB for each other file.

The project directory holds at most 64 files. Its name uses only `a-z 0-9 . _ -`, starts with a letter or digit, and has at most 63 characters.
