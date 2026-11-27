# project.yaml

This page describes each field of `projects/<name>/project.yaml` and each file in the project directory. It is for a maintainer, or a coding agent, who writes a project directory. A project will also be able to enroll from its own repository, with the folder `.theorem/` ([below](#theorem-on-your-repository)). The GitHub App Theorem Verify that this needs is not made yet, and setup refuses each setup pull request until it is made.

Start from [templates/project.yaml](../templates/project.yaml). The rules of this page are for `projects/<name>/`, where this repository's CI checks them, and `theorem app setup` checks them for `.theorem/` ([below](#theorem-on-your-repository)). We use the same rules when we import a project.

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
| `ubsan_checks` | no | changes to the UBSan checks of the `ubsan` and `asan-ubsan` builds, with the next toolchain version ([below](#ubsan_checks)) | none: the checks that OSS-Fuzz makes fatal, for the project's language, with `strict-flex-arrays` |
| `fuzz_targets` | no | the fuzz targets to verify | each fuzz target that the build makes |
| `mutants` | no | the directory of the breakage patches, from the `WORKDIR` of the `Dockerfile` ([below](#mutants)) | none |
| `patch_style` | no | the path of your `patch_style.md` in your repository ([below](#patch_style)) | |
| `budgets` | no | the memory budgets of the statements | today's values |
| `proofs` | no | where we may publish the proofs ([below](#proofs)) | the proofs repository |
| `publish` | no | when we may publish the proofs: `eager`, `after_fixes` or `never` ([below](#publish)) | `after_fixes` |

`oss-verify validate` refuses each field that is not in this table.

### repo

Give exactly one git repository, as an `https://` URL. We clone it anonymously.

After `#`, give one of these:

* A branch or a tag. Each build uses the commit that the branch or tag names when the build starts. We do not build again each time the branch moves ([what-gets-proven.md](what-gets-proven.md#when)).
* A full commit id: 40 hexadecimal digits, or 64 for a SHA-256 repository. Each build then uses exactly that commit.

The lock in the proofs repository records the commit of each build. It is the only place that records it. `oss-verify validate` warns you about a ref that looks like a shortened commit id.

### primary_contact, auto_ccs and pgp

These fields work as they do in OSS Scanner.

* `primary_contact` gets each finding and each build problem.
* `auto_ccs` lists more addresses. Each report goes to them too.
* `pgp` holds your armored OpenPGP public key. We then encrypt each report to this key, and send it to `primary_contact` only. Thus you cannot use `pgp` with `auto_ccs`.

The addresses are public. Use an address that you are glad to publish, such as a security alias. We send each finding privately to these addresses ([what-gets-proven.md](what-gets-proven.md#findings)). `oss-verify validate` warns about an address at a domain that is reserved for examples, such as `example.org` or `.invalid`, because no report reaches it.

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
| | Ruby, Lua | in progress: `oss-verify validate` does not accept them yet | |
| | R | pending (likely address-only): `oss-verify validate` does not accept it yet | |
| | Swift | not possible: RISC-V LLVM has no Swift calling convention | |

Our builder builds `c`, `c++`, `rust`, `python` and `go` projects today. `oss-verify validate` warns about the other languages, and `oss-verify check` refuses them. The builders of the other languages are pending. We add each one to [infra/toolchains.tsv](../infra/toolchains.tsv) after its image is published.

A `rust` project has all four builds. Its `ubsan` build uses rustc's UB checks, not UndefinedBehaviorSanitizer ([build-contract.md](build-contract.md#rust-fuzz-targets)). A `python` project has all four builds: each build compiles CPython with its own flags, or takes the CPython that the toolchain image ships for the same inputs ([build-contract.md](build-contract.md#the-prebuilt-cpython-runtime)).

A `go` or `jvm` project has only the plain build. Go has no UndefinedBehaviorSanitizer or AddressSanitizer build, and the Go builder does not support cgo. Our tools do not write theorem statements for Go yet. A `jvm` project has halts statements only. Leave out `sanitizers`, or give `sanitizers: []`. A `go` project's fuzz targets are its OSS-Fuzz Go fuzz targets, which OSS-Fuzz's Go helpers build ([build-contract.md](build-contract.md#go-fuzz-targets)).

A fuzz target source in the project directory has a suffix of C or C++: `*.c` `*.cc` `*.cpp` `*.h` `*.hh` `*.hpp`. Each other language also permits the suffixes that the table gives.

### dockerfile

Use `dockerfile` only if the `Dockerfile` is in your repository. We recommend the path `.oss-verify/Dockerfile`. In the folder `.theorem/` ([below](#theorem-on-your-repository)), put the `Dockerfile` in `.theorem/`, and set `dockerfile` only for a `Dockerfile` that your repository already holds in another place.

* If the `Dockerfile` and `build.sh` are in the project directory, do not set `dockerfile`. The build context is then the project directory.
* If you set `dockerfile`, the build context is your repository at the commit that we build. Put `build.sh` next to the `Dockerfile`, unless the `Dockerfile` makes `$SRC/build.sh`. Then put your fuzz target sources, build patches and `sources` file in your repository too. Only `project.yaml`, `patch_style.md` and seed corpora can then be in the project directory.

A seeded project can have no build files yet. `oss-verify validate` warns about it, and `oss-verify check` refuses it, because there is nothing to build.

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

> **WARNING:** Today's toolchain vintage does not apply this field. Its builds keep the fixed UBSan flags of the release ([build-contract.md](build-contract.md#the-builds)), so that its binaries are the release's. With this vintage, `oss-verify check` refuses a project that sets the field. The field applies with the next toolchain version.

If you leave out the field, the builds make the checks that OSS-Fuzz makes fatal, which are those of its `-fno-sanitize-recover` list, with `strict-flex-arrays`, and for a `c++` project also libc++'s hardening. For a `c++` project, these are the checks:

    array-bounds bool builtin enum function integer-divide-by-zero null object-size return
    returns-nonnull-attribute shift signed-integer-overflow unreachable vla-bound vptr libcxx-hardening
    strict-flex-arrays

OSS-Fuzz leaves out `function` when it compiles C code, and when it compiles a Python project's native code. Thus a `c` or `python` project's default does not have `function`, and the C files of a `c++` project are compiled without it. `vptr` and `libcxx-hardening` are about C++ code, so a `c` or `python` project's default does not have them either.

* `vptr` needs the UBSan runtime, which trap mode does not have. The `ubsan` build makes it through the toolchain image's trap-only handler (`/opt/ubsan-vptr-trap/libclang_rt.ubsan_vptr_trap.a`), which traps on a mismatch as the other checks do. A compile with `-fno-rtti` has no vptr check: the compiler shim adds `-fno-sanitize=vptr` to it, so a project built without RTTI needs no change. The `asan-ubsan` build leaves `vptr` out.
* `libcxx-hardening` is not a clang check. It is libc++'s extensive hardening mode: the `ubsan` build compiles and links the project's C++ against the toolchain image's hardened libc++ (`/opt/asan-static/musl-hardened.cfg`). libc++ then checks its preconditions, for example an index past the end of a `std::span`, `std::string_view` or `std::vector`, or `*` of an empty `std::optional`, in the headers and in `libc++.a`, and a failed check traps with no output. The other builds keep the default libc++. To leave it out, write `remove: [libcxx-hardening]`, as for any check.
* `strict-flex-arrays` is not a clang check. It is `-fstrict-flex-arrays=1`, which changes what `array-bounds` checks, in the `ubsan` and `asan-ubsan` builds. Without it, clang takes the last array of a struct to be of unknown size, whatever its declared size, so `array-bounds` does not check an index into it: `p->buf[20]` with `char buf[16]` as the last member is not caught, and AddressSanitizer does not catch it either while it stays inside the allocation. With it, a trailing array whose declared size is 2 or more is checked. A trailing `[1]`, `[0]` or `[]` is not, because that is how C writes a flexible array, allocated with room for more elements: older code writes `[1]`, and indexes past it as intended. If a struct's last array is indexed past its declared size on purpose and that size is 2 or more, write `remove: [strict-flex-arrays]`, as for any check. It adds no check without `array-bounds`, though it still changes how clang optimizes the code of the two UBSan builds. A compile of the project whose last `-fstrict-flex-arrays=` gives a lower level than the build's, or that hands a lower one to the front end, counts as not instrumented in the checks of `uv run oss-verify check --checks`.
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

`oss-verify validate` refuses a name that clang does not know, a check that the field both adds and removes, and a change without a reason. In these lists, `null` needs no quotes.

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

Give the place where we may publish the proofs: `repo`, an `https://` URL, with `#<branch>` if it is not the repository's default branch, and `path`, a directory in that repository. Most projects do not use this field. By default, this place is the main branch of [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs), with the project's statements in `projects/<name>/` and its proofs in `proofs/<name>/`:

```yaml
proofs:
  repo: https://github.com/theorem-labs/oss-verify-proofs
  path: projects/<name>
```

### publish

We decide whether to publish the proofs of your project, and we do not promise to publish them. `publish` only limits when we may publish them. We never publish them before the pull request that enrolls your project merges.

| value | we may publish the proofs |
|---|---|
| `after_fixes` (the default) | when each patch that we sent you is public or in your project |
| `eager` | while we work on them |
| `never` | never outside Theorem |

With `never`, we publish neither the proofs nor the theorem statements. With each other value, we may also publish the theorem statements after that merge. We hold back each statement that shows a finding that is not public yet. When we have a patch for a finding, or we reported it, we hold back all the statements of the project until the finding is public. A project that was private stays private, also if you change `publish` ([what-gets-proven.md](what-gets-proven.md#publishing)).

## `.theorem/` on your repository

A project will also be able to enroll from its own repository, with the GitHub App Theorem Verify. The App is not made yet, and until it is made, setup refuses each setup pull request. You can write `.theorem/` now. When the App is made, the maintainer installs it. The maintainer's coding agent writes the folder `.theorem/` at the root of the repository, with the skill [`theorem-setup`](../.claude/skills/theorem-setup/SKILL.md). The maintainer opens the setup pull request from the branch `theorem/setup`. `theorem app setup` checks the folder, and `theorem app build` builds the project from it. Start from [templates/.theorem/](../templates/.theorem/).

`.theorem/` holds the files of a project directory, and two folders:

| file | when |
|---|---|
| `config.yml` | always: the fields of `project.yaml`, with two changes ([below](#configyml)) |
| `Dockerfile` | if `dockerfile` is not set ([below](#the-build-context)) |
| `build.sh` | with a `Dockerfile` in `.theorem/` |
| `patch_style.md`, fuzz target sources, `*.patch` and `series`, `sources` and the files that it copies or reads, `<target>_seed_corpus.zip` | optional, as in a project directory ([below](#the-files-in-the-project-directory)) |
| `statements/<target>.<ext>` | optional: the statements of the fuzz target `<target>`, which Theorem's agents write ([below](#statements)) |
| `contracts/<target>/` | optional: the contracts of the functions of the fuzz target `<target>`, which Theorem's agents write ([below](#contracts)) |

Theorem's agents write the files of `statements/` and `contracts/`, and the App commits them. A person at Theorem approves the contracts and the contract checks before the App commits them. The maintainer's agent writes each other file.

`theorem app setup` checks this form. The rules of this page for `projects/<name>/` apply to `.theorem/` too, with these changes:

* `config.yml` takes the place of `project.yaml`. It has no field `repo` of [the table](#the-fields), and `theorem app setup` refuses that field ([below](#configyml)).
* [The build context](#the-build-context) takes the place of what [dockerfile](#dockerfile) says about the build context. In `.theorem/`, the build context is always the root of the repository.
* With `dockerfile` set, `.theorem/` can still hold each file of [its table](#theorem-on-your-repository), because the `Dockerfile` reads the whole repository. So the last two sentences of the second item of [dockerfile](#dockerfile), on where the fuzz target sources, the build patches and `sources` go and on the files that the project directory can then hold, apply only to `projects/<name>/`.
* In `.theorem/`, a fuzz target of [fuzz_targets](#fuzz_targets) that the build does not make yet does not fail the build when `statements/` holds its file. Its statements need a proof, and the check "Theorem Verify" says that it is not built yet ([statements/](#statements)).
* [Limits](#limits) takes the place of the rules of [Rules for each file](#rules-for-each-file) on folders, on names, on sizes and on the number of files, and of its rule on the name of the project directory: the folder is `.theorem/`. `.theorem/` holds the folders `statements/` and `contracts/`, its 64 files are the files beside these folders, and a file of `statements/` has the size that its part gives. The rule of that part on `OFT_FRAME_POINTERS` applies to `.theorem/`.

Each other rule of this page applies to `.theorem/` as it applies to `projects/<name>/`.

### config.yml

`config.yml` holds the fields of `project.yaml` ([above](#the-fields)), with two changes:

* It has no `repo`. The project's repository is the repository that holds `.theorem/`.
* It can have one more field, `name`: the name of the project. The default is the name of the repository, in lower case.

`proofs` keeps its form: `repo` and `path` ([above](#proofs)). `theorem app setup` refuses a top-level `repo`. It also refuses each field that is neither `name` nor in the table of fields.

`theorem app setup` refuses a `name` that another enrolled repository holds ([below](#a-project-that-is-enrolled-today)).

### The build context

The Docker build context is the root of the repository at the commit that `theorem app build` builds. This is also true for a `Dockerfile` in `.theorem/`. Thus the `Dockerfile` names each file by its path from the root, for example `COPY .theorem/build.sh $SRC/`. It takes the project's source with `COPY`, for example `COPY . $SRC/<name>`, not with `fetch-commit`.

`theorem app build plan` builds the `Dockerfile` with the build arguments `COMMIT`, `REPO` and `BASE_BUILDER`. A `Dockerfile` must be in `.theorem/`, unless `dockerfile` names a `Dockerfile` in another place of the repository.

### statements/

`statements/` holds one file `<target>.<ext>` for each fuzz target that has statements. `<ext>` is the file extension of the prover that the fuzz target's `harness.yaml` names: `v` for Rocq, which is the only prover today. For example, the Rocq statements of the fuzz target `fuzz_pcap` are in `statements/fuzz_pcap.v`.

`statements/` holds at most 1,000 files. Each file is at most 1 MiB.

The fuzz target must be in `fuzz_targets`. It can be a fuzz target that the build does not make yet. Then its statements need a proof.

### contracts/

`contracts/<target>/` holds two files for each function of the proof plan of the fuzz target `<target>`. Theorem's agents write the proof plan.

* `<function>.contract.md` is the contract of the function.
* `<function>.check.<ext>` is the contract check of the function.

`<function>` is the name of the function, with `_` in place of each character outside `A-Z a-z 0-9 _`. `<ext>` is the source extension of the language of the fuzz target: `c`, `cc`, `rs`, `py` or `go`.

The contract is a Markdown file. It has these four parts, in this order:

1. `## Declaration`: the declaration of the function, in a fenced block in the language of the source.
2. `## Requires`: what the function requires.
3. `## Promises`: what the function promises.
4. `## May change`: what the function may change.

The contract check is a small fuzz harness:

* It defines the entry point of the fuzz target, for example `LLVMFuzzerTestOneInput` in C and C++.
* It calls the function with inputs that meet what the contract requires.
* It builds with the project's own build.
* It calls `abort()` when a promise of the contract does not hold.

`theorem app setup` checks the form of the two files.

### Limits

`.theorem/` obeys these limits:

* Beside `statements/` and `contracts/`, it holds at most 64 regular files.
* It holds no symbolic link.
* It holds no folder other than `statements/`, `contracts/` and `contracts/<target>/`, where `<target>` is a fuzz target of `config.yml`.
* Each file beside `statements/` and `contracts/` has a name that uses only `A-Z a-z 0-9 . _ -` and starts with a letter or digit.
* Each file is UTF-8 text. A seed corpus is the only exception.
* `config.yml` is at most 128 KiB.
* `build.sh`, a fuzz target source, a file that `sources` copies or reads, and a build patch are each at most 256 KiB.
* Each other file beside `statements/` and `contracts/`, but a seed corpus ([Seed corpora](#seed-corpora)), is at most 64 KiB.

### A project that is enrolled today

A project is enrolled today when its directory `projects/<name>/` is in this repository and its `primary_contact` is not `n/a`. The repository that its `repo` field names holds the name `<name>`. Thus the project keeps its name when it moves to `.theorem/`. A seeded project is adopted as [Seeded projects](#seeded-projects) says.

In the setup pull request, the maintainer's agent moves the files of `projects/<name>/` into `.theorem/`, as the skill `theorem-setup` tells. `project.yaml` becomes `config.yml`, with no `repo`. The agent changes each `COPY` and each path of the `Dockerfile` for the new build context ([above](#the-build-context)). For example, `COPY build.sh $SRC/` becomes `COPY .theorem/build.sh $SRC/`.

## Seeded projects

We seeded some projects ourselves. A project whose proofs we publish in [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs) is in `projects/<name>/`. Each other one is in [seeds/](../seeds/)`<name>/`: its `project.yaml`, and its build files if it has any. We used the build data of the oss-fuzz-theorems 2026.10 release. A seeded project has `primary_contact: n/a`. Its `project.yaml` starts with two comment lines that tell that we seeded it. `oss-verify validate` warns about `n/a`, and the `oss-verify validate` row of the triage comment on a pull request shows that warning.

From [this commit of OSS-Fuzz](https://github.com/google/oss-fuzz/tree/bd2ce21991a94a362b92fb1bf25f86d5a1a60842), we seeded each project that our builder can build and that we can describe honestly. A seeded `project.yaml` gives only what the recorded build data tells, and no guess. [seeded-projects.tsv](seeded-projects.tsv) lists each of the 1,381 projects of OSS-Fuzz at that commit. For a project that we did not seed, it gives the reason.

A seeded project needs no seed corpus and no `mutant:` record while it is seeded. We did not write the fuzz targets of a seeded project to the rules of step 3 of the add-project skill ([.claude/skills/add-project/SKILL.md](../.claude/skills/add-project/SKILL.md)).

A core maintainer can adopt a seeded project. `enrollment` refuses a pull request from a fork that changes `projects/<name>/` of a seeded project. Such a change can change [seeded-projects.tsv](seeded-projects.tsv), and a pull request from a fork that changes `projects/` cannot change that table. So a maintainer of this repository makes the change on a branch of this repository, where the `tests` check runs the test of the table. To adopt a seeded project, make the change in a branch of your fork, and open its pull request with the checklist done, "I accept the OSS Verify terms" ticked, and `projects/<name>` in its description (the heading of the template names it). `enrollment` refuses that pull request, and it stays your record that you accept the terms. A maintainer of this repository then carries the change on a branch of this repository. The pull request of that branch names yours on a line `Adoption: #<number>` of its description. `terms-accepted` passes the branch only when your pull request comes from a fork, ticks the box, and names that project and no other. A later change of `primary_contact`, or an added `auto_ccs` address, of a seeded project needs the same record, from the new address. Every `seeds/<name>/project.yaml` keeps `primary_contact: n/a` and no `auto_ccs`: the addresses go in `projects/<name>/project.yaml`. Make the change with these steps:

1. Copy its `projects/<name>/`, or its `seeds/<name>/`, to `projects/<name>/` in a branch of your fork.
2. Remove each patch that fixes a bug. The directory of a seeded project whose proofs we publish can hold such a patch, but the directory of an enrolled project cannot ([above](#build-patches)). For each one, delete the patch file, its line in `series`, its `patch` line in `sources`, and its name where the `Dockerfile` or `build.sh` copies or applies it. `lay-out-sources` applies each `patch` line of `sources` in turn, and stops when those lines are not the patches that `series` lists, in the same order. So keep the patches that remain in their order in both files.
3. Set `primary_contact` to the address that gets findings.
4. Remove the two comment lines.
5. Make the fuzz targets obey the rules of step 3 of the add-project skill ([.claude/skills/add-project/SKILL.md](../.claude/skills/add-project/SKILL.md)), with their seed corpora and breakages. Do this before you open the pull request that enrolls the project.
6. Do the steps in the [README](../README.md#enroll-a-project) from step 3.

The build files of a seeded project come from the build recipe of that release. They make that release's binaries again, byte for byte. A patch that the build files apply since the check of their seed port, or no longer apply, can change some of these binaries ([build-contract.md](build-contract.md#builds-ported-from-oss-fuzz-theorems)). The build notes in [seeded-projects.tsv](seeded-projects.tsv) name each such patch, and tell which binaries differ from the release's, or may differ. When the build notes of a project say that some binaries may differ and do not name them, each binary of that project may differ. Keep the build files, or write your own. If a seeded project has no build files, [seeded-projects.tsv](seeded-projects.tsv) tells why. Add a `Dockerfile` and a `build.sh` before you open the pull request.

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

The seed corpus of a `python` project is an input of the build of its fuzz target. The build gives the seeds to `pyclosure.py`, which runs the harness on each one, and the modules that these runs reach go into the frozen module set of the binary ([infra/base-builder/python/recipes.sh](../infra/base-builder/python/recipes.sh), `oft_py_freeze`). Thus a change to such a seed corpus can change the bytes of the binaries. For each other language, no build reads the seeds. `uv run oss-verify check --checks` runs the seeds of a `c` or `c++` project to measure its checks, and that run changes no binary ([build-contract.md](build-contract.md#the-checks-of-a-fuzz-target)).

### Build patches

`series` lists each patch that the build applies, one file name on each line, in order, but not the patches of a C library that the build declares (below). We ignore empty lines and lines that start with `#`. List each patch exactly once.

The build applies each patch with `git apply` under `core.symlinks=false`, so a patch cannot make a symbolic link: a link in a patch becomes a regular file holding the text of its target.

A patch in the `series` of an enrolled project can only change how the project builds. For example, it can make the build static, set up cross-compilation, correct a version stamp or make a generated file. A change that fixes a bug of your project never goes in the directory of your project. We send it to you as a patch, with its finding ([what-gets-proven.md](what-gets-proven.md#findings)). If we publish a proof that needed that patch, we publish the patch with the proof ([what-gets-proven.md](what-gets-proven.md#publishing)). Only the directory of a seeded project whose proofs we publish can hold such a patch ([build-contract.md](build-contract.md#build-patches)).

A build can declare its own C library. A patch of that C library is a file of the project directory. Its name does not end in `.patch`, because `oss-verify validate` asks `series` to list each file with that ending. A `copy` line of `sources` lays it out, and `build.sh` applies it. What such a patch can change is in [build-contract.md](build-contract.md#the-c-library), "The C library".

### Rules for each file

Each file must obey these rules:

* It is a regular file. Symbolic links and subdirectories are not permitted.
* Its name uses only `A-Z a-z 0-9 . _ -` and starts with a letter or digit.
* It is UTF-8 text. A seed corpus is the only exception.
* Its size is at most 128 KiB for `project.yaml`.
* Its size is at most 256 KiB for `build.sh`, a fuzz target source, a file that `sources` copies or reads, or a build patch.
* Its size is at most 64 KiB for each other file.
* The `Dockerfile` and `build.sh` do not name `OFT_FRAME_POINTERS`, because only the toolchain image gives that setting ([build-contract.md](build-contract.md#frame-pointers)).

The project directory holds at most 64 files. Its name uses only `a-z 0-9 . _ -`, starts with a letter or digit, and has at most 63 characters.
