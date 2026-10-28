# What gets proven

This page tells what our statements say and what a proof covers. It also tells what we do with a finding, and what we publish. It is for maintainers and for reviewers of our claims.

This repository tells how to build the fuzz targets of a project. The statements and their proofs are in [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs), on its main branch: each project's statements and lock in `projects/<name>/`, and its proofs in `proofs/<name>/`. This page gives a summary. The Rocq definitions in the proofs repository are the authority.

## The statements

A statement is about the exact bytes of one binary: one fuzz target in one build, pinned by its SHA-256 in the lock. We state it in [Linux Process Semantics (LPS)](https://github.com/theorem-labs/rocq-linux-process-semantics), a formal model of a riscv64 Linux process. A statement is about each input that the process can get:

* the input file and its contents, or no file;
* the arguments and the environment;
* the rest of the process's world, as LPS defines it.

There are two main statements:

* **Halts.** On each input that stays in the build's memory budget, each run exits with a status that the statement accepts, usually 0 or 2 ([below](#what-a-statement-accepts)). Thus the binary does not crash, fail an assertion, hang, or fail a sanitizer check on such an input.
* **Agrees.** On each input on which the plain build stays in its budget, the plain build and a sanitizer build both reach no error. They also have the same behaviour: they write the same bytes and exit with the same status. A sanitizer detection stops the program, so this statement excludes each error that the sanitizer checks.

The project's directory in the proofs repository, `projects/<name>/`, lists the statements of each fuzz target and build, and the proofs that are done.

## What a statement accepts

A halts statement accepts only the exit statuses that its `exits` field names. Most `budget` halts statements accept only **0 and 2** ([build-contract.md](build-contract.md#exit-statuses)). Status 0 tells that each call of the fuzz target returned 0 or -1. Status 2 tells that the driver refused the input, for example a file of 64 MiB or more. A `may-fail` halts statement, and a few `budget` ones, accept any exit status ([below](#memory-budgets)).

**Next toolchain version.** For a fuzz target in C, C++ or Rust, and for a DSL fuzz target, the driver exits with status 3 when one or more calls returned -1. A halts statement for such a fuzz target then accepts 0, 2 and 3. The drivers for Python, JavaScript, Go and JVM fuzz targets do not give status 3, so their halts statements accept only 0 and 2 (our tools do not write theorem statements for Go yet). A project with proofs keeps today's driver ([build-contract.md](build-contract.md#exit-statuses)).

Thus each expected outcome must end as `return 0`. Examples of expected outcomes are malformed input that the library rejects, a size limit, and an error code from the library.

> **WARNING:** Do not return 1 for an input that is not of interest, as some OSS-Fuzz fuzz targets do. That return value makes the statement false.

> **WARNING:** Do not return -1 for a failed property. -1 counts as a pass, so the statement holds although the property fails. For a failed property, call `abort()`.

## What the statements catch

The statements catch each failure that the fuzz target would catch in OSS-Fuzz: a crash, a hang, a failed assertion or a sanitizer detection. They catch it on each input, not only on the inputs that a fuzzer tries.

There are exceptions, and this is the full list. Each exception is a limit of how we run the fuzz target, which these builds cannot remove. No exception is a choice that a project makes.

* **Leaks.** Leak detection is off in the AddressSanitizer builds (`detect_leaks=0`). The leak check of LeakSanitizer at exit cannot run in the sealed static runtime. Thus a leak, which OSS-Fuzz reports, is not an error here.
* **A UBSan check that trap mode cannot make.** The UBSan builds trap, with no runtime. Thus today's builds leave out `vptr`, which needs a runtime. OSS-Fuzz makes it ([below](#ubsan-checks)). With the next toolchain version, the `ubsan` build of a `c++` project makes it through a trap-only handler, in code compiled with RTTI; the `asan-ubsan` build still leaves it out.
* **No MemorySanitizer.** There is no MemorySanitizer build, so we do not check reads of uninitialized memory. OSS-Fuzz runs MemorySanitizer for some projects. MemorySanitizer needs each library in the program built with it, the C and C++ libraries included. This static riscv64 toolchain does not supply them.
* **One thread.** A process in LPS runs one thread. LPS does not cover a fuzz target that starts a thread. We cannot prove the statements of such a fuzz target until LPS includes threads.
* **Inputs smaller than 64 MiB.** The driver refuses an input file of 64 MiB or more, with status 2. Thus no statement is about a larger input.
* **The size classes of the AddressSanitizer allocator.** On riscv64, this allocator refuses a request when the size class of the request holds 3.5 GiB. The plain build can use up to 16 GiB. Thus an AddressSanitizer build can refuse memory to an input that the plain build accepts. For this cause, their budgets are different ([below](#memory-budgets)).

*This list is a draft. We will audit it against the toolchain and LPS.*

## UBSan checks

A statement about a `ubsan` or `asan-ubsan` binary names the UBSan checks in effect in its build. A check that is not in effect is not part of the statement.

* **Today's toolchain vintage.** The checks are fixed: those that clang's `undefined` group makes in trap mode ([build-contract.md](build-contract.md#the-builds)).
* **The next toolchain version.** The checks are those that OSS-Fuzz makes fatal, changed by the project's `ubsan_checks` if it has one ([project-yaml.md](project-yaml.md#ubsan_checks)).

These are the default checks of a `c++` project:

    array-bounds bool builtin enum function integer-divide-by-zero null object-size return
    returns-nonnull-attribute shift signed-integer-overflow unreachable vla-bound vptr libcxx-hardening

`libcxx-hardening` is libc++'s extensive hardening mode, which OSS-Fuzz does not turn on: a failed libc++ precondition traps, as a UBSan check does. It and `vptr` are made in the `ubsan` build only. The default of a `c` or `python` project is the same, less `function`, `vptr` and `libcxx-hardening`, and the checks of a `c++` project's C files are the same less `function`. OSS-Fuzz leaves `function` out of those compiles too. OSS-Fuzz also instruments `unsigned-integer-overflow`, but it silences the reports, so its default does not catch an unsigned overflow either. An unsigned overflow is not undefined behaviour, and correct code uses it.

## Memory budgets

A program can run out of memory, and a statement must tell what happens then. The statements obey these rules:

* **Each statement has a reading.** The reading is a field of the statement. It tells which calls LPS can refuse.
  * `budget` (halts statements): a call fails only where the process's own state forces it to. Thus LPS refuses a memory request only when the build has used its budget or no address range is free.
  * `alloc-forced-only` (agrees, bound and decidability statements): any other system call can fail, but memory is refused as in `budget`.
  * `may-fail` (halts, agrees, bound and decidability statements): any system call can fail at any time, and memory requests too.
* **A `budget` halts statement permits exhaustion.** On each input in the budget, each run exits with a status that the statement accepts (usually 0 or 2). A run that stops because it has no memory must exit with such a status too, or the statement is false. Refusals at start do not count: the statement is not about a program that gets no memory before it gets to the fuzz target.
* **A `may-fail` halts statement covers each refusal.** Each run must halt, whatever LPS refuses, but it can exit with any status. A refusal at start counts: a build that waits forever when a refusal at start occurs makes the statement false.
* **An agrees statement compares behaviour.** It does not claim that a run halts. An input on which the plain build is refused memory for its budget is not in the statement. In an `alloc-forced-only` agrees statement, a memory refusal that only the sanitizer build gets, because it used its budget or found no free address range, can make the two builds write different bytes, and that makes the statement false. In a `may-fail` agrees statement, either build can get any refusal. So each output of one build, under some refusals, must also be an output of the other build, under some refusals.
* **Only a `may-fail` statement lets an allocation fail at random.** No other statement lets an allocation fail without a cause. There is no setting in `project.yaml` for out-of-memory behaviour.

A budget is a quantity of memory that a build can allocate. It is a condition of the statement: an input that needs more memory is not in the statement. It is not a failure. These are the defaults, which the oss-fuzz-theorems 2026.10 release uses:

```yaml
budgets:
  halts: 16GiB               # each build that runs alone; only 16GiB
  agrees:                    # for each sanitizer: [plain side, sanitizer side]
    address: [2GiB, 512GiB]  # also for asan-ubsan
    undefined: [16GiB, 512GiB]
```

* `halts` is the budget of each build in its halts statement. It is always 16 GiB: a project's own halts budget is not carried into the statements yet.
* `agrees.<sanitizer>` gives the two budgets of the agrees statement: the plain build's budget, which is the condition, and the sanitizer build's budget. The sanitizer build's budget is large, because a sanitizer needs memory of its own. `address` applies to the `asan` and `asan-ubsan` builds, and `undefined` to the `ubsan` build.
* The plain side of `address` is 2 GiB, because the AddressSanitizer allocator limits each size class to 3.5 GiB on riscv64. The address space that the AddressSanitizer runtime reserves at start, more than 100 GiB, is not part of a budget.
* So a plain side of `address` that is more than 2 GiB can make an agrees statement false for a correct program.

A project can set its own budgets in `project.yaml` ([project-yaml.md](project-yaml.md#budgets)).

A statement made under a project's own budgets names both of them. A smaller plain-side budget covers fewer inputs. A larger sanitizer-side budget lets the sanitizer build use more memory before a refusal counts as a difference. So two agrees statements with different budgets claim different things: compare the budgets before you compare the statements.

**Not decided yet:** maybe the `asan` and `asan-ubsan` builds need a smaller `halts` budget. Their allocator can refuse memory to an input that is in the 16 GiB budget.

## Allocation failure

A `budget` halts statement does not ask a program to survive a refused allocation. A `may-fail` statement does: in it, any allocation can fail. A project that wants its library to survive refused allocations adds an allocation-failure fuzz target. In this fuzz target, allocations fail as the input tells them to ([build-contract.md](build-contract.md#allocation-failure-fuzz-targets)). In the other fuzz targets, the driver makes no allocation fail.

## Write "correct" into the fuzz target

A statement covers what the fuzz target checks. Thus the fuzz target is the place to say what "correct" means.

* A fuzz target that only gives its input to the library shows only that the library does not crash, hang or fail a sanitizer check.
* A fuzz target that checks a property, and aborts when it is false, makes the halts proof a proof of that property for each input. An example is `if (decompress(compress(x)) != x) abort();`. Do not use `assert()`: a build that defines `NDEBUG` removes it.

Put each property that a fuzz target can express into the fuzz target. The Rocq statements keep only what a fuzz target cannot express.

A project can use three types of fuzz target:

* its own fuzz targets, from its repository;
* its OSS-Fuzz fuzz targets;
* fuzz targets that we write with the project, in the project directory. These include drivers that call the library's API in sequences that the input selects.

A fuzz target that needs a different sanitizer configuration is a separate fuzz target.

## What a proof covers

A proof covers these items:

* the bytes of the binary: the library, the fuzz target and the driver, as compiled for that build;
* each input in the budget, which includes each input file smaller than 64 MiB;
* in a sanitizer build, each check that the build makes ([build-contract.md](build-contract.md#the-builds)).

A proof does not cover these items:

* the source of the library in general: another compiler, other flags, another architecture, or the x86-64 builds of OSS-Fuzz;
* the exceptions above, and errors that no sanitizer checks, here or in OSS-Fuzz, for example an access through another live object;
* code that no sanitizer instruments: the C library, the compiler's runtime libraries and the sanitizer runtime. OSS-Fuzz does not instrument them either;
* inputs that need more memory than the budget;
* what LPS leaves out. The documentation of LPS tells where it is narrower than Linux.

## Findings

When we work on a proof, we can find a failure instead. An example is an input on which a fuzz target crashes, hangs, fails an assertion or fails a sanitizer check. We call this failure a finding.

A finding contains the input, the build and the binary, and the steps to reproduce it. It contains a patch when we have one. We also send each build problem to `primary_contact`. [theorem.dev/oss-verify](https://theorem.dev/oss-verify/#what-will-maintainers-receive) tells who generates findings and patches. We obey these rules:

* **We send the finding to you privately.** We send it to `primary_contact` and to each address in `auto_ccs`. If you set `pgp`, we encrypt the finding to your key and send it to `primary_contact` only.
* **There is no disclosure deadline.** We do not set a date on which a finding becomes public.
* **We do not publish findings.** You decide if and when a finding becomes public.
* **What we publish does not show the finding.** Until the finding is public, we hold back the statements that it affects. No file name, comment, patch or statement that we publish describes it.

A seeded project has `primary_contact: n/a`, because no maintainer has adopted it yet ([project-yaml.md](project-yaml.md#seeded-projects)). For a seeded project, these rules apply:

* We send a finding for a seeded project to no one. Nothing goes automatically to the project, to its security contact or to another person.
* There is no deadline.
* The finding stays with us until a person gives it to the project by hand.
* Until the finding is public, we do not publish the project's statements and proofs.

To report a vulnerability in this repository or its tools, follow [SECURITY.md](../SECURITY.md).

## When

There is no fixed timeline. A proof takes days of work, and often more. We can also stop work on a part of a project without a proof ([the terms](https://theorem.dev/oss-verify/terms/), section 1).

* We build the binaries when we start work on the project, and pin them in a lock. If `repo` names a branch or a tag, we build the commit that it names at that time ([project-yaml.md](project-yaml.md#repo)).
* We do not build again each time the branch moves. After the first proof, we update the proofs from time to time. An update can build a newer commit, and that build gets a new lock.

## Publishing

The `publish` field tells us when to publish the proofs, and the `proofs` field tells where ([project-yaml.md](project-yaml.md#publish)). We publish:

* the statements about the project's binaries;
* the proofs of these statements;
* the lock: the SHA-256 of each binary, the commit that we built it from, and the toolchain;
* the binaries and the source archives that we built them from;
* each patch a proof needed, once its finding is public (below).

We write the lock from the manifest of `tools/check` ([build-contract.md](build-contract.md#the-manifest)). Each value of `publish` obeys these rules:

* We publish nothing that shows a finding that is not public yet. We hold back the statements that the finding affects until it is public. What we publish does not tell why.
* We publish a seeded project only while none of its findings is private.
* If a proof needed a patch that fixes a bug, we publish it only once the finding of that bug is public. We publish the text of each such patch with the proof, as the list above tells. The `patches` list of the project's facts in the proofs repository gives the summary and the upstream state of each such patch. The state is one of three: the bug is reported to the project, the bug is fixed in the project, or it is not a bug. Where the facts publish it, `library.patch_count` gives the number of all the patches that the build applies ([facts.md](https://github.com/theorem-labs/oss-verify-proofs/blob/main/docs/facts.md)).

## Where the claims come from

Each public claim rests on three pinned inputs, and on a fourth when a proof of an enrolled project needed a patch:

* the commit of the project's source;
* the commit of this repository that holds the build files;
* the digest of the toolchain image;
* for a proof of an enrolled project that needed a patch to the project's code, the patch, which we publish with the proof ([above](#publishing)).

We pin only binaries that two clean builds reproduce ([build-contract.md](build-contract.md#reproducibility)). A published proof uses the released version of LPS, these build files, and the project's source. For an enrolled project, it uses the source as it is, or with the published patch. For a seeded project whose proofs we publish, the build files can also apply patches that fix bugs ([build-contract.md](build-contract.md#build-patches)). A published proof of such a project can thus be about a build that has patches.

To check a binary yourself, follow [build-contract.md](build-contract.md#check-a-binary-against-a-lock). It tells how to rebuild the binary and compare it with the lock, and which checkout of this repository to use with it: the commit in `oss_verifier.commit` for a lock that has that field, and `main` for a `harness.yaml` of the oss-fuzz-theorems 2026.10 release, which has none. At that checkout, the build files apply the patches that they hold. Thus `tools/check` can rebuild a binary of a seeded project whose proofs we publish. It does not apply a patch that is outside the project directory, so it does not rebuild a binary of an enrolled project that needed a patch to the project's code.
