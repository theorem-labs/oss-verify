# What gets proven

This page tells what our statements say and what a proof covers. It also tells what we do with a finding, and what we publish. It is for maintainers and for reviewers of our claims.

This repository tells how to build the fuzz targets of a project. The statements and their proofs are in [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs), on its main branch: each project's statements and lock in `projects/<name>/`, and its proofs in `proofs/<name>/`. This page gives a summary. The Rocq definitions in the proofs repository are the authority.

## The statements

A statement is about the exact bytes of one binary: one fuzz target in one build, pinned by its SHA-256 in the lock. We state it in [rocq-linux-process-semantics](https://github.com/theorem-labs/rocq-linux-process-semantics), a formal model of a riscv64 Linux process. A statement is about each input that the process can get:

* the input file and its contents, or no file;
* the arguments and the environment;
* the rest of the process's world, as the model defines it.

There are two main statements:

* **Halts.** On each input that stays in the build's memory budget, each run exits with status 0 or 2 ([below](#what-a-statement-accepts)). Thus the binary does not crash, fail an assertion, hang, or fail a sanitizer check on such an input.
* **Agrees.** On each input on which the plain build stays in its budget, the plain build and a sanitizer build both reach no error. They also have the same behaviour: they write the same bytes and exit with the same status. A sanitizer detection stops the program, so this statement excludes each error that the sanitizer checks.

The project's directory in the proofs repository, `projects/<name>/`, lists the statements of each fuzz target and build, and the proofs that are done.

## What a statement accepts

A statement accepts only the exit statuses **0 and 2** ([build-contract.md](build-contract.md#exit-statuses)). Status 0 tells that each call of the fuzz target returned 0 or -1. Status 2 tells that the driver refused the input, for example a file of 64 MiB or more.

**Next toolchain version.** For a fuzz target in C, C++ or Rust, and for a DSL fuzz target, the driver exits with status 3 when one or more calls returned -1. A halts statement for such a fuzz target then accepts 0, 2 and 3. The drivers for Python, JavaScript, Go and JVM fuzz targets do not give status 3, so their halts statements accept only 0 and 2. A project with proofs keeps today's driver ([build-contract.md](build-contract.md#exit-statuses)).

Thus each expected outcome must end as `return 0`. Examples of expected outcomes are malformed input that the library rejects, a size limit, and an error code from the library.

> **WARNING:** Do not return 1 for an input that is not of interest, as some OSS-Fuzz fuzz targets do. That return value makes the statement false.

> **WARNING:** Do not return -1 for a failed property. -1 counts as a pass, so the statement holds although the property fails. For a failed property, call `abort()`.

## What the statements catch

The statements catch each failure that the fuzz target would catch in OSS-Fuzz: a crash, a hang, a failed assertion or a sanitizer detection. They catch it on each input, not only on the inputs that a fuzzer tries.

There are exceptions, and this is the full list. Each exception is a limit of how we run the fuzz target, which these builds cannot remove. No exception is a choice that a project makes.

* **Leaks.** Leak detection is off in the AddressSanitizer builds (`detect_leaks=0`). The leak check of LeakSanitizer at exit cannot run in the sealed static runtime. Thus a leak, which OSS-Fuzz reports, is not an error here.
* **A UBSan check that trap mode cannot make.** The UBSan builds trap, with no runtime. Thus they leave out `vptr`, which needs a runtime. OSS-Fuzz makes it ([below](#ubsan-checks)).
* **No MemorySanitizer.** There is no MemorySanitizer build, so we do not check reads of uninitialized memory. OSS-Fuzz runs MemorySanitizer for some projects. MemorySanitizer needs each library in the program built with it, the C and C++ libraries included. This static riscv64 toolchain does not supply them.
* **One thread.** The process model runs one thread. A fuzz target that starts a thread leaves the model. We cannot prove its statements until the model includes threads.
* **Inputs smaller than 64 MiB.** The driver refuses an input file of 64 MiB or more, with status 2. Thus no statement is about a larger input.
* **The size classes of the AddressSanitizer allocator.** On riscv64, this allocator refuses a request when the size class of the request holds 3.5 GiB. The plain build can use up to 16 GiB. Thus an AddressSanitizer build can refuse memory to an input that the plain build accepts. For this cause, their budgets are different ([below](#memory-budgets)).

*This list is a draft. We will audit it against the toolchain and the process model.*

## UBSan checks

A statement about a `ubsan` or `asan-ubsan` binary names the UBSan checks in effect in its build. A check that is not in effect is not part of the statement.

* **Today's toolchain vintage.** The checks are fixed: those that clang's `undefined` group makes in trap mode ([build-contract.md](build-contract.md#the-builds)).
* **The next toolchain version.** The checks are those that OSS-Fuzz makes fatal, changed by the project's `ubsan_checks` if it has one ([project-yaml.md](project-yaml.md#ubsan_checks)).

These are the default checks of a `c++` project:

    array-bounds bool builtin enum function integer-divide-by-zero null object-size return
    returns-nonnull-attribute shift signed-integer-overflow unreachable vla-bound

The default of a `c` or `python` project is the same, less `function`, and so are the checks of a `c++` project's C files. OSS-Fuzz leaves `function` out of those compiles too. Trap mode leaves out `vptr`, which OSS-Fuzz makes. OSS-Fuzz also instruments `unsigned-integer-overflow`, but it silences the reports, so its default does not catch an unsigned overflow either. An unsigned overflow is not undefined behaviour, and correct code uses it.

## Memory budgets

A program can run out of memory, and a statement must tell what happens then. The statements obey these rules:

* **Exhaustion is part of the statement.** The process model refuses a memory request only when the build has used its budget. The program can then stop because it has no memory, and the statement permits this. But each run must halt.
* **Refusals at start do not count.** A statement is not about a program that gets no memory before it gets to the fuzz target.
* **No allocation fails at random.** No statement lets an allocation fail without a cause. There is no setting in `project.yaml` for out-of-memory behaviour.

A budget is a quantity of memory that a build can allocate. It is a condition of the statement: an input that needs more memory is not in the statement. It is not a failure. These are the defaults, which the oss-fuzz-theorems 2026.10 release uses:

```yaml
budgets:
  halts: 16GiB               # each build that runs alone
  agrees:                    # for each sanitizer: [plain side, sanitizer side]
    address: [2GiB, 512GiB]  # also for asan-ubsan
    undefined: [16GiB, 512GiB]
```

* `halts` is the budget of each build in its halts statement.
* `agrees.<sanitizer>` gives the two budgets of the agrees statement: the plain build's budget, which is the condition, and the sanitizer build's budget. The sanitizer build's budget is large, because a sanitizer needs memory of its own. `address` applies to the `asan` and `asan-ubsan` builds, and `undefined` to the `ubsan` build.
* The plain side of `address` is 2 GiB, because the AddressSanitizer allocator limits each size class to 3.5 GiB on riscv64. The address space that the AddressSanitizer runtime reserves at start, more than 100 GiB, is not part of a budget.

A project can set its own budgets in `project.yaml` ([project-yaml.md](project-yaml.md#budgets)).

**Not decided yet:** maybe the `asan` and `asan-ubsan` builds need a smaller `halts` budget. Their allocator can refuse memory to an input that is in the 16 GiB budget.

## Allocation failure

The halts statement does not ask a program to survive a refused allocation. A project that wants its library to survive refused allocations adds an allocation-failure fuzz target. In this fuzz target, allocations fail as the input tells them to ([build-contract.md](build-contract.md#allocation-failure-fuzz-targets)). The other fuzz targets do not get refused allocations.

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
* what the process model leaves out. The model's documentation tells where it is narrower than Linux.

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
* While the finding stands, we do not publish the project's statements and proofs.

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
* We publish a seeded project only while it has no findings.
* If a proof needed a patch to the project's code, we publish it only once the finding that the patch fixes is public. We list the patch with the proof: its text, a summary, and whether the project has it.

## Where the claims come from

Each public claim rests on three pinned inputs, and on a fourth when a proof needed a patch:

* the commit of the project's source;
* the commit of this repository that holds the build files;
* the digest of the toolchain image;
* for a proof that needed a patch to the project's code, the patch, which we publish with the proof ([above](#publishing)).

We pin only binaries that two clean builds reproduce ([build-contract.md](build-contract.md#reproducibility)). A published proof uses the released process model, these build files, and the project's source as it is, or with the published patch. A patch that fixes a bug is never in the project directory: the build files there contain build patches only, which change how the project builds and fix no bug ([project-yaml.md](project-yaml.md#build-patches)).

To check a binary yourself, follow [build-contract.md](build-contract.md#check-a-binary-against-a-lock). It tells how to rebuild the binary and compare it with the lock. `tools/check` builds the project's source as it is, so it does not rebuild a binary that needed a patch to the project's code.
