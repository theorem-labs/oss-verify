# The rules of a fuzz target, its statements and its contracts

This page gives the rules that a fuzz target, its statements and its contracts must obey, and what the checks of a fuzz target find. It is for the maintainer of a project that enrolls from its own repository with the folder `.theorem/` ([project-yaml.md](project-yaml.md#theorem-on-your-repository)), and for the maintainer's coding agent. The skill [`theorem-setup`](../.claude/skills/theorem-setup/SKILL.md) tells the agent how to write `.theorem/` to these rules.

## The citations

A rule that cites lines of another document links them at a fixed commit. Thus a later edit of that document does not move a cited line.

* The links into this repository, theorem-labs/oss-verify, are to the commit [`889360251058a34691b2b30bdca79d941a0539fb`](https://github.com/theorem-labs/oss-verify/commit/889360251058a34691b2b30bdca79d941a0539fb).
* The links into the public proofs repository, theorem-labs/oss-verify-proofs, are to the commit [`89eb8357aef1a7c20efddbf4f39c2c0fb9c764a5`](https://github.com/theorem-labs/oss-verify-proofs/commit/89eb8357aef1a7c20efddbf4f39c2c0fb9c764a5).

A rule with no cited lines is new on this page. The rules of a contract are such rules. A link with no line numbers goes to a page of this repository that tells more about the same subject.

## How a fuzz target is declared and registered

A fuzz target is an executable that defines `LLVMFuzzerTestOneInput`. Each build writes it to `$OUT` ([project-yaml.md, lines 141-146](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/project-yaml.md?plain=1#L141-L146)).

* `fuzz_targets` in `.theorem/config.yml` names the fuzz targets that Theorem verifies. Without this field, Theorem verifies each fuzz target that the build makes (the same lines).
* A pull request registers a new fuzz target when it adds the fuzz target to `fuzz_targets`. The check "Theorem Verify" builds it, and statements can name it from that commit.
* A fuzz target that has statements must be in `fuzz_targets` ([project-yaml.md](project-yaml.md#statements)).

## What a fuzz target must be

A proof is only as strong as its fuzz target. Each fuzz target obeys these rules:

1. It is a static riscv64 Linux program for RV64G, linked with lld against musl ([build-contract.md, line 29](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L29)).
2. It is in each build of the project: the `plain` build, and each build that the field `sanitizers` asks for. The four builds are `plain`, `ubsan`, `asan` and `asan-ubsan` ([build-contract.md, lines 81-86](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L81-L86)).
3. `LLVMFuzzerTestOneInput` returns 0, or -1 to refuse an input. It returns -1 only for a failed expectation that the input chooses, or for an input outside the domain of a property. It never returns -1 for a failed property ([build-contract.md, line 348](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L348)).
4. It stops a failed property with `abort()`, not with `assert()`. A build that defines `NDEBUG` removes each `assert()` ([what-gets-proven.md, lines 106-110](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/what-gets-proven.md?plain=1#L106-L110), [build-contract.md, line 343](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L343)).
5. It installs no signal handler, and it registers no exit handler that does not return. A C++ fuzz target calls no `std::set_terminate`. A Rust fuzz target does not replace the panic hook ([build-contract.md, lines 285-289](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L285-L289)).
6. It calls no `exit()` and no `_exit()` ([the skill `add-project`, line 128](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/.claude/skills/add-project/SKILL.md?plain=1#L128)).
7. It runs as one process, and its input is its only data. It starts no thread and reads no clock. It takes each random number from the input. It uses no network and no environment. It opens no file other than the input and temporary files ([the skill `add-project`, lines 116-124](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/.claude/skills/add-project/SKILL.md?plain=1#L116-L124)).
8. Each count, size and loop that comes from the input has a bound ([build-contract.md, line 346](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L346)).

## What a statement must be

Theorem's agents write the statements of a fuzz target in `.theorem/statements/<target>.v`. A person at Theorem approves them before the App Theorem Verify commits them ([project-yaml.md](project-yaml.md#statements)). The maintainer's agent writes no statement. Each statement obeys these rules:

1. It applies a shape of [`theories/Shapes.v`](https://github.com/theorem-labs/oss-verify-proofs/blob/89eb8357aef1a7c20efddbf4f39c2c0fb9c764a5/theories/Shapes.v) of theorem-labs/oss-verify-proofs.
2. Each halting shape and each agreement shape is proved equal to the definition of [Linux Process Semantics (LPS)](https://github.com/theorem-labs/rocq-linux-process-semantics) that it stands for. LPS is the formal model of a riscv64 Linux process that the statements use ([statements.md, lines 11-14](https://github.com/theorem-labs/oss-verify-proofs/blob/89eb8357aef1a7c20efddbf4f39c2c0fb9c764a5/docs/statements.md?plain=1#L11-L14)).
3. It admits nothing (the same lines).
4. It names no function and no variable of the source.
5. A fuzz target has 5 to 15 statements ([statements.md, lines 48-49](https://github.com/theorem-labs/oss-verify-proofs/blob/89eb8357aef1a7c20efddbf4f39c2c0fb9c764a5/docs/statements.md?plain=1#L48-L49)).
6. A statement about a feature that does not exist yet is about a fuzz target that calls the feature.

## What the checks of a fuzz target find

`theorem app build checks` applies the checks of this part and of the next part to each fuzz target. The checks run the fuzz target on the inputs of its seed corpus ([project-yaml.md](project-yaml.md#seed-corpora)). On a setup pull request, the check "Theorem Verify" gives the result of each check. It names each check by the name in quotes below.

1. **Reach** ("reach"). A seed input reaches each property check of the fuzz target. A property check is a call of `abort()`. A run reaches it when the run evaluates its guard: the condition of its `if`, `while` or `for`, or the `switch` of its `case` or `default` label ([build-contract.md, lines 354-356](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L354-L356)).
2. **Breakages** ("breakages"). Each breakage makes a property check fire, and each property check has a breakage ([build-contract.md, lines 357-366](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L357-L366)). A breakage is a change to the code, of one of two kinds:
   * A record in the comment of the property check. It names a one-line change and the seed input that makes the check fire with the change:

         mutant: <path>:<line> `<old>` -> `<new>`
         input: <file name in the seed corpus>

   * A patch in the folder that the field `mutants` names ([project-yaml.md](project-yaml.md#mutants)).

   A stop that is not a property, for example `if (!buf) abort();` after a failed allocation, has one line `not a property: <reason>` in its comment, in place of the records. It needs no seed input and no breakage ([build-contract.md, line 367](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L367)).

## What the checks of the binaries of a fuzz target find

These checks hold each binary of a fuzz target against LPS, at the commit of LPS that `release.yaml` of theorem-labs/oss-verify-proofs names ([build-contract.md, line 375](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L375)).

1. **ELF and instructions** ("ELF and instructions"). Each binary is a 64-bit RISC-V executable. Each byte of its executable code is part of an instruction that LPS executes, or zero padding ([build-contract.md, line 377](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L377)).
2. **System calls** ("system calls"). The binary runs on the empty input and on the first 8 inputs of the seed corpus. Each system call of these runs is one that LPS has, with arguments and a result that LPS allows ([build-contract.md, line 378](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L378)).
3. **Quiet and loud** ("quiet and loud"). The quiet twin of the binary is the same link, with the objects of the driver built to write nothing. It runs on the same inputs. It writes nothing to standard output or standard error, and it exits with the same status as the binary ([build-contract.md, line 379](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L379)).
4. **Instrumented code** ("instrumented code"). A binary links no code that is built without the sanitizer of its build, other than the code that the cited lines allow, such as the C library and the other files of the toolchain image ([build-contract.md, lines 380-382](https://github.com/theorem-labs/oss-verify/blob/889360251058a34691b2b30bdca79d941a0539fb/docs/build-contract.md?plain=1#L380-L382)).

## What a contract and its contract check must be

Theorem's agents write the proof plan of a fuzz target. For each function of the proof plan, `.theorem/contracts/<target>/` holds two files ([project-yaml.md](project-yaml.md#contracts)):

| file | what it is |
|---|---|
| `<function>.contract.md` | the contract of the function |
| `<function>.check.<ext>` | the contract check of the function |

`<function>` is the name of the function, with `_` in place of each character outside `A-Z a-z 0-9 _`. `<ext>` is the source extension of the language of the fuzz target: `c`, `cc`, `rs`, `py` or `go`.

Theorem's agents write both files. A person at Theorem approves them before the App Theorem Verify commits them. The maintainer's agent writes no file of `contracts/`.

### The contract

The contract is a Markdown file in the terms of the source. It has these four parts, in this order:

1. `## Declaration`: the declaration of the function, in a fenced code block in the language of the source.
2. `## Requires`: what the function requires.
3. `## Promises`: what the function promises.
4. `## May change`: what the function may change.

### The contract check

The contract check is a small fuzz harness:

* It defines the entry point of the fuzz target: `LLVMFuzzerTestOneInput` in C and C++.
* It calls the function with inputs that meet what the contract requires.
* It calls `abort()` when a promise of the contract does not hold.
* It builds with the project's own build.

Before the App commits a contract check, Theorem's agent runs it against a stub of the function that does nothing. The contract check fails there. A contract check that passes on such a stub tests nothing.

### The form of the two files

* Each of the two files is at most 256 KiB.
* A contract with no contract check beside it fails setup. A contract check with no contract beside it fails setup too.
* `theorem app setup` checks the form of the two files.

### How the developer uses them

* The developer runs the contract checks with their usual build, on their own machine. They need no `theorem` binary and no access to Theorem.
* The developer, or their agent, pushes a function when its contract check passes. Theorem's agents then prove the function.
* The proofs stay in Theorem's proofs repository.

### Code shapes

This part is advice. No check enforces it. Code whose contracts stay small is easier to prove. Thus write bounded loops and small functions, and use no shared state.
