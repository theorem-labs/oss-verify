---
name: add-project
description: Use when a maintainer asks to enroll a project in OSS Verify, or when you write or correct a project's fuzz targets (DSL ones included), its patch_style.md, or a port of its OSS-Fuzz build to the OSS Verify builder.
---

# Enroll a project in OSS Verify

You help a maintainer make one directory, `projects/<name>/`, and a pull request that the maintainer opens.

Work only in `projects/<name>/`. First read `README.md` (and get the tools its "Enroll a project" lists), `docs/project-yaml.md`, `docs/build-contract.md`, `docs/what-gets-proven.md` and, for API-level fuzz targets, `docs/dsl.md`. Tell the maintainer what the README's "Who can enroll" says about our capacity.

## 1 and 2. Ask the maintainer

Before you talk to the maintainer, read [references/maintainer-questions.md](references/maintainer-questions.md): step 1 asks what "correct" means, for the fuzz targets, and step 2 asks about findings, reports and patches, for `patch_style.md`. Ask each question; do not guess an answer.

## 3. Write the fuzz targets

Start from the fuzz targets the maintainer keeps (its own and its OSS-Fuzz ones), then write those that step 1 needs. A fuzz target defines `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. For an API-level entry point, start from the DSL (`docs/dsl.md`); any shape that obeys this step is fine. Put each in `projects/<name>/`, with a suffix the project's language permits.

A weak fuzz target makes the theorems vacuous. OSS-Fuzz's fuzz targets often break these rules, and `oss-verify validate` and `check` pass them: many return -1 for malformed input (3.7), and some ignore an API's result. Read each one you keep against each rule below, and correct it.

### 3.1 Drive the API

Read the input as a small program: each byte or field selects the next call and its arguments. Make the decoding total: every input is a sequence, ended by the end of the input. Write one fuzz target for each group of properties or API area; code that needs another sanitizer configuration is a separate fuzz target. A DSL driver also obeys `docs/build-contract.md`, "The fuzz targets".

### 3.2 Write each property as a check that aborts

Write `if (!condition) abort();` after the calls. Never `assert()`: a build that defines `NDEBUG`, such as CMake's `Release`, removes it without a warning. Above the check, a comment says in the maintainer's words what it checks and why it must be true. Compute the expected value from the input and the documented rule, not with the library's own function or state: such a check shows only that the library agrees with itself. A comparison of two public entry points is a property only when the comment says that they must agree, and they do not share the code that computes the value.

### 3.3 Show that each check runs

A small set of inputs, the coverage witness, must run each API call and each property check at least once. Put the inputs at the top level of `projects/<name>/<target>_seed_corpus.zip` (`docs/project-yaml.md`, "Seed corpora"). Read [references/witness-and-breakage.md](references/witness-and-breakage.md) for the commands that show each count is more than 0.

### 3.4 Show that each property can fail

For each property, find a breakage: a one-line change, in the library or the fuzz target, that makes the property fail on an input of the seed corpus (the same reference says how). Undo the change, and record it with the input in the property's comment. The path starts at the `WORKDIR` of the `Dockerfile`, the line is its number at the commit `repo` names, and the old text occurs once on it (`docs/build-contract.md`, "The checks of a fuzz target"):

       /* The checksum of the block closes.
        * mutant: src/checksum.c:51 `return sum == 0;` -> `return 1;`
        * input: corrupt-block */
       if (!block_sums_to_zero(frame)) abort();

A property that no change can make fail checks nothing: write it again. A stop that is not a property, such as `if (!buf) abort();` after a failed allocation, gets `not a property: <reason>` in its comment in place of a record. A change of several lines can be a patch: save it with `git diff` into one directory for all such patches, and set `mutants` in `project.yaml` to it.

### 3.5 Make each run end quickly

Bound each count, size and loop that comes from the input (a modulus, a small maximum), but not a value that the property needs to be large. Do not recurse on the depth of the input without a limit.

### 3.6 Depend only on the input

The statements use [Linux Process Semantics](https://github.com/theorem-labs/rocq-linux-process-semantics), in which a process has one thread and the input is its only data. Start no thread, read no clock, take each random number from the input, use no network or environment, and open no file but the input and temporary files.

### 3.7 Return 0 or -1

- Do not call `exit()` or `_exit()`, catch all exceptions, install a signal handler, register an exit handler that does not return, call `std::set_terminate`, or in Rust replace the panic hook: each hides failures (`docs/build-contract.md`, "What the driver does not intercept").
- A failed property calls `abort()` (3.2), never `return -1`: libFuzzer reads -1 as "do not keep this input", and the driver counts -1 as a pass.
- An expectation that the input chooses, such as an `expect` frame of a DSL driver, often fails, which is normal. Evaluate each, then return -1 if any failed, else 0; the driver prints the return value.
- -1 can also reject an input outside a property's domain, for few inputs only (3.3).
- Everything else returns 0. Turn each expected outcome into `return 0` narrowly: check the library's error code, or catch the one exception type the API documents.

### 3.8 Give each file its licence lines

Each file of code in `projects/<name>/` (fuzz targets, `Dockerfile`, `build.sh`, scripts) begins with licence lines, below only a `#!`, `# syntax=` or `coding:` line. Build patches, `project.yaml`, `sources`, `series`, `patch_style.md`, locks and seed inputs need none. No check reads them. Before you write the first file, read [references/licence-lines.md](references/licence-lines.md) for the case of each kind of file. Add no licence file, and do not change `LICENSE`, `LICENSES/` or `NOTICE`.

## 4. Port the build

Read [references/porting.md](references/porting.md) before you write the `Dockerfile` and `build.sh`: it gives the rules for each language.

## 5. Write project.yaml

Start from `templates/project.yaml`. Fill in `repo` with `#<tag or branch>`, `primary_contact` (public: it gets the findings), `language`, `fuzz_targets`, `patch_style` if `patch_style.md` is in the project's repository, and each other field the maintainer wants, such as `auto_ccs`, `pgp` and `publish` (ask; `after_fixes` by default). Leave out `ubsan_checks` unless the maintainer wants other checks than the default, and remove a check only when it flags code that is not a bug (`docs/project-yaml.md`, "ubsan_checks").

## 6. Check

`oss-verify check` builds the `Dockerfile` with network access: read the `Dockerfile` first.

1. Run `uv run oss-verify validate projects/<name>`, and correct each problem.
2. Run `uv run oss-verify check --no-shell --twice <name>`, and correct each problem. The fuzz targets it finds in each build are those in `fuzz_targets`, and it reports that the second build has the same bytes.
3. Each property has a coverage witness (3.3) and a breakage (3.4). For a C or C++ project, `uv run oss-verify check --no-shell --checks report.md <name>` (with `qemu-riscv64-static` on `PATH`) lists each check that misses one, as the pull request's Build check does.

## 7. Prepare the pull request

1. Make a branch that changes only `projects/<name>/`. Write the description from `.github/PULL_REQUEST_TEMPLATE.md`; in its context note, say in a few lines what each fuzz target checks, and which files came from where (3.8).
2. Optional: preview the triage comment, as `CONTRIBUTING.md`, "Review of an enrollment", says.
3. Show the branch and the description to the maintainer. The maintainer opens the pull request: only they can confirm "I am a core maintainer" and accept the OSS Verify terms.
