---
name: theorem-setup
description: Use when a maintainer sets up OSS Verify on their own repository with the folder .theorem/ and the GitHub App Theorem Verify, or asks to write or correct a file of .theorem/, or to move an enrolled project into .theorem/.
---

# Set up OSS Verify on a project's own repository

You are the maintainer's coding agent. You help the maintainer set up OSS Verify on the repository of their project, with the GitHub App Theorem Verify. You write the folder `.theorem/` at the root of the repository, and the description of the setup pull request. The maintainer opens the setup pull request.

Who writes what:

- You write each file of `.theorem/` outside `statements/` and `contracts/`.
- Theorem's agents write the statements, the contracts and the contract checks, in `.theorem/statements/` and `.theorem/contracts/`, after the merge. The App Theorem Verify commits them. A person at Theorem approves the contracts and the contract checks before the App commits them. Write no file of `statements/` or `contracts/`.
- No agent of Theorem writes or opens the setup pull request.

> **WARNING:** The App Theorem Verify is not made yet. Until it is made, setup refuses each setup pull request, and this skill gives no id of the App for the ruleset (step 8). You can write `.theorem/` now. Then stop when the branch and the description are ready (step 7).

Each relative link in this skill, and each path that starts with `docs/`, `templates/` or `app/`, is a file of [theorem-labs/oss-verify](https://github.com/theorem-labs/oss-verify). First read [docs/project-yaml.md](../../../docs/project-yaml.md), with its section [`.theorem/` on your repository](../../../docs/project-yaml.md#theorem-on-your-repository), [docs/build-contract.md](../../../docs/build-contract.md), [docs/what-gets-proven.md](../../../docs/what-gets-proven.md) and, for API-level fuzz targets, [docs/dsl.md](../../../docs/dsl.md). Tell the maintainer what the README's ["Who can enroll"](../../../README.md#who-can-enroll) says about Theorem's capacity.

The setup check is `theorem app setup`. It checks `.theorem/`, and `theorem app build` builds the project from it. Step 9 runs the setup check and follows its messages.

## 1. Start the branch

Work in a checkout of the project's own repository. Make the branch `theorem/setup` from the default branch, and commit `.theorem/` on it. The App takes the pull request from this branch as the setup pull request.

The setup pull request changes at most 100 files, all in `.theorem/`. Change no other file on this branch.

Before you write `.theorem/`, check these three things with the maintainer. `gh api repos/OWNER/REPO --jq '.fork, .license.spdx_id'` shows the first two.

- The repository is not a fork. Set up the repository that it was forked from.
- GitHub finds an open-source licence file in the repository. If it finds none, the maintainer adds one in a pull request of its own, before the setup pull request.
- When the App Theorem Verify is made, the maintainer installs it on the repository. Ask which account will install it, and tell the maintainer that only that account can tick the box of the terms and merge (step 10). While the App is not made, go on without it.

## 2. A project that is enrolled today

A project is enrolled today when theorem-labs/oss-verify has `projects/<name>/`, its `project.yaml` names this repository in `repo`, and its `primary_contact` is not `n/a`. For a seeded project, whose `primary_contact` is `n/a`, read the last item of [references/porting.md](references/porting.md). For a project that is enrolled today, move the files of `projects/<name>/` into `.theorem/`:

1. Copy each file of `projects/<name>/` into `.theorem/`. Each file of code keeps its licence lines (4.8). Leave `projects/<name>/` of theorem-labs/oss-verify as it is.
2. Rename `project.yaml` to `config.yml`, and remove its field `repo`. Remove the comments of `config.yml` that are about `repo` or the commit that it pins: `config.yml` has no pin.
3. Keep the project's name. Set `name: <name>` in `config.yml` when the name of the repository in lower case is not `<name>`.
4. A `Dockerfile` that the field `dockerfile` names in another place of the repository stays where it is, and `dockerfile` keeps naming it. It already builds from the repository root, and the setup check refuses a setup pull request that changes a file outside `.theorem/`.
5. Rewrite each `COPY` and each path of a moved `Dockerfile` for the repository root as the build context ([docs/project-yaml.md, "The build context"](../../../docs/project-yaml.md#the-build-context)). For libreac, `COPY build.sh $SRC/` becomes `COPY .theorem/build.sh $SRC/`.
6. Take the source with `COPY`, not with `fetch-commit`. For libreac, `RUN fetch-commit $SRC/libreac` becomes `COPY . $SRC/libreac`.
7. Change no other build step. Then the build makes the same binaries as the pins only while the files that the build compiles are the same as at the pinned commit. The source that the build copies is now the head of the setup pull request, so a change that the repository made since the pin changes the binaries and the pins too. When the default branch moved since the pinned commit, say so in the description of the setup pull request.
8. Correct each comment of a moved file that the move makes false, for example a comment that names `fetch-commit` or says that the build copies only `build.sh`. In the description of the setup pull request, say what items 5, 6 and 8 changed in each file. A comment outside `.theorem/` that the move makes false stays as it is, because the setup pull request changes no file outside `.theorem/`: tell the maintainer, who can correct it in a pull request of its own.

The maintainer answered the questions of step 3 when the project enrolled. Ask only about what they want to change. Do the items above for each project that is enrolled today. Do steps 4, 5 and 6 of this skill (the fuzz targets, the build and `config.yml`) only for a file that is missing or that breaks a rule. A change to a fuzz target, to a build step or to the built source changes the binaries, so the pins change too. Make a change to a fuzz target or a build step only when a fuzz target breaks a rule of step 4, when a message of the setup check asks for it (step 9), or when the maintainer asks for it. Say in the description of the setup pull request what changed and why.

## 3. Ask the maintainer

Before you talk to the maintainer, read [references/maintainer-questions.md](references/maintainer-questions.md). Its first part asks what "correct" means, for the fuzz targets. Its second part asks about findings, reports and patches, for `.theorem/patch_style.md`. For a new project, ask each question. For a project that is enrolled today, ask only what the maintainer wants to change (step 2). Do not guess an answer.

## 4. Write the fuzz targets

This step gives the rules of a fuzz target, and tells how to meet them. The setup check measures parts of 4.3 and 4.4 for each fuzz target, with its checks "reach" and "breakages" (step 9).

Start from the fuzz targets that the maintainer keeps (the project's own and its OSS-Fuzz ones), then write those that step 3 needs. A fuzz target defines `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. For an API-level entry point, start from the DSL (`docs/dsl.md`). Any shape that obeys this step is fine.

Put each new fuzz target in `.theorem/`, with a suffix that the project's language permits. A fuzz target that the repository already holds in another place can stay there when it obeys this step: `build.sh` builds it from its path. To correct such a fuzz target, copy it into `.theorem/` and correct the copy, because the setup pull request changes no file outside `.theorem/`.

A weak fuzz target makes the theorems vacuous. OSS-Fuzz's fuzz targets often break these rules, and `theorem app setup` and `theorem app build` do not refuse them. Many return -1 for malformed input (4.7), and some ignore an API's result. Read each fuzz target that you keep against each rule below, and correct it.

### 4.1 Drive the API

Read the input as a small program: each byte or field selects the next call and its arguments. Make the decoding total: every input is a sequence, ended by the end of the input. Write one fuzz target for each group of properties or API area. Code that needs another sanitizer configuration is a separate fuzz target. A DSL driver also obeys `docs/build-contract.md`, "The fuzz targets".

### 4.2 Write each property as a check that aborts

Write `if (!condition) abort();` after the calls. Never use `assert()`: a build that defines `NDEBUG`, such as CMake's `Release`, removes it without a warning. Above the check, a comment says in the maintainer's words what it checks and why it must be true. Compute the expected value from the input and the documented rule, not with the library's own function or state. Such a check shows only that the library agrees with itself. A comparison of two public entry points is a property only when the comment says that they must agree, and they do not share the code that computes the value.

### 4.3 Show that each check runs

A small set of inputs, the coverage witness, must run each API call and each property check at least once. Put the inputs at the top level of `.theorem/<target>_seed_corpus.zip` (`docs/project-yaml.md`, "Seed corpora"). Read [references/witness-and-breakage.md](references/witness-and-breakage.md) for the commands that show that each count is more than 0.

### 4.4 Show that each property can fail

For each property, find a breakage: a one-line change, in the library or the fuzz target, that makes the property fail on an input of the seed corpus. The same reference tells how. Undo the change, and record it with the input in the property's comment. The path starts at the `WORKDIR` of the `Dockerfile`. With `templates/.theorem/Dockerfile`, the `WORKDIR` is the copy of the repository root, so a file in `.theorem/` is `.theorem/<file>`. The line is its number at the commit that the setup check builds, and the old text occurs once on it (`docs/build-contract.md`, "The checks of a fuzz target"):

       /* The checksum of the block closes.
        * mutant: src/checksum.c:51 `return sum == 0;` -> `return 1;`
        * input: corrupt-block */
       if (!block_sums_to_zero(frame)) abort();

A property that no change can make fail checks nothing: write it again. A stop that is not a property, such as `if (!buf) abort();` after a failed allocation, gets `not a property: <reason>` in its comment in place of a record.

A change of several lines can be a patch in the folder that `mutants` in `config.yml` names. Use such a patch only when the repository already holds it in that folder. Add no patch to that folder, because the setup pull request changes no file outside `.theorem/`, and `.theorem/` can hold no such folder (`docs/project-yaml.md`, "Limits"). Write each new breakage as a one-line record.

### 4.5 Make each run end quickly

Bound each count, size and loop that comes from the input, for example with a modulus or a small maximum. Do not bound a value that the property needs to be large. Do not recurse on the depth of the input without a limit.

### 4.6 Depend only on the input

The statements use [Linux Process Semantics](https://github.com/theorem-labs/rocq-linux-process-semantics), in which a process has one thread and the input is its only data. Start no thread, read no clock, take each random number from the input, use no network or environment, and open no file but the input and temporary files.

### 4.7 Return 0 or -1

- Do not call `exit()` or `_exit()`, catch all exceptions, install a signal handler, register an exit handler that does not return, call `std::set_terminate`, or in Rust replace the panic hook. Each hides failures (`docs/build-contract.md`, "What the driver does not intercept").
- A failed property calls `abort()` (4.2), never `return -1`. libFuzzer reads -1 as "do not keep this input", and the driver counts -1 as a pass.
- An expectation that the input chooses, such as an `expect` frame of a DSL driver, often fails, which is normal. Evaluate each, then return -1 if any failed, else 0. The driver prints the return value.
- -1 can also refuse an input outside a property's domain, for few inputs only (4.3).
- Everything else returns 0. Turn each expected outcome into `return 0` narrowly: check the library's error code, or catch the one exception type that the API documents.

### 4.8 Keep the licence lines of each copied file

A file that the maintainer writes in `.theorem/` carries the licence of the repository, as each other file of the repository does. It needs no licence lines, and you do not ask the maintainer to add any. A file of code (a fuzz target, the `Dockerfile`, `build.sh`, a script) that holds lines copied from elsewhere keeps their licence lines, below only a `#!`, `# syntax=` or `coding:` line. Build patches, the patches of a C library that the build declares (`docs/build-contract.md`, "The C library"), `config.yml`, `sources`, `series`, `patch_style.md`, locks and seed inputs need none. No check reads them. Before you write the first file, read [references/licence-lines.md](references/licence-lines.md) for the case of each kind of file. Add no licence file to `.theorem/`, and change no file outside it.

## 5. Port the build

Read [references/porting.md](references/porting.md) before you write `.theorem/Dockerfile` and `.theorem/build.sh`. It gives the rules for each language. Start from [templates/.theorem/Dockerfile](../../../templates/.theorem/Dockerfile) and [templates/.theorem/build.sh](../../../templates/.theorem/build.sh).

The Docker build context is the root of the repository at the commit that `theorem app build` builds. The `Dockerfile` names each file by its path from the root, and it takes the project's source with `COPY`, not with `fetch-commit`. Put the `Dockerfile` in `.theorem/`. Use the field `dockerfile` only for a `Dockerfile` that the repository already holds in another place.

## 6. Write config.yml

Start from [templates/.theorem/config.yml](../../../templates/.theorem/config.yml). Leave out `repo`: the project's repository is the repository that holds `.theorem/`. Set `name` only when the project's name is not the name of the repository in lower case (step 2). Fill in `primary_contact` (it is public, and it gets the findings), `language`, `fuzz_targets`, and `patch_style` if `patch_style.md` is in another place of the repository. Fill in each other field that the maintainer wants, such as `auto_ccs`, `pgp` and `publish`. Ask about `publish`. Its default is `after_fixes`. Leave out `ubsan_checks` unless the maintainer wants other checks than the default. Remove a check only when it flags code that is not a bug (`docs/project-yaml.md`, "ubsan_checks").

## 7. Prepare the setup pull request

1. Write the title and the description of the setup pull request. A short title is enough, for example `Set up OSS Verify`. In the description, say in one line for each fuzz target what it checks, and say which files came from where (4.8). Then add this line, exactly as it is here, with the box not ticked:

       - [ ] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/)

   This line is `- [ ] ` followed by `setup_pull_request.terms_line` of [app/sentences.yaml](../../../app/sentences.yaml). Do not tick the box. The account that installed the App ticks it later (step 10). The setup check reads which account ticked it from the edits of the description.
2. Show the branch and the description to the maintainer.
3. Where `theorem` with its `app` plug-in is on your `PATH`, first run `theorem app setup` as step 9, item 1, says. While step 8 gives no id of the App, stop here, before the push: the App is not made yet. Tell the maintainer that the branch and the description are ready, and that setup refuses each setup pull request until the App is made.
4. The maintainer pushes the branch to the repository, and opens the setup pull request from it into the default branch. The App then shows the check "Theorem Verify" with the title "Not checked yet." on the setup pull request.

## 8. Add the ruleset

The maintainer who installed the App adds a ruleset on the default branch. The ruleset requires the status check "Theorem Verify" from the App Theorem Verify, by the App's `integration_id`. Thus no other App and no other job that shows a check with the name "Theorem Verify" counts. The ruleset also requires a branch that is up to date before the merge (`strict_required_status_checks_policy: true`). The setup check refuses a ruleset that requires the check with no `integration_id` or with another id, or that has no rule for a branch that is up to date.

The App Theorem Verify is not made yet. So it has no id, and this skill gives none.

With the GitHub CLI, the maintainer sends this body:

```bash
gh api --method POST repos/OWNER/REPO/rulesets --input - <<'EOF'
{
  "name": "Theorem Verify",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          {
            "context": "Theorem Verify",
            "integration_id": APP_ID
          }
        ]
      }
    }
  ]
}
EOF
```

`APP_ID` shows where the id of the App Theorem Verify goes. It is not a number, so GitHub refuses the body until this skill gives the id.

In GitHub's settings, the maintainer does these steps:

1. Open the repository's **Settings**. In the sidebar, under "Code, planning, and automation", click **Rules**, then **Rulesets**.
2. Click **New ruleset**, then **New branch ruleset**.
3. Under "Ruleset name", type `Theorem Verify`. Set the enforcement status to **Active**.
4. Under "Target branches", click **Add target**, then **Include default branch**.
5. Select **Require status checks to pass before merging**. Under it, select **Require branches to be up to date before merging**.
6. Add the check `Theorem Verify`. Set its source to the App Theorem Verify, not to "any source". GitHub offers the App only after the App showed a check on the repository, so open the setup pull request first (step 7).
7. Click **Create**.

## 9. Run the setup check, and correct `.theorem/`

The setup check, `theorem app setup`, is the statement of the rules. Each refusal says what is wrong and how to fix it. So run the setup check, and follow its messages:

1. Where `theorem` with its `app` plug-in is on your `PATH`, run `theorem app setup` in the root of the repository first. Correct `.theorem/` from each message. Run it again until it passes.
2. On the setup pull request, the App runs the setup check when the maintainer asks for it, with the button "Check" on the check run "Theorem Verify", or with a comment `@theorem-verify check`, as for every check. The setup check runs `theorem app setup` on `.theorem/`, and builds each fuzz target once with `theorem app build`.
3. When a check of setup fails, the check run has the title "<failed> of <count> setup checks failed." Its summary has one line for each check that failed, which says what to change. Correct `.theorem/` from these lines, and commit on `theorem/setup`. Then the maintainer asks for the check again. Each new commit shows "Not checked yet." until the maintainer asks. Do this until the check passes.

| check of setup | it passes when |
|---|---|
| `terms` | the description holds the line `- [x] I accept the [OSS Verify terms](https://theorem.dev/oss-verify/terms/)`, ticked by the account that installed the App |
| `scope` | the setup pull request changes at most 100 files, all in `.theorem/` |
| `name` | no other repository has the project's name. Else set another `name` in `.theorem/config.yml` |
| `fork` | the repository is not a fork |
| `license` | GitHub finds an open-source licence file |
| `ruleset` | the ruleset of step 8 is on the default branch |
| `rules` | `.theorem/` obeys each rule of `docs/project-yaml.md` |
| `statements` | no file of `.theorem/statements/` loads a module that a statement may not load. You write no such file |
| `build` | the fuzz targets build from the build steps in `.theorem/` |

The summary also has one line for each fuzz target with a decided check. Each line gives the results of the checks of `theorem app build checks`: "ELF and instructions", "system calls", "quiet and loud", "instrumented code", "reach" and "breakages". Correct each check that failed.

Do not tell the maintainer to run a tool that they cannot get.

## 10. Tick the box and merge

The check `terms` passes only when the box of the terms is ticked. So the account that installed the App ticks the box in the description, at the latest when each other check of setup passes, and asks for the check again. When the check passes, the check run has the title "Setup is ready to merge." Then that account merges the setup pull request.

Only the account that installed the App ticks the box and merges. A merge that changes `.theorem/`, or a merge before the check passed at the head of the setup pull request, does not enroll the repository.

After the merge, Theorem's agents write the statements, the contracts and the contract checks, and the App commits them. A person at Theorem approves the contracts and the contract checks before the App commits them.
