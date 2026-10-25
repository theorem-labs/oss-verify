# Instructions for coding agents

This file is for coding agents. It tells an agent how to enroll a project in OSS Verify with the project's maintainer.

If you read this file from a URL, get the repository first. Clone `https://github.com/theorem-labs/oss-verify` next to the project. Do the work in that clone. In that clone, read each file that this file links to. Do not fork the repository. When you finish, tell the maintainer to push your branch to their fork. The maintainer opens the pull request from that fork.

Follow the skill [.claude/skills/add-project/SKILL.md](.claude/skills/add-project/SKILL.md). It gives each step, the questions to ask the maintainer and the checks to run.

Obey these rules:

1. Change only `projects/<name>/`. This repository accepts no other change ([CONTRIBUTING.md](CONTRIBUTING.md)).
2. Ask the maintainer each question in the skill. Do not guess an answer.
3. Follow the rules for the project directory in [docs/project-yaml.md](docs/project-yaml.md).
4. Follow the rules for the build in [docs/build-contract.md](docs/build-contract.md).
5. Read the project's `Dockerfile` before you run `tools/check` on it.
6. Give each file of code its licence lines, as the skill says in step 3.8. A file copied from outside this repository keeps its own. No check finds a missing one.
7. Do not open the pull request. Give it to the maintainer, who opens it and accepts the terms.
