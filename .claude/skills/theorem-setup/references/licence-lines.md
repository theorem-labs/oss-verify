# Licence lines of a file in .theorem/

The maintainer is the author of the contribution: ask them which name and organisation to give.
Use the first case that fits.

1. **A seeded project's file that you adopt unchanged**, from `seeds/<name>/` or `projects/<name>/` of theorem-labs/oss-verify: add nothing. [NOTICE](../../../../NOTICE) and `seeds/UPSTREAM-CARRIED.tsv` give its licence.
   - A seeded file that you change is case 3: keep its licence lines, for example the Google header of a seeded Python fuzz target.
   - If it has none, give the licence that `seeds/UPSTREAM-CARRIED.tsv` names for it. If that file does not name it, give `Copyright 2026 Theorem Labs, PBC` and `SPDX-License-Identifier: Apache-2.0` (NOTICE).
   - Keep unchanged the lines that NOTICE names by number (wazuh, mariadb). NOTICE grants them wherever they are copied. Then add a `Modified` line.
   - New build files that you write in the form of a seeded project's (the Rust, Python and Go items of [porting.md](porting.md)) are case 4.
2. **A file that you start from `templates/.theorem/`, with no lines copied from elsewhere**: delete the template's comments and give it the lines of a file that the maintainer wrote (case 4), as `projects/cjson/Dockerfile` does. If it also holds lines copied from elsewhere, for example from an OSS-Fuzz `build.sh`, delete the template's comments and use case 3.
3. **A file copied from elsewhere**, whole or in part (the project's repository, OSS-Fuzz, another project, or `projects/<name>/` of theorem-labs/oss-verify for a project that is enrolled today): keep its licence lines unchanged, for example the Google header of an OSS-Fuzz `build.sh`, as `seeds/go-toml/build.sh` does.
   - If it has none, add `SPDX-License-Identifier: <its licence>`, as the LICENSE and NOTICE of its source repository say, and a line with the URL and commit that it came from. Add a `Copyright` line only when that repository names the holder.
   - If you changed the file, add one line under its licence lines that says who changed it, when, and what changed in this file, as [templates/.theorem/Dockerfile](../../../../templates/.theorem/Dockerfile) does. For example: `Modified 2026 by Alex Doe: built with the OSS Verify builder.`
4. **A file that the maintainer wrote**: `Copyright <year> <their name or organisation>` and `SPDX-License-Identifier: Apache-2.0`, as in [templates/.theorem/build.sh](../../../../templates/.theorem/build.sh).
   - If the project is under version 2 of the GNU GPL only, give `SPDX-License-Identifier: MIT OR Apache-2.0` instead: code under that licence cannot be linked with Apache-2.0 code ([NOTICE](../../../../NOTICE)).
   - For such a project, tell the maintainer that a fuzz target copied from OSS-Fuzz stays under Apache-2.0, and that it can keep the project's binaries from being published (NOTICE, wazuh and mariadb).
