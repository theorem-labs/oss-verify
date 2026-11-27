# Questions for the maintainer

For a new project, ask each question. For a project that is enrolled today, ask only about what the maintainer wants to change (step 2 of the skill). Do not guess an answer.

## What "correct" means

The answers go into the code and comments of the fuzz targets (step 4 of the skill), and into no other document.

1. **Entry points**: which API areas, functions and call sequences to test, which existing fuzz targets to keep, and which new ones to write.
2. **Untrusted input**: which functions get input that an attacker controls (a parser, a decoder, a protocol handler), and which inputs are trusted (the configuration).
3. **Input size**: how large a real input can be. The driver refuses an input file of 64 MiB or more, unless the fuzz target's build raises the limit, to at most 2 GiB (`docs/build-contract.md`, "The settings of one fuzz target").
4. **Expected outcomes**: an error code for malformed input, a size limit, a refused option. Each ends as `return 0`: a statement accepts only the exit statuses 0 and 2.
5. **Refused allocations**: must the library survive one? If yes, add an allocation-failure fuzz target (`docs/build-contract.md`, "Allocation-failure fuzz targets").
6. **Properties** other than "no crash": a round trip (`decode(encode(x)) == x`), an invariant of a data structure, agreement between two APIs, a limit on the size of an output.

## Findings, reports and patches

Ask about each topic that [templates/.theorem/patch_style.md](../../../../templates/.theorem/patch_style.md) suggests (`docs/project-yaml.md`, "patch_style"). Write the answers in `.theorem/patch_style.md` as free text: Theorem's AI reads it before it sends a report or writes a patch. Leave out a topic that the maintainer does not care about. Record a link to the project's policy on AI-generated contributions, which Theorem's agents obey.

Then tell the maintainer that AI models generate the findings and patches, which can be wrong or incomplete. Tell them also that Theorem does not promise that a person reviews them before Theorem sends them.
