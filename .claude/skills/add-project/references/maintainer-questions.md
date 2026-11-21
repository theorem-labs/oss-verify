# Questions for the maintainer

Ask each question. Do not guess an answer.

## What "correct" means (step 1)

The answers go into the code and comments of the fuzz targets, and no other document.

1. **Entry points**: which API areas, functions and call sequences to test; which existing fuzz targets to keep; which new ones to write.
2. **Untrusted input**: which functions get input an attacker controls (a parser, a decoder, a protocol handler), and which inputs are trusted (the configuration).
3. **Input size**: how large a real input can be. The driver refuses an input file of 64 MiB or more, unless the fuzz target's build raises the limit, to at most 2 GiB (`docs/build-contract.md`, "The settings of one fuzz target").
4. **Expected outcomes**: an error code for malformed input, a size limit, a refused option. Each ends as `return 0`: a statement accepts only the exit statuses 0 and 2.
5. **Refused allocations**: must the library survive one? If yes, add an allocation-failure fuzz target (`docs/build-contract.md`, "Allocation-failure fuzz targets").
6. **Properties** besides "no crash": a round trip (`decode(encode(x)) == x`), an invariant of a data structure, agreement between two APIs, a limit on the size of an output.

## Findings, reports and patches (step 2)

Ask about each topic that [templates/patch_style.md](../../../../templates/patch_style.md) suggests (`docs/project-yaml.md`, "patch_style"), and write the answers in `projects/<name>/patch_style.md` as free text: our AI reads it before it sends a report or writes a patch. Leave out a topic the maintainer does not care about, and record a link to the project's policy on AI-generated contributions, which our agents obey.

Then tell the maintainer that AI models generate the findings and patches, which can be wrong or incomplete, and that we do not promise a person reviews them before we send them.
