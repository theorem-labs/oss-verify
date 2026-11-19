# The summary of a review run by hand

Write `$WORK/summary.md` for the people at Theorem who decide, in this form. In CI, write no summary.

```markdown
# <name>: oss-verify pull request #<PR>, "<title>"

Opened by <login> on <date>. <Draft or ready>. Repository <owner/repo> at `<ref>`, built at `<commit>`.

## Facts
| fuzz target | build | .text bytes | file bytes | static |
<one row for each binary>
Language: <language>. Reproducible: <yes or no>. `publish`: <value, or after_fixes by default>. `patch_style.md`: <beside project.yaml, in the repository, or none>.

## Verdicts
| check | verdict | evidence |
<one row for each item of A to G>

## For a person
- <each person verdict: the question, the facts, a recommendation and its reason>
- Whether we intend to prove the project. A merge means that we intend to prove it.

## Asked of the maintainer
<the numbered requests of the comment, one line each>
```

"For a person" always ends with that merge decision: the review never merges a project.
