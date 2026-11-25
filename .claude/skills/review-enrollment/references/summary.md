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

## A setup pull request

A review of a setup pull request by hand writes the summary in the same form, with these changes:

- The heading is `# <owner/repo>: setup pull request #<PR>, "<title>"`.
- The line under it gives the head in the place of the ref and the built commit, from `pr.json`, `repository.txt` and `record.json`: `Opened by <login> on <date>. <Draft or ready>. Repository <owner/repo> at the head <commit>. <installer> installed the App. The box of the terms is <ticked by <login>, or not ticked yet>.`
- "Facts" has no table of binaries and no "Reproducible", because the review has no build data. In their place, it gives the result of each check of `theorem app setup` from `setup.txt`. `patch_style.md` is beside `config.yml`, in the repository, or none.
- "Verdicts" gives each check that `review.md` drops as **pass**, with the evidence "Not a check of a setup pull request."
- "For a person" ends with "Whether we intend to prove the project." alone. The account that installed the App merges a setup pull request, so the merge does not show what we intend.
