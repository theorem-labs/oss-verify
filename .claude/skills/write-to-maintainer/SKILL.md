---
name: write-to-maintainer
description: "Use before you write or edit any text that an outside maintainer reads: the enrollment review comment, a reply on an enrollment pull request, a merge or hold note, or an issue or pull request on a project's own repository. Also when the text seems too short to need it, such as a one-line merge note or a reply to a yes."
---

# Write to a maintainer

If this skill disagrees with the code, a command's output or its `--help`, follow those and say which line of this skill is wrong.

## When to write

A maintainer gets a message from us at four points only. Each point is one comment on the pull request. When its content changes, edit that comment. Never post a second one for the same point, because each new comment notifies the maintainer again.

| Point | Who writes it | What it says |
|---|---|---|
| missing | the review job, by `review.md` | the changes that block the merge, or that nothing blocks it |
| decision | whoever merges or holds the pull request | `Merged.`, or what holds it and what clears the hold |
| answer | whoever owns the pull request, when a maintainer asks a question or asks us to act | the answer, or the action done with its link |
| results | whoever publishes them | statements, proofs, or bugs that disclosure has made public, each with a link |

- Write nothing between these points: no progress note, no account of how we work, no new comment that corrects an old one. Edit the old one instead, because a correction as a new comment doubles the thread.
- A step that is ours, such as approving a fork's workflow run or running a failed job again, is not a message. Take the step and write nothing, because the maintainer cannot act on it.
- A failed review job is not a message. Run it again. The review comment, when it posts, is the only text about the review. A maintainer's question about the failure is answered by the new run and the current decision, not by an account of what went wrong.
- Answer each question or request from a maintainer once. When the message also gives a decision, the decision is the first sentence and the answer the second. Otherwise the first sentence gives the answer and its reason, for example "No: `libfoo` 1.2 is not built yet, because its build fails at `configure`." An unanswered question is how threads grow.
- If an earlier request of ours was wrong, put the corrected request in the current comment for that point: what to change now, with its evidence. Do not apologise or tell the history.
- After a merge, post only the decision `Merged.` and, later, results. A merged enrollment changes only through a new pull request.
- On a project's own repository, keep at most 3 of our issues and pull requests open with no answer from its maintainers. The rest wait until they answer, because a burst of them buries the maintainer.

## The shape

Write these parts in this order, and stop after the last one:

1. The decision, as the first sentence: `2 changes are needed before the merge.`, `No changes are needed.`, `Merged.`, `Statements for libfoo: <link>.` The maintainer must know the outcome without reading further.
2. One numbered item for each change that blocks the merge: what is wrong, the evidence (a file and line, the input that shows it, or a link to the comment that gives that input), and the exact change to make. One to three sentences each, because the details block holds the rest.
3. One collapsed block for facts that the maintainer needs only while making a fix: inputs, steps, long lists, and findings that do not block. Start it with `<details><summary>Details</summary>` and end it with `</details>`. Name every failed check in the facts here, even when no rule says whether it blocks; then say that it does not block. A failure that the message leaves out comes back as a second message.
4. Only when the maintainer's pull request is a draft, because GitHub does not merge a draft, the last line: `When it is ready, mark the pull request ready for review.`

Count these limits on everything outside a closed `<details>` block and outside HTML comments, code included. The summary of a closed block counts, and so does a `<details open>` block, because GitHub shows both:

- The review comment: at most 5 blocking items, and under 1,500 characters. Put each further blocking item in the details block, under `More blocking items`.
- Every other message: under 80 words, because it carries one decision or one answer.

## Leave out

Each of these made our messages long, and none of them helps the maintainer act:

- Thanks, greetings and sign-offs. The decision goes first.
- What passed, and anything that the diff or the checks already show. The maintainer can read those.
- Apologies, and the story of a mistake. Edit the wrong text, and state what is true now.
- Promises, dates, queue order, offers of future work, and "we will". A commitment needs a person's approval, and the writer cannot check that it will hold.
- Sentences about our tools, our review, our model or our team, except the reason that holds the merge (for example, a language that our tools do not write statements for yet).
- Filler and hedges: "please note", "just", "feel free", "happy to", "it seems", "I hope", "great".

## Write plainly

- Use short sentences, one idea each, in the active voice, with no semicolons. Use the words that the code and the docs use.
- Take every fact from a file, a command's output or a link that you read for this message. A wrong fact costs a second comment.

## Before you post

Post only through the route that your lane names. The route runs a fresh reader on the text with `judge.md` from this directory, and it measures the limits with `measure.py`. It refuses a text that fails. Fix each finding that it names, and send the text again.
