#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Measure a message to a maintainer against the limits of SKILL.md, beside this file.

    measure.py --kind review|triage|reply [FILE]

Reads the message from FILE, or from standard input. Prints one JSON object: the visible characters, the visible
words, the numbered items, and each limit the message breaks. Exits 0 when it keeps every limit, 1 when it breaks
one, 2 on a usage error.

Visible text is all the text that GitHub shows without a click, code included. Only two things are left out: HTML
comments (from <!-- to the --> that closes it, or to the end), and each closed <details> block, from its <details>
tag to the </details> that closes it, except the text of its <summary>, which GitHub shows. A <details open> block is
shown, so it counts. A block inside a closed block is hidden with it, its summary too. Fenced code counts line by line,
without its fence lines; GitHub shows a tag or a comment start inside it, or inside an inline code span (which can
run onto the next lines of its paragraph), as text, so there it hides nothing. Runs of whitespace count as one
character. Items are the lines that start outside fenced code, a comment and a code span, with at most 3 spaces, a
number and a dot or a closing parenthesis, as a CommonMark ordered list item does, also inside a blockquote (> 1.).
"""
import argparse
import json
import re
import sys

# triage, the triage comment, has the review comment's limits: build.yaml posts both on the pull request.
LIMITS = {"review": {"chars": 1500, "items": 5}, "triage": {"chars": 1500, "items": 5}, "reply": {"words": 80}}
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
TAG = re.compile(r"<(/?)(details|summary)\b([^>]*)>", re.I)
OPEN = re.compile(r"(?:^|\s)open(?:[\s=]|$)", re.I)
TICKS = re.compile(r"`+")
ITEM = re.compile(r"^(?: {0,3}> ?)* {0,3}\d{1,9}[.)](?:[ \t]|$)")


def closer(run):
    """The backtick run that closes a code span opened by `run`: the same length, no backtick beside it."""
    return re.compile(f"(?<!`){run}(?!`)")


def shown_lines(text):
    """Each line of the message as GitHub shows it (the top of this file says what is left out), with whether a list
    item can start it."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out, fence, comment, span, summary = [], None, False, None, False
    stack = []  # one entry for each <details> block that the text is in: True when it is open

    def seen():
        closed = [depth for depth, opened in enumerate(stack) if not opened]
        return not closed or (closed == [len(stack) - 1] and summary)

    def span_closes(run, number, at):
        """Whether the code span that `run` opens at `at` on line `number` closes in its paragraph."""
        if closer(run).search(lines[number], at + len(run)):
            return True
        for line in lines[number + 1:]:
            if not line.strip() or FENCE.match(line):
                return False
            if closer(run).search(line):
                return True
        return False

    for number, line in enumerate(lines):
        free = fence is None and not comment and span is None
        found = FENCE.match(line) if fence is not None or free else None
        if fence is not None:
            if found and found.group(1)[0] == fence[0] and len(found.group(1)) >= len(fence):
                fence, line = None, ""
            out.append((line if seen() else "", False))
            continue
        if found:
            fence = found.group(1)
            out.append(("", False))
            continue
        shown, at = [], 0
        while at < len(line):
            if span is not None:
                close = closer(span).search(line, at)
                if seen():
                    shown.append(line[at:close.start() if close else len(line)])
                span, at = (None, close.end()) if close else (span, len(line))
                continue
            if comment:
                end = line.find("-->", at)
                if end < 0:
                    break
                comment, at = False, end + 3
                continue
            if line.startswith("<!--", at):
                comment, at = True, at + 4
                continue
            if line[at] == "`":
                run = TICKS.match(line, at).group(0)
                if span_closes(run, number, at):
                    span = run
                elif seen():
                    shown.append(run)
                at += len(run)
                continue
            tag = TAG.match(line, at)
            if tag:
                ending, name, attributes = tag.groups()
                if name.lower() == "details":
                    if ending:
                        stack = stack[:-1]
                    else:
                        stack.append(bool(OPEN.search(attributes)))
                    summary = False
                else:
                    summary = not ending
                at = tag.end()
                continue
            if seen():
                shown.append(line[at])
            at += 1
        if span is not None and seen():
            shown.append(" ")
        out.append(("".join(shown), free))
    return out


def visible(text):
    """The visible text of a message, line by line."""
    return "\n".join(shown for shown, _ in shown_lines(text))


def measure(text, kind):
    lines = shown_lines(text)
    flat = " ".join(" ".join(shown for shown, _ in lines).split())
    found = {"visible_chars": len(flat), "visible_words": len(flat.split()),
             "items": sum(1 for shown, free in lines if free and ITEM.match(shown))}
    broken = []
    limits = LIMITS[kind]
    if "chars" in limits and found["visible_chars"] >= limits["chars"]:
        broken.append(f"visible text is {found['visible_chars']} characters; the limit is under {limits['chars']}")
    if "items" in limits and found["items"] > limits["items"]:
        broken.append(f"{found['items']} numbered items are visible; the limit is {limits['items']}")
    if "words" in limits and found["visible_words"] >= limits["words"]:
        broken.append(f"visible text is {found['visible_words']} words; the limit is under {limits['words']}")
    return {**found, "kind": kind, "broken": broken}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kind", required=True, choices=sorted(LIMITS))
    parser.add_argument("file", nargs="?")
    options = parser.parse_args()
    if options.file:
        with open(options.file, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    else:
        text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    result = measure(text, options.kind)
    print(json.dumps(result))
    return 1 if result["broken"] else 0


if __name__ == "__main__":
    sys.exit(main())
