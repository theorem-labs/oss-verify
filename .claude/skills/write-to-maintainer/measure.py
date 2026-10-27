#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Measure a message to a maintainer against the limits of SKILL.md, beside this file.

    measure.py --kind review|triage|reply [FILE]

Reads the message from FILE, or from standard input. Prints one JSON object: the visible characters, the visible
words, the numbered items, and each limit the message breaks. Exits 0 when it keeps every limit, 1 when it breaks
one, 2 on a usage error.

Visible text is what a reader sees on GitHub without opening anything. Left out: fenced code blocks (a fence that
nothing closes runs to the end, as in CommonMark), HTML comments (from <!-- to the --> that closes it, or to the end),
and each <details> block from its <details> tag to the </details> that closes it, nested blocks counted once, except
the text of the outer block's <summary>, which GitHub shows. Inside an inline code span, GitHub shows <!--, <details>
and <summary> as text, so they count as text there and hide nothing. A code span ends on its own line here. Runs of
whitespace count as one character. Items are the lines of the visible text that start with at most 3 spaces, a number
and a dot or a closing parenthesis, as a CommonMark ordered list item does.
"""
import argparse
import json
import re
import sys

# triage, the triage comment, has the review comment's limits: build.yaml posts both on the pull request.
LIMITS = {"review": {"chars": 1500, "items": 5}, "triage": {"chars": 1500, "items": 5}, "reply": {"words": 80}}
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
TAG = re.compile(r"<(/?)(details|summary)\b[^>]*>", re.I)
TICKS = re.compile(r"`+")
ITEM = re.compile(r"^ {0,3}\d{1,9}[.)](?:[ \t]|$)")


def visible(text):
    """The visible text of a message (the top of this file says what that is), line by line."""
    out, fence, comment, depth, summary = [], None, False, 0, False
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        found = None if comment else FENCE.match(line)
        if fence is not None:
            if found and found.group(1)[0] == fence[0] and len(found.group(1)) >= len(fence):
                fence = None
            continue
        if found:
            fence = found.group(1)
            continue
        shown, at = [], 0
        while at < len(line):
            if comment:
                end = line.find("-->", at)
                if end < 0:
                    break
                comment, at = False, end + 3
                continue
            seen = depth == 0 or (depth == 1 and summary)
            if line.startswith("<!--", at):
                comment, at = True, at + 4
                continue
            if line[at] == "`":
                run = TICKS.match(line, at).group(0)
                close = re.compile(f"(?<!`){run}(?!`)").search(line, at + len(run))
                end = close.start() if close else at + len(run)
                if seen:
                    shown.append(line[at + len(run):end] if close else run)
                at = close.end() if close else end
                continue
            tag = TAG.match(line, at)
            if tag:
                if tag.group(2).lower() == "details":
                    depth, summary = (max(depth - 1, 0) if tag.group(1) else depth + 1), False
                else:
                    summary = not tag.group(1) and depth == 1
                at = tag.end()
                continue
            if seen:
                shown.append(line[at])
            at += 1
        out.append("".join(shown))
    return "\n".join(out)


def measure(text, kind):
    shown = visible(text)
    flat = " ".join(shown.split())
    found = {"visible_chars": len(flat), "visible_words": len(flat.split()),
             "items": sum(1 for line in shown.split("\n") if ITEM.match(line))}
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
