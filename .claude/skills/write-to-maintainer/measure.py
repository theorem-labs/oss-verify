#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Measure a message to a maintainer against the limits of SKILL.md, beside this file.

    measure.py --kind review|triage|reply [FILE]

Reads the message from FILE, or from standard input. Prints one JSON object: the visible characters, the visible
words, the numbered items, and each limit the message breaks. Exits 0 when it keeps every limit, 1 when it breaks
one, 2 on a usage error.

Visible text is what a reader sees without opening anything: the message without HTML comments, without each
<details> block (from its <details> tag to the </details> that closes it), and without fenced code blocks. Runs of
whitespace count as one character. Items are the lines of the visible text that start with a number and a dot or a
closing parenthesis, at the start of the line.
"""
import argparse
import json
import re
import sys

# triage, the triage comment, has the review comment's limits: build.yaml posts both on the pull request.
LIMITS = {"review": {"chars": 1500, "items": 5}, "triage": {"chars": 1500, "items": 5}, "reply": {"words": 80}}
COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.S)
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
DETAILS_OPEN = re.compile(r"<details\b", re.I)
DETAILS_CLOSE = re.compile(r"</details\s*>", re.I)
ITEM = re.compile(r"^\d{1,3}[.)]\s")


def without_fences(text):
    """text without its fenced code blocks; a fence that nothing closes runs to the end, as in CommonMark."""
    out, fence = [], None
    for line in text.split("\n"):
        found = FENCE.match(line)
        if fence is None and found:
            fence = found.group(1)
        elif fence is not None and found and found.group(1)[0] == fence[0] and len(found.group(1)) >= len(fence):
            fence = None
        elif fence is None:
            out.append(line)
    return "\n".join(out)


def without_details(text):
    """text without each <details> block. Nested blocks count once; a block that nothing closes runs to the end."""
    out, depth, at = [], 0, 0
    while True:
        opened, closed = DETAILS_OPEN.search(text, at), DETAILS_CLOSE.search(text, at)
        if depth == 0:
            if not opened:
                out.append(text[at:])
                return "".join(out)
            out.append(text[at:opened.start()])
            depth, at = 1, opened.end()
        elif closed and (not opened or closed.start() < opened.start()):
            depth, at = depth - 1, closed.end()
        elif opened:
            depth, at = depth + 1, opened.end()
        else:
            return "".join(out)


def visible(text):
    text = COMMENT.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    return without_details(without_fences(text))


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
