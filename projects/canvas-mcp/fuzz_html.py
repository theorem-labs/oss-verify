#!/usr/bin/python3
# Copyright 2026 Vishal Sachdev
# SPDX-License-Identifier: Apache-2.0
"""fuzz_html: an atheris fuzz target for canvas-mcp's HTML tokenizer (src/canvas_mcp/core/html.py).

canvas-mcp reads Canvas LMS page bodies, syllabi, announcements, discussion posts and calendar events. Students and
other course members write that HTML, so each byte of it is untrusted. html.py turns it into plain text for the
model with three functions: iter_html_tags, remove_html_tags and strip_html_tags. This target calls all three on the
same text and checks the properties below. A failed property raises PropertyFailed, which the host reports as an
uncaught exception (status 79). The target catches no exception: html.py documents no exception for any str input.

The input is decoded in one of two ways (the decoding is total, and the text has at most MAX_CHARS characters):
  * first byte 0xFF: the rest goes through atheris.FuzzedDataProvider.ConsumeUnicodeNoSurrogates, which reaches
    each Unicode code point;
  * else, each byte is one piece of text. Bytes 0x00-0x1F select a fragment from FRAGMENTS (markup, entities and
    whitespace that the tokenizer treats specially). Each other byte is the character with that code point, so an
    ASCII seed reads as itself.
"""
import re
import sys

import atheris

from canvas_mcp.core import html as cm_html

# 64 Ki characters: larger than most Canvas page bodies, and small enough that each run ends quickly.
MAX_CHARS = 65536

FRAGMENTS = (
    "<script>", "</script>", "<style>", "</style>", "<!--", "-->", "&amp;", "&nbsp;",
    "&#9;", "\t", "\n", "&lt;", "<br>", "\r", "</p>", "</td>",
    "</th>", "<!DOCTYPE html>", "<?xml?>", "İ", "K", "　", "</div>", "<li>",
    "&#0;", "&#13;", " ", "<a href=", "</SCRIPT >", "<SCRIPT>", '="', "\x00",
)

# The tag name that iter_html_tags reports: empty for a comment or a declaration, else what _TAG_HEAD matched
# (ASCII only), in lower case.
_TAG_NAME = re.compile(r"[a-z][a-z0-9:_-]*", re.ASCII)


class PropertyFailed(Exception):
    """A property of html.py failed. Raised, never caught: the host exits with status 79."""


def _check(condition, what):
    if not condition:
        raise PropertyFailed(what)


def _text(data):
    if data[:1] == b"\xff":
        return atheris.FuzzedDataProvider(data[1:]).ConsumeUnicodeNoSurrogates(MAX_CHARS)
    parts = []
    size = 0
    for byte in data:
        piece = FRAGMENTS[byte] if byte < len(FRAGMENTS) else chr(byte)
        parts.append(piece)
        size += len(piece)
        if size >= MAX_CHARS:
            break
    return "".join(parts)[:MAX_CHARS]


def TestOneInput(data):
    text = _text(data)
    tags = list(cm_html.iter_html_tags(text))

    # P1. iter_html_tags gives each tag as a span of the text: the spans are in order and do not overlap, each one
    # starts at a "<", and the name ends inside the span. Callers slice the text with these offsets
    # (remove_html_tags, strip_html_tags), so a span outside the text or behind the previous one loses or repeats
    # text.
    # Mutant: html.py `cursor = closing.end()` -> `cursor = closing.start()` (the raw-text branch).
    # Input: b"<script>x</script>y</script>" (two closing tags at the same place, so the spans overlap).
    previous_end = 0
    for tag in tags:
        _check(previous_end <= tag.start < tag.end <= len(text), "P1: tag span out of order or out of bounds")
        _check(text[tag.start] == "<", "P1: tag does not start at '<'")
        _check(tag.start < tag.name_end <= tag.end, "P1: name_end outside its tag")
        previous_end = tag.end

        # P2. A tag name is empty (a comment or a declaration) or an ASCII name in lower case. Only an opening tag
        # with a name has attributes. Each attribute value is the exact text at its offsets, inside its tag after
        # the name. A quoted value excludes its quotes: the same quote is just before and just after it, and not in
        # it. An unquoted value has no white space and does not start with a quote. tools/accessibility.py rewrites
        # the style, class and alt values at these offsets, inserts a scope attribute at name_end, and expects a
        # closing quote at the end offset of a quoted id. A wrong offset corrupts the page that it writes back to
        # Canvas. P2 does not check that each value is found: with no reference parser, a quoted value that the
        # tokenizer reads as empty passes it.
        # Mutant: html.py `value_end = cursor` -> `value_end = cursor + 1` (the quoted-value branch).
        # Input: b'<a href="x">' (the value is then 'x"', which holds its closing quote).
        _check(tag.name == "" or _TAG_NAME.fullmatch(tag.name) is not None, "P2: tag name is not a lower-case name")
        _check(not tag.attributes or (tag.name and not tag.closing), "P2: attributes on a closing or nameless tag")
        for attribute in tag.attributes.values():
            value, start, end = attribute.value, attribute.start, attribute.end
            _check(tag.name_end <= start <= end < tag.end, "P2: attribute outside its tag")
            _check(text[start:end] == value, "P2: attribute value is not its text")
            quote = text[start - 1]
            if quote in "\"'":
                _check(text[end] == quote and quote not in value, "P2: quoted value includes or misses a quote")
            else:
                _check(value[:1] not in ("\"", "'"), "P2: unquoted value starts with a quote")
                _check(not any(char.isspace() for char in value), "P2: unquoted value has white space")

    # P3. remove_html_tags removes exactly the tags that iter_html_tags finds, and nothing else: its result is the
    # text outside the tag spans, in order and unchanged. P1 makes the spans ordered and disjoint, so this text is
    # well defined.
    # Mutant: html.py `parts.append(text[cursor:token.start])` -> `parts.append(text[cursor + 1:token.start + 1])`.
    # Input: b"a<b>c" (the result is then "<c", which has the length of "ac" but not its text).
    expected = []
    cursor = 0
    for tag in tags:
        expected.append(text[cursor:tag.start])
        cursor = tag.end
    expected.append(text[cursor:])
    _check(cm_html.remove_html_tags(text) == "".join(expected), "P3: remove_html_tags changed text outside the tags")

    # P4. strip_html_tags gives normalized plain text: no space or blank line at either end, no run of two
    # spaces, no tab or no-break space (an entity such as &#9; or &nbsp; decodes to one before the normalization),
    # no space beside a line break, and at most one blank line in a row. The model reads this text, and the
    # truncation and length checks (student_feed.py) count its characters.
    # Mutant: html.py `re.sub(r"[ \t\xa0]+", " ", text)` -> `re.sub(r"[ \xa0]+", " ", text)`.
    # Input: b"a\x09b" (FRAGMENTS[9] is a tab, which then stays in the output).
    stripped = cm_html.strip_html_tags(text)
    _check(isinstance(stripped, str), "P4: strip_html_tags did not return str")
    _check(stripped == stripped.strip(), "P4: whitespace at an end")
    _check("  " not in stripped, "P4: two spaces in a row")
    _check("\t" not in stripped and "\xa0" not in stripped, "P4: tab or no-break space")
    _check(" \n" not in stripped and "\n " not in stripped, "P4: space beside a line break")
    _check("\n\n\n" not in stripped, "P4: more than one blank line in a row")
    return 0


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
