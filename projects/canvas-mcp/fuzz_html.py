#!/usr/bin/python3
# Copyright 2026 Vishal Sachdev
# SPDX-License-Identifier: Apache-2.0
"""fuzz_html: an atheris fuzz target for canvas-mcp's HTML tokenizer (src/canvas_mcp/core/html.py).

canvas-mcp reads Canvas LMS page bodies, syllabi, announcements, discussion posts and calendar events. Students and
other course members write that HTML, so each byte of it is untrusted. html.py turns it into plain text for the
model with three functions: iter_html_tags, remove_html_tags and strip_html_tags. This target calls all three on the
same text and checks the properties below. A failed property raises PropertyFailed, which the host reports as an
uncaught exception (status 79). The target catches no exception: html.py documents no exception for any str input.

Each check computes its expected value from the text with this file's own code. No check reads a value of html.py
to decide what html.py must give: a check that does could not see a change to that value.

The input is decoded in one of two ways (the decoding is total, and the text has at most MAX_CHARS characters):
  * first byte 0xFF: the rest goes through atheris.FuzzedDataProvider.ConsumeUnicodeNoSurrogates, which reaches
    each Unicode code point;
  * else, each byte is one piece of text. Bytes 0x00-0x1F select a fragment from FRAGMENTS (markup, entities and
    whitespace that the tokenizer treats specially). Each other byte is the character with that code point, so an
    ASCII seed reads as itself.
"""
import html
import re
import sys

import atheris

from canvas_mcp.core import html as cm_html

# 64 Ki characters: larger than most Canvas page bodies, and small enough that each run ends quickly.
MAX_CHARS = 65536

FRAGMENTS = (
    "<script>", "</script>", "<style>", "</style>", "<!--", "-->", "&amp;", "&nbsp;",
    "&#9;", "\t", "\n", "&lt;", "<br>", "\r", "</p>", "</td>",
    "</th>", "<!DOCTYPE html>", "<?xml?>", "İ", "K", "　", "</div>", "<li>",
    "&#0;", "&#13;", " ", "<a href=", "</SCRIPT >", "<SCRIPT>", '="', "\x00",
)

# The head of a tag with a name: "<", white space, an optional "/" (a closing tag), white space, then an ASCII letter
# and name characters. The white space is the six ASCII characters that html.py's _TAG_HEAD matches with \s and
# re.ASCII. Names compare in ASCII only: a non-ASCII letter that folds to an ASCII one (U+017F, U+0130, U+212A) is
# not a name character.
_HEAD = re.compile(r"<[ \t\n\r\f\v]*(/?)[ \t\n\r\f\v]*([A-Za-z][A-Za-z0-9:_-]*)")

# A whole tag, in a text with no quote, no "<!", no "<?" and no "script" or "style" (P1, the tag search).
_PLAIN_TAG = re.compile(r"<[ \t\n\r\f\v]*/?[ \t\n\r\f\v]*[A-Za-z][^<>]*>")
_NOT_PLAIN = re.compile(r"[\"']|<!|<\?|script|style", re.IGNORECASE | re.ASCII)

# The tags whose end strip_html_tags marks with a line break. This list is this file's own; it does not read
# html.py's _BLOCKS.
_BLOCK_NAMES = frozenset((
    "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "ul", "ol",
    "tr", "table", "thead", "tbody", "tfoot", "section", "article", "header",
    "footer", "blockquote", "pre",
))


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


def _normalize(text):
    """The white-space rules of strip_html_tags, in this file's own code."""
    # Each run of spaces, tabs and no-break spaces becomes one space.
    spaced = []
    for char in text:
        if char not in " \t\xa0":
            spaced.append(char)
        elif not spaced or spaced[-1] != " ":
            spaced.append(" ")
    # A space beside a line break goes. After the first step, no two spaces are next to each other.
    last = len(spaced) - 1
    tight = [
        char for index, char in enumerate(spaced)
        if char != " " or not ((index > 0 and spaced[index - 1] == "\n") or (index < last and spaced[index + 1] == "\n"))
    ]
    # Three or more line breaks in a row become two.
    kept = []
    breaks = 0
    for char in tight:
        breaks = breaks + 1 if char == "\n" else 0
        if breaks <= 2:
            kept.append(char)
    return "".join(kept).strip()


def _plain_text(text, tags, heads):
    """The text that strip_html_tags must give, from the spans that P1 checks and the names that P2 checks."""
    parts = []
    hidden = None
    cursor = 0
    for tag, (name, closing) in zip(tags, heads):
        if hidden is None:
            parts.append(text[cursor:tag.start])
        if hidden is not None:
            # The text of a script or style tag is dropped up to its closing tag.
            if closing and name == hidden:
                hidden = None
        elif not closing and name in ("script", "style"):
            hidden = name
        elif name == "br" or (closing and name in _BLOCK_NAMES):
            parts.append("\n")
        elif closing and name in ("td", "th"):
            parts.append("\t")
        elif name:
            parts.append(" ")
        cursor = tag.end
    # A script or style tag with no closing tag drops the text to the end.
    if hidden is None:
        parts.append(text[cursor:])
    return _normalize(html.unescape("".join(parts)))


def TestOneInput(data):
    text = _text(data)
    tags = list(cm_html.iter_html_tags(text))

    # P1. iter_html_tags gives each tag as a span of the text: the spans are in order and do not overlap, each one
    # starts at a "<", and the name ends inside the span. Callers slice the text with these offsets
    # (remove_html_tags, strip_html_tags), so a span outside the text or behind the previous one loses or repeats
    # text.
    # The record's input has two closing tags at the same place, so the spans overlap.
    # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:90 `cursor = closing.end()` -> `cursor = closing.start()`
    # input: 13-mutant-P1
    previous_end = 0
    heads = []
    for tag in tags:
        _check(previous_end <= tag.start < tag.end <= len(text), "P1: tag span out of order or out of bounds")
        _check(text[tag.start] == "<", "P1: tag does not start at '<'")
        _check(tag.start < tag.name_end <= tag.end, "P1: name_end outside its tag")
        previous_end = tag.end

        # P1. Each span ends where its tag ends. A comment ends just after the first "-->" that starts after its
        # "<!--", or at the end of the text if there is none. Each other tag ends with ">".
        # The record's input has a closed comment, whose span then leaves its last ">" in the text.
        # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:98 `end + 3` -> `end + 2`
        # input: 04-comments
        if text.startswith("<!--", tag.start):
            close = text.find("-->", tag.start + 4)
            _check(tag.end == (len(text) if close < 0 else close + 3), "P1: comment span ends in the wrong place")
        else:
            _check(text[tag.end - 1] == ">", "P1: tag span does not end with '>'")

        # P2. The name and the kind of each tag come from the text at its start. A tag whose text starts with "<!"
        # or "<?" (a comment or a declaration) has an empty name and is not a closing tag. Each other tag starts
        # with a match of _HEAD: its name is group 2 in lower case, and it is a closing tag when group 1 is "/".
        # tools/accessibility.py finds the th and img tags by name, and skips closing tags.
        # The record's input has named tags, which then have no name (and so no attributes).
        # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:107 `head.group(2).lower() if head else ""` -> `""`
        # input: 01-attributes
        # The record's input has a closing tag, which then counts as an opening tag.
        # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:122 `bool(head and head.group(1))` -> `False`
        # input: 01-attributes
        if text.startswith(("<!", "<?"), tag.start):
            name, closing = "", False
            _check(tag.name == "" and not tag.closing, "P2: comment or declaration has a name or is closing")
        else:
            head = _HEAD.match(text, tag.start)
            _check(head is not None, "P2: named tag does not start with a tag head")
            name, closing = head.group(2).lower(), head.group(1) == "/"
            _check(tag.name == name, "P2: tag name is not the name in the text")
            _check(tag.closing == closing, "P2: closing flag does not match the text")

            # P2. The name of an opening tag ends where its head ends. tools/accessibility.py inserts a scope
            # attribute at name_end, so an early or late name_end writes the attribute into the name.
            # The record's input has opening tags, whose name_end is then one character early.
            # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:108 `head.end() if head` -> `head.end() - 1 if head`
            # input: 01-attributes
            if not closing:
                _check(tag.name_end == head.end(), "P2: name_end is not the end of the tag name")
        heads.append((name, closing))

        # P2. Only an opening tag with a name has attributes. Each attribute value is the exact text at its offsets,
        # inside its tag after the name. A quoted value excludes its quotes: the same quote is just before and just
        # after it, and not in it. An unquoted value has no white space and does not start with a quote.
        # tools/accessibility.py rewrites the style, class and alt values at these offsets, inserts a scope
        # attribute at name_end, and expects a closing quote at the end offset of a quoted id. A wrong offset
        # corrupts the page that it writes back to Canvas. P2 does not check that each value is found: with no
        # reference parser, a quoted value that the tokenizer reads as empty passes it.
        # The record's input has a quoted value, which then holds its closing quote.
        # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:63 `value_end = cursor` -> `value_end = cursor + 1`
        # input: 13-mutant-P2
        _check(not tag.attributes or (name and not closing), "P2: attributes on a closing or nameless tag")
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

    # P1. iter_html_tags finds each tag. This check runs only on a text with no quote, no "<!", no "<?" and no
    # "script" or "style" in any ASCII case. Such a text has no comment, declaration, quoted value or raw text, so
    # its tags are exactly the matches of _PLAIN_TAG, in order. A tokenizer that finds no tag passes each check
    # above, and fails this one.
    # The record's input has one tag, which the tokenizer then does not find.
    # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:93 `text.find("<", cursor)` -> `-1`
    # input: 13-mutant-P3
    if _NOT_PLAIN.search(text) is None:
        found = [(tag.start, tag.end) for tag in tags]
        _check(found == [match.span() for match in _PLAIN_TAG.finditer(text)], "P1: tags missed or invented")

    # P3. remove_html_tags removes exactly the tags that iter_html_tags finds, and nothing else: its result is the
    # text outside the tag spans, in order and unchanged. P1 makes the spans ordered and disjoint, so this text is
    # well defined.
    # The record's input gives "<c", which has the length of "ac" but not its text.
    # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:138 `parts.append(text[cursor:token.start])` -> `parts.append(text[cursor + 1:token.start + 1])`
    # input: 13-mutant-P3
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
    # The record's input has a tab (FRAGMENTS[9]), which then stays in the output.
    # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:178 `re.sub(r"[ \t\xa0]+", " ", text)` -> `re.sub(r"[ \xa0]+", " ", text)`
    # input: 13-mutant-P4
    stripped = cm_html.strip_html_tags(text)
    _check(isinstance(stripped, str), "P4: strip_html_tags did not return str")
    _check(stripped == stripped.strip(), "P4: whitespace at an end")
    _check("  " not in stripped, "P4: two spaces in a row")
    _check("\t" not in stripped and "\xa0" not in stripped, "P4: tab or no-break space")
    _check(" \n" not in stripped and "\n " not in stripped, "P4: space beside a line break")
    _check("\n\n\n" not in stripped, "P4: more than one blank line in a row")

    # P4. The plain text is the text between the tags, with the text of script and style tags dropped, a line
    # break for br and for the end of a block, a tab for the end of td and th, and a space for each other named
    # tag; then the entities decode and the white space is normalized. _plain_text computes it from the spans and
    # names that P1 and P2 check.
    # The record's input has an entity (&amp;), which then does not decode.
    # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:177 `html.unescape("".join(parts))` -> `"".join(parts)`
    # input: 01-attributes
    # The record's input has tags, which then stay in the text.
    # mutant: upstream/canvas-mcp/src/canvas_mcp/core/html.py:159 `html_content[cursor:token.start]` -> `html_content[cursor:token.end]`
    # input: 01-attributes
    _check(stripped == _plain_text(text, tags, heads), "P4: strip_html_tags is not the plain text of the HTML")
    return 0


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
