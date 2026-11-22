# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The checks of a C or C++ fuzz target, read from its source, for oss-verify check --checks
(src/oss_verify/check_checks.py).

Each abort() call is a check. This finds what decides whether it runs (its guard), and reads its comment: the
`mutant:` and `input:` records of step 3.4 of the add-project skill, and `not a property: <reason>`
(docs/build-contract.md, "The checks of a fuzz target"). Written for theorem-labs/oss-verify#24, by the agent that
wrote it, and moved here when that pull request folded into this step.
"""
import array
import bisect
import dataclasses
import pathlib
import re

CONDITIONS = frozenset({"if", "while", "for", "switch"})
ABORT = re.compile(r"(?:(?:::\s*)?\bstd\s*::\s*|::\s*)?\b(?:__builtin_)?abort\s*\(\s*\)")
LABEL = re.compile(r"(?:case\b.*|default)\s*$", re.S)
MUTANT = re.compile(r"mutant:\s*(?P<path>[^\s`]+):(?P<line>[0-9]+)\s+`(?P<old>[^`]*)`\s*->\s*`(?P<new>[^`]*)`\s*")
INPUT = re.compile(r"input:\s*(?P<name>\S(?:.*\S)?)\s*")
EXEMPT = re.compile(r"not a property:\s*(?P<reason>\S(?:.*\S)?)\s*")

@dataclasses.dataclass
class Record:
    """One mutant and the input that must catch it, from the comment of a property check."""
    path: str
    line: int
    old: str
    new: str
    input: str

    def mutant(self):
        return (self.path, self.line, self.old, self.new)

    def __str__(self):
        return f"{self.path}:{self.line} `{self.old}` -> `{self.new}` on {self.input}"


@dataclasses.dataclass
class Check:
    """An abort() call in a fuzz target's source: its line, the lines of its guard (None if no condition in its
    function guards it), and what its comment records. `note` is set for an abort() that is not read as a check: it
    is listed as information only. `column` is the call's column, `guard_at` the (line, column) where its guard
    starts, and `text` the source line where the guard starts, for the report."""
    line: int
    guard: tuple
    records: list = dataclasses.field(default_factory=list)
    not_property: str = None
    problems: list = dataclasses.field(default_factory=list)
    note: str = None
    path: str = ""
    column: int = 0
    guard_at: tuple = None
    text: str = ""


# --- Reading C and C++ ---------------------------------------------------------------------------------------------


def blank(text, directives=None):
    """Return (code, comments): `text` with each comment, string literal, character literal, preprocessor line and
    `#if 0` block replaced by spaces (newlines kept, so offsets and lines stay), and the (start, end) offsets of each
    comment. A comment in a directive is not one of them. If `directives` is a list, each directive's (start, text
    without its comments) is added to it."""
    code = list(text)
    comments = []
    n = len(text)

    def wipe(start, end):
        for k in range(start, end):
            if code[k] != "\n":
                code[k] = " "

    def directive_end(start):
        """The offset of the newline that ends the directive at `start` (a `\\` before it continues it)."""
        j = start
        while j < n and not (text[j] == "\n" and text[j - 1] != "\\" and text[j - 2:j] != "\\\r"):
            j += 1
        return j

    def directive(start):
        """The end of the directive at `start`, and its text with each comment in it replaced by spaces. Comments go
        before directives (translation phases 3 and 4): a /* that a directive line opens takes the directive on to the
        line of its */, and an abort() in a comment is not in the directive."""
        j, spans, last = start, [], [-1, -1]  # last: see separator(), so 1'1'1'1 is read once here too
        while j < n and not (text[j] == "\n" and text[j - 1] != "\\" and text[j - 2:j] != "\\\r"):
            if text.startswith("/*", j):
                k = text.find("*/", j + 2)
                k = n if k < 0 else k + 2
            elif text.startswith("//", j):
                k = directive_end(j)
            # A /* in a literal opens no comment.
            elif text[j] == '"' or (text[j] == "'" and not separator(text, j, last)):
                k = j + 1
                while k < n and text[k] not in (text[j], "\n"):
                    k += 2 if text[k] == "\\" else 1
                k = min(k, n)  # a backslash that ends the text escapes nothing after it
                j = k + 1 if k < n and text[k] == text[j] else k
                continue
            else:
                j += 1
                continue
            spans.append((j, k))
            j = k
        body = list(text[start:j])
        for first, end in spans:
            for k in range(first - start, end - start):
                if body[k] != "\n":
                    body[k] = " "
        return j, "".join(body)

    i, line_start, skipping = 0, True, 0
    quote = [-1, -1]  # the last `'` read as code, and where the number it may be in starts: see separator()
    while i < n:
        c = text[i]
        if c == "\n":
            line_start = True
            i += 1
            continue
        if line_start and c in " \t\r":
            i += 1
            continue
        if line_start and c == "#":
            j, body = directive(i)
            if directives is not None:
                directives.append((i, body))
            word = re.match(r"#\s*(\w*)\s*(\S*)", body)
            if skipping:
                skipping += {"if": 1, "ifdef": 1, "ifndef": 1, "endif": -1}.get(word[1], 0)
                if skipping == 1 and word[1] in ("else", "elif"):
                    skipping = 0
            elif word[1] == "if" and word[2] == "0":
                skipping = 1
            wipe(i, j)
            i = j
            continue
        line_start = False
        if skipping:
            j = text.find("\n", i)
            j = n if j < 0 else j
            wipe(i, j)
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append((i, j))
            wipe(i, j)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments.append((i, j))
            wipe(i, j)
            i = j
        elif c == '"' or (c == "'" and not separator(text, i, quote)):
            j = i + 1
            while j < n and text[j] not in (c, "\n"):
                j += 2 if text[j] == "\\" else 1
            j = min(j, n)  # a backslash that ends the text escapes nothing after it
            if j < n and text[j] == c:
                j += 1
            wipe(i, j)
            i = j
        else:
            i += 1
    return "".join(code), comments


def separator(text, at, last=None):
    """True if the `'` at `at` is a C++14 digit separator: it is inside a number such as 1'000 or 0xDEAD'BEEF.
    `last`, if given, is [offset, start] of the `'` read before this one, and is set to this one's: the walk back
    stops there, so a number such as 1'1'1'1 is read once, not once for each of its separators."""
    k = at - 1
    while k >= 0 and (text[k].isalnum() or text[k] in "_.'"):
        if last is not None and k == last[0]:
            k = last[1] - 1
            break
        k -= 1
    if last is not None:
        last[:] = [at, k + 1]
    return at > k + 1 and text[k + 1].isdigit()


def previous(code, position):
    """The offset of the last character before `position` that is not white space, or -1."""
    k = position - 1
    while k >= 0 and code[k].isspace():
        k -= 1
    return k


def word_before(code, end):
    """The identifier that ends at offset `end` (inclusive), and its start; ("", end + 1) if there is none."""
    start = end
    while start >= 0 and (code[start].isalnum() or code[start] == "_"):
        start -= 1
    return code[start + 1:end + 1], start + 1


def matching(code, close, opener, closer):
    """The offset of the `opener` that the `closer` at offset `close` ends, or -1."""
    depth = 0
    for k in range(close, -1, -1):
        if code[k] == closer:
            depth += 1
        elif code[k] == opener:
            depth -= 1
            if depth == 0:
                return k
    return -1


def condition(code, close, words=CONDITIONS):
    """(start, end) of `<word> (...)` whose `)` is at `close`, if <word> is one of `words`; else None."""
    start = matching(code, close, "(", ")")
    if start < 0:
        return None
    word, begin = word_before(code, previous(code, start))
    return (begin, close) if word in words else None


def case_guard(code, colon, memo):
    """The `switch (...)` of the case or default label whose colon is at `colon`, or None. The switch of a block is
    found once, into `memo`: a switch may have many labels."""
    k = colon - 1
    while k >= 0 and code[k] not in ";{}":
        k -= 1
    if not LABEL.fullmatch(code[k + 1:colon].strip()):
        return None
    opener = enclosing_block(code, k + 1, memo)
    if opener < 0:
        return None
    if ("switch", opener) not in memo:
        before = previous(code, opener)
        memo["switch", opener] = condition(code, before, {"switch"}) if before >= 0 and code[before] == ")" else None
    return memo["switch", opener]


def forward_matching(code, open_):
    """The offset of the `)` that closes the `(` at offset `open_`, or -1."""
    depth = 0
    for k in range(open_, len(code)):
        if code[k] == "(":
            depth += 1
        elif code[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


def else_guard(code, at):
    """The condition of the `if` whose `else` starts at `at`, or None."""
    k = previous(code, at)
    if k < 0:
        return None
    if code[k] == "}":
        before = previous(code, matching(code, k, "{", "}"))
        return condition(code, before, {"if"}) if before >= 0 and code[before] == ")" else None
    if code[k] != ";":
        return None
    # `if (c) statement; else`: the statement starts at the last boundary (`;`, `{`, `}`) outside parentheses.
    start, depth = k - 1, 0
    while start >= 0 and not (depth == 0 and code[start] in ";{}"):
        depth += {")": 1, "]": 1, "(": -1, "[": -1}.get(code[start], 0)
        start -= 1
    found = list(re.finditer(r"\bif\s*\(", code[start + 1:k]))
    if not found:
        return None
    begin = start + 1 + found[-1].start()
    close = forward_matching(code, start + found[-1].end())
    return (begin, close) if close >= 0 else None


def enclosing_block(code, at, memo):
    """The offset of the `{` of the innermost block that holds offset `at`, or -1. The braces of `code` are read once,
    into `memo`: a block may hold many checks."""
    if "blocks" not in memo:
        memo["blocks"] = blocks(code)
    braces, openers = memo["blocks"]
    k = bisect.bisect_left(braces, at)
    return openers[k - 1] if k else -1


def blocks(code):
    """The offset of each brace of `code`, and after each the `{` of the innermost block still open, or -1. A `}` with
    no `{` open closes nothing. Arrays, not lists: a source may be all braces."""
    braces, openers, stack = array.array("q"), array.array("q"), []
    for found in re.finditer(r"[{}]", code):
        if found[0] == "{":
            stack.append(found.start())
        elif stack:
            stack.pop()
        braces.append(found.start())
        openers.append(stack[-1] if stack else -1)
    return braces, openers


def block_guard(code, opener, memo):
    """The guard of the statements in the block that the `{` at `opener` opens, or None (a function's body). Found once
    for each block, into `memo`: the guard may be long, and its block hold many checks."""
    if ("block", opener) in memo:
        return memo["block", opener]
    k = previous(code, opener)
    if k < 0:
        guard = None
    elif code[k] == ")":
        guard = condition(code, k)
    elif code[k] == ":":
        guard = case_guard(code, k, memo)
    else:
        word, start = word_before(code, k)
        guard = else_guard(code, start) if word == "else" else None
    memo["block", opener] = guard
    return guard


def guard_of(code, at, memo):
    """(start, end) offsets of the code that decides whether the abort() at `at` runs, or None if no condition in its
    function does. `memo` keeps what is found of the blocks of `code`, for its other checks: {} for a new source."""
    j = previous(code, at)
    if j < 0:
        return None
    if code[j] == "{":
        return block_guard(code, j, memo)
    if code[j] == ")":
        return condition(code, j)
    if code[j] == ":":
        return case_guard(code, j, memo)
    word, start = word_before(code, j)
    if word == "else":
        return else_guard(code, start)
    if code[j] in ";}":
        # After other statements: the guard of the block that holds them.
        opener = enclosing_block(code, at, memo)
        return block_guard(code, opener, memo) if opener >= 0 else None
    return None


def label_start(code, at):
    """If the abort() at `at` comes right after a `case`, `default` or goto label (also with a `{` between), the
    offset where that label starts; else None."""
    j = previous(code, at)
    if j >= 0 and code[j] == "{":
        j = previous(code, j)
    if j < 0 or code[j] != ":":
        return None
    k = j - 1
    while k >= 0 and code[k] not in ";{}":
        k -= 1
    return k + 1 + (len(code[k + 1:j]) - len(code[k + 1:j].lstrip()))


def call_kind(code, at):
    """"call" if the abort() at `at` is a statement, "expression" if it is part of an expression (`c ? abort() : 0`),
    or None for a declaration such as `void abort()`."""
    j = previous(code, at)
    if j < 0 or code[j] in ";{}):":
        return "call"
    if word_before(code, j)[0] in ("else", "do"):
        return "call"
    return "expression" if code[j] in "?,(=&|!" else None


def clean(line):
    """A comment line without its markers: leading spaces, `//`, `/*` and `*`, and a trailing `*/`."""
    line = line.strip()
    if line.endswith("*/"):
        line = line[:-2]
    return line.lstrip(" \t/*").strip()


def parse_records(lines, check):
    """Read the records and the `not a property` line from a check's comment lines into `check`."""
    pending = None
    for text in lines:
        if pending is not None:
            found = INPUT.fullmatch(text)
            if found:
                pending.input = found["name"]
                check.records.append(pending)
            else:
                check.problems.append(f"the line after `mutant: {pending.path}:{pending.line} ...` is not `input: "
                                      "<file name in the seed corpus>`")
            pending = None
            continue
        if text.startswith("mutant:"):
            found = MUTANT.fullmatch(text)
            if not found:
                check.problems.append("a `mutant:` line is not `mutant: <path>:<line> `<old>` -> `<new>``")
            elif not found["old"]:
                check.problems.append(f"the mutant at {found['path']}:{found['line']} replaces nothing (`<old>` is "
                                      "empty)")
            elif len(found["line"]) > 9:  # no file has a billion lines, and int() refuses over 4300 digits
                check.problems.append(f"the mutant at {found['path']} names line {found['line'][:12]}..., which no "
                                      "file has")
            else:
                pending = Record(found["path"], int(found["line"]), found["old"], found["new"], "")
        elif text.startswith("input:"):
            check.problems.append("an `input:` line has no `mutant:` line before it")
        elif EXEMPT.fullmatch(text):
            check.not_property = EXEMPT.fullmatch(text)["reason"]
    if pending is not None:
        check.problems.append(f"`mutant: {pending.path}:{pending.line} ...` has no `input:` line after it")
    if check.not_property is not None and (check.records or check.problems):
        check.problems.append("the comment has both `not a property:` and a mutant record: keep one")


def find_checks(text, path=""):
    """The abort() calls of a C or C++ source: [Check], in the order of their lines. `path` names the file in them.
    Give the text decoded as latin-1, so that a column counts bytes, as llvm-cov's do."""
    directives = []
    code, comments = blank(text, directives)
    starts = [0] + [k + 1 for k, c in enumerate(text) if c == "\n"]

    def line_of(offset):
        return bisect.bisect_right(starts, offset)

    code_lines = {line_of(k) for k, c in enumerate(code) if not c.isspace()}
    pieces = {}  # line -> [comment text on that line]
    for start, end in comments:
        first = line_of(start)
        for offset, part in enumerate(text[start:end].split("\n")):
            pieces.setdefault(first + offset, []).append(part)

    def above(line):
        """The comment lines directly above `line`, with no code and no empty line between."""
        lines = []
        line -= 1
        while line >= 1 and line in pieces and line not in code_lines:
            lines.append(line)
            line -= 1
        return lines[::-1]

    def column_of(offset):
        return offset - starts[line_of(offset) - 1] + 1

    source_lines = text.split("\n")
    stripped = {}  # line -> its text without the white space around it: many checks may share one long line

    def text_of(line):
        if line not in stripped:
            stripped[line] = source_lines[line - 1].strip()
        return stripped[line]

    # The lines that hold a comment, in order: of the lines of a guard, only these can hold a check's records, and a
    # guard of many lines may be the guard of many checks.
    commented = sorted(pieces)
    memo = {}  # what guard_of() finds of the blocks of `code`
    checks = []
    for found in ABORT.finditer(code):
        kind = call_kind(code, found.start())
        line = line_of(found.start())
        if kind is None:
            continue
        at = found.start() + found.group().rindex("abort")
        if kind == "expression":
            checks.append(Check(line, None, path=path, column=column_of(at), text=text_of(line),
                                note="an abort() inside an expression is not read as a property check: write "
                                     "`if (!condition) abort();`"))
            continue
        guard = guard_of(code, found.start(), memo)
        first, last = (line_of(guard[0]), line_of(guard[1])) if guard else (line, line)
        within = commented[bisect.bisect_left(commented, first):bisect.bisect_right(commented, last)]
        lines = set(above(first)) | set(within) | set(above(line)) | {line}
        label = label_start(code, found.start())
        if label is not None:
            lines |= set(above(line_of(label)))
        check = Check(line, (first, last) if guard else None, path=path, column=column_of(at),
                      guard_at=(first, column_of(guard[0])) if guard else None,
                      text=text_of(first))
        parse_records([clean(part) for number in sorted(lines) for part in pieces.get(number, [])], check)
        if guard is None and (check.not_property is None or check.problems):
            check.note = ("no condition in its function guards this abort(), so no seed that passes reaches it: "
                          "write `if (!condition) abort();`")
        checks.append(check)
    for start, body in directives:
        for number, part in enumerate(body.split("\n"), line_of(start)):
            if ABORT.search(part):
                checks.append(Check(number, None, path=path, text=source_lines[number - 1].strip(),
                                    note="an abort() in a macro is not read as a property check: write "
                                         "`if (!condition) abort();` where the check is"))
    return sorted(checks, key=lambda check: check.line)


def mutate(data, record):
    """The bytes of a file with the record's one replacement made, or (None, why) if the record does not fit them."""
    lines = data.split(b"\n")
    if not 1 <= record.line <= len(lines):
        return None, f"{record.path} has {len(lines)} lines, not {record.line}"
    # The comment was read as latin-1, so its text is encoded back the same way: byte for byte.
    old, new = record.old.encode("latin-1"), record.new.encode("latin-1")
    count = lines[record.line - 1].count(old)
    if count != 1:
        return None, f"`{record.old}` occurs {count} times on {record.path}:{record.line}, not once"
    lines[record.line - 1] = lines[record.line - 1].replace(old, new)
    return b"\n".join(lines), None


def safe_path(path):
    """True if `path` is a relative path that stays below the directory it is relative to, with no control character
    (a NUL cannot be in a command's arguments, so image_files() could not ask for it)."""
    parts = pathlib.PurePosixPath(path).parts
    return (bool(parts) and not path.startswith("/") and ".." not in parts and "\\" not in path
            and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in path))

