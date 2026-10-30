# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""A small evaluator of GitHub Actions expressions, so that a test can compute what a workflow's `if:` or env
expression gives for the contexts it names, as a run would
(https://docs.github.com/en/actions/reference/workflows-and-actions/expressions):

    evaluate("${{ !cancelled() && needs.route.outputs.kind == 'enrollment' }}",
             {"needs": {"route": {"outputs": {"kind": "enrollment"}}}}, {"cancelled": lambda: False})

It reads literals (null, true, false, numbers, 'strings' with '' for a quote), property access on the contexts
(a.b.c, a['b']), calls of the functions the caller gives, ( ), !, the comparisons, && and ||, with GitHub's rules: a
property that is not there is null; && and || give one of their operands; == and != compare strings without case and
other types after converting both to numbers (null and '' are 0, true is 1, a string that is no number is NaN); null,
false, 0, '' and NaN are falsy. It knows nothing else, and refuses what it cannot read.
"""
import math
import re

_TOKEN = re.compile(r"(?P<num>\d+(?:\.\d+)?)|(?P<str>'(?:[^']|'')*')|(?P<op>==|!=|<=|>=|&&|\|\||[!()<>.,\[\]])"
                    r"|(?P<name>[A-Za-z_][A-Za-z0-9_-]*)")


def _tokens(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        match = _TOKEN.match(text, pos)
        if not match:
            raise ValueError(f"cannot read the expression at {text[pos:]!r}")
        out.append((match.lastgroup, match.group(match.lastgroup)))
        pos = match.end()
    return out


def _number(value):
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        if value.strip() == "":
            return 0
        try:
            return float(value)
        except ValueError:
            return math.nan
    return math.nan


def truthy(value):
    if value is None or value is False or value == "":
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and not math.isnan(value)
    return True


def _equal(a, b):
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if type(a) is type(b) and not isinstance(a, (int, float)):
        return a == b
    return _number(a) == _number(b)


class _Parser:
    def __init__(self, text, contexts, functions):
        self.tokens, self.at, self.contexts, self.functions = _tokens(text), 0, contexts, functions

    def peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else (None, None)

    def take(self, value=None):
        token = self.peek()
        if token[0] is None or (value is not None and token[1] != value):
            raise ValueError(f"expected {value!r}, found {token[1]!r}")
        self.at += 1
        return token

    def parse(self):
        value = self.disjunction()
        if self.peek()[0] is not None:
            raise ValueError(f"cannot read the expression from {self.peek()[1]!r}")
        return value

    def disjunction(self):
        value = self.conjunction()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.conjunction()
            value = value if truthy(value) else right
        return value

    def conjunction(self):
        value = self.comparison()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.comparison()
            value = right if truthy(value) else value
        return value

    def comparison(self):
        value = self.unary()
        if self.peek()[0] == "op" and self.peek()[1] in ("==", "!=", "<", ">", "<=", ">="):
            op = self.take()[1]
            right = self.unary()
            if op == "==":
                return _equal(value, right)
            if op == "!=":
                return not _equal(value, right)
            a, b = _number(value), _number(right)
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        return value

    def unary(self):
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.unary())
        return self.primary()

    def primary(self):
        kind, text = self.take()
        if kind == "num":
            value = float(text) if "." in text else int(text)
        elif kind == "str":
            value = text[1:-1].replace("''", "'")
        elif (kind, text) == ("op", "("):
            value = self.disjunction()
            self.take(")")
        elif kind == "name" and text in ("null", "true", "false"):
            value = {"null": None, "true": True, "false": False}[text]
        elif kind == "name" and self.peek() == ("op", "("):
            self.take("(")
            arguments = []
            while self.peek() != ("op", ")"):
                arguments.append(self.disjunction())
                if self.peek() == ("op", ","):
                    self.take()
            self.take(")")
            if text not in self.functions:
                raise ValueError(f"no function {text}() was given")
            value = self.functions[text](*arguments)
        elif kind == "name":
            value = self.contexts.get(text)
        else:
            raise ValueError(f"cannot read {text!r}")
        while self.peek() in (("op", "."), ("op", "[")):
            if self.take()[1] == ".":
                key = self.take()[1]
            else:
                key = self.disjunction()
                self.take("]")
            value = value.get(key) if isinstance(value, dict) else None
        return value


def evaluate(expression, contexts, functions=None):
    """The value of `expression` (with or without its ${{ }}) for `contexts` and the `functions` given."""
    text = str(expression).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return _Parser(text, contexts, functions or {}).parse()
