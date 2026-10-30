# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""A stand-in for GitHub Actions' expressions, for the tests that evaluate a workflow's own conditions and values
(test_routed_workflows.py, test_check_checks.py). It reads the part of the language these workflows use; any other
function or form fails loudly, so a workflow that starts using one must be read again."""
import re

TOKEN = re.compile(r"\s*(?:('(?:[^']|'')*')|(\d+(?:\.\d+)?)|(&&|\|\||==|!=|[!(),])|([A-Za-z_][\w-]*(?:\.[\w*-]+)*))")


def evaluate(text, context):
    """A GitHub Actions expression, in the part of the language these workflows use, with `context`: {"inputs": ...,
    "vars": ..., "needs": ..., "github": ...}, where a missing name is null. The operators, string literals,
    cancelled() (false), contains() and format(), and GitHub's loose comparison: strings without regard to case, and
    values of two types as numbers, so that null and '' are equal. A text that is one ${{ }} gives its value; a text
    with ${{ }} among other text gives the text with each replaced; a text without ${{ }} (an if:) is an expression."""
    text = str(text)
    whole = re.fullmatch(r"\s*\$\{\{(.*?)\}\}\s*", text, re.S)
    if whole:
        return _Expression(whole.group(1), context).value()
    if "${{" in text:
        return re.sub(r"\$\{\{(.*?)\}\}", lambda m: as_text(_Expression(m.group(1), context).value()), text, flags=re.S)
    return _Expression(text, context).value()


def as_text(value):
    """A value as GitHub casts it to a string: null is '', a boolean 'true' or 'false', a whole number its digits."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _number(value):
    if value is None:
        return 0
    if isinstance(value, (bool, int, float)):
        return float(value)
    try:
        return float(value) if value.strip() else 0
    except ValueError:
        return float("nan")


def _equal(a, b):
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b if type(a) is type(b) else _number(a) == _number(b)


class _Expression:
    def __init__(self, text, context):
        self.context, self.tokens, at = context, [], 0
        while text[at:].strip():
            match = TOKEN.match(text, at)
            assert match, f"cannot read the expression at {text[at:]!r}"
            self.tokens.append(match.groups())
            at = match.end()
        self.at = 0

    def value(self):
        value = self.either()
        assert self.at == len(self.tokens), self.tokens[self.at:]
        return value

    def peek(self):
        return self.tokens[self.at][2] if self.at < len(self.tokens) else None

    def take(self, operator):
        assert self.peek() == operator, (operator, self.tokens[self.at:])
        self.at += 1

    def either(self):
        left = self.both()
        while self.peek() == "||":
            self.at += 1
            right = self.both()
            left = left if left else right
        return left

    def both(self):
        left = self.compare()
        while self.peek() == "&&":
            self.at += 1
            right = self.compare()
            left = right if left else left
        return left

    def compare(self):
        left = self.unary()
        while self.peek() in ("==", "!="):
            operator = self.peek()
            self.at += 1
            right = self.unary()
            left = _equal(left, right) == (operator == "==")
        return left

    def unary(self):
        if self.peek() == "!":
            self.at += 1
            return not self.unary()
        return self.primary()

    def primary(self):
        string, number, operator, name = self.tokens[self.at]
        self.at += 1
        if operator == "(":
            value = self.either()
            self.take(")")
            return value
        if string is not None:
            return string[1:-1].replace("''", "'")
        if number is not None:
            return float(number)
        assert name is not None, operator
        if self.peek() == "(":
            self.at += 1
            arguments = []
            while self.peek() != ")":
                arguments.append(self.either())
                if self.peek() == ",":
                    self.at += 1
            self.take(")")
            return self.call(name, arguments)
        if name in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[name]
        value = self.context
        for part in name.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return value

    @staticmethod
    def call(name, arguments):
        if name == "cancelled":
            return False
        if name == "contains":
            return as_text(arguments[1]).lower() in as_text(arguments[0]).lower()
        if name == "format":
            pattern, rest = arguments[0], arguments[1:]
            return re.sub(r"\{\{|\}\}|\{(\d+)\}",
                          lambda m: as_text(rest[int(m.group(1))]) if m.group(1) else m.group(0)[0], pattern)
        raise AssertionError(f"no stand-in for {name}()")
