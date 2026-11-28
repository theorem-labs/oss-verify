# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""The tests are pytest's, but those of the files still to convert:  uv run pytest tests/test_pytest_style.py

pytest runs the tests (pyproject.toml's [tool.pytest.ini_options]; tests.yaml runs python3 -m pytest), and they are
written for it: plain assert, fixtures, parametrize and test classes named Test*, not unittest.TestCase classes. The
files in STILL_UNITTEST still hold unittest's tests; each leaves the list when it is converted, and no other file may
join it. unittest.mock alone does not make a file unittest's: tests/test_conflicting_locks.py uses it in pytest tests.
A helper of a pytest test is not named assert*: the check reads self.assert* as unittest's.
"""
import ast
import importlib
import os
import pathlib
import subprocess
import sys
import unittest

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
ROOT = TESTS.parent
# The test files still to convert to pytest's tests: open pull requests changed each of them when the others were
# converted. test_required_check.py's class TestSteps is a unittest.TestCase through the class Runner that it imports
# from test_outside_screen.py, so it converts with that file.
STILL_UNITTEST = {
    "test_builder.py", "test_check_checks.py", "test_check_records.py", "test_enroll_dispatch.py",
    "test_outside_screen.py", "test_required_check.py", "test_screen.py", "test_seeded_projects.py", "test_triage.py",
    "test_trigger_move.py",
}
# unittest's names whose use makes a file unittest's: its skips and its runner.
UNITTEST_NAMES = ("skip", "skipIf", "skipUnless", "SkipTest", "main")
# Run in a root with a configuration file and the paths to collect, with this directory on PYTHONPATH: pytest collects
# them with Inventory, and the script prints the path of each file that holds unittest's tests, one to a line.
COLLECT = r"""
import sys
import pytest
import test_pytest_style
inventory = test_pytest_style.Inventory()
code = pytest.main(["--collect-only", "-p", "no:terminal", "-p", "no:cacheprovider", "-c", *sys.argv[1:]],
                   plugins=[inventory])
if code != 0:
    sys.exit(f"pytest collected {sys.argv[2:]} with exit status {code}")
print("\n".join(sorted(inventory.paths)))
"""


def local_imports(tree):
    """The objects that the import statements anywhere in `tree` bind, by name. A relative import, or a module that
    cannot be imported, binds nothing here."""
    names = {}
    for node in ast.walk(tree):
        try:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name if alias.asname else alias.name.split(".")[0]
                    names[alias.asname or name] = importlib.import_module(name)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                module = importlib.import_module(node.module)
                names.update((alias.asname or alias.name, getattr(module, alias.name, None)) for alias in node.names)
        except ImportError:
            continue
    return names


def resolved(node, names):
    """The object that the name or attribute `node` names by `names`, or None."""
    try:
        if isinstance(node, ast.Name):
            return names.get(node.id)
        if isinstance(node, ast.Attribute):
            return getattr(resolved(node.value, names), node.attr, None)
    except Exception:  # an attribute whose reading raises names nothing that this check looks for
        return None
    return None


def uses_unittest(path, namespace):
    """Whether the test file `path`, imported as a module whose namespace is `namespace`, uses self.assert*, or names
    one of unittest's UNITTEST_NAMES. A name is read as Python binds it: the module's own binding, and else one that
    an import inside a function makes; so an alias, a name imported by another name, or a function's import of the
    same name does not hide a use."""
    tree = ast.parse(path.read_text(), str(path))
    names = {**local_imports(tree), **namespace}
    targets = [getattr(unittest, name) for name in UNITTEST_NAMES]
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            if node.attr.startswith("assert"):
                return True
        elif isinstance(node, (ast.Name, ast.Attribute)):
            found = resolved(node, names)
            if any(found is target for target in targets):
                return True
    return False


class Inventory:
    """A pytest plugin: the paths of the test files it collects that hold unittest's tests. A file holds them when
    pytest collects a unittest.TestCase class from it (with tests, or none, as a base of others), or a test that a
    unittest skip decorator marked, or when it uses self.assert* or names unittest's skips or runner (uses_unittest).
    pytest finds the classes and tests as it would run them, through any import, name, nesting or base."""

    def __init__(self):
        self.paths = set()

    def pytest_collectreport(self, report):
        for node in report.result:
            obj = getattr(node, "obj", None)
            if (isinstance(obj, type) and issubclass(obj, unittest.TestCase)
                    or getattr(obj, "__unittest_skip__", False) is True
                    or isinstance(node, pytest.Module) and uses_unittest(node.path, vars(obj))):
                self.paths.add(str(node.path))


def unittest_files(root, config, tests="tests"):
    """The paths, relative to `root`/`tests`, of its test files that hold unittest's tests (Inventory), as pytest
    collects them with the configuration file `config`, in a process of its own."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("OV_")}
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, [str(TESTS), environment.get("PYTHONPATH")]))
    run = subprocess.run([sys.executable, "-P", "-c", COLLECT, config, tests], cwd=root, env=environment,
                         capture_output=True, text=True, timeout=300)
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-4000:]
    directory = (root / tests).resolve()
    return {pathlib.Path(line).relative_to(directory).as_posix() for line in run.stdout.splitlines()}


def test_no_test_file_uses_unittest():
    found = unittest_files(ROOT, "pyproject.toml")
    assert sorted(found - STILL_UNITTEST) == [], "these test files hold unittest's tests: write them as pytest's"
    assert sorted(STILL_UNITTEST - found) == [], "these test files hold no unittest test: take them out of the list"


def test_the_inventory_finds_each_unittest_test(tmp_path):
    """Controls. Found: a TestCase class; one with no test, a base for others; an IsolatedAsyncioTestCase class; one
    through a class imported from another file, directly, under another name through a third file, or by a relative
    import in a package; one through TestCase imported by name, from unittest or unittest.case, or bound to another
    name, also when the name is bound again after the class; one whose module's name a function shadows; one defined
    under an if; one nested in a pytest class; one in a subdirectory and one in a file named *_test.py; a test that
    unittest skips, also when its condition is false (so it leaves no mark), and one whose alias of unittest a
    function's import shadows; unittest.main, also under such an alias, and imported by another name; a SkipTest
    raised in a test that imports unittest itself; self.assertEqual; and a helper named self.assert_x. The classes
    hold only plain asserts, so each is found as a TestCase alone. Not found: a file that uses unittest.mock in pytest
    tests, as tests/test_conflicting_locks.py does; pytest tests and their helpers named otherwise; unittest in a
    string; and a TestCase class in a file that is not a test file."""
    test = "    def test_a(self):\n        assert True\n"
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n")
    tests = tmp_path / "tests"
    for package in ("unit", "other", "pkg"):
        (tests / package).mkdir(parents=True)
        (tests / package / "__init__.py").write_text("")
    for name, text in {
        "test_case.py": f"import unittest\n\n\nclass Case(unittest.TestCase):\n{test}",
        "test_base_only.py": "import unittest\n\n\nclass BaseOnly(unittest.TestCase):\n    pass\n",
        "test_async.py": ("import unittest\n\n\nclass Async(unittest.IsolatedAsyncioTestCase):\n"
                          "    async def test_a(self):\n        assert True\n"),
        "test_through.py": "from test_case import Case as Base\n\n\nclass TestThrough(Base):\n    pass\n",
        "again.py": "from test_case import Case as Again\n",
        "test_through_again.py": "from again import Again\n\n\nclass TestThroughAgain(Again):\n    pass\n",
        "pkg/test_base.py": f"import unittest\n\n\nclass Base(unittest.TestCase):\n{test}",
        "pkg/test_relative.py": "from .test_base import Base\n\n\nclass TestRelative(Base):\n    pass\n",
        "test_by_name.py": f"from unittest import TestCase\n\n\nclass TestByName(TestCase):\n{test}",
        "test_case_module.py": f"from unittest.case import TestCase\n\n\nclass TestModule(TestCase):\n{test}",
        "test_alias.py": f"import unittest\n\nBase = unittest.TestCase\n\n\nclass TestAlias(Base):\n{test}",
        "test_rebound.py": ("import unittest\n\nBase = unittest.TestCase\n\n\n"
                            f"class TestRebound(Base):\n{test}\n\nBase = object\n"),
        "test_shadow.py": ("import unittest as ut\n\n\ndef helper():\n    import unittest.mock as ut\n"
                           f"    return ut\n\n\nclass Shadow(ut.TestCase):\n{test}"),
        "test_under_if.py": ("import unittest\n\nif True:\n    class UnderIf(unittest.TestCase):\n"
                             "        def test_a(self):\n            assert True\n"),
        "test_nested_class.py": ("import unittest\n\n\nclass TestOuter:\n    class TestInner(unittest.TestCase):\n"
                                 "        def test_a(self):\n            assert True\n"),
        "unit/test_nested.py": f"import unittest\n\n\nclass Nested(unittest.TestCase):\n{test}",
        "other/test_pytest_only.py": f"class TestOther:\n{test}",
        "suffix_test.py": f"import unittest\n\n\nclass Suffix(unittest.TestCase):\n{test}",
        "test_skip.py": "import unittest\n\n\n@unittest.skipIf(True, 'no')\ndef test_a():\n    pass\n",
        "test_skip_false.py": "import unittest\n\n\n@unittest.skipIf(False, 'never')\ndef test_a():\n    pass\n",
        "test_skip_shadowed.py": ("import unittest as ut\n\n\n@ut.skipIf(True, 'no')\ndef test_a():\n    pass\n\n\n"
                                  "def helper():\n    import unittest.mock as ut\n    return ut\n"),
        "test_main.py": "import unittest\n\nif __name__ == '__main__':\n    unittest.main()\n",
        "test_main_shadowed.py": ("import unittest as ut\n\n\ndef helper():\n    import unittest.mock as ut\n"
                                  "    return ut\n\n\nif __name__ == '__main__':\n    ut.main()\n"),
        "test_main_by_name.py": "from unittest import main as run\n\nif __name__ == '__main__':\n    run()\n",
        "test_skip_inside.py": "def test_a():\n    import unittest\n    raise unittest.SkipTest('no')\n",
        "test_assert.py": "class TestAssert:\n    def test_a(self):\n        self.assertEqual(1, 1)\n",
        "test_assert_helper.py": ("class TestAssertHelper:\n    def assert_shape(self, value):\n"
                                  "        assert value\n\n    def test_a(self):\n        self.assert_shape(1)\n"),
        "test_mock.py": ("import sys\nfrom unittest import mock\n\n\ndef test_a():\n"
                         "    with mock.patch.object(sys, 'argv', []):\n        assert sys.argv == []\n"),
        "test_pytest.py": f"import pytest\n\n\nclass TestA:\n{test}",
        "test_helper.py": ("class TestHelper:\n    def check_shape(self, value):\n        assert value\n\n"
                           "    def test_a(self):\n        self.check_shape(1)\n"),
        "test_string.py": 'SCRIPT = "import unittest\\nclass A(unittest.TestCase): pass"\n',
        "helper.py": f"import unittest\n\n\nclass Helper(unittest.TestCase):\n{test}",
    }.items():
        (tests / name).write_text(text)
    assert unittest_files(tmp_path, "pyproject.toml") == {
        "test_case.py", "test_base_only.py", "test_async.py", "test_through.py", "test_through_again.py",
        "pkg/test_base.py", "pkg/test_relative.py", "test_by_name.py", "test_case_module.py", "test_alias.py",
        "test_rebound.py", "test_shadow.py", "test_under_if.py", "test_nested_class.py", "unit/test_nested.py",
        "suffix_test.py", "test_skip.py", "test_skip_false.py", "test_skip_shadowed.py", "test_main.py",
        "test_main_shadowed.py", "test_main_by_name.py", "test_skip_inside.py", "test_assert.py",
        "test_assert_helper.py"}
