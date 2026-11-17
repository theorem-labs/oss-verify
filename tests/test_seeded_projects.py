# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for src/oss_verify/seeded_projects.py, and that docs/seeded-projects.tsv is what it writes:
uv run pytest"""
import difflib
import hashlib
import itertools
import pathlib
import string
import sys
import tempfile
import time
import unittest

from oss_verify import seeded_projects, validate

LANGUAGE_HEADER = ("# project\toss_fuzz\tlanguage\trepo\tcommit\thomepage\tsanitizers\tfuzz_targets\trelease_targets"
                   "\theld\n")
CHECKED_PATCH = "--- a/kay.c\n+++ b/kay.c\n@@ -1 +1 @@\n-0\n+1\n"
NEW_PATCH = "--- a/kay.c\n+++ b/kay.c\n@@ -1 +1 @@\n-1\n+2\n"
# The start and the end of kay's row when its port applies a patch since the check of its seed port.
SINCE = "kay\tyes\treproduces\tthe seed port's check: all binaries match the release's; since that check the port "
KAY_NOTES = "\tfuzz_a: the release modified this harness"


def language_row(project, oss_fuzz, language, targets, held="-"):
    return "\t".join((project, oss_fuzz, language, f"https://github.com/example/{project}", "0" * 40,
                      f"https://github.com/example/{project}", "address,undefined", targets, targets, held)) + "\n"


class Committed(unittest.TestCase):
    def test_docs_seeded_projects_tsv_is_what_the_generator_writes(self):
        committed = seeded_projects.TABLE.read_bytes()
        made = seeded_projects.table().encode("utf-8")
        if committed != made:
            diff = difflib.unified_diff(committed.decode("utf-8", "replace").splitlines(keepends=True),
                                        made.decode("utf-8").splitlines(keepends=True), "docs/seeded-projects.tsv",
                                        "src/oss_verify/seeded_projects.py's output", n=0)
            self.fail("docs/seeded-projects.tsv is not what src/oss_verify/seeded_projects.py writes. Run "
                      "uv run python3 -m oss_verify.seeded_projects. Then commit docs/seeded-projects.tsv. The "
                      "diff:\n" + "".join(list(diff)[:20]))


class Table(unittest.TestCase):
    """table() on a small seeds/ and projects/ made here."""

    FILES = {
        "oss-fuzz-projects.tsv": (
            "# the release's projects\nproject\treason or notes\n"
            "cee\tcee_fuzzer: the release modified this harness\n"
            "dee\t-\n"
            "gone\tthe release did not build it (status held: held)\n"
            "kay\tfuzz_a: the release modified this harness\n"
            "multi\t-\n"
            "py\t-\n"),
        "languages.tsv": (
            "# the release's language builds\n" + LANGUAGE_HEADER
            + language_row("multi-b", "multi", "rust", "fuzz_b")
            + language_row("multi-a", "multi", "rust", "fuzz_a", held="asan")
            + language_row("py", "py", "python", "fuzz_one,fuzz_two")),
        "builds.tsv": (
            "# the result of oss-verify check\nproject\tresult\tdetail\n"
            "cee\treproduces\tall binaries match the release's\n"
            "dee\treproducible\t4 binaries; a second build is identical; the release has none to compare\n"
            "kay\treproduces\tall binaries match the release's\n"
            "multi-a\treproducible\t4 binaries\n"
            "multi-b\treproducible\t8 binaries\n"
            "py\treproducible\t8 binaries\n"),
        "checked-patches.tsv": (
            "# the patches each seed port's check applied\nproject\tpatch\tsha256\n"
            f"kay\tkay-fuzz_a.0001-checked.patch\t{hashlib.sha256(CHECKED_PATCH.encode()).hexdigest()}\n"),
    }

    # kay's port, which applies the patch its check applied. The trees of kay-fuzz_b and kay-fuzz_c are links to
    # that of kay-fuzz_a (kay-fuzz_c's through kay-fuzz_b's), and kay-fuzz_d reads the tree of the key kay-dep.
    PORT = {
        "projects/kay/series": "# the order of the patches\nkay-fuzz_a.0001-checked.patch\n",
        "projects/kay/kay-fuzz_a.0001-checked.patch": CHECKED_PATCH,
        "projects/kay/sources": (
            "# kind\tpath\targuments: see lay-out-sources\n"
            "tree\text/kay-fuzz_a/src\tupstream/kay\n"
            "link\text/kay-fuzz_b/src\text/kay-fuzz_a/src\n"
            "link\text/kay-fuzz_c/src\text/kay-fuzz_b/src\n"
            "tree\text/kay-dep/src\tupstream/kay-dep\n"
            "tree\text/kay-fuzz_d/src\tupstream/kay\n"
            "file\ttargets/kay-fuzz_d/fuzz_d.c\thttps://example.com/fuzz_d.c\t" + "0" * 64 + "\n"
            "tree\text/kay-fuzz_e/src\tupstream/kay\n"
            "patch\text/kay-fuzz_a/src\tkay-fuzz_a.0001-checked.patch\n"),
        "projects/kay/build.sh": (
            "#!/bin/sh -e\n"
            "# A comment that names kay-fuzz_d, kay-dep and kay-fuzz_e does not count.\n"
            ". /usr/local/lib/oss-verify/release-target.sh\n"
            "(\nov_target_begin kay-fuzz_a\nov_target_build fuzz_a\n)\n"
            "(\nov_target_begin kay-fuzz_b\nov_target_build fuzz_b\n)\n"
            "(\nov_target_begin kay-fuzz_c\nov_target_build fuzz_c\n)\n"
            "(\nov_target_begin kay-fuzz_d kay-dep\n  # the harness of kay-fuzz_d\nov_target_build fuzz_d\n)\n"
            "(\nov_target_begin kay-fuzz_e\nbuild_lib() {\n  oft_build_harness \"fuzz_e.c\"\n}\n"
            "ov_target_build fuzz_e\n)\n"),
    }

    def table(self, changes=None, ports=None):
        """table() on FILES with `changes` in seeds/, and PORT with `ports` (paths under the root, None for no
        file)."""
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            files = {f"seeds/{name}": text for name, text in {**self.FILES, **(changes or {})}.items()}
            for name, data in {**files, **self.PORT, **(ports or {})}.items():
                if data is not None:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
            return seeded_projects.table(root / "seeds", root / "projects")

    def row(self, project, changes=None, ports=None):
        """The line of `project` in table()."""
        return next(line for line in self.table(changes, ports).splitlines() if line.startswith(f"{project}\t"))

    def new_patch(self, at, name="kay.0002-new.patch", links="", build=None):
        """PORT's changes for a patch `name` that kay's port applies since its check: listed in series, beside it,
        and on a patch line of sources at `at` (None: no such line), after the lines `links`. `build` replaces
        build.sh."""
        sources = self.PORT["projects/kay/sources"] + links + (f"patch\t{at}\t{name}\n" if at else "")
        ports = {"projects/kay/series": self.PORT["projects/kay/series"] + name + "\n",
                 f"projects/kay/{name}": NEW_PATCH, "projects/kay/sources": sources}
        return ports if build is None else {**ports, "projects/kay/build.sh": build}

    def test_rows(self):
        self.assertEqual(self.table().splitlines()[1:], [
            "project\tseedable\tbuild\tbuild notes\treason or notes",
            "cee\tyes\treproduces\tall binaries match the release's\tcee_fuzzer: the release modified this harness",
            "dee\tyes\treproducible\t4 binaries; a second build is identical; the release has none to compare\t-",
            "gone\tno\t-\t-\tthe release did not build it (status held: held)",
            "kay\tyes\treproduces\tall binaries match the release's\tfuzz_a: the release modified this harness",
            "multi\tno\t-\t-\tseeded as multi-a, multi-b: one project for each of its repositories",
            "multi-a\tyes\treproducible\t4 binaries\tthe release built it in its Rust build, which it did not publish; "
            "one of the repositories of OSS-Fuzz's project multi, each a project here; the release held back these "
            "builds: asan",
            "multi-b\tyes\treproducible\t8 binaries\tthe release built it in its Rust build, which it did not publish; "
            "one of the repositories of OSS-Fuzz's project multi, each a project here",
            "py\tyes\treproducible\t8 binaries\tthe release built it in its Python build, which it did not publish",
        ])

    def test_a_patch_since_the_check_at_a_targets_tree(self):
        self.assertEqual(self.row("kay", ports=self.new_patch("targets/kay-fuzz_d")),
                         SINCE + "applies kay.0002-new.patch to fuzz_d: the binaries of fuzz_d differ from the "
                         "release's" + KAY_NOTES)

    def test_a_patch_at_a_tree_that_links_share(self):
        self.assertEqual(self.row("kay", ports=self.new_patch("ext/kay-fuzz_c/src")),
                         SINCE + "applies kay.0002-new.patch to fuzz_a, fuzz_b, fuzz_c: the binaries of fuzz_a, "
                         "fuzz_b, fuzz_c differ from the release's" + KAY_NOTES)

    def test_a_patch_at_the_tree_of_a_dependency_key(self):
        self.assertEqual(self.row("kay", ports=self.new_patch("ext/kay-dep/src")),
                         SINCE + "applies kay.0002-new.patch to fuzz_d: the binaries of fuzz_d differ from the "
                         "release's" + KAY_NOTES)

    def test_a_patch_in_a_tree_or_at_a_tree_that_holds_one(self):
        # kay-fuzz_ab's key starts with kay-fuzz_a's, as openssl-asn1parse's starts with openssl-asn1's: a tree is a
        # list of path components, so targets/kay-fuzz_ab is not in targets/kay-fuzz_a. The tree of kay-fuzz_f is
        # in the tree of kay-fuzz_a, as a vendored library is.
        build = (self.PORT["projects/kay/build.sh"] + "(\nov_target_begin kay-fuzz_ab\nov_target_build fuzz_ab\n)\n"
                 "(\nov_target_begin kay-fuzz_f\nov_target_build fuzz_f\n)\n")
        links = "tree\text/kay-fuzz_ab/src\tupstream/kay\nlink\text/kay-fuzz_f/src\text/kay-fuzz_a/src/vendor\n"
        cases = {
            "a patch in the tree of a block": ("ext/kay-fuzz_e/src/lib", "fuzz_e"),
            "a patch at a tree that holds the tree of another block": ("ext/kay-fuzz_a/src",
                                                                       "fuzz_a, fuzz_b, fuzz_c, fuzz_f"),
            "a patch at the tree of a key that starts with another key": ("targets/kay-fuzz_ab", "fuzz_ab"),
        }
        for case, (at, targets) in cases.items():
            with self.subTest(case):
                self.assertEqual(self.row("kay", ports=self.new_patch(at, links=links, build=build)),
                                 SINCE + f"applies kay.0002-new.patch to {targets}: the binaries of {targets} differ "
                                 "from the release's" + KAY_NOTES)

    def test_a_block_whose_tree_is_in_a_link_cycle(self):
        # The tree of the patch has no link, but the tree of kay-fuzz_e does not resolve, so the table cannot tell if
        # the build of kay-fuzz_e reads the patched tree.
        links = "link\text/kay-fuzz_e\text/kay-y\nlink\text/kay-y\text/kay-fuzz_e\n"
        self.assertEqual(self.row("kay", ports=self.new_patch("targets/kay-fuzz_d", links=links)),
                         SINCE + "applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its "
                         "binaries may differ from the release's" + KAY_NOTES)

    def test_a_patch_in_a_tree_that_a_link_in_a_block_tree_points_to(self):
        # As the Rust ports share one vendor tree: the link ext/kay-fuzz_g/vendor is in the tree ext/kay-fuzz_g, so the
        # build of kay-fuzz_g reads ext/kay-fuzz_a/vendor. The links of kay-fuzz_b and kay-fuzz_c point only to
        # ext/kay-fuzz_a/src.
        build = self.PORT["projects/kay/build.sh"] + "(\nov_target_begin kay-fuzz_g\nov_target_build fuzz_g\n)\n"
        links = "tree\text/kay-fuzz_a/vendor\tupstream/vendor\nlink\text/kay-fuzz_g/vendor\text/kay-fuzz_a/vendor\n"
        cases = {"a patch through the link": "ext/kay-fuzz_g/vendor/lib",
                 "a patch in the tree that the link points to": "ext/kay-fuzz_a/vendor/lib"}
        for case, at in cases.items():
            with self.subTest(case):
                self.assertEqual(self.row("kay", ports=self.new_patch(at, links=links, build=build)),
                                 SINCE + "applies kay.0002-new.patch to fuzz_a, fuzz_g: the binaries of fuzz_a, fuzz_g "
                                 "differ from the release's" + KAY_NOTES)

    def test_a_patch_in_a_tree_that_a_link_in_a_linked_tree_points_to(self):
        # The link ext/kay-fuzz_h/vendor is in the tree ext/kay-fuzz_h and points to ext/kay-lib. The link
        # ext/kay-lib/vendor is in that tree and points to the patched tree. So the build of kay-fuzz_h reads it.
        build = self.PORT["projects/kay/build.sh"] + "(\nov_target_begin kay-fuzz_h\nov_target_build fuzz_h\n)\n"
        links = ("tree\text/kay-fuzz_a/vendor\tupstream/vendor\ntree\text/kay-lib\tupstream/kay-lib\n"
                 "link\text/kay-lib/vendor\text/kay-fuzz_a/vendor\nlink\text/kay-fuzz_h/vendor\text/kay-lib\n")
        self.assertEqual(self.row("kay", ports=self.new_patch("ext/kay-fuzz_a/vendor/lib", links=links, build=build)),
                         SINCE + "applies kay.0002-new.patch to fuzz_a, fuzz_h: the binaries of fuzz_a, fuzz_h differ "
                         "from the release's" + KAY_NOTES)

    def test_a_link_to_a_tree_in_a_tree_that_other_links_reach(self):
        # The link ext/kay-fuzz_g/vendor points to ext/kay-fuzz_c/src/sub. ext/kay-fuzz_c/src is a link to
        # ext/kay-fuzz_b/src, which is a link to ext/kay-fuzz_a/src. So the build of kay-fuzz_g reads
        # ext/kay-fuzz_a/src/sub, and no other part of ext/kay-fuzz_a/src.
        build = self.PORT["projects/kay/build.sh"] + "(\nov_target_begin kay-fuzz_g\nov_target_build fuzz_g\n)\n"
        links = "link\text/kay-fuzz_g/vendor\text/kay-fuzz_c/src/sub\n"
        cases = {"a patch in that tree": ("ext/kay-fuzz_a/src/sub/lib", "fuzz_a, fuzz_b, fuzz_c, fuzz_g"),
                 "a patch in another part of ext/kay-fuzz_a/src": ("ext/kay-fuzz_a/src/other",
                                                                   "fuzz_a, fuzz_b, fuzz_c")}
        for case, (at, targets) in cases.items():
            with self.subTest(case):
                self.assertEqual(self.row("kay", ports=self.new_patch(at, links=links, build=build)),
                                 SINCE + f"applies kay.0002-new.patch to {targets}: the binaries of {targets} differ "
                                 "from the release's" + KAY_NOTES)

    def test_a_link_whose_parent_is_in_a_link_cycle(self):
        # The tree of the patch has no link, but the parent of the link ext/kay-x/vendor does not resolve. So the table
        # cannot tell which tree holds that link, nor which builds read the tree that it points to.
        links = ("link\text/kay-x\text/kay-y\nlink\text/kay-y\text/kay-x\n"
                 "link\text/kay-x/vendor\text/kay-fuzz_a/src\n")
        self.assertEqual(self.row("kay", ports=self.new_patch("targets/kay-fuzz_d", links=links)),
                         SINCE + "applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its "
                         "binaries may differ from the release's" + KAY_NOTES)

    def test_a_patch_through_a_link_that_lay_out_sources_puts_in_a_linked_tree(self):
        # lay-out-sources makes the parents of a link through the links laid out before it. So the link
        # ext/kay-fuzz_p/src/vendor sits in ext/kay-shared, as ext/kay-shared/vendor, and points to ext/kay-lib. The
        # patched path ext/kay-fuzz_q/src/dep/vendor reaches that link through ext/kay-fuzz_q/src/dep: the patch is in
        # ext/kay-lib. The builds of kay-fuzz_p and kay-fuzz_q read it through ext/kay-shared/vendor, and the build of
        # kay-fuzz_r reads it through ext/kay-fuzz_r/src.
        build = self.PORT["projects/kay/build.sh"] + "".join(
            f"(\nov_target_begin kay-fuzz_{name}\nov_target_build fuzz_{name}\n)\n" for name in "pqr")
        links = ("tree\text/kay-shared\tupstream/shared\ntree\text/kay-lib\tupstream/lib\n"
                 "tree\text/kay-fuzz_q/src\tupstream/q\n"
                 "link\text/kay-fuzz_p/src\text/kay-shared\nlink\text/kay-fuzz_p/src/vendor\text/kay-lib\n"
                 "link\text/kay-fuzz_q/src/dep\text/kay-shared\nlink\text/kay-fuzz_r/src\text/kay-lib\n")
        self.assertEqual(self.row("kay", ports=self.new_patch("ext/kay-fuzz_q/src/dep/vendor", links=links,
                                                              build=build)),
                         SINCE + "applies kay.0002-new.patch to fuzz_p, fuzz_q, fuzz_r: the binaries of fuzz_p, "
                         "fuzz_q, fuzz_r differ from the release's" + KAY_NOTES)

    def test_port_content_that_fills_sources_takes_a_bounded_time(self):
        # A sources file of validate.MAX_FILE_BYTES (64 KiB) and a build.sh of validate.MAX_SOURCE_BYTES (256 KiB) are
        # the most that oss-verify validate takes. seeded-projects.yml stops after 5 minutes, and the table reads each
        # seeded port. Each case here fits in these limits.
        # A chain: each link points into the next one, so the path of each link takes one step for each link after
        # it, and becomes longer at each step. The patched tree is the end of the chain, which no block reads.
        chain = "".join(f"link\tc{i}\tc{i + 1}/x\n" for i in range(2000))
        # A fan: each of 2400 blocks has a link to one shared tree, which is the patched tree.
        names = sorted(f"fuzz_v{i}" for i in range(2400))
        fan = "tree\ts\tupstream/s\n" + "".join(f"link\text/v{i}/vendor\ts\n" for i in range(2400))
        fan_build = self.PORT["projects/kay/build.sh"] + "".join(
            f"(\nov_target_begin v{i}\nov_target_build fuzz_v{i}\n)\n" for i in range(2400))
        # A long link: ext/w is a link whose target has 32,000 components. The first component, l40, is the top of a
        # ladder of 40 links. Each of the 23,000 keys of one ov_target_begin line is w/<n>, so the walk of the block
        # tree ext/w/<n> follows ext/w and the 40 links of the ladder. It stops at the 41st link, before it reads the
        # rest of the target of ext/w.
        ladder = "link\tl1\tz\n" + "".join(f"link\tl{n}\tl{n - 1}\n" for n in range(2, 41))
        long = ladder + "link\text/w\tl40" + "/x" * 31_999 + "\n"
        long_build = "(\nov_target_begin " + " ".join(f"w/{n}" for n in range(23_000)) + "\nov_target_build fuzz_w\n)\n"
        # Many keys: one ov_target_begin line that names the same key 130,000 times, or 60,000 different keys.
        same_build = "(\nov_target_begin" + " k" * 130_000 + "\nov_target_build fuzz_k\n)\n"
        keys = ["".join(letters) for letters in itertools.product(string.ascii_letters, repeat=3)][:60_000]
        keys_build = "(\nov_target_begin " + " ".join(keys) + "\nov_target_build fuzz_k\n)\n"
        # A key with long trees, named many times: ext/D is a link whose target has 10,000 components, and one
        # ov_target_begin line names D 60,000 times. Each time that a block names a key, the table must not read the
        # key's trees again.
        deep = "tree\tbase\tupstream/base\nlink\text/D\tbase" + "/x" * 10_000 + "\n"
        deep_build = "(\nov_target_begin kay-fuzz_z" + " D" * 60_000 + "\nov_target_build fuzz_z\n)\n"
        # 8,000 keys on one ov_target_begin line, each with a character that is not a word character, a dot or a dash.
        # For each of these keys, the table searches the other lines of build.sh.
        odd_build = "(\nov_target_begin " + " ".join(f"+{key}" for key in keys[:8000]) + "\nov_target_build fuzz_k\n)\n"
        cannot = ("applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its binaries may "
                  "differ from the release's")
        cases = {
            "a chain of links": (self.new_patch("c0", links=chain),
                                 "applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its "
                                 "binaries may differ from the release's"),
            "a fan of links to one tree": (self.new_patch("s", links=fan, build=fan_build),
                                           f"applies kay.0002-new.patch to {', '.join(names)}: the binaries of "
                                           f"{', '.join(names)} differ from the release's"),
            "a long link that each block tree follows": (
                self.new_patch("targets/kay-fuzz_d", links=long, build=long_build), cannot),
            "a key that one line names 130,000 times": (self.new_patch("targets/kay-fuzz_d", build=same_build), cannot),
            "60,000 keys on one line": (self.new_patch("targets/kay-fuzz_d", build=keys_build), cannot),
            "a key with long trees that one line names 60,000 times": (
                self.new_patch("targets/kay-fuzz_d", links=deep, build=deep_build), cannot),
            "8,000 keys with another character on one line": (
                self.new_patch("targets/kay-fuzz_d", build=odd_build), cannot),
        }
        for case, (ports, words) in cases.items():
            with self.subTest(case):
                self.assertLessEqual(len(ports["projects/kay/sources"].encode()), validate.MAX_FILE_BYTES)
                self.assertLessEqual(len(ports.get("projects/kay/build.sh", "").encode()), validate.MAX_SOURCE_BYTES)
                start = time.process_time()
                row = self.row("kay", ports=ports)
                self.assertLess(time.process_time() - start, 5)
                self.assertEqual(row, SINCE + words + KAY_NOTES)

    def test_fuzz_targets_this_table_cannot_name(self):
        build = self.PORT["projects/kay/build.sh"]
        self.assertEqual(self.row("kay", ports=self.new_patch("ext/kay-fuzz_e/src")),
                         SINCE + "applies kay.0002-new.patch to fuzz_e: the binaries of fuzz_e differ from the "
                         "release's" + KAY_NOTES)
        cases = {
            "no patch line in sources": self.new_patch(None),
            "a patch that reaches no block": self.new_patch("ext/kay-other/src"),
            "a block with no ov_target_build": self.new_patch(
                "ext/kay-fuzz_e/src", build=build.replace("ov_target_build fuzz_e\n", "")),
            "the key in a line of build.sh": self.new_patch("ext/kay-fuzz_e/src", build=build.replace(
                "ov_target_build fuzz_d\n", "cp \"$LIBROOT/kay-fuzz_e/lib/liboft.a\" \"$BUILDDIR/\"\n"
                "ov_target_build fuzz_d\n")),
            "a link cycle": self.new_patch(
                "ext/kay-x/src", links="link\text/kay-x/src\text/kay-y/src\nlink\text/kay-y/src\text/kay-x/src\n"),
        }
        for case, ports in cases.items():
            with self.subTest(case):
                self.assertEqual(self.row("kay", ports=ports),
                                 SINCE + "applies kay.0002-new.patch, whose fuzz targets this table cannot name: "
                                 "some of its binaries may differ from the release's" + KAY_NOTES)

    def test_what_lay_out_sources_refuses_the_step_budget_and_keys_with_other_characters(self):
        build = self.PORT["projects/kay/build.sh"]
        cannot = (SINCE + "applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its binaries "
                  "may differ from the release's" + KAY_NOTES)

        def names(targets):
            return (SINCE + f"applies kay.0002-new.patch to {targets}: the binaries of {targets} differ from the "
                    "release's" + KAY_NOTES)

        # Lines that lay-out-sources refuses. Without them, a patch at targets/kay-fuzz_d changes fuzz_d.
        refused = {
            "a line without a tab": "tree ext/kay-z upstream/z\n",
            "a link line without a target": "link\text/kay-z\n",
            "a link line with one field more": "link\text/kay-z\text/kay-fuzz_a/src\tmore\n",
            "a patch line with one field more": "patch\text/kay-fuzz_e/src\tkay.0002-new.patch\tmore\n",
            "an empty link path": "link\t\text/kay-fuzz_a/src\n",
            "an absolute link path": "link\t/ext/kay-z\text/kay-fuzz_a/src\n",
            "a link target that holds ..": "link\text/kay-z\t../kay-fuzz_a/src\n",
            "a link at a path that holds a tree laid out before it": "link\text/kay-fuzz_e\text/kay-fuzz_a/src\n",
            "a link at a path that holds its own target": "link\text/kay-z\text/kay-z/sub\n",
        }
        # A chain of links to ext/kay-fuzz_e/src: the path l<n> follows n links.
        chain = "link\tl1\text/kay-fuzz_e/src\n" + "".join(f"link\tl{n}\tl{n - 1}\n" for n in range(2, 42))
        # A deep tree that holds a link to itself, and patch lines that follow that link 40 times. Each line takes
        # more than 40,000 steps, so together they take more than STEPS. The sources file fits in
        # validate.MAX_FILE_BYTES (64 KiB).
        deep = "/".join(["d"] * 1000)
        steps = f"tree\t{deep}\tupstream/d\nlink\t{deep}/s\t{deep}\n" + "".join(
            f"patch\t{deep}{'/s' * 40}\tkay.0002-new.patch\n" for _ in range(25))
        # A block whose key has a character that is not a word character, a dot or a dash.
        odd = build + "(\nov_target_begin kay+x\nov_target_build fuzz_x\n)\n"
        cases = {
            **{case: (self.new_patch("targets/kay-fuzz_d", links=links), cannot) for case, links in refused.items()},
            "a path that follows 40 links": (self.new_patch("l40", links=chain), names("fuzz_e")),
            "a path that follows 41 links": (self.new_patch("l41", links=chain), cannot),
            "a key that holds ..": (self.new_patch(
                "targets/kay-fuzz_d", build=build + "(\nov_target_begin ../kay-up\nov_target_build fuzz_up\n)\n"),
                cannot),
            "links that take more steps than STEPS": (self.new_patch("targets/kay-fuzz_d", links=steps), cannot),
            "a key with another character that no other line names": (self.new_patch(
                "ext/kay+x/src", links="tree\text/kay+x/src\tupstream/x\n", build=odd + "echo kay+xy\n"),
                names("fuzz_x")),
            "a key with another character that another line names": (self.new_patch(
                "ext/kay+x/src", links="tree\text/kay+x/src\tupstream/x\n",
                build=odd + "cp \"$LIBROOT/kay+x/lib/liboft.a\" \"$BUILDDIR/\"\n"), cannot),
        }
        for case, (ports, row) in cases.items():
            with self.subTest(case):
                self.assertLessEqual(len(ports["projects/kay/sources"].encode()), validate.MAX_FILE_BYTES)
                self.assertEqual(self.row("kay", ports=ports), row)

    def test_a_checked_patch_in_other_bytes(self):
        self.assertEqual(self.row("kay", ports={"projects/kay/kay-fuzz_a.0001-checked.patch": NEW_PATCH}),
                         SINCE + "applies kay-fuzz_a.0001-checked.patch in bytes other than that check's, to fuzz_a, "
                         "fuzz_b, fuzz_c: the binaries of fuzz_a, fuzz_b, fuzz_c differ from the release's" + KAY_NOTES)

    def test_a_checked_patch_that_series_no_longer_lists(self):
        self.assertEqual(self.row("kay", ports={"projects/kay/series": "# the order of the patches\n"}),
                         SINCE + "no longer applies kay-fuzz_a.0001-checked.patch: some of its binaries may differ "
                         "from the release's" + KAY_NOTES)

    def test_a_change_that_names_its_targets_and_one_that_does_not(self):
        ports = self.new_patch("targets/kay-fuzz_d")
        ports["projects/kay/series"] += "kay.0003-new.patch\n"
        ports["projects/kay/kay.0003-new.patch"] = NEW_PATCH
        self.assertEqual(self.row("kay", ports=ports),
                         SINCE + "applies kay.0002-new.patch to fuzz_d; applies kay.0003-new.patch, whose fuzz targets "
                         "this table cannot name: the binaries of fuzz_d differ from the release's, and others may"
                         + KAY_NOTES)

    def test_a_reproducible_row_with_a_patch_since_the_check(self):
        ports = {"projects/dee/series": "dee-fuzz.0001-new.patch\n", "projects/dee/dee-fuzz.0001-new.patch": NEW_PATCH,
                 "projects/dee/sources": "tree\text/dee-fuzz/src\tupstream/dee\n"
                                         "patch\text/dee-fuzz/src\tdee-fuzz.0001-new.patch\n",
                 "projects/dee/build.sh": "(\nov_target_begin dee-fuzz\nov_target_build fuzz_dee\n)\n"}
        self.assertEqual(self.row("dee", ports=ports),
                         "dee\tyes\treproducible\tthe seed port's check: 4 binaries; a second build is identical; the "
                         "release has none to compare; since that check the port applies dee-fuzz.0001-new.patch to "
                         "fuzz_dee\t-")

    def test_the_port_in_projects_decides(self):
        changed = self.new_patch("targets/kay-fuzz_d")
        in_seeds = {name.replace("projects/", "seeds/"): text for name, text in {**self.PORT, **changed}.items()}
        with self.subTest("a port in seeds/ and in projects/"):
            self.assertEqual(self.row("kay", ports=in_seeds),
                             "kay\tyes\treproduces\tall binaries match the release's" + KAY_NOTES)
        with self.subTest("a port in seeds/ only"):
            self.assertEqual(self.row("kay", ports={**in_seeds, **dict.fromkeys(self.PORT)}),
                             SINCE + "applies kay.0002-new.patch to fuzz_d: the binaries of fuzz_d differ from the "
                             "release's" + KAY_NOTES)

    def test_port_content_never_stops_the_table(self):
        series = self.PORT["projects/kay/series"]
        cannot = ", whose fuzz targets this table cannot name: some of its binaries may differ from the release's"
        cases = {
            "series lists a file that is missing": (
                {**self.new_patch("ext/kay-fuzz_a/src", "kay.0002-missing.patch"),
                 "projects/kay/kay.0002-missing.patch": None},
                SINCE + "applies kay.0002-missing.patch" + cannot + KAY_NOTES),
            "series holds bytes that are not UTF-8": (
                {"projects/kay/series": series.encode() + b"kay-\xff.patch\n"},
                SINCE + "applies kay-\ufffd.patch" + cannot + KAY_NOTES),
            "series lists a file outside the port": (
                {"projects/kay/series": series + "../../seeds/builds.tsv\n",
                 "projects/kay/sources": self.PORT["projects/kay/sources"]
                 + "patch\text/kay-fuzz_e/src\t../../seeds/builds.tsv\n"},
                SINCE + "applies ../../seeds/builds.tsv" + cannot + KAY_NOTES),
            "build.sh holds bytes that are not UTF-8": (
                self.new_patch("targets/kay-fuzz_d", build=self.PORT["projects/kay/build.sh"].encode() + b"\xfe\xff\n"),
                SINCE + "applies kay.0002-new.patch to fuzz_d: the binaries of fuzz_d differ from the release's"
                + KAY_NOTES),
        }
        for case, (ports, row) in cases.items():
            with self.subTest(case):
                self.assertEqual(self.row("kay", ports=ports), row)

    def test_a_project_without_a_builds_row_is_not_seeded(self):
        builds = self.FILES["builds.tsv"].replace("cee\treproduces\tall binaries match the release's\n", "")
        self.assertIn("\ncee\tno\t-\t-\tcee_fuzzer: the release modified this harness\n",
                      self.table({"builds.tsv": builds}))

    def test_refusals(self):
        release, builds = self.FILES["oss-fuzz-projects.tsv"], self.FILES["builds.tsv"]
        checked = self.FILES["checked-patches.tsv"]
        refused = {
            "a builds row for a project that no file names": {"builds.tsv": builds + "stray\treproduces\tall\n"},
            "notes on a project that languages.tsv seeds": {
                "oss-fuzz-projects.tsv": release.replace("py\t-", "py\tthe release built it")},
            "no reason why a project is not seeded": {"oss-fuzz-projects.tsv": release + "zed\t-\n"},
            "an empty reason": {"oss-fuzz-projects.tsv": release + "zed\t\n"},
            "a row with a missing column": {"oss-fuzz-projects.tsv": release + "zed\n"},
            "two rows for one project": {"builds.tsv": builds + "cee\tfails\tit fails\n"},
            "a language seed with no builds row": {"builds.tsv": builds.replace("py\treproducible\t8 binaries\n", "")},
            "a language seed of a project that oss-fuzz-projects.tsv does not name": {
                "oss-fuzz-projects.tsv": release.replace("multi\t-\n", "")},
            "a line of column names that is not the file's": {
                "oss-fuzz-projects.tsv": release.replace("project\treason or notes", "project\treason")},
            "a builds row for a project seeded as one project for each repository": {
                "builds.tsv": builds + "multi\treproduces\tall\n"},
            "a checked patch with a missing column": {"checked-patches.tsv": checked + "kay\tkay.0002-new.patch\n"},
            "two rows for one checked patch": {"checked-patches.tsv": checked + checked.splitlines()[-1] + "\n"},
            "a checked patch whose sha256 is not 64 lower-case hex digits": {
                "checked-patches.tsv": checked + "kay\tkay.0002-new.patch\t" + "A" * 64 + "\n"},
            "a checked patch of a project with no builds row": {
                "checked-patches.tsv": checked + "gone\tgone.0001-x.patch\t" + "0" * 64 + "\n"},
            "a line of column names of checked-patches.tsv that is not the file's": {
                "checked-patches.tsv": checked.replace("project\tpatch\tsha256", "project\tpatch\tsum")},
        }
        for case, changes in refused.items():
            with self.subTest(case), self.assertRaises(seeded_projects.Error):
                self.table(changes)


if __name__ == "__main__":
    unittest.main()
