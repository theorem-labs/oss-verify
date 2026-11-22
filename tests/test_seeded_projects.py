# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for src/oss_verify/seeded_projects.py, that docs/seeded-projects.tsv is what it writes, and that every
seeds/<name>/project.yaml has primary_contact: n/a and no auto_ccs:  uv run pytest"""
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


def block(name, key=None):
    """The lines of build.sh that build fuzz_<name> in a block of the key `key` (kay-fuzz_<name> if None), after the
    comment line that marks fuzz_<name> as a target of the release."""
    key = f"kay-fuzz_{name}" if key is None else key
    return f"# fuzz_{name}: the release's target {key}\n(\nov_target_begin {key}\nov_target_build fuzz_{name}\n)\n"


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


def seed_contacts(seeds):
    """A line for each seeds/<name>/project.yaml under the directory `seeds` that can give findings to someone, as
    oss_verify.validate.load reads it: its primary_contact is not n/a, or it has an auto_ccs that is not an empty list.
    The line names the file and the value, or why load refuses the file."""
    lines = []
    for config_file in sorted(seeds.glob("*/project.yaml")):
        path = config_file.relative_to(seeds.parent)
        try:
            config = validate.load(config_file.parent)
        except ValueError as error:
            lines.append(f"{path}: {error}")
            continue
        contact = config.get("primary_contact") if isinstance(config, dict) else None
        if contact != "n/a":
            lines.append(f"{path}: primary_contact is {contact!r}, not 'n/a'")
        ccs = config.get("auto_ccs", []) if isinstance(config, dict) else []
        if ccs != []:
            lines.append(f"{path}: auto_ccs is {ccs!r}, not absent or []")
    return lines


class SeedContacts(unittest.TestCase):
    """Every seeds/<name>/project.yaml has primary_contact: n/a and no auto_ccs: it gives findings to no one. The
    addresses of a seeded project go in projects/<name>/project.yaml, and .github/scripts/terms-accepted reads them
    only there: a branch that adds one needs the adopter's record of the OSS Verify terms. An address in seeds/ would
    skip that record. The tests check runs this test for every change but a fork's change to projects/, which enrollment
    refuses if it changes seeds/."""

    def test_every_seed_port_has_primary_contact_n_a_and_no_auto_ccs(self):
        self.assertTrue(list(seeded_projects.SEEDS.glob("*/project.yaml")), "seeds/ has no <name>/project.yaml")
        lines = seed_contacts(seeded_projects.SEEDS)
        if lines:
            self.fail("Each seeds/<name>/project.yaml must have primary_contact: n/a and no auto_ccs. To adopt a "
                      "seeded project, set its addresses in projects/<name>/project.yaml (docs/project-yaml.md, "
                      "Seeded projects). These do not:\n" + "\n".join(lines))

    def test_a_seed_port_with_another_contact_or_an_auto_ccs_fails_the_check(self):
        # Negative control, on a seeds/ made here.
        with tempfile.TemporaryDirectory() as directory:
            seeds = pathlib.Path(directory) / "seeds"
            texts = {"kept": "repo: https://github.com/example/kept\nprimary_contact: n/a\n",
                     "empty": "repo: https://github.com/example/empty\nprimary_contact: n/a\nauto_ccs: []\n",
                     "cc": "repo: https://github.com/example/cc\nprimary_contact: n/a\nauto_ccs: [x@y.example]\n",
                     "x": "repo: https://github.com/example/x\nprimary_contact: maintainer@x.example\n",
                     "none": "repo: https://github.com/example/none\n",
                     "large": "primary_contact: n/a\n" + "#" * validate.MAX_CONFIG_BYTES}
            for name, text in texts.items():
                (seeds / name).mkdir(parents=True)
                (seeds / name / "project.yaml").write_text(text)
            self.assertEqual(seed_contacts(seeds), [
                "seeds/cc/project.yaml: auto_ccs is ['x@y.example'], not absent or []",
                "seeds/large/project.yaml: project.yaml is larger than 128 KiB",
                "seeds/none/project.yaml: primary_contact is None, not 'n/a'",
                "seeds/x/project.yaml: primary_contact is 'maintainer@x.example', not 'n/a'"])


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
    # that of kay-fuzz_a (kay-fuzz_c's through kay-fuzz_b's), and kay-fuzz_d reads the tree of the key kay-dep. build.sh
    # marks each fuzz target as a target of the release, as a port made from the release's recipe does.
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
            + "".join(block(name) for name in "abc")
            + "# fuzz_d: the release's target kay-fuzz_d\n"
            "(\nov_target_begin kay-fuzz_d kay-dep\n  # the harness of kay-fuzz_d\nov_target_build fuzz_d\n)\n"
            "# fuzz_e: the release's target kay-fuzz_e\n"
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

    def test_a_patch_at_a_tree_of_a_dsl_fuzz_target(self):
        """A block that links a DSL fuzz target (ov_target_build_dsl) names its fuzz target as ov_target_build does."""
        build = self.PORT["projects/kay/build.sh"].replace("ov_target_build fuzz_d", "ov_target_build_dsl fuzz_d")
        self.assertEqual(self.row("kay", ports=self.new_patch("targets/kay-fuzz_d", build=build)),
                         SINCE + "applies kay.0002-new.patch to fuzz_d: the binaries of fuzz_d differ from the "
                         "release's" + KAY_NOTES)

    def test_a_patch_in_a_tree_or_at_a_tree_that_holds_one(self):
        # kay-fuzz_ab's key starts with kay-fuzz_a's, as openssl-asn1parse's starts with openssl-asn1's: a tree is a
        # list of path components, so targets/kay-fuzz_ab is not in targets/kay-fuzz_a. The tree of kay-fuzz_f is
        # in the tree of kay-fuzz_a, as a vendored library is.
        build = self.PORT["projects/kay/build.sh"] + block("ab") + block("f")
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
        build = self.PORT["projects/kay/build.sh"] + block("g")
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
        build = self.PORT["projects/kay/build.sh"] + block("h")
        links = ("tree\text/kay-fuzz_a/vendor\tupstream/vendor\ntree\text/kay-lib\tupstream/kay-lib\n"
                 "link\text/kay-lib/vendor\text/kay-fuzz_a/vendor\nlink\text/kay-fuzz_h/vendor\text/kay-lib\n")
        self.assertEqual(self.row("kay", ports=self.new_patch("ext/kay-fuzz_a/vendor/lib", links=links, build=build)),
                         SINCE + "applies kay.0002-new.patch to fuzz_a, fuzz_h: the binaries of fuzz_a, fuzz_h differ "
                         "from the release's" + KAY_NOTES)

    def test_a_link_to_a_tree_in_a_tree_that_other_links_reach(self):
        # The link ext/kay-fuzz_g/vendor points to ext/kay-fuzz_c/src/sub. ext/kay-fuzz_c/src is a link to
        # ext/kay-fuzz_b/src, which is a link to ext/kay-fuzz_a/src. So the build of kay-fuzz_g reads
        # ext/kay-fuzz_a/src/sub, and no other part of ext/kay-fuzz_a/src.
        build = self.PORT["projects/kay/build.sh"] + block("g")
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
        build = self.PORT["projects/kay/build.sh"] + "".join(block(name) for name in "pqr")
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
        # the most that oss-verify validate takes. Committed runs in the required check tests, in a job that stops
        # after 10 minutes, and the table reads each seeded port. Each case here fits in these limits.
        # A chain: each link points into the next one. lay-out-sources refuses it at its second link, c1: the target
        # of the first link, c1/x, is in c1. So the table stops at that line.
        chain = "".join(f"link\tc{i}\tc{i + 1}/x\n" for i in range(2000))
        # A fan: each of 2400 blocks has a link to one shared tree, which is the patched tree.
        names = sorted(f"fuzz_v{i}" for i in range(2400))
        fan = "tree\ts\tupstream/s\n" + "".join(f"link\text/v{i}/vendor\ts\n" for i in range(2400))
        fan_build = self.PORT["projects/kay/build.sh"] + "".join(block(f"v{i}", f"v{i}") for i in range(2400))
        # A long link: ext/w is a link whose target has 32,000 components. The first component, l39, is the top of a
        # ladder of 39 links. Each of the 23,000 keys of one ov_target_begin line is w/<n>, so the walk of the block
        # tree ext/w/<n> follows ext/w and the 39 links of the ladder, and then reads the rest of the target of ext/w.
        # This walk and the walk of ext/w/<n>/src end, and each takes about 64,000 steps. So the steps run out at the
        # sixth key.
        ladder = "link\tl1\tz\n" + "".join(f"link\tl{n}\tl{n - 1}\n" for n in range(2, 40))
        long = ladder + "link\text/w\tl39" + "/x" * 31_999 + "\n"
        long_build = "(\nov_target_begin " + " ".join(f"w/{n}" for n in range(23_000)) + "\nov_target_build fuzz_w\n)\n"
        # Many keys: one ov_target_begin line that names the same key 130,000 times, or 60,000 different keys. The
        # table reads the trees of a key once, so the row of the same key names fuzz_k. For the 60,000 keys, the steps
        # run out at about the 15,000th key.
        same_build = ("# fuzz_k: the release's target k\n(\nov_target_begin" + " k" * 130_000
                      + "\nov_target_build fuzz_k\n)\n")
        keys = ["".join(letters) for letters in itertools.product(string.ascii_letters, repeat=3)][:60_000]
        keys_build = "(\nov_target_begin " + " ".join(keys) + "\nov_target_build fuzz_k\n)\n"
        # A key with long trees, named many times: ext/D is a link whose target has 10,000 components, and one
        # ov_target_begin line names D 60,000 times. Each time that a block names a key, the table must not read the
        # key's trees again. So the row names fuzz_z.
        deep = "tree\tbase\tupstream/base\nlink\text/D\tbase" + "/x" * 10_000 + "\n"
        deep_build = ("# fuzz_z: the release's target kay-fuzz_z\n(\nov_target_begin kay-fuzz_z" + " D" * 60_000
                      + "\nov_target_build fuzz_z\n)\n")
        # Keys with a character that is not a word character, a dot or a dash: 8,000 keys on one ov_target_begin line,
        # and one key +x+x... of 40,000 characters, which a line x+x+x... of 160,000 characters holds many times, each
        # time after an x. The table does not search build.sh for such a key. So the row cannot name the fuzz targets
        # of a patch at a tree of the key, and the steps do not run out.
        odd_build = "(\nov_target_begin " + " ".join(f"+{key}" for key in keys[:8000]) + "\nov_target_build fuzz_k\n)\n"
        plus = "+x" * 20_000
        plus_build = "(\nov_target_begin " + plus + "\nov_target_build fuzz_x\n)\nx" + "+x" * 80_000 + "\n"
        # A big trie that the table reads again and again: 10,000 keys put 20,000 trees under ext, and 2,100 patch
        # lines apply the patch at ext. So each search for the trees that meet ext reads all of them, and the steps run
        # out.
        trie = "patch\text\tkay.0002-new.patch\n" * 2099
        trie_build = "(\nov_target_begin " + " ".join(keys[:10_000]) + "\nov_target_build fuzz_k\n)\n"
        cannot = ("applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its binaries may "
                  "differ from the release's")

        def named(targets):
            return f"applies kay.0002-new.patch to {targets}: the binaries of {targets} differ from the release's"

        cases = {
            "a chain of links": (self.new_patch("c0", links=chain), cannot),
            "a fan of links to one tree": (self.new_patch("s", links=fan, build=fan_build), named(", ".join(names))),
            "a long link that each block tree follows": (
                self.new_patch("targets/w/0", links=long, build=long_build), cannot),
            "a key that one line names 130,000 times": (self.new_patch("ext/k", build=same_build), named("fuzz_k")),
            "60,000 keys on one line": (self.new_patch(f"ext/{keys[0]}", build=keys_build), cannot),
            "a key with long trees that one line names 60,000 times": (
                self.new_patch("ext/D", links=deep, build=deep_build), named("fuzz_z")),
            "8,000 keys with another character on one line": (
                self.new_patch(f"ext/+{keys[0]}", build=odd_build), cannot),
            "a key of 40,000 characters with another character that a line of 160,000 characters holds": (
                self.new_patch(f"targets/{plus}", build=plus_build), cannot),
            "2,100 patch lines at a tree that holds 20,000 trees": (
                self.new_patch("ext", links=trie, build=trie_build), cannot),
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

    def test_lines_that_the_shell_reads_in_other_words(self):
        # A block of kay-q, mostly with the dependency key kay-dep, and a patch at the tree ext/kay-dep/src that
        # kay-fuzz_d reads too. The shell gives ov_target_begin the same words for kay-dep and "kay-dep", and it ends
        # the word kay-dep; before the ;. So the table cannot name the fuzz targets when a line of a call has such a
        # word, or when a call is not the first word of its line. A comment line does not count. A call after a ( or
        # a ; is in a block of its own, so the ov_target_build after it is not in the block of kay-fuzz_e.
        build = self.PORT["projects/kay/build.sh"] + "# fuzz_q: the release's target kay-q\n"
        cannot = (SINCE + "applies kay.0002-new.patch, whose fuzz targets this table cannot name: some of its binaries "
                  "may differ from the release's" + KAY_NOTES)
        both = (SINCE + "applies kay.0002-new.patch to fuzz_d, fuzz_q: the binaries of fuzz_d, fuzz_q differ from the "
                "release's" + KAY_NOTES)
        cases = {
            "plain words": ("(\nov_target_begin kay-q kay-dep\nov_target_build fuzz_q\n)\n", "ext/kay-dep/src", both),
            "a comment that quotes a call": (
                "(\n# ov_target_begin kay-q \"kay-dep\"; ov_target_build \"fuzz_q\"\n"
                "ov_target_begin kay-q kay-dep\nov_target_build fuzz_q\n)\n", "ext/kay-dep/src", both),
            "a quoted key": (
                "(\nov_target_begin kay-q \"kay-dep\"\nov_target_build fuzz_q\n)\n", "ext/kay-dep/src", cannot),
            "a key in single quotes": (
                "(\nov_target_begin kay-q 'kay-dep'\nov_target_build fuzz_q\n)\n", "ext/kay-dep/src", cannot),
            "a key that a ; ends": (
                "(\nov_target_begin kay-q kay-dep; ov_target_build fuzz_q\n)\n", "ext/kay-dep/src", cannot),
            "a key that && ends": (
                "(\nov_target_begin kay-q kay-dep && ov_target_build fuzz_q\n)\n", "ext/kay-dep/src", cannot),
            "a key in a variable": (
                "(\nD=kay-dep\nov_target_begin kay-q $D\nov_target_build fuzz_q\n)\n", "ext/kay-dep/src", cannot),
            "a quoted fuzz target": (
                "(\nov_target_begin kay-q kay-dep\nov_target_build \"fuzz_q\"\n)\n", "ext/kay-dep/src", cannot),
            "a call after a (": ("( ov_target_begin kay-q\nov_target_build fuzz_q\n)\n", "ext/kay-fuzz_e/src", cannot),
            "a call after another command": (
                "(\ntrue; ov_target_begin kay-q\nov_target_build fuzz_q\n)\n", "ext/kay-fuzz_e/src", cannot),
            "a call that is not the first word": (
                "(\ncommand ov_target_begin kay-q\nov_target_build fuzz_q\n)\n", "ext/kay-fuzz_e/src", cannot),
            "a call after an assignment": (
                "(\nX=1 ov_target_begin kay-q\nov_target_build fuzz_q\n)\n", "ext/kay-fuzz_e/src", cannot),
            "a call right after a (": ("(ov_target_begin kay-q\nov_target_build fuzz_q\n)\n", "ext/kay-fuzz_e/src",
                                      cannot),
            "a lone key that a ; ends": (
                "(\nov_target_begin kay-q kay-dep;\nov_target_build fuzz_q\n)\n", "ext/kay-dep/src", cannot),
        }
        for case, (block, at, row) in cases.items():
            with self.subTest(case):
                ports = self.new_patch(at, build=build + block)
                ports["projects/kay/sources"] += "tree\text/kay-q/src\tupstream/kay\n"
                self.assertEqual(self.row("kay", ports=ports), row)

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
        # A block whose key has a character that is not a word character, a dot or a dash. The table does not search
        # build.sh for such a key. So it cannot name the fuzz targets of a patch at a tree of the key, if another line
        # names the key or not. A patch at a tree that the block does not read changes fuzz_d.
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
                "ext/kay+x/src", links="tree\text/kay+x/src\tupstream/x\n", build=odd + "echo kay+xy\n"), cannot),
            "a key with another character that another line names": (self.new_patch(
                "ext/kay+x/src", links="tree\text/kay+x/src\tupstream/x\n",
                build=odd + "cp \"$LIBROOT/kay+x/lib/liboft.a\" \"$BUILDDIR/\"\n"), cannot),
            "a key with another character, and a patch at a tree that its block does not read": (self.new_patch(
                "targets/kay-fuzz_d", links="tree\text/kay+x/src\tupstream/x\n", build=odd + "echo kay+xy\n"),
                names("fuzz_d")),
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

    def test_a_fuzz_target_that_the_release_did_not_build(self):
        # As zlib's compress_roundtrip_full_fuzzer: the tree of kay-fuzz_n is a link to that of kay-fuzz_e, and build.sh
        # does not mark fuzz_n as a target of the release. A patch at that tree changes fuzz_e and fuzz_n: the notes
        # name only fuzz_e in the list of the patch and as a binary that differs from the release's, and end with
        # fuzz_n, which the release did not build. A patch at targets/kay-fuzz_n changes fuzz_n only. When the port
        # also applies kay.0003-new.patch, whose fuzz targets the table cannot name, the notes still end with fuzz_n.
        # When kay.0002-new.patch is at targets/kay-fuzz_n and kay.0003-new.patch at the tree of kay-fuzz_e, which the
        # tree of kay-fuzz_m is a link to too, both patches change fuzz_n, and the second also changes fuzz_m, which
        # build.sh does not mark either: the notes end with each of them once, sorted.
        build = (self.PORT["projects/kay/build.sh"] + "# fuzz_n: not a target of the release.\n"
                 "(\nov_target_begin kay-fuzz_n\nov_target_build fuzz_n\n)\n")
        links = "link\text/kay-fuzz_n/src\text/kay-fuzz_e/src\n"
        cannot = "; applies kay.0003-new.patch, whose fuzz targets this table cannot name"
        cases = {
            "a patch that changes a fuzz target of the release and another": (
                "ext/kay-fuzz_e/src", False, "applies kay.0002-new.patch to fuzz_e: the binaries of fuzz_e differ from "
                "the release's; the release did not build fuzz_n"),
            "a patch that changes no fuzz target of the release": (
                "targets/kay-fuzz_n", False, "applies kay.0002-new.patch to no fuzz target that the release built; the "
                "release did not build fuzz_n"),
            "a patch that changes a fuzz target of the release and another, and one whose fuzz targets this table "
            "cannot name": (
                "ext/kay-fuzz_e/src", True,
                "applies kay.0002-new.patch to fuzz_e" + cannot + ": the binaries of fuzz_e differ from the release's, "
                "and others may; the release did not build fuzz_n"),
            "a patch that changes no fuzz target of the release, and one whose fuzz targets this table cannot name": (
                "targets/kay-fuzz_n", True,
                "applies kay.0002-new.patch to no fuzz target that the release built" + cannot + ": some of its "
                "binaries may differ from the release's; the release did not build fuzz_n"),
        }
        for case, (at, unnamed, words) in cases.items():
            with self.subTest(case):
                ports = self.new_patch(at, links=links, build=build)
                if unnamed:
                    # Series lists kay.0003-new.patch, and sources does not apply it.
                    ports["projects/kay/series"] += "kay.0003-new.patch\n"
                    ports["projects/kay/kay.0003-new.patch"] = NEW_PATCH
                self.assertEqual(self.row("kay", ports=ports), SINCE + words + KAY_NOTES)
        with self.subTest("two patches that change fuzz_n, and the second also another fuzz target"):
            ports = self.new_patch("targets/kay-fuzz_n", links=links + "link\text/kay-fuzz_m/src\text/kay-fuzz_e/src\n",
                                   build=build + "# fuzz_m: not a target of the release.\n"
                                   "(\nov_target_begin kay-fuzz_m\nov_target_build fuzz_m\n)\n")
            ports["projects/kay/series"] += "kay.0003-new.patch\n"
            ports["projects/kay/kay.0003-new.patch"] = NEW_PATCH
            ports["projects/kay/sources"] += "patch\text/kay-fuzz_e/src\tkay.0003-new.patch\n"
            self.assertEqual(self.row("kay", ports=ports),
                             SINCE + "applies kay.0002-new.patch to no fuzz target that the release built; applies "
                             "kay.0003-new.patch to fuzz_e: the binaries of fuzz_e differ from the release's; the "
                             "release did not build fuzz_m, fuzz_n" + KAY_NOTES)

    def test_a_reproducible_row_with_a_patch_since_the_check(self):
        # A row whose result is not reproduces names no binary that differs from the release's. Its notes still end
        # with the fuzz targets that the patch changes and that the release did not build: in the second case, the
        # tree of dee-other is a link to that of dee-fuzz, and build.sh does not mark fuzz_other as a target of the
        # release.
        ports = {"projects/dee/series": "dee-fuzz.0001-new.patch\n", "projects/dee/dee-fuzz.0001-new.patch": NEW_PATCH,
                 "projects/dee/sources": "tree\text/dee-fuzz/src\tupstream/dee\n"
                                         "patch\text/dee-fuzz/src\tdee-fuzz.0001-new.patch\n",
                 "projects/dee/build.sh": block("dee", "dee-fuzz")}
        link = "link\text/dee-other/src\text/dee-fuzz/src\n"
        other = "(\nov_target_begin dee-other\nov_target_build fuzz_other\n)\n"
        unmarked = {**ports, "projects/dee/sources": ports["projects/dee/sources"] + link,
                    "projects/dee/build.sh": ports["projects/dee/build.sh"] + other}
        since = ("dee\tyes\treproducible\tthe seed port's check: 4 binaries; a second build is identical; the "
                 "release has none to compare; since that check the port applies dee-fuzz.0001-new.patch to fuzz_dee")
        cases = {"a patch that changes a fuzz target of the release": (ports, since + "\t-"),
                 "a patch that also changes a fuzz target that the release did not build": (
                     unmarked, since + "; the release did not build fuzz_other\t-")}
        for case, (files, row) in cases.items():
            with self.subTest(case):
                self.assertEqual(self.row("dee", ports=files), row)

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
        # Every other character at which str.splitlines ends a line, put at the end of dee's row (line 4). A line ends at
        # a newline only, so such a character would be part of a row: kay's name after the character, or, for "\r\n", a
        # "\r" at the end of dee's last field. tsv_fields refuses each at dee's line, before it splits the line into
        # fields.
        for end in ("\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(end=end), self.assertRaisesRegex(
                    seeded_projects.Error, r"/seeds/builds\.tsv: line 4 holds a line end other than a newline"):
                self.table({"builds.tsv": builds.replace("\nkay\t", f"{end}kay\t")})


if __name__ == "__main__":
    unittest.main()
