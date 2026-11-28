# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: OSS Verify's fields (language, sanitizers, fuzz_targets, patch_style, budgets,
# proofs, publish) and files (build.sh, patch_style.md, harness sources, build-only patches and their series), the
# n/a contact of a seeded project, warnings, and checking named directories.
"""Check projects/<name>/ directories against the enrollment rules in docs/project-yaml.md.

    oss-verify validate                 check every directory under projects/
    oss-verify validate projects/<name> check the directories named

If there are problems, prints one line per problem and exits 1. Otherwise prints one summary line per project, and
any warnings, and exits 0. Runs offline and never writes anything. Requires PyYAML (on Ubuntu, apt install
python3-yaml).

Fields allowed in project.yaml:

    repo: https://...[#ref]             required   one git repository, https only; #ref is a branch or tag to
                                                   follow, or a full commit id to verify exactly that commit
    primary_contact: a@b.c              required   n/a only for a project we seeded (a warning)
    language: <language>                required   OSS-Fuzz's name, from the table in docs/project-yaml.md#language
    dockerfile: <path in your repo>     required   unless a Dockerfile is next to project.yaml (no default); a
                                                   project we seeded may have neither yet (a warning)
    auto_ccs: [a@b.c, ...]              optional   cannot be combined with pgp
    homepage: https://...               optional
    pgp: <armored public key>           optional   if set, reports are encrypted to this key
    disabled: true | false              optional   true pauses the project
    sanitizers: [address, undefined]    optional   the sanitizer builds besides plain (this is the default; go and
                                                   jvm take none, and default to [])
    ubsan_checks: {add, remove, reason}  optional  changes to the UBSan checks of the ubsan builds (default: OSS-Fuzz's, by language,
                                                   with strict-flex-arrays), with a toolchain that applies them; provisional format
    fuzz_targets: [<target>, ...]       optional   default: every fuzz target the build produces
    programs: [{file, sha256}, ...]     optional   whole programs in place of fuzz targets: each file that build.sh
                                                   writes, its pinned SHA-256 and an optional link_map; the plain build
                                                   alone, with no fuzz_targets, mutants or seed corpus
    patch_style: <path in your repo>    optional   or a patch_style.md next to project.yaml
    budgets: {halts: ..., agrees: ...}  optional   memory budgets (docs/what-gets-proven.md)
    proofs: {repo: ..., path: ...}      optional   where the proofs are published (docs/project-yaml.md)
    publish: eager | after_fixes | never  optional  when the proofs are published (default after_fixes)
    mutants: <path from WORKDIR>        optional   the directory of breakage patches (docs/project-yaml.md#mutants)

Files allowed next to project.yaml: a Dockerfile with its build.sh (unless dockerfile: is set), a patch_style.md
(unless patch_style: is set), harness sources (*.c *.cc *.cpp *.h *.hh *.hpp, and those of the project's language),
build-only patches (*.patch) with the series file that lists them in the order they are applied, and seed corpora
(<target>_seed_corpus.zip, as OSS-Fuzz names them). With dockerfile: set, the build context is your repository, so
build.sh, harness sources and patches belong there instead; a seed corpus may stay here.
"""
import argparse
import collections
import datetime
import io
import itertools
import math
import os
import pathlib
import re
import stat
import sys
import zipfile
from urllib.parse import urlparse

from . import check_build

try:
    import yaml
except ImportError:
    sys.exit("oss-verify validate needs PyYAML: on Ubuntu, apt install python3-yaml")

PROJECTS = check_build.ROOT / "projects"

REQUIRED_KEYS = ("repo", "primary_contact", "language")
OPTIONAL_KEYS = (
    "auto_ccs", "homepage", "pgp", "disabled", "dockerfile",
    "sanitizers", "ubsan_checks", "fuzz_targets", "programs", "patch_style", "budgets", "proofs", "publish", "mutants",
)
ALLOWED_KEYS = REQUIRED_KEYS + OPTIONAL_KEYS
# Settings controlled by the program's operators. A pull request may not set them. There are none yet.
OPERATOR_KEYS = ()
# Maps each file that may sit next to project.yaml, instead of in the project's repository, to the key that would
# point to it there.
FILE_KEYS = {"Dockerfile": "dockerfile", "patch_style.md": "patch_style"}
SERIES = "series"
# The pins of a project's other source trees (commits, sha256s), which lay-out-sources lays out.
SOURCES = "sources"
C_SOURCES = (".c", ".cc", ".cpp", ".h", ".hh", ".hpp")
PATCH_SUFFIX = ".patch"
MAX_FILE_BYTES = 64 * 1024  # Dockerfile, patch_style.md, series, sources
MAX_SOURCE_BYTES = 256 * 1024  # build.sh, a harness source or a patch
MAX_CONFIG_BYTES = 128 * 1024
# A seed corpus, as OSS-Fuzz names it: a zip file of example inputs of one fuzz target, which together run each of
# its API calls and property checks at least once. Its inputs are files at the top level of the zip file.
SEED_CORPUS = re.compile(r"(?P<target>[A-Za-z0-9][A-Za-z0-9._-]{0,83})_seed_corpus\.zip")
MAX_CORPUS_BYTES = 1024 * 1024  # the zip file
MAX_CORPUS_INPUTS = 1024
MAX_CORPUS_EXPANDED = 16 * 1024 * 1024  # all its inputs, uncompressed
MAX_FILES = 64
# The setting of a toolchain image with frame pointers. Only the toolchain image gives it, so a Dockerfile or build.sh
# beside project.yaml does not name it (docs/build-contract.md, "Frame pointers").
FRAME_POINTERS = "OFT_FRAME_POINTERS"

NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
# A file next to project.yaml: a plain name, as the build workflow takes it from a pull request.
FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
URL = re.compile(r"https://[^\s#]+(#[A-Za-z0-9._/-]{1,100})?")
# A relative path with no `..` that uses only safe characters (no spaces, backslashes or control characters).
REPO_PATH = re.compile(r"(?!/)(?!.*\.\.)[A-Za-z0-9._/-]+")
FULL_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
SHORT_COMMIT = re.compile(r"[0-9a-f]{7,39}")
TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")
# A file's SHA-256, as sha256sum writes it: 64 hex digits, lower case. validate.py has its own pattern, because
# .github/scripts/copy-validate-rules copies no module of the package other than check_build.
SHA256 = re.compile(r"[0-9a-f]{64}")
# The fields of an entry of programs: file and sha256, which it must have, and link_map, which it may have.
PROGRAM_KEYS = ("file", "sha256", "link_map")
# The most characters of a string of project.yaml that a problem quotes. Through YAML aliases, a small project.yaml
# can put one long string in many places.
MAX_QUOTED = 200
# The most bits of an integer that a problem quotes by its digits: it then has at most MAX_QUOTED decimal digits. A
# mapping key of a small project.yaml can be an integer of more than 4,300 digits, which Python does not give as text.
MAX_QUOTED_BITS = int(MAX_QUOTED * math.log2(10))
# The most problems that validate gives for one project, and the most warnings. Through YAML aliases and merge keys, a
# small project.yaml can give one bad value at thousands of places, and each place makes a new problem. After the
# first MAX_PROBLEMS, one more line says that validate does not show the others.
MAX_PROBLEMS = 100
MORE_PROBLEMS = f"more problems are not shown: validate gives the first {MAX_PROBLEMS}"
MORE_WARNINGS = f"more warnings are not shown: validate gives the first {MAX_PROBLEMS}"
SIZE = re.compile(r"([1-9][0-9]{0,15})(KiB|MiB|GiB|TiB)?")
# The smallest plain-side agrees budget: one page. Below it, no run is in the statement.
MIN_PLAIN_BUDGET = 4096
PGP_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
PGP_END = "-----END PGP PUBLIC KEY BLOCK-----"

# The contact of a project we seeded, which no maintainer has adopted yet.
NO_CONTACT = "n/a"
# Domains reserved for documentation and testing (RFC 2606, RFC 6761), which no real mailbox uses: an address there
# is a placeholder left in project.yaml.
RESERVED_DOMAIN = re.compile(r"(?:.*\.)?(?:example\.(?:com|net|org)|example|invalid|test|localhost)", re.IGNORECASE)
# The values of language, OSS-Fuzz's names, each with the suffixes of the harness sources it permits beside
# project.yaml: its own, and C's and C++'s for native code. The language table in docs/project-yaml.md, the documents'
# only list of them, gives the same values.
LANGUAGES = {
    "c": C_SOURCES,
    "c++": C_SOURCES,
    "rust": (".rs", *C_SOURCES),
    "python": (".py", *C_SOURCES),
    "go": (".go", *C_SOURCES),
    "jvm": (".java", ".kt", *C_SOURCES),
    "javascript": (".js", ".mjs", ".cjs", ".ts", *C_SOURCES),
}
# Every suffix that some language permits.
SOURCE_SUFFIXES = tuple(dict.fromkeys(suffix for suffixes in LANGUAGES.values() for suffix in suffixes))
# The languages with the plain build only: they take no sanitizer builds.
PLAIN_ONLY = ("go", "jvm")
# The languages that the builder builds today: those of the toolchains in infra/toolchains.tsv. The builders of the
# others are pending.
BUILT_TODAY = ("c", "c++", "rust", "python", "go")
# The languages whose UBSan builds are clang's UndefinedBehaviorSanitizer, which ubsan_checks changes (a python
# project's builds compile CPython with it). A rust project's ubsan build is rustc's UB checks
# (docs/build-contract.md#rust-fuzz-targets).
UBSAN_CHECK_LANGUAGES = ("c", "c++", "python")
SANITIZERS = ("address", "undefined")
PUBLISH = ("eager", "after_fixes", "never")
# The builds, in the order their statements and manifests list them, each with the SANITIZER that `compile` takes.
BUILDS = {"plain": "none", "ubsan": "undefined", "asan": "address", "asan-ubsan": "address-undefined"}

DEFAULT_SANITIZERS = ["address", "undefined"]
# The UndefinedBehaviorSanitizer checks and groups that the toolchain's clang (20) takes with -fsanitize-trap for
# riscv64, and vptr, which it takes only without trap mode (objc-cast it does not take for riscv64 at all).
UBSAN_NAMES = (
    "alignment", "array-bounds", "bool", "bounds", "builtin", "enum", "float-cast-overflow", "float-divide-by-zero",
    "function", "implicit-bitfield-conversion", "implicit-conversion", "implicit-integer-arithmetic-value-change",
    "implicit-integer-sign-change", "implicit-integer-truncation", "implicit-signed-integer-truncation",
    "implicit-unsigned-integer-truncation", "integer", "integer-divide-by-zero", "local-bounds", "nonnull-attribute",
    "null", "nullability", "nullability-arg", "nullability-assign", "nullability-return", "object-size",
    "pointer-overflow", "return", "returns-nonnull-attribute", "shift", "shift-base", "shift-exponent",
    "signed-integer-overflow", "undefined", "unreachable", "unsigned-integer-overflow", "unsigned-shift-base",
    "vla-bound", "vptr",
)
# libc++'s extensive hardening mode, named in ubsan_checks as if it were a check: a failed libc++ precondition traps,
# as a UBSan check does. It is not a clang check name; the ubsan build of a c++ project compiles and links its C++
# against the toolchain image's hardened libc++ (infra/base-builder/toolchain.sh).
LIBCXX_HARDENING = "libcxx-hardening"
# -fstrict-flex-arrays=1, named in ubsan_checks as if it were a check. It is not a clang check name: it changes what
# array-bounds checks. clang takes any trailing array of a struct ([N], [1], [0] or []) to be of unknown size unless
# told otherwise, so array-bounds checks no index into the last array of a struct; with it, a trailing [N] with N of 2
# or more is checked, and [1], [0] and [], the ways C writes a flexible array, are not. Both UBSan builds get it
# (infra/base-builder/toolchain.sh).
STRICT_FLEX_ARRAYS = "strict-flex-arrays"
# The names that ubsan_checks takes besides clang's.
NOT_CLANG_CHECKS = (LIBCXX_HARDENING, STRICT_FLEX_ARRAYS)
# Without ubsan_checks, the checks that OSS-Fuzz makes fatal (its -fno-sanitize-recover list), and for a c++ project
# also libc++'s hardening, which OSS-Fuzz does not turn on, and for each language strict-flex-arrays, which OSS-Fuzz does
# not turn on either. vptr is one of OSS-Fuzz's checks that trap mode cannot make
# (TRAP_EXCEPTIONS): the ubsan build makes it through the toolchain's trap-only handler. OSS-Fuzz drops function from
# each C compile, and from a Python project's native code, so a c or python project's default does not have it, and a
# c++ project's C compiles do not either (C_COMPILE_EXCLUDED); vptr and the hardening are about C++ code, so those
# defaults do not have them either. OSS-Fuzz also instruments unsigned-integer-overflow, but silences it with
# silence_unsigned_overflow=1, which trap mode cannot do, so no default has it.
CXX_UBSAN_CHECKS = [
    "array-bounds", "bool", "builtin", "enum", "function", "integer-divide-by-zero", "null", "object-size", "return",
    "returns-nonnull-attribute", "shift", "signed-integer-overflow", "unreachable", "vla-bound", "vptr",
    LIBCXX_HARDENING, STRICT_FLEX_ARRAYS,
]
C_COMPILE_EXCLUDED = ("function",)
CXX_ONLY = ("function", "vptr", LIBCXX_HARDENING)
DEFAULT_UBSAN_CHECKS = {
    "c++": CXX_UBSAN_CHECKS,
    "c": [check for check in CXX_UBSAN_CHECKS if check not in CXX_ONLY],
    "python": [check for check in CXX_UBSAN_CHECKS if check not in CXX_ONLY],
}
# The checks that trap mode cannot make, and how the builds make them: through a trap-only handler of the toolchain
# image in the ubsan build. The asan-ubsan build leaves them out, and so does any build whose checks do not name them.
TRAP_EXCEPTIONS = {
    "vptr": "only the ubsan build makes it, through the toolchain's trap-only handler, and only in code compiled with "
            "RTTI; the asan-ubsan build leaves it out",
}
# The keys of ubsan_checks: changes to the default, and the reason for them. Provisional, until the format is agreed.
UBSAN_CHANGES = ("add", "remove", "reason")
DEFAULT_PUBLISH = "after_fixes"
# Today's values (docs/what-gets-proven.md, Memory budgets): the halts budget for each build run alone; for each
# sanitizer, the agrees budgets of the plain side and the sanitizer side. asan-ubsan uses the address pair.
DEFAULT_BUDGETS = {"halts": "16GiB", "agrees": {"address": ["2GiB", "512GiB"], "undefined": ["16GiB", "512GiB"]}}
PROOFS_REPO = "https://github.com/theorem-labs/oss-verify-proofs"


def is_https_url(value):
    """Return True if `value` is an https:// URL with a host and at most one simple #fragment."""
    if not (isinstance(value, str) and URL.fullmatch(value)):
        return False
    try:
        return bool(urlparse(value.split("#", 1)[0]).hostname)
    except ValueError:
        return False


def is_public_key(text):
    """Return True if `text` is exactly one armored PGP public key block.

    This only checks the format. We check whether the key actually works.
    """
    text = text.strip()
    return (
        text.startswith(PGP_BEGIN)
        and text.endswith(PGP_END)
        and text.count(PGP_BEGIN) == 1
        and text.count(PGP_END) == 1
        and "PRIVATE KEY" not in text
        and len(text) <= MAX_FILE_BYTES
    )


def size_in_bytes(value):
    """The number of bytes a budget names (an integer, or a string such as 16GiB), or None if it names none."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    match = SIZE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return None
    unit = {None: 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}[match.group(2)]
    return int(match.group(1)) * unit


def has_programs(config):
    """Whether a project.yaml that is a mapping names whole programs (programs:) in place of fuzz targets. In YAML, an
    empty `programs:` (or `~`, or `null`) means the key is not set."""
    return config.get("programs") is not None


def sanitizers_of(config):
    """The sanitizers a valid project.yaml asks for. Without sanitizers:, a go or jvm project and a project with
    programs ask for none."""
    sanitizers = config.get("sanitizers")
    if isinstance(sanitizers, list):
        return list(sanitizers)
    return [] if config.get("language") in PLAIN_ONLY or has_programs(config) else list(DEFAULT_SANITIZERS)


def ubsan_changes_of(config):
    """A project's ubsan_checks as {"add": [...], "remove": [...], "reason": ...}, or None if it has none, or the value
    as it is if it is not a mapping. YAML reads a bare `null` as no value: in these lists it is the check null."""
    changes = config.get("ubsan_checks")
    if not isinstance(changes, dict):
        return changes
    tidy = dict(changes)
    for key in ("add", "remove"):
        if isinstance(tidy.get(key), list):
            tidy[key] = ["null" if item is None else item for item in tidy[key]]
    return tidy


def default_ubsan_checks(language):
    """The UBSan checks of a project in this language that does not set ubsan_checks."""
    return list(DEFAULT_UBSAN_CHECKS.get(language, DEFAULT_UBSAN_CHECKS["c"]))


def ubsan_checks_in_effect(config):
    """The UBSan checks that a valid project.yaml asks for: its language's default, less `remove`, with `add`."""
    default = default_ubsan_checks(config.get("language"))
    changes = ubsan_changes_of(config) or {}
    removed = set(changes.get("remove") or [])
    added = [check for check in changes.get("add") or [] if check not in default]
    return [check for check in default if check not in removed] + added


def source_suffixes(config):
    """The suffixes of the harness sources that the project's language permits beside project.yaml."""
    language = config.get("language") if isinstance(config, dict) else None
    return LANGUAGES.get(language, C_SOURCES) if isinstance(language, str) else C_SOURCES


def builds_of(config):
    """The builds a valid project.yaml asks for: plain, one per sanitizer, and asan-ubsan when there are both."""
    sanitizers = sanitizers_of(config)
    wanted = {"plain", *(("ubsan",) if "undefined" in sanitizers else ()), *(("asan",) if "address" in sanitizers else ())}
    if "address" in sanitizers and "undefined" in sanitizers:
        wanted.add("asan-ubsan")
    return [build for build in BUILDS if build in wanted]


def quoted(value):
    """`value`, a value of project.yaml or a name in a file beside it (a line of series, an input of a seed corpus), as
    a problem or a warning quotes it. Each form is short, whatever the value:

    - a string, or bytes (a !!binary value): its repr. Of more than MAX_QUOTED characters or bytes, it gives the first
      MAX_QUOTED, then `...`.
    - an integer of more than MAX_QUOTED_BITS bits: `an integer of <N> bits`. Python gives no integer of more than
      4,300 digits as text.
    - null, true or false, another number, a date or a timestamp: its repr.
    - another value (a list, a mapping or a set): its type, for example `a list`. Through aliases, a list of a few
      hundred bytes of YAML can hold millions of strings.
    """
    if isinstance(value, (str, bytes)):
        return f"{value[:MAX_QUOTED]!r}..." if len(value) > MAX_QUOTED else repr(value)
    if isinstance(value, int) and value.bit_length() > MAX_QUOTED_BITS:
        return f"an integer of {value.bit_length()} bits"
    if value is None or isinstance(value, (bool, int, float, datetime.date)):
        return repr(value)
    return f"a {type(value).__name__}"


def check_keys(config):
    """Yield a problem for each unknown, operator-only, or missing required key."""
    for key in config:
        if key in OPERATOR_KEYS:
            yield f"{quoted(key)} is set by the operators, not in project.yaml"
        elif key not in ALLOWED_KEYS:
            yield f"unknown field {quoted(key)} (allowed: {', '.join(ALLOWED_KEYS)})"
    for key in REQUIRED_KEYS:
        if not config.get(key):
            yield f"missing {key}"


def check_types(config):
    """Yield a problem for each field that has the wrong YAML type."""
    for key in ("primary_contact", "homepage", "pgp", "language", "publish", "dockerfile", "patch_style", "mutants"):
        if config.get(key) is not None and not isinstance(config[key], str):
            yield f"{key} must be a string"
    if isinstance(config.get("mutants"), str) and not REPO_PATH.fullmatch(config["mutants"]):
        yield "mutants must be a relative path, from the Dockerfile's WORKDIR, to a directory of breakage patches"
    if config.get("disabled") is not None and not isinstance(config["disabled"], bool):
        yield "disabled must be true or false"
    for key in ("budgets", "proofs"):
        if config.get(key) is not None and not isinstance(config[key], dict):
            yield f"{key} must be a mapping"


def check_urls(config):
    """Yield a problem if repo or homepage is not a valid https:// URL."""
    if config.get("repo") is not None and not is_https_url(config["repo"]):
        yield "repo must be ONE https:// URL of a git repository (a string, not a list; add #branch, #tag or #commit)"
    homepage = config.get("homepage")
    if isinstance(homepage, str) and not is_https_url(homepage.split("#", 1)[0]):
        yield "homepage must be an https:// URL"


def is_address_list(value):
    """Whether `value`, the value of auto_ccs, is a list of strings."""
    return isinstance(value, list) and all(isinstance(address, str) for address in value)


def finding_addresses(config):
    """The addresses that get findings from a project.yaml that is a mapping: primary_contact, unless it is n/a, and
    each address of auto_ccs. A value that is not a string, and an auto_ccs that is not a list of strings, give none.
    .github/scripts/terms-accepted reads the addresses of a seeded project with it."""
    addresses = []
    if isinstance(config.get("primary_contact"), str) and config["primary_contact"] != NO_CONTACT:
        addresses.append(config["primary_contact"])
    if is_address_list(config.get("auto_ccs")):
        addresses += config["auto_ccs"]
    return addresses


def check_addresses(config):
    """Yield a problem for auto_ccs that is not a list, and for each malformed email address."""
    ccs = config.get("auto_ccs")
    if ccs is not None and not is_address_list(ccs):
        yield "auto_ccs must be a list of addresses"
    # Each address once: through YAML aliases, auto_ccs can name one long address thousands of times.
    for address in dict.fromkeys(finding_addresses(config)):
        if not EMAIL.fullmatch(address):
            yield f"bad email {quoted(address)}"


def check_pgp(config):
    """Yield a problem if pgp is malformed, or is combined with auto_ccs."""
    key = config.get("pgp")
    if key and config.get("auto_ccs"):
        yield "pgp and auto_ccs together are not supported: an encrypted report goes to primary_contact only"
    if isinstance(key, str) and not is_public_key(key):
        yield (
            f"pgp must be one armored public key: the text from {PGP_BEGIN} to {PGP_END} "
            "(not a fingerprint, a URL or a private key)"
        )


def check_builds(config):
    """Yield a problem with language, sanitizers, fuzz_targets or publish."""
    language = config.get("language")
    if isinstance(language, str) and language not in LANGUAGES:
        yield f"language must be one of {', '.join(LANGUAGES)} (got {quoted(language)})"

    sanitizers = config.get("sanitizers")
    if sanitizers is not None:
        if not (isinstance(sanitizers, list) and all(isinstance(item, str) for item in sanitizers)):
            yield f"sanitizers must be a list, a subset of [{', '.join(SANITIZERS)}]"
        else:
            for item in sanitizers:
                if item not in SANITIZERS:
                    yield f"sanitizers: {quoted(item)} is not one of {', '.join(SANITIZERS)}"
            if len(set(sanitizers)) != len(sanitizers):
                yield "sanitizers names a sanitizer twice"
            if language in PLAIN_ONLY and sanitizers:
                yield (f"a {language} project has the plain build only: give sanitizers: [] "
                       "or leave it out")
            elif has_programs(config) and sanitizers:
                yield "a project with programs has the plain build only: give sanitizers: [] or leave it out"

    changes = ubsan_changes_of(config)
    if changes is not None:
        yield from check_ubsan_changes(config, changes)

    targets = config.get("fuzz_targets")
    if targets is not None:
        if not (isinstance(targets, list) and targets and all(isinstance(item, str) for item in targets)):
            yield "fuzz_targets must be a non-empty list of fuzz target names (or left out, for all of them)"
        else:
            for item in targets:
                if not TARGET.fullmatch(item):
                    yield f"fuzz_targets: {quoted(item)} is not a fuzz target name (A-Z a-z 0-9 . _ + -, at most 100)"
            if len(set(targets)) != len(targets):
                yield "fuzz_targets names a fuzz target twice"

    publish = config.get("publish")
    if isinstance(publish, str) and publish not in PUBLISH:
        yield f"publish must be one of {', '.join(PUBLISH)} (got {quoted(publish)})"


def check_programs(config):
    """Yield a problem with programs: the whole programs that build.sh writes in $OUT, which a project names in place
    of fuzz targets. Each entry gives a program's file name, its SHA-256, and optionally the file name of the link map
    that the build writes. A project with programs has the plain build alone (check_builds), no seed corpus
    (check_corpus), no fuzz_targets and no mutants."""
    if not has_programs(config):
        return
    entries = config["programs"]
    if config.get("fuzz_targets") is not None:
        yield "programs and fuzz_targets together are not supported: a project with programs lists no fuzz target"
    if config.get("mutants") is not None:
        yield "mutants applies only to fuzz targets: the breakages do not run for a project with programs"
    if not (isinstance(entries, list) and entries):
        yield ("programs must be a non-empty list of mappings, each with file and sha256, and optionally link_map "
               "(or left out, for a project of fuzz targets)")
        return
    # Through YAML aliases, a small project.yaml can give tens of thousands of entries, and one entry object can be at
    # many places. An entry that is not a mapping is refused at each place (check_config shows at most MAX_PROBLEMS
    # problems). The keys and values of a mapping are checked at its first place only. A merge key (<<) makes a new
    # mapping, which is checked at its own place. The file and link map of a mapping count at each place, so that the
    # checks of names given twice see them.
    files, link_maps, first_maps, checked = [], [], [], set()
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            yield f"programs: entry {number} must be a mapping with file and sha256, and optionally link_map"
            continue
        if isinstance(entry.get("file"), str):
            files.append(entry["file"])
        if isinstance(entry.get("link_map"), str):
            link_maps.append(entry["link_map"])
        if id(entry) in checked:
            continue
        checked.add(id(entry))
        for key in entry:
            if key not in PROGRAM_KEYS:
                yield f"programs: entry {number}: unknown field {quoted(key)} (allowed: {', '.join(PROGRAM_KEYS)})"
        for key in ("file", "sha256"):
            if entry.get(key) is None:
                yield f"programs: entry {number}: missing {key}"
        for key in ("file", "link_map"):
            value = entry.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                # Its type, not its repr: through aliases, a list of a few hundred bytes of YAML can hold millions of
                # strings.
                yield (f"programs: entry {number}: {key} must be a string, the name of a file in $OUT "
                       f"(it is a {type(value).__name__})")
            elif not TARGET.fullmatch(value):
                yield (f"programs: entry {number}: {key} {quoted(value)} is not a file name in $OUT "
                       "(A-Z a-z 0-9 . _ + -, starting with a letter or digit, at most 100)")
        sha256 = entry.get("sha256")
        if sha256 is not None and not (isinstance(sha256, str) and SHA256.fullmatch(sha256)):
            yield f"programs: entry {number}: sha256 must be the SHA-256 of the file: 64 hex digits, lower case"
        if isinstance(entry.get("link_map"), str):
            first_maps.append((number, entry["link_map"]))
    # A set and counts, not scans of the lists, which can be long.
    file_names = set(files)
    for number, link_map in first_maps:
        if link_map in file_names:
            yield f"programs: entry {number}: link_map {quoted(link_map)} is also the file of a program"
    for name in sorted(name for name, count in collections.Counter(files).items() if count > 1):
        yield f"programs names the file {quoted(name)} twice"
    for name in sorted(name for name, count in collections.Counter(link_maps).items() if count > 1):
        yield f"programs names the link map {quoted(name)} twice"


def check_budgets(config):
    """Yield a problem with the budgets block (docs/what-gets-proven.md, Memory budgets)."""
    budgets = config.get("budgets")
    if not isinstance(budgets, dict):
        return
    for key in budgets:
        if key not in ("halts", "agrees"):
            yield f"budgets: unknown field {quoted(key)} (allowed: halts, agrees)"
    if "halts" in budgets:
        halts = size_in_bytes(budgets["halts"])
        if halts is None:
            yield "budgets.halts must be a size: a positive number of bytes, or a number with KiB, MiB, GiB or TiB"
        elif halts != size_in_bytes(DEFAULT_BUDGETS["halts"]):   # the only halts budget the statements carry
            yield (f"budgets.halts: only {DEFAULT_BUDGETS['halts']} is supported; a project's own halts budget is not "
                   "carried into the statements yet")
    agrees = budgets.get("agrees")
    if agrees is None:
        return
    if not isinstance(agrees, dict):
        yield "budgets.agrees must be a mapping from a sanitizer to [plain side, sanitizer side]"
        return
    # A missing or null sanitizers: is the default, as for builds_of(). A malformed one is check_builds' problem, and
    # wants no sanitizer here.
    sanitizers = config.get("sanitizers")
    wanted = sanitizers_of(config) if sanitizers is None or isinstance(sanitizers, list) else []
    for sanitizer, pair in agrees.items():
        if sanitizer not in SANITIZERS:
            yield f"budgets.agrees: {quoted(sanitizer)} is not one of {', '.join(SANITIZERS)}"
            continue
        if sanitizer not in wanted:
            yield f"budgets.agrees.{sanitizer} is set, but {sanitizer} is not one of this project's sanitizers"
        if not (isinstance(pair, list) and len(pair) == 2 and all(size_in_bytes(size) for size in pair)):
            yield f"budgets.agrees.{sanitizer} must be two sizes: [plain side, sanitizer side]"
            continue
        plain, sanitizer_side = (size_in_bytes(size) for size in pair)
        if plain < MIN_PLAIN_BUDGET:
            yield f"budgets.agrees.{sanitizer}: the plain side must be at least {MIN_PLAIN_BUDGET} bytes"
        if sanitizer_side < plain:
            yield f"budgets.agrees.{sanitizer}: the sanitizer side must be at least the plain side"


def check_proofs(config):
    """Yield a problem with the proofs block."""
    proofs = config.get("proofs")
    if not isinstance(proofs, dict):
        return
    for key in proofs:
        if key not in ("repo", "path"):
            yield f"proofs: unknown field {quoted(key)} (allowed: repo, path)"
    if "repo" in proofs and not is_https_url(proofs["repo"]):
        yield "proofs.repo must be ONE https:// URL of a git repository, with #branch if not the default branch"
    if "path" in proofs and not (isinstance(proofs["path"], str) and REPO_PATH.fullmatch(proofs["path"])):
        yield "proofs.path must be a relative path inside that repository"


def series_entries(text):
    """The patch names a series file lists, in order: one per line, ignoring blank lines and lines that start with #.

    As lay-out-sources reads it: a # after a space starts no comment, so "  # x" names the patch "# x".
    """
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def copied_by_sources(files):
    """The project files the sources file copies into place or reads (its `copy` and `gomodules` directives), which
    may have any name."""
    text = files.get(SOURCES)
    if not text:
        return set()
    return {fields[2] for line in text.splitlines() if not line.startswith("#")
            for fields in [line.split("\t")] if len(fields) == 3 and fields[0] in ("copy", "gomodules")}


def check_files(config, files):
    """Yield problems with the files next to project.yaml, and with the keys that point into the repository instead.

    `files` maps the name of each file next to project.yaml to its text, or to None if it could not be read or is
    too large.
    """
    for key in FILE_KEYS.values():
        path = config.get(key)
        if path is not None and not (isinstance(path, str) and REPO_PATH.fullmatch(path)):
            yield f"{key} must be a relative path inside your repository"

    # In YAML, an empty `dockerfile:` (or `~`, or `null`) means the key is not set.
    in_repo = config.get("dockerfile") is not None
    # A project we seeded may wait for build files that have been verified (config_warnings says so).
    if "Dockerfile" not in files and not in_repo and config.get("primary_contact") != NO_CONTACT:
        yield (
            "a Dockerfile is required, in exactly one place: beside project.yaml (with its build.sh), or in your "
            "repository at the path you give as dockerfile: (there is no default path)"
        )
    if len(files) > MAX_FILES:
        yield f"at most {MAX_FILES} files may sit in a project's directory (there are {len(files)})"

    patches = sorted(name for name in files if name.endswith(PATCH_SUFFIX))
    copied = copied_by_sources(files)
    for name, text in files.items():
        is_source = name.endswith(source_suffixes(config)) or name in copied
        corpus = SEED_CORPUS.fullmatch(name)
        if not FILE_NAME.fullmatch(name):
            yield f"{name}: a file name may use only A-Z a-z 0-9 . _ - (starting with a letter or digit)"
            continue
        if corpus:
            yield from check_corpus(config, name, corpus["target"], text)
            continue
        if name not in (*FILE_KEYS, "build.sh", SERIES, SOURCES) and not is_source and name not in patches:
            yield (
                f"{name}: only project.yaml, Dockerfile, build.sh, sources, patch_style.md, harness sources "
                f"({' '.join('*' + suffix for suffix in source_suffixes(config))}), *.patch, series, seed corpora "
                "(<target>_seed_corpus.zip) and the files sources copies may sit in a project's directory"
            )
            continue
        limit = MAX_SOURCE_BYTES if is_source or name in patches or name == "build.sh" else MAX_FILE_BYTES
        if text is None:
            yield f"{name} is larger than {limit // 1024} KiB (or not UTF-8 text)"
            continue
        if name in ("Dockerfile", "build.sh"):
            if not text.strip():
                yield f"{name} is empty"
            if FRAME_POINTERS in text:
                yield (
                    f"{name} names {FRAME_POINTERS}: only the toolchain image gives that setting "
                    '(docs/build-contract.md, "Frame pointers")'
                )
        if name in FILE_KEYS and config.get(FILE_KEYS[name]) is not None:
            yield f"{name} is given both beside project.yaml and as {FILE_KEYS[name]}: in your repository; one place only"
        if in_repo and name not in FILE_KEYS:
            yield (
                f"{name}: with dockerfile: set, your repository is the build context, so {name} belongs there, "
                "beside the Dockerfile"
            )

    if SERIES in files and files[SERIES] is not None:
        listed = series_entries(files[SERIES])
        for name in listed:
            if name not in files or not name.endswith(PATCH_SUFFIX):
                yield f"series lists {quoted(name)}, which is not a .patch file beside project.yaml"
        # Counts, not a scan of the list for each name: a series of 64 KiB has more than 20,000 lines.
        for name in sorted(name for name, count in collections.Counter(listed).items() if count > 1):
            yield f"series lists {quoted(name)} more than once"
        for name in patches:
            if name not in listed:
                yield f"{name} is not listed in series (it says the order patches are applied in)"
    elif patches:
        yield "patches need a series file beside them that lists them, one per line, in the order they are applied"


def check_ubsan_changes(config, changes):
    """Yield a problem with ubsan_checks: changes to the default list, with the reason. (The format is provisional.)"""
    if not isinstance(changes, dict):
        yield "ubsan_checks must be a mapping of add, remove and reason (or left out, for the default)"
        return
    for key in changes:
        if key not in UBSAN_CHANGES:
            yield printable(f"ubsan_checks: unknown field {quoted(key)} (allowed: {', '.join(UBSAN_CHANGES)})")
    for key in ("add", "remove"):
        checks = changes.get(key)
        if checks is None:
            continue
        if not (isinstance(checks, list) and all(isinstance(item, str) for item in checks)):
            yield f"ubsan_checks.{key} must be a list of UBSan check names"
            continue
        for item in checks:
            if item not in UBSAN_NAMES and item not in NOT_CLANG_CHECKS:
                yield printable(f"ubsan_checks.{key}: {quoted(item)} is not a UBSan check that clang knows")
        if len(set(checks)) != len(checks):
            yield f"ubsan_checks.{key} names a check twice"
    added, removed = changes.get("add") or [], changes.get("remove") or []
    if isinstance(added, list) and isinstance(removed, list):
        # Only the strings, never the text of other items: through aliases, a list of a few hundred bytes of YAML can
        # hold millions of strings.
        if {item for item in added if isinstance(item, str)} & {item for item in removed if isinstance(item, str)}:
            yield "ubsan_checks adds and removes the same check"
        if not added and not removed:
            yield "ubsan_checks changes nothing: leave it out for the default"
    reason = changes.get("reason")
    if not (isinstance(reason, str) and reason.strip()):
        yield "ubsan_checks.reason must say why the project's checks differ from the default"
    if isinstance(added, list) and LIBCXX_HARDENING in added and config.get("language") != "c++":
        yield f"ubsan_checks.add: {LIBCXX_HARDENING} applies only to a c++ project"
    if "undefined" not in sanitizers_of(config):
        yield "ubsan_checks applies only to the UBSan builds: sanitizers must contain undefined"
    language = config.get("language")
    if isinstance(language, str) and language in LANGUAGES and language not in UBSAN_CHECK_LANGUAGES:
        yield (f"ubsan_checks applies only to C, C++ and Python: a {language} project's ubsan build does not use "
               "UndefinedBehaviorSanitizer")


def newest_toolchain_applies_ubsan_checks():
    """Whether the newest toolchain in infra/toolchains.tsv applies a project's ubsan_checks."""
    try:
        return check_build.ubsan_mode(check_build.newest_toolchain()) == "checks"
    except (OSError, check_build.Failed):
        return False


def first_distinct(lines, more):
    """The lines that the iterable `lines` gives, each distinct line once, in the order found, and at most MAX_PROBLEMS
    of them. When one more distinct line comes, the list ends with the line `more`, and no more of `lines` is read: the
    checks after it do no work. Through YAML aliases and merge keys, a small project.yaml can give one bad item at
    thousands of places."""
    found = {}
    for line in lines:
        if line not in found:
            if len(found) == MAX_PROBLEMS:
                return [*found, more]
            found[line] = None
    return list(found)


def warnings_of(config, files):
    """Yield warnings: things that are allowed but worth a second look. The project.yaml and the files have no problem
    (check_config), so each value that a warning gives without quoted() is one of a fixed list, or short."""
    changes = ubsan_changes_of(config)
    if isinstance(changes, dict):
        added = changes.get("add") if isinstance(changes.get("add"), list) else []
        removed = changes.get("remove") if isinstance(changes.get("remove"), list) else []
        for item in sorted(set(map(str, added)) & set(TRAP_EXCEPTIONS)):
            yield f"ubsan_checks: {item}: {TRAP_EXCEPTIONS[item]}"
        default = default_ubsan_checks(config.get("language"))
        for item in sorted(set(map(str, added)) & set(default)):
            yield f"ubsan_checks.add: {item} is in the default already"
        for item in sorted(set(map(str, removed)) - set(default)):
            yield f"ubsan_checks.remove: {item} is not in the default, so there is nothing to remove"
        if not (set(map(str, added)) | set(map(str, removed))) - set(UBSAN_NAMES) - set(NOT_CLANG_CHECKS):
            in_effect = ubsan_checks_in_effect(config)
            if STRICT_FLEX_ARRAYS in in_effect and not {"array-bounds", "bounds", "undefined"} & set(in_effect):
                yield (f"ubsan_checks: {STRICT_FLEX_ARRAYS} adds no check without array-bounds, which the checks leave "
                       "out; it still changes how clang optimizes the code of the two UBSan builds")
        if not newest_toolchain_applies_ubsan_checks():
            yield ("ubsan_checks has no effect yet: the newest toolchain keeps the release's fixed UBSan flags, and "
                   "oss-verify check refuses the field with it")
    if config.get("primary_contact") == NO_CONTACT:
        yield "primary_contact is n/a: only a project we seeded may say that, and only until a maintainer adopts it"
    # Each address once: through YAML aliases, auto_ccs can name one long address thousands of times.
    for address in dict.fromkeys(finding_addresses(config)):
        if RESERVED_DOMAIN.fullmatch(address.rpartition("@")[2]):
            yield f"{quoted(address)} is a placeholder: its domain is reserved for examples, so no report reaches it"
    repo = config.get("repo")
    if isinstance(repo, str) and "#" in repo:
        ref = repo.split("#", 1)[1]
        if SHORT_COMMIT.fullmatch(ref) and not FULL_COMMIT.fullmatch(ref):
            yield f"#{ref} looks like a shortened commit id; give a commit in full, or this names a branch or tag"
    language = config.get("language")
    if language in LANGUAGES and language not in BUILT_TODAY:
        yield (f"language {language}: the builder cannot build it yet (docs/project-yaml.md#language), so "
               "oss-verify check refuses it")
    if "Dockerfile" not in files and config.get("dockerfile") is None:
        yield "no build files yet (a seeded project): it cannot be built until a Dockerfile and build.sh are added"
    if "Dockerfile" in files and "build.sh" not in files:
        yield "there is a Dockerfile but no build.sh beside it: the Dockerfile must create $SRC/build.sh itself"
    for name in sorted(files):
        text = files[name]
        if name.endswith(PATCH_SUFFIX) and text is not None and not re.search(r"^(--- |\+\+\+ |diff )", text, re.M):
            yield f"{name} does not look like a patch (no diff, --- or +++ line)"


def config_warnings(config, files):
    """Return the warnings of a project.yaml with no problem and of the files next to it: each distinct warning once, in
    the order found, and at most MAX_PROBLEMS of them, then MORE_WARNINGS (first_distinct)."""
    return first_distinct(warnings_of(config, files), MORE_WARNINGS)


def check_config(config, files):
    """Return the problems with a parsed project.yaml and the files next to it: each distinct problem once, in the order
    found, and at most MAX_PROBLEMS of them, then MORE_PROBLEMS (first_distinct). The checks give their problems one at
    a time, so a check after the last problem shown does no work."""
    if not isinstance(config, dict):
        return [f"not a mapping (top level is a {type(config).__name__})"]
    return first_distinct(itertools.chain(
        check_keys(config),
        check_types(config),
        check_urls(config),
        check_addresses(config),
        check_pgp(config),
        check_builds(config),
        check_programs(config),
        check_budgets(config),
        check_proofs(config),
        check_files(config, files),
    ), MORE_PROBLEMS)


def check_corpus(config, name, target, data):
    """Yield problems with a seed corpus: `data` is its bytes, or None if it is larger than MAX_CORPUS_BYTES. It is
    read as untrusted input: its inputs are decompressed, but only up to MAX_CORPUS_EXPANDED bytes in all. A project
    with programs has no seed corpus."""
    if has_programs(config):
        yield f"{name}: a project with programs has no seed corpus: the seed runs are for fuzz targets only"
        return
    targets = config.get("fuzz_targets")
    if isinstance(targets, list) and target not in targets:
        yield f"{name} is the seed corpus of {target}, which fuzz_targets does not list"
    if data is None:
        yield f"{name} is larger than {MAX_CORPUS_BYTES // 1024} KiB"
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if not entries:
                yield f"{name} holds no input"
            if len(entries) > MAX_CORPUS_INPUTS:
                yield f"{name} holds more than {MAX_CORPUS_INPUTS} inputs"
                return
            expanded = 0
            for entry in entries:
                plain = entry.filename not in ("", ".", "..") and not any(c in entry.filename for c in "/\\:")
                if entry.is_dir() or not plain:
                    yield printable(f"{name}: {quoted(entry.filename)} is not a file at the top level of the zip file")
                    continue
                with archive.open(entry) as stream:
                    while chunk := stream.read(1 << 16):
                        expanded += len(chunk)
                        if expanded > MAX_CORPUS_EXPANDED:
                            yield f"{name} expands to more than {MAX_CORPUS_EXPANDED // (1 << 20)} MiB"
                            return
    # A damaged or hostile zip file can fail in many ways: each one means that it is not a seed corpus we can use.
    except Exception:  # noqa: BLE001
        yield f"{name} is not a zip file that Python's zipfile module can read"


def read_bytes(path, limit):
    """Return the file's bytes, or None if it is larger than `limit` or unreadable."""
    try:
        if path.lstat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def read_text(path, limit):
    """Return the file's text, or None if it is larger than `limit`, unreadable, or not UTF-8."""
    try:
        if path.lstat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def limit_for(name, suffixes=SOURCE_SUFFIXES):
    """The largest a file with this name may be, in bytes. `suffixes` are those of the harness sources."""
    if name.endswith(suffixes) or name.endswith(PATCH_SUFFIX) or name == "build.sh":
        return MAX_SOURCE_BYTES
    return MAX_FILE_BYTES


def load(directory):
    """Parse projects/<name>/project.yaml. Raise ValueError with the reason if it cannot be read."""
    config_file = directory / "project.yaml"
    if config_file.lstat().st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"project.yaml is larger than {MAX_CONFIG_BYTES // 1024} KiB")
    try:
        return yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    # ValueError covers UnicodeDecodeError, and what PyYAML's scalar constructors raise for a value such as the date
    # 2024-13-45, which is not a YAMLError.
    except (yaml.YAMLError, ValueError, RecursionError) as error:
        raise ValueError(f"project.yaml does not parse: {type(error).__name__}: {str(error)[:300]}") from None


def check_project(directory):
    """Check one projects/<name>/ directory. Return (problems, warnings, summary line).

    The summary line is None when there are problems. This runs on pull requests from anyone, so it never reads
    through a symbolic link.
    """
    name, config_file = directory.name, directory / "project.yaml"
    if not NAME.fullmatch(name):
        return ["the directory name must be a-z 0-9 . _ - (starting with a letter or digit, at most 63)"], [], None
    if directory.is_symlink():
        return [f"symbolic links are not accepted (projects/{name} is one)"], [], None
    if config_file.is_symlink():
        return [f"symbolic links are not accepted (projects/{name}/project.yaml is one)"], [], None
    if not config_file.is_file():
        return [f"projects/{name}/project.yaml is missing"], [], None

    beside = sorted(path for path in directory.iterdir() if path != config_file)
    irregular = [path.name for path in beside if not stat.S_ISREG(path.lstat().st_mode)]
    if irregular:
        return [
            f"only regular files are accepted: no symbolic links or directories ({', '.join(irregular)})"
        ], [], None

    try:
        config = load(directory)
    except ValueError as error:
        return [str(error)], [], None

    files = {path.name: read_bytes(path, MAX_CORPUS_BYTES) if SEED_CORPUS.fullmatch(path.name)
             else read_text(path, limit_for(path.name, source_suffixes(config))) for path in beside}
    for copied in copied_by_sources(files) & set(files):
        files[copied] = read_text(directory / copied, MAX_SOURCE_BYTES)
    problems = check_config(config, files)
    if problems:
        return problems, [], None

    if "Dockerfile" in files:
        where = "beside project.yaml"
    elif config.get("dockerfile") is not None:
        where = f"in the repository at {config['dockerfile']}"
    else:
        where = "none yet"
    if has_programs(config):
        built = f"programs: {', '.join(entry['file'] for entry in config['programs'])}"
    else:
        built = f"fuzz targets: {', '.join(config['fuzz_targets']) if config.get('fuzz_targets') else 'all'}"
    summary = (
        f"{name:<24} {config['repo']}  -> {config['primary_contact']}  "
        f"(Dockerfile: {where}; builds: {' '.join(builds_of(config))}; {built})"
    )
    return [], config_warnings(config, files), summary


def printable(text):
    """Text for the terminal or a CI log: control characters (escape sequences, BEL, newlines) from a project.yaml or a
    directory name are shown as \\xNN, never sent raw."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda m: f"\\x{ord(m.group()):02x}", text)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="oss-verify validate", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directories", nargs="*", type=pathlib.Path, help="projects/<name> directories (default: all)")
    options = parser.parse_args(argv)

    # The name of "." is "" and that of ".." is "..": neither is a project name. abspath() takes away "." and ".." by
    # the text of the path and follows no symbolic link, so check_project still sees one named in the path. "." alone
    # is the working directory, which the system gives with every link resolved, so a link entered with cd is not seen.
    directories = [pathlib.Path(os.path.abspath(directory)) for directory in options.directories] or sorted(
        path for path in PROJECTS.glob("*") if path.is_dir() or path.is_symlink()
    )
    problems, warnings, summaries = [], [], []
    for directory in directories:
        found, cautions, summary = check_project(directory)
        problems += [printable(f"{directory.name}: {problem}") for problem in found]
        warnings += [printable(f"{directory.name}: warning: {caution}") for caution in cautions]
        summaries.append(summary)

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"ok: {len(summaries)} project(s)")
    for summary in summaries:
        print(f"  {printable(summary)}")
    for warning in warnings:
        print(warning)
    return 0


if __name__ == "__main__":
    sys.exit(main())
