#!/usr/bin/env python3
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
# Modified 2026 by Theorem Labs, PBC: OSS Verify's fields (language, sanitizers, fuzz_targets, patch_style, budgets,
# proofs, publish) and files (build.sh, patch_style.md, harness sources, build-only patches and their series), the
# n/a contact of a seeded project, warnings, and checking named directories.
"""Check projects/<name>/ directories against the enrollment rules in docs/project-yaml.md.

    tools/validate.py                 check every directory under projects/
    tools/validate.py projects/<name> check the directories named

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
    ubsan_checks: {add, remove, reason}  optional  changes to the UBSan checks of the ubsan builds (default: OSS-Fuzz's, by language),
                                                   with a toolchain that applies them; provisional format
    fuzz_targets: [<target>, ...]       optional   default: every fuzz target the build produces
    patch_style: <path in your repo>    optional   or a patch_style.md next to project.yaml
    budgets: {halts: ..., agrees: ...}  optional   memory budgets (docs/what-gets-proven.md)
    proofs: {repo: ..., path: ...}      optional   where the proofs are published (docs/project-yaml.md)
    publish: eager | after_fixes | never  optional  when the proofs are published (default after_fixes)

Files allowed next to project.yaml: a Dockerfile with its build.sh (unless dockerfile: is set), a patch_style.md
(unless patch_style: is set), harness sources (*.c *.cc *.cpp *.h *.hh *.hpp, and those of the project's language),
build-only patches (*.patch) with the series file that lists them in the order they are applied, and seed corpora
(<target>_seed_corpus.zip, as OSS-Fuzz names them). With dockerfile: set, the build context is your repository, so
build.sh, harness sources and patches belong there instead; a seed corpus may stay here.
"""
import argparse
import io
import pathlib
import re
import stat
import sys
import zipfile
from urllib.parse import urlparse

import check_build

try:
    import yaml
except ImportError:
    sys.exit("tools/validate.py needs PyYAML: on Ubuntu, apt install python3-yaml")

PROJECTS = pathlib.Path(__file__).resolve().parent.parent / "projects"

REQUIRED_KEYS = ("repo", "primary_contact", "language")
OPTIONAL_KEYS = (
    "auto_ccs", "homepage", "pgp", "disabled", "dockerfile",
    "sanitizers", "ubsan_checks", "fuzz_targets", "patch_style", "budgets", "proofs", "publish",
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
SIZE = re.compile(r"([1-9][0-9]{0,15})(KiB|MiB|GiB|TiB)?")
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
# The languages with halts statements only, about the plain build: they take no sanitizer builds.
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
# Without ubsan_checks, the checks that OSS-Fuzz makes fatal (its -fno-sanitize-recover list), less vptr, which trap
# mode cannot make (TRAP_EXCEPTIONS). OSS-Fuzz drops function from each C compile, and from a Python project's native
# code, so a c or python project's default does not have it, and a c++ project's C compiles do not either
# (C_COMPILE_EXCLUDED). OSS-Fuzz also instruments unsigned-integer-overflow, but silences it with
# silence_unsigned_overflow=1, which trap mode cannot do, so no default has it.
CXX_UBSAN_CHECKS = [
    "array-bounds", "bool", "builtin", "enum", "function", "integer-divide-by-zero", "null", "object-size", "return",
    "returns-nonnull-attribute", "shift", "signed-integer-overflow", "unreachable", "vla-bound",
]
C_COMPILE_EXCLUDED = ("function",)
DEFAULT_UBSAN_CHECKS = {
    "c++": CXX_UBSAN_CHECKS,
    "c": [check for check in CXX_UBSAN_CHECKS if check not in C_COMPILE_EXCLUDED],
    "python": [check for check in CXX_UBSAN_CHECKS if check not in C_COMPILE_EXCLUDED],
}
# The checks that the trapping builds leave out of any list, and why.
TRAP_EXCEPTIONS = {
    "vptr": "it needs the UBSan runtime, which trap mode does not have",
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


def sanitizers_of(config):
    """The sanitizers a valid project.yaml asks for."""
    sanitizers = config.get("sanitizers")
    if isinstance(sanitizers, list):
        return list(sanitizers)
    return [] if config.get("language") in PLAIN_ONLY else list(DEFAULT_SANITIZERS)


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


def check_keys(config):
    """Yield a problem for each unknown, operator-only, or missing required key."""
    for key in config:
        if key in OPERATOR_KEYS:
            yield f"{key!r} is set by the operators, not in project.yaml"
        elif key not in ALLOWED_KEYS:
            yield f"unknown field {key!r} (allowed: {', '.join(ALLOWED_KEYS)})"
    for key in REQUIRED_KEYS:
        if not config.get(key):
            yield f"missing {key}"


def check_types(config):
    """Yield a problem for each field that has the wrong YAML type."""
    for key in ("primary_contact", "homepage", "pgp", "language", "publish", "dockerfile", "patch_style"):
        if config.get(key) is not None and not isinstance(config[key], str):
            yield f"{key} must be a string"
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


def check_addresses(config):
    """Yield a problem for auto_ccs that is not a list, and for each malformed email address."""
    addresses = []
    if isinstance(config.get("primary_contact"), str) and config["primary_contact"] != NO_CONTACT:
        addresses.append(config["primary_contact"])
    ccs = config.get("auto_ccs")
    if isinstance(ccs, list) and all(isinstance(address, str) for address in ccs):
        addresses += ccs
    elif ccs is not None:
        yield "auto_ccs must be a list of addresses"
    for address in addresses:
        if not EMAIL.fullmatch(address):
            yield f"bad email {address!r}"


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
        yield f"language must be one of {', '.join(LANGUAGES)} (got {language!r})"

    sanitizers = config.get("sanitizers")
    if sanitizers is not None:
        if not (isinstance(sanitizers, list) and all(isinstance(item, str) for item in sanitizers)):
            yield f"sanitizers must be a list, a subset of [{', '.join(SANITIZERS)}]"
        else:
            for item in sanitizers:
                if item not in SANITIZERS:
                    yield f"sanitizers: {item!r} is not one of {', '.join(SANITIZERS)}"
            if len(set(sanitizers)) != len(sanitizers):
                yield "sanitizers names a sanitizer twice"
            if language in PLAIN_ONLY and sanitizers:
                yield (f"a {language} project has halts statements only, about the plain build: give sanitizers: [] "
                       "or leave it out")

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
                    yield f"fuzz_targets: {item!r} is not a fuzz target name (A-Z a-z 0-9 . _ + -, at most 100)"
            if len(set(targets)) != len(targets):
                yield "fuzz_targets names a fuzz target twice"

    publish = config.get("publish")
    if isinstance(publish, str) and publish not in PUBLISH:
        yield f"publish must be one of {', '.join(PUBLISH)} (got {publish!r})"


def check_budgets(config):
    """Yield a problem with the budgets block (docs/what-gets-proven.md, Memory budgets)."""
    budgets = config.get("budgets")
    if not isinstance(budgets, dict):
        return
    for key in budgets:
        if key not in ("halts", "agrees"):
            yield f"budgets: unknown field {key!r} (allowed: halts, agrees)"
    if "halts" in budgets and size_in_bytes(budgets["halts"]) is None:
        yield "budgets.halts must be a size: a positive number of bytes, or a number with KiB, MiB, GiB or TiB"
    agrees = budgets.get("agrees")
    if agrees is None:
        return
    if not isinstance(agrees, dict):
        yield "budgets.agrees must be a mapping from a sanitizer to [plain side, sanitizer side]"
        return
    wanted = sanitizers_of(config) if isinstance(config.get("sanitizers", []), list) else []
    for sanitizer, pair in agrees.items():
        if sanitizer not in SANITIZERS:
            yield f"budgets.agrees: {sanitizer!r} is not one of {', '.join(SANITIZERS)}"
            continue
        if sanitizer not in wanted:
            yield f"budgets.agrees.{sanitizer} is set, but {sanitizer} is not one of this project's sanitizers"
        if not (isinstance(pair, list) and len(pair) == 2 and all(size_in_bytes(size) for size in pair)):
            yield f"budgets.agrees.{sanitizer} must be two sizes: [plain side, sanitizer side]"


def check_proofs(config):
    """Yield a problem with the proofs block."""
    proofs = config.get("proofs")
    if not isinstance(proofs, dict):
        return
    for key in proofs:
        if key not in ("repo", "path"):
            yield f"proofs: unknown field {key!r} (allowed: repo, path)"
    if "repo" in proofs and not is_https_url(proofs["repo"]):
        yield "proofs.repo must be ONE https:// URL of a git repository, with #branch if not the default branch"
    if "path" in proofs and not (isinstance(proofs["path"], str) and REPO_PATH.fullmatch(proofs["path"])):
        yield "proofs.path must be a relative path inside that repository"


def series_entries(text):
    """The patch names a series file lists, in order: one per line, ignoring blank lines and # comments."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


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
        if name in ("Dockerfile", "build.sh") and not text.strip():
            yield f"{name} is empty"
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
                yield f"series lists {name!r}, which is not a .patch file beside project.yaml"
        for name in sorted({name for name in listed if listed.count(name) > 1}):
            yield f"series lists {name!r} more than once"
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
            yield printable(f"ubsan_checks: unknown field {key!r} (allowed: {', '.join(UBSAN_CHANGES)})")
    for key in ("add", "remove"):
        checks = changes.get(key)
        if checks is None:
            continue
        if not (isinstance(checks, list) and all(isinstance(item, str) for item in checks)):
            yield f"ubsan_checks.{key} must be a list of UBSan check names"
            continue
        for item in checks:
            if item not in UBSAN_NAMES:
                yield printable(f"ubsan_checks.{key}: {item!r} is not a UBSan check that clang knows")
        if len(set(checks)) != len(checks):
            yield f"ubsan_checks.{key} names a check twice"
    added, removed = changes.get("add") or [], changes.get("remove") or []
    if isinstance(added, list) and isinstance(removed, list):
        if set(map(str, added)) & set(map(str, removed)):
            yield "ubsan_checks adds and removes the same check"
        if not added and not removed:
            yield "ubsan_checks changes nothing: leave it out for the default"
    reason = changes.get("reason")
    if not (isinstance(reason, str) and reason.strip()):
        yield "ubsan_checks.reason must say why the project's checks differ from the default"
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


def config_warnings(config, files):
    """Return warnings: things that are allowed but worth a second look."""
    warnings = []
    changes = ubsan_changes_of(config)
    if isinstance(changes, dict):
        added = changes.get("add") if isinstance(changes.get("add"), list) else []
        removed = changes.get("remove") if isinstance(changes.get("remove"), list) else []
        for item in sorted(set(map(str, added)) & set(TRAP_EXCEPTIONS)):
            warnings.append(f"ubsan_checks: the trapping builds leave out {item}: {TRAP_EXCEPTIONS[item]}")
        default = default_ubsan_checks(config.get("language"))
        for item in sorted(set(map(str, added)) & set(default)):
            warnings.append(f"ubsan_checks.add: {item} is in the default already")
        for item in sorted(set(map(str, removed)) - set(default)):
            warnings.append(f"ubsan_checks.remove: {item} is not in the default, so there is nothing to remove")
        if not newest_toolchain_applies_ubsan_checks():
            warnings.append("ubsan_checks has no effect yet: the newest toolchain keeps the release's fixed UBSan flags, "
                            "and tools/check refuses the field with it")
    if config.get("primary_contact") == NO_CONTACT:
        warnings.append(
            "primary_contact is n/a: only a project we seeded may say that, and only until a maintainer adopts it"
        )
    contacts = [config.get("primary_contact")]
    if isinstance(config.get("auto_ccs"), list):
        contacts += config["auto_ccs"]
    for address in contacts:
        if isinstance(address, str) and RESERVED_DOMAIN.fullmatch(address.rpartition("@")[2]):
            warnings.append(f"{address} is a placeholder: its domain is reserved for examples, so no report reaches it")
    repo = config.get("repo")
    if isinstance(repo, str) and "#" in repo:
        ref = repo.split("#", 1)[1]
        if SHORT_COMMIT.fullmatch(ref) and not FULL_COMMIT.fullmatch(ref):
            warnings.append(f"#{ref} looks like a shortened commit id; give a commit in full, or this names a branch or tag")
    language = config.get("language")
    if language in LANGUAGES and language not in BUILT_TODAY:
        warnings.append(f"language {language}: the builder cannot build it yet (docs/project-yaml.md#language), so "
                        "tools/check refuses it")
    if "Dockerfile" not in files and config.get("dockerfile") is None:
        warnings.append("no build files yet (a seeded project): it cannot be built until a Dockerfile and build.sh are added")
    if "Dockerfile" in files and "build.sh" not in files:
        warnings.append("there is a Dockerfile but no build.sh beside it: the Dockerfile must create $SRC/build.sh itself")
    for name in sorted(files):
        text = files[name]
        if name.endswith(PATCH_SUFFIX) and text is not None and not re.search(r"^(--- |\+\+\+ |diff )", text, re.M):
            warnings.append(f"{name} does not look like a patch (no diff, --- or +++ line)")
    return warnings


def check_config(config, files):
    """Return a list of every problem with a parsed project.yaml and the files next to it."""
    if not isinstance(config, dict):
        return [f"not a mapping (top level is a {type(config).__name__})"]
    return [
        *check_keys(config),
        *check_types(config),
        *check_urls(config),
        *check_addresses(config),
        *check_pgp(config),
        *check_builds(config),
        *check_budgets(config),
        *check_proofs(config),
        *check_files(config, files),
    ]


def check_corpus(config, name, target, data):
    """Yield problems with a seed corpus: `data` is its bytes, or None if it is larger than MAX_CORPUS_BYTES. It is
    read as untrusted input: its inputs are decompressed, but only up to MAX_CORPUS_EXPANDED bytes in all."""
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
                    yield printable(f"{name}: {entry.filename!r} is not a file at the top level of the zip file")
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
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError) as error:
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
    targets = ", ".join(config["fuzz_targets"]) if config.get("fuzz_targets") else "all"
    summary = (
        f"{name:<24} {config['repo']}  -> {config['primary_contact']}  "
        f"(Dockerfile: {where}; builds: {' '.join(builds_of(config))}; fuzz targets: {targets})"
    )
    return [], config_warnings(config, files), summary


def printable(text):
    """Text for the terminal or a CI log: control characters (escape sequences, BEL, newlines) from a project.yaml or a
    directory name are shown as \\xNN, never sent raw."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda m: f"\\x{ord(m.group()):02x}", text)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directories", nargs="*", type=pathlib.Path, help="projects/<name> directories (default: all)")
    options = parser.parse_args()

    directories = options.directories or sorted(
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
