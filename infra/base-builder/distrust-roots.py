#!/usr/bin/env python3
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""
Make the builder trust no root of eMudhra's emSign CAs or of Comodo's AAA Certificate Services. The Dockerfile runs
this once, as root, in the builder image (python3 distrust-roots.py); tests/test_distrust_roots.py tests it.

    1. Disable the roots in Alpine's store: prefix their lines in /etc/ca-certificates.conf with "!" and run
       update-ca-certificates, which writes /etc/ssl/certs/ca-certificates.crt again, removes their links in
       /etc/ssl/certs, and (update.d) makes the Java store /etc/ssl/certs/java/cacerts again.
    2. Remove them from every certifi/cacert.pem in the image, and from the certifi/cacert.pem inside every wheel
       (ensurepip's bundled pip wheels: `python3 -m venv` installs pip from them), with the wheel's RECORD line made
       again for the new bytes.
    3. Fail unless every store it changed now holds exactly the roots it held before, less these, and unless no
       PEM file (*.pem, *.crt, *.cer, and every file in /etc/ssl/certs) and no PEM member of a wheel in the image
       holds one of them. /usr/share/ca-certificates is skipped: it is update-ca-certificates' source, not a store.

Alpine has no openssl command, so Python's ssl module reads the PEM certificates and keytool the Java store.
"""
import base64
import hashlib
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
import zipfile

# Subjects and certifi comments name AAA "AAA Certificate Services"; the conf line names its file
# mozilla/Comodo_AAA_Services_root.crt.
BAD = re.compile(r"emSign|eMudhra|AAA[ _]Certificate[ _]Services|Comodo_AAA_Services", re.I)
SYSTEM = pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
JAVA = pathlib.Path("/etc/ssl/certs/java/cacerts")
CONF = pathlib.Path("/etc/ca-certificates.conf")
NOT_WALKED = ("/proc", "/sys", "/dev", "/usr/share/ca-certificates")
PEM_SUFFIXES = (".pem", ".crt", ".cer")
CERTIFI = re.compile(r"(^|/)certifi/cacert\.pem$")
PEM_BLOCK = re.compile(r"-----BEGIN (?:X509 )?CERTIFICATE-----.*?-----END (?:X509 )?CERTIFICATE-----", re.S)


def subjects(text):
    """The subject of each CA certificate in PEM text, as 'key=value, ...'. Only the PEM blocks are read, so a
    comment in any language does not matter."""
    blocks = PEM_BLOCK.findall(text)
    if not blocks:
        return []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata="\n".join(blocks))
    return [", ".join("%s=%s" % kv for rdn in cert["subject"] for kv in rdn) for cert in context.get_ca_certs()]


def block_subjects(text):
    """subjects() of each PEM certificate block in text on its own, skipping a block OpenSSL cannot read (test data
    such as CPython's): no TLS library can trust a certificate it cannot read."""
    found = []
    for block in PEM_BLOCK.findall(text):
        if not block.isascii():
            continue
        try:
            found += subjects(block)
        except ssl.SSLError:
            pass
    return found


def disable(conf):
    """/etc/ca-certificates.conf's text with each active line that names a bad root prefixed with '!'."""
    return "".join(("!" + l if not l.startswith(("!", "#")) and BAD.search(l) else l) + "\n"
                   for l in conf.splitlines())


def failures(before, after):
    """For each store, a message unless it holds exactly the roots it held before less the bad ones (in any order),
    and at least one."""
    found = []
    for where in before:
        want = sorted(s for s in before[where] if not BAD.search(s))
        got = sorted(after[where])
        if not want or got != want:
            found.append(f"{where}: it should hold the {len(want)} roots it held less these, and holds {len(got)}: "
                         f"{sorted(set(got) ^ set(want))}")
    return found


def strip_bundle(text):
    """certifi's cacert.pem without the blocks whose Issuer, Subject or Label comment names a bad root."""
    blocks = re.split(r"\n(?=\n# Issuer:)", text)
    kept = [b for b in blocks if not any(BAD.search(h) for h in re.findall(r"^# (?:Issuer|Subject|Label):.*$", b, re.M))]
    return "\n".join(kept)


def record_line(name, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def strip_wheel(path):
    """Strip each certifi/cacert.pem in the wheel at path, and its RECORD line. Return {member: (before, after)}
    with the subjects of each stripped member, or {} if the wheel has none."""
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        data = {i.filename: z.read(i) for i in infos}
    changed = {}
    for name in data:
        if CERTIFI.search(name):
            text = data[name].decode()
            new = strip_bundle(text)
            changed[name] = (subjects(text), subjects(new))
            data[name] = new.encode()
    if not changed:
        return {}
    for name in data:
        if name.endswith(".dist-info/RECORD"):
            lines = data[name].decode().splitlines()
            lines = [record_line(l.split(",")[0], data[l.split(",")[0]]) if l.split(",")[0] in changed else l
                     for l in lines]
            data[name] = ("\n".join(lines) + "\n").encode()
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    os.close(fd)
    with zipfile.ZipFile(tmp, "w") as z:
        for info in infos:
            z.writestr(info, data[info.filename])
    os.chmod(tmp, path.stat().st_mode & 0o7777)
    os.replace(tmp, path)
    return changed


def walk(root="/"):
    """Every file under root, outside NOT_WALKED, in a fixed order: a link to a file counts (/etc/ssl/certs holds
    links), a link to a directory is not followed."""
    for top, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if os.path.join(top, d) not in NOT_WALKED)
        for f in sorted(files):
            p = pathlib.Path(top, f)
            if p.is_file():
                yield p


def leftovers(files):
    """[(where, subject)] for each bad root in a PEM file or a PEM member of a wheel."""
    found = []
    for p in files:
        if p.suffix in PEM_SUFFIXES or p.parent == SYSTEM.parent:
            found += [(str(p), s) for s in block_subjects(p.read_text(errors="replace")) if BAD.search(s)]
        elif p.suffix == ".whl":
            with zipfile.ZipFile(p) as z:
                for name in z.namelist():
                    if name.endswith(PEM_SUFFIXES):
                        found += [(f"{p}:{name}", s) for s in block_subjects(z.read(name).decode(errors="replace"))
                                  if BAD.search(s)]
    return found


def java_owners():
    listing = subprocess.run(["keytool", "-list", "-v", "-keystore", str(JAVA), "-storepass", "changeit"],
                             check=True, capture_output=True, text=True).stdout
    return [l for l in listing.splitlines() if l.startswith("Owner:")]


def main():
    before = {str(SYSTEM): subjects(SYSTEM.read_text()), str(JAVA): java_owners()}
    after = {}

    CONF.write_text(disable(CONF.read_text()))
    subprocess.run(["update-ca-certificates"], check=True, stdout=subprocess.DEVNULL)
    after[str(SYSTEM)] = subjects(SYSTEM.read_text())
    after[str(JAVA)] = java_owners()

    files = list(walk())
    for p in (p for p in files if not p.is_symlink()):  # a link's target is stripped as itself
        if CERTIFI.search(p.as_posix()):
            text = p.read_text()
            before[str(p)] = subjects(text)
            p.write_text(strip_bundle(text))
            after[str(p)] = subjects(p.read_text())
        elif p.suffix == ".whl":
            for name, (b, a) in strip_wheel(p).items():
                before[f"{p}:{name}"], after[f"{p}:{name}"] = b, a

    for where in before:
        print(f"{where}: {len(before[where])} -> {len(after[where])} roots")
    messages = failures(before, after) + [f"{where} still holds {subject}" for where, subject in leftovers(files)]
    for message in messages:
        print(f"FAIL: {message}")
    return 1 if messages else 0


if __name__ == "__main__":
    sys.exit(main())
