# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""infra/base-builder/distrust-roots.py, the builder step that removes the emSign and AAA Certificate Services roots:
uv run pytest

The tests make their own self-signed roots, so they need no image: a certifi-style bundle, a wheel that carries one,
and a tree of files for the check that nothing still holds a root. They need the cryptography package (the tests
workflow installs it), and fail without it rather than skip."""
import base64
import datetime
import hashlib
import importlib.util
import pathlib
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "infra/base-builder/distrust-roots.py"
SPEC = importlib.util.spec_from_file_location("distrust_roots", SCRIPT)
distrust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(distrust)

NAMES = ["Good Root CA", "emSign Root CA - G1", "AAA Certificate Services", "Other Root CA"]


def root(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def bundle():
    """certifi's layout: a header, then per root a blank line, its comments and its PEM."""
    parts = ["# certifi test bundle"]
    for cn in NAMES:
        parts.append(f"\n# Issuer: CN={cn}\n# Subject: CN={cn}\n# Label: \"{cn}\"\n{root(cn).rstrip()}")
    return "\n".join(parts) + "\n"


def test_strip_bundle_keeps_only_the_good_roots(bundle):
    assert distrust.subjects(bundle) == [f"commonName={cn}" for cn in NAMES]
    stripped = distrust.strip_bundle(bundle)
    assert distrust.subjects(stripped) == ["commonName=Good Root CA", "commonName=Other Root CA"]
    assert stripped.startswith("# certifi test bundle")
    assert distrust.strip_bundle(stripped) == stripped


def make_wheel(path, bundle):
    pem = "pip/_vendor/certifi/cacert.pem"
    members = {"pip/__init__.py": b"# pip\n", pem: bundle.encode()}
    record = [distrust.record_line(n, d) for n, d in members.items()] + ["pip-1.0.dist-info/RECORD,,"]
    members["pip-1.0.dist-info/RECORD"] = ("\n".join(record) + "\n").encode()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return pem


def test_strip_wheel_strips_the_bundle_and_its_record_line(tmp_path, bundle):
    wheel = tmp_path / "pip-1.0-py3-none-any.whl"
    pem = make_wheel(wheel, bundle)
    wheel.chmod(0o644)
    changed = distrust.strip_wheel(wheel)
    assert list(changed) == [pem]
    assert len(changed[pem][0]) == 4 and len(changed[pem][1]) == 2
    with zipfile.ZipFile(wheel) as z:
        assert z.testzip() is None
        assert z.read("pip/__init__.py") == b"# pip\n"
        assert [i.compress_type for i in z.infolist()] == [zipfile.ZIP_DEFLATED] * 3
        data = z.read(pem)
        record = dict(l.split(",", 1) for l in z.read("pip-1.0.dist-info/RECORD").decode().splitlines())
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    assert record[pem] == f"sha256={digest},{len(data)}"
    assert record["pip/__init__.py"] == distrust.record_line("pip/__init__.py", b"# pip\n").split(",", 1)[1]
    assert wheel.stat().st_mode & 0o777 == 0o644
    assert distrust.strip_wheel(wheel) == {pem: (changed[pem][1], changed[pem][1])}


def test_strip_wheel_leaves_a_wheel_without_certifi(tmp_path):
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr("other/__init__.py", b"")
    before = wheel.read_bytes()
    assert distrust.strip_wheel(wheel) == {}
    assert wheel.read_bytes() == before


def test_leftovers_finds_a_root_in_any_pem_file_or_wheel_member(tmp_path, bundle):
    (tmp_path / "ok.pem").write_text(root("Good Root CA"))
    (tmp_path / "bad.crt").write_text(root("emSign ECC Root CA - C3"))
    (tmp_path / "notes.txt").write_text(root("emSign Root CA - C1"))
    (tmp_path / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"
                                         "-----BEGIN CERTIFICATE-----\nnon-ASCII é\n-----END CERTIFICATE-----\n"
                                         + root("Good Root CA"))
    x509 = root("emSign Root CA - G1").replace(" CERTIFICATE-----", " X509 CERTIFICATE-----")
    (tmp_path / "x509.pem").write_text(x509)
    (tmp_path / "link.pem").symlink_to(tmp_path / "bad.crt")
    make_wheel(tmp_path / "pip-1.0-py3-none-any.whl", bundle)
    found = distrust.leftovers(distrust.walk(str(tmp_path)))
    assert found == [
        (str(tmp_path / "bad.crt"), "commonName=emSign ECC Root CA - C3"),
        (str(tmp_path / "link.pem"), "commonName=emSign ECC Root CA - C3"),
        (f"{tmp_path / 'pip-1.0-py3-none-any.whl'}:pip/_vendor/certifi/cacert.pem", "commonName=emSign Root CA - G1"),
        (f"{tmp_path / 'pip-1.0-py3-none-any.whl'}:pip/_vendor/certifi/cacert.pem",
         "commonName=AAA Certificate Services"),
        (str(tmp_path / "x509.pem"), "commonName=emSign Root CA - G1"),
    ]
    distrust.strip_wheel(tmp_path / "pip-1.0-py3-none-any.whl")
    (tmp_path / "bad.crt").unlink()
    (tmp_path / "link.pem").unlink()
    (tmp_path / "x509.pem").unlink()
    assert distrust.leftovers(distrust.walk(str(tmp_path))) == []


def test_disable_marks_only_active_lines_that_name_a_bad_root():
    conf = ("# emSign roots are listed below\n!mozilla/emSign_Root_CA_-_C1.crt\nmozilla/emSign_Root_CA_-_G1.crt\n"
            "mozilla/ISRG_Root_X1.crt\nmozilla/Comodo_AAA_Services_root.crt\n")
    assert distrust.disable(conf) == ("# emSign roots are listed below\n!mozilla/emSign_Root_CA_-_C1.crt\n"
                                      "!mozilla/emSign_Root_CA_-_G1.crt\nmozilla/ISRG_Root_X1.crt\n"
                                      "!mozilla/Comodo_AAA_Services_root.crt\n")
    assert distrust.disable(distrust.disable(conf)) == distrust.disable(conf)


@pytest.mark.parametrize("after, ok", [
    (["CN=Good", "CN=Other"], True),
    (["CN=Other", "CN=Good"], True),  # order does not matter
    (["CN=Good"], False),  # lost a good root
    (["CN=Good", "CN=Other", "CN=emSign Root CA - G1"], False),  # kept a bad root
])
def test_failures(after, ok):
    before = {"store": ["CN=Good", "CN=emSign Root CA - G1", "CN=Other"]}
    assert (distrust.failures(before, {"store": after}) == []) == ok


def test_failures_refuses_a_store_with_no_good_root():
    assert distrust.failures({"store": ["CN=AAA Certificate Services"]}, {"store": []}) != []


def test_subjects_ignores_non_ascii_comments():
    assert distrust.subjects("# Issuer: CN=Česká Root\n" + root("Good Root CA")) == ["commonName=Good Root CA"]
