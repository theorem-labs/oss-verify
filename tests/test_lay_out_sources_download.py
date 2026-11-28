# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the downloads of infra/base-builder/lay-out-sources (its file, archive and gomodules rows), which need no
Docker:  uv run pytest

The tests serve the file themselves, over https on the loopback interface, under a certificate authority of their own
that SSL_CERT_FILE makes the trusted one. Each answer a test plans is one that a real host gives: the 503 that
raw.githubusercontent.com gave build.yaml run 45300318550 and the other statuses that can pass, a connection reset, a
body cut short, a host that refuses the connection or closes it before TLS starts, a 404, a timeout, a certificate the
build does not trust, or bytes that are not the pinned ones. lay-out-sources sleeps between tries; the tests record each
sleep instead of taking it, so they wait for nothing and check every wait.
They need the cryptography package (the tests workflow installs it), and fail without it rather than skip.
"""
import collections
import datetime
import hashlib
import http.server
import importlib.machinery
import importlib.util
import ipaddress
import pathlib
import socket
import ssl
import struct
import sys
import threading
import types
import urllib.request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TESTS = pathlib.Path(__file__).resolve().parent
LOADER = importlib.machinery.SourceFileLoader(
    "lay_out_sources", str(TESTS.parent / "infra" / "base-builder" / "lay-out-sources"))
SPEC = importlib.util.spec_from_loader("lay_out_sources", LOADER)
lay_out_sources = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(lay_out_sources)

BODY = b"int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n"
PINNED = hashlib.sha256(BODY).hexdigest()

# The answers a test can plan. A ("send", status, reason, body, headers) is an HTTP answer.
OK = ("send", 200, "OK", BODY, {})
WRONG = ("send", 200, "OK", b"<html>a page, not the file</html>\n", {})
BUSY = ("send", 503, "Backend.max_conn reached", b"", {})
MISSING = ("send", 404, "Not Found", b"404: Not Found", {})
RESET = ("reset",)  # the connection reset, before any answer
CUT = ("cut",)  # a 200 whose body stops halfway, the connection closed
STALL = ("stall",)  # nothing at all, until the client gives up and closes the connection
STALL_LIMIT = 30


class Host(http.server.ThreadingHTTPServer):
    """An https server that answers each GET of a path with the next answer planned for it (the last one again once
    the plan runs out), and counts the GETs of each path."""

    def __init__(self, context):
        super().__init__(("127.0.0.1", 0), Answer)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.lock = threading.Lock()
        self.plans, self.gets = {}, collections.Counter()

    def plan(self, name, *answers):
        """The URL of a new path that gives `answers`, in turn."""
        path = f"/{name}"
        self.plans[path] = list(answers)
        return f"https://127.0.0.1:{self.server_address[1]}{path}"


class Answer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.lock:
            plan = self.server.plans[self.path]
            answer = plan.pop(0) if len(plan) > 1 else plan[0]
            self.server.gets[self.path] += 1
        self.close_connection = True
        if answer == RESET:
            # A linger of zero seconds makes close() send a TCP reset, not a FIN.
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.connection.close()
        elif answer == CUT:
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY[:len(BODY) // 2])
            self.wfile.flush()
            self.connection.close()
        elif answer == STALL:
            # Held open until the client gives up and closes it: a close of ours after a few seconds would race the
            # client's timeout, and the client would see a closed connection instead. STALL_LIMIT, sixty times the
            # test's client timeout, only stops a client that never gives up from holding the test for 600 seconds.
            self.connection.settimeout(STALL_LIMIT)
            try:
                self.connection.recv(1)
            except OSError:
                pass
        else:
            _, status, reason, body, headers = answer
            self.send_response(status, reason)
            for name, value in {"Content-Length": str(len(body)), **headers}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)


def receive(connection, size):
    """Exactly `size` bytes from a socket, or fewer if the other end closes first."""
    data = b""
    while len(data) < size and (more := connection.recv(size - len(data))):
        data += more
    return data


def certificates(directory):
    """(the authority's certificate file, the server's TLS context): an authority, and a server certificate for
    127.0.0.1 that it signs. The extensions are those a strict verifier asks for."""
    now = datetime.datetime.now(datetime.timezone.utc)
    authority_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    authority_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lay-out-sources tests")])
    authority = (
        x509.CertificateBuilder().subject_name(authority_name).issuer_name(authority_name)
        .public_key(authority_key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(authority_key.public_key()), critical=False)
        .sign(authority_key, hashes.SHA256()))
    server = (
        x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(authority_name).public_key(key.public_key()).serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                       critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()), critical=False)
        .sign(authority_key, hashes.SHA256()))
    trusted, chain = directory / "authority.pem", directory / "server.pem"
    trusted.write_bytes(authority.public_bytes(serialization.Encoding.PEM))
    chain.write_bytes(server.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain)
    return trusted, context


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    return certificates(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def host(tls):
    served = Host(tls[1])
    threading.Thread(target=served.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    yield served
    served.shutdown()
    served.server_close()


class TestDownload:
    @pytest.fixture(autouse=True)
    def set_up(self, tmp_path, tls, host):
        self.top, self.trusted, self.host = tmp_path, tls[0], host
        self.sources = tmp_path / "sources"

    def lay_out(self, url, timeout=None, trusted=True):
        """Run lay-out-sources on a sources file of one file row for `url`, pinned to BODY; with `trusted` false, the
        tests' certificate authority is not trusted. Return (what it said when it stopped, or None if it laid the file
        out; the seconds it slept between tries)."""
        self.sources.write_text(f"file\tout.c\t{url}\t{PINNED}\n")
        slept = []
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(lay_out_sources, "DOWNLOADS", {})
            patch.setattr(lay_out_sources, "time", types.SimpleNamespace(sleep=slept.append), raising=False)
            if timeout is not None:
                patch.setattr(lay_out_sources, "TIMEOUT", timeout, raising=False)
            patch.setattr(sys, "argv", ["lay-out-sources", str(self.sources), str(self.top / "root")])
            if trusted:
                patch.setenv("SSL_CERT_FILE", str(self.trusted))
            else:
                patch.delenv("SSL_CERT_FILE", raising=False)
            # urlopen makes its opener, and with it the TLS context and the certificates it trusts, at its first call
            # in a process, as a build does once. Each run here gets a new one, so it reads SSL_CERT_FILE as a build
            # would, whatever called urlopen before it in this process.
            patch.setattr(urllib.request, "_opener", None)
            try:
                lay_out_sources.main()
            except SystemExit as stopped:
                return str(stopped.code), slept
        assert (self.top / "root" / "out.c").read_bytes() == BODY
        return None, slept

    def gets(self, url):
        return self.host.gets[url[url.index("/", len("https://")):]]

    def stop(self, url, said):
        return f"lay-out-sources: {self.sources}:1: {url}: {said}"

    # A download that works takes one GET and no wait: on a build where nothing fails, the change costs nothing.

    def test_a_file_that_comes_at_once_takes_one_get_and_no_wait(self):
        url = self.host.plan("first-time", OK)
        assert self.lay_out(url) == (None, [])
        assert self.gets(url) == 1

    # A failure that can pass is tried again, after the waits that the docstring of lay-out-sources states.

    @pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
    def test_each_transient_status_is_tried_again_and_the_file_is_laid_out(self, status):
        answer = BUSY if status == 503 else ("send", status, http.HTTPStatus(status).phrase, b"", {})
        url = self.host.plan(f"transient-{status}", answer, OK)
        assert self.lay_out(url) == (None, [5])
        assert self.gets(url) == 2

    def test_a_reset_connection_is_tried_again(self):
        url = self.host.plan("reset-once", RESET, OK)
        assert self.lay_out(url) == (None, [5])
        assert self.gets(url) == 2

    def test_a_body_cut_short_is_tried_again(self):
        url = self.host.plan("cut-once", CUT, OK)
        assert self.lay_out(url) == (None, [5])
        assert self.gets(url) == 2

    @pytest.mark.parametrize("seconds", ["30", "30 \t"], ids=["bare", "with-whitespace"])
    def test_a_retry_after_in_seconds_is_waited_instead(self, seconds):
        url = self.host.plan(f"retry-after-{len(seconds)}",
                             ("send", 429, "Too Many Requests", b"", {"Retry-After": seconds}), OK)
        assert self.lay_out(url) == (None, [30])

    def test_a_retry_after_that_is_a_date_takes_the_usual_wait(self):
        dated = ("send", 503, "Service Unavailable", b"", {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})
        url = self.host.plan("retry-after-date", dated, OK)
        assert self.lay_out(url) == (None, [5])

    # The tries are bounded as that docstring states, and then the build stops with the last failure.

    def test_a_host_that_stays_busy_stops_the_build_after_three_tries(self):
        url = self.host.plan("busy", BUSY)
        assert self.lay_out(url) == (self.stop(url, "HTTP Error 503: Backend.max_conn reached (3 tries)"), [5, 15])
        assert self.gets(url) == 3

    def test_the_longest_waits_the_host_may_ask_for_are_the_most_the_docstring_states(self):
        # A host that asks for the longest wait it may, on each failure, gets that wait each time: 120 seconds in all.
        longest = ("send", 503, "Service Unavailable", b"", {"Retry-After": "60"})
        url = self.host.plan("retry-after-longest", longest)
        assert self.lay_out(url) == (self.stop(url, "HTTP Error 503: Service Unavailable (3 tries)"), [60, 60])
        assert self.gets(url) == 3

    def test_a_host_that_refuses_the_connection_stops_the_build_after_three_tries(self):
        # A port bound and never listened on refuses each connection, and no other program can take it meanwhile.
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            url = f"https://127.0.0.1:{bound.getsockname()[1]}/file.c"
            said, slept = self.lay_out(url)
        assert said.startswith(self.stop(url, "<urlopen error ")) and "Connection refused" in said, said
        assert said.endswith(" (3 tries)"), said
        assert slept == [5, 15]

    def test_a_host_that_closes_before_tls_stops_the_build_after_three_tries(self):
        closer = socket.socket()
        closer.bind(("127.0.0.1", 0))
        closer.listen()
        accepted = []

        def close_each():
            while True:
                try:
                    connection, _ = closer.accept()
                except OSError:
                    return
                accepted.append(connection)
                # The client's first TLS record read whole, then closed: a FIN. Closed with the record unread, the
                # connection would end with a reset instead, whenever the record came before the close.
                header = receive(connection, 5)
                receive(connection, int.from_bytes(header[3:5], "big"))
                connection.close()

        threading.Thread(target=close_each, daemon=True).start()
        url = f"https://127.0.0.1:{closer.getsockname()[1]}/file.c"
        try:
            said, slept = self.lay_out(url)
        finally:
            closer.close()
        # OpenSSL's words for a connection closed before the handshake differ between its versions.
        assert said.startswith(self.stop(url, "<urlopen error ")) and "EOF" in said, said
        assert said.endswith(" (3 tries)"), said
        assert (len(accepted), slept) == (3, [5, 15])

    @pytest.mark.parametrize("seconds", ["3600", "3600 \t"], ids=["bare", "with-whitespace"])
    def test_a_retry_after_longer_than_a_minute_stops_the_build_at_once(self, seconds):
        url = self.host.plan(f"retry-after-long-{len(seconds)}",
                             ("send", 503, "Service Unavailable", b"", {"Retry-After": seconds}), OK)
        assert self.lay_out(url) == (
            self.stop(url, "HTTP Error 503: Service Unavailable, and the host asks for a wait of 3600 seconds, more "
                           "than the 60 this waits"), [])
        assert self.gets(url) == 1

    def test_a_timeout_is_not_tried_again(self):
        # Each try waits TIMEOUT seconds for each read; a host that sends nothing for that long has no short fault,
        # and three tries would only make the build wait three times as long.
        url = self.host.plan("stall", STALL)
        said, slept = self.lay_out(url, timeout=0.5)
        assert said.startswith(self.stop(url, "")) and "timed out" in said and "tries" not in said, said
        assert slept == []

    # What is not a passing failure stops the build at once, and the pin still refuses every other byte.

    def test_a_404_stops_the_build_at_once(self):
        url = self.host.plan("missing", MISSING, OK)
        assert self.lay_out(url) == (self.stop(url, "HTTP Error 404: Not Found"), [])
        assert self.gets(url) == 1

    def test_a_certificate_the_build_does_not_trust_stops_the_build_at_once(self):
        url = self.host.plan("untrusted", OK)
        said, slept = self.lay_out(url, trusted=False)
        assert said.startswith(self.stop(url, "<urlopen error ")) and "CERTIFICATE_VERIFY_FAILED" in said, said
        assert "tries" not in said, said
        assert (slept, self.gets(url)) == ([], 0)

    def test_other_bytes_stop_the_build_at_once(self):
        url = self.host.plan("wrong", WRONG, OK)
        got = hashlib.sha256(WRONG[3]).hexdigest()
        assert self.lay_out(url) == (self.stop(url, f"sha256 {got}, expected {PINNED}"), [])
        assert self.gets(url) == 1

    def test_other_bytes_after_a_503_are_refused_too(self):
        url = self.host.plan("busy-then-wrong", BUSY, WRONG, OK)
        got = hashlib.sha256(WRONG[3]).hexdigest()
        assert self.lay_out(url) == (self.stop(url, f"sha256 {got}, expected {PINNED}"), [5])
        assert self.gets(url) == 2


def test_the_docstring_states_the_bound_that_the_code_uses():
    # The docstring at the top of lay-out-sources is where a reader learns the bound. Each number of it here is taken
    # from the constant that the code uses, so a change to one of the two without the other fails.
    first, second = lay_out_sources.WAITS
    *others, last = sorted(lay_out_sources.TRANSIENT)
    most = sum(max(wait, lay_out_sources.LONGEST_WAIT) for wait in lay_out_sources.WAITS)
    sentences = [
        f"A download is tried at most {len(lay_out_sources.WAITS) + 1} times.",
        f"it waits {first} seconds before the second try and {second} seconds before the third, or the seconds that "
        f"the host's Retry-After asks for, when they are at most {lay_out_sources.LONGEST_WAIT}; a longer Retry-After "
        "stops the build at once.",
        f"So the waits of one download are at most {most} seconds.",
        f"A failure that can pass is an answer of {', '.join(map(str, others))} or {last},",
        f"each try already waits up to {lay_out_sources.TIMEOUT} seconds for each read.",
    ]
    # Each run of whitespace one space, as a reader reads the text across its line breaks.
    text = " ".join(lay_out_sources.__doc__.split())
    assert [sentence for sentence in sentences if sentence not in text] == []
