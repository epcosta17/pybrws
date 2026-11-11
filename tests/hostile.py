"""Misbehaving peers for the hostile-input tests.

Every server here runs on loopback in a thread and is scripted: a test says
which messages go out, in which records, under which keys, so it can send what
a correct server never would. The TLS 1.3 server derives its secrets with
`pybrws.keyschedule` and encrypts with `pybrws.records.Cipher`, both checked
against OpenSSL elsewhere in the suite; the record framing and the order of
messages are its own, so a test can break them on purpose.

`openssl_server` is the opposite instrument: a real TLS stack (the stdlib
`ssl` module), for the cases where the question is whether this client
interoperates rather than whether it refuses.

Not a test module: the name does not start with `test_`.
"""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.verification import Store

from pybrws.keyschedule import (CIPHER_SUITES, KeySchedule,
                                finished_verify_data, hkdf_expand_label,
                                transcript_hash)
from pybrws.parser import parse_client_hello
from pybrws.proxy import CertificateAuthority
from pybrws.records import Cipher
from pybrws.wire import u8, u16, u24, vector

SUITE = CIPHER_SUITES[0x1301]

CHANGE_CIPHER_SPEC = 0x14
ALERT = 0x15
HANDSHAKE = 0x16
APPLICATION_DATA = 0x17

CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02
NEW_SESSION_TICKET = 0x04
ENCRYPTED_EXTENSIONS = 0x08
CERTIFICATE = 0x0B
CERTIFICATE_VERIFY = 0x0F
FINISHED = 0x14
KEY_UPDATE = 0x18
MESSAGE_HASH = 0xFE

X25519 = 0x001D
SECP256R1 = 0x0017
SECP384R1 = 0x0018

# RFC 8446 section 4.1.3, written out here rather than imported from the
# client, so a typo in the client's copy cannot agree with itself.
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
SIGNATURE_CONTEXT = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"


def hs(message_type: int, body: bytes) -> bytes:
    """One handshake message: type, 24-bit length, body."""
    return u8(message_type) + u24(len(body)) + body


def trusted_ca():
    """A throwaway CA, the Store a client should trust it with, and the
    temporary directory holding it (keep a reference; cleanup on drop)."""
    tmp = tempfile.TemporaryDirectory()
    ca = CertificateAuthority(Path(tmp.name))
    return ca, Store([ca.certificate]), tmp


def leaf(ca, host: str):
    """(certificate, private key) for `host`, signed by `ca`.

    A DNS-name SAN from the CA's own builder; for an IP literal, an IP
    address SAN with the same extensions, which that builder cannot make.
    """
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return ca._leaf(host)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(address))]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(address)]),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca.key.public_key()), critical=False)
        .sign(ca.key, hashes.SHA256())
    )
    return certificate, key


def leaf_der(ca, host: str) -> bytes:
    return leaf(ca, host)[0].public_bytes(serialization.Encoding.DER)


class ServerSide:
    """The scripted end of one TLS 1.3 connection.

    Its defaults complete a correct handshake (`handshake()` does all of it);
    each step is also callable on its own, with arguments that break it.
    Messages are added to the transcript as they are *sent*, so a builder
    such as `certificate_verify()` signs everything sent before it.
    """

    def __init__(self, sock: socket.socket, ca, host: str, index: int = 0):
        self.sock = sock
        self.index = index
        certificate, self.leaf_key = leaf(ca, host)
        self.leaf_der = certificate.public_bytes(serialization.Encoding.DER)
        self.suite = SUITE
        self.transcript = bytearray()
        self.read_cipher: Cipher | None = None
        self.write_cipher: Cipher | None = None
        self.client_hello = None
        self.client_hellos: list = []
        self.group: int | None = None
        self.c_hs = self.s_hs = self.c_app = self.s_app = None
        self.client_finished_ok: bool | None = None
        self.client_key_updates = 0
        self._schedule: KeySchedule | None = None

    # -- records ---------------------------------------------------------------

    def _recv_exactly(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise EOFError("client closed after %d of %d bytes"
                               % (len(data), n))
            data += chunk
        return bytes(data)

    def read_record(self) -> tuple[int, bytes]:
        header = self._recv_exactly(5)
        body = self._recv_exactly(int.from_bytes(header[3:5], "big"))
        content_type = header[0]
        if content_type == APPLICATION_DATA and self.read_cipher is not None:
            content_type, body = self.read_cipher.decrypt(header, body)
        return content_type, body

    def send_record(self, content_type: int, payload: bytes, *,
                    encrypted: bool) -> None:
        if encrypted:
            self.sock.sendall(self.write_cipher.encrypt(content_type, payload))
        else:
            self.sock.sendall(u8(content_type) + u16(0x0303)
                              + u16(len(payload)) + payload)

    # -- the handshake, step by step --------------------------------------------

    def read_client_hello(self):
        while True:
            content_type, body = self.read_record()
            if content_type != CHANGE_CIPHER_SPEC:
                break
        if content_type != HANDSHAKE or body[:1] != u8(CLIENT_HELLO):
            raise AssertionError("expected a ClientHello, got type %d" % content_type)
        self.client_hello = parse_client_hello(body)
        self.client_hellos.append(bytes(body))
        self.transcript += body
        return self.client_hello

    def client_share(self, group: int) -> bytes:
        data = self.client_hello.extension(51).data
        at, end = 2, 2 + int.from_bytes(data[:2], "big")
        while at < end:
            kind = int.from_bytes(data[at:at + 2], "big")
            size = int.from_bytes(data[at + 2:at + 4], "big")
            if kind == group:
                return data[at + 4:at + 4 + size]
            at += 4 + size
        raise AssertionError("the client sent no share for 0x%04x" % group)

    def _exchange(self, group: int) -> tuple[bytes, bytes]:
        peer = self.client_share(group)
        if group == X25519:
            key = x25519.X25519PrivateKey.generate()
            public = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return public, key.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
        curve = {SECP256R1: ec.SECP256R1, SECP384R1: ec.SECP384R1}[group]()
        key = ec.generate_private_key(curve)
        public = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        shared = key.exchange(
            ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(curve, peer))
        return public, shared

    def send_hrr(self, *, group: int | None, cookie: bytes | None = None) -> None:
        extensions = u16(43) + vector(u16(0x0304), 2)
        if group is not None:
            extensions += u16(51) + vector(u16(group), 2)
        if cookie is not None:
            extensions += u16(44) + vector(vector(cookie, 2), 2)
        message = hs(SERVER_HELLO, u16(0x0303) + HELLO_RETRY_REQUEST_RANDOM
                     + vector(self.client_hello.session_id, 1)
                     + u16(self.suite.id) + u8(0) + vector(extensions, 2))
        digest = transcript_hash(self.suite, bytes(self.transcript))
        self.transcript = bytearray(u8(MESSAGE_HASH) + u24(len(digest)) + digest
                                    + message)
        self.send_record(HANDSHAKE, message, encrypted=False)
        if group is not None:
            self.group = group

    def send_server_hello(self, *, extensions: bytes | None = None,
                          extra_extensions: bytes = b"",
                          random: bytes | None = None,
                          session_id_echo: bytes | None = None,
                          compression: int = 0, extra_plaintext: bytes = b"",
                          ccs: bool = True) -> None:
        """Answer the hello and switch to the handshake keys.

        `extensions` replaces the default supported_versions + key_share
        pair entirely; `extra_extensions` is appended to it. `extra_plaintext`
        rides in the same plaintext record as the ServerHello, which is how a
        message is made to span the key change.
        """
        group = self.group or X25519
        public, shared = self._exchange(group)
        if extensions is None:
            extensions = (u16(43) + vector(u16(0x0304), 2)
                          + u16(51) + vector(u16(group) + vector(public, 2), 2))
        extensions += extra_extensions
        echo = (self.client_hello.session_id if session_id_echo is None
                else session_id_echo)
        message = hs(SERVER_HELLO, u16(0x0303) + (random or os.urandom(32))
                     + vector(echo, 1) + u16(self.suite.id) + u8(compression)
                     + vector(extensions, 2))
        self.send_record(HANDSHAKE, message + extra_plaintext, encrypted=False)
        self.transcript += message
        if ccs:
            self.send_record(CHANGE_CIPHER_SPEC, b"\x01", encrypted=False)
        self._schedule = KeySchedule(self.suite)
        self.c_hs, self.s_hs = self._schedule.handshake(shared, bytes(self.transcript))
        self.read_cipher = Cipher(self.suite, self.c_hs)
        self.write_cipher = Cipher(self.suite, self.s_hs)

    def encrypted_extensions(self, alpn: str | None = None,
                             extra: bytes = b"") -> bytes:
        extensions = b""
        if alpn is not None:
            extensions += u16(16) + vector(
                vector(vector(alpn.encode("ascii"), 1), 2), 2)
        return hs(ENCRYPTED_EXTENSIONS, vector(extensions + extra, 2))

    def certificate(self, chain: list[bytes] | None = None) -> bytes:
        entries = b"".join(vector(der, 3) + vector(b"", 2)
                           for der in (chain or [self.leaf_der]))
        return hs(CERTIFICATE, vector(b"", 1) + vector(entries, 3))

    def certificate_verify(self) -> bytes:
        signed = SIGNATURE_CONTEXT + transcript_hash(self.suite, bytes(self.transcript))
        signature = self.leaf_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        return hs(CERTIFICATE_VERIFY, u16(0x0403) + vector(signature, 2))

    def finished(self) -> bytes:
        return hs(FINISHED, finished_verify_data(self.suite, self.s_hs,
                                                 bytes(self.transcript)))

    def send_handshake(self, messages: bytes) -> None:
        """Send handshake messages in one record under the current key."""
        self.send_record(HANDSHAKE, messages, encrypted=True)
        self.transcript += messages

    def read_client_finished(self) -> None:
        """Read the client's second flight and switch to application keys."""
        through_server_finished = bytes(self.transcript)
        while True:
            content_type, body = self.read_record()
            if content_type != CHANGE_CIPHER_SPEC:
                break
        if content_type != HANDSHAKE:
            raise AssertionError("expected the client Finished, got type %d"
                                 % content_type)
        at = 0
        while at < len(body):
            size = int.from_bytes(body[at + 1:at + 4], "big")
            message = body[at:at + 4 + size]
            if message[0] == FINISHED:
                expected = finished_verify_data(self.suite, self.c_hs,
                                                bytes(self.transcript))
                self.client_finished_ok = message[4:] == expected
            self.transcript += message
            at += 4 + size
        self.c_app, self.s_app = self._schedule.application(through_server_finished)
        self.read_cipher = Cipher(self.suite, self.c_app)
        self.write_cipher = Cipher(self.suite, self.s_app)

    def handshake(self, *, alpn: str | None = None) -> None:
        """A complete, correct server side."""
        self.read_client_hello()
        self.send_server_hello()
        self.send_handshake(self.encrypted_extensions(alpn))
        self.send_handshake(self.certificate())
        self.send_handshake(self.certificate_verify())
        self.send_handshake(self.finished())
        self.read_client_finished()

    # -- after the handshake ----------------------------------------------------

    def send_app(self, data: bytes) -> None:
        self.send_record(APPLICATION_DATA, data, encrypted=True)

    def read_app(self) -> bytes:
        """The next application payload, following any client KeyUpdate."""
        while True:
            content_type, body = self.read_record()
            if content_type == HANDSHAKE and body[:1] == u8(KEY_UPDATE):
                self.client_key_updates += 1
                self.c_app = hkdf_expand_label(self.suite, self.c_app,
                                               b"traffic upd", b"",
                                               self.suite.hash_size)
                self.read_cipher = Cipher(self.suite, self.c_app)
                continue
            if content_type == APPLICATION_DATA:
                return body
            raise AssertionError("unexpected record type %d" % content_type)

    def new_session_ticket(self, identity: bytes, *, lifetime: int = 3600,
                           nonce: bytes = b"\x00") -> bytes:
        body = (lifetime.to_bytes(4, "big") + bytes(4) + vector(nonce, 1)
                + vector(identity, 2) + vector(b"", 2))
        return hs(NEW_SESSION_TICKET, body)

    def key_update(self, request: bool) -> None:
        """Send a KeyUpdate, then ratchet this side's write key."""
        self.send_record(HANDSHAKE, hs(KEY_UPDATE, u8(1 if request else 0)),
                         encrypted=True)
        self.s_app = hkdf_expand_label(self.suite, self.s_app, b"traffic upd",
                                       b"", self.suite.hash_size)
        self.write_cipher = Cipher(self.suite, self.s_app)

    def close_notify(self) -> None:
        self.send_record(ALERT, b"\x01\x00", encrypted=True)

    def fin(self) -> None:
        """Close the TCP stream without a close_notify."""
        self.sock.shutdown(socket.SHUT_WR)


class Tls13Server(threading.Thread):
    """Accepts `connections` clients and runs `script(peer)` for each."""

    def __init__(self, script, *, ca, host: str = "localhost",
                 bind: str = "127.0.0.1", connections: int = 1) -> None:
        super().__init__(daemon=True)
        family = socket.AF_INET6 if ":" in bind else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.bind((bind, 0))
        self.listener.listen(4)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.script = script
        self.ca = ca
        self.host = host
        self.connections = connections
        self.errors: list[Exception] = []
        self.peers: list[ServerSide] = []

    @property
    def peer(self) -> ServerSide | None:
        return self.peers[0] if self.peers else None

    def run(self) -> None:
        try:
            for index in range(self.connections):
                conn, _ = self.listener.accept()
                conn.settimeout(10)
                peer = ServerSide(conn, self.ca, self.host, index)
                self.peers.append(peer)
                try:
                    self.script(peer)
                except Exception as exc:  # a refused handshake lands here
                    self.errors.append(exc)
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
        except Exception as exc:
            self.errors.append(exc)
        finally:
            self.listener.close()


class Tls12Server(threading.Thread):
    """A scripted TLS 1.2 ECDHE-ECDSA AES-128-GCM server for one connection.

    Built on `pybrws.tls12`'s primitives, mirroring the client's
    `_handshake_12` from the other side. The options make it do what real
    servers do and the client used to mishandle:

    - `coalesce_first_flight`: ServerHello to ServerHelloDone in one record,
      which RFC 5246 6.2.1 allows (one message per record is only OpenSSL's
      habit);
    - `certificate_status`: a stapled OCSP CertificateStatus after the
      Certificate, answering the status_request both profiles send;
    - `random_suffix`: the last eight bytes of ServerHello.random, for the
      TLS 1.3 downgrade sentinel;
    - `renegotiation_info`: the extension's payload, `b"\\x00"` being the
      correct empty one, `None` leaving the extension out.
    """

    def __init__(self, *, ca, host: str = "localhost",
                 coalesce_first_flight: bool = False,
                 certificate_status: bool = False,
                 random_suffix: bytes | None = None,
                 renegotiation_info: bytes | None = b"\x00") -> None:
        super().__init__(daemon=True)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        certificate, self.leaf_key = leaf(ca, host)
        self.leaf_der = certificate.public_bytes(serialization.Encoding.DER)
        self.coalesce = coalesce_first_flight
        self.certificate_status = certificate_status
        self.random_suffix = random_suffix
        self.renegotiation_info = renegotiation_info
        self.errors: list[Exception] = []
        self.completed = False

    def run(self) -> None:
        try:
            conn, _ = self.listener.accept()
            conn.settimeout(10)
            try:
                self._serve(conn)
            finally:
                conn.close()
        except Exception as exc:
            self.errors.append(exc)
        finally:
            self.listener.close()

    def _serve(self, conn) -> None:
        from pybrws import tls12
        from pybrws.records import RecordLayer

        suite = tls12.suite_for(0xC02B)
        records = RecordLayer(conn)
        transcript = bytearray()

        _, body = records.read()
        hello = parse_client_hello(body)
        transcript += body

        server_random = (os.urandom(32) if self.random_suffix is None
                         else os.urandom(24) + self.random_suffix)
        extensions = u16(23) + vector(b"", 2)   # extended_master_secret
        if self.renegotiation_info is not None:
            extensions += u16(0xFF01) + vector(self.renegotiation_info, 2)
        if self.certificate_status:
            extensions += u16(5) + vector(b"", 2)   # status_request, RFC 6066
        server_hello = hs(SERVER_HELLO, u16(0x0303) + server_random + vector(b"", 1)
                          + u16(0xC02B) + u8(0) + vector(extensions, 2))
        certificate = hs(CERTIFICATE, vector(vector(self.leaf_der, 3), 3))
        status = (hs(0x16, u8(1) + vector(b"stapled-ocsp-response", 3))
                  if self.certificate_status else b"")
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        params = u8(3) + u16(X25519) + vector(public, 1)
        signature = self.leaf_key.sign(hello.random + server_random + params,
                                       ec.ECDSA(hashes.SHA256()))
        key_exchange = hs(0x0C, params + u16(0x0403) + vector(signature, 2))
        done = hs(0x0E, b"")
        messages = [server_hello, certificate, status, key_exchange, done]
        flight = b"".join(messages)
        transcript += flight
        if self.coalesce:
            records.write(HANDSHAKE, flight)
        else:
            for message in messages:
                if message:
                    records.write(HANDSHAKE, message)

        records.legacy = True
        _, second = records.read()   # [Certificate] + ClientKeyExchange
        transcript += second
        at = 0
        client_public = b""
        while at < len(second):
            size = int.from_bytes(second[at + 1:at + 4], "big")
            if second[at] == 0x10:
                client_public = second[at + 5:at + 4 + size]
            at += 4 + size
        pre_master = private.exchange(
            x25519.X25519PublicKey.from_public_bytes(client_public))
        master = tls12.extended_master_secret(
            suite, pre_master, tls12.handshake_hash(suite, bytes(transcript)))
        client_key, server_key, client_iv, server_iv = tls12.key_block(
            suite, master, hello.random, server_random)

        content_type, _ = records.read()
        if content_type != CHANGE_CIPHER_SPEC:
            raise AssertionError("expected the client's ChangeCipherSpec")
        records.read_cipher = tls12.Cipher(suite, client_key, client_iv)
        _, finished = records.read()
        expected = tls12.finished_verify_data(
            suite, master, b"client finished",
            tls12.handshake_hash(suite, bytes(transcript)))
        if finished[4:] != expected:
            raise AssertionError("client Finished does not match")
        transcript += finished
        records.write(CHANGE_CIPHER_SPEC, b"\x01")
        records.write_cipher = tls12.Cipher(suite, server_key, server_iv)
        records.write(HANDSHAKE, hs(FINISHED, tls12.finished_verify_data(
            suite, master, b"server finished",
            tls12.handshake_hash(suite, bytes(transcript)))))
        self.completed = True


def openssl_server(handler, *, ca, curve: str | None = None,
                   alpn=("http/1.1",), connections: int = 1,
                   max_version=None, host: str = "localhost") -> int:
    """A real TLS server (stdlib ssl) on loopback. Returns its port.

    `handler(tls_socket)` serves each accepted connection.
    """
    certificate, key = leaf(ca, host)
    directory = Path(tempfile.mkdtemp())
    cert_path = directory / "leaf.pem"
    key_path = directory / "leaf-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    if curve is not None:
        context.set_ecdh_curve(curve)
    if alpn:
        context.set_alpn_protocols(list(alpn))
    if max_version is not None:
        context.maximum_version = max_version
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            for _ in range(connections):
                raw, _ = listener.accept()
                raw.settimeout(10)
                try:
                    with context.wrap_socket(raw, server_side=True) as tls:
                        handler(tls)
                except Exception:
                    pass   # the client side of the test reports what happened
        finally:
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def echo(tls) -> None:
    """An openssl_server handler: answer one read with `pong:` + it."""
    data = tls.recv(4096)
    tls.sendall(b"pong:" + data)


def http_ok(tls) -> None:
    """An openssl_server handler: read one HTTP/1.1 request head, answer 200."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(4096)
        if not chunk:
            return
        data += chunk
    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nok")


class ScriptedTls:
    """An established 'connection' that replays canned inbound chunks.

    Records everything sent in `.sent`. When the script runs out, `recv`
    raises `at_end`; an exception in the script is raised in its turn.
    """

    def __init__(self, chunks, alpn: str = "h2", at_end=None) -> None:
        self.alpn = alpn
        self.sent = bytearray()
        self._inbound = list(chunks)
        self.at_end = at_end or AssertionError("client read past the script")

    def send(self, data: bytes) -> None:
        self.sent += data

    def recv(self) -> bytes:
        if not self._inbound:
            raise self.at_end
        item = self._inbound.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self) -> None:
        pass


def frames_in(data: bytes) -> list[tuple[int, int, int, bytes]]:
    """Split HTTP/2 bytes into (type, flags, stream id, payload) tuples."""
    out = []
    at = 0
    while at + 9 <= len(data):
        length = int.from_bytes(data[at:at + 3], "big")
        out.append((data[at + 3], data[at + 4],
                    int.from_bytes(data[at + 5:at + 9], "big") & 0x7FFFFFFF,
                    bytes(data[at + 9:at + 9 + length])))
        at += 9 + length
    return out
