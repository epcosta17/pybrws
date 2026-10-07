"""TLS 1.3 client handshake.

Certificates are accepted without verification. See the note in README.
"""

from __future__ import annotations

import socket

from . import certs
from .emitter import build_client_hello, retry_hello
from . import keyexchange
from .keyexchange import KeyExchange
from .keyschedule import (
    CIPHER_SUITES,
    KeySchedule,
    finished_verify_data,
    transcript_hash,
)
from .parser import _Reader
from .profiles import firefox157
from .proxies import open_socket
from .records import APPLICATION_DATA, HANDSHAKE, Cipher, RecordLayer
from .wire import u24, u8

SERVER_HELLO = 0x02
NEW_SESSION_TICKET = 0x04
ENCRYPTED_EXTENSIONS = 0x08
CERTIFICATE = 0x0B
CERTIFICATE_VERIFY = 0x0F
FINISHED = 0x14
KEY_UPDATE = 0x18
COMPRESSED_CERTIFICATE = 0x19  # RFC 8879, sent because we offer compress_certificate

EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_ALPN = 16
EXT_COOKIE = 44

MESSAGE_HASH = 0xFE

HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


class HandshakeError(Exception):
    pass


class ServerHello:
    """The fields of a ServerHello that drive the rest of the handshake."""

    def __init__(self, message: bytes) -> None:
        reader = _Reader(message, "ServerHello")
        if reader.uint(1) != SERVER_HELLO:
            raise HandshakeError("expected a ServerHello")
        body = _Reader(reader.vector(3), "ServerHello body")

        body.uint(2)  # legacy_version
        self.random = body.read(32)
        self.session_id_echo = body.vector(1)
        self.cipher_suite = body.uint(2)
        body.uint(1)  # legacy_compression_method

        self.selected_version: int | None = None
        self.selected_group: int | None = None
        self.peer_key_share: bytes = b""
        self.cookie: bytes | None = None

        extensions = _Reader(body.vector(2), "ServerHello extensions")
        while extensions.remaining:
            ext_type = extensions.uint(2)
            data = extensions.vector(2)
            if ext_type == EXT_SUPPORTED_VERSIONS:
                self.selected_version = int.from_bytes(data[:2], "big")
            elif ext_type == EXT_KEY_SHARE:
                self.selected_group = int.from_bytes(data[:2], "big")
                # A HelloRetryRequest names a group and sends no key with it.
                self.peer_key_share = data[4:] if len(data) > 2 else b""
            elif ext_type == EXT_COOKIE:
                self.cookie = data

    @property
    def is_hello_retry_request(self) -> bool:
        return self.random == HELLO_RETRY_REQUEST_RANDOM


class _HandshakeReader:
    """Reassembles handshake messages, which need not align with records."""

    def __init__(self, records: RecordLayer) -> None:
        self.records = records
        self.buffer = bytearray()

    def next_message(self) -> bytes:
        while True:
            if len(self.buffer) >= 4:
                length = int.from_bytes(self.buffer[1:4], "big")
                if len(self.buffer) >= 4 + length:
                    message = bytes(self.buffer[: 4 + length])
                    del self.buffer[: 4 + length]
                    return message
            content_type, body = self.records.read()
            if content_type != HANDSHAKE:
                raise HandshakeError(
                    "expected a handshake record, got content type " + str(content_type)
                )
            self.buffer += body


def suite_for(hello: "ServerHello"):
    """The cipher suite a ServerHello or HelloRetryRequest selected."""
    suite = CIPHER_SUITES.get(hello.cipher_suite)
    if suite is None:
        raise HandshakeError("unsupported cipher suite 0x%04x" % hello.cipher_suite)
    return suite


def _retry(client_hello: bytes, hello: "ServerHello", raw_message: bytes,
           key_exchange: KeyExchange, suite):
    """Answer a HelloRetryRequest.

    Returns the second ClientHello, a key exchange for the group the server
    asked for, and the rewritten transcript.
    """
    group = hello.selected_group
    if group is None:
        raise HandshakeError("HelloRetryRequest named no group")
    if group in key_exchange.groups:
        # The server already had a share for it, so asking again means it
        # will ask forever.
        raise HandshakeError(
            "HelloRetryRequest asked for 0x%04x, which was already offered" % group
        )
    if not keyexchange.supported(group):
        raise HandshakeError(
            "HelloRetryRequest asked for 0x%04x, which this client cannot produce"
            % group
        )

    retry_exchange = KeyExchange([group])
    second = retry_hello(client_hello, group, retry_exchange.public_share(group),
                         hello.cookie)

    # RFC 8446 section 4.4.1: the first ClientHello is replaced in the
    # transcript by a synthetic message carrying only its hash. Appending it
    # as usual would make every later verification fail.
    digest = transcript_hash(suite, client_hello[5:])
    synthetic = u8(MESSAGE_HASH) + u24(len(digest)) + digest
    return second, retry_exchange, bytearray(synthetic + raw_message)


class Connection:
    """An established TLS 1.3 connection."""

    def __init__(self, sock: socket.socket, records: RecordLayer, suite, alpn: str) -> None:
        self.sock = sock
        self.records = records
        self.suite = suite
        self.alpn = alpn

    def send(self, data: bytes) -> None:
        self.records.write(APPLICATION_DATA, data)

    def recv(self) -> bytes:
        """Return the next application payload, skipping post-handshake messages."""
        while True:
            content_type, body = self.records.read()
            if content_type == APPLICATION_DATA:
                return body
            if content_type == HANDSHAKE:
                continue  # NewSessionTicket and friends
            raise HandshakeError("unexpected content type " + str(content_type))

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def connect(
    host: str,
    port: int = 443,
    *,
    profile=firefox157,
    timeout: float = 15.0,
    proxy=None,
    verify: bool = True,
    trust_store=None,
) -> Connection:
    """Open a TLS 1.3 connection impersonating `profile`.

    Args:
        host: hostname, used for both DNS and the `server_name` extension.
        port: TCP port.
        profile: the client to imitate.
        timeout: socket timeout in seconds.
        proxy: a proxy URL or Proxy, or None for a direct connection. The
            handshake is identical either way; only the egress address and
            the TCP/IP signature change.
        verify: check the certificate chain and the CertificateVerify
            signature. Turning this off makes the connection trivially
            interceptable, which a proxy tested during development was
            doing.
        trust_store: anchors to trust instead of the system's.

    Returns:
        A Connection ready to carry application data.

    Raises:
        HandshakeError: on protocol failures, including an unverifiable
            server Finished.
        CertificateError: if the chain or the signature does not check out.
        TlsAlert: if the server rejects the handshake.
    """
    key_exchange = KeyExchange([group for group, _ in profile.KEY_SHARE_GROUPS])
    client_hello = build_client_hello(host, profile=profile, key_exchange=key_exchange)

    sock = open_socket(host, port, proxy=proxy, timeout=timeout)
    records = RecordLayer(sock)
    try:
        sock.sendall(client_hello)
        # Middlebox compatibility: a dummy ChangeCipherSpec after the first flight.
        records.write(0x14, b"\x01")

        transcript = bytearray(client_hello[5:])
        handshake_reader = _HandshakeReader(records)

        message = handshake_reader.next_message()
        hello = ServerHello(message)
        if hello.is_hello_retry_request:
            client_hello, key_exchange, transcript = _retry(
                client_hello, hello, message, key_exchange, suite_for(hello)
            )
            records.write(HANDSHAKE, client_hello[5:])
            message = handshake_reader.next_message()
            hello = ServerHello(message)
            if hello.is_hello_retry_request:
                raise HandshakeError("the server sent a second "
                                     "HelloRetryRequest, which RFC 8446 forbids")
        if hello.selected_version != 0x0304:
            raise HandshakeError(
                "server did not select TLS 1.3 (got %r)" % (hello.selected_version,)
            )
        suite = suite_for(hello)
        transcript += message

        shared_secret = key_exchange.shared_secret(
            hello.selected_group, hello.peer_key_share
        )
        schedule = KeySchedule(suite)
        client_hs_secret, server_hs_secret = schedule.handshake(
            shared_secret, bytes(transcript)
        )
        records.read_cipher = Cipher(suite, server_hs_secret)

        alpn = ""
        leaf = None
        while True:
            message = handshake_reader.next_message()
            msg_type = message[0]

            if msg_type == FINISHED:
                expected = finished_verify_data(suite, server_hs_secret, bytes(transcript))
                if message[4:] != expected:
                    raise HandshakeError("server Finished did not verify")
                transcript += message
                break

            if msg_type == ENCRYPTED_EXTENSIONS:
                extensions = _Reader(_Reader(message[4:]).vector(2))
                while extensions.remaining:
                    ext_type = extensions.uint(2)
                    data = extensions.vector(2)
                    if ext_type == EXT_ALPN:
                        alpn = data[3:].decode("ascii", "replace")
            elif msg_type in (CERTIFICATE, COMPRESSED_CERTIFICATE):
                if verify:
                    body = message[4:]
                    if msg_type == COMPRESSED_CERTIFICATE:
                        body = certs.decompress_certificate(body)
                    leaf = certs.verify_chain(certs.parse_certificate(body),
                                              host, trust_store)
            elif msg_type == CERTIFICATE_VERIFY:
                if verify:
                    if leaf is None:
                        raise HandshakeError(
                            "CertificateVerify arrived before any certificate"
                        )
                    # Signed over the transcript as it stood before this
                    # message, which is why the check happens here and not
                    # after the append below.
                    body = _Reader(message[4:], "CertificateVerify")
                    certs.verify_signature(leaf, body.uint(2), body.vector(2),
                                           transcript_hash(suite, bytes(transcript)))
            else:
                raise HandshakeError("unexpected handshake message 0x%02x" % msg_type)

            transcript += message

        if verify and leaf is None:
            raise HandshakeError("the server sent no certificate")

        client_verify = finished_verify_data(suite, client_hs_secret, bytes(transcript))
        client_finished = u8(FINISHED) + u24(len(client_verify)) + client_verify

        records.write_cipher = Cipher(suite, client_hs_secret)
        records.write(HANDSHAKE, client_finished)

        client_app_secret, server_app_secret = schedule.application(bytes(transcript))
        records.read_cipher = Cipher(suite, server_app_secret)
        records.write_cipher = Cipher(suite, client_app_secret)

        return Connection(sock, records, suite, alpn)
    except Exception:
        sock.close()
        raise
