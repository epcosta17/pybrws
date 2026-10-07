"""TLS 1.3 client handshake.

Certificates are accepted without verification. See the note in README.
"""

from __future__ import annotations

import socket

from . import certs
from hmac import compare_digest

from .emitter import build_client_hello, retry_hello, with_psk
from . import tls12
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
from .tickets import parse_new_session_ticket
from .proxies import open_socket
from .records import CHANGE_CIPHER_SPEC, APPLICATION_DATA, HANDSHAKE, Cipher, RecordLayer
from .wire import u24, u8, vector

SERVER_HELLO = 0x02
NEW_SESSION_TICKET = 0x04
ENCRYPTED_EXTENSIONS = 0x08
CERTIFICATE = 0x0B
CERTIFICATE_REQUEST = 0x0D
CERTIFICATE_VERIFY = 0x0F
FINISHED = 0x14
KEY_UPDATE = 0x18
COMPRESSED_CERTIFICATE = 0x19  # RFC 8879, sent because we offer compress_certificate

EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_ALPN = 16
EXT_COOKIE = 44
EXT_PRE_SHARED_KEY = 41

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

        # Kept rather than discarded: with no supported_versions extension
        # this is the negotiated version, which is how a 1.2 server answers.
        self.legacy_version = body.uint(2)
        self.random = body.read(32)
        self.session_id_echo = body.vector(1)
        self.cipher_suite = body.uint(2)
        body.uint(1)  # legacy_compression_method

        self.selected_version: int | None = None
        self.selected_group: int | None = None
        self.peer_key_share: bytes = b""
        self.cookie: bytes | None = None
        self.selected_psk: int | None = None

        # Kept whole: over TLS 1.2 the ServerHello is where ALPN and
        # extended_master_secret arrive, there being no EncryptedExtensions.
        self.extensions: dict[int, bytes] = {}
        extensions = _Reader(body.vector(2), "ServerHello extensions")
        while extensions.remaining:
            ext_type = extensions.uint(2)
            data = extensions.vector(2)
            self.extensions[ext_type] = data
            if ext_type == EXT_SUPPORTED_VERSIONS:
                self.selected_version = int.from_bytes(data[:2], "big")
            elif ext_type == EXT_KEY_SHARE:
                self.selected_group = int.from_bytes(data[:2], "big")
                # A HelloRetryRequest names a group and sends no key with it.
                self.peer_key_share = data[4:] if len(data) > 2 else b""
            elif ext_type == EXT_COOKIE:
                self.cookie = data
            elif ext_type == EXT_PRE_SHARED_KEY:
                self.selected_psk = int.from_bytes(data[:2], "big")

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


def _alpn_from(hello) -> str:
    """The protocol a 1.2 server chose, which it puts in the ServerHello."""
    data = hello.extensions.get(16)
    if not data or len(data) < 3:
        return ""
    return data[3:].decode("ascii", "replace")


def _handshake_12(sock, records, hello, hello_message, transcript, host, *,
                  verify: bool, trust_store):
    """Finish a TLS 1.2 handshake. RFC 5246, with RFC 4492 for ECDHE.

    Reached when the server answers with legacy version 0x0303 and no
    supported_versions extension, which is how a 1.2 server says so. The
    ClientHello was the same one either way: it offers both, as Firefox does.
    """
    suite = tls12.suite_for(hello.cipher_suite)
    records.legacy = True
    reader = _HandshakeReader(records)
    transcript += hello_message

    chain: list[bytes] = []
    exchange = None
    certificate_requested = False

    while True:
        message = reader.next_message()
        msg_type, body = message[0], message[4:]
        transcript += message
        if msg_type == tls12.HANDSHAKE_CERTIFICATE:
            chain = tls12.parse_certificate(body)
        elif msg_type == tls12.HANDSHAKE_SERVER_KEY_EXCHANGE:
            exchange = tls12.parse_server_key_exchange(body)
        elif msg_type == tls12.HANDSHAKE_CERTIFICATE_REQUEST:
            # Answered with an empty Certificate, the way a browser with no
            # client certificate does. Asking is itself a bot check: the
            # server does not need one, it wants to see what happens.
            certificate_requested = True
        elif msg_type == tls12.HANDSHAKE_SERVER_HELLO_DONE:
            break
        else:
            raise HandshakeError(
                "unexpected TLS 1.2 handshake message 0x%02x" % msg_type)

    if exchange is None:
        raise HandshakeError(
            "the server sent no ServerKeyExchange, so it chose a suite with "
            "no forward secrecy; only ECDHE is implemented"
        )
    if not chain:
        raise HandshakeError("the server sent no certificate")

    leaf = certs.verify_chain(chain, host, trust_store) if verify else None
    if leaf is None:
        from cryptography import x509

        leaf = x509.load_der_x509_certificate(chain[0])
    # The client random sits at a fixed offset in the hello: the
    # four-byte handshake header, two bytes of legacy version, then 32
    # bytes. Reading it back out of the transcript beats threading it
    # through every call that needs it.
    client_random = bytes(transcript[6:38])
    tls12.verify_key_exchange(leaf, exchange, client_random, hello.random)

    # The group comes from the server, so the key is generated now rather
    # than reused from the hello's key_share: a 1.2 server may name a curve
    # the key_share never offered a point for.
    ephemeral = KeyExchange([exchange.group])
    pre_master = ephemeral.shared_secret(exchange.group, exchange.peer_point)

    outbound = b""
    if certificate_requested:
        body = tls12.empty_certificate()
        outbound += u8(tls12.HANDSHAKE_CERTIFICATE) + u24(len(body)) + body
    body = tls12.client_key_exchange(ephemeral.public_share(exchange.group))
    outbound += u8(tls12.HANDSHAKE_CLIENT_KEY_EXCHANGE) + u24(len(body)) + body
    # Sent before the transcript is hashed for anything, and before the
    # cipher changes: these messages travel in the clear.
    records.write(HANDSHAKE, outbound)
    transcript += outbound

    if tls12.EXT_EXTENDED_MASTER_SECRET in hello.extensions:
        # RFC 7627. Firefox asks for it, so a server that echoes it derives
        # this way and anything else fails Finished with bad_record_mac.
        master = tls12.extended_master_secret(
            suite, pre_master, tls12.handshake_hash(suite, bytes(transcript)))
    else:
        master = tls12.master_secret(suite, pre_master, client_random,
                                     hello.random)

    client_key, server_key, client_iv, server_iv = tls12.key_block(
        suite, master, client_random, hello.random)

    verify_data = tls12.finished_verify_data(
        suite, master, b"client finished",
        tls12.handshake_hash(suite, bytes(transcript)))
    client_finished = (u8(tls12.HANDSHAKE_FINISHED) + u24(len(verify_data))
                       + verify_data)

    records.write(CHANGE_CIPHER_SPEC, b"\x01")
    records.write_cipher = tls12.Cipher(suite, client_key, client_iv)
    records.write(HANDSHAKE, client_finished)
    transcript += client_finished

    # A NewSessionTicket may come first, and it counts towards the server's
    # Finished, so it goes in the transcript rather than being skipped.
    # RFC 5077 with RFC 5246 section 7.4.9: the verify_data covers every
    # handshake message before the Finished itself.
    while True:
        content_type, body = records.read()
        if content_type == CHANGE_CIPHER_SPEC:
            break
        if content_type != HANDSHAKE:
            raise HandshakeError(
                "expected ChangeCipherSpec, got content type %d" % content_type)
        transcript += body
    records.read_cipher = tls12.Cipher(suite, server_key, server_iv)

    content_type, body = records.read()
    if content_type != HANDSHAKE or not body or body[0] != tls12.HANDSHAKE_FINISHED:
        raise HandshakeError("expected the server's Finished")
    expected = tls12.finished_verify_data(
        suite, master, b"server finished",
        tls12.handshake_hash(suite, bytes(transcript)))
    if not compare_digest(body[4:], expected):
        raise HandshakeError(
            "the server's Finished does not match the transcript, so the "
            "handshake was tampered with or one side derived differently"
        )

    return Connection(sock, records, suite, _alpn_from(hello), host=host)


class Connection:
    """An established TLS connection, 1.3 or 1.2."""

    def __init__(self, sock: socket.socket, records: RecordLayer, suite, alpn: str,
                 host: str = "", resumption_secret: bytes | None = None,
                 tickets=None, resumed: bool = False) -> None:
        self.sock = sock
        self.records = records
        self.suite = suite
        self.alpn = alpn
        self.host = host
        self.resumption_secret = resumption_secret
        self.tickets = tickets
        self.resumed = resumed

    def send(self, data: bytes) -> None:
        self.records.write(APPLICATION_DATA, data)

    def recv(self) -> bytes:
        """Return the next application payload, skipping post-handshake messages."""
        while True:
            content_type, body = self.records.read()
            if content_type == APPLICATION_DATA:
                return body
            if content_type == HANDSHAKE:
                self._post_handshake(body)
                continue
            raise HandshakeError("unexpected content type " + str(content_type))

    def _post_handshake(self, body: bytes) -> None:
        """Collect NewSessionTicket messages, which arrive after the handshake."""
        if self.tickets is None or self.resumption_secret is None:
            return
        reader = _Reader(body, "post-handshake")
        while reader.remaining >= 4:
            msg_type = reader.uint(1)
            message = reader.vector(3)
            if msg_type != NEW_SESSION_TICKET:
                continue
            try:
                ticket = parse_new_session_ticket(message, self.suite,
                                                  self.resumption_secret)
            except ValueError:
                continue
            self.tickets.add(self.host, ticket)

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
    tickets=None,
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
            tickets: a TicketStore. One is offered if it holds a ticket for
            this host, and any the server issues are kept, so a second
            connection resumes rather than starting over.

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

    offered = tickets.take(host) if tickets is not None else None
    if offered is not None:
        # The binder is keyed by the hash of the suite the ticket came from,
        # so a server choosing another suite simply will not select it.
        client_hello = with_psk(client_hello, [offered],
                                CIPHER_SUITES[offered.suite_id],
                                profile=profile)

    sock = open_socket(host, port, proxy=proxy, timeout=timeout)
    records = RecordLayer(sock)
    try:
        sock.sendall(client_hello)

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
        if hello.selected_version is None and hello.legacy_version == 0x0303:
            return _handshake_12(sock, records, hello, message,
                                 bytearray(client_hello[5:]), host,
                                 verify=verify, trust_store=trust_store)
        if hello.selected_version != 0x0304:
            raise HandshakeError(
                "server did not select TLS 1.3 (got %r, legacy %r)"
                % (hello.selected_version, hello.legacy_version)
            )
        suite = suite_for(hello)
        transcript += message

        resumed = offered is not None and hello.selected_psk == 0
        if offered is not None and not resumed:
            # Offered and declined. Not an error, but worth not pretending.
            offered = None

        shared_secret = key_exchange.shared_secret(
            hello.selected_group, hello.peer_key_share
        )
        schedule = KeySchedule(suite, psk=offered.psk if resumed else None)
        client_hs_secret, server_hs_secret = schedule.handshake(
            shared_secret, bytes(transcript)
        )
        records.read_cipher = Cipher(suite, server_hs_secret)

        alpn = ""
        leaf = None
        certificate_request_context: bytes | None = None
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
            elif msg_type == CERTIFICATE_REQUEST:
                # The server wants a client certificate. We have none, and a
                # browser in the same position does not fail: it answers with
                # an empty Certificate and no CertificateVerify, RFC 8446
                # section 4.4.2. The context has to be echoed back.
                #
                # Asking is itself a bot check -- the server does not need the
                # certificate, it wants to see what an unexpected message does
                # to the client. Until this existed, ulta.com was unreachable.
                certificate_request_context = _Reader(
                    message[4:], "CertificateRequest").vector(1)
            else:
                raise HandshakeError("unexpected handshake message 0x%02x" % msg_type)

            transcript += message

        if verify and leaf is None and not resumed:
            raise HandshakeError("the server sent no certificate")

        # RFC 8446 section 7.1: the application traffic secrets are derived
        # from the transcript up to and including the *server's* Finished, so
        # the snapshot has to be taken before anything of ours is appended.
        # Getting this wrong gives a handshake that completes and application
        # keys the peer does not share, which shows up as InvalidTag on the
        # first record and says nothing about the cause.
        through_server_finished = bytes(transcript)

        client_flight = b""
        if certificate_request_context is not None:
            body = vector(certificate_request_context, 1) + vector(b"", 3)
            client_flight = u8(CERTIFICATE) + u24(len(body)) + body
            transcript += client_flight

        client_verify = finished_verify_data(suite, client_hs_secret, bytes(transcript))
        client_finished = client_flight + u8(FINISHED) + u24(len(client_verify)) + client_verify

        # Middlebox compatibility, RFC 8446 appendix D.4: a dummy
        # ChangeCipherSpec immediately before the second flight. It used to go
        # out right after the ClientHello, which every TLS 1.3 server
        # tolerated -- and which a TLS 1.2 server answers with
        # handshake_failure, since a ChangeCipherSpec before the
        # ClientKeyExchange is a protocol violation there. The bug was
        # invisible for as long as 1.2 was unreachable.
        records.write(CHANGE_CIPHER_SPEC, b"\x01")
        records.write_cipher = Cipher(suite, client_hs_secret)
        records.write(HANDSHAKE, client_finished)

        client_app_secret, server_app_secret = schedule.application(
            through_server_finished)
        # Only the Finished: any Certificate ahead of it went in already,
        # before the verify_data was computed over it.
        transcript += client_finished[len(client_flight):]
        resumption_secret = schedule.resumption(bytes(transcript))

        records.read_cipher = Cipher(suite, server_app_secret)
        records.write_cipher = Cipher(suite, client_app_secret)

        return Connection(sock, records, suite, alpn, host=host,
                          resumption_secret=resumption_secret, tickets=tickets,
                          resumed=resumed)
    except Exception:
        sock.close()
        raise
