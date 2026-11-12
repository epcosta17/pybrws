"""TLS 1.3 client handshake.

By default the server's certificate chain is checked against the trust store
and its CertificateVerify signature is checked (see certs.py); verify=False
turns both checks off.
"""

from __future__ import annotations

import socket

from . import certs, hosts
from hmac import compare_digest

from .emitter import build_client_hello, retry_hello, with_psk
from . import tls12
from . import keyexchange
from .keyexchange import KeyExchange
from .keyschedule import (
    CIPHER_SUITES,
    KeySchedule,
    finished_verify_data,
    hkdf_expand_label,
    transcript_hash,
)
from .parser import _Reader
from .profiles import firefox157
from .tickets import parse_new_session_ticket, ticket_key
from .proxies import open_socket
from .records import (CHANGE_CIPHER_SPEC, APPLICATION_DATA, HANDSHAKE, Cipher,
                      RecordLayer, TlsAlert)
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
EXT_RENEGOTIATION_INFO = 0xFF01

MESSAGE_HASH = 0xFE

# RFC 8446 section 4.1.3: the last eight bytes of a TLS 1.3 server's random
# when it negotiates 1.2 (first) or 1.1 and below (second).
DOWNGRADE_SENTINELS = (b"DOWNGRD\x01", b"DOWNGRD\x00")

HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


class HandshakeError(Exception):
    pass


class TruncatedStream(EOFError):
    """The peer closed the TCP stream without a close_notify.

    Over TLS only an authenticated close_notify proves the stream ended where
    the peer meant it to. A bare FIN can be anyone on the path cutting the
    connection, so whatever was being read when it came may be cut short.
    An EOFError, so code that treats a closed connection as retryable still
    does.
    """


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
        if body.uint(1) != 0:
            raise HandshakeError("ServerHello compression method is not null "
                                 "(RFC 8446 4.1.3: illegal_parameter)")

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
            if ext_type in self.extensions:
                raise HandshakeError(
                    "extension %d appears twice in the ServerHello "
                    "(RFC 8446 4.2: illegal_parameter)" % ext_type)
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
           key_exchange: KeyExchange, suite, offered=None):
    """Answer a HelloRetryRequest.

    Returns the second ClientHello, the key exchange behind it, and the
    rewritten transcript: RFC 8446 section 4.4.1's synthetic message_hash for
    the first hello, then the HelloRetryRequest, then the second hello. The
    second hello used to be sent and left out, so every key derived after a
    retry was wrong and the handshake died on its first encrypted record.

    A retry may name a group, carry a cookie, or both. A cookie alone leaves
    the key shares as they were. `offered` is the ticket the first hello
    offered, if any: it is offered again with a binder over the new
    transcript when the server's suite can use it, and dropped otherwise.
    """
    group = hello.selected_group
    if group is None and hello.cookie is None:
        raise HandshakeError(
            "HelloRetryRequest named no group and carried no cookie, so there "
            "is nothing to change")
    if group is not None:
        if group in key_exchange.groups:
            # The server already had a share for it, so asking again means it
            # will ask forever.
            raise HandshakeError(
                "HelloRetryRequest asked for 0x%04x, which was already offered"
                % group)
        if not keyexchange.supported(group):
            raise HandshakeError(
                "HelloRetryRequest asked for 0x%04x, which this client cannot "
                "produce" % group)
        retry_exchange = KeyExchange([group])
        share = retry_exchange.public_share(group)
    else:
        retry_exchange, share = key_exchange, None

    # RFC 8446 section 4.4.1: the first ClientHello is replaced in the
    # transcript by a synthetic message carrying only its hash.
    digest = transcript_hash(suite, client_hello[5:])
    synthetic = u8(MESSAGE_HASH) + u24(len(digest)) + digest

    tickets = None
    if offered is not None and CIPHER_SUITES[offered.suite_id].digest == suite.digest:
        tickets = [offered]
    second = retry_hello(client_hello, group, share, hello.cookie,
                         binder_context=synthetic + raw_message,
                         tickets=tickets, suite=suite if tickets else None)
    return second, retry_exchange, bytearray(synthetic + raw_message + second[5:])


def _offered(client_hello: bytes) -> tuple[bytes, list[str]]:
    """The session id and the ALPN names this client's own hello offered."""
    from .parser import parse_client_hello

    hello = parse_client_hello(client_hello)
    names = []
    alpn = hello.extension(EXT_ALPN)
    if alpn is not None:
        reader = _Reader(_Reader(alpn.data).vector(2))
        while reader.remaining:
            names.append(reader.vector(1).decode("ascii", "replace"))
    return hello.session_id, names


# What may legally follow what in a TLS 1.3 server flight (RFC 8446 section
# 4): EncryptedExtensions first; on a full handshake an optional
# CertificateRequest, the certificate, CertificateVerify, then Finished; on a
# PSK handshake, nothing between EncryptedExtensions and Finished.
_FULL_FLIGHT = {
    ("start", ENCRYPTED_EXTENSIONS): "extensions",
    ("extensions", CERTIFICATE_REQUEST): "requested",
    ("extensions", CERTIFICATE): "certificate",
    ("extensions", COMPRESSED_CERTIFICATE): "certificate",
    ("requested", CERTIFICATE): "certificate",
    ("requested", COMPRESSED_CERTIFICATE): "certificate",
    ("certificate", CERTIFICATE_VERIFY): "verified",
    ("verified", FINISHED): "done",
}
_PSK_FLIGHT = {
    ("start", ENCRYPTED_EXTENSIONS): "extensions",
    ("extensions", FINISHED): "done",
}


def _check_server_hello_13(hello: "ServerHello", session_id: bytes) -> None:
    """The ServerHello and HelloRetryRequest rules RFC 8446 4.1.3 and 4.2
    lay down, which the transcript alone would not catch."""
    if hello.session_id_echo != session_id:
        raise HandshakeError("legacy_session_id_echo does not match the "
                             "session id sent (RFC 8446 4.1.3: illegal_parameter)")
    allowed = ({EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_COOKIE}
               if hello.is_hello_retry_request
               else {EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_PRE_SHARED_KEY})
    for ext_type in hello.extensions:
        if ext_type not in allowed:
            raise HandshakeError(
                "extension %d is not allowed in a TLS 1.3 %s (RFC 8446 4.2: "
                "unsupported_extension)" % (
                    ext_type, "HelloRetryRequest" if hello.is_hello_retry_request
                    else "ServerHello"))


def _alpn_from(hello) -> str:
    """The protocol a 1.2 server chose, which it puts in the ServerHello."""
    data = hello.extensions.get(16)
    if not data or len(data) < 3:
        return ""
    return data[3:].decode("ascii", "replace")


def _handshake_12(sock, records, hello, hello_message, transcript, host, *,
                  verify: bool, trust_store, reader=None):
    """Finish a TLS 1.2 handshake. RFC 5246, with RFC 4492 for ECDHE.

    Reached when the server answers with legacy version 0x0303 and no
    supported_versions extension, which is how a 1.2 server says so. The
    ClientHello was the same one either way: it offers both, as Firefox does.
    """
    suite = tls12.suite_for(hello.cipher_suite)
    records.legacy = True
    # The reader that delivered the ServerHello, not a new one: a server may
    # put its whole first flight in one record (RFC 5246 6.2.1), and the
    # bytes after the ServerHello are already in this reader's buffer. A new
    # reader dropped them and waited for the socket timeout.
    if reader is None:
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
        elif msg_type == tls12.HANDSHAKE_CERTIFICATE_STATUS:
            # Stapled OCSP, the answer to the status_request both profiles
            # send. Legal right after the Certificate. Not parsed or checked:
            # revocation is not something this client claims to enforce.
            if not chain:
                raise HandshakeError("CertificateStatus before the Certificate")
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
                 tickets=None, resumed: bool = False, ticket_key=None,
                 read_secret: bytes | None = None,
                 write_secret: bytes | None = None) -> None:
        self.sock = sock
        self.records = records
        self.suite = suite
        self.alpn = alpn
        self.host = host
        self.resumption_secret = resumption_secret
        self.tickets = tickets
        self.resumed = resumed
        # Where tickets this connection receives are kept: bound to this
        # server and to how it was checked (tickets.ticket_key).
        self.ticket_key = ticket_key if ticket_key is not None else host
        # The current TLS 1.3 application traffic secrets, which a KeyUpdate
        # ratchets. None on a TLS 1.2 connection, which has no KeyUpdate.
        self.read_secret = read_secret
        self.write_secret = write_secret
        # A post-handshake message may span records, like any handshake one.
        self._post_buffer = bytearray()
        self._closed = False

    def send(self, data: bytes) -> None:
        self.records.write(APPLICATION_DATA, data)

    def recv(self) -> bytes:
        """Return the next application payload, skipping post-handshake messages.

        Returns b"" only when the peer has sent close_notify, the clean end
        of the stream. An empty application record is legal and is skipped,
        not read as an end. A connection closed without close_notify raises
        TruncatedStream.
        """
        if self._closed:
            return b""
        while True:
            try:
                content_type, body = self.records.read()
            except TlsAlert as alert:
                if alert.description == 0:   # close_notify
                    self._closed = True
                    return b""
                raise
            except EOFError as exc:
                raise TruncatedStream(
                    "the peer closed the connection without close_notify; "
                    "anything being read may be truncated") from exc
            if content_type == APPLICATION_DATA:
                if not body:
                    continue
                return body
            if content_type == HANDSHAKE:
                self._post_handshake(body)
                continue
            raise HandshakeError("unexpected content type " + str(content_type))

    def _post_handshake(self, body: bytes) -> None:
        """Handle the messages that arrive after the handshake: tickets, and
        key updates. A message may arrive split across several records, so
        what is left over waits for the next one."""
        self._post_buffer += body
        while len(self._post_buffer) >= 4:
            length = int.from_bytes(self._post_buffer[1:4], "big")
            if len(self._post_buffer) < 4 + length:
                return
            msg_type = self._post_buffer[0]
            message = bytes(self._post_buffer[4:4 + length])
            del self._post_buffer[:4 + length]
            if msg_type == KEY_UPDATE:
                if self._post_buffer:
                    # The key changes after this message, so nothing that
                    # came with it under the old key can be read as new.
                    raise HandshakeError(
                        "a handshake message spans the key change "
                        "(RFC 8446 5.1: unexpected_message)")
                self._key_update(message)
            elif msg_type == NEW_SESSION_TICKET:
                self._ticket(message)

    def _ticket(self, message: bytes) -> None:
        if self.tickets is None or self.resumption_secret is None:
            return
        try:
            ticket = parse_new_session_ticket(message, self.suite,
                                              self.resumption_secret)
        except ValueError:
            return
        self.tickets.add(self.ticket_key, ticket)

    def _key_update(self, message: bytes) -> None:
        """RFC 8446 section 4.6.3.

        The peer has switched to its next key, so this side's read key moves
        with it, or the next record fails authentication. When the peer asks
        (update_requested), this side answers with a KeyUpdate of its own,
        under the old key, and then moves its write key too.
        """
        if self.read_secret is None:
            raise HandshakeError("KeyUpdate on a connection that has no "
                                 "TLS 1.3 traffic secrets")
        if len(message) != 1 or message[0] not in (0, 1):
            raise HandshakeError("KeyUpdate request_update must be 0 or 1 "
                                 "(RFC 8446 4.6.3: illegal_parameter)")
        self.read_secret = self._next_secret(self.read_secret)
        self.records.read_cipher = Cipher(self.suite, self.read_secret)
        if message[0] == 1:
            self.records.write(HANDSHAKE, u8(KEY_UPDATE) + u24(1) + u8(0))
            self.write_secret = self._next_secret(self.write_secret)
            self.records.write_cipher = Cipher(self.suite, self.write_secret)

    def _next_secret(self, secret: bytes) -> bytes:
        return hkdf_expand_label(self.suite, secret, b"traffic upd", b"",
                                 self.suite.hash_size)

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
        trust_store: the roots the chain must lead to, a
            `cryptography.x509.verification.Store`. None means
            `certs.default_store()`: Mozilla's roots plus the platform's.
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
    # One ASCII form for SNI, DNS and certificate checks alike (hosts.py).
    host = hosts.ascii_host(host)
    key_exchange = KeyExchange([group for group, _ in profile.KEY_SHARE_GROUPS])
    client_hello = build_client_hello(host, profile=profile, key_exchange=key_exchange)

    key = ticket_key(host, port, verify, trust_store)
    offered = tickets.take(key) if tickets is not None else None
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
        sent_session_id, offered_alpn = _offered(client_hello)

        message = handshake_reader.next_message()
        hello = ServerHello(message)
        if hello.is_hello_retry_request:
            _check_server_hello_13(hello, sent_session_id)
            retry_suite = suite_for(hello)
            client_hello, key_exchange, transcript = _retry(
                client_hello, hello, message, key_exchange, retry_suite,
                offered=offered,
            )
            if (offered is not None
                    and CIPHER_SUITES[offered.suite_id].digest != retry_suite.digest):
                # Dropped from the second hello: the server's suite cannot use it.
                offered = None
            records.write(HANDSHAKE, client_hello[5:])
            message = handshake_reader.next_message()
            hello = ServerHello(message)
            if hello.is_hello_retry_request:
                raise HandshakeError("the server sent a second "
                                     "HelloRetryRequest, which RFC 8446 forbids")
        if hello.selected_version is None and hello.legacy_version == 0x0303:
            if hello.random[24:] in DOWNGRADE_SENTINELS:
                # A TLS 1.3 server answering 1.2 marks its random this way,
                # so a 1.2 answer carrying the mark means something in the
                # path stripped the client's 1.3 offer.
                raise HandshakeError(
                    "ServerHello.random carries the TLS 1.3 downgrade "
                    "sentinel (RFC 8446 4.1.3: illegal_parameter)")
            renegotiation = hello.extensions.get(EXT_RENEGOTIATION_INFO)
            if renegotiation is not None and renegotiation != b"\x00":
                # On an initial handshake the renegotiated_connection field
                # is empty; anything else is an attack on the renegotiation
                # binding or a broken server.
                raise HandshakeError(
                    "renegotiation_info is not empty on an initial handshake "
                    "(RFC 5746 3.4: handshake_failure)")
            chosen = _alpn_from(hello)
            if chosen and chosen not in offered_alpn:
                raise HandshakeError(
                    "the server chose ALPN %r, which was not offered "
                    "(RFC 7301: illegal_parameter)" % chosen)
            return _handshake_12(sock, records, hello, message,
                                 bytearray(client_hello[5:]), host,
                                 verify=verify, trust_store=trust_store,
                                 reader=handshake_reader)
        if hello.selected_version != 0x0304:
            raise HandshakeError(
                "server did not select TLS 1.3 (got %r, legacy %r)"
                % (hello.selected_version, hello.legacy_version)
            )
        _check_server_hello_13(hello, sent_session_id)
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
        if handshake_reader.buffer:
            # Bytes that came in the ServerHello's plaintext record but belong
            # after it would be read as if they had been encrypted.
            raise HandshakeError(
                "a handshake message spans the key change "
                "(RFC 8446 5.1: unexpected_message)")
        records.read_cipher = Cipher(suite, server_hs_secret)
        records.encrypted_only = True

        alpn = ""
        leaf = None
        cert_verified = False
        certificate_request_context: bytes | None = None
        flight = _PSK_FLIGHT if resumed else _FULL_FLIGHT
        stage = "start"
        while True:
            message = handshake_reader.next_message()
            msg_type = message[0]

            following = flight.get((stage, msg_type))
            if following is None:
                if msg_type == FINISHED and not resumed:
                    raise HandshakeError(
                        "the server sent no CertificateVerify before its "
                        "Finished (RFC 8446 4.4: unexpected_message)")
                raise HandshakeError(
                    "handshake message 0x%02x out of order after %s "
                    "(RFC 8446 4: unexpected_message)" % (msg_type, stage))
            stage = following

            if msg_type == FINISHED:
                expected = finished_verify_data(suite, server_hs_secret, bytes(transcript))
                if message[4:] != expected:
                    raise HandshakeError("server Finished did not verify")
                transcript += message
                records.handshake_done = True
                break

            if msg_type == ENCRYPTED_EXTENSIONS:
                extensions = _Reader(_Reader(message[4:]).vector(2))
                while extensions.remaining:
                    ext_type = extensions.uint(2)
                    data = extensions.vector(2)
                    if ext_type == EXT_ALPN:
                        alpn = data[3:].decode("ascii", "replace")
                        if alpn not in offered_alpn:
                            raise HandshakeError(
                                "the server chose ALPN %r, which was not "
                                "offered (RFC 7301: illegal_parameter)" % alpn)
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
                    cert_verified = True
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

        if verify and not resumed:
            # A full (non-resumed) TLS 1.3 server authenticates with a
            # Certificate *and* a CertificateVerify. The server Finished is
            # keyed from the ECDHE secret, which an active middlebox shares
            # with us, so it is not what ties the handshake to the
            # certificate -- CertificateVerify is. Accepting a handshake that
            # carried a chain but no CertificateVerify lets an attacker replay
            # the real site's public chain, which it does not hold the key
            # for, and omit the one message it cannot forge.
            if leaf is None:
                raise HandshakeError("the server sent no certificate")
            if not cert_verified:
                raise HandshakeError(
                    "the server sent no CertificateVerify, so nothing proves "
                    "it holds the certificate's private key"
                )

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
                          resumed=resumed, ticket_key=key,
                          read_secret=server_app_secret,
                          write_secret=client_app_secret)
    except Exception:
        sock.close()
        raise
