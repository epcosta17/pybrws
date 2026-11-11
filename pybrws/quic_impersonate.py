"""Make aioquic send the ClientHello a profile describes.

aioquic is a fine QUIC transport and an unconvincing browser. Its hello
carries seven extensions in a hardcoded order, three key shares' worth of
nothing like Firefox's 1327 bytes, and transport parameters sorted by id,
which no browser does. None of that is aioquic's fault; it is not trying to
impersonate anything.

Three seams are patched, all of them narrow and all of them named here so a
reader knows what is load bearing.

**`push_client_hello`** writes the message. aioquic calls it inside
`with push_message(key_schedule, output_buf):`, and that context manager
hashes whatever ended up in the buffer, so replacing the writer keeps the
transcript correct with nothing further to do. This is the seam that makes
the whole approach cheap.

**`Context._client_send_hello`** is wrapped only to get hold of the
connection: the writer is handed a buffer and a hello, not the Context, and
per-connection state has to live somewhere.

**The key exchange.** This is the awkward one. Firefox offers
X25519MLKEM768, a 1216-byte post-quantum share that makes up two thirds of
its hello, and aioquic's `Group` enum does not have it -- an unknown group is
silently skipped, so there is no configuration that produces one. We have our
own implementation in `keyexchange.py`, verified against real servers on TCP,
so the shares written here are ours for all three groups and aioquic's own
private keys go unused. That means the shared secret has to come from us too,
whichever group the server picks.

aioquic computes it as `self._x25519_private_key.exchange(peer_public_key)`
after `decode_public_key` turns the server's share into a key object. So
`decode_public_key` is patched to keep the raw share and hand back a dummy
whose type satisfies the `isinstance` check, and `_x25519_private_key` is
replaced by an object whose `exchange` ignores its argument and returns the
real secret. It is a stub standing in a hole of exactly the right shape, and
it is the least invasive thing that works: the alternative is copying
`_client_handle_hello` into this file, where it would go stale in silence.

**`Context._handle_reassembled_message`**, for compressed certificates. This
seam was not planned: it appeared because the impersonation worked. Firefox
advertises `compress_certificate`, so the profile does, so Cloudflare took us
at our word and sent an RFC 8879 CompressedCertificate -- handshake message
type 25, which aioquic answers with `unexpected_message` because it has never
heard of it. We already decompress those in `certs.py` for the TCP client.

The care needed is in the transcript. RFC 8879 section 5 puts the *compressed*
message in the handshake hash, so decompressing and handing the result to
aioquic's certificate handler would hash the wrong bytes and fail the Finished
check with no hint as to why. The interception therefore hashes the compressed
message itself and calls the parsing half directly.

**`QuicConnection.__init__`**, for the connection ids. Firefox's source id is
three bytes and its initial destination id must be at least eight, because
RFC 9000 section 7.2 says so and the Initial keys are derived from it. aioquic
has one setting for both lengths, so matching Firefox's source id made the
destination id three bytes too -- a protocol violation that Cloudflare
tolerated and Google answered by dropping every Initial packet in silence.
The two are separated here.

The stub is also where this will break first if aioquic changes, so there is
a test that asserts the seams still exist rather than only that the result
looks right.

**Scope.** The patches are process-wide, but they act only on connections
whose configuration came from `configuration()`, which marks it with the
profile to imitate. Any other aioquic connection in the process -- a DNS
over QUIC client, a test server -- gets aioquic's own behaviour. The state a
hello needs lives on its QuicConnection, handed to each tls.Context that
**`QuicConnection._initialize`** creates (a Retry makes a second one), and
the little that must cross
from a method to a module function (the writer, `decode_public_key`) goes
through context variables, so threads and tasks do not see each other's.
"""

from __future__ import annotations

import contextvars
import os
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import x25519

from .certs import CertificateError, decompress_certificate
from .keyexchange import KeyExchange
from .profiles import firefox157_quic
from .quic import parse_transport_parameters
from .wire import extension, u8, u16, u24, vector

TLS_VERSION_1_2 = 0x0303
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_CERTIFICATE = 0x0B
HANDSHAKE_COMPRESSED_CERTIFICATE = 0x19   # RFC 8879
PARAMETER_SOURCE_CONNECTION_ID = 0x0F


class NotInstalled(Exception):
    pass


class _Connection:
    """Per-connection state the patched functions share."""

    __slots__ = ("kex", "server_share", "profile", "rng", "hello")

    def __init__(self, profile, rng) -> None:
        self.profile = profile
        self.rng = rng
        self.kex = KeyExchange(list(group for group, _ in profile.KEY_SHARE_GROUPS))
        self.server_share: tuple[int, bytes] | None = None
        # The ClientHello as first sent. RFC 9000 17.2.5.3: after a Retry "a
        # client MUST use the same cryptographic handshake message", and
        # aioquic rebuilds it from scratch -- new random, new draw, new grease.
        self.hello: bytes | None = None


# The connection whose hello is being written, set for the duration of one
# _client_send_hello call; and the one whose ServerHello is being read, for
# one _client_handle_hello call. Context variables, not module globals: each
# thread and each task sees its own, so concurrent handshakes do not collide.
_current: contextvars.ContextVar[_Connection | None] = contextvars.ContextVar(
    "pybrws_quic_hello", default=None)
_decoding: contextvars.ContextVar[_Connection | None] = contextvars.ContextVar(
    "pybrws_quic_decoding", default=None)

# The source of random bytes for connection ids and greased values; install()
# sets it.
_rng: Callable[[int], bytes] = os.urandom

_DUMMY_PUBLIC_KEY = x25519.X25519PrivateKey.generate().public_key()


class _StubExchange:
    """Stands where aioquic expects an X25519 private key.

    Its one job is to answer `exchange`, which aioquic calls with the server's
    public key. The real derivation needs the group as well as the share, and
    the group is not in the argument, so it comes from the connection state
    that `decode_public_key` filled in a moment earlier.
    """

    __slots__ = ("_connection",)

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def exchange(self, _peer_public_key) -> bytes:
        if self._connection.server_share is None:
            raise NotInstalled("the server's key_share was never recorded; "
                               "decode_public_key is not patched")
        group, share = self._connection.server_share
        return self._connection.kex.shared_secret(group, share)


def _key_share(connection: _Connection) -> bytes:
    entries = b""
    for group, size in connection.profile.KEY_SHARE_GROUPS:
        share = connection.kex.public_share(group)
        if len(share) != size:
            raise ValueError(
                "key_share for 0x%04x: expected %d bytes, got %d"
                % (group, size, len(share))
            )
        entries += u16(group) + vector(share, 2)
    return vector(entries, 2)


def _transport_parameters(connection: _Connection, hello) -> bytes:
    """The profile's parameters, carrying this connection's own source id.

    aioquic puts its own in `other_extensions`, and one value in there is not
    the profile's to choose: `initial_source_connection_id` has to be the id
    actually in use or the peer rejects the handshake.
    """
    kind = connection.profile.EXT_QUIC_TRANSPORT_PARAMETERS
    for extension_type, payload in hello.other_extensions:
        if extension_type == kind:
            own = dict(parse_transport_parameters(payload))
            source = own.get(PARAMETER_SOURCE_CONNECTION_ID)
            if source is None:
                raise NotInstalled(
                    "aioquic's transport parameters carry no "
                    "initial_source_connection_id to copy"
                )
            return connection.profile.transport_parameters(source)
    raise NotInstalled("aioquic sent no quic_transport_parameters extension")


def _payload(connection: _Connection, kind: int, hello) -> bytes:
    profile = connection.profile
    if kind in profile.STATIC_PAYLOADS:
        return profile.STATIC_PAYLOADS[kind]
    if kind == profile.EXT_SERVER_NAME:
        return profile.server_name(hello.server_name)
    if kind == profile.EXT_KEY_SHARE:
        return _key_share(connection)
    if kind == profile.EXT_QUIC_TRANSPORT_PARAMETERS:
        return _transport_parameters(connection, hello)
    if kind == profile.EXT_ENCRYPTED_CLIENT_HELLO:
        return profile.greased_ech(connection.rng)
    raise NotInstalled("no payload for extension %d" % kind)


def build_hello(connection: _Connection, hello) -> bytes:
    """Serialise one ClientHello in the profile's shape.

    `hello` is aioquic's, and three things are taken from it rather than from
    the profile: the random and the server name, because the handshake and the
    caller own those, and the transport parameters' source connection id.
    """
    profile = connection.profile
    body = (
        u16(TLS_VERSION_1_2)
        + hello.random
        + vector(bytes(profile.SESSION_ID_SIZE), 1)
        + vector(b"".join(u16(suite) for suite in profile.CIPHER_SUITES), 2)
        + vector(bytes(profile.LEGACY_COMPRESSION_METHODS), 1)
    )
    # A payload of None leaves the extension out: server_name for an IP
    # literal, which aioquic still verifies the certificate against.
    payloads = ((kind, _payload(connection, kind, hello))
                for kind in profile.extension_order(connection.rng))
    extensions = b"".join(extension(kind, data) for kind, data in payloads
                          if data is not None)
    body += vector(extensions, 2)
    return u8(HANDSHAKE_CLIENT_HELLO) + u24(len(body)) + body


def _buffer_over(data: bytes):
    """A Buffer aioquic's parsers can read, over bytes we built."""
    from aioquic.buffer import Buffer

    return Buffer(data=data)


_originals: dict[str, object] = {}


def install(profile=None, rng: Callable[[int], bytes] = os.urandom) -> None:
    """Patch aioquic in place, once; a later call only replaces `rng`.

    The patches act on connections made from `configuration()` alone, each
    with the profile its configuration names. `profile` is accepted for
    compatibility and ignored: the profile is chosen per connection, by
    `configuration(profile=...)`.

    Raises:
        NotInstalled: if aioquic does not look the way this module expects,
            which is better than patching something that has moved and
            finding out from a handshake failure.
    """
    import aioquic.tls as tls

    global _rng
    _rng = rng
    if _originals:
        return

    for name in ("push_client_hello", "decode_public_key", "pull_certificate"):
        if not hasattr(tls, name):
            raise NotInstalled("aioquic.tls has no %s; the seams have moved"
                               % name)
    if not hasattr(tls.Context, "_client_send_hello"):
        raise NotInstalled("aioquic.tls.Context has no _client_send_hello")
    if not hasattr(tls.Context, "_client_handle_hello"):
        raise NotInstalled("aioquic.tls.Context has no _client_handle_hello")
    if not hasattr(tls.Context, "_handle_reassembled_message"):
        raise NotInstalled(
            "aioquic.tls.Context has no _handle_reassembled_message")
    for name in ("_set_peer_certificate", "_set_state"):
        if not hasattr(tls.Context, name):
            raise NotInstalled("aioquic.tls.Context has no %s" % name)

    from aioquic.quic.connection import QuicConnection

    for name in ("_peer_cid", "_original_destination_connection_id",
                 "_configuration", "_is_client"):
        # Set in __init__, so the check is against an instance's slots rather
        # than the class.
        if name not in QuicConnection.__init__.__code__.co_names:
            raise NotInstalled("aioquic's QuicConnection no longer sets %s"
                               % name)
    if not hasattr(QuicConnection, "_initialize"):
        raise NotInstalled("aioquic's QuicConnection has no _initialize")
    if "tls" not in QuicConnection._initialize.__code__.co_names:
        raise NotInstalled("aioquic's QuicConnection._initialize no longer "
                           "creates self.tls")
    _originals["QuicConnection.__init__"] = QuicConnection.__init__
    _originals["QuicConnection._initialize"] = QuicConnection._initialize

    _originals["push_client_hello"] = tls.push_client_hello
    _originals["decode_public_key"] = tls.decode_public_key
    _originals["_client_send_hello"] = tls.Context._client_send_hello
    _originals["_client_handle_hello"] = tls.Context._client_handle_hello
    _originals["_handle_reassembled_message"] = (
        tls.Context._handle_reassembled_message)

    def push_client_hello(buf, hello) -> None:
        connection = _current.get()
        if connection is None:
            # Not a connection we set up: leave aioquic's own behaviour
            # alone rather than guessing.
            _originals["push_client_hello"](buf, hello)
            return
        if connection.hello is None:
            connection.hello = build_hello(connection, hello)
        buf.push_bytes(connection.hello)

    # The wrappers take *args: their job is to bracket a call, not to know
    # its signature, and getting that wrong cost a handshake to find out.
    def client_send_hello(self, *args, **kwargs):
        connection = getattr(self, "_pybrws_connection", None)
        if connection is None:
            return _originals["_client_send_hello"](self, *args, **kwargs)
        if _current.get() is not None:
            raise NotInstalled("a hello is being built inside another one")
        if connection.hello is not None:
            # A rebuild after a Retry: the bytes sent will be the first
            # hello's, so this Context's random is made to match them.
            # (type 1, length 3, version 2, then the 32-byte random)
            self.client_random = connection.hello[6:38]
        token = _current.set(connection)
        try:
            return _originals["_client_send_hello"](self, *args, **kwargs)
        finally:
            _current.reset(token)

    # decode_public_key is a module function with no access to the Context,
    # so the connection is handed to it the same way the writer gets one:
    # set for the duration of a single _client_handle_hello call.
    def decode_public_key(key_share):
        connection = _decoding.get()
        if connection is not None:
            connection.server_share = (key_share[0], bytes(key_share[1]))
            return _DUMMY_PUBLIC_KEY
        return _originals["decode_public_key"](key_share)

    def client_handle_hello(self, *args, **kwargs):
        connection = getattr(self, "_pybrws_connection", None)
        if connection is None:
            return _originals["_client_handle_hello"](self, *args, **kwargs)
        self._x25519_private_key = _StubExchange(connection)
        token = _decoding.set(connection)
        try:
            return _originals["_client_handle_hello"](self, *args, **kwargs)
        finally:
            _decoding.reset(token)

    def handle_reassembled_message(self, message_type, input_buf, *args,
                                   **kwargs):
        if (message_type != HANDSHAKE_COMPRESSED_CERTIFICATE
                or getattr(self, "_pybrws_connection", None) is None):
            return _originals["_handle_reassembled_message"](
                self, message_type, input_buf, *args, **kwargs)

        # A CompressedCertificate stands for a Certificate, so it is taken
        # only where aioquic's own dispatcher would take one. Anywhere else
        # -- before the ServerHello, after the handshake -- it is what
        # aioquic answers any misplaced message with.
        if self.state not in (
                tls.State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE,
                tls.State.CLIENT_EXPECT_CERTIFICATE):
            raise tls.AlertUnexpectedMessage

        # Every failure below is an alert: aioquic turns an Alert into a
        # connection close and lets anything else escape into the event
        # loop, where the caller waits for a handshake that will never end.
        # The whole message, header included, which is what the transcript
        # takes. RFC 8879 section 5: the compressed message is hashed, not the
        # certificate it expands to.
        compressed = bytes(input_buf.data_slice(0, input_buf.capacity))
        try:
            body = decompress_certificate(compressed[4:])
        except CertificateError as exc:
            # RFC 8879 section 4: cannot be decompressed, or not to the
            # length it announced. Decompression is bounded by that length.
            raise tls.AlertBadCertificate(str(exc)) from exc
        except ValueError as exc:
            # Its own lengths do not add up (RFC 8446 6.2).
            raise tls.AlertDecodeError(str(exc)) from exc
        plain = (u8(HANDSHAKE_CERTIFICATE) + u24(len(body)) + body)

        try:
            certificate = tls.pull_certificate(_buffer_over(plain))
        except ValueError as exc:   # BufferReadError among them
            raise tls.AlertDecodeError("the decompressed Certificate does not "
                                       "parse: %s" % exc) from exc
        try:
            self._set_peer_certificate(certificate)
        except ValueError as exc:   # DER that is no certificate
            raise tls.AlertBadCertificate(str(exc)) from exc
        self.key_schedule.update_hash(compressed)
        self._set_state(tls.State.CLIENT_EXPECT_CERTIFICATE_VERIFY)

    def quic_connection_init(self, *args, **kwargs):
        _originals["QuicConnection.__init__"](self, *args, **kwargs)
        profile = getattr(self._configuration, "_pybrws_profile", None)
        if profile is None or not self._is_client:
            return   # not ours: aioquic's own connection, untouched
        # Kept on the QuicConnection, not the tls.Context: aioquic builds a
        # new Context on every _initialize, a Retry included.
        self._pybrws_connection = _Connection(profile, _rng)
        size = getattr(profile, "INITIAL_DESTINATION_ID_SIZE", None)
        if size is None or len(self._peer_cid.cid) == size:
            return
        # Both have to change together: the Initial keys are derived from the
        # destination id in the packet, so the recorded original and the id
        # actually sent must be the same bytes.
        self._peer_cid.cid = _rng(size)
        self._original_destination_connection_id = self._peer_cid.cid

    def quic_connection_initialize(self, *args, **kwargs):
        _originals["QuicConnection._initialize"](self, *args, **kwargs)
        connection = getattr(self, "_pybrws_connection", None)
        if connection is not None:
            self.tls._pybrws_connection = connection
            # No ticket is offered: Firefox's resumed QUIC hello is
            # unmeasured, and aioquic serialises a PSK hello into a buffer
            # our 1.9 KB hello overflows. One set on the configuration after
            # configuration() refused it ends here.
            self.tls.session_ticket = None

    tls.push_client_hello = push_client_hello
    tls.decode_public_key = decode_public_key
    tls.Context._handle_reassembled_message = handle_reassembled_message
    QuicConnection.__init__ = quic_connection_init
    QuicConnection._initialize = quic_connection_initialize
    tls.Context._client_send_hello = client_send_hello
    tls.Context._client_handle_hello = client_handle_hello


def configuration(server_name: str, *, profile=firefox157_quic,
                  verify: bool = True, cadata: bytes | None = None, **overrides):
    """A QuicConfiguration whose behaviour matches what the profile says.

    The hello is only half of it. The transport parameters announce a
    connection window, a stream window and an idle timeout, and aioquic
    enforces whatever its own configuration says rather than what we wrote on
    the wire. Announcing one set and enforcing another is not a fingerprint
    problem, it is a correctness problem: the peer sends up to what we
    advertised and the connection stalls or resets.

    The connection id length matters for a different reason -- it is the only
    profile value that reaches the wire twice, once in the QUIC header and
    once inside initial_source_connection_id.
    """
    from aioquic.quic.configuration import QuicConfiguration

    if overrides.get("session_ticket") is not None:
        raise ValueError(
            "QUIC resumption is unmeasured: no resumed Firefox QUIC hello has "
            "been captured, so no session ticket is offered over QUIC")
    settings = dict(
        is_client=True,
        alpn_protocols=list(profile.ALPN_PROTOCOLS),
        server_name=server_name,
        connection_id_length=profile.CONNECTION_ID_SIZE,
        idle_timeout=profile.IDLE_TIMEOUT_SECONDS,
        max_data=profile.MAX_DATA,
        max_stream_data=profile.MAX_STREAM_DATA,
        max_datagram_frame_size=profile.MAX_DATAGRAM_FRAME_SIZE,
    )
    if not verify:
        settings["verify_mode"] = 0
    if cadata is not None:
        settings["cadata"] = cadata   # PEM: anchors to trust besides the system's
    settings.update(overrides)
    config = QuicConfiguration(**settings)
    # The mark the patches look for: only connections made from this
    # configuration are impersonated, and with this profile.
    config._pybrws_profile = profile
    return config


def uninstall() -> None:
    """Put aioquic back, so a test can measure both arms in one process."""
    import aioquic.tls as tls

    if not _originals:
        return
    tls.push_client_hello = _originals["push_client_hello"]
    tls.decode_public_key = _originals["decode_public_key"]
    tls.Context._handle_reassembled_message = (
        _originals["_handle_reassembled_message"])
    from aioquic.quic.connection import QuicConnection

    QuicConnection.__init__ = _originals["QuicConnection.__init__"]
    QuicConnection._initialize = _originals["QuicConnection._initialize"]
    tls.Context._client_send_hello = _originals["_client_send_hello"]
    tls.Context._client_handle_hello = _originals["_client_handle_hello"]
    _originals.clear()


def installed() -> bool:
    return bool(_originals)
