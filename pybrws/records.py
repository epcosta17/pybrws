"""TLS record layer: framing and AEAD protection."""

from __future__ import annotations

import socket

from .keyschedule import CipherSuite, traffic_keys
from .wire import u8, u16

CHANGE_CIPHER_SPEC = 0x14
ALERT = 0x15
HANDSHAKE = 0x16
APPLICATION_DATA = 0x17

LEGACY_VERSION = 0x0303
MAX_FRAGMENT = 1 << 14
AEAD_TAG_SIZE = 16

ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    47: "illegal_parameter",
    48: "unknown_ca",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    80: "internal_error",
    112: "unrecognized_name",
    116: "certificate_required",
}


class TlsAlert(Exception):
    def __init__(self, level: int, description: int) -> None:
        name = ALERT_DESCRIPTIONS.get(description, str(description))
        kind = "fatal" if level == 2 else "warning"
        super().__init__(kind + " alert: " + name)
        self.level = level
        self.description = description


class Cipher:
    """One direction of an AEAD-protected record stream."""

    def __init__(self, suite: CipherSuite, secret: bytes) -> None:
        key, self.iv = traffic_keys(suite, secret)
        self.aead = suite.aead(key)
        self.sequence = 0

    def _nonce(self) -> bytes:
        counter = self.sequence.to_bytes(len(self.iv), "big")
        self.sequence += 1
        return bytes(a ^ b for a, b in zip(self.iv, counter))

    def encrypt(self, content_type: int, plaintext: bytes) -> bytes:
        inner = plaintext + u8(content_type)
        header = (
            u8(APPLICATION_DATA)
            + u16(LEGACY_VERSION)
            + u16(len(inner) + AEAD_TAG_SIZE)
        )
        return header + self.aead.encrypt(self._nonce(), inner, header)

    def decrypt(self, header: bytes, ciphertext: bytes) -> tuple[int, bytes]:
        inner = self.aead.decrypt(self._nonce(), ciphertext, header)
        inner = inner.rstrip(b"\x00")
        if not inner:
            raise ValueError("decrypted record carries no content type")
        return inner[-1], inner[:-1]


class RecordLayer:
    """Reads and writes records on a socket, encrypted once keys are installed."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.read_cipher: Cipher | None = None
        self.write_cipher: Cipher | None = None
        # TLS 1.2 changes two things here and nothing else. An encrypted
        # record keeps its own content type instead of hiding it inside the
        # ciphertext and presenting itself as application data; and
        # ChangeCipherSpec is a real message that says when to start
        # decrypting, rather than the padding TLS 1.3 sends for middleboxes.
        self.legacy = False

    def _recv_exactly(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise EOFError(
                    "peer closed after " + str(n - remaining) + " of " + str(n) + " bytes"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def read(self) -> tuple[int, bytes]:
        """Read one record, decrypting it and skipping compatibility padding.

        Raises:
            TlsAlert: if the peer sends an alert.
        """
        while True:
            header = self._recv_exactly(5)
            body = self._recv_exactly(int.from_bytes(header[3:5], "big"))

            content_type = header[0]
            if self.legacy:
                if (self.read_cipher is not None
                        and content_type != CHANGE_CIPHER_SPEC):
                    content_type, body = self.read_cipher.decrypt(header, body)
            elif content_type == APPLICATION_DATA and self.read_cipher is not None:
                content_type, body = self.read_cipher.decrypt(header, body)
            elif content_type == CHANGE_CIPHER_SPEC:
                # Middlebox compatibility only; carries no meaning in TLS 1.3.
                continue

            if content_type == ALERT:
                raise TlsAlert(body[0], body[1])
            return content_type, body

    def write(self, content_type: int, payload: bytes) -> None:
        for start in range(0, max(len(payload), 1), MAX_FRAGMENT):
            fragment = payload[start : start + MAX_FRAGMENT]
            if self.write_cipher is not None:
                record = self.write_cipher.encrypt(content_type, fragment)
            else:
                record = (
                    u8(content_type)
                    + u16(LEGACY_VERSION)
                    + u16(len(fragment))
                    + fragment
                )
            self.sock.sendall(record)
