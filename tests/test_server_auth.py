"""Server authentication on the full TLS 1.3 path.

In TLS 1.3 the server Finished is keyed from the ECDHE secret, which a peer
in the network path shares with the client, so it does not by itself bind the
handshake to the certificate. CertificateVerify is the message that does: a
signature, over the transcript, with the certificate's private key. A client
that completes a handshake carrying a valid chain but no CertificateVerify
would accept anyone able to replay a public chain.

These tests stand up a minimal TLS 1.3 server on a loopback socket, with a
leaf from a CA the client is told to trust, and drive the real
`handshake.connect`. One arm sends CertificateVerify, one omits it; the
second must be rejected. No network.
"""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.x509.verification import Store

from pybrws.certs import CertificateError
from pybrws.handshake import HandshakeError, connect
from pybrws.keyschedule import CIPHER_SUITES, KeySchedule, finished_verify_data
from pybrws.parser import parse_client_hello
from pybrws.proxy import CertificateAuthority
from pybrws.records import Cipher, RecordLayer

HOST = "localhost"
SUITE = CIPHER_SUITES[0x1301]


def _u8(n):
    return n.to_bytes(1, "big")


def _u16(n):
    return n.to_bytes(2, "big")


def _u24(n):
    return n.to_bytes(3, "big")


def _vec(data, length_bytes):
    return len(data).to_bytes(length_bytes, "big") + data


def _hs(message_type, body):
    return _u8(message_type) + _u24(len(body)) + body


def _client_x25519_share(hello):
    data = hello.extension(51).data
    at, end = 2, 2 + int.from_bytes(data[:2], "big")
    while at < end:
        group = int.from_bytes(data[at:at + 2], "big")
        size = int.from_bytes(data[at + 2:at + 4], "big")
        share = data[at + 4:at + 4 + size]
        at += 4 + size
        if group == 0x001D:  # x25519
            return share
    raise AssertionError("client offered no x25519 key share")


class _Server(threading.Thread):
    """A TLS 1.3 server that negotiates x25519 and sends `send_cert_verify`
    (or not), then a correct Finished. It never holds application data."""

    def __init__(self, sock, leaf_der, send_cert_verify):
        super().__init__(daemon=True)
        self.sock = sock
        self.leaf_der = leaf_der
        self.send_cert_verify = send_cert_verify

    def run(self):
        conn, _ = self.sock.accept()
        conn.settimeout(5)
        records = RecordLayer(conn)
        try:
            _, client_hello = records.read()
            hello = parse_client_hello(client_hello)

            private = x25519.X25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            shared = private.exchange(
                x25519.X25519PublicKey.from_public_bytes(_client_x25519_share(hello)))

            extensions = (_u16(0x002B) + _vec(_u16(0x0304), 2)
                          + _u16(0x0033) + _vec(_u16(0x001D) + _vec(public, 2), 2))
            server_hello = _hs(2, _u16(0x0303) + os.urandom(32)
                               + _vec(hello.session_id, 1) + _u16(0x1301)
                               + _u8(0) + _vec(extensions, 2))

            transcript = bytearray(client_hello + server_hello)
            client_hs, server_hs = KeySchedule(SUITE).handshake(shared, bytes(transcript))
            records.write(22, server_hello)
            conn.sendall(b"\x14\x03\x03\x00\x01\x01")  # compatibility CCS
            records.write_cipher = Cipher(SUITE, server_hs)

            flight = _hs(8, _vec(b"", 2))  # EncryptedExtensions
            chain = _vec(self.leaf_der, 3) + _vec(b"", 2)
            flight += _hs(11, _vec(b"", 1) + _vec(chain, 3))  # Certificate
            if self.send_cert_verify:
                # A syntactically present CertificateVerify with a signature
                # that cannot verify: enough to reach the signature check.
                flight += _hs(15, _u16(0x0804) + _vec(os.urandom(256), 2))
            transcript += flight
            flight += _hs(20, finished_verify_data(SUITE, server_hs, bytes(transcript)))
            records.write(22, flight)

            records.read_cipher = Cipher(SUITE, client_hs)
            records.read()  # drain the client's CCS/Finished so it can send
        except Exception:
            pass
        finally:
            conn.close()


class TestServerAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ca = CertificateAuthority(Path(cls.tmp.name))
        cls.store = Store([cls.ca.certificate])
        leaf, _key = cls.ca._leaf(HOST)
        cls.leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _connect_against(self, send_cert_verify):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server = _Server(listener, self.leaf_der, send_cert_verify)
        server.start()
        try:
            return connect(HOST, port, verify=True, trust_store=self.store, timeout=5)
        finally:
            server.join(5)
            listener.close()

    def test_a_handshake_without_certificate_verify_is_rejected(self):
        # The leaf is from a trusted CA and the Finished is correct, so the
        # only thing missing is proof the server holds the key. That must be
        # fatal, not accepted.
        with self.assertRaises(HandshakeError) as caught:
            self._connect_against(send_cert_verify=False)
        self.assertIn("CertificateVerify", str(caught.exception))

    def test_a_bad_certificate_verify_signature_is_rejected(self):
        # The control: a CertificateVerify is present but does not verify, so
        # the failure is the signature check rather than the missing-message
        # guard. Confirms the first test is not passing for the wrong reason.
        with self.assertRaises(CertificateError):
            self._connect_against(send_cert_verify=True)


if __name__ == "__main__":
    unittest.main()
