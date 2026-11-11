"""Server authentication on the full TLS 1.3 path.

In TLS 1.3 the server Finished is keyed from the ECDHE secret, which a peer
in the network path shares with the client, so it does not by itself bind the
handshake to the certificate. CertificateVerify is the message that does: a
signature, over the transcript, with the certificate's private key. A client
that completes a handshake carrying a valid chain but no CertificateVerify
would accept anyone able to replay a public chain.

The server is the scripted one in `tests/hostile.py`, with a leaf from a CA
the client is told to trust. One arm sends a CertificateVerify that cannot
verify, one omits it; both must be rejected. No network.
"""

from __future__ import annotations

import os
import unittest

from pybrws.certs import CertificateError
from pybrws.handshake import HandshakeError, connect
from pybrws.wire import u16, vector

from tests import hostile


def _flight_without_certificate_verify(peer):
    peer.read_client_hello()
    peer.send_server_hello()
    peer.send_handshake(peer.encrypted_extensions() + peer.certificate())
    peer.send_handshake(peer.finished())
    peer.read_client_finished()


def _flight_with_bad_certificate_verify(peer):
    peer.read_client_hello()
    peer.send_server_hello()
    peer.send_handshake(peer.encrypted_extensions() + peer.certificate())
    # Syntactically present, impossible to verify: enough to reach the
    # signature check.
    peer.send_handshake(hostile.hs(hostile.CERTIFICATE_VERIFY,
                                   u16(0x0804) + vector(os.urandom(256), 2)))
    peer.send_handshake(peer.finished())
    peer.read_client_finished()


class TestServerAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca, cls.store, cls._tmp = hostile.trusted_ca()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _connect_against(self, script):
        server = hostile.Tls13Server(script, ca=self.ca)
        server.start()
        try:
            return connect("localhost", server.port, verify=True,
                           trust_store=self.store, timeout=5)
        finally:
            server.join(5)

    def test_a_handshake_without_certificate_verify_is_rejected(self):
        # The leaf is from a trusted CA and the Finished is correct, so the
        # only thing missing is proof the server holds the key. That must be
        # fatal, not accepted.
        with self.assertRaises(HandshakeError) as caught:
            self._connect_against(_flight_without_certificate_verify)
        self.assertIn("CertificateVerify", str(caught.exception))

    def test_a_bad_certificate_verify_signature_is_rejected(self):
        # The control: a CertificateVerify is present but does not verify,
        # so the failure is the signature check rather than the
        # missing-message guard. Confirms the first test is not passing for
        # the wrong reason.
        with self.assertRaises(CertificateError):
            self._connect_against(_flight_with_bad_certificate_verify)


if __name__ == "__main__":
    unittest.main()
