"""Tests for pybrws.records."""

import socket
import threading
import unittest

from pybrws.keyschedule import CIPHER_SUITES
from pybrws.records import (
    ALERT,
    APPLICATION_DATA,
    CHANGE_CIPHER_SPEC,
    HANDSHAKE,
    Cipher,
    RecordLayer,
    TlsAlert,
)

SUITE = CIPHER_SUITES[0x1301]
SECRET = bytes(range(32))


class TestCipher(unittest.TestCase):
    def test_round_trip(self):
        sender = Cipher(SUITE, SECRET)
        receiver = Cipher(SUITE, SECRET)
        record = sender.encrypt(HANDSHAKE, b"hello")
        content_type, plaintext = receiver.decrypt(record[:5], record[5:])
        self.assertEqual((content_type, plaintext), (HANDSHAKE, b"hello"))

    def test_outer_header_claims_application_data(self):
        record = Cipher(SUITE, SECRET).encrypt(HANDSHAKE, b"hello")
        self.assertEqual(record[0], APPLICATION_DATA)
        self.assertEqual(record[1:3], b"\x03\x03")
        self.assertEqual(int.from_bytes(record[3:5], "big"), len(record) - 5)

    def test_sequence_number_advances(self):
        sender = Cipher(SUITE, SECRET)
        receiver = Cipher(SUITE, SECRET)
        for i in range(4):
            record = sender.encrypt(APPLICATION_DATA, b"payload %d" % i)
            _, plaintext = receiver.decrypt(record[:5], record[5:])
            self.assertEqual(plaintext, b"payload %d" % i)
        self.assertEqual(sender.sequence, 4)

    def test_reusing_a_sequence_number_fails_authentication(self):
        sender = Cipher(SUITE, SECRET)
        receiver = Cipher(SUITE, SECRET)
        first = sender.encrypt(APPLICATION_DATA, b"one")
        sender.encrypt(APPLICATION_DATA, b"two")
        receiver.decrypt(first[:5], first[5:])
        # Receiver is now at sequence 1; replaying the first record must fail.
        with self.assertRaises(Exception):
            receiver.decrypt(first[:5], first[5:])

    def _decrypt_inner(self, inner: bytes):
        """Hand-build one record so the inner plaintext layout can be chosen."""
        sender = Cipher(SUITE, SECRET)
        receiver = Cipher(SUITE, SECRET)
        header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
        body = sender.aead.encrypt(sender._nonce(), inner, header)
        return receiver.decrypt(header, body)

    def test_padding_after_the_content_type_is_stripped(self):
        # TLSInnerPlaintext is content || type || zeros.
        inner = b"data" + bytes([HANDSHAKE]) + b"\x00\x00\x00"
        self.assertEqual(self._decrypt_inner(inner), (HANDSHAKE, b"data"))

    def test_content_ending_in_zeros_survives(self):
        inner = b"data\x00\x00" + bytes([HANDSHAKE])
        self.assertEqual(self._decrypt_inner(inner), (HANDSHAKE, b"data\x00\x00"))

    def test_content_ending_in_zeros_survives_alongside_padding(self):
        inner = b"data\x00" + bytes([HANDSHAKE]) + b"\x00\x00"
        self.assertEqual(self._decrypt_inner(inner), (HANDSHAKE, b"data\x00"))

    def test_an_all_zero_inner_plaintext_is_rejected(self):
        with self.assertRaises(ValueError):
            self._decrypt_inner(b"\x00\x00\x00")


class TestRecordLayer(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)

    def test_plaintext_round_trip(self):
        RecordLayer(self.a).write(HANDSHAKE, b"client hello")
        self.assertEqual(RecordLayer(self.b).read(), (HANDSHAKE, b"client hello"))

    def test_change_cipher_spec_is_skipped(self):
        writer = RecordLayer(self.a)
        writer.write(CHANGE_CIPHER_SPEC, b"\x01")
        writer.write(HANDSHAKE, b"real message")
        self.assertEqual(RecordLayer(self.b).read(), (HANDSHAKE, b"real message"))

    def test_alert_raises(self):
        RecordLayer(self.a).write(ALERT, bytes([2, 50]))
        with self.assertRaises(TlsAlert) as caught:
            RecordLayer(self.b).read()
        self.assertEqual(caught.exception.description, 50)
        self.assertIn("decode_error", str(caught.exception))

    def test_encrypted_round_trip(self):
        writer = RecordLayer(self.a)
        reader = RecordLayer(self.b)
        writer.write_cipher = Cipher(SUITE, SECRET)
        reader.read_cipher = Cipher(SUITE, SECRET)
        writer.write(APPLICATION_DATA, b"secret payload")
        self.assertEqual(reader.read(), (APPLICATION_DATA, b"secret payload"))

    def test_large_payload_is_fragmented(self):
        # The write has to run concurrently with the read. A socketpair's
        # send buffer is 8 KiB on macOS, so a payload larger than one record
        # fills it and `sendall` blocks forever with nobody reading -- the
        # suite hung here rather than failing, which is why it went unnoticed.
        # On Linux the default buffer is a few hundred kilobytes and the
        # sequential version passed, which is what made it look portable.
        payload = b"x" * ((1 << 14) + 100)
        writer = threading.Thread(
            target=RecordLayer(self.a).write,
            args=(APPLICATION_DATA, payload),
            daemon=True,
        )
        writer.start()
        self.addCleanup(writer.join, 5)
        reader = RecordLayer(self.b)
        first = reader.read()[1]
        second = reader.read()[1]
        self.assertEqual(len(first), 1 << 14)
        self.assertEqual(len(second), 100)
        self.assertEqual(first + second, payload)

    def test_truncated_stream_raises(self):
        self.a.sendall(b"\x16\x03\x03\x00\x10only-five")
        self.a.close()
        with self.assertRaises(EOFError):
            RecordLayer(self.b).read()


if __name__ == "__main__":
    unittest.main()
