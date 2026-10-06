"""Tests for pybrws.keyschedule."""

import unittest

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from pybrws.keyschedule import (
    CIPHER_SUITES,
    KeySchedule,
    derive_secret,
    finished_verify_data,
    hkdf_expand,
    hkdf_expand_label,
    hkdf_extract,
    traffic_keys,
    transcript_hash,
)

SHA256_SUITE = CIPHER_SUITES[0x1301]
SHA384_SUITE = CIPHER_SUITES[0x1302]


class TestHkdf(unittest.TestCase):
    def test_expand_matches_a_known_good_implementation(self):
        secret = bytes(range(32))
        info = b"some info"
        for suite in (SHA256_SUITE, SHA384_SUITE):
            for length in (1, 16, 42, 100):
                expected = HKDFExpand(
                    algorithm=suite.digest(), length=length, info=info
                ).derive(secret)
                self.assertEqual(
                    hkdf_expand(suite, secret, info, length),
                    expected,
                    f"{suite.name} length={length}",
                )

    def test_extract_is_hmac_of_the_input_keying_material(self):
        salt, ikm = b"salt" * 4, b"input keying material"
        ctx = hmac.HMAC(salt, SHA256_SUITE.digest())
        ctx.update(ikm)
        self.assertEqual(hkdf_extract(SHA256_SUITE, salt, ikm), ctx.finalize())

    def test_extract_treats_an_empty_salt_as_zeros(self):
        ikm = b"x" * 32
        self.assertEqual(
            hkdf_extract(SHA256_SUITE, b"", ikm),
            hkdf_extract(SHA256_SUITE, bytes(32), ikm),
        )

    def test_expand_label_uses_the_tls13_prefix(self):
        suite = SHA256_SUITE
        secret = bytes(32)
        info = (
            (16).to_bytes(2, "big")
            + bytes([len(b"tls13 key")])
            + b"tls13 key"
            + bytes([0])
        )
        self.assertEqual(
            hkdf_expand_label(suite, secret, b"key", b"", 16),
            hkdf_expand(suite, secret, info, 16),
        )

    def test_expand_label_is_sensitive_to_the_label(self):
        secret = bytes(32)
        self.assertNotEqual(
            hkdf_expand_label(SHA256_SUITE, secret, b"key", b"", 16),
            hkdf_expand_label(SHA256_SUITE, secret, b"iv", b"", 16),
        )


class TestTrafficKeys(unittest.TestCase):
    def test_sizes_follow_the_cipher_suite(self):
        for suite, key_size in ((SHA256_SUITE, 16), (SHA384_SUITE, 32)):
            key, iv = traffic_keys(suite, bytes(suite.hash_size))
            self.assertEqual(len(key), key_size, suite.name)
            self.assertEqual(len(iv), 12, suite.name)

    def test_chacha_uses_a_32_byte_key(self):
        key, iv = traffic_keys(CIPHER_SUITES[0x1303], bytes(32))
        self.assertEqual((len(key), len(iv)), (32, 12))


class TestDerivation(unittest.TestCase):
    def test_derive_secret_depends_on_the_transcript(self):
        secret = bytes(32)
        a = derive_secret(SHA256_SUITE, secret, b"c hs traffic", b"transcript-a")
        b = derive_secret(SHA256_SUITE, secret, b"c hs traffic", b"transcript-b")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), SHA256_SUITE.hash_size)

    def test_transcript_hash_is_the_plain_digest(self):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(b"abc")
        self.assertEqual(transcript_hash(SHA256_SUITE, b"abc"), digest.finalize())

    def test_finished_verify_data_is_hash_sized(self):
        data = finished_verify_data(SHA384_SUITE, bytes(48), b"transcript")
        self.assertEqual(len(data), 48)


class TestKeySchedule(unittest.TestCase):
    def test_client_and_server_secrets_differ(self):
        schedule = KeySchedule(SHA256_SUITE)
        client, server = schedule.handshake(b"shared" * 8, b"transcript")
        self.assertNotEqual(client, server)
        self.assertEqual(len(client), 32)

    def test_application_requires_the_handshake_stage_first(self):
        with self.assertRaises(ValueError):
            KeySchedule(SHA256_SUITE).application(b"transcript")

    def test_application_secrets_differ_from_handshake_secrets(self):
        schedule = KeySchedule(SHA256_SUITE)
        hs_client, _ = schedule.handshake(b"shared" * 8, b"t1")
        app_client, app_server = schedule.application(b"t1t2")
        self.assertNotIn(hs_client, (app_client, app_server))
        self.assertIsNotNone(schedule.master_secret)

    def test_early_secret_is_deterministic(self):
        self.assertEqual(
            KeySchedule(SHA256_SUITE).early_secret,
            KeySchedule(SHA256_SUITE).early_secret,
        )


if __name__ == "__main__":
    unittest.main()
