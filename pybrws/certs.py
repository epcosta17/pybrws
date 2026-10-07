"""Certificate handling: parsing, decompression, chain and signature checks.

Path validation is delegated to `cryptography.x509.verification`. Hand-rolling
it would mean reimplementing name constraints, policy handling and revocation
semantics, which is the kind of code that is wrong in ways nobody notices
until it matters.
"""

from __future__ import annotations

import ssl
import warnings

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.verification import PolicyBuilder, Store

from .parser import _Reader

# RFC 8879
COMPRESSION_ZLIB = 1
COMPRESSION_BROTLI = 2
COMPRESSION_ZSTD = 3

# The string a TLS 1.3 server signs, RFC 8446 section 4.4.3.
SIGNATURE_CONTEXT = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"

RSA_PSS = {
    0x0804: hashes.SHA256,
    0x0805: hashes.SHA384,
    0x0806: hashes.SHA512,
}
ECDSA = {
    0x0403: hashes.SHA256,
    0x0503: hashes.SHA384,
    0x0603: hashes.SHA512,
}
RSA_PKCS1 = {
    0x0401: hashes.SHA256,
    0x0501: hashes.SHA384,
    0x0601: hashes.SHA512,
}
ED25519 = 0x0807


class CertificateError(Exception):
    pass


def decompress_certificate(message: bytes) -> bytes:
    """Turn an RFC 8879 CompressedCertificate body into a Certificate body."""
    reader = _Reader(message, "CompressedCertificate")
    algorithm = reader.uint(2)
    expected = reader.uint(3)
    compressed = reader.vector(3)

    if algorithm == COMPRESSION_ZLIB:
        import zlib

        plain = zlib.decompress(compressed)
    elif algorithm == COMPRESSION_BROTLI:
        import brotli

        plain = brotli.decompress(compressed)
    elif algorithm == COMPRESSION_ZSTD:
        try:
            from compression import zstd
        except ImportError:
            import zstandard

            plain = zstandard.ZstdDecompressor().decompress(compressed)
        else:
            plain = zstd.decompress(compressed)
    else:
        raise CertificateError("unknown certificate compression " + str(algorithm))

    if len(plain) != expected:
        raise CertificateError(
            "decompressed to %d bytes, the server said %d" % (len(plain), expected)
        )
    return plain


def parse_certificate(body: bytes) -> list[bytes]:
    """Return the DER certificates in a Certificate message body, leaf first."""
    reader = _Reader(body, "Certificate")
    reader.vector(1)  # certificate_request_context, empty for a server
    entries = _Reader(reader.vector(3), "certificate_list")
    chain = []
    while entries.remaining:
        chain.append(entries.vector(3))
        entries.vector(2)  # per-certificate extensions
    if not chain:
        raise CertificateError("the server sent an empty certificate list")
    return chain


def system_store() -> Store:
    """The platform's trust anchors, as Python's ssl module sees them."""
    context = ssl.create_default_context()
    anchors = []
    warnings.filterwarnings("ignore", message="Parsed a serial number")
    for der in context.get_ca_certs(binary_form=True):
        try:
            anchors.append(x509.load_der_x509_certificate(der))
        except Exception:
            # Platform stores carry the occasional malformed anchor. One
            # unparseable certificate should not cost the other few hundred.
            continue
    if not anchors:
        raise CertificateError("no trust anchors available from the system store")
    return Store(anchors)


def verify_chain(chain: list[bytes], hostname: str, store: Store | None = None):
    """Validate the chain for `hostname`, returning the leaf certificate.

    Raises:
        CertificateError: if the chain does not validate.
    """
    certificates = [x509.load_der_x509_certificate(der) for der in chain]
    leaf, intermediates = certificates[0], certificates[1:]
    verifier = (
        PolicyBuilder()
        .store(store if store is not None else system_store())
        .build_server_verifier(x509.DNSName(hostname))
    )
    try:
        verifier.verify(leaf, intermediates)
    except Exception as exc:
        raise CertificateError("certificate chain rejected: " + str(exc)) from exc
    return leaf


def verify_signature(leaf, scheme: int, signature: bytes, transcript_hash: bytes) -> None:
    """Check the CertificateVerify signature over the handshake transcript.

    This is what proves the peer holds the key in the certificate, rather
    than merely having a copy of someone else's chain.
    """
    signed = SIGNATURE_CONTEXT + transcript_hash
    key = leaf.public_key()
    try:
        if scheme in RSA_PSS:
            algorithm = RSA_PSS[scheme]()
            key.verify(signature, signed,
                       padding.PSS(mgf=padding.MGF1(algorithm),
                                   salt_length=algorithm.digest_size),
                       algorithm)
        elif scheme in ECDSA:
            key.verify(signature, signed, ec.ECDSA(ECDSA[scheme]()))
        elif scheme == ED25519:
            key.verify(signature, signed)
        elif scheme in RSA_PKCS1:
            # Not permitted for TLS 1.3 CertificateVerify, but accepting it
            # silently would hide a server doing the wrong thing.
            raise CertificateError(
                "server signed with rsa_pkcs1, which TLS 1.3 forbids here"
            )
        else:
            raise CertificateError("unsupported signature scheme 0x%04x" % scheme)
    except InvalidSignature as exc:
        raise CertificateError("CertificateVerify signature is invalid") from exc
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError("CertificateVerify could not be checked: "
                               + str(exc)) from exc


def expected_key_type(leaf) -> str:
    key = leaf.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ecdsa"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    return type(key).__name__
