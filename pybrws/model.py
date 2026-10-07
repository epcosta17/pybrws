"""Data shapes and lookup tables for TLS handshake structures."""

from __future__ import annotations

from dataclasses import dataclass, field

# RFC 8701. Reserved values clients advertise to detect ossified middleboxes.
# Stripped before computing JA3/JA4.
GREASE_VALUES = frozenset(
    {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }
)


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


# Extensions seen in practice, grouped by purpose.
EXTENSION_NAMES: dict[int, str] = {
    # peer identification
    0: "server_name",
    16: "alpn",
    17513: "application_settings",      # Chrome only
    65037: "encrypted_client_hello",
    # cryptographic parameters
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    43: "supported_versions",
    51: "key_share",
    # certificate handling
    5: "status_request",
    18: "signed_certificate_timestamp",
    27: "compress_certificate",
    # session resumption
    35: "session_ticket",
    41: "pre_shared_key",               # must be the last extension
    45: "psk_key_exchange_modes",
    # transport
    57: "quic_transport_parameters",  # QUIC only, RFC 9001 section 8.2
    # legacy and compatibility
    21: "padding",
    23: "extended_master_secret",
    28: "record_size_limit",            # Firefox / NSS
    34: "delegated_credentials",        # Firefox / NSS
    65281: "renegotiation_info",
}


def extension_name(ext_type: int) -> str:
    if is_grease(ext_type):
        return "GREASE"
    return EXTENSION_NAMES.get(ext_type, f"unknown({ext_type})")


@dataclass(frozen=True)
class Extension:
    type: int
    data: bytes

    @property
    def name(self) -> str:
        return extension_name(self.type)

    def __repr__(self) -> str:
        return f"<Extension {self.name} ({self.type}) len={len(self.data)}>"


@dataclass
class ClientHello:
    """A parsed ClientHello body."""

    legacy_version: int                 # 0x0303 regardless of negotiated version
    random: bytes                       # 32 bytes
    session_id: bytes                   # 0 or 32 bytes (TLS 1.3 compat mode)
    cipher_suites: list[int]
    compression_methods: list[int]
    extensions: list[Extension]         # wire order is significant
    raw: bytes = field(default=b"", repr=False)

    def extension(self, ext_type: int) -> Extension | None:
        for ext in self.extensions:
            if ext.type == ext_type:
                return ext
        return None

    def extension_types(self) -> list[int]:
        return [e.type for e in self.extensions]

    def summary(self) -> str:
        lines = [
            f"legacy_version   0x{self.legacy_version:04x}",
            f"random           {self.random.hex()}",
            f"session_id       ({len(self.session_id)}B) {self.session_id.hex()}",
            f"cipher_suites    ({len(self.cipher_suites)})",
        ]
        for cs in self.cipher_suites:
            tag = " GREASE" if is_grease(cs) else ""
            lines.append(f"    0x{cs:04x}{tag}")
        lines.append(f"compression      {self.compression_methods}")
        lines.append(f"extensions       ({len(self.extensions)})")
        for ext in self.extensions:
            lines.append(f"    {ext.type:>5}  {ext.name:<28} {len(ext.data):>4}B")
        if self.raw:
            lines.append(f"total raw        {len(self.raw)} bytes")
        return "\n".join(lines)
