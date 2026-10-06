"""Primitive encoders for TLS wire structures."""

from __future__ import annotations


def u8(value: int) -> bytes:
    return value.to_bytes(1, "big")


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def vector(data: bytes, length_bytes: int) -> bytes:
    """Prefix `data` with its big-endian length."""
    limit = 1 << (length_bytes * 8)
    if len(data) >= limit:
        raise ValueError(f"{len(data)} bytes do not fit a {length_bytes}-byte length")
    return len(data).to_bytes(length_bytes, "big") + data


def extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + vector(data, 2)
