"""Type definitions and coercion helpers for Tempo transactions.

These converters are designed to work with attrs.field(converter=...).
"""

from typing import NewType, Optional, Union

from eth_utils import to_bytes

Address = NewType("Address", bytes)
Hash32 = NewType("Hash32", bytes)

BytesLike = Union[bytes, str]


def as_bytes(value: BytesLike) -> bytes:
    """Convert hex string, bytes, bytearray, or memoryview to bytes.

    Use as: attrs.field(converter=as_bytes)
    """
    if isinstance(value, str):
        if value == "" or value == "0x":
            return b""
        return to_bytes(hexstr=value)
    return bytes(value)


def as_address(value: BytesLike) -> Address:
    """Convert hex string or bytes to a validated 20-byte address.

    Use as: attrs.field(converter=as_address)
    """
    if isinstance(value, str):
        if value == "" or value == "0x":
            return Address(b"")
        b = to_bytes(hexstr=value)
    else:
        b = bytes(value)

    if len(b) not in (0, 20):
        raise ValueError(f"address must be 20 bytes (or empty), got {len(b)}")
    return Address(b)


def as_optional_address(value: Optional[BytesLike]) -> Optional[Address]:
    """Convert to Address, treating empty/None as None.

    Use as: attrs.field(converter=as_optional_address)
    """
    if value is None:
        return None
    b = as_bytes(value)
    if b == b"":
        return None
    return as_address(b)


def as_hash32(value: BytesLike) -> Hash32:
    """Convert hex string or bytes to a validated 32-byte hash.

    Use as: attrs.field(converter=as_hash32)
    """
    if isinstance(value, str):
        b = to_bytes(hexstr=value)
    else:
        b = bytes(value)

    if len(b) != 32:
        raise ValueError(f"hash32 must be 32 bytes, got {len(b)}")
    return Hash32(b)
