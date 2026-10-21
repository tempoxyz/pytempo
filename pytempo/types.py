"""Type definitions and coercion helpers for Tempo transactions.

These converters are designed to work with attrs.field(converter=...).
"""

from typing import NewType, Optional, Union

from eth_utils import to_bytes

Address = NewType("Address", bytes)
Hash32 = NewType("Hash32", bytes)
Selector = NewType("Selector", bytes)

BytesLike = Union[bytes, str]


def _hex_to_bytes(value: str) -> bytes:
    """Decode a hex string, rejecting an odd number of hex digits.

    ``eth_utils.to_bytes`` left-pads an odd-length hex string with a zero
    nibble, so ``"0x" + "a" * 39`` decodes to 20 bytes and passes a length
    check with every byte shifted. Reject it instead, so a truncated value is
    not accepted as a different, well-formed one.
    """
    digits = value[2:] if value[:2].lower() == "0x" else value
    if len(digits) % 2:
        raise ValueError(
            f"hex string must have an even number of digits, got {len(digits)}"
        )
    return to_bytes(hexstr=value)


def as_bytes(value: BytesLike) -> bytes:
    """Convert hex string, bytes, bytearray, or memoryview to bytes.

    Use as: attrs.field(converter=as_bytes)

    Raises:
        TypeError: If value is not a string or bytes-like object (rejects int).
        ValueError: If the hex string has an odd number of digits.
    """
    if isinstance(value, str):
        if value == "" or value == "0x":
            return b""
        return _hex_to_bytes(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        f"expected str, bytes, bytearray, or memoryview, got {type(value).__name__}"
    )


def as_address(value: BytesLike) -> Address:
    """Convert hex string or bytes to a validated 20-byte address.

    Use as: attrs.field(converter=as_address)

    Raises:
        TypeError: If value is not a string or bytes-like object (rejects int).
        ValueError: If the hex string has an odd number of digits, or the
            address is not 0 or 20 bytes.
    """
    if isinstance(value, str):
        if value == "" or value == "0x":
            return Address(b"")
        b = _hex_to_bytes(value)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
    else:
        raise TypeError(
            f"expected str, bytes, bytearray, or memoryview, got {type(value).__name__}"
        )

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

    Raises:
        TypeError: If value is not a string or bytes-like object (rejects int).
        ValueError: If the hex string has an odd number of digits, or the hash
            is not exactly 32 bytes.
    """
    if isinstance(value, str):
        b = _hex_to_bytes(value)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
    else:
        raise TypeError(
            f"expected str, bytes, bytearray, or memoryview, got {type(value).__name__}"
        )

    if len(b) != 32:
        raise ValueError(f"hash32 must be 32 bytes, got {len(b)}")
    return Hash32(b)


def as_selector(value: BytesLike) -> Selector:
    """Convert hex string or bytes to a validated 4-byte function selector.

    Use as: attrs.field(converter=as_selector)

    Raises:
        TypeError: If value is not a string or bytes-like object (rejects int).
        ValueError: If the hex string has an odd number of digits, or the
            selector is not exactly 4 bytes.
    """
    b = as_bytes(value)
    if len(b) != 4:
        raise ValueError(f"selector must be exactly 4 bytes, got {len(b)}")
    return Selector(b)


def validate_nonempty_address(
    instance: object, attribute: object, value: Address
) -> None:
    """Attrs validator: address must be exactly 20 bytes (not empty)."""
    if len(bytes(value)) != 20:
        raise ValueError("address must be exactly 20 bytes")
