"""Internal helpers for decoding fixed-width ABI return values."""

from eth_utils import to_checksum_address


def decode_word(result: bytes, name: str) -> bytes:
    """Decode a single ABI word, rejecting empty or malformed responses."""
    raw = bytes(result)
    if len(raw) != 32:
        raise ValueError(
            f"{name} result wrong length, expected 32 bytes, got {len(raw)}"
        )
    return raw


def decode_uint(result: bytes, name: str) -> int:
    """Decode a single uint ABI word."""
    return int.from_bytes(decode_word(result, name), "big")


def decode_u64(result: bytes, name: str) -> int:
    """Decode a uint64 encoded in a single ABI word."""
    value = decode_uint(result, name)
    if value > 2**64 - 1:
        raise ValueError(f"{name} result exceeds uint64, got {value}")
    return value


def decode_bool(result: bytes, name: str) -> bool:
    """Decode a single bool ABI word, rejecting non-canonical values."""
    value = decode_uint(result, name)
    if value not in (0, 1):
        raise ValueError(f"{name} result must be ABI bool 0 or 1, got {value}")
    return bool(value)


def decode_address(result: bytes, name: str) -> str:
    """Decode an address encoded in a single ABI word.

    A canonical ABI address word left-pads the 20-byte address with 12 zero
    bytes; reject non-zero upper bytes rather than silently discarding them, so
    a malformed response is not accepted as a valid address.
    """
    word = decode_word(result, name)
    if word[:12] != b"\x00" * 12:
        raise ValueError(
            f"{name} result has non-zero upper bytes for a 20-byte address"
        )
    return to_checksum_address(word[-20:])


def decode_hash32(result: bytes, name: str) -> bytes:
    """Decode a bytes32 ABI word."""
    return decode_word(result, name)
