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
    """Decode an address encoded in a single ABI word."""
    return to_checksum_address(decode_word(result, name)[-20:])


def decode_hash32(result: bytes, name: str) -> bytes:
    """Decode a bytes32 ABI word."""
    return decode_word(result, name)
