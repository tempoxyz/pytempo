"""Tests for the internal fixed-width ABI decode helpers."""

import pytest
from eth_utils import to_checksum_address

from pytempo.contracts._decode import (
    decode_address,
    decode_bool,
    decode_u64,
    decode_word,
)

# 20 non-zero address bytes.
ADDR = bytes(range(1, 21))


class TestDecodeAddress:
    def test_decodes_canonical_word(self):
        word = b"\x00" * 12 + ADDR
        assert decode_address(word, "addr") == to_checksum_address(ADDR)

    def test_rejects_non_zero_upper_bytes(self):
        # A canonical ABI address word left-pads the 20-byte address with 12
        # zero bytes; non-zero upper bytes indicate a malformed response and
        # must not be silently discarded (matching decode_bool / decode_u64,
        # which also reject non-canonical words).
        word = b"\xff" * 12 + ADDR
        with pytest.raises(ValueError, match="upper bytes"):
            decode_address(word, "addr")

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            decode_address(b"\x00" * 31, "addr")


class TestDecodeStrictnessSiblings:
    """The decode helpers deliberately reject non-canonical words."""

    def test_bool_rejects_non_canonical(self):
        with pytest.raises(ValueError, match="ABI bool"):
            decode_bool((2).to_bytes(32, "big"), "flag")

    def test_u64_rejects_overflow(self):
        with pytest.raises(ValueError, match="exceeds uint64"):
            decode_u64((2**64).to_bytes(32, "big"), "amount")

    def test_word_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            decode_word(b"\x00" * 33, "word")
