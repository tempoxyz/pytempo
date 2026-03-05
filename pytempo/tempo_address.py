"""Bech32m-encoded Tempo addresses (BIP-350).

Provides ``TempoAddress``, a frozen attrs class for encoding and decoding
Tempo blockchain addresses using bech32m.  Supports both mainnet addresses
(HRP ``"tempo"``) and zone addresses (HRP ``"tempoz"``).

Encoding layout::

    payload = [0x00 version] [compact_size(zone_id) if zone] [20-byte address]

The bech32m checksum uses constant ``0x2BC830A3`` per BIP-350.

Example::

    from pytempo.tempo_address import TempoAddress

    addr = TempoAddress(address="0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")
    assert addr.format() == "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"

    parsed = TempoAddress.parse("tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0")
    assert parsed.address == addr.address
"""

from collections.abc import Sequence
from typing import Optional

import attrs

from .types import Address, as_address

# ---------------------------------------------------------------------------
# Bech32m (BIP-350) — pure-Python implementation
# ---------------------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: Sequence[int]) -> int:
    """Internal polynomial modular checksum."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == _BECH32M_CONST


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ _BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(
    data: Sequence[int], frombits: int, tobits: int, pad: bool = True
) -> list[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError(f"invalid value for convertbits: {value}")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in convertbits")
    return ret


def _bech32m_encode(hrp: str, data_bytes: bytes) -> str:
    """Encode *data_bytes* as a bech32m string with the given HRP."""
    data5 = _convertbits(list(data_bytes), 8, 5, pad=True)
    checksum = _bech32_create_checksum(hrp, data5)
    return hrp + "1" + "".join(_CHARSET[d] for d in data5 + checksum)


def _bech32m_decode(bech: str) -> tuple:
    """Decode a bech32m string.  Returns ``(hrp, data_bytes)``."""
    bech_lower = bech.lower()
    if bech_lower != bech and bech.upper() != bech:
        raise ValueError("mixed case in bech32m string")
    bech = bech_lower
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        raise ValueError("invalid bech32m separator position")
    hrp = bech[:pos]
    data5 = []
    for ch in bech[pos + 1 :]:
        idx = _CHARSET.find(ch)
        if idx < 0:
            raise ValueError(f"invalid bech32m character: {ch!r}")
        data5.append(idx)
    if not _bech32_verify_checksum(hrp, data5):
        raise ValueError("invalid bech32m checksum")
    data8 = _convertbits(data5[:-6], 5, 8, pad=False)
    return hrp, bytes(data8)


# ---------------------------------------------------------------------------
# CompactSize (Bitcoin varint, little-endian)
# ---------------------------------------------------------------------------


def _compact_size_encode(n: int) -> bytes:
    """Encode an unsigned integer as a Bitcoin CompactSize varint."""
    if n < 0:
        raise ValueError("compact_size value must be non-negative")
    if n <= 252:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _compact_size_decode(data: bytes, offset: int = 0) -> tuple:
    """Decode a CompactSize varint.  Returns ``(value, bytes_consumed)``."""
    if offset >= len(data):
        raise ValueError("compact_size: unexpected end of data")
    first = data[offset]
    if first <= 252:
        return first, 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), 5
    # 0xFF
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), 9


# ---------------------------------------------------------------------------
# HRP constants
# ---------------------------------------------------------------------------

HRP_MAINNET = "tempo"
HRP_ZONE = "tempoz"
_VERSION_BYTE = 0x00


# ---------------------------------------------------------------------------
# TempoAddress
# ---------------------------------------------------------------------------


def _as_optional_zone_id(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if not isinstance(value, int):
        raise TypeError(f"zone_id must be int or None, got {type(value).__name__}")
    if value < 0:
        raise ValueError("zone_id must be non-negative")
    return value


@attrs.define(frozen=True)
class TempoAddress:
    """A Tempo blockchain address with optional zone ID.

    Encodes to and decodes from bech32m strings using the ``"tempo"`` or
    ``"tempoz"`` human-readable prefix (HRP).

    Parameters:
        address: 20-byte Ethereum-style address (hex string or bytes).
        zone_id: Optional zone identifier.  When present the HRP becomes
            ``"tempoz"`` and the zone ID is encoded as a CompactSize varint
            in the payload.

    Examples::

        # Mainnet address (no zone)
        a = TempoAddress(address="0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")
        assert str(a) == "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"

        # Zone address
        b = TempoAddress(
            address="0x742d35CC6634c0532925a3B844bc9e7595F2Bd28",
            zone_id=1,
        )
        assert str(b) == "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"
    """

    address: Address = attrs.field(converter=as_address)
    zone_id: Optional[int] = attrs.field(default=None, converter=_as_optional_zone_id)

    # -- encoding / decoding ------------------------------------------------

    def _payload(self) -> bytes:
        """Build the raw payload: version || [compact_size zone_id] || address."""
        parts = bytearray([_VERSION_BYTE])
        if self.zone_id is not None:
            parts.extend(_compact_size_encode(self.zone_id))
        parts.extend(bytes(self.address))
        return bytes(parts)

    def format(self) -> str:
        """Return the bech32m-encoded string representation.

        Uses HRP ``"tempo"`` for addresses without a zone and ``"tempoz"``
        for addresses with a ``zone_id``.
        """
        hrp = HRP_ZONE if self.zone_id is not None else HRP_MAINNET
        return _bech32m_encode(hrp, self._payload())

    @classmethod
    def parse(cls, s: str) -> "TempoAddress":
        """Decode a bech32m Tempo address string.

        Args:
            s: A ``tempo1…`` or ``tempoz1…`` bech32m string.

        Returns:
            A new ``TempoAddress`` instance.

        Raises:
            ValueError: If the string is not a valid Tempo bech32m address.
        """
        hrp, payload = _bech32m_decode(s)

        if hrp not in (HRP_MAINNET, HRP_ZONE):
            raise ValueError(
                f"unknown HRP: {hrp!r} (expected {HRP_MAINNET!r} or {HRP_ZONE!r})"
            )

        if len(payload) < 1:
            raise ValueError("payload too short: missing version byte")
        version = payload[0]
        if version != _VERSION_BYTE:
            raise ValueError(f"unsupported version byte: 0x{version:02x}")

        offset = 1
        zone_id: Optional[int] = None

        if hrp == HRP_ZONE:
            zone_id, consumed = _compact_size_decode(payload, offset)
            offset += consumed

        remaining = payload[offset:]
        if len(remaining) != 20:
            raise ValueError(f"address must be 20 bytes, got {len(remaining)}")

        return cls(address=remaining, zone_id=zone_id)

    @staticmethod
    def validate(s: str) -> bool:
        """Check whether *s* is a valid bech32m Tempo address string.

        Returns ``True`` if the string decodes successfully, ``False`` otherwise.
        """
        try:
            TempoAddress.parse(s)
            return True
        except (ValueError, IndexError):
            return False

    # -- dunder methods -----------------------------------------------------

    def __str__(self) -> str:
        return self.format()

    def __repr__(self) -> str:
        if self.zone_id is not None:
            return f"TempoAddress({self.format()!r}, zone_id={self.zone_id})"
        return f"TempoAddress({self.format()!r})"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

_TEST_RAW = "0x742d35CC6634c0532925a3B844bc9e7595F2Bd28"

_VECTORS: list = [
    # (address_hex, zone_id, expected_bech32m)
    (_TEST_RAW, None, "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"),
    (_TEST_RAW, 1, "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"),
    (_TEST_RAW, 1000, "tempoz1qr77sqm5956uce35cpfjjfdrhpzte8n4jhet62qxx4zvx"),
    (_TEST_RAW, 65535, "tempoz1qr7lllm5956uce35cpfjjfdrhpzte8n4jhet62q8pdj6j"),
    (_TEST_RAW, 65536, "tempoz1qrlqqqqpqp6z6dwvvc6vq5efyk3ms39une6etu4a9qdupk5c"),
]


def test_format_vectors() -> None:
    """TempoAddress.format() matches viem test vectors."""
    for hex_addr, zone_id, expected in _VECTORS:
        ta = TempoAddress(address=hex_addr, zone_id=zone_id)
        assert ta.format() == expected, (
            f"format mismatch for zone_id={zone_id}: {ta.format()!r} != {expected!r}"
        )


def test_parse_vectors() -> None:
    """TempoAddress.parse() round-trips viem test vectors."""
    raw_bytes = as_address(_TEST_RAW)
    for _hex_addr, zone_id, bech in _VECTORS:
        parsed = TempoAddress.parse(bech)
        assert parsed.address == raw_bytes
        assert parsed.zone_id == zone_id


def test_roundtrip() -> None:
    """format -> parse -> format is idempotent."""
    for hex_addr, zone_id, _ in _VECTORS:
        ta = TempoAddress(address=hex_addr, zone_id=zone_id)
        assert TempoAddress.parse(ta.format()) == ta


def test_str_returns_bech32m() -> None:
    """str(TempoAddress) returns the bech32m string."""
    ta = TempoAddress(address=_TEST_RAW)
    assert str(ta) == ta.format()


def test_validate_accepts_valid() -> None:
    for _, _, bech in _VECTORS:
        assert TempoAddress.validate(bech) is True


def test_validate_rejects_invalid() -> None:
    assert TempoAddress.validate("tempo1invalid") is False
    assert (
        TempoAddress.validate("bitcoin1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0")
        is False
    )
    assert TempoAddress.validate("not-a-bech32m-string") is False
    assert TempoAddress.validate("") is False


def test_frozen() -> None:
    """TempoAddress instances are immutable."""
    ta = TempoAddress(address=_TEST_RAW)
    import pytest

    with pytest.raises(attrs.exceptions.FrozenInstanceError):
        ta.address = b"\x00" * 20  # type: ignore[misc]


def test_zone_id_validation() -> None:
    """zone_id must be non-negative or None."""
    import pytest

    with pytest.raises(ValueError, match="non-negative"):
        TempoAddress(address=_TEST_RAW, zone_id=-1)


def test_compact_size_encoding() -> None:
    """Verify CompactSize encoding for boundary values."""
    assert _compact_size_encode(0) == b"\x00"
    assert _compact_size_encode(252) == b"\xfc"
    assert _compact_size_encode(253) == b"\xfd\xfd\x00"
    assert _compact_size_encode(65535) == b"\xfd\xff\xff"
    assert _compact_size_encode(65536) == b"\xfe\x00\x00\x01\x00"
    assert _compact_size_encode(0xFFFFFFFF) == b"\xfe\xff\xff\xff\xff"
    assert _compact_size_encode(0x100000000) == b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"


def test_parse_bad_version() -> None:
    """Reject payloads with unsupported version byte."""
    import pytest

    ta = TempoAddress(address=_TEST_RAW)
    # Manually encode with version=1
    bad_payload = b"\x01" + bytes(ta.address)
    bad_bech = _bech32m_encode(HRP_MAINNET, bad_payload)
    with pytest.raises(ValueError, match="unsupported version"):
        TempoAddress.parse(bad_bech)


def test_repr() -> None:
    ta = TempoAddress(address=_TEST_RAW)
    assert "tempo1" in repr(ta)
    tz = TempoAddress(address=_TEST_RAW, zone_id=1)
    assert "zone_id=1" in repr(tz)
