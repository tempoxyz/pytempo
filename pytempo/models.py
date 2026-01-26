"""Strongly-typed data models for Tempo transactions."""

from typing import Optional

import attrs
import rlp
from eth_account import Account
from eth_utils import keccak

from .types import (
    Address,
    BytesLike,
    Hash32,
    as_address,
    as_bytes,
    as_hash32,
    as_optional_address,
)


def _validate_call_value(
    instance: "Call", attribute: attrs.Attribute, value: int
) -> None:
    if value < 0:
        raise ValueError("call.value must be >= 0")


def _validate_call_to(
    instance: "Call", attribute: attrs.Attribute, value: Address
) -> None:
    if len(bytes(value)) not in (0, 20):
        raise ValueError("call.to must be 20 bytes (or empty for contract creation)")


@attrs.define(frozen=True)
class Call:
    """Single call in a batch transaction."""

    to: Address = attrs.field(converter=as_address)
    value: int = attrs.field(default=0, validator=_validate_call_value)
    data: bytes = attrs.field(factory=bytes, converter=as_bytes)

    def as_rlp_list(self) -> list:
        return [bytes(self.to), self.value, self.data]

    @classmethod
    def create(
        cls,
        to: BytesLike,
        value: int = 0,
        data: BytesLike = b"",
    ) -> "Call":
        """Create a Call with automatic type coercion."""
        return cls(to=to, value=value, data=data)


def _validate_access_list_address(
    instance: "AccessListItem", attribute: attrs.Attribute, value: Address
) -> None:
    if len(bytes(value)) != 20:
        raise ValueError("access list address must be 20 bytes")


def _convert_storage_keys(keys: tuple[BytesLike, ...]) -> tuple[Hash32, ...]:
    return tuple(as_hash32(k) for k in keys)


@attrs.define(frozen=True)
class AccessListItem:
    """Single entry in an EIP-2930 access list."""

    address: Address = attrs.field(
        converter=as_address, validator=_validate_access_list_address
    )
    storage_keys: tuple[Hash32, ...] = attrs.field(
        factory=tuple, converter=_convert_storage_keys
    )

    def as_rlp_list(self) -> list:
        return [bytes(self.address), [bytes(k) for k in self.storage_keys]]

    @classmethod
    def create(
        cls,
        address: BytesLike,
        storage_keys: tuple[BytesLike, ...] = (),
    ) -> "AccessListItem":
        """Create an AccessListItem with automatic type coercion."""
        return cls(address=address, storage_keys=storage_keys)


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2


def _validate_signature_r(
    instance: "Signature", attribute: attrs.Attribute, value: int
) -> None:
    if not (0 < value < SECP256K1_N):
        raise ValueError(f"signature r must be in range (0, secp256k1_n), got {value}")


def _validate_signature_s(
    instance: "Signature", attribute: attrs.Attribute, value: int
) -> None:
    if not (0 < value <= SECP256K1_HALF_N):
        raise ValueError(
            f"signature s must be in range (0, secp256k1_n/2] (low-s), got {value}"
        )


def _validate_signature_v(
    instance: "Signature", attribute: attrs.Attribute, value: int
) -> None:
    if value not in (0, 1, 27, 28):
        raise ValueError(f"signature v must be 0, 1, 27, or 28, got {value}")


@attrs.define(frozen=True)
class Signature:
    """65-byte secp256k1 signature (r || s || v).

    Validates:
    - r is in range (0, secp256k1_n)
    - s is in low-s canonical form: (0, secp256k1_n/2]
    - v is 0, 1, 27, or 28
    """

    r: int = attrs.field(validator=_validate_signature_r)
    s: int = attrs.field(validator=_validate_signature_s)
    v: int = attrs.field(validator=_validate_signature_v)

    def to_bytes(self) -> bytes:
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big") + bytes([self.v])

    @classmethod
    def from_bytes(cls, sig_bytes: bytes) -> "Signature":
        """Parse a 65-byte signature and validate r/s/v ranges.

        Raises:
            ValueError: If signature is not 65 bytes or values are out of range.
        """
        if len(sig_bytes) != 65:
            raise ValueError(f"signature must be 65 bytes, got {len(sig_bytes)}")
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")
        v = sig_bytes[64]
        return cls(r=r, s=s, v=v)


def _convert_calls(calls: tuple[Call, ...]) -> tuple[Call, ...]:
    return tuple(calls)


def _convert_access_list(
    items: tuple[AccessListItem, ...],
) -> tuple[AccessListItem, ...]:
    return tuple(items)


def _convert_tempo_auth_list(items: tuple[BytesLike, ...]) -> tuple[bytes, ...]:
    return tuple(as_bytes(x) for x in items)


@attrs.define(frozen=True)
class TempoTransaction:
    """
    Tempo Transaction (Type 0x76).

    An immutable, strongly-typed representation of a Tempo transaction.

    Features:
    - Four signature types: secp256k1, P256, WebAuthn, Keychain
    - 2D nonce system for parallel transactions
    - Gas sponsorship via fee payer
    - Call batching
    - Optional fee tokens
    - Transaction expiry windows
    - Access keys with spending limits

    Example:
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100_000,
            max_fee_per_gas=2_000_000_000,
            calls=(Call.create(to="0xRecipient...", value=1000),),
        )
        signed_tx = tx.sign("0xPrivateKey...")
    """

    TRANSACTION_TYPE: int = attrs.field(default=0x76, init=False, repr=False)
    FEE_PAYER_MAGIC_BYTE: int = attrs.field(default=0x78, init=False, repr=False)

    chain_id: int = 1
    max_priority_fee_per_gas: int = 0
    max_fee_per_gas: int = 0
    gas_limit: int = 21_000

    calls: tuple[Call, ...] = attrs.field(factory=tuple, converter=_convert_calls)
    access_list: tuple[AccessListItem, ...] = attrs.field(
        factory=tuple, converter=_convert_access_list
    )

    nonce_key: int = 0
    nonce: int = 0

    valid_before: Optional[int] = None
    valid_after: Optional[int] = None

    fee_token: Optional[Address] = attrs.field(
        default=None, converter=as_optional_address
    )

    sender_address: Optional[Address] = attrs.field(
        default=None, converter=as_optional_address
    )
    awaiting_fee_payer: bool = False

    fee_payer_signature: Optional[Signature | bytes] = None
    sender_signature: Optional[Signature | bytes] = None

    tempo_authorization_list: tuple[bytes, ...] = attrs.field(
        factory=tuple, converter=_convert_tempo_auth_list
    )

    # -------------------------------------------------------------------------
    # Factory methods
    # -------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        chain_id: int = 1,
        gas_limit: int = 21_000,
        max_fee_per_gas: int = 0,
        max_priority_fee_per_gas: int = 0,
        nonce: int = 0,
        nonce_key: int = 0,
        valid_before: Optional[int] = None,
        valid_after: Optional[int] = None,
        fee_token: Optional[BytesLike] = None,
        awaiting_fee_payer: bool = False,
        calls: tuple[Call, ...] = (),
        access_list: tuple[AccessListItem, ...] = (),
        tempo_authorization_list: tuple[BytesLike, ...] = (),
    ) -> "TempoTransaction":
        """
        Create a transaction with automatic type coercion.

        Args:
            chain_id: Chain ID (default: 1)
            gas_limit: Gas limit (default: 21_000)
            max_fee_per_gas: Max fee per gas in wei
            max_priority_fee_per_gas: Max priority fee per gas in wei
            nonce: Transaction nonce
            nonce_key: Nonce key for 2D nonce system
            valid_before: Expiration timestamp (optional)
            valid_after: Activation timestamp (optional)
            fee_token: Fee token address as hex string or bytes (optional)
            awaiting_fee_payer: Whether transaction awaits fee payer signature
            calls: Tuple of Call objects
            access_list: Tuple of AccessListItem objects
            tempo_authorization_list: Tuple of authorization bytes

        Returns:
            New TempoTransaction instance
        """
        return cls(
            chain_id=chain_id,
            gas_limit=gas_limit,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            nonce=nonce,
            nonce_key=nonce_key,
            valid_before=valid_before,
            valid_after=valid_after,
            fee_token=fee_token,
            awaiting_fee_payer=awaiting_fee_payer,
            calls=calls,
            access_list=access_list,
            tempo_authorization_list=tempo_authorization_list,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "TempoTransaction":
        """
        Parse a transaction from a dict with camelCase or snake_case keys.

        Supports legacy single-call format (to/value/data) and batched calls format.
        """

        def get_key(*keys, default=None):
            for key in keys:
                if key in d:
                    return d[key]
            return default

        chain_id = get_key("chainId", "chain_id", default=1)
        max_priority_fee = get_key(
            "maxPriorityFeePerGas", "max_priority_fee_per_gas", default=0
        )
        max_fee = get_key("maxFeePerGas", "max_fee_per_gas", default=0)
        gas_limit = get_key("gas", "gasLimit", "gas_limit", default=21_000)

        calls_data = get_key("calls", default=[])
        if not calls_data:
            to_addr = get_key("to", default="")
            value = get_key("value", default=0)
            data = get_key("data", "input", default="0x")
            if to_addr or value or (data and data != "0x"):
                calls_data = [{"to": to_addr, "value": value, "data": data}]

        calls = tuple(
            Call.create(
                to=call.get("to", "") or b"",
                value=call.get("value", 0),
                data=call.get("data", call.get("input", "0x")),
            )
            for call in calls_data
        )

        access_list_data = get_key("accessList", "access_list", default=[])
        access_list = tuple(
            AccessListItem.create(
                address=item["address"],
                storage_keys=tuple(
                    item.get("storageKeys", item.get("storage_keys", []))
                ),
            )
            for item in access_list_data
        )

        fee_token = as_optional_address(get_key("feeToken", "fee_token"))

        tempo_auth = get_key(
            "tempoAuthorizationList",
            "tempo_authorization_list",
            "aaAuthorizationList",
            "aa_authorization_list",
            default=[],
        )

        return cls(
            chain_id=chain_id,
            max_priority_fee_per_gas=max_priority_fee,
            max_fee_per_gas=max_fee,
            gas_limit=gas_limit,
            calls=calls,
            access_list=access_list,
            nonce_key=get_key("nonceKey", "nonce_key", default=0),
            nonce=get_key("nonce", default=0),
            valid_before=get_key("validBefore", "valid_before"),
            valid_after=get_key("validAfter", "valid_after"),
            fee_token=fee_token,
            awaiting_fee_payer=bool(
                get_key("_will_have_fee_payer", "awaiting_fee_payer", default=False)
            ),
            tempo_authorization_list=tuple(as_bytes(x) for x in tempo_auth),
        )

    def validate(self, *, require_sender: bool = False) -> None:
        """Validate the transaction fields."""
        if self.chain_id <= 0:
            raise ValueError("chain_id must be > 0")
        if self.gas_limit <= 0:
            raise ValueError("gas_limit must be > 0")
        if self.max_priority_fee_per_gas < 0:
            raise ValueError("max_priority_fee_per_gas must be >= 0")
        if self.max_fee_per_gas < 0:
            raise ValueError("max_fee_per_gas must be >= 0")
        if (
            self.max_fee_per_gas
            and self.max_priority_fee_per_gas > self.max_fee_per_gas
        ):
            raise ValueError("max_priority_fee_per_gas cannot exceed max_fee_per_gas")
        if self.nonce < 0:
            raise ValueError("nonce must be >= 0")
        if self.nonce_key < 0:
            raise ValueError("nonce_key must be >= 0")
        if not self.calls:
            raise ValueError("at least one call is required")
        if require_sender and not self.sender_address:
            raise ValueError("sender_address is required")
        if self.fee_payer_signature is not None and not self.sender_address:
            raise ValueError("fee_payer_signature requires sender_address")
        if self.valid_before is not None and self.valid_after is not None:
            if self.valid_after > self.valid_before:
                raise ValueError("valid_after cannot be greater than valid_before")

    def _has_fee_payer(self) -> bool:
        return self.fee_payer_signature is not None or self.awaiting_fee_payer

    def _encode_optional_uint(self, v: Optional[int]) -> bytes | int:
        return b"" if v is None else v

    def get_signing_hash(self, for_fee_payer: bool = False) -> bytes:
        """
        Get the hash to sign.

        Args:
            for_fee_payer: If True, compute fee payer hash (0x78), else sender hash (0x76)

        Returns:
            32-byte hash to sign
        """
        if for_fee_payer:
            return self._signing_hash_fee_payer()
        return self._signing_hash_sender()

    def _signing_hash_sender(self) -> bytes:
        self.validate()
        has_fee_payer = self._has_fee_payer()

        fields = [
            self.chain_id,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            [c.as_rlp_list() for c in self.calls],
            [a.as_rlp_list() for a in self.access_list],
            self.nonce_key,
            self.nonce,
            self._encode_optional_uint(self.valid_before),
            self._encode_optional_uint(self.valid_after),
            b""
            if has_fee_payer
            else (bytes(self.fee_token) if self.fee_token else b""),
            bytes([0x00]) if has_fee_payer else b"",
            list(self.tempo_authorization_list),
        ]

        return keccak(bytes([self.TRANSACTION_TYPE]) + rlp.encode(fields))

    def _signing_hash_fee_payer(self) -> bytes:
        self.validate(require_sender=True)

        fields = [
            self.chain_id,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            [c.as_rlp_list() for c in self.calls],
            [a.as_rlp_list() for a in self.access_list],
            self.nonce_key,
            self.nonce,
            self._encode_optional_uint(self.valid_before),
            self._encode_optional_uint(self.valid_after),
            bytes(self.fee_token) if self.fee_token else b"",
            bytes(self.sender_address),  # type: ignore[arg-type]
            list(self.tempo_authorization_list),
        ]

        return keccak(bytes([self.FEE_PAYER_MAGIC_BYTE]) + rlp.encode(fields))

    def encode(self) -> bytes:
        """
        Encode complete transaction: 0x76 || rlp([14 fields])

        Returns:
            Encoded transaction with type prefix
        """
        self.validate()

        def sig_to_bytes(sig: Optional[Signature | bytes]) -> bytes:
            if sig is None:
                return b""
            if isinstance(sig, bytes):
                return sig
            return sig.to_bytes()

        sender_sig = sig_to_bytes(self.sender_signature)
        fee_payer_sig = sig_to_bytes(self.fee_payer_signature)

        fields = [
            self.chain_id,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            [c.as_rlp_list() for c in self.calls],
            [a.as_rlp_list() for a in self.access_list],
            self.nonce_key,
            self.nonce,
            self._encode_optional_uint(self.valid_before),
            self._encode_optional_uint(self.valid_after),
            bytes(self.fee_token) if self.fee_token else b"",
            fee_payer_sig,
            list(self.tempo_authorization_list),
            sender_sig,
        ]

        return bytes([self.TRANSACTION_TYPE]) + rlp.encode(fields)

    def hash(self) -> bytes:
        """Get transaction hash."""
        return keccak(self.encode())

    def vrs(self) -> tuple[Optional[int], Optional[int], Optional[int]]:
        """Get v, r, s values for secp256k1 signatures.

        Returns (None, None, None) if signature is not a Signature object
        (e.g., for keychain signatures stored as raw bytes).
        """
        if isinstance(self.sender_signature, Signature):
            return (
                self.sender_signature.v,
                self.sender_signature.r,
                self.sender_signature.s,
            )
        return (None, None, None)

    def sign(self, private_key: str, for_fee_payer: bool = False) -> "TempoTransaction":
        """
        Sign the transaction with secp256k1 private key.

        Returns a new TempoTransaction with the signature applied.

        Args:
            private_key: Private key as hex string
            for_fee_payer: If True, sign as fee payer; else sign as sender
        """
        account = Account.from_key(private_key)

        if for_fee_payer:
            msg_hash = self.get_signing_hash(for_fee_payer=True)
            signed_msg = account.unsafe_sign_hash(msg_hash)
            sig = Signature(r=signed_msg.r, s=signed_msg.s, v=signed_msg.v)
            return attrs.evolve(self, fee_payer_signature=sig)
        else:
            msg_hash = self.get_signing_hash(for_fee_payer=False)
            signed_msg = account.unsafe_sign_hash(msg_hash)
            sig = Signature(r=signed_msg.r, s=signed_msg.s, v=signed_msg.v)
            sender_addr = as_address(account.address)
            return attrs.evolve(self, sender_signature=sig, sender_address=sender_addr)
