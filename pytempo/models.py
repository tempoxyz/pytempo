"""Strongly-typed data models for Tempo transactions."""

from dataclasses import dataclass, field, replace
from typing import Optional

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


@dataclass(frozen=True)
class Call:
    """Single call in a batch transaction."""

    to: Address
    value: int
    data: bytes

    def validate(self) -> None:
        if self.value < 0:
            raise ValueError("call.value must be >= 0")
        if len(bytes(self.to)) not in (0, 20):
            raise ValueError(
                "call.to must be 20 bytes (or empty for contract creation)"
            )

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
        return cls(
            to=as_address(to),
            value=value,
            data=as_bytes(data),
        )


@dataclass(frozen=True)
class AccessListItem:
    """Single entry in an EIP-2930 access list."""

    address: Address
    storage_keys: tuple[Hash32, ...]

    def validate(self) -> None:
        if len(bytes(self.address)) != 20:
            raise ValueError("access list address must be 20 bytes")
        for key in self.storage_keys:
            if len(bytes(key)) != 32:
                raise ValueError("storage key must be 32 bytes")

    def as_rlp_list(self) -> list:
        return [bytes(self.address), [bytes(k) for k in self.storage_keys]]

    @classmethod
    def create(
        cls,
        address: BytesLike,
        storage_keys: tuple[BytesLike, ...] = (),
    ) -> "AccessListItem":
        """Create an AccessListItem with automatic type coercion."""
        return cls(
            address=as_address(address),
            storage_keys=tuple(as_hash32(k) for k in storage_keys),
        )


@dataclass(frozen=True)
class Signature:
    """65-byte secp256k1 signature (r || s || v)."""

    r: int
    s: int
    v: int

    def to_bytes(self) -> bytes:
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big") + bytes([self.v])

    @classmethod
    def from_bytes(cls, sig_bytes: bytes) -> "Signature":
        if len(sig_bytes) != 65:
            raise ValueError(f"signature must be 65 bytes, got {len(sig_bytes)}")
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")
        v = sig_bytes[64]
        return cls(r=r, s=s, v=v)


@dataclass(frozen=True)
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
        tx = (TempoTransaction.create(chain_id=42429)
            .with_gas(100_000)
            .with_max_fee_per_gas(2_000_000_000)
            .add_call("0xRecipient...", value=1000)
            .sign("0xPrivateKey..."))
    """

    TRANSACTION_TYPE: int = field(default=0x76, init=False, repr=False)
    FEE_PAYER_MAGIC_BYTE: int = field(default=0x78, init=False, repr=False)

    chain_id: int = 1
    max_priority_fee_per_gas: int = 0
    max_fee_per_gas: int = 0
    gas_limit: int = 21_000

    calls: tuple[Call, ...] = ()
    access_list: tuple[AccessListItem, ...] = ()

    nonce_key: int = 0
    nonce: int = 0

    valid_before: Optional[int] = None
    valid_after: Optional[int] = None

    fee_token: Optional[Address] = None

    sender_address: Optional[Address] = None
    awaiting_fee_payer: bool = False

    fee_payer_signature: Optional[Signature] = None
    sender_signature: Optional[Signature] = None

    tempo_authorization_list: tuple[bytes, ...] = ()

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
            fee_token=as_optional_address(fee_token),
            awaiting_fee_payer=awaiting_fee_payer,
            calls=tuple(calls),
            access_list=tuple(access_list),
            tempo_authorization_list=tuple(
                as_bytes(x) for x in tempo_authorization_list
            ),
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

    # -------------------------------------------------------------------------
    # Chainable immutable mutators
    # -------------------------------------------------------------------------

    def with_gas(self, gas_limit: int) -> "TempoTransaction":
        """Return a new transaction with updated gas limit."""
        return replace(self, gas_limit=gas_limit)

    def with_max_fee_per_gas(self, max_fee: int) -> "TempoTransaction":
        """Return a new transaction with updated max fee per gas."""
        return replace(self, max_fee_per_gas=max_fee)

    def with_max_priority_fee_per_gas(self, priority_fee: int) -> "TempoTransaction":
        """Return a new transaction with updated max priority fee per gas."""
        return replace(self, max_priority_fee_per_gas=priority_fee)

    def with_nonce(self, nonce: int) -> "TempoTransaction":
        """Return a new transaction with updated nonce."""
        return replace(self, nonce=nonce)

    def with_nonce_key(self, nonce_key: int) -> "TempoTransaction":
        """Return a new transaction with updated nonce key."""
        return replace(self, nonce_key=nonce_key)

    def with_valid_before(self, timestamp: int) -> "TempoTransaction":
        """Return a new transaction with expiration timestamp."""
        return replace(self, valid_before=timestamp)

    def with_valid_after(self, timestamp: int) -> "TempoTransaction":
        """Return a new transaction with activation timestamp."""
        return replace(self, valid_after=timestamp)

    def with_fee_token(self, token: BytesLike) -> "TempoTransaction":
        """Return a new transaction with fee token address."""
        return replace(self, fee_token=as_address(token))

    def sponsored(self, enabled: bool = True) -> "TempoTransaction":
        """Return a new transaction marked as awaiting fee payer signature."""
        return replace(self, awaiting_fee_payer=enabled)

    def add_call(
        self,
        to: BytesLike,
        value: int = 0,
        data: BytesLike = b"",
    ) -> "TempoTransaction":
        """Return a new transaction with an additional call."""
        new_call = Call.create(to=to, value=value, data=data)
        return replace(self, calls=self.calls + (new_call,))

    def add_contract_creation(
        self,
        value: int = 0,
        data: BytesLike = b"",
    ) -> "TempoTransaction":
        """Return a new transaction with a contract creation call."""
        new_call = Call.create(to=b"", value=value, data=data)
        return replace(self, calls=self.calls + (new_call,))

    def add_access_list_item(
        self,
        address: BytesLike,
        storage_keys: tuple[BytesLike, ...] = (),
    ) -> "TempoTransaction":
        """Return a new transaction with an additional access list entry."""
        new_item = AccessListItem.create(address=address, storage_keys=storage_keys)
        return replace(self, access_list=self.access_list + (new_item,))

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
        for call in self.calls:
            call.validate()
        for item in self.access_list:
            item.validate()
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

        sender_sig = self.sender_signature.to_bytes() if self.sender_signature else b""
        fee_payer_sig = (
            self.fee_payer_signature.to_bytes() if self.fee_payer_signature else b""
        )

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
        """Get v, r, s values for secp256k1 signatures."""
        if self.sender_signature:
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
            return replace(self, fee_payer_signature=sig)
        else:
            msg_hash = self.get_signing_hash(for_fee_payer=False)
            signed_msg = account.unsafe_sign_hash(msg_hash)
            sig = Signature(r=signed_msg.r, s=signed_msg.s, v=signed_msg.v)
            sender_addr = as_address(account.address)
            return replace(self, sender_signature=sig, sender_address=sender_addr)
