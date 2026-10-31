"""Strongly-typed data models for Tempo transactions."""

from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

import attrs
import rlp
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from .types import (
    Address,
    BytesLike,
    Hash32,
    as_address,
    as_bytes,
    as_hash32,
    as_optional_address,
)

if TYPE_CHECKING:
    from .keychain import KeychainSignature, SignedKeyAuthorization


def _validate_call_value(
    instance: Call, attribute: attrs.Attribute, value: int
) -> None:
    if value < 0:
        raise ValueError("call.value must be >= 0")


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
    ) -> Call:
        """Create a Call with automatic type coercion."""
        return cls(to=to, value=value, data=data)


def _validate_access_list_address(
    instance: AccessListItem, attribute: attrs.Attribute, value: Address
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
    ) -> AccessListItem:
        """Create an AccessListItem with automatic type coercion."""
        return cls(address=address, storage_keys=storage_keys)


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2


def _validate_signature_r(
    instance: Signature, attribute: attrs.Attribute, value: int
) -> None:
    if not (0 < value < SECP256K1_N):
        raise ValueError(f"signature r must be in range (0, secp256k1_n), got {value}")


def _validate_signature_s(
    instance: Signature, attribute: attrs.Attribute, value: int
) -> None:
    if not (0 < value <= SECP256K1_HALF_N):
        raise ValueError(
            f"signature s must be in range (0, secp256k1_n/2] (low-s), got {value}"
        )


def _validate_signature_v(
    instance: Signature, attribute: attrs.Attribute, value: int
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

    def to_rlp_list(self) -> list:
        """Return [v, r, s] for RLP encoding as a list (used for fee_payer_signature).

        Note: Tempo RLP encoding uses [v, r, s] order (via write_rlp_vrs).
        """
        v_normalized = self.v if self.v in (0, 1) else self.v - 27
        return [v_normalized, self.r, self.s]

    def recover(self, msg_hash: bytes) -> str:
        """Recover the checksummed address that signed the 32-byte *msg_hash*.

        Raises:
            ValueError: If *msg_hash* is not 32 bytes or no key recovers.
        """
        if len(msg_hash) != 32:
            raise ValueError(f"msg_hash must be 32 bytes, got {len(msg_hash)}")
        v = self.v if self.v in (0, 1) else self.v - 27
        try:
            recovered = Account._recover_hash(msg_hash, vrs=(v, self.r, self.s))
        except Exception as e:  # eth_keys raises BadSignature for unrecoverable r
            raise ValueError(f"signature recovery failed: {e}") from e
        return to_checksum_address(recovered)

    @classmethod
    def from_bytes(cls, sig_bytes: bytes) -> Signature:
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

    Example::

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

    valid_before: int | None = None
    valid_after: int | None = None

    fee_token: Address | None = attrs.field(default=None, converter=as_optional_address)

    sender_address: Address | None = attrs.field(
        default=None, converter=as_optional_address
    )
    awaiting_fee_payer: bool = False

    fee_payer_signature: Signature | None = None
    sender_signature: Signature | KeychainSignature | None = None

    tempo_authorization_list: tuple[bytes, ...] = attrs.field(
        factory=tuple, converter=_convert_tempo_auth_list
    )

    key_authorization: SignedKeyAuthorization | None = None

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
        valid_before: int | None = None,
        valid_after: int | None = None,
        fee_token: BytesLike | None = None,
        awaiting_fee_payer: bool = False,
        calls: tuple[Call, ...] = (),
        access_list: tuple[AccessListItem, ...] = (),
        tempo_authorization_list: tuple[BytesLike, ...] = (),
        key_authorization: SignedKeyAuthorization | None = None,
    ) -> TempoTransaction:
        """Create a transaction with automatic type coercion."""
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
            key_authorization=key_authorization,
        )

    @classmethod
    def from_dict(cls, d: dict) -> TempoTransaction:
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
        # 0 encodes as absent, so only a window with both ends set must be non-empty.
        if self.valid_before and self.valid_after:
            # tempo-primitives requires valid_before > valid_after (strictly).
            if self.valid_after >= self.valid_before:
                raise ValueError(
                    "valid_after cannot be greater than or equal to valid_before"
                )

    # -------------------------------------------------------------------------
    # Decoding and recovery
    # -------------------------------------------------------------------------

    @classmethod
    def decode(cls, raw: BytesLike) -> TempoTransaction:
        """Decode a signed ``0x76`` transaction as sent to ``eth_sendRawTransaction``.

        Parses every field and recovers the sender (the root account for
        keychain signatures) into ``sender_address``; a fee payer signature
        must recover too (see :meth:`recover_fee_payer`). Decoding is as strict
        as tempo-primitives: it rejects a wrong type byte, truncated input,
        trailing bytes (including the legacy tempo.ts fee payer trailer),
        non-canonical RLP or integers, out-of-range values, high-s signatures,
        ``v`` outside ``{0, 1, 27, 28}``, empty calls, a CREATE that is not
        the first call, and ``valid_after >= valid_before``. It also applies
        :meth:`validate`. The result re-encodes to exactly *raw*, so
        :meth:`hash` is ``keccak256(raw)``.

        Raises:
            ValueError: If *raw* is not a valid signed Tempo transaction.
            NotImplementedError: If it is well-formed but uses something pytempo
                cannot represent: P256, WebAuthn or configurable account
                signatures (sender, keychain inner key or key authorization),
                or a non-empty ``tempo_authorization_list``.
        """
        from .keychain import KeyAuthorization, SignedKeyAuthorization

        data = as_bytes(raw)
        if not data:
            raise ValueError("transaction is empty")
        if data[0] != _TEMPO_TX_TYPE:
            raise ValueError(
                f"expected transaction type {_TEMPO_TX_TYPE:#04x}, got {data[0]:#04x}"
            )
        try:
            items = rlp.decode(data[1:], strict=True)
        except rlp.exceptions.DecodingError as e:
            raise ValueError(f"invalid transaction RLP: {e}") from e
        items = _rlp_list(items, "transaction")

        # 13 fields, an optional key authorization (always an RLP list), then
        # the sender signature bytes.
        if len(items) == 14:
            key_auth_item = None
        elif len(items) == 15:
            key_auth_item = _rlp_list(items[13], "key_authorization")
        else:
            raise ValueError(
                f"transaction must have 14 or 15 RLP fields, got {len(items)}"
            )
        sender_sig_bytes = _rlp_bytes(items[-1], "sender signature")

        chain_id = _rlp_uint(items[0], "chain_id", 64)
        max_priority_fee_per_gas = _rlp_uint(items[1], "max_priority_fee_per_gas", 128)
        max_fee_per_gas = _rlp_uint(items[2], "max_fee_per_gas", 128)
        gas_limit = _rlp_uint(items[3], "gas_limit", 64)
        calls = tuple(
            _decode_call(item, f"calls[{i}]")
            for i, item in enumerate(_rlp_list(items[4], "calls"))
        )
        access_list = tuple(
            _decode_access_list_item(item, f"access_list[{i}]")
            for i, item in enumerate(_rlp_list(items[5], "access_list"))
        )
        nonce_key = _rlp_uint(items[6], "nonce_key", 256)
        nonce = _rlp_uint(items[7], "nonce", 64)
        valid_before = _rlp_uint(items[8], "valid_before", 64) or None
        valid_after = _rlp_uint(items[9], "valid_after", 64) or None
        fee_token = _rlp_bytes(items[10], "fee_token")
        if fee_token and len(fee_token) != 20:
            raise ValueError(f"fee_token must be 20 bytes, got {len(fee_token)}")
        fee_payer_signature = _decode_fee_payer_signature(items[11])

        auth_list = _rlp_list(items[12], "tempo_authorization_list")
        for i, entry in enumerate(auth_list):
            _rlp_list(entry, f"tempo_authorization_list[{i}]")
        if auth_list:
            raise NotImplementedError(
                "decoding a non-empty tempo_authorization_list is not supported "
                "by pytempo"
            )

        if not calls:
            raise ValueError("calls list cannot be empty")
        for call in calls[1:]:
            if not bytes(call.to):
                raise ValueError(
                    "only one CREATE call is allowed per transaction, and it "
                    "must be the first call of the batch"
                )

        key_authorization = None
        if key_auth_item is not None:
            if len(key_auth_item) != 2:
                raise ValueError(
                    "key_authorization must be [authorization, signature], "
                    f"got {len(key_auth_item)} items"
                )
            authorization = KeyAuthorization.from_rlp(key_auth_item[0])
            ka_sig = _rlp_bytes(key_auth_item[1], "key_authorization signature")
            if len(ka_sig) != 65:
                if len(ka_sig) >= 2 and ka_sig[0] in (0x03, 0x04):
                    raise ValueError(
                        "key_authorization signature cannot be a keychain signature"
                    )
                _raise_for_typed_signature(ka_sig, "key_authorization signature")
            key_authorization = SignedKeyAuthorization(
                authorization=authorization, signature=Signature.from_bytes(ka_sig)
            )

        sender_signature = _decode_sender_signature(sender_sig_bytes)

        tx = cls(
            chain_id=chain_id,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas_limit=gas_limit,
            calls=calls,
            access_list=access_list,
            nonce_key=nonce_key,
            nonce=nonce,
            valid_before=valid_before,
            valid_after=valid_after,
            fee_token=fee_token or None,
            fee_payer_signature=(
                None
                if fee_payer_signature is _AWAITING_FEE_PAYER
                else fee_payer_signature
            ),
            awaiting_fee_payer=fee_payer_signature is _AWAITING_FEE_PAYER,
            sender_signature=sender_signature,
            key_authorization=key_authorization,
        )
        tx = attrs.evolve(tx, sender_address=tx.recover_sender())
        tx.recover_fee_payer()
        tx.validate()

        if tx.encode() != data:
            raise ValueError("non-canonical transaction encoding")
        return tx

    def recover_sender(self) -> str:
        """Recover the checksummed sender from ``sender_signature``.

        For a keychain signature this is its root account, once the access
        key's inner signature has been checked to recover a key.

        Raises:
            ValueError: If there is no sender signature or it does not recover.
        """
        from .keychain import KeychainSignature

        sig = self.sender_signature
        if sig is None:
            raise ValueError("transaction has no sender signature")
        unsigned = attrs.evolve(
            self,
            sender_signature=None,
            fee_payer_signature=None,
            awaiting_fee_payer=self._has_fee_payer(),
        )
        msg_hash = unsigned.get_signing_hash()
        if isinstance(sig, KeychainSignature):
            sig.recover_key_id(msg_hash)
            return to_checksum_address(bytes(sig.root_account))
        return sig.recover(msg_hash)

    def recover_fee_payer(self) -> str | None:
        """Recover the checksummed fee payer, or ``None`` if not sponsored.

        The fee payer signs the ``0x78`` payload committing to the sender
        (recovered from ``sender_signature`` when present, else
        ``sender_address``) and the fee token.

        Raises:
            ValueError: If the fee payer signature does not recover.
        """
        if self.fee_payer_signature is None:
            return None
        sender = (
            self.recover_sender()
            if self.sender_signature is not None
            else self.sender_address
        )
        if not sender:
            raise ValueError("fee payer recovery requires the sender")
        msg_hash = attrs.evolve(self, sender_address=sender).get_signing_hash(
            for_fee_payer=True
        )
        return self.fee_payer_signature.recover(msg_hash)

    def _has_fee_payer(self) -> bool:
        return self.fee_payer_signature is not None or self.awaiting_fee_payer

    def _encode_optional_uint(self, v: int | None) -> bytes | int:
        return b"" if v is None else v

    def get_signing_hash(self, for_fee_payer: bool = False) -> bytes:
        """
        Get the hash to sign.

        Args:
            for_fee_payer: If True, compute fee payer hash (0x78), else sender hash (0x76)

        Returns:
            32-byte hash to sign
        """
        return keccak(self.encode_for_signing(for_fee_payer=for_fee_payer))

    def encode_for_signing(self, for_fee_payer: bool = False) -> bytes:
        """Encode the transaction preimage used for signing.

        This is the exact byte sequence hashed by :meth:`get_signing_hash`.
        It is useful for protocols that bind transaction context before the
        transaction is broadcast.
        """
        if for_fee_payer:
            return self._encode_for_fee_payer_signing()
        return self._encode_for_sender_signing()

    def _encode_for_sender_signing(self) -> bytes:
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

        if self.key_authorization is not None:
            fields.append(self.key_authorization.as_rlp_payload())

        return bytes([self.TRANSACTION_TYPE]) + rlp.encode(fields)

    def _encode_for_fee_payer_signing(self) -> bytes:
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

        if self.key_authorization is not None:
            fields.append(self.key_authorization.as_rlp_payload())

        return bytes([self.FEE_PAYER_MAGIC_BYTE]) + rlp.encode(fields)

    def encode(self) -> bytes:
        """Encode complete transaction: ``0x76 || rlp([fields])``."""
        self.validate()

        sender_sig = self.sender_signature.to_bytes() if self.sender_signature else b""
        # Before the fee payer co-signs, a sponsored transaction carries the 0x00
        # marker and no fee token (the fee payer picks it), as ox serializes it.
        awaiting = self.awaiting_fee_payer and self.fee_payer_signature is None
        if self.fee_payer_signature:
            fee_payer_sig = self.fee_payer_signature.to_rlp_list()
        else:
            fee_payer_sig = bytes([0x00]) if awaiting else b""

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
            bytes(self.fee_token) if self.fee_token and not awaiting else b"",
            fee_payer_sig,
            list(self.tempo_authorization_list),
        ]

        if self.key_authorization is not None:
            fields.append(self.key_authorization.as_rlp_payload())
            fields.append(sender_sig)
        else:
            fields.append(sender_sig)

        return bytes([self.TRANSACTION_TYPE]) + rlp.encode(fields)

    def hash(self) -> bytes:
        """Get transaction hash."""
        return keccak(self.encode())

    def vrs(self) -> tuple[int | None, int | None, int | None]:
        """Get v, r, s values for secp256k1 signatures.

        Returns (None, None, None) for keychain signatures.
        """
        if isinstance(self.sender_signature, Signature):
            return (
                self.sender_signature.v,
                self.sender_signature.r,
                self.sender_signature.s,
            )
        return (None, None, None)

    def sign(self, private_key: str, for_fee_payer: bool = False) -> TempoTransaction:
        """Sign the transaction with secp256k1 private key.

        Returns a new TempoTransaction with the signature applied.

        Args:
            private_key: Private key as hex string (as used by
                ``Account.from_key``).
            for_fee_payer: If True, sign as fee payer; else sign as sender.
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

    def sign_access_key(
        self,
        access_key_private_key: str,
        root_account: str,
    ) -> TempoTransaction:
        """Sign the transaction using an access key (Keychain signature).

        Returns a new TempoTransaction with the keychain signature applied.

        Args:
            access_key_private_key: Private key of the access key (hex string,
                as used by ``Account.from_key``).
            root_account: Address of the root account (hex string).
        """
        from .keychain import KeychainSignature

        root_addr = as_address(root_account)
        tx_with_sender = attrs.evolve(self, sender_address=root_addr)
        msg_hash = tx_with_sender.get_signing_hash(for_fee_payer=False)
        sig = KeychainSignature.sign(msg_hash, access_key_private_key, root_addr)
        return attrs.evolve(tx_with_sender, sender_signature=sig)

    def to_estimate_gas_request(
        self,
        sender: str,
        key_id: str | None = None,
        key_authorization: dict | SignedKeyAuthorization | None = None,
    ) -> dict:
        """Build an eth_estimateGas request dict from this transaction.

        A single call is sent as ``to``/``data``/``value``. A batch is sent as
        ``calls`` so the node estimates every call, not just the first.

        Args:
            sender: Address of the sender (hex string).
            key_id: Optional access key address for keychain signature gas estimation.
            key_authorization: Optional :class:`SignedKeyAuthorization` or
                pre-built JSON dict.
        """
        if not self.calls:
            raise ValueError("Transaction must have at least one call")

        request: dict = {"from": sender}

        if len(self.calls) == 1:
            call = self.calls[0]
            to_addr = bytes(call.to)
            request["data"] = "0x" + call.data.hex() if call.data else "0x"
            if to_addr:
                request["to"] = to_checksum_address(to_addr)
            if call.value:
                request["value"] = hex(call.value)
        else:
            request["calls"] = [
                {
                    "to": to_checksum_address(bytes(c.to)) if bytes(c.to) else None,
                    "value": hex(c.value),
                    "data": "0x" + c.data.hex(),
                }
                for c in self.calls
            ]

        if key_id is not None:
            request["keyId"] = key_id

        if key_authorization is not None:
            if isinstance(key_authorization, dict):
                request["keyAuthorization"] = key_authorization
            else:
                request["keyAuthorization"] = key_authorization.to_json()

        return request


# -----------------------------------------------------------------------------
# Decoding helpers (TempoTransaction.decode)
# -----------------------------------------------------------------------------

_TEMPO_TX_TYPE = 0x76
_SIGNATURE_TYPE_P256 = 0x01
_SIGNATURE_TYPE_WEBAUTHN = 0x02
_SIGNATURE_TYPE_KEYCHAIN_V1 = 0x03
_SIGNATURE_TYPE_KEYCHAIN_V2 = 0x04
_SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT = 0x05
_SECP256K1_SIGNATURE_LENGTH = 65
_P256_SIGNATURE_LENGTH = 129
_MAX_WEBAUTHN_SIGNATURE_LENGTH = 2048


def _rlp_bytes(item: object, name: str) -> bytes:
    if not isinstance(item, bytes):
        raise ValueError(f"{name} must be an RLP string, got a list")
    return item


def _rlp_list(item: object, name: str) -> list:
    if not isinstance(item, list):
        raise ValueError(f"{name} must be an RLP list, got a string")
    return item


def _rlp_uint(item: object, name: str, bits: int) -> int:
    b = _rlp_bytes(item, name)
    if b[:1] == b"\x00":
        raise ValueError(f"{name} has leading zero bytes (non-canonical integer)")
    if len(b) > bits // 8:
        raise ValueError(f"{name} exceeds uint{bits}")
    return int.from_bytes(b, "big")


def _rlp_address(item: object, name: str) -> bytes:
    b = _rlp_bytes(item, name)
    if len(b) != 20:
        raise ValueError(f"{name} must be 20 bytes, got {len(b)}")
    return b


def _decode_call(item: object, name: str) -> Call:
    fields = _rlp_list(item, name)
    if len(fields) != 3:
        raise ValueError(f"{name} must be [to, value, data], got {len(fields)} items")
    to = _rlp_bytes(fields[0], f"{name}.to")
    if to and len(to) != 20:
        raise ValueError(f"{name}.to must be empty or 20 bytes, got {len(to)}")
    return Call(
        to=to,
        value=_rlp_uint(fields[1], f"{name}.value", 256),
        data=_rlp_bytes(fields[2], f"{name}.data"),
    )


def _decode_access_list_item(item: object, name: str) -> AccessListItem:
    fields = _rlp_list(item, name)
    if len(fields) != 2:
        raise ValueError(
            f"{name} must be [address, storage_keys], got {len(fields)} items"
        )
    keys = []
    for i, key in enumerate(_rlp_list(fields[1], f"{name}.storage_keys")):
        b = _rlp_bytes(key, f"{name}.storage_keys[{i}]")
        if len(b) != 32:
            raise ValueError(f"{name}.storage_keys[{i}] must be 32 bytes")
        keys.append(b)
    return AccessListItem(
        address=_rlp_address(fields[0], f"{name}.address"), storage_keys=tuple(keys)
    )


_AWAITING_FEE_PAYER = object()


def _decode_fee_payer_signature(item: object) -> Signature | object | None:
    """Decode the fee payer field.

    Returns None when unsponsored, _AWAITING_FEE_PAYER for the 0x00 marker a
    sender writes before the fee payer co-signs, or the fee payer signature.
    """
    if item == b"":
        return None
    if item == b"\x00":
        return _AWAITING_FEE_PAYER
    if not isinstance(item, list):
        raise ValueError("fee_payer_signature must be an RLP list [v, r, s] or empty")
    if len(item) != 3:
        raise ValueError(
            f"fee_payer_signature must be [v, r, s], got {len(item)} items"
        )
    v = _rlp_uint(item[0], "fee_payer_signature.v", 8)
    if v not in (0, 1):
        raise ValueError(f"fee_payer_signature.v must be 0 or 1, got {v}")
    return Signature(
        r=_rlp_uint(item[1], "fee_payer_signature.r", 256),
        s=_rlp_uint(item[2], "fee_payer_signature.s", 256),
        v=v,
    )


def _raise_for_typed_signature(data: bytes, name: str) -> NoReturn:
    """Reject a typed (non-65-byte) primitive signature.

    Malformed envelopes raise ValueError; well-formed P256, WebAuthn and
    configurable account signatures raise NotImplementedError, since pytempo
    cannot recover them.
    """
    if len(data) < 2:
        raise ValueError(f"{name} is too short: expected type identifier + data")
    type_id, body = data[0], data[1:]
    if type_id == _SIGNATURE_TYPE_P256:
        if len(body) != _P256_SIGNATURE_LENGTH:
            raise ValueError(f"{name}: invalid P256 signature length")
        kind = "P256"
    elif type_id == _SIGNATURE_TYPE_WEBAUTHN:
        if not 128 <= len(body) <= _MAX_WEBAUTHN_SIGNATURE_LENGTH:
            raise ValueError(f"{name}: invalid WebAuthn signature length")
        kind = "WebAuthn"
    elif type_id == _SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT:
        kind = "configurable account"
    else:
        raise ValueError(f"{name}: unknown signature type identifier {type_id:#04x}")
    raise NotImplementedError(
        f"{name}: {kind} signatures are not supported by pytempo "
        "(only secp256k1 and secp256k1 keychain signatures can be recovered)"
    )


def _decode_sender_signature(data: bytes) -> Signature | KeychainSignature:
    from .keychain import KeychainSignature

    if not data:
        raise ValueError("sender signature is empty")
    if len(data) == _SECP256K1_SIGNATURE_LENGTH:
        return Signature.from_bytes(data)
    if len(data) >= 2 and data[0] in (
        _SIGNATURE_TYPE_KEYCHAIN_V1,
        _SIGNATURE_TYPE_KEYCHAIN_V2,
    ):
        if len(data) < 21:
            raise ValueError("keychain signature is too short for the root account")
        inner = data[21:]
        if len(inner) == _SECP256K1_SIGNATURE_LENGTH:
            return KeychainSignature.from_bytes(data)
        if len(inner) >= 2 and inner[0] in (
            _SIGNATURE_TYPE_KEYCHAIN_V1,
            _SIGNATURE_TYPE_KEYCHAIN_V2,
        ):
            raise ValueError("keychain signature cannot wrap another keychain")
        if (
            data[0] == _SIGNATURE_TYPE_KEYCHAIN_V1
            and inner[:1] == bytes([_SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT])
            and len(inner) >= 2
        ):
            raise ValueError(
                "keychain V1 signature cannot wrap a configurable account signature"
            )
        _raise_for_typed_signature(inner, "keychain inner signature")
    _raise_for_typed_signature(data, "sender signature")
