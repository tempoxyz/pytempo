"""Tempo AccountKeychain precompile: access key management and signing.

The AccountKeychain precompile manages access key authorizations and spending limits.
Access keys allow a separate key to sign transactions on behalf of a wallet.

Per Tempo spec, Keychain V2 signatures have format::

    0x04 || user_address (20 bytes) || inner_signature (65 bytes)

Where:

- 0x04 is the Keychain V2 signature type identifier
- user_address is the root account (the account the access key signs on behalf of)
- inner_signature is the secp256k1 signature from the access key (r || s || v)

The access key signs ``keccak256(0x04 || sig_hash || user_address)`` rather than
the raw sig_hash. The ``0x04`` domain separator prevents cross-scheme signature
confusion.

Total signature length: 86 bytes.

KeyAuthorization is used to provision access keys inline within a Tempo transaction.
The authorization is RLP-encoded and signed by the root account.
Format: ``[chain_id, key_type, key_id, expiry?, limits?]``
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, ClassVar

import attrs
import rlp
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from .types import (
    Address,
    BytesLike,
    Selector,
    as_address,
    as_selector,
    validate_nonempty_address,
)

if TYPE_CHECKING:
    from .models import Signature, TempoTransaction

# ---------------------------------------------------------------------------
# Signature type enum
# ---------------------------------------------------------------------------


class SignatureType(IntEnum):
    """Signature type for access keys."""

    SECP256K1 = 0
    P256 = 1
    WEBAUTHN = 2

    def to_json_name(self) -> str:
        return _SIG_TYPE_JSON_NAMES[self]


_SIG_TYPE_JSON_NAMES = {
    SignatureType.SECP256K1: "secp256k1",
    SignatureType.P256: "p256",
    SignatureType.WEBAUTHN: "webAuthn",
}


# ---------------------------------------------------------------------------
# Token limit
# ---------------------------------------------------------------------------


def _validate_u256(instance: object, attribute: object, value: int) -> None:
    if not (0 <= value <= 2**256 - 1):
        raise ValueError(f"limit must be in [0, 2**256 - 1], got {value}")


@attrs.define(frozen=True)
class TokenLimit:
    """Token spending limit for access keys.

    Defines a per-token spending limit for an access key provisioned via key_authorization.
    This limit is enforced by the AccountKeychain precompile when the key is used.

    Args:
        token: TIP20 token address
        limit: Maximum spending amount for this token (enforced over the key's lifetime)
    """

    token: Address = attrs.field(
        converter=as_address, validator=validate_nonempty_address
    )
    limit: int = attrs.field(validator=_validate_u256)

    def to_rlp(self) -> list:
        return [bytes(self.token), self.limit]


# ---------------------------------------------------------------------------
# Call scope
# ---------------------------------------------------------------------------

_WILDCARD_SELECTOR = Selector(b"\x00\x00\x00\x00")
_TIP20_PREFIX = bytes.fromhex("20C000000000000000000000")

# Allowed TIP-20 selectors for call-scoped access keys.
_TIP20_TRANSFER = Selector(bytes.fromhex("a9059cbb"))
_TIP20_APPROVE = Selector(bytes.fromhex("095ea7b3"))
_TIP20_TRANSFER_WITH_MEMO = Selector(bytes.fromhex("95777d59"))


def _validate_tip20_address(target: BytesLike) -> Address:
    addr = as_address(target)
    if not bytes(addr).startswith(_TIP20_PREFIX):
        raise ValueError(
            f"target must be a TIP20 address (prefix 0x20C0...00), "
            f"got 0x{bytes(addr)[:12].hex()}"
        )
    return addr


@attrs.define(frozen=True)
class CallScope:
    """Call scope restriction for access keys (TIP-1011).

    Restricts an access key to only call specific contract functions.
    Used in ``AccountKeychain.authorize_key()`` when ``allow_any_calls`` is False.

    Construct via the named constructors:

    - ``CallScope.unrestricted(target=...)`` — allow all functions on a target.
    - ``CallScope.transfer(target=...)`` — allow ``transfer`` on a TIP20 token.
    - ``CallScope.approve(target=...)`` — allow ``approve`` on a TIP20 token.
    - ``CallScope.transfer_with_memo(target=...)`` — allow ``transferWithMemo``
      on a TIP20 token.

    Args:
        target: Contract address the key is allowed to call.
        selector: 4-byte function selector. Only applicable for TIP20 tokens.
    """

    target: Address = attrs.field(
        converter=as_address, validator=validate_nonempty_address
    )
    selector: Selector = attrs.field(converter=as_selector)

    @classmethod
    def unrestricted(cls, *, target: BytesLike) -> CallScope:
        """Allow all functions on a target (any contract, including TIP20)."""
        return cls(target=target, selector=_WILDCARD_SELECTOR)

    @classmethod
    def transfer(cls, *, target: BytesLike) -> CallScope:
        """Allow ``transfer(address,uint256)`` on a TIP20 token target."""
        return cls(target=_validate_tip20_address(target), selector=_TIP20_TRANSFER)

    @classmethod
    def approve(cls, *, target: BytesLike) -> CallScope:
        """Allow ``approve(address,uint256)`` on a TIP20 token target."""
        return cls(target=_validate_tip20_address(target), selector=_TIP20_APPROVE)

    @classmethod
    def transfer_with_memo(cls, *, target: BytesLike) -> CallScope:
        """Allow ``transferWithMemo(address,uint256,bytes32)`` on a TIP20 token target."""
        return cls(
            target=_validate_tip20_address(target),
            selector=_TIP20_TRANSFER_WITH_MEMO,
        )


# ---------------------------------------------------------------------------
# Key authorization
# ---------------------------------------------------------------------------


def _convert_limits(
    value: tuple[TokenLimit, ...] | list[TokenLimit] | None,
) -> tuple[TokenLimit, ...] | None:
    return None if value is None else tuple(value)


def _validate_optional_expiry(
    instance: object, attribute: object, value: int | None
) -> None:
    if value is not None and value < 0:
        raise ValueError(f"expiry must be >= 0, got {value}")


@attrs.define(frozen=True)
class KeyAuthorization:
    """Key authorization for provisioning access keys.

    Used in TempoTransaction to add a new key to the AccountKeychain precompile.
    The transaction must be signed by the root key to authorize adding this access key.

    Args:
        key_id: Key identifier (address derived from the public key)
        chain_id: Chain ID for replay protection (0 = valid on any chain)
        key_type: Type of key being authorized (SignatureType.SECP256K1, P256, or WEBAUTHN)
        expiry: Unix timestamp when key expires (None = never expires)
        limits: Token spending limits (None = unlimited, () = no spending, tuple of :class:`TokenLimit` = specific limits)
    """

    key_id: Address = attrs.field(
        converter=as_address, validator=validate_nonempty_address
    )
    chain_id: int = attrs.field(default=0, validator=attrs.validators.ge(0))
    key_type: SignatureType = attrs.field(
        default=SignatureType.SECP256K1, converter=SignatureType
    )
    expiry: int | None = attrs.field(default=None, validator=_validate_optional_expiry)
    limits: tuple[TokenLimit, ...] | None = attrs.field(
        default=None, converter=_convert_limits
    )

    def as_rlp_payload(self) -> list:
        """Return the RLP-encodable list representation."""
        # Build list with required fields
        items: list = [self.chain_id, int(self.key_type), bytes(self.key_id)]

        # Add optional trailing fields
        if self.expiry is not None or self.limits is not None:
            items.append(self.expiry if self.expiry is not None else b"")

        if self.limits is not None:
            items.append([limit.to_rlp() for limit in self.limits])

        return items

    def rlp_encode(self) -> bytes:
        """RLP encode the key authorization."""
        return rlp.encode(self.as_rlp_payload())

    def signature_hash(self) -> bytes:
        """Compute the authorization message hash for signing."""
        return keccak(self.rlp_encode())

    def sign(self, private_key: str) -> SignedKeyAuthorization:
        """Sign the key authorization with the root account's private key.

        Args:
            private_key: Root account private key (hex string, as used by ``Account.from_key``)

        Returns:
            SignedKeyAuthorization that can be attached to a transaction
        """
        from .models import Signature

        msg_hash = self.signature_hash()
        account = Account.from_key(private_key)
        signed = account.unsafe_sign_hash(msg_hash)

        return SignedKeyAuthorization(
            authorization=self,
            signature=Signature(r=signed.r, s=signed.s, v=signed.v),
        )


# ---------------------------------------------------------------------------
# Signed key authorization
# ---------------------------------------------------------------------------


@attrs.define(frozen=True)
class SignedKeyAuthorization:
    """Signed key authorization that can be attached to a transaction.

    Contains the key authorization and the signature from the root account.
    """

    authorization: KeyAuthorization
    signature: Signature  # from .models

    @property
    def v(self) -> int:
        """Signature v value (deprecated, use ``self.signature.v``)."""
        return self.signature.v

    @property
    def r(self) -> int:
        """Signature r value (deprecated, use ``self.signature.r``)."""
        return self.signature.r

    @property
    def s(self) -> int:
        """Signature s value (deprecated, use ``self.signature.s``)."""
        return self.signature.s

    def as_rlp_payload(self) -> list:
        """Return the RLP-encodable list representation."""
        return [self.authorization.as_rlp_payload(), self.signature.to_bytes()]

    def rlp_encode(self) -> bytes:
        """RLP encode the signed key authorization."""
        return rlp.encode(self.as_rlp_payload())

    def to_json(self) -> dict:
        """Convert to JSON format for eth_estimateGas and other RPC calls.

        Returns:
            Dict with camelCase keys matching Tempo's JSON-RPC format.
        """
        result: dict = {
            "chainId": hex(self.authorization.chain_id),
            "keyType": self.authorization.key_type.to_json_name(),
            "keyId": to_checksum_address(bytes(self.authorization.key_id)),
            "signature": {
                "type": "secp256k1",
                "r": hex(self.signature.r),
                "s": hex(self.signature.s),
                "v": self.signature.v,
            },
        }

        if self.authorization.expiry is not None:
            result["expiry"] = hex(self.authorization.expiry)

        if self.authorization.limits is not None:
            result["limits"] = [
                {
                    "token": to_checksum_address(bytes(limit.token)),
                    "limit": hex(limit.limit),
                }
                for limit in self.authorization.limits
            ]

        return result

    def recover_signer(self) -> str:
        """Recover the checksummed address that signed this authorization."""
        msg_hash = self.authorization.signature_hash()
        recovered = Account._recover_hash(
            msg_hash,
            vrs=(self.signature.v, self.signature.r, self.signature.s),
        )
        return to_checksum_address(recovered)


# ---------------------------------------------------------------------------
# Keychain signature (0x04 envelope)
# ---------------------------------------------------------------------------


@attrs.define(frozen=True)
class KeychainSignature:
    """Keychain V2 signature: ``0x04 || root_account (20) || inner (65)``.

    Args:
        root_account: Address of the root account the access key signs on behalf of.
        inner: The secp256k1 signature from the access key.
    """

    TYPE_BYTE: ClassVar[int] = 0x04
    LENGTH: ClassVar[int] = 86

    root_account: Address = attrs.field(
        converter=as_address, validator=validate_nonempty_address
    )
    inner: Signature  # from .models

    def to_bytes(self) -> bytes:
        return (
            bytes([self.TYPE_BYTE]) + bytes(self.root_account) + self.inner.to_bytes()
        )

    @classmethod
    def from_bytes(cls, raw: BytesLike) -> KeychainSignature:
        """Parse a 86-byte keychain signature."""
        from .models import Signature
        from .types import as_bytes as _as_bytes

        b = _as_bytes(raw)
        if len(b) != cls.LENGTH:
            raise ValueError(
                f"keychain signature must be {cls.LENGTH} bytes, got {len(b)}"
            )
        if b[0] != cls.TYPE_BYTE:
            raise ValueError(f"expected type byte 0x04, got {b[0]:#04x}")
        return cls(
            root_account=b[1:21],
            inner=Signature.from_bytes(b[21:86]),
        )

    @classmethod
    def sign(
        cls,
        msg_hash: bytes,
        access_key_private_key: str,
        root_account: BytesLike,
    ) -> KeychainSignature:
        """Build a Keychain V2 signature for a message hash.

        The access key signs ``keccak256(0x04 || sig_hash || user_address)``
        instead of the raw sig_hash, providing domain separation.

        Args:
            msg_hash: 32-byte transaction signature hash.
            access_key_private_key: Private key of the access key (hex string,
                as used by ``Account.from_key``).
            root_account: Address of the root account (hex string or bytes).
        """
        from .models import Signature

        if len(msg_hash) != 32:
            raise ValueError(f"msg_hash must be 32 bytes, got {len(msg_hash)}")

        root_bytes = as_address(root_account)

        signing_hash = keccak(bytes([cls.TYPE_BYTE]) + msg_hash + bytes(root_bytes))

        account = Account.from_key(access_key_private_key)
        signed_msg = account.unsafe_sign_hash(signing_hash)

        return cls(
            root_account=root_bytes,
            inner=Signature(r=signed_msg.r, s=signed_msg.s, v=signed_msg.v),
        )


# ---------------------------------------------------------------------------
# Convenience aliases / constants for backwards compat
# ---------------------------------------------------------------------------

KEYCHAIN_SIGNATURE_TYPE = KeychainSignature.TYPE_BYTE
INNER_SIGNATURE_LENGTH = 65  # r (32) + s (32) + v (1)
KEYCHAIN_SIGNATURE_LENGTH = KeychainSignature.LENGTH


# ---------------------------------------------------------------------------
# Deprecated free functions — thin wrappers for backwards compat
# ---------------------------------------------------------------------------


def create_key_authorization(
    key_id: str,
    chain_id: int = 0,
    key_type: int = SignatureType.SECP256K1,
    expiry: int | None = None,
    limits: list[dict] | None = None,
) -> KeyAuthorization:
    """Create a key authorization for provisioning an access key.

    .. deprecated::
        Use ``KeyAuthorization(...)`` directly.
    """
    token_limits = None
    if limits is not None:
        token_limits = [
            TokenLimit(token=lim["token"], limit=lim["limit"]) for lim in limits
        ]

    return KeyAuthorization(
        key_id=key_id,
        chain_id=chain_id,
        key_type=key_type,
        expiry=expiry,
        limits=token_limits,
    )


def build_keychain_signature(
    msg_hash: bytes,
    access_key_private_key: str,
    root_account: str,
) -> bytes:
    """Build a Keychain V2 signature for a message hash.

    .. deprecated::
        Use ``KeychainSignature.sign()`` instead, which returns a structured
        :class:`KeychainSignature` object.
    """
    return KeychainSignature.sign(
        msg_hash, access_key_private_key, root_account
    ).to_bytes()


def sign_tx_access_key(
    tx: TempoTransaction,
    access_key_private_key: str,
    root_account: str,
) -> TempoTransaction:
    """Sign a Tempo transaction using access key mode (Keychain signature).

    .. deprecated::
        Use ``tx.sign_access_key()`` instead.
    """
    return tx.sign_access_key(access_key_private_key, root_account)
