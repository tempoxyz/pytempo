"""Typed helpers for the Account Keychain precompile.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo import KeyRestrictions, SignatureType
    from pytempo.contracts import AccountKeychain

    call = AccountKeychain.authorize_key(
        key_id=access_key.address,
        signature_type=SignatureType.SECP256K1,
        restrictions=KeyRestrictions(expiry=2**64 - 1),
    )

    tx = TempoTransaction.create(..., calls=(call,))
"""

from __future__ import annotations

from collections.abc import Sequence

from pytempo.keychain import CallScope, KeyRestrictions, SignatureType
from pytempo.models import Call
from pytempo.types import BytesLike, as_hash32

from ._decode import decode_address, decode_bool, decode_u64, decode_uint
from ._encode import encode_calldata
from .abis import ACCOUNT_KEYCHAIN_ABI
from .addresses import ACCOUNT_KEYCHAIN_ADDRESS

_ABI = ACCOUNT_KEYCHAIN_ABI


def _hash32(value: BytesLike) -> bytes:
    return bytes(as_hash32(value))


def _require_addresses(**values: str) -> None:
    missing = ", ".join(name for name, value in values.items() if not value)
    if missing:
        raise ValueError(f"{missing} required")


class AccountKeychain:
    """Account Keychain precompile call builders.

    All methods target the keychain precompile at :data:`ACCOUNT_KEYCHAIN_ADDRESS`.
    """

    ADDRESS = ACCOUNT_KEYCHAIN_ADDRESS

    @staticmethod
    def authorize_key(
        *,
        key_id: str,
        signature_type: SignatureType,
        restrictions: KeyRestrictions,
        legacy: bool = False,
        witness: BytesLike | None = None,
    ) -> Call:
        """Build an ``authorizeKey`` call.

        Args:
            key_id: The access key address to authorize.
            signature_type: Type of key being authorized.
            restrictions: Key restrictions (expiry, limits, call scopes).
            legacy: Use pre-T3 flat-parameter encoding. Pass ``True``
                until T3 is activated, then remove this argument.
            witness: Optional T5 key-authorization witness.
        """
        if legacy:
            if witness is not None:
                raise ValueError("legacy=True does not support witnesses")
            if restrictions.allowed_calls is not None:
                raise ValueError("legacy=True does not support call restrictions")
            if restrictions.limits and any(
                lim.period != 0 for lim in restrictions.limits
            ):
                raise ValueError("legacy=True does not support periodic limits")

            limit_tuples = (
                [(bytes(lim.token).hex(), lim.limit) for lim in restrictions.limits]
                if restrictions.limits
                else []
            )
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [
                    key_id,
                    int(signature_type),
                    restrictions.expiry
                    if restrictions.expiry is not None
                    else 2**64 - 1,
                    restrictions.limits is not None,
                    limit_tuples,
                ],
            )
        else:
            args = [key_id, int(signature_type), restrictions.to_abi_tuple()]
            if witness is not None:
                args.append(_hash32(witness))
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                args,
            )

        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def authorize_admin_key(
        *,
        key_id: str,
        signature_type: SignatureType,
        witness: BytesLike,
    ) -> Call:
        """Build an ``authorizeAdminKey(address,uint8,bytes32)`` call."""
        _require_addresses(key_id=key_id)
        data = encode_calldata(
            _ABI, "authorizeAdminKey", [key_id, int(signature_type), _hash32(witness)]
        )
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def authorize_key_legacy(
        *,
        key_id: str,
        signature_type: SignatureType,
        restrictions: KeyRestrictions,
    ) -> Call:
        """Build a pre-T3 ``authorizeKey`` call.

        Convenience wrapper equivalent to
        ``authorize_key(..., legacy=True)``.
        """
        return AccountKeychain.authorize_key(
            key_id=key_id,
            signature_type=signature_type,
            restrictions=restrictions,
            legacy=True,
        )

    @staticmethod
    def revoke_key(*, key_id: str) -> Call:
        """Build a ``revokeKey(address)`` call."""
        data = encode_calldata(_ABI, "revokeKey", [key_id])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def burn_key_authorization_witness(*, witness: BytesLike) -> Call:
        """Build a ``burnKeyAuthorizationWitness(bytes32)`` call."""
        data = encode_calldata(_ABI, "burnKeyAuthorizationWitness", [_hash32(witness)])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def set_allowed_calls(
        *,
        key_id: str,
        scopes: Sequence[CallScope],
    ) -> Call:
        """Build a ``setAllowedCalls(address,CallScope[])`` call.

        Args:
            key_id: The access key address.
            scopes: List of :class:`~pytempo.CallScope` to set as the allowlist.
        """
        call_tuples = [s.to_abi_tuple() for s in scopes]
        data = encode_calldata(_ABI, "setAllowedCalls", [key_id, call_tuples])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def remove_allowed_calls(*, key_id: str, target: str) -> Call:
        """Build a ``removeAllowedCalls(address,address)`` call.

        Removes all call-scope rules targeting ``target`` from the key's allowlist.

        Args:
            key_id: The access key address.
            target: The contract address to remove from the allowlist.
        """
        data = encode_calldata(_ABI, "removeAllowedCalls", [key_id, target])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def update_spending_limit(*, key_id: str, token: str, new_limit: int) -> Call:
        """Build an ``updateSpendingLimit(address,address,uint256)`` call."""
        data = encode_calldata(_ABI, "updateSpendingLimit", [key_id, token, new_limit])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def get_key(
        w3,
        *,
        account_address: str,
        key_id: str,
    ) -> dict:
        """Query key info from the AccountKeychain precompile.

        Args:
            w3: Web3 instance connected to a Tempo RPC.
            account_address: The root wallet address.
            key_id: The access key ID (address).

        Returns:
            Dict with ``signature_type``, ``key_id``, ``expiry``,
            ``enforce_limits``, and ``is_revoked`` fields.

        Raises:
            ValueError: If any address parameter is empty or result is wrong length.
        """
        _require_addresses(account_address=account_address, key_id=key_id)

        call_data = encode_calldata(_ABI, "getKey", [account_address, key_id])
        result = bytes(w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data}))

        if len(result) != 160:
            raise ValueError(
                f"getKey result wrong length, expected 160 bytes, got {len(result)}"
            )

        words = [result[i : i + 32] for i in range(0, 160, 32)]

        return {
            "signature_type": int.from_bytes(words[0], "big"),
            "key_id": decode_address(words[1], "getKey.keyId"),
            "expiry": int.from_bytes(words[2], "big"),
            "enforce_limits": decode_bool(words[3], "getKey.enforceLimits"),
            "is_revoked": decode_bool(words[4], "getKey.isRevoked"),
        }

    @staticmethod
    def get_remaining_limit(
        w3,
        *,
        account_address: str,
        key_id: str,
        token_address: str,
    ) -> int:
        """Query remaining spending limit for an access key.

        Args:
            w3: Web3 instance connected to a Tempo RPC.
            account_address: The root wallet address.
            key_id: The access key ID (address).
            token_address: The token to check limit for.

        Returns:
            Remaining spending limit in base units.

        Raises:
            ValueError: If any address parameter is empty.
        """
        _require_addresses(
            account_address=account_address,
            key_id=key_id,
            token_address=token_address,
        )

        call_data = encode_calldata(
            _ABI,
            "getRemainingLimit",
            [account_address, key_id, token_address],
        )
        result = w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data})
        return decode_uint(result, "getRemainingLimit")

    @staticmethod
    def get_remaining_limit_with_period(
        w3,
        *,
        account_address: str,
        key_id: str,
        token_address: str,
    ) -> dict:
        """Query remaining spending limit and current period end for an access key."""
        _require_addresses(
            account_address=account_address,
            key_id=key_id,
            token_address=token_address,
        )

        call_data = encode_calldata(
            _ABI,
            "getRemainingLimitWithPeriod",
            [account_address, key_id, token_address],
        )
        result = bytes(w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data}))
        if len(result) != 64:
            raise ValueError(
                "getRemainingLimitWithPeriod result wrong length, "
                f"expected 64 bytes, got {len(result)}"
            )
        return {
            "remaining": decode_uint(
                result[:32], "getRemainingLimitWithPeriod.remaining"
            ),
            "period_end": decode_u64(
                result[32:], "getRemainingLimitWithPeriod.periodEnd"
            ),
        }

    @staticmethod
    def get_transaction_key(w3) -> str:
        """Query the active transaction key from the AccountKeychain precompile."""
        call_data = encode_calldata(_ABI, "getTransactionKey", [])
        result = w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data})
        return decode_address(result, "getTransactionKey")

    @staticmethod
    def is_admin_key(w3, *, account_address: str, key_id: str) -> bool:
        """Query whether ``key_id`` is an admin key for ``account_address``."""
        _require_addresses(account_address=account_address, key_id=key_id)

        call_data = encode_calldata(_ABI, "isAdminKey", [account_address, key_id])
        result = w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data})
        return decode_bool(result, "isAdminKey")

    @staticmethod
    def is_key_authorization_witness_burned(
        w3,
        *,
        account_address: str,
        witness: BytesLike,
    ) -> bool:
        """Query whether a key-authorization witness has been burned."""
        _require_addresses(account_address=account_address)

        call_data = encode_calldata(
            _ABI,
            "isKeyAuthorizationWitnessBurned",
            [account_address, _hash32(witness)],
        )
        result = w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data})
        return decode_bool(result, "isKeyAuthorizationWitnessBurned")
