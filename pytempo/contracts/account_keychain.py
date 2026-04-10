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

import warnings
from collections.abc import Sequence

from eth_utils import to_checksum_address

from pytempo.keychain import CallScope, KeyRestrictions, SignatureType, TokenLimit
from pytempo.models import Call

from ._encode import encode_calldata
from .abis import ACCOUNT_KEYCHAIN_ABI
from .addresses import ACCOUNT_KEYCHAIN_ADDRESS

_ABI = ACCOUNT_KEYCHAIN_ABI


def _resolve_restrictions(
    *,
    restrictions: KeyRestrictions | None,
    expiry: int | None,
    enforce_limits: bool,
    limits: Sequence[tuple[str, int] | tuple[str, int, int]] | None,
    allow_any_calls: bool,
    allowed_calls: Sequence[CallScope] | None,
) -> KeyRestrictions:
    """Build a ``KeyRestrictions`` from either the new or deprecated params."""
    _has_legacy = (
        expiry is not None
        or enforce_limits
        or limits is not None
        or not allow_any_calls
        or allowed_calls is not None
    )

    if restrictions is not None:
        if _has_legacy:
            raise ValueError(
                "cannot combine 'restrictions' with deprecated individual "
                "params (expiry, limits, allowed_calls, …)"
            )
        return restrictions

    if not _has_legacy:
        return KeyRestrictions()

    warnings.warn(
        "Passing individual expiry/limits/allowed_calls params is deprecated. "
        "Use restrictions=KeyRestrictions(...) instead.",
        DeprecationWarning,
        stacklevel=3,
    )

    if allowed_calls and allow_any_calls:
        raise ValueError(
            "allowed_calls was provided but allow_any_calls=True; "
            "pass allow_any_calls=False to create a scoped key"
        )

    token_limits: list[TokenLimit] | None = None
    if enforce_limits or limits is not None:
        token_limits = []
        if limits:
            for lim in limits:
                t, a = lim[0], lim[1]
                p = lim[2] if len(lim) > 2 else 0  # type: ignore[arg-type]
                token_limits.append(TokenLimit(token=t, limit=a, period=p))

    resolved_calls: list[CallScope] | None = None
    if not allow_any_calls:
        resolved_calls = list(allowed_calls) if allowed_calls else []

    return KeyRestrictions(
        expiry=expiry,
        limits=token_limits,
        allowed_calls=resolved_calls,
    )


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
        restrictions: KeyRestrictions | None = None,
        legacy: bool = False,
        # Deprecated individual params — use ``restrictions`` instead.
        expiry: int | None = None,
        enforce_limits: bool = False,
        limits: Sequence[tuple[str, int] | tuple[str, int, int]] | None = None,
        allow_any_calls: bool = True,
        allowed_calls: Sequence[CallScope] | None = None,
    ) -> Call:
        """Build an ``authorizeKey`` call.

        Pass a :class:`~pytempo.KeyRestrictions` for the recommended API::

            AccountKeychain.authorize_key(
                key_id=addr,
                signature_type=SignatureType.SECP256K1,
                restrictions=KeyRestrictions(expiry=2**64 - 1),
            )

        The individual ``expiry`` / ``limits`` / ``allowed_calls`` params are
        deprecated but still supported for backward compatibility.

        Args:
            key_id: The access key address to authorize.
            signature_type: Type of key being authorized.
            restrictions: Key restrictions (expiry, limits, call scopes).
            legacy: Use pre-T3 flat-parameter encoding.
        """
        r = _resolve_restrictions(
            restrictions=restrictions,
            expiry=expiry,
            enforce_limits=enforce_limits,
            limits=limits,
            allow_any_calls=allow_any_calls,
            allowed_calls=allowed_calls,
        )

        if legacy:
            if r.allowed_calls is not None:
                raise ValueError("legacy=True does not support call restrictions")
            if r.limits and any(lim.period != 0 for lim in r.limits):
                raise ValueError("legacy=True does not support periodic limits")

            limit_tuples = (
                [(bytes(lim.token).hex(), lim.limit) for lim in r.limits]
                if r.limits
                else []
            )
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [
                    key_id,
                    int(signature_type),
                    r.expiry if r.expiry is not None else 2**64 - 1,
                    r.limits is not None,
                    limit_tuples,
                ],
            )
        else:
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [key_id, int(signature_type), r.to_abi_tuple()],
            )

        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def revoke_key(*, key_id: str) -> Call:
        """Build a ``revokeKey(address)`` call."""
        data = encode_calldata(_ABI, "revokeKey", [key_id])
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
        if not account_address or not key_id:
            raise ValueError("account_address and key_id are required")

        call_data = encode_calldata(_ABI, "getKey", [account_address, key_id])
        result = bytes(w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data}))

        if len(result) != 160:
            raise ValueError(
                f"getKey result wrong length, expected 160 bytes, got {len(result)}"
            )

        words = [result[i : i + 32] for i in range(0, 160, 32)]

        return {
            "signature_type": int.from_bytes(words[0], "big"),
            "key_id": to_checksum_address(words[1][-20:]),
            "expiry": int.from_bytes(words[2], "big"),
            "enforce_limits": bool(int.from_bytes(words[3], "big")),
            "is_revoked": bool(int.from_bytes(words[4], "big")),
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
        if not account_address or not key_id or not token_address:
            raise ValueError("account_address, key_id, and token_address are required")

        call_data = encode_calldata(
            _ABI,
            "getRemainingLimit",
            [account_address, key_id, token_address],
        )
        result = w3.eth.call({"to": ACCOUNT_KEYCHAIN_ADDRESS, "data": call_data})
        return int.from_bytes(result, "big")
