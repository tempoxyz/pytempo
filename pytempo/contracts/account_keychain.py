"""Typed helpers for the Account Keychain precompile.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo import SignatureType
    from pytempo.contracts import AccountKeychain

    # T3+ (default)
    call = AccountKeychain.authorize_key(
        key_id=access_key.address,
        signature_type=SignatureType.SECP256K1,
        expiry=2**64 - 1,
    )

    # Pre-T3
    call = AccountKeychain.authorize_key(
        key_id=access_key.address,
        signature_type=SignatureType.SECP256K1,
        expiry=2**64 - 1,
        legacy=True,
    )

    tx = TempoTransaction.create(..., calls=(call,))
"""

from collections.abc import Sequence
from typing import Optional

from eth_utils import to_checksum_address

from pytempo.keychain import CallScope, SignatureType
from pytempo.models import Call

from ._encode import encode_calldata
from .abis import ACCOUNT_KEYCHAIN_ABI
from .addresses import ACCOUNT_KEYCHAIN_ADDRESS

_ABI = ACCOUNT_KEYCHAIN_ABI


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
        expiry: int,
        enforce_limits: bool = False,
        limits: Optional[Sequence[tuple[str, int] | tuple[str, int, int]]] = None,
        allow_any_calls: bool = True,
        allowed_calls: Optional[Sequence[CallScope]] = None,
        legacy: bool = False,
    ) -> Call:
        """Build an ``authorizeKey`` call.

        Uses the TIP-1011 ``KeyRestrictions`` struct encoding by default (T3+).
        Pass ``legacy=True`` for the pre-T3 flat-parameter encoding.

        Args:
            key_id: The access key address to authorize.
            signature_type: Type of key being authorized (SignatureType.SECP256K1, P256, or WEBAUTHN)
            expiry: Unix timestamp when key expires (use ``2**64 - 1`` for never).
            enforce_limits: Whether to enforce spending limits.
            limits: List of ``(token_address, amount)`` or ``(token_address, amount, period)`` tuples.
                Period defaults to 0 (one-time limit) if omitted.
            allow_any_calls: Whether the key can call any contract (default True).
                Ignored when ``legacy=True``.
            allowed_calls: List of :class:`~pytempo.CallScope` restricting
                which contracts/functions the key can call.
                Only used when ``allow_any_calls`` is False.
                Ignored when ``legacy=True``.
            legacy: Use pre-T3 flat-parameter encoding. Pass ``True`` until T3 is activated, then remove this argument.
        """
        if legacy and (allowed_calls or not allow_any_calls):
            raise ValueError("legacy=True does not support call restrictions")

        if allowed_calls and allow_any_calls:
            raise ValueError(
                "allowed_calls was provided but allow_any_calls=True; "
                "pass allow_any_calls=False to create a scoped key"
            )

        if legacy:
            limit_tuples = (
                [(t, a) for t, a, *_ in ((*lim, 0)[:3] for lim in limits)]
                if limits
                else []
            )
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [key_id, int(signature_type), expiry, enforce_limits, limit_tuples],
            )
        else:
            limit_tuples = (
                [(t, a, p) for t, a, p in ((*lim, 0)[:3] for lim in limits)]
                if limits
                else []
            )
            call_tuples = (
                [s.to_abi_tuple() for s in allowed_calls] if allowed_calls else []
            )
            config = (
                expiry,
                enforce_limits,
                limit_tuples,
                allow_any_calls,
                call_tuples,
            )
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [key_id, int(signature_type), config],
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
