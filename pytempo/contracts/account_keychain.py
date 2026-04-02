"""Typed helpers for the Account Keychain precompile.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import AccountKeychain

    # T3+ (TIP-1011): KeyRestrictions struct
    call = AccountKeychain.authorize_key(
        key_id=access_key.address,
        signature_type=0,
        expiry=2**64 - 1,
    )

    # Pre-T3 (legacy): flat params
    call = AccountKeychain.authorize_key_legacy(
        key_id=access_key.address,
        signature_type=0,
        expiry=2**64 - 1,
    )

    tx = TempoTransaction.create(..., calls=(call,))
"""

from collections.abc import Sequence
from typing import Optional

from pytempo.keychain import CallScope
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
        signature_type: int,
        expiry: int,
        enforce_limits: bool = False,
        limits: Optional[Sequence[tuple[str, int]]] = None,
        allow_any_calls: bool = True,
        allowed_calls: Optional[Sequence[CallScope]] = None,
    ) -> Call:
        """Build a TIP-1011 ``authorizeKey(address,uint8,KeyRestrictions)`` call (T3+).

        Args:
            key_id: The access key address to authorize.
            signature_type: 0 = Secp256k1, 1 = P256, 2 = WebAuthn.
            expiry: Unix timestamp when key expires (use ``2**64 - 1`` for never).
            enforce_limits: Whether to enforce spending limits.
            limits: List of ``(token_address, amount)`` tuples for spending limits.
            allow_any_calls: Whether the key can call any contract (default True).
            allowed_calls: List of :class:`~pytempo.keychain.CallScope` restricting
                which contracts/functions the key can call.
                Only used when ``allow_any_calls`` is False.
        """
        limit_tuples = list(limits) if limits else []
        call_tuples = (
            [(s.target, s.selector) for s in allowed_calls] if allowed_calls else []
        )
        config = (expiry, enforce_limits, limit_tuples, allow_any_calls, call_tuples)
        data = encode_calldata(
            _ABI,
            "authorizeKey",
            [key_id, signature_type, config],
        )
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def authorize_key_legacy(
        *,
        key_id: str,
        signature_type: int,
        expiry: int,
        enforce_limits: bool = False,
        limits: Optional[Sequence[tuple[str, int]]] = None,
    ) -> Call:
        """Build a legacy ``authorizeKey(address,uint8,uint64,bool,(address,uint256)[])`` call (pre-T3).

        Args:
            key_id: The access key address to authorize.
            signature_type: 0 = Secp256k1, 1 = P256, 2 = WebAuthn.
            expiry: Unix timestamp when key expires (use ``2**64 - 1`` for never).
            enforce_limits: Whether to enforce spending limits.
            limits: List of ``(token_address, amount)`` tuples for spending limits.
        """
        limit_tuples = list(limits) if limits else []
        data = encode_calldata(
            _ABI,
            "authorizeKey",
            [key_id, signature_type, expiry, enforce_limits, limit_tuples],
        )
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def revoke_key(*, key_id: str) -> Call:
        """Build a ``revokeKey(address)`` call."""
        data = encode_calldata(_ABI, "revokeKey", [key_id])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

    @staticmethod
    def update_spending_limit(*, key_id: str, token: str, new_limit: int) -> Call:
        """Build an ``updateSpendingLimit(address,address,uint256)`` call."""
        data = encode_calldata(_ABI, "updateSpendingLimit", [key_id, token, new_limit])
        return Call.create(to=ACCOUNT_KEYCHAIN_ADDRESS, data=data)

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
