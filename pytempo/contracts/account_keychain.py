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
        limits: Optional[Sequence[tuple[str, int]]] = None,
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
            limits: List of ``(token_address, amount)`` tuples for spending limits.
            allow_any_calls: Whether the key can call any contract (default True).
                Ignored when ``legacy=True``.
            allowed_calls: List of :class:`~pytempo.CallScope` restricting
                which contracts/functions the key can call.
                Only used when ``allow_any_calls`` is False.
                Ignored when ``legacy=True``.
            legacy: Use pre-T3 flat-parameter encoding. Pass ``True`` until T3 is activated, then remove this argument.
        """
        limit_tuples = list(limits) if limits else []

        if legacy:
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [key_id, int(signature_type), expiry, enforce_limits, limit_tuples],
            )
        else:
            call_tuples = (
                [(bytes(s.target), bytes(s.selector)) for s in allowed_calls]
                if allowed_calls
                else []
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
