"""Typed helpers for the Account Keychain precompile.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import AccountKeychain

    call = AccountKeychain.authorize_key(
        key_id=access_key.address,
        signature_type=0,
        expiry=2**64 - 1,
    )
    tx = TempoTransaction.create(..., calls=(call,))
"""

from collections.abc import Sequence
from typing import Optional

from eth_utils import to_checksum_address

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
    ) -> Call:
        """Build an ``authorizeKey(address,uint8,uint64,bool,(address,uint256)[])`` call.

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
