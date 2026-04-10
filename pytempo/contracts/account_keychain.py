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

from eth_utils import to_checksum_address

from pytempo.keychain import CallScope, KeyRestrictions, SignatureType
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
        restrictions: KeyRestrictions,
        legacy: bool = False,
    ) -> Call:
        """Build an ``authorizeKey`` call.

        Args:
            key_id: The access key address to authorize.
            signature_type: Type of key being authorized.
            restrictions: Key restrictions (expiry, limits, call scopes).
            legacy: Use pre-T3 flat-parameter encoding.
        """
        if legacy:
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
            data = encode_calldata(
                _ABI,
                "authorizeKey",
                [key_id, int(signature_type), restrictions.to_abi_tuple()],
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
