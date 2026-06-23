"""Typed helpers for the ReceivePolicyGuard precompile (T6 / TIP-1028).

When an inbound TIP-20 transfer or mint is blocked by a receiver's receive
policy, the funds are redirected here instead of reverting. A ``TransferBlocked``
event is emitted carrying an opaque ``receipt`` (bytes). The originator or the
configured recovery authority can later ``claim`` or ``burnBlockedReceipt`` using
that receipt.

Held receipts are **not** enumerable on-chain — index the ``TransferBlocked``
event (e.g. via ``w3.eth.contract(abi=RECEIVE_POLICY_GUARD_ABI)``) to discover
claimable receipts.

::

    from pytempo.contracts import ReceivePolicyGuard

    amount = ReceivePolicyGuard.balance_of(w3, receipt=receipt_bytes)
    call = ReceivePolicyGuard.claim(to="0xDest...", receipt=receipt_bytes)
"""

from __future__ import annotations

from enum import IntEnum

from pytempo.models import Call

from ..types import BytesLike, as_bytes
from ._decode import decode_uint
from ._encode import encode_calldata
from .abis import RECEIVE_POLICY_GUARD_ABI
from .addresses import RECEIVE_POLICY_GUARD_ADDRESS

_ABI = RECEIVE_POLICY_GUARD_ABI


class InboundKind(IntEnum):
    """How the blocked funds originally arrived."""

    TRANSFER = 0
    MINT = 1


class ReceivePolicyGuard:
    """ReceivePolicyGuard precompile call builders.

    All methods target the guard precompile at
    :data:`RECEIVE_POLICY_GUARD_ADDRESS`.
    """

    ADDRESS = RECEIVE_POLICY_GUARD_ADDRESS

    @staticmethod
    def balance_of(w3, *, receipt: BytesLike) -> int:
        """Query the amount held for a blocked-transfer ``receipt``."""
        call_data = encode_calldata(_ABI, "balanceOf", [as_bytes(receipt)])
        result = w3.eth.call({"to": RECEIVE_POLICY_GUARD_ADDRESS, "data": call_data})
        return decode_uint(result, "balanceOf")

    @staticmethod
    def claim(*, to: str, receipt: BytesLike) -> Call:
        """Build a ``claim(address,bytes)`` call to recover held funds to ``to``."""
        if not to:
            raise ValueError("to required")
        data = encode_calldata(_ABI, "claim", [to, as_bytes(receipt)])
        return Call.create(to=RECEIVE_POLICY_GUARD_ADDRESS, data=data)

    @staticmethod
    def burn_blocked_receipt(*, receipt: BytesLike) -> Call:
        """Build a ``burnBlockedReceipt(bytes)`` call to discard a held receipt."""
        data = encode_calldata(_ABI, "burnBlockedReceipt", [as_bytes(receipt)])
        return Call.create(to=RECEIVE_POLICY_GUARD_ADDRESS, data=data)
