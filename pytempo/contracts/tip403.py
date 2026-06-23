"""Typed helpers for the TIP-403 Policy Registry precompile (receive policies).

T6 (TIP-1028) adds account-level *receive policies* to the TIP-403 registry. An
account can declare which TIP-20 tokens and which senders it is willing to
receive. Blocked inbound transfers/mints do not revert — they are redirected to
the :data:`RECEIVE_POLICY_GUARD_ADDRESS` precompile for later recovery.

Build a receive policy with :meth:`TIP403Registry.set_receive_policy` and read it
back with :meth:`TIP403Registry.receive_policy` /
:meth:`TIP403Registry.validate_receive_policy`::

    from pytempo.contracts import TIP403Registry

    call = TIP403Registry.set_receive_policy(
        sender_policy_id=1,        # built-in 1 = allow all senders
        token_filter_id=7,         # a TIP-403 policy id of allowed tokens
        recovery_authority="0xRecovery...",
    )

Built-in policy ids ``0`` and ``1`` have fixed meanings for both
``sender_policy_id`` and ``token_filter_id``: ``0`` rejects everything and
``1`` allows everything. To functionally disable filtering once a receive
policy exists, set both ids to ``1``. (If no receive policy has ever been set
the account accepts all inbound transfers/mints regardless.)
"""

from __future__ import annotations

from enum import IntEnum

from pytempo.models import Call

from ._decode import decode_address, decode_bool, decode_u64, decode_uint
from ._encode import encode_calldata
from .abis import TIP403_REGISTRY_ABI
from .addresses import TIP403_REGISTRY_ADDRESS

_ABI = TIP403_REGISTRY_ABI


class PolicyType(IntEnum):
    """TIP-403 policy semantics."""

    WHITELIST = 0
    BLACKLIST = 1
    COMPOUND = 2


class BlockedReason(IntEnum):
    """Reason an inbound transfer would be blocked / redirected."""

    NONE = 0
    TOKEN_FILTER = 1
    RECEIVE_POLICY = 2


class TIP403Registry:
    """TIP-403 Policy Registry precompile — receive-policy call builders.

    All methods target the registry precompile at
    :data:`TIP403_REGISTRY_ADDRESS`.
    """

    ADDRESS = TIP403_REGISTRY_ADDRESS

    @staticmethod
    def set_receive_policy(
        *,
        sender_policy_id: int,
        token_filter_id: int,
        recovery_authority: str,
    ) -> Call:
        """Build a ``setReceivePolicy(uint64,uint64,address)`` call.

        Args:
            sender_policy_id: TIP-403 policy id restricting allowed senders.
                Built-in ``0`` = reject all, ``1`` = allow all.
            token_filter_id: TIP-403 policy id restricting allowed tokens.
                Built-in ``0`` = reject all, ``1`` = allow all.
            recovery_authority: Who may claim blocked funds. ``address(0)`` =
                the transfer originator; the receiver's own address = receiver
                recovery; any other nonzero address names that claimer.
        """
        data = encode_calldata(
            _ABI,
            "setReceivePolicy",
            [sender_policy_id, token_filter_id, recovery_authority],
        )
        return Call.create(to=TIP403_REGISTRY_ADDRESS, data=data)

    @staticmethod
    def receive_policy(w3, *, account: str) -> dict:
        """Query the receive policy configured for ``account``.

        Returns a dict with ``has_receive_policy``, ``sender_policy_id``,
        ``sender_policy_type``, ``token_filter_id``, ``token_filter_type``, and
        ``recovery_authority``.
        """
        if not account:
            raise ValueError("account required")

        call_data = encode_calldata(_ABI, "receivePolicy", [account])
        result = bytes(w3.eth.call({"to": TIP403_REGISTRY_ADDRESS, "data": call_data}))
        if len(result) != 192:
            raise ValueError(
                f"receivePolicy result wrong length, expected 192 bytes, "
                f"got {len(result)}"
            )
        words = [result[i : i + 32] for i in range(0, 192, 32)]
        return {
            "has_receive_policy": decode_bool(
                words[0], "receivePolicy.hasReceivePolicy"
            ),
            "sender_policy_id": decode_u64(words[1], "receivePolicy.senderPolicyId"),
            "sender_policy_type": PolicyType(
                decode_uint(words[2], "receivePolicy.senderPolicyType")
            ),
            "token_filter_id": decode_u64(words[3], "receivePolicy.tokenFilterId"),
            "token_filter_type": PolicyType(
                decode_uint(words[4], "receivePolicy.tokenFilterType")
            ),
            "recovery_authority": decode_address(
                words[5], "receivePolicy.recoveryAuthority"
            ),
        }

    @staticmethod
    def validate_receive_policy(
        w3,
        *,
        token: str,
        sender: str,
        receiver: str,
    ) -> dict:
        """Query whether a ``token`` transfer from ``sender`` to ``receiver`` is allowed.

        Returns a dict with ``authorized`` (bool) and ``blocked_reason``
        (:class:`BlockedReason`).
        """
        if not (token and sender and receiver):
            raise ValueError("token, sender, and receiver required")

        call_data = encode_calldata(
            _ABI, "validateReceivePolicy", [token, sender, receiver]
        )
        result = bytes(w3.eth.call({"to": TIP403_REGISTRY_ADDRESS, "data": call_data}))
        if len(result) != 64:
            raise ValueError(
                f"validateReceivePolicy result wrong length, expected 64 bytes, "
                f"got {len(result)}"
            )
        return {
            "authorized": decode_bool(result[:32], "validateReceivePolicy.authorized"),
            "blocked_reason": BlockedReason(
                decode_uint(result[32:], "validateReceivePolicy.blockedReason")
            ),
        }
