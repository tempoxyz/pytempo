"""Typed helpers for the StorageCredits precompile (T7 / TIP-1060).

Storage credits are per-account, non-transferable credits that offset the
TIP-1000 storage-creation cost when previously freed storage is reused. An
account earns one credit whenever it deletes one of its own storage slots
(a nonzero-to-zero transition) and can apply that credit to a later storage
creation.

Each account selects how its credits are applied to its own storage creations
via a *mode* (see :class:`StorageCreditMode`) and, for ``Direct`` mode, a
*budget*.

Transient vs. persistent state:

- ``balance_of`` reads **persistent** state (the account's credit balance).
- ``mode_of`` and ``budget_of`` read **transaction-local (transient)** state.
  The mode defaults to ``Refund`` and the budget to ``0`` at the start of every
  transaction, and both reset at the end of the transaction. A standalone
  ``eth_call`` therefore normally observes the defaults, not a durable account
  setting.

Because mode/budget are transient, :meth:`StorageCredits.set_mode` and
:meth:`StorageCredits.set_budget` only affect the transaction they are included
in, and MUST appear **before** the storage-creating calls they are meant to
influence::

    from pytempo.contracts import StorageCredits, StorageCreditMode

    tx = TempoTransaction.create(
        ...,
        calls=(
            StorageCredits.set_mode(StorageCreditMode.PRESERVE),
            # ... subsequent calls that create storage ...
        ),
    )

    balance = StorageCredits.balance_of(w3, account="0xAbc...")
"""

from __future__ import annotations

from enum import IntEnum

from pytempo.models import Call

from ._decode import decode_u64
from ._encode import encode_calldata
from .abis import STORAGE_CREDITS_ABI
from .addresses import STORAGE_CREDITS_ADDRESS

_ABI = STORAGE_CREDITS_ABI


class StorageCreditMode(IntEnum):
    """How an account applies storage credits to its own storage creations.

    - ``REFUND`` (default): ``STORAGE_CREDIT_VALUE`` is charged upfront; at
      end-of-transaction settlement, any available credit is consumed and the
      value refunded. Simulation-safe — required gas does not depend on the
      credit balance at inclusion time.
    - ``PRESERVE``: the full storage-creation cost is always charged; credits
      are never consumed.
    - ``DIRECT``: if a credit and nonzero budget are available, one credit is
      consumed synchronously to cover ``STORAGE_CREDIT_VALUE``. Carries a
      simulation-vs-inclusion risk: a credit available at simulation may be
      drained before inclusion, causing the transaction to run out of gas.
    """

    REFUND = 0
    PRESERVE = 1
    DIRECT = 2


def _require_account(account: str) -> None:
    if not account:
        raise ValueError("account required")


class StorageCredits:
    """StorageCredits precompile call builders and views.

    All methods target the StorageCredits precompile at
    :data:`STORAGE_CREDITS_ADDRESS`.
    """

    ADDRESS = STORAGE_CREDITS_ADDRESS

    @staticmethod
    def set_mode(mode: StorageCreditMode | int) -> Call:
        """Build a ``setMode(uint8)`` call for the calling account.

        Sets the caller's transient storage-creation mode for the current
        transaction. Per TIP-1060, ``setMode(DIRECT)`` sets the direct-spend
        budget to ``type(uint64).max`` (effectively unlimited); use
        :meth:`set_budget` instead to enter ``DIRECT`` mode with a bounded
        budget. Selecting any non-``DIRECT`` mode resets the budget to ``0``.

        Args:
            mode: A :class:`StorageCreditMode` or an equivalent ``int``
                (``0``, ``1``, or ``2``).

        Raises:
            ValueError: If ``mode`` is not a valid :class:`StorageCreditMode`
                (e.g. the reserved value ``3``).
        """
        mode_value = StorageCreditMode(mode)
        data = encode_calldata(_ABI, "setMode", [int(mode_value)])
        return Call.create(to=STORAGE_CREDITS_ADDRESS, data=data)

    @staticmethod
    def set_budget(credits: int) -> Call:
        """Build a ``setBudget(uint64)`` call for the calling account.

        Switches the caller to ``DIRECT`` mode with ``credits`` as the maximum
        number of credits spendable synchronously in the current transaction.
        ``credits == 0`` selects ``DIRECT`` mode with no immediately spendable
        budget.

        Args:
            credits: Maximum credits to spend directly this transaction. Must
                fit in a ``uint64``.
        """
        if not 0 <= credits <= 2**64 - 1:
            raise ValueError("credits must fit in uint64")
        data = encode_calldata(_ABI, "setBudget", [credits])
        return Call.create(to=STORAGE_CREDITS_ADDRESS, data=data)

    @staticmethod
    def balance_of(w3, *, account: str) -> int:
        """Query the persistent storage-credit balance for ``account``.

        Args:
            w3: Web3 instance connected to a Tempo RPC.
            account: The account whose credit balance is queried.

        Returns:
            The number of unspent credits (saturates at ``uint64`` max).

        Raises:
            ValueError: If ``account`` is empty or the result is malformed.
        """
        _require_account(account)
        call_data = encode_calldata(_ABI, "balanceOf", [account])
        result = w3.eth.call({"to": STORAGE_CREDITS_ADDRESS, "data": call_data})
        return decode_u64(result, "balanceOf")

    @staticmethod
    def mode_of(w3, *, account: str) -> StorageCreditMode:
        """Query the transient storage-creation mode for ``account``.

        Note: mode is transaction-local. A standalone call normally returns the
        default ``REFUND`` unless the account changed it earlier in the same
        transaction.

        Raises:
            ValueError: If ``account`` is empty, the result is malformed, or the
                chain returns an unknown mode value.
        """
        _require_account(account)
        call_data = encode_calldata(_ABI, "modeOf", [account])
        result = w3.eth.call({"to": STORAGE_CREDITS_ADDRESS, "data": call_data})
        value = decode_u64(result, "modeOf")
        try:
            return StorageCreditMode(value)
        except ValueError as exc:
            raise ValueError(f"modeOf returned unknown mode value {value}") from exc

    @staticmethod
    def budget_of(w3, *, account: str) -> int:
        """Query the transient Direct-spend budget for ``account``.

        Note: budget is transaction-local. A standalone call normally returns
        ``0`` unless the account set it earlier in the same transaction.

        Raises:
            ValueError: If ``account`` is empty or the result is malformed.
        """
        _require_account(account)
        call_data = encode_calldata(_ABI, "budgetOf", [account])
        result = w3.eth.call({"to": STORAGE_CREDITS_ADDRESS, "data": call_data})
        return decode_u64(result, "budgetOf")
