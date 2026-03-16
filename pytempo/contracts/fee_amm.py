"""Typed helpers for the Fee AMM interface.

The Fee AMM handles liquidity operations for Tempo's fee token system.
It is part of the Fee Manager precompile — all calls target :data:`FEE_MANAGER_ADDRESS`.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import FeeAMM, BETA_USD, PATH_USD

    call = FeeAMM.mint(
        user_token=BETA_USD,
        validator_token=PATH_USD,
        amount=1_000_000_000,
        to="0xRecipient...",
    )
    tx = TempoTransaction.create(..., calls=(call,))
"""

from pytempo.models import Call

from ._encode import encode_calldata
from .abis import FEE_AMM_ABI
from .addresses import FEE_MANAGER_ADDRESS

_ABI = FEE_AMM_ABI


class FeeAMM:
    """Fee AMM call builders.

    All methods target the fee manager precompile at :data:`FEE_MANAGER_ADDRESS`.
    """

    ADDRESS = FEE_MANAGER_ADDRESS

    @staticmethod
    def mint(
        *,
        user_token: str,
        validator_token: str,
        amount: int,
        to: str,
    ) -> Call:
        """Build a ``mint(address,address,uint256,address)`` call for adding liquidity."""
        data = encode_calldata(_ABI, "mint", [user_token, validator_token, amount, to])
        return Call.create(to=FEE_MANAGER_ADDRESS, data=data)

    @staticmethod
    def burn(
        *,
        user_token: str,
        validator_token: str,
        liquidity: int,
        to: str,
    ) -> Call:
        """Build a ``burn(address,address,uint256,address)`` call for removing liquidity."""
        data = encode_calldata(
            _ABI, "burn", [user_token, validator_token, liquidity, to]
        )
        return Call.create(to=FEE_MANAGER_ADDRESS, data=data)

    @staticmethod
    def rebalance_swap(
        *,
        user_token: str,
        validator_token: str,
        amount_out: int,
        to: str,
    ) -> Call:
        """Build a ``rebalanceSwap(address,address,uint256,address)`` call."""
        data = encode_calldata(
            _ABI, "rebalanceSwap", [user_token, validator_token, amount_out, to]
        )
        return Call.create(to=FEE_MANAGER_ADDRESS, data=data)
