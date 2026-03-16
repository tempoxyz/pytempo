"""Typed helpers for the Fee Manager precompile.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import FeeManager, BETA_USD

    call = FeeManager.set_user_token(token=BETA_USD)
    tx = TempoTransaction.create(..., calls=(call,))

``FeeManager`` inherits from :class:`FeeAMM`, so liquidity methods
(``mint``, ``burn``, ``rebalance_swap``) are also available directly::

    call = FeeManager.mint(
        user_token=BETA_USD,
        validator_token=PATH_USD,
        amount=1_000_000_000,
        to="0xRecipient...",
    )
"""

from pytempo.models import Call

from ._encode import encode_calldata
from .abis import FEE_MANAGER_ABI
from .addresses import FEE_MANAGER_ADDRESS
from .fee_amm import FeeAMM

_ABI = FEE_MANAGER_ABI


class FeeManager(FeeAMM):
    """Fee Manager precompile call builders.

    Inherits liquidity methods from :class:`FeeAMM`.
    All methods target the fee manager precompile at :data:`FEE_MANAGER_ADDRESS`.
    """

    ADDRESS = FEE_MANAGER_ADDRESS

    @staticmethod
    def set_user_token(*, token: str) -> Call:
        """Build a ``setUserToken(address)`` call."""
        data = encode_calldata(_ABI, "setUserToken", [token])
        return Call.create(to=FEE_MANAGER_ADDRESS, data=data)

    @staticmethod
    def set_validator_token(*, token: str) -> Call:
        """Build a ``setValidatorToken(address)`` call."""
        data = encode_calldata(_ABI, "setValidatorToken", [token])
        return Call.create(to=FEE_MANAGER_ADDRESS, data=data)

    @staticmethod
    def distribute_fees(*, validator: str, token: str) -> Call:
        """Build a ``distributeFees(address,address)`` call."""
        data = encode_calldata(_ABI, "distributeFees", [validator, token])
        return Call.create(to=FEE_MANAGER_ADDRESS, data=data)
