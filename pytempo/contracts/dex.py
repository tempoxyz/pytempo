"""Typed helpers for the Stablecoin DEX precompile.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import StablecoinDEX, BETA_USD

    call = StablecoinDEX.place(token=BETA_USD, amount=100_000_000, is_bid=True, tick=10)
    tx = TempoTransaction.create(..., calls=(call,))
"""

from pytempo.models import Call

from ._decode import decode_u64
from ._encode import encode_calldata
from .abis import STABLECOIN_DEX_ABI
from .addresses import STABLECOIN_DEX_ADDRESS

_ABI = STABLECOIN_DEX_ABI


class StablecoinDEX:
    """Stablecoin DEX call builders.

    All methods target the StablecoinDEX precompile at :data:`STABLECOIN_DEX_ADDRESS`.
    """

    ADDRESS = STABLECOIN_DEX_ADDRESS

    @staticmethod
    def place(*, token: str, amount: int, is_bid: bool, tick: int) -> Call:
        """Build a ``place(address,uint128,bool,int16)`` call."""
        data = encode_calldata(_ABI, "place", [token, amount, is_bid, tick])
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def place_flip(
        *,
        token: str,
        amount: int,
        is_bid: bool,
        tick: int,
        flip_tick: int,
    ) -> Call:
        """Build a ``placeFlip(address,uint128,bool,int16,int16)`` call."""
        data = encode_calldata(
            _ABI, "placeFlip", [token, amount, is_bid, tick, flip_tick]
        )
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def cancel(*, order_id: int) -> Call:
        """Build a ``cancel(uint128)`` call."""
        data = encode_calldata(_ABI, "cancel", [order_id])
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def cancel_stale_order(*, order_id: int) -> Call:
        """Build a ``cancelStaleOrder(uint128)`` call."""
        data = encode_calldata(_ABI, "cancelStaleOrder", [order_id])
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def swap_exact_amount_in(
        *,
        token_in: str,
        token_out: str,
        amount_in: int,
        min_amount_out: int,
    ) -> Call:
        """Build a ``swapExactAmountIn(address,address,uint128,uint128)`` call."""
        data = encode_calldata(
            _ABI,
            "swapExactAmountIn",
            [token_in, token_out, amount_in, min_amount_out],
        )
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def swap_exact_amount_out(
        *,
        token_in: str,
        token_out: str,
        amount_out: int,
        max_amount_in: int,
    ) -> Call:
        """Build a ``swapExactAmountOut(address,address,uint128,uint128)`` call."""
        data = encode_calldata(
            _ABI,
            "swapExactAmountOut",
            [token_in, token_out, amount_out, max_amount_in],
        )
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def withdraw(*, token: str, amount: int) -> Call:
        """Build a ``withdraw(address,uint128)`` call."""
        data = encode_calldata(_ABI, "withdraw", [token, amount])
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def create_pair(*, base: str) -> Call:
        """Build a ``createPair(address)`` call."""
        data = encode_calldata(_ABI, "createPair", [base])
        return Call.create(to=STABLECOIN_DEX_ADDRESS, data=data)

    @staticmethod
    def storage_credits(w3, *, user: str) -> int:
        """Query the reusable order-storage credits owned by ``user`` (TIP-1064).

        A maker earns one credit for each of their own order-record storage
        slots that is freed, and can apply it to offset the cost of creating
        storage for a later order.

        Args:
            w3: Web3 instance connected to a Tempo RPC.
            user: The user whose DEX storage-credit balance is queried.

        Returns:
            The number of storage credits available to ``user`` (saturates at
            ``uint64`` max).

        Raises:
            ValueError: If ``user`` is empty or the result is malformed.
        """
        if not user:
            raise ValueError("user required")
        call_data = encode_calldata(_ABI, "storageCredits", [user])
        result = w3.eth.call({"to": STABLECOIN_DEX_ADDRESS, "data": call_data})
        return decode_u64(result, "storageCredits")
