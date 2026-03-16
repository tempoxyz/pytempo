"""Typed helpers for TIP-20 token interactions.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import TIP20, ALPHA_USD

    alpha = TIP20(ALPHA_USD)
    call = alpha.transfer(to=recipient, amount=100_000_000)
    tx = TempoTransaction.create(..., calls=(call,))
"""

from pytempo.models import Call

from ._encode import encode_calldata
from .abis import TIP20_ABI

_ABI = TIP20_ABI


class TIP20:
    """TIP-20 token call builders.

    Instantiate with a token address, then call methods without repeating it::

        alpha = TIP20(ALPHA_USD)
        alpha.transfer(to=recipient, amount=100_000_000)
    """

    def __init__(self, token: str) -> None:
        self.token = token

    def transfer(self, *, to: str, amount: int) -> Call:
        """Build a ``transfer(address,uint256)`` call."""
        data = encode_calldata(_ABI, "transfer", [to, amount])
        return Call.create(to=self.token, data=data)

    def transfer_with_memo(self, *, to: str, amount: int, memo: bytes) -> Call:
        """Build a ``transferWithMemo(address,uint256,bytes32)`` call.

        *memo* is right-padded to 32 bytes if shorter.
        """
        if len(memo) > 32:
            raise ValueError("memo must be at most 32 bytes")
        padded = memo.ljust(32, b"\x00")
        data = encode_calldata(_ABI, "transferWithMemo", [to, amount, padded])
        return Call.create(to=self.token, data=data)

    def transfer_from(self, *, sender: str, to: str, amount: int) -> Call:
        """Build a ``transferFrom(address,address,uint256)`` call."""
        data = encode_calldata(_ABI, "transferFrom", [sender, to, amount])
        return Call.create(to=self.token, data=data)

    def transfer_from_with_memo(
        self, *, sender: str, to: str, amount: int, memo: bytes
    ) -> Call:
        """Build a ``transferFromWithMemo(address,address,uint256,bytes32)`` call."""
        if len(memo) > 32:
            raise ValueError("memo must be at most 32 bytes")
        padded = memo.ljust(32, b"\x00")
        data = encode_calldata(
            _ABI, "transferFromWithMemo", [sender, to, amount, padded]
        )
        return Call.create(to=self.token, data=data)

    def approve(self, *, spender: str, amount: int) -> Call:
        """Build an ``approve(address,uint256)`` call."""
        data = encode_calldata(_ABI, "approve", [spender, amount])
        return Call.create(to=self.token, data=data)

    def mint(self, *, to: str, amount: int) -> Call:
        """Build a ``mint(address,uint256)`` call (issuer only)."""
        data = encode_calldata(_ABI, "mint", [to, amount])
        return Call.create(to=self.token, data=data)

    def mint_with_memo(self, *, to: str, amount: int, memo: bytes) -> Call:
        """Build a ``mintWithMemo(address,uint256,bytes32)`` call (issuer only)."""
        if len(memo) > 32:
            raise ValueError("memo must be at most 32 bytes")
        padded = memo.ljust(32, b"\x00")
        data = encode_calldata(_ABI, "mintWithMemo", [to, amount, padded])
        return Call.create(to=self.token, data=data)

    def burn(self, *, amount: int) -> Call:
        """Build a ``burn(uint256)`` call."""
        data = encode_calldata(_ABI, "burn", [amount])
        return Call.create(to=self.token, data=data)

    def burn_with_memo(self, *, amount: int, memo: bytes) -> Call:
        """Build a ``burnWithMemo(uint256,bytes32)`` call."""
        if len(memo) > 32:
            raise ValueError("memo must be at most 32 bytes")
        padded = memo.ljust(32, b"\x00")
        data = encode_calldata(_ABI, "burnWithMemo", [amount, padded])
        return Call.create(to=self.token, data=data)

    def permit(
        self,
        *,
        owner: str,
        spender: str,
        value: int,
        deadline: int,
        v: int,
        r: bytes,
        s: bytes,
    ) -> Call:
        """Build a ``permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`` call."""
        if len(r) != 32:
            raise ValueError("r must be exactly 32 bytes")
        if len(s) != 32:
            raise ValueError("s must be exactly 32 bytes")
        data = encode_calldata(
            _ABI, "permit", [owner, spender, value, deadline, v, r, s]
        )
        return Call.create(to=self.token, data=data)
