"""Typed helpers for TIP-20 token interactions.

Returns :class:`~pytempo.Call` objects ready to use in a
:class:`~pytempo.TempoTransaction`::

    from pytempo.contracts import TIP20, ALPHA_USD

    alpha = TIP20(ALPHA_USD)
    call = alpha.transfer(to=recipient, amount=100_000_000)
    tx = TempoTransaction.create(..., calls=(call,))
"""

from pytempo.models import Call
from pytempo.types import BytesLike, as_hash32

from ._decode import decode_bool, decode_hash32
from ._encode import encode_calldata
from .abis import TIP20_ABI, TIP20_ROLES_AUTH_ABI

_ABI = TIP20_ABI
_ROLES_ABI = TIP20_ROLES_AUTH_ABI


def _memo32(memo: bytes) -> bytes:
    if len(memo) > 32:
        raise ValueError("memo must be at most 32 bytes")
    return memo.ljust(32, b"\x00")


def _role32(role: BytesLike) -> bytes:
    return bytes(as_hash32(role))


def _require_account(account: str) -> None:
    if not account:
        raise ValueError("account required")


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
        data = encode_calldata(_ABI, "transferWithMemo", [to, amount, _memo32(memo)])
        return Call.create(to=self.token, data=data)

    def transfer_from(self, *, sender: str, to: str, amount: int) -> Call:
        """Build a ``transferFrom(address,address,uint256)`` call."""
        data = encode_calldata(_ABI, "transferFrom", [sender, to, amount])
        return Call.create(to=self.token, data=data)

    def transfer_from_with_memo(
        self, *, sender: str, to: str, amount: int, memo: bytes
    ) -> Call:
        """Build a ``transferFromWithMemo(address,address,uint256,bytes32)`` call."""
        data = encode_calldata(
            _ABI, "transferFromWithMemo", [sender, to, amount, _memo32(memo)]
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
        data = encode_calldata(_ABI, "mintWithMemo", [to, amount, _memo32(memo)])
        return Call.create(to=self.token, data=data)

    def burn(self, *, amount: int) -> Call:
        """Build a ``burn(uint256)`` call."""
        data = encode_calldata(_ABI, "burn", [amount])
        return Call.create(to=self.token, data=data)

    def burn_with_memo(self, *, amount: int, memo: bytes) -> Call:
        """Build a ``burnWithMemo(uint256,bytes32)`` call."""
        data = encode_calldata(_ABI, "burnWithMemo", [amount, _memo32(memo)])
        return Call.create(to=self.token, data=data)

    def burn_blocked(self, *, sender: str, amount: int) -> Call:
        """Build a ``burnBlocked(address,uint256)`` call."""
        data = encode_calldata(_ABI, "burnBlocked", [sender, amount])
        return Call.create(to=self.token, data=data)

    def change_transfer_policy_id(self, *, new_policy_id: int) -> Call:
        """Build a ``changeTransferPolicyId(uint64)`` call."""
        data = encode_calldata(_ABI, "changeTransferPolicyId", [new_policy_id])
        return Call.create(to=self.token, data=data)

    def claim_rewards(self) -> Call:
        """Build a ``claimRewards()`` call."""
        data = encode_calldata(_ABI, "claimRewards", [])
        return Call.create(to=self.token, data=data)

    def complete_quote_token_update(self) -> Call:
        """Build a ``completeQuoteTokenUpdate()`` call."""
        data = encode_calldata(_ABI, "completeQuoteTokenUpdate", [])
        return Call.create(to=self.token, data=data)

    def distribute_reward(self, *, amount: int) -> Call:
        """Build a ``distributeReward(uint256)`` call."""
        data = encode_calldata(_ABI, "distributeReward", [amount])
        return Call.create(to=self.token, data=data)

    def pause(self) -> Call:
        """Build a ``pause()`` call."""
        data = encode_calldata(_ABI, "pause", [])
        return Call.create(to=self.token, data=data)

    def set_logo_uri(self, *, logo_uri: str) -> Call:
        """Build a ``setLogoURI(string)`` call."""
        data = encode_calldata(_ABI, "setLogoURI", [logo_uri])
        return Call.create(to=self.token, data=data)

    def set_next_quote_token(self, *, new_quote_token: str) -> Call:
        """Build a ``setNextQuoteToken(address)`` call."""
        data = encode_calldata(_ABI, "setNextQuoteToken", [new_quote_token])
        return Call.create(to=self.token, data=data)

    def set_reward_recipient(self, *, new_reward_recipient: str) -> Call:
        """Build a ``setRewardRecipient(address)`` call."""
        data = encode_calldata(_ABI, "setRewardRecipient", [new_reward_recipient])
        return Call.create(to=self.token, data=data)

    def set_supply_cap(self, *, new_supply_cap: int) -> Call:
        """Build a ``setSupplyCap(uint256)`` call."""
        data = encode_calldata(_ABI, "setSupplyCap", [new_supply_cap])
        return Call.create(to=self.token, data=data)

    def unpause(self) -> Call:
        """Build an ``unpause()`` call."""
        data = encode_calldata(_ABI, "unpause", [])
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

    def grant_role(self, *, role: BytesLike, account: str) -> Call:
        """Build a ``grantRole(bytes32,address)`` call."""
        data = encode_calldata(_ROLES_ABI, "grantRole", [_role32(role), account])
        return Call.create(to=self.token, data=data)

    def revoke_role(self, *, role: BytesLike, account: str) -> Call:
        """Build a ``revokeRole(bytes32,address)`` call."""
        data = encode_calldata(_ROLES_ABI, "revokeRole", [_role32(role), account])
        return Call.create(to=self.token, data=data)

    def renounce_role(self, *, role: BytesLike) -> Call:
        """Build a ``renounceRole(bytes32)`` call."""
        data = encode_calldata(_ROLES_ABI, "renounceRole", [_role32(role)])
        return Call.create(to=self.token, data=data)

    def set_role_admin(self, *, role: BytesLike, admin_role: BytesLike) -> Call:
        """Build a ``setRoleAdmin(bytes32,bytes32)`` call."""
        data = encode_calldata(
            _ROLES_ABI, "setRoleAdmin", [_role32(role), _role32(admin_role)]
        )
        return Call.create(to=self.token, data=data)

    def get_role_admin(self, w3, *, role: BytesLike) -> bytes:
        """Query ``getRoleAdmin(bytes32)``."""
        call_data = encode_calldata(_ROLES_ABI, "getRoleAdmin", [_role32(role)])
        result = w3.eth.call({"to": self.token, "data": call_data})
        return decode_hash32(result, "getRoleAdmin")

    def has_role(self, w3, *, role: BytesLike, account: str) -> bool:
        """Query ``hasRole(address,bytes32)``."""
        _require_account(account)
        call_data = encode_calldata(_ROLES_ABI, "hasRole", [account, _role32(role)])
        result = w3.eth.call({"to": self.token, "data": call_data})
        return decode_bool(result, "hasRole")

    def burn_blocked_role(self, w3) -> bytes:
        """Query ``BURN_BLOCKED_ROLE()``."""
        return self._role_constant(w3, "BURN_BLOCKED_ROLE")

    def issuer_role(self, w3) -> bytes:
        """Query ``ISSUER_ROLE()``."""
        return self._role_constant(w3, "ISSUER_ROLE")

    def pause_role(self, w3) -> bytes:
        """Query ``PAUSE_ROLE()``."""
        return self._role_constant(w3, "PAUSE_ROLE")

    def unpause_role(self, w3) -> bytes:
        """Query ``UNPAUSE_ROLE()``."""
        return self._role_constant(w3, "UNPAUSE_ROLE")

    def _role_constant(self, w3, name: str) -> bytes:
        call_data = encode_calldata(_ABI, name, [])
        result = w3.eth.call({"to": self.token, "data": call_data})
        return decode_hash32(result, name)
