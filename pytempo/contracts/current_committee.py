"""Typed helpers for the Current Committee precompile.

Query the effective validator committee selected by consensus::

    from pytempo.contracts import CurrentCommittee
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))
    epoch, public_keys = CurrentCommittee.get_committee_members(w3)
"""

from ._encode import encode_calldata
from .abis import CURRENT_COMMITTEE_ABI
from .addresses import CURRENT_COMMITTEE_ADDRESS

_ABI = CURRENT_COMMITTEE_ABI


class CurrentCommittee:
    """Current Committee precompile read helpers."""

    ADDRESS = CURRENT_COMMITTEE_ADDRESS

    @staticmethod
    def get_committee_members(w3) -> tuple[int, tuple[bytes, ...]]:
        """Return the effective committee for the current epoch.

        The public keys are ordered Ed25519 keys from the DKG outcome selected
        by consensus.
        """
        call_data = encode_calldata(_ABI, "getCommitteeMembers", [])
        result = w3.eth.call({"to": CURRENT_COMMITTEE_ADDRESS, "data": call_data})
        epoch, public_keys = w3.codec.decode(["uint64", "bytes32[]"], result)
        return epoch, tuple(public_keys)
