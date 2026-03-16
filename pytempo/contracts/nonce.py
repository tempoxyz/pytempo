"""Typed helpers for the Nonce precompile.

Query nonce values for Tempo's 2D nonce system::

    from pytempo.contracts import Nonce
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))

    nonce = Nonce.get_nonce(w3, account="0xAccount...", nonce_key=0)
"""

from ._encode import encode_calldata
from .abis import NONCE_ABI
from .addresses import NONCE_ADDRESS

_ABI = NONCE_ABI


class Nonce:
    """Nonce precompile call builders.

    All methods target the nonce precompile at :data:`NONCE_ADDRESS`.
    """

    ADDRESS = NONCE_ADDRESS

    @staticmethod
    def get_nonce(w3, *, account: str, nonce_key: int) -> int:
        """Query the current nonce for an account and nonce key.

        Args:
            w3: Web3 instance connected to a Tempo RPC.
            account: The account address.
            nonce_key: The nonce key (2D nonce lane).

        Returns:
            Current nonce value for the given account and key.
        """
        call_data = encode_calldata(_ABI, "getNonce", [account, nonce_key])
        result = w3.eth.call({"to": NONCE_ADDRESS, "data": call_data})
        return int.from_bytes(result, "big")
