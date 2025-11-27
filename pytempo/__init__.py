"""
PyTempo - Web3.py extension for Tempo blockchain

Extends web3.py with native support for Tempo's Account Abstraction
transactions (Type 0x76) and other Tempo-specific features.
"""

from .transaction import (
    TempoAATransaction,
    create_tempo_transaction,
    patch_web3_for_tempo,
)

__version__ = "0.1.0"

__all__ = [
    "TempoAATransaction",
    "create_tempo_transaction",
    "patch_web3_for_tempo",
]
