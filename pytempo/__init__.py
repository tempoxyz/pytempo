"""
PyTempo - Web3.py extension for Tempo blockchain

Extends web3.py with native support for Tempo's Account Abstraction
transactions (Type 0x76) and other Tempo-specific features.
"""

from .keychain import (
    # Precompile address and selectors
    ACCOUNT_KEYCHAIN_ADDRESS,
    GET_REMAINING_LIMIT_SELECTOR,
    INNER_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_LENGTH,
    # Signature constants
    KEYCHAIN_SIGNATURE_TYPE,
    # Signing functions
    build_keychain_signature,
    # Precompile queries
    encode_get_remaining_limit_calldata,
    format_spending_limit,
    get_remaining_spending_limit,
    sign_tx_access_key,
)
from .transaction import (
    TempoAATransaction,
    create_tempo_transaction,
    patch_web3_for_tempo,
)

__version__ = "0.2.0"

__all__ = [
    # Transaction
    "TempoAATransaction",
    "create_tempo_transaction",
    "patch_web3_for_tempo",
    # Keychain precompile
    "ACCOUNT_KEYCHAIN_ADDRESS",
    "GET_REMAINING_LIMIT_SELECTOR",
    "encode_get_remaining_limit_calldata",
    "get_remaining_spending_limit",
    "format_spending_limit",
    # Keychain signing
    "KEYCHAIN_SIGNATURE_TYPE",
    "KEYCHAIN_SIGNATURE_LENGTH",
    "INNER_SIGNATURE_LENGTH",
    "build_keychain_signature",
    "sign_tx_access_key",
]
