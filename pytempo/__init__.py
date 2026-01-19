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

from .access_keys import (
    KEYCHAIN_SIGNATURE_TYPE,
    KEYCHAIN_SIGNATURE_LENGTH,
    build_keychain_signature,
    sign_tx_access_key,
)

from .precompiles import (
    ACCOUNT_KEYCHAIN_ADDRESS,
    GET_REMAINING_LIMIT_SELECTOR,
    encode_get_remaining_limit_calldata,
    get_remaining_spending_limit,
    format_spending_limit,
)

__version__ = "0.2.0"

__all__ = [
    # Transaction
    "TempoAATransaction",
    "create_tempo_transaction",
    "patch_web3_for_tempo",
    # Access keys
    "KEYCHAIN_SIGNATURE_TYPE",
    "KEYCHAIN_SIGNATURE_LENGTH",
    "build_keychain_signature",
    "sign_tx_access_key",
    # Precompiles
    "ACCOUNT_KEYCHAIN_ADDRESS",
    "GET_REMAINING_LIMIT_SELECTOR",
    "encode_get_remaining_limit_calldata",
    "get_remaining_spending_limit",
    "format_spending_limit",
]
