"""
PyTempo - Web3.py extension for Tempo blockchain

Extends web3.py with native support for Tempo transactions (Type 0x76)
and other Tempo-specific features.

Strongly-Typed API (Recommended):
    from pytempo import TempoTransactionBuilder

    tx = (TempoTransactionBuilder(chain_id=42429)
        .set_gas(100_000)
        .set_max_fee_per_gas(2_000_000_000)
        .add_call("0xRecipient...", value=1000)
        .build()
        .sign("0xPrivateKey..."))

Legacy API (Backwards Compatible):
    from pytempo import create_tempo_transaction, patch_web3_for_tempo

    patch_web3_for_tempo()
    tx = create_tempo_transaction(to="0x...", value=1000, chain_id=42429)
    tx.sign("0xPrivateKey...")
"""

from .builder import TempoTransactionBuilder
from .keychain import (
    ACCOUNT_KEYCHAIN_ADDRESS,
    GET_REMAINING_LIMIT_SELECTOR,
    INNER_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_TYPE,
    build_keychain_signature,
    encode_get_remaining_limit_calldata,
    get_remaining_spending_limit,
    sign_tx_access_key,
)
from .models import (
    AccessListItem,
    Call,
    Signature,
)
from .models import (
    TempoTransaction as TypedTempoTransaction,
)
from .transaction import (
    TempoAATransaction,
    TempoTransaction,
    create_tempo_transaction,
    patch_web3_for_tempo,
)
from .types import (
    Address,
    BytesLike,
    Hash32,
    as_address,
    as_bytes,
    as_hash32,
)

__version__ = "0.3.0"

__all__ = [
    # Types
    "Address",
    "Hash32",
    "BytesLike",
    "as_address",
    "as_bytes",
    "as_hash32",
    # Models
    "Call",
    "AccessListItem",
    "Signature",
    "TypedTempoTransaction",
    # Builder
    "TempoTransactionBuilder",
    # Transaction (backwards compatible)
    "TempoTransaction",
    "TempoAATransaction",
    "create_tempo_transaction",
    "patch_web3_for_tempo",
    # Keychain precompile
    "ACCOUNT_KEYCHAIN_ADDRESS",
    "GET_REMAINING_LIMIT_SELECTOR",
    "encode_get_remaining_limit_calldata",
    "get_remaining_spending_limit",
    # Keychain signing
    "KEYCHAIN_SIGNATURE_TYPE",
    "KEYCHAIN_SIGNATURE_LENGTH",
    "INNER_SIGNATURE_LENGTH",
    "build_keychain_signature",
    "sign_tx_access_key",
]
