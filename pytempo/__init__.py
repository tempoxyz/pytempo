"""
PyTempo - Web3.py extension for Tempo blockchain

Extends web3.py with native support for Tempo transactions (Type 0x76)
and other Tempo-specific features.

Strongly-Typed API (Recommended):
    from pytempo import TempoTransaction, Call

    tx = TempoTransaction.create(
        chain_id=42429,
        gas_limit=100_000,
        max_fee_per_gas=2_000_000_000,
        calls=(Call.create(to="0xRecipient...", value=1000),),
    )
    signed_tx = tx.sign("0xPrivateKey...")

    # Send raw bytes - no patching needed
    w3.eth.send_raw_transaction(signed_tx.encode())

Legacy API (Backwards Compatible):
    from pytempo import create_tempo_transaction, patch_web3_for_tempo

    # Patch required if using web3's internal transaction parsing
    patch_web3_for_tempo()
    tx = create_tempo_transaction(to="0x...", value=1000, chain_id=42429)
    tx.sign("0xPrivateKey...")
"""

from .keychain import (
    ACCOUNT_KEYCHAIN_ADDRESS,
    GET_REMAINING_LIMIT_SELECTOR,
    INNER_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_TYPE,
    KeyAuthorization,
    SignatureType,
    SignedKeyAuthorization,
    TokenLimit,
    build_keychain_signature,
    create_key_authorization,
    encode_get_remaining_limit_calldata,
    get_remaining_spending_limit,
    sign_tx_access_key,
)
from .models import (
    AccessListItem,
    Call,
    Signature,
    TempoTransaction,
)
from .transaction import (
    LegacyTempoTransaction,
    TempoAATransaction,
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
    as_optional_address,
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
    "as_optional_address",
    # Models (strongly-typed API)
    "Call",
    "AccessListItem",
    "Signature",
    "TempoTransaction",
    # Legacy API (backwards compatible)
    "LegacyTempoTransaction",
    "TempoAATransaction",
    "create_tempo_transaction",
    "patch_web3_for_tempo",
    # Keychain precompile
    "ACCOUNT_KEYCHAIN_ADDRESS",
    "GET_REMAINING_LIMIT_SELECTOR",
    "encode_get_remaining_limit_calldata",
    "get_remaining_spending_limit",
    # Key authorization (inline access key provisioning)
    "KeyAuthorization",
    "SignedKeyAuthorization",
    "SignatureType",
    "TokenLimit",
    "create_key_authorization",
    # Keychain signing
    "KEYCHAIN_SIGNATURE_TYPE",
    "KEYCHAIN_SIGNATURE_LENGTH",
    "INNER_SIGNATURE_LENGTH",
    "build_keychain_signature",
    "sign_tx_access_key",
]
