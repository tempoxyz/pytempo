"""Access key (Keychain) signing for Tempo transactions.

Tempo access keys allow a separate key to sign transactions on behalf of a wallet.
The Keychain signature format embeds the root account address in the signature,
which the protocol uses to look up the access key authorization via the
AccountKeychain precompile.

Per Tempo spec, Keychain signatures have format:
    0x03 || user_address (20 bytes) || inner_signature (65 bytes)

Where:
- 0x03 is the Keychain signature type identifier
- user_address is the root account (the account the access key signs on behalf of)
- inner_signature is the secp256k1 signature from the access key (r || s || v)

Total signature length: 86 bytes
"""

from eth_account import Account
from eth_utils import to_bytes

# Keychain signature type identifier
KEYCHAIN_SIGNATURE_TYPE = 0x03

# Expected signature lengths
INNER_SIGNATURE_LENGTH = 65  # r (32) + s (32) + v (1)
KEYCHAIN_SIGNATURE_LENGTH = 86  # type (1) + address (20) + inner (65)


def build_keychain_signature(
    msg_hash: bytes,
    access_key_private_key: str,
    root_account: str,
) -> bytes:
    """Build a Keychain signature for a message hash.
    
    Args:
        msg_hash: 32-byte hash to sign
        access_key_private_key: Private key of the access key (hex string with 0x prefix)
        root_account: Address of the root account (hex string with 0x prefix)
    
    Returns:
        86-byte Keychain signature: 0x03 || root_account (20 bytes) || inner_sig (65 bytes)
    """
    # Sign with the access key
    account = Account.from_key(access_key_private_key)
    signed_msg = account.unsafe_sign_hash(msg_hash)
    
    # Build the inner secp256k1 signature (65 bytes): r || s || v
    inner_sig = (
        signed_msg.r.to_bytes(32, 'big') +
        signed_msg.s.to_bytes(32, 'big') +
        bytes([signed_msg.v])
    )
    
    # Build Keychain signature: 0x03 || root_account (20 bytes) || inner_sig (65 bytes)
    root_account_bytes = to_bytes(hexstr=root_account)
    keychain_sig = bytes([KEYCHAIN_SIGNATURE_TYPE]) + root_account_bytes + inner_sig
    
    assert len(keychain_sig) == KEYCHAIN_SIGNATURE_LENGTH, \
        f"Expected {KEYCHAIN_SIGNATURE_LENGTH} bytes, got {len(keychain_sig)}"
    
    return keychain_sig


def sign_tx_access_key(tx, access_key_private_key: str, root_account: str):
    """Sign a Tempo transaction using access key mode (Keychain signature).
    
    This mutates the transaction in place:
    - Sets tx.sender_address to root_account
    - Sets tx.signature to the Keychain signature
    - Clears tx.v, tx.r, tx.s
    
    Args:
        tx: TempoAATransaction to sign
        access_key_private_key: Private key of the access key (hex string with 0x prefix)
        root_account: Address of the root account (hex string with 0x prefix)
    
    Returns:
        The transaction (for chaining)
    """
    # CRITICAL: Set sender_address to root account BEFORE computing signing hash
    tx.sender_address = to_bytes(hexstr=root_account)
    
    # Get the signing hash
    msg_hash = tx.get_signing_hash(for_fee_payer=False)
    
    # Build and set the Keychain signature
    tx.signature = build_keychain_signature(msg_hash, access_key_private_key, root_account)
    
    # Clear v/r/s since we're using raw signature bytes
    tx.v = None
    tx.r = None
    tx.s = None
    
    return tx
