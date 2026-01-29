"""Tempo AccountKeychain precompile: access key management and signing.

The AccountKeychain precompile manages access key authorizations and spending limits.
Access keys allow a separate key to sign transactions on behalf of a wallet.

Per Tempo spec, Keychain signatures have format:
    0x03 || user_address (20 bytes) || inner_signature (65 bytes)

Where:
- 0x03 is the Keychain signature type identifier
- user_address is the root account (the account the access key signs on behalf of)
- inner_signature is the secp256k1 signature from the access key (r || s || v)

Total signature length: 86 bytes
"""

from eth_account import Account
from eth_utils import keccak, to_bytes, to_checksum_address

# AccountKeychain precompile address
ACCOUNT_KEYCHAIN_ADDRESS = "0xaAAAaaAA00000000000000000000000000000000"

# Function selectors
GET_REMAINING_LIMIT_SELECTOR = (
    "0x63b4290d"  # getRemainingLimit(address,address,address)
)
GET_KEY_SELECTOR = "0xbc298553"  # getKey(address,address)

# Event signatures
# KeyAuthorized(address indexed account, address indexed publicKey, uint8 signatureType, uint64 expiry)
KEY_AUTHORIZED_TOPIC = (
    "0x" + keccak(text="KeyAuthorized(address,address,uint8,uint64)").hex()
)
# KeyRevoked(address indexed account, address indexed publicKey)
KEY_REVOKED_TOPIC = "0x" + keccak(text="KeyRevoked(address,address)").hex()

# Keychain signature constants
KEYCHAIN_SIGNATURE_TYPE = 0x03
INNER_SIGNATURE_LENGTH = 65  # r (32) + s (32) + v (1)
KEYCHAIN_SIGNATURE_LENGTH = 86  # type (1) + address (20) + inner (65)


def encode_get_remaining_limit_calldata(
    account_address: str,
    key_id: str,
    token_address: str,
) -> str:
    """Encode calldata for getRemainingLimit(address,address,address).

    Args:
        account_address: The root wallet address
        key_id: The access key ID (address)
        token_address: The token to check limit for

    Returns:
        Hex-encoded calldata string (with 0x prefix)
    """
    account_padded = account_address[2:].lower().zfill(64)
    key_padded = key_id[2:].lower().zfill(64)
    token_padded = token_address[2:].lower().zfill(64)

    return f"{GET_REMAINING_LIMIT_SELECTOR}{account_padded}{key_padded}{token_padded}"


def get_remaining_spending_limit(
    w3,
    account_address: str,
    key_id: str,
    token_address: str,
) -> int:
    """Query remaining spending limit for an access key from the AccountKeychain precompile.

    Args:
        w3: Web3 instance connected to a Tempo RPC
        account_address: The root wallet address
        key_id: The access key ID (address)
        token_address: The token to check limit for

    Returns:
        Remaining spending limit in base units (0 if error or no limit)

    Raises:
        ValueError: If any address parameter is empty
    """
    if not account_address or not key_id or not token_address:
        raise ValueError("account_address, key_id, and token_address are required")

    keychain = to_checksum_address(ACCOUNT_KEYCHAIN_ADDRESS)
    call_data = encode_get_remaining_limit_calldata(
        account_address, key_id, token_address
    )

    result = w3.eth.call({"to": keychain, "data": call_data})
    return int.from_bytes(result, "big")


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
        signed_msg.r.to_bytes(32, "big")
        + signed_msg.s.to_bytes(32, "big")
        + bytes([signed_msg.v])
    )

    # Build Keychain signature: 0x03 || root_account (20 bytes) || inner_sig (65 bytes)
    root_account_bytes = to_bytes(hexstr=root_account)
    keychain_sig = bytes([KEYCHAIN_SIGNATURE_TYPE]) + root_account_bytes + inner_sig

    assert len(keychain_sig) == KEYCHAIN_SIGNATURE_LENGTH, (
        f"Expected {KEYCHAIN_SIGNATURE_LENGTH} bytes, got {len(keychain_sig)}"
    )

    return keychain_sig


def sign_tx_access_key(tx, access_key_private_key: str, root_account: str):
    """Sign a Tempo transaction using access key mode (Keychain signature).

    This mutates the transaction in place:
    - Sets tx.sender_address to root_account
    - Sets tx.signature to the Keychain signature
    - Clears tx.v, tx.r, tx.s

    Args:
        tx: TempoTransaction to sign
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
    tx.signature = build_keychain_signature(
        msg_hash, access_key_private_key, root_account
    )

    # Clear v/r/s since we're using raw signature bytes
    tx.v = None
    tx.r = None
    tx.s = None

    return tx


def get_access_key_info(
    w3,
    account_address: str,
    key_id: str,
) -> dict:
    """Query access key info from the AccountKeychain precompile.

    Args:
        w3: Web3 instance connected to a Tempo RPC
        account_address: The root wallet address
        key_id: The access key ID (address)

    Returns:
        Dict with key info:
        - signature_type: 0=Secp256k1, 1=P256, 2=WebAuthn
        - key_id: The key address
        - expiry: Unix timestamp when key expires (0 = no expiry)
        - enforce_limits: Whether spending limits are enforced
        - is_revoked: Whether key has been revoked

        Returns empty dict if key doesn't exist or on error.
    """
    if not account_address or not key_id:
        return {}

    # Validate: account_address must differ from key_id
    if account_address.lower() == key_id.lower():
        return {}

    try:
        keychain = to_checksum_address(ACCOUNT_KEYCHAIN_ADDRESS)

        # Encode calldata: selector + padded account + padded keyId
        account_padded = account_address[2:].lower().zfill(64)
        key_padded = key_id[2:].lower().zfill(64)
        call_data = f"{GET_KEY_SELECTOR}{account_padded}{key_padded}"

        result = w3.eth.call({"to": keychain, "data": call_data})

        # Decode result: (uint8 signatureType, address keyId, uint64 expiry, bool enforceLimits, bool isRevoked)
        # ABI encoding: each field is 32 bytes padded
        if len(result) < 160:  # 5 * 32 bytes
            return {}

        signature_type = int.from_bytes(result[0:32], "big")
        returned_key_id = "0x" + result[32:64].hex()[-40:]
        expiry = int.from_bytes(result[64:96], "big")
        enforce_limits = int.from_bytes(result[96:128], "big") != 0
        is_revoked = int.from_bytes(result[128:160], "big") != 0

        # If returned key_id is zero address, key doesn't exist
        if returned_key_id == "0x" + "0" * 40:
            return {}

        return {
            "signature_type": signature_type,
            "key_id": to_checksum_address(returned_key_id),
            "expiry": expiry,
            "enforce_limits": enforce_limits,
            "is_revoked": is_revoked,
        }
    except Exception:
        return {}


def list_access_keys(
    w3,
    account_address: str,
    include_revoked: bool = False,
) -> list[dict]:
    """List all access keys for an account by querying KeyAuthorized events.

    Queries the AccountKeychain precompile events to find all keys that have
    been authorized for an account, then fetches current status for each.

    Args:
        w3: Web3 instance connected to a Tempo RPC
        account_address: The root wallet address to list keys for
        include_revoked: Whether to include revoked keys (default: False)

    Returns:
        List of dicts, each containing:
        - key_id: The access key address
        - signature_type: 0=Secp256k1, 1=P256, 2=WebAuthn
        - expiry: Unix timestamp when key expires (0 = no expiry)
        - enforce_limits: Whether spending limits are enforced
        - is_revoked: Whether key has been revoked
    """
    if not account_address:
        return []

    try:
        keychain = to_checksum_address(ACCOUNT_KEYCHAIN_ADDRESS)

        # Pad address to 32 bytes for topic filter (indexed parameter)
        addr_padded = "0x" + "0" * 24 + account_address[2:].lower()

        # Query KeyAuthorized events for this account
        logs = w3.eth.get_logs(
            {
                "address": keychain,
                "fromBlock": "earliest",
                "toBlock": "latest",
                "topics": [KEY_AUTHORIZED_TOPIC, addr_padded],
            }
        )

        # Extract unique key IDs from events
        # topic[2] is the indexed publicKey (key_id)
        key_ids = set()
        for log in logs:
            if len(log["topics"]) >= 3:
                key_id = "0x" + log["topics"][2].hex()[-40:]
                key_ids.add(to_checksum_address(key_id))

        # Fetch current info for each key
        keys = []
        for key_id in key_ids:
            info = get_access_key_info(w3, account_address, key_id)
            if info:
                if include_revoked or not info.get("is_revoked", False):
                    keys.append(info)

        return keys
    except Exception:
        return []
