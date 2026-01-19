"""Tempo precompile addresses and utilities.

Tempo has several precompiled contracts at reserved addresses for protocol
functionality like account abstraction, fee tokens, and access key management.
"""

from eth_utils import to_checksum_address

# Account Keychain precompile - manages access key authorizations and spending limits
ACCOUNT_KEYCHAIN_ADDRESS = "0xaAAAaaAA00000000000000000000000000000000"

# Function selectors for AccountKeychain precompile
GET_REMAINING_LIMIT_SELECTOR = "0x63b4290d"  # getRemainingLimit(address,address,address)


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
    call_data = encode_get_remaining_limit_calldata(account_address, key_id, token_address)
    
    result = w3.eth.call({"to": keychain, "data": call_data})
    return int.from_bytes(result, 'big')


def format_spending_limit(limit_base_units: int, decimals: int = 6) -> str:
    """Format spending limit for display.
    
    Args:
        limit_base_units: Limit in base units
        decimals: Token decimals (default 6 for USDM)
    
    Returns:
        Formatted string like "$10.00" or "∞" for unlimited
    """
    if limit_base_units == 0:
        return "$0"
    if limit_base_units >= 2**128:  # Effectively unlimited
        return "∞"
    amount = limit_base_units / (10 ** decimals)
    return f"${amount:.2f}"
