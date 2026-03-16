"""Internal helper for ABI-encoding calldata from shipped ABI definitions."""

from eth_utils import is_hex_address, to_checksum_address
from web3 import Web3

# Offline Web3 instance — no provider needed, just ABI encoding.
_w3 = Web3()

# Cache contract objects per ABI (keyed by id of the ABI list).
# We store a reference to the ABI list to prevent GC from reusing its id.
_contract_cache: dict[int, tuple[list, object]] = {}


def _get_contract(abi: list):
    key = id(abi)
    if key not in _contract_cache:
        _contract_cache[key] = (abi, _w3.eth.contract(abi=abi))
    return _contract_cache[key][1]


def _normalize_arg(value: object) -> object:
    """Auto-checksum bare hex addresses so callers don't have to."""
    if isinstance(value, str) and is_hex_address(value):
        return to_checksum_address(value)
    if isinstance(value, (list, tuple)):
        return type(value)(_normalize_arg(v) for v in value)
    return value


def encode_calldata(abi: list, fn_name: str, args: list) -> str:
    """Encode calldata using a shipped ABI definition.

    Args:
        abi: The ABI JSON list (e.g. ``TIP20_ABI``).
        fn_name: Solidity function name (e.g. ``"transfer"``).
        args: Positional arguments matching the function signature.

    Returns:
        Hex-encoded calldata string (with ``0x`` prefix).
    """
    contract = _get_contract(abi)
    normalized = [_normalize_arg(a) for a in args]
    return contract.encode_abi(fn_name, args=normalized)
