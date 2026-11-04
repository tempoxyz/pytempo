"""Internal helper for ABI-encoding calldata from shipped ABI definitions.

Encodes with ``eth_abi`` directly so the core package does not need web3.
"""

from __future__ import annotations

from eth_abi import encode as abi_encode
from eth_utils import is_hex_address, keccak, to_bytes, to_checksum_address


def _collapse_type(param: dict) -> str:
    """Return the canonical ABI type string, expanding tuples to ``(a,b)``."""
    typ = param["type"]
    if not typ.startswith("tuple"):
        return typ
    inner = ",".join(_collapse_type(c) for c in param["components"])
    return f"({inner}){typ[len('tuple') :]}"


def _normalize(param: dict, value: object) -> object:
    """Coerce a Python value into what ``eth_abi`` expects for ``param``.

    Bare hex addresses are checksummed and hex strings for ``bytes``/``bytesN``
    are decoded, as web3's ``encode_abi`` accepted them.
    """
    typ = param["type"]
    if typ.endswith("]"):
        elem = dict(param, type=typ[: typ.rindex("[")])
        return [_normalize(elem, v) for v in value]  # type: ignore[union-attr]
    if typ == "tuple":
        components = param["components"]
        if isinstance(value, dict):
            value = [value[c["name"]] for c in components]
        return tuple(
            _normalize(c, v)
            for c, v in zip(components, value, strict=True)  # type: ignore[call-overload]
        )
    if typ == "address":
        if isinstance(value, str) and is_hex_address(value):
            return to_checksum_address(value)
        if isinstance(value, (bytes, bytearray)) and len(value) == 20:
            return to_checksum_address(value)
        return value
    if typ.startswith("bytes") and isinstance(value, str):
        return to_bytes(hexstr=value)
    return value


def _find_function(abi: list, fn_name: str, args: list) -> dict:
    """Pick the ABI entry for ``fn_name``, resolving overloads by arity."""
    candidates = [
        e
        for e in abi
        if e.get("type") == "function"
        and e.get("name") == fn_name
        and len(e.get("inputs", [])) == len(args)
    ]
    if not candidates:
        raise ValueError(
            f"No function {fn_name!r} with {len(args)} argument(s) in the ABI"
        )
    if len(candidates) > 1:
        raise ValueError(f"Ambiguous function {fn_name!r} with {len(args)} arguments")
    return candidates[0]


def encode_calldata(abi: list, fn_name: str, args: list) -> str:
    """Encode calldata using a shipped ABI definition.

    Args:
        abi: The ABI JSON list (e.g. ``TIP20_ABI``).
        fn_name: Solidity function name (e.g. ``"transfer"``).
        args: Positional arguments matching the function signature.

    Returns:
        Hex-encoded calldata string (with ``0x`` prefix).
    """
    fn = _find_function(abi, fn_name, args)
    inputs = fn.get("inputs", [])
    types = [_collapse_type(p) for p in inputs]
    selector = keccak(text=f"{fn_name}({','.join(types)})")[:4]
    normalized = [_normalize(p, a) for p, a in zip(inputs, args, strict=True)]
    return "0x" + (selector + abi_encode(types, normalized)).hex()
