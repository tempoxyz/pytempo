"""Internal helper for ABI-encoding calldata from shipped ABI definitions."""

from collections.abc import Mapping, Sequence

from eth_abi import encode, is_encodable
from eth_utils import is_hex_address, keccak, to_checksum_address

# Cache resolved function entries per ABI (keyed by id of the ABI list).
# We store a reference to the ABI list to prevent GC from reusing its id.
_fn_cache: dict[int, tuple[list, dict[str, list[tuple[bytes, list[str], list]]]]] = {}


def _abi_type(param: Mapping) -> str:
    """Canonical type string of an ABI parameter, expanding tuples."""
    typ = param["type"]
    if typ.startswith("tuple"):
        inner = ",".join(_abi_type(c) for c in param["components"])
        return f"({inner}){typ[len('tuple') :]}"
    return typ


def _functions(abi: list) -> dict[str, list[tuple[bytes, list[str], list]]]:
    key = id(abi)
    if key not in _fn_cache:
        fns: dict[str, list[tuple[bytes, list[str], list]]] = {}
        for entry in abi:
            if entry.get("type") != "function":
                continue
            inputs = entry.get("inputs", [])
            types = [_abi_type(p) for p in inputs]
            selector = keccak(text=f"{entry['name']}({','.join(types)})")[:4]
            fns.setdefault(entry["name"], []).append((selector, types, inputs))
        _fn_cache[key] = (abi, fns)
    return _fn_cache[key][1]


def _normalize_arg(value: object, param: Mapping | None = None) -> object:
    """Auto-checksum bare hex addresses and order struct dicts by component."""
    if isinstance(value, str) and is_hex_address(value):
        return to_checksum_address(value)
    typ = param["type"] if param is not None else ""
    if typ.startswith("tuple"):
        components = param["components"]
        if typ != "tuple":  # tuple[] / tuple[N]: an array of structs
            elem = {**param, "type": typ[: typ.rindex("[")]}
            return [_normalize_arg(v, elem) for v in value]
        if isinstance(value, Mapping):
            value = [value[c["name"]] for c in components]
        return tuple(_normalize_arg(v, c) for v, c in zip(value, components))
    if (
        typ.endswith("]")
        and isinstance(value, Sequence)
        and not isinstance(value, (str, bytes, bytearray))
    ):
        elem = {**param, "type": typ[: typ.rindex("[")]}
        return [_normalize_arg(v, elem) for v in value]
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
    candidates = _functions(abi).get(fn_name)
    if not candidates:
        raise ValueError(f"Function {fn_name!r} not found in ABI")

    matches = []
    for selector, types, inputs in candidates:
        if len(inputs) != len(args):
            continue
        normalized = [_normalize_arg(a, p) for a, p in zip(args, inputs)]
        if all(is_encodable(t, v) for t, v in zip(types, normalized)):
            matches.append((selector, types, normalized))

    if not matches:
        raise ValueError(f"Arguments do not match any {fn_name!r} signature in ABI")
    if len(matches) > 1:
        raise ValueError(f"Arguments match several {fn_name!r} signatures in ABI")

    selector, types, normalized = matches[0]
    return "0x" + (selector + encode(types, normalized)).hex()
