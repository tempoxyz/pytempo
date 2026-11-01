---
pytempo: patch
---

Fixed `TempoTransaction.from_dict` to accept JSON-RPC-style hex-string quantities (e.g. `{"chainId": "0xa5bd", "value": "0x64"}`). Previously such dicts — the standard Ethereum JSON encoding implied by the supported camelCase keys — raised `TypeError` during validation because quantities were left as strings. Decimal-string and integer inputs continue to work.
