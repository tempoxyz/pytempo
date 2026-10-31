---
pytempo: minor
---

Added `TempoTransaction.decode()` to strictly decode signed `0x76` transactions (as tempo-primitives does) and recover the sender (the root account for keychain signatures), plus `TempoTransaction.recover_sender()`, `TempoTransaction.recover_fee_payer()`, `Signature.recover()` and `KeychainSignature.recover_key_id()`. `KeychainSignature` now also parses and encodes legacy V1 (`0x03`) envelopes via a new `version` field. P256, WebAuthn and configurable account signatures raise `NotImplementedError` when decoding. Added support for periodic token limits (`TokenLimit.period`) in inline key authorizations: they are encoded as `[token, limit, period]`, signed and included in `to_json()`, instead of being rejected. Fixed `TempoTransaction.validate()` to reject `valid_after == valid_before`, which the node rejects.
