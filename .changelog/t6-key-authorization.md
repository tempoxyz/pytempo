---
pytempo: minor
---

Support the T6 (TIP-1049) `KeyAuthorization` wire format: encode and decode the
new `is_admin` and `account` fields (plus the trailing `witness` field) using the
trailing-canonical RLP layout. Adds admin-key validation, canonical-RLP decoding
(`KeyAuthorization.decode` / `SignedKeyAuthorization.decode`), and `to_json`
support. `expiry=0` is now rejected — use `None` for "never expires".
