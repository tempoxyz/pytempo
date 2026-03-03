---
pytempo: minor
---

Fixed Keychain signature type identifier from `0x03` to `0x04` (V2 format) and updated the signing scheme to use `keccak256(0x04 || sig_hash || user_address)` instead of the raw sig_hash, providing domain separation to prevent cross-scheme signature confusion.
