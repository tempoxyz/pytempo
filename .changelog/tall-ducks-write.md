---
pytempo: minor
---

Exposed the Tempo transaction signing preimage via `TempoTransaction.encode_for_signing()`, allowing callers to access the exact byte sequence that is hashed for signing. Refactored internal `_signing_hash_*` methods into `_encode_for_*_signing()` helpers and added tests verifying the preimage matches the signing hash.
