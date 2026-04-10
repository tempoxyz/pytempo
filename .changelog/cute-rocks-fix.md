---
pytempo: minor
---

Added `KeyRestrictions` class for access-key restriction management and integrated it into `AccountKeychain.authorize_key()`.

- `KeyRestrictions` with `expiry`, `limits`, `allowed_calls` fields
- `is_unrestricted()` and `is_call_allowed(target, input_data)` introspection helpers
- `to_abi_tuple()` for ABI encoding
- `no_spending()` / `no_calls()` convenience constructors
- `TokenLimit.period` field with uint64 validation
- `AccountKeychain.authorize_key()` now takes `restrictions=KeyRestrictions(...)` (breaking)
- `AccountKeychain.authorize_key_legacy()` convenience method
- `KeyAuthorization` rejects periodic limits with a clear error
- `CallScope.with_selector()` documented in access-keys guide
