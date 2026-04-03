---
pytempo: minor
---

Added `AccountKeychain.get_key()` method to query key info from the AccountKeychain precompile, returning signature type, key ID, expiry, enforce limits, and revocation status. Added integration tests for keychain selectors, spending limits, inline key authorization, transaction validation, and encoding round-trips, plus unit tests for the new `get_key` method.
