---
pytempo: major
---

Added TIP-1011 `authorizeKey` support with `KeyRestrictions` struct (T3+) as the new `authorize_key` method, and renamed the previous flat-params variant to `authorize_key_legacy` for pre-T3 compatibility. Updated `IAccountKeychain` ABI with the new function signature and `LegacyAuthorizeKeySelectorChanged` error.
