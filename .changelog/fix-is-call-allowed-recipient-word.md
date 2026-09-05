---
pytempo: patch
---

Fixed `KeyRestrictions.is_call_allowed` to reject a recipient-constrained call whose first ABI word after the selector has non-zero upper bytes. It now requires a clean ABI-encoded address (upper 12 bytes zero) before comparing the recipient, matching `tempo_alloy`'s `call_scopes_allow` and the on-chain precompile. Previously the upper 12 bytes were ignored, so a malformed word could be reported as allowed even though the chain rejects it.
