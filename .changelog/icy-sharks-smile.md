---
pytempo: patch
---

Fixed RLP encoding to treat `expiry=0` the same as `expiry=None` (never expires) in both `KeyAuthorization` and `SignedKeyAuthorization`.
