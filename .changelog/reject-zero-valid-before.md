---
pytempo: patch
---

Fixed `TempoTransaction.validate()` to reject `valid_before=0`, which encoded as no expiry and produced a transaction that never expires.
