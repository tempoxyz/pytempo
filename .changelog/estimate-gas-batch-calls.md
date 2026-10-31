---
pytempo: patch
---

Fixed `TempoTransaction.to_estimate_gas_request` estimating only the first call of a batch. A transaction with several calls is now sent as `calls`, so the node estimates the whole batch. Previously the returned gas limit covered only the first call, and the node rejected the resulting batch transaction with "intrinsic gas too low". Single-call requests are unchanged.
