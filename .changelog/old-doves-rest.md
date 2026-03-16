---
pytempo: major
---

Added `pytempo.contracts` module with typed call builders (`TIP20`, `StablecoinDEX`, `AccountKeychain`, `FeeAMM`, `FeeManager`, `Nonce`), canonical precompile and token addresses, and ABI definitions synced from `tempoxyz/tempo-std`. Removed legacy precompile helpers (`GET_REMAINING_LIMIT_SELECTOR`, `encode_get_remaining_limit_calldata`, `get_remaining_spending_limit`) and changed `TIP20` to be instance-based, both of which are breaking API changes.
