---
pytempo: patch
---

### New Features

- Added `pytempo.contracts` module with typed call builders, canonical addresses, and ABI definitions synced from `tempoxyz/tempo-std` via `scripts/sync_abis.sh`. Shipped ABIs are the single source of truth — no hardcoded selectors or manual calldata construction.
- **Typed helpers** — build `Call` objects with zero ABI knowledge:
  - `TIP20(token)` — instance-based TIP-20 token operations (transfer, approve, mint, burn, permit)
  - `StablecoinDEX` — Stablecoin DEX operations (place, cancel, swap, withdraw)
  - `AccountKeychain` — access key management (authorize, revoke, spending limits) and queries (`get_remaining_limit`)
  - `FeeAMM` — fee AMM liquidity operations (mint, burn, rebalance_swap)
  - `FeeManager` — fee manager operations (set fee token, distribute fees); inherits `FeeAMM`
  - `Nonce` — nonce precompile queries (`get_nonce`)
- **Canonical addresses** — precompile addresses (`ACCOUNT_KEYCHAIN_ADDRESS`, `STABLECOIN_DEX_ADDRESS`, `FEE_MANAGER_ADDRESS`, `NONCE_ADDRESS`, etc.) and token addresses (`PATH_USD`, `ALPHA_USD`, `BETA_USD`, `THETA_USD`)
- **ABI definitions** — `TIP20_ABI`, `ACCOUNT_KEYCHAIN_ABI`, `STABLECOIN_DEX_ABI`, `FEE_MANAGER_ABI`, `FEE_AMM_ABI`, `NONCE_ABI`

### Breaking Changes

- Removed `GET_REMAINING_LIMIT_SELECTOR`, `encode_get_remaining_limit_calldata()`, and `get_remaining_spending_limit()` from public API — use `AccountKeychain.get_remaining_limit()` instead.
- `TIP20` is now instance-based: `TIP20(token_address).transfer(...)` instead of `TIP20.transfer(token=..., ...)`.

### Patch Changes

- Removed hardcoded function selectors and manual hex-padding calldata construction from `pytempo/keychain.py`.
- Fixed stale docs: corrected Keychain signature type (`0x03` → `0x04`), removed references to deleted legacy API, replaced hardcoded addresses with constants in examples.
