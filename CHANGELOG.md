# Changelog

## 0.4.0 (2026-03-16)

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

## 0.3.1 (2026-03-04)

- Bumped to make the library publishable. Thanks PyPI.

## 0.3.0 (2026-03-03)

### Minor Changes

- Fixed Keychain signature type identifier from `0x03` to `0x04` (V2 format) and updated the signing scheme to use `keccak256(0x04 || sig_hash || user_address)` instead of the raw sig_hash, providing domain separation to prevent cross-scheme signature confusion. (by @onbjerg, [#27](https://github.com/tempoxyz/pytempo/pull/27))
- Added Sphinx documentation with guides for transactions, fee sponsorship, access keys, and parallel nonces. Removed the legacy transaction API (`LegacyTempoTransaction`, `create_tempo_transaction`, `patch_web3_for_tempo`) and updated examples and tests to use the typed API exclusively. (by @onbjerg, [#27](https://github.com/tempoxyz/pytempo/pull/27))
- <!-- note: this is marked as a minor to bump to v0.x.x until we have a stable release !-->
- Removed the legacy transaction API (`LegacyTempoTransaction`, `TempoAATransaction`, `create_tempo_transaction`, `patch_web3_for_tempo`) and the `pytempo/transaction.py` module. Updated all examples, tests, and documentation to use only the typed `TempoTransaction` and `Call` API. (by @onbjerg, [#27](https://github.com/tempoxyz/pytempo/pull/27))

### Patch Changes

- Fixed a race condition in integration tests by waiting for funding transaction receipts instead of using fixed sleep delays. (by @onbjerg, [#27](https://github.com/tempoxyz/pytempo/pull/27))
- Renamed package from tempopy back to pytempo. (by @onbjerg, [#27](https://github.com/tempoxyz/pytempo/pull/27))

## `pytempo@0.2.1`

### Minor Changes

- Initial release of pytempo - Web3.py extension for Tempo blockchain with support for AA transactions and Tempo-specific features. (by @BrendanRyan, [#14](https://github.com/tempoxyz/pytempo/pull/14))
