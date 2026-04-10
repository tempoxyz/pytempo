# Changelog

## 0.5.0 (2026-04-10)

### Minor Changes

- Added TIP-1011 `authorizeKey` support with `KeyRestrictions` struct (T3+) as the new `authorize_key` method, and renamed the previous flat-params variant to `authorize_key_legacy` for pre-T3 compatibility. Updated `IAccountKeychain` ABI with the new function signature and `LegacyAuthorizeKeySelectorChanged` error. (by @DerekCofausper, [#46](https://github.com/tempoxyz/pytempo/pull/46))
- Added `KeyRestrictions` class for access-key restriction management and integrated it into `AccountKeychain.authorize_key()`.
- `KeyRestrictions` with `expiry`, `limits`, `allowed_calls` fields
- `is_unrestricted()` and `is_call_allowed(target, input_data)` introspection helpers
- `to_abi_tuple()` for ABI encoding
- `no_spending()` / `no_calls()` convenience constructors
- `TokenLimit.period` field with uint64 validation
- `AccountKeychain.authorize_key()` now takes `restrictions=KeyRestrictions(...)` (breaking)
- `AccountKeychain.authorize_key_legacy()` convenience method
- `KeyAuthorization` rejects periodic limits with a clear error
- `CallScope.with_selector()` documented in access-keys guide (by @DerekCofausper, [#46](https://github.com/tempoxyz/pytempo/pull/46))
- Added `AccountKeychain.get_key()` method to query key info from the AccountKeychain precompile, returning signature type, key ID, expiry, enforce limits, and revocation status. Added integration tests for keychain selectors, spending limits, inline key authorization, transaction validation, and encoding round-trips, plus unit tests for the new `get_key` method. (by @DerekCofausper, [#46](https://github.com/tempoxyz/pytempo/pull/46))
- Added `SelectorRule` class for per-selector recipient filtering in call scope restrictions. Extended `CallScope` factory methods (`transfer`, `approve`, `transfer_with_memo`) to accept optional `recipients` lists, and added `CallScope.with_selector` for arbitrary 4-byte selector scoping. Added `AccountKeychain.set_allowed_calls` and `remove_allowed_calls` static methods, and added validation guards to `authorize_key` rejecting conflicting `legacy`/`allowed_calls` combinations. (by @DerekCofausper, [#46](https://github.com/tempoxyz/pytempo/pull/46))

## 0.4.0 (2026-03-16)

### Minor Changes

- ### New Features
- Added `pytempo.contracts` module with typed call builders, canonical addresses, and ABI definitions synced from `tempoxyz/tempo-std` via `scripts/sync_abis.sh`. Shipped ABIs are the single source of truth — no hardcoded selectors or manual calldata construction.
- **Typed helpers** — build `Call` objects with zero ABI knowledge:
-   - `TIP20(token)` — instance-based TIP-20 token operations (transfer, approve, mint, burn, permit)
-   - `StablecoinDEX` — Stablecoin DEX operations (place, cancel, swap, withdraw)
-   - `AccountKeychain` — access key management (authorize, revoke, spending limits) and queries (`get_remaining_limit`)
-   - `FeeAMM` — fee AMM liquidity operations (mint, burn, rebalance_swap)
-   - `FeeManager` — fee manager operations (set fee token, distribute fees); inherits `FeeAMM`
-   - `Nonce` — nonce precompile queries (`get_nonce`)
- **Canonical addresses** — precompile addresses (`ACCOUNT_KEYCHAIN_ADDRESS`, `STABLECOIN_DEX_ADDRESS`, `FEE_MANAGER_ADDRESS`, `NONCE_ADDRESS`, etc.) and token addresses (`PATH_USD`, `ALPHA_USD`, `BETA_USD`, `THETA_USD`)
- **ABI definitions** — `TIP20_ABI`, `ACCOUNT_KEYCHAIN_ABI`, `STABLECOIN_DEX_ABI`, `FEE_MANAGER_ABI`, `FEE_AMM_ABI`, `NONCE_ABI`
- ### Breaking Changes
- Removed `GET_REMAINING_LIMIT_SELECTOR`, `encode_get_remaining_limit_calldata()`, and `get_remaining_spending_limit()` from public API — use `AccountKeychain.get_remaining_limit()` instead.
- `TIP20` is now instance-based: `TIP20(token_address).transfer(...)` instead of `TIP20.transfer(token=..., ...)`.
- ### Patch Changes
- Removed hardcoded function selectors and manual hex-padding calldata construction from `pytempo/keychain.py`.
- Fixed stale docs: corrected Keychain signature type (`0x03` → `0x04`), removed references to deleted legacy API, replaced hardcoded addresses with constants in examples. (by @onbjerg, [#38](https://github.com/tempoxyz/pytempo/pull/38))

### Patch Changes

- Fixed a test race condition in `TestAccessKeys` by waiting for block propagation before reusing an access key, ensuring load-balanced RPC nodes have imported the provisioning block. (by @onbjerg, [#38](https://github.com/tempoxyz/pytempo/pull/38))

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
