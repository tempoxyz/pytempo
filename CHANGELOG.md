# Changelog

## 0.6.0 (2026-09-03)

### Minor Changes

- Add T5 hardfork contract bindings, including refreshed ABIs, AccountKeychain helpers, TIP20 role/admin/reward controls, and stricter ABI response decoding. (by @Mablr, [#56](https://github.com/tempoxyz/pytempo/pull/56))
- Add T6 contract bindings: TIP-1028 receive policies (`TIP403Registry`
- receive-policy helpers and `ReceivePolicyGuard`) and the TIP-1020
- `SignatureVerifier` precompile, along with their precompile addresses and
- refreshed ABIs. (by @stevencartavia, [#60](https://github.com/tempoxyz/pytempo/pull/60))
- Support the T6 (TIP-1049) `KeyAuthorization` wire format: encode and decode the
- new `is_admin` and `account` fields (plus the trailing `witness` field) using the
- trailing-canonical RLP layout. Adds admin-key validation, canonical-RLP decoding
- (`KeyAuthorization.decode` / `SignedKeyAuthorization.decode`), and `to_json`
- support. `expiry=0` is now rejected — use `None` for "never expires". (by @stevencartavia, [#59](https://github.com/tempoxyz/pytempo/pull/59))
- Expose the T6 (TIP-1049) stateful keychain signature checks on the
- `SignatureVerifier` precompile binding: `verify_keychain(account, hash, signature)`
- and `verify_keychain_admin(account, hash, signature)`. Bumped the vendored
- `tempo-std` ABI ref to pick up the `verifyKeychain` / `verifyKeychainAdmin`
- additions to `ISignatureVerifier`. (by @stevencartavia, [#62](https://github.com/tempoxyz/pytempo/pull/62))
- Add the `StablecoinDEX.storage_credits(w3, user=...)` view (TIP-1064) to query a
- maker's reusable order-storage credit balance on the Stablecoin DEX. (by @stevencartavia, [#65](https://github.com/tempoxyz/pytempo/pull/65))
- Add T7 StorageCredits precompile bindings (TIP-1060): the `StorageCredits`
- helper with `set_mode`/`set_budget` call builders and `balance_of`/`mode_of`/
- `budget_of` views, the `StorageCreditMode` enum, the `STORAGE_CREDITS_ADDRESS`
- precompile address, and the `IStorageCredits` ABI. (by @stevencartavia, [#64](https://github.com/tempoxyz/pytempo/pull/64))
- Add T8 `CurrentCommittee` bindings, including the precompile address, ABI, and
- typed `get_committee_members` read helper. (by @stevencartavia, [#67](https://github.com/tempoxyz/pytempo/pull/67))
- Exposed the Tempo transaction signing preimage via `TempoTransaction.encode_for_signing()`, allowing callers to access the exact byte sequence that is hashed for signing. Refactored internal `_signing_hash_*` methods into `_encode_for_*_signing()` helpers and added tests verifying the preimage matches the signing hash. (by @ParvAhuja, [#69](https://github.com/tempoxyz/pytempo/pull/69))
- Add scalar view helpers to `TIP20`: `balance_of`, `allowance`, `total_supply`,
- `decimals`, `supply_cap`, and `paused`. These mirror the existing role query
- helpers, returning decoded Python values from a single `eth_call`. (by @Devorun, [#75](https://github.com/tempoxyz/pytempo/pull/75))

### Patch Changes

- Updated the fee token integration test to use genesis-seeded FeeAMM liquidity, consolidating two tests into one and removing the liquidity minting step. (by @DerekCofausper, [#87](https://github.com/tempoxyz/pytempo/pull/87))
- Update the fee token integration test to use genesis-seeded FeeAMM liquidity. (by @DerekCofausper, [#87](https://github.com/tempoxyz/pytempo/pull/87))
- Document T7 changes: mark the TIP-20 reward builders `distribute_reward` and
- `set_reward_recipient` as deprecated (TIP-1075 — post-T7 no-ops). `claim_rewards`
- stays valid: it still checkpoints and settles pre-T7 lazy accruals through T7,
- and pays only already-settled balances from the T8 cleanup fork. Also note the
- dynamic base fee (TIP-1067) so `max_fee_per_gas` should come from a live estimate
- rather than a constant. (by @stevencartavia, [#66](https://github.com/tempoxyz/pytempo/pull/66))
- Updated live keychain integration coverage to use transaction-embedded authorization on TIP-1099 networks. (by @DerekCofausper, [#85](https://github.com/tempoxyz/pytempo/pull/85))

## 0.5.1 (2026-04-24)

### Patch Changes

- Hardened CI supply chain security by pinning GitHub Actions to specific commit SHAs, adding SHA256 checksum verification for downloaded binaries, enabling Dependabot for automated dependency updates, and locking tool versions (`uv`, `changelogs`) to prevent supply chain attacks. (by @grandizzy, [#51](https://github.com/tempoxyz/pytempo/pull/51))

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
