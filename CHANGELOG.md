# Changelog

## 0.3.2 (2026-03-10)

### Patch Changes

- Fixed a test race condition in `TestAccessKeys` by waiting for block propagation before reusing an access key, ensuring load-balanced RPC nodes have imported the provisioning block. (by @DerekCofausper, [#35](https://github.com/tempoxyz/pytempo/pull/35))

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
