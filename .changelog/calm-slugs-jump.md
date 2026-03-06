---
pytempo: patch
---

Updated `test_add_fee_token_liquidity` to `test_fee_token_liquidity_exists`, replacing the liquidity minting transaction with a read-only `getPool` call that verifies genesis-seeded FeeAMM liquidity already exists for fee tokens.
