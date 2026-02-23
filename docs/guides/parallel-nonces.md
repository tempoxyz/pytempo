# Parallel Nonces

Tempo uses a **2D nonce system** — each transaction has both a `nonce` and a `nonce_key`. Transactions with different `nonce_key` values are independent and can be executed in parallel.

## Example

```python
from pytempo import TempoTransaction, Call

# These two transactions can execute concurrently
tx1 = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    nonce=0,
    nonce_key=1,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)

tx2 = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    nonce=0,
    nonce_key=2,
    calls=(Call.create(to="0xRecipient...", value=2000),),
)
```

Each `nonce_key` maintains its own nonce sequence, so `tx1` and `tx2` don't block each other.

## When to use

- **High-throughput applications** — send many transactions without waiting for confirmations.
- **Multi-path workflows** — independent operations that shouldn't block each other.
- **Default behavior** — `nonce_key=0` is the default, matching standard single-lane nonce semantics.
