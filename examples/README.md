# Examples

This directory contains working examples of using the pytempo library.

## Running Examples

All examples require the `PRIVATE_KEY` environment variable:

```bash
PRIVATE_KEY=0x... python examples/simple_send.py
```

### `simple_send.py` - Simple Transaction

The simplest possible Tempo AA transaction.

```bash
PRIVATE_KEY=0xYourPrivateKeyHere python examples/simple_send.py
```

### `batch_calls.py` - Batch Multiple Calls

Demonstrates batching multiple calls into a single transaction.

```bash
PRIVATE_KEY=0xYourPrivateKeyHere python examples/batch_calls.py
```

## Notes

- All examples connect to Tempo devnet
- Tempo doesn't support native transfers (sending ETH value), so transactions use value=0
- Gas is paid in custom fee tokens (ERC-20)
