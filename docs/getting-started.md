# Getting Started

## Installation

Install with pip:

```bash
pip install pytempo
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add pytempo
```

## Requirements

- Python 3.9+
- web3.py 7.0+

## Your first transaction

```python
from pytempo import TempoTransaction, Call
from web3 import Web3

# Connect to a Tempo RPC
w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))

# Build a transaction
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    max_priority_fee_per_gas=1_000_000_000,
    nonce=0,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)

# Sign and send
signed_tx = tx.sign("0xYourPrivateKey...")
tx_hash = w3.eth.send_raw_transaction(signed_tx.encode())
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```

## Next steps

- {doc}`guides/transactions` — full transaction guide
- {doc}`guides/fee-sponsorship` — gas sponsorship
- {doc}`guides/access-keys` — delegate signing
- {doc}`guides/parallel-nonces` — concurrent execution
