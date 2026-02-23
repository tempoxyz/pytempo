# pytempo

Web3.py extension for [Tempo](https://tempo.xyz) blockchain — adds native support for Tempo AA transactions (Type `0x76`) and Tempo-specific features.

```{important}
This is a **proof-of-concept**. Please reach out to the Tempo team if you are interested in using this library in production.
```

## Features

- **Strongly-typed transactions** — immutable dataclasses with validation
- **Call batching** — execute multiple calls in a single transaction
- **Gas sponsorship** — fee payer support for sponsored transactions
- **Custom fee tokens** — pay gas in any supported ERC-20
- **Parallel nonces** — 2D nonce system for concurrent execution
- **Access keys** — delegate signing via the AccountKeychain precompile
- **Transaction expiry** — optional validity windows

## Quick example

```python
from pytempo import TempoTransaction, Call
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    max_priority_fee_per_gas=1_000_000_000,
    nonce=0,
    fee_token="0x20c0000000000000000000000000000000000001",
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
signed_tx = tx.sign("0xYourPrivateKey...")
tx_hash = w3.eth.send_raw_transaction(signed_tx.encode())
```

```{toctree}
:maxdepth: 2
:caption: Getting Started

getting-started
```

```{toctree}
:maxdepth: 2
:caption: Guides

guides/transactions
guides/fee-sponsorship
guides/access-keys
guides/parallel-nonces
```

```{toctree}
:maxdepth: 2
:caption: API Reference

reference/models
reference/keychain
reference/types
```
