# Transactions

Tempo uses a custom transaction type (`0x76`) that extends EIP-1559 with call batching, fee tokens, and gas sponsorship.

## Creating a transaction

Use {py:meth}`TempoTransaction.create() <pytempo.TempoTransaction.create>` to build a transaction:

```python
from pytempo import TempoTransaction, Call

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    max_priority_fee_per_gas=1_000_000_000,
    nonce=0,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
```

All parameters accept Python-native types. Hex strings are automatically coerced to bytes.

## Signing

`sign()` returns a **new** transaction — the original is unchanged:

```python
signed_tx = tx.sign("0xPrivateKey...")

assert tx.sender_signature is None       # original unchanged
assert signed_tx.sender_signature is not None
```

## Encoding and sending

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))
tx_hash = w3.eth.send_raw_transaction(signed_tx.encode())
```

## Batch calls

Pass multiple {py:class}`~pytempo.Call` objects to execute them atomically:

```python
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=200_000,
    max_fee_per_gas=2_000_000_000,
    calls=(
        Call.create(to="0xAddress1...", value=100_000),
        Call.create(to="0xAddress2...", value=200_000, data="0xabcdef"),
    ),
)
```

## Custom fee tokens

Pay gas fees in a supported ERC-20 token:

```python
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    fee_token="0x20c0000000000000000000000000000000000001",  # AlphaUSD
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
```

## Transaction expiry

Set optional validity windows:

```python
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    valid_after=1700000000,    # valid from this timestamp
    valid_before=1700003600,   # expires after this timestamp
    calls=(Call.create(to="0xRecipient..."),),
)
```

## Parsing from dicts

{py:meth}`TempoTransaction.from_dict() <pytempo.TempoTransaction.from_dict>` accepts both `camelCase` and `snake_case` keys:

```python
tx = TempoTransaction.from_dict({
    "chainId": 42429,
    "gas": 100_000,
    "maxFeePerGas": 2_000_000_000,
    "to": "0xRecipient...",
    "value": 1000,
})
```

## Contract creation

Pass an empty `to` address with contract bytecode in `data`:

```python
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=500_000,
    max_fee_per_gas=2_000_000_000,
    calls=(Call.create(to=b"", data="0x6080604052..."),),
)
```

## Gas estimation

Use {py:meth}`~pytempo.TempoTransaction.to_estimate_gas_request` to build an `eth_estimateGas` request:

```python
gas = w3.eth.estimate_gas(tx.to_estimate_gas_request(sender="0xYourAddress..."))
```
