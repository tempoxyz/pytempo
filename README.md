# pytempo

Web3.py extension for Tempo.

## Installation

```bash
pip install -e .
```

Or with uv:
```bash
uv add .
```

## Quick Start

```python
from pytempo import patch_web3_for_tempo, create_tempo_transaction
from web3 import Web3

# Step 1: Patch web3.py to add Tempo support
patch_web3_for_tempo()

# Step 2: Use web3.py normally with Tempo features
w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))
account = w3.eth.account.from_key("0x...")

# Step 3: Create Tempo AA transaction (Type 0x76)
tx = create_tempo_transaction(
    to="0xRecipient...",
    value=0,
    gas=100000,
    max_fee_per_gas=w3.eth.gas_price * 2,
    max_priority_fee_per_gas=w3.eth.gas_price,
    nonce=w3.eth.get_transaction_count(account.address),
    chain_id=w3.eth.chain_id,
    fee_token="0x20c0000000000000000000000000000000000001", # AlphaUSD
)

# Step 4: Sign and send using standard web3.py
tx.sign(account.key.hex())
tx_hash = w3.eth.send_raw_transaction(tx.encode())
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```

## Usage

### Basic Transaction

```python
from pytempo import create_tempo_transaction

tx = create_tempo_transaction(
    to="0xRecipient...",
    value=1000000000000000,
    gas=100000,
    max_fee_per_gas=2000000000,
    max_priority_fee_per_gas=2000000000,
    nonce=0,
    chain_id=42429,
)

tx.sign("0xYourPrivateKey...")
encoded = tx.encode()
```

### With Custom Fee Token

```python
tx = create_tempo_transaction(
    to="0xRecipient...",
    value=0,
    fee_token="0xTokenAddress...",  # Pay gas in this ERC-20 token
    gas=100000,
    max_fee_per_gas=2000000000,
    max_priority_fee_per_gas=2000000000,
    nonce=0,
    chain_id=42429,
)
```

### Gas Sponsorship

```python
# User creates and signs
tx = create_tempo_transaction(
    to="0xRecipient...",
    value=1000000000000000,
    gas=100000,
    max_fee_per_gas=2000000000,
    max_priority_fee_per_gas=2000000000,
    nonce=0,
    chain_id=42429,
    fee_token="0xTokenAddress...",
)

# Mark that fee payer will sign
tx._will_have_fee_payer = True

# User signs
tx.sign("0xUserPrivateKey...", for_fee_payer=False)

# Fee payer signs (pays gas)
tx.sign("0xFeePayerPrivateKey...", for_fee_payer=True)

# Send
w3.eth.send_raw_transaction(tx.encode())
```

### Batch Multiple Calls

```python
tx = create_tempo_transaction(
    to="",  # Not used
    calls=[
        {"to": "0xAddress1...", "value": 100000, "data": "0x"},
        {"to": "0xAddress2...", "value": 200000, "data": "0xabcdef"},
    ],
    gas=200000,
    max_fee_per_gas=2000000000,
    max_priority_fee_per_gas=2000000000,
    nonce=0,
    chain_id=42429,
)
```

### Parallel Nonces

```python
# Use different nonce keys for parallel execution
tx1 = create_tempo_transaction(
    to="0xRecipient...",
    nonce=0,
    nonce_key=1,  # First parallel key
    # ... other params
)

tx2 = create_tempo_transaction(
    to="0xRecipient...",
    nonce=0,
    nonce_key=2,  # Second parallel key
    # ... other params
)

# Both can be executed in parallel
```

## API Reference

### `patch_web3_for_tempo()`

Monkey patches web3.py to recognize Tempo AA transactions. **Must be called before using web3**.

### `create_tempo_transaction(...)`

Creates a Tempo AA transaction.

**Parameters:**
- `to` (str): Destination address
- `value` (int): Value in wei (default: 0)
- `gas` (int): Gas limit
- `max_fee_per_gas` (int): Maximum fee per gas
- `max_priority_fee_per_gas` (int): Maximum priority fee per gas
- `nonce` (int): Transaction nonce
- `chain_id` (int): Chain ID
- `nonce_key` (int): Nonce key for parallel execution (default: 0)
- `fee_token` (str, optional): ERC-20 token address for gas payment
- `calls` (list, optional): List of calls for batching
- `data` (str, optional): Transaction data
- `valid_before` (int, optional): Timestamp before which tx is valid
- `valid_after` (int, optional): Timestamp after which tx becomes valid

**Returns:** `TempoAATransaction`

### `TempoAATransaction`

Main transaction class.

**Methods:**
- `sign(private_key, for_fee_payer=False)` - Sign the transaction
- `encode()` - Encode to bytes for transmission
- `hash()` - Get transaction hash
- `get_signing_hash(for_fee_payer=False)` - Get hash to sign
- `vrs()` - Get v, r, s values (secp256k1 only)

## Examples

See the `examples/` directory:
- `simple_send.py` - Simple value transfer
- `basic_transaction.py` - Transaction with fee token
- `fee_payer_sponsored.py` - Gas sponsorship and call batching

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
