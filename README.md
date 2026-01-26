<br>
<br>

<p align="center">
  <a href="https://tempo.xyz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tempoxyz/.github/refs/heads/main/assets/combomark-dark.svg">
      <img alt="tempo combomark" src="https://raw.githubusercontent.com/tempoxyz/.github/refs/heads/main/assets/combomark-bright.svg" width="auto" height="120">
    </picture>
  </a>
</p>

<br>
<br>

# pytempo

> [!IMPORTANT]
> This is a **proof-of-concept**, please reach out to the Tempo team if you are interested in using this library in production.

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

### Recommended: Typed API

```python
from pytempo import TempoTransaction, Call
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))

# Create a strongly-typed immutable transaction
# No patching needed - we handle encoding ourselves
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

# Send using web3.py
tx_hash = w3.eth.send_raw_transaction(signed_tx.encode())
```

### Legacy API (Backwards Compatible)

```python
from pytempo import patch_web3_for_tempo, create_tempo_transaction
from web3 import Web3

# Step 1: Patch web3.py to add Tempo support
# (Only needed if using web3's internal transaction parsing)
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

## Typed API (v0.3.0+)

The typed API provides immutable dataclasses with validation:

```python
from pytempo import TempoTransaction, Call, AccessListItem

# All parameters passed directly to create()
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    fee_token="0x20c0000000000000000000000000000000000001",
    awaiting_fee_payer=True,  # Mark for fee payer
    calls=(
        Call.create(to="0xRecipient...", value=1000, data="0xabcd"),
        Call.create(to="0xOther...", value=2000),  # Batch multiple calls
    ),
)

# Immutable signing - returns new transaction
signed = tx.sign("0xPrivateKey...")
assert tx.sender_signature is None  # Original unchanged
assert signed.sender_signature is not None
```

### Parsing from Dicts

```python
from pytempo import TempoTransaction

# Supports both camelCase and snake_case keys
tx = TempoTransaction.from_dict({
    "chainId": 42429,
    "gas": 100_000,
    "maxFeePerGas": 2_000_000_000,
    "to": "0xRecipient...",
    "value": 1000,
})
```

### Type Coercion Helpers

```python
from pytempo import as_address, as_hash32, as_bytes, as_optional_address

# Validate and convert addresses
addr = as_address("0xF0109fC8DF283027b6285cc889F5aA624EaC1F55")  # -> bytes (20)
addr = as_address(b"\x00" * 20)  # Also accepts bytes

# Optional addresses (treats empty as None)
addr = as_optional_address("0x")  # -> None
addr = as_optional_address(None)  # -> None

# Validate 32-byte hashes
h = as_hash32("0x" + "ab" * 32)  # -> bytes (32)

# Convert hex strings to bytes
data = as_bytes("0xabcdef")  # -> b'\xab\xcd\xef'
```

## Legacy Usage

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
from pytempo import TempoTransaction, Call

# User creates and signs a sponsored transaction
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    fee_token="0xTokenAddress...",
    awaiting_fee_payer=True,  # Mark for fee payer
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
signed_tx = tx.sign("0xUserPrivateKey...")

# Fee payer signs (pays gas)
final_tx = signed_tx.sign("0xFeePayerPrivateKey...", for_fee_payer=True)

# Send
w3.eth.send_raw_transaction(final_tx.encode())
```

### Batch Multiple Calls

```python
from pytempo import TempoTransaction, Call

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=200_000,
    max_fee_per_gas=2_000_000_000,
    calls=(
        Call.create(to="0xAddress1...", value=100000),
        Call.create(to="0xAddress2...", value=200000, data="0xabcdef"),
    ),
)
signed_tx = tx.sign("0xPrivateKey...")
```

### Parallel Nonces

```python
from pytempo import TempoTransaction, Call

# Use different nonce keys for parallel execution
tx1 = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    nonce=0,
    nonce_key=1,  # First parallel key
    calls=(Call.create(to="0xRecipient..."),),
)

tx2 = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    nonce=0,
    nonce_key=2,  # Second parallel key
    calls=(Call.create(to="0xRecipient..."),),
)

# Both can be executed in parallel
```

### Contract Creation

```python
from pytempo import TempoTransaction, Call

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=500_000,
    calls=(Call.create(to=b"", data="0x6080604052..."),),  # Empty 'to' for creation
)
signed_tx = tx.sign("0xPrivateKey...")
```

## API Reference

### `TempoTransaction` (Recommended)

Immutable, strongly-typed transaction (frozen dataclass).

**Factory Methods:**

- `TempoTransaction.create(**kwargs)` - Create with type coercion
- `TempoTransaction.from_dict(d)` - Parse from camelCase/snake_case dict

**Create Parameters:**

- `chain_id` (int) - Chain ID (default: 1)
- `gas_limit` (int) - Gas limit (default: 21_000)
- `max_fee_per_gas` (int) - Max fee per gas in wei
- `max_priority_fee_per_gas` (int) - Max priority fee per gas in wei
- `nonce` (int) - Transaction nonce
- `nonce_key` (int) - Nonce key for parallel execution
- `valid_before` (int, optional) - Expiration timestamp
- `valid_after` (int, optional) - Activation timestamp
- `fee_token` (str/bytes, optional) - Fee token address
- `awaiting_fee_payer` (bool) - Mark for fee payer signature
- `calls` (tuple[Call, ...]) - Tuple of Call objects
- `access_list` (tuple[AccessListItem, ...]) - EIP-2930 access list

**Methods:**

- `sign(private_key, for_fee_payer=False)` - Sign transaction (returns new instance)
- `encode()` - Encode to bytes for transmission
- `hash()` - Get transaction hash
- `get_signing_hash(for_fee_payer=False)` - Get hash to sign
- `vrs()` - Get v, r, s values
- `validate()` - Validate transaction fields

### `Call`

Single call in a batch transaction.

- `Call.create(to, value=0, data=b"")` - Create with type coercion

### `AccessListItem`

EIP-2930 access list entry.

- `AccessListItem.create(address, storage_keys=())` - Create with type coercion

### `patch_web3_for_tempo()`

Monkey patches web3.py to recognize Tempo AA transactions. **Must be called before using web3**.

### `create_tempo_transaction(...)` (Legacy)

Creates a mutable Tempo AA transaction.

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

**Returns:** `LegacyTempoTransaction`

## Development

```bash
make install  # Install dependencies
make test     # Run tests
make lint     # Lint
make format   # Format code
make check    # Run all checks (lint + format-check + test)
```

## Examples

See the `examples/` directory:

- `simple_send.py` - Simple value transfer
- `basic_transaction.py` - Transaction with fee token
- `fee_payer_sponsored.py` - Gas sponsorship and call batching

## Contributing

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/tempo?tab=contributing-ov-file).

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/pytempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
