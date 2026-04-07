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

Web3.py extension for Tempo.

## Installation

```bash
pip install pytempo
```

Or with uv:

```bash
uv add pytempo
```

## Quick Start

### Typed Contract Helpers (v0.4.0+)

Use the built-in typed helpers for Tempo precompiles — no ABI knowledge needed:

```python
from pytempo import TempoTransaction
from pytempo.contracts import TIP20, StablecoinDEX, ALPHA_USD, BETA_USD
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
    calls=(
        TIP20(ALPHA_USD).approve(spender=StablecoinDEX.ADDRESS, amount=10**18),
        StablecoinDEX.place(token=BETA_USD, amount=100_000_000, is_bid=True, tick=10),
    ),
)
signed_tx = tx.sign("0xYourPrivateKey...")

# Send using web3.py
tx_hash = w3.eth.send_raw_transaction(signed_tx.encode())
```

### Manual Calls (v0.2.1+)

For arbitrary contract calls or simple transfers, use `Call.create()` directly:

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
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
signed_tx = tx.sign("0xYourPrivateKey...")
tx_hash = w3.eth.send_raw_transaction(signed_tx.encode())
```

### Custom Fee Tokens (v0.2.1+)

```python
from pytempo.contracts import BETA_USD

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    fee_token=BETA_USD,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
```

### Gas Sponsorship (v0.2.1+)

```python
from pytempo import TempoTransaction, Call

# User creates and signs a sponsored transaction
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    awaiting_fee_payer=True,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
signed_tx = tx.sign("0xUserPrivateKey...")

# Fee payer signs (pays gas)
final_tx = signed_tx.sign("0xFeePayerPrivateKey...", for_fee_payer=True)

w3.eth.send_raw_transaction(final_tx.encode())
```

### Batch Multiple Calls (v0.2.1+)

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

### Parallel Nonces (v0.2.1+)

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

### Contract Creation (v0.2.1+)

```python
from pytempo import TempoTransaction, Call

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=500_000,
    calls=(Call.create(to=b"", data="0x6080604052..."),),  # Empty 'to' for creation
)
signed_tx = tx.sign("0xPrivateKey...")
```

### Parsing from Dicts (v0.2.1+)

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

### Type Coercion Helpers (v0.2.1+)

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

## API Reference

### `TempoTransaction`

Immutable, strongly-typed transaction (frozen attrs model).

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
- `sign_access_key(access_key_private_key, root_account)` - Sign with access key (returns new instance)
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

### Contract Helpers

Typed call builders for Tempo precompiles and tokens:

- `TIP20` — TIP-20 token operations (transfer, approve, mint, burn, permit)
- `StablecoinDEX` — Stablecoin DEX operations (place, cancel, swap, withdraw)
- `AccountKeychain` — Access key management (authorize, revoke, spending limits, queries)
- `FeeAMM` — Fee AMM liquidity operations (mint, burn, rebalance_swap)
- `FeeManager` — Fee manager operations (set fee token, distribute fees); inherits `FeeAMM`
- `Nonce` — Nonce precompile queries (get_nonce)

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

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/pytempo?tab=contributing-ov-file).

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/pytempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
