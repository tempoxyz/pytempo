# Access Keys

Access keys let a separate key sign transactions on behalf of a root wallet, with optional spending limits and expiry. They are managed by the **AccountKeychain** precompile.

## Provisioning a key

Create a {py:class}`~pytempo.KeyAuthorization`, sign it with the root account, and attach it to a transaction:

```python
from pytempo import (
    TempoTransaction, Call,
    create_key_authorization, SignatureType,
)

# Create authorization for a new access key
auth = create_key_authorization(
    key_id="0xAccessKeyAddress...",
    chain_id=42429,
    key_type=SignatureType.SECP256K1,
    expiry=1893456000,  # optional: expires ~2030
    limits=[
        {"token": "0xUSDCAddress...", "limit": 1000 * 10**6},
    ],
)

# Sign with root account
signed_auth = auth.sign("0xRootPrivateKey...")

# Attach to a transaction
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    calls=(Call.create(to="0xRecipient...", value=1000),),
    key_authorization=signed_auth.rlp_encode(),
)
```

## Signing with an access key

Use {py:func}`~pytempo.sign_tx_access_key` to sign a transaction as an access key holder:

```python
from pytempo import TempoTransaction, Call, sign_tx_access_key

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)

signed_tx = sign_tx_access_key(
    tx,
    access_key_private_key="0xAccessKeyPrivateKey...",
    root_account="0xRootAccountAddress...",
)
```

This produces a **Keychain signature** (type `0x03`): 86 bytes consisting of the type byte, root account address, and inner secp256k1 signature.

## Querying remaining limits

Check how much spending limit remains for an access key:

```python
from pytempo import get_remaining_spending_limit
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))

remaining = get_remaining_spending_limit(
    w3,
    account_address="0xRootAccount...",
    key_id="0xAccessKey...",
    token_address="0xUSDC...",
)
print(f"Remaining: {remaining}")
```

## Signature types

The {py:class}`~pytempo.SignatureType` constants define supported key types:

| Constant | Value | Description |
|---|---|---|
| `SECP256K1` | 0 | Standard Ethereum signature |
| `P256` | 1 | NIST P-256 / secp256r1 (passkeys) |
| `WEBAUTHN` | 2 | WebAuthn / FIDO2 |
