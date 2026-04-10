# Access Keys

Access keys let a separate key sign transactions on behalf of a root wallet, with optional spending limits and expiry. They are managed by the **AccountKeychain** precompile.

## Provisioning a key

Create a {py:class}`~pytempo.KeyAuthorization`, sign it with the root account, and attach it to a transaction:

```python
from pytempo import (
    TempoTransaction, Call,
    KeyAuthorization, SignatureType, TokenLimit,
)

# Create authorization for a new access key
auth = KeyAuthorization(
    key_id="0xAccessKeyAddress...",
    chain_id=42429,
    key_type=SignatureType.SECP256K1,
    expiry=1893456000,  # optional: expires ~2030
    limits=(
        TokenLimit(token="0xUSDCAddress...", limit=1000 * 10**6),
    ),
)

# Sign with root account
signed_auth = auth.sign("0xRootPrivateKey...")

# Attach to a transaction
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    calls=(Call.create(to="0xRecipient...", value=1000),),
    key_authorization=signed_auth,
)
```

## Signing with an access key

Use {py:meth}`~pytempo.TempoTransaction.sign_access_key` to sign a transaction as an access key holder:

```python
from pytempo import TempoTransaction, Call

tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)

signed_tx = tx.sign_access_key(
    access_key_private_key="0xAccessKeyPrivateKey...",
    root_account="0xRootAccountAddress...",
)
```

This produces a **Keychain V2 signature** (type `0x04`): 86 bytes consisting of the type byte, root account address, and inner secp256k1 signature.

## Querying remaining limits

Check how much spending limit remains for an access key:

```python
from pytempo.contracts import AccountKeychain
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))

remaining = AccountKeychain.get_remaining_limit(
    w3,
    account_address="0xRootAccount...",
    key_id="0xAccessKey...",
    token_address="0xUSDC...",
)
print(f"Remaining: {remaining}")
```

## On-chain key authorization with call scopes (T3+)

For on-chain key provisioning via the AccountKeychain precompile, you can restrict which contracts and functions the key is allowed to call:

```python
from pytempo import CallScope, KeyRestrictions, SignatureType
from pytempo.contracts import AccountKeychain, ALPHA_USD

call = AccountKeychain.authorize_key(
    key_id="0xAccessKeyAddress...",
    signature_type=SignatureType.SECP256K1,
    restrictions=KeyRestrictions(
        expiry=2**64 - 1,
        allowed_calls=[
            CallScope.transfer(target=ALPHA_USD),
            CallScope.approve(target=ALPHA_USD),
        ],
    ),
)
```

Available call scope constructors:

- `CallScope.unrestricted(target=...)` — allow all functions on a target
- `CallScope.transfer(target=...)` — allow `transfer(address,uint256)` on a TIP20 token
- `CallScope.approve(target=...)` — allow `approve(address,uint256)` on a TIP20 token
- `CallScope.transfer_with_memo(target=...)` — allow `transferWithMemo(address,uint256,bytes32)` on a TIP20 token
- `CallScope.with_selector(target=..., selector=...)` — allow an arbitrary 4-byte selector on any contract

```{note}
Before T3 is activated, pass ``legacy=True`` to use the pre-T3 encoding::

    call = AccountKeychain.authorize_key(..., legacy=True)

Remove ``legacy=True`` once T3 is live.
```

## Signature types

The {py:class}`~pytempo.SignatureType` enum defines supported key types:

| Constant | Value | Description |
|---|---|---|
| `SECP256K1` | 0 | Standard Ethereum signature |
| `P256` | 1 | NIST P-256 / secp256r1 (passkeys) |
| `WEBAUTHN` | 2 | WebAuthn / FIDO2 |
