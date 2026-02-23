# Fee Sponsorship

Tempo supports gas sponsorship, where a *fee payer* covers the gas cost on behalf of the transaction sender.

## How it works

1. The **sender** creates a transaction with `awaiting_fee_payer=True` and signs it.
2. The **fee payer** receives the signed transaction, sets the fee token, and counter-signs with `for_fee_payer=True`.
3. The fully-signed transaction is submitted on-chain.

## Example

```python
from pytempo import TempoTransaction, Call

# Step 1: Sender creates and signs
tx = TempoTransaction.create(
    chain_id=42429,
    gas_limit=100_000,
    max_fee_per_gas=2_000_000_000,
    fee_token="0xTokenAddress...",
    awaiting_fee_payer=True,
    calls=(Call.create(to="0xRecipient...", value=1000),),
)
signed_by_sender = tx.sign("0xSenderPrivateKey...")

# Step 2: Fee payer counter-signs
fully_signed = signed_by_sender.sign("0xFeePayerPrivateKey...", for_fee_payer=True)

# Step 3: Send
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("https://rpc.testnet.tempo.xyz"))
tx_hash = w3.eth.send_raw_transaction(fully_signed.encode())
```

## Notes

- When `awaiting_fee_payer=True`, the sender's signing hash excludes the fee token — the fee payer decides which token to use.
- Both signatures are included in the final encoded transaction.
