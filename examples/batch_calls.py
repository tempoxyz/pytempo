"""
Example: Batch Multiple Calls

This example shows how to batch multiple calls into a single transaction.

Usage:
    PRIVATE_KEY=0x... python examples/batch_calls.py
"""

import os

from web3 import Web3

from pytempo import create_tempo_transaction, patch_web3_for_tempo

# Patch web3 to support Tempo transactions
patch_web3_for_tempo()

# Connect to Tempo
w3 = Web3(Web3.HTTPProvider("https://eng:zealous-mayer@rpc.devnet.tempo.xyz"))

# Get private key from environment
private_key = os.environ.get("PRIVATE_KEY")
if not private_key:
    raise ValueError("PRIVATE_KEY environment variable not set")

account = w3.eth.account.from_key(private_key)

# Create transaction with multiple calls
tx = create_tempo_transaction(
    to="",  # Not used when calls are provided
    calls=[
        {"to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": 0, "data": "0x"},
        {"to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": 0, "data": "0x"},
        {"to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": 0, "data": "0x"},
    ],
    gas=300000,
    max_fee_per_gas=w3.eth.gas_price * 2 if w3.eth.gas_price else 2000000000,
    max_priority_fee_per_gas=w3.eth.gas_price if w3.eth.gas_price else 2000000000,
    nonce=w3.eth.get_transaction_count(account.address),
    chain_id=w3.eth.chain_id,
    fee_token="0x20c0000000000000000000000000000000000001",
)
tx.sign(private_key)

print(f"Batching {len(tx.calls)} calls in one transaction")

# Send transaction
tx_hash = w3.eth.send_raw_transaction(tx.encode())
print(f"Transaction hash: {tx_hash.hex()}")

# Wait for confirmation
print("Waiting for confirmation...")
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Confirmed in block {receipt['blockNumber']} (gas used: {receipt['gasUsed']})")
