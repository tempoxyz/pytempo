from .client import get_web3
from .config import PRIVATE_KEY, PATHUSD_ADDRESS, EXPLORER
from .payment import build_transfer_tx
from web3 import Web3

def main():
    w3 = get_web3()
    # target (default merchant) 
    to_addr = "0x000000000000000000000000000000000000dEaD"
    # amount: 0.001 PATHUSD (assume 18 decimals)
    amount = Web3.to_wei(0.001, "ether")

    # build unsigned tx
    unsigned = build_transfer_tx(w3, PATHUSD_ADDRESS, PRIVATE_KEY, to_addr, amount)

    # ensure chainId and correct nonce
    unsigned.setdefault("chainId", w3.eth.chain_id)
    unsigned["nonce"] = w3.eth.get_transaction_count(w3.eth.account.from_key(PRIVATE_KEY).address)

    # Dynamically choose gasPrice from node, add small buffer to avoid 'underpriced'
    try:
        node_gas_price = w3.eth.gas_price  # recommended gas price from node (int, wei)
        # add 20% buffer
        buffered = node_gas_price * 12 // 10
        unsigned["gasPrice"] = buffered
        print(f"Using gasPrice from node: {node_gas_price} wei, buffered: {buffered} wei")
    except Exception as e:
        # fallback to existing or conservative default (1 gwei)
        fallback = Web3.to_wei(1, "gwei")
        unsigned.setdefault("gasPrice", fallback)
        print("Could not fetch node gas price, using fallback:", fallback)

    print("Unsigned tx preview:")
    print(unsigned)

    # sign
    signed = w3.eth.account.sign_transaction(unsigned, PRIVATE_KEY)
    raw = signed.raw_transaction

    # send
    tx_hash = w3.eth.send_raw_transaction(raw)
    print("Sent tx:", tx_hash.hex())
    print("Explorer:", f"{EXPLORER.rstrip('/')}/tx/{tx_hash.hex()}")

if __name__ == '__main__':
    main()
