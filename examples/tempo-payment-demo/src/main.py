from .client import get_web3
from .config import PRIVATE_KEY, EXPLORER
from .faucet import fund_address
from .payment import build_transfer_tx
from web3 import Web3

def demo():
    w3 = get_web3()
    acct = w3.eth.account.from_key(PRIVATE_KEY)
    print("Address:", acct.address)
    # faucet example (may fail if RPC doesn't expose)
    try:
        res = fund_address(w3, acct.address)
        print("Faucet result:", res)
    except Exception as e:
        print("Faucet call error (non-fatal):", e)
    # build tx (not broadcasted here)
    dummy_token = "0x0000000000000000000000000000000000000000"  # placeholder

    tx = build_transfer_tx(
        w3,
        dummy_token,
        acct.key.hex(),
        acct.address,
        1
    )

    print("Built tx (preview):", tx)

if __name__ == '__main__':
    demo()
