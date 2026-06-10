from web3 import Web3
from .config import RPC_URL

def get_web3():
    return Web3(Web3.HTTPProvider(RPC_URL))
