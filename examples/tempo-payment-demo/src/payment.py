from web3 import Web3

# ABI ERC20 sederhana
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [
            {"name": "_owner", "type": "address"}
        ],
        "name": "balanceOf",
        "outputs": [
            {"name": "balance", "type": "uint256"}
        ],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [
            {"name": "success", "type": "bool"}
        ],
        "type": "function"
    }
]

def get_token_contract(web3: Web3, token_address: str):
    """Return ERC20 contract instance"""
    return web3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI)


def build_transfer_tx(web3: Web3, token_address: str, private_key: str, to: str, amount: int):
    """Build unsigned ERC20 transfer transaction"""
    account = web3.eth.account.from_key(private_key)
    contract = get_token_contract(web3, token_address)

    tx = contract.functions.transfer(
        Web3.to_checksum_address(to),
        amount
    ).build_transaction({
        "from": account.address,
        "nonce": web3.eth.get_transaction_count(account.address),
        "gas": 120000,
        "gasPrice": web3.to_wei("0.1", "gwei"),
    })

    return tx

