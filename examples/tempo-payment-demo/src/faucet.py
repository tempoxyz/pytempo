# simple wrapper for tempo_fundAddress via JSON-RPC
def fund_address(w3, address):
    # web3.py low-level JSON RPC call
    return w3.provider.make_request('tempo_fundAddress', [address])
