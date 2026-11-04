---
pytempo: minor
---

Made web3.py an optional dependency, installed with the `web3` extra (`pip install "pytempo[web3]"`). Calldata encoding now uses eth-abi directly, so building, signing and encoding transactions no longer installs web3.py and its HTTP and websocket stack.
