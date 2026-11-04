---
pytempo: patch
---

Removed the hard dependency on `web3`: calldata is now ABI-encoded with `eth-abi` directly, which drops 15 transitive packages (aiohttp, requests, websockets and others) from a default install. Install `pytempo[web3]` if your code uses web3 without depending on it directly.
