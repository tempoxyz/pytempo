---
pytempo: minor
---

Removed the hard dependency on `web3`: calldata is now ABI-encoded with `eth-abi` directly, which drops 15 transitive packages (aiohttp, requests, websockets and others) from a default install. Install `pytempo[web3]` if your code uses web3 without depending on it directly. The minimum `eth-account` is now 0.13.1, the first release with `LocalAccount.unsafe_sign_hash` (web3 7 previously enforced it).
