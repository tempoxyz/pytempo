---
pytempo: patch
---

Fixed `SignedKeyAuthorization.to_json` omitting `expiry` for keys that never expire. The node requires the field, so `eth_estimateGas` rejected these authorizations with "missing field `expiry`", which affected every admin key because admin keys cannot carry an expiry. `expiry` is now always sent, as `null` when the key never expires.
