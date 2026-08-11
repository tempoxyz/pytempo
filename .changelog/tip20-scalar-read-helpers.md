---
pytempo: minor
---

Add scalar view helpers to `TIP20`: `balance_of`, `allowance`, `total_supply`,
`decimals`, `supply_cap`, and `paused`. These mirror the existing role query
helpers, returning decoded Python values from a single `eth_call`.
