---
pytempo: patch
---

Document T7 changes: mark the TIP-20 reward builders `distribute_reward` and
`set_reward_recipient` as deprecated (TIP-1075 — post-T7 no-ops; `claim_rewards`
still pays already-settled balances), and note the dynamic base fee (TIP-1067)
so `max_fee_per_gas` should come from a live estimate rather than a constant.
