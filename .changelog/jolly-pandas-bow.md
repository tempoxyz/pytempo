---
pytempo: patch
---

Replaced the hardcoded `COUNTER_CONTRACT` address with a dynamically deployed `counter_contract` fixture that deploys an isolated counter contract at test time, and introduced a `TEST_ADDRESS` placeholder for offline-only tests. Added storage slot assertions to batch transaction tests to verify call counts.
