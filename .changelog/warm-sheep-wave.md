---
pytempo: major
---

Removed the legacy transaction API (`LegacyTempoTransaction`, `TempoAATransaction`, `create_tempo_transaction`, `patch_web3_for_tempo`) and the `pytempo/transaction.py` module. Updated all examples, tests, and documentation to use only the typed `TempoTransaction` and `Call` API.
