---
pytempo: minor
---

Added `SelectorRule` class for per-selector recipient filtering in call scope restrictions. Extended `CallScope` factory methods (`transfer`, `approve`, `transfer_with_memo`) to accept optional `recipients` lists, and added `CallScope.with_selector` for arbitrary 4-byte selector scoping. Added `AccountKeychain.set_allowed_calls` and `remove_allowed_calls` static methods, and added validation guards to `authorize_key` rejecting conflicting `legacy`/`allowed_calls` combinations.
