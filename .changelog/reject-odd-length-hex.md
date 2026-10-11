---
pytempo: patch
---

Fixed `as_bytes`, `as_address`, `as_hash32` and `as_selector` to reject a hex string with an odd number of digits. `eth_utils.to_bytes` left-pads such a string with a zero nibble, so an address that lost a character decoded to 20 bytes and passed the length check as a different, well-formed address. Odd-length hex now raises `ValueError` instead.
