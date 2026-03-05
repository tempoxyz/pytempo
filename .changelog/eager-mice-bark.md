---
pytempo: minor
---

Added `TempoAddress`, a new class for bech32m-encoded Tempo blockchain addresses (BIP-350). Supports both mainnet addresses (HRP `"tempo"`) and zone addresses (HRP `"tempoz"`), with encoding, decoding, validation, and round-trip support.
