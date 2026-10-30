---
pytempo: minor
---

Added P256 and WebAuthn signing and verification that match viem's tempo Accounts byte for byte, in the new `pytempo.signatures` module: `P256Account` and `WebAuthnAccount` (headless, like `Account.fromP256` and `Account.fromHeadlessWebAuthn`), `Secp256k1Account`, `P256Signature`, `WebAuthnSignature`, and `recover_signer`, which verifies any Tempo signature envelope (secp256k1, P256, WebAuthn, and Keychain V1 or V2 with any inner signature) as tempo-primitives does. Added `TempoTransaction.sign_with`, `TempoTransaction.sign_access_key_with` and `TempoTransaction.recover_signer`, `KeychainSignature.sign_with` for P256 and WebAuthn access keys, and `KeyAuthorization.sign_with` for any root key. `KeychainSignature` now carries a `version` (0x03 or 0x04) and any inner signature, and `SignedKeyAuthorization.decode` accepts P256 and WebAuthn signatures. Declared `pycryptodome` as a direct dependency.
