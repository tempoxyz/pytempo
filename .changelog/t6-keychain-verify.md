---
pytempo: minor
---

Expose the T6 (TIP-1049) stateful keychain signature checks on the
`SignatureVerifier` precompile binding: `verify_keychain(account, hash, signature)`
and `verify_keychain_admin(account, hash, signature)`. Bumped the vendored
`tempo-std` ABI ref to pick up the `verifyKeychain` / `verifyKeychainAdmin`
additions to `ISignatureVerifier`.
