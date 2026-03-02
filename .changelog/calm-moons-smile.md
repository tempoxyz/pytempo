---
pytempo: patch
---

Fixed access key integration tests to skip on nodes that do not support Keychain V2 signatures (requires >= v1.0.0), preventing false failures on older testnets running v0.8.x.
