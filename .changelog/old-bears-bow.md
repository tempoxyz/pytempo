---
pytempo: patch
---

Fixed a test race condition in `TestAccessKeys` by waiting for block propagation before reusing an access key, ensuring load-balanced RPC nodes have imported the provisioning block.
