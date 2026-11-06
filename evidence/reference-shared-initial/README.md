# Real-node two-party shared profile

All91 live workflow checks pass against the pinned Haskell wallet on the fresh Conway node11.1.3 cluster. This includes the basic payment/restoration flow and two-party shared creation, incomplete construction403, reciprocal activation, matching addresses, real shared funding discovered by both cosigners, construct/decode, partial signature rejection403, merged two-key signing and submission202, both shared wallet histories/balances and independent recipient UTxOs from the real node.

The Rust harness independently verifies both signatures over the unchanged transaction body and the native script's domain-separated hash against the funded address. It checks that this script is all-of-two and requires the two actual verified signing keys. All owned wallets were cleaned up. The68 offline regression tests, all-target/all-feature Clippy and formatting passed before this run. Initial Clippy style issues were corrected without changing the test approach or weakening assertions.

The separately configured real-node faucet/UTxO integration test also passed, run last. Isolated Nix package, Clippy, formatting and credential fault-injection checks passed for this implementation. The current cluster has now funded the fixed public integration fixture: future HTTP baselines require another empty fresh cluster.

This is separate profile evidence under the fingerprint in live.json. Do not combine it with the earlier family's baseline fingerprint. The643-obligation gate is not yet complete; Byron funding correction is pending approval and state, asset and governance cases remain mandatory. Haskell behavior remains authoritative and no draft has been promoted.

All owned wallet/cluster processes received SIGTERM after evidence capture. Cluster shutdown completed and all eight observed wallet/cluster/node process IDs were verified absent. No processes from this run remain active.
