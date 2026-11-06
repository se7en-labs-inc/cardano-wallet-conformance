# Initial real pending expiry run

Source491b459b80 after specificationa235686f65. Fresh owned cluster/wallet;21 checks,20PASS/one failed validity assertion. It stops after construction/signing and before producer pause or transaction submission. No pending-expiry conformance credit. Wallet and cluster cleanup checks pass, owned processes are stopped/reaped by the audited supervisors. No private runtime keys, database or logs are copied.

The assertion expected no lower validity bound. Pinned Haskell Server.hs instead parses an omitted lower bound as SlotNo0 and explicitly wraps it with Just in the construction context. Exact pinned excerpts are preserved; the narrow correction awaits review. It preserves the strict independently computed upper slot and every expiry/node/state assertion. Full161 harness tests, Clippy, Rust formatting and isolated Nix package/Clippy/fmt checks pass for source491b459b80; these do not replace actual successful expiry execution. Last coherent passing baseline remains587/643; current gate remains644.

Final read-only process verification through pinned procps found no cardano-node, local-cluster or cardano-wallet process referencing this run's owned workspace. No service remains running.
