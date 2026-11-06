# Actual transaction, metadata and ledger signature evidence

All26 frozen profiles pass against the pinned source-built Haskell adapter with zero failed or unregistered inputs. The51 offline Cargo tests, all-target/all-feature Clippy, formatting and isolated Nix build/Clippy/fmt checks pass. See [build and capture instructions](../../docs/reference-ledger.md).

The ledger DSIGN profile rejects noncanonical S and small-order R/public keys, while the separately preserved legacy extended-wallet profile has different acceptance behavior. Actual wallet decoding rejects the probed indefinite outer array, duplicate body fee key, trailing bytes and truncation. Independent Rust checks preserve exact body hashes and metadata serialization, symmetric integer limits and UTF-8 lengths.

The optional live-node Cargo test was invoked without runtime configuration during validation and failed on missing CONFORMANCE_CARDANO_CLI. It has not been counted as passing in this evidence set; the next configured real-cluster run must execute it. No node was running for this component capture. Dijkstra fixture generation raises a TODO in the pinned source and has no passing evidence.

This is a component subset under its own fingerprint. All927 current internal vectors, the complete HTTP/funded/state matrix and one coherent final fingerprint remain required; this report does not certify643 obligations.
