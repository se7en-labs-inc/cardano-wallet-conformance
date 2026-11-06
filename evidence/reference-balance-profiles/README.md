# Actual fee and minimum-ADA component evidence

All32 frozen profiles pass against the source-built pinned Haskell adapter, with zero failed or unregistered inputs. The55 offline Cargo tests, all-target/all-feature Clippy, formatting and isolated Nix build/Clippy/fmt checks pass. See [build and capture instructions](../../docs/reference-balance.md).

Actual wallet fee helpers cover witness-size estimates, combined rational execution rounding, linear coefficients and adjacent estimated-size boundaries. Ledger output decoding and minimum coin calculations cover native assets, inline datum, reference script, protocol cost changes, serialized coin boundaries and exact minimum thresholds. Independent Rust checks preserve the difference between actual and conservative wallet minimum ADA. These estimates do not substitute for real ledger admission or reference-script tier-fee evidence.

This is a component subset under a fresh fingerprint, not complete conformance. All959 current internal vectors and the HTTP/funded/state obligations still require one coherent final evidence run before the643-obligation gate can pass. Historical reports remain unchanged.
