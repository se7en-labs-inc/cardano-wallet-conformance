# Real scheduled Babbage→Conway control audit

The fixture audit passed at assertion source `d6ebdfa310`, after spec `d32109904f`. Five directly owned node11.1.3 processes used copied explicit genesis/credential files, new private databases, new loopback ports and matching integer genesis clocks. The original protocol parameters, initial funds and stake were preserved. Conway was scheduled at epoch3 instead of0. The Haskell wallet and native launcher source were unchanged.

The actual relay first observed Babbage at epoch0, block0, slot1. The same chain then reached Conway at epoch3, block188, slot361. Both actual parameter snapshots retained protocol version12. This verifies a genuine runtime hard fork; no API response or independent chain was substituted. All five node children exited0, were reaped and were independently verified absent with the audit parent.

This control audit earns no wallet conformance credit. `chain.era-boundaries` still requires restoration, actual signed wallet submission and stake-certificate checks across the same observed boundary. All643 obligations and thirteen pending proposals remain unchanged. Private credentials and node logs were not copied.

Two focused tests, all34 harness tests, Clippy across targets/features, binaries, formatting and isolated Nix Clippy/format checks passed. The filtered offline run passed139 tests, excluding the unchanged known input-set parser failure. No full Cargo test or Nix package pass is claimed. The initial unnecessary-format Clippy diagnostic is retained alongside the successful corrected check. Exact pinned node source was resolved through the wallet flake; no store directory was enumerated.
