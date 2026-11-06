# Eight-era transaction codec component evidence

All27 registered ledger profiles pass, including the approved Dijkstra fixture constructed with actual ledger mkBasicTx/mkBasicTxBody/mkBasicTxOut. The unchanged pinned wallet decoder, renderer and transaction-ID path accept and round-trip the Dijkstra bytes, and Rust independently hashes the exact body. All26 earlier inputs and expected results remain identical; only executable provenance changes. Historical seven-era evidence and its earlier pins remain preserved.

The60 offline tests and isolated Nix package/Clippy/fmt checks pass; all-target/all-feature Clippy and formatting pass. See docs/reference-ledger.md for the current source/executable hashes and build flags. The actual wallet's Dijkstra certificate rejection remains a separate observed behavior in writer profiles. No real-ledger admission claim is made for codec fixtures, and this subset cannot certify643 obligations.
