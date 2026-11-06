# Wallet conformance constitution

1. The Haskell wallet at a pinned revision and published cryptographic vectors are independent oracles. Never use the candidate or Pallas to manufacture its own expected answers.
2. This project tests HTTP and wallet semantics, including internals through a JSON adapter. CLI compatibility is out of scope.
3. Live tests require real block production, funded UTxOs, ledger submission and confirmation. Mocks validate the harness only.
4. Missing, skipped, unsupported or unexecuted requirements prevent exhaustive conformance. Operation coverage alone is insufficient. No finite test suite proves universal equivalence.
5. Exact deterministic bytes, integers, units, errors and ordering matter. Randomized selection must satisfy conservation, eligibility, fee, asset, collateral and size constraints; randomness is never a blanket exemption.
6. Rust implementation, pinned Cargo and Nix dependencies, the disassembler/nix-templates Rust template, formatting, Clippy and meaningful harness regression tests are required.
7. Tests own only wallets they successfully create. Private fixture material must not appear in reports. Local cluster processes must be cleaned up on success and failure.
8. Haskell behavior is authoritative now. Retain the original OpenAPI source and record narrow, evidence-backed corrections explicitly. The specification generated from the conformance suite will become authoritative in the future; do not silently promote incomplete observations into that specification.
