# Wallet conformance

Use the installed `speckit` skill for features; follow `.specify/memory/constitution.md`.
This is a standalone open source conformance tool for testing new wallet implementations before adoption by Daedalus or other projects that use cardano-wallet.
The default branch is `master`; the repository uses a `.bare` directory and sibling worktrees.
Reuse the existing `specs/70007-wallet-conformance` artifacts for the migrated conformance work (`SPECIFY_FEATURE=70007-wallet-conformance` when invoking Spec Kit helpers on `master`).
Run development commands through `nix --quiet develop`.
Required checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
Live tests and reference comparisons must be reported separately from mock harness tests.
Never label partial coverage or missing adapter results exhaustive conformance.
