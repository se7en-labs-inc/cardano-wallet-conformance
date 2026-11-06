# Validation status

Reference runtime: published wallet v2026-09-16, git revision `33fcb5e4104db4d0979669a1adc9f5b782acd1c0`; cardano-node 11.1.1, git revision `c2ebdc87dfe07706a83e52f219e712c60d1b0a56`. Release archive SHA-256 `318ca7e1b8d49249aeee0a6ee9dff92c095ae1ad5279133b4b70e8f3b39dbfb5`. API/source-contract revision is separately pinned to `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`.

- Nix development environment and package build succeed.
- Rust harness regression tests and Clippy pass; final counts are recorded after all edits.
- 63 independent published primitive vectors pass the harness's primitive oracle.
- Exact key/address fixtures captured from SHA-256-pinned Haskell cardano-address; 122 vectors, including an extended signature independently verified against the Haskell golden.
- Real local Conway cluster with network magic 42 produces blocks. Published reference wallet connects and reaches full-node ready state.
- HTTP lifecycle, read-only network/service API suite and metadata signature golden pass against the reference.
- Differential lifecycle and metadata signature checks pass between isolated reference services, accounting for asynchronous creation state.
- Generated rejection suite: 79/83 pass; remaining four fail strict schemas that omit the actual generic bad-request response.
- Funded live workflow reaches restoration, faucet funding, construction, ADA conservation and unique-input checks. It stops at the confirmed decoded-input `oneOf` defect; owned wallets are cleaned up.

The schema-correction policy is awaiting user direction. Strict failures are retained, not waived. Full ledger confirmation and the complete requirement catalogue remain unvalidated. See `docs/known-spec-defects.md` and `docs/coverage.md`.

Final harness checks before the pending schema decision: 22 tests pass; Cargo Clippy with denied warnings and Cargo formatting check pass. The Nix template formatter is now pinned to the same Fenix Rust formatter and Rust 2021 edition as Cargo, resolving the default treefmt Rust 2024 mismatch. Independent node-oracle queries successfully observe real Conway block production; recipient-UTxO confirmation is implemented and mutation-tested but cannot yet be reached by the strict-schema funded workflow.

A separate real-node oracle integration test passes: the existing cluster faucet creates a fresh payment to a pinned public test address, and the trusted cardano-cli query observes its new transaction/output with the exact amount. Existing outputs cannot satisfy the assertion. This validates the independent node-query boundary without claiming that the schema-blocked wallet transfer workflow has passed.

The final strict reference gate records 209/644 covered obligations, 435 missing, four rejected-response schema failures and the decode/workflow failure. Redacted reports are committed under `evidence/reference-v2026-09-16/`. All temporary cluster and wallet processes were shut down after validation.

## Haskell behavioral baseline after the authority decision

The user selected Haskell behavior as the current oracle and a future conformance-derived specification as authority. Explicit checked corrections now apply while preserving the original API. Historical strict-schema failures above remain as provenance, not current failures.

Current evidence: `evidence/reference-behavior-v1/`. All six differential HTTP suites pass: lifecycle 11, network 14, metadata signature 4, independent key/address/passphrase/watch-only matrix 41, syntax rejections 83, response-status/precedence matrix 188 (341 total). The real funded wallet workflow passes 48 checks, including body hashes/witnesses, actual ledger submission, independent node recipient/change UTxOs and header hash/slot/height, unsigned rejection, exact balances and UTxO histograms, and recipient deletion/mnemonic restoration with matching addresses/history. The independent fresh-faucet-output integration test also passes.

28 harness regression tests, Cargo formatting, Clippy with all features/denied warnings, Nix package/Clippy/fmt checks pass. All 134 published/independently captured primitive oracle cases pass; these are rejected by the conformance gate as harness-only evidence. The gate records 375/649 covered obligations, 274 missing, zero execution failures, and named unexecuted semantic cases. Both normal and completeness-required specification exports produce the same draft contract; completeness-required export correctly returns exit 1. Reports bind to suite SHA-256 `fd43c5cbe2d6ad896f495261c762de0cb0d6117c98155f0a64a32e3df3f9547b`, executable source commit `a52c0c8d3e`. All temporary cluster/wallet processes from this run were stopped and their absence verified. Full exhaustive conformance remains unestablished.

## Direct source internal reference

A separate source/component run uses wallet source `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`, GHC 9.12.3, Cryptonite0.30 and the declared cardano-crypto1.3.0 backend. The wallet passphrase and crypto wrapper modules are compiled directly from pinned source, with all output outside the worktrees. It passes98 registered primitive/PBKDF2/scrypt/wallet-verifier cases. Actual source-built oracle SHA-256 `db05a39d6253e0f4dd7ba71cc8bd2a2d20e9ca5468edd26c902cd0bc901cbbb4`; driver SHA-256 `01e2e3f2d5ed82c7c3bc757efc0512f8daae532c5494718937e703e813ba78e5`. Evidence and dependency details are in `evidence/reference-internals-2fc5c383/`. This is separate from the published wallet live environment.

The runtime-registration regression now prevents altered external fixture contents from closing obligations through reused IDs. There are29 passing Rust harness tests; Cargo Clippy/all features, fmt, and Nix package/Clippy/fmt checks pass. The corpus now contains535 internal vectors, including explicit legacy wallet verifier identity-point and S+L behavior, and650 obligations. Historical live reports remain valid for their older suite fingerprint and cannot be combined with the changed current suite. The full exhaustive task remains open.

## Pinned selection source validation

`cardano-coin-selection` revision176611048d5b9f33df19d106cd925d63a7858bb2 is compiled unchanged into the reference driver, with random1.3.1, MonadRandom0.6.2.1 and signed64-bit mkStdGen seeding. The source-built run passes515 registered cases:98 crypto/passphrase/verifier checks,260 invariant selections and157 exact minimal/optimal selection vectors. Replay and independent Rust laws check every selection. Corpus capture stopped on incorrect test assumptions about ADA dust and ADA sizing; those were resolved from the pinned `assignCoinsToChangeMaps`/size-assessment code before answers were frozen. ADA remains within its supply budget; native-asset totals exceed64 bits in the wide-arithmetic fixtures.

Current oracle SHA-2562f9dc7dece467de7e52f9d6d0cccf1c0989e0ad25b23bb456aacefe0decadb44; driver source SHA-256d5733b541d0d219473da3708a4b0b8c0cfd4843796a7b04c0ffe845870989aea. Evidence is in `evidence/reference-selection-1766110/`. This component environment covers17/650 requirements, with633 missing and no failures; it must not be combined with historical live reports from a different environment or suite fingerprint.

All32 Rust regression tests, Cargo Clippy/all features and formatting, and Nix default/Clippy/fmt builds pass. A reproduced adjacent-negative-metadata-integer rounding bug is fixed by exact JSON number storage. Schema-evaluator failures are isolated so owned-wallet cleanup still executes. There are692 frozen internal vectors. Exhaustive coverage remains incomplete.

## Wallet-family and numeric grammar validation

Source commit `3c8ceaadfd`, suite SHA-256 `2b7821e12f3488d1a04d99f581915c4ab006d58e96b2ec12a3eb41d5c0ab9d1d`: all seven differential HTTP suites pass (411 cases), including 70 new family/numeric cases. The real-node funded workflow passes all 48 checks; the separate fresh-faucet-output integration passes. Two isolated v2026-09-16 wallet services share a real advancing Conway cluster. Independent node observations advanced from block 451 to 1191 during this phase. Initial Byron rename failures are retained separately: the borrowed schema referenced the Shelley wallet type. The correction retains error statuses and uses the actual Byron success type; a regression protects both. Servant NoContent declarations and live unsupported-Accept 204 responses justify removal of seven unreachable 406 obligations. Existing precedence probes remain frozen and passing.

The current live gate covers 422/643 requirements, with 221 missing and no failures. All 32 Rust regressions, all-feature Clippy, formatting, Nix package/Clippy/fmt builds pass. Evidence is in `evidence/reference-families-v2/`; it must not be combined with older suite fingerprints or the distinct source-component environment. Both wallet services and the cluster were terminated and process absence verified. The generated specification remains a draft. Funded Byron/shared spending and the unimplemented internal/stateful obligations remain open under T011.

## Production encrypted-root validation

The source/component driver now calls cardano-crypto-wallet 0.2.0.0 with actual production Argon2id parameters, initialized libsodium and deterministic test entropy (no fast-KDF override). The exact source archive, driver/package versions and executable/source hashes are recorded in `evidence/reference-root-v2-production/runtime.json`. Its 63 new cases include exact envelopes, empty/Unicode/binary passwords, wrong-password failures, authenticated field tampering, malformed/truncated/trailing CBOR, invalid AAD/KDF parameters, rotation with unchanged deterministic signatures, and hardened/soft/max-index derivation matching the independent cardano-address corpus. cborg's noncanonical list acceptance and canonical AAD reconstruction are preserved, as is unauthenticated 128-byte V1 classification.

All 578 supported registered internal cases pass under suite fingerprint `210ffd80176b8fb1b5343dc44d34da29cb12ae638a372e518e65526691ecbe82`, executable source `aeb33a5939`. The gate covers 17/643 obligations, leaves 626 missing, and retains five explicit V1 encryption/unlocking/change/migration obligations. There are 755 internal vectors. The Nix build initially caught a missing source-set entry after the driver was added to the fingerprint; the exact Haskell file is now included in the explicit source set. This component evidence is separate from the live API environment; no exhaustive certificate is established.

## Actual wallet credential transition validation

The actual pinned Nix wallet library and public test-fixture library build successfully. `WalletCredentialAdapter.hs` links those libraries directly and calls real attachment, `withRootKey`, passphrase-update and SQLite-backed in-memory DB functions. The compiler environment initially failed when its expression admitted local path-flake package-index state; using the immutable Git reference resolved it. Exact test-sublibrary unit selection and existential DB record pattern matching were required for compilation. The adapter builds with `-Wall -Werror`; no fast KDF override is used.

All 53 frozen credential cases pass capture, replay, independent laws and registered execution. Alongside the 578 supported component cases, 631 cases pass under suite SHA-256 `a36386b4c2a1891ec4fa5178374e1467082f7883acbb7dede96afcfcd9e96eaa` (implementation `14986c478a`). Root public keys match independent cardano-address goldens and signatures pass strict Rust verification. The matrix covers four flavors and both V1 password schemes; migration can persist before a deliberately failing callback. V1 scrypt credentials on Byron/Icarus upgrade their password scheme to PBKDF2 on rotation while staying V1. Wrong passwords preserve credentials and metadata; migration preserves the password-update timestamp.

All 34 Rust tests, all-feature Clippy, formatting and isolated Nix package/Clippy/fmt checks pass. The gate covers 18/643 requirements with 625 missing and zero execution failures/unregistered inputs. There are 808 internal vectors. Migration crypto-failure preservation remains explicitly unexecuted; disk restart/crash durability is outside this in-memory profile. Evidence and actual library/compiler paths and hashes are in `evidence/reference-wallet-credentials/`.
