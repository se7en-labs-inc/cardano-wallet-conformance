# Cardano wallet conformance

An open source conformance tool for testing new wallet implementations before they are used in Daedalus or other projects that use cardano-wallet under the hood. It tests compatibility with cardano-wallet's behavior, regardless of the implementation language.

The harness is implemented in Rust and distributed under the Apache-2.0 license. Its standalone repository uses the [disassembler Rust Nix template](https://github.com/disassembler/nix-templates/tree/741a0a1f5e876bab991623289e10ef6010b3bb5b/rust).

The contract includes public HTTP behavior **and wallet internals**: key derivation, cryptography, signatures, transaction bytes, selection and accounting, discovery, restoration and rollback. CLI compatibility is outside the contract.

**The reviewed active catalogue is qualified at643/643 obligations.** The packaged runner passed3808 checks across37 fresh reports, including owned real-node profiles. This qualifies the tool against the declared Haskell reference target within the reviewed contract; each new implementation requires its own conformance run. A passing subset or harness self-test never establishes full catalogue conformance. See [qualification evidence](evidence/reviewed-executable-643-20261106/README.md) and [remaining limits](docs/conformance-suite-report.md).

Run the executable specification with `wallet-conformance conform --config implementation.json --workspace /absolute/fresh/run`. It drives all37 profiles against the configured service/internal adapter and owned real-node fixtures, then evaluates the strict gate. See [configuration and outputs](docs/executable-spec.md). The complete effective646 inventory has only three explicitly approved source-stale retirements, giving643 active obligations. Historical644 gates remain unchanged and incomplete; they are never relabeled.

```sh
nix --quiet develop
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run -- inventory > inventory.json
```

The Nix and Cargo lockfiles pin dependencies. The OpenAPI file is copied from Haskell wallet commit `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`, with API version `v2026-09-16`. The template source revision and oracle provenance are recorded in [fixtures/provenance.json](fixtures/provenance.json). This revision identifies the source contract; a runtime being tested may be a different revision and must be identified in the environment label and external build records.

Run HTTP cases against dedicated, isolated wallet services connected to the same test network:

```sh
cargo run -- http \
  --target http://127.0.0.1:8091/v2/ \
  --reference http://127.0.0.1:8090/v2/ \
  --environment conway-node11.1.1-linux \
  --suite fixtures/http.json --report http-report.json

cargo run -- http \
  --target http://127.0.0.1:8091/v2/ \
  --reference http://127.0.0.1:8090/v2/ \
  --environment conway-node11.1.1-linux \
  --suite fixtures/http-rejections.json --report rejection-report.json
```

Omitting `--reference` runs independently specified status, response-schema and assertion checks. Differential mode additionally compares media types and typed response bodies, preserving ordering, absent/null distinctions and large integers. Per-case volatile scalar exclusions must have a reason; whole objects and arrays cannot be silently ignored. Both implementations returning the same unexpected error is a failure.

Run actual integration tests against a wallet connected to a synced, block-producing testnet node:

```sh
# Supply a dedicated funded testnet mnemonic through the named environment variable.
cargo run -- live \
  --target http://127.0.0.1:8091/v2/ \
  --node-socket /absolute/path/to/node.socket --network-magic 1 \
  --funded-mnemonic-env CONFORMANCE_FUNDED_MNEMONIC \
  --environment conway-node11.1.1-linux --report live-report.json
```

Alternatively, use the existing `local-cluster` faucet:

```sh
cargo run -- live \
  --target http://127.0.0.1:8091/v2/ \
  --node-socket /tmp/wc-example/node.socket --network-magic 42 \
  --faucet http://127.0.0.1:8077/ \
  --environment conway-node11.1.1-linux --report live-report.json
```

The live workflow requires advancing block height and full node mode; creates/restores dedicated wallets; funds through the real cluster faucet if selected; constructs and decodes a payment; verifies input uniqueness and ADA conservation; checks wrong-passphrase rejection; signs; independently hashes the actual CBOR body and verifies its signatures; submits; waits for the same transaction in both wallets' ledger histories; and checks outputs and final balances including the fee. It attempts cleanup of owned wallets even on failure. Supply exactly one funding source. Existing wallets are not adopted or deleted. See [local-cluster setup](docs/local-cluster.md).

Internal tests use a small language-independent test adapter, not a production API or CLI compatibility requirement:

```sh
cargo run -- vectors --adapter /path/to/candidate-conformance-adapter \
  --target http://127.0.0.1:8091/v2/ --environment conway-node11.1.1-linux \
  --corpus fixtures/vectors/primitives.json \
  --corpus fixtures/vectors/bip39-reference.json \
  --corpus fixtures/vectors/cardano-wallet.json \
  --corpus fixtures/vectors/haskell-keys.json \
  --corpus fixtures/vectors/coin-selection.json \
  --corpus fixtures/vectors/generated-selection.json \
  --report internal-report.json

cargo run -- gate --report http-report.json --report rejection-report.json \
  --report live-report.json --report internal-report.json --output coverage.json
```

Each implementation supplies a thin adapter exposing its actual internal functions. [The adapter protocol](docs/adapter.md) specifies existing operations and is independent of the implementation language. Expected answers come from published vectors and pinned Haskell sources/tools; the candidate must not generate its own expected answers. Selection cases check independent invariants and seeded replay, while exact Haskell strategy comparison is tracked separately.

Check the harness's primitive oracle against published fixtures:

```sh
cargo run -- vectors --oracle-check \
  --corpus fixtures/vectors/primitives.json --report primitive-oracle-report.json
```

This checks the harness, not any wallet. The exhaustive gate rejects these reports. Exit status: `0` means all requested cases passed (or a complete catalogue gate passed); `1` means case failures or incomplete coverage; `2` means invalid configuration, corpus or protocol invocation. Always inspect the gate for completeness. Reports contain no request bodies, mnemonic phrases, passphrases or private key results.

Additional HTTP suites are `fixtures/http-network.json` (node, pools, settings and governance reads) and `fixtures/http-signatures.json` (exact Haskell metadata-signing golden plus independent signature verification). Run them separately with `http --suite ...` and include their reports in the same environment's gate. Include `fixtures/vectors/bip39-reference.json` in internal-vector runs for all 48 pinned published entropy/seed cases.

For asynchronous creation, `settle_wallet_state` first validates the original POST response, then requires an independently schema-validated GET to reach `ready`, and compares the observed terminal state while preserving every other stable POST field. This prevents valid differences in restoration scheduling from causing false incompatibility. Scalar exclusions may be absent in both responses; absence in only one response still fails.

The live test additionally requires a trusted Haskell `cardano-cli` (PATH or `--cardano-cli /absolute/path`) to query the supplied node socket independently. It checks actual node block advancement and the submitted transaction's recipient UTxO. This does not require the candidate to implement a wallet CLI.

To exercise the independent node oracle directly against an existing real local cluster:

```sh
CONFORMANCE_NODE_SOCKET=/tmp/wc-example/node.socket \
CONFORMANCE_NODE_MAGIC=42 \
CONFORMANCE_FAUCET_URL=http://127.0.0.1:8077/ \
CONFORMANCE_CARDANO_CLI=/absolute/path/to/cardano-cli \
nix --quiet develop --command cargo test --features live-node-tests --test node_integration
```

This opt-in integration test requires its configuration and funds a public test address through the real faucet. It verifies a newly created UTxO using the independent node query; pre-existing outputs cannot satisfy it. It validates the node-oracle integration, while the separate `live` workflow tests wallet submission.

Haskell behavior is the current authority. The original OpenAPI is preserved; [explicit corrections](fixtures/api/haskell-corrections.json) are checked against its digest and applied before alias expansion. See [the authority policy](docs/authority.md) and [observed discrepancies](docs/known-spec-defects.md). The future authoritative specification will be generated from this suite and reviewed separately.

Run `fixtures/http-keys.json` for exact independently captured account/role/key-hash/address expectations, passphrase rotation, and watch-only restoration. Its Bech32 assertions check both the HRP and decoded bytes against frozen Haskell keys; its explicit absence assertions preserve omitted versus null fields. `fixtures/http-statuses.json` adds the malformed-body, unknown-wallet and media-negotiation status matrix, including observed error precedence. Run every committed HTTP suite with `--reference` and include every report in `gate`. Add `fixtures/vectors/primitive-boundaries.json` to the vector command for independent binary-message boundary and Unicode PBKDF2 cases.

The funded workflow also rejects unsigned submission, compares UTxO snapshots and logarithmic histogram buckets with confirmed balances, checks change outputs independently on the node, and deletes/restores the recipient from its mnemonic to verify identity, discovered addresses and transaction history. Missing checkpoint, restart and rollback tests remain explicit gaps.

Export a reviewable behavioral specification:

```sh
cargo run -- specification --output /tmp/wallet-behavior.draft.json \
  --report http-report.json --report live-report.json
# In CI, require complete bounded coverage while still leaving authority promotion to review:
cargo run -- specification --output /tmp/wallet-behavior.ci.json \
  --require-complete --report http-report.json --report live-report.json
```

Exports include corrected API schemas, HTTP expectations and exclusions, adapter protocol, exact internal vectors and provenance, requirements, execution reports, and missing semantic case IDs. With no reports, all requirements are unvalidated. Exports remain drafts even if the bounded catalogue passes. The completeness option returns failure while any obligation is missing. Existing output files are never overwritten.

Reports carry a suite fingerprint covering executable assertions, pinned dependencies, schemas, corrections and corpora. The gate rejects missing or stale fingerprints, including historical reports from before the corrections; rerun reference validation rather than modifying old evidence. Historical reports under `evidence/reference-v2026-09-16/` remain unchanged.

A thin [Haskell internal reference driver](docs/reference-adapter.md) now executes actual wallet passphrase functions and the declared crypto backends. It has 98 passing registered cases, including legacy wallet signature-verifier boundaries; its source/component environment is separate from the published wallet's live environment. `vectors --operation OP` can select supported operations without modifying frozen fixtures. Modified or unregistered runtime cases are listed in reports and rejected by `gate`, even if they retain a known case ID. Add `fixtures/vectors/passphrase-checks.json` and `fixtures/vectors/signature-verification.json` to complete candidate vector runs.

The reference driver now also calls the pinned Haskell selection component. `fixtures/vectors/haskell-selection.json` adds157 exact minimal/optimal strategy, seed, dust and change-splitting cases; the complete supported source-based run passes515 cases, including the260 existing invariant cases. JSON comparison preserves signed metadata integers beyond64-bit signed range, and schema-evaluation failures cannot bypass owned-wallet cleanup. The complete mandatory catalogue is still unfinished.

`fixtures/http-families.json` adds 70 Byron/shared lifecycle and numeric grammar cases: random/Icarus/Trezor/Ledger restoration, passphrase rotation, empty history/UTxO, active shared wallets, cosigner collection and activation, and exact decimal/exponent quantity parsing. All 411 HTTP cases and 48 funded live-node checks pass in the new [reference evidence](evidence/reference-families-v2/runtime.json). That live environment covers 422/643 obligations, leaving 221 missing. Funded shared/Byron spending, encrypted-root internals, rollback/restart and the remaining semantic matrix still require work. Use this seventh HTTP suite with `--reference`, and include its report in `gate` and specification exports.

`fixtures/vectors/root-encryption.json` adds 63 production-cost V2 encrypted-root cases. The Haskell source/component run now passes 578 registered cases, including independent public-key/signature cross-checks, passphrase rotation, derivation, ciphertext/AAD tampering and preserved noncanonical CBOR acceptance. See [build and capture instructions](docs/reference-adapter.md) and [component evidence](evidence/reference-root-v2-production/runtime.json). There are 755 internal vectors in total; V1 unlocking/migration and other internal/stateful domains remain open. Component and live evidence have distinct environments and suite fingerprints and cannot be combined into a conformance certificate.

`fixtures/vectors/wallet-credentials.json` adds 53 actual wallet/database transition cases. All 631 supported internal cases now pass, out of 808 frozen vectors. The [credential reference](docs/reference-credentials.md) calls the Nix-built pinned wallet library and real SQLite-backed in-memory DB: it checks migration, password rotation, callback failures, unchanged-state guarantees and the Byron/Icarus V1 exclusions. Independent laws reject false migration claims, incorrect password acceptance and altered signatures. [Evidence](evidence/reference-wallet-credentials/runtime.json) retains migration-failure injection and disk durability as open obligations.

The earlier [coherent pinned-source baseline](evidence/reference-source-coherent/runtime.json) passed411 differential HTTP cases,48 funded real-node checks and631 supported internal cases. Its strict gate covered440/643 obligations. [Reproduction and epoch sampling](docs/reference-source-runtime.md) document the source-built wallet/cluster/node bindings. The original epoch-boundary failure remains saved.

The historical [coherent expanded baseline](evidence/reference-expanded-coherent/runtime.json) passes **1,556 cases**:486 differential HTTP,1,022 actual Haskell internal profiles and48 funded live-node checks. The separate real-node integration also passes. Its strict gate covers **539/643 obligations, leaving104 open**, with zero failures or unregistered inputs. The internal profiles cover standard/raw BIP39, hardware/factor roots, address/script codecs, actual migration-failure preservation/retry, eight-era CBOR, metadata/ledger signatures, fees/minimum ADA, witness merging, certificates and collateral/mint/burn selection. The remaining funded/API/state scenarios still prevent exhaustive conformance. The generated specification stays a draft at `artifacts/behavioral-specification.expanded-coherent.draft.json`; historical evidence remains preserved under its original fingerprints.

For funded partial-transaction balancing, add `--balance` to the local-cluster live run. It verifies the balance API, exact transaction/signature/fee conservation, real submission and independent node outputs. Replay the11 new `fixtures/vectors/balancing-profiles.json` inputs through the pinned ledger adapter as well as the87 slot/time profiles through the slotting adapter. Optional `--collateral` covers source-defined unsupported collateral fields and uses the user-approved return-code schema overlay; it does not bypass validation. See [live contracts](docs/live-contracts.md) for exact assertions and limitations.

The reviewed active gate passes **643/643 obligations** in a fresh packaged run, with all3808 checks passing in25m22s. The previous historical37-report cohort remains643/644 with3810 checks, not a relabeled result. See the [current methodology and blind-spot report](docs/conformance-suite-report.md). Historical evidence retains its original fingerprints and denominators; components are never merged into a new combined result.
