# Haskell internal reference driver

`reference/HaskellAdapter.hs` is a thin test-only JSON adapter. The runner is Rust; this driver calls the actual Haskell implementations so their internal behavior can be measured before the replacement exists. It supports SHA-256/SHA-512, the wallet's BLAKE2b digest sizes (20/28/32/64), standard backend Ed25519 signing/verification, wallet extended verification, PBKDF2 hashing/checking, legacy scrypt checking and seeded minimal/optimal coin selection. Unsupported operations fail explicitly. It does not provide a complete reference adapter yet.

Build from the Haskell source revision recorded in `fixtures/provenance.json`, currently `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. The following invocation was tested with the existing GHC 9.12.3 development shell and package database. It compiles the wallet's passphrase and cryptographic wrapper modules directly from that checkout, rather than using the old locally compiled wallet library. The remaining dependency versions and binary hashes must be recorded as part of each run. `cardano-crypto 1.3.0` is the backend declared by that source's Cabal project; Cryptonite is 0.30.

Run in a scratch directory: the Haskell shell generates a `cabal.project.local` in its working directory. Keep compiler output outside the conformance and Haskell worktrees.

```sh
CONFORMANCE_DIR=/absolute/path/to/cardano-wallet-conformance/master
HASKELL_SOURCE=/absolute/path/to/cardano-wallet/master
REFERENCE_BUILD=/tmp/wallet-reference-build
COIN_SELECTION_SOURCE=/absolute/path/to/cardano-coin-selection-176611048d5b9f33df19d106cd925d63a7858bb2
mkdir -p "$REFERENCE_BUILD"
cd "$REFERENCE_BUILD"
# Resolve this exact dependency from `ghc-pkg field cardano-crypto-wallet depends`.
# Multiple local/global units can share a package name and version.
CRYPTO_CLASS_UNIT_ID=cardano-crypto-class-2.5.1.0-81NNjvXXDS2Hp0xj39fht9
nix --quiet develop "$HASKELL_SOURCE" --command ghc \
  -O1 -Wall -Werror -Wno-data-kinds-tc \
  -Wno-unused-imports -Wno-unused-top-binds \
  -XNoImplicitPrelude -XOverloadedStrings -XDerivingStrategies \
  -hide-package crypton \
  -package-db "$HASKELL_SOURCE/dist-newstyle/packagedb/ghc-9.12.3" \
  -package base -package bytestring -package text -package time \
  -package deepseq -package aeson -package cryptonite -package memory \
  -package cardano-crypto -package cborg -package text-class \
  -package cardano-crypto-wallet -package-id "$CRYPTO_CLASS_UNIT_ID" \
  -package cardano-coin-selection -package MonadRandom -package random \
  -i"$HASKELL_SOURCE/lib/secrets/src" \
  -i"$HASKELL_SOURCE/lib/crypto-primitives/src" \
  -i"$COIN_SELECTION_SOURCE/lib" \
  -outputdir "$REFERENCE_BUILD" \
  -o "$REFERENCE_BUILD/haskell-wallet-reference" \
  "$CONFORMANCE_DIR/reference/HaskellAdapter.hs"
```

The coin-selection source must be revision `176611048d5b9f33df19d106cd925d63a7858bb2`, as pinned by the wallet's Cabal project. The source build compiles it directly; no selection algorithm is copied into the driver. The warning flags match the wallet's documented GHC9.12 compatibility settings for that upstream source. The measured RNG versions are random1.3.1 and MonadRandom0.6.2.1, with `mkStdGen` and signed64-bit seed conversion. The shell contains both Crypton and Cryptonite, which share module names; the driver selects Cryptonite. A compiler/module visibility error is not evidence of a conformance failure.

Use the same Rust vector runner as for the future candidate. Select the operations the development driver supports; selection is explicit and does not remove obligations from the gate:

```sh
cargo run -- vectors --adapter /tmp/wallet-reference-build/haskell-wallet-reference \
  --target haskell-source-reference \
  --environment source-2fc5c383-selection1766110-root-v2-production \
  --corpus fixtures/vectors/primitives.json \
  --corpus fixtures/vectors/primitive-boundaries.json \
  --corpus fixtures/vectors/cardano-wallet.json \
  --corpus fixtures/vectors/passphrase-checks.json \
  --corpus fixtures/vectors/signature-verification.json \
  --corpus fixtures/vectors/coin-selection.json \
  --corpus fixtures/vectors/generated-selection.json \
  --corpus fixtures/vectors/haskell-selection.json \
  --corpus fixtures/vectors/root-encryption.json \
  --operation sha256 --operation sha512 --operation blake2b \
  --operation ed25519.sign --operation ed25519.verify \
  --operation passphrase.hash-pbkdf2 --operation passphrase.check-pbkdf2 \
  --operation passphrase.check-scrypt --operation keys.verify-extended \
  --operation coin-selection.select --operation coin-selection.haskell \
  --operation root-key.parse --operation root-key.create-v2 \
  --operation root-key.check-v2 --operation root-key.sign-v2 \
  --operation root-key.change-v2 --operation root-key.derive-v2 \
  --timeout-seconds 60 \
  --report reference-internals-report.json
```

This executes 578 registered cases in the current corpus. The gate still fails for missing complete HD key derivation, V1 encryption/migration, collateral, state and other domain operations. Do not combine this source/component environment with the published wallet's live-service environment. Earlier installed wallet packages identify themselves as2026.8.21 and have unestablished source provenance; their development results are separate from this direct source build.

The wallet verifier is not interchangeable with the strict verifier used by the harness to inspect real transaction witnesses. `fixtures/vectors/signature-verification.json` freezes canonical/tampered, malformed-length, chain-code and legacy identity/S+L behavior of `Cardano.Crypto.Wallet.verify`, also used in the Haskell metadata integration test. These are compatibility expectations for that named profile. They do not claim ledger acceptance of a malformed transaction. Reports and future generated specifications must retain that distinction.

The157 exact selection vectors cover both strategies and seed boundaries, permuted input order, ADA/native-token dust, minimum-change thresholds, proportional coin change, asset-count/token-quantity splitting, ADA near the ledger supply bound and native-asset totals wider than64 bits. Rust independently checks every successful result and repeated seeded execution. `capture-selections --oracle ... --output ...` refuses to overwrite a corpus and requires the hash-pinned source-built oracle; changed oracle builds require an explicit reviewed pin update. Expected answers never come from the candidate or Pallas.

The encrypted-root profile calls installed cardano-crypto-wallet 0.2.0.0, whose exact source archive is `sha256-jpHIKobCE2NI80SpHptUB7eY3MoWcMU+/DF3iVIDtXY=`. This is the wallet's declared V2 backend, with cardano-crypto-class 2.5.1.0. The driver initializes libsodium and enables deterministic test entropy only; it never calls `withFastKdfForTesting`. Argon2id retains its production 131072 KiB/time 3/parallelism 4/output 32 settings. Salt is 32 bytes, nonce 24 bytes. The recorded driver source SHA-256 is `d8e116f43fb23ce85504f68e3eedfe4948c014cdea4f66ed088b0fbb14690a1c`, executable `2a9fd2d0b24de402fee3787ec85600b159f1c66e7b1833afe8872b80cf12e1d2`. `capture-roots --oracle ... --output ...` requires that exact executable and refuses overwrite. The older selection-capture command retains its historical binary pin; it has not been silently repointed.

The 63 root vectors preserve production envelope bytes, empty/Unicode/binary passwords, wrong-password errors across four operations, authentication of salt/nonce/public-key/chain-code/ciphertext/tag, structural/AAD/KDF parameter rejection, passphrase rotation, and soft/hardened derivation including maximum indices. Public keys match the independently captured cardano-address corpus, and Rust strictly verifies signatures before freezing answers. cborg accepts overlong list encodings in the outer envelope and AAD; authentication also accepts them because the backend reconstructs canonical AAD from decoded fields. The corpus preserves this behavior. Exactly 128 bytes are classified as legacy V1 without authentication (including all zeros or a V2 prefix); the V2 check operation rejects those keys. Wallet-level V1 decryption and migration remain open.

Full Conway ledger fees use `reference/FeeAdapter.hs`, built with the same pinned wallet toolchain and actual ledger dependencies. Source SHA256 `0b150658dea988680f6c821c48f93bd238db941b5632e25b0ec33588eb49217e`; executable SHA256 `56e29eb99e518c0c130b0e85c4cccd3a3ca92b02f61fc57e0c99d2b443020766`. Compile with the pinned GHC and packages aeson, memory, lens, cardano-wallet-read, cardano-ledger-read, cardano-ledger-api, cardano-ledger-conway, cardano-ledger-alonzo, cardano-ledger-core, cardano-ledger-binary, plutus-ledger-api, and the exact crypto-class unit used by the other source adapters. No wallet source changes or fast KDF overrides are involved.

`capture-ledger-fees --oracle /path/to/wallet-fee-reference --output /new/path.json` pins and repeats each oracle invocation, then checks independent Rust laws before writing. The37 frozen profiles in `fixtures/vectors/ledger-fees.json` cover the real Conway `getMinFeeTx`, including the ledger's three-element size envelope, existing and replaced spending redeemers, aggregate execution ceiling, final reference-tier floor, stride boundaries, zero prices and zero/one/two actual wallet-produced vkey witnesses. `vectors --adapter /path/to/wallet-fee-reference --target <wallet-url> --environment <same-source-cluster-environment> --corpus fixtures/vectors/ledger-fees.json --report <new-report.json>` executes them against any conforming adapter. These component transactions are not asserted to be admissible funded ledger transactions; node admission remains a distinct live obligation.
