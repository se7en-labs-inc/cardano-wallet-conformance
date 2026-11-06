# Actual wallet credential reference

`reference/WalletCredentialAdapter.hs` calls the actual pinned `Cardano.Wallet` library and its SQLite-backed in-memory database. It does not implement migration itself. It uses real Shelley/shared/Byron/Icarus states and keys, and brackets database lifetime with `withBootDBLayerInMemory`. Network and transaction-layer access fail explicitly: this profile tests credentials, not chain synchronization.

Build the compiler environment from an immutable Git flake reference. The local Cabal registrations contain older broken package units and must not be used for this oracle. A `builtins.getFlake` filesystem path also admitted local package-index state during investigation; the locked Git reference below avoids that failure.

```sh
CONFORMANCE_DIR=/absolute/path/to/cardano-wallet-conformance/master
WALLET_FLAKE=git+file:///absolute/path/to/cardano-wallet/master?rev=2fc5c383c94bb907deaa0cd27b1b407f86224b6c
REFERENCE_BUILD=/tmp/wallet-credential-reference-build
mkdir -p "$REFERENCE_BUILD"
nix --quiet develop --command rustc --edition=2021 --crate-type=staticlib \
  -C panic=abort -O -D warnings "$CONFORMANCE_DIR/reference/credential-faults.rs" \
  -o "$REFERENCE_BUILD/libcredential_faults.a"
REFERENCE_GHC=$(nix --quiet build --no-link --print-out-paths \
  --file "$CONFORMANCE_DIR/reference/wallet-toolchain.nix" \
  --argstr walletFlake "$WALLET_FLAKE")
REFERENCE_TEST_COMMON_UNIT=$("$REFERENCE_GHC/bin/ghc-pkg" field \
  z-cardano-wallet-unit-z-test-common-2026.9.16 id --simple-output)
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -XNoImplicitPrelude -XOverloadedStrings \
  -package aeson -package memory -package contra-tracer \
  -package cardano-crypto -package cardano-crypto-wallet -package cardano-crypto-class \
  -package cardano-wallet -package-id "$REFERENCE_TEST_COMMON_UNIT" \
  -package cardano-wallet-primitive -package cardano-wallet-secrets \
  -package address-derivation-discovery -package cardano-addresses -package crypto-primitives \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-credential-reference" \
  "$CONFORMANCE_DIR/reference/WalletCredentialAdapter.hs" \
  "$REFERENCE_BUILD/libcredential_faults.a" \
  -optl-Wl,--wrap=cardano_crypto_wallet_argon2id
```

The toolchain recipe asserts wallet revision `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. The measured wallet library is `/nix/store/vlja3sr32gvp007yddw8scpnjpnhpik8-cardano-wallet-lib-cardano-wallet-0.2026.9.16`; the test fixture library is `/nix/store/g37vxdbgv1g4yg8dbp7s27jdqhhncqbq-cardano-wallet-unit-lib-test-common-2026.9.16`. These are package output paths, not directories to scan. GHC 9.12.3 exposes the named test sublibrary through its exact unit ID; package-name-only flags did not expose it.

The current capture pin is executable SHA-256 `f63e63025466f42461010c8dab590378309363524a9bdca0370b51d18a912fbe`, adapter source SHA-256 `f1e92df7df5967c3cb5e252fe74ffd05ad0bd267078e58905df12541c360f5e6`, fault-shim source SHA-256 `97ccbdb4cf93109496c8f403f145d6c08f6dc64ff3f2e26e40fe9f74a2a05abc`. Rebuilt binaries require an explicitly reviewed pin update before recapture. `capture-credentials --oracle ... --output ...` refuses overwrite and checks independent transition laws, root public-key goldens, strict signatures and deterministic replay before saving expected results. No candidate or Pallas code supplies expectations. Historical53-case source/binary pins remain recorded in earlier evidence.

Run the61 frozen cases with:

```sh
cargo run -- vectors --adapter /absolute/path/to/wallet-credential-reference \
  --target haskell-source-reference --environment source-2fc5c383-wallet-credentials-production \
  --corpus fixtures/vectors/wallet-credentials.json \
  --operation wallet.credentials --timeout-seconds 120 \
  --report wallet-credential-report.json
```

The matrix covers all four flavors, PBKDF2/scrypt V1 credentials, empty/nonempty/Unicode passwords, normal credential attachment, missing root keys, correct/incorrect unlocks, rotation, unchanged-password rotation and deliberately failing callbacks. The snapshot records encrypted-key bytes and password acceptance, preserving deterministic V2 test entropy while retaining production Argon2id parameters. Raw password hashes and wall-clock values are not exported. Equality observations still include the actual stored hash and metadata.

The first correct Shelley/shared V1 unlock migrates stored credentials to V2 before the callback, but the callback receives V1 access. A later callback receives V2. A callback error can therefore leave migration committed. Wrong-password failures do not migrate or change metadata. Migration changes the stored scheme while preserving the password-update timestamp; successful passphrase changes update that timestamp. Byron/Icarus stay V1, with scrypt credentials upgraded to PBKDF2 on password change. Root public keys and signatures remain unchanged across correct migration and re-encryption.

Eight additional cases inject one actual Argon2 failure during authorized Shelley/shared V1 unlock for both PBKDF2 and scrypt credentials, with successful and failing callbacks. The unchanged wallet emits its actual migration warning, preserves V1 key/metadata/timestamp, and still exposes V1 callback access. A normal retry then migrates successfully and later access is V2. The Rust FFI shim delegates ordinary calls unchanged and asserts production KDF arguments; the Nix `credential-faults` check verifies one-shot consumption/delegation. The original53 expected results remain unchanged. Disk restart/crash durability, shared activation/reattachment and database-corruption behavior require additional profiles; this in-memory matrix does not establish those behaviors or complete wallet conformance.
