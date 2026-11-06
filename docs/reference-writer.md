# Wallet witnesses and certificates

Build with the pinned compiler from [credential setup](reference-credentials.md):

```sh
REFERENCE_BUILD=/tmp/wallet-writer-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -package aeson -package memory -package lens -package cardano-wallet \
  -package cardano-wallet-read -package cardano-ledger-read -package cardano-balance-tx \
  -package cardano-api -package cardano-addresses -package cardano-crypto \
  -package-id cardano-crypto-class-2.5.1.0-81NNjvXXDS2Hp0xj39fht9 \
  -package cardano-ledger-api -package cardano-ledger-core \
  -package cardano-ledger-alonzo -package cardano-ledger-binary \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-writer-reference" \
  /absolute/path/to/cardano-wallet-conformance/master/reference/WriterAdapter.hs
```

Source SHA-256 `32a31e617a1c3b483c53d1df7a2ce5be311e12ad385c8c7810db1e1e221375de`; executable SHA-256 `9d6548868037df4648ebc648aa0fc364ef538064ea8bb2e28072d7c92dac37f2`. The28 profiles execute actual wallet `mkShelleyWitnessLedger`, `mkByronWitnessLedger`, `signTransaction`, native-script conversion and delegation/voting certificate builders. The CBOR inputs and128-byte key fixtures are public test data captured independently from the pinned Haskell implementation. These structurally representative transactions do not claim real ledger-valid UTxOs.

Witness cases check signatures over the unchanged body, bootstrap chain codes and derivation/network attributes, native script witness-set encoding, two distinct merged keys, duplicate/repeated signing, unresolved-input preservation, malformed key length and transaction decoding. Rust verifies every transaction signature independently. The capture command asserts that the merge fixture produces two distinct witnesses: Shelley/shared generation-factor roots intentionally coincide, so the second merge key uses the independently captured Ledger root.

Certificate cases cover stake join/register/refund, key/script credentials, zero/max deposit serialization, vote registration and key/script/abstain/no-confidence DReps. Rust independently derives credential/script hashes and certificate tags/CBOR. The actual pinned wallet throws explicit errors for Dijkstra certificates and missing required deposits; the adapter narrowly catches those documented exceptions as `unsupported_era` and `deposit_required`. It exits on unexpected exceptions. This Dijkstra certificate rejection is separate from the unresolved Dijkstra codec fixture generator TODO.

```sh
nix --quiet develop --command cargo run -- capture-writer-profiles \
  --oracle "$REFERENCE_BUILD/wallet-writer-reference" --output new-writer-profiles.json
nix --quiet develop --command cargo run -- vectors \
  --adapter "$REFERENCE_BUILD/wallet-writer-reference" \
  --target haskell-source-reference --environment source-2fc5c383-writer \
  --corpus fixtures/vectors/writer-profiles.json --report writer-reference-report.json
```

The643-obligation gate still requires actual funded stake/governance transitions and the remaining API/state evidence under a final common fingerprint.
