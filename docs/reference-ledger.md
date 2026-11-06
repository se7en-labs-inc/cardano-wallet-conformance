# Transaction, metadata and ledger signature reference

Build the actual Haskell components with the pinned compiler environment from [credential setup](reference-credentials.md):

```sh
REFERENCE_BUILD=/tmp/wallet-ledger-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -package aeson -package memory -package lens -package cardano-wallet-read \
  -package cardano-wallet-primitive -package cardano-ledger-binary \
  -package cardano-ledger-api -package cardano-ledger-core \
  -package cardano-ledger-mary -package cardano-strict-containers \
  -package-id cardano-binary-1.9.1.0-KL3qUL7ggQfJTmanZLl0lU \
  -package-id cardano-crypto-class-2.5.1.0-81NNjvXXDS2Hp0xj39fht9 \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-ledger-reference" \
  /absolute/path/to/cardano-wallet-conformance/master/reference/LedgerAdapter.hs
```

Source SHA-256: `a131e747e497576cef186b098c54001f66ceaa3aaa38aa35bfc0b22c236a28d0`. Executable SHA-256: `5f9ad0a56fba7f4c60854d7a763de8d38ea39b3b1a56050d2e9659663d94026c`. The exact cardano-binary unit avoids a second incompatible package registration in the compiler environment. Fixed-size ledger key/signature decoding uses `Cardano.Binary.FixedSizeCodec.rawDecodeFixedSized`.

The27 captured cases cover actual wallet CBOR decoding, rendering and IDs for Byron through Dijkstra; rejection of indefinite outer arrays, duplicate body keys, trailing and truncated bytes; actual wallet metadata validation and ledger serialization; and actual ledger DSIGN verification. The capture helper uses the wallet fixture generator for the first seven eras. The pinned Dijkstra fixture generator raises a TODO in `Read/Tx/Gen/Dijkstra.hs:121`; with the user's approval, capture uses actual ledger mkBasicTx/mkBasicTxBody/mkBasicTxOut constructors for that era, then executes the unchanged wallet decoder/renderer/hash path. All26 earlier operation inputs and expected results remain identical. These transactions do not establish ledger validity or owned UTxOs. Historical seven-era evidence and executable pins remain preserved in their original reports/commits.

Rust independently hashes the exact encoded body, encodes metadata CBOR, checks symmetric ±(2^64−1) integer limits and UTF-8 byte limits, and verifies signatures strictly. Metadata covers labels0/u64max,64/65-byte blobs,64/66-byte Unicode strings, nested validation errors, empty maps and last-value behavior for duplicate labels. The ledger rejects noncanonical S and small-order R/public keys. Preserve that behavior separately from the legacy extended-wallet verifier.

```sh
nix --quiet develop --command cargo run -- capture-ledger-profiles \
  --oracle "$REFERENCE_BUILD/wallet-ledger-reference" --output new-ledger-profiles.json
nix --quiet develop --command cargo run -- vectors \
  --adapter "$REFERENCE_BUILD/wallet-ledger-reference" \
  --target haskell-source-reference --environment source-2fc5c383-ledger \
  --corpus fixtures/vectors/ledger-profiles.json --report ledger-reference-report.json
```

The complete643-obligation gate still requires the remaining fee, min-UTxO, witness, funded/API and state-transition evidence under a final common fingerprint.
