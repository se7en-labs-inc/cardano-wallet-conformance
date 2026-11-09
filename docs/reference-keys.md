# Pinned-source key reference

`reference/KeyAdapter.hs` calls the actual Shelley, Shared, Icarus and Byron wallet root generators from wallet revision `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. Path derivation, extended-key decoding/serialization and signing call the wallet's declared `Cardano.Address.Derivation` API. The adapter never reads fixture expected values or invokes the executable that originally produced the goldens.

Use the pinned compiler environment from [credential reference setup](reference-credentials.md), then compile in a scratch directory:

```sh
CONFORMANCE_DIR=/absolute/path/to/cardano-wallet-conformance/master
REFERENCE_BUILD=/tmp/wallet-key-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -package aeson -package memory -package cardano-addresses -package cardano-crypto \
  -package address-derivation-discovery -package cardano-wallet-primitive \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-key-reference" \
  "$CONFORMANCE_DIR/reference/KeyAdapter.hs"
```

The measured adapter source SHA-256 is `5ebf8ed97a16cf3a15757e70e919d2d56ce8b9a43ddb34823fca716c4340d09c`. Historical evidence used executable SHA-256 `9326e291df8ccb064cd77740a3a7063cf84cc382d5dc4481be28a47680d44114`; a rebuild was reported as `337e2b28428a1a241ff6d27bae025069c619fb5a5836c55d25b4ae4ed2122993`. Executable bytes may vary with build details, so capture and rollback do not require a hardcoded executable digest. They record the actual digest and require it to stay unchanged during adapter calls. Historical vector provenance remains unchanged. For `conform`, set the configuration's `trusted_sha256["key-oracle"]` and any reference-adapter pin to the actual helper digest; these run-specific identity checks still apply.

`capture-key-boundaries` replays each request, verifies signatures independently in Rust and compares their public keys with the pinned metadata-signature golden. The encrypted Byron root must match `ByronSpec.hs`'s pre-existing `generateTest2` golden exactly. Capture refuses to overwrite a corpus. Build from the pinned source and run the frozen vectors below to qualify a rebuilt helper; a recorded digest alone does not establish its provenance or behavior.

The legacy wallet root serialization is 128 bytes: encrypted secret, cached public key and chain code. The cardano-address test representation is 96 bytes: extended secret and chain code. The adapter converts an unencrypted wallet root to the latter by retaining the first64 and final32 bytes, then calls the actual decoder. The separate `byron.generate-root` operation preserves the full128-byte wallet representation, including nonempty encryption-password behavior.

Run the existing independent key goldens, the wallet Byron unit golden, and the new boundaries:

```sh
cargo run -- vectors --adapter /absolute/path/to/wallet-key-reference \
  --target haskell-source-reference --environment source-2fc5c383-key-derivation \
  --corpus fixtures/vectors/haskell-keys.json \
  --corpus fixtures/vectors/cardano-wallet.json \
  --corpus fixtures/vectors/key-boundaries.json \
  --operation keys.derive --operation keys.derive-public \
  --operation keys.sign-extended --operation byron.generate-root \
  --report key-reference-report.json
```

This executes 133 cases:116 existing root/child/signing goldens, one existing wallet Byron root golden, and16 new boundaries. Tests also check all54 public/private child pairs, chain-code agreement and signature/message mutation rejection. Exact expected results remain mandatory alongside independent checks.

The existing goldens use an empty generation second factor. Nonempty factors return `unsupported_profile` from this reference adapter and remain required, unexecuted semantic cases. Hardware roots, extended address encodings and the rest of the derivation/input domain remain separate obligations. Path validation is the test adapter's explicitly bounded wallet profile; rejection does not imply that a low-level scalar-derivation function rejects that index sequence. These reports are current-fingerprint internal evidence; older live reports cannot be combined with them without rerunning the live corpus.
