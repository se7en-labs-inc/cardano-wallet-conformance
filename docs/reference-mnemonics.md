# Mnemonic and hardware reference profiles

Build `reference/MnemonicAdapter.hs` using the immutable wallet compiler environment from [credential setup](reference-credentials.md):

```sh
REFERENCE_BUILD=/tmp/wallet-mnemonic-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -package aeson -package memory -package cardano-addresses -package cardano-crypto \
  -package address-derivation-discovery -package cardano-wallet-primitive \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-mnemonic-reference" \
  /absolute/path/to/cardano-wallet-conformance/master/reference/MnemonicAdapter.hs
```

The source digest is `eeafb1df2ef384d5a88294c6a4af4228b20ee2678c684e6abd27333a4cd37624`; measured executable digest is `2b9c4740fde182225f7ccd47257b1a6681b50dc3da31ebc81cb03016bd2a86a1`. `capture-mnemonic-profiles` pins this executable, replays requests, verifies child signatures independently and checks cross-profile/public/private relations before freezing13 new profiles.

The adapter calls actual Cardano.Mnemonic entropy/checksum functions, Crypto.Encoding.BIP39 seed generation, Shelley/shared wallet generation-factor functions, wallet Ledger/Icarus generators and the declared cardano-address Icarus factor helper. Trezor HTTP restoration calls the same wallet generator as Icarus; this observed equivalence is checked against previously frozen independent Icarus keys. Icarus/Trezor nonempty factor cases name the low-level component profile; they do not imply an HTTP restore feature. Ledger Unicode passwords affect its128-byte encrypted legacy representation while preserving the decrypted96-byte root and public identity.

The pinned seed helper takes raw UTF-8 without NFKD normalization. This behavior has its own `bip39.wallet-seed` profile; composed and decomposed passwords produce different seeds. The Rust `haskell-mnemonic-reference` transport wrapper applies pinned-library NFKD only for standard `bip39.to-seed`, then delegates cryptography to the Haskell helper. It leaves raw seed and wallet encryption inputs unchanged. All existing independent published/OpenSSL standard Unicode vectors stay unchanged.

```sh
nix --quiet develop --command cargo build --bins
nix --quiet develop --command cargo run -- vectors \
  --adapter target/debug/haskell-mnemonic-reference \
  --adapter-arg /absolute/path/to/wallet-mnemonic-reference \
  --target haskell-source-reference --environment source-2fc5c383-mnemonic \
  --corpus fixtures/vectors/primitives.json \
  --corpus fixtures/vectors/bip39-reference.json \
  --corpus fixtures/vectors/primitive-boundaries.json \
  --corpus fixtures/vectors/haskell-keys.json \
  --corpus fixtures/vectors/mnemonic-profiles.json \
  --operation bip39.entropy-to-mnemonic --operation bip39.to-seed \
  --operation bip39.wallet-seed --operation address.enterprise \
  --operation keys.generate-root-profile --report mnemonic-reference-report.json
```

This executes73 cases:54 pre-existing BIP39 cases, six enterprise addresses and13 new hardware/factor/raw-seed cases. Mnemonic entropy round trips, exact seeds, address credential hashes/network/Bech32 bytes, encrypted-root layout, signatures and cross-profile identities receive independent Rust checks. The complete catalogue still requires the remaining address/script, transaction and live-state domains. A full aggregate report requires fresh evidence under the final shared fingerprint; historical reports are retained unchanged.
