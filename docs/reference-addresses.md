# Address, script and codec reference

Build `reference/AddressAdapter.hs` with the pinned compiler environment from [credential setup](reference-credentials.md):

```sh
REFERENCE_BUILD=/tmp/wallet-address-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror -Wno-deprecations \
  -package aeson -package memory -package cardano-addresses \
  -package cardano-wallet-primitive -package cardano-ledger-allegra \
  -package cardano-ledger-core -package cardano-strict-containers \
  -package-id cardano-crypto-class-2.5.1.0-81NNjvXXDS2Hp0xj39fht9 \
  -package cardano-slotting -package bech32 -package base58-bytestring \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-address-reference" \
  /absolute/path/to/cardano-wallet-conformance/master/reference/AddressAdapter.hs
```

The explicit deprecation exception retains the actual random-Byron helpers required for legacy compatibility. The measured source SHA-256 is `23074c3ba5720a53f1e273ecd75016a74af123da13242aee6607da546cbb720d`, executable SHA-256 `f751ef54b76bf04781eed6ca96c7fb59b03f1e9ed8770fc9320776005ccc6147`. `capture-address-profiles` pins this executable and replays all requests before writing a new corpus; it refuses overwrites.

The56 cases cover key/script base addresses, reward-script and pointer encoding (including u64 maxima), four shared-script forms, random/Icarus Byron mainnet/preprod network attributes and CRC rejection, authenticated derivation-path CBOR, raw base58 leading zeros/malformed inputs, Bech32 checksum/case/padding, CIP-129 key/script/committee identifiers and bad headers, credential hashing and wallet asset fingerprints. Native scripts use the actual ledger `evalTimelock` with supplied witness hashes and validity bounds; serialization and required structural validation use Cardano.Address.Script. Empty/all/any/zero/impossible thresholds, unbounded timelocks and exact boundary crossings are explicit cases.

Rust independently checks script domain-prefixed canonical CBOR, hashes and truth conditions, address headers/credentials/pointer varints, Bech32/base58 bytes, Byron CRC/protocol attributes and governance headers. Generic `Cardano.Address.bech32` does not choose the reward HRP: the adapter uses the Haskell Bech32 codec with `stake`/`stake_test` for reward bytes. Generic `Cardano.Address.fromBase58` is an address parser and rejects raw non-address data; the raw codec operation calls base58-bytestring directly. Regression tests preserve both distinctions. Native script serialization includes its leading00 domain byte before the script CBOR, and the script hash includes that byte.

```sh
nix --quiet develop --command cargo run -- vectors \
  --adapter /absolute/path/to/wallet-address-reference \
  --target haskell-source-reference --environment source-2fc5c383-address-script \
  --corpus fixtures/vectors/address-profiles.json \
  --report address-reference-report.json
```

These component cases leave the separately required cross-network HTTP rejection, ledger transactions, wallet durability and full API matrix mandatory. A full gate needs all reports rerun under the final shared fingerprint; partial component execution cannot certify643 obligations.
