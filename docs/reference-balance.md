# Fee and minimum-ADA reference

Build `reference/BalanceAdapter.hs` with the pinned compiler environment from [credential setup](reference-credentials.md):

```sh
REFERENCE_BUILD=/tmp/wallet-balance-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -package aeson -package memory -package lens -package cardano-balance-tx \
  -package cardano-ledger-api -package cardano-ledger-conway \
  -package cardano-ledger-core -package cardano-ledger-binary \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-balance-reference" \
  /absolute/path/to/cardano-wallet-conformance/master/reference/BalanceAdapter.hs
```

The measured source SHA-256 is `ebc8379b022ebf681c00cfde8f7442656e1069765e1b44c483904874a3786216`; executable SHA-256 is `e93a25718344e23de66cad102e3b65409c9e47282039e1935a3272a66e640cd2`. The wallet's pinned `cardano-balance-tx` source is cardano-balance-transaction8975773, resolved through its Nix package source attribute. No wallet or backend source is modified.

The32 profiles execute actual `feeOfBytes`, `sizeOf_VKeyWitnesses`, `sizeOf_BootstrapWitnesses`, `maxScriptExecutionCost`, ledger output decoding and `getMinCoinTxOut`, and wallet `computeMinimumCoinForTxOut`/`isBelowMinimumCoinForTxOut`. Fee cases cover coefficient boundaries, witness counts0/1/23/24/many, mixed bootstrap/vkey estimates, execution-unit prices, combined rational rounding, maximum estimated size and adjacent witness-inclusive limits. The witness estimate intentionally uses the actual conservative array overhead; it is not the exact serialized size of a specific signed transaction. Reference-script tier fees and real transaction admission remain separate.

Minimum-ADA cases cover ADA/native assets, inline datum, native reference script, combined fields, zero/change protocol cost, actual coin encoding boundaries and exact minimum/one-below thresholds. Rust independently encodes the public output inputs, checks the160-byte ledger overhead and serialized length, and replaces only the coin with45,000,000,000,000,000 for the conservative wallet estimate. The actual minimum and conservative wallet minimum must remain distinct.

```sh
nix --quiet develop --command cargo run -- capture-balance-profiles \
  --oracle "$REFERENCE_BUILD/wallet-balance-reference" --output new-balance-profiles.json
nix --quiet develop --command cargo run -- vectors \
  --adapter "$REFERENCE_BUILD/wallet-balance-reference" \
  --target haskell-source-reference --environment source-2fc5c383-balance \
  --corpus fixtures/vectors/balance-profiles.json --report balance-reference-report.json
```

Capture pins the executable hash, replays every request and checks independent laws before saving. This component subset does not establish the complete643-obligation gate.
