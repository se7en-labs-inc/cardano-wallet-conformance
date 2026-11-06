# Wallet collateral and extra-value selection

This profile executes actual `Cardano.Balance.Tx.Balance.CoinSelection.performSelection` from pinned cardano-balance-tx8975773 and its actual `asCollateral` filtering. The earlier balance-only selection adapter remains separately pinned. Build with the compiler from [credential setup](reference-credentials.md):

```sh
REFERENCE_BUILD=/tmp/wallet-selection-reference-build
mkdir -p "$REFERENCE_BUILD"
"$REFERENCE_GHC/bin/ghc" -O1 -Wall -Werror \
  -package aeson -package cardano-balance-tx -package cardano-coin-selection \
  -package MonadRandom -package random -package transformers \
  -outputdir "$REFERENCE_BUILD" -o "$REFERENCE_BUILD/wallet-selection-reference" \
  /absolute/path/to/cardano-wallet-conformance/master/reference/SelectionAdapter.hs
```

Source SHA-256 `fa0816590c3cafd7d35788d9d77e1542b1f76e3afc813aa82d0354a5796df9ea`; executable SHA-256 `08406fef161c9722fe5407774133e10708cfdea5273ba4fe32b96475b406871e`. The34 profiles pin/replay seeded minimal/optimal selection, collateral caps0/1/2, exact/rounded percentages, ADA-only versus native-asset collateral eligibility, external availability, ordinary/collateral overlap and mint/burn extra-value conservation at quantity boundaries. All fixture addresses/policies/keys are public test data. Supplied u32 IDs become output indices under an all-zero public transaction hash.

The minimum-fee and minimum-change callbacks are explicitly constant component constraints. The size assessor accepts this fixed single-asset profile; this does not establish ledger-dependent fees, serialized transaction-size admission, general token-bundle limits or collateral-return support. The largest available collateral combination and minimum amount come from actual typed errors. Rust independently checks integer conservation, availability, asset purity, count caps, percentage ceiling, minimum change and fee-shortfall proofs. Ordinary and collateral inputs may overlap because the ledger and wallet permit it.

The initial capture stopped before writing on two incorrect fixture assumptions. Empty ordinary UTxO with a payment returns balance_insufficient; no payment/zero fee returns empty_utxo. When ADA covers outputs exactly but cannot pay the fee, the wallet returns unable_to_construct_change. The final corpus tests each condition with its own strict error golden and independent shortage proof; the actual wallet/callback implementation was unchanged.

```sh
nix --quiet develop --command cargo run -- capture-wallet-selections \
  --oracle "$REFERENCE_BUILD/wallet-selection-reference" --output new-wallet-selections.json
nix --quiet develop --command cargo run -- vectors \
  --adapter "$REFERENCE_BUILD/wallet-selection-reference" \
  --target haskell-source-reference --environment source-2fc5c383-wallet-selection \
  --corpus fixtures/vectors/wallet-selection.json --report wallet-selection-report.json
```

These component cases do not establish real mint/burn ledger submission or a complete643-obligation gate.
