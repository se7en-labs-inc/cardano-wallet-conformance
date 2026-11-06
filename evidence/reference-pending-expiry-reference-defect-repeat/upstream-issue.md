## Description

Submitting an already signed transaction through the wallet's submission API stores a new default expiry in the local submission pool instead of the transaction's signed upper validity bound. If the transaction is accepted into the node mempool but expires before inclusion, the wallet continues reporting it as pending, reserving its inputs and retrying submission beyond the signed expiry.

Reproduced twice with fresh, owned local clusters. An isolated change to use the decoded signed upper bound passes the same strict live scenario (47 checks), with no assertion or timeout relaxation.

## Version and environment

- cardano-wallet 2026.9.16, source revision `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`, built through Nix.
- cardano-node 11.1.3; cardano-cli 11.2.3.0; Linux 6.18.60.
- Owned local Conway cluster, 0.2-second slots, network magic 42. No production network or real funds involved.
- This report describes the tested pinned source, rather than claiming a reproduction on the latest release. The same default-TTL code is also present in upstream master when checked on 2026-11-04.

## Steps to reproduce

1. Restore and fund a normal Shelley wallet with one confirmed 100,000,000-lovelace output; wait until it is ready and independently confirm that output at the node.
2. Construct and sign a payment with an explicit short upper validity bound. Keep the bound safely inside the node's forecast horizon. In the second reproduction, the upper bound was slot 350; the independent stable tip was 312 and the current slot was 315.
3. Pause only the owned cluster's block-producing processes, leaving its relay and wallet queryable. Submit the signed transaction through `POST /v2/wallets/{walletId}/transactions-submit`. Independently verify node mempool admission, wallet pending state and the transaction's signature/encoded upper bound.
4. Keep production paused until the signed upper bound has elapsed, then resume the producers. Wait for both the native node tip and ready wallet tip to advance beyond that bound.
5. Query transaction history, wallet balances, native UTxOs and native mempool. Observe local resubmission past the signed bound. Selected read-only submission metadata can also establish the mismatched stored deadline.

### Expected behavior

The local submission expires according to the signed upper validity bound. The wallet reports the transaction as expired, releases reserved funds and stops resubmitting it. The original input remains unspent and the transaction creates no ledger outputs.

### Actual behavior

In the second independent reproduction, transaction `39fbfe4c63cd7b618775ed77b24bea9b8c7fca85345952fd64d81d66fad67a9a` had:

| Observation | Value |
| --- | --- |
| Signed and API-rendered upper validity slot | 350 |
| Stored submission expiration | 36316 |
| Stored resubmitted slot | 505 |
| Submission-store tip / finality | 521 / 461 |
| Native tip at the unchanged 180-second polling deadline | 1255 |
| Independent mempool query at slot 1256 | Transaction absent |
| Original funding input | Still unspent |
| Wallet history status | Pending |
| Wallet available / projected total | 0 / 97,870,500 lovelace |

The node rejects subsequent attempts with `OutsideValidityIntervalUTxO`. The first reproduction independently showed the same pending/locked-funds outcome well past signed expiry. No database edits or fake node acknowledgements were used.

## Source diagnosis and validated correction

The normal [submitTransaction handler](https://github.com/cardano-foundation/cardano-wallet/blob/2fc5c383c94bb907deaa0cd27b1b407f86224b6c/lib/api/src/Cardano/Wallet/Api/Http/Shelley/Server.hs#L4098) computes `W.transactionExpirySlot ti Nothing` and uses it for `txValidityInterval` when constructing local transaction metadata. Its existing ADP-1193 TODO specifically calls out using the decoded transaction instead. The fallback is a two-hour default. API rendering still displays the signed expiry, obscuring the submission-store discrepancy.

The shared-wallet submission handler has the same source pattern; this report's live reproduction covers normal wallets only.

The isolated correction moves expiry selection after decoding in both handlers:

```haskell
ttl <- case apiDecoded ^. #validityInterval of
    Just (ApiValidityIntervalExplicit interval) ->
        pure $ SlotNo $ getQuantity $ interval ^. #invalidHereafter
    Nothing -> liftIO $ W.transactionExpirySlot ti Nothing
```

Against that correction, the unchanged signed-upper-350 scenario expires after native slot 353, restores all 100,000,000 lovelace and passes the independent unspent-input/no-output/mempool checks, expired-transaction deletion and final real-node integration check. Nix build, Fourmolu/HLint and targeted API/submission tests pass. Dedicated live shared-wallet expiry validation and the full Haskell unit suite have not been run.

The original pinned wallet and both failing reports remain preserved in our conformance work. This defect is recorded as a known failing reference case, without waiving the strict expiry requirement.
