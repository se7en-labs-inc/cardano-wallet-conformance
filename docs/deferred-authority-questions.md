# Deferred authority decisions

These notes preserve source evidence and authority questions. On2026-11-06 the user explicitly approved the documented-status reconciliation: complete646 inventory minus only three source-stale responses gives643 active obligations. See [the approved registry](../fixtures/api/retired-responses.json). The historical644 gates remain unchanged. This decision does not promote the corrected runtime or generated specification as authority; other questions below remain open unless explicitly marked resolved.

## Original submitted-expiry defect

The pinned original wallet replaces the signed upper validity limit with its default local-submission expiry. Fresh strict runs reproduce pending history/reserved funds after signed expiry; [upstream5479](https://github.com/cardano-foundation/cardano-wallet/issues/5479) is filed. The separately authorized isolated Haskell correction passed the unchanged47-check expiry profile, but its runtime has not replaced the original authority. Pending-expiry and expired-history cases remain strict. A future decision must explicitly distinguish a reviewed corrected-reference profile from original behavior; historical failures stay retained.

## Resolved2026-11-06: shared-wallet creation500

Original OpenAPI declares `postSharedWallet:500` with `missing_reward_account`; this obligation was explicitly included in the644 inventory. Current pinned source revision remains `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`.

A focused search of `lib` finds `ErrFetchRewardsMissingRewardAccount` only at its type declaration (`lib/wallet/src/Cardano/Wallet.hs:5031`) and HTTP mapping (`lib/api/src/Cardano/Wallet/Api/Http/Server/Error.hs:1012`). No constructor expression/call site was found. Current reward handling at Wallet.hs1840 accepts `Either ErrFetchRewards Coin`, logs an error value if supplied and continues; the nearby active caller passes `Right query`. Cached `fetchRewardBalance` is now a plain database read returning `IO Coin` (Wallet.hs1623). Both shared-wallet creation variants select `idleWorker` when there is no delegation template and a reward manager when one exists (Shelley/Server.hs1320–1460). The historical error mapping remains present, but that alone does not exercise this HTTP response.

This is strong source evidence of a stale documented named-error path, not a formal proof about every possible runtime exception. Deliberate generic database failure, a proxy500, direct serializer invocation or modifying the reference wallet to manufacture the constructor would not prove the original registered HTTP route/schema. No live missing_reward_account500 was observed or credited. The user explicitly approved retiring this response from the effective contract on2026-11-06. No replacement obligation is invented to retain a convenient total.

Exact source SHA-256 values read for this audit:

- `lib/wallet/src/Cardano/Wallet.hs`: `ed5f54d2be47ad7bff1e8e88a2d09e4c5e1009df76eaf1d48ebe6f130eea4b70`.
- `lib/api/src/Cardano/Wallet/Api/Http/Server/Error.hs`: `dd0bd0b1297a700b09009d38baa447532af4ac47dd9481e686a61c3601e8c3c3`.
- `lib/api/src/Cardano/Wallet/Api/Http/Shelley/Server.hs`: `bbce5b298c4131e9c3068d54294ac4cb104afb1ad7ac894ac19fd2c9ff994dcb`.

## Resolved2026-11-06: two omitted documented503 responses

The complete audit found two original statuses outside the former644 requirements: `patchSharedWalletInPayment:503` and `patchSharedWalletInDelegation:503`, both `wallet_metadata_not_found`. The former200–500 bound omitted them. [The retained audit](../evidence/reference-documented-status-audit/README.md) gives exact paths and source findings. Wallet.hs4889 declares the corresponding error and Error.hs1133 maps it; no production construction site was found. The user approved reviewing all646 responses and retiring these two plus shared-creation500. Inventory now covers every200–599 status, with regressions against future501/503/599 omissions. Historical644 results remain unchanged; the new643 active contract requires fresh qualification.
