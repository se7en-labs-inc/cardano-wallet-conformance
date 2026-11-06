# Pinned lifecycle source audit

Source revision2fc5c383c94bb907deaa0cd27b1b407f86224b6c, read from the unchanged Haskell checkout. source-sha256.txt binds the two full files; the three excerpt files preserve exact relevant source spans.

Api.Http.Shelley.Server.newApiLayer5838–5872 creates a worker registry and starts workers for every database returned by listDatabases. Wallet.submitTx3534–3578 posts the sealed transaction to the network before updating persistent submissions. submitExternalTx explicitly excludes external proxy submissions from the local retry pool. Wallet.hs3701–3769 schedules locally pending retries every10expected blocks, with1second minimum sampling interval, and resubmits only due pending transactions as the node tip advances.

These facts guide lifecycle tests. They are not runtime evidence and close no mandatory cases. A process restart alone does not prove pending durability or retry: live tests must establish node admission, pending status across the transition, original body/witness identity and eventual ledger effects. Expiry, disconnection and rollback need independently controlled runtime transitions. The owned-process harness currently proves only its own process/filesystem ownership behavior.
