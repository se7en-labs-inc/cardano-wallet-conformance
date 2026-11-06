# Pinned confirmed-submission deletion source

Source2fc5c383c94bb907deaa0cd27b1b407f86224b6c. Exact excerpts/full-file digests are retained. deleteTransaction invokes W.forgetTx, which updates local submission state. removePendingOrExpiredTx returns404 for Unknown,403 for InLedger and a Forget delta for other statuses. Error mapping supplies exact transaction_already_in_ledger code, full message and transaction_id info; ApiError JSON uses tagged code/info plus message.

Use a fresh locally submitted/confirmed transaction before finality pruning. An incoming faucet transaction was never locally submitted and cannot establish this branch. This source audit supplies no runtime coverage by itself.
