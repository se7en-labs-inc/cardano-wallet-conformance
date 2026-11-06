# Pinned history selector source audit

Source2fc5c383c94bb907deaa0cd27b1b407f86224b6c. Exact excerpts and full-file SHA256s are retained. API.ListTransactions656–667 exposes minWithdrawal, inclusive start/end, order, max_count, address and metadata rendering. The HTTP handler defaults to descending. Wallet.listTransactions3789–3838 converts inclusive UTC bounds to slots and queries with status=None. No public status selector is exposed.

DB.hs380–414 selects in-ledger history and submissions, applies address/minimum-withdrawal filters, slot order and a final count limit. Confirmed history also receives an SQL-level range/limit/order before the merge. DB.hs512–550 describes ordering and address checks including collateral; this profile tests three distinct confirmed slots and ordinary inputs/outputs. It does not establish same-slot ties, collateral-address selection or pending/expired ordering. ApiLimit uses Natural; max_count0 is accepted by Haskell despite the original OpenAPI request minimum1. The original OpenAPI remains unchanged; the new runtime test records the actual observed result.

These source observations guide tests and do not independently close conformance cases.
