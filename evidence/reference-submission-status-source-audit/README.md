# Submission status reachability audit

Pinned Haskell source: `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. The three uncovered HTTP425 obligations are `postTransaction`, `postByronTransaction` and `postExternalTransaction`. They inherit the original OpenAPI's mempool-full response. The original OpenAPI is unchanged.

Both deprecated wallet transaction routes call `postTransactionOld`, which calls `buildSignSubmitTransaction`. Its V1 and V2 paths call the network layer's `postSealedTx`, wrapping network errors in `ErrSubmitTxNetwork`. External submission calls `submitExternalTx`, which reaches the same network layer. `postSealedTx` delegates to `postTxToQueue`: unsupported eras return `ErrPostTxEraUnsupported`, successful submissions return success, and every `SubmitFail` becomes `ErrPostTxValidationError`. The submission queue is an unbounded `TQueue`.

Searching every Haskell file in the pinned repository's `lib` found only three references to `ErrPostTxMempoolFull`: its declaration, its text renderer, and its HTTP error mapping. No production code constructs it. The network validation error maps to HTTP500 `created_invalid_transaction`, while the unreachable constructor maps to425 `mempool_is_full`.

Consequently, neither queue saturation nor a real node mempool rejection can exercise the documented425 through this pinned implementation. A direct unit invocation of the dead mapping would not establish live HTTP reachability. No conformance credit or catalogue change follows from this audit.

The coherent asset profile already observes HTTP500 for a transaction with an invalid witness through the wallet's `submitTransaction` route, verifies the ledger rejection cause and preserves funding before submitting the valid transaction through the external proxy. That supplemental rejection is not an observation of `postExternalTransaction`500. No live500 observation is claimed here for any of the three proposed replacement operations. All three need separate real-node rejection controls before credit under any approved catalogue correction. An earlier version of this audit misattributed the existing rejection to the proxy; this record corrects that provenance error without changing the source reachability finding.

The proposed, unapplied correction is preserved in `submission-status-correction.proposed.json`. It requires approval and new tests; this source audit alone does not close any obligation.
