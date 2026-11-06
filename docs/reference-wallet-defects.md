# Reference implementation defects

## Submitted signed expiry is replaced by a two-hour local deadline

Known upstream issue: [cardano-wallet #5479](https://github.com/cardano-foundation/cardano-wallet/issues/5479). The user authorized filing this issue and continuing the full644-obligation work while recording problems for later review.

Pinned Haskell2fc5c383c94bb907deaa0cd27b1b407f86224b6c fails the strict real pending-expiry test twice: a transaction expires at the ledger while the ready wallet continues reporting it pending, reserves its funding and retries rejected submissions. The short producer pause stays inside the native forecast horizon; both node and wallet advance beyond signed expiry.

[The first execution](../evidence/reference-pending-expiry-reference-defect-first/README.md) preserves public API/native state, ledger expiry errors and pinned source excerpts. [The second fresh execution](../evidence/reference-pending-expiry-reference-defect-repeat/README.md) adds full public phase proofs and read-only selected submission metadata: signed/API upper350, stored expiration36316, resubmitted505, store tip521/finality461. At the strict deadline native tip1255 and absent mempool coexist with pending wallet history and locked funds.

The submission handler's ADP-1193 TODO computes a new default7200-second deadline for local metadata instead of using the decoded signed upper bound. The submission store consumes that metadata, while API rendering displays signed expiry. Upstream master retained the same code when checked during issue filing. The shared handler has the same source pattern; live reproduction covers normal wallets only.

The user approved isolated correction validation. Worktree70008-submitted-expiry starts at the original pin; specificationc1b9999814 precedes fix30f84bcf3d. Nix build, Fourmolu/HLint and targeted tests pass: API19 examples/0 failures/1 pre-existing pending, plus two submission properties with100 generated tests each. The full Haskell unit suite and dedicated live shared expiry remain unexecuted.

[The corrected-reference execution](../evidence/corrected-reference-submitted-expiry/README.md) passes all47 unchanged live expiry checks with the same harness fingerprint as the second original-reference failure. Signed upper350 produces expired history after native slot353, restores100000000 lovelace, preserves unspent funding/absent outputs/mempool and passes expired deletion, independent final node integration and owned-process cleanup.

The strict original-reference failure remains mandatory evidence. Known-issue status adds no waiver, skip, passing obligation or source-pin promotion. Component results from the corrected runtime cannot be merged into an original-reference passing gate. Continue independent missing scenarios while retaining this distinction.

## Confirmed and pending rows for the same transaction after reapplication

A new original-reference live response contains the same transaction ID twice, once `in_ledger` and once `pending`, after genuine rollback and automatic reapplication. The strict history uniqueness assertion fails. [Public raw responses and the local issue draft](../evidence/reference-duplicate-history-first/upstream-issue.draft.md) retain exact signed bytes, insertion/pending points and native tips. No additional upstream issue has been sent.

An [actual Haskell diagnostic](reference-submission-race.md) independently proves that delayed `resubmitTx` bookkeeping can reset an already confirmed entry to pending. The worker reads pending entries before submitting to the node, then updates bookkeeping afterward; the update does not require the current entry to remain pending. The history reader concatenates ledger and submission records without ID deduplication. This is a source-supported mechanism; the exact live worker interleaving remains unproven. Quiescent follow-up has not triggered on later passing runs. No duplicate response is accepted by the harness and no reference revision is promoted.

The [proposed guard](../evidence/reference-duplicate-history-first/confirmed-resubmission-guard.proposed.patch) passes isolated actual-function validation with the same signed input: confirmation is preserved and the ordinary pending control still works. Subsequent full-wallet validation is recorded below; this proposal does not change the authoritative reference runtime.

The isolated full wallet build8fcb6fb0ee combining the callback guard with the signed-expiry correction now passes47/47 strict expiry and224/224 strict rollback checks, final native integration and cleanup. Six submission unit examples and targeted API server tests pass, with one pre-existing API pending test and no full-unit-suite claim. [The corrected-runtime evidence](../evidence/corrected-reference-submission-guard/README.md) remains distinct from original2fc. A later original rerun also passed224/224, reinforcing that the observed duplicate is intermittent; passing reruns do not erase its raw response or prove its resolution.
