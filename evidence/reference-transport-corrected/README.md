# Exact-message correction replay

All1726 checks pass under one fingerprint after the user-approved exact malformed JSON message correction:486HTTP,1059internal,181live; independent node integration1PASS. All80offline tests and Clippy/fmt/treefmt/isolated Nix checks passed. The strict gate correctly remains572/643,71missing,zero failures.

This checkpoint exposed a harness binding defect: the six transport records use prefixed case names and semantic case IDs as requirement IDs. They therefore cannot satisfy the exact api.transport-errors/api.error-precedence required-case pairs. Historical reports remain unchanged. The next implementation fixes only those evidence labels and adds a coverage regression; all response assertions remain unchanged and evidence must be executed anew under its fingerprint.

Supplementary read-only audits under observations/ capture path/body, unknown-wallet/passphrase, cross-network address decoding and empty-wallet/output precedence. These are exploratory responses, not registered conformance evidence. The owned audit wallet was created201 and deleted204, and its mnemonic/request material is excluded. Empty-wallet output1 and valid2m requests both return403 no_utxos_available; a funded control remains necessary before claiming output-validation precedence.

All eight HTTP suites ran before funding in fresh /tmp/wc-tfix-xOoYpL. Independent node integration ran last. All owned wallets were cleaned up and runtime shutdown is audited separately. The generated artifacts/behavioral-specification.transport-corrected.draft.json is incomplete and non-authoritative. Previous failure preserved at reference-transport-coherent.
