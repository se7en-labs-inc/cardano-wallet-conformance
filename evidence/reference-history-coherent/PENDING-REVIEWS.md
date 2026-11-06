# Pending decisions at the582/643 checkpoint

These nine proposals remain unapplied, awaiting replies to the existing review questions. pending-review-sha256.txt binds their exact contents. Your AGENTS.md requires review before changing approach after a failed test; none of these decisions is inferred from an automatic goal continuation.

| Proposal in artifacts/ | Requested correction |
| --- | --- |
| byron-funding-correction.proposed.json | Use an independently confirmed Shelley bridge to fund Byron addresses that the faucet cannot accept directly. |
| concurrency-spent-input-correction.proposed.json | Assert the actual all-inputs-spent node guard and prove the spent funding through the node. |
| metadata-order-profiles.proposed.json | Preserve distinct successful and failing Haskell metadata-order profiles. |
| shared-decryption-catalogue-correction.proposed.json | Replace the unreachable documented shared-decryption403 obligation with the exact observed TODO500 while keeping643 obligations. |
| precedence-history-depth-correction.proposed.json | Validate changing history depth against observed heights while retaining exact stable fields. |
| validity-mempool-slot-correction.proposed.json | Bracket validity rejection using the actual node mempool admission slot. |
| voting-certificate-correction.proposed.json | Add the actual owned cast_vote certificate branch to the guarded schema overlay. |
| input-set-parser-correction.proposed.json | Accept canonical definite/terminated-indefinite spending-input sets while preserving all structural/signature checks. |
| restart-wallet-identity-correction.proposed.json | Preserve mnemonic-wallet root identity and account key separately; keep the valid watch-only account-key identity formula. |

Original failing reports and original OpenAPI remain preserved. This index does not authorize any correction.
