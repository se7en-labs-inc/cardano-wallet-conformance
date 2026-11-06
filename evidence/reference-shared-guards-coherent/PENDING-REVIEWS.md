# Pending decisions at the 585/643 checkpoint

Nine proposals still await replies to the existing review questions. The exact proposal contents are preserved below and their original artifact hashes are recorded in pending-review-sha256.txt. Your AGENTS.md working agreement requires review before changing approach after a failed test. These copies make the decisions reviewable; none has been applied or authorized by a goal continuation.

| Proposal | Requested correction |
| --- | --- |
| [Byron funding](review-proposals/byron-funding-correction.proposed.json) | Use an independently confirmed Shelley bridge for Byron addresses the faucet cannot fund directly. |
| [Concurrent-spend rejection](review-proposals/concurrency-spent-input-correction.proposed.json) | Check the actual all-inputs-spent node guard and independently prove the funding is spent. |
| [Metadata ordering](review-proposals/metadata-order-profiles.proposed.json) | Keep distinct successful and failing Haskell ordered-map decryption profiles. |
| [Shared decryption](review-proposals/shared-decryption-catalogue-correction.proposed.json) | Replace the unreachable documented decryption403 with the exact observed TODO500 while keeping643 obligations. |
| [History depth](review-proposals/precedence-history-depth-correction.proposed.json) | Validate advancing depth against observed heights and retain exact stable fields. |
| [Validity admission slot](review-proposals/validity-mempool-slot-correction.proposed.json) | Bracket rejection with the actual node mempool admission slot. |
| [Voting certificate](review-proposals/voting-certificate-correction.proposed.json) | Add the actual owned cast_vote certificate branch to the guarded overlay. |
| [Input-set parser](review-proposals/input-set-parser-correction.proposed.json) | Accept canonical terminated indefinite spending-input sets while preserving structural and signature checks. |
| [Restart identity](review-proposals/restart-wallet-identity-correction.proposed.json) | Preserve mnemonic-wallet root identity and account key separately; retain the watch-only formula. |

Original failed reports and the original OpenAPI remain preserved. The new independent403 checks do not implement these corrections.
