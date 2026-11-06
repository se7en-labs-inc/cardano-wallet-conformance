# Feature Specification: Wallet implementation conformance

**Feature Branch**: `70007-wallet-conformance`
**Created**: 2026-11-02
**Status**: In implementation
**Input**: Build an open source conformance tool for testing new wallet implementations before they are used in Daedalus or other projects that use cardano-wallet under the hood. Candidates may use any implementation language. Public HTTP API and wallet internals matter; CLI compatibility is outside scope. The harness uses Rust and the user's Rust Nix template.

**Repository**: Migrated to the standalone `cardano-wallet-conformance` repository on `master`. The original feature identifier is retained for specification links and history.

## User Scenarios & Testing

### US1 — Compare external behavior (P1)
Given a pinned Haskell API specification and two isolated wallet services, when the same test scenarios run, then status, media type, JSON structure and deterministic values match. Unexpected failures in both services must fail rather than agree. A new OpenAPI operation must create a coverage gap.

### US2 — Exercise a real chain (P1)
Given a block-producing node, a synced wallet and either a funded mnemonic or local-cluster faucet, when wallets restore, construct, decode, sign and submit payments, then the ledger confirms the transaction and sender/recipient balances conserve value including fees. The same tests run against the Haskell reference and later the candidate. Missing funds or absent nodes are failures, never skips.

### US3 — Validate wallet internals (P1)
Given adapters exposing the same JSON operations, when independent vectors and generated edge cases run, then key derivation, hashes, signatures, address encoding, transaction serialization, fee calculations, coin selection, discovery, synchronization and rollback obey their contracts. Deterministic results compare exactly; randomized results require explicit invariants and replayable seeds.

### US4 — Audit completeness (P1)
Given the required coverage catalogue, when any requirement lacks an executed passing case, then the exhaustive gate fails and names the gap. Reports identify oracle revision, suite version, seed, target, assertions, failures and omissions.

## Requirements

### Approved correction batch (T069)

The user explicitly approved all fifteen corrections indexed by docs/pending-reviews.md after reviewing their scope and the complete remaining-obligation audit. Apply those exact proposals, preserve original failed reports and OpenAPI, and retain643 obligations. Approval permits implementation and fresh verification; it supplies no conformance credit. Keep distinct Haskell metadata ordering profiles, strict operation-scoped observed status/schema corrections, canonical input-set checks, independently grounded dynamic state brackets and owned-process identity/cleanup. Source-only observations and fixture preparation must not close live obligations. Additional failures requiring a different approach remain subject to the working agreement.

- FR-001: HTTP is the only production interface required. Internal JSON adapters are a test interface.
- FR-002: Read the pinned OpenAPI 3 document including YAML merges and all operations.
- FR-003: Validate documented status and response schema; compare typed JSON exactly except narrowly justified volatile fields. Preserve absent versus null, array ordering and integer precision.
- FR-004: Cases must have independently specified expected statuses; matching two server errors is not success.
- FR-005: Real-chain tests must observe advancing block height, restore funded wallets, construct/decode/sign/submit, confirm on both wallets, assert transaction identity, outputs, fee and balance conservation, and clean up only owned wallets.
- FR-006: Support external live services and an existing `local-cluster` faucet without assuming the replacement's CLI.
- FR-007: Define a versioned internal adapter contract with bounded process execution and structured error behavior.
- FR-008: Verify crypto against independent vectors and reject malformed keys, signatures, paths and encodings. A candidate cannot supply its own expected result.
- FR-009: Require every API operation to have positive and negative cases and every internal catalogue requirement to have passing evidence before the exhaustive gate passes.
- FR-010: Separate harness self-tests from genuine wallet conformance evidence; no empty or skipped suite can pass.
- FR-011: Never expose mnemonic, passphrase, root keys or signing request bodies in reports.
- FR-012: Document unresolved coverage and remaining oracle work explicitly.
- FR-013: Treat observed Haskell behavior as the current authority. Apply explicit, versioned schema corrections with provenance. Generate the future authoritative specification from the conformance corpus and evidence, retaining unresolved requirements rather than asserting inferred behavior.

## Edge Cases

T063: Protocol-parameter conformance must compare wallet-visible fields and slotting with the actual node, then enact a real controlled Conway governance update and prove new fee/min-UTxO behavior in wallet-built signed node-confirmed transactions. Changing genesis alone does not prove runtime updates. Committee authorization, proposal/vote signatures, deposits, inputs/outputs and enactment must be independently verified; controlled governance thresholds are fixture policy, not a claim about mainnet policy.

T062: Stake-pool conformance must cover node-backed registration parameters and ranking, stable reward ties within one service, exact stake-percentage/saturation conversion, valid metadata and hash-mismatch rejection, maintenance in direct/none modes, and an actual owned retirement certificate through epoch activation. Pool fixture generation alone earns no conformance credit. Preserve source/epoch provenance and restore wallet settings after failure.

T061: A freshly funded Shelley wallet must keep unused internal addresses hidden during fee/coin-selection previews. Its first confirmed outgoing payment must expose the exact internal index0 change address with the selected public address/path and independently confirmed change value. External addresses remain unchanged; the original funding output is spent. Test exact list ordering and role separation, not only the final wallet balance.

T060: Sequential discovery must respect a non-default gap10, extend the external pool after ledger-confirmed funding at its boundary, preserve previously derived addresses, expose exact used/unused filters and paths, and account for funds/history against the independent node. Exercise consecutive boundaries9 and19, not merely a first-address payment. This closes only the sequential named case; the full discovery requirement still needs internal-change, random and shared semantics.

T059: An explicitly owned cluster supervisor must distinguish block producers from its non-producing relay, pause only owned producers while keeping independent relay queries available, and resume block production on success and failure. Identity checks must prevent signalling unrelated or reused processes. A control audit is infrastructure evidence only; pending, rollback and conformance credit require separate executed wallet workflows.

T058: On a testnet wallet, construction with a mainnet enterprise address must return the exact pinned network-discrimination400. The same payment credential and amount with only the network tag changed to testnet must pass address parsing and reach the empty-wallet403. The wallet's address array, ready state and zero balances must remain unchanged. This independently executable HTTP scenario must not alter the separate funded precedence profile or resolve its pending correction implicitly.

Malformed JSON and content types; unknown IDs; unsigned and corrupted transactions; wrong passphrase; empty and overflowing amounts; multiasset conservation; duplicate UTxOs; unavailable collateral; tiny change; fee boundaries; hardened/soft derivation limits; network/era mismatch; rollback and restoration; concurrent state transitions; failed cleanup; reference and target both broken; stale or missing vectors.

## Key Entities

Operation (method, path, ID, response contract); case (requirement IDs, inputs, expected outcomes); adapter vector (operation, independent provenance, input, expected result); observation (status, schema result, assertions); coverage requirement (stable ID, mandatory evidence); report (provenance and failures).

## Success Criteria

1. A deliberately altered status, deterministic field, signature or selected output is rejected.
2. A real-node payment is accepted by the ledger, visible in both histories and conserves funds.
3. Independent crypto vectors pass against the harness's verification oracle.
4. Every uncovered API polarity and internal requirement is listed; exhaustive success is impossible while any gap remains.
5. Build, formatting, lint and regression tests pass through the pinned Nix environment.

## Assumptions

The candidate does not yet exist. The initial Haskell source is commit `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`, API `v2026-09-16`. Services and real-node binaries are supplied externally. The cluster faucet is the existing Haskell local-cluster HTTP service. Broader era/OS coverage is a matrix of separate runs; it cannot be inferred from one run.

### Approved epoch-boundary sampling (T024)
On 2026-11-02 the user approved read-only epoch alignment after the pinned-source network-information differential test crossed an epoch boundary. Every sampled response must independently satisfy `next_epoch.epoch_number = network_tip.epoch_number + 1`. Compare next-epoch numbers and timestamps strictly once both samples refer to the same network-tip epoch. Preserve the original failed report; never retry malformed responses or mismatches within one epoch.

### Internal key derivation execution (T025)
Execute the existing independent cardano-address root/private/public goldens through a new thin adapter using the pinned wallet's actual root-generation and cryptographic derivation functions. Preserve the distinct 96-byte adapter and 128-byte legacy wallet key encodings. Exercise soft/hardened boundaries, public/private agreement and extended signing, with explicit malformed mnemonic, key, index and role rejections. Test input checks are adapter-domain checks, not claims about a permissive low-level crypto function. Do not claim second-factor, hardware or complete root-family coverage until their named cases execute.

### Remaining mnemonic and root profiles (T026)
Execute entropy/checksum, nonempty generation factors and hardware root/child profiles through actual pinned Haskell functions. Preserve standard BIP39 normalized seed semantics separately from the pinned component's raw UTF-8 seed semantics; do not conflate a primitive profile with wallet HTTP behavior. Capture actual hardware password handling and Trezor/Icarus equivalence where the wallet routes them identically. Execute the six frozen enterprise-address goldens through the declared Haskell address builder. Every new vector remains mandatory, registered and exported; named obligations require their exact case IDs and independent checks.

### Address, codec, native-script and Byron payload execution (T027)
Capture exact base/pointer/reward, script/shared, Byron/Icarus and governance identifier bytes through declared Haskell builders. Check canonical encodings, checksums, network discriminants and malformed inputs. Native-script cases must include actual ledger evaluation with signer and validity-interval inputs, in addition to serialization/hash validation. Byron derivation-path encryption/decryption must call actual CBOR/authentication helpers and test incorrect authentication and malformed encoding. Independent Rust checks must validate credential headers/digests, variable-length pointer encoding, script CBOR/hash/evaluation, base58/Bech32 and governance headers; do not manufacture expected outputs with the future implementation.

### Real migration backend failure (T028)
Trigger an actual recoverable Argon2 backend failure during opportunistic V1-to-V2 migration while leaving the pinned wallet/database code unchanged. Require that V1 credentials, scheme, encrypted bytes and metadata/timestamp remain unchanged, that the wallet emits its migration-failure warning, that the authorized callback still receives/signs with V1, and that a subsequent ordinary unlock retries and completes migration. The fault must be consumed exactly once and production KDF parameters must remain in use. Mutated-key fixtures cannot substitute: the backend clamps arbitrary scalars and does not fail that branch.

### Transaction codec, metadata and ledger signature profiles (T029, first slice)
Use the actual pinned wallet transaction reader/renderer and transaction-ID extraction across Byron through Dijkstra. Capture typed source-built fixture transactions, exact decoding/round-trip bytes and hashes, plus indefinite/trailing/duplicate-key boundaries as actually observed; do not substitute an independently stricter parser for Haskell behavior. Codec acceptance is distinct from ledger validity and real spending. Metadata profiles must test wallet validation of exact signed integer/label limits, UTF-8 byte lengths, byte strings, nested maps/lists and canonical ledger serialization. Verify low-order/noncanonical signatures through the actual ledger DSIGN backend as a separate profile from legacy extended-wallet verification.

### Registered DRep lookup (T064)
Register a fresh owned key-credential DRep on a real node before starting the wallet whose lookup is tested. Independently verify public-key hashing, CIP129 identity, registration certificate bytes, the deposit, complete signed transaction witnesses/body, value conservation, node confirmation and spent inputs. Compare the wallet's exact registered-DRep detail and summary with actual stable node state, including activity/expiry, deposit, voting power, credential kind/hash and explicit null anchor/name/metadata. Keep an independently absent DRep control. Fixture preparation alone receives no conformance credit. Preserve Haskell's 900-second cache behavior; do not modify it or treat stale responses as fresh node evidence. This slice does not claim all governance, metadata or script-credential semantics complete and does not apply any pending correction.

### Real era boundary (T065)
Exercise restoration, actual submission and stake certificates across an observed hard fork on one continuously advancing chain. A dedicated fixture must start before the boundary and prove actual era/epoch/block progression afterward; independent clusters or edited API responses do not substitute. Preserve pinned Haskell unsupported-era behavior before its writable Conway era. Independently check wallet history, balances, UTxOs, transaction bodies, signatures, fees and node acceptance after the boundary. Fixture startup alone receives no conformance credit and does not change any pending process-control or profile correction.

### Independent funded delegation-fee reads (T066)
Check the funded delegation-fee API separately from vote/delegation submission. For one independently funded unregistered Shelley input, require exact node deposit, empty minimum-coins list, identical fee percentiles, exact units and a fee equal to an independently sized matching balanced no-payment transaction. Preserve the pinned Haskell default no-certificate estimation behavior and maxBound upper validity slot. Verify the unsigned and wallet-signed body's input, internal change address, conservation, no assets/certificates/extra fields, signature and fee arithmetic. Reads, balancing and signing must leave balances, addresses, UTxOs, history and the node funding output unchanged. Keep the existing voting profile and all pending corrections untouched.

### Independent empty delegation guards (T067)
Exercise the exact documented403 responses for vote delegation from an empty owned wallet and for quitting when not delegating. Validate complete source-grounded code/message and omitted info, independently check each service's status/schema, and compare both pinned reference services. Require terminal-ready zero balances/assets, unchanged wallet identity/name/delegation, complete address and UTxO snapshots and empty history before and after the rejected requests. Preserve all funded delegation/voting requirements and pending corrections.

### Empty stake-pool join with independent membership (T068)
Select an actually active stake pool from the trusted node, require the wallet to list that same pool, and test exact documented403 no_utxos_available from a fresh owned empty wallet. Check full error fields and unchanged wallet, address, UTxO, history, stake registration and node pool membership state across repeated requests. Keep all funded pool/vote/certificate requirements and pending corrections unchanged.

## Approved follow-up decisions (2026-11-03)
The user explicitly requires all644 obligations, including the original OpenAPI postSharedWallet500 missing_reward_account response. This supersedes the earlier643 total; historical reports retain their original denominators and no new coverage is inferred. The user also approved the narrow node_not_yet_in_recent_era construction403 branch and supported_recent_eras info-key correction, and actual pinned Haskell per-distinct-input-reference mock-witness counting for size/fee estimation. Physical signed witnesses remain independently checked. Preserve original OpenAPI and failed reports,600 real funding outputs, strict statuses, adjacent accepted/rejected size proof and ledger/accounting checks.

## Pending-state persistence and deletion (next independent slice)
A real pending transaction must survive death/restart of the exclusively owned foreground wallet with its identity, signed bytes, pending history, locked inputs, available/total balances, key/address state and unchanged node UTxOs preserved. Use only the already audited exclusively owned cluster supervisor and producer pidfds; keep the relay queryable and prove a stable tip and exact mempool transaction membership while forging is paused. Forgetting a pending transaction must return documented204, remove wallet pending history, restore wallet input availability, preserve the node mempool and ledger, and permit the exact transaction to reappear as confirmed history after producers resume and its original signed transaction is included. Independently prove signatures, body hash, outputs, conservation and consumed inputs. Resume producers and reap owned processes on every exit. This slice earns no retry, expiry, rollback, checkpoint or all644 conformance credit.

## DRep semantic query binding
The mandatory governance:drep-queries case must be recorded only after all actual registered-detail, absent-detail, complete-list, summary and unchanged-wallet/node-cache-bracket assertions pass. Preserve exact CIP129 identity, key credential, deposit/expiry/status, decimal-string voting-power units, explicit null fields, absent error and same-epoch stable independent node state. Fixture preparation supplies no conformance credit. This binding does not satisfy governance:vote-state, nonzero delegated voting power, script credentials or metadata by implication.

## Approved remaining corrections (2026-11-04)
The user's instruction to fix the remaining items authorizes all three pending reviewed corrections: select owned non-retiring pool3 for negative metadata and its subsequent explicit retirement; validate eligible, preserved and fully accounted optimal-selection additions only in intermediate size probes while keeping the final adjacent boundary exact with no extra inputs; require the native mempool query's exact exists/slot/txId response with independent mempool-slot bracketing. Preserve all previous failures,644 obligations, exact errors/statuses, node/accounting/signature checks and cleanup. Approval supplies no conformance credit; execute fresh real-node verification.

## Continued fixture corrections (2026-11-04)
The user's request to keep working authorizes the two prepared remaining fixture corrections: reserve12ADA instead of4ADA in the600-input size probe, and perform the exact native retirement timestamp-to-slot comparison after the already required native epoch activation wait. Preserve all644 obligations, all original failures, the600 real1ADA outputs, strict final adjacent no-extra-input boundary, full fee/conservation/signature/node checks, immediate original wallet/genesis timestamp and scheduled-node-state assertions, and every retirement removal assertion. Classify subsequent failures from independent evidence; never alter an expected result merely to make the reference pass.

## Failed size-control diagnostics
When a returned unsigned transaction fails the size-control framing assertion, preserve its public encoded transaction in the failure detail. Retain every existing assertion and replay the same workflow before proposing any parser or expectation change. Diagnostic capture supplies no conformance credit and must not include wallet credentials or database contents.

## Independent real pending expiry
A separate explicit expiry mode must create and sign a short-lived payment, prove its validity upper slot and expiry timestamp against public genesis, submit it to a real node while exclusively owned producers are paused, and prove actual pending history, locked input accounting, signature and mempool membership. After wall-clock expiry, resume producers and observe a native chain tip beyond the encoded validity limit. Require exact expired history fields, restored funds, unchanged original funding UTxO, no recipient/change outputs and eventual native mempool absence. Forgetting the expired transaction must restore baseline history and preserve keys, funds and node state. Record live:pending-expiry only after all checks pass; never infer pending retry, rollback or complete wallet.resubmission from expiry alone. Retain the existing restart/deletion mode unchanged.

## Authorized threshold and expiry-bound corrections
The user's renewed instruction to keep going approves both prepared narrow corrections: canonical definite input sets through23 and terminated indefinite sets above23, and exactlySome(0) for the constructed expiry transaction's default lower bound. Preserve the independent upper bound, all644 obligations, all original failures and every final input-boundary, fee, signature, node, history and accounting assertion. Approval supplies no execution credit.

## Approved bounded expiry fixture
The user's explicit do-it approval authorizes the prepared8-second expiry window and public-genesis horizon guard. Require the encoded upper limit plus one slot strictly inside the conservative3k/f window from the stabilized paused native tip before submission. Fail if the independently computed current slot already reaches the upper bound. Preserve every signature, exact validity/expiry field, actual pending admission, post-expiry native advancement, history/accounting/input/output/mempool/deletion assertion, all644 obligations and all prior failed reports.

## Preserve actual expiry defect evidence
The bounded fixture now reaches a synced wallet/native chain beyond the signed expiry, while wallet history remains pending and funds remain locked. Keep the strict expiry assertion failing. Preserve public admission/signature/funding/horizon and native post-expiry phase proofs before waiting for status so an eventual failure retains its evidence. Repeat the identical scenario for reproducibility; never relabel a wallet defect as a harness correction or silently require two-hour expiry.

## Byron native-asset receipts (T080)

The native-asset profile must fund fresh random and Icarus Byron wallets with actual ledger-confirmed empty-name and named tokens. For each wallet, both asset lookup routes must return exact policy/name/CIP14 fingerprint, with list/balance/UTxO/history data reconciled against independently inspected signed transaction bytes and native node outputs. ADA-only family receipts cannot satisfy these routes. Preserve original reference failures, all644 obligations and owned-wallet cleanup; known upstream expiry issue5479 is not an exemption.

## Reusable funded stake delegation and rewards (T081)

Given an independently registered, wallet-visible pool in an owned cluster, the suite must register/delegate a freshly funded stake credential, observe actual activation and nonzero ledger rewards, withdraw them through independently verified signed bytes, then deregister and account for any automatic residual withdrawal and deposit refund. Bind stake-delegate and reward-withdrawal only after their own actual proofs pass; prior source audits earn no credit. Legacy pool joining must execute its documented202 route; a separately signed modern construction cross-checks certificates and keys without substituting for that route.

The user's latest instruction authorizes continued progress while recording problems and questions for later. Preserve failures and strict invariants; routine repairs and independent work must not wait for another permission question. Known defects and unexecuted cases continue to prevent an all-passing644 claim.

## Genuine pending and confirmed Byron deletion (T082)

Both random and Icarus wallets must submit real transactions while owned producers are paused, prove exact pending/mempool/unspent-input state, forget them through204 and exact404 without changing the node mempool, then rediscover the same transactions upon real inclusion after production resumes. Deleting each confirmed transaction must yield the exact403 and preserve wallet/node state. No confirmed rejection substitutes for positive pending deletion.

## Source-grounded scheduled-delegation status correction (T083)

The first real stake run confirms join202 and ledger inclusion, then fails the strict next-delegation enum. Pinned ApiWalletDelegationStatus defines VotingAndDelegating, serialized voting_and_delegating; original OpenAPI incorrectly spells delegating_and_voting. Under the user's continued-progress authorization, correct only that enum spelling in the hash-guarded overlay, retain the original source and failed report, require a regression rejecting the original misspelling and unknown statuses, and rerun the unchanged live workflow. No response/status/count/accounting relaxation.

T081 fixture follow-up: the corrected-enum run reaches actual delegation but receives zero rewards within180seconds. Independent pool-state/stake-snapshot observations show declared pledge150trillion while the entire pool's active stake is approximately129trillion, so that fixture cannot satisfy its pledge. Re-register only the owned pool with explicit pledge0 using the existing audited tool; preserve the failed run and unchanged reward/signature/accounting requirements. Require actual on-chain pledge0 activation before a fresh random-wallet replay. This changes a fixture parameter, not wallet source, timeouts, deposited rewards or the conformance contract.

## Requested combined checkpoint and blind-spot report (T084)

The user requests a combined run now, a summary report at its end describing remaining blind spots, then continued implementation toward100%. Freeze the current executable assertions and corpus for this checkpoint. Execute all available actual Haskell internal vectors, all differential HTTP suites and available real-node profiles under a declared source/runtime cohort. Preserve every failure and unexecuted case; original expiry issue5479 remains known and strict, and no corrected-reference result may be relabeled original-reference. The report must derive actual obligation coverage from fresh receipts and explicitly distinguish fixture prerequisites, unreachable documented branches and missing semantic implementation. Resume new coverage work only after writing that report.

## Source-grounded Byron deletion contexts (T085)

The requested combined checkpoint is complete and its report is written. Continue T082 by distinguishing two real contexts. The pinned submission layer returns404 for Unknown and403 for InLedger; forgetting removes the submission record even when later chain discovery restores transaction history. Preserve and assert the previously forgotten/rediscovered404 with exact fields and unchanged state. For each random/Icarus style, add a separate freshly funded wallet and a locally submitted, never-forgotten confirmed transaction, then require exact403 and complete wallet/node preservation. Both documented statuses stay strict; no obligation, source pin or failed report is removed.

## Real scheduled retry and legacy node rejection (T086)

Add an owned retry mode with a separate explicitly launched adversary wallet service. For Shelley, Icarus and random Byron, the services share only a newly generated wallet mnemonic and independently observed funding. While owned producers are paused and the relay remains queryable, the adversary submits an eight-second transaction. A different long-lived legacy transaction from the target spends the same input and must receive the real node's exact500/created_invalid_transaction BadInputs rejection. Require that target transaction's genuine pending record, reserved balance and initial mempool absence. After the short conflict expires and production resumes, make no further submission API calls: the identical target transaction must be automatically retried and confirmed. Preserve strict ledger/input/output/fee/ownership and absent adversary-output proofs; no mock acknowledgement, injected response or manual resubmission. Bind live:pending-retry only after all styles pass, and bind each actual legacy500 operation separately. Original expiry failure and644 obligations remain unchanged.

### T086 observed Conway mempool conflict constructor

The second fresh real run reaches the intended primary legacy500 while the conflicting short-lived transaction is in the actual node mempool. The pinned node rejects its one input with `ConwayMempoolFailure "All inputs are spent. Transaction has probably already been included"`, rather than the assumed ledger `BadInputsUTxO` constructor. Preserve the failed cause assertion and extracted public network rejection. Require this exact observed constructor/message for this pinned Conway fixture, retain status500/code/media/schema, native original-input preservation and adversary-mempool membership, and capture the actual public HTTP rejection before validating it so subsequent failures retain their evidence. This corrects the fixture's expected constructor, not the wallet or node; no arbitrary500 gets retry credit.

## Actual checkpoint restoration and offline catch-up (T087)

Given an exclusively owned funded wallet synchronized to a real chain, stop and reap its service, advance the same chain and include a new incoming payment while the wallet is offline, then restart the unchanged executable against its unchanged private database. Require an actual non-genesis chain-sync intersection offered by the restarted client, accepted by the independent node, at a slot no later than the independently recorded pre-stop tip. The advertised node tip and final native tip must demonstrate the offline advance. Do not infer checkpoint reuse from final balances or a restart alone. Observe full32-byte hashes on actual transport; never substitute truncated log hashes or require the candidate to use Haskell SQLite tables.

A passive bounded observer may inspect node-to-client mux/CBOR frames without altering any forwarded byte or logging blocks, transactions, credentials or raw protocol payloads. Retain only connection IDs, public points/tips, counters and explicit observation errors. Malformed framing, overflow, unmatched intersection responses or unfinished observed messages cannot earn credit. Genesis-only replay, immediate restart without offline advancement and unrelated current-tip queries cannot satisfy the checkpoint case. Existing byte-transparent fault controls keep their default behavior. Only the complete live workflow, state preservation, independent native accounting, final integration probe and owned cleanup may bind `state:restore-from-checkpoint`; observer regressions alone earn no coverage.

## Genuine divergent-branch rollback and reapplication (T088)

Build a common real chain with three independently funded wallet inputs and retained native/common-header proofs. Gracefully shut down and reap every directly owned native node before privately copying its closed database. Launch two isolated native branches from that same common snapshot and byte-identical genesis: branch A with pool1, branch B with pools2–4, each with its own relay/database/topology/ports. No producer key forges on both branches. Require independently queried divergence and a strictly longer branch B; edited responses, production pause alone, mutable live database copies and socket reconnection alone cannot satisfy rollback.

Keep the owned wallet process/database running throughout the fork. On A, create/sign/submit one transaction locally and confirm it, sign another wallet's transaction but submit its actual signed bytes directly to the native node and confirm it, then admit a third wallet's local transaction as genuinely pending under paused production. The common three inputs must still be present/unspent on B, and A-only outputs absent there. Switch only the owned byte-transparent node connection to B, observe a real accepted common intersection and RollBackward on the actual transport, and verify the wallet has caught up to B's independent full tip. Require locally confirmed→pending, existing pending preserved, discovered-only A history/outputs removed, exact restored available inputs for the discovered-only sender, exact locked/projected balances for local submissions, recipient history/balance reversal, and stable keys/addresses as permitted by real change discovery. All transaction identities, signatures, inputs/outputs, fees and native values stay exact.

Reapply the original signed transactions on B, retaining genuine automatic resubmission for local pending entries where supported and submitting the discovered-only transaction's exact original bytes. Require native inclusion of each exact ID, original inputs consumed once, correct recipient/change outputs, fees and complete final wallet history/accounting without duplicate credits. Keep the A and B headers/UTxOs, public signed transaction evidence, observer proof and all failures. Only a complete passing profile plus native final integration and owned cleanup may bind the four existing rollback cases. Do not reduce644, waive expiry/shared errors or claim a fork fixture audit alone as wallet conformance.

### T088 source-grounded unused internal-change ownership

The first fresh profile funded the common wallets but stopped before forking because an unused allocated internal change address is not yet returned by the pinned `listAddresses` implementation. Preserve that failed ownership assertion and complete cleanup evidence. Replace its listing-membership assumption with a stronger independent account-public-key derivation proof: require the constructed change's exact CIP1852 account/role/index path, invoke the already SHA-pinned actual Haskell key adapter for soft public derivation, and independently verify the payment/stake credential hashes and signed input authorization in Rust. The oracle receives public extended keys only. Record all public derivation inputs/results and the pinned oracle identity; API status, signatures, ownership, fees, native values and all rollback assertions remain strict.

## Fresh coherent644 replay after real retry/checkpoint/rollback (T089)

The requested methodology report and new live components are complete. Freeze the current assertion/corpus executable and execute a new coherent cohort of all available HTTP suites, actual Haskell internal operations and live profiles, including newly implemented retry, checkpoint and real native rollback. Use original Haskell runtime authority throughout; original submitted-expiry5479 remains a strict failed result and shared-creation500 remains mandatory/unexecuted unless actually reproduced. Do not merge any earlier component report, relabel a corrected runtime as original or claim an aggregate percentage before the new unchanged gate finishes. Preserve fixture phase isolation: run strict two-pool lifecycle independently of the additional reward pool. Retain every new failure, runtime/genesis/oracle identity, final native integration and cleanup. Update the human methodology/blind-spot report and exact missing cases from actual new results, then continue any independent work without waiting on deferred authority questions.

## Post-report clock and inclusion corrections (T090)

Preserve the failed639/644 checkpoint. Correct the pool genesis consistency guard to the actual pinned cluster's nearest-integer, ties-to-even POSIX rounding, sharing the already used rule with validity and pending clocks. Retirement slot/time and activation assertions remain exact. For normal pending reappearance only, wait read-only within the existing bound for an output of the exact signed transaction. Retry only its absence; malformed node responses, wrong matching address/coin/assets and query failures fail immediately. A new block or unrelated transaction never proves inclusion. Keep immediate payment checks in state-preservation controls. Record public admission/forgetting/tip/signed transaction proofs before the inclusion wait so a failure retains its context. Require meaningful regression cases, full Rust/format/Clippy/Nix checks and fresh owned pending/pool runs before completion. No authority, status, count or expiry waiver is authorized by this correction.

## Native fixture funding orphan recovery (T091)

The fresh combined rollback fixture timed out before its fork: native peers admitted a funding transaction and removed it around competing same-slot blocks. An isolated recovery of the closed native relay database proves the exact parent funding input remains unspent and the exact recipient output is absent; the unchanged signed bytes are accepted again into the recovered node's mempool. Preserve these public facts and the original failed cohort. Private fixture funding may replay identical signed bytes within the original single confirmation deadline only after independently proving its exact output absent, its original input/value/address unchanged, mempool absence and native block advancement since submission. Bound replay count explicitly and retain public per-attempt diagnostics before waiting, including failure. Malformed state, conflicting input consumption, changed signed bytes, wrong outputs or exhausted limits fail strictly. This applies only to the independent native genesis funder, never the wallet transactions whose rollback/resubmission is tested. Require meaningful guards/regressions, all checks and a fresh complete native rollback workflow with final integration/cleanup before credit.

T091 native replay race: the first recovered fresh run completed wallet rollback/reapplication but failed the final native probe when inclusion raced the guarded replay. Preserve the205-check failed report, guard snapshot and signed bytes. A rejected replay may count as already confirmed only after independently observing the exact transaction output with exact address/coin/no-assets and its original input consumed. Retain the rejected replay as a rejected attempt, not successful admission; otherwise propagate the failure. Add an end-to-end controlled-CLI harness regression for this race and for ordinary exact replay, without awarding wallet coverage to simulated results.

T091 final-history diagnosis: the next native run reached reapplication but failed the combined uniqueness/all-in-ledger assertion. Preserve its173-check failure without classifying it as a wallet or harness defect. Before changing synchronization or expectations, retain each actual final wallet snapshot, baseline and native tips bracketing the snapshot so duplicate IDs, pending entries and a concurrent native fork can be distinguished. The history assertion remains unchanged.

## Confirmed/pending duplicate reference diagnosis (T092)

The diagnostic original-reference run returns the same transaction ID twice in a single history response, once in_ledger and once pending; retain this API consistency violation. Do not deduplicate the response in the harness, retry it away, change the expected history or count it as passing. On a future failing final-history assertion only, pause the independently owned B producers, wait for a stable native tip and wallet catch-up, then retain raw history/wallet/native output observations before preserving the original strict failure. This is diagnostic follow-up, not replacement evidence. Independently invoke the actual pinned Haskell submission functions for the interleaving pending-read → ledger confirmation → delayed resubmit bookkeeping. Capture actual before/after status and source/binary hashes with a real public signed transaction. Record whether the source can reset confirmed state, document the observed defect and prepare a local upstream issue draft; do not send another upstream issue without explicit authorization. No expectation,644 count, source authority or known-issue waiver changes.

T092 isolated proposal validation: prepare a narrow source patch that makes resubmitTx bookkeeping conditional on the current entry still being InSubmission. Validate the same actual Haskell diagnostic against an explicitly separate module copy with that patch; retain original and proposed outputs/hashes and the ordinary pending control. Do not modify the pinned wallet checkout, replace the live runtime, claim full application validation or promote corrected behavior to authority. The local patch and issue draft remain reviewable proposals.

## Isolated full wallet correction validation (T093)

Validate the proposed current-InSubmission callback guard in a separately identified full Haskell wallet build, based on the already validated isolated signed-expiry correction. Keep the original2fc source/runtime and every strict failure intact. Reuse the unchanged strict Rust rollback/expiry profiles against a distinctly declared corrected runtime; do not merge its evidence into an original-reference gate or adopt it as authority. Include a meaningful Haskell regression for delayed bookkeeping after confirmation and an ordinary-pending control, source quality checks, reproducible Nix build identity, fresh live tests and complete cleanup. This validation prepares a concrete reviewable correction; it does not authorize publication, upstream messaging or source-pin promotion.

## Fresh complete corrected-runtime cohort (T094)

Execute all available 37 HTTP, internal and real-node profiles afresh under one frozen harness fingerprint and declared environment against the separately validated8fcb6fb0ee wallet runtime. Retain original2fc internal/differential oracles with explicit roles and hashes. All644 mandatory obligations and strict failures remain unchanged. This is a proposed corrected-reference validation, not promotion of source authority. Preserve every new failure, native phase identity, cleanup, measured timing and exact gate result. Generate an updated methodology report from these new reports only; never merge component or historical results. Any unavailable shared-creation500 remains explicitly missing, not waived.

## Nix regression-helper portability (T095)

The full Nix package check must execute the private fixture-replay regression without depending on an unsandboxed /usr/bin/env. Preserve all four modes, exact signed-byte replay, rejection/confirmation and tampering assertions. This is a harness packaging correction only; no live assertion, corpus, inventory or reference authority may change. Preserve the observed sandbox failure and verify both development-shell and sandboxed package checks. Apply after T094's frozen cohort completes.

## Deterministic native inclusion after pending deletion (T096)

Preserve the frozen cohort's failed44-check normal pending run. The node retained the exact transaction after DELETE, but a copy of its closed relay state later proves original funding unspent, requested output absent and identical signed bytes valid for admission. This is native fixture loss, not evidence of wallet failure. Normal pending reappearance must still require actual identical transaction inclusion, exact signatures/fields/accounting and all existing restart/deletion checks. Do not replay the wallet transaction or retry away the failed run. Avoid competing native producers during its controlled inclusion interval instead, using only independently identified owned processes and guaranteed resume/cleanup. Other pending modes remain unchanged.

## Owned fixture port-allocation shortage (T097)

The frozen checkpoint run fails before any wallet starts: node discovery times out. Its closed topology has only three producer peer ports despite four configured genesis pools; launch logs show three producers plus relay. Pinned randomUnusedTCPPorts explicitly may return fewer ports than requested, while withCluster launches zipped pools/ports and waits for the original pool count. Preserve the strict failed report and exact topology/source evidence. A new cohort may recover only this independently verified pre-wallet fixture initialization defect using bounded fresh owned attempts and complete cleanup, never retrying wallet assertions or swallowing unrelated startup errors.

## Explicit complete-status contract review (T098)

A concrete review proposal inventories all646 documented obligations, identifies the existing three source-stale response candidates and preserves the historical644 gate. On2026-11-06 the user explicitly approved reviewing the complete646 inventory and retiring only the three named response slots, yielding643 active obligations. Preserve original OpenAPI bytes, historical evidence, strict runtime/schema checks and separately declared corrected target provenance. No fabricated failure, replacement obligation, known-issue waiver or claim of historical644/644 is permitted. Approval of this narrow contract reconciliation does not promote the corrected runtime or the entire generated draft as authority.

## Executable wallet specification and complete runner (T106)

The user requires an executable specification against which a future implementation can run; a prose document alone is insufficient. Extend the existing Rust executable contracts rather than introducing Lean as a dependency. A single `conform --config ... --workspace ...` invocation must execute all9HTTP,16internal and12live profiles, drive owned standard/committee/pending/fork/era fixtures, and emit machine-readable reports, strict coverage, a bundled specification and execution/cleanup provenance. CLI compatibility remains out of scope; candidate launch arguments are configuration.

Candidate configuration supplies its real foreground HTTP service launch and one thin internal adapter; reference qualification may explicitly map existing independent adapters per internal profile. Trusted node/CLI/factory/reference-wallet/key-oracle executables are independently configured and hash-pinned. A new implementation cannot substitute itself or Pallas for these oracles. No hardcoded /tmp helper paths or development-checkout working directory may be required by the runner. All registered HTTP/vector corpora must be embedded and materialized under the fresh run workspace. The default run must not permit skipping profiles or importing historical reports; unsupported adapter operations fail.

Reuse existing executable assertions and process ownership controls in-process, including cleanup on ordinary/errors, exact schema/status/signature/selection/state/native checks and final native integrations. Keep all native node/wallet/private fixture files private. Persist public reports and a receipt of every attempted profile and fixture failure; one setup failure cannot be silently replaced by a passing label. Require the final37 fresh reports and complete gate, bind their corpus/assertion fingerprint and executable identities, and preserve all historical644 evidence. A complete active643 catalogue remains finite conformance, not a universal equivalence proof or automatic specification-authority promotion.

## Independent current644 packaged replay while contract review is pending (T099)

Continue authorized execution without waiting on the separate T098 contract decision: freshly replay all37 reports against the current unchanged644 catalogue with the validated packaged CLI and corrected target. Keep any pending review unapplied throughout this frozen cohort. Retain all attempts/failures, explicit provenance, final native integrations and cleanup. This independent run can establish the remaining executable coverage but cannot certify the source-stale500 or promote source authority. A later approved contract change requires its own new fingerprint/evidence, never historical report relabeling.

## Release-runtime owned node discovery (T100)

The full packaged cohort exposes five immediate ENOENT setup failures that the development build's component tests did not reproduce. Preserve all37 reports and632/644 failed gate. Before changing readiness semantics, identify the exact missing owned path/stage through contextual errors and an untraced release control audit. Then handle only a proven asynchronous startup condition within the existing deadline, retaining canonical ownership, executable hashes, parent/group/start identities, key completeness and fail-closed malformed/escaping paths. No wallet assertion or catalogue change is permitted. Verify release execution of all five affected owned profiles before another complete cohort.

## Fully qualified packaged current644 cohort (T101)

The release-only setup ordering correction now passes all201 Rust/full Nix checks, a real untraced producer-control audit and417 fresh live checks across all five previously failing modes. Freeze this validated package and execute a new complete37-report current644 cohort. Preserve prior632/641/639 gates and all failures; no component report merge, count change, source promotion or pending contract-review application. Derive all acceptance/timing/cleanup results from new observations only.

## Owned faucet funding on one native producer (T102)

The qualified cohort's normal pending profile fails before any wallet transaction: its native faucet funding never enters the selected chain. An isolated copy of the closed relay state proves original genesis input unspent, requested100ADA output absent, and unchanged faucet bytes accepted. Preserve the original strict failure and diagnostic. Prevent competing native producers throughout owned pending fixture funding and wallet workflows, without replaying wallet transactions or relaxing any wallet/node/accounting assertion. Select the pinned factory's earliest producer (first configured pool, no scheduled retirement) rather than an arbitrary producer that may retire. Nested pause guards must resume only producers they themselves stopped, leaving the outer fixture guard's paused producers untouched.

## Early-lease complete current644 replay (T103)

Once all five early-lease release qualifications complete successfully, freeze the actual Nix package and freshly execute all37 reports under one new environment/fingerprint. Keep every original/previous corrected/package/funding failure, all644 current requirements and source authority unchanged. No component result may substitute for a fresh report and no pending policy proposal is applied. Publish exact gate/remaining scenarios/timing/cleanup from these observations only.

## Explicit mixed-status history consistency (T104)

The follow-up combined execution (T105) must use one frozen packaged assertion/corpus fingerprint after successful T104 live qualification. All37 reports must be freshly executed; no earlier history or other component receipt may be substituted. Keep all644 obligations mandatory, preserve original-reference authority and the separately declared corrected target, and publish the exact gate result even if the documented shared-creation500 remains unexecuted. A successful history component alone cannot change a combined percentage.

The completed3785/3785-check cohort still lacks mandatoryhistory:status. Do not award it from a related passing marker. Pinned API.hs ListTransactions has no status selector; DB.readTransactions merges ledger and pending/expired records, sorts by slot with ID ties and applies the global limit. Extend the actual owned expiry workflow to verify confirmed funding together with pending then expired submitted history, exact list/get stable-field equality, supported order/max_count behavior and deletion preservation against existing independent native funding/mempool/expiry proofs. Keep all644 obligations and existing assertions; no invented public status query or time-filter law for unconfirmed records. Bind the case only after complete workflow/native integration/cleanup success.
