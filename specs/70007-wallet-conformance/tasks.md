# Tasks

Standalone migration (2026-11-06):

- [x] T108 Consolidate the standalone default branch into two initial commits, with planning/specification/documentation before implementation/fixtures/evidence; retain the imported development history in an external local Git bundle and the original worktree. Preserve all tracked content and keep historical evidence identifiers intact.

- [x] T107 Preserve the 406-commit orphan history and ignored local artifacts in an independent bare-plus-worktrees repository with `master` as the default branch; update project descriptions and adapter paths for language-independent open source conformance before Daedalus/cardano-wallet consumer adoption. Verify repository integrity, artifact equality, Spec Kit selection, formatting, all-target Clippy and all 211 Cargo tests through Nix. Live/reference qualification is retained historical evidence, not rerun by this migration.

- [x] T001 Initialize orphan worktree and pinned Rust Nix template.
- [x] T002 Write constitution, specification, plan and requirements checklist.
- [x] T003 [US1] Implement OpenAPI operation inventory, response validation and HTTP transport in src/api.rs.
- [x] T004 [US1] Implement declarative scenarios and differential comparison in src/scenarios.rs.
- [x] T005 [US2] Implement advancing-node, funded transfer, construction/signing/confirmation and owned-wallet cleanup in src/live.rs.
- [x] T006 [US3] Implement internal JSON adapter protocol and independent crypto vectors in src/adapter.rs and fixtures/vectors/.
- [x] T007 [US4] Implement mandatory domain catalogue, API polarity coverage and fail-closed JSON reporting in src/report.rs.
- [x] T008 Add meaningful mock, adapter, vector and invariant regression tests under tests/ and src/.
- [x] T009 Document reference/candidate runs, local-cluster setup, adapter contract and exhaustive coverage gaps.
- [x] T010 Run Nix build environment, formatting, Clippy and Cargo tests; record genuine live validation separately.
- [x] T011 Close all mandatory internal requirements with independent oracle vectors and execute all live/API coverage against a reference service.
- [x] T012 Apply evidence-backed Haskell response contract corrections, retaining pinned source and regression checks.
- [x] T013 Generate a reviewable behavioral specification from the conformance catalogue, corpus and reference evidence, with unresolved obligations explicit.

Dependencies: T003 precedes T004/T005; T006 and T007 precede T008; T009 follows interfaces; T010 follows implementation; T011 requires reference runtime and domain corpus.
- [x] T014 Add independent public HTTP key/account/address, passphrase-change and watch-only restoration matrix.
- [x] T015 Add and validate the response-status/error-precedence matrix against isolated Haskell services.
- [x] T016 Capture and independently validate primitive boundary and Unicode-passphrase vectors.
- [x] T017 Build and validate a thin Haskell internal reference adapter with explicit actual-build provenance.
- [x] T018 Reject modified runtime inputs reusing registered case IDs and verify wallet signature boundary profiles.
- [x] T019 Execute Haskell minimal/optimal seeded selection, capture exact outputs and independently validate selection properties.
- [x] T020 Extend Byron/shared wallet lifecycle, numeric JSON acceptance and NoContent response contracts against live reference services.
- [x] T021 Capture and execute production-cost V2 encrypted-root parsing, authentication, signing, derivation and passphrase-change vectors through the pinned Haskell backend, retaining legacy/migration gaps explicitly.
- [x] T022 Exercise actual wallet DB credential transitions: V1 correct/wrong-password unlock, opportunistic migration, passphrase changes, idempotent V2 use and legacy-flavor migration exclusions.
- [x] T023 Validate the complete executable corpus against Nix-built pinned-source wallet/cluster components and their matched node runtime, retaining one coherent source/environment evidence set.
- [x] T024 Add approved bounded read-only epoch alignment with per-sample successor checks, strict same-epoch comparison, regression tests and preserved boundary-failure evidence.
- [x] T025 Execute independent key-derivation/signing goldens through pinned-source KeyAdapter.hs; add malformed-input boundaries, Rust cross-checks and source-bound reference evidence without claiming unexecuted semantic cases.
- [x] T026 Execute mnemonic entropy/checksum, generation-factor, hardware root/child and enterprise-address profiles through the pinned Haskell adapter, with captured goldens and independent Rust checks.
- [x] T027 Complete remaining address encodings, Byron payload, CIP-129 and native-script profiles with actual Haskell capture and independent validations.
- [x] T028 Exercise actual wallet migration backend-failure preservation through controlled fault injection and unchanged wallet/database code.
- [x] T029 Complete transaction serialization/witness/fee/min-UTxO/metadata/mint/collateral/governance component profiles.
- [x] T030 Complete funded Byron/shared/multiasset/delegation/governance and remaining positive/status HTTP workflows against the real node.
- [x] T031 Exercise restart, rollback, resubmission/disconnect and concurrent-spend state scenarios with controlled real-runtime transitions.
- [x] T032 Rerun all registered evidence under one final fingerprint/source environment; require all643 obligations and regenerate the reviewable specification draft.
- [x] T033 Add explicit funded family profile: real random/icarus and Shelley payments, fee/selection conservation, migration plans/submission, independently confirmed node outputs and family-aware cleanup.
- [x] T034 Add actual funded two-party shared activation, discovery, partial signing rejection, merged witness verification and ledger confirmation.
- [x] T035 Validate funded watch-only construction/no-root rejection, separate reference-service witness generation, target submission and independent node/crypto accounting with cleanup on both services.
- [x] T036 Exercise wallet-native mint/burn, empty/named asset queries/fingerprints, exact binary proxy submission, strict actual node invalid-witness rejection and independently reconciled multiasset snapshots.
- [x] T037 Validate the independently selectable funded Shelley fee/selection/deprecated payment and complete migration profile with unchanged family laws.
- [x] T038 Exercise simultaneous funded constructions and signed submissions, strict source-grounded loser outcomes, exact node conflicting-spend rejection and final wallet/node accounting.
- [x] T039 Export versioned readable live-profile contracts and individual executable source digests alongside actual validation evidence.
- [x] T040 Validate actual CIP83 encrypted metadata, independent OpenSSL decryption, exact CBOR/binary history, Shelley wrong-password403 and separately audited shared TODO behavior.
- [x] T041 Execute exact source-grounded malformed JSON, unknown method/path, media negotiation and media-before-body probes against Haskell; retain remaining precedence gaps.
- [x] T042 Complete source-grounded path/body, wallet/passphrase, funded-versus-empty output precedence and cross-network address rejection with exact case/group binding and independent controls.
- [x] T043 Capture actual Haskell slot/time boundary vectors and execute funded lower-bound/TTL/expired-transaction controls against the node, preserving hard-fork gaps.
- [x] T044 Capture actual collateral-return codec/unsupported-input guards and execute funded balanceTransaction construction, signing, submission and independent node accounting.
- [x] T045 Execute exact differential staking/governance406/415 cases on valid routes, preserving strict media error bodies and all643 obligations.
- [x] T046 Audit and implement funded Conway stake registration/delegation, vote delegation, quit/refund and delegation-fee APIs with independent certificates, witnesses, node stake state and exact ledger accounting.
- [x] T047 Build and validate a reusable Rust fixture command that re-registers an owned local-cluster pool on-chain and proves wallet visibility without source/database changes.
- [x] T048 Audit nonzero pool rewards, explicit reward withdrawal and retirement/refund against independent node stake-account and UTxO observations.
- [x] T049 Capture actual Haskell reward-withdrawal transaction roundtrips and independently verify CBOR reward maps, signatures, node identity and ADA conservation.
- [x] T050 Audit actual signed-size estimation and input-count/maximum-size boundaries, then execute source-grounded many-input balance controls without inventing a selection hard cap.
- [x] T051 Implement owned foreground wallet crash/restart controls with fresh private database, executable identity, exact argv/environment and guaranteed child reaping; then validate persisted confirmed/pending/key-address state against HTTP and the live node.
- [x] T052 Implement and independently audit transparent owned Unix node-socket disconnection/reconnection, then prove wallet catch-up/accounting through a real node without substituting startup-phase controls for rollback or forging control.
- [x] T053 Validate funded history time/order/max-count/address/min-withdrawal controls and exact binary metadata through signed ledger-confirmed payments, retaining pending/expired status semantics as an explicit separate gap.
- [x] T054 Validate exact documented403 for forgetting freshly confirmed locally submitted transactions and prove transaction/wallet/node preservation.
- [x] T055 Validate shared creation template-key403 and funded shared wrong-passphrase signing403 with exact errors, unchanged wallet/node state and existing positive controls.
- [x] T056 Validate plaintext metadata decryption-structure403, successful unchanged ordinary decode and state preservation before real signing/submission.
- [x] T057 Validate wrong-old-password403, unchanged passphrase metadata/addresses and successful credential rotation across all four Byron mnemonic wallet styles.
- [x] T058 Validate cross-network HTTP construction rejection with a same-credential testnet control and unchanged wallet addresses/state, independently of funded precedence history.
- [x] T059 Implement and independently audit an owned Linux cluster supervisor with producer-only pidfd pause/resume, a queryable relay and guaranteed cleanup; do not count the control audit as wallet conformance evidence.
- [x] T060 Validate sequential non-default gap discovery across two funded boundaries, exact paths/state filters and independent node/history accounting; retain other discovery semantics as mandatory gaps.
- [x] T061 Validate transient preview preservation and confirmed internal-index0 discovery with exact selected address/path, list ordering and independent change/funding accounting.
- [x] T062 Validate complete owned stake-pool ranking/metadata/maintenance/retirement lifecycle with exact node arithmetic, hash rejection and real epoch activation; retain all fixture and failure provenance.
- [x] T063 Validate real owned-committee protocol updates, exact node/wallet parameter snapshots and pre/post fee/min-ADA signed transaction behavior through actual enactment.
- [x] T064 Validate real pre-start DRep registration and exact registered/absent lookup, summary, expiry/deposit/voting-power/null fields against independent stable node state without changing Haskell cache behavior.
- [x] T065 Independently audit a real scheduled Babbage→Conway fixture and verify wallet restoration, actual signed submission and stake certificates across the observed boundary on one continuous chain.
- [x] T066 Validate independent funded delegation-fee reads against node deposit, exact no-certificate balancing/signed-size arithmetic and unchanged wallet/node state, without altering the pending voting workflow.
- [x] T067 Validate differential empty-wallet vote/quit403 guards with exact error fields and unchanged identity, balances, addresses, UTxOs and history, retaining all funded voting gaps.
- [x] T068 Validate empty stake-pool join403 against independently active/known pool membership and complete repeated-request state preservation, without invoking funded vote construction.
- [x] T069 Apply and independently verify all fifteen explicitly approved corrections, retaining original failures/OpenAPI, all643 obligations and every remaining implementation task; rerun full offline and fresh live/coherent evidence before credit.
- [x] T070 Apply the three explicitly approved follow-ups: require644 including original shared-creation500; correct exact pre-era schema/info fields; capture actual Haskell conservative input witness counts and verify adjacent real-node size limits. Preserve all failures and rerun full checks.
- [x] T071 Implement and verify owned real-node pending restart and pending deletion/reappearance through audited producer pause/resume, strict mempool/ledger/HTTP/accounting checks and guaranteed cleanup; retain retry/expiry/rollback/checkpoint gaps.
- [x] T072 Bind the complete independently verified DRep query workflow to governance:drep-queries and rerun real owned registration/fresh-cache lookup, preserving separate voting and remaining governance semantics.
- [x] T073 Apply the three explicitly approved remaining corrections (pool3, strict intermediate optimal-selection accounting with exact final boundary, exact native mempool response/slot bracket); run full checks and fresh real-node profiles, preserving failures and644 obligations.
- [x] T074 Apply the two prepared fixture corrections authorized by continued work:12ADA oversized-input reserve and exact native retirement-slot check after observed activation; verify full offline/Nix and fresh real-node boundaries/retirement, preserving original failures and644 scope.
- [x] T075 Preserve public unsigned size-control transaction bytes on framing failure; replay unchanged assertions on fresh owned state and diagnose before proposing a different approach.
- [x] T076 Implement and independently verify real pending expiry mode with exact genesis/encoded TTL, paused admission, actual chain advancement beyond expiry, strict expired history/accounting, unspent node funding/no outputs, mempool removal and expired deletion; preserve restart mode and all644 scope.
- [x] T077 Apply the two explicitly approved input-set threshold and exact expiry lower-bound corrections, retaining all invariants; verify fresh real input boundary and pending expiry workflows plus required checks and cleanup.
- [x] T078 Apply the explicitly approved8-second expiry fixture and exact public-genesis horizon guard, then verify all existing real expiry/node/state assertions, full checks and owned cleanup while preserving failures.
- [x] T079 Preserve phase-level public expiry evidence and repeat the unchanged bounded live scenario to substantiate the observed Haskell default-submission-TTL defect; retain strict failure and source provenance.

T076–T078 completion is backed by corrected-reference47/47 with unchanged strict assertions. Original2fc expiry remains a documented failing reference defect; no source pin or aggregate gate is promoted. T069 and the remaining full-scope tasks stay open.
- [x] T080 Validate real random/Icarus native-asset receipts and both Byron asset routes with independent signatures/mint policy/node UTxOs, exact balances/snapshots/history/fingerprints, preservation of source tokens, required checks and owned cleanup.
- [x] T081 Implement and freshly execute reusable real stake joining/activation/nonzero reward withdrawal/deregistration with exact independent certificates, signatures, native rewards/UTxOs, deposit/refund and final accounting; preserve failure diagnostics, full644 and final integration/cleanup.
- [x] T082 Validate genuine pending Byron DELETE204/exact404 and confirmed DELETE403 for random/Icarus wallets with stable real-node mempool/input/accounting proofs, actual same-transaction inclusion, complete preservation, required checks and owned cleanup.
- [x] T083 Correct only the source-proven delegation enum spelling through the hash-guarded overlay; preserve the failed real join report, reject old/unknown spellings and rerun strict stake/reward checks plus all required checks.
- [x] T084 Execute the user-requested fresh combined checkpoint, write actual644-gate results and remaining blind spots with provenance/timing/cleanup, then resume implementation toward100%.
- [x] T085 Distinguish source-proven rediscovered404 from fresh never-forgotten confirmed403 for both Byron styles; preserve all strict status/state/node proofs and verify fresh real execution plus required checks.
- [x] T086 Implement and verify genuine automatic pending retry plus separately bound Shelley/Byron legacy500 paths through a real short-TTL mempool conflict, all three wallet styles, independent ledger/accounting proofs, required checks and complete owned cleanup.
- [x] T087 Prove actual persisted-checkpoint reuse and offline catch-up through a passive bounded node-to-client intersection observer, delayed owned restart, independent new-payment/state/accounting proofs, meaningful observer/lifecycle regressions, required checks and complete real-runtime cleanup.
- [x] T088 Implement and validate an owned common-chain snapshot and isolated native fork fixture, then prove all four real rollback/pending/input/history/reapplication cases with exact signatures/accounting, required checks, native integration and complete cleanup.
- [x] T089 Execute a fresh coherent original-reference644 cohort including new retry/checkpoint/rollback profiles, retain all failures and runtime/cleanup/timing provenance, derive actual gate coverage and update the methodology/blind-spot report without waivers or historical report merging.
- [x] T090 Correct source-proven pool genesis rounding and normal pending exact-inclusion timing after the completed report; preserve failures, add meaningful regression coverage, run required checks and fresh owned components without changing644 or reference authority.
- [x] T091 Preserve native funding diagnostics and recover only independently proven orphaned private fixture payments by bounded identical-byte replay; verify guards, required checks and a fresh complete rollback workflow without altering wallet submissions.
- [ ] T092 Diagnose observed duplicate confirmed/pending history through quiescent live evidence and actual pinned Haskell resubmission functions; preserve strict failures, source provenance and a local unposted issue draft without changing644 or reference authority.
- [x] T093 Validate the proposed submission-state guard in an isolated full Haskell build with the existing signed-expiry correction, meaningful regressions, required source checks and fresh strict corrected-runtime live evidence; retain the original baseline and all authority questions.
- [x] T094 Execute a fresh coherent37-report corrected-runtime644 cohort with all required checks, explicit original-oracle/corrected-target provenance, unchanged gate and complete cleanup; update the report without promoting source authority or merging earlier results.
- [x] T095 Correct the test-only fixture CLI interpreter resolution after the frozen cohort, preserving all strict replay modes; verify development and sandboxed Nix package checks with the original failed log retained.
- [x] T096 Prevent competing-producer fixture loss during normal pending DELETE/reappearance with verified selective pidfd resume and guaranteed cleanup; retain exact admission/inclusion assertions, real-process regressions, failed evidence and fresh live/full-check validation.
- [x] T097 Diagnose and narrowly recover a proven pre-wallet owned-cluster port shortage with one fresh attempt, strict identity/shape/cardinality guards and complete cleanup; retain failed evidence and verify fresh checkpoint/full checks before coherent replay.
- [x] T098 Resolve the explicit complete-status review, implement only the selected policy with guarded original preservation and regressions, then verify full checks and a fresh coherent37-report packaged-CLI gate without historical merging or authority promotion.
- [x] T106 Deliver and qualify a typed Rust top-level executable specification runner with embedded profiles/corpora, configurable candidate HTTP/internal adapter and pinned independent oracles, all37 owned profiles, strict final643 gate, executable/attempt/cleanup provenance and no historical imports or hardcoded temporary paths.

T011/T030/T032/T069/T098/T106 completion is backed by evidence/reviewed-executable-643-20261106:the actual packaged Rust conform command from/tmp runs all37 fresh reports,3808/3808checks and42/42attemptedcomponentsPASS,strictactive643/643gatePASS. Full211Rust/Nixchecks,unchangedidentities,nativeintegrationsandfinalownedprocessabsencepass. All646 effective documented obligations were reviewed;ONLY3source-stale responses retired by explicit2026-11-06 approval. Historical644 evidence is unchanged. Source5d5b75e1b4/fingerprintca899c8620fb5cee45a7a7b0120d59c6f327095513f0f9989c7ac611d624f66d. Corrected8fcb target remains nonauthoritative versus original2fc oracles; export remains a review draft. T092's additional original-defect quiescence investigation remains open outside the complete active catalogue.
- [x] T099 Execute a fresh coherent37-report packaged-CLI current644 cohort with the validated fixture corrections while the separate contract review remains pending; preserve all results, timing, cleanup and authority boundaries.
- [x] T100 Identify and narrowly correct the actual release-only node-discovery filesystem race with precise diagnostics, strict ownership/readiness regressions, full checks and fresh packaged control/live execution before complete replay.
- [x] T101 Execute a fresh coherent37-report current644 cohort using the fully qualified Nix release package; retain exact gate, timing, runtime/oracle/genesis identity, native integrations and process absence without component merging or applying unanswered policy changes.
- [x] T102 Prevent native fixture funding loss with an early single nonretiring producer and nested pause ownership; preserve strict failed evidence and all wallet assertions, verify real-process regressions/full checks and fresh packaged execution before coherent replay.
- [x] T103 Execute the fresh37-report current644 cohort with the fully qualified early-lease package; retain exact source-bound results, failures, native/runtime/genesis/cleanup/timing proof and updated human/specification report without changing unanswered policy.
- [x] T104 Verify the complete mixed confirmed/pending/expired history list/get/order/limit/deletion matrix in the real expiry workflow, with independent native proofs and credit only after cleanup; validate regressions/full checks/fresh packaged execution and a new coherent gate without relabeling old evidence.
- [x] T105 After packaged history qualification, execute a fresh frozen37-report unchanged644 cohort; preserve actual gate/draft/timing/provenance/native controls/cleanup and update the report without historical merging or applying unanswered contract policy.

T029/T031/T046/T104/T105 completion is backed by evidence/proposed-history-combined-644-20261105:37 fresh reports,3810/3810checksPASS,643/644strictgateFAIL only original shared-creation500, no unexecuted semantic cases. Full203 Rust/Nix checks and79-check packaged history qualification pass. Actual native integrations/owned cleanup pass. Corrected8fcb target remains nonauthoritative versus original2fc contract/oracles. T011/T030/T032/T069/T092/T098 remain open; no complete-contract or source-authority approval is inferred.
