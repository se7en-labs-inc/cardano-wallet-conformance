# Executable wallet specification: qualification and methodology

The reviewed active contract now passes **643/643 obligations (100%)**, with **3,808/3,808 checks across37 fresh reports**, no missing semantic cases and no failed attempts. The packaged Rust `conform` command ran from `/tmp`, outside the checkout, in **25 minutes22 seconds**. Its final gate was independently replayed against the copied evidence and matched exactly. [Full qualification](../evidence/reviewed-executable-643-20261106/README.md), [coverage](../evidence/reviewed-executable-643-20261106/coverage.json), [result](../evidence/reviewed-executable-643-20261106/result.json) and [execution totals](../evidence/reviewed-executable-643-20261106/summary.json) retain the proof.

This qualifies the executable specification against the separately declared corrected Haskell8fcb target, with original2fc HTTP/internal/adversary oracles. The corrected runtime has **not** become authority, the generated export remains a review draft, and each new wallet implementation requires its own conformance run. This is complete coverage of the reviewed finite catalogue, not universal equivalence for every input or schedule.

## What you run against a new implementation

```sh
nix build --out-link result
./result/bin/wallet-conformance conform \
  --config /absolute/path/implementation.json \
  --workspace /absolute/path/fresh-private-run
```

Use the [configuration example](../fixtures/execution-config.example.json) and [runner instructions](executable-spec.md). Supply the candidate's foreground HTTP launch and one thin JSON adapter around its actual internal functions. The independent node, CLI, factory, Haskell reference service, key oracle and OpenSSL are separately configured and pinned. Candidate CLI arguments are configurable; CLI compatibility is excluded. Lean is not required.

The executable specification consists of the Rust assertions, embedded HTTP schemas/cases, internal vectors and live state-transition profiles, with a version/fingerprint and machine-readable export. It is not merely a document or a list of endpoint names. The runner extracts its own corpus, drives owned fixtures, checks real behavior and returns a strict complete/incomplete result. It supports neither skipped profiles nor historical-report imports. Unsupported internal operations fail.

The qualified package has source revision `5d5b75e1b4`, executable SHA256 `80ba0b12a887eb431dcf3994fa928ceb396788adfa8a3890c725e3f6693b30f9` and assertion/corpus fingerprint `ca899c8620fb5cee45a7a7b0120d59c6f327095513f0f9989c7ac611d624f66d`. All211 Rust tests, formatting, Clippy, full Nix package and flake checks passed before execution.

## What the active obligations cover

| Area | Obligations | Scope |
| --- | ---: | --- |
| Public HTTP API | 561 | 96 operations:96 positive behaviors,90 negative behaviors,375 active response statuses |
| Cryptography | 25 | Hashes, signatures, derivation, mnemonics, passphrases, encrypted keys |
| Addresses and native scripts | 8 | Shelley, Byron, shared addresses, networks, encodings, script/policy hashes |
| Coin selection | 10 | Eligibility, conservation, change, assets, insufficient funds, size limits, seeded behavior |
| Transactions and signing | 16 | Serialization, witnesses, fees, minimum ADA, validity, metadata, mint/burn, collateral, staking, governance |
| Wallet behavior | 14 | Discovery, restoration, rollback, restart, retry, concurrency, credential migration, shared/watch-only wallets |
| Chain behavior | 6 | Production, confirmation, ledger accounting, parameters, era transitions |
| Cross-cutting API behavior | 3 | Transport, error precedence, other contract rules |
| **Active total** | **643** | Complete646 effective documented inventory minus three explicitly reviewed retirements |

A requirement can demand multiple named scenarios and many assertions. The gate requires every registered HTTP/vector case and every named semantic case, rather than accepting one representative result per family. Check counts include operational observations and can vary: this run has two fewer readiness `getWallet` observations than the prior3810 run, with the complete requirement/case set preserved.

## Methodology and independence

Original Haskell revision `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`, independent published vectors and explicit reviewed corrections define the current contract. The original OpenAPI remains unchanged. Known wallet defects are retained; they do not silently become required behavior or passing exceptions. Adoption of the generated specification as future authority remains a separate review.

The suite combines four layers:

1. **HTTP contracts and differential execution.** Exact statuses, media types, schemas, deterministic values, errors and state preservation are checked against expectations and a separate reference service. Agreement between two unexpectedly failing servers does not earn success. Funded workflows cover behaviors empty-wallet probes cannot establish.
2. **Actual internal functions.** Thin adapters call real key, encryption, signing, address, selection, codec, fee and accounting functions. Published/reference vectors define deterministic answers. Randomized selection must satisfy independent eligibility, uniqueness, conservation, fee and change laws; seeded behavior is tested separately. Standard BIP39 normalization and Haskell raw-password behavior are explicit profiles.
3. **Independent transaction validation.** Rust parses CBOR, hashes bodies, verifies signatures and reconciles credentials, inputs, outputs, fees, assets, withdrawals and certificates. OpenSSL checks encrypted metadata. Neither the candidate nor Pallas manufactures expected answers. Ledger acceptance alone cannot establish correct selection, change ownership, fees, metadata or witnesses.
4. **Real chain transitions.** Actual funding, mempool admission, signed submission and confirmation receive independent native queries. Owned process death, producer pauses and socket faults create conditions without editing wallet databases or inventing node responses. Rewards, retirement and parameter changes require real epoch activation.

Checkpoint restoration requires a real offered and node-accepted persisted intersection after offline advancement. Rollback requires actual native branches, an observed RollBackward, state reversal and reapplication of the original transactions. The era profile follows one continuous Babbage-to-Conway chain. Standard setup keeps the verified earliest nonretiring producer active and registers that active pool for rewards; no wallet transaction is replayed by the fixture.

Reports bind the same fingerprint, environment, target and reference revision. The gate rejects missing/failed/stale/mixed evidence, changed registered inputs and harness self-tests. Executable identities are checked before and after execution. A fresh private workspace prevents old-report imports. Each attempted component is retained; setup failures cannot turn into passing wallet observations.

## Actual qualification results

| Layer | Fresh result |
| --- | --- |
| Nine differential HTTP reports | 537/537 checks passed |
| Sixteen actual Haskell internal reports | 1,241/1,241 checks passed |
| Twelve real-node reports | 2,030/2,030 checks passed |
| All attempted test/setup components | 42/42 passed |
| Rust harness and Nix checks | 211 tests, format, Clippy, package and flake checks passed |
| Final native probes and owned cleanup | Passed; final broad exact-root process check empty |

The live reports cover funded operations/restart948, disconnection82, DRep6, pools120, parameters149, normal pending56, expiry/mixed history79, Byron180, retry108, checkpoint29, rollback224 and era49 checks. They exercise payments across wallet families, mint/burn, shared/watch-only signing, encrypted metadata, concurrent spending, input/size boundaries, discovery/history, voting, delegation, nonzero rewards, deposit/refund accounting, retirement, enactment and controlled recovery.

Automatic retry uses a real short-lived conflicting transaction: the target is rejected by the node, stays pending and later confirms without another wallet submission call. Mixed history compares pending/expired/confirmed list rows with separately fetched transaction records, exact ordering/global limits and post-deletion preservation. No nonexistent HTTP status selector is invented. All owned workflows retain their independent native and cleanup controls.

## Reviewed retirement and preserved failures

On2026-11-06 the user approved the complete646 effective inventory and retirement of only shared-creation500/`missing_reward_account` and two shared-template503/`wallet_metadata_not_found` responses. Source audit found declarations/mappings without production construction sites; that is not a formal unreachability proof. The [approved registry](../fixtures/api/retired-responses.json), [original proposals](../evidence/reference-documented-status-audit/status-policy.proposed.json) and [source audit](../evidence/reference-documented-status-audit/shared-creation-call-path.md) preserve the decision. Inventory now includes all200–599 responses, with regressions preventing future501/503/599 omissions.

No retired response receives an invented live pass or replacement obligation. The historical [643/644 gate](../evidence/proposed-history-combined-644-20261105/README.md) remains incomplete. Earlier639/641/632/641/642 results and their failures remain separate. No historical report is relabeled or merged into this643/643 result.

The suite exposed a genuine signed-expiry bug, filed as [issue5479](https://github.com/cardano-foundation/cardano-wallet/issues/5479), and captured duplicate confirmed/pending history for one transaction ID. Actual pinned functions demonstrate a delayed-callback mechanism; its precise live schedule and quiescent persistence remain unproven. The [duplicate-history draft](../evidence/reference-duplicate-history-first/upstream-issue.draft.md) is unposted. Corrected8fcb combines expiry and current-status-guard fixes; targeted Haskell tests pass, with one pre-existing pending API test. A full Haskell unit-suite pass is not claimed, and the corrected runtime is not promoted as authority.

Harness fixes addressed genesis rounding, exact confirmation waits, private fixture funding loss, interpreter resolution, port shortages, database readiness and competing producers. During this delivery, a Nix rebuild exposed a parallel ephemeral-port unit race; exclusive bound/non-listening socket reservations corrected the test controls without weakening production checks or skipping tests. Its failed log and the initial missing-runtime preflight are retained with qualification evidence.

## Remaining limits

Restoring missing runtime outputs regenerated the exact prior Nix derivations but produced different factory/wallet binary bytes. The precise cause is unestablished. Both old/new hashes, derivation provenance and explicit fresh-run pins are retained. Bit-reproducible runtime builds are not established.

The runner resolves the former manual37-profile orchestration gap, but trusted helper/runtime provisioning still requires pinned Nix builds and configuration paths. Owned controls and the flake currently target Linux/x86_64. Only Babbage-to-Conway is live-qualified; later codec fixtures do not establish later-era ledger acceptance. Native peer consensus adoption is outside the connection-switch rollback proof. Dedicated shared-expiry and retired-DRep regressions are not separately qualified; [issue5466](https://github.com/cardano-foundation/cardano-wallet/issues/5466) remains outside reproduced successes. Functional crypto conformance does not establish side-channel resistance.

Selected vectors, boundaries and concurrent schedules do not exhaust every possible script, external failure, adversarial input or future era. Reports are trusted-execution evidence, not cryptographic attestations against a malicious harness/service running as the same OS user. The future wallet must expose its real functions, run this complete workflow as the candidate and retain fresh evidence. A clean gate establishes conformance to this reviewed specification version's exercised requirements; broader tests should extend the versioned catalogue as new defects emerge.
