# Coherent Byron password checkpoint

**586 of 643 mandatory obligations are covered; 57 remain missing.** All 2,121 registered checks passed: 522 differential HTTP checks, 1,223 actual Haskell internal cases and 376 live-node checks. Independent node integration passed after the registered workflows. The 24 reports share one target, environment and fingerprint. Gate exit 1 records incompleteness.

Assertion source: `6469a407d0`. Fingerprint: `f3cbfab61a6e5a57059e252dff0d95e835048800e2b0c9a4accca9e4f22135b9`. Environment: `source-2fc5c383-conway-node11.1.3-byron-password`.

The newly covered obligation is `api:putByronWalletPassphrase:status:403`. The expanded family suite passed 102 cases. Random, Icarus, Trezor and Ledger mnemonic wallets reject an incorrect old password with the exact Haskell code, message and wallet-id information. Per-service passphrase metadata and the complete address array remain unchanged. Correct password updates succeed with an empty 204 response; the obsolete password subsequently rejects and the replacement password authorizes a second rotation. The original 74 cases remain, including private-key wallet creation. See the sibling source audit for the implementation path.

The family suite ran first, followed by eight other HTTP suites before funding. Read-only queries observed empty Shelley, Byron and shared wallet lists on both services afterward. Manual service A was stopped and reaped, then the same pinned executable and URL used a new owned database behind the socket relay. Service B remained the external signer. This transition is not restart-persistence evidence. All supported live profiles passed, including disconnection/reconnection, history, balancing, collateral, assets, payments and shared signing. Public receipts are retained in the live report. Protocol parameter snapshots match; this does not establish update or era-transition behavior.

**The full offline harness is not green.** The filtered run passed 118 tests and excluded the one unchanged known input-set-parser failure. Focused tests, formatting and isolated Nix Clippy/format checks passed. No full Cargo test or Nix package pass is claimed. See `harness-status.json`. Nine correction proposals remain unapplied; their exact contents and review context are preserved in [the previous checkpoint's review bundle](../reference-shared-guards-coherent/PENDING-REVIEWS.md).

The independent faucet test also ran once during the live run; that extra execution is not counted in conformance totals. The retained node-integration report is the separate passing execution after all registered workflows. The post-integration gate agrees exactly with the initial gate.

The owned service/relay cleaned up, service B and the cluster exited with status 130, and all eight observed external PIDs are absent. No cardano-wallet process remains and the proxy socket is removed. Private databases and service logs remain in the private scratch directory; no live credentials were copied into public evidence.

`artifacts/behavioral-specification.byron-password-coherent.draft.json` remains an incomplete, non-authoritative review draft. Historical evidence is preserved separately.
