# Confirmed contract defects

The unmodified OpenAPI source is retained under `fixtures/api/openapi.yaml`.

1. `x-transactionInputsGeneral.items.oneOf` contains an outside-wallet branch requiring only `id` and `index`, and an inside-wallet branch requiring those fields plus `address`, `amount` and `derivation_path`. Additional properties are permitted, so every inside-wallet input matches both branches. A valid Haskell `decodeTransaction` response therefore fails strict JSON Schema validation at `/inputs/0`. This was observed on the SHA-256-verified v2026-09-16 release, wallet revision `33fcb5e4104db4d0979669a1adc9f5b782acd1c0`, node 11.1.1, on a real Conway cluster. The schema's output/withdrawal/certificate unions require the same audit; they are not automatically waived.
2. `submitTransaction` references `responsesPostExternalTransaction`, which omits the 403 missing-witness response explicitly asserted by the Haskell integration case `TRANS_NEW_SIGN_02` in `lib/integration/scenarios/Test/Integration/Scenario/API/Shelley/TransactionsNew.hs`.

The user selected Haskell behavior as the current authority on 2026-11-02. Narrow corrections are recorded and applied before YAML alias expansion; the original source remains unchanged. Global `oneOf` weakening and blanket schema bypasses remain prohibited. The specification generated from the conformance suite will become authoritative in the future.

3. The 400 responses of `listTransactions`, `listByronTransactions` and `listSharedTransactions` enumerate only range/withdrawal errors, omitting the ordinary `bad_request` produced for malformed wallet identifiers. All three were observed in the generated rejection suite.
4. `listStakePools` documents only `query_param_missing` for 400, but malformed `stake` values return `bad_request` at the same status. This was observed with `stake=invalid`.

The checked correction manifest is `fixtures/api/haskell-corrections.json`. The funded reference workflow now passes through strict decoding, signing, submission and independent ledger confirmation with those corrections. The original failing reports remain historical evidence; they are not rewritten.

5. `postAccountKey` omits 403 entirely. Two isolated v2026-09-16 services return 403 `wrong_encryption_passphrase` after a successful passphrase change and 403 `no_root_key` when deriving a private account key from a restored public-key wallet. The correction adds only those two error alternatives.

The same key matrix confirms that mnemonic and account-public-key restoration produce different wallet IDs for the same derived addresses. Haskell derives the former from the root extended public key and the latter from the account extended public key; both IDs are Blake2b-160 over all 64 public-key/chain-code bytes (`WalletKey.digest`, Shelley HTTP server restoration paths). Independent Rust hashes of frozen Haskell keys assert both IDs. This is preserved behavior, not an OpenAPI correction.

Public-key-only restoration omits the `passphrase` property entirely; it does not serialize it as null. The watch-only HTTP case asserts absence explicitly, in addition to checking its independently computed wallet ID and exact address equality with mnemonic restoration.

6. Shelley and Byron single-asset lookups return 404 `no_such_wallet` for an unknown wallet; the inherited asset response schema permits only `asset_not_present`. The correction adds a distinct `no_such_wallet` alternative, retaining the exact asset-missing error.

The status matrix retains Haskell precedence explicitly: several 204/NoContent endpoints ignore unsupported Accept and proceed to wallet lookup or request-body parsing; importing one Byron address has no request body and ignores supplied malformed JSON. Quitting a pool uses a DELETE request with a required JSON passphrase body.

7. A single Byron address import returns 404 `no_such_wallet` for an unknown wallet, even with an unused malformed body; its published response schema omits 404. The correction adds the existing wallet-not-found response anchor.

8. `putByronWallet` inherits the Shelley `ApiWallet` success schema, which requires a reward balance. The Haskell `PutByronWallet` Servant type returns `ApiByronWallet`; random, Icarus, Trezor and Ledger rename requests all return the Byron balance shape. Correct only this operation's 200 schema, explicitly preserving all error anchors.

9. Delete-wallet (Shelley/Byron/shared), delete-transaction (Shelley/Byron) and wallet passphrase-update (Shelley/Byron) endpoints use Servant `DeleteNoContent` or `PutNoContent`, so they do not negotiate a response representation. Remove their inherited 406 responses. Live requests with unsupported Accept successfully return 204 with zero body bytes for all three wallet families and Shelley/all four Byron passphrase updates; the retained unknown-wallet/malformed-body precedence cases also pass. The NoContent transaction deletion behavior is corroborated by both its Servant declaration and unknown-wallet precedence, but funded pending-transaction deletion remains a separate unexecuted positive obligation. Other NoContent operations are not corrected by inference.

10. Pool maintenance documents404, but its pinned handler (`Api/Http/Server.hs:445`) calls `forceMetadataGC` and returns NoContent without a NotFound branch. The actual implementation (`Wallet/Pools.hs:454`) resets GC state and restarts synchronization. Fresh real-cluster probes return204 for a valid request and400 bad_request for malformed JSON. The user approved replacing only this unreachable404 anchor with the observed400 anchor on2026-11-03. The original OpenAPI remains unchanged.

11. An empty wallet's delegation-fee request returns403 no_utxos_available through actual balance-error conversion (`Api/Http/Server/Error.hs:736`), but its schema permits only cannot_cover_fee. Add the existing no_utxos_available schema as a distinct alternative. Also, ApiBalanceTransactionPostData's actual nonoptional inputs/redeemers fields (`Api/Types.hs:1436`) are missing from the request schema's required list: actual JSON decoding rejects omission before wallet lookup. The user approved both narrow corrections. The initial74-case report and exact suite remain in evidence/reference-extended-initial-failure, including these failures and the invalid soft Byron address-index fixture. Hardened index corrections keep status assertions strict.
