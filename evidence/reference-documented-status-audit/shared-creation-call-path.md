# Shared creation error: focused pinned-source audit

Read-only audit of original revision `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. This is source evidence for review, not a live route pass, a contract correction or a formal unreachability proof.

- `lib/api/src/Cardano/Wallet/Api/Http/Shelley/Server.hs:1269`: `postSharedWallet` dispatches to root-private-key or account-public-key creation.
- The returned shared-wallet representation is built by `mkSharedWallet` at line1490. Pending wallets return their incomplete representation directly. Active wallets fetch cached rewards at line1517; the adjacent source comment states this returns zero when no balance is found.
- `lib/wallet/src/Cardano/Wallet.hs:1623`: `fetchRewardBalance :: forall s. DBLayer IO s -> IO Coin`. Its implementation atomically reads cached delegation rewards; the result is not an `Either ErrFetchRewards Coin`.
- `ErrFetchRewardsMissingRewardAccount` is declared at Wallet.hs5031 and mapped to500/`missing_reward_account` at Api/Http/Server/Error.hs1012. A focused search of all `lib` finds those two occurrences, with no production construction expression.
- `handleRewardAccountQuery` at Wallet.hs1839 does accept an `Either ErrFetchRewards Coin`, but its current caller in `manageRewardBalance` passes `Right query`. Even its `Left` branch logs/ignores the error instead of throwing it through the shared-creation HTTP handler.
- `ErrReadRewardAccountMissing` has a separate501 mapping with the same serialized error code. It is a distinct error type/status and cannot satisfy the shared-creation500 obligation.

Consequently, missing a shared delegation template is not established as a valid trigger for the documented500. Injecting a constructor, altering a database or returning a synthetic proxy error would not demonstrate the original route's behavior. No such evidence receives credit. The original OpenAPI and current644 requirements remain unchanged; the explicit response-policy proposal remains unapplied.
