# Passing confirmed deletion preservation component

Source4d726f7259 against pinned Haskell2fc5c383, Conway magic42, node11.1.3/CLI11.2.3.0. Fresh cluster /tmp/wc-forget-F3godn and owned foreground wallet behind its node relay.165registered live checks pass,0failures/no unregistered inputs. Suitea507142d88d529d34b9ac2d1245e3876ace4f281fef1edee32b61a32682995ea, environment source-2fc5c383-conway-node11.1.3-confirmed-delete-initial.

Both freshly submitted metadata self-payments confirm, then reject DELETE with documented403 and exact transaction_already_in_ledger/code/message/info. Each remains retrievable with unchanged stable transaction fields, post-fee balance, wallet UTxO snapshot and all affected node UTxOs. Final history/filter/metadata/node accounting continues to pass. Public payment receipts retain the exact rejection and preservation snapshots. Pending/expired deletion204 is not claimed.

The component gate now covers26/643,617missing, expected exit1 for incompleteness. This closes the real documented403 obligation but cannot be combined with another fingerprint. A complete coherent replay is still required before reporting an updated aggregate. Two history mutation regressions and34harness tests pass, along with formatting/all-target/all-feature Clippy/bins/treefmt/isolated Nixclippyfmt. Full cargo/Nixpackage checks remain unresolved due the separate pending input-array inspector regression. All nine proposed corrections remain unchanged.

All three owned wallets were deleted, the service stopped/reaped and proxy removed. The cluster session exited130 after SIGTERM; all six observed cluster/node PIDs are absent and no cardano-wallet process remains. Private DB/logs remain in the0700scratch workspace.
