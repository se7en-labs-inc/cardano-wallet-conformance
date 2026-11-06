# Actual wallet collateral and mint/burn selection evidence

All34 registered profiles pass against the pinned-source wallet selection wrapper, with zero failed or unregistered inputs. The63 offline tests pass through the isolated Nix package check; all-target/all-feature Clippy, formatting and isolated Nix Clippy/fmt checks pass. See [build and profile scope](../../docs/reference-wallet-selection.md).

The actual wrapper filters native assets out of collateral and honors explicit candidate availability, percentage ceiling, input caps, minimal/optimal seeded selection and ordinary/collateral overlap. Mint/burn extra-value cases receive independent exact conservation checks. These explicitly constant-fee/minimum-change component callbacks do not establish ledger-dependent fee estimates or transaction admission.

Initial capture stopped before writing on two fixture classification assumptions. The retained probes show that empty ordinary UTxO with a payment is balance_insufficient, while no outputs/zero fee is empty_utxo; output-covered ADA with a fee shortfall is unable_to_construct_change. The final corpus tests each condition separately with its strict actual error and independent budget proof. No wallet/callback algorithm was changed.

The current internal inventory is1022 vectors. This subset does not establish the complete643-obligation gate, real collateral-return support or real mint/burn submission; the final coherent evidence run remains mandatory.
