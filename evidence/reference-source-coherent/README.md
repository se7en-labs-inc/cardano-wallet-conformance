# Pinned-source baseline

At harness revision3bb8415486, all411 differential HTTP cases,48 funded real-node checks and631 internal adapter cases passed under the same fingerprint, target and source-bound environment. The independent real-node faucet/UTxO integration also passed. The mock/independent Rust test suite passed38 tests; Nix default build, Clippy and formatting checks passed.

`runtime.json` records the actual binaries and source binding. HTTP endpoints used separate databases on one advancing Conway cluster; all seven HTTP suites ran sequentially before the funded workflow. Internal helpers invoke the pinned wallet/component code through JSON, not through the HTTP endpoints. Both service binaries are Nix-built wallet source2fc5c383; the unwrapped executable embeds a zero Git revision, so the source claim is backed by its pinned derivation. Node11.1.3 and CLI11.2.3.0 come from the matching wallet-flake runtime input. Public tip samples, protocol parameters and configuration hashes are retained; private cluster data is excluded.

`coverage.json` covers440/643 mandatory obligations with203 missing, no execution failures and no unregistered runtime inputs. Gate and specification `--require-complete` both correctly exit1. The local generated draft is `artifacts/behavioral-specification.source-2fc.draft.json`; it remains incomplete and non-authoritative. Historical reports are untouched and excluded from this gate. The preserved epoch-boundary failure is in the sibling `reference-source-epoch-boundary` directory.

Reproduction details are in [the source-runtime guide](../../docs/reference-source-runtime.md). Owned wallet and cluster processes were terminated after validation and absence checked with an exact scratch-path process match.
