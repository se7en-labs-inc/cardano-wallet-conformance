# Coherent pinned-source reference validation

The source baseline is wallet revision `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. Build the executables through that checkout's pinned flake:

```sh
nix --quiet build --no-link --print-out-paths \
  /absolute/path/to/cardano-wallet/master#legacyPackages.x86_64-linux.hsPkgs.cardano-wallet-application.components.exes.cardano-wallet \
  /absolute/path/to/cardano-wallet/master#local-cluster \
  /absolute/path/to/cardano-wallet/master#cardano-node \
  /absolute/path/to/cardano-wallet/master#cardano-cli
```

Check the checkout revision before building. Record output paths, derivations and SHA-256 digests. The unwrapped wallet executable reports `v2026-09-16 (git revision: 0000000000000000000000000000000000000000)`; its source identity comes from the pinned Nix derivation, not that version string. The matched runtime is node11.1.3 and CLI11.2.3.0, from node revision `938cba990357ae7c4b7f95c8f75dd9d31174bbeb`. A node11.2 upgrade on another branch is a different baseline.

Use [local-cluster setup](local-cluster.md) with the source-built cluster, node and CLI, Conway era, two separate wallet databases and source-built wallet executables. Run all eight HTTP suites sequentially before the funded workflow: read-only wallet-list cases require empty lists and must not overlap another suite's temporary wallets. The source-component helpers use the exact wallet/component versions documented in [the component adapter](reference-adapter.md) and [the credential adapter](reference-credentials.md). They share the runtime implementation's source identity; their operations use the internal adapter transport rather than HTTP. Bind all reports to one environment and implementation target, retaining this distinction explicitly in runtime metadata.

`fixtures/http-network.json` enables bounded epoch alignment for network information. Every response must have `next_epoch.epoch_number = network_tip.epoch_number + 1`. If the two independently sampled network-tip epochs differ, the runner takes at most three additional read-only sample pairs, separated by100 ms. Every sample receives status, schema and assertion checks. Once epochs match, the normal differential comparison remains strict for next-epoch number and timestamp. Bad successor values, schemas, assertions, transport failures and same-epoch timestamp mismatches fail without this retry. The original boundary failure is preserved in `evidence/reference-source-epoch-boundary/`.

Run `cargo test --features live-node-tests --test node_integration` through the development shell with `CONFORMANCE_CARDANO_CLI`, `CONFORMANCE_NODE_SOCKET`, `CONFORMANCE_NODE_MAGIC` and `CONFORMANCE_FAUCET_URL` set to the trusted CLI, socket, network magic and faucet. Record it separately from report-producing live checks and from mock tests. Retain public tip samples, genesis/config hashes and protocol parameters; exclude private cluster files. Stop only observed owned process IDs and verify their absence after collecting evidence.

A combined gate or specification export must use only reports with the current fingerprint and the same target/environment. Historical release/component reports remain useful evidence but cannot be mixed into that gate. The export is a draft; missing semantic obligations remain mandatory and the Haskell behavior remains the authority.
