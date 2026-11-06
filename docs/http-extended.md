# Extended unfunded HTTP matrix

`fixtures/http-extended.json` contains70 main cases and five owned-wallet cleanup cases. Generate it reproducibly with `generate-extended-api`. The fixture uses actual public Conway transaction CBOR and account keys, valid bodies for unknown-wallet requests, owned Shelley/random-Byron/Icarus/shared/watch-only wallets, duplicate409 checks, policy keys/IDs, stake-key queries, hardened random-address creation and imports, active shared-wallet restrictions, unfunded transaction/migration paths, settings, maintenance and malformed URL/body errors.

```sh
nix --quiet develop --command cargo run -- http \
  --target http://127.0.0.1:18790/v2/ --reference http://127.0.0.1:18791/v2/ \
  --environment source-2fc5c383-conway-apimatrix \
  --suite fixtures/http-extended.json --report extended-http-report.json
```

The user approved the narrow observed request/schema corrections described in [known defects](known-spec-defects.md). The initial74-case run (68pass/6fail) and exact inputs remain in [preserved failure evidence](../evidence/reference-extended-initial-failure/README.md). Correcting valid request encodings retains the404/201/403 assertions; the delegation-fee case also asserts the actual no_utxos_available code. Maintenance's unreachable404 is replaced with the observed malformed-JSON400 in the correction overlay, while the original OpenAPI remains unchanged. The suite owns only wallets whose creation returned201.

Run all eight HTTP suites sequentially before funded workflows when using a fresh pair of wallet databases. Existing wallet-list cases require empty databases; this suite cleans up its owned wallets. Funded positives, actual chain transitions and a coherent final643-obligation evidence gate remain separate.
