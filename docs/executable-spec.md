# Running the executable wallet specification

The specification consists of the packaged Rust assertions, embedded HTTP schemas/cases, internal vectors and live state-transition profiles. The JSON export records their version/fingerprint and provenance. A new implementation runs against those executable rules through its public HTTP service and a thin JSON adapter around its actual internal functions. Lean is not required.

Build the pinned Nix package and run its complete entrypoint:

```sh
nix build --out-link result
./result/bin/wallet-conformance conform \
  --config /absolute/path/implementation.json \
  --workspace /absolute/path/fresh-private-run
```

The workspace must not exist. It contains private node/wallet databases, keys and logs: do not publish it wholesale. The runner materializes its embedded corpora there, so execution does not require the source checkout as its working directory. It owns the services and clusters it starts and refuses occupied service listeners. CLI arguments are configurable; CLI compatibility is not required.

Start with [the configuration example](../fixtures/execution-config.example.json). Replace executable/config paths and compute SHA256 pins for the independent tools. Supply one `adapter` for the candidate. Its protocol and mandatory operations are defined in [adapter.md](adapter.md); it must call the implementation's real internals. Unsupported operations fail. `reference_adapters` is an explicit qualification-only alternative covering all16 internal profiles with independently pinned helpers; it is not required of a new implementation. Absolute file arguments to those reference adapters also require `adapter-argument:PROFILE:INDEX` entries in `trusted_sha256`. Candidate adapter arguments can include subcommands/options and are passed as arguments, never shell command text.

The trusted tools are the pinned native node, cardano-cli, local-cluster factory, original Haskell reference wallet, actual Haskell key oracle and OpenSSL. Use the existing pinned [reference build instructions](reference-adapter.md). The candidate and its dependencies cannot substitute for these oracles. Candidate executable and adapter identities are observed before execution and must remain unchanged through the run. Reference/tool pins are required, not inferred from a filename.

Wallet launch arguments must contain exactly one whole-value `{database}`, `{node_socket}` and `{byron_genesis}` placeholder; environment entries must be literal. The local-cluster launch uses whole-value `{cluster_configs}`, `{cluster}`, `{socket}`, `{funds}` and optionally `{logs}`/`{workspace}`. Services must remain in the foreground. The current controlled fixture uses network magic42 and explicit loopback URLs. Keep candidate, reference, faucet and any UI ports distinct. No production wallet or adopted external process is controlled.

Every invocation runs the compiled [execution profile inventory](../fixtures/execution-profiles.json):

- Nine differential HTTP suites against the candidate and independent Haskell reference.
- Sixteen internal-vector groups against the candidate's adapter, currently1241 assertions.
- Twelve real-node profiles: funded operations/restart, disconnection, DRep queries, pool lifecycle, parameter enactment, normal pending/deletion, expiry/mixed history, Byron pending/deletion, automatic retry, checkpoint restoration, native rollback/reapplication and a continuous Babbage-to-Conway transition.

The runner creates separate standard/committee/owned/fork/era fixtures and fresh wallet state. Standard setup uses the verified earliest nonretiring producer and registers that active pool for the reward workflow. Pool lifecycle retains its own retirement/activation controls. Full native probes run after standard and committee profiles; the remaining owned profiles retain their existing final native probes and cleanup assertions. Exact schemas, errors, signatures, selection/conservation/fee laws, history/state transitions, ledger accounting and epoch/era activation remain executable requirements.

There is no skip-profile option or historical-report import. Failed or missing cases, unsupported adapter operations, changed tools, incomplete cleanup, or an incomplete gate prevent success. Each attempted component is retained in `attempts.json`. A setup error produces an incomplete result and preserves the available reports; it cannot become a passing wallet observation.

Inspect these outputs:

| Output | Meaning |
| --- | --- |
| `result.json` | Overall complete/incomplete result, counts, setup/execution errors and elapsed time |
| `coverage.json` | Strict active catalogue coverage; null if no report could be produced |
| `reports/` | Fresh public HTTP/internal/live assertion receipts |
| `specification.json` | Embedded executable-contract export before validation |
| `validated-specification.json` | Same contract with this run's actual coverage and reports |
| `identities.json`, `run.json`, `attempts.json` | Binary/config/corpus binding and execution provenance |
| `standard-cleanup.json`, `committee-cleanup.json` | Successful owned runtime cleanup receipts; other profiles retain cleanup inside their reports |

Exit0 requires all37 fresh reports, every attempted component passing, unchanged identities and a complete active gate. Exit1 means incomplete/failed conformance; exit2 means an invalid invocation/configuration or an unrecoverable report-validation error. These outputs are trusted-run evidence, not cryptographic attestations against a malicious harness or service running as the same OS user.

The reviewed active catalogue has643 obligations after explicit retirement of three source-stale responses from the complete646 documented inventory. The original OpenAPI, retirement decisions and historical failed644 gates are preserved. A complete active gate does not relabel them as644/644, automatically promote the corrected Haskell target, or prove equivalence for every possible input/schedule/platform/era. The generated export remains a review draft until separately adopted as authority. Current qualification results are recorded in [the status report](conformance-suite-report.md).
