# Actual wallet witness and certificate evidence

All28 frozen profiles pass against the source-built pinned Haskell adapter with zero failed or unregistered inputs. The58 offline tests pass through the isolated Nix package check; all-target/all-feature Clippy, formatting and isolated Nix Clippy/fmt checks pass. See [build and capture instructions](../../docs/reference-writer.md).

Actual wallet signing merges two distinct keys, preserves existing signatures, deduplicates repeated signing and skips unresolved inputs. Rust independently verifies every signature and the unchanged transaction body. Bootstrap witness attributes and chain codes, native script witness serialization, stake deposits/refunds and DRep certificates have independent byte checks. Actual documented Dijkstra/missing-deposit exceptions remain explicitly represented.

Review caught that initial Shelley/shared merge fixture keys were intentionally equivalent. Before freezing the corpus, the second key was changed to a distinct independently captured Ledger root; capture and regression checks now require two distinct verified witnesses. The initial scratch capture remains outside the registered corpus and was never admitted as conformance evidence.

This component subset cannot certify643 obligations. All987 internal vectors plus the complete HTTP/funded/state matrix remain required under one final fingerprint; historical reports stay unchanged.
