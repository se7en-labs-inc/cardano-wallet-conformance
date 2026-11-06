# Source key derivation evidence

Harness710fd203d8 executes764 supported internal cases under one fingerprint:133 key/root/signature cases,578 cryptography/selection/encrypted-root cases and53 actual wallet/database credential cases. All pass, with no unregistered inputs or execution failures. Rust41 tests, all-target/all-feature Clippy, formatting and isolated Nix checks pass. The key adapter builds with -Wall -Werror against the pinned source toolchain.

The internal-only gate covers21/643 requirements and leaves622 missing. It closes the named Byron-root, derivation-boundary and public/private derivation requirements. Extended signing also needs its public HTTP metadata-signature evidence. Remaining families retain named unexecuted cases, including nonempty generation factors and hardware roots. Gate and specification --require-complete correctly exit1. This evidence set does not execute live cases and must not be mixed with historical fingerprints.

The local draft is artifacts/behavioral-specification.key-internals.draft.json. It remains incomplete and non-authoritative. See [key adapter reproduction](../../docs/reference-keys.md) and runtime.json for source/binary provenance. No cluster is owned by these internal adapters.
