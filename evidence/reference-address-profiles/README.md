# Address and script component evidence

All56 frozen profiles pass against the pinned source-built Haskell adapter, with no modified/unregistered inputs. Rust47 tests, all-target/all-feature Clippy, formatting and isolated Nix checks pass. The corpus includes actual ledger native-script evaluation, canonical domain-prefixed script bytes/hashes, pointer u64 boundaries, shared/base/reward credentials, Byron CRC/authentication rejection, raw codecs, CIP-129 and wallet asset fingerprints. See [build and validation instructions](../../docs/reference-addresses.md).

Independent checks stopped initial capture on two test-adapter mistakes before any corpus was saved: a reward address was rendered with the generic addr HRP, and an address-level base58 parser rejected non-address raw bytes. The adapter now uses stake/stake_test HRPs for reward bytes and the underlying base58-bytestring codec for raw operations. The expectations remain strict, and regressions preserve both distinctions. These were adapter setup failures, not Haskell wallet incompatibilities.

This is a current-fingerprint component subset, not a complete gate or live-node run. Historical coherent reports remain unchanged and cannot be mixed with this report. All893 internal vectors and the remaining semantic/API/live-state obligations remain mandatory at the final gate.
