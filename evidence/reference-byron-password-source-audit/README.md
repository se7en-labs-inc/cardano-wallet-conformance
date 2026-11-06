# Byron password source audit

Pinned source: `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. Exact source hashes and excerpts accompany this record. The handler delegates password updates to the wallet implementation. Root-key authentication validates the supplied current password before re-encryption and metadata updates. Both legacy V1 and V2 credential checks occur before the callback that changes the root key. The error mapping returns HTTP403 with `wrong_encryption_passphrase`, the exact message and the wallet id.

T057 exercises this behavior for all four mnemonic styles without modifying Haskell source. The coherent live HTTP results are in [the Byron password checkpoint](../reference-byron-password-coherent/README.md).
