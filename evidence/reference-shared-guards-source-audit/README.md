# Source audit for shared and metadata structure guards

Pinned source `2fc5c383c94bb907deaa0cd27b1b407f86224b6c`. Exact excerpts and full-file digests are retained.

The API parser rejects empty cosigner maps, so the creation probes use a valid foreign account public key instead. Template validation requires the wallet's own key in payment and delegation templates. Failure maps to the exact shared_wallet_script_template_invalid403 with a local, deterministic reason. The positive account-key export and later pending-peer creation remain part of the same HTTP suite.

Shared signing invokes withRootKey before signing. Wrong-password errors carry wrong_encryption_passphrase403, the complete message and info.wallet_id. Both funded cosigners are tested before ordinary partial/merged signing and real node confirmation.

Shelley decode applies metadata decryption only when metadata exists. A plaintext list at label674 lacks the required basic encryption marker and returns ErrMissingEncryptionMethod before cryptographic decryption/adjustment. Its exact invalid_metadata_decryption403 is distinct from the pending ordered-map crypto failure and shared TODO500. This audit alone supplies no runtime coverage.
