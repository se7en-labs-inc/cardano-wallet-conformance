# Preserved native-asset prefix assertion failure

The basic live transfer/restoration flow and asset policy derivation, mint construction and signing passed. The new profile failed its exact error-message prefix assertion after the intentionally corrupted policy witness was rejected by the real node. The59 recorded checks include58passes/1failure; all owned wallet cleanup passed.

Actual status500, JSON media and created_invalid_transaction code passed their strict assertions. Node logs show ConwayUtxowFailure InvalidWitnessesUTXOW for the deliberately corrupted policy key. The prefix assertion incorrectly expected the newline written by ErrPostTxValidationError's message constructor. Pinned Api/Http/Server/Error/IsServerError.hs apiError applies T.replace "\n" " " before JSON encoding. The correction uses that exact single-space prefix, retains the same status/code/cause and same actual-ledger approach, and preserves this report unchanged. This is a test expectation correction, not an accepted alternate response or relaxed comparison. No native mint/burn conformance is established by this failed run.

Private runtime data and raw logs remain excluded. A separate rerun records validation after correcting the source-grounded prefix. The original OpenAPI remains unmodified; this500 is a supplemental strict source behavior profile.
