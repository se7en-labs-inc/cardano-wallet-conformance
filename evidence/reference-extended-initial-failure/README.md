# Preserved initial extended HTTP failure

The exact initial suite and report are retained unchanged:74cases,68pass,6fail,zero unregistered inputs. The pinned-source Conway cluster was /tmp/wc-70007-apimatrix with separate source-built Haskell wallet services on18790/18791.

The balance request omitted actual required inputs/redeemers arrays and returned400 before wallet lookup. The soft Byron address index12345 was rejected with400 because the parser requires2147483648..4294967295; address-dependent imports could not expand their capture. The empty-wallet stake-fee response was403 no_utxos_available, outside the original schema's sole cannot_cover_fee alternative.

The user approved the exact fixture and narrow schema corrections before rerunning. The original statuses remain strict and the original OpenAPI is preserved. This failed report is historical evidence and cannot close conformance obligations or be mixed with later fingerprints. No real funded wallets were used.
