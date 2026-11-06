# Many-input inspector failure

The new offline many-input boundary regression fails before live execution because transaction::inspect rejects indefinite spending-input arrays. The pinned ledger uses that encoding for sets larger than23; the separate signed-size validator already handles it.

The saved cargo test log reports39passing library tests and1failure. The full suite and subsequent checks were not completed in this run. No many-input live evidence or additional obligation coverage is claimed.

source-sha256.txt binds the failing implementation and unchanged inspector. parser-correction.proposed.json preserves the exact proposed correction awaiting user approval. The original inspector remains unchanged.

A fresh cluster was started while offline checks ran, then terminated after the failure. No wallet services, funding or live profile execution occurred. shutdown.txt verifies absence of the cluster and all five node PIDs observed in its process snapshot.
