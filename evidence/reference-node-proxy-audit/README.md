# Actual node connection-control audit

Source49447b88a7, pinned Haskell2fc5c383 runtime, Conway/magic42, node11.1.3 and CLI11.2.3.0. Fresh cluster /tmp/wc-proxy-QdNgf3, with no wallet service launched for this control audit. receipt.json passed and explicitly count_as_conformance_evidence=false.

A real cardano-cli exchange through the byte relay matched the independently queried direct tip at height44/slot118. Pausing/draining then rejected a new CLI query without admitting it upstream, while the direct node advanced to height45/slot121. Resuming allowed a fresh real exchange matching the new direct tip. Counts:2admissions before pause,1rejection,4admissions total after reconnect,0upstream failures/worker panics. The proxy socket was removed and the direct node remained queryable after teardown.

This proves the connection control against an actual node, not wallet behavior. The separate registered wallet disconnection run subsequently used the same cluster; its report has its own source/fingerprint and remains separate. After both operations, the cluster was terminated and all six observed cluster/node PIDs were absent (shutdown.txt). No historical report is relabelled or combined here.
