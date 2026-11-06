# Pinned node-disconnection source audit

Pinned wallet source2fc5c383c94bb907deaa0cd27b1b407f86224b6c. Exact excerpts/full-file digests are retained. The cluster HTTP control API exposes ready, step, switch and observe over startup phases; its handlers and phase type provide no running-chain forging pause, partition or rollback control.

Network.Implementation.hs454–470 keeps node clients running through connection loss. Its retry handlers1260–1322 consult retry policy for vanished/missing resources and recognized mux connection failures. These facts ground a real socket fault test; they do not establish transaction retry/expiry, pending durability or rollback.
