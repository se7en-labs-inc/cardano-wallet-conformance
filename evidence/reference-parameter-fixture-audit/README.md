# Owned committee fixture audit

Preparation source: `b2bce6d71f`; enactment source: `12ecefa6ed`. This audit receives no conformance credit. It demonstrates a real owned-committee authorization, proposal, positive vote and enacted protocol-parameter change using independently checked transaction bodies and signatures.

The first runtime `/tmp/wc-parameter-jvgFcw` encountered an environmental TCP port collision: one pool node failed to bind. Its diagnostic, initial public snapshots and verified shutdown are preserved. The unchanged prepared configuration was replayed on a fresh healthy runtime `/tmp/wc-parameter-retry-nmx8nG`. `enactment.json` contains the successful runtime's own before/after observations and proofs. Do not interpret the first partial-start snapshots as healthy-cluster evidence.

The successful runtime enacted fee-per-byte 100→101, UTxO cost 4310→4320 and pool target 3→4. The wallet exposed pool target 4. Independent node integration passed last. All wallet lists were empty; all observed cluster, wallet and node processes were stopped and verified absent. Private credentials and runtime logs remain outside this evidence directory.
