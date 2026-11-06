# Real-node funded Shelley payment and migration profile

All75 live checks pass against the pinned Haskell wallet and actual Conway node11.1.3. Alongside the basic transfer/restoration flow, the standalone Shelley family profile validates funded fee estimation, selection conservation and fee interval, deprecated create/send payment, transaction history, complete migration plan selection/no leftover and fee accounting, submitted migration count/fees/output conservation, zero source balance and exact independently queried recipient UTxOs. All owned wallet cleanup passes.

The profile uses the same shared family assertions as the existing full family flow and changes no Byron funding behavior. The proposed Byron funding bridge remains pending approval and was not executed. All73 offline tests, Clippy and formatting passed before this run. This standalone report is not a full643-obligation aggregate; a common-fingerprint full rerun remains required.
