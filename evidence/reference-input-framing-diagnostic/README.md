# Preserved actual23-input encoding

Diagnostic source63a63621c2 changes only failure context, after specificationb64a62b557. The same fresh600-output workflow again records103 checks/101PASS/two records of the same framing failure. Independent node integration passed last. No input-limit coverage is earned.

The actual returned unsigned transaction is preserved in live.json and returned-unsigned.base64. Its leading bytes are84 a4 00 d9 01 02 97: four-element transaction, four-key body, input key0, set tag258, definite array length23. The harness's special size-control shape verifier incorrectly requires an indefinite array at every count, although its own adjacent-boundary arithmetic explicitly accounts for the23→24 set-framing transition. The generic transaction inspector already handles both framings. This demonstrates a harness assertion defect at the23-item boundary, not evidence of a wallet defect. It does not establish that later boundary checks will pass.

A proposed narrow correction is prepared separately; no parser acceptance has changed. Preserve mandatory258 tag, canonical length-dependent framing, exact input structure/order/eligibility/uniqueness, no extra body/witness/auxiliary fields, requested output/change, conservative fee/size, final adjacent no-extra-input condition and actual signature/node/accounting checks. All644 obligations remain required.

Owned cluster659642 and observed children659751,659770,660223,660225,660226 were signaled only after exact executable/argv ownership verification; final absence verification is recorded with the completion evidence. Private runtime material is excluded.

Completion: all six recorded owned process PIDs are absent and the cluster supervisor was reaped with exit130. Full160 Cargo tests, Clippy, Rust formatting and isolated Nix package/Clippy/fmt checks pass for diagnostic source63a63621c2. An initial Nix command used a nonexistent package check attribute; the corrected command builds .#wallet-conformance and the declared clippy/fmt checks without changing source or criteria.
