# Proving boundaries: no plonky2 proving in the browser

**Policy (2026-09-04, project owner):** plonky2 proofs (balance, spend, validity, close, withdrawal,
withdrawal-claim, post-close-claim, cancel-close, their recursive wrappers) and the MLE/WHIR proofs
derived from them are **never produced in a user's browser or on a user's device**. Nobody is
asked to run a plonky2 prover client-side, and no design, benchmark, or gas/security trade-off in
this repository may assume that they do.

What runs where:

| Statement | Prover location |
|---|---|
| Regev ciphertext STARKs (Plonky3, BabyBear): channelTx / channelUpdate / withdrawClaim / refresh | client-side (browser WASM or delegate node) — these are the only client-side proofs |
| plonky2 circuits and their MLE/WHIR on-chain proofs | server-side provers only (validity prover service, close/claim provers run by the operator or a delegate node) |

Consequences for engineering decisions:

- Proving time and memory of the plonky2 / MLE / WHIR pipeline are **server** budgets (native,
  multi-core, tens of GB). Browser proving time is not a constraint on them, and WHIR parameters
  (proof-of-work bits, rate, folding factor) may be chosen for on-chain gas without regard to
  client-side proving cost.
- The browser wallet WASM package must not link or invoke plonky2 provers. Any `wasm_wallet`
  export that constructs a plonky2 prover (at the time of writing `wallet_withdrawal_claim` in
  `src/wasm_wallet.rs` still constructs `WithdrawalClaimProver` and calls `prove` / `prove_mle`)
  is a deviation from this policy and is to be moved behind a server/delegate API, not optimized.
- Documentation that says "proving runs in your browser" refers to the Regev STARKs only.
