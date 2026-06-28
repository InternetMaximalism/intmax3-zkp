# F-WITHDRAW-1 — contract-side soundness verdict

Cross-check spawned from the Lean formalization of `WithdrawalCircuit`
(task_cae4b173). Summary entry lives in `tasks/todo.md`; this is the full
line-referenced argument.

## F-WITHDRAW-1 (= audit622 C-M2) — `WithdrawalCircuit` partial `ExtendedPublicState` binding

**Status: CLOSED — SAFE (case (a)). Contract re-pins all 5 unbound extended fields.**

### The concern (from Lean formalization)
`withdrawal_circuit.rs:190-194` builds an `ExtendedPublicState` whose 5 extended fields
(`block_hash_chain`, `deposit_hash_chain`, `deposit_count`, `channel_reg_hash_chain`,
`bp_sig_chain`) are **free witnesses**; only `ext_public_state.inner` is `connect`-ed to the
verified withdrawal-chain proof. Yet `ext_public_state_commitment` — which commits to **all 13
fields** — is registered as an on-chain PI (`withdrawal_circuit.rs:200,207`) and consumed by L1.
Question: does the contract trust any forgeable extended field as ground truth?

### Verdict: case (a) — the contract completes the binding. No forgeable field.

The withdrawal PI is the **full** commitment, and the contract requires it to be a member of the
set of validity-finalized state roots. Because the commitment is a collision-resistant Poseidon
hash over all 13 fields, the only preimage that can land in that set is the exact
`(inner, ext5)` tuple the validity proof already committed — where the 5 ext fields are the TRUE
accumulated values constrained by the validity circuit. Forging any ext field changes the
commitment to a value absent from `finalizedStateRoots` → revert.

### Evidence chain

1. **Withdrawal PI = full commitment.** `WithdrawalCircuit` registers
   `ext_public_state_commitment` = `ExtendedPublicStateTarget::commitment` =
   `Poseidon(inner || block_hash_chain || deposit_hash_chain || deposit_count ||
   channel_reg_hash_chain || bp_sig_chain)` over all fields
   (`ext_public_state.rs:280-286`, `to_vec()` covers every field). Registered at
   [`withdrawal_circuit.rs:207`](src/circuits/withdraw/withdrawal_circuit.rs:207).

2. **Contract requires membership in the finalized-root set, not field-level trust.**
   `withdrawNative` decodes `extCommitment = pi[8..16]` and checks
   `if (!finalizedStateRoots[extCommitment]) revert WithdrawalExtCommitmentMismatch();`
   — [`IntmaxRollup.sol:1330-1331`](contracts/src/IntmaxRollup.sol:1331). No individual extended
   field (`deposit_count`, `deposit_hash_chain`, `bp_sig_chain`, …) is ever decoded from the
   withdrawal PIs and used as ground truth. They are never read out at all — only the aggregate
   commitment is checked.

3. **`finalizedStateRoots` is populated only by `finalize()`** with `stateRoot`
   ([`IntmaxRollup.sol:1122`](contracts/src/IntmaxRollup.sol:1122)), and `fullVerify` enforces
   `validityPIs.finalExtCommitment == stateRoot`
   ([`IntmaxRollup.sol:1469`](contracts/src/IntmaxRollup.sol:1469)) while binding `validityPIs` to
   a verified validity MLE/WHIR proof via the piHash check
   ([`IntmaxRollup.sol:1479-1483`](contracts/src/IntmaxRollup.sol:1480)). So every member of
   `finalizedStateRoots` is a validity-proof `final_ext_commitment`.

4. **The validity circuit computes that commitment identically and constrains all 5 ext fields.**
   `final_ext_commitment = block_chain_pis.ext_public_state.commitment(...)`
   ([`validity_circuit.rs:242`](src/circuits/validity/block_hash_chain/validity_circuit.rs:242)) —
   the SAME `ExtendedPublicStateTarget::commitment` over the SAME 13-field `to_vec()`. Inside the
   validity span the 5 ext fields are accumulated/constrained to their true values (deposit chain,
   block-producer sig chain D3 with the A8 truncation guard, channel-reg chain R4, etc.), not free.

5. **Binding ⇒ no forgery.** Poseidon is collision-resistant, so a withdrawal prover cannot find an
   alternative `(inner, ext5)` whose commitment collides with any finalized root. To pass step 2
   they must use the genuine tuple, in which the 5 ext fields equal the validity-finalized values.
   The partial in-circuit binding is therefore **intentional and completed contract-side**.

### Notes / residuals (do not reopen F-WITHDRAW-1)
- The membership check does double duty: it also anchors `inner` (state/account roots) to a
  finalized state, so the withdrawal cannot be proven against an unfinalized or forged inner state.
- `block_number` (pi[16]) is independently sound: in-circuit it is `ext_public_state.inner.block_number`
  (bound to the chain proof, [`withdrawal_circuit.rs:195`](src/circuits/withdraw/withdrawal_circuit.rs:195))
  and is also folded into `pis_hash`.
- The argument's only external dependency is that the **validity circuit** truly constrains the 5
  ext fields. That is the validity circuit's own invariant (separate scope), and audit622 / the
  in-code SECURITY comments document it (D3/A8/R4). It is not a withdrawal-side gap.
- audit622 C-M2 already noted "L1 `finalizedStateRoots` compensates"; this cross-check upgrades that
  note to a rigorous, line-referenced soundness argument.
