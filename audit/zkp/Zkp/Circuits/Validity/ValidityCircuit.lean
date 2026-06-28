import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Validity circuit (top-level block validity + on-chain binding)
  ==============================================================

  Source: `src/circuits/validity/block_hash_chain/validity_circuit.rs`

  ## Protocol role

  The top of the validity stack. It verifies the recursive block-hash-
  chain proof (the consensus over a span of blocks) and exposes
  `keccak256(ValidityPublicInputs)` as the single public input the L1
  contract binds to. Its hardest soundness duty is the BP **signature
  non-skippability** (decision D3): a block span that contains ANY
  signing block must have its signature-list proof verified.

  The critical design point (SECURITY comment, :213): verification of
  the signature-list proof is gated on the **COMPUTED** accumulated
  `final.bp_sig_chain`, NOT a free prover flag. `bp_sig_chain` is folded
  over every signing block by the block chain, so a prover cannot zero
  it while having signed blocks.

  ## Constraint inventory (validity_circuit.rs:192-256)

  | line     | gate                                                        | meaning |
  |----------|-------------------------------------------------------------|---------|
  | :197-198 | `add_proof_target_and_verify_cyclic(block_hash_chain_vd)`   | verify block chain (cyclic) |
  | :222-224 | `connect(initial.bp_sig_chain limbs, 0)`                    | span starts with empty sig list |
  | :226     | `chain_is_zero = final.bp_sig_chain.is_zero()`              | COMPUTED gate |
  | :227     | `should_verify_list = not(chain_is_zero)`                   | verify iff signatures present |
  | :229     | `conditionally_verify(list_proof, should_verify_list)`      | verify sig-list proof |
  | :233-236 | `list_commitment.conditional_assert_eq(final.bp_sig_chain, should_verify_list)` | bind list ↔ accumulator |
  | :244-256 | build `ValidityPublicInputs` (initial/final chains)         | the statement |
  | (hash)   | `keccak256(ValidityPublicInputs)`                          | on-chain PI |
-/

namespace Zkp
namespace Circuits.ValidityCircuit

open CField Builder Bytes

variable {F : Type} [CField F]

/-- The zero `bp_sig_chain` (empty signature accumulator). -/
opaque zeroChain (F : Type) [CField F] : Bytes32 F

/-- `keccak256(ValidityPublicInputs)` — on-chain binding digest. -/
opaque validityHash {F : Type} [CField F] : Bytes32 F → Bytes32 F → Bytes32 F → Bytes32 F

structure Constraints
    (initialBpSigChain finalBpSigChain : Bytes32 F)
    (chainIsZero shouldVerify : F)
    (listCommitment : Bytes32 F) (listVerified : Prop) : Prop where
  -- :222-224  initial accumulator empty
  initialZero : initialBpSigChain = zeroChain F
  -- :226  is_zero advice: boolean, = 1 ↔ final accumulator is empty (COMPUTED, not free)
  isZeroBool : chainIsZero = 0 ∨ chainIsZero = 1
  isZeroIff  : chainIsZero = 1 ↔ finalBpSigChain = zeroChain F
  -- :227  should_verify = not(chain_is_zero)
  shouldDef  : shouldVerify = notGate chainIsZero
  -- :229  verify the list proof when should_verify
  condVerify : shouldVerify = 1 → listVerified
  -- :233-236  bind list commitment to the accumulator when verifying
  condBind   : shouldVerify = 1 → listCommitment = finalBpSigChain

/-- **Signatures are non-skippable.** If the COMPUTED `final.bp_sig_chain`
    is non-empty (the span contains a signing block), then the signature-
    list proof IS verified AND its commitment equals the accumulator. A
    prover cannot present signed blocks while skipping signature
    verification — the gate is the computed accumulator, not a free flag. -/
theorem signatures_not_skippable
    {initialBpSigChain finalBpSigChain : Bytes32 F} {chainIsZero shouldVerify : F}
    {listCommitment : Bytes32 F} {listVerified : Prop}
    (h : Constraints initialBpSigChain finalBpSigChain chainIsZero shouldVerify
          listCommitment listVerified)
    (hsig : finalBpSigChain ≠ zeroChain F) :
    listVerified ∧ listCommitment = finalBpSigChain := by
  -- final ≠ 0 ⇒ chain_is_zero ≠ 1 ⇒ chain_is_zero = 0 ⇒ should_verify = 1
  have hcz0 : chainIsZero = 0 := by
    rcases h.isZeroBool with h0 | h1
    · exact h0
    · exact absurd (h.isZeroIff.mp h1) hsig
  have hsv : shouldVerify = 1 := by
    rw [h.shouldDef, hcz0]
    -- notGate 0 = 1 - 0 = 1
    unfold notGate; simp
  exact ⟨h.condVerify hsv, h.condBind hsv⟩

/-- Conversely, skipping the list proof forces an empty accumulator. -/
theorem skip_implies_empty
    {initialBpSigChain finalBpSigChain : Bytes32 F} {chainIsZero shouldVerify : F}
    {listCommitment : Bytes32 F} {listVerified : Prop}
    (h : Constraints initialBpSigChain finalBpSigChain chainIsZero shouldVerify
          listCommitment listVerified)
    (hskip : shouldVerify = 0) :
    finalBpSigChain = zeroChain F := by
  -- should_verify = not(chain_is_zero) = 0 ⇒ chain_is_zero = 1 ⇒ final = 0
  have : notGate chainIsZero = 0 := h.shouldDef ▸ hskip
  have hcz1 : chainIsZero = 1 := by
    rcases h.isZeroBool with h0 | h1
    · exfalso; rw [h0] at this; unfold notGate at this; simp at this
      exact one_ne_zero this
    · exact h1
  exact h.isZeroIff.mp hcz1

/-!
  ## SECURITY OBSERVATIONS

  * **Computed gate, not prover flag (audit622: "bp_sig_chain gates
    ListCircuit on computed accumulator").** `signatures_not_skippable`
    is the machine-checked statement of decision D3: because
    `should_verify` is DEFINED as `not(is_zero(final.bp_sig_chain))` and
    `bp_sig_chain` is folded by the block chain over every signing block,
    a malicious prover cannot set `should_verify = 0` while having
    signatures — that would force `final.bp_sig_chain = 0` (proved in
    `skip_implies_empty`), contradicting the accumulated value. The
    soundness of "bp_sig_chain truly accumulates every signing block"
    lives in `block_step.rs` (model next); here we prove the GATE is
    honest given that accumulation.

  * **On-chain binding.** The single PI is
    `keccak256(ValidityPublicInputs)` (initial/final block & deposit
    chains, …). Collision resistance of keccak (uninterpreted here)
    makes the on-chain commitment bind exactly the proven span. The
    contract anchors `final` state; combined with `initial.bp_sig_chain
    = 0`, each span is self-contained.

  * **block_hash_chain sub-files** (`block_step.rs`, `small_block_message`,
    `ext_public_state`, `block_chain_pis`, `block_hash_chain_circuit/
    processor`) remain to model — block_step.rs is where `bp_sig_chain`
    and the block hash chain are actually folded and SPHINCS+/Poseidon
    signature gates are embedded (primitive uninterpreted). That file
    discharges the accumulation assumption used above.
-/

end Circuits.ValidityCircuit
end Zkp
