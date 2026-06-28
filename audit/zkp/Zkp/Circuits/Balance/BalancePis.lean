import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Balance proof public inputs
  ===========================

  Source: `src/circuits/balance/balance_pis.rs`

  ## Protocol role

  `BalancePublicInputs` is the statement a balance proof exposes:

    * `channel_id`          — whose balance this is
    * `public_state`        — the on-chain state it is relative to
    * `block_r`             — block at which the balance is guaranteed
                              (must satisfy `block_r ≤ public_state.block_number`)
    * `private_commitment`  — commitment to the hidden private state
    * `settled_tx_chain`    — hash-chain fold over absorbed settles
                              (deposits / inter-channel transfers)

  These are what downstream circuits (withdrawal, the on-chain wrapper)
  bind to. Two correctness concerns at THIS layer:

    1. `connect` must equate EVERY field (else recursion can carry a
       differing field undetected — same class of bug as F-PUBST-1).
    2. `BalanceFullPublicInputs.commitment` folds the verifier data
       `vd` into the Poseidon commitment, binding WHICH circuit produced
       the proof (anti cross-circuit substitution in the IVC).
-/

namespace Zkp
namespace Circuits.BalancePis

open CField Builder Bytes

variable {F : Type} [CField F]

/-- The on-chain public state (abstract; full structural equality). -/
opaque PublicState : Type → Type

/-- The five-field balance public input. -/
structure BalancePublicInputs (F : Type) where
  channelId : F
  publicState : PublicState F
  blockR : F
  privateCommitment : HashOut F
  settledTxChain : Bytes32 F

/-- `BalancePublicInputsTarget::connect` — field-by-field `connect`
    over all five fields (balance_pis.rs:232-244). -/
def connectPis (a b : BalancePublicInputs F) : Prop :=
  connect a.channelId b.channelId
  ∧ a.publicState = b.publicState
  ∧ connect a.blockR b.blockR
  ∧ a.privateCommitment = b.privateCommitment
  ∧ a.settledTxChain = b.settledTxChain

/-- **Binding completeness.** `connect` holding is EQUIVALENT to full
    record equality — it omits no field. So when an outer circuit
    `connect`s a child balance proof's PIs to expected values, every
    component (including `settled_tx_chain` and `private_commitment`)
    is pinned; nothing can silently differ across the recursion. -/
theorem connectPis_iff_eq (a b : BalancePublicInputs F) :
    connectPis a b ↔ a = b := by
  constructor
  · rintro ⟨hc, hp, hb, hpc, hs⟩
    unfold connect at hc hb
    cases a; cases b
    simp_all
  · intro h; subst h
    refine ⟨rfl, rfl, rfl, rfl, rfl⟩

/-!
  ## SECURITY OBSERVATIONS

  * **vd binding (anti-substitution).** `BalanceFullPublicInputs.commitment`
    (`:322-329`) computes `Poseidon(pis ++ vd)`. Folding `vd` (the
    verifier-only circuit data) into the commitment binds the proof to
    the specific balance circuit that produced it. Without it, a proof
    from a DIFFERENT circuit with matching `pis` could be substituted
    in the cyclic recursion. The binding is sound given Poseidon CR
    (`Bytes.PoseidonCR`) over the concatenated `pis ++ vd` layout — and
    given the layout is unambiguous (fixed segment lengths, no
    aliasing), which `to_vec`/`from_pis` guarantee by construction.

  * **F-BLKR-1 (check item).** The struct doc (`:59-64`) states the
    invariant `block_r ≤ public_state.block_number`, but
    `BalancePublicInputsTarget::new` (`:165-176`) only range-checks
    `block_r` — it does NOT assert `block_r ≤ block_number`. That
    inequality must be enforced wherever `block_r` is SET (the
    update/processor circuits). If no circuit asserts it, a prover
    could claim a balance "guaranteed at block_r" that exceeds the
    referenced state's height — a freshness/soundness gap for anything
    relying on `block_r`. Action: locate the `block_r ≤ block_number`
    assertion in `balance_processor.rs` / update circuits (Phase 2).
-/

end Circuits.BalancePis
end Zkp
