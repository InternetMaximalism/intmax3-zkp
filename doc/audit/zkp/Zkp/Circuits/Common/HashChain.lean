import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Cyclic hash-chain accumulator — base-case pinning & chain integrity
  ===================================================================

  Source: `src/utils/hash_chain/cyclic_chain_circuit.rs` (plus
  `hash_inner_circuit.rs` and `mod.rs` for the fold hash).

  ## Protocol role

  `CyclicChainCircuit` is the generic IVC accumulator for keccak hash
  chains: each step verifies one `HashInnerCircuit` proof — which binds
  `hash = keccak256(prev_hash ++ content)` (`hash_inner_circuit.rs:43-47`,
  `mod.rs:40-42`) where `content` is the public-input vector of one
  verified "single" proof — and chains it onto the previous accumulator
  proof. The accumulator's own public output `[0..8]` is the running
  chain hash (`cyclic_chain_circuit.rs:55-56`).

  The soundness-critical piece is the **base case**: a chain proof must
  start from `prev_hash = 0`, otherwise a prover could begin a chain
  mid-way (fabricating an arbitrary "previous" accumulated hash and
  presenting a suffix of a chain as if it were the whole chain).

  ## Constraints modeled (`cyclic_chain_circuit.rs`, exact lines)

    :51     `is_first_step = builder.add_virtual_bool_target_safe()`
            — the "safe" variant emits `assert_bool(is_first_step)`.
    :52     `is_not_first_step = builder.not(is_first_step)` (deterministic).
    :53-55  inner `HashInnerCircuit` proof verified; its PIs are
            `prev_hash = pi[0..8]`, `hash = pi[8..16]`.
    :56     `register_public_inputs(hash)` — this circuit's output PI
            IS the inner `hash` wire (`out = hash`).
    :61-68  `conditionally_verify_cyclic_proof_or_dummy(is_not_first_step,
            prev_proof, ..)` — when `is_not_first_step = 1` (i.e.
            `is_first_step = 0`) the previous proof is a REAL accepted
            proof of THIS same circuit (verifier-data fixed point;
            abstracted exactly as in `BalanceCircuit.cyclic_sound`);
            when `is_first_step = 1` it is a dummy and carries no claim.
    :69-70  `prev_pis = prev_proof.pi[0..8]` connected limb-wise to the
            inner proof's `prev_hash` (`Bytes32Target::connect`,
            `u32limb_trait.rs:157-165` — one `builder.connect` per limb).
    :71-73  base-case pinning: `prev_hash.conditional_assert_eq(zero,
            is_first_step)` — per limb `conditional_assert_eq(is_first_step,
            limb, 0)` (`u32limb_trait.rs:167-176`), i.e.
            `is_first_step = 1 → prev_hash = 0`.

  ## What is (and is NOT) constrained — F-PUBST-1-style honesty

  The circuit constrains ONE direction only:

      is_first_step = 1  ⇒  prev_hash = 0          (:72-73, proved below)

  The converse (`prev_hash = 0 ⇒ is_first_step = 1`) is **not a
  constraint** — see `zero_prev_does_not_force_first` below, which
  exhibits a satisfying witness with `is_first_step = 0` and
  `prev_hash = 0`. This is deliberate and harmless *as an isolated
  constraint system*: with `is_first_step = 0` the cyclic verification
  (:62-68) additionally demands an accepted previous accumulator proof
  whose OUTPUT hash is 0 — i.e. a keccak preimage of zero — so the
  converse holds computationally (preimage resistance), not
  syntactically. `chain_integrity` states exactly what the constraints
  give: every accepted step either starts at zero or extends an
  accepted previous accumulator output.

  ## Consumers (grep-verified, 2026-07-02)

  Direct consumers of THIS gadget (`CyclicChainCircuit` /
  `HashChainProcessor`):
    * `src/poseidon_sig/list.rs:186-196` — `ListCircuit` (delegate-
      account signature-list recursion) wraps its per-step folder in
      `CyclicChainCircuit`; the running commitment in PI `[0..8]`.
    * `src/utils/hash_chain/chain_end_circuit.rs:131-148` — terminates
      a chain, re-exposing `keccak(last_hash ++ proof_submitter)`.

  NOT consumers (despite the naming): the validity-side chains
  `deposit_hash_chain_circuit.rs`, `block_hash_chain_circuit.rs`, and
  `channel_reg_*` implement their own step/wrapper circuits (covered
  by `Circuits/Validity/DepositStep.lean`, `BlockStep.lean`, and
  `Circuits/Plumbing.lean` CYCLIC-WRAPPER; channel_reg is out of
  scope). Their base cases are pinned differently: the validity
  circuit exposes initial/final chain values as public inputs and
  **IntmaxRollup.sol:1466-1467 anchors them on-chain**
  (`initialExtCommitment == latestFinalizedStateRoot`,
  `initialBlockChain == blockHashChainAt[initialBlockNumber]`) — the
  known mitigation that makes mid-chain starts unusable on the L1
  path even without an in-circuit `is_first_step` pin.
-/

namespace Zkp
namespace Circuits.HashChain

open CField Builder Bytes

variable {F : Type} [CField F]

/-- The chain fold hash: `keccak256(prev_hash ++ content)`
    (`mod.rs:23-26` native, `mod.rs:28-42` circuit — the circuit form
    is deterministic keccak wiring with no assertions). Modeled as an
    uninterpreted function, mirroring `Bytes.poseidon`: determinism is
    all the chain-integrity argument below needs. Where a caller's
    protocol additionally relies on collision/preimage resistance it
    must state that hypothesis explicitly (cf. `Bytes.PoseidonCR`). -/
opaque keccakChain : Bytes32 F → List F → Bytes32 F

/-- All limbs zero — the value of `Bytes32Target::zero`
    (`u32limb_trait.rs:339-345`), which builds one `builder.zero()`
    constant per limb. Stated membership-wise so no length bookkeeping
    is smuggled into the soundness statement. -/
def IsZeroB32 (h : Bytes32 F) : Prop := ∀ x ∈ h, x = 0

/-- Every constraint emitted by `CyclicChainCircuit::new`
    (`cyclic_chain_circuit.rs`) over the wires of one accumulator
    step, on a satisfying witness. Wire roles:
    `isFirst` = `is_first_step`; `prevHash`/`hash` = the inner proof's
    PI halves (:54-55); `prevOut` = the previous accumulator proof's
    output PI `[0..8]` (:69); `out` = this circuit's registered output
    PI (:56). Proof-verification gates (:53, :62-68) are NOT conjuncts
    here — they are the recursion premises, taken as hypotheses in
    `Accepted` below, exactly as the audit abstracts cyclic
    verification elsewhere (`BalanceCircuit.cyclic_sound`). -/
structure Constraints (isFirst : F) (prevHash hash prevOut out : Bytes32 F) : Prop where
  /-- `:51` — `add_virtual_bool_target_safe` asserts `b·(b−1) = 0`. -/
  isFirst_bool : assertBool isFirst
  /-- `:56` — the registered output PI is the inner proof's `hash`. -/
  out_eq_hash : out = hash
  /-- `:69-70` — limb-wise `connect(prev_pis, prev_hash)`
      (`u32limb_trait.rs:157-165`), i.e. the previous accumulator's
      output equals this step's `prev_hash`. -/
  prev_link : prevOut = prevHash
  /-- `:71-73` — per-limb `conditional_assert_eq(is_first_step, limb, 0)`
      against `Bytes32Target::zero` (`u32limb_trait.rs:167-176`). -/
  base_pin : ∀ x ∈ prevHash, condAssertEq isFirst x 0

/-! ## (a) Base-case pinning -/

/-- **Base case, constrained direction** (`:71-73`): on any satisfying
    witness with `is_first_step = 1`, the chain's previous hash is
    all-zero. A prover cannot open a "first step" at a nonzero
    accumulator value. -/
theorem first_step_pins_prev {isFirst : F} {prevHash hash prevOut out : Bytes32 F}
    (h : Constraints isFirst prevHash hash prevOut out) (hf : isFirst = 1) :
    IsZeroB32 prevHash :=
  fun x hx => h.base_pin x hx hf

/-- **Base case, unconstrained direction (finding-grade honesty).**
    The converse `prevHash = 0 → isFirst = 1` is NOT implied by the
    emitted constraints: here is a satisfying witness with
    `isFirst = 0` and an all-zero `prevHash`. This is not a
    vulnerability in context — with `isFirst = 0` the cyclic gate
    (:62-68) demands an accepted previous proof whose output is 0,
    i.e. a keccak zero-preimage (see `chain_integrity`) — but any
    reading of `:71-73` as an "iff" would be WRONG, and a consumer
    that relied on `prev = 0 ⇒ first` syntactically would be unsound.
    Recorded so the assumption cannot be silently strengthened. -/
theorem zero_prev_does_not_force_first (content : List F) :
    ∃ (isFirst : F) (prevHash hash prevOut out : Bytes32 F),
      Constraints isFirst prevHash hash prevOut out
        ∧ isFirst = 0 ∧ IsZeroB32 prevHash := by
  refine ⟨0, List.replicate 8 0, keccakChain (List.replicate 8 0) content,
    List.replicate 8 0, keccakChain (List.replicate 8 0) content,
    ⟨?_, rfl, rfl, ?_⟩, rfl, ?_⟩
  · -- assertBool 0 : 0·(0−1) = 0
    unfold assertBool
    rw [zero_mul']
  · -- conditional pin is vacuous at isFirst = 0 (0 = 1 is absurd)
    intro x _ h01
    exact absurd h01.symm one_ne_zero
  · intro x hx
    exact (List.mem_replicate.mp hx).2

/-! ## (b) Chain integrity -/

/-- One ACCEPTED accumulator step: the circuit's own constraints plus
    the two facts supplied by the recursive proof verification gates,
    abstracted as hypotheses (the standard cyclic abstraction of this
    audit, cf. `BalanceCircuit.cyclic_sound`):

    1. the verified inner `HashInnerCircuit` proof binds
       `hash = keccak256(prevHash ++ content)`
       (`hash_inner_circuit.rs:43-47`, `mod.rs:40-42`), and
    2. when `isFirst = 0`, `conditionally_verify_cyclic_proof_or_dummy`
       (`cyclic_chain_circuit.rs:62-68`, with `is_not_first_step =
       not(is_first_step)`, `:52`) forces `prevOut` to be the output
       PI of an accepted proof of THIS same circuit — abstracted as
       an arbitrary predicate `Prev`. -/
def Accepted (Prev : Bytes32 F → Prop) (content : List F) (out : Bytes32 F) : Prop :=
  ∃ (isFirst : F) (prevHash hash prevOut : Bytes32 F),
    Constraints isFirst prevHash hash prevOut out
      ∧ hash = keccakChain prevHash content
      ∧ (isFirst = 0 → Prev prevOut)

/-- **Chain integrity.** Any accepted step's output is the fold hash
    of THIS step's content over some `prevHash` that is either
    (base case) all-zero, or (inductive case) the output of an
    accepted previous accumulator proof. Nothing else is accepted:
    a prover cannot inject an arbitrary nonzero starting accumulator,
    because `isFirst` is boolean (:51) and each branch of the
    disjunction is forced by :71-73 resp. :62-70.

    (What the constraints do NOT give, stated for honesty: uniqueness
    of `prevHash` given `out` — that needs keccak collision
    resistance, out of scope for the constraint system itself.) -/
theorem chain_integrity {Prev : Bytes32 F → Prop} {content : List F} {out : Bytes32 F}
    (h : Accepted Prev content out) :
    ∃ prevHash, out = keccakChain prevHash content
      ∧ (IsZeroB32 prevHash ∨ Prev prevHash) := by
  obtain ⟨isFirst, prevHash, hash, prevOut, hc, hhash, hprev⟩ := h
  refine ⟨prevHash, by rw [hc.out_eq_hash, hhash], ?_⟩
  rcases assertBool_sound hc.isFirst_bool with h0 | h1
  · -- non-first step: the previous accumulator output IS prevHash (:69-70)
    right
    have hp := hprev h0
    rwa [hc.prev_link] at hp
  · -- first step: base pin forces prevHash = 0 (:71-73)
    left
    exact first_step_pins_prev hc h1

/-! ## Satisfiability (the constraint set is not vacuous) -/

/-- Completeness, base step: the honest first-step witness
    (`isFirst = 1`, `prevHash = 0`, `hash = keccak(0 ++ content)`)
    satisfies every constraint. -/
theorem accepted_base (Prev : Bytes32 F → Prop) (content : List F) :
    Accepted Prev content (keccakChain (List.replicate 8 (0 : F)) content) := by
  refine ⟨1, List.replicate 8 0, keccakChain (List.replicate 8 0) content,
    List.replicate 8 0, ⟨?_, rfl, rfl, ?_⟩, rfl, ?_⟩
  · -- assertBool 1 : 1·(1−1) = 0
    unfold assertBool
    rw [sub_self', mul_zero']
  · intro x hx _
    exact (List.mem_replicate.mp hx).2
  · intro h10
    exact absurd h10 one_ne_zero

/-- Completeness, inductive step: given any accepted previous output
    `p`, the honest extension witness (`isFirst = 0`, `prevHash = p`)
    satisfies every constraint and outputs `keccak(p ++ content)`. -/
theorem accepted_extend {Prev : Bytes32 F → Prop} {p : Bytes32 F}
    (hp : Prev p) (content : List F) :
    Accepted Prev content (keccakChain p content) := by
  refine ⟨0, p, keccakChain p content, p, ⟨?_, rfl, rfl, ?_⟩, rfl, fun _ => hp⟩
  · unfold assertBool
    rw [zero_mul']
  · intro x _ h01
    exact absurd h01.symm one_ne_zero

end Circuits.HashChain
end Zkp
