import Zkp.Implementation.FalconAggregate
import Zkp.Implementation.FalconCore
import Zkp.Implementation.CloseSignatureBridge

/-!
# FalconAggProgram: per-primitive lowering of the Falcon aggregation tree

Source: `src/falcon_sig/agg.rs` (module doc :1-113, layout helpers :149-200, the LEAF
constructor `FalconLeafCircuit::new` :268-305, the positional child reader `child_pis` :332-339,
the LEVEL constructor `FalconAggLevelCircuit::new` :370-479).

This is a handwritten SEMANTIC MODEL, not a refinement proof of the Rust, of plonky2's
recursive verifier, or of Falcon. Every theorem here is a theorem about the Lean model; the
source-to-model correspondence is a line-map claim only.

## What this module adds over `FalconAggregate`

`FalconAggregate` models the aggregation as a TREE evaluator (`evalTree`, `levelCompose`) over
an opaque `SigEnv.falconAccepts` callback. That left one whole-circuit premise — "a satisfiable
aggregate constraint system yields such a tree" — and one whole-gadget premise — "the accept
callback is the `gadget.rs` gate set".

Here the two aggregation circuits become ordered BUILDER TRANSCRIPTS in the style of
`CloseCircuit.constructorProgram`:

* `LeafOp` / `leafProgram` / `LeafOp.holds` — one constructor per builder call of agg.rs:268-305,
  each `holds` the local proposition that primitive enforces on the wires an assignment values.
  The leaf's signature op is `FalconCore.CircuitSatisfied` DIRECTLY: no opaque `Bool` callback.
* `LevelOp` / `levelProgram k` / `LevelOp.holds` — one constructor per builder call of
  agg.rs:370-479, with the two recursive verifications left opaque in `LevelEnvironment`.
* `leaf_program_satisfied_implies_statement` and `level_program_satisfied_implies_compose`
  derive the exposed public-input vector, so the circuit-to-statement step is now
  per-primitive.
* `satisfiable_top_level_gives_witness_list` runs the induction over the four circuits
  (leaf, level 1, 2, 3) from two ABSTRACT premises, `RecursionSound` and `LevelLowering`,
  over an abstract satisfiability relation `Sat : Nat → List Nat → Prop`.
* `witness_list_gives_signer_evidence` converts that witness list into
  `CloseSignatureBridge.SignerEvidence` under `CloseSignatureBridge.FalconUnforgeable`.

## Field arithmetic

Wire arithmetic is Goldilocks (`FalconCore.fieldModulus`). Every `sub` / `mul` / `add` op states
its equation MODULO `fieldModulus`; a wire that is the OUTPUT of a field gate additionally
records `< fieldModulus` (a field element is canonical). The `Nat`-level conclusions —
"the exposed count is `count_l + present * count_r`", "the messages agree limb by limb",
"an absent right child exposes exactly zero" — are then DERIVED from the range hypotheses the
induction supplies: every limb is a canonical `u32` (`Bytes32Target::new(_, true)`,
gadget.rs:351-353 and 660) and every signer count is at most `MAX_SIG_CLUSTER = 8`, both far
below the modulus.

## What is NOT proved here (named boundaries)

* `LevelEnvironment.verifyChild` — plonky2's recursive verifier. `RecursionSound` is the
  premise that a verified child proof means the child circuit is satisfiable at those public
  inputs; nothing in this audit models a plonky2 proof.
* `LevelEnvironment.childVerifierData` — the A7 binding (agg.rs:99-105) is recorded as the
  `constant_verifier_data` wire identity of `verifyLeftChild`, not proved to pin a circuit.
* `LevelLowering` — that a satisfiable circuit instance yields an assignment satisfying the
  transcript. This is the residual "the transcript IS the circuit" obligation, now stated
  per level instead of once for the whole tree.
* Per-op faithfulness: each `holds` case must equal the gate set plonky2 really emits for that
  one builder call (`add_proof_target_and_verify`,
  `add_proof_target_and_conditionally_verify`, `add_virtual_bool_target_safe`, `sub`, `mul`,
  `add`, `assert_zero`, `constant`, `register_public_input(s)`).
* The DUMMY-proof path: with `is_right_present = 0` the right child's public inputs are
  UNCONSTRAINED except for their length (agg.rs:49-52, :353-357). The model says exactly that,
  and `FalconAggregate.absent_right_child_statement_is_ignored` is why the exposed statement
  cannot depend on them.
* Signer DISTINCTNESS and member-set membership stay CONSUMER obligations (agg.rs:86-88).
-/

namespace Zkp.Implementation.FalconAggProgram

/-! ## 0. Small list and modular-arithmetic helpers (no Mathlib in this project) -/

/-- Pointwise extensionality through `getD`, the positional reader every public-input claim
below is phrased with. -/
theorem list_ext_get_default : ∀ (x y : List Nat), x.length = y.length →
    (∀ i, i < x.length → x.getD i 0 = y.getD i 0) → x = y := by
  intro x
  induction x with
  | nil =>
    intro y hy _
    cases y with
    | nil => rfl
    | cons _ _ => simp at hy
  | cons u us ih =>
    intro y hy hget
    cases y with
    | nil => simp at hy
    | cons v vs =>
      have hlen : us.length = vs.length := by simpa using hy
      have hhead : u = v := by simpa using hget 0 (by simp)
      have htail : us = vs := by
        refine ih vs hlen (fun i hi => ?_)
        have := hget (i + 1) (by simpa using Nat.succ_lt_succ hi)
        simpa using this
      rw [hhead, htail]

/-- `getD` past the end returns the default, so a uniform bound on the members bounds every
positional read. -/
theorem get_default_lt : ∀ (l : List Nat) (B : Nat), 0 < B → (∀ x ∈ l, x < B) →
    ∀ i, l.getD i 0 < B := by
  intro l
  induction l with
  | nil => intro B hB _ i; simpa using hB
  | cons u us ih =>
    intro B hB h i
    cases i with
    | zero => simpa using h u (by simp)
    | succ j => simpa using ih B hB (fun x hx => h x (by simp [hx])) j

/-- Every member of a flattened slot list is a member of one slot. -/
theorem join_members_lt {S : List FalconAggregate.Limbs} {B : Nat}
    (h : ∀ p ∈ S, ∀ x ∈ p, x < B) : ∀ x ∈ S.join, x < B := by
  intro x hx
  obtain ⟨p, hp, hxp⟩ := List.mem_join.mp hx
  exact h p hp x hxp

/-- `map` respects a pointwise equality on the members. -/
theorem map_congr_members {α β : Type} (f g : α → β) : ∀ (l : List α),
    (∀ x ∈ l, f x = g x) → l.map f = l.map g := by
  intro l
  induction l with
  | nil => intro _; rfl
  | cons u us ih =>
    intro h
    simp only [List.map_cons, h u (by simp), ih (fun x hx => h x (by simp [hx]))]

/-- Two runs of the same padding value concatenate. -/
theorem replicate_append_replicate {α : Type} (x : α) : ∀ (m n : Nat),
    List.replicate m x ++ List.replicate n x = List.replicate (m + n) x := by
  intro m
  induction m with
  | zero => intro n; simp
  | succ i ih =>
    intro n
    simp only [List.replicate_succ, List.cons_append, ih, Nat.succ_add]

theorem replicate_members_zero {n : Nat} : ∀ x ∈ List.replicate n (0 : Nat), x = 0 := by
  intro x hx
  exact List.eq_of_mem_replicate hx

/-- `List.range` is not equipped with a length lemma in this toolchain's `Std`. -/
theorem range_loop_length : ∀ (n : Nat) (ns : List Nat),
    (List.range.loop n ns).length = n + ns.length := by
  intro n
  induction n with
  | zero => intro ns; simp [List.range.loop]
  | succ m ih =>
    intro ns
    rw [show List.range.loop (m + 1) ns = List.range.loop m (m :: ns) from rfl, ih]
    simp
    omega

theorem range_length (n : Nat) : (List.range n).length = n := by
  simpa using range_loop_length n []

/-- `omega` casts `2 ^ k` into `Int` as `(2 : Int) ^ k` and therefore does not know it is
non-negative; every truncated subtraction below feeds it this fact. -/
theorem two_pow_pos (k : Nat) : 0 < 2 ^ k := by
  induction k with
  | zero => decide
  | succ i ih => rw [Nat.pow_succ]; exact Nat.mul_pos ih (by decide)

/-- Reading past a zero block is zero. -/
theorem replicate_zero_get_default : ∀ (n i : Nat), (List.replicate n (0 : Nat)).getD i 0 = 0 := by
  intro n
  induction n with
  | zero => intro i; simp
  | succ m ih =>
    intro i
    cases i with
    | zero => simp [List.replicate_succ]
    | succ j => simpa [List.replicate_succ] using ih j

/-- The three layout constants as literals, so `omega` can see through them. -/
theorem bytes32_len_unfold : FalconAggregate.bytes32Len = 8 := rfl

theorem pk_list_offset_unfold : FalconAggregate.falconAggPkListOffset = 9 := rfl

theorem len_at_unfold (k : Nat) :
    FalconAggregate.falconAggPublicInputsLenAt k = 9 + 2 ^ k * 8 := rfl

/-- `2 ^ k` splits in half at every positive level — the slot-count arithmetic of the tree. -/
theorem pow_two_split (k : Nat) (hk : 1 ≤ k) : 2 ^ k = 2 ^ (k - 1) + 2 ^ (k - 1) := by
  obtain ⟨j, rfl⟩ : ∃ j, k = j + 1 := ⟨k - 1, by omega⟩
  simp [Nat.pow_succ, Nat.mul_two]

/-- Uniqueness of a `digit * base + remainder` split with a non-literal base (`omega` cannot
see through `x * B ^ n`, so the split is done by hand). -/
theorem mod_mul_split (m b n : Nat) (hm : 0 < m) (hb : 0 < b) :
    n % (m * b) = n / m % b * m + n % m := by
  have hq : n / m % b < b := Nat.mod_lt _ hb
  have hq' : n / m % b + 1 ≤ b := hq
  have hr : n % m < m := Nat.mod_lt _ hm
  have h1 : m * (n / m) + n % m = n := Nat.div_add_mod n m
  have h2 : b * (n / m / b) + n / m % b = n / m := Nat.div_add_mod (n / m) b
  have hsplit : n / m % b * m + n % m + m * b * (n / m / b) = n := by
    calc n / m % b * m + n % m + m * b * (n / m / b)
        = m * (b * (n / m / b)) + (m * (n / m % b) + n % m) := by
          rw [Nat.mul_assoc, Nat.mul_comm (n / m % b) m]
          omega
      _ = m * (b * (n / m / b) + n / m % b) + n % m := by
          rw [Nat.mul_add, Nat.add_assoc]
      _ = m * (n / m) + n % m := by rw [h2]
      _ = n := h1
  have hlt : n / m % b * m + n % m < m * b := by
    have h3 : (n / m % b + 1) * m ≤ b * m := Nat.mul_le_mul_right m hq'
    have h4 : n / m % b * m + n % m < n / m % b * m + m := Nat.add_lt_add_left hr _
    have h5 : n / m % b * m + m = (n / m % b + 1) * m := (Nat.succ_mul _ _).symm
    have h6 : b * m = m * b := Nat.mul_comm b m
    exact Nat.lt_of_lt_of_le (h5 ▸ h4) (h6 ▸ h3)
  calc n % (m * b)
      = (n / m % b * m + n % m + m * b * (n / m / b)) % (m * b) := by rw [hsplit]
    _ = (n / m % b * m + n % m) % (m * b) :=
        Nat.add_mul_mod_self_left _ (m * b) (n / m / b)
    _ = n / m % b * m + n % m := Nat.mod_eq_of_lt hlt

/-! ## 1. `u32` limb vectors (`limbsOfNat`), the inverse of the D1 bridge's `digestOfLimbs` -/

/-- `2 ^ 32` — the canonical `u32` limb bound that `Bytes32Target::new(_, true)` range-checks
(gadget.rs:351-353 for the salt/digest note, gadget.rs:660 for the two `Bytes32Target` inputs
of `FalconSigVerifyTarget::build`). -/
def limbBase : Nat := CloseSignatureBridge.limbBase

theorem limb_base_pinned : limbBase = 2 ^ 32 := rfl

/-- The Goldilocks modulus wire values live in (`FalconCore.fieldModulus`). -/
def fieldModulus : Nat := FalconCore.fieldModulus

theorem field_modulus_pinned : fieldModulus = 18446744069414584321 := rfl

theorem field_modulus_pos : 0 < fieldModulus := by decide

theorem limb_base_lt_field : limbBase < fieldModulus := by decide

/-- A canonical `u32` limb is a canonical field element. -/
theorem limb_lt_field {x : Nat} (h : x < limbBase) : x < fieldModulus :=
  Nat.lt_trans h limb_base_lt_field

/-- A signer count never exceeds `MAX_SIG_CLUSTER`, far below the modulus. -/
theorem small_lt_field {x : Nat} (h : x ≤ 8) : x < fieldModulus :=
  Nat.lt_of_le_of_lt h (by decide)

theorem mod_idem (x : Nat) : x % fieldModulus % fieldModulus = x % fieldModulus :=
  Nat.mod_eq_of_lt (Nat.mod_lt _ field_modulus_pos)

/-- `limbsOfNatAux k n` is the top `k` big-endian `2 ^ 32` limbs of `n`. -/
def limbsOfNatAux : Nat → Nat → List Nat
  | 0, _ => []
  | k + 1, n => n / limbBase ^ k % limbBase :: limbsOfNatAux k n

/-- The 8 big-endian `u32` limbs of `n % 2 ^ 256` — the `Bytes32::to_u32_vec` view of a digest
value, inverse to `CloseSignatureBridge.digestOfLimbs` on canonical 8-limb vectors. -/
def limbsOfNat (n : Nat) : FalconAggregate.Limbs :=
  limbsOfNatAux FalconAggregate.bytes32Len n

theorem limbs_of_nat_aux_length : ∀ (k n : Nat), (limbsOfNatAux k n).length = k := by
  intro k
  induction k with
  | zero => intro _; rfl
  | succ m ih => intro n; simp [limbsOfNatAux, ih]

theorem limbs_of_nat_length (n : Nat) : (limbsOfNat n).length = FalconAggregate.bytes32Len :=
  limbs_of_nat_aux_length _ n

theorem limbs_of_nat_aux_canonical : ∀ (k n : Nat), ∀ x ∈ limbsOfNatAux k n, x < limbBase := by
  intro k
  induction k with
  | zero => intro _ x hx; cases hx
  | succ m ih =>
    intro n x hx
    rcases List.mem_cons.mp hx with h | h
    · rw [h]; exact Nat.mod_lt _ (by decide)
    · exact ih n x h

theorem limbs_of_nat_canonical (n : Nat) : ∀ x ∈ limbsOfNat n, x < limbBase :=
  limbs_of_nat_aux_canonical _ n

theorem limb_base_pow_pos : ∀ j : Nat, 0 < limbBase ^ j := by
  intro j
  induction j with
  | zero => decide
  | succ i ih => rw [Nat.pow_succ]; exact Nat.mul_pos ih (by decide)

theorem digest_of_limbs_aux : ∀ (k n : Nat),
    CloseSignatureBridge.digestOfLimbs (limbsOfNatAux k n) = n % limbBase ^ k := by
  intro k
  induction k with
  | zero =>
    intro n
    show CloseSignatureBridge.digestOfLimbs [] = n % limbBase ^ 0
    rw [Nat.pow_zero, Nat.mod_one]
    rfl
  | succ m ih =>
    intro n
    rw [limbsOfNatAux, CloseSignatureBridge.digest_of_limbs_cons, limbs_of_nat_aux_length, ih,
      Nat.pow_succ]
    exact (mod_mul_split (limbBase ^ m) limbBase n (limb_base_pow_pos m) (by decide)).symm

/-- The packing is a left inverse of the limb decomposition below `2 ^ 256`. -/
theorem digest_of_limbs_limbs_of_nat (n : Nat) (h : n < 2 ^ 256) :
    CloseSignatureBridge.digestOfLimbs (limbsOfNat n) = n := by
  have h8 : limbBase ^ FalconAggregate.bytes32Len = 2 ^ 256 := by decide
  rw [limbsOfNat, digest_of_limbs_aux, h8, Nat.mod_eq_of_lt h]

/-- ... and a right inverse on canonical 8-limb vectors, which is the only domain the gadget
can produce (`Bytes32Target::new(_, true)`). -/
theorem limbs_of_nat_digest_of_limbs (l : FalconAggregate.Limbs)
    (hlen : l.length = FalconAggregate.bytes32Len) (hc : ∀ x ∈ l, x < limbBase) :
    limbsOfNat (CloseSignatureBridge.digestOfLimbs l) = l := by
  have hbound : CloseSignatureBridge.digestOfLimbs l < 2 ^ 256 := by
    have hlt := CloseSignatureBridge.digest_of_limbs_lt l hc
    rw [hlen] at hlt
    have h8 : CloseSignatureBridge.limbBase ^ FalconAggregate.bytes32Len = 2 ^ 256 := by decide
    rw [h8] at hlt
    exact hlt
  refine CloseSignatureBridge.digest_of_limbs_injective _ _ ?_ ?_ hc ?_
  · rw [limbs_of_nat_length, hlen]
  · exact limbs_of_nat_canonical _
  · exact digest_of_limbs_limbs_of_nat _ hbound

/-- The active pk slots of a witness list are 8 limbs wide. -/
theorem active_slots_well_formed (cws : List FalconCore.CircuitWitness) :
    FalconAggregate.SlotsWellFormed (cws.map (fun cw => limbsOfNat cw.pkG)) := by
  intro q hq
  obtain ⟨cw, _, hcw⟩ := List.mem_map.mp hq
  rw [← hcw]
  exact limbs_of_nat_length _

theorem active_slots_canonical (cws : List FalconCore.CircuitWitness) :
    ∀ q ∈ cws.map (fun cw => limbsOfNat cw.pkG), ∀ x ∈ q, x < limbBase := by
  intro q hq x hx
  obtain ⟨cw, _, hcw⟩ := List.mem_map.mp hq
  rw [← hcw] at hx
  exact limbs_of_nat_canonical _ x hx

theorem zero_slot_canonical : ∀ x ∈ FalconAggregate.zeroSlot, x < limbBase := by
  intro x hx
  rw [FalconAggregate.mem_replicate_eq hx]
  decide

/-! ## 2. The LEAF circuit as a builder transcript (agg.rs:268-305) -/

/-- One constructor per builder call of `FalconLeafCircuit::new`.

* `falconSigVerify` — agg.rs:271, `FalconSigVerifyTarget::new(&mut builder)`. This is the
  UNCONDITIONAL gadget (agg.rs:234-239): there is no `verify` gate wire, so the slot is always
  ACTIVE. It also allocates the two `Bytes32Target` INPUTS with `true`, i.e. a `range_check(_,
  32)` on each of the 16 limbs (gadget.rs:659-661, and the note at gadget.rs:351-353).
* `registerMessageDigest8` — agg.rs:274,
  `register_public_inputs(&sig.message_digest.to_vec())`: PI `0..8` IS the gadget's own
  `message_digest` input wire, so there is no free witness between "what was signed" and
  "what is exposed" (agg.rs:236-239).
* `constantOne` — agg.rs:276, `let one = builder.one()`.
* `registerSignerCount` — agg.rs:277, `register_public_input(one)`: PI 8, the CONSTANT 1 that
  is the induction base of `signer_count >= 1` (agg.rs:64-72).
* `registerPkG8` — agg.rs:279, `register_public_inputs(&sig.pk_g.to_vec())`: PI `9..17`, the
  gadget-derived `pk_g = Poseidon(IMFK || encode(h))`.
* `requireLeafWidth` — agg.rs:292-296, the RELEASE-mode `assert_eq!` that the arity is
  `falcon_agg_public_inputs_len(0) = 17`.
* `addConstGate` — agg.rs:285, `add_const_gate(&mut builder)`: puts a `ConstantGate` in the
  gate set so the next level can rebuild this circuit's dummy. "Adds no constraints on witness
  values" (agg.rs:283-284), so its `holds` is `True`.
* `build` — agg.rs:288, `builder.build::<C>()`: emits no constraint, `holds` is `True`. -/
inductive LeafOp where
  | falconSigVerify
  | registerMessageDigest8
  | constantOne
  | registerSignerCount
  | registerPkG8
  | requireLeafWidth
  | addConstGate
  | build
  deriving DecidableEq, Repr

/-- A value for every wire `FalconLeafCircuit::new` allocates: the gadget instance, the 8
message limbs and the 8 `pk_g` limbs (the `Bytes32Target` views the registrations read), and
the constant-one wire. -/
structure LeafAssignment where
  sig : FalconCore.CircuitWitness
  messageLimbs : FalconAggregate.Limbs
  pkGLimbs : FalconAggregate.Limbs
  countWire : Nat

/-- The registered public inputs, in `register_public_input(s)` order (agg.rs:274-279). -/
def readLeafPublic (a : LeafAssignment) : List Nat :=
  a.messageLimbs ++ [a.countWire] ++ a.pkGLimbs

/-- The ordered transcript of `FalconLeafCircuit::new` (agg.rs:268-305). -/
def leafProgram : List LeafOp :=
  [LeafOp.falconSigVerify, LeafOp.registerMessageDigest8, LeafOp.constantOne,
   LeafOp.registerSignerCount, LeafOp.registerPkG8, LeafOp.requireLeafWidth,
   LeafOp.addConstGate, LeafOp.build]

theorem leaf_program_length : leafProgram.length = 8 := by decide

theorem leaf_program_registers_before_build :
    leafProgram.reverse.take 3
      = [LeafOp.build, LeafOp.addConstGate, LeafOp.requireLeafWidth] := by decide

/-- Local satisfaction semantics of one builder call; see the `LeafOp` docstring for the
source line of each. The limb/`Nat` reconciliation of the gadget's `message_digest` and `pk_g`
wires is the D1 bridge's `CloseSignatureBridge.digestOfLimbs`. -/
def LeafOp.holds (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (op : LeafOp) (a : LeafAssignment) : Prop :=
  match op with
  | .falconSigVerify =>
      FalconCore.CircuitSatisfied e p a.sig ∧
        a.sig.verifyBit = 1 ∧
        a.sig.messageDigest = CloseSignatureBridge.digestOfLimbs a.messageLimbs ∧
        a.sig.pkG = CloseSignatureBridge.digestOfLimbs a.pkGLimbs ∧
        (∀ x ∈ a.messageLimbs, x < limbBase) ∧
        (∀ x ∈ a.pkGLimbs, x < limbBase)
  | .registerMessageDigest8 => a.messageLimbs.length = FalconAggregate.bytes32Len
  | .constantOne => a.countWire = 1
  | .registerSignerCount => FalconAggregate.decodeCount (readLeafPublic a) = a.countWire
  | .registerPkG8 => a.pkGLimbs.length = FalconAggregate.bytes32Len
  | .requireLeafWidth =>
      (readLeafPublic a).length = FalconAggregate.falconAggPublicInputsLenAt 0
  | .addConstGate => True
  | .build => True

/-- `ProgramSatisfied leafProgram a` in the plan's notation. -/
def LeafProgramSatisfied (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (a : LeafAssignment) : Prop :=
  ∀ op ∈ leafProgram, op.holds e p a

theorem leaf_program_satisfied_of (e : FalconCore.HashEnvironment)
    (p : FalconCore.PolynomialProduct) (a : LeafAssignment)
    (h1 : LeafOp.falconSigVerify.holds e p a)
    (h2 : LeafOp.registerMessageDigest8.holds e p a)
    (h3 : LeafOp.constantOne.holds e p a)
    (h4 : LeafOp.registerSignerCount.holds e p a)
    (h5 : LeafOp.registerPkG8.holds e p a)
    (h6 : LeafOp.requireLeafWidth.holds e p a) :
    LeafProgramSatisfied e p a := by
  intro op hop
  simp only [leafProgram, List.mem_cons, List.not_mem_nil, or_false] at hop
  rcases hop with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact h1
  · exact h2
  · exact h3
  · exact h4
  · exact h5
  · exact h6
  · trivial
  · trivial

/-- THE LEAF STATEMENT. A satisfied leaf transcript exposes exactly the canonical level-0
statement `[message(8), signer_count = 1, pk_g(8)]` of an ACTIVE gadget instance whose signed
digest IS the exposed message and whose key slot IS the limb decomposition of the gadget's own
`pk_g` wire. -/
theorem leaf_program_satisfied_implies_statement (e : FalconCore.HashEnvironment)
    (p : FalconCore.PolynomialProduct) (a : LeafAssignment)
    (h : LeafProgramSatisfied e p a) :
    readLeafPublic a = FalconAggregate.statementPublicInputs
        { message := a.messageLimbs, count := 1, pks := [a.pkGLimbs] } ∧
      FalconCore.CircuitSatisfied e p a.sig ∧
      a.sig.verifyBit = 1 ∧
      a.sig.messageDigest = CloseSignatureBridge.digestOfLimbs a.messageLimbs ∧
      a.pkGLimbs = limbsOfNat a.sig.pkG ∧
      a.messageLimbs.length = FalconAggregate.bytes32Len ∧
      (∀ x ∈ a.messageLimbs, x < limbBase) := by
  have hsig := h LeafOp.falconSigVerify (by simp [leafProgram])
  have hmlen := h LeafOp.registerMessageDigest8 (by simp [leafProgram])
  have hone := h LeafOp.constantOne (by simp [leafProgram])
  have hpklen := h LeafOp.registerPkG8 (by simp [leafProgram])
  simp only [LeafOp.holds] at hsig hmlen hone hpklen
  obtain ⟨hsat, hbit, hdig, hpkdig, hmcan, hpkcan⟩ := hsig
  refine ⟨?_, hsat, hbit, hdig, ?_, hmlen, hmcan⟩
  · simp only [readLeafPublic, FalconAggregate.statementPublicInputs, hone, List.join]
    simp
  · rw [hpkdig, limbs_of_nat_digest_of_limbs a.pkGLimbs hpklen hpkcan]

/-! ## 3. Positional decoding of a child proof's public inputs (`child_pis`, agg.rs:332-339) -/

/-- `chunks` of a flat limb vector of exactly the right width recover the slot list. -/
theorem chunks_length (w : Nat) : ∀ (n : Nat) (l : List Nat),
    (FalconAggregate.chunks w n l).length = n := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ m ih => intro l; simp [FalconAggregate.chunks, ih]

theorem chunks_join_id : ∀ (n : Nat) (l : List Nat),
    l.length = n * FalconAggregate.bytes32Len →
      (FalconAggregate.chunks FalconAggregate.bytes32Len n l).join = l := by
  intro n
  induction n with
  | zero =>
    intro l hl
    have : l = [] := List.eq_nil_of_length_eq_zero (by simpa using hl)
    rw [this]
    rfl
  | succ m ih =>
    intro l hl
    have hdrop : (l.drop FalconAggregate.bytes32Len).length
        = m * FalconAggregate.bytes32Len := by
      rw [List.length_drop, hl, bytes32_len_unfold]
      omega
    simp only [FalconAggregate.chunks, List.join_cons, ih _ hdrop, List.take_append_drop]

theorem chunks_well_formed : ∀ (n : Nat) (l : List Nat),
    l.length = n * FalconAggregate.bytes32Len →
      FalconAggregate.SlotsWellFormed (FalconAggregate.chunks FalconAggregate.bytes32Len n l) := by
  intro n
  induction n with
  | zero => intro _ _; exact FalconAggregate.slots_well_formed_nil
  | succ m ih =>
    intro l hl
    have hlen : FalconAggregate.bytes32Len ≤ l.length := by
      rw [hl, bytes32_len_unfold]
      omega
    have hdrop : (l.drop FalconAggregate.bytes32Len).length
        = m * FalconAggregate.bytes32Len := by
      rw [List.length_drop, hl, bytes32_len_unfold]
      omega
    refine FalconAggregate.slots_well_formed_cons ?_ (ih _ hdrop)
    rw [List.length_take]
    exact Nat.min_eq_left hlen

/-- The slot list a level-`k` public-input vector carries (`child_pis`, agg.rs:337). -/
def decodeSlots (k : Nat) (pis : List Nat) : List FalconAggregate.Limbs :=
  FalconAggregate.chunks FalconAggregate.bytes32Len (2 ^ k)
    (pis.drop FalconAggregate.falconAggPkListOffset)

/-- The whole positional decode of a level-`k` proof's public inputs (`child_pis`,
agg.rs:332-339, uniform across levels including the leaf at `k = 0`). -/
def decodeStatementAt (k : Nat) (pis : List Nat) : FalconAggregate.AggStatement :=
  { message := FalconAggregate.decodeMessage pis
    count := FalconAggregate.decodeCount pis
    pks := decodeSlots k pis }

theorem decode_prefix_length {k : Nat} {pis : List Nat}
    (hlen : pis.length = FalconAggregate.falconAggPublicInputsLenAt k) :
    (pis.drop FalconAggregate.falconAggPkListOffset).length
      = 2 ^ k * FalconAggregate.bytes32Len := by
  have hp := two_pow_pos k
  rw [List.length_drop, hlen, len_at_unfold, pk_list_offset_unfold, bytes32_len_unfold]
  omega

theorem decode_statement_at_shape {k : Nat} {pis : List Nat}
    (hlen : pis.length = FalconAggregate.falconAggPublicInputsLenAt k) :
    (decodeStatementAt k pis).message.length = FalconAggregate.bytes32Len ∧
      (decodeStatementAt k pis).pks.length = 2 ^ k ∧
      FalconAggregate.SlotsWellFormed (decodeStatementAt k pis).pks := by
  refine ⟨?_, chunks_length _ _ _, chunks_well_formed _ _ (decode_prefix_length hlen)⟩
  show (pis.take FalconAggregate.bytes32Len).length = FalconAggregate.bytes32Len
  rw [List.length_take]
  refine Nat.min_eq_left ?_
  have hp := two_pow_pos k
  rw [hlen, len_at_unfold, bytes32_len_unfold]
  omega

/-- A public-input vector of the right width IS the canonical encoding of its own decode. -/
theorem statement_public_inputs_of_decode (k : Nat) (pis : List Nat)
    (hlen : pis.length = FalconAggregate.falconAggPublicInputsLenAt k) :
    FalconAggregate.statementPublicInputs (decodeStatementAt k pis) = pis := by
  have hjoin : (decodeSlots k pis).join = pis.drop FalconAggregate.falconAggPkListOffset :=
    chunks_join_id _ _ (decode_prefix_length hlen)
  have hdrop8 : pis.drop FalconAggregate.bytes32Len
      = (pis.drop FalconAggregate.bytes32Len).headD 0 ::
        pis.drop FalconAggregate.falconAggPkListOffset := by
    have hne : (pis.drop FalconAggregate.bytes32Len).length ≠ 0 := by
      have hp := two_pow_pos k
      rw [List.length_drop, hlen, len_at_unfold, bytes32_len_unfold]
      omega
    cases hcase : pis.drop FalconAggregate.bytes32Len with
    | nil => rw [hcase] at hne; simp at hne
    | cons x rest =>
      have hshift : pis.drop FalconAggregate.falconAggPkListOffset = rest := by
        have : pis.drop FalconAggregate.falconAggPkListOffset
            = (pis.drop FalconAggregate.bytes32Len).drop 1 := by
          rw [List.drop_drop]
          rfl
        rw [this, hcase]
        simp
      rw [hshift]
      simp
  show FalconAggregate.decodeMessage pis ++ [FalconAggregate.decodeCount pis] ++
      (decodeSlots k pis).join = pis
  rw [hjoin, List.append_assoc]
  show pis.take FalconAggregate.bytes32Len ++
      ((pis.drop FalconAggregate.bytes32Len).headD 0 ::
        pis.drop FalconAggregate.falconAggPkListOffset) = pis
  rw [← hdrop8, List.take_append_drop]

/-- ... and conversely the decode of a canonical encoding is the statement itself. -/
theorem decode_statement_at_public_inputs (k : Nat) (s : FalconAggregate.AggStatement)
    (hm : s.message.length = FalconAggregate.bytes32Len) (hlen : s.pks.length = 2 ^ k)
    (hw : FalconAggregate.SlotsWellFormed s.pks) :
    decodeStatementAt k (FalconAggregate.statementPublicInputs s) = s := by
  have hprefix : (s.message ++ [s.count]).length = FalconAggregate.falconAggPkListOffset := by
    simp [List.length_append, hm, FalconAggregate.falconAggPkListOffset]
  have hmsg : FalconAggregate.decodeMessage (FalconAggregate.statementPublicInputs s)
      = s.message := by
    show (FalconAggregate.statementPublicInputs s).take FalconAggregate.bytes32Len = s.message
    simp only [FalconAggregate.statementPublicInputs, List.append_assoc]
    exact List.take_left' hm
  have hcount : FalconAggregate.decodeCount (FalconAggregate.statementPublicInputs s)
      = s.count := by
    simp only [FalconAggregate.decodeCount, FalconAggregate.falconAggCountOffset,
      FalconAggregate.statementPublicInputs, List.append_assoc]
    rw [List.drop_left' hm]
    simp
  have hslots : decodeSlots k (FalconAggregate.statementPublicInputs s) = s.pks := by
    simp only [decodeSlots, FalconAggregate.statementPublicInputs]
    rw [List.drop_left' hprefix]
    have := FalconAggregate.chunks_join s.pks hw
    rw [hlen] at this
    exact this
  simp only [decodeStatementAt, hmsg, hcount, hslots]

/-! ## 4. The LEVEL circuit as a builder transcript (agg.rs:370-479) -/

/-- The opaque recursive-verification boundary of one level.

`verifyChild k proof pis` stands for `add_proof_target_and_verify` /
`add_proof_target_and_conditionally_verify` at level `k`: the proof verifies against the
level-`(k-1)` circuit's verifier data, which both helpers bake in as a CONSTANT (agg.rs:99-105,
:394-404). `childVerifierData` is that constant, carried so the A7 identity is visible as a
wire equation rather than hidden. Nothing here models a plonky2 proof; `RecursionSound` below
is the premise that connects it to satisfiability. -/
structure LevelEnvironment (ProofTy : Type) where
  childVerifierData : Nat → List Nat
  verifyChild : Nat → ProofTy → List Nat → Prop

/-- One constructor per builder call of `FalconAggLevelCircuit::new`.

* `verifyLeftChild` — agg.rs:399, `add_proof_target_and_verify(child_vd, &mut builder)`: the
  left child is verified UNCONDITIONALLY, at the CONSTANT child verifier data (A7,
  agg.rs:394-398). The child's public-input arity is the build-time assert of agg.rs:375-379.
* `addVirtualBoolSafe` — agg.rs:402, `add_virtual_bool_target_safe()` constrains the presence
  flag to `{0, 1}` (agg.rs:400-401: without it a fractional presence could scale counts and
  limbs arbitrarily).
* `conditionallyVerifyRightChild` — agg.rs:403-404,
  `add_proof_target_and_conditionally_verify(child_vd, &mut builder, is_right_present)`: when
  the flag is 1 the right proof is verified at the REAL child verifier data; when it is 0 the
  slot carries a canonical DUMMY proof whose public inputs are UNTRUSTED (agg.rs:49-52,
  :353-357). The model therefore constrains NOTHING about `rightPis` when the flag is 0 except
  its LENGTH.
* `gatedMessageEquality i` — agg.rs:412-416, ONE op per message limb `i` with the three builder
  calls of that loop iteration folded: `diff = sub(l, r)`, `gated = mul(flag, diff)`,
  `assert_zero(gated)`. Eight ops (`BYTES32_LEN`).
* `gatedCountR` — agg.rs:422, `mul(is_right_present.target, count_r)`.
* `signerCountAdd` — agg.rs:423, `add(count_l, gated_count_r)`.
* `halfFullConstant` — agg.rs:434, `constant(F::from_canonical_usize(1 << (level - 1)))`.
* `leftFullnessGap` — agg.rs:435, `sub(count_l, half_full)`.
* `gatedGap` — agg.rs:436, `mul(is_right_present.target, left_fullness_gap)`.
* `assertZeroGap` — agg.rs:437, `assert_zero(gated_gap)`: the LEFT-PACKING gate
  (agg.rs:425-433).
* `registerMessage8` — agg.rs:442, `register_public_inputs(&msg_l)`: the exposed message is the
  LEFT child's, copied verbatim.
* `registerSignerCount` — agg.rs:443, `register_public_input(signer_count)`.
* `registerLeftPks` — agg.rs:444, `register_public_inputs(&pks_l)`: the left child's slot
  limbs verbatim.
* `registerGatedRightPk i` — agg.rs:445-448, ONE op per RIGHT-half limb `i` with the two
  builder calls of that loop iteration folded: `gated = mul(flag, t)` and
  `register_public_input(gated)`. `2 ^ (level - 1) * BYTES32_LEN` ops.
* `requireLevelWidth` — agg.rs:456-462, the RELEASE-mode `assert_eq!` on the exposed arity; at
  `level = AGG_LEVELS` this IS the 73-element consumer contract.
* `addConstGate` — agg.rs:452, the `ConstantGate` for the NEXT level's dummy reconstruction;
  it adds no constraint on witness values, so its `holds` is `True`.
* `build` — agg.rs:455, `builder.build::<C>()`: emits no constraint, `holds` is `True`. -/
inductive LevelOp where
  | verifyLeftChild
  | addVirtualBoolSafe
  | conditionallyVerifyRightChild
  | gatedMessageEquality (limb : Nat)
  | gatedCountR
  | signerCountAdd
  | halfFullConstant
  | leftFullnessGap
  | gatedGap
  | assertZeroGap
  | registerMessage8
  | registerSignerCount
  | registerLeftPks
  | registerGatedRightPk (limb : Nat)
  | requireLevelWidth
  | addConstGate
  | build
  deriving DecidableEq, Repr

/-- A value for every wire `FalconAggLevelCircuit::new` allocates: the two child proofs with
their public-input vectors, the constant child verifier data, the presence flag, and the
intermediate `sub` / `mul` / `add` / `constant` wires in source order. -/
structure LevelAssignment (ProofTy : Type) where
  leftProof : ProofTy
  rightProof : ProofTy
  childVdWire : List Nat
  leftPis : List Nat
  rightPis : List Nat
  flag : Nat
  diffWire : Nat → Nat
  gatedMsgWire : Nat → Nat
  gatedCountRWire : Nat
  signerCountWire : Nat
  halfFullWire : Nat
  leftFullnessGapWire : Nat
  gatedGapWire : Nat
  gatedRightPkWire : Nat → Nat

/-- `2 ^ (level - 1) * BYTES32_LEN` — the number of pk limbs each child exposes
(`child_pis`, agg.rs:333-338). -/
def childSlotLimbs (k : Nat) : Nat := 2 ^ (k - 1) * FalconAggregate.bytes32Len

/-- `pks_l` (agg.rs:406). -/
def leftPkLimbs {ProofTy : Type} (k : Nat) (a : LevelAssignment ProofTy) : List Nat :=
  (a.leftPis.drop FalconAggregate.falconAggPkListOffset).take (childSlotLimbs k)

/-- `pks_r` (agg.rs:407). -/
def rightPkLimbs {ProofTy : Type} (k : Nat) (a : LevelAssignment ProofTy) : List Nat :=
  (a.rightPis.drop FalconAggregate.falconAggPkListOffset).take (childSlotLimbs k)

/-- Indexed wire block, `indexedWires`-style (avoids `List.range` in the reasoning). -/
def wireLimbs (f : Nat → Nat) : Nat → Nat → List Nat
  | _, 0 => []
  | s, n + 1 => f s :: wireLimbs f (s + 1) n

theorem wire_limbs_length (f : Nat → Nat) : ∀ (n s : Nat), (wireLimbs f s n).length = n := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ m ih => intro s; simp [wireLimbs, ih]

theorem wire_limbs_eq (f : Nat → Nat) : ∀ (n s : Nat) (l : List Nat), l.length = n →
    (∀ i, i < n → f (s + i) = l.getD i 0) → wireLimbs f s n = l := by
  intro n
  induction n with
  | zero =>
    intro s l hl _
    rw [List.eq_nil_of_length_eq_zero hl]
    rfl
  | succ m ih =>
    intro s l hl hget
    cases l with
    | nil => simp at hl
    | cons v vs =>
      have hlen : vs.length = m := by simpa using hl
      have hhead : f s = v := by
        have := hget 0 (by omega)
        simpa using this
      have htail : wireLimbs f (s + 1) m = vs := by
        refine ih (s + 1) vs hlen (fun i hi => ?_)
        have := hget (i + 1) (by omega)
        have hs : s + (i + 1) = s + 1 + i := by omega
        rw [hs] at this
        simpa using this
      simp only [wireLimbs, hhead, htail]

/-- The exposed right-half limbs `is_right_present * t` (agg.rs:445-448). -/
def gatedRightLimbs {ProofTy : Type} (k : Nat) (a : LevelAssignment ProofTy) : List Nat :=
  wireLimbs a.gatedRightPkWire 0 (childSlotLimbs k)

/-- The registered public inputs, in `register_public_input(s)` order (agg.rs:442-448). -/
def readLevelPublic {ProofTy : Type} (k : Nat) (a : LevelAssignment ProofTy) : List Nat :=
  FalconAggregate.decodeMessage a.leftPis ++ [a.signerCountWire] ++ leftPkLimbs k a ++
    gatedRightLimbs k a

/-- The ordered transcript of `FalconAggLevelCircuit::new` (agg.rs:370-479). -/
def levelProgram (k : Nat) : List LevelOp :=
  [LevelOp.verifyLeftChild, LevelOp.addVirtualBoolSafe, LevelOp.conditionallyVerifyRightChild] ++
    ((List.range FalconAggregate.bytes32Len).map LevelOp.gatedMessageEquality ++
      ([LevelOp.gatedCountR, LevelOp.signerCountAdd, LevelOp.halfFullConstant,
        LevelOp.leftFullnessGap, LevelOp.gatedGap, LevelOp.assertZeroGap,
        LevelOp.registerMessage8, LevelOp.registerSignerCount, LevelOp.registerLeftPks] ++
        ((List.range (childSlotLimbs k)).map LevelOp.registerGatedRightPk ++
          [LevelOp.requireLevelWidth, LevelOp.addConstGate, LevelOp.build])))

theorem level_program_length (k : Nat) :
    (levelProgram k).length = 23 + childSlotLimbs k := by
  simp only [levelProgram, List.length_append, List.length_map, range_length,
    List.length_cons, List.length_nil, bytes32_len_unfold]
  omega

theorem level_program_op_counts :
    (levelProgram 1).length = 31 ∧ (levelProgram 2).length = 39 ∧
      (levelProgram 3).length = 55 := by
  refine ⟨?_, ?_, ?_⟩ <;>
    · rw [level_program_length]
      decide

/-- Local satisfaction semantics of one builder call; see the `LevelOp` docstring for the
source line of each. Every arithmetic op is stated MODULO `fieldModulus` (Goldilocks); a wire
that is the OUTPUT of a field gate additionally records `< fieldModulus`, which is what "this
wire holds a field element" means. -/
def LevelOp.holds {ProofTy : Type} (env : LevelEnvironment ProofTy) (k : Nat)
    (op : LevelOp) (a : LevelAssignment ProofTy) : Prop :=
  match op with
  | .verifyLeftChild =>
      a.childVdWire = env.childVerifierData (k - 1) ∧
        env.verifyChild k a.leftProof a.leftPis ∧
        a.leftPis.length = FalconAggregate.falconAggPublicInputsLenAt (k - 1)
  | .addVirtualBoolSafe => a.flag = 0 ∨ a.flag = 1
  | .conditionallyVerifyRightChild =>
      a.rightPis.length = FalconAggregate.falconAggPublicInputsLenAt (k - 1) ∧
        (a.flag = 1 → env.verifyChild k a.rightProof a.rightPis)
  | .gatedMessageEquality i =>
      (a.diffWire i + (FalconAggregate.decodeMessage a.rightPis).getD i 0) % fieldModulus
          = (FalconAggregate.decodeMessage a.leftPis).getD i 0 % fieldModulus ∧
        a.gatedMsgWire i % fieldModulus = (a.flag * a.diffWire i) % fieldModulus ∧
        a.gatedMsgWire i % fieldModulus = 0
  | .gatedCountR =>
      a.gatedCountRWire % fieldModulus
        = (a.flag * FalconAggregate.decodeCount a.rightPis) % fieldModulus
  | .signerCountAdd =>
      a.signerCountWire < fieldModulus ∧
        a.signerCountWire % fieldModulus
          = (FalconAggregate.decodeCount a.leftPis + a.gatedCountRWire) % fieldModulus
  | .halfFullConstant => a.halfFullWire % fieldModulus = 2 ^ (k - 1) % fieldModulus
  | .leftFullnessGap =>
      (a.leftFullnessGapWire + a.halfFullWire) % fieldModulus
        = FalconAggregate.decodeCount a.leftPis % fieldModulus
  | .gatedGap =>
      a.gatedGapWire % fieldModulus = (a.flag * a.leftFullnessGapWire) % fieldModulus
  | .assertZeroGap => a.gatedGapWire % fieldModulus = 0
  | .registerMessage8 =>
      (FalconAggregate.decodeMessage a.leftPis).length = FalconAggregate.bytes32Len
  | .registerSignerCount =>
      FalconAggregate.decodeCount (readLevelPublic k a) = a.signerCountWire
  | .registerLeftPks => (leftPkLimbs k a).length = childSlotLimbs k
  | .registerGatedRightPk i =>
      a.gatedRightPkWire i < fieldModulus ∧
        a.gatedRightPkWire i % fieldModulus
          = (a.flag * (rightPkLimbs k a).getD i 0) % fieldModulus
  | .requireLevelWidth =>
      (readLevelPublic k a).length = FalconAggregate.falconAggPublicInputsLenAt k
  | .addConstGate => True
  | .build => True

/-- `ProgramSatisfied (levelProgram k) a` in the plan's notation. -/
def LevelProgramSatisfied {ProofTy : Type} (env : LevelEnvironment ProofTy) (k : Nat)
    (a : LevelAssignment ProofTy) : Prop :=
  ∀ op ∈ levelProgram k, op.holds env k a

theorem level_program_satisfied_of {ProofTy : Type} (env : LevelEnvironment ProofTy) (k : Nat)
    (a : LevelAssignment ProofTy)
    (h1 : LevelOp.verifyLeftChild.holds env k a)
    (h2 : LevelOp.addVirtualBoolSafe.holds env k a)
    (h3 : LevelOp.conditionallyVerifyRightChild.holds env k a)
    (hmsg : ∀ i, i < FalconAggregate.bytes32Len →
      (LevelOp.gatedMessageEquality i).holds env k a)
    (h4 : LevelOp.gatedCountR.holds env k a)
    (h5 : LevelOp.signerCountAdd.holds env k a)
    (h6 : LevelOp.halfFullConstant.holds env k a)
    (h7 : LevelOp.leftFullnessGap.holds env k a)
    (h8 : LevelOp.gatedGap.holds env k a)
    (h9 : LevelOp.assertZeroGap.holds env k a)
    (h10 : LevelOp.registerMessage8.holds env k a)
    (h11 : LevelOp.registerSignerCount.holds env k a)
    (h12 : LevelOp.registerLeftPks.holds env k a)
    (hpk : ∀ i, i < childSlotLimbs k → (LevelOp.registerGatedRightPk i).holds env k a)
    (h13 : LevelOp.requireLevelWidth.holds env k a) :
    LevelProgramSatisfied env k a := by
  intro op hop
  rcases List.mem_append.mp hop with h | h
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl | rfl
    · exact h1
    · exact h2
    · exact h3
  · rcases List.mem_append.mp h with h | h
    · obtain ⟨i, hi, rfl⟩ := List.mem_map.mp h
      exact hmsg i ((CloseCircuit.mem_range_iff_lt i _).mp hi)
    · rcases List.mem_append.mp h with h | h
      · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
        rcases h with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
        · exact h4
        · exact h5
        · exact h6
        · exact h7
        · exact h8
        · exact h9
        · exact h10
        · exact h11
        · exact h12
      · rcases List.mem_append.mp h with h | h
        · obtain ⟨i, hi, rfl⟩ := List.mem_map.mp h
          exact hpk i ((CloseCircuit.mem_range_iff_lt i _).mp hi)
        · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
          rcases h with rfl | rfl | rfl
          · exact h13
          · trivial
          · trivial

theorem level_program_holds {ProofTy : Type} {env : LevelEnvironment ProofTy} {k : Nat}
    {a : LevelAssignment ProofTy} (h : LevelProgramSatisfied env k a) :
    LevelOp.verifyLeftChild.holds env k a ∧
      LevelOp.addVirtualBoolSafe.holds env k a ∧
      LevelOp.conditionallyVerifyRightChild.holds env k a ∧
      (∀ i, i < FalconAggregate.bytes32Len → (LevelOp.gatedMessageEquality i).holds env k a) ∧
      LevelOp.gatedCountR.holds env k a ∧
      LevelOp.signerCountAdd.holds env k a ∧
      LevelOp.halfFullConstant.holds env k a ∧
      LevelOp.leftFullnessGap.holds env k a ∧
      LevelOp.gatedGap.holds env k a ∧
      LevelOp.assertZeroGap.holds env k a ∧
      LevelOp.registerMessage8.holds env k a ∧
      LevelOp.registerSignerCount.holds env k a ∧
      LevelOp.registerLeftPks.holds env k a ∧
      (∀ i, i < childSlotLimbs k → (LevelOp.registerGatedRightPk i).holds env k a) ∧
      LevelOp.requireLevelWidth.holds env k a := by
  have memA : ∀ op : LevelOp,
      op ∈ [LevelOp.verifyLeftChild, LevelOp.addVirtualBoolSafe,
            LevelOp.conditionallyVerifyRightChild] → op ∈ levelProgram k := by
    intro op hop
    exact List.mem_append.mpr (Or.inl hop)
  have memC : ∀ op : LevelOp,
      op ∈ [LevelOp.gatedCountR, LevelOp.signerCountAdd, LevelOp.halfFullConstant,
            LevelOp.leftFullnessGap, LevelOp.gatedGap, LevelOp.assertZeroGap,
            LevelOp.registerMessage8, LevelOp.registerSignerCount,
            LevelOp.registerLeftPks] → op ∈ levelProgram k := by
    intro op hop
    exact List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inr
      (List.mem_append.mpr (Or.inl hop)))))
  refine ⟨h _ (memA _ (by simp)), h _ (memA _ (by simp)), h _ (memA _ (by simp)), ?_,
    h _ (memC _ (by simp)), h _ (memC _ (by simp)), h _ (memC _ (by simp)),
    h _ (memC _ (by simp)), h _ (memC _ (by simp)), h _ (memC _ (by simp)),
    h _ (memC _ (by simp)), h _ (memC _ (by simp)), h _ (memC _ (by simp)), ?_, ?_⟩
  · intro i hi
    refine h _ (List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inl ?_))))
    exact List.mem_map.mpr ⟨i, (CloseCircuit.mem_range_iff_lt i _).mpr hi, rfl⟩
  · intro i hi
    refine h _ (List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inr
      (List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inl ?_))))))))
    exact List.mem_map.mpr ⟨i, (CloseCircuit.mem_range_iff_lt i _).mpr hi, rfl⟩
  · refine h _ (List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inr
      (List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inr (by simp)))))))))

/-! ### 4.1 Gate-level arithmetic derivations -/

/-- `assert_zero(mul(1, d))` forces `d ≡ 0` in the field. -/
theorem gated_zero_present {g d f : Nat} (hf : f = 1)
    (hmul : g % fieldModulus = (f * d) % fieldModulus) (hzero : g % fieldModulus = 0) :
    d % fieldModulus = 0 := by
  rw [hf, Nat.one_mul] at hmul
  exact hmul.symm.trans hzero

/-- The `sub` wire of agg.rs:413 with a zero difference forces limb equality on canonical
limbs. -/
theorem sub_gate_eq {d r l : Nat} (hd : d % fieldModulus = 0)
    (heq : (d + r) % fieldModulus = l % fieldModulus)
    (hr : r < fieldModulus) (hl : l < fieldModulus) : l = r := by
  have h1 : (d + r) % fieldModulus = r % fieldModulus := by
    rw [Nat.add_mod, hd, Nat.zero_add, mod_idem]
  rw [h1, Nat.mod_eq_of_lt hr, Nat.mod_eq_of_lt hl] at heq
  exact heq.symm

/-- `mul(1, v)` on canonical wires is `v`. -/
theorem mul_gate_present {g v f : Nat} (hf : f = 1) (hg : g < fieldModulus)
    (hv : v < fieldModulus) (hmul : g % fieldModulus = (f * v) % fieldModulus) : g = v := by
  rw [hf, Nat.one_mul, Nat.mod_eq_of_lt hv, Nat.mod_eq_of_lt hg] at hmul
  exact hmul

/-- `mul(0, v)` on a canonical wire is EXACTLY zero — the byte-identical padding of
agg.rs:73-77. -/
theorem mul_gate_absent {g v f : Nat} (hf : f = 0) (hg : g < fieldModulus)
    (hmul : g % fieldModulus = (f * v) % fieldModulus) : g = 0 := by
  rw [hf, Nat.zero_mul, Nat.zero_mod, Nat.mod_eq_of_lt hg] at hmul
  exact hmul

/-! ### 4.2 Well-formedness of a decoded child statement -/

/-- Everything a VERIFIED child statement carries into its parent. The range fields are the
hypotheses the induction supplies: canonical `u32` limbs and `1 <= count <= 2 ^ k`. -/
structure StatementWellFormed (k : Nat) (s : FalconAggregate.AggStatement) : Prop where
  message_length : s.message.length = FalconAggregate.bytes32Len
  message_canonical : ∀ x ∈ s.message, x < limbBase
  count_ge_one : 1 ≤ s.count
  count_le : s.count ≤ 2 ^ k
  pks_length : s.pks.length = 2 ^ k
  pks_well_formed : FalconAggregate.SlotsWellFormed s.pks
  pks_canonical : ∀ p ∈ s.pks, ∀ x ∈ p, x < limbBase

/-- The witness list a level-`k` statement stands for: `signer_count` genuinely verified,
ACTIVE gadget instances over ONE message, left-packed with an exactly-zero suffix. -/
structure WitnessedStatement (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (k : Nat) (s : FalconAggregate.AggStatement)
    (cws : List FalconCore.CircuitWitness) : Prop where
  count_eq : s.count = cws.length
  count_ge_one : 1 ≤ cws.length
  count_le : cws.length ≤ 2 ^ k
  message_length : s.message.length = FalconAggregate.bytes32Len
  message_canonical : ∀ x ∈ s.message, x < limbBase
  pks_eq : s.pks = cws.map (fun cw => limbsOfNat cw.pkG) ++
    List.replicate (2 ^ k - cws.length) FalconAggregate.zeroSlot
  signed : ∀ cw ∈ cws, FalconCore.CircuitSatisfied e p cw ∧ cw.verifyBit = 1 ∧
    cw.messageDigest = CloseSignatureBridge.digestOfLimbs s.message

theorem witnessed_statement_well_formed {e : FalconCore.HashEnvironment}
    {p : FalconCore.PolynomialProduct} {k : Nat} {s : FalconAggregate.AggStatement}
    {cws : List FalconCore.CircuitWitness} (hw : WitnessedStatement e p k s cws) :
    StatementWellFormed k s := by
  have hpad : FalconAggregate.SlotsWellFormed
      (List.replicate (2 ^ k - cws.length) FalconAggregate.zeroSlot) :=
    FalconAggregate.slots_well_formed_replicate _
  refine ⟨hw.message_length, hw.message_canonical, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hw.count_eq]; exact hw.count_ge_one
  · rw [hw.count_eq]; exact hw.count_le
  · rw [hw.pks_eq, List.length_append, List.length_map, List.length_replicate]
    exact Nat.add_sub_cancel' hw.count_le
  · rw [hw.pks_eq]
    exact FalconAggregate.slots_well_formed_append (active_slots_well_formed cws) hpad
  · rw [hw.pks_eq]
    intro q hq x hx
    rcases List.mem_append.mp hq with hq' | hq'
    · exact active_slots_canonical cws q hq' x hx
    · rw [FalconAggregate.mem_replicate_eq hq'] at hx
      exact zero_slot_canonical x hx

/-! ### 4.3 `levelCompose` in `.ok` form -/

theorem level_compose_present_ok {level : Nat} {l r s : FalconAggregate.AggStatement}
    (h : FalconAggregate.levelCompose level true l r = .ok s) :
    s = { message := l.message, count := l.count + r.count, pks := l.pks ++ r.pks } := by
  simp only [FalconAggregate.levelCompose, if_true] at h
  split at h
  · cases h
  · split at h
    · cases h
    · exact (Except.ok.inj h).symm

theorem level_compose_present_of {level : Nat} {l r : FalconAggregate.AggStatement}
    (hmsg : l.message = r.message) (hlen : l.message.length = r.message.length)
    (hfull : l.count = 2 ^ (level - 1)) :
    FalconAggregate.levelCompose level true l r =
      .ok { message := l.message, count := l.count + r.count, pks := l.pks ++ r.pks } := by
  have hagree : FalconAggregate.messageAgrees l.message r.message = true :=
    (FalconAggregate.message_agrees_iff_eq _ _ hlen).mpr hmsg
  simp only [FalconAggregate.levelCompose, if_true, hagree, Bool.not_true, Bool.false_eq_true,
    if_false]
  rw [if_neg (by simp [hfull])]

theorem level_compose_absent_ok {level : Nat} {l r s : FalconAggregate.AggStatement}
    (h : FalconAggregate.levelCompose level false l r = .ok s) :
    s = { message := l.message, count := l.count,
          pks := l.pks ++ FalconAggregate.gateSlots false r.pks } := by
  simp only [FalconAggregate.levelCompose, Bool.false_eq_true, if_false] at h
  exact (Except.ok.inj h).symm

theorem level_compose_absent_of {level : Nat} (l r : FalconAggregate.AggStatement) :
    FalconAggregate.levelCompose level false l r =
      .ok { message := l.message, count := l.count,
            pks := l.pks ++ FalconAggregate.gateSlots false r.pks } := by
  simp only [FalconAggregate.levelCompose, Bool.false_eq_true, if_false]

/-! ### 4.4 The level theorem -/

/-- THE LEVEL COMPOSITION. A satisfied level-`k` transcript composes its two children exactly
as `FalconAggregate.levelCompose` does, and the registered public inputs are the encoding of
that composition.

The presence bit is the ONLY witness: with `flag = 1` the message agreement (agg.rs:412-416)
and left-fullness (agg.rs:434-437) gates FORCE the `.ok` branch; with `flag = 0` nothing about
the right child's public inputs is used except their WIDTH (the dummy-proof path,
agg.rs:49-52), which is why the derived statement is
`FalconAggregate.absent_right_child_statement_is_ignored`-stable. -/
theorem level_program_satisfied_implies_compose {ProofTy : Type}
    (env : LevelEnvironment ProofTy) (k : Nat) (hk1 : 1 ≤ k)
    (hk3 : k ≤ FalconAggregate.aggLevels) (a : LevelAssignment ProofTy)
    (sl : FalconAggregate.AggStatement) (hsl : StatementWellFormed (k - 1) sl)
    (hlpis : a.leftPis = FalconAggregate.statementPublicInputs sl)
    (hsr : a.flag = 1 → StatementWellFormed (k - 1) (decodeStatementAt (k - 1) a.rightPis))
    (h : LevelProgramSatisfied env k a) :
    ∃ s : FalconAggregate.AggStatement,
      FalconAggregate.levelCompose k (a.flag == 1) sl (decodeStatementAt (k - 1) a.rightPis)
          = .ok s ∧
        readLevelPublic k a = FalconAggregate.statementPublicInputs s := by
  obtain ⟨hleft, hbool, hright, hmsgeq, hgcr, hadd, hhalf, hgap, hggap, hzgap, _hregm,
    hregc, _hregl, hregpk, _hwidth⟩ := level_program_holds h
  simp only [LevelOp.holds] at hleft hbool hright hmsgeq hgcr hadd hhalf hgap hggap hzgap
    hregc hregpk
  have hrlen : a.rightPis.length = FalconAggregate.falconAggPublicInputsLenAt (k - 1) :=
    hright.1
  obtain ⟨_hrmlen, hrpklen0, hrpkwf0⟩ := decode_statement_at_shape (k := k - 1) hrlen
  obtain ⟨sr, hsrdef⟩ : ∃ sr, decodeStatementAt (k - 1) a.rightPis = sr := ⟨_, rfl⟩
  rw [hsrdef] at hsr hrpklen0 hrpkwf0 ⊢
  have hrpklen : sr.pks.length = 2 ^ (k - 1) := hrpklen0
  have hrpkwf : FalconAggregate.SlotsWellFormed sr.pks := hrpkwf0
  -- the left child's positional reads
  have hlmsg : FalconAggregate.decodeMessage a.leftPis = sl.message := by
    rw [hlpis]
    exact congrArg FalconAggregate.AggStatement.message
      (decode_statement_at_public_inputs (k - 1) sl hsl.message_length hsl.pks_length
        hsl.pks_well_formed)
  have hlcount : FalconAggregate.decodeCount a.leftPis = sl.count := by
    rw [hlpis]
    exact congrArg FalconAggregate.AggStatement.count
      (decode_statement_at_public_inputs (k - 1) sl hsl.message_length hsl.pks_length
        hsl.pks_well_formed)
  have hlslots : decodeSlots (k - 1) a.leftPis = sl.pks := by
    rw [hlpis]
    exact congrArg FalconAggregate.AggStatement.pks
      (decode_statement_at_public_inputs (k - 1) sl hsl.message_length hsl.pks_length
        hsl.pks_well_formed)
  have hllen : a.leftPis.length = FalconAggregate.falconAggPublicInputsLenAt (k - 1) :=
    hleft.2.2
  have hljoin : leftPkLimbs k a = sl.pks.join := by
    have hjoin : (decodeSlots (k - 1) a.leftPis).join
        = a.leftPis.drop FalconAggregate.falconAggPkListOffset :=
      chunks_join_id _ _ (decode_prefix_length hllen)
    have hlenj : (a.leftPis.drop FalconAggregate.falconAggPkListOffset).length
        = childSlotLimbs k := decode_prefix_length hllen
    show (a.leftPis.drop FalconAggregate.falconAggPkListOffset).take (childSlotLimbs k)
      = sl.pks.join
    rw [← hlenj, List.take_length, ← hjoin, hlslots]
  have hrjoin : rightPkLimbs k a = sr.pks.join := by
    have hjoin : (decodeSlots (k - 1) a.rightPis).join
        = a.rightPis.drop FalconAggregate.falconAggPkListOffset :=
      chunks_join_id _ _ (decode_prefix_length hrlen)
    have hlenj : (a.rightPis.drop FalconAggregate.falconAggPkListOffset).length
        = childSlotLimbs k := decode_prefix_length hrlen
    show (a.rightPis.drop FalconAggregate.falconAggPkListOffset).take (childSlotLimbs k)
      = sr.pks.join
    rw [← hlenj, List.take_length, ← hjoin]
    exact congrArg List.join (congrArg FalconAggregate.AggStatement.pks hsrdef)
  have hrmsg : FalconAggregate.decodeMessage a.rightPis = sr.message :=
    congrArg FalconAggregate.AggStatement.message hsrdef
  have hrcount : FalconAggregate.decodeCount a.rightPis = sr.count :=
    congrArg FalconAggregate.AggStatement.count hsrdef
  -- range facts
  have hk3' : k ≤ 3 := hk3
  have hhalfle : 2 ^ (k - 1) ≤ 4 := by
    have : (2 : Nat) ^ (k - 1) ≤ 2 ^ 2 := Nat.pow_le_pow_right (by decide) (by omega)
    simpa using this
  have hslcount : sl.count < fieldModulus :=
    small_lt_field (Nat.le_trans hsl.count_le (by omega))
  -- case on the presence bit
  rcases hbool with hf | hf
  · -- ABSENT right child: the exposed statement ignores its public inputs entirely
    have hgcrz : a.gatedCountRWire % fieldModulus = 0 := by
      rw [hgcr, hf, Nat.zero_mul, Nat.zero_mod]
    have hcount : a.signerCountWire = sl.count := by
      have h1 := hadd.2
      rw [Nat.add_mod, hgcrz, hlcount, Nat.add_zero, mod_idem,
        Nat.mod_eq_of_lt hslcount, Nat.mod_eq_of_lt hadd.1] at h1
      exact h1
    have hgated : gatedRightLimbs k a = List.replicate (childSlotLimbs k) 0 := by
      refine wire_limbs_eq _ _ _ _ (List.length_replicate _ _) (fun i hi => ?_)
      have hz : a.gatedRightPkWire (0 + i) = 0 := by
        have := hregpk (0 + i) (by omega)
        exact mul_gate_absent hf this.1 this.2
      rw [hz, replicate_zero_get_default]
    refine ⟨{ message := sl.message, count := sl.count,
              pks := sl.pks ++ FalconAggregate.gateSlots false sr.pks }, ?_, ?_⟩
    · rw [show (a.flag == 1) = false by simp [hf]]
      exact level_compose_absent_of sl sr
    · have hgs : FalconAggregate.gateSlots false sr.pks
          = List.replicate (2 ^ (k - 1)) FalconAggregate.zeroSlot := by
        rw [FalconAggregate.gate_slots_absent _ hrpkwf, hrpklen]
      show FalconAggregate.decodeMessage a.leftPis ++ [a.signerCountWire] ++ leftPkLimbs k a ++
        gatedRightLimbs k a = _
      rw [hlmsg, hcount, hljoin, hgated]
      show sl.message ++ [sl.count] ++ sl.pks.join ++ List.replicate (childSlotLimbs k) 0
        = sl.message ++ [sl.count] ++ (sl.pks ++
            FalconAggregate.gateSlots false sr.pks).join
      rw [hgs, FalconAggregate.join_append_eq, FalconAggregate.join_replicate_zero_slot,
        List.append_assoc]
      rfl
  · -- PRESENT right child: message agreement and left-fullness are forced
    have hsrwf := hsr hf
    have hmsgs : sl.message = sr.message := by
      refine list_ext_get_default _ _ (by rw [hsl.message_length, hsrwf.message_length]) ?_
      intro i hi
      have hi8 : i < FalconAggregate.bytes32Len := by
        rw [hsl.message_length] at hi; exact hi
      obtain ⟨hsub, hmul, hzero⟩ := hmsgeq i hi8
      have hd : a.diffWire i % fieldModulus = 0 := gated_zero_present hf hmul hzero
      rw [hlmsg, hrmsg] at hsub
      exact sub_gate_eq hd hsub
        (limb_lt_field (get_default_lt _ _ (by decide) hsrwf.message_canonical i))
        (limb_lt_field (get_default_lt _ _ (by decide) hsl.message_canonical i))
    have hfull : sl.count = 2 ^ (k - 1) := by
      have hgapz : a.leftFullnessGapWire % fieldModulus = 0 :=
        gated_zero_present hf hggap hzgap
      have h1 := hgap
      rw [Nat.add_mod, hgapz, Nat.zero_add, mod_idem, hhalf, hlcount] at h1
      have h2 : 2 ^ (k - 1) % fieldModulus = 2 ^ (k - 1) :=
        Nat.mod_eq_of_lt (small_lt_field (by omega))
      rw [h2, Nat.mod_eq_of_lt hslcount] at h1
      exact h1.symm
    have hsrcount : sr.count < fieldModulus :=
      small_lt_field (Nat.le_trans hsrwf.count_le (by omega))
    have hsum : sl.count + sr.count ≤ 8 := by
      have := hsrwf.count_le
      omega
    have hgcrv : a.gatedCountRWire % fieldModulus = sr.count := by
      rw [hgcr, hf, Nat.one_mul, hrcount, Nat.mod_eq_of_lt hsrcount]
    have hcount : a.signerCountWire = sl.count + sr.count := by
      have h1 := hadd.2
      rw [Nat.add_mod, hgcrv, hlcount, Nat.mod_eq_of_lt hslcount,
        Nat.mod_eq_of_lt (small_lt_field hsum), Nat.mod_eq_of_lt hadd.1] at h1
      exact h1
    have hgated : gatedRightLimbs k a = sr.pks.join := by
      have hjlen : sr.pks.join.length = childSlotLimbs k := by
        rw [FalconAggregate.join_length_of_well_formed _ hrpkwf, hrpklen]
        rfl
      refine wire_limbs_eq _ _ _ _ hjlen (fun i hi => ?_)
      have hpk := hregpk (0 + i) (by omega)
      have hlt : (rightPkLimbs k a).getD (0 + i) 0 < fieldModulus := by
        rw [hrjoin]
        exact limb_lt_field (get_default_lt _ _ (by decide)
          (join_members_lt hsrwf.pks_canonical) _)
      have := mul_gate_present hf hpk.1 hlt hpk.2
      rw [this, hrjoin]
      simp
    refine ⟨{ message := sl.message, count := sl.count + sr.count, pks := sl.pks ++ sr.pks },
      ?_, ?_⟩
    · rw [show (a.flag == 1) = true by simp [hf]]
      exact level_compose_present_of hmsgs
        (by rw [hsl.message_length, hsrwf.message_length]) hfull
    · show FalconAggregate.decodeMessage a.leftPis ++ [a.signerCountWire] ++ leftPkLimbs k a ++
        gatedRightLimbs k a = _
      rw [hlmsg, hcount, hljoin, hgated]
      show sl.message ++ [sl.count + sr.count] ++ sl.pks.join ++ sr.pks.join
        = sl.message ++ [sl.count + sr.count] ++ (sl.pks ++ sr.pks).join
      rw [FalconAggregate.join_append_eq, List.append_assoc]

/-! ## 5. The induction over the four circuits (leaf, level 1, 2, 3) -/

/-- (d0') RECURSION SOUNDNESS, per level: a proof that the level-`k` circuit's recursive
verifier accepts means the level-`(k-1)` circuit is SATISFIABLE at those public inputs. This
is plonky2's own soundness, restricted to the four pinned circuits; nothing in this audit
models a proof. -/
def RecursionSound {ProofTy : Type} (Sat : Nat → List Nat → Prop)
    (env : LevelEnvironment ProofTy) : Prop :=
  ∀ k : Nat, 1 ≤ k → k ≤ FalconAggregate.aggLevels →
    ∀ (proof : ProofTy) (pis : List Nat), env.verifyChild k proof pis → Sat (k - 1) pis

/-- (d1') PER-PRIMITIVE LOWERING, per level: a satisfiable circuit instance yields an
assignment satisfying the corresponding builder transcript with the same public inputs. This
replaces the whole-circuit `aggregateStatementLowering` premise. -/
def LevelLowering {ProofTy : Type} (Sat : Nat → List Nat → Prop)
    (env : LevelEnvironment ProofTy) (e : FalconCore.HashEnvironment)
    (p : FalconCore.PolynomialProduct) : Prop :=
  (∀ words : List Nat, Sat 0 words →
      ∃ a : LeafAssignment, LeafProgramSatisfied e p a ∧ readLeafPublic a = words) ∧
  (∀ k : Nat, 1 ≤ k → k ≤ FalconAggregate.aggLevels → ∀ words : List Nat, Sat k words →
      ∃ a : LevelAssignment ProofTy,
        LevelProgramSatisfied env k a ∧ readLevelPublic k a = words)

/-- One aggregation step on the WITNESS side: the parent's witness list is the concatenation
of the children's (an absent right child contributes nothing but padding). -/
theorem witnessed_level_step (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (k : Nat) (hk1 : 1 ≤ k) (present : Bool) (sl sr s : FalconAggregate.AggStatement)
    (cwsl : List FalconCore.CircuitWitness) (hwl : WitnessedStatement e p (k - 1) sl cwsl)
    (hrwf : FalconAggregate.SlotsWellFormed sr.pks) (hrlen : sr.pks.length = 2 ^ (k - 1))
    (hwr : present = true → ∃ cwsr, WitnessedStatement e p (k - 1) sr cwsr)
    (hok : FalconAggregate.levelCompose k present sl sr = .ok s) :
    ∃ cws, WitnessedStatement e p k s cws := by
  have hhalf : 2 ^ k = 2 ^ (k - 1) + 2 ^ (k - 1) := pow_two_split k hk1
  cases present with
  | false =>
    have hs := level_compose_absent_ok hok
    have hgs : FalconAggregate.gateSlots false sr.pks
        = List.replicate (2 ^ (k - 1)) FalconAggregate.zeroSlot := by
      rw [FalconAggregate.gate_slots_absent _ hrwf, hrlen]
    refine ⟨cwsl, ?_⟩
    have hpks : s.pks = cwsl.map (fun cw => limbsOfNat cw.pkG) ++
        List.replicate (2 ^ k - cwsl.length) FalconAggregate.zeroSlot := by
      rw [hs]
      show sl.pks ++ FalconAggregate.gateSlots false sr.pks = _
      rw [hgs, hwl.pks_eq, List.append_assoc, replicate_append_replicate]
      have : 2 ^ (k - 1) - cwsl.length + 2 ^ (k - 1) = 2 ^ k - cwsl.length := by
        have := hwl.count_le
        omega
      rw [this]
    refine ⟨?_, hwl.count_ge_one, ?_, ?_, ?_, hpks, ?_⟩
    · rw [hs]; exact hwl.count_eq
    · exact Nat.le_trans hwl.count_le (by omega)
    · rw [hs]; exact hwl.message_length
    · rw [hs]; exact hwl.message_canonical
    · intro cw hcw
      obtain ⟨h1, h2, h3⟩ := hwl.signed cw hcw
      exact ⟨h1, h2, by rw [hs]; exact h3⟩
  | true =>
    obtain ⟨cwsr, hwr'⟩ := hwr rfl
    have hs := level_compose_present_ok hok
    have hfull : sl.count = 2 ^ (k - 1) :=
      FalconAggregate.level_present_forces_full_left_child hok
    have hmsgeq : sl.message = sr.message :=
      FalconAggregate.level_present_forces_message_agreement hok
        (by rw [hwl.message_length, hwr'.message_length])
    have hlfull : cwsl.length = 2 ^ (k - 1) := by rw [← hwl.count_eq]; exact hfull
    have hlpks : sl.pks = cwsl.map (fun cw => limbsOfNat cw.pkG) := by
      rw [hwl.pks_eq, hlfull, Nat.sub_self]
      simp
    refine ⟨cwsl ++ cwsr, ?_⟩
    have hpks : s.pks = (cwsl ++ cwsr).map (fun cw => limbsOfNat cw.pkG) ++
        List.replicate (2 ^ k - (cwsl ++ cwsr).length) FalconAggregate.zeroSlot := by
      rw [hs]
      show sl.pks ++ sr.pks = _
      rw [hlpks, hwr'.pks_eq, List.map_append, List.append_assoc, List.length_append, hlfull]
      have : 2 ^ (k - 1) - cwsr.length = 2 ^ k - (2 ^ (k - 1) + cwsr.length) := by
        have := hwr'.count_le
        omega
      rw [this]
    refine ⟨?_, ?_, ?_, ?_, ?_, hpks, ?_⟩
    · rw [hs, List.length_append]
      show sl.count + sr.count = cwsl.length + cwsr.length
      rw [hwl.count_eq, hwr'.count_eq]
    · rw [List.length_append]
      have := hwl.count_ge_one
      omega
    · rw [List.length_append, hlfull]
      have := hwr'.count_le
      omega
    · rw [hs]; exact hwl.message_length
    · rw [hs]; exact hwl.message_canonical
    · intro cw hcw
      rcases List.mem_append.mp hcw with hcw' | hcw'
      · obtain ⟨h1, h2, h3⟩ := hwl.signed cw hcw'
        exact ⟨h1, h2, by rw [hs]; exact h3⟩
      · obtain ⟨h1, h2, h3⟩ := hwr'.signed cw hcw'
        exact ⟨h1, h2, by rw [hs]; show cw.messageDigest = _; rw [hmsgeq]; exact h3⟩

/-- THE INDUCTION, at a general level. From recursive-verifier soundness and per-level
primitive lowering alone, a satisfiable level-`k` public-input vector is the canonical encoding
of a statement backed by between 1 and `2 ^ k` ACTIVE `gadget.rs` instances, all over ONE
message. -/
theorem satisfiable_level_gives_witness_list {ProofTy : Type}
    (env : LevelEnvironment ProofTy) (Sat : Nat → List Nat → Prop)
    (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (hrec : RecursionSound Sat env) (hlow : LevelLowering Sat env e p) :
    ∀ (k : Nat), k ≤ FalconAggregate.aggLevels → ∀ (words : List Nat), Sat k words →
      ∃ (s : FalconAggregate.AggStatement) (cws : List FalconCore.CircuitWitness),
        words = FalconAggregate.statementPublicInputs s ∧ WitnessedStatement e p k s cws := by
  intro k
  induction k with
  | zero =>
    intro _ words hsat
    obtain ⟨a, hprog, hread⟩ := hlow.1 words hsat
    obtain ⟨hpub, hsatc, hbit, hdig, hpk, hmlen, hmcan⟩ :=
      leaf_program_satisfied_implies_statement e p a hprog
    refine ⟨{ message := a.messageLimbs, count := 1, pks := [a.pkGLimbs] }, [a.sig], ?_, ?_⟩
    · rw [← hread, hpub]
    · refine ⟨by simp, by simp, by simp, hmlen, hmcan, ?_, ?_⟩
      · show [a.pkGLimbs] = _
        rw [hpk]
        simp
      · intro cw hcw
        have : cw = a.sig := by simpa using hcw
        rw [this]
        exact ⟨hsatc, hbit, hdig⟩
  | succ n ih =>
    intro hk words hsat
    have hk1 : 1 ≤ n + 1 := Nat.succ_le_succ (Nat.zero_le n)
    have hn : n ≤ FalconAggregate.aggLevels := by
      have : n + 1 ≤ 3 := hk
      show n ≤ 3
      omega
    obtain ⟨a, hprog, hread⟩ := hlow.2 (n + 1) hk1 hk words hsat
    obtain ⟨hleft, _, hright, _, _, _, _, _, _, _, _, _, _, _, _⟩ := level_program_holds hprog
    have hsatl : Sat n a.leftPis := by
      have := hrec (n + 1) hk1 hk a.leftProof a.leftPis hleft.2.1
      simpa using this
    obtain ⟨sl, cwsl, hlpis, hwl⟩ := ih hn a.leftPis hsatl
    have hslwf : StatementWellFormed n sl := witnessed_statement_well_formed hwl
    have hslwf' : StatementWellFormed (n + 1 - 1) sl := by simpa using hslwf
    have hrwit : a.flag = 1 →
        ∃ cwsr, WitnessedStatement e p n (decodeStatementAt n a.rightPis) cwsr := by
      intro hf
      have hver := hright.2 hf
      have hsatr : Sat n a.rightPis := by
        have := hrec (n + 1) hk1 hk a.rightProof a.rightPis hver
        simpa using this
      obtain ⟨sr, cwsr, hrpis, hwr⟩ := ih hn a.rightPis hsatr
      have hswf : StatementWellFormed n sr := witnessed_statement_well_formed hwr
      have hdec : decodeStatementAt n a.rightPis = sr := by
        rw [hrpis]
        exact decode_statement_at_public_inputs n sr hswf.message_length hswf.pks_length
          hswf.pks_well_formed
      rw [hdec]
      exact ⟨cwsr, hwr⟩
    have hsrwf : a.flag = 1 → StatementWellFormed (n + 1 - 1) (decodeStatementAt (n + 1 - 1)
        a.rightPis) := by
      intro hf
      obtain ⟨cwsr, hwr⟩ := hrwit hf
      have := witnessed_statement_well_formed hwr
      simpa using this
    obtain ⟨s, hok, hpub⟩ :=
      level_program_satisfied_implies_compose env (n + 1) hk1 hk a sl hslwf'
        (by simpa using hlpis ▸ rfl) hsrwf hprog
    have hrlen : a.rightPis.length
        = FalconAggregate.falconAggPublicInputsLenAt (n + 1 - 1) := hright.1
    obtain ⟨_, hrpklen, hrpkwf⟩ := decode_statement_at_shape (k := n + 1 - 1) hrlen
    have hstep := witnessed_level_step e p (n + 1) hk1 (a.flag == 1) sl
      (decodeStatementAt (n + 1 - 1) a.rightPis) s cwsl (by simpa using hwl) hrpkwf
      (by simpa using hrpklen) (fun hb => hrwit (by simpa using hb)) hok
    obtain ⟨cws, hw⟩ := hstep
    exact ⟨s, cws, by rw [← hread, hpub], hw⟩

/-- THE HEADLINE. A satisfiable TOP-level (`k = AGG_LEVELS = 3`) public-input vector is
literally `falcon_agg_expected_public_inputs` (agg.rs:176-195) of one message and between 1 and
`MAX_SIG_CLUSTER` genuinely satisfied, ACTIVE `gadget.rs` instances, every one of them verified
against THAT message. -/
theorem satisfiable_top_level_gives_witness_list {ProofTy : Type}
    (env : LevelEnvironment ProofTy) (Sat : Nat → List Nat → Prop)
    (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (hrec : RecursionSound Sat env) (hlow : LevelLowering Sat env e p)
    (words : List Nat) (hsat : Sat FalconAggregate.aggLevels words) :
    ∃ (message : FalconAggregate.Limbs) (cws : List FalconCore.CircuitWitness),
      message.length = FalconAggregate.bytes32Len ∧
      (∀ x ∈ message, x < limbBase) ∧
      words = FalconAggregate.aggExpectedPublicInputs FalconAggregate.aggLevels message
        (cws.map (fun cw => limbsOfNat cw.pkG)) ∧
      1 ≤ cws.length ∧ cws.length ≤ FalconAggregate.maxSigCluster ∧
      (∀ cw ∈ cws, FalconCore.CircuitSatisfied e p cw ∧ cw.verifyBit = 1 ∧
        cw.messageDigest = CloseSignatureBridge.digestOfLimbs message) := by
  obtain ⟨s, cws, hwords, hw⟩ :=
    satisfiable_level_gives_witness_list env Sat e p hrec hlow FalconAggregate.aggLevels
      (Nat.le_refl _) words hsat
  refine ⟨s.message, cws, hw.message_length, hw.message_canonical, ?_, hw.count_ge_one, ?_,
    hw.signed⟩
  · have hmatch := FalconAggregate.statement_public_inputs_match_reference
      (level := FalconAggregate.aggLevels) (message := s.message)
      (active := cws.map (fun cw => limbsOfNat cw.pkG)) hw.message_length
      (active_slots_well_formed cws) (by simpa using hw.count_le)
    rw [hwords, ← hmatch]
    show FalconAggregate.statementPublicInputs s = _
    simp only [FalconAggregate.statementPublicInputs, hw.count_eq, hw.pks_eq, List.length_map]
  · have := hw.count_le
    have h8 : (2 : Nat) ^ FalconAggregate.aggLevels = FalconAggregate.maxSigCluster := by decide
    rw [← h8]
    exact hw.count_le

/-! ## 6. From the witness list to per-signer evidence -/

/-- The `FalconAggregate.SigEnv` this module's conclusions speak in: the key digest callback is
`FalconCore.falconPkDigest` in LIMB form (`limbsOfNat`), and the accept callback is the
constant `true` — `CloseSignatureBridge.SignerEvidence` never reads it, because the per-slot
evidence now comes from `FalconCore.CircuitSatisfied` directly rather than from an opaque
`Bool`. -/
def sigEnvOf (e : FalconCore.HashEnvironment) : FalconAggregate.SigEnv :=
  { pkDigest := fun h => limbsOfNat (FalconCore.falconPkDigest e h)
    falconAccepts := fun _ _ _ _ => true }

theorem sig_env_of_shape (e : FalconCore.HashEnvironment) :
    FalconAggregate.SigEnvShape (sigEnvOf e) := fun _ => limbs_of_nat_length _

/-- The slot witness a satisfied gadget instance presents to the aggregate model
(`FalconSigGadgetWitness`, gadget.rs:800-810: `h`, `s2` and `salt` convert by IDENTITY). -/
def slotWitnessOf (message : FalconAggregate.Limbs) (cw : FalconCore.CircuitWitness) :
    FalconAggregate.SlotWitness :=
  { h := cw.h, s2 := cw.s2, salt := cw.salt, messageDigest := message }

/-- THE CONSUMER BRIDGE. The conclusion of the induction theorem, at a public-input vector that
IS the close circuit's aggregate statement, plus (d3) unforgeability, gives exactly
`CloseSignatureBridge.SignerEvidence`: the count, the left-packed key digests with an
exactly-zero suffix, one shared message, and an authorisation by each active slot's key
holder.

Nothing here assumes Poseidon injectivity: `keys_eq` speaks of DIGESTS, obtained from the
gadget's own `pk_g` binding wire (`FalconCore.CircuitSatisfied.pkBinding`). -/
theorem witness_list_gives_signer_evidence (e : FalconCore.HashEnvironment)
    (p : FalconCore.PolynomialProduct) (authorized : List Nat → List Nat → Prop)
    (unforgeable : CloseSignatureBridge.FalconUnforgeable e p authorized)
    (st : CloseCircuit.AggregateStatement) (message : FalconAggregate.Limbs)
    (cws : List FalconCore.CircuitWitness)
    (hmlen : message.length = FalconAggregate.bytes32Len)
    (hwords : FalconAggregate.statementPublicInputs (CloseSignatureBridge.toAggStatement st)
      = FalconAggregate.aggExpectedPublicInputs FalconAggregate.aggLevels message
        (cws.map (fun cw => limbsOfNat cw.pkG)))
    (hge : 1 ≤ cws.length) (hle : cws.length ≤ FalconAggregate.maxSigCluster)
    (hcws : ∀ cw ∈ cws, FalconCore.CircuitSatisfied e p cw ∧ cw.verifyBit = 1 ∧
      cw.messageDigest = CloseSignatureBridge.digestOfLimbs message) :
    CloseSignatureBridge.SignerEvidence (sigEnvOf e) authorized st.message st.keys
      st.signerCount := by
  obtain ⟨active, hactive⟩ : ∃ l, cws.map (fun cw => limbsOfNat cw.pkG) = l := ⟨_, rfl⟩
  rw [hactive] at hwords
  have hactivewf : FalconAggregate.SlotsWellFormed active := hactive ▸ active_slots_well_formed cws
  have hactivelen : active.length = cws.length := by
    rw [← hactive]; exact List.length_map _ _
  have hn : active.length ≤ 2 ^ FalconAggregate.aggLevels := by
    rw [hactivelen]
    exact hle
  have hstwf : FalconAggregate.SlotsWellFormed (CloseSignatureBridge.toAggStatement st).pks :=
    CloseSignatureBridge.to_agg_statement_slots_well_formed st
  have hstmsg : (CloseSignatureBridge.toAggStatement st).message.length
      = FalconAggregate.bytes32Len := rfl
  -- the message
  have hmsg : st.message.words = message := by
    have hl : FalconAggregate.decodeMessage
        (FalconAggregate.statementPublicInputs (CloseSignatureBridge.toAggStatement st))
        = st.message.words := by
      show (FalconAggregate.statementPublicInputs
        (CloseSignatureBridge.toAggStatement st)).take FalconAggregate.bytes32Len = _
      simp only [FalconAggregate.statementPublicInputs, List.append_assoc]
      exact List.take_left' hstmsg
    have hr := FalconAggregate.agg_expected_decode_message (level := FalconAggregate.aggLevels)
      hmlen hactivewf hn
    rw [← hl, hwords, hr]
  -- the count
  have hcount : st.signerCount = cws.length := by
    have hl : FalconAggregate.decodeCount
        (FalconAggregate.statementPublicInputs (CloseSignatureBridge.toAggStatement st))
        = st.signerCount := by
      simp only [FalconAggregate.decodeCount, FalconAggregate.falconAggCountOffset,
        FalconAggregate.statementPublicInputs, List.append_assoc]
      rw [List.drop_left' hstmsg]
      simp [CloseSignatureBridge.toAggStatement]
    have hr := FalconAggregate.agg_expected_decode_count (level := FalconAggregate.aggLevels)
      hmlen hactivewf hn
    rw [← hl, hwords, hr, hactivelen]
  -- the key slots
  have hpadwf : FalconAggregate.SlotsWellFormed
      (active ++ List.replicate (2 ^ FalconAggregate.aggLevels - active.length)
        FalconAggregate.zeroSlot) :=
    FalconAggregate.slots_well_formed_append hactivewf
      (FalconAggregate.slots_well_formed_replicate _)
  have hpadlen : (active ++ List.replicate (2 ^ FalconAggregate.aggLevels - active.length)
      FalconAggregate.zeroSlot).length = 2 ^ FalconAggregate.aggLevels := by
    rw [List.length_append, List.length_replicate]
    exact Nat.add_sub_cancel' hn
  have hjoin : (CloseSignatureBridge.toAggStatement st).pks.join
      = (active ++ List.replicate (2 ^ FalconAggregate.aggLevels - active.length)
        FalconAggregate.zeroSlot).join := by
    have hright : FalconAggregate.aggExpectedPublicInputs FalconAggregate.aggLevels message
        active = message ++ [active.length] ++
          (active ++ List.replicate (2 ^ FalconAggregate.aggLevels - active.length)
            FalconAggregate.zeroSlot).join :=
      FalconAggregate.agg_expected_normal_form hmlen hactivewf hn
    have hprefix : (st.message.words ++ [st.signerCount]).length
        = FalconAggregate.falconAggPkListOffset := by
      simp [List.length_append, FalconAggregate.falconAggPkListOffset,
        FalconAggregate.bytes32Len]
    have hprefix' : (message ++ [active.length]).length
        = FalconAggregate.falconAggPkListOffset := by
      simp [List.length_append, hmlen, FalconAggregate.falconAggPkListOffset,
        FalconAggregate.bytes32Len]
    have heq := hwords
    rw [hright] at heq
    have := congrArg (fun l => l.drop FalconAggregate.falconAggPkListOffset) heq
    simp only [FalconAggregate.statementPublicInputs, CloseSignatureBridge.toAggStatement]
      at this
    rw [List.drop_left' (by rw [← hprefix]; simp [CloseSignatureBridge.toAggStatement]),
      List.drop_left' hprefix'] at this
    exact this
  have hkeyslen : (CloseSignatureBridge.toAggStatement st).pks.length
      = 2 ^ FalconAggregate.aggLevels := by
    have h1 := FalconAggregate.join_length_of_well_formed _ hstwf
    have h2 := FalconAggregate.join_length_of_well_formed _ hpadwf
    rw [hjoin, h2, hpadlen] at h1
    have h3 : (2:Nat) ^ FalconAggregate.aggLevels * FalconAggregate.bytes32Len
        = (CloseSignatureBridge.toAggStatement st).pks.length * FalconAggregate.bytes32Len :=
      h1.symm
    simp only [FalconAggregate.bytes32Len] at h3
    omega
  have hkeys : (CloseSignatureBridge.toAggStatement st).pks
      = active ++ List.replicate (2 ^ FalconAggregate.aggLevels - active.length)
        FalconAggregate.zeroSlot := by
    have h1 := FalconAggregate.chunks_join _ hstwf
    have h2 := FalconAggregate.chunks_join _ hpadwf
    rw [hkeyslen] at h1
    rw [hpadlen] at h2
    rw [← h1, hjoin, h2]
  -- the witness list
  refine ⟨cws.map (slotWitnessOf message), ?_, ?_, ?_, ?_, ?_⟩
  · rw [List.length_map, hcount]
  · rw [hcount]; exact hge
  · rw [hcount]; exact hle
  · have hmap : (cws.map (slotWitnessOf message)).map
        (fun w => (sigEnvOf e).pkDigest w.h) = active := by
      rw [List.map_map, ← hactive]
      refine map_congr_members _ _ cws (fun cw hcw => ?_)
      have hbind := (hcws cw hcw).1.pkBinding
      show limbsOfNat (FalconCore.falconPkDigest e cw.h) = limbsOfNat cw.pkG
      rw [hbind]
    show st.keys.map CloseCircuit.Words8.words = _
    rw [hmap, hcount]
    have : st.keys.map CloseCircuit.Words8.words
        = (CloseSignatureBridge.toAggStatement st).pks := rfl
    rw [this, hkeys, hactivelen]
    have h8 : (2:Nat) ^ FalconAggregate.aggLevels = 8 := by decide
    rw [h8]
  · intro w hw
    obtain ⟨cw, hcw, hwe⟩ := List.mem_map.mp hw
    obtain ⟨hsat, hbit, hdig⟩ := hcws cw hcw
    have hauth : authorized cw.h message := unforgeable cw message hsat hbit hdig
    rw [← hwe]
    exact ⟨by rw [hmsg]; rfl, by rw [hmsg]; exact hauth⟩

/-! ## 7. Non-vacuity

A concrete leaf assignment and a concrete level-1 assignment with TWO present leaves, both
satisfying their transcripts. Without these, every `ProgramSatisfied` hypothesis above could be
empty. The environments are `FalconCore`'s DEGENERATE stand-ins (constant hash, constant
product); they are not Poseidon. -/

/-- The all-zero digest, as 8 canonical `u32` limbs. -/
def exampleMessageLimbs : FalconAggregate.Limbs := [0, 0, 0, 0, 0, 0, 0, 0]

theorem example_message_digest : CloseSignatureBridge.digestOfLimbs exampleMessageLimbs = 0 := by
  decide

/-- The `FalconSigGadgetWitness::padding` shape (gadget.rs:847-856) as a leaf assignment: the
one slot shape for which `FalconCore` exhibits a satisfying gate assignment. -/
def exampleLeafAssignment : LeafAssignment where
  sig := FalconCore.zeroWitness 1 0
  messageLimbs := exampleMessageLimbs
  pkGLimbs := exampleMessageLimbs
  countWire := 1

theorem example_leaf_program_satisfied :
    LeafProgramSatisfied FalconCore.zeroEnvironment FalconCore.zeroProduct
      exampleLeafAssignment := by
  refine leaf_program_satisfied_of _ _ _ ?_ ?_ ?_ ?_ ?_ ?_
  · refine ⟨FalconCore.zero_witness_satisfied 0 1 (by decide), rfl, ?_, ?_, ?_, ?_⟩
    · exact example_message_digest.symm
    · exact example_message_digest.symm
    · intro x hx
      have : x = 0 := by
        simp only [exampleMessageLimbs, List.mem_cons, List.not_mem_nil, or_false] at hx
        rcases hx with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> rfl
      rw [this]; decide
    · intro x hx
      have : x = 0 := by
        simp only [exampleMessageLimbs, List.mem_cons, List.not_mem_nil, or_false] at hx
        rcases hx with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> rfl
      rw [this]; decide
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl

/-- The 17 public inputs the example leaf exposes. -/
def exampleLeafPis : List Nat := readLeafPublic exampleLeafAssignment

theorem example_leaf_public_inputs_width : exampleLeafPis.length = 17 := by decide

/-- The opaque child-verification relation, instantiated trivially: the example is about the
BOOKKEEPING, not about plonky2. -/
def exampleLevelEnv : LevelEnvironment Unit where
  childVerifierData := fun _ => []
  verifyChild := fun _ _ _ => True

/-- Two present leaves at level 1: `is_right_present = 1`, `signer_count = 2`. -/
def exampleLevelAssignment : LevelAssignment Unit where
  leftProof := ()
  rightProof := ()
  childVdWire := []
  leftPis := exampleLeafPis
  rightPis := exampleLeafPis
  flag := 1
  diffWire := fun _ => 0
  gatedMsgWire := fun _ => 0
  gatedCountRWire := 1
  signerCountWire := 2
  halfFullWire := 1
  leftFullnessGapWire := 0
  gatedGapWire := 0
  gatedRightPkWire := fun _ => 0

theorem example_level_program_satisfied :
    LevelProgramSatisfied exampleLevelEnv 1 exampleLevelAssignment := by
  refine level_program_satisfied_of _ _ _ ⟨rfl, trivial, by decide⟩ (Or.inr rfl)
    ⟨by decide, fun _ => trivial⟩ (fun i _ => ⟨?_, ?_, ?_⟩) ?_ ⟨by decide, ?_⟩ ?_ ?_ ?_ ?_
    (by decide) (by decide) (by decide) (fun i _ => ⟨by decide, ?_⟩) (by decide)
  · show (0 + (FalconAggregate.decodeMessage exampleLeafPis).getD i 0) % fieldModulus
      = (FalconAggregate.decodeMessage exampleLeafPis).getD i 0 % fieldModulus
    rw [Nat.zero_add]
  · show (0 : Nat) % fieldModulus = (1 * 0) % fieldModulus
    decide
  · decide
  · show (1 : Nat) % fieldModulus = (1 * FalconAggregate.decodeCount exampleLeafPis)
      % fieldModulus
    decide
  · show (2 : Nat) % fieldModulus
      = (FalconAggregate.decodeCount exampleLeafPis + 1) % fieldModulus
    decide
  · show (1 : Nat) % fieldModulus = 2 ^ (1 - 1) % fieldModulus
    decide
  · show (0 + 1) % fieldModulus = FalconAggregate.decodeCount exampleLeafPis % fieldModulus
    decide
  · show (0 : Nat) % fieldModulus = (1 * 0) % fieldModulus
    decide
  · decide
  · show (0 : Nat) % fieldModulus
      = (1 * (rightPkLimbs 1 exampleLevelAssignment).getD i 0) % fieldModulus
    have : (rightPkLimbs 1 exampleLevelAssignment).getD i 0 = 0 := by
      have hb : ∀ x ∈ rightPkLimbs 1 exampleLevelAssignment, x < 1 := by decide
      have := get_default_lt _ 1 (by decide) hb i
      omega
    rw [this]

/-- The exposed level-1 statement: two signers, their (equal, all-zero) key digests in slots 0
and 1, at the `falcon_agg_public_inputs_len(1) = 25` width. -/
theorem example_level_public_inputs :
    readLevelPublic 1 exampleLevelAssignment
      = FalconAggregate.aggExpectedPublicInputs 1 exampleMessageLimbs
        [FalconAggregate.zeroSlot, FalconAggregate.zeroSlot] := by
  decide

end Zkp.Implementation.FalconAggProgram
