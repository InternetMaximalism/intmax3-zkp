import Zkp.Implementation.CloseCircuit
import Zkp.Implementation.FalconAggregate
import Zkp.Implementation.FalconCore

/-!
# CloseSignatureBridge: from an accepted aggregate proof to per-signature evidence

Handwritten SEMANTIC BRIDGE between three existing models:

* `Zkp.Implementation.CloseCircuit` — the close circuit's `AggregateStatement`
  (`message : Words8`, `signerCount : Nat`, `keys : List Words8`) as
  `src/circuits/channel/close_circuit.rs` consumes it;
* `Zkp.Implementation.FalconAggregate` — the aggregation tree of `src/falcon_sig/agg.rs`
  (`AggStatement`, `evalTree`, `AggOk`);
* `Zkp.Implementation.FalconCore` — the single-signature gate set of `src/falcon_sig/gadget.rs`
  and the native verifier of `src/falcon_sig/mod.rs`.

This is NOT a refinement proof of the Rust, of plonky2's recursive verifier, or of Falcon.
Every theorem is a theorem about the Lean models; the source-to-model correspondence is a
line-map claim only.

## What this module DERIVES (previously the monolithic premise `signatureValidity`)

`accepted_aggregate_tree_gives_signer_evidence`: from
`evalTree env t aggLevels = .ok (toAggStatement s)` — i.e. the close circuit's exposed
aggregate statement is the statement of an accepted level-3 aggregation tree — plus the two
named premises below, one obtains `SignerEvidence`:

* `count_eq` / `count_ge_one` / `count_le` — `s.signerCount` is exactly the number of slots
  whose Falcon predicate was evaluated, and `1 <= signerCount <= 8`;
* `keys_eq` — `s.keys` is the list of `pkDigest` values of those slots' own public
  polynomials, LEFT-PACKED, followed by an EXACTLY-zero suffix;
* `authorized_each` — every one of those slots ran its predicate against the ONE exposed
  message, and (through the two premises) its key holder authorised that message.

The aggregate bookkeeping (count, left packing, one shared message, per-slot predicate) is
therefore no longer assumed; it is derived from `FalconAggregate.agg_tree_ok_characterization`.

## What stays OPAQUE, and where the planner must carry it (layer T `TrustBoundary` fields)

* **(d0) recursive-verifier soundness** — that `verifyAggregate aggregateVerifier proof st`
  implies the pinned `FalconAggCircuit` constraint system is satisfiable at `st.words`.
  Nothing here; plonky2's own recursive verifier is not modelled anywhere in this audit.
* **(d1) coarse aggregate statement lowering** — that a satisfiable `FalconAggCircuit`
  instance at `st.words` yields SOME aggregation tree `t` with
  `evalTree sigEnv t aggLevels = .ok (toAggStatement st)`. This is a WHOLE-CIRCUIT premise:
  `FalconAggregate` has no `BuildOp` program, so no per-primitive refinement exists yet.
  `to_agg_statement_public_inputs` is the part of it that IS proved here: the two public-input
  layouts (`CloseCircuit.AggregateStatement.words` and
  `FalconAggregate.statementPublicInputs`) are the same 73-element vector.
* **(d2) gadget faithfulness** — `FalconPredicateIsGadget`, below: that the aggregate model's
  opaque `SigEnv.falconAccepts` callback really is the `gadget.rs` gate set of
  `FalconCore.CircuitSatisfied` on an ACTIVE slot.
* **(d3) unforgeability** — `FalconUnforgeable`, below: the usable form of
  `FalconCore.LatticeHardness` / `ntruShortVectorAssumption`. It is the ONE step from
  "the gate set is satisfied" to "the holder of `h` authorised this digest".

Poseidon stays OPAQUE throughout: `SigEnv.pkDigest` is a callback with no injectivity and no
preimage resistance, so `SignerEvidence.keys_eq` — and every downstream consumer — speaks of
KEY DIGESTS, never of public polynomials. Tying a digest to a registered member remains a
consumer obligation (the close circuit's member-set commitment and distinctness chain).

## The one conversion this bridge had to choose, and why

`FalconAggregate.SlotWitness` mirrors `FalconSigGadgetWitness` (gadget.rs:800-810) field for
field: `h` = canonical `h` coefficients, `s2` = canonical `s2` residues, `salt` = the 8 packed
salt elements (`salt_to_elements`, gadget.rs:858-866), and `messageDigest` = the `Bytes32` as
its 8 `u32` limbs. `FalconCore.CircuitWitness` mirrors `FalconSigVerifyTarget`
(gadget.rs:595-605) with the SAME three list fields, but models the `Bytes32Target`
`message_digest` input as a single `Nat`. So `h`, `s2` and `salt` convert by IDENTITY and only
the digest needs a named conversion: `digestOfLimbs`, the big-endian base-`2^32` packing of the
8 limbs (`Bytes32` "is stored in big endian format", src/ethereum_types/bytes32.rs:18-22; the
limb order is `Bytes32::to_u32_vec`, the order both `hash_to_point_poseidon`
(vendor/hash_to_point.rs:73-76) and `h2p_circuit` (gadget.rs:378-380) absorb). The packing loses
nothing on the digests the gadget can see — its limbs are canonical `u32`s by construction
(`Bytes32Target::new(_, true)`, gadget.rs:351-353, 660) — and that is `digest_of_limbs_injective`,
proved below. No further hypothesis is needed: `FalconPredicateIsGadget` and `FalconUnforgeable`
are closed `Prop`s over `(env, e, p, authorized)`.
-/

namespace Zkp.Implementation.CloseSignatureBridge

/-! ## 1. Lowering the close circuit's aggregate statement (close_circuit.rs, agg.rs:176-195) -/

/-- `CloseCircuit.flattenAmounts` (close_circuit.rs model, CloseCircuit.lean:284) is
`List.join` after `Words8.words` — the concatenation `FalconAggregate.statementPublicInputs`
performs on its slot list. -/
theorem flatten_amounts_is_join :
    ∀ (ks : List CloseCircuit.Words8),
      CloseCircuit.flattenAmounts ks = (ks.map CloseCircuit.Words8.words).join := by
  intro ks
  induction ks with
  | nil => rfl
  | cons k ks ih =>
    simp only [CloseCircuit.flattenAmounts, List.map_cons, List.join_cons, ih]

/-- The close circuit's view of the aggregate statement, read as the aggregator's own
`AggStatement`. Pure re-typing: `Words8` becomes its 8 limbs. -/
def toAggStatement (s : CloseCircuit.AggregateStatement) : FalconAggregate.AggStatement :=
  { message := s.message.words
    count := s.signerCount
    pks := s.keys.map CloseCircuit.Words8.words }

theorem to_agg_statement_message (s : CloseCircuit.AggregateStatement) :
    (toAggStatement s).message = s.message.words := rfl

theorem to_agg_statement_count (s : CloseCircuit.AggregateStatement) :
    (toAggStatement s).count = s.signerCount := rfl

theorem to_agg_statement_pks (s : CloseCircuit.AggregateStatement) :
    (toAggStatement s).pks = s.keys.map CloseCircuit.Words8.words := rfl

/-- Every `Words8` slot is 8 limbs wide, so the lowered statement is slot-well-formed. -/
theorem to_agg_statement_slots_well_formed (s : CloseCircuit.AggregateStatement) :
    FalconAggregate.SlotsWellFormed (toAggStatement s).pks := by
  intro q hq
  rcases List.mem_map.mp hq with ⟨k, _, hk⟩
  rw [← hk]
  rfl

/-- THE LAYOUT IDENTITY. The close circuit's 73-word aggregate public-input vector
(`CloseCircuit.AggregateStatement.words`) and the aggregator's own
(`FalconAggregate.statementPublicInputs`, agg.rs:442-448) are the SAME list:
`message(8) ++ [signer_count] ++ join keys`. This is what makes premise (d1) a statement about
one vector rather than about two layouts. -/
theorem to_agg_statement_public_inputs (s : CloseCircuit.AggregateStatement) :
    FalconAggregate.statementPublicInputs (toAggStatement s) = s.words := by
  simp only [FalconAggregate.statementPublicInputs, toAggStatement,
    CloseCircuit.AggregateStatement.words, flatten_amounts_is_join]

/-! ## 2. What an accepted aggregate says about the signers

A `structure ... : Prop` cannot carry the DATA field `witnesses`, so the readable named-field
structure is parameterised by the witness list and `SignerEvidence` existentially quantifies
it. `SignerEvidence` is the Prop consumers (layer T) use. -/

/-- The per-slot evidence an accepted aggregate yields, relative to an explicit witness list. -/
structure SignerEvidenceFor (env : FalconAggregate.SigEnv)
    (authorized : List Nat → List Nat → Prop) (message : CloseCircuit.Words8)
    (keys : List CloseCircuit.Words8) (count : Nat)
    (witnesses : List FalconAggregate.SlotWitness) : Prop where
  /-- `signer_count` counts exactly the slots whose predicate was evaluated. -/
  count_eq : witnesses.length = count
  /-- `signer_count >= 1` structurally (agg.rs:68-72; the leaf's constant `1`). -/
  count_ge_one : 1 ≤ count
  /-- `signer_count <= MAX_SIG_CLUSTER = 8` (constants.rs:135, agg.rs:154-158). -/
  count_le : count ≤ 8
  /-- LEFT-PACKED: the exposed key list is the active slots' key digests in slot order,
  followed by an EXACTLY-zero suffix. Poseidon is opaque: these are DIGESTS. -/
  keys_eq : keys.map CloseCircuit.Words8.words =
    witnesses.map (fun w => env.pkDigest w.h) ++
      List.replicate (8 - count) FalconAggregate.zeroSlot
  /-- Every active slot ran its predicate against the ONE exposed message, and its key
  holder authorised that message. -/
  authorized_each : ∀ w ∈ witnesses,
    w.messageDigest = message.words ∧ authorized w.h message.words

/-- The consumer-facing form: some witness list carries the evidence. -/
def SignerEvidence (env : FalconAggregate.SigEnv) (authorized : List Nat → List Nat → Prop)
    (message : CloseCircuit.Words8) (keys : List CloseCircuit.Words8) (count : Nat) : Prop :=
  ∃ witnesses : List FalconAggregate.SlotWitness,
    SignerEvidenceFor env authorized message keys count witnesses

/-! ## 3. The single-signature bridge (gadget.rs, mod.rs:504-511)

### 3.1 The digest conversion -/

/-- `2 ^ 32` — one `Bytes32` limb. -/
def limbBase : Nat := 4294967296

theorem limb_base_pinned : limbBase = 2 ^ 32 := rfl

/-- The `Bytes32` value of its 8 `u32` limbs, BIG-ENDIAN (first limb most significant):
`Bytes32` "is stored in big endian format" (src/ethereum_types/bytes32.rs:18-22), and
`Bytes32::to_u32_vec` is the order both the native `hash_to_point_poseidon`
(src/falcon_sig/vendor/hash_to_point.rs:73-76) and the in-circuit `h2p_circuit`
(src/falcon_sig/gadget.rs:378-380) absorb into the sponge rate.

This is the ONE conversion the bridge needs: `FalconAggregate.SlotWitness.messageDigest` is
the limb vector (as `FalconSigGadgetWitness.message_digest : Bytes32`, gadget.rs:803), while
`FalconCore.CircuitWitness.messageDigest` models the same input as a single `Nat`. -/
def digestOfLimbs : List Nat → Nat
  | [] => 0
  | x :: xs => x * limbBase ^ xs.length + digestOfLimbs xs

theorem digest_of_limbs_nil : digestOfLimbs [] = 0 := rfl

theorem digest_of_limbs_cons (x : Nat) (xs : List Nat) :
    digestOfLimbs (x :: xs) = x * limbBase ^ xs.length + digestOfLimbs xs := rfl

/-- Positional bound: a canonical limb vector packs below `2 ^ (32 * length)`. -/
theorem digest_of_limbs_lt :
    ∀ (l : List Nat), (∀ x ∈ l, x < limbBase) → digestOfLimbs l < limbBase ^ l.length := by
  intro l
  induction l with
  | nil => intro _; simp [digestOfLimbs]
  | cons x xs ih =>
    intro h
    have hx : x < limbBase := h x (by simp)
    have hrest : digestOfLimbs xs < limbBase ^ xs.length := ih (fun y hy => h y (by simp [hy]))
    have hstep : x * limbBase ^ xs.length + digestOfLimbs xs
        < (x + 1) * limbBase ^ xs.length := by
      rw [Nat.succ_mul]
      exact Nat.add_lt_add_left hrest _
    have hle : (x + 1) * limbBase ^ xs.length ≤ limbBase * limbBase ^ xs.length :=
      Nat.mul_le_mul_right _ hx
    have hpow : limbBase * limbBase ^ xs.length = limbBase ^ (xs.length + 1) := by
      rw [Nat.pow_succ]
      exact Nat.mul_comm _ _
    rw [digest_of_limbs_cons, List.length_cons]
    calc x * limbBase ^ xs.length + digestOfLimbs xs
        < (x + 1) * limbBase ^ xs.length := hstep
      _ ≤ limbBase * limbBase ^ xs.length := hle
      _ = limbBase ^ (xs.length + 1) := hpow

/-- Uniqueness of a `digit * base + remainder` split, with `base` an arbitrary term (`omega`
cannot see through `x * limbBase ^ n`, so the split is done by hand). -/
theorem base_split_unique (B x y d1 d2 : Nat) (h1 : d1 < B) (h2 : d2 < B)
    (h : x * B + d1 = y * B + d2) : x = y ∧ d1 = d2 := by
  have key : ∀ a b e f : Nat, e < B → a < b → a * B + e < b * B + f := by
    intro a b e f he hab
    have h3 : a * B + e < a * B + B := Nat.add_lt_add_left he _
    have h45 : a * B + B ≤ b * B := by
      have hmul : (a + 1) * B ≤ b * B := Nat.mul_le_mul_right B hab
      simpa [Nat.succ_mul] using hmul
    omega
  have hxy : x = y := by
    rcases Nat.lt_trichotomy x y with hlt | heq | hgt
    · exact absurd h (Nat.ne_of_lt (key x y d1 d2 h1 hlt))
    · exact heq
    · exact absurd h.symm (Nat.ne_of_lt (key y x d2 d1 h2 hgt))
  subst hxy
  exact ⟨rfl, by omega⟩

/-- THE CONVERSION LOSES NOTHING. On canonical limb vectors of equal length the packing is
injective, so a statement about `digestOfLimbs d` is a statement about `d`. The gadget only
ever sees canonical `u32` limbs (`Bytes32Target::new(_, true)`, gadget.rs:351-353 and 660), so
this is exactly the domain the bridge uses. -/
theorem digest_of_limbs_injective :
    ∀ (a b : List Nat), a.length = b.length → (∀ x ∈ a, x < limbBase) →
      (∀ x ∈ b, x < limbBase) → digestOfLimbs a = digestOfLimbs b → a = b := by
  intro a
  induction a with
  | nil =>
    intro b hlen _ _ _
    cases b with
    | nil => rfl
    | cons _ _ => simp at hlen
  | cons x xs ih =>
    intro b hlen ha hb heq
    cases b with
    | nil => simp at hlen
    | cons y ys =>
      have hlen' : xs.length = ys.length := by simpa using hlen
      have hdx : digestOfLimbs xs < limbBase ^ xs.length :=
        digest_of_limbs_lt xs (fun z hz => ha z (by simp [hz]))
      have hdy : digestOfLimbs ys < limbBase ^ xs.length := by
        rw [hlen']
        exact digest_of_limbs_lt ys (fun z hz => hb z (by simp [hz]))
      have heq' : x * limbBase ^ xs.length + digestOfLimbs xs
          = y * limbBase ^ xs.length + digestOfLimbs ys := by
        rw [digest_of_limbs_cons, digest_of_limbs_cons, hlen'] at heq
        rw [hlen']
        exact heq
      obtain ⟨hxy, hrest⟩ := base_split_unique (limbBase ^ xs.length) x y
        (digestOfLimbs xs) (digestOfLimbs ys) hdx hdy heq'
      have htail : xs = ys :=
        ih ys hlen' (fun z hz => ha z (by simp [hz])) (fun z hz => hb z (by simp [hz])) hrest
      rw [hxy, htail]

/-! ### 3.2 The premise (d2): the opaque accept callback IS the gadget

`FalconAggregate.SigEnv.falconAccepts h msg salt s2` is an OPAQUE `Bool` callback; its
docstring says it stands for the native `verify` (mod.rs:504-511) and its in-circuit mirror.
`FalconPredicateIsGadget` is that sentence made into a `Prop`: whenever the callback accepts,
the `gadget.rs` gate set (`FalconCore.CircuitSatisfied`) is satisfiable on an ACTIVE slot
(`verifyBit = 1`, the `new_conditional` wire the leaf circuit does not even create — the leaf
uses the UNCONDITIONAL `FalconSigVerifyTarget::new`, agg.rs:234-239, 270) by a witness whose
fields ARE the slot's fields:

* `cw.h = w.h` — canonical `h` coefficients (gadget.rs:806-807 vs FalconCore.lean:1526);
* `cw.s2 = w.s2` — canonical `s2` residues (gadget.rs:808-809 vs FalconCore.lean:1528);
* `cw.salt = w.salt` — the 8 packed salt elements (gadget.rs:600-601, 804-805);
* `cw.messageDigest = digestOfLimbs w.messageDigest` — the single named conversion (§3.1).

NOTE what is deliberately absent: nothing relates `env.pkDigest` (the aggregate side's opaque
Poseidon callback, limbs) to `FalconCore.falconPkDigest` (`Nat`). Both are opaque; the bridge's
conclusion is phrased in `env.pkDigest` terms and never needs the identification. -/
def FalconPredicateIsGadget (env : FalconAggregate.SigEnv) (e : FalconCore.HashEnvironment)
    (p : FalconCore.PolynomialProduct) : Prop :=
  ∀ w : FalconAggregate.SlotWitness,
    env.falconAccepts w.h w.messageDigest w.salt w.s2 = true →
      ∃ cw : FalconCore.CircuitWitness,
        cw.h = w.h ∧ cw.s2 = w.s2 ∧ cw.salt = w.salt ∧
          cw.messageDigest = digestOfLimbs w.messageDigest ∧
            cw.verifyBit = 1 ∧ FalconCore.CircuitSatisfied e p cw

/-- (d2) has CONTENT: under it an accepted slot carries the identity binding
`pk_g = Poseidon(IMFK || encode(h))` and the inclusive norm bound `||(s1, s2)||^2 <= beta^2`
over centered coefficients — the two facts the native `verify_with_pk_g` decides
(FalconCore `circuit_active_slot_implies_native_norm_bound`, gadget.rs:610-613). -/
theorem accepted_slot_meets_the_native_norm_bound (env : FalconAggregate.SigEnv)
    (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (predicate : FalconPredicateIsGadget env e p) (w : FalconAggregate.SlotWitness)
    (hacc : FalconAggregate.slotAccepts env w = true) :
    ∃ cw : FalconCore.CircuitWitness, FalconCore.CircuitSatisfied e p cw ∧ cw.h = w.h ∧
      cw.pkG = FalconCore.falconPkDigest e cw.h ∧
        FalconCore.normSquared cw.s1 cw.s2 ≤ FalconCore.falconSigL2Bound := by
  obtain ⟨cw, hh, _, _, _, hbit, hsat⟩ := predicate w hacc
  exact ⟨cw, hsat, hh, hsat.pkBinding,
    FalconCore.circuit_active_slot_implies_native_norm_bound e p cw hsat hbit⟩

/-! ## 4. The premise (d3): unforgeability in usable form -/

/-- `FalconCore.LatticeHardness` (NTRU/GPV, `ntruShortVectorAssumption`) as the implication a
consumer actually needs: a SATISFIED active gadget instance for public polynomial `cw.h` and a
digest that packs to `cw.messageDigest` means the holder of `h` authorised that digest.

`authorized : List Nat → List Nat → Prop` takes the public polynomial and the digest LIMBS
(`Words8.words`), so the limb vector is passed alongside and tied by `digestOfLimbs`; this is
the honest place where the `Nat`-valued model of the digest input is reconciled with the
8-limb wire, and it is not hidden inside a definition. -/
def FalconUnforgeable (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (authorized : List Nat → List Nat → Prop) : Prop :=
  ∀ (cw : FalconCore.CircuitWitness) (digest : FalconAggregate.Limbs),
    FalconCore.CircuitSatisfied e p cw → cw.verifyBit = 1 →
      cw.messageDigest = digestOfLimbs digest → authorized cw.h digest

/-! ## 5. The bridge theorem -/

/-- `2 ^ AGG_LEVELS = MAX_SIG_CLUSTER = 8` (agg.rs:155-158). -/
theorem agg_levels_slot_count : 2 ^ FalconAggregate.aggLevels = 8 := by decide

/-- THE BRIDGE. An accepted level-3 aggregation tree whose exposed statement is the close
circuit's aggregate statement gives per-signer evidence: the count, the left-packed key
digests, one shared message, and — through (d2) and (d3) — an authorisation by each active
slot's key holder.

Everything about the BOOKKEEPING is derived (via `FalconAggregate.agg_tree_ok_characterization`).
The two `Prop` arguments are the whole cryptographic residue: `predicate` is (d2) gadget
faithfulness, `unforgeable` is (d3) the lattice assumption. The premise that an accepted
plonky2 aggregate proof yields such a tree at all is (d0) + (d1) and lives in layer T. -/
theorem accepted_aggregate_tree_gives_signer_evidence (env : FalconAggregate.SigEnv)
    (e : FalconCore.HashEnvironment) (p : FalconCore.PolynomialProduct)
    (authorized : List Nat → List Nat → Prop)
    (predicate : FalconPredicateIsGadget env e p)
    (unforgeable : FalconUnforgeable e p authorized)
    (s : CloseCircuit.AggregateStatement) (t : FalconAggregate.AggTree)
    (hwidth : ∀ w ∈ FalconAggregate.activeWitnesses t, w.messageDigest.length = 8)
    (hok : FalconAggregate.evalTree env t FalconAggregate.aggLevels = .ok (toAggStatement s)) :
    SignerEvidence env authorized s.message s.keys s.signerCount := by
  have hagg : FalconAggregate.AggOk env FalconAggregate.aggLevels t (toAggStatement s) :=
    FalconAggregate.agg_tree_ok_characterization env t FalconAggregate.aggLevels
      (toAggStatement s) hwidth hok
  obtain ⟨hcount, hge, hle, hpks, hsigned, _hmsgw⟩ := hagg
  refine ⟨FalconAggregate.activeWitnesses t, hcount.symm, hge, ?_, ?_, ?_⟩
  · show s.signerCount ≤ 8
    rw [← agg_levels_slot_count]
    exact hle
  · show s.keys.map CloseCircuit.Words8.words = _
    rw [← agg_levels_slot_count]
    exact hpks
  · intro w hw
    obtain ⟨hacc, hmsg⟩ := hsigned w hw
    have hmsg' : w.messageDigest = s.message.words := hmsg
    obtain ⟨cw, hh, _, _, hdig, hbit, hsat⟩ := predicate w hacc
    have hauth : authorized cw.h w.messageDigest := unforgeable cw w.messageDigest hsat hbit hdig
    rw [hh] at hauth
    exact ⟨hmsg', hmsg' ▸ hauth⟩

/-! ## 6. Non-vacuity

Two concrete level-3 trees with 2 signers. The first is the plan's literal shape (an
all-accepting environment): it shows the EVALUATION is reachable, i.e.
`evalTree ... = .ok (toAggStatement s)` is not an empty hypothesis. The second pins the accept
callback to one slot shape so that (d2) itself is DISCHARGED — an all-accepting callback cannot
satisfy `FalconPredicateIsGadget`, because it accepts public polynomials of the wrong length,
for which no `CircuitSatisfied` witness exists. With (d3) instantiated at the trivial
`authorized`, the bridge theorem then applies with NO undischarged hypothesis. -/

/-- A concrete 8-limb message. -/
def exampleMessage : CloseCircuit.Words8 := ⟨1, 2, 3, 4, 5, 6, 7, 8⟩

/-- The `FalconSigGadgetWitness::padding` shape (gadget.rs:847-856) as a slot witness: it is
the one slot shape for which `FalconCore` exhibits a satisfying gate assignment
(`zero_witness_satisfied`). -/
def exampleWitness : FalconAggregate.SlotWitness :=
  { h := List.replicate FalconCore.falconN 0
    s2 := List.replicate FalconCore.falconN 0
    salt := List.replicate 8 0
    messageDigest := exampleMessage.words }

/-- Two signers at level 3: `((leaf | leaf) | -) | -`. -/
def exampleTree : FalconAggregate.AggTree :=
  .nodeLeftOnly (.nodeLeftOnly (.nodePair (.leaf exampleWitness) (.leaf exampleWitness)))

/-- The close-circuit statement the tree exposes: 2 signers, 8 key slots. -/
def exampleStatement : CloseCircuit.AggregateStatement :=
  { message := exampleMessage
    signerCount := 2
    keys := List.replicate 8 CloseCircuit.Words8.zero }

/-- The plan's all-accepting environment (`FalconAggregate.permissiveEnv` shape). -/
def permissiveEnv : FalconAggregate.SigEnv :=
  { pkDigest := fun _ => FalconAggregate.zeroSlot
    falconAccepts := fun _ _ _ _ => true }

/-- NON-VACUITY (evaluation): the level-3 tree evaluates to exactly the lowered close-circuit
statement — 2 signers, their key digests in slots 0 and 1, an exactly-zero suffix. -/
theorem example_two_signer_tree_evaluates :
    FalconAggregate.evalTree permissiveEnv exampleTree FalconAggregate.aggLevels
      = .ok (toAggStatement exampleStatement) := rfl

/-- The same tree under an environment whose accept callback is pinned to the one slot shape
`FalconCore` can satisfy. -/
def exampleEnv : FalconAggregate.SigEnv :=
  { pkDigest := fun _ => FalconAggregate.zeroSlot
    falconAccepts := fun h _ salt s2 =>
      (h == exampleWitness.h) && (salt == exampleWitness.salt) && (s2 == exampleWitness.s2) }

set_option maxRecDepth 8000 in
theorem example_pinned_tree_evaluates :
    FalconAggregate.evalTree exampleEnv exampleTree FalconAggregate.aggLevels
      = .ok (toAggStatement exampleStatement) := by
  rfl

/-- (d2) discharged for `exampleEnv` with the degenerate `FalconCore` environments. -/
theorem example_predicate_is_gadget :
    FalconPredicateIsGadget exampleEnv FalconCore.zeroEnvironment FalconCore.zeroProduct := by
  intro w hacc
  have hacc' : ((w.h == exampleWitness.h) && (w.salt == exampleWitness.salt) &&
      (w.s2 == exampleWitness.s2)) = true := hacc
  simp only [Bool.and_eq_true, beq_iff_eq] at hacc'
  obtain ⟨⟨hh, hsalt⟩, hs2⟩ := hacc'
  refine ⟨FalconCore.zeroWitness 1 (digestOfLimbs w.messageDigest), ?_, ?_, ?_, rfl, rfl,
    FalconCore.zero_witness_satisfied _ 1 (by decide)⟩
  · exact hh.symm
  · exact hs2.symm
  · exact hsalt.symm

/-- (d3) at the trivial `authorized`: vacuous here BY CONSTRUCTION — the point of the example
is the bookkeeping, not the cryptography. -/
theorem example_unforgeable :
    FalconUnforgeable FalconCore.zeroEnvironment FalconCore.zeroProduct (fun _ _ => True) :=
  fun _ _ _ _ _ => trivial

theorem example_tree_digest_width :
    ∀ w ∈ FalconAggregate.activeWitnesses exampleTree, w.messageDigest.length = 8 := by
  intro w hw
  have hmem : w = exampleWitness := by
    simpa [exampleTree, FalconAggregate.activeWitnesses] using hw
  rw [hmem]
  rfl

/-- NON-VACUITY (the bridge theorem applies, all hypotheses discharged). -/
theorem example_two_signer_tree_gives_signer_evidence :
    SignerEvidence exampleEnv (fun _ _ => True) exampleStatement.message exampleStatement.keys
      exampleStatement.signerCount :=
  accepted_aggregate_tree_gives_signer_evidence exampleEnv FalconCore.zeroEnvironment
    FalconCore.zeroProduct (fun _ _ => True) example_predicate_is_gadget example_unforgeable
    exampleStatement exampleTree example_tree_digest_width example_pinned_tree_evaluates

end Zkp.Implementation.CloseSignatureBridge
