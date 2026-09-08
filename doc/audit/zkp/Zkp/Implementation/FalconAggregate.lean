import Zkp.Implementation.UtilGadgets

/-!
# FalconAggregate: the aggregate-signature statement, its list commitment and its batch equation

Handwritten SEMANTIC MODEL of the aggregate side of the Falcon-512/Poseidon signature stack:

* `src/falcon_sig/agg.rs` (1201 lines) — the binary-tree aggregator: the canonical public-input
  layout `[message(8) | signer_count(1) | pk_g_0(8) .. pk_g_7(8)]`, the leaf circuit, the level
  circuit (gated message equality, gated count, left-packing) and the `FalconAggCircuit` facade.
* `src/falcon_sig/agg_list.rs` (912) — the N-of-N list proof: the `IMPL` pk-list digest, the
  `IMAL` widened leaf `(message, signer_count, pk_list_digest)`, the chain fold, the prover-side
  public-input parser and the step circuit's structural checks.
* `src/falcon_sig/list.rs` (528) — the retired single-signature `(m, pk)` list step and its
  cyclic chain (explicitly NO LONGER the validity path's consumer).
* `src/falcon_sig/batch.rs` (1170) — the flat batch aggregate: monotone slot flags, the witnessed
  integer product `pi = h * s2`, the Fiat-Shamir transcript, the `tau` product check, the merged
  centered `s1` fold and the gated norm bound.

This is NOT a refinement proof of the Rust code, of plonky2's gate lowering, of the recursive
verifier, or of the Falcon scheme. Every theorem below is a theorem about the Lean model; the
source-to-model correspondence is a line-map claim only.

## What this module deliberately does NOT claim

* **No cryptographic soundness.** The Falcon accept predicate is an OPAQUE callback
  (`SigEnv.falconAccepts`). Nothing here says that an accepting `(h, salt, s2)` implies knowledge
  of a secret key, unforgeability, or anything about NTRU / short vectors — that is the boundary
  `ntruShortVectorAssumption`, and it is the ONE step where the lattice assumption is needed:
  turning "a short `(s1, s2)` with `s1 = c - s2*h mod (q, x^n+1)` exists" into "the holder of the
  trapdoor for `h` participated". The model reproduces the *arithmetic* of that check and stops.
* **No hash-to-point security.** `SigEnv.h2p` (`c = H2P(salt, message)`) is opaque; the model
  proves only that ONE shared `message` wire feeds every slot (`batch.rs`) or that every level
  forces its present children to agree (`agg.rs`). Boundary `hashToPointOpaque`.
* **No Poseidon injectivity.** `pkDigest` and the chain hashes are opaque callbacks
  (`UtilGadgets.HashEnv`). Every fold theorem is about the PREIMAGE encoding, never about digest
  distinctness. Boundary `hashOpaque` (inherited from `UtilGadgets`).
* **No proof soundness.** Recursive verification of a child/aggregate proof at a constant verifier
  key is recorded as data, never as "the statement is true". Boundaries `proofVerificationOpaque`,
  `constantVerifierKeyBinding`.
* **No Schwartz-Zippel.** The batch product check is proved COMPLETE (the honest integer product
  satisfies the evaluation identity at every point, `poly_eval_mul` / `batch_honest_witness_
  satisfies_the_product_check`); the converse — evaluation agreement at the transcript challenge
  implies coefficient equality — is the explicit premise `ProductCheckSound`
  (boundary `schwartzZippelChallenge`), together with `fiatShamirRandomOracle` for the claim that
  `tau` behaves as a random point.
* **No distinctness, no membership.** `aggregate_accepted_does_not_establish_distinctness` and
  `aggregate_accepted_does_not_establish_membership` are stated as explicit non-results: the same
  leaf may occupy two slots, and no slot is tied to a registered member here. Those are CONSUMER
  obligations (`update_channel_tree`, close / cancel-close).

## What an accepted aggregate proof DOES establish, in this model

`agg_tree_ok_characterization` (tree) and `batch_exposed_statement` (flat batch): the exposed
statement `(message, signer_count, pk_g slots)` satisfies

* `signer_count` equals the number of slots whose Falcon predicate was evaluated and accepted;
* the pk list is exactly `map pkDigest (those slots' own h)` followed by an EXACTLY-zero suffix;
* every one of those slots ran its predicate against the SAME exposed `message`;
* `1 <= signer_count <= 2^level` structurally.

Everything else about the signer set is outside the statement.

## Named boundaries (all undischarged; repeated in the line maps)

`ntruShortVectorAssumption`, `hashToPointOpaque`, `hashOpaque`, `pkDigestOpaque`,
`proofVerificationOpaque`, `constantVerifierKeyBinding`, `dummyProofUntrustedPublicInputs`,
`schwartzZippelChallenge`, `fiatShamirRandomOracle`, `extensionFieldEvaluation`,
`gateLoweringOpaque`, `fieldRepresentativeAbstraction`, `cyclicWrapperOpaque`,
`vendorFalconParameters`.
-/

namespace Zkp.Implementation.FalconAggregate

abbrev Hash := UtilGadgets.Hash
abbrev HashEnv := UtilGadgets.HashEnv

/-- A `Bytes32` as its 8 `u32` limbs (the form every public input uses). -/
abbrev Limbs := List Nat

/-! ## 0. Small list helpers (no Mathlib in this project) -/

/-- `List.getD` read through `drop`; every positional public-input claim below reduces to
`drop`/`take` algebra via this bridge. -/
theorem get_default_eq_head_of_drop (l : List Nat) (i : Nat) :
    l.getD i 0 = (l.drop i).headD 0 := by
  induction i generalizing l with
  | zero => cases l <;> simp
  | succ n ih =>
    cases l with
    | nil => simp
    | cons a t => simpa using ih t

/-- Every element of a `List.replicate` is the replicated value. -/
theorem mem_replicate_eq {α : Type} {x v : α} {n : Nat} (h : x ∈ List.replicate n v) : x = v := by
  induction n with
  | zero => simp at h
  | succ m ih =>
    rw [List.replicate_succ] at h
    cases h with
    | head => rfl
    | tail _ h' => exact ih h'

/-! ## 1. Pinned layout constants (agg.rs 149-172) -/

/-- `BYTES32_LEN` — a `Bytes32` is 8 `u32` limbs. -/
def bytes32Len : Nat := 8

theorem bytes32_len_pinned : bytes32Len = 8 := rfl

theorem bytes32_len_matches_util : bytes32Len = UtilGadgets.bytes32Len := rfl

/-- `MAX_SIG_CLUSTER` (constants.rs:135) — the sig-cluster width the top level exposes. -/
def maxSigCluster : Nat := 8

theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl

theorem max_sig_cluster_matches_util : maxSigCluster = UtilGadgets.maxSigCluster := rfl

/-- `AGG_LEVELS` (agg.rs:154). The module docstring above it still says `AGG_LEVELS = 4` and
`FALCON_AGG_PUBLIC_INPUTS_LEN = 137`; the CODE says 3 and 73. The const-assert
`MAX_SIG_CLUSTER == 1 << AGG_LEVELS` is what actually binds. -/
def aggLevels : Nat := 3

theorem agg_levels_pinned : aggLevels = 3 := rfl

/-- agg.rs:155-158, the `const _: () = assert!(MAX_SIG_CLUSTER == 1 << AGG_LEVELS)`. -/
theorem agg_levels_is_log2_max_sig_cluster : 2 ^ aggLevels = maxSigCluster := by decide

/-- `FALCON_AGG_MSG_OFFSET` (agg.rs:161). -/
def falconAggMsgOffset : Nat := 0

/-- `FALCON_AGG_COUNT_OFFSET` (agg.rs:163). -/
def falconAggCountOffset : Nat := bytes32Len

/-- `FALCON_AGG_PK_LIST_OFFSET` (agg.rs:165). -/
def falconAggPkListOffset : Nat := bytes32Len + 1

/-- `FALCON_AGG_PUBLIC_INPUTS_LEN` (agg.rs:167) — the 73-element consumer contract. -/
def falconAggPublicInputsLen : Nat := bytes32Len + 1 + maxSigCluster * bytes32Len

/-- `falcon_agg_public_inputs_len(level)` (agg.rs:170-172). -/
def falconAggPublicInputsLenAt (level : Nat) : Nat := bytes32Len + 1 + 2 ^ level * bytes32Len

theorem falcon_agg_msg_offset_pinned : falconAggMsgOffset = 0 := rfl

theorem falcon_agg_count_offset_pinned : falconAggCountOffset = 8 := rfl

theorem falcon_agg_pk_list_offset_pinned : falconAggPkListOffset = 9 := rfl

theorem falcon_agg_public_inputs_len_pinned : falconAggPublicInputsLen = 73 := by decide

/-- The per-level widths the level circuits assert on their children (agg.rs:375-379) and the
`agg_list` build-time arity gate rejects (agg_list.rs:304-307). -/
theorem falcon_agg_public_inputs_len_at_table :
    falconAggPublicInputsLenAt 0 = 17 ∧ falconAggPublicInputsLenAt 1 = 25 ∧
      falconAggPublicInputsLenAt 2 = 41 ∧ falconAggPublicInputsLenAt 3 = 73 := by decide

/-- The top level IS the consumer contract (agg.rs:456-462 release-mode self-check, and the
`debug_assert_eq!` of batch.rs:697-700). -/
theorem top_level_width_is_the_consumer_contract :
    falconAggPublicInputsLenAt aggLevels = falconAggPublicInputsLen := by decide

/-- agg.rs:387-390, the `const { assert!(...) }` that pins the LEAF layout the induction base
reads its `signer_count` from. -/
theorem leaf_layout_induction_base_pins :
    falconAggCountOffset = bytes32Len ∧
      falconAggPublicInputsLenAt 0 = bytes32Len + 1 + bytes32Len := by decide

/-- `[prev_chain(8), new_chain(8)]` — the list-step arity asserted in list.rs:165-169 and
agg_list.rs:352-356. -/
def listStepPublicInputsLen : Nat := 2 * bytes32Len

theorem list_step_public_inputs_len_pinned : listStepPublicInputsLen = 16 := by decide

/-! ## 2. The canonical public-input encoder (agg.rs 176-195) -/

/-- An all-zero pk slot: the padding value the aggregation constrains its inactive slots to, and
the value `close_member_set_commitment` pads with natively. -/
def zeroSlot : Limbs := List.replicate bytes32Len 0

theorem zero_slot_length : zeroSlot.length = bytes32Len := by simp [zeroSlot]

/-- Every slot of a well-formed pk list is 8 limbs wide. -/
def SlotsWellFormed (pks : List Limbs) : Prop := ∀ p ∈ pks, p.length = bytes32Len

theorem slots_well_formed_nil : SlotsWellFormed [] := by
  intro p hp; cases hp

theorem slots_well_formed_cons {p : Limbs} {ps : List Limbs}
    (hp : p.length = bytes32Len) (hps : SlotsWellFormed ps) :
    SlotsWellFormed (p :: ps) := by
  intro q hq
  cases hq with
  | head => exact hp
  | tail _ h => exact hps _ h

theorem slots_well_formed_append {a b : List Limbs}
    (ha : SlotsWellFormed a) (hb : SlotsWellFormed b) : SlotsWellFormed (a ++ b) := by
  intro q hq
  rcases List.mem_append.mp hq with h | h
  · exact ha _ h
  · exact hb _ h

theorem slots_well_formed_replicate (n : Nat) : SlotsWellFormed (List.replicate n zeroSlot) := by
  intro q hq
  rw [mem_replicate_eq hq]
  exact zero_slot_length

/-- Concatenated slot limbs of a well-formed list. -/
theorem join_length_of_well_formed :
    ∀ (pks : List Limbs), SlotsWellFormed pks → pks.join.length = pks.length * bytes32Len := by
  intro pks
  induction pks with
  | nil => intro _; simp
  | cons p ps ih =>
    intro hw
    have hp : p.length = bytes32Len := hw p (by simp)
    have hps : SlotsWellFormed ps := by
      intro q hq; exact hw q (by simp [hq])
    simp [List.length_append, hp, ih hps, Nat.succ_mul, Nat.add_comm]

/-- `falcon_agg_expected_public_inputs` (agg.rs:176-195): message limbs, then the signer count,
then the active pk slots in slot order, then zero padding to the level width. `Vec::resize`
truncates as well as pads, so the model uses `take` — the source's
`assert!(signer_pks.len() <= (1 << level))` is what makes truncation unreachable. -/
def aggExpectedPublicInputs (level : Nat) (message : Limbs) (signerPks : List Limbs) : List Nat :=
  let body := message ++ [signerPks.length] ++ signerPks.join
  (body ++ List.replicate (falconAggPublicInputsLenAt level - body.length) 0).take
    (falconAggPublicInputsLenAt level)

/-- The encoder's body length: `8 + 1 + 8 * n`. -/
theorem agg_expected_body_length {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks) :
    (message ++ [pks.length] ++ pks.join).length = bytes32Len + 1 + pks.length * bytes32Len := by
  simp [List.length_append, hm, join_length_of_well_formed pks hw]
  omega

/-- Width: a left-packed encoding at `level` is exactly `falcon_agg_public_inputs_len(level)`
elements (agg.rs:187-194). -/
theorem agg_expected_public_inputs_length {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks)
    (hn : pks.length ≤ 2 ^ level) :
    (aggExpectedPublicInputs level message pks).length = falconAggPublicInputsLenAt level := by
  have hbody := agg_expected_body_length hm hw
  have hmul : pks.length * bytes32Len ≤ 2 ^ level * bytes32Len := Nat.mul_le_mul_right _ hn
  simp only [aggExpectedPublicInputs, List.length_take, List.length_append,
    List.length_replicate, hbody, falconAggPublicInputsLenAt]
  omega

/-! ### 2.1 Positional readers — the slicing every consumer does blindly

`agg_list.rs` (`from_agg_public_inputs`, `AggListStepCircuit::new`) and the close / cancel-close
circuits read the aggregate statement POSITIONALLY. These readers are that slicing. -/

/-- `pis[FALCON_AGG_MSG_OFFSET .. +8]`. -/
def decodeMessage (pis : List Nat) : Limbs := pis.take bytes32Len

/-- `pis[FALCON_AGG_COUNT_OFFSET]`. -/
def decodeCount (pis : List Nat) : Nat := (pis.drop falconAggCountOffset).headD 0

/-- `pis[FALCON_AGG_PK_LIST_OFFSET + i*8 .. +8]`. -/
def decodeSlot (pis : List Nat) (i : Nat) : Limbs :=
  (pis.drop (falconAggPkListOffset + i * bytes32Len)).take bytes32Len

theorem decode_count_is_the_positional_read (pis : List Nat) :
    decodeCount pis = pis.getD falconAggCountOffset 0 :=
  (get_default_eq_head_of_drop pis falconAggCountOffset).symm

/-- `List.join` distributes over `++` (not in the 4.10 core simp set). -/
theorem join_append_eq {α : Type} :
    ∀ (a b : List (List α)), (a ++ b).join = a.join ++ b.join := by
  intro a b
  induction a with
  | nil => simp
  | cons x xs ih => simp [ih, List.append_assoc]

/-- The zero padding of a slot list, flattened. -/
theorem join_replicate_zero_slot (k : Nat) :
    (List.replicate k zeroSlot).join = List.replicate (k * bytes32Len) 0 :=
  List.join_replicate_replicate

/-- Normal form of the encoder: message, count, then EXACTLY `2^level` slots of which the tail is
zero padding. This is the "left-packed with a zero suffix" shape the level circuit maintains. -/
theorem agg_expected_normal_form {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks)
    (hn : pks.length ≤ 2 ^ level) :
    aggExpectedPublicInputs level message pks =
      message ++ [pks.length] ++ (pks ++ List.replicate (2 ^ level - pks.length) zeroSlot).join := by
  have hbody := agg_expected_body_length hm hw
  have hmul : pks.length * bytes32Len ≤ 2 ^ level * bytes32Len := Nat.mul_le_mul_right _ hn
  have hpad : falconAggPublicInputsLenAt level - (message ++ [pks.length] ++ pks.join).length
      = (2 ^ level - pks.length) * bytes32Len := by
    rw [hbody, Nat.mul_sub_right_distrib]
    simp only [falconAggPublicInputsLenAt]
    omega
  have hjoin : (pks ++ List.replicate (2 ^ level - pks.length) zeroSlot).join
      = pks.join ++ List.replicate ((2 ^ level - pks.length) * bytes32Len) 0 := by
    rw [join_append_eq, join_replicate_zero_slot]
  have hshape : (message ++ [pks.length] ++ pks.join) ++
      List.replicate ((2 ^ level - pks.length) * bytes32Len) 0
      = message ++ [pks.length] ++ (pks ++ List.replicate (2 ^ level - pks.length) zeroSlot).join := by
    rw [hjoin, List.append_assoc, List.append_assoc]
  have hlen : ((message ++ [pks.length] ++ pks.join) ++
      List.replicate ((2 ^ level - pks.length) * bytes32Len) 0).length
      = falconAggPublicInputsLenAt level := by
    simp only [List.length_append, List.length_replicate, hbody, falconAggPublicInputsLenAt,
      Nat.mul_sub_right_distrib]
    omega
  show ((message ++ [pks.length] ++ pks.join) ++
      List.replicate (falconAggPublicInputsLenAt level -
        (message ++ [pks.length] ++ pks.join).length) 0).take
      (falconAggPublicInputsLenAt level) = _
  rw [hpad, ← hlen, List.take_length, hshape]

/-! ### 2.2 Slot algebra and encoder injectivity -/

/-- The `i`-th pk slot of a slot list (`zeroSlot` past the end — the padding value). -/
def slotOf (S : List Limbs) (i : Nat) : Limbs := (S.drop i).headD zeroSlot

theorem slot_of_append_left :
    ∀ (A B : List Limbs) (i : Nat), i < A.length → slotOf (A ++ B) i = slotOf A i := by
  intro A
  induction A with
  | nil => intro B i h; exact absurd h (Nat.not_lt_zero i)
  | cons p ps ih =>
    intro B i h
    cases i with
    | zero => simp [slotOf]
    | succ n =>
      have hn : n < ps.length := Nat.lt_of_succ_lt_succ (by simpa using h)
      simpa [slotOf] using ih B n hn

theorem slot_of_append_right :
    ∀ (A B : List Limbs) (i : Nat), A.length ≤ i → slotOf (A ++ B) i = slotOf B (i - A.length) := by
  intro A
  induction A with
  | nil => intro B i _; simp [slotOf]
  | cons p ps ih =>
    intro B i h
    cases i with
    | zero => simp at h
    | succ n =>
      have hn : ps.length ≤ n := Nat.le_of_succ_le_succ (by simpa using h)
      simpa [slotOf] using ih B n hn

theorem slot_of_replicate (k i : Nat) : slotOf (List.replicate k zeroSlot) i = zeroSlot := by
  induction k generalizing i with
  | zero => simp [slotOf]
  | succ m ih =>
    cases i with
    | zero => simp [slotOf, List.replicate_succ]
    | succ n => simpa [slotOf, List.replicate_succ] using ih n

/-- Reading slot `i` out of the FLATTENED limb vector is reading slot `i` of the slot list —
the positional slicing every consumer of the 73-element contract performs. -/
theorem join_slot_extract :
    ∀ (S : List Limbs), SlotsWellFormed S → ∀ i, i < S.length →
      (S.join.drop (i * bytes32Len)).take bytes32Len = slotOf S i := by
  intro S
  induction S with
  | nil => intro _ i h; exact absurd h (Nat.not_lt_zero i)
  | cons p ps ih =>
    intro hw i hi
    have hp : p.length = bytes32Len := hw p (by simp)
    have hps : SlotsWellFormed ps := by intro q hq; exact hw q (by simp [hq])
    cases i with
    | zero => simpa [slotOf] using List.take_left' hp
    | succ n =>
      have hn : n < ps.length := Nat.lt_of_succ_lt_succ (by simpa using hi)
      have hshift : (n + 1) * bytes32Len = n * bytes32Len + bytes32Len := by
        simp [Nat.succ_mul]
      have hpeel : ((p ++ ps.join).drop (n * bytes32Len + bytes32Len)).take bytes32Len
          = (ps.join.drop (n * bytes32Len)).take bytes32Len := by
        rw [← List.drop_drop, List.drop_left' hp]
      simp only [List.join_cons, hshift, hpeel, slotOf, List.drop_succ_cons]
      simpa [slotOf] using ih hps n hn

/-- `pis[0..8]` of a left-packed encoding is the message. -/
theorem agg_expected_decode_message {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks) (hn : pks.length ≤ 2 ^ level) :
    decodeMessage (aggExpectedPublicInputs level message pks) = message := by
  rw [agg_expected_normal_form hm hw hn]
  simpa [decodeMessage, List.append_assoc] using List.take_left' hm

/-- `pis[8]` of a left-packed encoding is `signer_pks.len()` (agg.rs:189). -/
theorem agg_expected_decode_count {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks) (hn : pks.length ≤ 2 ^ level) :
    decodeCount (aggExpectedPublicInputs level message pks) = pks.length := by
  rw [agg_expected_normal_form hm hw hn]
  simp only [decodeCount, falconAggCountOffset, List.append_assoc]
  rw [List.drop_left' hm]
  simp

/-- `pis[9 + 8i .. +8]` of a left-packed encoding is slot `i` of `signer_pks ++ zero padding`. -/
theorem agg_expected_decode_slot {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks) (hn : pks.length ≤ 2 ^ level)
    (i : Nat) (hi : i < 2 ^ level) :
    decodeSlot (aggExpectedPublicInputs level message pks) i
      = slotOf (pks ++ List.replicate (2 ^ level - pks.length) zeroSlot) i := by
  have hSlen : (pks ++ List.replicate (2 ^ level - pks.length) zeroSlot).length = 2 ^ level := by
    simp [List.length_append, List.length_replicate]
    omega
  have hSw : SlotsWellFormed (pks ++ List.replicate (2 ^ level - pks.length) zeroSlot) :=
    slots_well_formed_append hw (slots_well_formed_replicate _)
  have hhead : (message ++ [pks.length]).length = falconAggPkListOffset := by
    simp [List.length_append, hm, falconAggPkListOffset]
  rw [agg_expected_normal_form hm hw hn]
  simp only [decodeSlot]
  rw [Nat.add_comm falconAggPkListOffset (i * bytes32Len), ← List.drop_drop,
    List.drop_left' hhead]
  exact join_slot_extract _ hSw i (by omega)

/-- Active slots read back exactly. -/
theorem agg_expected_slot_active {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks) (hn : pks.length ≤ 2 ^ level)
    (i : Nat) (hi : i < pks.length) :
    decodeSlot (aggExpectedPublicInputs level message pks) i = slotOf pks i := by
  rw [agg_expected_decode_slot hm hw hn i (Nat.lt_of_lt_of_le hi hn),
    slot_of_append_left _ _ _ hi]

/-- Padding slots are EXACTLY zero — the property `close_member_set_commitment` and
`AggListEntry::from_agg_public_inputs` both rely on (agg.rs:76-81, agg_list.rs:196-200). -/
theorem agg_expected_slot_padding {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks) (hn : pks.length ≤ 2 ^ level)
    (i : Nat) (hlo : pks.length ≤ i) (hhi : i < 2 ^ level) :
    decodeSlot (aggExpectedPublicInputs level message pks) i = zeroSlot := by
  rw [agg_expected_decode_slot hm hw hn i hhi, slot_of_append_right _ _ _ hlo, slot_of_replicate]

/-- Slot-wise extensionality for slot lists. -/
theorem list_ext_by_slots :
    ∀ (S T : List Limbs), S.length = T.length → (∀ i, i < S.length → slotOf S i = slotOf T i) →
      S = T := by
  intro S
  induction S with
  | nil => intro T hlen _; cases T with
    | nil => rfl
    | cons _ _ => simp at hlen
  | cons p ps ih =>
    intro T hlen hslot
    cases T with
    | nil => simp at hlen
    | cons q qs =>
      have hhead : p = q := by simpa [slotOf] using hslot 0 (by simp)
      have htail : ps = qs := by
        refine ih qs (by simpa using hlen) ?_
        intro i hi
        simpa [slotOf] using hslot (i + 1) (Nat.succ_lt_succ hi)
      rw [hhead, htail]

/-- ENCODER INJECTIVITY on the left-packed domain: the 73-element vector determines the message
and the ordered active pk list. (This is an injectivity claim about the ENCODING only; nothing
about Poseidon.) -/
theorem agg_expected_public_inputs_injective {level : Nat} {m1 m2 : Limbs} {p1 p2 : List Limbs}
    (hm1 : m1.length = bytes32Len) (hm2 : m2.length = bytes32Len)
    (hw1 : SlotsWellFormed p1) (hw2 : SlotsWellFormed p2)
    (hn1 : p1.length ≤ 2 ^ level) (hn2 : p2.length ≤ 2 ^ level)
    (heq : aggExpectedPublicInputs level m1 p1 = aggExpectedPublicInputs level m2 p2) :
    m1 = m2 ∧ p1 = p2 := by
  have hmsg : m1 = m2 := by
    rw [← agg_expected_decode_message hm1 hw1 hn1, ← agg_expected_decode_message hm2 hw2 hn2, heq]
  have hcount : p1.length = p2.length := by
    rw [← agg_expected_decode_count hm1 hw1 hn1, ← agg_expected_decode_count hm2 hw2 hn2, heq]
  refine ⟨hmsg, list_ext_by_slots p1 p2 hcount ?_⟩
  intro i hi
  have h1 := agg_expected_slot_active hm1 hw1 hn1 i hi
  have h2 := agg_expected_slot_active hm2 hw2 hn2 i (hcount ▸ hi)
  rw [← h1, ← h2, heq]


/-! ## 3. The signature environment — the one place the lattice assumption is needed

`SigEnv` collects the two callbacks the aggregate side consumes from `falcon_sig/mod.rs` and
`falcon_sig/gadget.rs`:

* `pkDigest h` = `falcon_pk_digest(h)` = `Poseidon(IMFK ‖ encode(h))` (mod.rs:261-280) — the wire
  `pk_g` the leaf circuit registers and the batch circuit gates into its slot list. OPAQUE:
  boundary `pkDigestOpaque` (no injectivity, no preimage resistance).
* `falconAccepts h message salt s2` = the native `verify` predicate (mod.rs:504-511) and the
  gadget's in-circuit mirror: hash-to-point, `s1 = c - s2*h mod (q, x^n+1)`, then
  `||(s1, s2)||^2 <= beta^2`. OPAQUE here: boundaries `hashToPointOpaque` and, crucially,
  `ntruShortVectorAssumption`.

`ntruShortVectorAssumption` is the SINGLE step this model cannot and does not take: from
"`falconAccepts h m salt s2` holds" to "the party that registered `h` authorised `m`". Everything
below is arithmetic and bookkeeping around that predicate; nothing derives unforgeability from it.
`falcon_predicate_carries_no_cryptographic_content` states the limitation as a theorem. -/

/-- One signature slot's witness: the public polynomial `h`, the signature `(salt, s2)` and the
digest the norm bound is checked against (`FalconSigGadgetWitness`). -/
structure SlotWitness where
  h : List Nat
  s2 : List Nat
  salt : List Nat
  messageDigest : Limbs

/-- The opaque callbacks. -/
structure SigEnv where
  pkDigest : List Nat → Limbs
  falconAccepts : List Nat → Limbs → List Nat → List Nat → Bool

/-- Digest width premise (the model never inspects a digest's content). -/
def SigEnvShape (env : SigEnv) : Prop := ∀ h, (env.pkDigest h).length = bytes32Len

/-- The Falcon accept predicate on one slot witness. -/
def slotAccepts (env : SigEnv) (w : SlotWitness) : Bool :=
  env.falconAccepts w.h w.messageDigest w.salt w.s2

/-- LIMITATION, stated as a theorem: the model's accept predicate has no content of its own. An
environment that accepts everything is a legal `SigEnv`, so no theorem below can be read as
saying an accepted aggregate implies a genuine signature — that implication is exactly the
undischarged boundary `ntruShortVectorAssumption`. -/
theorem falcon_predicate_carries_no_cryptographic_content
    (pk : List Nat → Limbs) (w : SlotWitness) :
    slotAccepts { pkDigest := pk, falconAccepts := fun _ _ _ _ => true } w = true := rfl

/-! ## 4. The aggregate statement and the leaf circuit (agg.rs 229-324) -/

/-- The statement a level-`k` proof exposes: `[message(8) | signer_count | 2^k pk_g slots]`. -/
structure AggStatement where
  message : Limbs
  count : Nat
  pks : List Limbs

/-- Encoding an exposed statement into the flat public-input vector (agg.rs:442-448 registers
exactly these, in this order). -/
def statementPublicInputs (s : AggStatement) : List Nat :=
  s.message ++ [s.count] ++ s.pks.join

/-- A left-packed statement encodes to the canonical reference vector
`falcon_agg_expected_public_inputs` (agg.rs:176-195) — the equality `check_pis` asserts. -/
theorem statement_public_inputs_match_reference {level : Nat} {message : Limbs}
    {active : List Limbs} (hm : message.length = bytes32Len) (hw : SlotsWellFormed active)
    (hn : active.length ≤ 2 ^ level) :
    statementPublicInputs
        { message := message, count := active.length,
          pks := active ++ List.replicate (2 ^ level - active.length) zeroSlot }
      = aggExpectedPublicInputs level message active := by
  rw [agg_expected_normal_form hm hw hn]
  rfl

/-- `FalconLeafCircuit`: PI `0..8` is the gadget's own `message_digest` wire, PI 8 is the CONSTANT
1, PI `9..17` is the gadget-derived `pk_g` (agg.rs:271-279). -/
def leafStatement (env : SigEnv) (w : SlotWitness) : AggStatement :=
  { message := w.messageDigest, count := 1, pks := [env.pkDigest w.h] }

theorem leaf_count_is_the_constant_one (env : SigEnv) (w : SlotWitness) :
    (leafStatement env w).count = 1 := rfl

/-- The leaf's exposed message IS the digest the predicate is evaluated against — there is no free
witness between "what was signed" and "what is exposed" (agg.rs:236-239). -/
theorem leaf_message_is_the_checked_digest (env : SigEnv) (w : SlotWitness) :
    (leafStatement env w).message = w.messageDigest := rfl

/-- The leaf's exposed key is the digest of the slot's OWN `h` — the binding of a member public
key to a signature slot (agg.rs:278, batch.rs:587-590). -/
theorem leaf_key_is_the_digest_of_its_own_h (env : SigEnv) (w : SlotWitness) :
    (leafStatement env w).pks = [env.pkDigest w.h] := rfl

theorem leaf_statement_width (env : SigEnv) (w : SlotWitness) :
    (leafStatement env w).pks.length = 2 ^ 0 := rfl

/-! ## 5. The level circuit (agg.rs 326-505) -/

/-- Exposed right-hand slot limbs are `is_right_present * limb` (agg.rs:445-448). -/
def gateLimbs (b : Bool) (p : Limbs) : Limbs := p.map (fun x => if b then x else 0)

theorem gate_limbs_present (p : Limbs) : gateLimbs true p = p := by
  simp [gateLimbs]

theorem gate_limbs_absent_is_zero (p : Limbs) (hp : p.length = bytes32Len) :
    gateLimbs false p = zeroSlot := by
  have : ∀ (l : List Nat), gateLimbs false l = List.replicate l.length 0 := by
    intro l
    induction l with
    | nil => rfl
    | cons a t ih => simp [gateLimbs, List.replicate_succ] at *; exact ih
  rw [this, hp, zeroSlot]

def gateSlots (b : Bool) (S : List Limbs) : List Limbs := S.map (gateLimbs b)

theorem gate_slots_present (S : List Limbs) : gateSlots true S = S := by
  induction S with
  | nil => rfl
  | cons p ps ih =>
    simp only [gateSlots, List.map_cons, gate_limbs_present]
    simp only [gateSlots] at ih
    rw [ih]

theorem gate_slots_absent (S : List Limbs) (hw : SlotsWellFormed S) :
    gateSlots false S = List.replicate S.length zeroSlot := by
  induction S with
  | nil => rfl
  | cons p ps ih =>
    have hp : p.length = bytes32Len := hw p (by simp)
    have hps : SlotsWellFormed ps := by intro q hq; exact hw q (by simp [hq])
    simp only [gateSlots, List.map_cons, gate_limbs_absent_is_zero p hp, List.length_cons,
      List.replicate_succ]
    simp only [gateSlots] at ih
    rw [ih hps]

/-- The gated limb-by-limb message check of agg.rs:412-416, modelled as the `zip` the source
writes: `is_right_present * (l - r) == 0` over `msg_l.zip(msg_r)`. -/
def messageAgrees (a b : Limbs) : Bool := (a.zip b).all (fun p => p.1 == p.2)

/-- At the pinned 8-limb width the zip check IS list equality (a shorter list would leave the
tail unchecked — the arity assert of agg.rs:375-379 is what rules that out). -/
theorem message_agrees_iff_eq :
    ∀ (a b : Limbs), a.length = b.length → (messageAgrees a b = true ↔ a = b) := by
  intro a
  induction a with
  | nil => intro b hb; cases b with
    | nil => simp [messageAgrees]
    | cons _ _ => simp at hb
  | cons x xs ih =>
    intro b hb
    cases b with
    | nil => simp at hb
    | cons y ys =>
      have hlen : xs.length = ys.length := by simpa using hb
      have hstep : messageAgrees (x :: xs) (y :: ys) = ((x == y) && messageAgrees xs ys) := rfl
      rw [hstep, Bool.and_eq_true, beq_iff_eq, ih ys hlen]
      constructor
      · intro h; rw [h.1, h.2]
      · intro h; cases h; exact ⟨rfl, rfl⟩

/-- The ways a level's constraint system is UNSATISFIABLE. These are not runtime errors: they are
the gated equalities of agg.rs:412-437, read as a partial function. -/
inductive AggError where
  | signatureRejected
  | messageMismatch
  | leftNotFull
  | levelMismatch
  deriving DecidableEq, Repr

/-- One aggregation level (agg.rs:392-448). The exposed statement is WIRED from the two children's
public inputs and the boolean flag: message copied from the left child, count the gated sum, the
left half of the list verbatim and the right half gated. -/
def levelCompose (level : Nat) (present : Bool) (l r : AggStatement) :
    Except AggError AggStatement :=
  if present then
    if !messageAgrees l.message r.message then .error AggError.messageMismatch
    else if l.count ≠ 2 ^ (level - 1) then .error AggError.leftNotFull
    else .ok { message := l.message, count := l.count + r.count, pks := l.pks ++ r.pks }
  else
    .ok { message := l.message, count := l.count, pks := l.pks ++ gateSlots false r.pks }

/-- A present right child contributes its count; an absent one contributes 0 (agg.rs:422-423). -/
theorem level_count_is_the_gated_sum {level : Nat} {l r s : AggStatement} {present : Bool}
    (h : levelCompose level present l r = .ok s) :
    s.count = l.count + (if present then r.count else 0) := by
  cases present <;> simp only [levelCompose, Bool.false_eq_true, if_false, if_true] at h
  · cases h; simp
  · split at h
    · cases h
    · split at h
      · cases h
      · cases h; simp

/-- The exposed message is ALWAYS the left child's (agg.rs:442). -/
theorem level_message_is_the_left_message {level : Nat} {l r s : AggStatement} {present : Bool}
    (h : levelCompose level present l r = .ok s) : s.message = l.message := by
  cases present <;> simp only [levelCompose, Bool.false_eq_true, if_false, if_true] at h
  · cases h; rfl
  · split at h
    · cases h
    · split at h
      · cases h
      · cases h; rfl

/-- A PRESENT right child must agree with the left on the message, limb by limb. -/
theorem level_present_forces_message_agreement {level : Nat} {l r s : AggStatement}
    (h : levelCompose level true l r = .ok s)
    (hlen : l.message.length = r.message.length) : l.message = r.message := by
  simp only [levelCompose, if_true] at h
  split at h
  · cases h
  · exact (message_agrees_iff_eq _ _ hlen).mp (by
      rename_i hcond
      simpa using hcond)

/-- LEFT-PACKING: a present right child forces the left child to be FULL (agg.rs:434-437). -/
theorem level_present_forces_full_left_child {level : Nat} {l r s : AggStatement}
    (h : levelCompose level true l r = .ok s) : l.count = 2 ^ (level - 1) := by
  simp only [levelCompose, if_true] at h
  split at h
  · cases h
  · split at h
    · cases h
    · rename_i hne; exact Decidable.not_not.mp hne

/-- DUMMY-PROOF SAFETY (agg.rs:353-357, boundary `dummyProofUntrustedPublicInputs`): when the
right child is absent its statement comes from a canonical dummy proof whose public inputs carry
no claim. The exposed statement does not depend on them — only on their WIDTH. -/
theorem absent_right_child_statement_is_ignored (level : Nat) (l r1 r2 : AggStatement)
    (hw1 : SlotsWellFormed r1.pks) (hw2 : SlotsWellFormed r2.pks)
    (hlen : r1.pks.length = r2.pks.length) :
    levelCompose level false l r1 = levelCompose level false l r2 := by
  simp only [levelCompose, Bool.false_eq_true, if_false, gate_slots_absent _ hw1,
    gate_slots_absent _ hw2, hlen]


/-! ## 6. The aggregation tree and what an accepted top-level statement says (agg.rs 507-681) -/

/-- The shape of an aggregation: a leaf, a node with the right subtree ABSENT
(`prove(node, None)` — the lift step of `aggregate_to_level`), or a node with both children. -/
inductive AggTree where
  | leaf (w : SlotWitness)
  | nodeLeftOnly (left : AggTree)
  | nodePair (left right : AggTree)

/-- The slot witnesses actually carried by the tree, in slot order. -/
def activeWitnesses : AggTree → List SlotWitness
  | .leaf w => [w]
  | .nodeLeftOnly l => activeWitnesses l
  | .nodePair l r => activeWitnesses l ++ activeWitnesses r

/-- The statement a canonical DUMMY child proof presents. Its content is untrusted; only its
width matters (`absent_right_child_statement_is_ignored`). -/
def dummyStatement (message : Limbs) (k : Nat) : AggStatement :=
  { message := message, count := 0, pks := List.replicate (2 ^ k) zeroSlot }

/-- Evaluating the tree at a level: the leaf gates at level 0, one `levelCompose` per level. -/
def evalTree (env : SigEnv) : AggTree → Nat → Except AggError AggStatement
  | .leaf w, 0 =>
      if slotAccepts env w then .ok (leafStatement env w) else .error AggError.signatureRejected
  | .leaf _, _ + 1 => .error AggError.levelMismatch
  | .nodeLeftOnly _, 0 => .error AggError.levelMismatch
  | .nodePair _ _, 0 => .error AggError.levelMismatch
  | .nodeLeftOnly l, k + 1 =>
      match evalTree env l k with
      | .error e => .error e
      | .ok sl => levelCompose (k + 1) false sl (dummyStatement sl.message k)
  | .nodePair l r, k + 1 =>
      match evalTree env l k with
      | .error e => .error e
      | .ok sl =>
        match evalTree env r k with
        | .error e => .error e
        | .ok sr => levelCompose (k + 1) true sl sr

/-- EXACTLY what an accepted level-`k` aggregate statement says in this model. -/
structure AggOk (env : SigEnv) (k : Nat) (t : AggTree) (s : AggStatement) : Prop where
  /-- `signer_count` is the number of slots whose Falcon predicate was evaluated. -/
  count_eq : s.count = (activeWitnesses t).length
  /-- `signer_count >= 1` STRUCTURALLY (agg.rs:68-72). -/
  count_ge_one : 1 ≤ s.count
  /-- and never exceeds the level's slot count. -/
  count_le : s.count ≤ 2 ^ k
  /-- LEFT-PACKED: the pk list is the active keys in order, then an EXACTLY-zero suffix. -/
  pks_eq : s.pks =
    (activeWitnesses t).map (fun w => env.pkDigest w.h) ++ List.replicate (2 ^ k - s.count) zeroSlot
  /-- Every active slot ran the predicate against the ONE exposed message. -/
  signed : ∀ w ∈ activeWitnesses t, slotAccepts env w = true ∧ w.messageDigest = s.message
  /-- The exposed message keeps the pinned 8-limb width. -/
  message_width : s.message.length = bytes32Len

/-- THE CHARACTERISATION. An accepted aggregation tree exposes exactly: the number of evaluated
signature slots, their keys left-packed with a zero suffix, and one shared message.

Read carefully what is NOT here: nothing says the `h` values differ, nothing ties them to
registered members, and — boundary `ntruShortVectorAssumption` — `slotAccepts` is an opaque
predicate, so "signed" means "the modelled accept callback returned true", not "a signature
exists that only the key holder could produce". -/
theorem agg_tree_ok_characterization (env : SigEnv) (shape : SigEnvShape env) :
    ∀ (t : AggTree) (k : Nat) (s : AggStatement),
      (∀ w ∈ activeWitnesses t, w.messageDigest.length = bytes32Len) →
      evalTree env t k = .ok s → AggOk env k t s := by
  intro t
  induction t with
  | leaf w =>
    intro k s hwidth h
    cases k with
    | zero =>
      simp only [evalTree] at h
      split at h
      · rename_i hacc
        have hs : s = leafStatement env w := by
          simpa using h.symm
        subst hs
        refine ⟨rfl, Nat.le_refl 1, by simp [leafStatement], ?_, ?_, ?_⟩
        · simp [leafStatement, activeWitnesses]
        · intro w' hw'
          have : w' = w := by simpa [activeWitnesses] using hw'
          subst this
          exact ⟨hacc, rfl⟩
        · exact hwidth w (by simp [activeWitnesses])
      · exact absurd h (by simp)
    | succ n => exact absurd h (by simp [evalTree])
  | nodeLeftOnly l ih =>
    intro k s hwidth h
    cases k with
    | zero => exact absurd h (by simp [evalTree])
    | succ n =>
      simp only [evalTree] at h
      split at h
      · exact absurd h (by simp)
      · rename_i sl heq
        have hl : AggOk env n l sl := ih n sl (by simpa [activeWitnesses] using hwidth) heq
        have hdw : SlotsWellFormed (dummyStatement sl.message n).pks := by
          simpa [dummyStatement] using slots_well_formed_replicate (2 ^ n)
        simp only [levelCompose, Bool.false_eq_true, if_false,
          gate_slots_absent _ hdw] at h
        have hs : s = AggStatement.mk sl.message sl.count
            (sl.pks ++ List.replicate (dummyStatement sl.message n).pks.length zeroSlot) := by
          simpa using h.symm
        subst hs
        have hpow : 2 ^ (n + 1) = 2 ^ n + 2 ^ n := by
          simp [Nat.pow_succ, Nat.mul_two]
        refine ⟨by simpa [activeWitnesses] using hl.count_eq, hl.count_ge_one, ?_, ?_, ?_, ?_⟩
        · show sl.count ≤ 2 ^ (n + 1)
          have := hl.count_le; omega
        · show sl.pks ++ List.replicate (dummyStatement sl.message n).pks.length zeroSlot = _
          rw [hl.pks_eq]
          simp only [dummyStatement, List.length_replicate, List.append_assoc,
            List.append_replicate_replicate, activeWitnesses]
          have := hl.count_le
          have harith : 2 ^ n - sl.count + 2 ^ n = 2 ^ (n + 1) - sl.count := by omega
          rw [harith]
        · intro w hw
          exact hl.signed w (by simpa [activeWitnesses] using hw)
        · exact hl.message_width
  | nodePair l r ihl ihr =>
    intro k s hwidth h
    cases k with
    | zero => exact absurd h (by simp [evalTree])
    | succ n =>
      simp only [evalTree] at h
      split at h
      · exact absurd h (by simp)
      · rename_i sl heql
        split at h
        · exact absurd h (by simp)
        · rename_i sr heqr
          have hwl : ∀ w ∈ activeWitnesses l, w.messageDigest.length = bytes32Len := by
            intro w hw; exact hwidth w (by simp [activeWitnesses, hw])
          have hwr : ∀ w ∈ activeWitnesses r, w.messageDigest.length = bytes32Len := by
            intro w hw; exact hwidth w (by simp [activeWitnesses, hw])
          have hl : AggOk env n l sl := ihl n sl hwl heql
          have hr : AggOk env n r sr := ihr n sr hwr heqr
          have hfull : sl.count = 2 ^ n := by
            simpa using level_present_forces_full_left_child (level := n + 1) h
          have hmsg : sl.message = sr.message :=
            level_present_forces_message_agreement h
              (by rw [hl.message_width, hr.message_width])
          have hs : s = AggStatement.mk sl.message (sl.count + sr.count) (sl.pks ++ sr.pks) := by
            simp only [levelCompose, if_true] at h
            split at h
            · exact absurd h (by simp)
            · split at h
              · exact absurd h (by simp)
              · simpa using h.symm
          subst hs
          have hpow : 2 ^ (n + 1) = 2 ^ n + 2 ^ n := by simp [Nat.pow_succ, Nat.mul_two]
          have hrle := hr.count_le
          refine ⟨?_, ?_, ?_, ?_, ?_, hl.message_width⟩
          · show sl.count + sr.count = _
            rw [hl.count_eq, hr.count_eq]
            simp [activeWitnesses]
          · show 1 ≤ sl.count + sr.count
            have := hl.count_ge_one; omega
          · show sl.count + sr.count ≤ 2 ^ (n + 1)
            omega
          · show sl.pks ++ sr.pks =
              (activeWitnesses (AggTree.nodePair l r)).map (fun w => env.pkDigest w.h)
                ++ List.replicate (2 ^ (n + 1) - (sl.count + sr.count)) zeroSlot
            rw [hl.pks_eq, hr.pks_eq, hfull]
            have harith : 2 ^ n - sr.count = 2 ^ (n + 1) - (2 ^ n + sr.count) := by
              rw [hpow]; omega
            simp only [Nat.sub_self, List.replicate_zero, List.append_nil, activeWitnesses,
              List.map_append, List.append_assoc, harith]
          · intro w hw
            rcases List.mem_append.mp (by simpa [activeWitnesses] using hw) with hw' | hw'
            · exact hl.signed w hw'
            · exact ⟨(hr.signed w hw').1, by rw [(hr.signed w hw').2, hmsg]⟩

end Zkp.Implementation.FalconAggregate
