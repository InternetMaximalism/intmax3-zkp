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
theorem agg_tree_ok_characterization (env : SigEnv) :
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
        have _hpow := hpow
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


/-! ### 6.1 The exposed statement re-encodes to the canonical 73-element contract -/

theorem agg_ok_pks_well_formed {env : SigEnv} {k : Nat} {t : AggTree} {s : AggStatement}
    (shape : SigEnvShape env) (hok : AggOk env k t s) : SlotsWellFormed s.pks := by
  rw [hok.pks_eq]
  refine slots_well_formed_append ?_ (slots_well_formed_replicate _)
  intro q hq
  rcases List.mem_map.mp hq with ⟨w, _, hw⟩
  rw [← hw]
  exact shape w.h

theorem agg_ok_pks_length {env : SigEnv} {k : Nat} {t : AggTree} {s : AggStatement}
    (hok : AggOk env k t s) : s.pks.length = 2 ^ k := by
  have hle := hok.count_le
  rw [hok.pks_eq]
  simp only [List.length_append, List.length_map, List.length_replicate, ← hok.count_eq]
  omega

/-- The exposed statement encodes to EXACTLY `falcon_agg_public_inputs_len(k)` field elements —
the release-mode arity self-check of agg.rs:456-462 (73 at the top level). -/
theorem agg_ok_public_input_arity {env : SigEnv} {k : Nat} {t : AggTree} {s : AggStatement}
    (shape : SigEnvShape env) (hok : AggOk env k t s) :
    (statementPublicInputs s).length = falconAggPublicInputsLenAt k := by
  have hw := agg_ok_pks_well_formed shape hok
  simp only [statementPublicInputs, List.length_append, List.length_cons, List.length_nil,
    hok.message_width, join_length_of_well_formed _ hw, agg_ok_pks_length hok,
    falconAggPublicInputsLenAt]

/-- ... and it is byte-identical to the native left-packed reference
`falcon_agg_expected_public_inputs` (the `check_pis` equality of agg.rs:769-772). -/
theorem agg_ok_matches_the_native_reference {env : SigEnv} {k : Nat} {t : AggTree}
    {s : AggStatement} (shape : SigEnvShape env) (hok : AggOk env k t s) :
    statementPublicInputs s
      = aggExpectedPublicInputs k s.message ((activeWitnesses t).map (fun w => env.pkDigest w.h)) := by
  have hactive : SlotsWellFormed ((activeWitnesses t).map (fun w => env.pkDigest w.h)) := by
    intro q hq
    rcases List.mem_map.mp hq with ⟨w, _, hw⟩
    rw [← hw]; exact shape w.h
  have hlen : ((activeWitnesses t).map (fun w => env.pkDigest w.h)).length = s.count := by
    simp [hok.count_eq]
  have hle : ((activeWitnesses t).map (fun w => env.pkDigest w.h)).length ≤ 2 ^ k := by
    rw [hlen]; exact hok.count_le
  have href := statement_public_inputs_match_reference (level := k) (message := s.message)
    (active := (activeWitnesses t).map (fun w => env.pkDigest w.h)) hok.message_width hactive hle
  rw [← href]
  simp only [statementPublicInputs, hok.pks_eq, hlen]

/-! ### 6.2 The two things an accepted aggregate does NOT establish (agg.rs:86-88) -/

/-- A permissive environment: the model's accept callback is opaque, so nothing prevents one. -/
def permissiveEnv (d : Limbs) : SigEnv :=
  { pkDigest := fun _ => d, falconAccepts := fun _ _ _ _ => true }

/-- A concrete witness whose digest has the pinned width. -/
def sampleWitness : SlotWitness :=
  { h := [1, 2, 3], s2 := [4, 5], salt := [6], messageDigest := List.replicate bytes32Len 7 }

/-- NON-RESULT (agg.rs:86-88, agg_list.rs:41-46) and simultaneously a NON-VACUOUS positive trace:
a level-1 aggregation of the SAME leaf in both slots is accepted, exposing `signer_count = 2`
with two IDENTICAL pk slots. Signer distinctness is therefore NOT part of the statement; it is a
consumer obligation (A5 distinctness chain / member-tree recomputation). -/
theorem aggregate_accepted_does_not_establish_distinctness :
    evalTree (permissiveEnv zeroSlot) (.nodePair (.leaf sampleWitness) (.leaf sampleWitness)) 1
      = .ok { message := sampleWitness.messageDigest, count := 2, pks := [zeroSlot, zeroSlot] } := by
  rfl


/-! ## 7. The flat batch aggregate (batch.rs)

### 7.1 The parameter / bounds ledger (batch.rs 131-200) -/

/-- `FALCON_N`. -/
def falconN : Nat := 512
/-- `FALCON_Q`. -/
def falconQ : Nat := 12289
/-- `PI_COEFFS = 2N - 1` — the degree bound of the witnessed integer product. -/
def piCoeffs : Nat := 2 * falconN - 1
/-- `PI_BITS` — the honest `pi` coefficient bound (NO in-circuit range check exists). -/
def piBits : Nat := 37
/-- `POW32_MOD_Q`. -/
def pow32ModQ : Nat := 10952
/-- `S1_FOLD_OFFSET`. -/
def s1FoldOffset : Nat := (2 ^ piBits / falconQ + 1) * falconQ
/-- `S1_FOLD_K_BITS`. -/
def s1FoldKBits : Nat := 32
/-- `HALF_Q = (q-1)/2`. -/
def halfQ : Nat := (falconQ - 1) / 2
/-- `TRANSCRIPT_ELEMS_PER_SLOT = N/4 + N/4 + PI_COEFFS`. -/
def transcriptElemsPerSlot : Nat := falconN / 4 + falconN / 4 + piCoeffs
/-- `DOMAIN_FALCON_BATCH` ("IMFB") — the transcript sponge's capacity domain. -/
def domainFalconBatch : Nat := 0x494d4642
/-- `DOMAIN_FALCON_H2P` ("IMFH"). -/
def domainFalconH2P : Nat := 0x494d4648
/-- `DOMAIN_FALCON_PK` ("IMFK") — the `pk_g` digest domain. -/
def domainFalconPk : Nat := 0x494d464b
/-- `FALCON_SIG_L2_BOUND` (`vendor/mod.rs:91`, the Falcon-512 spec value). Boundary
`vendorFalconParameters`: this value comes from the vendored scheme, not from the mapped files. -/
def betaSq : Nat := 34034726
/-- The width of the range check the gated slack is pushed through (batch.rs:648). -/
def slackBits : Nat := 26
/-- The Goldilocks modulus `2^64 - 2^32 + 1`. -/
def goldilocks : Nat := 2 ^ 64 - 2 ^ 32 + 1

theorem falcon_n_pinned : falconN = 512 := rfl
theorem falcon_q_pinned : falconQ = 12289 := rfl
theorem pi_coeffs_pinned : piCoeffs = 1023 := by decide
theorem pi_bits_pinned : piBits = 37 := rfl
theorem half_q_pinned : halfQ = 6144 := by decide
theorem s1_fold_offset_pinned : s1FoldOffset = 137438959389 := by decide
theorem transcript_elems_per_slot_pinned : transcriptElemsPerSlot = 1279 := by decide
theorem slack_bits_pinned : slackBits = 26 := rfl
theorem goldilocks_pinned : goldilocks = 18446744069414584321 := by decide

theorem domain_falcon_batch_is_ascii_imfb :
    domainFalconBatch = UtilGadgets.asciiBE 0x49 0x4d 0x46 0x42 := by decide
theorem domain_falcon_h2p_is_ascii_imfh :
    domainFalconH2P = UtilGadgets.asciiBE 0x49 0x4d 0x46 0x48 := by decide
theorem domain_falcon_pk_is_ascii_imfk :
    domainFalconPk = UtilGadgets.asciiBE 0x49 0x4d 0x46 0x4b := by decide

/-- batch.rs:177-178 — the honest `pi` coefficient bound. -/
theorem pi_bits_covers_the_honest_product :
    falconN * (falconQ - 1) * (falconQ - 1) < 2 ^ piBits := by decide

/-- batch.rs:180 — the reduction constant really is `2^32 mod q`. -/
theorem pow32_mod_q_is_correct : 2 ^ 32 % falconQ = pow32ModQ := by decide

/-- batch.rs:182-183 — the fold offset is a multiple of `q` and covers the largest subtrahend. -/
theorem s1_fold_offset_ledger :
    s1FoldOffset % falconQ = 0 ∧ 2 ^ piBits - 1 ≤ s1FoldOffset := by decide

/-- batch.rs:187-192 — the merged fold quotient fits `S1_FOLD_K_BITS` bits. -/
theorem s1_fold_quotient_fits :
    (2 ^ 32 - 1) * pow32ModQ + (2 ^ 32 - 1) + (2 ^ piBits - 1) + s1FoldOffset + halfQ
      < 2 ^ s1FoldKBits * falconQ := by decide

/-- batch.rs:193 — and the decomposition cannot wrap mod p. -/
theorem s1_fold_decomposition_cannot_wrap : 2 ^ s1FoldKBits * falconQ - 1 < goldilocks := by decide

/-- batch.rs:194-196 — the integer-lift premise behind the Schwartz-Zippel argument. -/
theorem schwartz_zippel_lift_premise :
    2 ^ piBits + falconN * (falconQ - 1) * (falconQ - 1) < 2 ^ 62 := by decide

/-- gadget.rs:1123 / batch.rs:646-648 — `beta^2` fits the slack range check. -/
theorem beta_sq_fits_the_slack_range : betaSq < 2 ^ slackBits := by decide

/-! ### 7.2 Polynomial algebra: the batch product check is COMPLETE

The circuit replaces the ring multiplication `s2 * h` by a WITNESSED product `pi` checked at one
random point. What is provable here is the COMPLETENESS half: the honest integer product satisfies
the evaluation identity at EVERY point. The soundness half (agreement at `tau` implies coefficient
equality) is the premise `ProductCheckSound` — boundaries `schwartzZippelChallenge` and
`fiatShamirRandomOracle`. -/

/-- Horner evaluation, `eval_at_tau` (batch.rs:470-481), over the integers. -/
def polyEval (coeffs : List Nat) (x : Nat) : Nat :=
  coeffs.foldr (fun c acc => acc * x + c) 0

def polyScale (c : Nat) (p : List Nat) : List Nat := p.map (fun v => c * v)

def polyAdd : List Nat → List Nat → List Nat
  | [], b => b
  | a, [] => a
  | x :: xs, y :: ys => (x + y) :: polyAdd xs ys

/-- Schoolbook integer product — `integer_product` (batch.rs:783-796) read as a polynomial. -/
def polyMul : List Nat → List Nat → List Nat
  | [], _ => []
  | x :: xs, b => polyAdd (polyScale x b) (0 :: polyMul xs b)

theorem poly_eval_nil (x : Nat) : polyEval [] x = 0 := rfl

theorem poly_eval_cons (c : Nat) (p : List Nat) (x : Nat) :
    polyEval (c :: p) x = polyEval p x * x + c := rfl

theorem poly_eval_scale (c : Nat) : ∀ (p : List Nat) (x : Nat),
    polyEval (polyScale c p) x = c * polyEval p x := by
  intro p
  induction p with
  | nil => intro x; simp [polyScale, polyEval]
  | cons a t ih =>
    intro x
    simp only [polyScale, List.map_cons, poly_eval_cons]
    simp only [polyScale] at ih
    rw [ih]
    simp [Nat.mul_add, Nat.mul_assoc]

theorem poly_eval_add : ∀ (a b : List Nat) (x : Nat),
    polyEval (polyAdd a b) x = polyEval a x + polyEval b x := by
  intro a
  induction a with
  | nil => intro b x; simp [polyAdd, polyEval]
  | cons u us ih =>
    intro b x
    cases b with
    | nil => simp [polyAdd, polyEval]
    | cons v vs =>
      simp only [polyAdd, poly_eval_cons, ih vs x]
      simp [Nat.add_mul]
      omega

/-- THE FOLD ALGEBRA of the batch check: the witnessed integer product evaluates to the product of
the evaluations, at every point. -/
theorem poly_eval_mul : ∀ (a b : List Nat) (x : Nat),
    polyEval (polyMul a b) x = polyEval a x * polyEval b x := by
  intro a
  induction a with
  | nil => intro b x; simp [polyMul, polyEval]
  | cons u us ih =>
    intro b x
    simp only [polyMul, poly_eval_add, poly_eval_scale, poly_eval_cons, ih b x]
    simp only [Nat.add_mul, Nat.mul_add, Nat.mul_comm, Nat.mul_assoc, Nat.mul_left_comm,
      Nat.zero_add, Nat.add_zero]
    omega

theorem poly_add_length : ∀ (a b : List Nat),
    (polyAdd a b).length = max a.length b.length := by
  intro a
  induction a with
  | nil => intro b; simp [polyAdd]
  | cons u us ih =>
    intro b
    cases b with
    | nil => simp [polyAdd]
    | cons v vs => simp [polyAdd, ih vs, Nat.succ_max_succ]

/-- `deg(pi) <= 2N - 2`, i.e. `PI_COEFFS` coefficients for two degree-`N-1` inputs
(batch.rs:137-138). -/
theorem poly_mul_length : ∀ (a b : List Nat), a ≠ [] → b ≠ [] →
    (polyMul a b).length = a.length + b.length - 1 := by
  intro a
  induction a with
  | nil => intro b h; exact absurd rfl h
  | cons u us ih =>
    intro b _ hb
    cases us with
    | nil =>
      have hblen : 1 ≤ b.length := by
        cases b with
        | nil => exact absurd rfl hb
        | cons _ _ => simp
      have hstep : polyMul [u] b = polyAdd (polyScale u b) (0 :: polyMul [] b) := rfl
      rw [hstep, poly_add_length]
      simp only [polyScale, List.length_map, List.length_cons, List.length_nil, polyMul]
      omega
    | cons v vs =>
      have hne : (v :: vs) ≠ [] := by simp
      have hlen := ih b hne hb
      have hblen : 1 ≤ b.length := by
        cases b with
        | nil => exact absurd rfl hb
        | cons _ _ => simp
      have hstep : polyMul (u :: v :: vs) b = polyAdd (polyScale u b) (0 :: polyMul (v :: vs) b) :=
        rfl
      rw [hstep, poly_add_length]
      simp only [polyScale, List.length_map, List.length_cons, hlen]
      simp only [List.length_cons] at hlen ⊢
      omega

theorem poly_scale_mem_bound (c : Nat) : ∀ (p : List Nat) (B : Nat), (∀ v ∈ p, v ≤ B) →
    ∀ v ∈ polyScale c p, v ≤ c * B := by
  intro p
  induction p with
  | nil => intro B _ v hv; simp [polyScale] at hv
  | cons a t ih =>
    intro B hb v hv
    simp only [polyScale, List.map_cons, List.mem_cons] at hv
    rcases hv with hv | hv
    · rw [hv]; exact Nat.mul_le_mul_left c (hb a (by simp))
    · exact ih B (fun w hw => hb w (by simp [hw])) v (by simpa [polyScale] using hv)

theorem poly_add_mem_bound : ∀ (a b : List Nat) (X Y : Nat), (∀ v ∈ a, v ≤ X) → (∀ v ∈ b, v ≤ Y) →
    ∀ v ∈ polyAdd a b, v ≤ X + Y := by
  intro a
  induction a with
  | nil =>
    intro b X Y _ hy v hv
    exact Nat.le_trans (hy v (by simpa [polyAdd] using hv)) (Nat.le_add_left Y X)
  | cons u us ih =>
    intro b X Y hx hy v hv
    cases b with
    | nil =>
      exact Nat.le_trans (hx v (by simpa [polyAdd] using hv)) (Nat.le_add_right X Y)
    | cons w ws =>
      simp only [polyAdd, List.mem_cons] at hv
      rcases hv with hv | hv
      · rw [hv]
        exact Nat.add_le_add (hx u (by simp)) (hy w (by simp))
      · exact ih ws X Y (fun z hz => hx z (by simp [hz])) (fun z hz => hy z (by simp [hz])) v hv

/-- Each product coefficient is at most `deg * A * B` — the bound that keeps the witnessed `pi`
inside `2^PI_BITS` even though the circuit range-checks NOTHING about it. -/
theorem poly_mul_mem_bound : ∀ (a b : List Nat) (A B : Nat), (∀ v ∈ a, v ≤ A) → (∀ v ∈ b, v ≤ B) →
    ∀ v ∈ polyMul a b, v ≤ a.length * (A * B) := by
  intro a
  induction a with
  | nil => intro b A B _ _ v hv; simp [polyMul] at hv
  | cons u us ih =>
    intro b A B ha hb v hv
    have hscale : ∀ z ∈ polyScale u b, z ≤ A * B := by
      intro z hz
      exact Nat.le_trans (poly_scale_mem_bound u b B hb z hz)
        (Nat.mul_le_mul_right B (ha u (by simp)))
    have htail : ∀ z ∈ (0 : Nat) :: polyMul us b, z ≤ us.length * (A * B) := by
      intro z hz
      rcases List.mem_cons.mp hz with hz | hz
      · rw [hz]; exact Nat.zero_le _
      · exact ih b A B (fun w hw => ha w (by simp [hw])) hb z hz
    have := poly_add_mem_bound (polyScale u b) (0 :: polyMul us b) (A * B) (us.length * (A * B))
      hscale htail v (by simpa [polyMul] using hv)
    simpa [List.length_cons, Nat.succ_mul, Nat.add_comm] using this

/-- The honest `pi` witness of a canonical slot fits `PI_BITS` — the completeness half of the
bounds ledger (`integer_product_bound`, batch.rs:892-909). -/
theorem honest_pi_fits_pi_bits (h s2 : List Nat) (hh : h.length = falconN)
    (hhb : ∀ v ∈ h, v ≤ falconQ - 1) (hsb : ∀ v ∈ s2, v ≤ falconQ - 1) :
    ∀ v ∈ polyMul h s2, v < 2 ^ piBits := by
  intro v hv
  have hb := poly_mul_mem_bound h s2 (falconQ - 1) (falconQ - 1) hhb hsb v hv
  rw [hh] at hb
  have : falconN * ((falconQ - 1) * (falconQ - 1)) < 2 ^ piBits := by
    have := pi_bits_covers_the_honest_product
    simpa [Nat.mul_assoc] using this
  omega

/-- COMPLETENESS of the product check (batch.rs:673-679): the honest witness satisfies
`pi(tau) == h(tau) * s2(tau)` for EVERY challenge. -/
theorem batch_honest_witness_satisfies_the_product_check (h s2 : List Nat) (tau : Nat) :
    polyEval (polyMul h s2) tau = polyEval h tau * polyEval s2 tau := poly_eval_mul h s2 tau

/-- The SOUNDNESS half, as an explicit undischarged premise. `tau` is squeezed from a Poseidon
transcript over all slots' `(h, s2, pi)` and lives in `F_{p^2}`; the argument that agreement at
`tau` forces coefficient equality is Schwartz-Zippel over that extension plus a random-oracle
model of the sponge. NEITHER is proved here (boundaries `schwartzZippelChallenge`,
`fiatShamirRandomOracle`, `extensionFieldEvaluation`). -/
structure ProductCheckSound (h s2 pi : List Nat) (tau : Nat) : Prop where
  agreement_forces_equality : polyEval pi tau = polyEval h tau * polyEval s2 tau → pi = polyMul h s2

/-- Under that premise the check pins `pi` to the honest integer product — the step every later
use of `pi` (the fold offset bound and the norm) depends on. -/
theorem batch_product_check_pins_pi {h s2 pi : List Nat} {tau : Nat}
    (sound : ProductCheckSound h s2 pi tau)
    (checked : polyEval pi tau = polyEval h tau * polyEval s2 tau) :
    pi = polyMul h s2 := sound.agreement_forces_equality checked


/-! ### 7.3 Slot flags: left-packing without a tree (batch.rs 546-559) -/

/-- `is_active[i+1] <= is_active[i]`, the monotone-flag constraint (batch.rs:553-558). -/
def flagsMonotone : List Bool → Bool
  | [] => true
  | [_] => true
  | a :: b :: t => (a || !b) && flagsMonotone (b :: t)

/-- `signer_count = sum(is_active)` (batch.rs:559). -/
def signerCount (flags : List Bool) : Nat := (flags.filter (fun b => b)).length

/-- Once a flag is off, monotonicity forces every later flag off. -/
theorem monotone_tail_after_false :
    ∀ (t : List Bool), flagsMonotone (false :: t) = true →
      false :: t = List.replicate (t.length + 1) false := by
  intro t
  induction t with
  | nil => intro _; rfl
  | cons c t' ih =>
    intro hm
    have hsplit : ((false || !c) && flagsMonotone (c :: t')) = true := hm
    have hc : c = false := by
      cases c with
      | false => rfl
      | true => simp at hsplit
    subst hc
    have htail : flagsMonotone (false :: t') = true := by
      simpa using (Bool.and_eq_true .. |>.mp hsplit).2
    have := ih htail
    simp [List.replicate_succ] at this ⊢
    exact this

/-- STRUCTURAL LEFT-PACKING (batch.rs:63-68): slot 0 asserted active plus monotone flags means the
active slots are exactly a nonempty PREFIX. -/
theorem monotone_flags_are_a_prefix :
    ∀ (flags : List Bool), flags.headD false = true → flagsMonotone flags = true →
      ∃ k, 1 ≤ k ∧ k ≤ flags.length ∧
        flags = List.replicate k true ++ List.replicate (flags.length - k) false := by
  intro flags
  induction flags with
  | nil => intro h0 _; simp at h0
  | cons a t ih =>
    intro h0 hm
    have ha : a = true := by simpa using h0
    subst ha
    cases t with
    | nil => exact ⟨1, Nat.le_refl 1, by simp, by simp⟩
    | cons b t' =>
      have hsplit : ((true || !b) && flagsMonotone (b :: t')) = true := hm
      have htail : flagsMonotone (b :: t') = true := by
        simpa using (Bool.and_eq_true .. |>.mp hsplit).2
      cases b with
      | false =>
        refine ⟨1, Nat.le_refl 1, by simp, ?_⟩
        have := monotone_tail_after_false t' htail
        simp only [List.replicate_succ, List.length_cons] at this ⊢
        rw [this]
        simp [List.replicate_succ]
      | true =>
        obtain ⟨k, hk1, hk2, hk3⟩ := ih (by simp) htail
        refine ⟨k + 1, by omega, by simpa using Nat.succ_le_succ hk2, ?_⟩
        simp only [List.length_cons, List.replicate_succ, List.cons_append]
        rw [hk3]
        simp

theorem signer_count_of_prefix :
    ∀ (k m : Nat), signerCount (List.replicate k true ++ List.replicate m false) = k := by
  intro k
  induction k with
  | zero =>
    intro m
    induction m with
    | zero => rfl
    | succ j ih => simpa [signerCount, List.replicate_succ] using ih
  | succ j ih =>
    intro m
    simpa [signerCount, List.replicate_succ] using ih m

/-! ### 7.4 The exposed statement of the flat circuit (batch.rs 585-590, 681-688) -/

/-- One batch slot: its presence flag and its witness. -/
abbrev BatchSlot := Bool × SlotWitness

/-- `gated_pk_limbs.push(builder.mul(flag.target, limb))` over `pk_g = Poseidon(IMFK ‖ encode(h))`
of the slot's OWN `h` (batch.rs:587-590): the binding of a member key to a signature slot. -/
def batchExposedSlots (env : SigEnv) (slots : List BatchSlot) : List Limbs :=
  slots.map (fun s => gateLimbs s.1 (env.pkDigest s.2.h))

/-- The exposed statement: one shared message wire, the flag sum, the gated pk list. -/
def batchStatement (env : SigEnv) (message : Limbs) (slots : List BatchSlot) : AggStatement :=
  { message := message
    count := signerCount (slots.map Prod.fst)
    pks := batchExposedSlots env slots }

theorem batch_exposed_slots_of_append (env : SigEnv) (a b : List BatchSlot) :
    batchExposedSlots env (a ++ b) = batchExposedSlots env a ++ batchExposedSlots env b := by
  simp [batchExposedSlots]

/-- An active prefix exposes the signers' keys verbatim; the inactive suffix exposes EXACTLY
zero slots (batch.rs:69-75). -/
theorem batch_exposed_slots_left_packed (env : SigEnv) (shape : SigEnvShape env)
    (active padding : List SlotWitness) :
    batchExposedSlots env (active.map (fun w => (true, w)) ++ padding.map (fun w => (false, w)))
      = active.map (fun w => env.pkDigest w.h) ++ List.replicate padding.length zeroSlot := by
  rw [batch_exposed_slots_of_append]
  congr 1
  · induction active with
    | nil => rfl
    | cons w ws ih =>
      simp only [List.map_cons, batchExposedSlots, List.map_cons, gate_limbs_present]
      simp only [batchExposedSlots, List.map_map] at ih
      simp only [List.map_map] at *
      rw [ih]
  · induction padding with
    | nil => rfl
    | cons w ws ih =>
      simp only [List.map_cons, batchExposedSlots, List.map_cons, List.length_cons,
        List.replicate_succ, gate_limbs_absent_is_zero _ (shape w.h)]
      simp only [batchExposedSlots, List.map_map] at ih
      simp only [List.map_map] at *
      rw [ih]

theorem batch_flag_prefix_count (active padding : List SlotWitness) :
    signerCount ((active.map (fun w => (true, w)) ++ padding.map (fun w => (false, w))).map
      Prod.fst) = active.length := by
  have hmap : (active.map (fun w => ((true, w) : BatchSlot)) ++
      padding.map (fun w => ((false, w) : BatchSlot))).map Prod.fst
      = List.replicate active.length true ++ List.replicate padding.length false := by
    rw [List.map_append, List.map_map, List.map_map]
    congr 1
    · induction active with
      | nil => rfl
      | cons w ws ih => simpa [List.replicate_succ] using ih
    · induction padding with
      | nil => rfl
      | cons w ws ih => simpa [List.replicate_succ] using ih
  rw [hmap, signer_count_of_prefix]

/-- CONSUMER-CONTRACT EQUIVALENCE (batch.rs:84-88, 911-927): the flat circuit's exposed statement
encodes byte-identically to the tree's canonical left-packed reference — the property that makes
the swap a VERIFIER-KEY change only. -/
theorem batch_statement_matches_the_tree_contract (env : SigEnv) (shape : SigEnvShape env)
    {message : Limbs} {active padding : List SlotWitness}
    (hm : message.length = bytes32Len)
    (hslots : active.length + padding.length = 2 ^ aggLevels) :
    statementPublicInputs
        (batchStatement env message
          (active.map (fun w => (true, w)) ++ padding.map (fun w => (false, w))))
      = aggExpectedPublicInputs aggLevels message (active.map (fun w => env.pkDigest w.h)) := by
  have hactive : SlotsWellFormed (active.map (fun w => env.pkDigest w.h)) := by
    intro q hq
    rcases List.mem_map.mp hq with ⟨w, _, hw⟩
    rw [← hw]; exact shape w.h
  have hlen : (active.map (fun w => env.pkDigest w.h)).length = active.length := by simp
  have hle : (active.map (fun w => env.pkDigest w.h)).length ≤ 2 ^ aggLevels := by
    rw [hlen]; omega
  have href := statement_public_inputs_match_reference (level := aggLevels) (message := message)
    (active := active.map (fun w => env.pkDigest w.h)) hm hactive hle
  rw [← href]
  simp only [statementPublicInputs, batchStatement,
    batch_exposed_slots_left_packed env shape active padding,
    batch_flag_prefix_count active padding, hlen]
  have hpad : padding.length = 2 ^ aggLevels - active.length := by omega
  rw [hpad]

/-- `signer_count >= 1` in the flat circuit is the asserted flag of slot 0 (batch.rs:551). -/
theorem batch_signer_count_ge_one (active padding : List SlotWitness) (hne : active ≠ []) :
    1 ≤ signerCount ((active.map (fun w => (true, w)) ++
      padding.map (fun w => (false, w))).map Prod.fst) := by
  rw [batch_flag_prefix_count]
  cases active with
  | nil => exact absurd rfl hne
  | cons _ _ => simp

/-! ### 7.5 The gated norm bound — the ONLY gated comparison (batch.rs 644-648) -/

/-- Field subtraction of two canonical representatives (`builder.sub` in Goldilocks). -/
def fieldSub (a b : Nat) : Nat := if b ≤ a then a - b else goldilocks - (b - a)

/-- `select(is_active, beta^2 - norm, 0)` then `range_check(_, 26)`. -/
def gatedSlack (active : Bool) (norm : Nat) : Nat :=
  if active then fieldSub betaSq norm else 0

/-- A PADDING slot's norm is unconstrained — the gate is what lets an all-zero witness satisfy
every other constraint (batch.rs:70-75). -/
theorem inactive_slot_norm_is_unconstrained (norm : Nat) : gatedSlack false norm < 2 ^ slackBits := by
  simp only [gatedSlack, Bool.false_eq_true, if_false]
  decide

/-- An ACTIVE slot's 26-bit slack check IS the native norm bound `||(s1,s2)||^2 <= beta^2`: the
field wrap cannot rescue an over-large norm, because the norm of centered coefficients is far
below `p`. This is why flagging a padding slot active is unprovable (batch.rs:989-1009). -/
theorem active_slot_slack_check_is_the_norm_bound (norm : Nat) (hn : norm < 2 ^ 62) :
    gatedSlack true norm < 2 ^ slackBits ↔ norm ≤ betaSq := by
  have h1 : (2 : Nat) ^ slackBits = 67108864 := by decide
  have h2 : (2 : Nat) ^ 62 = 4611686018427387904 := by decide
  have hg : goldilocks = 18446744069414584321 := by decide
  have hb : betaSq = 34034726 := rfl
  rw [h2] at hn
  simp only [gatedSlack, if_true, fieldSub, h1, hg, hb]
  split <;> omega

/-- The norm this circuit computes — 1024 centered coefficients, each at most `HALF_Q` in absolute
value — never reaches the wrap regime, so the premise of the previous theorem is discharged for
every reachable witness. -/
theorem centered_norm_is_far_below_the_field (n : Nat) (hn : n ≤ 2 * falconN) :
    n * (halfQ * halfQ) < 2 ^ 62 := by
  have h2 : (2 : Nat) ^ 62 = 4611686018427387904 := by decide
  have hq : halfQ = 6144 := by decide
  have hf : falconN = 512 := rfl
  rw [h2, hq]
  rw [hf] at hn
  omega


/-! ### 7.6 The one-row canonicity check and the injective 4x14 packing -/

/-- `assert_canonical_coeff_fast` (batch.rs:218-227): a 14-bit decomposition plus
`b13 * b12 * (v - (q-1)) == 0`. -/
def canonicalFastAccepts (v : Nat) : Prop :=
  v < 2 ^ 14 ∧ (((v / 2 ^ 13) % 2 = 1 ∧ (v / 2 ^ 12) % 2 = 1) → v = falconQ - 1)

instance : DecidablePred canonicalFastAccepts := fun _ => inferInstanceAs (Decidable (_ ∧ _))

/-- The one-row check accepts EXACTLY `[0, q)` — the equivalence claimed in batch.rs:208-217. -/
theorem canonical_fast_accepts_iff_lt_q (v : Nat) : canonicalFastAccepts v ↔ v < falconQ := by
  simp only [canonicalFastAccepts, falconQ]
  omega

/-- The boundary table pinned by `fast_canonical_check_boundary` (batch.rs:1084-1104). -/
theorem canonical_fast_check_boundary :
    canonicalFastAccepts 0 ∧ canonicalFastAccepts 12287 ∧ canonicalFastAccepts 12288 ∧
      ¬ canonicalFastAccepts 12289 ∧ ¬ canonicalFastAccepts 16383 ∧
      ¬ canonicalFastAccepts 16384 := by decide

/-- `pack_coeffs_4x14` (batch.rs:408-423): lane 0 least significant. -/
def pack4 (a b c d : Nat) : Nat := ((d * 2 ^ 14 + c) * 2 ^ 14 + b) * 2 ^ 14 + a

/-- ENCODER INJECTIVITY of the transcript / `pk_g` packing on the CANONICITY-CHECKED domain
(batch.rs:56-59). Without the `< q < 2^14` checks the packing is not injective, which is why the
canonicity gate is a soundness requirement and not hygiene. -/
theorem pack4_injective_on_canonical {a b c d a' b' c' d' : Nat}
    (ha : a < 2 ^ 14) (hb : b < 2 ^ 14) (hc : c < 2 ^ 14) (hd : d < 2 ^ 14)
    (ha' : a' < 2 ^ 14) (hb' : b' < 2 ^ 14) (hc' : c' < 2 ^ 14) (hd' : d' < 2 ^ 14)
    (heq : pack4 a b c d = pack4 a' b' c' d') :
    a = a' ∧ b = b' ∧ c = c' ∧ d = d' := by
  simp only [pack4] at heq
  omega

/-- Canonical coefficients are in range for the packing (the precondition batch.rs:405-407
states the caller must enforce). -/
theorem canonical_coeff_fits_a_lane (v : Nat) (h : v < falconQ) : v < 2 ^ 14 := by
  simp only [falconQ] at h; omega

/-! ### 7.7 The merged centered `s1` fold (batch.rs 596-633) -/

/-- `t = c_lin + pi[512+j] + S1_FOLD_OFFSET - pi[j]`, over the integers. -/
def foldT (cLin piHi piLo : Nat) : Int := (cLin : Int) + piHi + s1FoldOffset - piLo

/-- The centered `s1` coefficient the circuit reads off: `s_shift - HALF_Q`. -/
def centeredCoeff (sShift : Nat) : Int := (sShift : Int) - halfQ

/-- The decomposition the `CenteredFoldGenerator` witnesses and the circuit constrains:
`t + HALF_Q = k*q + s_shift`, `k < 2^32`, `s_shift < 2^14`. -/
structure FoldDecomposition (cLin piHi piLo k sShift : Nat) : Prop where
  recompose : foldT cLin piHi piLo + (halfQ : Int) = (k : Int) * falconQ + sShift
  k_range : k < 2 ^ s1FoldKBits
  s_range : sShift < 2 ^ 14

/-- `t` is non-negative because the offset dominates the largest possible `pi` coefficient — the
reason the fold can be done in the field at all (batch.rs:157-160). -/
theorem fold_t_nonneg (cLin piHi piLo : Nat) (h : piLo < 2 ^ piBits) :
    0 ≤ foldT cLin piHi piLo := by
  have hoff : s1FoldOffset = 137438959389 := by decide
  have hpi : (2 : Nat) ^ piBits = 137438953472 := by decide
  simp only [foldT, hoff]
  rw [hpi] at h
  omega

/-- The centered value is congruent to `t` mod `q`, so (the offset being a multiple of `q`) it is
congruent to `c_lin + pi_hi - pi_lo` — the native negacyclic fold `c - s2*h mod (q, x^n+1)`. -/
theorem fold_centered_is_t_minus_k_q {cLin piHi piLo k sShift : Nat}
    (d : FoldDecomposition cLin piHi piLo k sShift) :
    centeredCoeff sShift = foldT cLin piHi piLo - (k : Int) * falconQ := by
  have := d.recompose
  simp only [centeredCoeff]
  omega

/-- With `s_shift < q` the read-off value is the EXACT centered representative. -/
theorem fold_centered_is_balanced {cLin piHi piLo k sShift : Nat}
    (_d : FoldDecomposition cLin piHi piLo k sShift) (hs : sShift < falconQ) :
    -(halfQ : Int) ≤ centeredCoeff sShift ∧ centeredCoeff sShift ≤ (halfQ : Int) := by
  have hq : falconQ = 12289 := rfl
  have hh : halfQ = 6144 := by decide
  simp only [centeredCoeff, hh]
  rw [hq] at hs
  omega

/-- The ONLY second decomposition admitted by the 14-bit (rather than `< q`) check on `s_shift`
is `(k-1, s_shift+q)` (batch.rs:605-612). -/
theorem fold_second_decomposition_is_the_q_alias {cLin piHi piLo k1 s1 k2 s2 : Nat}
    (d1 : FoldDecomposition cLin piHi piLo k1 s1) (d2 : FoldDecomposition cLin piHi piLo k2 s2) :
    (k1 = k2 ∧ s1 = s2) ∨ (k1 = k2 + 1 ∧ s2 = s1 + falconQ) ∨
      (k2 = k1 + 1 ∧ s1 = s2 + falconQ) := by
  have h1 := d1.recompose
  have h2 := d2.recompose
  have hs1 := d1.s_range
  have hs2 := d2.s_range
  have hq : falconQ = 12289 := rfl
  have h14 : (2 : Nat) ^ 14 = 16384 := by decide
  rw [h14] at hs1 hs2
  rw [hq] at h1 h2 ⊢
  omega

/-- SOUNDNESS OF THE FREE ALIAS: the alias can only INCREASE the reported coefficient magnitude,
so a lying prover can only hurt itself — the norm bound stays sound (batch.rs:605-612). -/
theorem fold_alias_only_increases_the_magnitude (sShift : Nat) (h : sShift + falconQ < 2 ^ 14) :
    (centeredCoeff sShift).natAbs < (centeredCoeff (sShift + falconQ)).natAbs := by
  have hq : falconQ = 12289 := rfl
  have hh : halfQ = 6144 := by decide
  have h14 : (2 : Nat) ^ 14 = 16384 := by decide
  simp only [centeredCoeff, hh]
  rw [hq] at h
  rw [h14] at h
  omega

theorem square_strict_mono {a b : Nat} (h : a < b) : a * a < b * b :=
  Nat.mul_lt_mul_of_lt_of_le h (Nat.le_of_lt h) (Nat.lt_of_le_of_lt (Nat.zero_le a) h)

/-- ... and therefore only increases the squared norm the bound is checked against. -/
theorem fold_alias_only_increases_the_norm (sShift : Nat) (h : sShift + falconQ < 2 ^ 14) :
    (centeredCoeff sShift).natAbs * (centeredCoeff sShift).natAbs <
      (centeredCoeff (sShift + falconQ)).natAbs * (centeredCoeff (sShift + falconQ)).natAbs :=
  square_strict_mono (fold_alias_only_increases_the_magnitude sShift h)

/-! ### 7.8 The alias-free 32/32 split of the H2P sponge output (batch.rs 280-304) -/

/-- `split_32_unique`: `x = hi*2^32 + lo (mod p)`, both halves `< 2^32`, plus the witnessed
quotient constraint `lo = w * (hi - (2^32 - 1))`. -/
structure Split32 (x lo hi w : Nat) : Prop where
  lo_range : lo < 2 ^ 32
  hi_range : hi < 2 ^ 32
  recompose : hi * 2 ^ 32 + lo = x ∨ hi * 2 ^ 32 + lo = x + goldilocks
  alias_free : (lo : Int) = (w : Int) * ((hi : Int) - (2 ^ 32 - 1))

/-- The alias constraint kills the second decomposition: with `hi = 2^32 - 1` the right-hand side
is identically zero, so `lo` must be 0 — and `((2^32-1), 0)` represents `p - 1`, which is
canonical. Hence the split is unique for every canonical `x`. -/
theorem split_32_is_unique {x lo1 hi1 w1 lo2 hi2 w2 : Nat}
    (hx : x < goldilocks)
    (s1 : Split32 x lo1 hi1 w1) (s2 : Split32 x lo2 hi2 w2) :
    lo1 = lo2 ∧ hi1 = hi2 := by
  have hg : goldilocks = 18446744069414584321 := by decide
  have h32 : (2 : Nat) ^ 32 = 4294967296 := by decide
  have kill : ∀ {lo hi w : Nat}, Split32 x lo hi w → hi = 2 ^ 32 - 1 → lo = 0 := by
    intro lo hi w sp hhi
    have := sp.alias_free
    rw [hhi] at this
    simp only [h32] at this ⊢
    omega
  have h1 := s1.recompose
  have h2 := s2.recompose
  have hl1 := s1.lo_range
  have hl2 := s2.lo_range
  have hh1 := s1.hi_range
  have hh2 := s2.hi_range
  rw [hg] at hx h1 h2
  by_cases e1 : hi1 = 2 ^ 32 - 1
  · have hz1 := kill s1 e1
    by_cases e2 : hi2 = 2 ^ 32 - 1
    · exact ⟨by rw [hz1, kill s2 e2], by rw [e1, e2]⟩
    · omega
  · by_cases e2 : hi2 = 2 ^ 32 - 1
    · have hz2 := kill s2 e2
      omega
    · omega


/-! ## 8. The N-of-N list commitment (agg_list.rs)

### 8.1 Domains and the widened leaf format (agg_list.rs 82-133) -/

/-- `AGG_LIST_LEAF_DOMAIN` — ASCII "IMAL". -/
def aggListLeafDomain : Nat := 0x494d414c
/-- `AGG_PK_LIST_DOMAIN` — ASCII "IMPL". -/
def aggPkListDomain : Nat := 0x494d504c
/-- `AGG_PK_LIST_LIMBS = MAX_SIG_CLUSTER * BYTES32_LEN`. -/
def aggPkListLimbs : Nat := maxSigCluster * bytes32Len

theorem agg_list_leaf_domain_pinned : aggListLeafDomain = 0x494d414c := rfl
theorem agg_pk_list_domain_pinned : aggPkListDomain = 0x494d504c := rfl
theorem agg_pk_list_limbs_pinned : aggPkListLimbs = 64 := by decide

theorem agg_list_leaf_domain_is_ascii_imal :
    aggListLeafDomain = UtilGadgets.asciiBE 0x49 0x4d 0x41 0x4c := by decide
theorem agg_pk_list_domain_is_ascii_impl :
    aggPkListDomain = UtilGadgets.asciiBE 0x49 0x4d 0x50 0x4c := by decide

/-- DOMAIN SEPARATION (agg_list.rs:26-34, 850-872): Poseidon here is a NO-PAD sponge, so the
leading constant is the ONLY thing separating the differently-shaped preimages. The three live
schemas' constants are pairwise distinct. NOTE: distinct constants make the PREIMAGES distinct;
that distinct preimages give distinct digests is the undischarged `hashOpaque` boundary. -/
theorem live_list_domains_are_pairwise_distinct :
    aggListLeafDomain ≠ aggPkListDomain ∧ aggListLeafDomain ≠ UtilGadgets.listLeafDomain ∧
      aggPkListDomain ≠ UtilGadgets.listLeafDomain := by decide

/-- `agg_pk_list_digest` preimage (agg_list.rs:106-119): the domain, then ALL 8 slots' limbs with
the padding slots included as explicit zeros. -/
def aggPkListPreimage (pks : List Limbs) : List Nat :=
  aggPkListDomain :: ((pks.join ++ List.replicate (aggPkListLimbs - pks.join.length) 0).take
    aggPkListLimbs)

def aggPkListDigest (env : HashEnv) (pks : List Limbs) : Hash :=
  env.poseidonU64 (aggPkListPreimage pks)

theorem agg_pk_list_preimage_length {pks : List Limbs} (hw : SlotsWellFormed pks)
    (hn : pks.length ≤ maxSigCluster) : (aggPkListPreimage pks).length = 1 + aggPkListLimbs := by
  have hj : pks.join.length = pks.length * bytes32Len := join_length_of_well_formed pks hw
  have hle : pks.join.length ≤ aggPkListLimbs := by
    rw [hj]
    have := Nat.mul_le_mul_right bytes32Len hn
    simpa [aggPkListLimbs] using this
  simp only [aggPkListPreimage, List.length_cons, List.length_take, List.length_append,
    List.length_replicate]
  omega

/-- Padding a list to a fixed width leaves the `take` a no-op. -/
theorem take_pad_id (l : List Nat) (n : Nat) (h : l.length ≤ n) :
    (l ++ List.replicate (n - l.length) 0).take n = l ++ List.replicate (n - l.length) 0 := by
  apply List.take_length_le
  simp only [List.length_append, List.length_replicate]
  omega

/-- The `resize`-to-64 padding IS a zero SUFFIX: the digest of `n` signers equals the digest of the
same signers followed by explicit zero slots (agg_list.rs:833-847). Proved at the PREIMAGE level,
so it holds for any hash. -/
theorem agg_pk_list_preimage_zero_suffix_is_free {pks : List Limbs} (hw : SlotsWellFormed pks)
    (k : Nat) (hn : pks.length + k ≤ maxSigCluster) :
    aggPkListPreimage (pks ++ List.replicate k zeroSlot) = aggPkListPreimage pks := by
  have hj : pks.join.length = pks.length * bytes32Len := join_length_of_well_formed pks hw
  have hjoin : (pks ++ List.replicate k zeroSlot).join
      = pks.join ++ List.replicate (k * bytes32Len) 0 := by
    rw [join_append_eq, join_replicate_zero_slot]
  have hn8 : pks.length + k ≤ 8 := by simpa [maxSigCluster] using hn
  have hle1 : pks.join.length ≤ aggPkListLimbs := by
    simp only [hj, aggPkListLimbs, maxSigCluster, bytes32Len]
    omega
  have hle2 : (pks ++ List.replicate k zeroSlot).join.length ≤ aggPkListLimbs := by
    simp only [hjoin, List.length_append, List.length_replicate, hj, aggPkListLimbs,
      maxSigCluster, bytes32Len]
    omega
  have hcount : k * bytes32Len + (aggPkListLimbs - (pks.join.length + k * bytes32Len))
      = aggPkListLimbs - pks.join.length := by
    simp only [hj, aggPkListLimbs, maxSigCluster, bytes32Len]
    omega
  simp only [aggPkListPreimage, take_pad_id _ _ hle1, take_pad_id _ _ hle2, hjoin,
    List.length_append, List.length_replicate, List.append_assoc,
    List.append_replicate_replicate, hcount]

theorem agg_pk_list_digest_zero_suffix_is_free (env : HashEnv) {pks : List Limbs}
    (hw : SlotsWellFormed pks) (k : Nat) (hn : pks.length + k ≤ maxSigCluster) :
    aggPkListDigest env (pks ++ List.replicate k zeroSlot) = aggPkListDigest env pks := by
  simp [aggPkListDigest, agg_pk_list_preimage_zero_suffix_is_free hw k hn]

/-- `agg_list_leaf` preimage (agg_list.rs:121-133): `[IMAL] ‖ message(8) ‖ signer_count ‖
pk_list_digest(4)`. THIS is where the signer count enters the commitment — a single field element
between the message limbs and the pk-list digest. -/
def aggListLeafPreimage (message : Limbs) (signerCount : Nat) (pkListDigest : Hash) : List Nat :=
  aggListLeafDomain :: (message ++ [signerCount] ++ pkListDigest)

def aggListLeaf (env : HashEnv) (message : Limbs) (signerCount : Nat) (pkListDigest : Hash) :
    Hash :=
  env.poseidonU64 (aggListLeafPreimage message signerCount pkListDigest)

/-- `Vec::with_capacity(1 + BYTES32_LEN + 1 + 4)` — 14 words. -/
theorem agg_list_leaf_preimage_length {message : Limbs} {d : Hash} (hm : message.length = bytes32Len)
    (hd : d.length = UtilGadgets.poseidonHashOutLen) (c : Nat) :
    (aggListLeafPreimage message c d).length = 1 + bytes32Len + 1 + UtilGadgets.poseidonHashOutLen := by
  simp only [aggListLeafPreimage, List.length_cons, List.length_append, List.length_nil, hm, hd]
  omega

/-- ENCODER INJECTIVITY of the widened leaf preimage at the pinned widths: the message, the signer
count and the pk-list digest are all recoverable, so the fold is sensitive to EVERY component
(the property `fold_is_sensitive_to_every_component` pins by example, agg_list.rs:791-848). Again:
this is injectivity of the ENCODING, not of Poseidon. -/
theorem agg_list_leaf_preimage_injective {m1 m2 : Limbs} {c1 c2 : Nat} {d1 d2 : Hash}
    (hm1 : m1.length = bytes32Len) (hm2 : m2.length = bytes32Len)
    (heq : aggListLeafPreimage m1 c1 d1 = aggListLeafPreimage m2 c2 d2) :
    m1 = m2 ∧ c1 = c2 ∧ d1 = d2 := by
  simp only [aggListLeafPreimage, List.cons.injEq, List.append_assoc] at heq
  have hbody : m1 ++ ([c1] ++ d1) = m2 ++ ([c2] ++ d2) := heq.2
  have hm : m1 = m2 := by
    have := congrArg (List.take bytes32Len) hbody
    rwa [List.take_left' hm1, List.take_left' hm2] at this
  have htail : [c1] ++ d1 = [c2] ++ d2 := by
    have := congrArg (List.drop bytes32Len) hbody
    rwa [List.drop_left' hm1, List.drop_left' hm2] at this
  simp only [List.cons_append, List.nil_append, List.cons.injEq] at htail
  exact ⟨hm, htail.1, htail.2⟩

/-- A DIFFERENT signer count is a DIFFERENT preimage, everything else fixed — the component the
retired `(m, pk)` leaf could not express. -/
theorem agg_list_leaf_preimage_separates_signer_counts {message : Limbs} {d : Hash} {c1 c2 : Nat}
    (hm : message.length = bytes32Len) (hne : c1 ≠ c2) :
    aggListLeafPreimage message c1 d ≠ aggListLeafPreimage message c2 d := by
  intro heq
  exact hne (agg_list_leaf_preimage_injective hm hm heq).2.1

/-- The IMAL leaf and the retired IMLL `(m, pk)` leaf are DIFFERENT preimages even on the same
arguments (agg_list.rs:866-871) — they differ in their leading domain constant. -/
theorem agg_list_leaf_preimage_differs_from_imll (message pk : Limbs) (c : Nat) (d : Hash) :
    aggListLeafPreimage message c d ≠ UtilGadgets.listLeafPreimage message pk := by
  intro heq
  have : aggListLeafDomain = UtilGadgets.listLeafDomain := (List.cons.injEq .. ▸ heq).1
  exact absurd this (by decide)

/-! ### 8.2 The chain fold (agg_list.rs 135-217) -/

/-- One folded block statement: "these `signer_pks` (in slot order) ALL signed `message`". -/
structure AggListEntry where
  message : Limbs
  signerPks : List Limbs
  deriving Repr

/-- `AggListEntry::leaf` (agg_list.rs:146-152). -/
def entryLeaf (env : HashEnv) (e : AggListEntry) : Hash :=
  aggListLeaf env e.message e.signerPks.length (aggPkListDigest env e.signerPks)

/-- `agg_list_commitment` (agg_list.rs:211-217): the SHARED `list_chain_step` from `C_0 = 0`; only
the leaf format widens. -/
def aggListCommitment (env : HashEnv) (entries : List AggListEntry) : Hash :=
  entries.foldl (fun chain e => UtilGadgets.listChainStep env chain (entryLeaf env e))
    UtilGadgets.zeroHash

/-- `C_0 = 0` — the value the cyclic wrapper forces at the first step and the validity circuit
gates on (agg_list.rs:832). -/
theorem agg_list_commitment_empty_is_zero (env : HashEnv) :
    aggListCommitment env [] = UtilGadgets.zeroHash := rfl

/-- The fold continues from any prefix — the algebra the cyclic wrapper's `prev_chain` wiring
relies on. -/
theorem agg_list_commitment_append (env : HashEnv) (a b : List AggListEntry) :
    aggListCommitment env (a ++ b)
      = b.foldl (fun chain e => UtilGadgets.listChainStep env chain (entryLeaf env e))
          (aggListCommitment env a) := by
  simp [aggListCommitment, List.foldl_append]

/-- One appended entry is one chain step (the equality each `prove_append` asserts). -/
theorem agg_list_commitment_snoc (env : HashEnv) (a : List AggListEntry) (e : AggListEntry) :
    aggListCommitment env (a ++ [e])
      = UtilGadgets.listChainStep env (aggListCommitment env a) (entryLeaf env e) := by
  rw [agg_list_commitment_append]
  rfl

/-- The chain STEP is bit-for-bit the one the single-signature list uses (agg_list.rs:210). -/
theorem agg_list_uses_the_shared_chain_step (env : HashEnv) (prev leaf : Hash) :
    UtilGadgets.listChainStep env prev leaf = env.poseidonU64 (prev ++ leaf) := rfl

end Zkp.Implementation.FalconAggregate
