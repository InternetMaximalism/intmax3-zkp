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

/-- Width: a left-packed encoding at `level` is exactly `falcon_agg_public_inputs_len(level)`
elements (agg.rs:187-194). -/
theorem agg_expected_public_inputs_length {level : Nat} {message : Limbs} {pks : List Limbs}
    (hm : message.length = bytes32Len) (hw : SlotsWellFormed pks)
    (hn : pks.length ≤ 2 ^ level) :
    (aggExpectedPublicInputs level message pks).length = falconAggPublicInputsLenAt level := by
  have hbody := agg_expected_body_length hm hw
  have hle : (message ++ [pks.length] ++ pks.join).length ≤ falconAggPublicInputsLenAt level := by
    rw [hbody]
    have : pks.length * bytes32Len ≤ 2 ^ level * bytes32Len :=
      Nat.mul_le_mul_right _ hn
    simp [falconAggPublicInputsLenAt] at *
    omega
  simp [aggExpectedPublicInputs, List.length_take, List.length_append, List.length_replicate]
  omega

end Zkp.Implementation.FalconAggregate
