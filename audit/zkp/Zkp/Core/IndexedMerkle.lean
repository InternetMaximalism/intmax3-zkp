import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Zkp.Core.IndexedMerkle  — nullifier non-membership / insert
  ===========================================================

  Source: `src/utils/trees/indexed_merkle_tree/insertion.rs`
          `src/utils/trees/indexed_merkle_tree/leaf.rs`
          `src/utils/trees/indexed_merkle_tree/mod.rs`
          `src/common/trees/nullifier_tree.rs`

  Addresses finding **F-NULL-1**: the spend-once guarantee used by
  `UpdatePrivateState` (`NullifierInsert`) rests on this gadget proving
  a key (nullifier) was ABSENT before insertion.

  ## Mechanism (indexed Merkle tree)

  Leaves form a sorted singly-linked list by `key`: each leaf stores
  `next_index`, `key`, `next_key` (the immediate successor key, or the
  `0` sentinel for the maximum) and `value` (leaf.rs:28-33). To insert
  `key`, the prover exhibits a `low_leaf` with

      low.key < key  AND  (key < low.next_key  OR  low.next_key = 0)

  and a Merkle proof that `low_leaf` is in the tree; insertion then
  splices `key` between `low_leaf` and its successor. The circuit does
  NOT check that `low.next_key` is the immediate successor — that is
  the linked-list INVARIANT, which must be (a) true of the genesis
  tree and (b) preserved by every accepted insertion. Both are proved
  below (`genesis_inv`, `insert_preserves_inv`); non-membership
  (`key_absent`) is then DERIVED from the invariant, not assumed.

  ## Circuit constraint inventory
  (`IndexedInsertionProofTarget::get_new_root`, insertion.rs:271-321;
  native counterpart `IndexedInsertionProof::get_new_root`, :129-174)

  | circuit  | native   | gate                                                  | model field |
  |----------|----------|-------------------------------------------------------|-------------|
  | :285-287 | :135-140 | `assert_one(prev_low_leaf.key.is_lt(key))`            | `lowBound`  |
  | :288-294 | :142-147 | `assert_one(key.is_lt(next_key) OR next_key.is_zero)` | `upBound`   |
  | :296-301 | :149-150 | `low_leaf_proof.verify(prev_low_leaf, low_leaf_index, prev_root)` | `lowIncl` |
  | :302-306 | :152-156 | `new_low_leaf = {next_index: index, next_key: key, ..prev_low_leaf}` | `spliceLow` |
  | :307-309 | :157-159 | `temp_root = low_leaf_proof.get_root(new_low_leaf, low_leaf_index)` | `emptySlot`/`post` |
  | :310-312 | :161-165 | `leaf_proof.verify(empty_leaf, index, temp_root)`     | `emptySlot` |
  | :313-318 | :167-172 | `leaf = {next_index: prev.next_index, key, next_key: prev.next_key, value}` | `insLeaf` |
  | :319-320 | :173     | `new_root = leaf_proof.get_root(leaf, index)`         | `post`      |

  Strictness of the comparisons: `U256Target::is_lt` is
  `is_le AND NOT is_eq` (fn at u256.rs:348; the strict and-composition at :353-356) — strict, so `key = low.key`
  and `key = low.next_key` are both rejected.

  ## The empty-leaf = MAX fix (leaf.rs:46-75)

  Empty slots hash to `zero_hashes`. If `empty_leaf == default` (key 0),
  an empty slot is indistinguishable from the genesis sentinel, and a
  prover could treat ANY empty slot as a pseudo-low-leaf to RE-insert a
  present key (the `nullifier_duplicate_insertion_poc`). Fix
  (leaf.rs:68-75): the empty leaf has `key = U256::MAX`, so the
  lower-bound check `low.key < key` (i.e. `MAX < key`) FAILS for every
  `key ≤ MAX`. Modeled as `emptyLeaf.key = MAX`; see
  `empty_leaf_cannot_be_low`.

  ## Modeling boundary: root ↔ leaf-map correspondence

  The circuit's state is a Poseidon root; our state is the LEAF MAP
  `Tree = Nat → Leaf` the root commits to (unoccupied slots hold
  `emptyLeaf`, exactly what `zero_hashes` commits to). The
  correspondence used, per constraint:

    * `lowIncl : T lowIdx = low` is the map-level shadow of
      `low_leaf_proof.verify(prev_low_leaf, low_leaf_index, prev_root)`
      (:296-301): under collision resistance of the fold compression
      (`Merkle.CompressCR`; leaf hashing additionally under
      `Bytes.PoseidonCR` — neither assumed here) a root binds one leaf
      map, and a verified inclusion pins the leaf at that index. At the
      root level this correspondence is now the NAMED hypothesis
      `Circuits.UpdatePrivateState.NullifierRootBinding`, consumed by
      `nullifierInsert_reachable_chain` there — it is no longer an
      undocumented gap between "same root" and "same map".
    * `emptySlot` / `post` are the shadows of the get_root splices
      (:307-309, :319-320): `verify` and `get_root` are called on the
      SAME proof object (`low_leaf_proof` resp. `leaf_proof`), i.e. the
      same siblings and the same index-bit decomposition, so temp/new
      roots commit to maps differing from the previous map ONLY at
      `low_leaf_index` resp. `index` (the shared-path argument, cf.
      `AssetUpdate` in Circuits/Balance/Common/UpdatePrivateState.lean
      and `MerkleVerify` in Core/Merkle.lean).

  Indices are `Nat` in the model, but the circuit-enforced 32-bit
  bound (`NULLIFIER_TREE_HEIGHT = 32`, constants.rs:38) is carried as
  the explicit `lowIdxLt`/`newIdxLt` conjuncts of `InsertConstraints`:
  `low_leaf_proof` and `leaf_proof` are height-32 `MerkleProofTarget`s
  (nullifier_tree.rs:99-101 passes `NULLIFIER_TREE_HEIGHT` to
  `IndexedInsertionProofTarget::new`, which allocates both proofs at
  that height, insertion.rs:216-217), and every `verify`/`get_root`
  call on them decomposes its index wire via `split_le(index, 32)`
  into 32 boolean wires (utils/trees/merkle_tree.rs:227) — so the
  addressed slot is one of the `2^32` the real root commits to. These
  bounds are load-bearing for the HONEST (bounded) root↔map binding
  `Circuits.UpdatePrivateState.NullifierRootBinding`, whose real
  height-32 root simply does not read slots `≥ 2^32`.
-/

namespace Zkp
namespace IndexedMerkle

open CField Builder Bytes Merkle

/-- Keys are U256; modeled by their ℕ value for ordering. `MAX` is the
    empty-leaf sentinel key (leaf.rs:68-75). -/
def MAX : Nat := 2 ^ 256 - 1

/-- A leaf of the indexed Merkle tree, field-for-field with
    `IndexedMerkleLeaf` (leaf.rs:28-33): `next_index : u64`,
    `key : U256`, `next_key : U256`, `value : u64`, each modeled by its
    ℕ value. `nextKey = 0` is the "largest leaf" sentinel. -/
structure Leaf where
  nextIndex : Nat
  key : Nat
  nextKey : Nat
  value : Nat
deriving DecidableEq

/-- `Leafable::empty_leaf` (leaf.rs:68-75): the content of every
    unoccupied tree slot. `key = U256::MAX` is the security-critical
    field (BAL-CRIT-001 fix); `next_index = u64::MAX` is
    defense-in-depth. -/
def emptyLeaf : Leaf := ⟨2 ^ 64 - 1, MAX, 0, 0⟩

/-- The genesis sentinel `IndexedMerkleLeaf::default()` (all zeros)
    pushed at index 0 by `IndexedMerkleTree::new` (mod.rs:26-30). -/
def genesisLeaf : Leaf := ⟨0, 0, 0, 0⟩

/-- Tree state = the total leaf map a Poseidon root commits to.
    Unoccupied slots hold `emptyLeaf` (that is literally what
    `zero_hashes` commits to, so "slot = emptyLeaf" and "slot
    unoccupied" are indistinguishable at the root — the map IS the
    committed state). See the root↔map boundary note in the header. -/
abbrev Tree := Nat → Leaf

/-- Point update of the leaf map (the effect of `get_root` with a new
    leaf along the verified path — shared-path argument, header note). -/
def Tree.update (T : Tree) (i : Nat) (l : Leaf) : Tree :=
  fun j => if j = i then l else T j

/-- A slot is occupied iff its content differs from the empty leaf. -/
def Occupied (T : Tree) (i : Nat) : Prop := T i ≠ emptyLeaf

/-- Key `k` is present in the tree: some occupied slot carries it. -/
def present (T : Tree) (k : Nat) : Prop := ∃ i, Occupied T i ∧ (T i).key = k

/-- The tree produced by `IndexedMerkleTree::new` (mod.rs:26-30): all
    slots empty, then `IndexedMerkleLeaf::default()` pushed at index 0. -/
def genesisTree : Tree := fun i => if i = 0 then genesisLeaf else emptyLeaf

/-- Gap-emptiness for one leaf: the open interval
    `(low.key, low.nextKey)` — or `(low.key, ∞)` when `nextKey = 0` —
    contains no present key. This is the linked-list property the
    non-membership argument needs; it is NOT checked by the circuit
    and is instead DERIVED from `Inv` (see `low_gapEmpty`). -/
def GapEmpty (low : Leaf) (present : Nat → Prop) : Prop :=
  ∀ k, low.key < k → (low.nextKey = 0 ∨ k < low.nextKey) → ¬ present k

/-- **The linked-list invariant** over the whole tree:
    occupied keys are pairwise distinct (`inj`), and EVERY occupied
    leaf's successor gap is empty of present keys (`gap`). This is the
    inductive strengthening that survives insertion
    (`insert_preserves_inv`); gap-emptiness alone does not (two leaves
    with equal keys would let an insert re-open the copy's gap). -/
structure Inv (T : Tree) : Prop where
  inj : ∀ i j, Occupied T i → Occupied T j → (T i).key = (T j).key → i = j
  gap : ∀ i, Occupied T i → GapEmpty (T i) (present T)

/-- The updated low leaf
    `{ next_index: index, next_key: key, ..prev_low_leaf }`
    (insertion.rs:302-306, native :152-156). -/
def spliceLow (low : Leaf) (key newIdx : Nat) : Leaf :=
  ⟨newIdx, low.key, key, low.value⟩

/-- The inserted leaf
    `{ next_index: prev_low_leaf.next_index, key, next_key:
    prev_low_leaf.next_key, value }` (insertion.rs:313-318, native
    :167-172): it inherits the low leaf's OLD successor. -/
def insLeaf (low : Leaf) (key value : Nat) : Leaf :=
  ⟨low.nextIndex, key, low.nextKey, value⟩

/-- **Exactly the constraints the insert circuit emits**
    (`get_new_root`, insertion.rs:271-321), at the leaf-map level
    (root↔map boundary in the header). Per-field citations:

    * `keyRange` — `key : U256Target` is 8 range-checked u32 limbs, so
      its value is ≤ 2^256−1. On the nullifier path the limbs come from
      `Bytes32Target::new(builder, is_checked)`
      (update_private_state.rs:131) reinterpreted via
      `U256Target::from_slice` (nullifier_tree.rs:134-140); both
      production instantiations pass `is_checked = true`
      (receive_transfer_circuit.rs:396, receive_deposit_circuit.rs:289).
    * `lowBound` — `assert_one(prev_low_leaf.key.is_lt(key))`
      (insertion.rs:285-287); `is_lt` is STRICT (`is_le AND NOT is_eq`, u256.rs:353-356).
    * `upBound` — `assert_one(key.is_lt(next_key) OR next_key.is_zero)`
      (insertion.rs:288-294).
    * `lowIncl` — `low_leaf_proof.verify(prev_low_leaf, low_leaf_index,
      prev_root)` (insertion.rs:296-301), map-level shadow.
    * `emptySlot` — the slot at `index` is empty in the tree AFTER the
      low-leaf splice: `temp_root = low_leaf_proof.get_root(new_low_leaf,
      low_leaf_index)` (insertion.rs:307-309) followed by
      `leaf_proof.verify(empty_leaf, index, temp_root)`
      (insertion.rs:310-312).
    * `post` — the post-tree is the spliced tree with the new leaf
      written at `index`: `new_root = leaf_proof.get_root(leaf, index)`
      (insertion.rs:313-320).
    * `lowIdxLt` / `newIdxLt` — the index wires address one of the
      `2^32` slots: `low_leaf_proof`/`leaf_proof` are
      height-`NULLIFIER_TREE_HEIGHT = 32` proofs (constants.rs:38;
      nullifier_tree.rs:99-101 → insertion.rs:216-217), and each
      `verify`/`get_root` call decomposes its index via
      `split_le(index, 32)` into 32 boolean wires
      (utils/trees/merkle_tree.rs:227), pinning the index value below
      `2^32`. (The two calls per proof object are two INDEPENDENT
      `split_le` decompositions of the same wire, identified under
      `Merkle.PowTwoInj F 32` — part of the root↔map boundary, see
      header.) -/
structure InsertConstraints (T : Tree) (low : Leaf)
    (lowIdx newIdx key value : Nat) (T' : Tree) : Prop where
  keyRange : key ≤ MAX
  lowBound : low.key < key
  upBound  : low.nextKey = 0 ∨ key < low.nextKey
  lowIncl  : T lowIdx = low
  emptySlot : Tree.update T lowIdx (spliceLow low key newIdx) newIdx = emptyLeaf
  post : T' = Tree.update (Tree.update T lowIdx (spliceLow low key newIdx))
                newIdx (insLeaf low key value)
  lowIdxLt : lowIdx < 2 ^ 32
  newIdxLt : newIdx < 2 ^ 32

section Facts

variable {T T' : Tree} {low : Leaf} {lowIdx newIdx key value : Nat}

/-- The low leaf's key cannot be the empty sentinel `MAX`
    (`MAX < key ≤ MAX` is impossible). -/
theorem low_key_ne_MAX (h : InsertConstraints T low lowIdx newIdx key value T') :
    low.key ≠ MAX := by
  have h1 := h.lowBound
  have h2 := h.keyRange
  omega

/-- Hence the low leaf is not the empty leaf. -/
theorem low_ne_empty (h : InsertConstraints T low lowIdx newIdx key value T') :
    low ≠ emptyLeaf := by
  intro he
  exact low_key_ne_MAX h (congrArg Leaf.key he)

/-- **Empty-leaf sentinel blocks the pseudo-low-leaf attack**
    (leaf.rs:68-75 fix, BAL-CRIT-001). If a prover presents an empty
    slot's content (key = MAX) as the low leaf, `lowBound` becomes
    `MAX < key` with `key ≤ MAX` — unsatisfiable. This closes
    `nullifier_duplicate_insertion_poc`. -/
theorem empty_leaf_cannot_be_low (hempty : low.key = MAX)
    (h : InsertConstraints T low lowIdx newIdx key value T') : False :=
  low_key_ne_MAX h hempty

/-- The spliced low leaf keeps `low.key ≠ MAX`, so it is not empty. -/
theorem splice_ne_empty (h : InsertConstraints T low lowIdx newIdx key value T') :
    spliceLow low key newIdx ≠ emptyLeaf := by
  intro he
  exact low_key_ne_MAX h (congrArg Leaf.key he)

/-- Projection helpers (definitional, stated for `rw`). -/
theorem insLeaf_key : (insLeaf low key value).key = key := rfl
theorem spliceLow_key : (spliceLow low key newIdx).key = low.key := rfl

/-- Occupancy only depends on the slot's content. -/
theorem occupied_congr {T₁ T₂ : Tree} {j : Nat} (e : T₁ j = T₂ j) :
    Occupied T₁ j ↔ Occupied T₂ j := by
  unfold Occupied
  rw [e]

/-- The insertion slot differs from the low-leaf slot: were they equal,
    the empty-slot check (:310-312) would pin the SPLICED low leaf to
    `emptyLeaf`, forcing `low.key = MAX`. -/
theorem newIdx_ne_lowIdx (h : InsertConstraints T low lowIdx newIdx key value T') :
    newIdx ≠ lowIdx := by
  intro he
  have hs := h.emptySlot
  unfold Tree.update at hs
  rw [if_pos he] at hs
  exact splice_ne_empty h hs

/-- The insertion slot was empty already in the PRE-tree. -/
theorem slot_was_empty (h : InsertConstraints T low lowIdx newIdx key value T') :
    T newIdx = emptyLeaf := by
  have hs := h.emptySlot
  unfold Tree.update at hs
  rw [if_neg (newIdx_ne_lowIdx h)] at hs
  exact hs

/-- The low-leaf slot is occupied in the pre-tree. -/
theorem low_occupied (h : InsertConstraints T low lowIdx newIdx key value T') :
    Occupied T lowIdx := by
  intro he
  rw [h.lowIncl] at he
  exact low_ne_empty h he

/-- Pointwise evaluation of the post-tree. -/
theorem post_eval (h : InsertConstraints T low lowIdx newIdx key value T') (j : Nat) :
    T' j = if j = newIdx then insLeaf low key value
           else if j = lowIdx then spliceLow low key newIdx else T j := by
  rw [h.post]; rfl

theorem T'_at_new (h : InsertConstraints T low lowIdx newIdx key value T') :
    T' newIdx = insLeaf low key value := by
  rw [post_eval h newIdx, if_pos rfl]

theorem T'_at_low (h : InsertConstraints T low lowIdx newIdx key value T') :
    T' lowIdx = spliceLow low key newIdx := by
  rw [post_eval h lowIdx, if_neg (Ne.symm (newIdx_ne_lowIdx h)), if_pos rfl]

theorem T'_at_other (h : InsertConstraints T low lowIdx newIdx key value T')
    {j : Nat} (hjn : j ≠ newIdx) (hjl : j ≠ lowIdx) : T' j = T j := by
  rw [post_eval h j, if_neg hjn, if_neg hjl]

/-- **Gap-emptiness of the low leaf is DERIVED from the invariant**
    (previously this was assumed as a hypothesis with no Rust
    counterpart — the over-constraint at the heart of F-NULL-1's
    original "discharge"). -/
theorem low_gapEmpty (hInv : Inv T)
    (h : InsertConstraints T low lowIdx newIdx key value T') :
    GapEmpty low (present T) := by
  have hg := hInv.gap lowIdx (low_occupied h)
  rwa [h.lowIncl] at hg

/-- **Non-membership (spend-once) soundness.** On any tree satisfying
    the linked-list invariant, a key the insert circuit accepts was NOT
    already present: the invariant makes `(low.key, low.next_key)` an
    empty gap, and `lowBound`/`upBound` bracket `key` inside it. -/
theorem key_absent (hInv : Inv T)
    (h : InsertConstraints T low lowIdx newIdx key value T') :
    ¬ present T key :=
  low_gapEmpty hInv h key h.lowBound h.upBound

/-- **No double-insertion.** If `key` is already present in an
    invariant-satisfying tree, the circuit rejects every candidate
    witness. (Contrapositive of `key_absent`.) -/
theorem no_double_insert (hInv : Inv T) (hpresent : present T key)
    (h : InsertConstraints T low lowIdx newIdx key value T') : False :=
  key_absent hInv h hpresent

/-- Presence is preserved into the post-tree (nothing is deleted). -/
theorem present_insert_of_present
    (h : InsertConstraints T low lowIdx newIdx key value T') {k : Nat}
    (hp : present T k) : present T' k := by
  obtain ⟨j, hocc, hkey⟩ := hp
  by_cases hjn : j = newIdx
  · rw [hjn] at hocc
    exact absurd (slot_was_empty h) hocc
  · by_cases hjl : j = lowIdx
    · rw [hjl, h.lowIncl] at hkey
      refine ⟨lowIdx, ?_, ?_⟩
      · intro he; rw [T'_at_low h] at he; exact splice_ne_empty h he
      · rw [T'_at_low h]; exact hkey
    · refine ⟨j, ?_, ?_⟩
      · exact (occupied_congr (T'_at_other h hjn hjl)).mpr hocc
      · rw [T'_at_other h hjn hjl]; exact hkey

/-- Every key present in the post-tree was present before, or is the
    freshly inserted `key`. -/
theorem present_of_present_insert
    (h : InsertConstraints T low lowIdx newIdx key value T') {k : Nat}
    (hp : present T' k) : present T k ∨ k = key := by
  obtain ⟨j, hocc, hkey⟩ := hp
  by_cases hjn : j = newIdx
  · rw [hjn, T'_at_new h] at hkey
    have hkey' : key = k := hkey
    exact Or.inr hkey'.symm
  · by_cases hjl : j = lowIdx
    · rw [hjl, T'_at_low h] at hkey
      have hkey' : low.key = k := hkey
      exact Or.inl ⟨lowIdx, low_occupied h, by rw [h.lowIncl]; exact hkey'⟩
    · have hocc' : Occupied T j := (occupied_congr (T'_at_other h hjn hjl)).mp hocc
      rw [T'_at_other h hjn hjl] at hkey
      exact Or.inl ⟨j, hocc', hkey⟩

/-- **Preservation: valid insertions keep the linked-list invariant.**
    This is the mathematical heart of F-NULL-1: the circuit never
    checks `GapEmpty` directly; it stays true because (a) the new leaf
    inherits the low leaf's old successor and the low leaf now points
    at the new key (:302-306, :313-318), and (b) key-injectivity plus
    old gap-emptiness rule out any OTHER leaf's gap swallowing the new
    key. -/
theorem insert_preserves_inv (hInv : Inv T)
    (h : InsertConstraints T low lowIdx newIdx key value T') : Inv T' := by
  have habs : ¬ present T key := key_absent hInv h
  have hgaplow : GapEmpty low (present T) := low_gapEmpty hInv h
  have hlb : low.key < key := h.lowBound
  -- any non-new occupied slot of T' carrying `key` is a contradiction
  have aux : ∀ j, j ≠ newIdx → Occupied T' j → (T' j).key = key → False := by
    intro j hjn hj hk
    by_cases hjl : j = lowIdx
    · rw [hjl, T'_at_low h, spliceLow_key] at hk
      omega
    · have hj' : Occupied T j := (occupied_congr (T'_at_other h hjn hjl)).mp hj
      rw [T'_at_other h hjn hjl] at hk
      exact habs ⟨j, hj', hk⟩
  constructor
  · -- key injectivity
    intro i j hi hj hk
    by_cases hin : i = newIdx <;> by_cases hjn : j = newIdx
    · rw [hin, hjn]
    · exfalso
      apply aux j hjn hj
      rw [← hk, hin, T'_at_new h, insLeaf_key]
    · exfalso
      apply aux i hin hi
      rw [hk, hjn, T'_at_new h, insLeaf_key]
    · by_cases hil : i = lowIdx <;> by_cases hjl : j = lowIdx
      · rw [hil, hjl]
      · have hj' : Occupied T j := (occupied_congr (T'_at_other h hjn hjl)).mp hj
        rw [hil, T'_at_low h, spliceLow_key, T'_at_other h hjn hjl] at hk
        have hk' : (T lowIdx).key = (T j).key := by rw [h.lowIncl]; exact hk
        rw [hil]
        exact hInv.inj lowIdx j (low_occupied h) hj' hk'
      · have hi' : Occupied T i := (occupied_congr (T'_at_other h hin hil)).mp hi
        rw [hjl, T'_at_low h, spliceLow_key, T'_at_other h hin hil] at hk
        have hk' : (T i).key = (T lowIdx).key := by rw [h.lowIncl]; exact hk
        rw [hjl]
        exact hInv.inj i lowIdx hi' (low_occupied h) hk'
      · have hi' : Occupied T i := (occupied_congr (T'_at_other h hin hil)).mp hi
        have hj' : Occupied T j := (occupied_congr (T'_at_other h hjn hjl)).mp hj
        rw [T'_at_other h hin hil, T'_at_other h hjn hjl] at hk
        exact hInv.inj i j hi' hj' hk
  · -- gap-emptiness of every occupied leaf of T'
    intro i hi
    by_cases hin : i = newIdx
    · -- the new leaf: gap (key, low.nextKey) ⊆ old gap of `low`
      rw [hin, T'_at_new h]
      intro k hk1 hk2 hpk
      have hk1' : key < k := hk1
      have hk2' : low.nextKey = 0 ∨ k < low.nextKey := hk2
      rcases present_of_present_insert h hpk with hpres | hke
      · exact hgaplow k (by omega) hk2' hpres
      · omega
    · by_cases hil : i = lowIdx
      · -- the spliced low leaf: gap (low.key, key) ⊆ old gap of `low`
        rw [hil, T'_at_low h]
        intro k hk1 hk2 hpk
        have hk1' : low.key < k := hk1
        have hk2' : key = 0 ∨ k < key := hk2
        have hklt : k < key := by
          rcases hk2' with h0 | h1
          · omega
          · exact h1
        rcases present_of_present_insert h hpk with hpres | hke
        · have hup : low.nextKey = 0 ∨ k < low.nextKey := by
            rcases h.upBound with h0 | h1
            · exact Or.inl h0
            · exact Or.inr (by omega)
          exact hgaplow k hk1' hup hpres
        · omega
      · -- an untouched leaf: only the new `key` could newly violate its
        -- gap; injectivity + old gaps force that leaf to BE the low
        -- leaf, contradiction.
        have hi' : Occupied T i := (occupied_congr (T'_at_other h hin hil)).mp hi
        rw [T'_at_other h hin hil]
        intro k hk1 hk2 hpk
        rcases present_of_present_insert h hpk with hpres | hke
        · exact hInv.gap i hi' k hk1 hk2 hpres
        · -- k = key sits in gap(T i); derive False
          rw [hke] at hk1 hk2
          -- (T i).key present and outside gap(low) ⇒ (T i).key ≤ low.key
          have hstep2 : (T i).key ≤ low.key := by
            refine Classical.byContradiction fun hgt => ?_
            have hup : low.nextKey = 0 ∨ (T i).key < low.nextKey := by
              rcases h.upBound with h0 | h1
              · exact Or.inl h0
              · exact Or.inr (by omega)
            exact hgaplow (T i).key (by omega) hup ⟨i, hi', rfl⟩
          have hlow_pres : present T low.key :=
            ⟨lowIdx, low_occupied h, by rw [h.lowIncl]⟩
          by_cases heq : (T i).key = low.key
          · -- equal keys ⇒ i = lowIdx by injectivity — contradiction
            have hkl : (T i).key = (T lowIdx).key := by rw [h.lowIncl]; exact heq
            exact hil (hInv.inj i lowIdx hi' (low_occupied h) hkl)
          · -- (T i).key < low.key: then low.key lies in gap(T i) — but
            -- low.key is present, contradicting T's gap at i
            have hup : (T i).nextKey = 0 ∨ low.key < (T i).nextKey := by
              rcases hk2 with h0 | h1
              · exact Or.inl h0
              · exact Or.inr (by omega)
            exact hInv.gap i hi' low.key (by omega) hup hlow_pres

end Facts

/-- The genesis tree satisfies the invariant: index 0 holds the all-zero
    sentinel `IndexedMerkleLeaf::default()` (mod.rs:26-30), everything
    else is empty; the sentinel's gap `(0, ∞)` contains no present key
    because 0 is the only present key. -/
theorem genesis_occ {i : Nat} (h : Occupied genesisTree i) : i = 0 := by
  refine Classical.byContradiction fun hne => ?_
  exact h (by unfold genesisTree; rw [if_neg hne])

theorem genesisLeaf_ne_empty : genesisLeaf ≠ emptyLeaf := by decide

theorem genesis_inv : Inv genesisTree := by
  constructor
  · intro i j hi hj _
    rw [genesis_occ hi, genesis_occ hj]
  · intro i hi
    have hi0 := genesis_occ hi
    subst hi0
    intro k hk1 _ hpres
    obtain ⟨j, hj, hjkey⟩ := hpres
    have hj0 := genesis_occ hj
    subst hj0
    have e0 : (genesisTree 0).key = 0 := rfl
    rw [e0] at hk1 hjkey
    omega

/-- Trees reachable from genesis by circuit-accepted insertions — the
    states an honest-or-malicious prover can drive the nullifier tree
    through while producing accepting proofs. -/
inductive Reachable : Tree → Prop where
  | genesis : Reachable genesisTree
  | insert {T T' : Tree} {low : Leaf} {lowIdx newIdx key value : Nat} :
      Reachable T → InsertConstraints T low lowIdx newIdx key value T' →
      Reachable T'

/-- **The preservation induction**: every reachable tree satisfies the
    linked-list invariant. Combines `genesis_inv` (base) with
    `insert_preserves_inv` (step). -/
theorem reachable_inv {T : Tree} (h : Reachable T) : Inv T := by
  induction h with
  | genesis => exact genesis_inv
  | insert _ hc ih => exact insert_preserves_inv ih hc

/-- Spend-once along the whole chain: on ANY reachable tree, an
    accepted insertion's key was absent. This — not a per-call
    assumption — is the F-NULL-1 discharge. -/
theorem reachable_key_absent {T T' : Tree} {low : Leaf}
    {lowIdx newIdx key value : Nat}
    (hr : Reachable T) (h : InsertConstraints T low lowIdx newIdx key value T') :
    ¬ present T key :=
  key_absent (reachable_inv hr) h

/-- The constraint system is satisfiable (not vacuously sound): the
    honest first insertion — key 1 into the genesis tree at slot 1,
    low leaf = genesis sentinel — is accepted. -/
theorem insertConstraints_satisfiable :
    ∃ (T : Tree) (low : Leaf) (lowIdx newIdx key value : Nat) (T' : Tree),
      InsertConstraints T low lowIdx newIdx key value T' := by
  refine ⟨genesisTree, genesisLeaf, 0, 1, 1, 0,
    Tree.update (Tree.update genesisTree 0 (spliceLow genesisLeaf 1 1))
      1 (insLeaf genesisLeaf 1 0), ?_⟩
  exact {
    keyRange := by decide
    lowBound := by decide
    upBound := Or.inl rfl
    lowIncl := rfl
    emptySlot := rfl
    post := rfl
    lowIdxLt := by decide
    newIdxLt := by decide
  }

/-!
  ## SECURITY OBSERVATIONS

  * **F-NULL-1 — what is now PROVED (previously assumed).** The earlier
    revision of this file bundled `GapEmpty` into `InsertConstraints`
    as a hypothesis with no Rust counterpart, making `key_absent`
    near-tautological. That over-constraint is removed.
    `InsertConstraints` now contains exactly the circuit's emitted
    checks (citation table above), and the chain is:
      1. `genesis_inv` — the initial tree satisfies the linked-list
         invariant (key-injectivity + all gaps empty);
      2. `insert_preserves_inv` — every accepted insertion PRESERVES
         it (the induction step the finding demanded);
      3. `reachable_inv` / `reachable_key_absent` — hence on every
         reachable tree, an accepted key was absent: spend-once.
    `no_double_insert` and `empty_leaf_cannot_be_low` are re-proved on
    the honest structure; `insertConstraints_satisfiable` shows the
    system is not vacuous.

  * **What the proof needed beyond a single leaf's gap.** Plain
    gap-emptiness is NOT inductive: two occupied leaves with equal keys
    would leave a stale gap that re-admits an inserted key. The
    invariant therefore also carries key-injectivity (`Inv.inj`); both
    parts are established at genesis and preserved.

  * **Remaining modeling boundaries (named, not hidden):**
      1. *Root ↔ map*: `lowIncl`/`emptySlot`/`post` are the map-level
         shadows of the root-level `verify`/`get_root` calls, valid
         under collision resistance of the fold compression
         (`Merkle.CompressCR`, with `Bytes.PoseidonCR` for leaf
         hashing) plus the shared-path structure of each proof object
         (which itself relies on `Merkle.PowTwoInj F 32` — see
         Core/Merkle.lean header). The root-level statement is the
         named Prop `Circuits.UpdatePrivateState.NullifierRootBinding`,
         consumed by `nullifierInsert_reachable_chain`.
      2. *keyRange*: the ≤ MAX bound is the U256 limb-range fact; it is
         emitted only when targets are built with `is_checked = true`,
         which both production balance circuits do
         (receive_transfer_circuit.rs:396, receive_deposit_circuit.rs:289).
      3. *Reachability of on-chain roots*: `reachable_key_absent`
         covers every tree reachable through this gadget from genesis;
         that the balance IVC chain only ever feeds such roots into
         `UpdatePrivateState` is the (separate) IVC-binding argument —
         see Circuits/Balance/Common/UpdatePrivateState.lean.

  * **Strictness dependency confirmed:** `is_lt` = `is_le ∧ ¬is_eq`
    (the and-composition at u256.rs:353-356), so `key = low.key` / `key = low.next_key` are
    rejected; a non-strict comparison would re-open duplicates.
-/

end IndexedMerkle
end Zkp
