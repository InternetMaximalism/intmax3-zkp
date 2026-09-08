import Std

/-!
# IndexedMerkleTree: the ordered-set structure behind nullifier insertion

Handwritten semantic model of the indexed Merkle tree used for the nullifier
tree and the account tree:

* `src/utils/trees/indexed_merkle_tree/mod.rs`       (109 lines)
* `src/utils/trees/indexed_merkle_tree/leaf.rs`      (159 lines)
* `src/utils/trees/indexed_merkle_tree/insertion.rs` (559 lines)

This is NOT a refinement proof of the Rust / plonky2 code. Every theorem below
is a theorem about the Lean model; the source-to-model correspondence is a
line-map claim only.

## Why this file exists

Every balance / claim circuit model in this audit treats "insert this nullifier"
as an opaque callback and lists *nullifier freshness / no double spend* as an
undischarged boundary. The structural half of that obligation lives here: the
indexed Merkle tree is an ORDERED SET, and the two bound checks performed by
`IndexedInsertionProof::get_new_root` are unsatisfiable for a key that is
already a leaf of the tree the proof opens against.

## The three objects, deliberately kept apart

* NATIVE tree operations (`Tree`, `lowIndex`, `insert`, `update`,
  `proveAndInsert`, `proveDummy`) — the Rust witness builder. These are
  executable `Except` functions mirroring the source's control flow, error
  values and error precedence.
* NATIVE proof checking (`getNewRoot`, `conditionalGetNewRoot`,
  `verifyInsertion`) — `impl IndexedInsertionProof`, again as `Except`.
* ARBITRARY satisfying witnesses (`Gates`) — the constraints
  `IndexedInsertionProofTarget::get_new_root` lays on a witness it did not
  build. `Gates` has no error ordering, no `index = tree size` constraint and
  no constraint on `value`; a theorem about the native path never silently
  covers `Gates` (`native_get_new_root_ok_implies_gates` is the only bridge,
  and it points one way).

## What is opaque here

Poseidon and the incremental Merkle tree are NOT modelled. They enter as a
`Commitment Hash` record of callbacks (`leafHash`, `rootFrom`, `root`, `path`)
plus two named premise bundles:

* `CommitmentLaws` — the three equations an honest incremental Merkle tree
  satisfies (`open_set`, `path_stable`, `extend_empty`). Used only to show the
  NATIVE proof produced by `proveAndInsert` is accepted.
* `Binding` — "a sibling list that opens leaf `L` at index `i` to `root t` forces
  `L = t.getLeaf i`". This is collision resistance of Poseidon plus injectivity
  of the leaf word encoding. It is an assumption, never proved here; the
  encoding half of it IS proved (`leaf_words_injective`), so what remains is a
  genuine Poseidon collision.

Both bundles are shown to be simultaneously satisfiable by the `transparent`
commitment (`transparent_laws`, `transparent_binding_of_wf`), so no theorem
below is vacuous.

## Which half of "no double spend" is discharged here

Discharged by the ORDERED-SET STRUCTURE ALONE, no hash assumption:
`present_key_has_no_low_candidate` / `insert_present_key_fails` — on a
well-formed tree, a key that is already a leaf has NO predecessor candidate, so
the native builder cannot even construct an insertion, and no leaf of the tree
satisfies the two bound checks for that key. `wf_insert` shows the ordered-set
invariant survives an insertion, so the argument composes over a chain of
insertions; `wf_new` starts the chain.

NOT discharged here, and needing hash collision resistance:
`accepted_insertion_implies_key_absent` and `gates_imply_key_absent` assume
`Binding C t`. Without it an adversarial witness may present a `prev_low_leaf`
that is not a leaf of the tree at all; the bound checks then say nothing about
the tree. Poseidon collision resistance is exactly what rules that out.

NOT discharged here at all, and outside these three files: that the `prev_root`
fed to the proof really is the current nullifier-tree root (state chaining), and
that the same nullifier key is derived from the spend being authorised. Those
are consumer obligations of the balance / claim circuits.

## BAL-CRIT-001 (empty slot vs sentinel)

`Leafable::empty_leaf` for `IndexedMerkleLeaf` is `key = U256::MAX`, deliberately
NOT `default()`. `getLeaf` of an out-of-range index returns `empty_leaf`
(`IncrementalMerkleTree::get_leaf`), so an adversary who points `low_leaf_index`
at an unoccupied slot gets a low leaf whose key is `U256::MAX`, and the lower
bound check `prev_low_leaf.key < key` then fails for every in-range key:
`empty_leaf_blocks_pseudo_sentinel`. Had `empty_leaf` been `default()`, the two
bound checks would pass for EVERY nonzero key:
`default_low_leaf_would_accept_any_nonzero_key` states that counterfactual
explicitly. This is the exploited path of `tests/nullifier_duplicate_insertion_poc.rs`,
and the case split for it is the second half of
`accepted_insertion_implies_key_absent`.

## Named boundaries (also in the line maps)

`leafHash` (Poseidon over the 18 leaf words), `rootFrom` / `root` / `path`
(incremental Merkle tree path fold, `merkle_tree.rs`, out of scope),
`CommitmentLaws` (honesty of that tree), `Binding` (Poseidon collision
resistance), `pushCapacityAssert` (`IncrementalMerkleTree::push` aborts the
process when the tree is full; modelled as the `size < capacity` hypothesis and
the `Wf.capacity` field, never as an error value), `u256RangeInvariant` (Rust's
`U256` type guarantees `key < 2 ^ 256`; in the model this is an explicit
hypothesis), `plonky2Lowering` (`is_lt` / `is_zero` / `assert_one` /
`conditional_assert_eq` / `select` gadget lowering and the builder plumbing),
`serdeRoundTrip` (`Serialize`/`Deserialize` derives).

## Untranslated on purpose

All `*Target` builder plumbing (`new`, `constant`, `set_witness`, `to_vec`),
the plonky2 witness generators, and the `#[cfg(test)]` module of
`insertion.rs`.
-/

namespace Zkp.Implementation.IndexedMerkleTree

/-! ## Constants pinned from the source -/

/-- `U32LimbTrait` limb base: `to_u32_vec` limbs are `u32`. -/
def wordBase : Nat := 2 ^ 32

/-- `U256` has 8 `u32` limbs. -/
def limbCount : Nat := 8

/-- Exclusive upper bound of the `U256` key space. -/
def keyBound : Nat := 2 ^ 256

/-- `U256::MAX`, the key of `empty_leaf` (leaf.rs 71). -/
def maxKey : Nat := 2 ^ 256 - 1

/-- `u64::MAX`, the `next_index` of `empty_leaf` (leaf.rs 70). -/
def u64Max : Nat := 2 ^ 64 - 1

theorem word_base_pinned : wordBase = 4294967296 := by decide

theorem limb_count_pinned : limbCount = 8 := rfl

theorem u256_width_is_exact : wordBase ^ limbCount = keyBound := by decide

theorem max_key_is_key_bound_pred : maxKey + 1 = keyBound := by decide

theorem max_key_ne_zero : maxKey ≠ 0 := by decide

theorem in_range_key_le_max_key {k : Nat} (h : k < keyBound) : k ≤ maxKey := by
  have : maxKey + 1 = keyBound := max_key_is_key_bound_pred
  omega

/-! ## Leaves (leaf.rs 28-33) -/

/-- `IndexedMerkleLeaf { next_index: u64, key: U256, next_key: U256, value: u64 }`.
Field ranges (`u64`, `U256`) are Rust type invariants, not modelled as
refinements; where a bound is needed it appears as an explicit hypothesis. -/
structure Leaf where
  nextIndex : Nat := 0
  key : Nat := 0
  nextKey : Nat := 0
  value : Nat := 0
  deriving Repr, DecidableEq, Inhabited

/-- `IndexedMerkleLeaf::default()` — the sentinel pushed at index 0 by
`IndexedMerkleTree::new` (mod.rs 28). All zeros. -/
def defaultLeaf : Leaf := {}

/-- `<IndexedMerkleLeaf as Leafable>::empty_leaf()` (leaf.rs 68-75): the leaf
every UNOCCUPIED tree slot holds. `key = U256::MAX` is the BAL-CRIT-001 fix. -/
def emptyLeaf : Leaf := { nextIndex := u64Max, key := maxKey, nextKey := 0, value := 0 }

theorem default_leaf_pinned :
    defaultLeaf.nextIndex = 0 ∧ defaultLeaf.key = 0 ∧
      defaultLeaf.nextKey = 0 ∧ defaultLeaf.value = 0 := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem empty_leaf_pinned :
    emptyLeaf.nextIndex = u64Max ∧ emptyLeaf.key = maxKey ∧
      emptyLeaf.nextKey = 0 ∧ emptyLeaf.value = 0 := by
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- The BAL-CRIT-001 separation: an unoccupied slot is NOT the sentinel. -/
theorem empty_leaf_ne_default_leaf : emptyLeaf ≠ defaultLeaf := by
  intro h
  have : maxKey = 0 := congrArg Leaf.key h
  exact max_key_ne_zero this

/-! ## Leaf word encoding (leaf.rs 36-43, 77-79)

`to_u64_vec` is `[next_index] ++ key.to_u32_vec() ++ next_key.to_u32_vec() ++
[value]`, big-endian limbs widened to `u64`; `hash` is Poseidon over that
vector. The hash itself is opaque (`Commitment.leafHash`); what is proved here
is that the WORD ENCODING is injective on in-range leaves, so a leaf-hash
collision is a genuine Poseidon collision rather than an encoding ambiguity. -/

/-- Big-endian base-`wordBase` limbs, `k` of them. -/
def limbsBE : Nat → Nat → List Nat
  | 0, _ => []
  | k + 1, n => limbsBE k (n / wordBase) ++ [n % wordBase]

/-- `U256::to_u32_vec` widened to `u64`. -/
def keyWords (n : Nat) : List Nat := limbsBE limbCount n

/-- `IndexedMerkleLeaf::to_u64_vec` (leaf.rs 36-43). -/
def leafWords (L : Leaf) : List Nat :=
  L.nextIndex :: (keyWords L.key ++ (keyWords L.nextKey ++ [L.value]))

/-- Big-endian recomposition, the left inverse of `limbsBE`. -/
def valueBE (xs : List Nat) : Nat := xs.foldl (fun acc d => acc * wordBase + d) 0

theorem limbs_be_length (k n : Nat) : (limbsBE k n).length = k := by
  induction k generalizing n with
  | zero => rfl
  | succ k ih => simp [limbsBE, ih]

theorem key_words_length (n : Nat) : (keyWords n).length = 8 := by
  simp [keyWords, limbs_be_length, limbCount]

theorem leaf_words_length (L : Leaf) : (leafWords L).length = 18 := by
  simp [leafWords, key_words_length]

theorem value_be_snoc (xs : List Nat) (d : Nat) :
    valueBE (xs ++ [d]) = valueBE xs * wordBase + d := by
  simp [valueBE, List.foldl_append]

theorem value_be_limbs_be {k n : Nat} (h : n < wordBase ^ k) : valueBE (limbsBE k n) = n := by
  induction k generalizing n with
  | zero =>
    have : n < 1 := by simpa using h
    simp [limbsBE, valueBE]
    omega
  | succ k ih =>
    have hb : 0 < wordBase := by decide
    have hlt : n / wordBase < wordBase ^ k := by
      rw [Nat.div_lt_iff_lt_mul hb]
      simpa [Nat.pow_succ] using h
    rw [limbsBE, value_be_snoc, ih hlt]
    simpa [Nat.mul_comm] using Nat.div_add_mod n wordBase

theorem value_be_key_words {n : Nat} (h : n < keyBound) : valueBE (keyWords n) = n := by
  refine value_be_limbs_be ?_
  rw [u256_width_is_exact]
  exact h

/-- The `U256` limb encoding is injective on the `U256` range. -/
theorem key_words_injective {a b : Nat} (ha : a < keyBound) (hb : b < keyBound)
    (h : keyWords a = keyWords b) : a = b := by
  have := congrArg valueBE h
  rwa [value_be_key_words ha, value_be_key_words hb] at this

/-- The hashed leaf word vector determines the leaf, for leaves whose `U256`
fields are in range. Hence the only way two distinct leaves can share a leaf
hash is a Poseidon collision. -/
theorem leaf_words_injective {L M : Leaf}
    (hLk : L.key < keyBound) (hLn : L.nextKey < keyBound)
    (hMk : M.key < keyBound) (hMn : M.nextKey < keyBound)
    (h : leafWords L = leafWords M) : L = M := by
  have hcons := h
  simp only [leafWords, List.cons.injEq] at hcons
  obtain ⟨hidx, htail⟩ := hcons
  have hlen : (keyWords L.key).length = (keyWords M.key).length := by
    rw [key_words_length, key_words_length]
  obtain ⟨hk, htail2⟩ := List.append_inj htail hlen
  have hlen2 : (keyWords L.nextKey).length = (keyWords M.nextKey).length := by
    rw [key_words_length, key_words_length]
  obtain ⟨hnk, hval⟩ := List.append_inj htail2 hlen2
  have hkey : L.key = M.key := key_words_injective hLk hMk hk
  have hnext : L.nextKey = M.nextKey := key_words_injective hLn hMn hnk
  have hv : L.value = M.value := by
    simpa using hval
  cases L; cases M
  simp_all

/-! ## Errors (`IndexedMerkleTreeError`, src/utils/trees/error.rs 17-44)

Error payloads are the values that go into the source's format strings, so that
error PRECEDENCE and error IDENTITY are both visible in the model. -/

inductive Error where
  | keyAlreadyExists (key : Nat)
  | keyDoesNotExist (key : Nat)
  | keyNotLowerBounded (key lowKey : Nat)
  | keyNotUpperBounded (key nextKey : Nat)
  | newRootMismatch
  | tooManyCandidates (site : String)
  | merkleProofError
  deriving Repr, DecidableEq

/-! ## The tree (mod.rs 21-30, over `IncrementalMerkleTree`)

`IndexedMerkleTree(IncrementalMerkleTree<IndexedMerkleLeaf>)`: an occupied
prefix `leaves` inside a fixed-height array of `2 ^ height` slots. Merkle
hashing is NOT part of this record; it enters through `Commitment` below. -/

structure Tree where
  height : Nat
  leaves : List Leaf
  deriving Repr

/-- Number of occupied slots (`IncrementalMerkleTree::len`, mod.rs 102-104). -/
def Tree.size (t : Tree) : Nat := t.leaves.length

/-- `2 ^ height`, the `assert!` bound of `IncrementalMerkleTree::push`. -/
def Tree.capacity (t : Tree) : Nat := 2 ^ t.height

/-- `IncrementalMerkleTree::get_leaf`: OUT-OF-RANGE INDICES RETURN `empty_leaf`,
not an error. This is the BAL-CRIT-001 surface. -/
def Tree.getLeaf (t : Tree) (i : Nat) : Leaf := (t.leaves[i]?).getD emptyLeaf

/-- `IncrementalMerkleTree::update` (`i < size`) and `::push` (`i = size`) in one
operation; a write past the end is a no-op here (the source would abort). -/
def Tree.setLeaf (t : Tree) (i : Nat) (L : Leaf) : Tree :=
  if i < t.leaves.length then { t with leaves := t.leaves.set i L }
  else if i = t.leaves.length then { t with leaves := t.leaves ++ [L] }
  else t

/-- `IndexedMerkleTree::new` (mod.rs 26-30): an empty incremental tree with the
all-zero SENTINEL leaf pushed at index 0. -/
def Tree.new (height : Nat) : Tree := { height := height, leaves := [defaultLeaf] }

theorem tree_new_size (h : Nat) : (Tree.new h).size = 1 := rfl

theorem tree_new_leaf_zero (h : Nat) : (Tree.new h).getLeaf 0 = defaultLeaf := by
  simp [Tree.new, Tree.getLeaf]

theorem get_leaf_of_ge {t : Tree} {i : Nat} (h : t.size ≤ i) : t.getLeaf i = emptyLeaf := by
  simp [Tree.getLeaf, List.getElem?_eq_none h]

theorem get_leaf_of_lt {t : Tree} {i : Nat} (h : i < t.size) :
    t.getLeaf i = t.leaves[i]'h := by
  simp [Tree.getLeaf, List.getElem?_eq_getElem h]

theorem set_leaf_size {t : Tree} {i : Nat} {L : Leaf} (h : i < t.size) :
    (t.setLeaf i L).size = t.size := by
  simp [Tree.setLeaf, Tree.size] at h ⊢
  simp [h]

theorem push_size {t : Tree} {L : Leaf} :
    (t.setLeaf t.size L).size = t.size + 1 := by
  simp [Tree.setLeaf, Tree.size]

theorem set_leaf_height {t : Tree} {i : Nat} {L : Leaf} :
    (t.setLeaf i L).height = t.height := by
  unfold Tree.setLeaf
  split
  · rfl
  · split <;> rfl

theorem get_elem_snoc {α : Type} (l : List α) (a : α) (j : Nat) :
    (l ++ [a])[j]? = if j = l.length then some a else l[j]? := by
  rcases Nat.lt_trichotomy j l.length with hj | hj | hj
  · rw [List.getElem?_append hj, if_neg (by omega)]
  · subst hj
    rw [List.getElem?_append_right (Nat.le_refl _), if_pos rfl]
    simp
  · have h1 : [a].length ≤ j - l.length := by simp; omega
    rw [List.getElem?_append_right (by omega), if_neg (by omega),
      List.getElem?_eq_none h1, List.getElem?_eq_none (by omega)]

/-- Reading back a write: the model's single structural lemma about slots. -/
theorem get_leaf_set_leaf {t : Tree} {i j : Nat} {L : Leaf} (h : i ≤ t.size) :
    (t.setLeaf i L).getLeaf j = if j = i then L else t.getLeaf j := by
  rcases Nat.lt_or_ge i t.size with hlt | hge
  · have hlt' : i < t.leaves.length := hlt
    simp only [Tree.setLeaf, if_pos hlt', Tree.getLeaf]
    rw [List.getElem?_set]
    by_cases hij : i = j
    · subst hij; simp [hlt']
    · simp [hij, Ne.symm hij]
  · have hi : i = t.size := Nat.le_antisymm h hge
    subst hi
    have hnl : ¬ (t.size < t.leaves.length) := Nat.lt_irrefl _
    have hpos : t.size = t.leaves.length := rfl
    have heq : (t.setLeaf t.size L).leaves = t.leaves ++ [L] := by
      unfold Tree.setLeaf
      rw [if_neg hnl, if_pos hpos]
    show (t.setLeaf t.size L).leaves[j]?.getD emptyLeaf = _
    rw [heq, get_elem_snoc]
    by_cases hj : j = t.leaves.length
    · rw [if_pos hj, if_pos (show j = t.size from hj)]; rfl
    · rw [if_neg hj, if_neg (show ¬ (j = t.size) from hj)]; rfl

theorem set_leaf_self {t : Tree} {i : Nat} (h : i < t.size) :
    t.setLeaf i (t.getLeaf i) = t := by
  have hlt : i < t.leaves.length := h
  simp only [Tree.setLeaf, if_pos hlt]
  have hset : t.leaves.set i (t.getLeaf i) = t.leaves := by
    apply List.ext_getElem?
    intro n
    rw [List.getElem?_set]
    by_cases hin : i = n
    · subst hin
      rw [if_pos rfl, if_pos hlt, get_leaf_of_lt h, List.getElem?_eq_getElem hlt]
    · rw [if_neg hin]
  rw [hset]

/-! ## Key membership and the ordered-set invariant -/

/-- `key` occupies some slot of the tree. This is the "modelled set". -/
def MemKey (t : Tree) (k : Nat) : Prop := ∃ i, i < t.size ∧ (t.getLeaf i).key = k

/-- `IndexedMerkleTree::leaves().map(|l| l.key)`. -/
def keysOf (t : Tree) : List Nat := t.leaves.map (fun L => L.key)

theorem mem_key_iff_mem_keys_of {t : Tree} {k : Nat} : MemKey t k ↔ k ∈ keysOf t := by
  constructor
  · rintro ⟨i, hi, hk⟩
    rw [get_leaf_of_lt hi] at hk
    exact hk ▸ List.mem_map_of_mem _ (List.getElem_mem _ _ hi)
  · intro h
    obtain ⟨L, hL, hk⟩ := List.mem_map.1 h
    obtain ⟨i, hi, hget⟩ := List.mem_iff_getElem.1 hL
    exact ⟨i, hi, by rw [get_leaf_of_lt hi, hget]; exact hk⟩

/-- The ordered-set invariant of an indexed Merkle tree.

`dense` is the load-bearing field: between a leaf and any strictly larger key in
the tree there is no room, i.e. the `next_key` chain has no gaps. It is what
turns "a predecessor candidate exists" into "the key is absent". -/
structure Wf (t : Tree) : Prop where
  /-- The sentinel slot exists. -/
  size_pos : 0 < t.size
  /-- Slot 0 holds the all-zero sentinel key (`IndexedMerkleTree::new`). -/
  sentinel : (t.getLeaf 0).key = 0
  /-- `U256` range invariant of the Rust types. -/
  in_range : ∀ i, i < t.size → (t.getLeaf i).key < keyBound ∧ (t.getLeaf i).nextKey < keyBound
  /-- Keys are unique: the tree really is a SET. -/
  distinct : ∀ i j, i < t.size → j < t.size → (t.getLeaf i).key = (t.getLeaf j).key → i = j
  /-- A non-sentinel successor is strictly above. -/
  succ_gt : ∀ i, i < t.size → (t.getLeaf i).nextKey ≠ 0 →
    (t.getLeaf i).key < (t.getLeaf i).nextKey
  /-- A non-sentinel successor is itself present. -/
  succ_mem : ∀ i, i < t.size → (t.getLeaf i).nextKey ≠ 0 → MemKey t (t.getLeaf i).nextKey
  /-- No gaps: if some key sits above leaf `i`, then `i`'s successor pointer is
  live and does not overshoot it. -/
  dense : ∀ i j, i < t.size → j < t.size → (t.getLeaf i).key < (t.getLeaf j).key →
    (t.getLeaf i).nextKey ≠ 0 ∧ (t.getLeaf i).nextKey ≤ (t.getLeaf j).key
  /-- `IncrementalMerkleTree::push`'s `assert!` has never fired. -/
  capacity : t.size ≤ t.capacity

theorem wf_new (h : Nat) : Wf (Tree.new h) := by
  have hsize : (Tree.new h).size = 1 := rfl
  have hleaf : ∀ i, i < (Tree.new h).size → (Tree.new h).getLeaf i = defaultLeaf := by
    intro i hi
    rw [hsize] at hi
    have : i = 0 := by omega
    subst this
    exact tree_new_leaf_zero h
  refine ⟨by omega, by rw [tree_new_leaf_zero]; rfl, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro i hi; rw [hleaf i hi]; exact ⟨by decide, by decide⟩
  · intro i j hi hj _; rw [hsize] at hi hj; omega
  · intro i hi hne; rw [hleaf i hi] at hne; exact absurd rfl hne
  · intro i hi hne; rw [hleaf i hi] at hne; exact absurd rfl hne
  · intro i j hi hj hlt; rw [hleaf i hi, hleaf j hj] at hlt; exact absurd hlt (by decide)
  · rw [hsize]
    show 1 ≤ 2 ^ h
    exact Nat.one_le_two_pow

/-- The freshly created tree is exactly the singleton set `{0}`. -/
theorem new_tree_key_set (h : Nat) (k : Nat) : MemKey (Tree.new h) k ↔ k = 0 := by
  constructor
  · rintro ⟨i, hi, hk⟩
    have hi1 : i < 1 := hi
    have : i = 0 := by omega
    subst this
    rw [tree_new_leaf_zero] at hk
    exact hk.symm ▸ rfl
  · intro hk
    refine ⟨0, ?_, ?_⟩
    · rw [tree_new_size]; omega
    · rw [tree_new_leaf_zero]; exact hk.symm ▸ rfl

/-! ## Index lists and the candidate filter

`.leaves().into_iter().enumerate().filter(..)` in mod.rs is modelled as a filter
over the ascending index list. `List.range` has no lemmas in this toolchain, so
the index list and its three lemmas are local. -/

def indices : Nat → List Nat
  | 0 => []
  | n + 1 => indices n ++ [n]

theorem mem_indices {i n : Nat} : i ∈ indices n ↔ i < n := by
  induction n with
  | zero => simp [indices]
  | succ m ih => simp [indices, ih]; omega

theorem filter_indices_eq_nil {p : Nat → Bool} {n : Nat} (h : ∀ i, i < n → p i = false) :
    (indices n).filter p = [] := by
  rw [List.filter_eq_nil]
  intro a ha
  rw [mem_indices] at ha
  simp [h a ha]

theorem filter_indices_unique {p : Nat → Bool} {n i : Nat} (hi : i < n) (hp : p i = true)
    (hu : ∀ j, j < n → p j = true → j = i) : (indices n).filter p = [i] := by
  induction n with
  | zero => omega
  | succ m ih =>
    rw [indices, List.filter_append]
    by_cases him : i = m
    · subst him
      have h0 : (indices i).filter p = [] := by
        refine filter_indices_eq_nil ?_
        intro j _hj
        cases hpj : p j with
        | false => rfl
        | true => exact absurd (hu j (by omega) hpj) (by omega)
      rw [h0, List.filter_cons_of_pos _ hp]
      rfl
    · have him' : i < m := by omega
      have hm : p m = false := by
        cases hpm : p m with
        | false => rfl
        | true => exact absurd (hu m (by omega) hpm) (by omega)
      rw [ih him' (fun j hj hpj => hu j (by omega) hpj),
        List.filter_cons_of_neg _ (by simp [hm])]
      rfl

/-! ## Predecessor search (`IndexedMerkleTree::low_index`, mod.rs 44-64) -/

/-- The `low_index` filter predicate: `leaf.key < key && (key < leaf.next_key ||
leaf.next_key == U256::default())`. -/
def isLowLeaf (key : Nat) (L : Leaf) : Bool :=
  (L.key < key) && ((key < L.nextKey) || (L.nextKey == 0))

theorem is_low_leaf_iff {key : Nat} {L : Leaf} :
    isLowLeaf key L = true ↔ L.key < key ∧ (key < L.nextKey ∨ L.nextKey = 0) := by
  simp [isLowLeaf]

def lowCandidates (t : Tree) (key : Nat) : List Nat :=
  (indices t.size).filter (fun i => isLowLeaf key (t.getLeaf i))

/-- `low_index`: empty candidate set is reported as `KeyAlreadyExists`, more than
one candidate as `TooManyCandidates("low_index")`. -/
def lowIndex (t : Tree) (key : Nat) : Except Error Nat :=
  match lowCandidates t key with
  | [] => .error (.keyAlreadyExists key)
  | [i] => .ok i
  | _ => .error (.tooManyCandidates "low_index")

theorem low_index_ok_iff {t : Tree} {key i : Nat} :
    lowIndex t key = .ok i ↔ lowCandidates t key = [i] := by
  unfold lowIndex
  cases h : lowCandidates t key with
  | nil => simp
  | cons a as =>
    cases as with
    | nil => simp [eq_comm]
    | cons b bs => simp

theorem low_index_lt {t : Tree} {key i : Nat} (h : lowIndex t key = .ok i) : i < t.size := by
  have hc : lowCandidates t key = [i] := low_index_ok_iff.1 h
  have : i ∈ lowCandidates t key := by rw [hc]; simp
  rw [lowCandidates, List.mem_filter, mem_indices] at this
  exact this.1

theorem low_index_is_low {t : Tree} {key i : Nat} (h : lowIndex t key = .ok i) :
    isLowLeaf key (t.getLeaf i) = true := by
  have hc : lowCandidates t key = [i] := low_index_ok_iff.1 h
  have : i ∈ lowCandidates t key := by rw [hc]; simp
  rw [lowCandidates, List.mem_filter] at this
  exact this.2

theorem low_index_unique {t : Tree} {key i : Nat} (h : lowIndex t key = .ok i) :
    ∀ j, j < t.size → isLowLeaf key (t.getLeaf j) = true → j = i := by
  intro j hj hp
  have hc : lowCandidates t key = [i] := low_index_ok_iff.1 h
  have hmem : j ∈ lowCandidates t key := by
    rw [lowCandidates, List.mem_filter, mem_indices]
    exact ⟨hj, hp⟩
  rw [hc] at hmem
  simpa using hmem

/-- ORDERED-SET SOUNDNESS, hash-free half: on a well-formed tree a key that is
already present has NO predecessor candidate. `dense` is what rules out a
candidate below the present key. -/
theorem present_key_has_no_low_candidate {t : Tree} {key : Nat} (hw : Wf t)
    (h : MemKey t key) : lowCandidates t key = [] := by
  obtain ⟨m, hm, hkm⟩ := h
  refine filter_indices_eq_nil ?_
  intro i hi
  cases hp : isLowLeaf key (t.getLeaf i) with
  | false => rfl
  | true =>
    exfalso
    obtain ⟨hlt, hup⟩ := is_low_leaf_iff.1 hp
    have hlt' : (t.getLeaf i).key < (t.getLeaf m).key := by rw [hkm]; exact hlt
    obtain ⟨hne, hle⟩ := hw.dense i m hi hm hlt'
    rw [hkm] at hle
    rcases hup with hup | hup
    · omega
    · exact hne hup

/-- No candidate below a present key means the tree's OWN leaves cannot witness
the two bound checks for that key. -/
theorem present_key_has_no_bounding_leaf {t : Tree} {key : Nat} (hw : Wf t)
    (h : MemKey t key) :
    ∀ i, i < t.size → ¬ ((t.getLeaf i).key < key ∧
      (key < (t.getLeaf i).nextKey ∨ (t.getLeaf i).nextKey = 0)) := by
  intro i hi hbad
  have hnil := present_key_has_no_low_candidate hw h
  have hmem : i ∈ lowCandidates t key := by
    rw [lowCandidates, List.mem_filter, mem_indices]
    exact ⟨hi, is_low_leaf_iff.2 hbad⟩
  rw [hnil] at hmem
  simp at hmem

/-! ## Native insertion (insertion.rs 52-70) and the other `mod.rs` writers -/

/-- `IndexedMerkleLeaf { next_index: index, next_key: key, ..prev_low_leaf }`. -/
def newLowLeaf (prevLow : Leaf) (index key : Nat) : Leaf :=
  { prevLow with nextIndex := index, nextKey := key }

/-- The appended leaf `IndexedMerkleLeaf { next_index: prev_low_leaf.next_index,
key, next_key: prev_low_leaf.next_key, value }`. -/
def insertedLeaf (prevLow : Leaf) (key value : Nat) : Leaf :=
  { nextIndex := prevLow.nextIndex, key := key, nextKey := prevLow.nextKey, value := value }

theorem new_low_leaf_key (prevLow : Leaf) (index key : Nat) :
    (newLowLeaf prevLow index key).key = prevLow.key := rfl

theorem new_low_leaf_next_key (prevLow : Leaf) (index key : Nat) :
    (newLowLeaf prevLow index key).nextKey = key := rfl

theorem new_low_leaf_next_index (prevLow : Leaf) (index key : Nat) :
    (newLowLeaf prevLow index key).nextIndex = index := rfl

theorem inserted_leaf_key (prevLow : Leaf) (key value : Nat) :
    (insertedLeaf prevLow key value).key = key := rfl

theorem inserted_leaf_next_key (prevLow : Leaf) (key value : Nat) :
    (insertedLeaf prevLow key value).nextKey = prevLow.nextKey := rfl

theorem inserted_leaf_next_index (prevLow : Leaf) (key value : Nat) :
    (insertedLeaf prevLow key value).nextIndex = prevLow.nextIndex := rfl

/-- The tree after `update(low, new_low_leaf); push(leaf)`. -/
def insertResult (t : Tree) (low key value : Nat) : Tree :=
  (t.setLeaf low (newLowLeaf (t.getLeaf low) t.size key)).setLeaf t.size
    (insertedLeaf (t.getLeaf low) key value)

/-- `IndexedMerkleTree::insert`. The capacity `assert!` of
`IncrementalMerkleTree::push` is NOT modelled as an error (see header). -/
def insert (t : Tree) (key value : Nat) : Except Error Tree := do
  let low ← lowIndex t key
  return insertResult t low key value

/-- `IndexedMerkleTree::index` (mod.rs 66-82). The source PANICS on more than
one candidate; the panic is modelled as an error value, not as an `Option`. -/
def indexOfKey (t : Tree) (key : Nat) : Except Error (Option Nat) :=
  match (indices t.size).filter (fun i => (t.getLeaf i).key == key) with
  | [] => .ok none
  | [i] => .ok (some i)
  | _ => .error (.tooManyCandidates "index")

/-- `IndexedMerkleTree::update` (mod.rs 88-96): value-only write on an existing
key; it never touches `key`, `next_key` or `next_index`. -/
def update (t : Tree) (key value : Nat) : Except Error Tree := do
  match ← indexOfKey t key with
  | none => .error (.keyDoesNotExist key)
  | some i => .ok (t.setLeaf i { t.getLeaf i with value := value })

theorem index_of_key_ok_some {t : Tree} {key i : Nat} (h : indexOfKey t key = .ok (some i)) :
    i < t.size ∧ (t.getLeaf i).key = key := by
  unfold indexOfKey at h
  split at h
  · simp at h
  · rename_i j heq
    have hmem : j ∈ (indices t.size).filter (fun m => (t.getLeaf m).key == key) := by
      rw [heq]; simp
    rw [List.mem_filter, mem_indices] at hmem
    simp only [Except.ok.injEq, Option.some.injEq] at h
    subst h
    exact ⟨hmem.1, by simpa using hmem.2⟩
  · simp at h

/-- Two trees with the same occupancy and the same key at every slot carry the
same modelled set. -/
theorem mem_key_congr {t t' : Tree} (hsize : t'.size = t.size)
    (hkeys : ∀ j, j < t.size → (t'.getLeaf j).key = (t.getLeaf j).key) (k : Nat) :
    MemKey t' k ↔ MemKey t k := by
  constructor
  · rintro ⟨i, hi, hk⟩
    rw [hsize] at hi
    exact ⟨i, hi, by rw [← hkeys i hi]; exact hk⟩
  · rintro ⟨i, hi, hk⟩
    exact ⟨i, by omega, by rw [hkeys i hi]; exact hk⟩

/-- `update` is a value-only write: it changes no key, so the modelled SET is
untouched (only the per-leaf payload moves). -/
theorem update_preserves_key_set {t t' : Tree} {key value : Nat}
    (h : update t key value = .ok t') (k : Nat) : MemKey t' k ↔ MemKey t k := by
  unfold update at h
  cases hidx : indexOfKey t key with
  | error e => rw [hidx] at h; simp [bind, Except.bind] at h
  | ok o =>
    rw [hidx] at h
    cases o with
    | none => simp [bind, Except.bind] at h
    | some i =>
      have hi := (index_of_key_ok_some hidx).1
      simp only [bind, Except.bind, Except.ok.injEq] at h
      subst h
      refine mem_key_congr (set_leaf_size hi) ?_ k
      intro j _hj
      rw [get_leaf_set_leaf (Nat.le_of_lt hi)]
      by_cases hji : j = i
      · rw [if_pos hji, hji]
      · rw [if_neg hji]

/-! ## Structure of the tree after a native insertion -/

theorem insert_ok_iff {t t' : Tree} {key value : Nat} :
    insert t key value = .ok t' ↔ ∃ low, lowIndex t key = .ok low ∧ t' = insertResult t low key value := by
  unfold insert
  cases h : lowIndex t key with
  | error e => simp [h, bind, Except.bind]
  | ok low =>
    simp only [h, bind, Except.bind, pure]
    constructor
    · intro hh; exact ⟨low, rfl, by injection hh with hh; exact hh.symm⟩
    · rintro ⟨l, hl, rfl⟩
      injection hl with hl
      subst hl
      rfl

theorem push_size_of_eq {t : Tree} {i : Nat} {L : Leaf} (h : i = t.size) :
    (t.setLeaf i L).size = t.size + 1 := by
  subst h; exact push_size

theorem insert_result_size {t : Tree} {low key value : Nat} (hlow : low < t.size) :
    (insertResult t low key value).size = t.size + 1 := by
  unfold insertResult
  have h1 : (t.setLeaf low (newLowLeaf (t.getLeaf low) t.size key)).size = t.size :=
    set_leaf_size hlow
  have h2 := push_size_of_eq (t := t.setLeaf low (newLowLeaf (t.getLeaf low) t.size key))
    (i := t.size) (L := insertedLeaf (t.getLeaf low) key value) h1.symm
  rw [h2, h1]

theorem insert_result_get {t : Tree} {low key value : Nat} (hlow : low < t.size) (j : Nat) :
    (insertResult t low key value).getLeaf j =
      if j = t.size then insertedLeaf (t.getLeaf low) key value
      else if j = low then newLowLeaf (t.getLeaf low) t.size key
      else t.getLeaf j := by
  unfold insertResult
  rw [get_leaf_set_leaf (Nat.le_of_eq (set_leaf_size hlow).symm)]
  by_cases hj : j = t.size
  · rw [if_pos hj, if_pos hj]
  · rw [if_neg hj, if_neg hj, get_leaf_set_leaf (Nat.le_of_lt hlow)]

theorem insert_result_height {t : Tree} {low key value : Nat} :
    (insertResult t low key value).height = t.height := by
  unfold insertResult
  rw [set_leaf_height, set_leaf_height]

/-- Old slots keep their keys: an insertion only ever rewrites the low leaf's
`next_index` / `next_key`, never any key. -/
theorem insert_result_old_key {t : Tree} {low key value j : Nat} (hlow : low < t.size)
    (hj : j < t.size) :
    ((insertResult t low key value).getLeaf j).key = (t.getLeaf j).key := by
  rw [insert_result_get hlow, if_neg (by omega)]
  by_cases hjl : j = low
  · rw [if_pos hjl, hjl]; rfl
  · rw [if_neg hjl]

theorem insert_result_new_key {t : Tree} {low key value : Nat} (hlow : low < t.size) :
    ((insertResult t low key value).getLeaf t.size).key = key := by
  rw [insert_result_get hlow, if_pos rfl]; rfl

/-- The key set after an insertion is exactly the old set plus the new key. -/
theorem insert_key_set {t : Tree} {low key value k : Nat} (hlow : low < t.size) :
    MemKey (insertResult t low key value) k ↔ (MemKey t k ∨ k = key) := by
  constructor
  · rintro ⟨i, hi, hk⟩
    rw [insert_result_size hlow] at hi
    by_cases hin : i = t.size
    · subst hin
      exact Or.inr (by rw [← hk, insert_result_new_key hlow])
    · have hi' : i < t.size := by omega
      exact Or.inl ⟨i, hi', by rw [← hk, insert_result_old_key hlow hi']⟩
  · rintro (⟨i, hi, hk⟩ | hk)
    · exact ⟨i, by rw [insert_result_size hlow]; omega,
        by rw [insert_result_old_key hlow hi]; exact hk⟩
    · exact ⟨t.size, by rw [insert_result_size hlow]; omega,
        by rw [insert_result_new_key hlow]; exact hk.symm⟩

/-- A native insertion cannot be built for a key that is already present:
`low_index` reports `KeyAlreadyExists`. -/
theorem insert_present_key_fails {t : Tree} {key value : Nat} (hw : Wf t) (h : MemKey t key) :
    insert t key value = .error (.keyAlreadyExists key) := by
  have hnil := present_key_has_no_low_candidate hw h
  unfold insert lowIndex
  rw [hnil]
  rfl

/-- Contrapositive, in the shape the callers of this file need: a NATIVE
insertion that succeeded proves the key was absent. No hash assumption. -/
theorem insert_ok_implies_absent {t t' : Tree} {key value : Nat} (hw : Wf t)
    (h : insert t key value = .ok t') : ¬ MemKey t key := by
  intro hmem
  rw [insert_present_key_fails hw hmem] at h
  simp at h

/-- The all-zero sentinel key is present in every well-formed tree, so key `0`
can never be inserted. (`next_key == 0` is the "no successor" marker, so a real
key `0` would break the encoding.) -/
theorem zero_key_can_never_be_inserted {t : Tree} {value : Nat} (hw : Wf t) :
    insert t 0 value = .error (.keyAlreadyExists 0) :=
  insert_present_key_fails hw ⟨0, hw.size_pos, hw.sentinel⟩

/-- ORDERED-SET INVARIANT PRESERVATION. Together with `wf_new` this is what lets
a chain of insertions be reasoned about: every intermediate tree is `Wf`, so
`insert_ok_implies_absent` applies at every step. -/
theorem wf_insert {t t' : Tree} {key value : Nat} (hw : Wf t) (hkey : key < keyBound)
    (hcap : t.size < t.capacity) (h : insert t key value = .ok t') : Wf t' := by
  obtain ⟨low, hlow, rfl⟩ := insert_ok_iff.1 h
  have hlt : low < t.size := low_index_lt hlow
  have hbounds := is_low_leaf_iff.1 (low_index_is_low hlow)
  have huniq := low_index_unique hlow
  have habs : ¬ MemKey t key := by
    intro hmem
    rw [insert_present_key_fails hw hmem] at h
    simp at h
  have hkey0 : 0 < key := by omega
  have hsize' : (insertResult t low key value).size = t.size + 1 := insert_result_size hlt
  have hget := insert_result_get (t := t) (low := low) (key := key) (value := value) hlt
  have hkeyold : ∀ {j : Nat}, j < t.size →
      ((insertResult t low key value).getLeaf j).key = (t.getLeaf j).key :=
    fun {_} hj => insert_result_old_key hlt hj
  have hkeynew := insert_result_new_key (t := t) (low := low) (key := key) (value := value) hlt
  have hmono : ∀ k, MemKey t k → MemKey (insertResult t low key value) k := by
    intro k hk; exact (insert_key_set hlt).2 (Or.inl hk)
  refine ⟨by omega, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- sentinel
    rw [hkeyold hw.size_pos]
    exact hw.sentinel
  · -- in_range
    intro i hi
    rw [hsize'] at hi
    by_cases hin : i = t.size
    · subst hin
      rw [hget, if_pos rfl, inserted_leaf_key, inserted_leaf_next_key]
      exact ⟨hkey, (hw.in_range low hlt).2⟩
    · have hi' : i < t.size := by omega
      refine ⟨by rw [hkeyold hi']; exact (hw.in_range i hi').1, ?_⟩
      rw [hget, if_neg hin]
      by_cases hil : i = low
      · rw [if_pos hil, new_low_leaf_next_key]; exact hkey
      · rw [if_neg hil]; exact (hw.in_range i hi').2
  · -- distinct
    intro i j hi hj hij
    rw [hsize'] at hi hj
    by_cases hin : i = t.size <;> by_cases hjn : j = t.size
    · rw [hin, hjn]
    · exfalso
      have hj' : j < t.size := by omega
      rw [hin, hkeynew, hkeyold hj'] at hij
      exact habs ⟨j, hj', hij.symm⟩
    · exfalso
      have hi' : i < t.size := by omega
      rw [hjn, hkeynew, hkeyold hi'] at hij
      exact habs ⟨i, hi', hij⟩
    · have hi' : i < t.size := by omega
      have hj' : j < t.size := by omega
      rw [hkeyold hi', hkeyold hj'] at hij
      exact hw.distinct i j hi' hj' hij
  · -- succ_gt
    intro i hi hne
    rw [hsize'] at hi
    by_cases hin : i = t.size
    · subst hin
      rw [hget, if_pos rfl] at hne ⊢
      rw [inserted_leaf_next_key] at hne ⊢
      rw [inserted_leaf_key]
      rcases hbounds.2 with hup | hup
      · exact hup
      · exact absurd hup hne
    · have hi' : i < t.size := by omega
      rw [hkeyold hi']
      rw [hget, if_neg hin] at hne ⊢
      by_cases hil : i = low
      · rw [if_pos hil] at hne ⊢
        rw [new_low_leaf_next_key] at hne ⊢
        rw [hil]
        exact hbounds.1
      · rw [if_neg hil] at hne ⊢
        exact hw.succ_gt i hi' hne
  · -- succ_mem
    intro i hi hne
    rw [hsize'] at hi
    by_cases hin : i = t.size
    · subst hin
      rw [hget, if_pos rfl] at hne ⊢
      rw [inserted_leaf_next_key] at hne ⊢
      exact hmono _ (hw.succ_mem low hlt hne)
    · have hi' : i < t.size := by omega
      rw [hget, if_neg hin] at hne ⊢
      by_cases hil : i = low
      · rw [if_pos hil] at hne ⊢
        rw [new_low_leaf_next_key] at hne ⊢
        exact ⟨t.size, by rw [hsize']; omega, hkeynew⟩
      · rw [if_neg hil] at hne ⊢
        exact hmono _ (hw.succ_mem i hi' hne)
  · -- dense
    intro i j hi hj hlti
    rw [hsize'] at hi hj
    by_cases hjn : j = t.size
    · -- inserting above i
      subst hjn
      rw [hkeynew] at hlti
      have hin : i ≠ t.size := by
        intro hc; rw [hc, hkeynew] at hlti; omega
      have hi' : i < t.size := by omega
      rw [hkeynew]
      rw [hget, if_neg hin]
      by_cases hil : i = low
      · rw [if_pos hil, new_low_leaf_next_key]
        exact ⟨by omega, Nat.le_refl _⟩
      · rw [if_neg hil]
        rw [hkeyold hi'] at hlti
        have hnc : isLowLeaf key (t.getLeaf i) ≠ true := by
          intro hc; exact hil (huniq i hi' hc)
        have := is_low_leaf_iff (key := key) (L := t.getLeaf i)
        by_cases hd : (t.getLeaf i).nextKey = 0
        · exact absurd (is_low_leaf_iff.2 ⟨hlti, Or.inr hd⟩) hnc
        · by_cases hd2 : key < (t.getLeaf i).nextKey
          · exact absurd (is_low_leaf_iff.2 ⟨hlti, Or.inl hd2⟩) hnc
          · exact ⟨hd, by omega⟩
    · have hj' : j < t.size := by omega
      rw [hkeyold hj'] at hlti ⊢
      by_cases hin : i = t.size
      · subst hin
        rw [hkeynew] at hlti
        rw [hget, if_pos rfl, inserted_leaf_next_key]
        have hPj : (t.getLeaf low).key < (t.getLeaf j).key := by omega
        exact hw.dense low j hlt hj' hPj
      · have hi' : i < t.size := by omega
        rw [hkeyold hi'] at hlti
        rw [hget, if_neg hin]
        by_cases hil : i = low
        · rw [if_pos hil, new_low_leaf_next_key]
          have hPj : (t.getLeaf low).key < (t.getLeaf j).key := by rw [← hil]; exact hlti
          obtain ⟨hne, hle⟩ := hw.dense low j hlt hj' hPj
          rcases hbounds.2 with hup | hup
          · exact ⟨by omega, by omega⟩
          · exact absurd hup hne
        · rw [if_neg hil]
          exact hw.dense i j hi' hj' hlti
  · -- capacity
    rw [hsize', Tree.capacity, insert_result_height]
    exact hcap

end Zkp.Implementation.IndexedMerkleTree
