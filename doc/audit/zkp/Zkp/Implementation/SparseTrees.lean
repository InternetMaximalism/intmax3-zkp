import Std

/-!
# Sparse and incremental Merkle trees (handwritten semantic model)

Sources:
* `src/utils/trees/sparse_merkle_tree.rs` (production 1–255, tests 256–799)
* `src/utils/trees/incremental_merkle_tree.rs` (production 1–233, tests 235–711)

This is a HANDWRITTEN model of the *observable behaviour* of those two files. It is
NOT a refinement proof of the Rust code, of `rustc`, of plonky2, or of the circuit
lowering: no source-to-Lean compiler refinement is proved anywhere below.

Both Rust types are thin wrappers around the private `MerkleTree<V>` of
`src/utils/trees/merkle_tree.rs` (node map keyed by `BitPath`, plus a cached
`zero_hashes` ladder) and around `BitPath` of `src/utils/trees/bit_path.rs`.
Those two files are a *dependency boundary* for this module: a separate module
(`Zkp.Implementation.MerkleTrees`) is being written for them and is deliberately
NOT imported here, so this file re-models the fragment of the backing tree that
the two wrappers actually call (`new`, `height`, `get_root`, `update_leaf`,
`prove`, `MerkleProof::get_root`, `MerkleProof::verify`). Boundary name:
`backing-merkle-tree-remodel`. Any agreement between this local re-model and the
`MerkleTrees` module is not proved here.

## What is opaque
The hash is an OPAQUE CALLBACK (`HashSpec`): `emptyLeaf` models `V::empty_leaf()`,
`leafHash` models `Leafable::hash`, `twoToOne` models `LeafableHasher::two_to_one`.
Nothing below assumes the hash is injective, collision resistant, or even
non-constant. Consequently:

* every theorem here is a STRUCTURAL fact about the bookkeeping (which map slot is
  written, what the leaf count is, what the ladder is), and
* NOTHING here says that a verifying Merkle proof implies membership, that a
  changed root implies a changed leaf set, or that two different leaf sets have
  different roots. Those need collision resistance of Poseidon, which is an
  undischarged premise (boundary `hash-collision-resistance`).
  `constant_hash_forges_membership` below *exhibits* a `HashSpec` under which a
  proof for a leaf that was never inserted verifies, so the missing premise is
  not a formality.

## Other named boundaries
* `u64-index-arithmetic`: Rust indices are `u64` and `BitPath.value` is a `u64`
  that is shifted right, never masked. `Nat` is used here, so wraparound of
  `1u64 << height` for `height >= 64` is not modelled. The low-bit flip
  `value ^= 1` of `BitPath::sibling` is modelled arithmetically
  (`if v % 2 = 0 then v + 1 else v - 1`); the two agree on every `u64` but that
  identity is a modelling assumption, not a theorem here.
* `hashmap-order`: `HashMap<u64, V>` is modelled by an insert-or-replace
  association list, so `len`/`is_empty` are faithful but iteration order is not.
* `panics`: `IncrementalMerkleTree::push` uses `assert!` and `update` indexes a
  `Vec`; both abort the process. They are modelled as `Except IncError`, and the
  Rust `update` mutates the backing tree *before* the out-of-bounds index panic,
  which the `Except` model does not reproduce.
* `serde-roundtrip`: the `Serialize`/`Deserialize` impls and the packed structs
  are modelled only as `pack`/`unpack`; the serde wire format is not modelled.
* `circuit-targets`: `SparseMerkleProofTarget` / `IncrementalMerkleProofTarget`
  and their `new`/`constant`/`set_witness`/`get_root`/`verify`/`conditional_verify`
  are plonky2 builder calls. They are NOT modelled; nothing here constrains an
  arbitrary in-circuit witness. This module is entirely about the NATIVE path.
-/

namespace Zkp.Implementation.SparseTrees

/-! ## The hash boundary -/

/-- The opaque hash interface the trees are generic over: `V::empty_leaf()`,
`Leafable::hash` and `LeafableHasher::two_to_one`. No algebraic property is
assumed of any field. -/
structure HashSpec (V H : Type) where
  emptyLeaf : V
  leafHash : V → H
  twoToOne : H → H → H

variable {V H : Type}

/-! ## Bit paths (`src/utils/trees/bit_path.rs`, dependency of both sources) -/

/-- `BitPath { length, value }`. `length` is the depth from the root, `value`
carries the remaining index bits. Equality is on both fields, exactly like the
derived `Eq`/`Hash` used as the `HashMap` key in `merkle_tree.rs`. -/
structure BitPath where
  length : Nat
  value : Nat
  deriving DecidableEq, Repr, Inhabited

/-- `BitPath::default()`, the key `MerkleTree::get_root` reads. -/
def BitPath.rootPath : BitPath := ⟨0, 0⟩

/-- `BitPath::new(height as u32, index)`. Note that `value` is the FULL index:
it is never reduced modulo `2^height`. -/
def BitPath.ofIndex (height index : Nat) : BitPath := ⟨height, index⟩

/-- `BitPath::pop`: `bit = value & 1; value >>= 1; length -= 1`. -/
def BitPath.pop (p : BitPath) : Option (Bool × BitPath) :=
  if p.length = 0 then none
  else some (decide (p.value % 2 = 1), ⟨p.length - 1, p.value / 2⟩)

/-- `BitPath::sibling`: `value ^= 1`, modelled as the arithmetic low-bit flip
(boundary `u64-index-arithmetic`). -/
def BitPath.sibling (p : BitPath) : BitPath :=
  ⟨p.length, if p.value % 2 = 0 then p.value + 1 else p.value - 1⟩

/-- The path reached after `lvl` `pop`s from `BitPath::new(height, index)`: the
level-`lvl` ancestor of leaf `index`. `lvl = 0` is the leaf, `lvl = height` is
the node `update_leaf` writes last. -/
def ancPath (height index lvl : Nat) : BitPath := ⟨height - lvl, index / 2 ^ lvl⟩

theorem anc_path_zero (height index : Nat) :
    ancPath height index 0 = BitPath.ofIndex height index := by
  simp [ancPath, BitPath.ofIndex]

theorem anc_path_length (height index lvl : Nat) :
    (ancPath height index lvl).length = height - lvl := rfl

/-- A sibling is never one of the ancestors at a level at or below its own,
because the sibling keeps the length and flips the low bit of the value. This is
what makes an `update_leaf` sweep read pre-update siblings only. -/
theorem anc_sibling_ne_anc (height index lvl k : Nat)
    (hlvl : lvl ≤ height) (hk : k ≤ lvl) :
    (ancPath height index lvl).sibling ≠ ancPath height index k := by
  intro heq
  have hlen : height - lvl = height - k := congrArg BitPath.length heq
  have hkl : k = lvl := by omega
  subst hkl
  have hval := congrArg BitPath.value heq
  dsimp only [BitPath.sibling, ancPath] at hval
  split at hval <;> omega

/-! ## The cached ladder of empty-subtree roots -/

/-- `zero_hashes[n]`: the root of a fully empty subtree of height `n`. This is a
pure function of `n` (and of the hash callback) — it does not depend on the tree
state, on the insertion history, or on any index. -/
def zeroAt (hs : HashSpec V H) : Nat → H
  | 0 => hs.leafHash hs.emptyLeaf
  | n + 1 => hs.twoToOne (zeroAt hs n) (zeroAt hs n)

/-- The `n+1`-element list `[zeroAt lvl, ..., zeroAt (lvl + n)]`. -/
def ladderFrom (hs : HashSpec V H) (lvl : Nat) : Nat → List H
  | 0 => [zeroAt hs lvl]
  | n + 1 => zeroAt hs lvl :: ladderFrom hs (lvl + 1) n

/-- `MerkleTree::new`'s `zero_hashes` vector. -/
def ladder (hs : HashSpec V H) (height : Nat) : List H := ladderFrom hs 0 height

theorem zero_at_succ (hs : HashSpec V H) (n : Nat) :
    zeroAt hs (n + 1) = hs.twoToOne (zeroAt hs n) (zeroAt hs n) := rfl

theorem ladder_from_length (hs : HashSpec V H) (n : Nat) :
    ∀ lvl, (ladderFrom hs lvl n).length = n + 1 := by
  induction n with
  | zero => intro lvl; rfl
  | succ n ih => intro lvl; simp [ladderFrom, ih (lvl + 1)]

/-- Pinned shape of the cached ladder: `MerkleTree::new(height)` pushes exactly
`height + 1` entries. -/
theorem ladder_length_pinned (hs : HashSpec V H) (height : Nat) :
    (ladder hs height).length = height + 1 := ladder_from_length hs height 0

theorem ladder_from_get (hs : HashSpec V H) (n : Nat) :
    ∀ lvl i, i ≤ n → (ladderFrom hs lvl n)[i]? = some (zeroAt hs (lvl + i)) := by
  induction n with
  | zero =>
    intro lvl i hi
    have : i = 0 := Nat.le_zero.mp hi
    subst this
    simp [ladderFrom]
  | succ n ih =>
    intro lvl i hi
    cases i with
    | zero => simp [ladderFrom]
    | succ i =>
      have hi' : i ≤ n := by omega
      have ih' := ih (lvl + 1) i hi'
      have heq : lvl + 1 + i = lvl + (i + 1) := by omega
      rw [heq] at ih'
      simpa [ladderFrom] using ih'

/-- The cached empty-subtree root at every level is a deterministic function of
the level alone. -/
theorem ladder_get (hs : HashSpec V H) (height i : Nat) (hi : i ≤ height) :
    (ladder hs height)[i]? = some (zeroAt hs i) := by
  have := ladder_from_get hs height 0 i hi
  simpa [ladder] using this

/-! ## The backing sparse node store (re-model of `merkle_tree.rs`) -/

/-- `MerkleTree<V> { height, node_hashes: HashMap<BitPath, HashOut<V>>, zero_hashes }`.
The node map is modelled as a total function into `Option H`; only `len` of the
*leaf* map is observable in the wrappers, so no ordering information is lost. -/
structure MTree (H : Type) where
  height : Nat
  nodes : BitPath → Option H
  zeros : List H

/-- `MerkleTree::new(height)`. -/
def mtNew (hs : HashSpec V H) (height : Nat) : MTree H :=
  { height := height, nodes := fun _ => none, zeros := ladder hs height }

/-- `MerkleTree::get_node_hash`: a stored node, else the cached empty-subtree
root for the subtree hanging at that depth. In Rust the fallback indexes
`zero_hashes[height - path.len()]`, which panics on `usize` underflow when
`path.len() > height`; that case is unreachable from the wrappers and is
modelled here by a default value. -/
def nodeAt (hs : HashSpec V H) (height : Nat) (zeros : List H)
    (nodes : BitPath → Option H) (p : BitPath) : H :=
  match nodes p with
  | some h => h
  | none => (zeros[height - p.length]?).getD (zeroAt hs 0)

def mtNode (hs : HashSpec V H) (t : MTree H) (p : BitPath) : H :=
  nodeAt hs t.height t.zeros t.nodes p

/-- `MerkleTree::get_root` = `get_node_hash(BitPath::default())`. -/
def mtRoot (hs : HashSpec V H) (t : MTree H) : H := mtNode hs t BitPath.rootPath

theorem node_at_congr (hs : HashSpec V H) (height : Nat) (zeros : List H)
    (n₁ n₂ : BitPath → Option H) (p : BitPath) (h : n₁ p = n₂ p) :
    nodeAt hs height zeros n₁ p = nodeAt hs height zeros n₂ p := by
  simp [nodeAt, h]

/-- `node_hashes.insert(path, h)`. -/
def setNode (nodes : BitPath → Option H) (p : BitPath) (h : H) :
    BitPath → Option H :=
  fun q => if q = p then some h else nodes q

theorem set_node_eq (nodes : BitPath → Option H) (p : BitPath) (h : H) :
    setNode nodes p h p = some h := by simp [setNode]

theorem set_node_ne (nodes : BitPath → Option H) (p q : BitPath) (h : H)
    (hq : q ≠ p) : setNode nodes p h q = nodes q := by simp [setNode, hq]

/-- One iteration of the `update_leaf` sweep: read the sibling, then combine in
the order dictated by the popped bit. -/
def combineAt (hs : HashSpec V H) (height index : Nat) (zeros : List H)
    (nodes : BitPath → Option H) (lvl : Nat) (h : H) : H :=
  if (index / 2 ^ lvl) % 2 = 1 then
    hs.twoToOne (nodeAt hs height zeros nodes (ancPath height index lvl).sibling) h
  else
    hs.twoToOne h (nodeAt hs height zeros nodes (ancPath height index lvl).sibling)

/-- The upward sweep of `MerkleTree::update_leaf`, `fuel` levels starting at
level `lvl` with running hash `h`. Each step inserts at the parent path. -/
def updateUp (hs : HashSpec V H) (height index : Nat) (zeros : List H) :
    Nat → Nat → H → (BitPath → Option H) → (BitPath → Option H)
  | 0, _, _, nodes => nodes
  | fuel + 1, lvl, h, nodes =>
      updateUp hs height index zeros fuel (lvl + 1)
        (combineAt hs height index zeros nodes lvl h)
        (setNode nodes (ancPath height index (lvl + 1))
          (combineAt hs height index zeros nodes lvl h))

/-- `MerkleTree::update_leaf(index, leaf_hash)`: insert at the leaf path, then
sweep `height` levels upward. Note the cached ladder is never touched. -/
def mtUpdateLeaf (hs : HashSpec V H) (t : MTree H) (index : Nat) (lh : H) : MTree H :=
  { t with
    nodes :=
      updateUp hs t.height index t.zeros t.height 0 lh
        (setNode t.nodes (ancPath t.height index 0) lh) }

/-- The sibling collection loop of `MerkleTree::prove`. -/
def proveLoop (hs : HashSpec V H) (height index : Nat) (zeros : List H)
    (nodes : BitPath → Option H) : Nat → Nat → List H
  | 0, _ => []
  | fuel + 1, lvl =>
      nodeAt hs height zeros nodes (ancPath height index lvl).sibling
        :: proveLoop hs height index zeros nodes fuel (lvl + 1)

/-- `MerkleTree::prove(index)`, bottom-up sibling list of length `height`. -/
def mtProve (hs : HashSpec V H) (t : MTree H) (index : Nat) : List H :=
  proveLoop hs t.height index t.zeros t.nodes t.height 0

theorem prove_loop_length (hs : HashSpec V H) (height index : Nat) (zeros : List H)
    (nodes : BitPath → Option H) (fuel : Nat) :
    ∀ lvl, (proveLoop hs height index zeros nodes fuel lvl).length = fuel := by
  induction fuel with
  | zero => intro lvl; rfl
  | succ fuel ih => intro lvl; simp [proveLoop, ih (lvl + 1)]

/-- Pinned shape: a proof carries exactly `height` siblings, which is also what
`MerkleProof::height` reports and what `MerkleProofTarget::new` allocates. -/
theorem prove_length_pinned (hs : HashSpec V H) (t : MTree H) (index : Nat) :
    (mtProve hs t index).length = t.height :=
  prove_loop_length hs t.height index t.zeros t.nodes t.height 0

/-! ## Merkle proofs (`MerkleProof::get_root` / `verify`, called by both wrappers) -/

/-- The fold of `MerkleProof::get_root`: pop a bit, combine with the sibling. -/
def proofFold (hs : HashSpec V H) : List H → H → Nat → H
  | [], st, _ => st
  | s :: ss, st, v =>
      proofFold hs ss (if v % 2 = 1 then hs.twoToOne s st else hs.twoToOne st s) (v / 2)

/-- `MerkleProof::get_root(leaf_data, index)`. -/
def proofRoot (hs : HashSpec V H) (siblings : List H) (leaf : V) (index : Nat) : H :=
  proofFold hs siblings (hs.leafHash leaf) index

/-- `MerkleProofError::VerificationFailed`. -/
inductive ProofError where
  | verificationFailed
  deriving DecidableEq, Repr

/-- `MerkleProof::verify`, the single root comparison. It compares hashes; it
does NOT establish membership (see `constant_hash_forges_membership`). -/
def proofVerify [DecidableEq H] (hs : HashSpec V H) (siblings : List H) (leaf : V)
    (index : Nat) (root : H) : Except ProofError Unit :=
  if proofRoot hs siblings leaf index = root then .ok () else .error .verificationFailed

/-- `MerkleProof::dummy(height)`: `height` default hashes, an arbitrary constant
here. Nothing claims a dummy proof fails to verify. -/
def proofDummy (d : H) (height : Nat) : List H := List.replicate height d

theorem proof_dummy_length (d : H) (height : Nat) :
    (proofDummy d height).length = height := by simp [proofDummy]

/-! ## Core structural lemmas about the update sweep -/

/-- The sweep writes only at ancestor paths of `index` strictly above `lvl`. -/
theorem update_up_frame (hs : HashSpec V H) (height index : Nat) (zeros : List H) :
    ∀ (fuel lvl : Nat) (h : H) (nodes : BitPath → Option H) (q : BitPath),
      (∀ k, lvl + 1 ≤ k → k ≤ lvl + fuel → q ≠ ancPath height index k) →
      updateUp hs height index zeros fuel lvl h nodes q = nodes q := by
  intro fuel
  induction fuel with
  | zero => intro lvl h nodes q _; rfl
  | succ fuel ih =>
    intro lvl h nodes q hq
    have hne : q ≠ ancPath height index (lvl + 1) := hq (lvl + 1) (by omega) (by omega)
    have hrec :
        updateUp hs height index zeros fuel (lvl + 1)
            (combineAt hs height index zeros nodes lvl h)
            (setNode nodes (ancPath height index (lvl + 1))
              (combineAt hs height index zeros nodes lvl h)) q
          = setNode nodes (ancPath height index (lvl + 1))
              (combineAt hs height index zeros nodes lvl h) q := by
      refine ih (lvl + 1) _ _ q ?_
      intro k hk1 hk2
      exact hq k (by omega) (by omega)
    simpa [updateUp, hrec] using set_node_ne nodes (ancPath height index (lvl + 1)) q _ hne

/-- The node written at the top of the sweep is exactly the Merkle-path
recomputation from the new leaf hash and the PRE-update siblings. -/
theorem update_up_eq_fold (hs : HashSpec V H) (height index : Nat) (zeros : List H)
    (orig : BitPath → Option H) :
    ∀ (fuel lvl : Nat) (h : H) (nodes : BitPath → Option H),
      lvl + fuel = height →
      nodes (ancPath height index lvl) = some h →
      (∀ q, (∀ k, k ≤ lvl → q ≠ ancPath height index k) → nodes q = orig q) →
      updateUp hs height index zeros fuel lvl h nodes (ancPath height index (lvl + fuel))
        = some (proofFold hs (proveLoop hs height index zeros orig fuel lvl) h
            (index / 2 ^ lvl)) := by
  intro fuel
  induction fuel with
  | zero =>
    intro lvl h nodes _ hwrote _
    simpa [updateUp, proveLoop, proofFold] using hwrote
  | succ fuel ih =>
    intro lvl h nodes hsum hwrote hagree
    have hlvl : lvl ≤ height := by omega
    have hsib : nodes (ancPath height index lvl).sibling
        = orig (ancPath height index lvl).sibling := by
      refine hagree _ ?_
      intro k hk
      exact anc_sibling_ne_anc height index lvl k hlvl hk
    have hcomb : combineAt hs height index zeros nodes lvl h
        = combineAt hs height index zeros orig lvl h := by
      simp only [combineAt, node_at_congr hs height zeros nodes orig _ hsib]
    have hwrote' : setNode nodes (ancPath height index (lvl + 1))
        (combineAt hs height index zeros nodes lvl h) (ancPath height index (lvl + 1))
        = some (combineAt hs height index zeros nodes lvl h) := set_node_eq _ _ _
    have hagree' : ∀ q, (∀ k, k ≤ lvl + 1 → q ≠ ancPath height index k) →
        setNode nodes (ancPath height index (lvl + 1))
          (combineAt hs height index zeros nodes lvl h) q = orig q := by
      intro q hq
      have hne : q ≠ ancPath height index (lvl + 1) := hq (lvl + 1) (by omega)
      rw [set_node_ne nodes _ q _ hne]
      exact hagree q (fun k hk => hq k (by omega))
    have hIH := ih (lvl + 1) (combineAt hs height index zeros nodes lvl h) _
      (by omega) hwrote' hagree'
    have hlevel : lvl + (fuel + 1) = lvl + 1 + fuel := by omega
    have hdiv : index / 2 ^ lvl / 2 = index / 2 ^ (lvl + 1) := by
      rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ]
    rw [hlevel]
    have hstep : updateUp hs height index zeros (fuel + 1) lvl h nodes
          (ancPath height index (lvl + 1 + fuel))
        = updateUp hs height index zeros fuel (lvl + 1)
            (combineAt hs height index zeros nodes lvl h)
            (setNode nodes (ancPath height index (lvl + 1))
              (combineAt hs height index zeros nodes lvl h))
            (ancPath height index (lvl + 1 + fuel)) := by
      simp only [updateUp]
    rw [hstep, hIH, hcomb, ← hdiv]
    simp only [proveLoop, proofFold, combineAt]

/-- `update_leaf` touches no node outside the ancestor path of its own index. -/
theorem mt_update_leaf_frame (hs : HashSpec V H) (t : MTree H) (index : Nat) (lh : H)
    (q : BitPath) (hq : ∀ k, k ≤ t.height → q ≠ ancPath t.height index k) :
    (mtUpdateLeaf hs t index lh).nodes q = t.nodes q := by
  have h0 : q ≠ ancPath t.height index 0 := hq 0 (Nat.zero_le _)
  have := update_up_frame hs t.height index t.zeros t.height 0 lh
    (setNode t.nodes (ancPath t.height index 0) lh) q
    (fun k hk1 hk2 => hq k (by omega))
  simp only [mtUpdateLeaf, this]
  exact set_node_ne t.nodes _ q lh h0

/-- The cached ladder survives every update: it is computed once in `new`. -/
theorem mt_update_leaf_preserves_zeros (hs : HashSpec V H) (t : MTree H)
    (index : Nat) (lh : H) : (mtUpdateLeaf hs t index lh).zeros = t.zeros := rfl

theorem mt_update_leaf_preserves_height (hs : HashSpec V H) (t : MTree H)
    (index : Nat) (lh : H) : (mtUpdateLeaf hs t index lh).height = t.height := rfl

/-- The new root after `update_leaf` is the path recomputation from the new leaf
hash and the siblings `prove(index)` returned BEFORE the update. This is the
structural consistency between `update_leaf` and `prove`; it says nothing about
any leaf other than through those siblings. -/
theorem mt_update_leaf_root (hs : HashSpec V H) (t : MTree H) (index : Nat) (lh : H)
    (hindex : index < 2 ^ t.height) :
    mtRoot hs (mtUpdateLeaf hs t index lh)
      = proofFold hs (mtProve hs t index) lh index := by
  have htop : ancPath t.height index t.height = BitPath.rootPath := by
    have : index / 2 ^ t.height = 0 := Nat.div_eq_of_lt hindex
    simp [ancPath, BitPath.rootPath, this]
  have hwrote : setNode t.nodes (ancPath t.height index 0) lh
      (ancPath t.height index 0) = some lh := set_node_eq _ _ _
  have hagree : ∀ q, (∀ k, k ≤ 0 → q ≠ ancPath t.height index k) →
      setNode t.nodes (ancPath t.height index 0) lh q = t.nodes q := by
    intro q hq
    exact set_node_ne t.nodes _ q lh (hq 0 (Nat.le_refl _))
  have key := update_up_eq_fold hs t.height index t.zeros t.nodes t.height 0 lh
    (setNode t.nodes (ancPath t.height index 0) lh) (by omega) hwrote hagree
  simp only [Nat.zero_add] at key
  have hroot : (mtUpdateLeaf hs t index lh).nodes BitPath.rootPath
      = some (proofFold hs (mtProve hs t index) lh index) := by
    rw [← htop]
    simpa [mtUpdateLeaf, mtProve, Nat.pow_zero, Nat.div_one] using key
  simp [mtRoot, mtNode, nodeAt, hroot]

/-- Out-of-range indices are the one place the wrappers and the backing tree
disagree: `BitPath` never masks `value`, so after `height` pops the sweep writes
at `⟨0, index >> height⟩`, which is NOT the root key `⟨0, 0⟩`. The root is
therefore left untouched. -/
theorem mt_update_leaf_out_of_range_root (hs : HashSpec V H) (t : MTree H)
    (index : Nat) (lh : H) (hindex : 2 ^ t.height ≤ index) :
    mtRoot hs (mtUpdateLeaf hs t index lh) = mtRoot hs t := by
  have hpos : 0 < 2 ^ t.height := Nat.pos_pow_of_pos _ (by omega)
  have hq : ∀ k, k ≤ t.height → BitPath.rootPath ≠ ancPath t.height index k := by
    intro k hk hcontra
    by_cases hk' : k = t.height
    · subst hk'
      have hval := congrArg BitPath.value hcontra
      have : 1 ≤ index / 2 ^ t.height := (Nat.le_div_iff_mul_le hpos).mpr (by omega)
      simp [BitPath.rootPath, ancPath] at hval
      omega
    · have hlen := congrArg BitPath.length hcontra
      simp [BitPath.rootPath, ancPath] at hlen
      omega
  have hframe := mt_update_leaf_frame hs t index lh BitPath.rootPath hq
  have hz : (mtUpdateLeaf hs t index lh).zeros = t.zeros := rfl
  have hh : (mtUpdateLeaf hs t index lh).height = t.height := rfl
  simp [mtRoot, mtNode, nodeAt, hframe, hz, hh]

/-! ## Empty trees: the ladder is the whole state -/

theorem mt_new_node_absent (hs : HashSpec V H) (height : Nat) (p : BitPath)
    (hp : p.length ≤ height) :
    mtNode hs (mtNew hs height) p = zeroAt hs (height - p.length) := by
  have hle : height - p.length ≤ height := by omega
  simp [mtNode, mtNew, nodeAt, ladder_get hs height (height - p.length) hle]

/-- The empty root is `zeroAt height`: a deterministic function of the height and
the hash callback only. -/
theorem mt_new_root (hs : HashSpec V H) (height : Nat) :
    mtRoot hs (mtNew hs height) = zeroAt hs height := by
  have := mt_new_node_absent hs height BitPath.rootPath (by simp [BitPath.rootPath])
  simpa [mtRoot, BitPath.rootPath] using this

/-- Empty-subtree roots for the two heights of a fresh tree agree level by level:
the ladder of a taller tree extends the shorter one, so `new` recomputes but
never redefines the cached values. -/
theorem ladder_prefix_agreement (hs : HashSpec V H) (h₁ h₂ i : Nat)
    (h1 : i ≤ h₁) (h2 : i ≤ h₂) :
    (mtNew hs h₁ : MTree H).zeros[i]? = (mtNew hs h₂ : MTree H).zeros[i]? := by
  simp [mtNew, ladder_get hs h₁ i h1, ladder_get hs h₂ i h2]

/-- Sibling list of a fresh tree: `[zeroAt lvl, ..., zeroAt (lvl + fuel - 1)]`. -/
def zeroSiblings (hs : HashSpec V H) (lvl : Nat) : Nat → List H
  | 0 => []
  | n + 1 => zeroAt hs lvl :: zeroSiblings hs (lvl + 1) n

theorem prove_loop_new (hs : HashSpec V H) (height index : Nat) :
    ∀ fuel lvl, lvl + fuel = height →
      proveLoop hs height index (ladder hs height) (fun _ => none) fuel lvl
        = zeroSiblings hs lvl fuel := by
  intro fuel
  induction fuel with
  | zero => intro lvl _; rfl
  | succ fuel ih =>
    intro lvl hsum
    have hlvl : lvl ≤ height := by omega
    have hsibnode : nodeAt hs height (ladder hs height) (fun _ => none)
        (ancPath height index lvl).sibling = zeroAt hs lvl := by
      have hlen : (ancPath height index lvl).sibling.length = height - lvl := rfl
      have : height - (height - lvl) = lvl := by omega
      simp [nodeAt, hlen, this, ladder_get hs height lvl hlvl]
    simp [proveLoop, zeroSiblings, hsibnode, ih (lvl + 1) (by omega)]

/-- `prove` on a fresh tree returns the cached ladder, for EVERY index. -/
theorem mt_new_prove (hs : HashSpec V H) (height index : Nat) :
    mtProve hs (mtNew hs height) index = zeroSiblings hs 0 height := by
  simpa [mtProve, mtNew] using prove_loop_new hs height index height 0 (by omega)

theorem fold_zero_siblings (hs : HashSpec V H) (n : Nat) :
    ∀ lvl v, proofFold hs (zeroSiblings hs lvl n) (zeroAt hs lvl) v
      = zeroAt hs (lvl + n) := by
  induction n with
  | zero => intro lvl v; simp [zeroSiblings, proofFold]
  | succ n ih =>
    intro lvl v
    have hstep : (if v % 2 = 1 then hs.twoToOne (zeroAt hs lvl) (zeroAt hs lvl)
        else hs.twoToOne (zeroAt hs lvl) (zeroAt hs lvl)) = zeroAt hs (lvl + 1) := by
      split <;> rfl
    have := ih (lvl + 1) (v / 2)
    simp only [zeroSiblings, proofFold, hstep, this]
    congr 1
    omega

/-! ## `SparseMerkleTree<V>` (`src/utils/trees/sparse_merkle_tree.rs`) -/

/-- `HashMap<u64, V>` lookup (boundary `hashmap-order`). -/
def findEntry (l : List (Nat × V)) (k : Nat) : Option V :=
  match l with
  | [] => none
  | (k', v') :: rest => if k' = k then some v' else findEntry rest k

/-- `HashMap::insert`: replace in place if present, otherwise add. -/
def insertEntry (l : List (Nat × V)) (k : Nat) (v : V) : List (Nat × V) :=
  match l with
  | [] => [(k, v)]
  | (k', v') :: rest =>
      if k' = k then (k, v) :: rest else (k', v') :: insertEntry rest k v

theorem find_insert_eq (l : List (Nat × V)) (k : Nat) (v : V) :
    findEntry (insertEntry l k v) k = some v := by
  induction l with
  | nil => simp [insertEntry, findEntry]
  | cons e rest ih =>
    obtain ⟨k', v'⟩ := e
    by_cases h : k' = k
    · simp [insertEntry, findEntry, h]
    · simp [insertEntry, findEntry, h, ih]

theorem find_insert_ne (l : List (Nat × V)) (k j : Nat) (v : V) (hj : j ≠ k) :
    findEntry (insertEntry l k v) j = findEntry l j := by
  induction l with
  | nil => simp [insertEntry, findEntry, Ne.symm hj]
  | cons e rest ih =>
    obtain ⟨k', v'⟩ := e
    by_cases h : k' = k
    · subst h
      simp [insertEntry, findEntry, Ne.symm hj]
    · by_cases h2 : k' = j
      · subst h2
        simp [insertEntry, findEntry, h]
      · simp [insertEntry, findEntry, h, h2, ih]

theorem length_insert_present (l : List (Nat × V)) (k : Nat) (v : V) (w : V)
    (hk : findEntry l k = some w) : (insertEntry l k v).length = l.length := by
  induction l with
  | nil => simp [findEntry] at hk
  | cons e rest ih =>
    obtain ⟨k', v'⟩ := e
    by_cases h : k' = k
    · simp [insertEntry, h]
    · simp only [findEntry, if_neg h] at hk
      simp [insertEntry, h, ih hk]

theorem length_insert_absent (l : List (Nat × V)) (k : Nat) (v : V)
    (hk : findEntry l k = none) : (insertEntry l k v).length = l.length + 1 := by
  induction l with
  | nil => simp [insertEntry]
  | cons e rest ih =>
    obtain ⟨k', v'⟩ := e
    by_cases h : k' = k
    · simp [findEntry, h] at hk
    · simp only [findEntry, if_neg h] at hk
      simp [insertEntry, h, ih hk]

/-- `SparseMerkleTree<V> { merkle_tree, leaves }`. -/
structure SparseTree (V H : Type) where
  tree : MTree H
  leaves : List (Nat × V)

/-- `SparseMerkleTree::new(height)`. -/
def sparseNew (hs : HashSpec V H) (height : Nat) : SparseTree V H :=
  { tree := mtNew hs height, leaves := [] }

/-- `SparseMerkleTree::height`. -/
def sparseHeight (t : SparseTree V H) : Nat := t.tree.height

/-- `SparseMerkleTree::get_leaf`: absent keys read as the EMPTY LEAF, not as an
error, so callers cannot distinguish "never written" from "written to the empty
value". -/
def sparseGetLeaf (hs : HashSpec V H) (t : SparseTree V H) (index : Nat) : V :=
  match findEntry t.leaves index with
  | some leaf => leaf
  | none => hs.emptyLeaf

/-- `SparseMerkleTree::get_root`. -/
def sparseRoot (hs : HashSpec V H) (t : SparseTree V H) : H := mtRoot hs t.tree

/-- `SparseMerkleTree::len`. -/
def sparseLen (t : SparseTree V H) : Nat := t.leaves.length

/-- `SparseMerkleTree::is_empty`. -/
def sparseIsEmpty (t : SparseTree V H) : Bool := t.leaves.isEmpty

/-- `SparseMerkleTree::update`: hash the leaf into the backing tree, then record
it in the map. No bound on `index` is checked here or in `update_leaf`. -/
def sparseUpdate (hs : HashSpec V H) (t : SparseTree V H) (index : Nat) (leaf : V) :
    SparseTree V H :=
  { tree := mtUpdateLeaf hs t.tree index (hs.leafHash leaf),
    leaves := insertEntry t.leaves index leaf }

/-- `SparseMerkleTree::prove`. -/
def sparseProve (hs : HashSpec V H) (t : SparseTree V H) (index : Nat) : List H :=
  mtProve hs t.tree index

/-- `SparseMerkleTreePacked` + `pack`/`unpack` (boundary `serde-roundtrip`). -/
def sparsePack (t : SparseTree V H) : Nat × List (Nat × V) :=
  (sparseHeight t, t.leaves)

def sparseUnpack (hs : HashSpec V H) (p : Nat × List (Nat × V)) : SparseTree V H :=
  p.2.foldl (fun acc e => sparseUpdate hs acc e.1 e.2) (sparseNew hs p.1)

/-! ### Sparse-tree theorems -/

theorem sparse_new_height (hs : HashSpec V H) (height : Nat) :
    sparseHeight (sparseNew hs height : SparseTree V H) = height := rfl

theorem sparse_new_len (hs : HashSpec V H) (height : Nat) :
    sparseLen (sparseNew hs height : SparseTree V H) = 0 := rfl

theorem sparse_new_is_empty (hs : HashSpec V H) (height : Nat) :
    sparseIsEmpty (sparseNew hs height : SparseTree V H) = true := rfl

/-- Reading an absent key yields the empty leaf. -/
theorem sparse_get_leaf_absent (hs : HashSpec V H) (t : SparseTree V H) (index : Nat)
    (h : findEntry t.leaves index = none) :
    sparseGetLeaf hs t index = hs.emptyLeaf := by simp [sparseGetLeaf, h]

/-- Every key of a fresh sparse tree is absent, hence reads as the empty leaf. -/
theorem sparse_new_get_leaf (hs : HashSpec V H) (height index : Nat) :
    sparseGetLeaf hs (sparseNew hs height : SparseTree V H) index = hs.emptyLeaf := rfl

theorem sparse_update_get_leaf (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf : V) :
    sparseGetLeaf hs (sparseUpdate hs t index leaf) index = leaf := by
  simp [sparseGetLeaf, sparseUpdate, find_insert_eq]

/-- Leaf-map frame property: an update is invisible at every other key. -/
theorem sparse_update_other_leaf (hs : HashSpec V H) (t : SparseTree V H)
    (index j : Nat) (leaf : V) (hj : j ≠ index) :
    sparseGetLeaf hs (sparseUpdate hs t index leaf) j = sparseGetLeaf hs t j := by
  simp [sparseGetLeaf, sparseUpdate, find_insert_ne t.leaves index j leaf hj]

/-- Node frame property: an update writes only on the ancestor path of its own
index; every other node of the backing tree is byte-identical. -/
theorem sparse_update_node_frame (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf : V) (q : BitPath)
    (hq : ∀ k, k ≤ sparseHeight t → q ≠ ancPath (sparseHeight t) index k) :
    (sparseUpdate hs t index leaf).tree.nodes q = t.tree.nodes q :=
  mt_update_leaf_frame hs t.tree index (hs.leafHash leaf) q hq

theorem sparse_update_preserves_height (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf : V) :
    sparseHeight (sparseUpdate hs t index leaf) = sparseHeight t := rfl

/-- The empty-subtree ladder is cached at construction and never rewritten. -/
theorem sparse_update_preserves_ladder (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf : V) :
    (sparseUpdate hs t index leaf).tree.zeros = t.tree.zeros := rfl

/-- Overwriting an existing key does not change `len`. -/
theorem sparse_update_len_present (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf w : V) (h : findEntry t.leaves index = some w) :
    sparseLen (sparseUpdate hs t index leaf) = sparseLen t :=
  length_insert_present t.leaves index leaf w h

/-- Writing a fresh key increments `len` by one. -/
theorem sparse_update_len_absent (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf : V) (h : findEntry t.leaves index = none) :
    sparseLen (sparseUpdate hs t index leaf) = sparseLen t + 1 :=
  length_insert_absent t.leaves index leaf h

/-- The root after an in-range update is the path recomputation from the new leaf
and the siblings the tree would have produced for that index beforehand. -/
theorem sparse_update_root (hs : HashSpec V H) (t : SparseTree V H)
    (index : Nat) (leaf : V) (hindex : index < 2 ^ sparseHeight t) :
    sparseRoot hs (sparseUpdate hs t index leaf)
      = proofRoot hs (sparseProve hs t index) leaf index :=
  mt_update_leaf_root hs t.tree index (hs.leafHash leaf) hindex

/-- SECURITY-RELEVANT ASYMMETRY: an update at an index that is not a valid leaf
of a height-`height` tree still lands in the leaf map (so `get_leaf`, `len` and
serialization report it) while leaving the ROOT completely unchanged. -/
theorem sparse_update_out_of_range_root_unchanged (hs : HashSpec V H)
    (t : SparseTree V H) (index : Nat) (leaf : V)
    (hindex : 2 ^ sparseHeight t ≤ index) :
    sparseRoot hs (sparseUpdate hs t index leaf) = sparseRoot hs t :=
  mt_update_leaf_out_of_range_root hs t.tree index (hs.leafHash leaf) hindex

theorem sparse_update_out_of_range_leaf_recorded (hs : HashSpec V H)
    (t : SparseTree V H) (index : Nat) (leaf : V)
    (_hindex : 2 ^ sparseHeight t ≤ index) :
    sparseGetLeaf hs (sparseUpdate hs t index leaf) index = leaf :=
  sparse_update_get_leaf hs t index leaf

/-- `prove` on a fresh tree returns the cached ladder for every index; absent
keys are indistinguishable from one another. -/
theorem sparse_new_prove (hs : HashSpec V H) (height index : Nat) :
    sparseProve hs (sparseNew hs height : SparseTree V H) index
      = zeroSiblings hs 0 height :=
  mt_new_prove hs height index

/-- The proof produced for an ABSENT key of a fresh tree verifies against the
empty leaf and the tree root, for any index. This is the model's version of the
Rust test `test_sparse_merkle_tree_prove` "proof for non-existent leaf". It is a
structural fact; it does NOT say the verifier rejects anything. -/
theorem sparse_new_absent_proof_verifies [DecidableEq H] (hs : HashSpec V H)
    (height index : Nat) :
    proofVerify hs (sparseProve hs (sparseNew hs height : SparseTree V H) index)
        (sparseGetLeaf hs (sparseNew hs height : SparseTree V H) index) index
        (sparseRoot hs (sparseNew hs height : SparseTree V H)) = .ok () := by
  have hfold : proofFold hs (zeroSiblings hs 0 height) (zeroAt hs 0) index
      = zeroAt hs height := by
    simpa using fold_zero_siblings hs height 0 index
  have hroot : sparseRoot hs (sparseNew hs height : SparseTree V H) = zeroAt hs height :=
    mt_new_root hs height
  simp [proofVerify, proofRoot, sparse_new_prove, sparse_new_get_leaf, hroot,
    show hs.leafHash hs.emptyLeaf = zeroAt hs 0 from rfl, hfold]

/-! ## `IncrementalMerkleTree<V>` (`src/utils/trees/incremental_merkle_tree.rs`) -/

/-- The two ways the Rust type aborts: `push`'s `assert!` and `update`'s `Vec`
index. Both are process panics in Rust (boundary `panics`). -/
inductive IncError where
  | capacityExceeded
  | indexOutOfBounds
  deriving DecidableEq, Repr

/-- `IncrementalMerkleTree<V> { merkle_tree, leaves: Vec<V> }`. -/
structure IncTree (V H : Type) where
  tree : MTree H
  leaves : List V

def incNew (hs : HashSpec V H) (height : Nat) : IncTree V H :=
  { tree := mtNew hs height, leaves := [] }

def incHeight (t : IncTree V H) : Nat := t.tree.height

/-- `IncrementalMerkleTree::get_leaf`: past the frontier, the empty leaf. -/
def incGetLeaf (hs : HashSpec V H) (t : IncTree V H) (index : Nat) : V :=
  (t.leaves[index]?).getD hs.emptyLeaf

def incRoot (hs : HashSpec V H) (t : IncTree V H) : H := mtRoot hs t.tree

/-- `IncrementalMerkleTree::len`, the append-only frontier position. -/
def incLen (t : IncTree V H) : Nat := t.leaves.length

def incIsEmpty (t : IncTree V H) : Bool := t.leaves.isEmpty

/-- `IncrementalMerkleTree::push`: the next index is the current length, the
`assert!` bounds it by `2^height`. -/
def incPush (hs : HashSpec V H) (t : IncTree V H) (leaf : V) :
    Except IncError (IncTree V H) :=
  if t.leaves.length < 2 ^ incHeight t then
    .ok { tree := mtUpdateLeaf hs t.tree t.leaves.length (hs.leafHash leaf),
          leaves := t.leaves ++ [leaf] }
  else .error .capacityExceeded

/-- `IncrementalMerkleTree::update`: only positions already inside the frontier
can be rewritten (`self.leaves[index] = leaf` panics otherwise). In Rust the
backing tree is updated BEFORE that panic; the `Except` model does not reproduce
the partially-mutated state (boundary `panics`). -/
def incUpdate (hs : HashSpec V H) (t : IncTree V H) (index : Nat) (leaf : V) :
    Except IncError (IncTree V H) :=
  if index < t.leaves.length then
    .ok { tree := mtUpdateLeaf hs t.tree index (hs.leafHash leaf),
          leaves := t.leaves.set index leaf }
  else .error .indexOutOfBounds

def incProve (hs : HashSpec V H) (t : IncTree V H) (index : Nat) : List H :=
  mtProve hs t.tree index

/-- `IncrementalMerkleTreePacked` + `unpack`, which replays `push`. -/
def incUnpack (hs : HashSpec V H) (height : Nat) (leaves : List V) :
    Except IncError (IncTree V H) :=
  leaves.foldlM (fun acc l => incPush hs acc l) (incNew hs height)

/-! ### Incremental-tree theorems -/

theorem inc_new_len (hs : HashSpec V H) (height : Nat) :
    incLen (incNew hs height : IncTree V H) = 0 := rfl

theorem inc_new_is_empty (hs : HashSpec V H) (height : Nat) :
    incIsEmpty (incNew hs height : IncTree V H) = true := rfl

/-- Reading past the frontier yields the empty leaf. -/
theorem inc_get_leaf_out_of_range (hs : HashSpec V H) (t : IncTree V H) (index : Nat)
    (h : incLen t ≤ index) : incGetLeaf hs t index = hs.emptyLeaf := by
  have : t.leaves[index]? = none := List.getElem?_eq_none h
  simp [incGetLeaf, this]

theorem inc_push_ok_bound (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') : incLen t < 2 ^ incHeight t := by
  by_cases hb : t.leaves.length < 2 ^ incHeight t
  · exact hb
  · simp [incPush, hb] at h

theorem inc_push_eq (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') :
    t' = { tree := mtUpdateLeaf hs t.tree t.leaves.length (hs.leafHash leaf),
           leaves := t.leaves ++ [leaf] } := by
  by_cases hb : t.leaves.length < 2 ^ incHeight t
  · simp [incPush, hb] at h; exact h.symm
  · simp [incPush, hb] at h

/-- Appending increments the leaf count by exactly one. -/
theorem inc_push_len (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') : incLen t' = incLen t + 1 := by
  rw [inc_push_eq hs t t' leaf h]; simp [incLen]

/-- Appending leaves every earlier leaf untouched. -/
theorem inc_push_preserves_earlier (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') (j : Nat) (hj : j < incLen t) :
    incGetLeaf hs t' j = incGetLeaf hs t j := by
  rw [inc_push_eq hs t t' leaf h]
  simp [incGetLeaf, List.getElem?_append hj]

/-- The appended leaf lands exactly at the old frontier position. -/
theorem inc_push_new_leaf (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') : incGetLeaf hs t' (incLen t) = leaf := by
  rw [inc_push_eq hs t t' leaf h]
  simp [incGetLeaf, incLen]

/-- The root after an append is the path recomputation from the appended leaf and
the frontier siblings of the pre-append tree. -/
theorem inc_push_root (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') :
    incRoot hs t' = proofRoot hs (incProve hs t (incLen t)) leaf (incLen t) := by
  have hb : t.leaves.length < 2 ^ t.tree.height := inc_push_ok_bound hs t t' leaf h
  rw [inc_push_eq hs t t' leaf h]
  exact mt_update_leaf_root hs t.tree t.leaves.length (hs.leafHash leaf) hb

/-- The ladder is untouched by appends as well. -/
theorem inc_push_preserves_ladder (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') : t'.tree.zeros = t.tree.zeros := by
  rw [inc_push_eq hs t t' leaf h]
  rfl

theorem inc_push_preserves_height (hs : HashSpec V H) (t t' : IncTree V H) (leaf : V)
    (h : incPush hs t leaf = .ok t') : incHeight t' = incHeight t := by
  rw [inc_push_eq hs t t' leaf h]
  rfl

/-- A full tree refuses further appends instead of wrapping around. -/
theorem inc_push_full (hs : HashSpec V H) (t : IncTree V H) (leaf : V)
    (h : 2 ^ incHeight t ≤ incLen t) : incPush hs t leaf = .error .capacityExceeded := by
  have : ¬ t.leaves.length < 2 ^ incHeight t := by simp [incLen] at h; omega
  simp [incPush, this]

/-- `update` cannot extend the frontier. -/
theorem inc_update_out_of_range (hs : HashSpec V H) (t : IncTree V H) (index : Nat)
    (leaf : V) (h : incLen t ≤ index) :
    incUpdate hs t index leaf = .error .indexOutOfBounds := by
  have : ¬ index < t.leaves.length := by simp [incLen] at h; omega
  simp [incUpdate, this]

theorem inc_update_len (hs : HashSpec V H) (t t' : IncTree V H) (index : Nat) (leaf : V)
    (h : incUpdate hs t index leaf = .ok t') : incLen t' = incLen t := by
  by_cases hb : index < t.leaves.length
  · simp [incUpdate, hb] at h
    rw [← h]; simp [incLen]
  · simp [incUpdate, hb] at h

/-! ## Honesty: what the hash boundary costs

The following is not a defect of the model, it is the point of the boundary. -/

/-- A hash callback that collapses everything to one value. Only used to exhibit
the missing premise. -/
def constSpec : HashSpec Nat Nat :=
  { emptyLeaf := 0, leafHash := fun _ => 0, twoToOne := fun _ _ => 0 }

/-- With a constant hash callback, a Merkle proof verifies for a leaf that was
never inserted, at an index that was never written, on a fresh tree. Every
membership-flavoured reading of `proofVerify` therefore REQUIRES collision
resistance of the concrete hash, which this module does not assume anywhere. -/
theorem constant_hash_forges_membership :
    ∃ (hs : HashSpec Nat Nat) (height index : Nat) (forged : Nat),
      forged ≠ hs.emptyLeaf ∧
      proofVerify hs (sparseProve hs (sparseNew hs height : SparseTree Nat Nat) index)
        forged index (sparseRoot hs (sparseNew hs height : SparseTree Nat Nat)) = .ok () := by
  refine ⟨constSpec, 3, 5, 1, by decide, ?_⟩
  have hroot : proofRoot constSpec
      (sparseProve constSpec (sparseNew constSpec 3 : SparseTree Nat Nat) 5) 1 5
      = sparseRoot constSpec (sparseNew constSpec 3 : SparseTree Nat Nat) := by decide
  simp [proofVerify, hroot]

/-! ## A concrete non-vacuous trace

`demoSpec` is a toy collision-prone hash; it is used only to exhibit that the
definitions above compute, and no security claim is attached to it. -/

def demoSpec : HashSpec Nat Nat :=
  { emptyLeaf := 0, leafHash := fun v => v + 1, twoToOne := fun a b => 3 * a + 5 * b + 7 }

def demoTree : SparseTree Nat Nat :=
  sparseUpdate demoSpec (sparseUpdate demoSpec (sparseNew demoSpec 3) 5 9) 2 4

theorem demo_len : sparseLen demoTree = 2 := by decide

theorem demo_get_written : sparseGetLeaf demoSpec demoTree 5 = 9 := by decide

theorem demo_get_absent : sparseGetLeaf demoSpec demoTree 6 = 0 := by decide

theorem demo_proof_length : (sparseProve demoSpec demoTree 5).length = 3 := by
  simpa using prove_length_pinned demoSpec demoTree.tree 5

/-- A concrete satisfying trace: the proof for a written leaf verifies against
the live root. -/
theorem demo_proof_verifies :
    proofVerify demoSpec (sparseProve demoSpec demoTree 5)
      (sparseGetLeaf demoSpec demoTree 5) 5 (sparseRoot demoSpec demoTree) = .ok () := by
  have hroot : proofRoot demoSpec (sparseProve demoSpec demoTree 5)
      (sparseGetLeaf demoSpec demoTree 5) 5 = sparseRoot demoSpec demoTree := by decide
  simp [proofVerify, hroot]

/-- The same tree, reached by `push` on the incremental type. -/
def demoIncTree : Except IncError (IncTree Nat Nat) := do
  let t ← incPush demoSpec (incNew demoSpec 3) 11
  incPush demoSpec t 12

theorem demo_inc_len : (demoIncTree.toOption.map incLen) = some 2 := by decide

end Zkp.Implementation.SparseTrees
