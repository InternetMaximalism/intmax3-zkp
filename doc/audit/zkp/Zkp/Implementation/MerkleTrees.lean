import Std

/-!
# Merkle openings: `BitPath`, `MerkleProof`, `get_root`, and the in-circuit counterpart

Handwritten semantic model of

* `src/utils/trees/merkle_tree.rs` (sparse `MerkleTree`, `MerkleProof`, `MerkleProofTarget`),
* `src/utils/trees/get_root.rs` (`get_merkle_root_from_leaves` and its circuit twin),
* `src/utils/trees/bit_path.rs` (`BitPath`),
* `src/utils/trees/mod.rs`, `src/utils/trees/error.rs`.

This is NOT a refinement proof of the Rust code, of plonky2's gate lowering, or of Poseidon.
The hash is an OPAQUE CALLBACK (`HashEnv`): `leafHash` models `Leafable::hash`, `twoToOne` models
`LeafableHasher::two_to_one`, `zeroDigest` models `HashOut::default()`. Nothing in this file assumes
that either callback is injective.

## What the model pins down

* `BitPath` is a `(length, value)` pair; `pop` consumes the LOW bit first, so the sibling list is
  ordered LEAF-TO-ROOT and the index is decomposed LITTLE-ENDIAN (`indexBits`). The in-circuit
  counterpart uses `builder.split_le(index, height)`, the same order.
* Node hashing is `two_to_one(left, right)` with the swap driven by the level bit:
  bit = 1 puts the running state on the RIGHT (`two_to_one(sibling, state)`), bit = 0 on the LEFT.
* There are NO domain tags: leaf hashing and node hashing feed the same permutation, and for
  `PoseidonHashOut` leaves `Leafable::hash` is the identity. `leaf_and_node_domains_are_not_separated`
  records the resulting leaf/node confusion in the model.
* Height convention: a proof's height IS its sibling count (`MerkleProof::height() = siblings.len()`),
  a tree of height `h` stores `h + 1` zero hashes (`zeroHashAt 0 .. zeroHashAt h`), and `prove`
  emits exactly `h` siblings.
* The dummy proof is `height` copies of the DEFAULT digest, not the zero-subtree hashes; the
  circuits use `depositTreeHeight = 63` and `sendTreeHeight = 32` (pinned).

## Structural vs. collision-resistance

STRUCTURAL (proved here, no cryptographic premise):
`root_from_bits_is_a_function_of_leaf_hash_bits_and_siblings`, the height/sibling-count relations,
the index truncation facts, the `.unwrap()`-freedom of `get_root`, the layer arithmetic of
`get_merkle_root_from_full_leaves`, and the fact that the circuit's `conditional_verify` places no
constraint at all when its condition is false.

NEEDS COLLISION RESISTANCE (kept as an EXPLICIT premise on the concrete compared pairs, never as
global hash injectivity): `equal_roots_force_equal_states_under_collision_premise` and its leaf
corollary take `NoCollisionAlong`, a level-by-level premise saying that the two SPECIFIC pairs
compared at each level are not a collision of `twoToOne`. Turning that into a statement about
Poseidon is out of scope. `LeafHashInjectiveOn` is the separate, equally explicit premise needed to
go from equal leaf HASHES to equal leaves.

## What an opening does NOT give you

* `opening_at_index_zero_leaves_index_one_unconstrained`: one root opens to `a` at index 0 and to an
  arbitrary `b` at index 1, so a valid opening says nothing about any other index.
* `same_index_hypothesis_is_necessary`: with the hash opaque, two openings at DIFFERENT indices with
  the same siblings can produce the same root from different leaves; the same-index hypothesis is
  not decorative.
* Nothing here says a root is canonical, current, or on-chain; nothing here is a proof-system
  soundness claim.

## Known native/circuit divergence

`BitPath::new(height, index)` does NOT mask `index`, so the native `verify` accepts
`index + 2^height` wherever it accepts `index` (`native_verify_accepts_index_beyond_height`).
The circuit's `split_le` instead range-constrains the index; the model records both.
-/

namespace Zkp.Implementation.MerkleTrees

variable {L D : Type}

/-! ## The opaque hash interface (`Leafable` / `LeafableHasher`) -/

/-- Opaque hash callbacks. No injectivity, no domain separation, no algebraic structure. -/
structure HashEnv (L D : Type) where
  emptyLeaf : L
  leafHash : L → D
  twoToOne : D → D → D
  zeroDigest : D

/-! ## `bit_path.rs` -/

/-- `BitPath { length, value }`. `value` is a `u64` in Rust; here an unbounded `Nat`. -/
structure BitPath where
  length : Nat
  value : Nat
  deriving DecidableEq, Repr

/-- `BitPath::default()` — the root path. -/
def BitPath.rootPath : BitPath := ⟨0, 0⟩

/-- `BitPath::is_empty`. -/
def BitPath.isEmpty (p : BitPath) : Bool := p.length == 0

/-- `x ^= 1` on the low bit (Rust `sibling()` flips the last bit). -/
def flipLowBit (v : Nat) : Nat := if v % 2 = 1 then v - 1 else v + 1

/-- `BitPath::sibling` — same length, low bit flipped. -/
def BitPath.sibling (p : BitPath) : BitPath := ⟨p.length, flipLowBit p.value⟩

/-- `BitPath::pop` — returns the LOW bit and shifts right; `None` at length 0. -/
def BitPath.pop (p : BitPath) : Option (Bool × BitPath) :=
  match p.length with
  | 0 => none
  | n + 1 => some (decide (p.value % 2 = 1), ⟨n, p.value / 2⟩)

/-- Little-endian bit decomposition of an index, leaf level first. -/
def indexBits : Nat → Nat → List Bool
  | 0, _ => []
  | n + 1, v => decide (v % 2 = 1) :: indexBits n (v / 2)

/-- All bits a `BitPath` will yield, in pop order. -/
def BitPath.bits (p : BitPath) : List Bool := indexBits p.length p.value

theorem bit_path_root_path_is_empty : BitPath.rootPath.isEmpty = true := by
  simp [BitPath.rootPath, BitPath.isEmpty]

theorem flip_low_bit_involutive (v : Nat) : flipLowBit (flipLowBit v) = v := by
  unfold flipLowBit
  by_cases h : v % 2 = 1
  · rw [if_pos h]
    have h2 : ¬ (v - 1) % 2 = 1 := by omega
    rw [if_neg h2]
    omega
  · rw [if_neg h]
    have h2 : (v + 1) % 2 = 1 := by omega
    rw [if_pos h2]
    omega

theorem flip_low_bit_keeps_parent (v : Nat) : flipLowBit v / 2 = v / 2 := by
  unfold flipLowBit
  by_cases h : v % 2 = 1
  · rw [if_pos h]; omega
  · rw [if_neg h]; omega

theorem bit_path_sibling_involutive (p : BitPath) : p.sibling.sibling = p := by
  cases p with
  | mk len val => simp [BitPath.sibling, flip_low_bit_involutive]

theorem bit_path_sibling_keeps_length (p : BitPath) : p.sibling.length = p.length := rfl

theorem index_bits_length (n v : Nat) : (indexBits n v).length = n := by
  induction n generalizing v with
  | zero => simp [indexBits]
  | succ n ih => simp [indexBits, ih]

theorem bit_path_bits_length (p : BitPath) : p.bits.length = p.length :=
  index_bits_length p.length p.value

theorem bit_path_pop_none_iff_empty (p : BitPath) : p.pop = none ↔ p.length = 0 := by
  cases p with
  | mk len val => cases len <;> simp [BitPath.pop]

theorem bit_path_pop_cons_bits (p : BitPath) (b : Bool) (q : BitPath)
    (popped : p.pop = some (b, q)) : p.bits = b :: q.bits := by
  cases p with
  | mk len val =>
    cases len with
    | zero => simp [BitPath.pop] at popped
    | succ n =>
      simp only [BitPath.pop] at popped
      obtain ⟨hb, hq⟩ := Prod.mk.injEq .. ▸ (Option.some.injEq .. ▸ popped)
      subst hb; subst hq
      simp [BitPath.bits, indexBits]

/-- The high bits of the index above the path length are silently DISCARDED (`BitPath::new` does
not mask `index`). -/
theorem index_bits_ignore_high_bits (n v k : Nat) : indexBits n (v + 2 ^ n * k) = indexBits n v := by
  induction n generalizing v with
  | zero => simp [indexBits]
  | succ n ih =>
    have hk : 2 ^ (n + 1) * k = 2 * (2 ^ n * k) := by
      rw [Nat.pow_succ, Nat.mul_comm (2 ^ n) 2, Nat.mul_assoc]
    rw [hk]
    simp only [indexBits]
    rw [Nat.add_mul_mod_self_left, Nat.add_mul_div_left _ _ (by decide : 0 < 2), ih]

/-! ## Recomputing a root from a leaf, index bits and siblings -/

/-- One level: bit = 1 puts the running state on the RIGHT. -/
def nodeOf (env : HashEnv L D) (bit : Bool) (state sibling : D) : D :=
  if bit then env.twoToOne sibling state else env.twoToOne state sibling

def leftOf (bit : Bool) (state sibling : D) : D := if bit then sibling else state

def rightOf (bit : Bool) (state sibling : D) : D := if bit then state else sibling

theorem node_of_eq_two_to_one (env : HashEnv L D) (bit : Bool) (state sibling : D) :
    nodeOf env bit state sibling = env.twoToOne (leftOf bit state sibling) (rightOf bit state sibling) := by
  cases bit <;> simp [nodeOf, leftOf, rightOf]

/-- The pure fold: a deterministic function of (state, bits, siblings) only. -/
def rootFromBits (env : HashEnv L D) : D → List Bool → List D → D
  | state, _, [] => state
  | state, [], _ :: _ => state
  | state, b :: bs, x :: xs => rootFromBits env (nodeOf env b state x) bs xs

/-- Faithful rendering of `MerkleProof::get_root`, including the `path.pop().unwrap()`
(modelled as `none`). -/
def climb (env : HashEnv L D) : List D → BitPath → D → Option D
  | [], _, state => some state
  | x :: xs, path, state =>
    match path.pop with
    | none => none
    | some (b, path') => climb env xs path' (nodeOf env b state x)

theorem climb_eq_root_from_bits (env : HashEnv L D) :
    ∀ (siblings : List D) (path : BitPath) (state : D),
      path.length = siblings.length →
      climb env siblings path state = some (rootFromBits env state path.bits siblings) := by
  intro siblings
  induction siblings with
  | nil => intro path state _; simp [climb, rootFromBits]
  | cons x xs ih =>
    intro path state hlen
    cases path with
    | mk len val =>
      cases len with
      | zero => simp at hlen
      | succ n =>
        have hn : n = xs.length := by simpa using hlen
        have hbits : (BitPath.mk (n + 1) val).bits
            = decide (val % 2 = 1) :: (BitPath.mk n (val / 2)).bits := by
          simp [BitPath.bits, indexBits]
        rw [hbits]
        simp only [climb, BitPath.pop, rootFromBits]
        exact ih ⟨n, val / 2⟩ (nodeOf env (decide (val % 2 = 1)) state x) hn

/-- STRUCTURAL: the recomputed root depends on nothing but the leaf hash, the index bits and the
sibling list — no tree state, no index bits above the path length. -/
theorem root_from_bits_is_a_function_of_leaf_hash_bits_and_siblings (env : HashEnv L D)
    (a b : L) (bitsA bitsB : List Bool) (sibA sibB : List D)
    (hleaf : env.leafHash a = env.leafHash b) (hbits : bitsA = bitsB) (hsib : sibA = sibB) :
    rootFromBits env (env.leafHash a) bitsA sibA = rootFromBits env (env.leafHash b) bitsB sibB := by
  subst hbits; subst hsib; rw [hleaf]

/-! ## `MerkleProof` -/

structure MerkleProof (D : Type) where
  siblings : List D

/-- `MerkleProof::height()` IS the sibling count. -/
def MerkleProof.height (p : MerkleProof D) : Nat := p.siblings.length

/-- `MerkleProof::dummy(height)` — `height` copies of `HashOut::default()`. -/
def MerkleProof.dummy (env : HashEnv L D) (height : Nat) : MerkleProof D :=
  ⟨List.replicate height env.zeroDigest⟩

/-- Faithful `get_root` (option-valued because of the `unwrap`). -/
def MerkleProof.getRootOption (env : HashEnv L D) (p : MerkleProof D) (leaf : L) (index : Nat) :
    Option D :=
  climb env p.siblings ⟨p.height, index⟩ (env.leafHash leaf)

/-- Total `get_root`. -/
def MerkleProof.getRoot (env : HashEnv L D) (p : MerkleProof D) (leaf : L) (index : Nat) : D :=
  rootFromBits env (env.leafHash leaf) (indexBits p.height index) p.siblings

/-- `trees/error.rs :: MerkleProofError`. -/
inductive MerkleProofError (D : Type) where
  | verificationFailed (fromProof expected : D)
  deriving DecidableEq

/-- `MerkleProof::verify`. -/
def MerkleProof.verify [DecidableEq D] (env : HashEnv L D) (p : MerkleProof D) (leaf : L)
    (index : Nat) (merkleRoot : D) : Except (MerkleProofError D) Unit :=
  let proofRoot := p.getRoot env leaf index
  if proofRoot ≠ merkleRoot then .error (.verificationFailed proofRoot merkleRoot) else .ok ()

theorem merkle_proof_height_is_sibling_count (p : MerkleProof D) :
    p.height = p.siblings.length := rfl

/-- The `path.pop().unwrap()` in `get_root` can never fire: the path length is the sibling count. -/
theorem merkle_proof_get_root_never_unwraps_none (env : HashEnv L D) (p : MerkleProof D) (leaf : L)
    (index : Nat) : p.getRootOption env leaf index = some (p.getRoot env leaf index) := by
  have h := climb_eq_root_from_bits env p.siblings ⟨p.height, index⟩ (env.leafHash leaf) rfl
  simpa [MerkleProof.getRootOption, MerkleProof.getRoot, BitPath.bits] using h

theorem merkle_proof_verify_ok_iff_root_matches [DecidableEq D] (env : HashEnv L D)
    (p : MerkleProof D) (leaf : L) (index : Nat) (merkleRoot : D) :
    p.verify env leaf index merkleRoot = .ok () ↔ p.getRoot env leaf index = merkleRoot := by
  by_cases h : p.getRoot env leaf index = merkleRoot
  · simp [MerkleProof.verify, h]
  · simp [MerkleProof.verify, h]

theorem merkle_proof_verify_ok_binds_recomputed_root [DecidableEq D] (env : HashEnv L D)
    (p : MerkleProof D) (leaf : L) (index : Nat) (merkleRoot : D)
    (accepted : p.verify env leaf index merkleRoot = .ok ()) :
    rootFromBits env (env.leafHash leaf) (indexBits p.height index) p.siblings = merkleRoot :=
  (merkle_proof_verify_ok_iff_root_matches env p leaf index merkleRoot).mp accepted

/-- The recomputed root only reads the low `height` bits of the index. -/
theorem merkle_proof_root_ignores_index_bits_above_height (env : HashEnv L D) (p : MerkleProof D)
    (leaf : L) (index k : Nat) :
    p.getRoot env leaf (index + 2 ^ p.height * k) = p.getRoot env leaf index := by
  simp [MerkleProof.getRoot, index_bits_ignore_high_bits]

/-- DIVERGENCE: native `verify` accepts an index that the in-circuit `split_le` range check would
reject. -/
theorem native_verify_accepts_index_beyond_height [DecidableEq D] (env : HashEnv L D)
    (p : MerkleProof D) (leaf : L) (index : Nat) (merkleRoot : D)
    (accepted : p.verify env leaf index merkleRoot = .ok ()) :
    p.verify env leaf (index + 2 ^ p.height) merkleRoot = .ok () := by
  have h := (merkle_proof_verify_ok_iff_root_matches env p leaf index merkleRoot).mp accepted
  have hshift := merkle_proof_root_ignores_index_bits_above_height env p leaf index 1
  rw [Nat.mul_one] at hshift
  exact (merkle_proof_verify_ok_iff_root_matches env p leaf (index + 2 ^ p.height) merkleRoot).mpr
    (hshift.trans h)

/-! ## Collision-freedom premises (never global hash injectivity) -/

/-- The two SPECIFIC compared node-input pairs are not a collision of `twoToOne`. -/
def NoSwapCollision (env : HashEnv L D) (a b c d : D) : Prop :=
  env.twoToOne a b = env.twoToOne c d → a = c ∧ b = d

/-- Level-by-level collision-freedom for exactly the pairs the two openings compare. -/
def NoCollisionAlong (env : HashEnv L D) : D → D → List Bool → List D → Prop
  | _, _, _, [] => True
  | _, _, [], _ :: _ => True
  | sA, sB, b :: bs, x :: xs =>
      NoSwapCollision env (leftOf b sA x) (rightOf b sA x) (leftOf b sB x) (rightOf b sB x)
        ∧ NoCollisionAlong env (nodeOf env b sA x) (nodeOf env b sB x) bs xs

/-- The separate premise needed to go from equal leaf HASHES to equal leaves. -/
def LeafHashInjectiveOn (env : HashEnv L D) (a b : L) : Prop :=
  env.leafHash a = env.leafHash b → a = b

/-- NEEDS COLLISION RESISTANCE. Two openings at the SAME index bits with the SAME siblings and
equal roots force equal starting states — but only under the explicit level-wise premise. -/
theorem equal_roots_force_equal_states_under_collision_premise (env : HashEnv L D) :
    ∀ (siblings : List D) (bits : List Bool) (sA sB : D),
      NoCollisionAlong env sA sB bits siblings →
      rootFromBits env sA bits siblings = rootFromBits env sB bits siblings →
      sA = sB := by
  intro siblings
  induction siblings with
  | nil => intro bits sA sB _ heq; simpa [rootFromBits] using heq
  | cons x xs ih =>
    intro bits sA sB premise heq
    cases bits with
    | nil => simpa [rootFromBits] using heq
    | cons b bs =>
      simp only [NoCollisionAlong] at premise
      simp only [rootFromBits] at heq
      have hnode : nodeOf env b sA x = nodeOf env b sB x := ih bs _ _ premise.2 heq
      rw [node_of_eq_two_to_one, node_of_eq_two_to_one] at hnode
      have hpair := premise.1 hnode
      cases b with
      | false => simpa [leftOf] using hpair.1
      | true => simpa [rightOf] using hpair.2

/-- Same-index corollary at the level of leaf hashes. -/
theorem same_index_equal_roots_force_equal_leaf_hash [DecidableEq D] (env : HashEnv L D)
    (p : MerkleProof D) (a b : L) (index : Nat) (merkleRoot : D)
    (premise : NoCollisionAlong env (env.leafHash a) (env.leafHash b)
      (indexBits p.height index) p.siblings)
    (openA : p.verify env a index merkleRoot = .ok ())
    (openB : p.verify env b index merkleRoot = .ok ()) :
    env.leafHash a = env.leafHash b := by
  have hA := merkle_proof_verify_ok_binds_recomputed_root env p a index merkleRoot openA
  have hB := merkle_proof_verify_ok_binds_recomputed_root env p b index merkleRoot openB
  exact equal_roots_force_equal_states_under_collision_premise env p.siblings
    (indexBits p.height index) _ _ premise (hA.trans hB.symm)

/-- Same-index corollary at the level of leaves — needs the SECOND explicit premise. -/
theorem same_index_equal_roots_force_equal_leaves [DecidableEq D] (env : HashEnv L D)
    (p : MerkleProof D) (a b : L) (index : Nat) (merkleRoot : D)
    (premise : NoCollisionAlong env (env.leafHash a) (env.leafHash b)
      (indexBits p.height index) p.siblings)
    (leafPremise : LeafHashInjectiveOn env a b)
    (openA : p.verify env a index merkleRoot = .ok ())
    (openB : p.verify env b index merkleRoot = .ok ()) :
    a = b :=
  leafPremise (same_index_equal_roots_force_equal_leaf_hash env p a b index merkleRoot premise
    openA openB)

/-! ## What an opening does NOT imply -/

/-- One root opens to `a` at index 0 and to a completely arbitrary `b` at index 1: a valid opening
constrains the leaf at ITS index only. -/
theorem opening_at_index_zero_leaves_index_one_unconstrained (env : HashEnv L D) (a b : L) :
    rootFromBits env (env.leafHash a) [false] [env.leafHash b]
      = rootFromBits env (env.leafHash b) [true] [env.leafHash a] := by
  simp [rootFromBits, nodeOf]

/-- Leaf hashing and node hashing share the same permutation with no domain tag, so when
`Leafable::hash` is the identity (the `PoseidonHashOut` case) a two-leaf subtree digest is
indistinguishable from a leaf carrying that digest. -/
theorem leaf_and_node_domains_are_not_separated (env : HashEnv D D)
    (identity : ∀ d : D, env.leafHash d = d) (a b x : D) :
    rootFromBits env (env.leafHash (env.twoToOne a b)) [false] [x]
      = rootFromBits env (env.twoToOne (env.leafHash a) (env.leafHash b)) [false] [x] := by
  simp [rootFromBits, nodeOf, identity]

/-! ## The sparse `MerkleTree` -/

structure MerkleTree (D : Type) where
  height : Nat
  nodeHashes : List (BitPath × D)
  zeroHashes : List D

/-- `zero_hashes[i]`: the root of an all-empty subtree of height `i`. -/
def zeroHashAt (env : HashEnv L D) : Nat → D
  | 0 => env.leafHash env.emptyLeaf
  | n + 1 => env.twoToOne (zeroHashAt env n) (zeroHashAt env n)

/-- `MerkleTree::new`. -/
def MerkleTree.new (env : HashEnv L D) (height : Nat) : MerkleTree D :=
  { height := height
    nodeHashes := []
    zeroHashes := (List.range (height + 1)).map (zeroHashAt env) }

/-- Association-list stand-in for the Rust `HashMap`; `insert` is modelled as a prepend, which has
the same first-match lookup behaviour. -/
def lookupNode (nodes : List (BitPath × D)) (p : BitPath) : Option D :=
  match nodes with
  | [] => none
  | (q, h) :: rest => if q = p then some h else lookupNode rest p

/-- `MerkleTree::get_node_hash` — stored node, else the zero hash for that level. -/
def MerkleTree.getNodeHash (env : HashEnv L D) (t : MerkleTree D) (p : BitPath) : D :=
  match lookupNode t.nodeHashes p with
  | some h => h
  | none => zeroHashAt env (t.height - p.length)

/-- `MerkleTree::get_root` — the node hash at the empty path. -/
def MerkleTree.getRoot (env : HashEnv L D) (t : MerkleTree D) : D :=
  t.getNodeHash env BitPath.rootPath

/-- Body of the `update_leaf` climb. -/
def climbUpdate (env : HashEnv L D) (t : MerkleTree D) : Nat → BitPath → D → MerkleTree D
  | 0, _, _ => t
  | n + 1, path, h =>
    let sibling := t.getNodeHash env path.sibling
    match path.pop with
    | none => t
    | some (bit, path') =>
      let h' := nodeOf env bit h sibling
      climbUpdate env { t with nodeHashes := (path', h') :: t.nodeHashes } n path' h'

/-- `MerkleTree::update_leaf` (takes a leaf HASH, not a leaf). -/
def MerkleTree.updateLeaf (env : HashEnv L D) (t : MerkleTree D) (index : Nat) (leafHash : D) :
    MerkleTree D :=
  let path : BitPath := ⟨t.height, index⟩
  climbUpdate env { t with nodeHashes := (path, leafHash) :: t.nodeHashes } t.height path leafHash

/-- Body of the `prove` climb. -/
def collectSiblings (env : HashEnv L D) (t : MerkleTree D) : Nat → BitPath → List D
  | 0, _ => []
  | n + 1, path =>
    t.getNodeHash env path.sibling ::
      (match path.pop with
       | none => []
       | some (_, path') => collectSiblings env t n path')

/-- `MerkleTree::prove`. -/
def MerkleTree.prove (env : HashEnv L D) (t : MerkleTree D) (index : Nat) : MerkleProof D :=
  ⟨collectSiblings env t t.height ⟨t.height, index⟩⟩

theorem merkle_tree_new_has_height_plus_one_zero_hashes (env : HashEnv L D) (height : Nat) :
    (MerkleTree.new env height).zeroHashes.length = height + 1 := by
  simp [MerkleTree.new, List.length_map, List.length_range]

theorem merkle_tree_new_has_no_stored_nodes (env : HashEnv L D) (height : Nat) :
    (MerkleTree.new env height).nodeHashes = ([] : List (BitPath × D)) := rfl

theorem empty_tree_root_is_top_zero_hash (env : HashEnv L D) (height : Nat) :
    (MerkleTree.new env height).getRoot env = zeroHashAt env height := by
  simp [MerkleTree.new, MerkleTree.getRoot, MerkleTree.getNodeHash, lookupNode, BitPath.rootPath]

theorem collect_siblings_length (env : HashEnv L D) (t : MerkleTree D) :
    ∀ (n : Nat) (path : BitPath), path.length = n → (collectSiblings env t n path).length = n := by
  intro n
  induction n with
  | zero => intro path _; simp [collectSiblings]
  | succ n ih =>
    intro path hlen
    cases path with
    | mk len val =>
      have hn : len = n + 1 := hlen
      subst hn
      simp only [collectSiblings, BitPath.pop, List.length_cons]
      rw [ih ⟨n, val / 2⟩ rfl]

/-- HEIGHT/SIBLING-COUNT: `prove` emits exactly `height` siblings, and a proof's height is that
count. -/
theorem merkle_tree_prove_has_height_siblings (env : HashEnv L D) (t : MerkleTree D) (index : Nat) :
    (t.prove env index).height = t.height := by
  simpa [MerkleTree.prove, MerkleProof.height] using
    collect_siblings_length env t t.height ⟨t.height, index⟩ rfl

/-! ## Pinned circuit heights and the dummy proof -/

/-- `constants.rs :: DEPOSIT_TREE_HEIGHT` (= `BLOCK_NUMBER_BITS` = `PUBLIC_STATE_TREE_HEIGHT`). -/
def depositTreeHeight : Nat := 63

/-- `constants.rs :: SEND_TREE_HEIGHT` (also `NULLIFIER_TREE_HEIGHT`, `SENT_TX_TREE_HEIGHT`). -/
def sendTreeHeight : Nat := 32

theorem deposit_tree_height_pinned : depositTreeHeight = 63 := rfl

theorem send_tree_height_pinned : sendTreeHeight = 32 := rfl

theorem dummy_proof_siblings_are_the_default_digest (env : HashEnv L D) (height : Nat) :
    (MerkleProof.dummy env height).siblings = List.replicate height env.zeroDigest := rfl

theorem dummy_proof_height (env : HashEnv L D) (height : Nat) :
    (MerkleProof.dummy env height).height = height := by
  simp [MerkleProof.dummy, MerkleProof.height]

theorem dummy_deposit_proof_has_63_siblings (env : HashEnv L D) :
    (MerkleProof.dummy env depositTreeHeight).siblings.length = 63 := by
  simp [MerkleProof.dummy, depositTreeHeight]

theorem dummy_send_proof_has_32_siblings (env : HashEnv L D) :
    (MerkleProof.dummy env sendTreeHeight).siblings.length = 32 := by
  simp [MerkleProof.dummy, sendTreeHeight]

/-! ## `get_root.rs` -/

/-- `trees/error.rs :: GetRootFromLeavesError`. -/
inductive GetRootFromLeavesError where
  | tooManyLeaves (n : Nat)
  | notPowerOfTwo (n : Nat)
  deriving DecidableEq, Repr

/-- One bottom-up layer step: `two_to_one(layer[2i], layer[2i+1])`. -/
def combineLayer (env : HashEnv L D) : List D → List D
  | a :: b :: rest => env.twoToOne a b :: combineLayer env rest
  | _ => []

def reduceLayers (env : HashEnv L D) : Nat → List D → List D
  | 0, layer => layer
  | n + 1, layer => reduceLayers env n (combineLayer env layer)

/-- `get_merkle_root_from_full_leaves`. -/
def getMerkleRootFromFullLeaves (env : HashEnv L D) (height : Nat) (leaves : List L) :
    Except GetRootFromLeavesError D :=
  if leaves.length ≠ 2 ^ height then .error (.tooManyLeaves leaves.length)
  else
    let layer := leaves.map env.leafHash
    if layer.isEmpty then .error (.tooManyLeaves 0)
    else
      match reduceLayers env height layer with
      | [r] => .ok r
      | l => .error (.notPowerOfTwo l.length)

/-- `get_merkle_root_from_leaves` — reject overflow, then pad with empty leaves to full width. -/
def getMerkleRootFromLeaves (env : HashEnv L D) (height : Nat) (leaves : List L) :
    Except GetRootFromLeavesError D :=
  if leaves.length > 2 ^ height then .error (.tooManyLeaves leaves.length)
  else
    getMerkleRootFromFullLeaves env height
      (leaves ++ List.replicate (2 ^ height - leaves.length) env.emptyLeaf)

/-- The circuit's extension loop: pair the sub-tree root with successive zero-subtree hashes,
always on the RIGHT. -/
def extendWithZeroSubtrees (env : HashEnv L D) (root : D) (fromLevel : Nat) : Nat → D
  | 0 => root
  | k + 1 => extendWithZeroSubtrees env (env.twoToOne root (zeroHashAt env fromLevel)) (fromLevel + 1) k

/-- `get_merkle_root_from_leaves_circuit`, with `next_power_of_two`/`trailing_zeros` supplied as
`subHeight` (a Rust `usize` intrinsic, left as a boundary). -/
def circuitRootFromLeaves (env : HashEnv L D) (subHeight height : Nat) (leaves : List L) :
    Except GetRootFromLeavesError D :=
  match getMerkleRootFromFullLeaves env subHeight
      (leaves ++ List.replicate (2 ^ subHeight - leaves.length) env.emptyLeaf) with
  | .error e => .error e
  | .ok subRoot => .ok (extendWithZeroSubtrees env subRoot subHeight (height - subHeight))

theorem combine_layer_halves_length (env : HashEnv L D) (l : List D) :
    (combineLayer env l).length = l.length / 2 := by
  induction l using combineLayer.induct env with
  | case1 a b rest ih => simp [combineLayer, ih]; omega
  | case2 l _ => cases l with
    | nil => simp [combineLayer]
    | cons a t => cases t with
      | nil => simp [combineLayer]
      | cons b r => simp_all

theorem reduce_layers_full_length (env : HashEnv L D) :
    ∀ (n : Nat) (l : List D), l.length = 2 ^ n → (reduceLayers env n l).length = 1 := by
  intro n
  induction n with
  | zero => intro l hl; simpa [reduceLayers] using hl
  | succ n ih =>
    intro l hl
    refine ih (combineLayer env l) ?_
    rw [combine_layer_halves_length, hl, Nat.pow_succ, Nat.mul_div_cancel _ (by decide : 0 < 2)]

theorem list_length_one_is_singleton (l : List D) (h : l.length = 1) : ∃ a, l = [a] := by
  cases l with
  | nil => simp at h
  | cons a t => cases t with
    | nil => exact ⟨a, rfl⟩
    | cons b r => simp at h

/-- The `NotPowerOfTwo` branch of `get_merkle_root_from_full_leaves` is UNREACHABLE: the length
check already forces a power-of-two width, and so does the empty-layer branch. -/
theorem full_leaves_never_reports_not_power_of_two (env : HashEnv L D) (height : Nat)
    (leaves : List L) (width : leaves.length = 2 ^ height) :
    ∃ r, getMerkleRootFromFullLeaves env height leaves = .ok r := by
  have hlayer : (leaves.map env.leafHash).length = 2 ^ height := by simpa using width
  have hone := reduce_layers_full_length env height (leaves.map env.leafHash) hlayer
  obtain ⟨r, hr⟩ := list_length_one_is_singleton _ hone
  have hne : ¬ (leaves.length ≠ 2 ^ height) := by simp [width]
  have hnonempty : ¬ (leaves.map env.leafHash).isEmpty = true := by
    cases hmap : leaves.map env.leafHash with
    | nil => rw [hmap] at hlayer; simp at hlayer; omega
    | cons a t => simp
  refine ⟨r, ?_⟩
  simp only [getMerkleRootFromFullLeaves, if_neg hne, if_neg hnonempty]
  rw [hr]

theorem get_root_from_leaves_rejects_overflow (env : HashEnv L D) (height : Nat) (leaves : List L)
    (tooMany : leaves.length > 2 ^ height) :
    getMerkleRootFromLeaves env height leaves = .error (.tooManyLeaves leaves.length) := by
  simp [getMerkleRootFromLeaves, tooMany]

theorem get_root_from_leaves_pads_to_full_width (env : HashEnv L D) (height : Nat) (leaves : List L)
    (fits : leaves.length ≤ 2 ^ height) :
    (leaves ++ List.replicate (2 ^ height - leaves.length) env.emptyLeaf).length = 2 ^ height := by
  simp only [List.length_append, List.length_replicate]
  generalize 2 ^ height = width at fits ⊢
  omega

theorem get_root_from_leaves_succeeds_when_it_fits (env : HashEnv L D) (height : Nat)
    (leaves : List L) (fits : leaves.length ≤ 2 ^ height) :
    ∃ r, getMerkleRootFromLeaves env height leaves = .ok r := by
  have hnot : ¬ (leaves.length > 2 ^ height) := by omega
  simp only [getMerkleRootFromLeaves, if_neg hnot]
  exact full_leaves_never_reports_not_power_of_two env height _
    (get_root_from_leaves_pads_to_full_width env height leaves fits)

/-- When the leaf count already fills the tree, the circuit path performs no extension and agrees
with the native path exactly. -/
theorem circuit_root_matches_native_at_full_width (env : HashEnv L D) (height : Nat)
    (leaves : List L) (fits : leaves.length ≤ 2 ^ height) :
    circuitRootFromLeaves env height height leaves = getMerkleRootFromLeaves env height leaves := by
  have hnot : ¬ (leaves.length > 2 ^ height) := by omega
  simp only [circuitRootFromLeaves, getMerkleRootFromLeaves, if_neg hnot, Nat.sub_self]
  cases h : getMerkleRootFromFullLeaves env height
      (leaves ++ List.replicate (2 ^ height - leaves.length) env.emptyLeaf) with
  | error e => rfl
  | ok r => simp [extendWithZeroSubtrees]

/-! ## In-circuit counterpart (`MerkleProofTarget`) -/

/-- An ARBITRARY satisfying witness of the in-circuit opening gadget — not the native builder. -/
structure TargetOpening (L D : Type) where
  leaf : L
  index : Nat
  siblings : List D
  root : D

def TargetOpening.recomputedRoot (env : HashEnv L D) (w : TargetOpening L D) : D :=
  rootFromBits env (env.leafHash w.leaf) (indexBits w.siblings.length w.index) w.siblings

/-- `builder.split_le(index, height)` range-constrains the index to `height` bits. -/
def SplitLeRange (height index : Nat) : Prop := index < 2 ^ height

/-- `MerkleProofTarget::verify`: sibling count fixed at circuit-build time, index decomposed with
`split_le`, final `connect_hash`. -/
def TargetVerify (env : HashEnv L D) (height : Nat) (w : TargetOpening L D) : Prop :=
  w.siblings.length = height ∧ SplitLeRange height w.index ∧ w.recomputedRoot env = w.root

/-- `MerkleProofTarget::conditional_verify`: the root is recomputed unconditionally, only the final
equality is gated. -/
def TargetConditionalVerify (env : HashEnv L D) (height : Nat) (condition : Bool)
    (w : TargetOpening L D) : Prop :=
  w.siblings.length = height ∧ SplitLeRange height w.index ∧
    (condition = true → w.recomputedRoot env = w.root)

/-- `MerkleProofTarget::set_witness` asserts matching sibling counts. -/
def setWitnessOk (height : Nat) (p : MerkleProof D) : Bool := p.siblings.length == height

theorem set_witness_requires_matching_height (height : Nat) (p : MerkleProof D) :
    setWitnessOk height p = true ↔ p.height = height := by
  simp [setWitnessOk, MerkleProof.height]

theorem target_verify_fixes_sibling_count (env : HashEnv L D) (height : Nat)
    (w : TargetOpening L D) (sat : TargetVerify env height w) : w.siblings.length = height := sat.1

/-- An arbitrary satisfying in-circuit witness yields a natively verifying opening. -/
theorem target_verify_implies_native_verify [DecidableEq D] (env : HashEnv L D) (height : Nat)
    (w : TargetOpening L D) (sat : TargetVerify env height w) :
    (MerkleProof.mk w.siblings).verify env w.leaf w.index w.root = .ok () := by
  refine (merkle_proof_verify_ok_iff_root_matches env ⟨w.siblings⟩ w.leaf w.index w.root).mpr ?_
  simpa [MerkleProof.getRoot, MerkleProof.height, TargetOpening.recomputedRoot] using sat.2.2

theorem target_verify_true_condition_is_verify (env : HashEnv L D) (height : Nat)
    (w : TargetOpening L D) :
    TargetConditionalVerify env height true w ↔ TargetVerify env height w := by
  simp [TargetConditionalVerify, TargetVerify]

/-- With the condition false, the gadget places NO constraint on the claimed root: any root at all
satisfies it. -/
theorem conditional_verify_false_does_not_bind_root (env : HashEnv L D) (height : Nat)
    (w : TargetOpening L D) (len : w.siblings.length = height) (rng : SplitLeRange height w.index)
    (anyRoot : D) :
    TargetConditionalVerify env height false { w with root := anyRoot } := by
  exact ⟨len, rng, by intro h; exact absurd h (by simp)⟩

/-- The in-circuit range check rules out exactly the shifted index the native path accepts. -/
theorem circuit_range_check_rejects_shifted_index (height index : Nat) :
    ¬ SplitLeRange height (index + 2 ^ height) := by
  simp only [SplitLeRange, Nat.not_lt]
  exact Nat.le_add_left _ _

/-! ## A concrete non-vacuous trace -/

/-- A deliberately weak, fully computable hash environment: it is NOT collision free, which is the
point — the model never assumes it is. -/
def toyEnv : HashEnv Nat Nat where
  emptyLeaf := 0
  leafHash := fun x => x + 5
  twoToOne := fun a b => 2 * a + 3 * b + 1
  zeroDigest := 0

theorem toy_update_prove_get_root_roundtrip :
    (((MerkleTree.new toyEnv 2).updateLeaf toyEnv 3 (toyEnv.leafHash 7)).prove toyEnv 3).getRoot
        toyEnv 7 3
      = ((MerkleTree.new toyEnv 2).updateLeaf toyEnv 3 (toyEnv.leafHash 7)).getRoot toyEnv := by
  decide

theorem toy_update_prove_verify_accepts :
    (((MerkleTree.new toyEnv 2).updateLeaf toyEnv 3 (toyEnv.leafHash 7)).prove toyEnv 3).verify
        toyEnv 7 3 (((MerkleTree.new toyEnv 2).updateLeaf toyEnv 3 (toyEnv.leafHash 7)).getRoot toyEnv)
      = .ok () :=
  (merkle_proof_verify_ok_iff_root_matches toyEnv _ 7 3 _).mpr toy_update_prove_get_root_roundtrip

theorem toy_update_changes_the_root :
    ((MerkleTree.new toyEnv 2).updateLeaf toyEnv 3 (toyEnv.leafHash 7)).getRoot toyEnv
      ≠ (MerkleTree.new toyEnv 2).getRoot toyEnv := by
  decide

/-- The dummy proof is NOT an opening of the empty tree: its siblings are `HashOut::default()`,
not the zero-subtree hashes. -/
theorem dummy_proof_is_not_an_empty_tree_opening :
    (MerkleProof.dummy toyEnv 1).getRoot toyEnv toyEnv.emptyLeaf 0
      ≠ (MerkleTree.new toyEnv 1).getRoot toyEnv := by
  decide

/-- The same-index hypothesis of the collision-premise theorem is NECESSARY: with the hash opaque,
the same siblings at different index bits can map different leaves to the same root. -/
theorem same_index_hypothesis_is_necessary :
    ∃ (a b : Nat) (bitsA bitsB : List Bool) (siblings : List Nat),
      a ≠ b ∧ bitsA ≠ bitsB ∧
        rootFromBits toyEnv a bitsA siblings = rootFromBits toyEnv b bitsB siblings :=
  ⟨3, 2, [false], [true], [0], by decide, by decide, by decide⟩

/-- The native and circuit padding strategies agree on a concrete sub-power-of-two instance
(2 leaves into a height-3 tree). -/
theorem circuit_padding_matches_native_on_example :
    circuitRootFromLeaves toyEnv 1 3 [11, 13] = getMerkleRootFromLeaves toyEnv 3 [11, 13] := by
  rfl

end Zkp.Implementation.MerkleTrees
