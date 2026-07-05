import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle
import Zkp.Core.U256
import Zkp.Core.IndexedMerkle

/-
  Private-state transition (asset credit)  — CRITICAL
  ===================================================

  Source: `src/circuits/balance/common/update_private_state.rs`

  ## Protocol role

  Applies ONE incoming credit (a received transfer or deposit) to the
  user's private state. It must, atomically:

    1. **Spend-once**: insert the credit's `nullifier` into the
       nullifier tree — provably absent beforehand — so the same
       transfer/deposit can never be credited twice.
    2. **Read** the current balance `prev_balance` at `token_index`
       from the asset tree (`asset_merkle_proof.verify`).
    3. **Credit**: `new_balance = prev_balance + amount`, overflow-
       rejected (see `U256.AddSpec`).
    4. **Write** the new balance back, changing ONLY that one leaf
       (`get_root` reuses the same proof + index).
    5. **Link** the IVC chain: `new.prev_private_commitment =
       commitment(prev_private_state)`, all other fields carried over.

  A flaw here is directly fund-affecting: skipping (1) ⇒ double-spend;
  wrapping (3) ⇒ balance inflation; changing more than the indexed
  leaf in (4) ⇒ silent balance edits elsewhere.

  ## Constraint inventory (update_private_state.rs:119-162)

  | line     | gate                                       | step |
  |----------|--------------------------------------------|------|
  | :127-129 | `range_check(token_index, TOKEN_INDEX_BITS=32)` iff checked | 2/4 index canonical |
  | :138-142 | `nullifier_proof.get_new_root` → new_null_root | 1 |
  | :144-149 | `asset_merkle_proof.verify(prev_balance, idx, prev_asset_root)` | 2 |
  | :151     | `new_asset_leaf = prev_balance.add(amount)` | 3 |
  | :152-153 | `asset_merkle_proof.get_root(new_asset_leaf, idx)` | 4 |
  | :155-162 | construct `new_private_state`               | 5 |

  ASSET_TREE_HEIGHT = TOKEN_INDEX_BITS = 32 ⇒ the index range check
  exactly bounds the tree index (no aliasing; cf. F-ACCT-1 caveat).
-/

namespace Zkp
namespace Circuits.UpdatePrivateState

open CField Builder Bytes Merkle U256

variable {F : Type} [CField F]

def ASSET_TREE_HEIGHT : Nat := 32

/-- The six-field private state (`private_state.rs`). Concrete so we
    can express the new-state construction and field carry-over. -/
structure PrivateState (F : Type) where
  assetTreeRoot : HashOut F
  nullifierTreeRoot : HashOut F
  sentTxTreeRoot : HashOut F
  prevPrivateCommitment : HashOut F
  nonce : F
  salt : F

/-- `PrivateState::commitment` (Poseidon over all fields). -/
opaque commitment {F : Type} [CField F] : PrivateState F → HashOut F

/-- The Poseidon Merkle root committing to a nullifier-tree leaf map.
    Opaque: the audit reasons at the leaf-map level (see the root↔map
    modeling boundary in Core/IndexedMerkle.lean). -/
opaque nullifierRoot {F : Type} [CField F] : IndexedMerkle.Tree → HashOut F

/-- The U256 key value of a nullifier: `Bytes32Target` reinterpreted
    limb-for-limb via `U256Target::from_slice`
    (nullifier_tree.rs:134-140). Opaque repacking, like
    `Bytes.fromHashOut`. -/
opaque nullifierKey {F : Type} [CField F] : Bytes32 F → Nat

/-- `NullifierInsertionProofTarget::get_new_root`
    (nullifier_tree.rs:121-141 → `IndexedInsertionProofTarget::
    get_new_root`, insertion.rs:271-321): the roots commit to leaf maps
    related by ONE circuit-accepted insertion of the nullifier's key
    with `value = zero` (nullifier_tree.rs:134,138). No longer opaque:
    this is `IndexedMerkle.InsertConstraints` — the MAP-LEVEL SHADOW of
    the emitted gates (each conjunct carries its Rust citation at the
    definition, but the transcription from root-level `verify`/
    `get_root` calls to leaf-map facts goes through the root↔map
    boundary documented in Core/IndexedMerkle.lean's header:
    `Merkle.CompressCR` + `Bytes.PoseidonCR` for inclusion binding and
    `Merkle.PowTwoInj F 32` for identifying each proof object's two
    independent `split_le` decompositions — it is NOT a gate-for-gate
    equality). The spend-once consequence is
    `nullifierInsert_spend_once` below; F-NULL-1's preservation
    induction lives in Core/IndexedMerkle.lean (`genesis_inv`,
    `insert_preserves_inv`, `reachable_inv`). -/
def NullifierInsert {F : Type} [CField F]
    (prevRoot : HashOut F) (nullifier : Bytes32 F) (newRoot : HashOut F) : Prop :=
  ∃ (T T' : IndexedMerkle.Tree) (low : IndexedMerkle.Leaf) (lowIdx newIdx : Nat),
    nullifierRoot T = prevRoot ∧
    nullifierRoot T' = newRoot ∧
    IndexedMerkle.InsertConstraints T low lowIdx newIdx (nullifierKey nullifier) 0 T'

/-- **Spend-once, unfolded (F-NULL-1 binding).** Any satisfied
    `NullifierInsert` exhibits pre/post leaf maps committed by the two
    roots such that: if the pre-tree satisfies the linked-list
    invariant, the nullifier's key was ABSENT and the post-tree keeps
    the invariant; and circuit-reachability is carried one step
    forward. Chained from the genesis root (the private state's
    initial `nullifier_tree_root` is `NullifierTree::init()` =
    `IndexedMerkle.genesisTree`, nullifier_tree.rs:36-38) this yields,
    via `IndexedMerkle.reachable_inv`, absence on EVERY tree the
    balance IVC chain can reach — the same nullifier is never credited
    twice. -/
theorem nullifierInsert_spend_once {F : Type} [CField F]
    {prevRoot newRoot : HashOut F} {nullifier : Bytes32 F}
    (h : NullifierInsert prevRoot nullifier newRoot) :
    ∃ T T' : IndexedMerkle.Tree,
      nullifierRoot T = prevRoot ∧ nullifierRoot T' = newRoot ∧
      (IndexedMerkle.Inv T → ¬ IndexedMerkle.present T (nullifierKey nullifier)) ∧
      (IndexedMerkle.Inv T → IndexedMerkle.Inv T') ∧
      (IndexedMerkle.Reachable T → IndexedMerkle.Reachable T') := by
  obtain ⟨T, T', low, lowIdx, newIdx, hprev, hnew, hc⟩ := h
  exact ⟨T, T', hprev, hnew,
    fun hInv => IndexedMerkle.key_absent hInv hc,
    fun hInv => IndexedMerkle.insert_preserves_inv hInv hc,
    fun hr => IndexedMerkle.Reachable.insert hr hc⟩

/-- **Named root↔map binding hypothesis** for the nullifier tree,
    stated HONESTLY over the root's support. The real root is a
    height-`NULLIFIER_TREE_HEIGHT = 32` Poseidon Merkle root
    (constants.rs:38): it is a function of the `2^32` slots
    `[0, 2^32)` ONLY, while the model's `Tree = Nat → Leaf` extends
    past them. The previous formulation
    (`nullifierRoot T = nullifierRoot T' → T = T'`) was therefore
    FALSE-BY-TRUNCATION even for a collision-free hash: two maps
    differing only at a slot `≥ 2^32` have literally identical roots.
    The two fields below are the honest split:

    * `binds` — equal roots force agreement ON THE SUPPORT
      `[0, 2^32)`. This is the root-level instance of the
      collision-resistance idealization (`Merkle.CompressCR` style):
      literal injectivity-on-support is still unsatisfiable by
      pigeonhole for a compressing hash, so read it as the symbolic
      "the root binds one committed slot assignment and no collision
      occurred in this execution" assumption — a named hypothesis,
      never an axiom.
    * `supp` — the root DEPENDS ONLY on the support: maps agreeing on
      `[0, 2^32)` have equal roots. This direction is unconditionally
      true of the real height-32 root (it never reads other slots)
      and is what lets reachability transport survive the bounded
      `binds` (see `nullifierInsert_reachable_chain`).

    Together they close the gap the meta-audit flagged: without
    `binds`, the existential trees inside `NullifierInsert` are
    unmoored from the reachability chain (`nullifierInsert_spend_once`
    only says "SOME tree with this root", not "THE tree the IVC chain
    built"). The `InsertConstraints` index bounds
    (`lowIdxLt`/`newIdxLt`, circuit-enforced via the height-32
    `split_le` decompositions, merkle_tree.rs:227) are what keep every
    fact the chain needs inside the support. -/
structure NullifierRootBinding (F : Type) [CField F] : Prop where
  binds : ∀ T T' : IndexedMerkle.Tree,
    nullifierRoot (F := F) T = nullifierRoot (F := F) T' →
    ∀ i, i < 2 ^ 32 → T i = T' i
  supp : ∀ T T' : IndexedMerkle.Tree,
    (∀ i, i < 2 ^ 32 → T i = T' i) →
    nullifierRoot (F := F) T = nullifierRoot (F := F) T'

/-- **Spend-once, chained at the ROOT level (consumes the binding).**
    If the previous root is the root of a circuit-reachable tree, then
    any accepted `NullifierInsert` (i) proves the nullifier's key was
    absent in THAT tree — not merely in some tree sharing the root —
    and (ii) hands reachability to a tree committing to the new root,
    so the argument composes along the whole IVC chain from
    `NullifierTree::init()`'s genesis root.

    Proof route under the BOUNDED binding: `binds` only yields
    support-agreement between the witness tree `T` and `Tr`, so the
    insertion is REPLAYED on `Tr` — every `InsertConstraints` field
    transfers because the circuit-enforced index bounds
    (`lowIdxLt`/`newIdxLt`) keep `lowIncl`/`emptySlot` inside the
    support; absence then comes from `reachable_key_absent` on `Tr`
    itself (over ALL slots — reachable trees are empty off-support
    anyway, since inserts only write bounded indices), and `supp`
    transports the committed `newRoot` to the replayed post-tree.
    This is the lemma that makes `NullifierRootBinding` load-bearing
    rather than decorative. -/
theorem nullifierInsert_reachable_chain {F : Type} [CField F]
    (hbind : NullifierRootBinding F)
    {prevRoot newRoot : HashOut F} {nullifier : Bytes32 F}
    {Tr : IndexedMerkle.Tree}
    (hreach : IndexedMerkle.Reachable Tr)
    (hroot : nullifierRoot (F := F) Tr = prevRoot)
    (h : NullifierInsert prevRoot nullifier newRoot) :
    ¬ IndexedMerkle.present Tr (nullifierKey nullifier)
    ∧ ∃ T' : IndexedMerkle.Tree,
        IndexedMerkle.Reachable T' ∧ nullifierRoot (F := F) T' = newRoot := by
  obtain ⟨T, T', low, lowIdx, newIdx, hprev, hnew, hc⟩ := h
  -- bounded binding: T and Tr agree on the root's support [0, 2^32)
  have hagree : ∀ i, i < 2 ^ 32 → T i = Tr i :=
    hbind.binds T Tr (by rw [hprev, hroot])
  -- replay the accepted insertion ON Tr: every constraint transfers
  -- because the circuit-enforced index bounds keep it in the support.
  have hcTr : IndexedMerkle.InsertConstraints Tr low lowIdx newIdx
      (nullifierKey nullifier) 0
      (IndexedMerkle.Tree.update
        (IndexedMerkle.Tree.update Tr lowIdx
          (IndexedMerkle.spliceLow low (nullifierKey nullifier) newIdx))
        newIdx (IndexedMerkle.insLeaf low (nullifierKey nullifier) 0)) :=
    { keyRange := hc.keyRange
      lowBound := hc.lowBound
      upBound := hc.upBound
      lowIncl := by rw [← hagree lowIdx hc.lowIdxLt]; exact hc.lowIncl
      emptySlot := by
        show (if newIdx = lowIdx then _ else Tr newIdx) = IndexedMerkle.emptyLeaf
        rw [if_neg (IndexedMerkle.newIdx_ne_lowIdx hc),
          ← hagree newIdx hc.newIdxLt]
        exact IndexedMerkle.slot_was_empty hc
      post := rfl
      lowIdxLt := hc.lowIdxLt
      newIdxLt := hc.newIdxLt }
  refine ⟨IndexedMerkle.reachable_key_absent hreach hcTr,
    _, IndexedMerkle.Reachable.insert hreach hcTr, ?_⟩
  -- the replayed post-tree agrees with T' on the support, so `supp`
  -- transports the committed new root to it.
  have hagree' : ∀ i, i < 2 ^ 32 →
      IndexedMerkle.Tree.update
        (IndexedMerkle.Tree.update Tr lowIdx
          (IndexedMerkle.spliceLow low (nullifierKey nullifier) newIdx))
        newIdx (IndexedMerkle.insLeaf low (nullifierKey nullifier) 0) i
      = T' i := by
    intro i hi
    rw [hc.post]
    show (if i = newIdx then _ else if i = lowIdx then _ else Tr i)
      = (if i = newIdx then _ else if i = lowIdx then _ else T i)
    by_cases h1 : i = newIdx
    · rw [if_pos h1, if_pos h1]
    · rw [if_neg h1, if_neg h1]
      by_cases h2 : i = lowIdx
      · rw [if_pos h2, if_pos h2]
      · rw [if_neg h2, if_neg h2]
        exact (hagree i hi).symm
  rw [hbind.supp _ T' hagree']
  exact hnew

/-- Asset read-then-write over the SAME proof object: Rust's `verify`
    (:144-149) and `get_root` (:152-153) are both called on
    `asset_merkle_proof`, so they share ONE sibling vector (the wires
    allocated by `MerkleProofTarget::new`, merkle_tree.rs:174-183) and
    ONE `token_index` wire — but each call runs its OWN
    `split_le(token_index, 32)` (merkle_tree.rs:227), i.e. TWO
    independent boolean decompositions. The model mirrors that
    faithfully: two existential bit lists (`bitsR` for the read fold,
    `bitsW` for the write fold), each equal to the index wire's value,
    over the shared `sib`. Their identification (`bitsR = bitsW`) is
    NOT baked in — it is proved in the consuming theorems from the
    named characteristic hypothesis `Merkle.PowTwoInj F 32`
    (Goldilocks-true; see Core/Merkle.lean), via
    `assetUpdate_toPathUpdate` below. -/
def AssetUpdate (prevRoot newRoot : HashOut F) (prevBalance newLeaf : U256 F)
    (tokenIndex : F) (sib : List (HashOut F)) : Prop :=
  (∃ bitsR : List Bool, bitsR.length = ASSET_TREE_HEIGHT ∧
    tokenIndex = bitsValue bitsR ∧
    fold (u256Leaf prevBalance) bitsR sib = prevRoot)
  ∧ (∃ bitsW : List Bool, bitsW.length = ASSET_TREE_HEIGHT ∧
    tokenIndex = bitsValue bitsW ∧
    fold (u256Leaf newLeaf) bitsW sib = newRoot)

/-- Under `PowTwoInj F 32`, the two independent decompositions of the
    one `token_index` wire coincide (both equal `bitsValue⁻¹` of the
    same field value at length 32), collapsing `AssetUpdate` to the
    shared-path `Merkle.PathUpdate` shape the CR theorems consume. -/
theorem assetUpdate_toPathUpdate (hpow : PowTwoInj F ASSET_TREE_HEIGHT)
    {prevRoot newRoot : HashOut F} {prevBalance newLeaf : U256 F}
    {tokenIndex : F} {sib : List (HashOut F)}
    (h : AssetUpdate prevRoot newRoot prevBalance newLeaf tokenIndex sib) :
    PathUpdate ASSET_TREE_HEIGHT (u256Leaf prevBalance) (u256Leaf newLeaf)
      tokenIndex sib prevRoot newRoot := by
  obtain ⟨⟨bitsR, hbR, hivR, hfR⟩, ⟨bitsW, hbW, hivW, hfW⟩⟩ := h
  have hbits : bitsR = bitsW := hpow bitsR bitsW hbR hbW (by rw [← hivR, ← hivW])
  exact ⟨bitsR, hbR, hivR, hfR, by rw [hbits]; exact hfW⟩

/-- Constraints emitted by `UpdatePrivateStateTarget::new`. -/
structure Constraints (prev new : PrivateState F)
    (amount prevBalance newLeaf : U256 F)
    (nullifier : Bytes32 F) (tokenIndex : F)
    (sib : List (HashOut F)) (newNullRoot : HashOut F) : Prop where
  /-- step 1: nullifier inserted (absent before) -/
  nullIns : NullifierInsert prev.nullifierTreeRoot nullifier newNullRoot
  /-- steps 2&4: shared-path asset read+write -/
  asset : AssetUpdate prev.assetTreeRoot new.assetTreeRoot prevBalance newLeaf tokenIndex sib
  /-- step 3: credit, overflow-rejected -/
  credit : AddSpec prevBalance amount newLeaf
  /-- step 5: new state field bindings -/
  eNull   : new.nullifierTreeRoot = newNullRoot
  eSent   : new.sentTxTreeRoot = prev.sentTxTreeRoot
  eCommit : new.prevPrivateCommitment = commitment prev
  eNonce  : new.nonce = prev.nonce
  eSalt   : new.salt = prev.salt

/-- **Soundness.** Any accepted transition:
    * inserts the nullifier (spend-once via
      `nullifierInsert_spend_once` + the F-NULL-1 induction in
      Core/IndexedMerkle.lean);
    * sets the new balance to the EXACT sum `prev_balance + amount`
      with no wraparound, and (when `amount>0`) strictly increases it;
    * changes only the `token_index` asset leaf — old and new asset
      roots share one Merkle path;
    * carries over nonce/salt/sent-tx unchanged and links the IVC chain
      via `prev_private_commitment = commitment(prev)`. -/
theorem updatePrivateState_sound
    {prev new : PrivateState F} {amount prevBalance newLeaf : U256 F}
    {nullifier : Bytes32 F} {tokenIndex : F} {sib : List (HashOut F)}
    {newNullRoot : HashOut F}
    (h : Constraints prev new amount prevBalance newLeaf nullifier tokenIndex sib newNullRoot) :
    NullifierInsert prev.nullifierTreeRoot nullifier new.nullifierTreeRoot
    ∧ uval newLeaf = uval prevBalance + uval amount
    ∧ AssetUpdate prev.assetTreeRoot new.assetTreeRoot prevBalance newLeaf tokenIndex sib
    ∧ new.sentTxTreeRoot = prev.sentTxTreeRoot
    ∧ new.nonce = prev.nonce ∧ new.salt = prev.salt
    ∧ new.prevPrivateCommitment = commitment prev := by
  refine ⟨?_, ?_, h.asset, h.eSent, h.eNonce, h.eSalt, h.eCommit⟩
  · rw [h.eNull]; exact h.nullIns
  · exact add_no_wrap h.credit

/-- Corollary: a credit of a positive amount strictly increases the
    written balance — no overflow can wrap it down. -/
theorem credit_strictly_increases
    {prev new : PrivateState F} {amount prevBalance newLeaf : U256 F}
    {nullifier : Bytes32 F} {tokenIndex : F} {sib : List (HashOut F)}
    {newNullRoot : HashOut F}
    (h : Constraints prev new amount prevBalance newLeaf nullifier tokenIndex sib newNullRoot)
    (hpos : 0 < uval amount) :
    uval prevBalance < uval newLeaf :=
  add_strict_mono h.credit hpos

/-! ### The single-leaf guarantee, made a theorem (CompressCR plumbed)

The docstring claim "only the indexed leaf changes" was previously
re-emitted as the `AssetUpdate` witness without a proof of its
consequence. The two theorems below state it as actual binding facts,
consuming `Merkle.CompressCR` (and, where two independent decompositions
must be identified, `Merkle.PowTwoInj`). The `sib.length =
ASSET_TREE_HEIGHT` hypothesis is a fact of the real proof object:
`MerkleProofTarget::new` allocates exactly `height` siblings
(utils/trees/merkle_tree.rs:174-183). -/

/-- **Other leaves survive the credit.** Under `CompressCR` (plus
    `PowTwoInj F 32` to identify the read/write decompositions of the
    one index wire — see `assetUpdate_toPathUpdate`), the asset
    read-then-write at `tokenIndex` leaves every OTHER index's
    inclusion proof valid: a leaf `l` included at `oidx ≠ tokenIndex`
    under the old asset root is still included — same leaf, same
    index — under the new root. This is the strongest honest form of
    "the credit cannot silently rewrite other token balances"
    available from the shared-proof-object model. -/
theorem assetUpdate_preserves_other (hcr : CompressCR F)
    (hpow : PowTwoInj F ASSET_TREE_HEIGHT)
    {prevRoot newRoot : HashOut F} {prevBalance newLeaf : U256 F}
    {tokenIndex : F} {sib : List (HashOut F)}
    (hsl : sib.length = ASSET_TREE_HEIGHT)
    (h : AssetUpdate prevRoot newRoot prevBalance newLeaf tokenIndex sib)
    {l : HashOut F} {oidx : F} {osib : List (HashOut F)}
    (hincl : MerkleVerify ASSET_TREE_HEIGHT l oidx osib prevRoot)
    (hne : oidx ≠ tokenIndex) :
    ∃ osib', MerkleVerify ASSET_TREE_HEIGHT l oidx osib' newRoot :=
  pathUpdate_preserves_other hcr hsl (assetUpdate_toPathUpdate hpow h) hincl hne

/-- **The written leaf is bound.** Under `CompressCR` and 32-bit
    decomposition uniqueness (`Merkle.PowTwoInj F 32`, Goldilocks-true),
    any inclusion proof at `tokenIndex` under the NEW root can only
    open to the freshly written balance leaf — the root does not admit
    a second, different leaf at the credited index. -/
theorem assetUpdate_new_leaf_binding (hcr : CompressCR F)
    (hpow : PowTwoInj F ASSET_TREE_HEIGHT)
    {prevRoot newRoot : HashOut F} {prevBalance newLeaf : U256 F}
    {tokenIndex : F} {sib : List (HashOut F)}
    (hsl : sib.length = ASSET_TREE_HEIGHT)
    (h : AssetUpdate prevRoot newRoot prevBalance newLeaf tokenIndex sib)
    {l : HashOut F} {osib : List (HashOut F)}
    (hincl : MerkleVerify ASSET_TREE_HEIGHT l tokenIndex osib newRoot) :
    l = u256Leaf newLeaf := by
  obtain ⟨_, ⟨bitsW, hbW, hivW, hfW⟩⟩ := h
  have hver : MerkleVerify ASSET_TREE_HEIGHT (u256Leaf newLeaf) tokenIndex sib newRoot :=
    ⟨bitsW, hbW, hsl, hivW, hfW⟩
  exact (merkleVerify_binding hcr hpow hincl hver).1

/-!
  ## SECURITY OBSERVATIONS

  * **F-NULL-1 (now bound to the indexed-tree model).** Spend-once
    rests on `NullifierInsert` proving the nullifier was ABSENT before
    insert. `NullifierInsert` is no longer a propertyless opaque: it is
    defined as `IndexedMerkle.InsertConstraints` — exactly the gates
    the gadget emits — over the leaf maps the two roots commit to.
    `nullifierInsert_spend_once` then gives absence + invariant
    preservation + reachability transport, with the invariant
    established from genesis by `IndexedMerkle.genesis_inv` /
    `insert_preserves_inv` / `reachable_inv`. The root↔map
    correspondence is no longer an unnamed boundary: it is the NAMED
    hypothesis `NullifierRootBinding` — stated honestly over the
    root's `2^32`-slot support (`binds`: equal roots ⇒ agreement on
    slots `< 2^32`; `supp`: the root reads only those slots), since
    whole-map injectivity would be false-by-truncation for the real
    height-32 root — consumed by `nullifierInsert_reachable_chain`,
    which pins absence to THE reachable tree behind `prevRoot` (by
    replaying the insertion on it, using the circuit-enforced
    `lowIdxLt`/`newIdxLt` bounds) and transports reachability to the
    new root. Remaining boundary (stated, not hidden): the IVC-level
    argument that
    `prev_private_state.nullifier_tree_root` descends from
    `NullifierTree::init()`'s genesis root through this circuit only
    (the balance-processor chain binding, `prev_private_commitment`
    linkage below).

  * **Single-leaf guarantee.** `AssetUpdate` mirrors the Rust exactly:
    one shared sibling vector and index wire (`asset_merkle_proof` is
    the same object for both `verify` and `get_root` — `:144` and
    `:153`), but TWO independent `split_le` decompositions (one per
    call, merkle_tree.rs:227), carried as the `bitsR`/`bitsW`
    existentials. Their identification — and hence "old/new roots can
    differ ONLY in the `token_index` leaf" — is PROVED in the
    consumers from the named `Merkle.PowTwoInj F 32`
    (`assetUpdate_toPathUpdate`), not baked into the structure:
    `assetUpdate_preserves_other` (every other index's inclusion proof
    stays valid, under `Merkle.CompressCR` + `PowTwoInj`) and
    `assetUpdate_new_leaf_binding` (the new root opens at `token_index`
    only to the written balance, under `CompressCR` + `PowTwoInj`).

  * **No-wrap.** `credit_strictly_increases` is the machine-checked
    statement that balance inflation via U256 overflow is impossible,
    given the `connect_u32(carry, zero)` gate (Core/U256.lean).
-/

end Circuits.UpdatePrivateState
end Zkp
