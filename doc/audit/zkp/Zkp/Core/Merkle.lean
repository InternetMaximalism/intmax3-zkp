import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Zkp.Core.Merkle
  ===============

  Semantics of the Merkle-inclusion gadget
  (`common/trees/*::MerkleProof::verify`) used pervasively: send
  tree, channel/account tree, tx tree, transfer tree, deposit tree.

  `MerkleProof::verify(builder, leaf, index, root)` asserts that
  folding `leaf`'s digest up the sibling path, branching left/right
  per the bits of `index`, reproduces `root`. In-circuit this entails:

    * decompose `index` into `height` wires, each `assert_bool`;
    * require `index == Σ bit_i · 2^i` (the decomposition gate);
    * fold with the 2-to-1 Poseidon compression `compress`;
    * `connect(recomputed_root, root)`.

  Modeling the asserted-boolean index wires as Lean `Bool` is exact:
  `assert_bool` pins each to `{0,1}`, and `Bool` is precisely that.

  SECURITY: inclusion soundness rests on (a) collision resistance of
  the 2-to-1 compression actually used by the fold — stated as
  `CompressCR` below and CONSUMED by the binding theorems
  (`fold_inj`, `merkleVerify_binding`, `pathUpdate_preserves_other`);
  the leaf-digest hash's CR is the separate `Bytes.PoseidonCR` — and
  (b) `index` being range-bound to `height` bits. If the index is
  NOT range-checked, the decomposition `index = Σ bit_i·2^i` admits a
  non-canonical bit string, so a prover can address a path the tree
  layout never intended (index aliasing). We therefore make the bit
  length an explicit conjunct (`bits.length = height`): a verify call
  whose caller skipped the range check cannot discharge it.

  SECURITY (per-call decompositions / characteristic reliance): in
  Rust, `verify` and `get_root` EACH run their own
  `split_le(index, height)` (utils/trees/merkle_tree.rs:227), i.e. two
  independent boolean decompositions of the same index wire (over ONE
  shared sibling vector — the same proof object). The circuit-level
  structures now mirror this faithfully with TWO existential bit
  lists (`SpendCircuit.DeductStep`/`SentTxRecord`,
  `UpdatePrivateState.AssetUpdate`, `UpdateUser.treeUpdate`); their
  identification — needed for any "only this leaf changed" claim — is
  proved in the consuming theorems from the named hypothesis
  `PowTwoInj F height` below (uniqueness of height-bit decompositions,
  i.e. char(F) > 2^height): true for Goldilocks
  (p = 2^64 − 2^32 + 1) for every height ≤ 63, FALSE for small-
  characteristic fields; it must be taken explicitly wherever needed
  and is never baked into a `Constraints` structure. The only
  shared-bits shape left is `PathUpdate` below — a LEMMA-level normal
  form produced from the split structures via `PowTwoInj` (e.g.
  `assetUpdate_toPathUpdate`, `deductStep_toPathUpdate`), plus the
  IndexedMerkle splice shadows, whose map-level model has no bit lists
  at all and absorbs the identification into its documented root↔map
  boundary.
-/

namespace Zkp
namespace Merkle

open CField Builder Bytes

variable {F : Type} [CField F]

/-- 2-to-1 Poseidon compression of two digests. Uninterpreted
    (primitive out of scope); determinism suffices for the fold,
    collision resistance is the named hypothesis `CompressCR` below
    (NOT `Bytes.PoseidonCR`, which is about the list-input leaf hash —
    a different opaque). -/
opaque compress : HashOut F → HashOut F → HashOut F

/-- Collision-resistance assumption for the 2-to-1 compression, stated
    as injectivity on ordered pairs — the fold-hash counterpart of
    `Bytes.PoseidonCR`, consumed by the Merkle binding theorems below.

    IDEALIZATION CAVEAT (stated honestly): literal injectivity is
    UNSATISFIABLE for a real compressing hash (domain two digests,
    range one digest — collisions exist by pigeonhole). `CompressCR`
    is the standard symbolic "no collision occurred in this
    execution" model: a theorem proved under it can only fail on a
    trace that EXHIBITS an explicit Poseidon 2-to-1 collision. It is
    a named hypothesis, never an axiom, so every consumer displays
    this trust assumption in its signature. -/
def CompressCR (F : Type) [CField F] : Prop :=
  ∀ a b a' b' : HashOut F, compress a b = compress a' b' → a = a' ∧ b = b'

/-- Fold a leaf digest up the path. `bit = false` ⇒ current node is
    the left child `compress cur sib`; `bit = true` ⇒ right child
    `compress sib cur`. LSB-first, matching the index bit order. -/
def fold (cur : HashOut F) : List Bool → List (HashOut F) → HashOut F
  | [], _ => cur
  | _, [] => cur
  | b :: bs, s :: ss =>
      fold (if b then compress s cur else compress cur s) bs ss

/-- Field value of an LSB-first bit list: `Σ bit_i · 2^i`. The
    decomposition gate constrains `index` to equal this. -/
def bitsValue : List Bool → F
  | [] => 0
  | b :: bs => (if b then (1 : F) else 0) + (1 + 1) * bitsValue bs

/-- **Named characteristic hypothesis**: `k`-bit boolean decompositions
    embed injectively into `F`. Equivalently char(F) > 2^k on the
    relevant range: two distinct length-`k` bit lists have distinct
    ℕ values `< 2^k`, so they alias in `F` iff the characteristic
    divides their difference. TRUE for Goldilocks
    (p = 2^64 − 2^32 + 1 > 2^63) for every `k ≤ 63`; FALSE for
    arbitrary fields (char 2 example, k = 2: `[true, false]` and
    `[true, true]` both evaluate to `1`). The deliberately
    char-agnostic `CField` axioms cannot prove it, so any theorem
    needing decomposition uniqueness must take it explicitly. -/
def PowTwoInj (F : Type) [CField F] (k : Nat) : Prop :=
  ∀ bits bits' : List Bool, bits.length = k → bits'.length = k →
    (bitsValue bits : F) = bitsValue bits' → bits = bits'

/-- The constraint emitted by `MerkleProof::verify`: there is a
    height-length boolean index decomposition matching `index`, and
    folding `leaf` along `siblings` reproduces `root`.

    The `bits.length = height` and `siblings.length = height`
    conjuncts encode the range-check / proof-length obligations; a
    caller that omits the index range check cannot supply them for a
    non-canonical index. -/
def MerkleVerify (height : Nat) (leaf : HashOut F) (index : F)
    (siblings : List (HashOut F)) (root : HashOut F) : Prop :=
  ∃ bits : List Bool,
    bits.length = height ∧ siblings.length = height ∧
    index = bitsValue bits ∧ fold leaf bits siblings = root

/-- `MerkleProof::conditional_verify(cond, leaf, index, root)`: the
    inclusion constraint is imposed only when boolean `cond` is `1`. -/
def CondMerkleVerify (cond : F) (height : Nat) (leaf : HashOut F) (index : F)
    (siblings : List (HashOut F)) (root : HashOut F) : Prop :=
  cond = 1 → MerkleVerify height leaf index siblings root

/-- A satisfied verify yields a concrete inclusion path reaching the
    root. This is the form downstream circuits consume to argue the
    leaf is committed under `root`. -/
theorem MerkleVerify_gives_path {height : Nat} {leaf : HashOut F}
    {index : F} {siblings : List (HashOut F)} {root : HashOut F}
    (h : MerkleVerify height leaf index siblings root) :
    ∃ bits : List Bool, bits.length = height ∧
      index = bitsValue bits ∧ fold leaf bits siblings = root := by
  obtain ⟨bits, hlen, _, hidx, hroot⟩ := h
  exact ⟨bits, hlen, hidx, hroot⟩

/-! ### Merkle binding under `CompressCR`

The theorems above only conclude "SOME leaf folds to the root". The
binding theorems below close the gap from "folds to the root" to "is
THE committed leaf": under `CompressCR`, a root determines the leaf
and the sibling path for each index. This is where the CR hypothesis
stops being decoration and becomes load-bearing. -/

/-- **Fold injectivity (same-bits binding).** Under `CompressCR`, two
    folds over the SAME index bits reaching the same value have equal
    leaves and equal sibling lists. The length hypotheses reflect the
    real proof object: `MerkleProofTarget::new` allocates exactly
    `height` siblings (utils/trees/merkle_tree.rs:174-183). -/
theorem fold_inj (hcr : CompressCR F) :
    ∀ {bits : List Bool} {sib sib' : List (HashOut F)} {leaf leaf' : HashOut F},
      sib.length = bits.length → sib'.length = bits.length →
      fold leaf bits sib = fold leaf' bits sib' →
      leaf = leaf' ∧ sib = sib' := by
  intro bits
  induction bits with
  | nil =>
      intro sib sib' leaf leaf' hs hs' h
      cases sib with
      | cons _ _ => simp at hs
      | nil =>
        cases sib' with
        | cons _ _ => simp at hs'
        | nil => exact ⟨h, rfl⟩
  | cons b bs ih =>
      intro sib sib' leaf leaf' hs hs' h
      cases sib with
      | nil => simp at hs
      | cons s ss =>
        cases sib' with
        | nil => simp at hs'
        | cons s' ss' =>
          simp only [List.length_cons] at hs hs'
          have hss : ss.length = bs.length := by omega
          have hss' : ss'.length = bs.length := by omega
          cases b with
          | false =>
              have h' : fold (compress leaf s) bs ss
                  = fold (compress leaf' s') bs ss' := h
              obtain ⟨hnode, hsibs⟩ := ih hss hss' h'
              obtain ⟨hl, hs0⟩ := hcr _ _ _ _ hnode
              exact ⟨hl, by rw [hs0, hsibs]⟩
          | true =>
              have h' : fold (compress s leaf) bs ss
                  = fold (compress s' leaf') bs ss' := h
              obtain ⟨hnode, hsibs⟩ := ih hss hss' h'
              obtain ⟨hs0, hl⟩ := hcr _ _ _ _ hnode
              exact ⟨hl, by rw [hs0, hsibs]⟩

/-- **Merkle binding (index-level).** Under `CompressCR` and
    decomposition uniqueness (`PowTwoInj F height` — needed because
    the two runs may witness a priori DIFFERENT bit lists for the same
    field index; see its docstring for why this is a genuine
    characteristic hypothesis), two accepted `MerkleVerify` runs with
    the same height, index and root bind the SAME leaf and the SAME
    sibling path. This is the "is THE committed leaf" step. -/
theorem merkleVerify_binding (hcr : CompressCR F) {height : Nat}
    (hpow : PowTwoInj F height)
    {leaf leaf' : HashOut F} {index : F}
    {sib sib' : List (HashOut F)} {root : HashOut F}
    (h : MerkleVerify height leaf index sib root)
    (h' : MerkleVerify height leaf' index sib' root) :
    leaf = leaf' ∧ sib = sib' := by
  obtain ⟨bits, hb, hsl, hiv, hf⟩ := h
  obtain ⟨bits', hb', hsl', hiv', hf'⟩ := h'
  have hbits : bits = bits' := hpow _ _ hb hb' (by rw [← hiv]; exact hiv')
  subst hbits
  exact fold_inj hcr (by omega) (by omega) (hf.trans hf'.symm)

/-- The read-then-write / shared-path update pattern: `verify` +
    `get_root` called on the SAME proof object, AFTER identifying the
    two per-call `split_le` decompositions. This is a lemma-level
    normal form, not a circuit transcription: the circuit-level
    structures (`UpdatePrivateState.AssetUpdate`,
    `SpendCircuit.DeductStep`, `UpdateUser.treeUpdate`) carry two
    independent bit lists mirroring the two Rust `split_le` calls, and
    are converted to this shape only under an explicit
    `PowTwoInj F height` hypothesis (`assetUpdate_toPathUpdate`,
    `deductStep_toPathUpdate`, or inline in the consumer). -/
def PathUpdate (height : Nat) (leafOld leafNew : HashOut F) (index : F)
    (siblings : List (HashOut F)) (rootOld rootNew : HashOut F) : Prop :=
  ∃ bits : List Bool, bits.length = height ∧ index = bitsValue bits ∧
    fold leafOld bits siblings = rootOld ∧ fold leafNew bits siblings = rootNew

/-- **Sibling-path update (core lemma).** If leaf `l` is included at
    path `obits` under a root, and the leaf at a DIFFERENT path `bits`
    is replaced (`leafOld → leafNew`, same siblings), then `l` is
    still included at `obits` under the new root, via a sibling list
    of the same length. Induction from the leaf side: if the tails
    diverge, recurse; if the tails agree, `fold_inj` pins the two
    level-1 nodes equal, the head bits must differ, and `CompressCR`
    identifies `l`'s head sibling with the OLD updated leaf — replace
    it with the NEW leaf. -/
theorem fold_update_other (hcr : CompressCR F) :
    ∀ (bits obits : List Bool) (sib osib : List (HashOut F))
      (leafOld leafNew l : HashOut F),
      obits.length = bits.length → sib.length = bits.length →
      osib.length = obits.length → bits ≠ obits →
      fold l obits osib = fold leafOld bits sib →
      ∃ osib' : List (HashOut F), osib'.length = obits.length ∧
        fold l obits osib' = fold leafNew bits sib := by
  intro bits
  induction bits with
  | nil =>
      intro obits sib osib leafOld leafNew l hlen _ _ hne _
      cases obits with
      | nil => exact absurd rfl hne
      | cons _ _ => simp at hlen
  | cons b bs ih =>
      intro obits sib osib leafOld leafNew l hlen hs hos hne h
      cases obits with
      | nil => simp at hlen
      | cons b' bs' =>
        cases sib with
        | nil => simp at hs
        | cons s ss =>
          cases osib with
          | nil => simp at hos
          | cons os oss =>
            simp only [List.length_cons] at hlen hs hos
            have hlen' : bs'.length = bs.length := by omega
            have hs' : ss.length = bs.length := by omega
            have hos' : oss.length = bs'.length := by omega
            by_cases hbs : bs = bs'
            · -- tails agree ⇒ the head bits differ; fold_inj pins the
              -- level-1 nodes and CompressCR identifies the wires.
              subst hbs
              have hbne : b ≠ b' := fun hb => hne (by rw [hb])
              cases b with
              | false =>
                  cases b' with
                  | false => exact absurd rfl hbne
                  | true =>
                      -- l sits RIGHT of its sibling; old leaf sits LEFT.
                      have h' : fold (compress os l) bs oss
                          = fold (compress leafOld s) bs ss := h
                      obtain ⟨hnode, hosseq⟩ := fold_inj hcr hos' hs' h'
                      obtain ⟨_hos0, hls⟩ := hcr _ _ _ _ hnode
                      refine ⟨leafNew :: oss, by simp only [List.length_cons]; omega, ?_⟩
                      have hgoal : fold (compress leafNew l) bs oss
                          = fold (compress leafNew s) bs ss := by
                        rw [hls, hosseq]
                      exact hgoal
              | true =>
                  cases b' with
                  | true => exact absurd rfl hbne
                  | false =>
                      -- l sits LEFT of its sibling; old leaf sits RIGHT.
                      have h' : fold (compress l os) bs oss
                          = fold (compress s leafOld) bs ss := h
                      obtain ⟨hnode, hosseq⟩ := fold_inj hcr hos' hs' h'
                      obtain ⟨hls, _hos0⟩ := hcr _ _ _ _ hnode
                      refine ⟨leafNew :: oss, by simp only [List.length_cons]; omega, ?_⟩
                      have hgoal : fold (compress l leafNew) bs oss
                          = fold (compress s leafNew) bs ss := by
                        rw [hls, hosseq]
                      exact hgoal
            · -- tails diverge ⇒ head siblings are untouched; recurse.
              have h' : fold (if b' then compress os l else compress l os) bs' oss
                  = fold (if b then compress s leafOld else compress leafOld s) bs ss := h
              obtain ⟨oss', holen, hfold⟩ := ih bs' ss oss
                  (if b then compress s leafOld else compress leafOld s)
                  (if b then compress s leafNew else compress leafNew s)
                  (if b' then compress os l else compress l os)
                  hlen' hs' hos' hbs h'
              refine ⟨os :: oss', by simp only [List.length_cons]; omega, ?_⟩
              exact hfold

/-- **Update preserves other leaves.** A shared-path update at `index`
    keeps EVERY other index's inclusion proof valid: any leaf `l`
    included at `oidx ≠ index` under the old root is included — same
    leaf, same index — under the new root. Note: no `PowTwoInj` is
    needed here, because DISTINCT field indices already force distinct
    bit decompositions. -/
theorem pathUpdate_preserves_other (hcr : CompressCR F) {height : Nat}
    {leafOld leafNew : HashOut F} {index : F} {sib : List (HashOut F)}
    {rootOld rootNew : HashOut F}
    (hsl : sib.length = height)
    (hupd : PathUpdate height leafOld leafNew index sib rootOld rootNew)
    {l : HashOut F} {oidx : F} {osib : List (HashOut F)}
    (hincl : MerkleVerify height l oidx osib rootOld)
    (hne : oidx ≠ index) :
    ∃ osib', MerkleVerify height l oidx osib' rootNew := by
  obtain ⟨bits, hb, hiv, hfo, hfn⟩ := hupd
  obtain ⟨obits, hob, hosl, hoiv, hof⟩ := hincl
  have hbne : bits ≠ obits := by
    intro he
    apply hne
    rw [hoiv, hiv, he]
  obtain ⟨osib', holen, hfold⟩ :=
    fold_update_other hcr bits obits sib osib leafOld leafNew l
      (by omega) (by omega) (by omega) hbne (hof.trans hfo.symm)
  exact ⟨osib', obits, hob, by omega, hoiv, by rw [hfold]; exact hfn⟩

end Merkle
end Zkp
