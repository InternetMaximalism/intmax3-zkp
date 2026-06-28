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

  SECURITY: inclusion soundness rests on (a) Poseidon collision
  resistance — stated as `Bytes.PoseidonCR`, NOT assumed here — and
  (b) `index` being range-bound to `height` bits. If the index is
  NOT range-checked, the decomposition `index = Σ bit_i·2^i` admits a
  non-canonical bit string, so a prover can address a path the tree
  layout never intended (index aliasing). We therefore make the bit
  length an explicit conjunct (`bits.length = height`): a verify call
  whose caller skipped the range check cannot discharge it.
-/

namespace Zkp
namespace Merkle

open CField Builder Bytes

variable {F : Type} [CField F]

/-- 2-to-1 Poseidon compression of two digests. Uninterpreted
    (primitive out of scope); determinism suffices for the fold,
    collision resistance is `Bytes.PoseidonCR` at the use site. -/
opaque compress : HashOut F → HashOut F → HashOut F

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

end Merkle
end Zkp
