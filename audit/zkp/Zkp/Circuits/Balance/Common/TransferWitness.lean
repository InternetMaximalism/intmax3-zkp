import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Transfer membership witness
  ===========================

  Source: `src/circuits/balance/common/transfer_witness.rs`

  ## Protocol role

  Proves a single `Transfer` is committed at `transfer_index` under a
  given `transfer_tree_root` (a tx's transfer tree, height 6 ⇒ ≤ 64
  transfers per tx). This is the leaf gadget that lets send/receive
  circuits reference an individual transfer inside a tx without
  unpacking the whole tree.

  ## Constraint inventory (transfer_witness.rs:72-101)

  | line     | gate                                  | meaning                       |
  |----------|---------------------------------------|-------------------------------|
  | :83-85   | `range_check(transfer_index, H)` (iff is_checked) | index canonical    |
  | :88-93   | `transfer_merkle_proof.verify`        | inclusion under the root      |
-/

namespace Zkp
namespace Circuits.TransferWitness

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

/-- `TRANSFER_TREE_HEIGHT = 6` (`constants.rs:71`). -/
def TRANSFER_TREE_HEIGHT : Nat := 6

/-- A transfer (abstract); `transferLeaf` is its Poseidon leaf digest. -/
opaque Transfer : Type → Type
opaque transferLeaf {F : Type} [CField F] : Transfer F → HashOut F

/-- Constraints emitted by `TransferWitnessTarget::new`. -/
def Constraints (transfer : Transfer F) (transferIndex : F)
    (sib : List (HashOut F)) (root : HashOut F) : Prop :=
  MerkleVerify TRANSFER_TREE_HEIGHT (transferLeaf transfer) transferIndex sib root

/-- **Soundness.** Acceptance yields a canonical-length inclusion path
    from this transfer's digest to `root` at `transfer_index`. -/
theorem transferWitness_sound {transfer : Transfer F} {transferIndex : F}
    {sib : List (HashOut F)} {root : HashOut F}
    (h : Constraints transfer transferIndex sib root) :
    ∃ bits, bits.length = TRANSFER_TREE_HEIGHT ∧
      transferIndex = bitsValue bits ∧
      fold (transferLeaf transfer) bits sib = root :=
  MerkleVerify_gives_path h

-- Same `is_checked`-gated range-check note as F-ACCT-1 applies to
-- `transfer_index` (transfer_witness.rs:83). Callers in scope must
-- pass is_checked = true; tracked under F-ACCT-1.

end Circuits.TransferWitness
end Zkp
