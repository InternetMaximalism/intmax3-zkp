import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle
import Zkp.Core.U256

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

/-- `NullifierInsertionProof::get_new_root`: from `prevRoot`, inserting
    `nullifier` — which the indexed-tree non-membership proof shows was
    ABSENT — yields `newRoot`. Absence is what guarantees spend-once.
    Modeled opaquely here; its non-membership enforcement must be
    verified when `indexed_merkle_tree` is modeled (item F-NULL-1). -/
opaque NullifierInsert {F : Type} [CField F] :
    HashOut F → Bytes32 F → HashOut F → Prop

/-- Asset read-then-write along a SINGLE shared Merkle path: the same
    `bits`/`sib` witness both the old leaf under `prevRoot` and the new
    leaf under `newRoot`. This couples the two roots so that ONLY the
    `tokenIndex` leaf can differ between them. -/
def AssetUpdate (prevRoot newRoot : HashOut F) (prevBalance newLeaf : U256 F)
    (tokenIndex : F) (sib : List (HashOut F)) : Prop :=
  ∃ bits : List Bool, bits.length = ASSET_TREE_HEIGHT ∧
    tokenIndex = bitsValue bits ∧
    fold (u256Leaf prevBalance) bits sib = prevRoot ∧
    fold (u256Leaf newLeaf) bits sib = newRoot

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
    * inserts the nullifier (spend-once, modulo F-NULL-1);
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

/-!
  ## SECURITY OBSERVATIONS

  * **F-NULL-1 (dependency).** Spend-once rests entirely on
    `NullifierInsert` proving the nullifier was ABSENT before insert.
    If the indexed-tree gadget's non-membership check is weak (e.g.
    accepts a low-leaf that doesn't actually bracket the key, or skips
    the range comparison), the SAME transfer/deposit could be credited
    twice. Must be discharged when modeling `indexed_merkle_tree.rs`.

  * **Single-leaf guarantee.** `AssetUpdate` shares one `bits`/`sib`
    witness across both folds, so old/new roots can differ ONLY in the
    `token_index` leaf. This is the formal reason the credit cannot
    silently rewrite OTHER token balances — provided `asset_merkle_proof`
    is the same object for both `verify` and `get_root` (it is:
    `:144` and `:153` use `asset_merkle_proof`).

  * **No-wrap.** `credit_strictly_increases` is the machine-checked
    statement that balance inflation via U256 overflow is impossible,
    given the `connect_u32(carry, zero)` gate (Core/U256.lean).
-/

end Circuits.UpdatePrivateState
end Zkp
