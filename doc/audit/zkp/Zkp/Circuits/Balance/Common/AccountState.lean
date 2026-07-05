import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Account state: nested Merkle membership
  =======================================

  Source: `src/circuits/balance/common/account_state.rs`

  ## Protocol role

  `AccountState` proves a user's *send leaf* is committed under the
  global `account_tree_root` via a TWO-level Merkle path:

    1. `send_leaf` is included at `send_leaf_index` under
       `channel_leaf.send_tree_root`               (SEND_TREE_HEIGHT)
    2. `channel_leaf` is included at `channel_id` under
       `account_tree_root`                          (CHANNEL_TREE_HEIGHT)

  This is what binds "this user (channel_id) has this send history
  (send_leaf)" to the block-level account root the validity proof
  attests. The send leaf in turn anchors the nullifier / spend logic.

  ## Constraint inventory (account_state.rs)

  | line      | gate                                   | meaning                          |
  |-----------|----------------------------------------|----------------------------------|
  | :110      | `ChannelIdTarget::new(.., is_checked)` | channel_id range-checked iff checked |
  | :115-117  | `range_check(send_leaf_index, H_send)` | index canonical iff is_checked   |
  | :123-128  | `send_merkle_proof.verify`             | level-1 inclusion                |
  | :130-135  | `user_merkle_proof.verify`             | level-2 inclusion                |

  Native `verify()` (:68-87) performs the identical two checks.
-/

namespace Zkp
namespace Circuits.AccountState

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

/-- Tree heights (constants; values irrelevant to the binding logic,
    only that the same height bounds index decomposition each side). -/
def SEND_TREE_HEIGHT : Nat := 32
def CHANNEL_TREE_HEIGHT : Nat := 32

/-- The two membership constraints emitted for an `AccountStateTarget`
    when `is_checked = true` (indices range-checked). Leaves are
    referenced by their digests; the channel leaf carries the
    `send_tree_root` used as the level-1 root. -/
def AccountStateConstraints
    (channelId : F)
    (accountTreeRoot : HashOut F)
    (sendLeaf : HashOut F) (sendLeafIndex : F) (sendSiblings : List (HashOut F))
    (channelLeaf : HashOut F) (sendTreeRoot : HashOut F)
    (userSiblings : List (HashOut F)) : Prop :=
  -- level 1: send_leaf ∈ channel_leaf.send_tree_root
  MerkleVerify SEND_TREE_HEIGHT sendLeaf sendLeafIndex sendSiblings sendTreeRoot
  -- level 2: channel_leaf ∈ account_tree_root, addressed by channel_id
  ∧ MerkleVerify CHANNEL_TREE_HEIGHT channelLeaf channelId userSiblings accountTreeRoot

/-- **Soundness.** A satisfying witness yields BOTH inclusion paths:
    a canonical-length path from `send_leaf` to `send_tree_root`, and
    one from `channel_leaf` to `account_tree_root` addressed by
    `channel_id`. Combined with Poseidon CR (named at the use site)
    and the channel leaf binding `send_tree_root`, this transitively
    commits `send_leaf` under `account_tree_root` at `channel_id`. -/
theorem accountState_sound
    {channelId : F} {accountTreeRoot sendLeaf : HashOut F} {sendLeafIndex : F}
    {sendSiblings : List (HashOut F)} {channelLeaf sendTreeRoot : HashOut F}
    {userSiblings : List (HashOut F)}
    (h : AccountStateConstraints channelId accountTreeRoot sendLeaf
          sendLeafIndex sendSiblings channelLeaf sendTreeRoot userSiblings) :
    (∃ bits, bits.length = SEND_TREE_HEIGHT ∧ sendLeafIndex = bitsValue bits ∧
        fold sendLeaf bits sendSiblings = sendTreeRoot)
    ∧ (∃ bits, bits.length = CHANNEL_TREE_HEIGHT ∧ channelId = bitsValue bits ∧
        fold channelLeaf bits userSiblings = accountTreeRoot) := by
  obtain ⟨h1, h2⟩ := h
  exact ⟨MerkleVerify_gives_path h1, MerkleVerify_gives_path h2⟩

/-!
  ## SECURITY OBSERVATION — `is_checked` gates the index range checks

  `account_state.rs:115` only emits `range_check(send_leaf_index,
  SEND_TREE_HEIGHT)` when `is_checked = true`; likewise `channel_id`
  is range-checked inside `ChannelIdTarget::new` only when checked.

  In our model the range check is what licenses the
  `bits.length = height` conjunct of `MerkleVerify`. With
  `is_checked = false` and no caller-side range check, `index` could
  exceed `2^height`, so the in-circuit decomposition need not be the
  canonical one — `index` and `index + 2^height` (mod p) would address
  the same path, an **index-aliasing** soundness hole IF such a leaf
  position is security-relevant (e.g. nullifier slot).

  This is NOT a finding by itself: every *caller* in scope must invoke
  `AccountStateTarget::new` with `is_checked = true` for prover-
  supplied witnesses. Action item F-ACCT-1: confirm all in-scope
  constructions pass `is_checked = true` (or feed a value already
  range-bound upstream). Tracked in tasks/todo.md.
-/

end Circuits.AccountState
end Zkp
