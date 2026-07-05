import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle
import Zkp.Circuits.Balance.Common.Recipient

/-
  Deposit membership + ownership witness
  ======================================

  Source: `src/circuits/balance/common/deposit_witness.rs`

  ## Protocol role

  Proves TWO things about a deposit the user wants to credit:

    1. **Membership**: `deposit` is committed at `deposit.deposit_index`
       under `deposit_tree_root` (the L1 deposit tree, height 63).
    2. **Ownership**: `deposit.recipient` equals the USER_ID recipient
       derived from `(channel_id, deposit_salt)` — so only the holder
       of the channel_id/salt preimage can claim it.

  Without (2) any prover could credit themselves with someone else's
  deposit that happens to be in the tree; (2) binds the deposit to the
  claimant's intmax identity.

  ## Constraint inventory (deposit_witness.rs:103-135)

  | line       | gate                                            | meaning              |
  |------------|-------------------------------------------------|----------------------|
  | :114       | `DepositTarget::new(.., is_checked)`            | deposit_index : U63, range-checked to 63 bits when checked |
  | :117-122   | `deposit_merkle_proof.verify`                   | membership           |
  | :124-126   | `connect(deposit.recipient, recipient(cid,salt))`| ownership            |

  ## Verified-safe check (was a suspected asymmetry)

  Native `verify()` (:77-83) explicitly rejects `deposit_index ≥
  2^DEPOSIT_TREE_HEIGHT`. The circuit emits no separate bound — but
  `deposit_index` is a `U63` and `DEPOSIT_TREE_HEIGHT = 63`, so
  `U63Target::new(is_checked)`'s 63-bit range check *exactly* enforces
  `deposit_index < 2^63 = 2^DEPOSIT_TREE_HEIGHT`. No gap, PROVIDED
  is_checked = true (same dependency as F-ACCT-1).
-/

namespace Zkp
namespace Circuits.DepositWitness

open CField Builder Bytes Merkle
open Circuits.Recipient (recipientFromUserId)

variable {F : Type} [CField F]

/-- `DEPOSIT_TREE_HEIGHT = 63` (`constants.rs:15`); matches `U63`. -/
def DEPOSIT_TREE_HEIGHT : Nat := 63

/-- A deposit (abstract) with its leaf digest, recipient, and index. -/
opaque Deposit : Type → Type
opaque depositLeaf {F : Type} [CField F] : Deposit F → HashOut F
opaque depositRecipient {F : Type} [CField F] : Deposit F → Bytes32 F
opaque depositIndex {F : Type} [CField F] : Deposit F → F

/-- Constraints emitted by `DepositWitnessTarget::new`. `sib` are the
    deposit Merkle siblings; `salt` the user's deposit salt. -/
def Constraints (channelId : F) (salt : List F) (deposit : Deposit F)
    (sib : List (HashOut F)) (root : HashOut F) : Prop :=
  MerkleVerify DEPOSIT_TREE_HEIGHT (depositLeaf deposit) (depositIndex deposit) sib root
  ∧ connect (depositRecipient deposit) (recipientFromUserId channelId salt)

/-- **Soundness.** Acceptance gives (1) an inclusion path of the
    deposit under `root` at its index, and (2) the deposit's recipient
    is exactly the channel_id/salt USER_ID commitment — binding the
    claimed deposit to the claimant's identity. -/
theorem depositWitness_sound {channelId : F} {salt : List F}
    {deposit : Deposit F} {sib : List (HashOut F)} {root : HashOut F}
    (h : Constraints channelId salt deposit sib root) :
    (∃ bits, bits.length = DEPOSIT_TREE_HEIGHT ∧
        depositIndex deposit = bitsValue bits ∧
        fold (depositLeaf deposit) bits sib = root)
    ∧ depositRecipient deposit = recipientFromUserId channelId salt := by
  obtain ⟨hmem, hown⟩ := h
  exact ⟨MerkleVerify_gives_path hmem, hown⟩

/-!
  ## SECURITY OBSERVATION — ownership is only as strong as Poseidon CR

  The ownership binding (2) prevents stealing another user's deposit
  *iff* `recipientFromUserId` is collision-resistant: distinct
  `(channel_id, salt)` preimages must give distinct recipients, AND an
  attacker must not find a `(channel_id', salt')` colliding with a
  victim's `deposit.recipient`. This is exactly `Bytes.PoseidonCR`
  (with the USER_ID_TAG top-byte overwrite, see recipient.rs:35). The
  tag overwrite reduces the digest's effective binding by one byte;
  since the remaining 31 bytes still come from Poseidon this is not a
  practical break, but it is the reason the binding lives at the
  recipient layer, not raw hash equality. Cross-link: F-RECIP-1
  concerns the *address* recipient path, not this USER_ID path.
-/

end Circuits.DepositWitness
end Zkp
