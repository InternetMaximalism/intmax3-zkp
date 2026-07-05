import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Tx settlement: bind spend authorization to block inclusion
  ==========================================================

  Source: `src/circuits/balance/common/tx_settlement.rs`

  ## Protocol role

  A user's balance proof, when it SENDS, must show the tx it is
  spending was actually included in a settled block. `TxSettlement`
  is that bridge. It ties together, for one tx:

    * a verified **spend proof** (authorization: the user signed/spent
      exactly this `tx`), via `tx == spend_pis.tx`;
    * the user's **account state** (send leaf ⇒ tx_tree_root), bound to
      the **public state**'s `account_tree_root` and to `channel_id`;
    * **inclusion** of the tx in the block tx tree at index `channel_id`
      — through EITHER the legacy `tx` path OR the `tx_v2` path,
      selected by the boolean `use_tx_v2`.

  The security crux: a prover must not be able to (a) settle a tx that
  the spend proof did not authorize, nor (b) skip the inclusion check.

  ## Constraint inventory (tx_settlement.rs:260-323)

  | line     | gate                                                | meaning                       |
  |----------|-----------------------------------------------------|-------------------------------|
  | :281     | `connect(account_state.channel_id, channel_id)`     | account ↔ this user           |
  | :282-284 | `connect(account_state.account_tree_root, ps.acct)` | account ↔ public state        |
  | :286-289 | `tx_tree_root := send_leaf.tx_tree_root`            | which tree to look in         |
  | :292     | `tx_index := channel_id` (TX_TREE_HEIGHT=CHANNEL_ID_BITS) | one tx slot per user/block |
  | :293     | `use_legacy_tx := not(use_tx_v2)`                    | path selector complement      |
  | :294-300 | `tx_merkle_proof.conditional_verify(use_legacy_tx)` | legacy inclusion              |
  | :301-307 | `tx_v2_merkle_proof.conditional_verify(use_tx_v2)`  | v2 inclusion                  |
  | :311-312 | if v2: `tx_v2.tx_class == UserTransfer`              | v2 must be a user transfer    |
  | :314     | if v2: `tx_v2.channel_action_root == 0`             | no channel action             |
  | :315-319 | if v2: `tx_v2.transfer_tree_root == tx.transfer_tree_root` | v2 ↔ tx consistency     |
  | :320     | if v2: `tx_v2.nonce == tx.nonce`                    | v2 ↔ tx consistency           |
  | :322-323 | `connect(tx, spend_pis.tx)`                          | authorization binding         |

  ## Resolves F-ACCT-1 (verified-safe)

  `is_checked` is threaded to `ChannelIdTarget`/`PublicStateTarget`/
  `AccountStateTarget`. Both non-test callers
  (`send_tx_circuit.rs:231`, `receive_transfer_circuit.rs:393`) pass
  literal `true`, and `TX_TREE_HEIGHT = CHANNEL_ID_BITS = 32` with
  `channel_id` range-checked ⇒ `tx_index = channel_id < 2^32` — no
  index aliasing. F-ACCT-1 closed.
-/

namespace Zkp
namespace Circuits.TxSettlement

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

/-- `TX_TREE_HEIGHT = CHANNEL_ID_BITS = 32`. -/
def TX_TREE_HEIGHT : Nat := 32

structure Tx (F : Type) where
  transferTreeRoot : HashOut F
  nonce : F
opaque txLeaf {F : Type} [CField F] : Tx F → HashOut F

structure TxV2 (F : Type) where
  txClass : F
  channelActionRoot : HashOut F
  transferTreeRoot : HashOut F
  nonce : F
opaque txv2Leaf {F : Type} [CField F] : TxV2 F → HashOut F

/-- `TxClass::UserTransfer` constant. -/
def USER_TRANSFER (F : Type) [CField F] : F := natLit F 0

/-- The zero Poseidon digest (`PoseidonHashOut::default`). -/
opaque zeroHash (F : Type) [CField F] : HashOut F

/-- Constraints emitted by `TxSettlementTarget::new`. -/
structure Constraints
    (channelId : F) (tx : Tx F) (txv2 : TxV2 F) (spendPisTx : Tx F)
    (accChannelId : F) (accAccountTreeRoot psAccountTreeRoot : HashOut F)
    (txTreeRoot : HashOut F) (useTxV2 : F)
    (txSib txv2Sib : List (HashOut F)) : Prop where
  bChan  : accChannelId = channelId
  bRoot  : accAccountTreeRoot = psAccountTreeRoot
  bSpend : tx = spendPisTx
  v2bool : useTxV2 = 0 ∨ useTxV2 = 1
  vLegacy : CondMerkleVerify (notGate useTxV2) TX_TREE_HEIGHT (txLeaf tx) channelId txSib txTreeRoot
  vV2     : CondMerkleVerify useTxV2 TX_TREE_HEIGHT (txv2Leaf txv2) channelId txv2Sib txTreeRoot
  cClass    : useTxV2 = 1 → txv2.txClass = USER_TRANSFER F
  cAction   : useTxV2 = 1 → txv2.channelActionRoot = zeroHash F
  cTransfer : useTxV2 = 1 → txv2.transferTreeRoot = tx.transferTreeRoot
  cNonce    : useTxV2 = 1 → txv2.nonce = tx.nonce

/-- **Inclusion is unavoidable.** Because `use_tx_v2` is a *safe*
    boolean (`add_virtual_bool_target_safe`), exactly one of the two
    conditional verifies is active, so the authorized tx (or its v2
    image, which is constrained equal to `tx` on the spent fields) is
    always included in the block tx tree at `channel_id`. The prover
    cannot set the selector to skip BOTH checks. -/
theorem inclusion_unavoidable
    {channelId : F} {tx : Tx F} {txv2 : TxV2 F} {spendPisTx : Tx F}
    {accChannelId : F} {accAccountTreeRoot psAccountTreeRoot txTreeRoot : HashOut F}
    {useTxV2 : F} {txSib txv2Sib : List (HashOut F)}
    (h : Constraints channelId tx txv2 spendPisTx accChannelId
          accAccountTreeRoot psAccountTreeRoot txTreeRoot useTxV2 txSib txv2Sib) :
    MerkleVerify TX_TREE_HEIGHT (txLeaf tx) channelId txSib txTreeRoot
    ∨ MerkleVerify TX_TREE_HEIGHT (txv2Leaf txv2) channelId txv2Sib txTreeRoot := by
  rcases h.v2bool with h0 | h1
  · -- use_tx_v2 = 0 ⇒ legacy path active (not 0 = 1)
    left
    apply h.vLegacy
    rw [notGate_eq_one_iff (Or.inl h0)]; exact h0
  · -- use_tx_v2 = 1 ⇒ v2 path active
    right
    exact h.vV2 h1

/-- **Authorization binding.** The settled tx equals the spend
    proof's public-input tx: nothing can be settled that the spend
    proof did not authorize. -/
theorem settled_tx_is_authorized
    {channelId : F} {tx : Tx F} {txv2 : TxV2 F} {spendPisTx : Tx F}
    {accChannelId : F} {accAccountTreeRoot psAccountTreeRoot txTreeRoot : HashOut F}
    {useTxV2 : F} {txSib txv2Sib : List (HashOut F)}
    (h : Constraints channelId tx txv2 spendPisTx accChannelId
          accAccountTreeRoot psAccountTreeRoot txTreeRoot useTxV2 txSib txv2Sib) :
    tx = spendPisTx := h.bSpend

/-- **Account ↔ public-state binding.** The account state used is the
    one committed under the public state's account root, for this user. -/
theorem account_bound_to_public_state
    {channelId : F} {tx : Tx F} {txv2 : TxV2 F} {spendPisTx : Tx F}
    {accChannelId : F} {accAccountTreeRoot psAccountTreeRoot txTreeRoot : HashOut F}
    {useTxV2 : F} {txSib txv2Sib : List (HashOut F)}
    (h : Constraints channelId tx txv2 spendPisTx accChannelId
          accAccountTreeRoot psAccountTreeRoot txTreeRoot useTxV2 txSib txv2Sib) :
    accChannelId = channelId ∧ accAccountTreeRoot = psAccountTreeRoot :=
  ⟨h.bChan, h.bRoot⟩

/-- When the v2 path is taken, the included `tx_v2` agrees with the
    authorized `tx` on the spent fields (transfer tree + nonce) and is
    a plain user transfer with no channel action — so v2 inclusion is
    as good as legacy inclusion of the authorized tx. -/
theorem v2_consistent_with_tx
    {channelId : F} {tx : Tx F} {txv2 : TxV2 F} {spendPisTx : Tx F}
    {accChannelId : F} {accAccountTreeRoot psAccountTreeRoot txTreeRoot : HashOut F}
    {useTxV2 : F} {txSib txv2Sib : List (HashOut F)}
    (h : Constraints channelId tx txv2 spendPisTx accChannelId
          accAccountTreeRoot psAccountTreeRoot txTreeRoot useTxV2 txSib txv2Sib)
    (hv2 : useTxV2 = 1) :
    txv2.transferTreeRoot = tx.transferTreeRoot ∧ txv2.nonce = tx.nonce
    ∧ txv2.txClass = USER_TRANSFER F ∧ txv2.channelActionRoot = zeroHash F :=
  ⟨h.cTransfer hv2, h.cNonce hv2, h.cClass hv2, h.cAction hv2⟩

/-!
  ## SECURITY OBSERVATION — C-M1 (aux_data semantics), cross-ref

  audit622 §C-M1 notes that send/receive fold a Merkle-bound `aux_data`
  into `settled_tx_chain` without proving `aux_data == tx_leaf_hash`.
  That binding lives in `send_tx_circuit.rs` / `receive_transfer_circuit.rs`,
  not here. `TxSettlement` DOES bind `tx == spend_pis.tx` and includes
  `tx`/`tx_v2` at `channel_id`; the open question is whether the channel
  inter-tx `aux_data` path reuses this guarantee. Re-examine when those
  two circuits are modeled (Phase 2) — tracked as F-AUX-1 placeholder.
-/

end Circuits.TxSettlement
end Zkp
