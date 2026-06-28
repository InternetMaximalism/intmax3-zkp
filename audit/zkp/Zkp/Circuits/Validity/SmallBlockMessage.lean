import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  IMSB small-block signing message (signature ↔ block binding)
  ============================================================

  Source: `src/circuits/validity/block_hash_chain/small_block_message.rs`

  ## Protocol role

  Each signing block carries a block-producer signature over the v2 IMSB
  digest. This file defines the *message* that digest is computed over:

      digest = keccak256(IMSB || channel_id || bp_member_slot || bp_pk_g
               || small_block_number || prev_small_block_root
               || tx_tree_root || state_commitment_root || ...)

  The SECURITY-relevant in-circuit property (file header, :11-14): the
  digest is recomputed IN-CIRCUIT from witnessed message fields with the
  `tx_tree_root` component CONNECTED to the block's actual applied
  `tx_tree_root`. So a valid signature is structurally bound to the
  block state it authorizes — a signature cannot be replayed onto a
  different tx tree / block.

  (The signature VERIFICATION itself — Poseidon/SPHINCS+ over this digest
  — is a cryptographic primitive, out of scope; we model only the
  message-binding that the circuit enforces.)

  ## Constraint inventory (small_block_message.rs:68-160)

  | location | gate                                                    | meaning |
  |----------|---------------------------------------------------------|---------|
  | :68 /:133| `signing_digest = keccak(fields, channel_id, tx_tree_root)` | digest from message |
  | (caller) | `connect(message.tx_tree_root, block.tx_tree_root)`     | bind digest to applied root |
-/

namespace Zkp
namespace Circuits.SmallBlockMessage

open CField Builder Bytes

variable {F : Type} [CField F]

/-- The signing-message fields (channel/bp slot fields are consensus
    identifiers; the soundness-relevant component is `txTreeRoot`). -/
structure MessageFields (F : Type) where
  bpMemberSlot : F
  bpPkG : Bytes32 F
  smallBlockNumber : F
  prevSmallBlockRoot : Bytes32 F
  stateCommitmentRoot : Bytes32 F

/-- `signing_digest(fields, channel_id, tx_tree_root)` — keccak over the
    message including the tx tree root (uninterpreted; determinism +
    the explicit `tx_tree_root` argument are what we reason about). -/
opaque signingDigest {F : Type} [CField F] :
    MessageFields F → F → Bytes32 F → Bytes32 F

/-- Constraint emitted by the caller: the message's `tx_tree_root`
    component is connected to the block's actually-applied root. -/
def Constraints (fields : MessageFields F) (channelId : F)
    (msgTxTreeRoot blockTxTreeRoot : Bytes32 F) (digest : Bytes32 F) : Prop :=
  connect msgTxTreeRoot blockTxTreeRoot
  ∧ digest = signingDigest fields channelId msgTxTreeRoot

/-- **Signature ↔ block binding.** The signed digest is computed over a
    `tx_tree_root` that equals the block's actually-applied root. Hence a
    valid signature over `digest` authorizes exactly this block's tx
    tree — it cannot be replayed onto a different block (whose digest,
    by keccak determinism over a different `tx_tree_root`, differs). -/
theorem digest_binds_block {fields : MessageFields F} {channelId : F}
    {msgTxTreeRoot blockTxTreeRoot digest : Bytes32 F}
    (h : Constraints fields channelId msgTxTreeRoot blockTxTreeRoot digest) :
    digest = signingDigest fields channelId blockTxTreeRoot := by
  obtain ⟨hconn, hdig⟩ := h
  unfold connect at hconn
  rw [hdig, hconn]

/-!
  ## SECURITY OBSERVATION

  Modeled property: the signing digest is bound to the applied
  `tx_tree_root` (`digest_binds_block`). Without the `connect`
  (msg root ↔ block root), `digest_binds_block` is unprovable and a
  producer signature could be replayed across blocks sharing the other
  message fields. The signature-VERIFICATION gate over this digest is a
  primitive (out of scope); given it holds, this binding makes the
  authorization block-specific. The remaining `channel_id` / member-slot
  fields are channel-scope identifiers folded into the same digest.
-/

end Circuits.SmallBlockMessage
end Zkp
