import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Receive-deposit balance transition (IVC step)
  =============================================

  Source: `src/circuits/balance/receive_deposit_circuit.rs`

  ## Protocol role

  One recursive step of a RECEIVER's balance proof that credits an L1
  deposit into the user's private asset tree. It composes four already-
  modeled gadgets: the recursive prev-balance proof, `update_public_state`,
  `deposit_witness` (membership + ownership), and `update_private_state`
  (the actual single-leaf credit + nullifier insert).

  The new content at THIS layer is the *wiring* that forces the private
  credit to be EXACTLY the witnessed deposit, and the block-number
  ordering that bounds `block_r`.

  ## Constraint inventory (receive_deposit_circuit.rs:265-355)

  | line     | gate                                                  | meaning |
  |----------|-------------------------------------------------------|---------|
  | :280     | `verify_proof(prev_balance_proof)`                    | recurse (IVC) |
  | :285-287 | `update.old.connect(prev.public_state)`               | chain state |
  | :289-296 | `account.channel_id/account_tree_root` bound          | account ↔ user/state |
  | :298-305 | `deposit.channel_id/deposit_tree_root` bound          | deposit ↔ user/on-chain tree |
  | :308-309 | `new_block_r ≥ prev_block_r`                          | block_r monotone |
  | :310     | `public_state.block_number ≥ new_block_r`             | **F-BLKR-1: block_r ≤ block_number** |
  | :318     | `new_block_r ≥ deposit.block_number`                  | deposit not in the future |
  | :322-329 | `update_priv.{token_index,amount,nullifier} = deposit.*` | credit binds to deposit |
  | :332-333 | `update_priv.prev_state.commitment = prev.private_commitment` | IVC private link |
  | :340-345 | `settled_tx_chain := push(prev.chain, deposit_nullifier)` | unconditional faithful fold |
-/

namespace Zkp
namespace Circuits.ReceiveDepositCircuit

open CField Builder Bytes

variable {F : Type} [CField F]

/-- Values wired together by this step. Block numbers as ℕ (their
    canonical values); credit fields as field/bytes values. -/
structure StepIO (F : Type) where
  prevBlockR : Nat
  newBlockR : Nat
  blockNumber : Nat       -- public_state.block_number
  depositBlock : Nat      -- deposit.block_number
  privTokenIndex : F      -- update_private_state.token_index
  depTokenIndex : F       -- deposit.token_index
  privAmount : F          -- update_private_state.amount
  depAmount : F           -- deposit.amount
  privNullifier : Bytes32 F
  depNullifier : Bytes32 F
  prevChain : Bytes32 F
  newChain : Bytes32 F
  pushedChain : Bytes32 F

/-- Constraints emitted by `ReceiveDepositTarget::new` (the wiring +
    ordering subset; the gadget-internal soundness is in the
    `DepositWitness` / `UpdatePrivateState` modules). -/
structure Constraints (io : StepIO F) : Prop where
  brMono   : io.prevBlockR ≤ io.newBlockR                 -- :308-309
  brBound  : io.newBlockR ≤ io.blockNumber                -- :310  (F-BLKR-1)
  depFresh : io.depositBlock ≤ io.newBlockR               -- :318
  cTok : connect io.privTokenIndex io.depTokenIndex        -- :322
  cAmt : connect io.privAmount io.depAmount                -- :324-326
  cNul : connect io.privNullifier io.depNullifier          -- :327-329
  cChain : io.newChain = io.pushedChain                    -- :340-345 (unconditional)

/-- **Credit binds to the deposit.** The private-state update credits
    exactly the witnessed deposit's `(token_index, amount)` and is
    keyed by the deposit's own nullifier. Combined with
    `UpdatePrivateState.updatePrivateState_sound` (single-leaf, no
    overflow, nullifier insert) and `DepositWitness.depositWitness_sound`
    (membership + ownership), the deposit is credited once, to the right
    balance, for the rightful owner. -/
theorem credit_binds_deposit {io : StepIO F} (h : Constraints io) :
    io.privTokenIndex = io.depTokenIndex
    ∧ io.privAmount = io.depAmount
    ∧ io.privNullifier = io.depNullifier := by
  refine ⟨?_, ?_, ?_⟩
  · have := h.cTok; unfold connect at this; exact this
  · have := h.cAmt; unfold connect at this; exact this
  · have := h.cNul; unfold connect at this; exact this

/-- **F-BLKR-1 resolved (this path).** The receive-deposit step pins
    the full block ordering `deposit_block ≤ new_block_r ≤
    block_number` and `prev_block_r ≤ new_block_r`. So the
    balance-PI invariant `block_r ≤ public_state.block_number` IS
    enforced where `block_r` is set, and the credited deposit is not
    dated after the guaranteed block. -/
theorem blockR_bounded {io : StepIO F} (h : Constraints io) :
    io.prevBlockR ≤ io.newBlockR
    ∧ io.depositBlock ≤ io.newBlockR
    ∧ io.newBlockR ≤ io.blockNumber := by
  exact ⟨h.brMono, h.depFresh, h.brBound⟩

/-!
  ## SECURITY OBSERVATIONS

  * **No F-AUX-1 residual here.** Unlike `send_tx`, the chain fold
    (`:340-345`) is UNCONDITIONAL and its leaf is the deposit
    `nullifier` — the very value whose Merkle-bound preimage (the
    deposit leaf) was verified against `public_state.deposit_tree_root`
    by `deposit_witness`. So the chain PI faithfully folds the deposit
    actually consumed; there is no unverified `aux_data` indirection.

  * **F-BLKR-1 closed for receive paths.** `block_r ≤ block_number` is
    asserted at `:310`. Confirm the SAME `enforce_ge` exists on the
    send / receive_transfer paths (send_tx selected `block_r` from
    `tx_block_number`; verify `tx_block ≤ new public_state.block_number`
    there to fully close F-BLKR-1 across all balance transitions).

  * **Ownership chain.** `deposit_witness.channel_id == prev.channel_id`
    (:298) + DepositWitness's `recipient == recipientFromUserId(channel_id,
    salt)` ⇒ only the channel_id owner can credit this deposit. Strength
    = `Bytes.PoseidonCR` (see DepositWitness F-observations).
-/

end Circuits.ReceiveDepositCircuit
end Zkp
