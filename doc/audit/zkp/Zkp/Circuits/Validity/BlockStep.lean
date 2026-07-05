import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Block hash-chain step (consensus accumulation threading)
  ========================================================

  Source: `src/circuits/validity/block_hash_chain/block_step.rs`
          (+ small_block_message / ext_public_state / block_chain_pis /
           block_hash_chain_circuit / _processor)

  ## Protocol role

  One block of the validity span. It advances the running extended
  public state by ONE block: it verifies the per-block `update_user`
  proof (which internally checks the user-tree update AND the block's
  SPHINCS+/Poseidon signatures — primitive gates OUT OF SCOPE, treated
  as a verified sub-proof) and threads four accumulators across the
  step: `block_number`, `block_hash_chain`, `bp_sig_chain`, and the
  (conditional) deposit chain.

  This file discharges the assumption used by
  `ValidityCircuit.signatures_not_skippable`: that `bp_sig_chain`
  faithfully ACCUMULATES every signing block. Here we prove the
  THREADING — each step pins `update.prev_bp_sig_chain ==
  prev.bp_sig_chain` and outputs `update.new_bp_sig_chain` — so the
  accumulator is an unbroken chain; the per-signing-block ADVANCEMENT
  is proved in `Zkp/Circuits/Validity/UpdateUser.lean`
  (`UpdateUser.signing_block_advances`).

  NOTE: the `channel_reg` branch (block_step.rs :261-338 native /
  :507-670 target) REPLACES the account tree root on registration
  blocks — it is BASE-LAYER, not channel scope. It is modeled in
  `Zkp/Circuits/Validity/UpdateUser.lean` (`UpdateUser.RegBranch`),
  with the residual dependence on the still-excluded channel_reg chain
  circuit recorded there as finding F-UPDU-1.

  ## Constraint inventory (block_step.rs:129-200, mirrored in Target::new)

  | line     | gate                                                    | meaning |
  |----------|---------------------------------------------------------|---------|
  | :171-176 | `block_number = prev.block_number + 1`                 | sequential blocks |
  | :179-183 | `update.prev_account_tree_root == prev.account_tree_root` | account continuity |
  | :184-188 | `update.prev_block_hash_chain == prev.block_hash_chain` | block-hash continuity |
  | :189     | `block_hash_chain = update.new_block_hash_chain`        | advance block-hash |
  | :195-197 | `update.prev_bp_sig_chain == prev.bp_sig_chain`         | **sig-accumulator continuity** |
  | :200     | `bp_sig_chain = update.new_bp_sig_chain`               | advance sig-accumulator |
-/

namespace Zkp
namespace Circuits.BlockStep

open CField Builder Bytes

variable {F : Type} [CField F]

/-- The per-block `update_user` sub-proof's relevant public inputs
    (its internals — user-tree update + signature gates — are a verified
    sub-proof, out of scope). -/
structure UpdateUser (F : Type) where
  prevAccountTreeRoot : HashOut F
  newAccountTreeRoot : HashOut F
  prevBlockHashChain : Bytes32 F
  newBlockHashChain : Bytes32 F
  prevBpSigChain : Bytes32 F
  newBpSigChain : Bytes32 F

/-- The threaded extended-public-state accumulators. -/
structure ExtState (F : Type) where
  blockNumber : Nat
  accountTreeRoot : HashOut F
  blockHashChain : Bytes32 F
  bpSigChain : Bytes32 F

structure Constraints (prev new : ExtState F) (upd : UpdateUser F) : Prop where
  blockSeq    : new.blockNumber = prev.blockNumber + 1               -- :171-176
  acctCont    : upd.prevAccountTreeRoot = prev.accountTreeRoot       -- :179-183
  bhcCont     : upd.prevBlockHashChain = prev.blockHashChain         -- :184-188
  bhcAdvance  : new.blockHashChain = upd.newBlockHashChain           -- :189
  sigCont     : upd.prevBpSigChain = prev.bpSigChain                 -- :195-197
  sigAdvance  : new.bpSigChain = upd.newBpSigChain                   -- :200

/-- **bp_sig_chain threading (continuity).** Each step's incoming
    accumulator equals the previous state's, and the outgoing one is the
    update proof's advanced value. So across a span the `bp_sig_chain` is
    an unbroken thread — exactly the accumulation assumption
    `ValidityCircuit.signatures_not_skippable` relies on. A prover cannot
    reset or fork the accumulator mid-span. -/
theorem bp_sig_chain_threaded {prev new : ExtState F} {upd : UpdateUser F}
    (h : Constraints prev new upd) :
    upd.prevBpSigChain = prev.bpSigChain ∧ new.bpSigChain = upd.newBpSigChain :=
  ⟨h.sigCont, h.sigAdvance⟩

/-- **Block-hash chain + block number threading.** Blocks are
    consecutive (`+1`) and the block-hash chain is continuous, so the
    span is a gapless, ordered sequence of blocks. -/
theorem block_chain_threaded {prev new : ExtState F} {upd : UpdateUser F}
    (h : Constraints prev new upd) :
    new.blockNumber = prev.blockNumber + 1
    ∧ upd.prevBlockHashChain = prev.blockHashChain
    ∧ new.blockHashChain = upd.newBlockHashChain :=
  ⟨h.blockSeq, h.bhcCont, h.bhcAdvance⟩

/-!
  ## SECURITY OBSERVATIONS

  * **Discharges `signatures_not_skippable`'s premise.**
    `bp_sig_chain_threaded` proves the cross-block continuity; combined
    with the `update_user` sub-proof advancing `new_bp_sig_chain` on any
    signing block — now machine-checked as
    `UpdateUser.signing_block_advances` / `signing_block_nonempty` in
    `Zkp/Circuits/Validity/UpdateUser.lean` — the span's final
    `bp_sig_chain` is nonzero iff some block signed — which is exactly
    the COMPUTED gate ValidityCircuit keys signature verification on.
    Dropping `sigCont` (:195-197) would let a prover splice a fresh
    zero accumulator after signing blocks, defeating the gate — so this
    continuity constraint is load-bearing.

  * **Sequentiality** (`block_chain_threaded`) prevents block reordering
    / skipping within a span; the deposit chain branch threads its own
    accumulators identically (and was proved gap-free in DepositStep).

  * **Update_user internals and the channel_reg branch are now IN
    scope:** both are modeled in `Zkp/Circuits/Validity/UpdateUser.lean`
    (the account-tree update, the bp_sig_chain fold, member-set
    immutability, and the registration-block root swap with finding
    F-UPDU-1 for the still-excluded channel_reg chain circuit).
    Signature-primitive gates (Poseidon/Regev single-sig proofs)
    remain uninterpreted primitives. The remaining block-chain files
    (`small_block_message`, `ext_public_state`, `block_chain_pis`,
    `block_hash_chain_circuit`/`_processor`) are message-encoding /
    PI-layout / cyclic-wrapper / orchestration with no new
    soundness-critical leaf constraints.
-/

end Circuits.BlockStep
end Zkp
