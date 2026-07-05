import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes

/-
  Withdrawal wrapper circuit (keccak PI + ext-state commitment)
  =============================================================

  Source: `src/circuits/withdraw/withdrawal_circuit.rs`

  ## Protocol role

  Final wrapper over the withdrawal-chain proof. It verifies the chain
  proof (cyclic), reads the aggregated `withdrawal_hash` and the chain's
  `public_state`, binds an `ExtendedPublicState` to that inner state,
  and emits the on-chain PIs: `keccak(withdrawal_hash, withdrawal_prover,
  ext_public_state_commitment, block_number)` plus the commitment and
  block number. The L1 contract consumes these to authorize payout.

  ## Constraint inventory (withdrawal_circuit.rs:181-209)

  | line     | gate                                                  | meaning |
  |----------|-------------------------------------------------------|---------|
  | :183     | `add_proof_target_and_verify_cyclic(verifier_data)`   | verify chain proof |
  | :184     | `withdrawal_hash := proof.pis[0..32]`                 | aggregated withdrawals |
  | :187-189 | `chain_public_state := proof.pis[..]`                 | chain's inner public state |
  | :190     | `ext_public_state = ExtendedPublicStateTarget::new`   | inner + 5 extended fields |
  | :191-193 | `ext.inner.connect(chain_public_state)`               | bind ONLY inner |
  | :194     | `ext_commitment := ext.commitment()`                  | commits inner + 5 extended |
  | :196     | `withdrawal_prover := AddressTarget::new` (free)      | claimant address |
  | :203-208 | `register keccak(pis) ++ ext_commitment ++ block_num` | on-chain PIs |
-/

namespace Zkp
namespace Circuits.WithdrawalCircuit

open CField Builder Bytes

variable {F : Type} [CField F]

/-- ExtendedPublicState (ext_public_state.rs): inner + 5 chain fields. -/
structure ExtendedPublicState (F : Type) where
  inner : HashOut F                 -- the PublicState (abstracted as its digest)
  blockHashChain : Bytes32 F
  depositHashChain : Bytes32 F
  depositCount : F
  channelRegHashChain : Bytes32 F
  bpSigChain : Bytes32 F

/-- `ExtendedPublicState::commitment` — keccak/Poseidon over ALL fields. -/
opaque extCommitment {F : Type} [CField F] : ExtendedPublicState F → Bytes32 F

structure Constraints (ext : ExtendedPublicState F)
    (chainPublicState : HashOut F) : Prop where
  bindInner : ext.inner = chainPublicState        -- :191-193  (ONLY inner is bound)

/-- **What IS provable.** Only the inner public state is bound to the
    verified chain proof. -/
theorem inner_bound {ext : ExtendedPublicState F} {chainPublicState : HashOut F}
    (h : Constraints ext chainPublicState) :
    ext.inner = chainPublicState := h.bindInner

/-!
  ## SECURITY FINDING — F-WITHDRAW-1 (= audit622 C-M2): partial ext-state binding

  `ExtendedPublicStateTarget::new` (`:190`) creates the 5 extended
  fields — `block_hash_chain`, `deposit_hash_chain`, `deposit_count`,
  `channel_reg_hash_chain`, `bp_sig_chain` — as FREE witnesses
  (range-checked but bound to NOTHING from the verified chain proof).
  Only `ext.inner` is `connect`-ed (`:191-193`). Yet
  `ext_public_state_commitment` (`:194`) — a registered on-chain PI —
  commits to ALL of them.

  Lean evidence: `Constraints` has a `bindInner` conjunct but NO
  conjunct binding `blockHashChain`/`depositHashChain`/`depositCount`/
  `channelRegHashChain`/`bpSigChain`. A stronger spec
  `ext_is_genuine : ext = (the chain block's true extended state)` is
  therefore NOT provable from `Constraints` — the prover may choose the
  5 extended fields arbitrarily, and the emitted commitment will reflect
  those arbitrary values.

  EXPLOITABILITY — completed off-circuit by the L1 contract:
  the binding is only safe if `IntmaxRollup` verifies
  `ext_public_state_commitment == storedBlock.extCommitment` (i.e. the
  contract re-pins the extended fields to the real block it recorded).
  IF the contract instead TRUSTS any extended field decoded from the
  proof's commitment (e.g. uses `deposit_count` / `bp_sig_chain` from
  the withdrawal PI without re-checking against the recorded block),
  a prover could forge those values. SEVERITY: MEDIUM, contingent on the
  contract. ACTION: confirm `IntmaxRollup.sol` compares
  `ext_public_state_commitment` against the stored block commitment for
  the claimed `block_number`, and does not consume any extended field as
  ground truth from the withdrawal proof. (Contract layer is outside the
  circuit scope of this audit but is the binding completion point.)
  Matches audit622 §C-M2 independently.
-/

end Circuits.WithdrawalCircuit
end Zkp
