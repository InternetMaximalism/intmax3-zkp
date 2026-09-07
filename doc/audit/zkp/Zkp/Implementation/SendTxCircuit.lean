import Zkp.Implementation.Spend
import Zkp.Implementation.UpdatePublicState

/-!
# SendTxCircuit: handwritten semantics of the send branch of the balance proof

Source: src/circuits/balance/send_tx_circuit.rs, all 709 lines read (the
`#[cfg(test)]` module included but not promoted to a constraint).
This is a handwritten SEMANTIC MODEL, NOT a refinement proof of the Rust,
plonky2 or compiled constraint system, and NOT a proof-system soundness claim.

What the send branch binds (both natively and in-circuit):
* the previous balance statement is parsed from the previous proof's public
  inputs (BalancePublicInputs full codec, 29 balance words + carried verifier
  data) and the carried verifier data is copied unchanged into the new statement;
* `prev.public_state = update.old`, `update.new = tx_settlement.public_state`,
  `prev.channel_id = tx_settlement.channel_id`,
  `prev.private_commitment = spend_pis.prev_private_commitment`;
* block ordering: `block_r >= send_block_number_before_tx` and, IN-CIRCUIT,
  `tx_block_number > block_r` (strict).  The NATIVE witness builder only checks
  `tx_block_number >= block_r`.  This is a prover-side divergence (native admits
  a witness whose proof cannot be generated), not a soundness hole: everything
  the circuit accepts also passes the native inequality.
* the outgoing transfer sits at index 0 of the settled tx's transfer tree
  (`transfer_witness.transfer_tree_root = tx.transfer_tree_root`, index pinned to 0);
* next `block_r` / `private_commitment` are the spend's values when
  `spend_pis.is_valid`, otherwise the previous ones (no-op send);
* the settled-tx chain is folded ONLY when `is_valid && aux_data != 0` with the
  keccak preimage `[IMTC domain] ++ chain(8 words) ++ aux(8 words)`, otherwise kept.

What this file does NOT do (kept as explicit callbacks / boundaries):
* nonce increment and the sent-tx tree root are NOT inspected here; they live
  in the spend proof's public inputs, whose `tx` is connected to the settled tx
  inside `TxSettlementTarget::new` (tx_settlement.rs, a dependency of this file).
  The send branch reads only prev/new private commitment and the validity flag.
* recursive verification of the previous balance proof under its carried
  verifier data, spend-proof verification under the pinned spend vd, account
  state / tx inclusion, transfer Merkle inclusion, the keccak gadget and the
  U63 range-check lowering of `enforce_ge`/`enforce_gt` are opaque callbacks.
* the spend validity wire is a `BoolTarget::new_unsafe` wrapper; that it is
  Boolean comes from the verified spend proof, so it is an explicit premise
  (`FlagBoolean`), never a local gate of this file.
* `is_valid = false` is accepted (block_r, commitment and chain are carried).
Hash outputs are opaque; no injectivity is assumed anywhere.  Nat is a
representative domain for u32/u63/u64/field wires.
-/

namespace Zkp.Implementation.SendTxCircuit

abbrev Root := BalancePublicInputs.Root
abbrev Bytes8 := BalancePublicInputs.Bytes8
abbrev PublicState := BalancePublicInputs.PublicState
abbrev BalanceInputs := BalancePublicInputs.PublicInputs
abbrev FullInputs := BalancePublicInputs.FullInputs
abbrev VerifierData := BalancePublicInputs.VerifierData
abbrev Hash4 := Spend.Hash4
abbrev Update := UpdatePublicState.Update

/-- SETTLED_TX_CHAIN_DOMAIN ("IMTC") from src/common/balance_state.rs. -/
def settledTxChainDomain : Nat := 0x494d5443
def balanceLength : Nat := 29
def auxLength : Nat := 8
def chainPreimageLength : Nat := 17
def outgoingTransferIndex : Nat := 0

theorem settled_tx_chain_domain_pinned : settledTxChainDomain = 0x494d5443 := rfl
theorem balance_length_pinned : balanceLength = BalancePublicInputs.balanceLength := rfl
theorem chain_preimage_length_pinned : chainPreimageLength = 1 + auxLength + auxLength := rfl
theorem outgoing_transfer_index_pinned : outgoingTransferIndex = 0 := rfl

/-- PoseidonHashOut values are shared between the spend statement (Spend.Hash4)
    and the balance statement (BalancePublicInputs.Root); the comparison in the
    source is on the same Rust type, modeled as this word-preserving cast. -/
def rootOfHash (h : Hash4) : Root := ⟨h.h0, h.h1, h.h2, h.h3⟩

theorem root_of_hash_preserves_words (h : Hash4) : (rootOfHash h).words = h.words := rfl

theorem root_of_hash_injective {a b : Hash4} (h : rootOfHash a = rootOfHash b) : a = b := by
  cases a; cases b
  simp only [rootOfHash, BalancePublicInputs.Root.mk.injEq] at h
  obtain ⟨h0, h1, h2, h3⟩ := h
  subst h0 h1 h2 h3
  rfl

/-! ## Settled-tx chain fold (settled_tx_chain_push / _circuit) -/

def zeroAux : List Nat := List.replicate auxLength 0

/-- `[SETTLED_TX_CHAIN_DOMAIN] ++ chain.to_u32_vec() ++ leaf.to_u32_vec()`. -/
def chainPreimage (chain : Bytes8) (aux : List Nat) : List Nat :=
  [settledTxChainDomain] ++ chain.words ++ aux

def settledTxChainPush (keccak : List Nat → Bytes8) (chain : Bytes8) (aux : List Nat) : Bytes8 :=
  keccak (chainPreimage chain aux)

theorem chain_preimage_has_17_words (chain : Bytes8) (aux : List Nat) (h : aux.length = auxLength) :
    (chainPreimage chain aux).length = chainPreimageLength := by
  simp [chainPreimage, BalancePublicInputs.Bytes8.words, h, auxLength, chainPreimageLength]

theorem chain_preimage_starts_with_domain (chain : Bytes8) (aux : List Nat) :
    (chainPreimage chain aux).head? = some settledTxChainDomain := rfl

theorem chain_preimage_injective {c d : Bytes8} {a b : List Nat}
    (h : chainPreimage c a = chainPreimage d b) : c = d ∧ a = b := by
  cases c; cases d
  simp [chainPreimage, BalancePublicInputs.Bytes8.words] at h
  obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7, hab⟩ := h
  subst h0 h1 h2 h3 h4 h5 h6 h7 hab
  exact ⟨rfl, rfl⟩

theorem chain_push_is_keccak_of_exact_preimage (keccak : List Nat → Bytes8) (chain : Bytes8)
    (aux : List Nat) :
    settledTxChainPush keccak chain aux = keccak ([settledTxChainDomain] ++ chain.words ++ aux) := rfl

/-! ## The next balance statement (shared by native builder and circuit) -/

/-- Lines 164-190: validity-selected block_r / commitment and the gated chain fold. -/
def nextInputs (keccak : List Nat → Bytes8) (prev : BalanceInputs) (newState : PublicState)
    (isValid : Bool) (newCommitment : Root) (txBlock : Nat) (aux : List Nat) : BalanceInputs :=
  { channelId := prev.channelId
    publicState := newState
    blockR := if isValid then txBlock else prev.blockR
    privateCommitment := if isValid then newCommitment else prev.privateCommitment
    settledChain :=
      if isValid ∧ aux ≠ zeroAux then settledTxChainPush keccak prev.settledChain aux
      else prev.settledChain }

theorem next_inputs_valid_spend_advances_reference_and_commitment (keccak : List Nat → Bytes8)
    (prev : BalanceInputs) (s : PublicState) (c : Root) (t : Nat) (aux : List Nat) :
    (nextInputs keccak prev s true c t aux).blockR = t ∧
    (nextInputs keccak prev s true c t aux).privateCommitment = c := by
  simp [nextInputs]

theorem next_inputs_invalid_spend_carries_everything_but_public_state (keccak : List Nat → Bytes8)
    (prev : BalanceInputs) (s : PublicState) (c : Root) (t : Nat) (aux : List Nat) :
    nextInputs keccak prev s false c t aux = { prev with publicState := s } := by
  simp [nextInputs]

theorem next_inputs_folds_chain_only_for_valid_nonzero_aux (keccak : List Nat → Bytes8)
    (prev : BalanceInputs) (s : PublicState) (c : Root) (t : Nat) (aux : List Nat) (v : Bool) :
    (nextInputs keccak prev s v c t aux).settledChain =
      (if v = true ∧ aux ≠ zeroAux then keccak (chainPreimage prev.settledChain aux)
       else prev.settledChain) := by
  simp [nextInputs, settledTxChainPush]

theorem next_inputs_zero_aux_never_folds (keccak : List Nat → Bytes8) (prev : BalanceInputs)
    (s : PublicState) (c : Root) (t : Nat) (v : Bool) :
    (nextInputs keccak prev s v c t zeroAux).settledChain = prev.settledChain := by
  simp [nextInputs]

theorem next_inputs_keep_channel_identity (keccak : List Nat → Bytes8) (prev : BalanceInputs)
    (s : PublicState) (c : Root) (t : Nat) (aux : List Nat) (v : Bool) :
    (nextInputs keccak prev s v c t aux).channelId = prev.channelId := rfl

theorem next_inputs_public_state_is_the_updated_state (keccak : List Nat → Bytes8)
    (prev : BalanceInputs) (s : PublicState) (c : Root) (t : Nat) (aux : List Nat) (v : Bool) :
    (nextInputs keccak prev s v c t aux).publicState = s := rfl

/-! ## Native witness (SendTxWitness) and its public-input builder -/

/-- The fields of TxSettlement that this file reads. `sendBlockBefore` /
    `txBlockNumber` are `account_state.send_leaf.prev` / `.cur`; the spend
    proof is represented by its public-input words. Construction checks of
    TxSettlement::new (spend proof verification, account/tx inclusion,
    `spend_pis.tx == tx`) belong to tx_settlement.rs and are boundaries here. -/
structure TxSettlement where
  channelId : Nat
  tx : Spend.Tx
  publicState : PublicState
  sendBlockBefore : Nat
  txBlockNumber : Nat
  spendPublicWords : List Nat
  deriving DecidableEq, Repr

structure TransferWitness (Path : Type) where
  transferTreeRoot : Hash4
  transfer : Spend.Transfer
  transferIndex : Nat
  merkleProof : Path

structure Witness (Path : Type) where
  prevBalanceWords : List Nat
  updatePublicState : Update
  txSettlement : TxSettlement
  transferWitness : TransferWitness Path

/-- Opaque dependencies of the native path: the balance_cd cap count, the
    field conversion of carried verifier words, transfer Merkle verification
    and keccak. -/
structure Environment (Path : Type) where
  capCount : Nat
  convertFields : List Nat → BalancePublicInputs.Result (List Nat)
  transferInclusion : Path → Spend.Transfer → Nat → Hash4 → Bool
  keccak : List Nat → Bytes8

/-- SendTxError; InvalidBalanceProof / InvalidBalanceVd are declared but never
    produced by this file. -/
inductive Error where
  | connection (detail : String)
  | balancePublicInputs (fault : BalancePublicInputs.Fault)
  | invalidBalanceProof (detail : String)
  | invalidBalanceVd (detail : String)
  | spendPis (fault : Spend.Error)
  | blockNumber (detail : String)
  | failedToProve (detail : String)
  deriving DecidableEq, Repr

/-- Lines 104-122, in source order. -/
def preChecks {Path : Type} (w : Witness Path) (prev : BalanceInputs) : Except Error Unit :=
  if prev.publicState ≠ w.updatePublicState.oldState then
    .error (.connection "prev_balance_pis.public_state != update_public_state.old") else
  if w.updatePublicState.newState ≠ w.txSettlement.publicState then
    .error (.connection "update_public_state.new != tx_settlement.public_state") else
  if w.txSettlement.channelId ≠ prev.channelId then
    .error (.connection "tx_settlement.channel_id != prev_balance_pis.channel_id") else
  .ok ()

/-- Lines 127-162, in source order. NOTE the non-strict `tx_block_number >= block_r`. -/
def postChecks {Path : Type} (env : Environment Path) (w : Witness Path) (prev : BalanceInputs)
    (spend : Spend.PublicInputs) : Except Error Unit :=
  if rootOfHash spend.previousPrivateCommitment ≠ prev.privateCommitment then
    .error (.connection "spend_pis.prev_private_commitment != prev_balance_pis.private_commitment") else
  if prev.blockR < w.txSettlement.sendBlockBefore then
    .error (.blockNumber "prev_balance_pis.block_r should be >= send_block_number_before_tx") else
  if w.txSettlement.txBlockNumber < prev.blockR then
    .error (.blockNumber "tx_block_number should be >= prev_balance_pis.block_r") else
  if w.transferWitness.transferIndex ≠ outgoingTransferIndex then
    .error (.connection "transfer_witness.transfer_index must be 0") else
  if w.transferWitness.transferTreeRoot ≠ w.txSettlement.tx.transferTreeRoot then
    .error (.connection "transfer_witness.transfer_tree_root != tx.transfer_tree_root") else
  if env.transferInclusion w.transferWitness.merkleProof w.transferWitness.transfer
      w.transferWitness.transferIndex w.transferWitness.transferTreeRoot = false then
    .error (.connection "invalid transfer witness") else
  .ok ()

/-- SendTxWitness::to_public_inputs (lines 93-195). -/
def toPublicInputs {Path : Type} (env : Environment Path) (w : Witness Path) :
    Except Error FullInputs :=
  match BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords with
  | .error fault => .error (.balancePublicInputs fault)
  | .ok full =>
    match preChecks w full.pis with
    | .error e => .error e
    | .ok () =>
      match Spend.parseNativePublicInputs w.txSettlement.spendPublicWords with
      | .error fault => .error (.spendPis fault)
      | .ok spend =>
        match postChecks env w full.pis spend with
        | .error e => .error e
        | .ok () =>
          .ok ⟨nextInputs env.keccak full.pis w.updatePublicState.newState spend.isValid
                (rootOfHash spend.newPrivateCommitment) w.txSettlement.txBlockNumber
                w.transferWitness.transfer.auxData, full.vd⟩

/-- The native admission conditions as one proposition. -/
structure NativeChecks {Path : Type} (env : Environment Path) (w : Witness Path)
    (prev : BalanceInputs) (spend : Spend.PublicInputs) : Prop where
  oldStateConnected : prev.publicState = w.updatePublicState.oldState
  newStateConnected : w.updatePublicState.newState = w.txSettlement.publicState
  channelConnected : w.txSettlement.channelId = prev.channelId
  previousCommitmentConnected : rootOfHash spend.previousPrivateCommitment = prev.privateCommitment
  blockReferenceGe : w.txSettlement.sendBlockBefore ≤ prev.blockR
  txBlockGe : prev.blockR ≤ w.txSettlement.txBlockNumber
  transferIndexZero : w.transferWitness.transferIndex = outgoingTransferIndex
  transferRootConnected : w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot
  transferIncluded : env.transferInclusion w.transferWitness.merkleProof w.transferWitness.transfer
    w.transferWitness.transferIndex w.transferWitness.transferTreeRoot = true

theorem pre_checks_ok_iff {Path : Type} (w : Witness Path) (prev : BalanceInputs) :
    preChecks w prev = .ok () ↔
      prev.publicState = w.updatePublicState.oldState ∧
      w.updatePublicState.newState = w.txSettlement.publicState ∧
      w.txSettlement.channelId = prev.channelId := by
  unfold preChecks
  split
  · simp [*]
  split
  · simp [*]
  split
  · simp [*]
  next h1 h2 h3 =>
    simp only [ne_eq, Classical.not_not] at h1 h2 h3
    exact ⟨fun _ => ⟨h1, h2, h3⟩, fun _ => rfl⟩

theorem post_checks_ok_iff {Path : Type} (env : Environment Path) (w : Witness Path)
    (prev : BalanceInputs) (spend : Spend.PublicInputs) :
    postChecks env w prev spend = .ok () ↔
      rootOfHash spend.previousPrivateCommitment = prev.privateCommitment ∧
      w.txSettlement.sendBlockBefore ≤ prev.blockR ∧
      prev.blockR ≤ w.txSettlement.txBlockNumber ∧
      w.transferWitness.transferIndex = outgoingTransferIndex ∧
      w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot ∧
      env.transferInclusion w.transferWitness.merkleProof w.transferWitness.transfer
        w.transferWitness.transferIndex w.transferWitness.transferTreeRoot = true := by
  unfold postChecks
  split
  · simp [*]
  split
  next hc => simp [Nat.not_le.mpr hc]
  split
  next hc => simp [Nat.not_le.mpr hc]
  split
  · simp [*]
  split
  · simp [*]
  split
  · simp [*]
  next h1 h2 h3 h4 h5 h6 =>
    simp only [ne_eq, Classical.not_not, Nat.not_lt] at h1 h2 h3 h4 h5
    exact ⟨fun _ => ⟨h1, h2, h3, h4, h5, (Bool.eq_false_or_eq_true _).resolve_right h6⟩,
      fun _ => rfl⟩

theorem native_admission_characterized {Path : Type} (env : Environment Path) (w : Witness Path)
    (out : FullInputs) (h : toPublicInputs env w = .ok out) :
    ∃ full spend,
      BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords = .ok full ∧
      Spend.parseNativePublicInputs w.txSettlement.spendPublicWords = .ok spend ∧
      NativeChecks env w full.pis spend ∧
      out = ⟨nextInputs env.keccak full.pis w.updatePublicState.newState spend.isValid
        (rootOfHash spend.newPrivateCommitment) w.txSettlement.txBlockNumber
        w.transferWitness.transfer.auxData, full.vd⟩ := by
  unfold toPublicInputs at h
  split at h
  · contradiction
  next full hfull =>
    split at h
    · contradiction
    next hpre =>
      split at h
      · contradiction
      next spend hspend =>
        split at h
        · contradiction
        next hpost =>
          have he := Except.ok.inj h
          subst he
          obtain ⟨c1, c2, c3⟩ := (pre_checks_ok_iff w full.pis).1 hpre
          obtain ⟨d1, d2, d3, d4, d5, d6⟩ := (post_checks_ok_iff env w full.pis spend).1 hpost
          exact ⟨full, spend, hfull, hspend, ⟨c1, c2, c3, d1, d2, d3, d4, d5, d6⟩, rfl⟩

theorem native_admission_of_checks {Path : Type} (env : Environment Path) (w : Witness Path)
    (full : FullInputs) (spend : Spend.PublicInputs)
    (hfull : BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords = .ok full)
    (hspend : Spend.parseNativePublicInputs w.txSettlement.spendPublicWords = .ok spend)
    (checks : NativeChecks env w full.pis spend) :
    toPublicInputs env w = .ok ⟨nextInputs env.keccak full.pis w.updatePublicState.newState
      spend.isValid (rootOfHash spend.newPrivateCommitment) w.txSettlement.txBlockNumber
      w.transferWitness.transfer.auxData, full.vd⟩ := by
  have hpre : preChecks w full.pis = .ok () :=
    (pre_checks_ok_iff w full.pis).2 ⟨checks.oldStateConnected, checks.newStateConnected,
      checks.channelConnected⟩
  have hpost : postChecks env w full.pis spend = .ok () :=
    (post_checks_ok_iff env w full.pis spend).2 ⟨checks.previousCommitmentConnected,
      checks.blockReferenceGe, checks.txBlockGe, checks.transferIndexZero,
      checks.transferRootConnected, checks.transferIncluded⟩
  simp [toPublicInputs, hfull, hpre, hspend, hpost]

theorem native_balance_parse_failure_is_reported_first {Path : Type} (env : Environment Path)
    (w : Witness Path) (fault : BalancePublicInputs.Fault)
    (h : BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords
      = .error fault) :
    toPublicInputs env w = .error (.balancePublicInputs fault) := by
  simp [toPublicInputs, h]

theorem native_output_carries_previous_verifier_data {Path : Type} (env : Environment Path)
    (w : Witness Path) (out : FullInputs) (h : toPublicInputs env w = .ok out) :
    ∃ full, BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords
      = .ok full ∧ out.vd = full.vd ∧ out.pis.channelId = full.pis.channelId := by
  obtain ⟨full, spend, hfull, _, _, rfl⟩ := native_admission_characterized env w out h
  exact ⟨full, hfull, rfl, rfl⟩

theorem native_output_public_state_is_updated_state {Path : Type} (env : Environment Path)
    (w : Witness Path) (out : FullInputs) (h : toPublicInputs env w = .ok out) :
    out.pis.publicState = w.updatePublicState.newState ∧
    out.pis.publicState = w.txSettlement.publicState := by
  obtain ⟨full, spend, _, _, checks, rfl⟩ := native_admission_characterized env w out h
  exact ⟨rfl, checks.newStateConnected⟩

theorem native_binds_previous_private_commitment_to_spend {Path : Type} (env : Environment Path)
    (w : Witness Path) (out : FullInputs) (h : toPublicInputs env w = .ok out) :
    ∃ full spend,
      BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords = .ok full ∧
      Spend.parseNativePublicInputs w.txSettlement.spendPublicWords = .ok spend ∧
      rootOfHash spend.previousPrivateCommitment = full.pis.privateCommitment := by
  obtain ⟨full, spend, hfull, hspend, checks, _⟩ := native_admission_characterized env w out h
  exact ⟨full, spend, hfull, hspend, checks.previousCommitmentConnected⟩

theorem native_valid_spend_advances_reference_and_commitment {Path : Type}
    (env : Environment Path) (w : Witness Path) (out : FullInputs) (spend : Spend.PublicInputs)
    (h : toPublicInputs env w = .ok out)
    (hspend : Spend.parseNativePublicInputs w.txSettlement.spendPublicWords = .ok spend)
    (valid : spend.isValid = true) :
    out.pis.blockR = w.txSettlement.txBlockNumber ∧
    out.pis.privateCommitment = rootOfHash spend.newPrivateCommitment := by
  obtain ⟨full, spend', _, hspend', _, rfl⟩ := native_admission_characterized env w out h
  rw [hspend] at hspend'
  cases Except.ok.inj hspend'
  simp [nextInputs, valid]

theorem native_invalid_spend_keeps_reference_commitment_and_chain {Path : Type}
    (env : Environment Path) (w : Witness Path) (out : FullInputs) (spend : Spend.PublicInputs)
    (h : toPublicInputs env w = .ok out)
    (hspend : Spend.parseNativePublicInputs w.txSettlement.spendPublicWords = .ok spend)
    (invalid : spend.isValid = false) :
    ∃ full, BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords
      = .ok full ∧ out.pis = { full.pis with publicState := w.updatePublicState.newState } := by
  obtain ⟨full, spend', hfull, hspend', _, rfl⟩ := native_admission_characterized env w out h
  rw [hspend] at hspend'
  cases Except.ok.inj hspend'
  exact ⟨full, hfull, by simp [nextInputs, invalid]⟩

theorem native_chain_fold_is_exact_imtc_keccak {Path : Type} (env : Environment Path)
    (w : Witness Path) (out : FullInputs) (spend : Spend.PublicInputs)
    (h : toPublicInputs env w = .ok out)
    (hspend : Spend.parseNativePublicInputs w.txSettlement.spendPublicWords = .ok spend) :
    ∃ full, BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords
      = .ok full ∧
      out.pis.settledChain =
        (if spend.isValid = true ∧ w.transferWitness.transfer.auxData ≠ zeroAux then
          env.keccak ([settledTxChainDomain] ++ full.pis.settledChain.words ++
            w.transferWitness.transfer.auxData)
        else full.pis.settledChain) := by
  obtain ⟨full, spend', hfull, hspend', _, rfl⟩ := native_admission_characterized env w out h
  rw [hspend] at hspend'
  cases Except.ok.inj hspend'
  exact ⟨full, hfull, by simp [nextInputs, settledTxChainPush, chainPreimage]⟩

theorem native_pins_outgoing_transfer_to_leaf_zero_of_settled_tx {Path : Type}
    (env : Environment Path) (w : Witness Path) (out : FullInputs)
    (h : toPublicInputs env w = .ok out) :
    w.transferWitness.transferIndex = 0 ∧
    w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot ∧
    env.transferInclusion w.transferWitness.merkleProof w.transferWitness.transfer 0
      w.txSettlement.tx.transferTreeRoot = true := by
  obtain ⟨_, _, _, _, checks, _⟩ := native_admission_characterized env w out h
  have hi := checks.transferIndexZero
  have hr := checks.transferRootConnected
  have hv := checks.transferIncluded
  rw [hi, hr] at hv
  exact ⟨hi, hr, hv⟩

theorem native_block_order_is_non_strict {Path : Type} (env : Environment Path)
    (w : Witness Path) (out : FullInputs) (h : toPublicInputs env w = .ok out) :
    ∃ full, BalancePublicInputs.fullFromNative env.convertFields env.capCount w.prevBalanceWords
      = .ok full ∧ w.txSettlement.sendBlockBefore ≤ full.pis.blockR ∧
      full.pis.blockR ≤ w.txSettlement.txBlockNumber := by
  obtain ⟨full, _, hfull, _, checks, _⟩ := native_admission_characterized env w out h
  exact ⟨full, hfull, checks.blockReferenceGe, checks.txBlockGe⟩

/-! ## prove (lines 383-397): native admission first, then witness filling and proving -/

def prove {Path Proof : Type} (env : Environment Path)
    (backend : Witness Path → FullInputs → Except String Proof) (w : Witness Path) :
    Except Error Proof :=
  match toPublicInputs env w with
  | .error e => .error e
  | .ok pis =>
    match backend w pis with
    | .error e => .error (.failedToProve e)
    | .ok proof => .ok proof

theorem proving_cannot_bypass_native_admission {Path Proof : Type} (env : Environment Path)
    (backend : Witness Path → FullInputs → Except String Proof) (w : Witness Path) (proof : Proof)
    (h : prove env backend w = .ok proof) :
    ∃ pis, toPublicInputs env w = .ok pis ∧ backend w pis = .ok proof := by
  unfold prove at h
  split at h
  · contradiction
  next pis hpis =>
    split at h
    · contradiction
    next result hb =>
      have he := Except.ok.inj h
      subst he
      exact ⟨pis, hpis, hb⟩

/-! ## Arbitrary satisfying witness of SendTxTarget::new (lines 209-317) -/

def bit (b : Bool) : Nat := if b then 1 else 0

/-- `builder.select(flag, t, f)`: determined only when the flag wire is Boolean. -/
def Selected {α : Type} (flag : Nat) (whenTrue whenFalse out : α) : Prop :=
  (flag = 1 → out = whenTrue) ∧ (flag = 0 → out = whenFalse)

structure CircuitWitness (Path : Type) where
  prevBalanceWords : List Nat
  prevFull : FullInputs
  updatePublicState : Update
  updateWitness : UpdatePublicState.Witness
  txSettlement : TxSettlement
  spendTargets : Spend.PublicInputTargets
  transferWitness : TransferWitness Path
  auxIsZeroWire : Bool
  doPushWire : Nat
  newBlockR : Nat
  newPrivateCommitment : Root
  pushedChain : Bytes8
  newSettledChain : Bytes8
  newFull : FullInputs
  registeredWords : List Nat

/-- Opaque in-circuit dependencies: the previous-balance recursive verifier
    under the CARRIED verifier data, TxSettlementTarget::new (spend proof
    under the pinned spend vd, account state, tx inclusion, `tx == spend tx`),
    the UpdatePublicState Merkle root call. -/
structure CircuitEnvironment (Path : Type) extends Environment Path where
  getRoot : UpdatePublicState.RootCall
  balanceProofAccepted : List Nat → VerifierData → Bool
  txSettlementAccepted : TxSettlement → Bool

structure CircuitGates {Path : Type} (env : CircuitEnvironment Path) (w : CircuitWitness Path) :
    Prop where
  prevParsed : BalancePublicInputs.fullFromTarget env.capCount w.prevBalanceWords = .ok w.prevFull
  prevProofVerified : env.balanceProofAccepted w.prevBalanceWords w.prevFull.vd = true
  updateGates : UpdatePublicState.CircuitGates env.getRoot w.updatePublicState w.updateWitness
  txSettlementGates : env.txSettlementAccepted w.txSettlement = true
  spendParsed : Spend.parseTargetPublicInputs w.txSettlement.spendPublicWords = some w.spendTargets
  transferIncluded : env.transferInclusion w.transferWitness.merkleProof w.transferWitness.transfer
    w.transferWitness.transferIndex w.transferWitness.transferTreeRoot = true
  oldStateConnected : w.prevFull.pis.publicState = w.updatePublicState.oldState
  newStateConnected : w.txSettlement.publicState = w.updatePublicState.newState
  channelConnected : w.prevFull.pis.channelId = w.txSettlement.channelId
  previousCommitmentConnected :
    w.prevFull.pis.privateCommitment = rootOfHash w.spendTargets.previousPrivateCommitment
  blockReferenceGe : w.txSettlement.sendBlockBefore ≤ w.prevFull.pis.blockR
  txBlockGt : w.prevFull.pis.blockR < w.txSettlement.txBlockNumber
  blockSelect : Selected w.spendTargets.validityWire w.txSettlement.txBlockNumber
    w.prevFull.pis.blockR w.newBlockR
  commitmentSelect : Selected w.spendTargets.validityWire
    (rootOfHash w.spendTargets.newPrivateCommitment) w.prevFull.pis.privateCommitment
    w.newPrivateCommitment
  transferRootConnected : w.transferWitness.transferTreeRoot = w.txSettlement.tx.transferTreeRoot
  transferIndexZero : w.transferWitness.transferIndex = 0
  auxZeroGate : w.auxIsZeroWire = decide (w.transferWitness.transfer.auxData = zeroAux)
  doPushGate : w.doPushWire = w.spendTargets.validityWire * (1 - bit w.auxIsZeroWire)
  chainPushGate : w.pushedChain =
    settledTxChainPush env.keccak w.prevFull.pis.settledChain w.transferWitness.transfer.auxData
  chainSelect : Selected w.doPushWire w.pushedChain w.prevFull.pis.settledChain w.newSettledChain
  outputAssembled : w.newFull =
    ⟨{ channelId := w.prevFull.pis.channelId
       publicState := w.updatePublicState.newState
       blockR := w.newBlockR
       privateCommitment := w.newPrivateCommitment
       settledChain := w.newSettledChain }, w.prevFull.vd⟩
  registered : BalancePublicInputs.FullInputs.toConfiguredWords env.capCount w.newFull
    = .ok w.registeredWords

/-- The spend validity wire is `BoolTarget::new_unsafe`; Booleanity is supplied
    by the verified spend proof (Spend registers a computed equality bit), not
    by a gate of this file. -/
def FlagBoolean {Path : Type} (w : CircuitWitness Path) : Prop :=
  w.spendTargets.validityWire ≤ 1

/-- Lowering premise for the U63 comparison gadgets and the keccak gadget. -/
structure FieldAndGadgetLowering {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) : Prop where
  blockRangeChecked : w.prevFull.pis.blockR < BalancePublicInputs.blockLimit ∧
    w.txSettlement.txBlockNumber < BalancePublicInputs.blockLimit ∧
    w.txSettlement.sendBlockBefore < BalancePublicInputs.blockLimit
  auxLimbsChecked : w.transferWitness.transfer.auxData.length = auxLength ∧
    ∀ x ∈ w.transferWitness.transfer.auxData, x < Spend.wordBase
  chainLimbsChecked : ∀ x ∈ w.prevFull.pis.settledChain.words, x < BalancePublicInputs.wordBase

theorem circuit_enforces_strict_tx_block_increase {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.prevFull.pis.blockR < w.txSettlement.txBlockNumber := g.txBlockGt

theorem circuit_block_order_implies_native_block_order {Path : Type}
    (env : CircuitEnvironment Path) (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.txSettlement.sendBlockBefore ≤ w.prevFull.pis.blockR ∧
    w.prevFull.pis.blockR ≤ w.txSettlement.txBlockNumber :=
  ⟨g.blockReferenceGe, Nat.le_of_lt g.txBlockGt⟩

theorem circuit_binds_carried_verifier_data {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.newFull.vd = w.prevFull.vd ∧
    env.balanceProofAccepted w.prevBalanceWords w.newFull.vd = true := by
  rw [g.outputAssembled]
  exact ⟨rfl, g.prevProofVerified⟩

theorem circuit_preserves_channel_identity {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.newFull.pis.channelId = w.prevFull.pis.channelId ∧
    w.newFull.pis.channelId = w.txSettlement.channelId := by
  rw [g.outputAssembled]
  exact ⟨rfl, g.channelConnected⟩

theorem circuit_public_state_is_the_verified_update {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.newFull.pis.publicState = w.updatePublicState.newState ∧
    w.prevFull.pis.publicState = w.updatePublicState.oldState ∧
    UpdatePublicState.CircuitGates env.getRoot w.updatePublicState w.updateWitness := by
  rw [g.outputAssembled]
  exact ⟨rfl, g.oldStateConnected, g.updateGates⟩

theorem circuit_binds_transfer_leaf_zero_of_settled_tx {Path : Type}
    (env : CircuitEnvironment Path) (w : CircuitWitness Path) (g : CircuitGates env w) :
    env.transferInclusion w.transferWitness.merkleProof w.transferWitness.transfer 0
      w.txSettlement.tx.transferTreeRoot = true := by
  have h := g.transferIncluded
  rw [g.transferIndexZero, g.transferRootConnected] at h
  exact h

theorem circuit_previous_commitment_is_the_spend_input {Path : Type}
    (env : CircuitEnvironment Path) (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.prevFull.pis.privateCommitment = rootOfHash w.spendTargets.previousPrivateCommitment :=
  g.previousCommitmentConnected

theorem flag_boolean_cases {Path : Type} (w : CircuitWitness Path) (b : FlagBoolean w) :
    w.spendTargets.validityWire = 0 ∨ w.spendTargets.validityWire = 1 := by
  unfold FlagBoolean at b
  omega

theorem circuit_do_push_is_valid_and_nonzero_aux {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) (b : FlagBoolean w) :
    w.doPushWire = (if w.spendTargets.validityWire = 1 ∧
      w.transferWitness.transfer.auxData ≠ zeroAux then 1 else 0) := by
  rw [g.doPushGate, g.auxZeroGate]
  rcases flag_boolean_cases w b with hv | hv <;>
    by_cases hz : w.transferWitness.transfer.auxData = zeroAux <;> simp [hv, hz, bit]

theorem circuit_output_is_next_inputs {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) (b : FlagBoolean w) :
    w.newFull.pis = nextInputs env.keccak w.prevFull.pis w.updatePublicState.newState
      (decide (w.spendTargets.validityWire ≠ 0)) (rootOfHash w.spendTargets.newPrivateCommitment)
      w.txSettlement.txBlockNumber w.transferWitness.transfer.auxData := by
  have hpush := circuit_do_push_is_valid_and_nonzero_aux env w g b
  obtain ⟨hb1, hb0⟩ := g.blockSelect
  obtain ⟨hc1, hc0⟩ := g.commitmentSelect
  obtain ⟨hs1, hs0⟩ := g.chainSelect
  rw [g.outputAssembled]
  rcases flag_boolean_cases w b with hv | hv
  · have hd : w.doPushWire = 0 := by rw [hpush]; simp [hv]
    simp [nextInputs, hv, hb0 hv, hc0 hv, hs0 hd]
  · by_cases hz : w.transferWitness.transfer.auxData = zeroAux
    · have hd : w.doPushWire = 0 := by rw [hpush]; simp [hz]
      simp [nextInputs, hv, hz, hb1 hv, hc1 hv, hs0 hd]
    · have hd : w.doPushWire = 1 := by rw [hpush]; simp [hv, hz]
      simp [nextInputs, hv, hz, hb1 hv, hc1 hv, hs1 hd, g.chainPushGate]

theorem circuit_chain_fold_requires_valid_spend_and_nonzero_aux {Path : Type}
    (env : CircuitEnvironment Path) (w : CircuitWitness Path) (g : CircuitGates env w)
    (b : FlagBoolean w) :
    (w.spendTargets.validityWire = 1 ∧ w.transferWitness.transfer.auxData ≠ zeroAux →
      w.newSettledChain = env.keccak (chainPreimage w.prevFull.pis.settledChain
        w.transferWitness.transfer.auxData)) ∧
    (w.spendTargets.validityWire = 0 ∨ w.transferWitness.transfer.auxData = zeroAux →
      w.newSettledChain = w.prevFull.pis.settledChain) := by
  have hpush := circuit_do_push_is_valid_and_nonzero_aux env w g b
  obtain ⟨hs1, hs0⟩ := g.chainSelect
  constructor
  · intro h
    have hd : w.doPushWire = 1 := by rw [hpush]; simp [h]
    rw [hs1 hd, g.chainPushGate]
    rfl
  · intro h
    have hd : w.doPushWire = 0 := by
      rw [hpush]
      rcases h with h | h
      · simp [h]
      · simp [h]
    exact hs0 hd

theorem circuit_invalid_spend_is_carried_not_rejected {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (g : CircuitGates env w) (hv : w.spendTargets.validityWire = 0) :
    w.newFull.pis = { w.prevFull.pis with publicState := w.updatePublicState.newState } := by
  have b : FlagBoolean w := by unfold FlagBoolean; omega
  rw [circuit_output_is_next_inputs env w g b]
  simp [hv, next_inputs_invalid_spend_carries_everything_but_public_state]

theorem circuit_registers_29_balance_words_plus_verifier_data {Path : Type}
    (env : CircuitEnvironment Path) (w : CircuitWitness Path) (g : CircuitGates env w) :
    w.registeredWords.length = balanceLength + BalancePublicInputs.verifierLength env.capCount ∧
    w.registeredWords.take balanceLength = w.newFull.pis.words := by
  have h := g.registered
  unfold BalancePublicInputs.FullInputs.toConfiguredWords
    BalancePublicInputs.VerifierData.toConfiguredWords at h
  split at h
  next hle =>
    simp only [Bind.bind, Except.bind, Pure.pure, Except.pure] at h
    have he := Except.ok.inj h
    rw [← he]
    constructor
    · simp [BalancePublicInputs.balance_word_count, BalancePublicInputs.Root.words,
        BalancePublicInputs.roots_encoding_length, BalancePublicInputs.verifierLength,
        List.length_take, Nat.min_eq_left hle, balanceLength, BalancePublicInputs.balanceLength]
      omega
    · have ht := List.take_left w.newFull.pis.words (w.newFull.vd.digest.words ++
          BalancePublicInputs.rootsWords (w.newFull.vd.cap.take env.capCount))
      rw [BalancePublicInputs.balance_word_count] at ht
      exact ht
  · simp only [Bind.bind, Except.bind] at h

/-! ## Constructor and witness-writing programs (lines 219-232, 330-337, 364-373) -/

inductive BuildOp where
  | allocatePreviousBalanceProof
  | parsePreviousFullInputs
  | verifyPreviousProofUnderCarriedVd
  | allocateUpdatePublicState
  | allocateTxSettlementWithSpendVerifier
  | allocateTransferWitnessChecked
  | connectOldState
  | connectNewState
  | connectChannel
  | connectPreviousCommitment
  | enforceBlockReferenceGe
  | enforceTxBlockGt
  | selectBlockReference
  | selectPrivateCommitment
  | connectTransferRoot
  | assertTransferIndexZero
  | computeAuxIsZero
  | andValidNonzeroAux
  | keccakChainPush
  | selectSettledChain
  | assembleNewFullInputs
  | assertSpendValidTrue
  deriving DecidableEq, Repr

def targetProgram : List BuildOp :=
  [.allocatePreviousBalanceProof, .parsePreviousFullInputs, .verifyPreviousProofUnderCarriedVd,
   .allocateUpdatePublicState, .allocateTxSettlementWithSpendVerifier,
   .allocateTransferWitnessChecked, .connectOldState, .connectNewState, .connectChannel,
   .connectPreviousCommitment, .enforceBlockReferenceGe, .enforceTxBlockGt,
   .selectBlockReference, .selectPrivateCommitment, .connectTransferRoot,
   .assertTransferIndexZero, .computeAuxIsZero, .andValidNonzeroAux, .keccakChainPush,
   .selectSettledChain, .assembleNewFullInputs]

inductive CircuitOp where
  | builderStandardRecursionConfig
  | buildTarget
  | registerConfiguredPublicInputs
  | addConstGate
  | build
  deriving DecidableEq, Repr

def constructorProgram : List CircuitOp :=
  [.builderStandardRecursionConfig, .buildTarget, .registerConfiguredPublicInputs,
   .addConstGate, .build]

inductive WriteOp where
  | previousBalanceProof
  | updatePublicState
  | txSettlement
  | transferWitness
  | newFullInputs
  | circuitPublicInputs
  deriving DecidableEq, Repr

/-- SendTxTarget::set_witness followed by SendTxCircuit::prove's own
    public_inputs.set_witness of the SAME native value. -/
def witnessWriteProgram : List WriteOp :=
  [.previousBalanceProof, .updatePublicState, .txSettlement, .transferWitness,
   .newFullInputs, .circuitPublicInputs]

def positionOf {α : Type} [DecidableEq α] (x : α) : List α → Nat
  | [] => 0
  | y :: ys => if x = y then 0 else positionOf x ys + 1

def occurrences {α : Type} [DecidableEq α] (x : α) (xs : List α) : Nat :=
  (xs.filter (fun y => decide (y = x))).length

theorem constructor_verifies_previous_proof_before_any_connection :
    positionOf BuildOp.verifyPreviousProofUnderCarriedVd targetProgram <
      positionOf BuildOp.connectOldState targetProgram := by decide

theorem constructor_pins_transfer_root_and_index_after_inclusion_allocation :
    positionOf BuildOp.allocateTransferWitnessChecked targetProgram <
      positionOf BuildOp.connectTransferRoot targetProgram ∧
    positionOf BuildOp.connectTransferRoot targetProgram <
      positionOf BuildOp.assertTransferIndexZero targetProgram := by decide

theorem constructor_registers_public_inputs_before_const_gate_and_build :
    constructorProgram = [.builderStandardRecursionConfig, .buildTarget,
      .registerConfiguredPublicInputs, .addConstGate, .build] := rfl

/-- The vocabulary contains an "assert the spend flag is true" operation so
    that its ABSENCE from the actual constructor is a checkable statement:
    an invalid spend is carried, never rejected, by the send branch. -/
theorem constructor_never_asserts_spend_validity :
    BuildOp.assertSpendValidTrue ∉ targetProgram := by decide

theorem witness_writes_new_public_inputs_twice_from_native_value :
    occurrences WriteOp.newFullInputs witnessWriteProgram +
      occurrences WriteOp.circuitPublicInputs witnessWriteProgram = 2 := by decide

/-! ## Serialization (lines 399-443) -/

structure CircuitImage (Data Common Target PublicTargets : Type) where
  data : Data
  balanceCd : Common
  target : Target
  publicInputs : PublicTargets

structure SerializationFailure where
  stage : String
  detail : String
  deriving DecidableEq, Repr

def toBytes {Data Common Target PublicTargets : Type}
    (serializeData : Data → Except String (List Nat))
    (serializeCommon : Common → Except String (List Nat))
    (encode : CircuitImage (List Nat) (List Nat) Target PublicTargets → Except String (List Nat))
    (circuit : CircuitImage Data Common Target PublicTargets) :
    Except SerializationFailure (List Nat) :=
  match serializeData circuit.data with
  | .error e => .error ⟨"send tx circuit data", e⟩
  | .ok data =>
    match serializeCommon circuit.balanceCd with
    | .error e => .error ⟨"send tx common circuit data", e⟩
    | .ok cd =>
      match encode ⟨data, cd, circuit.target, circuit.publicInputs⟩ with
      | .error e => .error ⟨"send tx circuit", e⟩
      | .ok bytes => .ok bytes

def fromBytes {Data Common Target PublicTargets : Type}
    (decode : List Nat →
      Except String (CircuitImage (List Nat) (List Nat) Target PublicTargets × Nat))
    (deserializeData : List Nat → Except String Data)
    (deserializeCommon : List Nat → Except String Common) (bytes : List Nat) :
    Except SerializationFailure (CircuitImage Data Common Target PublicTargets) :=
  match decode bytes with
  | .error e => .error ⟨"send tx circuit", e⟩
  | .ok (payload, _) =>
    match deserializeData payload.data with
    | .error e => .error ⟨"send tx circuit data", e⟩
    | .ok data =>
      match deserializeCommon payload.balanceCd with
      | .error e => .error ⟨"send tx common circuit data", e⟩
      | .ok cd => .ok ⟨data, cd, payload.target, payload.publicInputs⟩

theorem deserialization_keeps_payload_targets_without_reconstruction
    {Data Common Target PublicTargets : Type}
    (decode : List Nat →
      Except String (CircuitImage (List Nat) (List Nat) Target PublicTargets × Nat))
    (deserializeData : List Nat → Except String Data)
    (deserializeCommon : List Nat → Except String Common) (bytes : List Nat)
    (payload : CircuitImage (List Nat) (List Nat) Target PublicTargets) (consumed : Nat)
    (data : Data) (cd : Common) (hd : decode bytes = .ok (payload, consumed))
    (hdata : deserializeData payload.data = .ok data)
    (hcd : deserializeCommon payload.balanceCd = .ok cd) :
    fromBytes decode deserializeData deserializeCommon bytes =
      .ok ⟨data, cd, payload.target, payload.publicInputs⟩ := by
  simp [fromBytes, hd, hdata, hcd]

/-! ## Concrete traces: a normal valid send, and the native/circuit block-order divergence -/

def examplePublicState : PublicState := ⟨6, 0, 0, BalancePublicInputs.Root.zero, BalancePublicInputs.Root.zero, BalancePublicInputs.Root.zero⟩

def examplePrevious : BalanceInputs :=
  { channelId := 7
    publicState := examplePublicState
    blockR := 2
    privateCommitment := ⟨1, 2, 3, 4⟩
    settledChain := ⟨5, 5, 5, 5, 5, 5, 5, 5⟩ }

def exampleVd : VerifierData := ⟨⟨11, 12, 13, 14⟩, [⟨21, 22, 23, 24⟩]⟩

def exampleAux : List Nat := [9, 8, 7, 6, 5, 4, 3, 2]

def exampleTransfer : Spend.Transfer :=
  { recipient := [1, 1, 1, 1, 1, 1, 1, 1], tokenIndex := 0, amount := 10, auxData := exampleAux }

def exampleTx : Spend.Tx := ⟨⟨31, 32, 33, 34⟩, 0⟩

/-- Spend statement words: prev commitment, new commitment, tx (root, nonce), valid=1. -/
def exampleSpendWords : List Nat := [1, 2, 3, 4, 41, 42, 43, 44, 31, 32, 33, 34, 0, 1]

def exampleTxSettlement (txBlock : Nat) : TxSettlement :=
  { channelId := 7
    tx := exampleTx
    publicState := examplePublicState
    sendBlockBefore := 2
    txBlockNumber := txBlock
    spendPublicWords := exampleSpendWords }

def exampleTransferWitness : TransferWitness Unit :=
  ⟨exampleTx.transferTreeRoot, exampleTransfer, 0, ()⟩

def exampleUpdate : Update :=
  ⟨examplePublicState, examplePublicState, UpdatePublicState.dummyProof⟩

def exampleKeccak : List Nat → Bytes8 := fun xs => ⟨xs.length, 0, 0, 0, 0, 0, 0, 0⟩

def exampleEnvironment : Environment Unit :=
  { capCount := 1
    convertFields := fun xs => .ok xs
    transferInclusion := fun _ _ _ _ => true
    keccak := exampleKeccak }

def exampleWitness (txBlock : Nat) : Witness Unit :=
  { prevBalanceWords := BalancePublicInputs.FullInputs.words ⟨examplePrevious, exampleVd⟩
    updatePublicState := exampleUpdate
    txSettlement := exampleTxSettlement txBlock
    transferWitness := exampleTransferWitness }

def exampleOutput (txBlock : Nat) : FullInputs :=
  ⟨{ channelId := 7
     publicState := examplePublicState
     blockR := txBlock
     privateCommitment := ⟨41, 42, 43, 44⟩
     settledChain := ⟨17, 0, 0, 0, 0, 0, 0, 0⟩ }, exampleVd⟩

theorem example_previous_parses_natively :
    BalancePublicInputs.fullFromNative exampleEnvironment.convertFields exampleEnvironment.capCount
      (exampleWitness 3).prevBalanceWords = .ok ⟨examplePrevious, exampleVd⟩ := by
  apply BalancePublicInputs.native_full_roundtrip
  · simp [BalancePublicInputs.AllocationChecks, examplePrevious, examplePublicState,
      BalancePublicInputs.Bytes8.words, BalancePublicInputs.wordBase, BalancePublicInputs.blockLimit]
  · decide
  · rfl

theorem example_spend_words_parse_natively :
    Spend.parseNativePublicInputs exampleSpendWords =
      .ok ⟨⟨1, 2, 3, 4⟩, ⟨41, 42, 43, 44⟩, exampleTx, true⟩ := by
  rfl

theorem example_valid_send_is_admitted_natively :
    toPublicInputs exampleEnvironment (exampleWitness 3) = .ok (exampleOutput 3) := by
  have h := native_admission_of_checks exampleEnvironment (exampleWitness 3)
    ⟨examplePrevious, exampleVd⟩ ⟨⟨1, 2, 3, 4⟩, ⟨41, 42, 43, 44⟩, exampleTx, true⟩
    example_previous_parses_natively example_spend_words_parse_natively
    ⟨rfl, rfl, rfl, rfl, by decide, by decide, rfl, rfl, rfl⟩
  rw [h]
  rfl

/-- The prover-side divergence: `tx_block_number == block_r` passes the
    native builder (non-strict `>=`) ... -/
theorem native_admits_equal_tx_block_and_block_r :
    toPublicInputs exampleEnvironment (exampleWitness 2) = .ok (exampleOutput 2) := by
  have h := native_admission_of_checks exampleEnvironment (exampleWitness 2)
    ⟨examplePrevious, exampleVd⟩ ⟨⟨1, 2, 3, 4⟩, ⟨41, 42, 43, 44⟩, exampleTx, true⟩
    example_previous_parses_natively example_spend_words_parse_natively
    ⟨rfl, rfl, rfl, rfl, by decide, by decide, rfl, rfl, rfl⟩
  rw [h]
  rfl

/-- ... but no assignment of the remaining wires satisfies the circuit, whose
    `enforce_gt` is strict. So the native witness is unprovable, and nothing
    the circuit accepts violates the native inequality. -/
theorem circuit_rejects_equal_tx_block_and_block_r {Path : Type} (env : CircuitEnvironment Path)
    (w : CircuitWitness Path) (hprev : w.prevFull.pis.blockR = 2)
    (hts : w.txSettlement.txBlockNumber = 2) : ¬ CircuitGates env w := by
  intro g
  have h := g.txBlockGt
  omega

def exampleCircuitEnvironment : CircuitEnvironment Unit :=
  { exampleEnvironment with
    getRoot := fun _ _ _ => BalancePublicInputs.Root.zero
    balanceProofAccepted := fun _ _ => true
    txSettlementAccepted := fun _ => true }

def exampleCircuitWitness : CircuitWitness Unit :=
  { prevBalanceWords := BalancePublicInputs.FullInputs.words ⟨examplePrevious, exampleVd⟩
    prevFull := ⟨examplePrevious, exampleVd⟩
    updatePublicState := exampleUpdate
    updateWitness := ⟨true, false, BalancePublicInputs.Root.zero⟩
    txSettlement := exampleTxSettlement 3
    spendTargets := ⟨⟨1, 2, 3, 4⟩, ⟨41, 42, 43, 44⟩, exampleTx, 1⟩
    transferWitness := exampleTransferWitness
    auxIsZeroWire := false
    doPushWire := 1
    newBlockR := 3
    newPrivateCommitment := ⟨41, 42, 43, 44⟩
    pushedChain := ⟨17, 0, 0, 0, 0, 0, 0, 0⟩
    newSettledChain := ⟨17, 0, 0, 0, 0, 0, 0, 0⟩
    newFull := exampleOutput 3
    registeredWords := BalancePublicInputs.FullInputs.words (exampleOutput 3) }

theorem example_previous_parses_as_target :
    BalancePublicInputs.fullFromTarget 1 exampleCircuitWitness.prevBalanceWords =
      .ok ⟨examplePrevious, exampleVd⟩ := by
  have h := BalancePublicInputs.full_target_roundtrip ⟨examplePrevious, exampleVd⟩
  exact h

theorem example_update_gates :
    UpdatePublicState.CircuitGates exampleCircuitEnvironment.getRoot exampleUpdate
      ⟨true, false, BalancePublicInputs.Root.zero⟩ where
  pathHeight := UpdatePublicState.dummy_has_63_siblings
  equalityGate := by decide
  notGate := rfl
  merkleEvaluation := rfl
  conditionalRoot := fun h => by cases h

theorem example_valid_send_satisfies_circuit_gates :
    CircuitGates exampleCircuitEnvironment exampleCircuitWitness where
  prevParsed := example_previous_parses_as_target
  prevProofVerified := rfl
  updateGates := example_update_gates
  txSettlementGates := rfl
  spendParsed := rfl
  transferIncluded := rfl
  oldStateConnected := rfl
  newStateConnected := rfl
  channelConnected := rfl
  previousCommitmentConnected := rfl
  blockReferenceGe := by decide
  txBlockGt := by decide
  blockSelect := ⟨fun _ => rfl, fun h => by cases h⟩
  commitmentSelect := ⟨fun _ => rfl, fun h => by cases h⟩
  transferRootConnected := rfl
  transferIndexZero := rfl
  auxZeroGate := by decide
  doPushGate := rfl
  chainPushGate := rfl
  chainSelect := ⟨fun _ => rfl, fun h => by cases h⟩
  outputAssembled := rfl
  registered := by
    have h := BalancePublicInputs.configured_encoding_matches_full_shape (exampleOutput 3)
    exact h

theorem example_circuit_and_native_statements_agree :
    exampleCircuitWitness.newFull = exampleOutput 3 ∧
    toPublicInputs exampleEnvironment (exampleWitness 3) = .ok exampleCircuitWitness.newFull :=
  ⟨rfl, example_valid_send_is_admitted_natively⟩

theorem example_chain_was_folded_with_17_word_preimage :
    (exampleOutput 3).pis.settledChain =
      exampleKeccak (chainPreimage examplePrevious.settledChain exampleAux) ∧
    (chainPreimage examplePrevious.settledChain exampleAux).length = chainPreimageLength := by
  constructor
  · rfl
  · decide

end Zkp.Implementation.SendTxCircuit
