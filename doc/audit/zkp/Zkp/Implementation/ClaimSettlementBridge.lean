import Zkp.Implementation.SettlementCloseBridge
import Zkp.Implementation.WithdrawalClaimCircuit
import Zkp.Implementation.PostCloseClaimCircuit
import Zkp.Implementation.H1Gadget

/-!
# Exact claim circuit -> Solidity statement bridges

The SAME adapter/proof/returned words are used throughout each theorem. This
connects current handwritten implementation models; it is not backend soundness
or a source/bytecode refinement proof. Circuit gate satisfaction is explicitly
separate from an adapter returning a word list. No arbitrary adapter acceptance
is asserted to establish plaintext, possession, latest-state authority or funds.
Manager dispatch, stored final head and nullifier ledger remain other boundaries.
-/
namespace Zkp.Implementation.ClaimSettlementBridge

def withdrawalRecipient (v : SettlementVerifier.Address) : WithdrawalClaimCircuit.Address :=
  ⟨SettlementVerifier.word v.val 4,SettlementVerifier.word v.val 3,SettlementVerifier.word v.val 2,
    SettlementVerifier.word v.val 1,SettlementVerifier.word v.val 0⟩

def withdrawalStatement (f : SettlementVerifier.WithdrawalFields) : WithdrawalClaimCircuit.PublicInputs := {
  closeId := SettlementCloseBridge.digest f.closeIntentDigest
  channelId := f.channelId.val
  h1 := SettlementCloseBridge.digest f.finalBalanceStateH1
  memberPk := SettlementCloseBridge.digest f.memberPkG
  recipient := withdrawalRecipient f.recipient
  ciphertextDigest := SettlementCloseBridge.digest f.userAmountDigest
  nullifier := SettlementCloseBridge.digest f.withdrawalNullifier
  amount := SettlementCloseBridge.scalar f.amount
  tokenSlot := f.tokenSlot.val
  tokenIndex := f.tokenIndex.val }

def nativeDigest (v : SettlementVerifier.U256) : ClosePublicInputs.Words8 :=
  CloseEncodingBridge.toNativeWords8 (SettlementCloseBridge.digest v)

def nativeScalar (v : SettlementVerifier.U64) : ClosePublicInputs.Words2 :=
  CloseEncodingBridge.toNativeWords2 (SettlementCloseBridge.scalar v)

def postCloseRecipient (v : SettlementVerifier.Address) : PostCloseClaimPublicInputs.Address :=
  ⟨SettlementVerifier.word v.val 4,SettlementVerifier.word v.val 3,SettlementVerifier.word v.val 2,
    SettlementVerifier.word v.val 1,SettlementVerifier.word v.val 0⟩

def postCloseStatement (f : SettlementVerifier.PostCloseFields) : PostCloseClaimPublicInputs.PublicInputs := {
  closeIntentDigest := nativeDigest f.closeIntentDigest
  receiverChannelId := f.channelId.val
  incomingTxHash := nativeDigest f.incomingTxHash
  receiverPkG := nativeDigest f.receiverPkG
  recipient := postCloseRecipient f.recipient
  sharedNativeNullifier := nativeDigest f.sharedNativeNullifier
  amount := nativeScalar f.amount
  finalBalanceStateH1 := nativeDigest f.finalBalanceStateH1
  finalAccumulatorRoot := nativeDigest f.finalSettledTxAccumulatorRoot
  tokenIndex := f.tokenIndex.val }

theorem withdrawal_recipient_preserves_all_five_address_words (v : SettlementVerifier.Address) :
    (withdrawalRecipient v).words = SettlementVerifier.putAddress v := rfl

theorem post_close_recipient_preserves_all_five_address_words (v : SettlementVerifier.Address) :
    (postCloseRecipient v).words = SettlementVerifier.putAddress v := rfl

theorem withdrawal_layout_is_exact_50_word_statement (f : SettlementVerifier.WithdrawalFields) :
    (withdrawalStatement f).words = SettlementVerifier.expectedWithdrawalClaimLimbs f := rfl

theorem post_close_layout_is_exact_57_word_statement (f : SettlementVerifier.PostCloseFields) :
    (postCloseStatement f).words = SettlementVerifier.expectedPostCloseClaimLimbs f := rfl

theorem accepted_withdrawal_has_exact_adapter_receipt
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyWithdrawalClaim evm installed f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.withdrawal proof = .ok (withdrawalStatement f).words :=
  (SettlementVerifier.withdrawal_verification_exact_statement evm installed f proof accepted).1

theorem accepted_post_close_has_exact_adapter_receipt
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyPostCloseClaim evm installed f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.postClose proof = .ok (postCloseStatement f).words :=
  (SettlementVerifier.postClose_verification_exact_statement evm installed f proof accepted).1

theorem accepted_withdrawal_binds_all_ten_fields
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (p : WithdrawalClaimCircuit.PublicInputs)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.withdrawal proof = .ok p.words)
    (accepted : SettlementVerifier.verifyWithdrawalClaim evm installed f proof = .ok true) :
    p = withdrawalStatement f := by
  apply WithdrawalClaimCircuit.public_encoding_injective
  have call := accepted_withdrawal_has_exact_adapter_receipt evm installed f proof accepted
  rw [receipt] at call
  exact Except.ok.inj call

theorem accepted_post_close_binds_all_ten_fields
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (p : PostCloseClaimPublicInputs.PublicInputs)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.postClose proof = .ok p.words)
    (accepted : SettlementVerifier.verifyPostCloseClaim evm installed f proof = .ok true) :
    p = postCloseStatement f := by
  apply PostCloseClaimPublicInputs.public_input_encoding_is_injective
  have call := accepted_post_close_has_exact_adapter_receipt evm installed f proof accepted
  rw [receipt] at call
  exact Except.ok.inj call

theorem withdrawal_verified_asset_is_same_header_registry_slot
    {Path Core : Type} (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (p : WithdrawalClaimCircuit.PublicInputs) (e : WithdrawalClaimCircuit.Environment Path Core)
    (w : WithdrawalClaimCircuit.Witness Path Core) (g : WithdrawalClaimCircuit.CircuitGates e p w)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.withdrawal proof = .ok p.words)
    (accepted : SettlementVerifier.verifyWithdrawalClaim evm installed f proof = .ok true) :
    ∃ i : Fin 10, i.val = f.tokenSlot.val ∧ w.header.registry i = f.tokenIndex.val ∧
      w.ciphertexts i = SettlementCloseBridge.digest f.userAmountDigest := by
  have selected := WithdrawalClaimCircuit.selected_payment_asset_and_ciphertext g
  rw [accepted_withdrawal_binds_all_ten_fields evm installed f proof p receipt accepted] at selected
  exact selected

theorem withdrawal_core_receives_exact_solidity_amount
    {Path Core : Type} (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.WithdrawalFields) (proof : SettlementVerifier.Bytes)
    (p : WithdrawalClaimCircuit.PublicInputs) (e : WithdrawalClaimCircuit.Environment Path Core)
    (w : WithdrawalClaimCircuit.Witness Path Core) (g : WithdrawalClaimCircuit.CircuitGates e p w)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.withdrawal proof = .ok p.words)
    (accepted : SettlementVerifier.verifyWithdrawalClaim evm installed f proof = .ok true) :
    e.decryption w.polynomials w.core (f.amount.val % SettlementVerifier.limbBound)
      (f.amount.val / SettlementVerifier.limbBound) := by
  have core := g.amountConnect
  rw [accepted_withdrawal_binds_all_ten_fields evm installed f proof p receipt accepted] at core
  exact core

theorem post_close_core_receives_exact_solidity_amount
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (e : PostCloseClaimCircuit.Environment) (w : PostCloseClaimCircuit.RawWitness)
    (g : PostCloseClaimCircuit.ConstructorGates e w)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.postClose proof = .ok w.p.words)
    (accepted : SettlementVerifier.verifyPostCloseClaim evm installed f proof = .ok true) :
    w.coreAmount = nativeScalar f.amount := by
  have core := PostCloseClaimCircuit.amount_is_exact_core_output e w g
  rw [accepted_post_close_binds_all_ten_fields evm installed f proof w.p receipt accepted] at core
  exact core.symm

theorem post_close_source_hash_uses_exact_solidity_token_and_channel
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.PostCloseFields) (proof : SettlementVerifier.Bytes)
    (w : PostCloseClaimCircuit.RawWitness)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.postClose proof = .ok w.p.words)
    (accepted : SettlementVerifier.verifyPostCloseClaim evm installed f proof = .ok true) :
    (PostCloseClaimCircuit.txIds w).w5 = f.tokenIndex.val ∧
      (PostCloseClaimCircuit.txIds w).w6 = f.channelId.val := by
  have field := accepted_post_close_binds_all_ten_fields evm installed f proof w.p receipt accepted
  simp [PostCloseClaimCircuit.txIds,field,postCloseStatement]

def tenOfFunction {α : Type} (f : Fin 10 → α) : ClosePublicInputs.Ten α :=
  ⟨f 0,f 1,f 2,f 3,f 4,f 5,f 6,f 7,f 8,f 9⟩

def mapTen {α β : Type} (f : α → β) (t : ClosePublicInputs.Ten α) : ClosePublicInputs.Ten β :=
  ⟨f t.t0,f t.t1,f t.t2,f t.t3,f t.t4,f t.t5,f t.t6,f t.t7,f t.t8,f t.t9⟩

def withdrawalHeader (channel : Nat) (h : WithdrawalClaimCircuit.Header) : H1Gadget.Header :=
  ⟨channel,h.memberCount,h.delegateCount,h.tokenCount,tenOfFunction h.registry,h.slotRoot,
    h.settledChain,h.accumulatorRoot,h.stateVersion⟩

def withdrawalSlot (pk : CloseCircuit.Words8) (row : WithdrawalClaimCircuit.Ten CloseCircuit.Words8)
    (adds : WithdrawalClaimCircuit.Ten Nat) (a : WithdrawalClaimCircuit.Address) : H1Gadget.SlotLeaf :=
  ⟨pk,tenOfFunction row,tenOfFunction adds,⟨a.a0,a.a1,a.a2,a.a3,a.a4⟩⟩

def postHeader (h : PostCloseClaimCircuit.Header) : H1Gadget.Header :=
  ⟨h.channelId,h.memberCount,h.delegateCount,h.tokenCount,h.registry,
    ⟨h.slotRoot.h0,h.slotRoot.h1,h.slotRoot.h2,h.slotRoot.h3⟩,
    CloseEncodingBridge.toCircuitWords8 h.settledChain,
    CloseEncodingBridge.toCircuitWords8 h.accumulatorRoot,
    CloseEncodingBridge.toCircuitWords2 h.stateVersion⟩

def postSlot (s : PostCloseClaimCircuit.Slot) : H1Gadget.SlotLeaf :=
  ⟨CloseEncodingBridge.toCircuitWords8 s.pkDigest,
    mapTen CloseEncodingBridge.toCircuitWords8 s.encDigests,s.pendingAdds,
    ⟨s.recipient.a0,s.recipient.a1,s.recipient.a2,s.recipient.a3,s.recipient.a4⟩⟩

theorem withdrawal_uses_same_shared_h1_header (channel : Nat) (h : WithdrawalClaimCircuit.Header) :
    H1Gadget.headerWords (withdrawalHeader channel h) = WithdrawalClaimCircuit.headerPreimage channel h := rfl

theorem withdrawal_uses_same_shared_full_slot_leaf
    (pk : CloseCircuit.Words8) (row : WithdrawalClaimCircuit.Ten CloseCircuit.Words8)
    (adds : WithdrawalClaimCircuit.Ten Nat) (a : WithdrawalClaimCircuit.Address) :
    H1Gadget.leafWords (withdrawalSlot pk row adds a) = WithdrawalClaimCircuit.slotPreimage pk row adds a := by
  simp [H1Gadget.leafWords,withdrawalSlot,tenOfFunction,ClosePublicInputs.Ten.values,
    CloseCircuit.flattenAmounts,WithdrawalClaimCircuit.slotPreimage,WithdrawalClaimCircuit.digestRowWords,
    WithdrawalClaimCircuit.tenList,WithdrawalClaimCircuit.Address.words,H1Gadget.Words5.words,
    H1Gadget.leafDomain,WithdrawalClaimCircuit.slotDomain,List.append_assoc]

theorem post_close_uses_same_shared_h1_header (h : PostCloseClaimCircuit.Header) :
    H1Gadget.headerWords (postHeader h) = h.words := rfl

theorem post_close_uses_same_shared_full_slot_leaf (s : PostCloseClaimCircuit.Slot) :
    H1Gadget.leafWords (postSlot s) = s.words := by
  simp [H1Gadget.leafWords,postSlot,mapTen,ClosePublicInputs.Ten.values,
    CloseCircuit.flattenAmounts,PostCloseClaimCircuit.Slot.words,CloseEncodingBridge.toCircuitWords8,
    CloseCircuit.Words8.words,ClosePublicInputs.Words8.words,PostCloseClaimPublicInputs.Address.words,
    H1Gadget.Words5.words,H1Gadget.leafDomain,PostCloseClaimCircuit.ims2,List.bind,List.append_assoc]

theorem post_close_canonical_root_uses_same_safe_encode_back (w : ClosePublicInputs.Words8)
    (canonical : PostCloseClaimCircuit.CanonicalRoot w) :
    H1Gadget.TargetToHashOutGates (CloseEncodingBridge.toCircuitWords8 w) := by
  have eq := congrArg CloseEncodingBridge.toCircuitWords8 canonical
  exact eq.symm

end Zkp.Implementation.ClaimSettlementBridge
