import Zkp.Implementation.SettlementVerifier
import Zkp.Implementation.CancelCloseCircuit

/-!
# Exact Solidity/native/circuit cancel-close statement bridge

This composes manually reviewed models, not Rust/Solidity extraction, compiler
refinement or proof-backend soundness. A successful modeled Solidity call identifies
the exact same adapter/proof/returned29words. It does not itself produce a satisfying
circuit witness: where used, CircuitGates and the local aggregate-proof contract
are explicit separate premises. No collision resistance is needed for field-order
and exact input binding below. Member ownership, current pending-close authority,
request generation, consumed cancellation-version floors and chain finality remain
Manager/history obligations; no generation/replay guard is invented in the circuit.
-/
namespace Zkp.Implementation.CancelCloseBridge

def scalar (v : SettlementVerifier.U64) : CloseCircuit.Words2 :=
  ⟨v.val / SettlementVerifier.limbBound,v.val % SettlementVerifier.limbBound⟩
def digest (v : SettlementVerifier.U256) : CloseCircuit.Words8 :=
  ⟨SettlementVerifier.word v.val 7,SettlementVerifier.word v.val 6,
    SettlementVerifier.word v.val 5,SettlementVerifier.word v.val 4,
    SettlementVerifier.word v.val 3,SettlementVerifier.word v.val 2,
    SettlementVerifier.word v.val 1,SettlementVerifier.word v.val 0⟩

def statement (f : SettlementVerifier.CancelFields) : CancelCloseCircuit.PublicInputs :=
  ⟨f.channelId.val,digest f.closeIntentDigest,digest f.memberSetCommitment,
    scalar f.closeFinalStateVersion,scalar f.revivedStateVersion,digest f.revivedChannelStateDigest⟩
def nativeStatement (f : SettlementVerifier.CancelFields) : CancelClosePublicInputs.PublicInputs :=
  ⟨f.channelId.val,digest f.closeIntentDigest,digest f.memberSetCommitment,
    f.closeFinalStateVersion.val,f.revivedStateVersion.val,digest f.revivedChannelStateDigest⟩

theorem scalar_preserves_value (v : SettlementVerifier.U64) : (scalar v).value = v.val :=
  SettlementVerifier.putU64_reconstructs v

theorem solidity_layout_is_exact_circuit_encoding (f : SettlementVerifier.CancelFields) :
    (statement f).words = SettlementVerifier.expectedCancelCloseLimbs f := rfl

theorem native_codec_uses_the_same_twenty_nine_words (f : SettlementVerifier.CancelFields) :
    CancelClosePublicInputs.toU64Vec (nativeStatement f) = (statement f).words := rfl

theorem accepted_cancel_has_exact_adapter_receipt
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.CancelFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCancelClose evm installed f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.cancel proof = .ok (statement f).words :=
  (SettlementVerifier.cancel_verification_exact_statement evm installed f proof accepted).1

theorem accepted_cancel_supplies_every_public_limb_range
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.CancelFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCancelClose evm installed f proof = .ok true) :
    (statement f).AllocationChecks :=
  (SettlementVerifier.cancel_verification_exact_statement evm installed f proof accepted).2

theorem accepted_cancel_binds_every_circuit_field
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.CancelFields) (proof : SettlementVerifier.Bytes)
    (p : CancelCloseCircuit.PublicInputs)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.cancel proof = .ok p.words)
    (accepted : SettlementVerifier.verifyCancelClose evm installed f proof = .ok true) : p = statement f := by
  apply CancelCloseCircuit.public_encoding_is_injective
  have h := accepted_cancel_has_exact_adapter_receipt evm installed f proof accepted
  rw [receipt] at h
  exact Except.ok.inj h

theorem accepted_constrained_cancel_has_exact_version_and_era
    {AP Path Root : Type} (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.CancelFields) (proof : SettlementVerifier.Bytes)
    (p : CancelCloseCircuit.PublicInputs) (e : CancelCloseCircuit.Environment AP Path Root)
    (w : CancelCloseCircuit.ProofWitness AP Path) (g : CancelCloseCircuit.CircuitGates e p w)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.cancel proof = .ok p.words)
    (accepted : SettlementVerifier.verifyCancelClose evm installed f proof = .ok true) :
    f.closeFinalStateVersion.val < f.revivedStateVersion.val ∧
    w.privateData.closeNonce.value = w.privateData.nonce.value + 1 ∧
    w.privateData.closeNonce.value < 2^64 := by
  have h := CancelCloseCircuit.cancel_has_strict_version_and_exact_era e p w g
  have bound := accepted_cancel_binds_every_circuit_field evm installed f proof p receipt accepted
  rw [bound] at h
  simpa only [statement,scalar_preserves_value] using h

theorem accepted_constrained_members_signed_exact_solidity_revived_digest
    {AP Path Root : Type} (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (f : SettlementVerifier.CancelFields) (proof : SettlementVerifier.Bytes)
    (p : CancelCloseCircuit.PublicInputs) (e : CancelCloseCircuit.Environment AP Path Root)
    (w : CancelCloseCircuit.ProofWitness AP Path) (g : CancelCloseCircuit.CircuitGates e p w)
    (signed : CloseCircuit.Words8 → CloseCircuit.Words8 → Prop)
    (localAggregate : CloseCircuit.AggregateContractAt e signed w.aggregateProof w.aggregate)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.cancel proof = .ok p.words)
    (accepted : SettlementVerifier.verifyCancelClose evm installed f proof = .ok true) :
    e.keccak (CloseCircuit.memberSetPreimage w.privateData.memberCount
      w.privateData.memberActive w.aggregate.keys) = digest f.memberSetCommitment ∧
    ∀ slot, slot < w.privateData.memberCount →
      signed (w.aggregate.keys.getD slot CloseCircuit.Words8.zero) (digest f.revivedChannelStateDigest) := by
  have bound := accepted_cancel_binds_every_circuit_field evm installed f proof p receipt accepted
  constructor
  · simpa only [bound,statement] using g.memberSet
  · intro slot active
    have h := CancelCloseCircuit.every_active_member_signed_revived_imch e signed p w g localAggregate slot active
    rw [g.imch] at h
    simpa only [bound,statement] using h

end Zkp.Implementation.CancelCloseBridge
