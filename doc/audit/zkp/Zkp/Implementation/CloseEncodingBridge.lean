import Zkp.Implementation.CloseCircuit
import Zkp.Implementation.ClosePublicInputs

/-!
# Exact native/circuit close public-input representation bridge

Source composition: close_pis.rs::ChannelClosePublicInputs::{to_u64_vec,from_u64_slice}
and close_circuit.rs::ChannelClosePublicInputsTarget::{to_vec,from_slice}.
The imported files are handwritten implementation models, NOT extracted/compiler-
verified translations. This module proves an actual kernel-checked connection
between their separately defined word and public-input records; it does not assume
an encoding-equality premise or proof acceptance.

The unconstrained target slice reader only checks length. Native decoding also
checks nonzero channel, hash/channel u32 words and u8/u16 counts, and normalizes
its six scalar pairs by Rust u64 shift/OR. Interoperability is therefore stated
for canonical NativeWidths plus nonzero channel, never for arbitrary raw limbs.
Neither u8/u16 nor all-u32 is the protocol member/delegate capacity rule.
No signature, hash-binding, current-head, asset-backing, EVM ABI, or Solidity
byte-serialization theorem is claimed. All such boundaries remain elsewhere.
-/
namespace Zkp.Implementation.CloseEncodingBridge

def toCircuitWords2 (w : ClosePublicInputs.Words2) : CloseCircuit.Words2 := ⟨w.hi,w.lo⟩
def toNativeWords2 (w : CloseCircuit.Words2) : ClosePublicInputs.Words2 := ⟨w.hi,w.lo⟩
def toCircuitWords8 (w : ClosePublicInputs.Words8) : CloseCircuit.Words8 :=
  ⟨w.w0,w.w1,w.w2,w.w3,w.w4,w.w5,w.w6,w.w7⟩
def toNativeWords8 (w : CloseCircuit.Words8) : ClosePublicInputs.Words8 :=
  ⟨w.w0,w.w1,w.w2,w.w3,w.w4,w.w5,w.w6,w.w7⟩

theorem native_scalar_conversion_round_trip (w : ClosePublicInputs.Words2) :
    toNativeWords2 (toCircuitWords2 w) = w := rfl

theorem circuit_scalar_conversion_round_trip (w : CloseCircuit.Words2) :
    toCircuitWords2 (toNativeWords2 w) = w := rfl

theorem native_digest_conversion_round_trip (w : ClosePublicInputs.Words8) :
    toNativeWords8 (toCircuitWords8 w) = w := rfl

theorem circuit_digest_conversion_round_trip (w : CloseCircuit.Words8) :
    toCircuitWords8 (toNativeWords8 w) = w := rfl

theorem scalar_conversion_preserves_exact_words (w : ClosePublicInputs.Words2) :
    (toCircuitWords2 w).words = w.words := rfl

theorem digest_conversion_preserves_exact_words (w : ClosePublicInputs.Words8) :
    (toCircuitWords8 w).words = w.words := rfl

def toCircuit (p : ClosePublicInputs.PublicInputs) : CloseCircuit.PublicInputs := {
  channelId := p.channelId
  closeNonce := toCircuitWords2 p.closeNonce
  finalEpoch := toCircuitWords2 p.finalEpoch
  finalSmallBlock := toCircuitWords2 p.finalSmallBlock
  freezeNonce := toCircuitWords2 p.freezeNonce
  stateDigest := toCircuitWords8 p.stateDigest
  h1 := toCircuitWords8 p.h1
  genesisFund := toCircuitWords8 p.genesisFund
  fundRoot := toCircuitWords8 p.fundRoot
  burnHash := toCircuitWords8 p.burnHash
  withdrawalDigest := toCircuitWords8 p.withdrawalDigest
  closeId := toCircuitWords8 p.closeId
  snapshot := toCircuitWords2 p.snapshot
  stateVersion := toCircuitWords2 p.stateVersion
  settledChain := toCircuitWords8 p.settledChain
  accumulatorRoot := toCircuitWords8 p.accumulatorRoot
  memberSet := toCircuitWords8 p.memberSet
  memberCount := p.memberCount
  delegateCount := p.delegateCount
  tokenFundsDigest := toCircuitWords8 p.tokenFundsDigest }

def toNative (p : CloseCircuit.PublicInputs) : ClosePublicInputs.PublicInputs := {
  channelId := p.channelId
  closeNonce := toNativeWords2 p.closeNonce
  finalEpoch := toNativeWords2 p.finalEpoch
  finalSmallBlock := toNativeWords2 p.finalSmallBlock
  freezeNonce := toNativeWords2 p.freezeNonce
  stateDigest := toNativeWords8 p.stateDigest
  h1 := toNativeWords8 p.h1
  genesisFund := toNativeWords8 p.genesisFund
  fundRoot := toNativeWords8 p.fundRoot
  burnHash := toNativeWords8 p.burnHash
  withdrawalDigest := toNativeWords8 p.withdrawalDigest
  closeId := toNativeWords8 p.closeId
  snapshot := toNativeWords2 p.snapshot
  stateVersion := toNativeWords2 p.stateVersion
  settledChain := toNativeWords8 p.settledChain
  accumulatorRoot := toNativeWords8 p.accumulatorRoot
  memberSet := toNativeWords8 p.memberSet
  memberCount := p.memberCount
  delegateCount := p.delegateCount
  tokenFundsDigest := toNativeWords8 p.tokenFundsDigest }

theorem native_public_input_conversion_round_trip (p : ClosePublicInputs.PublicInputs) :
    toNative (toCircuit p) = p := rfl

theorem circuit_public_input_conversion_round_trip (p : CloseCircuit.PublicInputs) :
    toCircuit (toNative p) = p := rfl

theorem to_circuit_preserves_exact_encoding (p : ClosePublicInputs.PublicInputs) :
    (toCircuit p).words = ClosePublicInputs.toU64Vec p := rfl

theorem to_native_preserves_exact_encoding (p : CloseCircuit.PublicInputs) :
    ClosePublicInputs.toU64Vec (toNative p) = p.words := rfl

theorem both_encodings_have_exactly_103_words (p : ClosePublicInputs.PublicInputs) :
    (toCircuit p).words.length = 103 ∧ (ClosePublicInputs.toU64Vec p).length = 103 := by
  constructor
  · exact CloseCircuit.public_input_word_count _
  · exact ClosePublicInputs.exact_word_length _

theorem encoded_statement_equality_iff_field_conversion (n : ClosePublicInputs.PublicInputs)
    (c : CloseCircuit.PublicInputs) :
    ClosePublicInputs.toU64Vec n = c.words ↔ toCircuit n = c := by
  constructor
  · intro equal
    apply CloseCircuit.exact_public_input_encoding_is_injective
    exact equal
  · intro equal
    rw [← to_circuit_preserves_exact_encoding n,equal]

/-- No range premise is required merely to read an already encoded target
    record. This statement deliberately is NOT native decoder acceptance. -/
theorem circuit_parser_reads_native_field_encoding (p : ClosePublicInputs.PublicInputs) :
    CloseCircuit.parseTargets (ClosePublicInputs.toU64Vec p) = some (toCircuit p) := by
  rw [← to_circuit_preserves_exact_encoding]
  exact CloseCircuit.target_public_input_round_trip _

theorem native_reader_and_circuit_reader_match (xs : List Nat) :
    toCircuit (ClosePublicInputs.readFields xs) = CloseCircuit.readTargetFields xs := rfl

theorem scalar_canonical_domain_preserved (w : ClosePublicInputs.Words2) :
    ClosePublicInputs.canonicalScalar w ↔
      (toCircuitWords2 w).hi < CloseCircuit.wordBase ∧
      (toCircuitWords2 w).lo < CloseCircuit.wordBase := Iff.rfl

theorem digest_canonical_domain_preserved (w : ClosePublicInputs.Words8) :
    ClosePublicInputs.canonicalDigest w ↔ CloseCircuit.CheckedWords (toCircuitWords8 w).words := Iff.rfl

/-- Native Rust representation widths imply the target allocator's word ranges.
    This is not either constructor's signature/member-capacity check. -/
theorem native_widths_imply_circuit_allocation_ranges (p : ClosePublicInputs.PublicInputs)
    (widths : ClosePublicInputs.NativeWidths p) :
    CloseCircuit.PublicInputs.AllocationChecks (toCircuit p) := by
  rcases widths with ⟨channel,s1,s2,s3,s4,s5,s6,d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,member,delegates,d11⟩
  have member32 : p.memberCount < ClosePublicInputs.limbBase := by
    change p.memberCount < 4294967296
    omega
  have delegate32 : p.delegateCount < ClosePublicInputs.limbBase := by
    change p.delegateCount < 4294967296
    omega
  unfold CloseCircuit.PublicInputs.AllocationChecks CloseCircuit.CheckedWords
  rw [to_circuit_preserves_exact_encoding]
  simp_all [or_imp,forall_and,ClosePublicInputs.toU64Vec,ClosePublicInputs.PublicInputs.words,
    ClosePublicInputs.Words2.words,ClosePublicInputs.canonicalScalar,
    ClosePublicInputs.canonicalDigest,CloseCircuit.wordBase,ClosePublicInputs.limbBase]

theorem native_decoder_reads_circuit_encoding (p : CloseCircuit.PublicInputs)
    (widths : ClosePublicInputs.NativeWidths (toNative p)) (nonzero : p.channelId ≠ 0) :
    ClosePublicInputs.fromU64Slice p.words = .ok (toNative p) := by
  rw [← to_native_preserves_exact_encoding p]
  exact ClosePublicInputs.native_codec_roundtrip _ widths nonzero

/-- The same original native state is recovered by both paths under exactly
    the representation premises used by the native codec theorem. -/
theorem canonical_native_codec_and_target_parser_agree (p : ClosePublicInputs.PublicInputs)
    (widths : ClosePublicInputs.NativeWidths p) (nonzero : p.channelId ≠ 0) :
    ClosePublicInputs.fromU64Slice (ClosePublicInputs.toU64Vec p) = .ok p ∧
    CloseCircuit.parseTargets (ClosePublicInputs.toU64Vec p) = some (toCircuit p) := by
  exact ⟨ClosePublicInputs.native_codec_roundtrip p widths nonzero,
    circuit_parser_reads_native_field_encoding p⟩

theorem checked_native_reencoding_keeps_circuit_statement (p q : ClosePublicInputs.PublicInputs)
    (widths : ClosePublicInputs.NativeWidths p) (nonzero : p.channelId ≠ 0)
    (decoded : ClosePublicInputs.fromU64Slice (ClosePublicInputs.toU64Vec p) = .ok q) :
    toCircuit q = toCircuit p ∧ ClosePublicInputs.toU64Vec q = (toCircuit p).words := by
  rw [ClosePublicInputs.native_codec_roundtrip p widths nonzero] at decoded
  cases decoded
  exact ⟨rfl,rfl⟩

theorem ordinary_native_statement_round_trips_through_both_models :
    ClosePublicInputs.fromU64Slice (ClosePublicInputs.toU64Vec ClosePublicInputs.normalPublicInputs) =
      .ok ClosePublicInputs.normalPublicInputs ∧
    CloseCircuit.parseTargets (ClosePublicInputs.toU64Vec ClosePublicInputs.normalPublicInputs) =
      some (toCircuit ClosePublicInputs.normalPublicInputs) := by
  exact ⟨ClosePublicInputs.normal_public_input_roundtrip,
    circuit_parser_reads_native_field_encoding _⟩

end Zkp.Implementation.CloseEncodingBridge
