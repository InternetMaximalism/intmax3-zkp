import Zkp.Implementation.SettlementVerifier
import Zkp.Implementation.CloseEncodingBridge

/-!
# Solidity/native/circuit close statement bridge

Composes the current handwritten translations of ChannelSettlementVerifier.sol,
close_circuit.rs and close_pis.rs. No new proof-acceptance or funds-safe oracle is
introduced. Successful modeled Solidity verification is followed back to the
actual modeled adapter return and exact circuit public-input record.

All twenty public fields, including both recomputed digests, are represented.
This is a theorem BETWEEN reviewed models, not extraction/refinement of Solidity,
Rust, the builder's emitted gates or EVM bytecode. The adapter's cryptographic
soundness, Keccak and ownership/backing of the authenticated statement remain
separate dependencies. A successful codec comparison does not prove that the
statement is true, latest, properly funded or signed.
-/
namespace Zkp.Implementation.SettlementCloseBridge

def scalar (v : SettlementVerifier.U64) : CloseCircuit.Words2 := ⟨v.val / SettlementVerifier.limbBound, v.val % SettlementVerifier.limbBound⟩

def digest (v : SettlementVerifier.U256) : CloseCircuit.Words8 :=
  ⟨SettlementVerifier.word v.val 7, SettlementVerifier.word v.val 6, SettlementVerifier.word v.val 5, SettlementVerifier.word v.val 4,
   SettlementVerifier.word v.val 3, SettlementVerifier.word v.val 2, SettlementVerifier.word v.val 1, SettlementVerifier.word v.val 0⟩

theorem scalar_words_exact (v : SettlementVerifier.U64) : (scalar v).words = SettlementVerifier.putU64 v := rfl
theorem digest_words_exact (v : SettlementVerifier.U256) : (digest v).words = SettlementVerifier.putBytes32 v := rfl

theorem scalar_conversion_injective (a b : SettlementVerifier.U64) (eq : scalar a = scalar b) : a = b :=
  SettlementVerifier.putU64_injective a b (congrArg CloseCircuit.Words2.words eq)

theorem digest_conversion_injective (a b : SettlementVerifier.U256) (eq : digest a = digest b) : a = b :=
  SettlementVerifier.putUint256_injective a b (congrArg CloseCircuit.Words8.words eq)

theorem scalar_recovers_original_integer (v : SettlementVerifier.U64) : (scalar v).value = v.val :=
  SettlementVerifier.putU64_reconstructs v

theorem scalar_has_canonical_words (v : SettlementVerifier.U64) : CloseCircuit.CheckedWords (scalar v).words :=
  SettlementVerifier.putU64_canonical v

theorem digest_has_canonical_words (v : SettlementVerifier.U256) : CloseCircuit.CheckedWords (digest v).words :=
  SettlementVerifier.putUint256_canonical v

def statement (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) : CloseCircuit.PublicInputs := {
  channelId := f.channelId.val
  closeNonce := scalar f.closeNonce
  finalEpoch := scalar f.finalEpoch
  finalSmallBlock := scalar f.finalSmallBlockNumber
  freezeNonce := scalar f.closeFreezeNonce
  stateDigest := digest f.finalChannelStateDigest
  h1 := digest f.finalBalanceStateH1
  genesisFund := digest (f.channelFundAmounts 0)
  fundRoot := digest f.channelFundIntmaxStateRoot
  burnHash := digest f.burnTxHash
  withdrawalDigest := digest f.closeWithdrawalDigest
  closeId := digest (SettlementVerifier.closeIntentDigest hash f)
  snapshot := scalar f.snapshotMediumBlockNumber
  stateVersion := scalar f.finalStateVersion
  settledChain := digest f.finalSettledTxChain
  accumulatorRoot := digest f.finalSettledTxAccumulatorRoot
  memberSet := digest f.memberSetCommitment
  memberCount := f.memberCount.val
  delegateCount := delegates
  tokenFundsDigest := digest (hash (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts)) }

theorem solidity_layout_is_exact_circuit_encoding (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    (statement hash f delegates).words = SettlementVerifier.closeLayout hash f delegates
      (hash (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts)) := rfl

theorem solidity_layout_reads_as_exact_circuit_statement
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    CloseCircuit.parseTargets (SettlementVerifier.closeLayout hash f delegates
      (hash (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts))) =
      some (statement hash f delegates) := by
  rw [← solidity_layout_is_exact_circuit_encoding]
  exact CloseCircuit.target_public_input_round_trip _

theorem native_fields_read_encoded_circuit (p : CloseCircuit.PublicInputs) :
    ClosePublicInputs.readFields p.words = CloseEncodingBridge.toNative p := by
  have eq := CloseEncodingBridge.native_reader_and_circuit_reader_match p.words
  rw [CloseCircuit.target_fields_round_trip] at eq
  simpa only [CloseEncodingBridge.native_public_input_conversion_round_trip] using
    congrArg CloseEncodingBridge.toNative eq

theorem solidity_layout_reads_as_exact_native_fields
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    ClosePublicInputs.readFields (statement hash f delegates).words =
      CloseEncodingBridge.toNative (statement hash f delegates) :=
  native_fields_read_encoded_circuit (statement hash f delegates)

theorem accepted_binding_is_exact_statement (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (pi : List Nat)
    (accepted : SettlementVerifier.bindCloseIntentPublicInputs hash f pi = .ok true) :
    pi = (statement hash f f.minDelegateCount.val).words := by
  have h := SettlementVerifier.close_binding_success hash f pi accepted
  rw [h.2.1] at h
  exact h.2.2.2.2

theorem accepted_binding_constrains_delegate_snapshot_and_capacity
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (pi : List Nat)
    (accepted : SettlementVerifier.bindCloseIntentPublicInputs hash f pi = .ok true) :
    f.memberCount.val + f.minDelegateCount.val ≤ 1024 := by
  have h := SettlementVerifier.close_binding_success hash f pi accepted
  simpa only [h.2.1] using h.2.2.1

/-- No premise of the form "adapter success implies soundness" is needed to
    establish WHICH exact statement was returned. Truth is a separate theorem. -/
theorem accepted_verification_has_exact_adapter_receipt
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed) (hash : SettlementVerifier.Keccak)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes)
    (accepted : SettlementVerifier.verifyCloseIntent evm installed hash f proof = .ok true) :
    evm.verifyCompactPublicInputs installed.adapters.close proof =
      .ok (statement hash f f.minDelegateCount.val).words := by
  obtain ⟨pi, call, bound⟩ := SettlementVerifier.close_verification_has_external_provenance evm installed hash f proof accepted
  rw [accepted_binding_is_exact_statement hash f pi bound] at call
  exact call

theorem accepted_verification_parses_same_circuit_record
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed) (hash : SettlementVerifier.Keccak)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes) (pi : List Nat)
    (call : evm.verifyCompactPublicInputs installed.adapters.close proof = .ok pi)
    (accepted : SettlementVerifier.verifyCloseIntent evm installed hash f proof = .ok true) :
    CloseCircuit.parseTargets pi = some (statement hash f f.minDelegateCount.val) := by
  have exactCall := accepted_verification_has_exact_adapter_receipt evm installed hash f proof accepted
  rw [call] at exactCall
  cases Except.ok.inj exactCall
  exact CloseCircuit.target_public_input_round_trip _

/-- Connect any already-authenticated circuit record to the calldata fields;
    `call` identifies the SAME adapter/proof/return, not an unrelated proof. -/
theorem accepted_verification_binds_every_circuit_field
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed) (hash : SettlementVerifier.Keccak)
    (f : SettlementVerifier.CloseFields) (proof : SettlementVerifier.Bytes) (p : CloseCircuit.PublicInputs)
    (call : evm.verifyCompactPublicInputs installed.adapters.close proof = .ok p.words)
    (accepted : SettlementVerifier.verifyCloseIntent evm installed hash f proof = .ok true) :
    p = statement hash f f.minDelegateCount.val := by
  apply CloseCircuit.exact_public_input_encoding_is_injective
  have exactCall := accepted_verification_has_exact_adapter_receipt evm installed hash f proof accepted
  rw [call] at exactCall
  exact Except.ok.inj exactCall

theorem successful_binding_supplies_all_target_allocation_ranges
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (pi : List Nat)
    (accepted : SettlementVerifier.bindCloseIntentPublicInputs hash f pi = .ok true) :
    CloseCircuit.PublicInputs.AllocationChecks (statement hash f f.minDelegateCount.val) := by
  have checked := (SettlementVerifier.close_binding_success hash f pi accepted).2.2.2.1
  rw [accepted_binding_is_exact_statement hash f pi accepted] at checked
  exact checked

/-! ## Exact fixed-width byte packing, independent of hash security -/

def wordBytes : List Nat → List Nat
  | [] => []
  | w :: ws => SettlementVerifier.beBytes 4 w ++ wordBytes ws

theorem word_bytes_append (a b : List Nat) : wordBytes (a ++ b) = wordBytes a ++ wordBytes b := by
  induction a with
  | nil => rfl
  | cons x xs ih => simp [wordBytes, ih, List.append_assoc]

theorem four_bytes_ignore_upper_bits (v : Nat) :
    SettlementVerifier.beBytes 4 (v % SettlementVerifier.limbBound) =
      SettlementVerifier.beBytes 4 v := by
  simp [SettlementVerifier.beBytes, SettlementVerifier.limbBound]
  repeat constructor <;> omega

theorem scalar_words_pack_as_eight_bytes (v : SettlementVerifier.U64) :
    wordBytes (SettlementVerifier.putU64 v) = SettlementVerifier.beBytes 8 v.val := by
  simp only [wordBytes, SettlementVerifier.putU64, List.map_cons, List.map_nil,
    List.join_cons, List.join_nil, List.append_nil, four_bytes_ignore_upper_bits]
  simp [SettlementVerifier.beBytes, SettlementVerifier.limbBound, Nat.div_div_eq_div_mul]

theorem digest_words_pack_as_thirty_two_bytes (v : SettlementVerifier.U256) :
    wordBytes (SettlementVerifier.putUint256 v) = SettlementVerifier.beBytes 32 v.val := by
  simp only [wordBytes, SettlementVerifier.putUint256, SettlementVerifier.word,
    List.map_cons, List.map_nil, List.join_cons, List.join_nil, List.append_nil,
    four_bytes_ignore_upper_bits]
  simp [SettlementVerifier.beBytes, SettlementVerifier.limbBound, Nat.div_div_eq_div_mul]

theorem circuit_digest_words_pack_as_solidity_bytes (v : SettlementVerifier.U256) :
    wordBytes (digest v).words = SettlementVerifier.beBytes 32 v.val :=
  digest_words_pack_as_thirty_two_bytes v

theorem circuit_scalar_words_pack_as_solidity_bytes (v : SettlementVerifier.U64) :
    wordBytes (scalar v).words = SettlementVerifier.beBytes 8 v.val :=
  scalar_words_pack_as_eight_bytes v

theorem encoded_imcs_preimage_matches_solidity
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    wordBytes (CloseCircuit.imcsPreimage (statement hash f delegates)
      (digest f.finalChannelStateDigest)) = SettlementVerifier.closeIntentPreimage f := by
  simp only [CloseCircuit.imcsPreimage, statement, word_bytes_append,
    circuit_digest_words_pack_as_solidity_bytes, circuit_scalar_words_pack_as_solidity_bytes]
  rfl

def tokenWords (f : SettlementVerifier.CloseFields) : List Nat :=
  [CloseCircuit.imtfDomain] ++ SettlementVerifier.tenList (fun i => (f.tokenRegistry i).val) ++
  [f.tokenCount.val] ++ CloseCircuit.flattenAmounts (SettlementVerifier.tenList (fun i => digest (f.channelFundAmounts i)))

theorem encoded_whole_token_vector_matches_solidity (f : SettlementVerifier.CloseFields) :
    wordBytes (tokenWords f) =
      SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts := by
  simp only [tokenWords, word_bytes_append, SettlementVerifier.tenList,
    CloseCircuit.flattenAmounts, circuit_digest_words_pack_as_solidity_bytes]
  simp [wordBytes, SettlementVerifier.tokenFundsPreimage, SettlementVerifier.tenList,
    CloseCircuit.imtfDomain, SettlementVerifier.tokenFundsDomain, List.join, List.append_assoc]

/-- Hash-function implementation remains unproved; here it is ONE function
    applied to byte streams whose equality has been proved, not assumed. -/
def circuitHash (hash : SettlementVerifier.Keccak) (words : List Nat) : CloseCircuit.Words8 :=
  digest (hash (wordBytes words))

theorem imcs_hash_call_has_identical_preimage
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    circuitHash hash (CloseCircuit.imcsPreimage (statement hash f delegates)
      (digest f.finalChannelStateDigest)) = (statement hash f delegates).closeId := by
  unfold circuitHash
  rw [encoded_imcs_preimage_matches_solidity]
  rfl

theorem token_hash_call_has_identical_whole_vector
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields) (delegates : Nat) :
    circuitHash hash (tokenWords f) = (statement hash f delegates).tokenFundsDigest := by
  unfold circuitHash
  rw [encoded_whole_token_vector_matches_solidity]
  rfl

/-- An explicit bridge to an arbitrary circuit witness, retaining all ten
    registry entries and all ten U256 amounts, not just the genesis amount. -/
theorem actual_witness_token_preimage_matches_settlement
    (f : SettlementVerifier.CloseFields) (w : CloseCircuit.PrivateWitness)
    (registry : w.registry = SettlementVerifier.tenList (fun i => (f.tokenRegistry i).val))
    (count : w.tokenCount = f.tokenCount.val)
    (amounts : w.amounts = SettlementVerifier.tenList (fun i => digest (f.channelFundAmounts i))) :
    wordBytes (CloseCircuit.tokenFundsPreimage w) =
      SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts := by
  simpa only [CloseCircuit.tokenFundsPreimage, registry, count, amounts, tokenWords] using
    encoded_whole_token_vector_matches_solidity f

theorem four_byte_encoding_injective_on_u32 (a b : Nat)
    (ha : a < SettlementVerifier.limbBound) (hb : b < SettlementVerifier.limbBound)
    (eq : SettlementVerifier.beBytes 4 a = SettlementVerifier.beBytes 4 b) : a = b := by
  simp [SettlementVerifier.beBytes] at eq
  change a < 4294967296 at ha
  change b < 4294967296 at hb
  omega

theorem word_byte_encoding_injective_on_checked_words (a b : List Nat)
    (ha : CloseCircuit.CheckedWords a) (hb : CloseCircuit.CheckedWords b)
    (eq : wordBytes a = wordBytes b) : a = b := by
  induction a generalizing b with
  | nil =>
    cases b with
    | nil => rfl
    | cons x xs => simp [wordBytes, SettlementVerifier.beBytes] at eq
  | cons x xs ih =>
    cases b with
    | nil => simp [wordBytes, SettlementVerifier.beBytes] at eq
    | cons y ys =>
      have split := List.append_inj eq (by simp [SettlementVerifier.beBytes_length])
      have first := four_byte_encoding_injective_on_u32 x y
        (ha x (by simp)) (hb y (by simp)) split.1
      have tail := ih ys (fun v hv => ha v (by simp [hv]))
        (fun v hv => hb v (by simp [hv])) split.2
      rw [first, tail]

theorem token_words_are_checked (f : SettlementVerifier.CloseFields) : CloseCircuit.CheckedWords (tokenWords f) := by
  intro x hx
  simp only [tokenWords, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases hx with ((rfl | registry) | rfl) | amounts
  · decide
  · simp only [SettlementVerifier.tenList, List.mem_cons, List.not_mem_nil, or_false] at registry
    rcases registry with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      exact Fin.isLt _
  · have h := f.tokenCount.isLt
    change f.tokenCount.val < 4294967296
    change f.tokenCount.val < 256 at h
    omega
  · simp only [SettlementVerifier.tenList, CloseCircuit.flattenAmounts, List.mem_append,
      List.not_mem_nil, or_false] at amounts
    rcases amounts with h | h | h | h | h | h | h | h | h | h <;>
      exact digest_has_canonical_words _ x h

theorem witness_token_preimage_is_checked (w : CloseCircuit.PrivateWitness)
    (checked : w.Checked) : CloseCircuit.CheckedWords (CloseCircuit.tokenFundsPreimage w) := by
  intro x hx
  simp only [CloseCircuit.tokenFundsPreimage, List.mem_append, List.mem_cons,
    List.not_mem_nil, or_false] at hx
  rcases hx with ((rfl | registry) | rfl) | amounts
  · decide
  · exact checked x (by simp [registry])
  · exact checked w.tokenCount (by simp)
  · exact checked x (by simp [amounts])

/-- The only hash-binding hypothesis is the concrete pair compared in this
    execution. It does not quantify impossible injectivity over all messages. -/
theorem bound_close_preserves_entire_settlement_vector
    {BalanceProof AggregateProof Path Root : Type}
    (evm : SettlementVerifier.EvmView) (installed : SettlementVerifier.Installed)
    (hash : SettlementVerifier.Keccak) (f : SettlementVerifier.CloseFields)
    (proof : SettlementVerifier.Bytes) (p : CloseCircuit.PublicInputs)
    (e : CloseCircuit.Environment BalanceProof AggregateProof Path Root)
    (w : CloseCircuit.ProofWitness BalanceProof AggregateProof Path)
    (gates : CloseCircuit.CircuitGates e p w)
    (receipt : evm.verifyCompactPublicInputs installed.adapters.close proof = .ok p.words)
    (accepted : SettlementVerifier.verifyCloseIntent evm installed hash f proof = .ok true)
    (hashRepresentation : e.keccak (CloseCircuit.tokenFundsPreimage w.privateData) =
      circuitHash hash (CloseCircuit.tokenFundsPreimage w.privateData))
    (concreteBinding :
      hash (wordBytes (CloseCircuit.tokenFundsPreimage w.privateData)) =
        hash (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts) →
      wordBytes (CloseCircuit.tokenFundsPreimage w.privateData) =
        SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount f.channelFundAmounts) :
    w.privateData.registry = SettlementVerifier.tenList (fun i => (f.tokenRegistry i).val) ∧
    w.privateData.tokenCount = f.tokenCount.val ∧
    w.privateData.amounts = SettlementVerifier.tenList (fun i => digest (f.channelFundAmounts i)) := by
  have publicEq := accepted_verification_binds_every_circuit_field evm installed hash f proof p receipt accepted
  have digestEq := gates.tokenFunds
  rw [hashRepresentation, publicEq] at digestEq
  have hashEq := digest_conversion_injective _ _ digestEq
  have bytesEq := concreteBinding hashEq
  rw [← encoded_whole_token_vector_matches_solidity] at bytesEq
  have wordsEq := word_byte_encoding_injective_on_checked_words _ _
    (witness_token_preimage_is_checked _ gates.privateRanges) (token_words_are_checked f) bytesEq
  let expected := { w.privateData with
    registry := SettlementVerifier.tenList (fun i => (f.tokenRegistry i).val)
    tokenCount := f.tokenCount.val
    amounts := SettlementVerifier.tenList (fun i => digest (f.channelFundAmounts i)) }
  have sameLength : w.privateData.registry.length = expected.registry.length := by
    rw [gates.shape.1]
    rfl
  exact CloseCircuit.token_funds_preimage_binds_count_registry_and_every_amount
    w.privateData expected sameLength wordsEq

end Zkp.Implementation.SettlementCloseBridge
