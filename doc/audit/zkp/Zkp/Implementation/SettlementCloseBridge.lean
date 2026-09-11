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

/-! ## ABI faithfulness of the token-funds preimage

The hash-binding premise (e2) of `TrustBoundary` says: if the Solidity-side and the
circuit-side token-funds digests agree, then the two hashed byte strings agree.
What follows pins down exactly what kind of assumption that is.

* `token_funds_preimage_length` and `witness_token_preimage_length` show both compared
  strings are 368 bytes long (4 domain + 10*4 registry + 4 count + 10*32 amounts), and
  `token_funds_compared_strings_same_length` states that as one equation. So (e2) is a
  SAME-LENGTH collision claim: no length-extension or padding ambiguity is involved.
* `be_bytes_injective` and `token_funds_preimage_injective` show the layout itself is
  injective: distinct (registry, count, amounts) triples always produce distinct byte
  strings, so a collision can never arise from the encoding losing information.

Together these prove the "ABI-encoding faithfulness" half of (e2)'s obligation. What
remains is solely collision resistance of Keccak-256 on the one concrete pair of
368-byte strings compared inside an accepted close; nothing about the encoding, its
width, its domain separation or its field ordering is still assumed. -/

theorem token_funds_preimage_length (registry : Fin 10 → SettlementVerifier.U32)
    (count : SettlementVerifier.U8) (amounts : Fin 10 → SettlementVerifier.U256) :
    (SettlementVerifier.tokenFundsPreimage registry count amounts).length = 368 :=
  SettlementVerifier.tokenFundsPreimage_length registry count amounts

theorem word_bytes_length (ws : List Nat) : (wordBytes ws).length = ws.length * 4 := by
  induction ws with
  | nil => rfl
  | cons w ws ih =>
    simp only [wordBytes, List.length_append, SettlementVerifier.beBytes_length, ih,
      List.length_cons]
    omega

theorem witness_token_preimage_length (w : CloseCircuit.PrivateWitness)
    (shape : w.Shape) : (wordBytes (CloseCircuit.tokenFundsPreimage w)).length = 368 := by
  rw [word_bytes_length, CloseCircuit.token_funds_preimage_has_exact_92_words w shape]

theorem be_bytes_mod_eq_of_eq (n a b : Nat) :
    SettlementVerifier.beBytes n a = SettlementVerifier.beBytes n b →
      a % 256 ^ n = b % 256 ^ n := by
  induction n generalizing a b with
  | zero => intro _; simp [Nat.mod_one]
  | succ n ih =>
    intro h
    simp only [SettlementVerifier.beBytes, List.cons.injEq] at h
    have tail := ih a b h.2
    have expand : ∀ x : Nat,
        x % 256 ^ (n + 1) = 256 ^ n * (x / 256 ^ n % 256) + x % 256 ^ n := by
      intro x
      have dvd : (256 : Nat) ^ n ∣ 256 ^ (n + 1) := ⟨256, Nat.pow_succ 256 n⟩
      have hm : x % 256 ^ (n + 1) % 256 ^ n = x % 256 ^ n := Nat.mod_mod_of_dvd x dvd
      have hd : x % 256 ^ (n + 1) / 256 ^ n = x / 256 ^ n % 256 := by
        rw [Nat.pow_succ]
        exact Nat.mod_mul_right_div_self x (256 ^ n) 256
      calc x % 256 ^ (n + 1)
          = 256 ^ n * (x % 256 ^ (n + 1) / 256 ^ n) + x % 256 ^ (n + 1) % 256 ^ n :=
            (Nat.div_add_mod _ _).symm
        _ = 256 ^ n * (x / 256 ^ n % 256) + x % 256 ^ n := by rw [hm, hd]
    rw [expand a, expand b, h.1, tail]

theorem be_bytes_injective (n a b : Nat) (ha : a < 256 ^ n) (hb : b < 256 ^ n)
    (h : SettlementVerifier.beBytes n a = SettlementVerifier.beBytes n b) : a = b := by
  have hmod := be_bytes_mod_eq_of_eq n a b h
  rwa [Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] at hmod

theorem be_bytes_prefix_injective (n a b : Nat) (xs ys : List Nat)
    (ha : a < 256 ^ n) (hb : b < 256 ^ n)
    (h : SettlementVerifier.beBytes n a ++ xs = SettlementVerifier.beBytes n b ++ ys) :
    a = b ∧ xs = ys := by
  have split := List.append_inj h (by simp [SettlementVerifier.beBytes_length])
  exact ⟨be_bytes_injective n a b ha hb split.1, split.2⟩

theorem ten_be_bytes_join_injective (n : Nat) (f g : Fin 10 → Nat)
    (hf : ∀ i, f i < 256 ^ n) (hg : ∀ i, g i < 256 ^ n)
    (h : (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes n (f i)).join =
      (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes n (g i)).join) :
    ∀ i, f i = g i := by
  simp only [SettlementVerifier.tenList, List.join_cons, List.join_nil] at h
  obtain ⟨e0, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 0) (hg 0) h
  obtain ⟨e1, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 1) (hg 1) h
  obtain ⟨e2, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 2) (hg 2) h
  obtain ⟨e3, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 3) (hg 3) h
  obtain ⟨e4, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 4) (hg 4) h
  obtain ⟨e5, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 5) (hg 5) h
  obtain ⟨e6, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 6) (hg 6) h
  obtain ⟨e7, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 7) (hg 7) h
  obtain ⟨e8, h⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 8) (hg 8) h
  obtain ⟨e9, -⟩ := be_bytes_prefix_injective n _ _ _ _ (hf 9) (hg 9) h
  intro i
  obtain ⟨v, hv⟩ := i
  match v, hv with
  | 0, _ => exact e0
  | 1, _ => exact e1
  | 2, _ => exact e2
  | 3, _ => exact e3
  | 4, _ => exact e4
  | 5, _ => exact e5
  | 6, _ => exact e6
  | 7, _ => exact e7
  | 8, _ => exact e8
  | 9, _ => exact e9
  | k + 10, hk => exact absurd hk (by omega)

theorem token_funds_preimage_injective
    (r r' : Fin 10 → SettlementVerifier.U32) (c c' : SettlementVerifier.U8)
    (a a' : Fin 10 → SettlementVerifier.U256)
    (h : SettlementVerifier.tokenFundsPreimage r c a =
      SettlementVerifier.tokenFundsPreimage r' c' a') :
    r = r' ∧ c = c' ∧ a = a' := by
  have regBound : ∀ (f : Fin 10 → SettlementVerifier.U32) (i : Fin 10), (f i).val < 256 ^ 4 :=
    fun f i => Nat.lt_of_lt_of_le (f i).isLt (by decide)
  have amtBound : ∀ (f : Fin 10 → SettlementVerifier.U256) (i : Fin 10), (f i).val < 256 ^ 32 :=
    fun f i => Nat.lt_of_lt_of_le (f i).isLt (by decide)
  have countBound : ∀ x : SettlementVerifier.U8, x.val < 256 ^ 4 :=
    fun x => Nat.lt_of_lt_of_le x.isLt (by decide)
  simp only [SettlementVerifier.tokenFundsPreimage] at h
  have amountsSplit :
      SettlementVerifier.beBytes 4 SettlementVerifier.tokenFundsDomain ++
            (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 4 (r i).val).join ++
            SettlementVerifier.beBytes 4 c.val =
          SettlementVerifier.beBytes 4 SettlementVerifier.tokenFundsDomain ++
            (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 4 (r' i).val).join ++
            SettlementVerifier.beBytes 4 c'.val ∧
        (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 32 (a i).val).join =
          (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 32 (a' i).val).join :=
    List.append_inj h (by simp [SettlementVerifier.tenList, SettlementVerifier.beBytes_length])
  have countSplit :
      SettlementVerifier.beBytes 4 SettlementVerifier.tokenFundsDomain ++
            (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 4 (r i).val).join =
          SettlementVerifier.beBytes 4 SettlementVerifier.tokenFundsDomain ++
            (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 4 (r' i).val).join ∧
        SettlementVerifier.beBytes 4 c.val = SettlementVerifier.beBytes 4 c'.val :=
    List.append_inj amountsSplit.1
      (by simp [SettlementVerifier.tenList, SettlementVerifier.beBytes_length])
  have registryJoin :
      (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 4 (r i).val).join =
        (SettlementVerifier.tenList fun i => SettlementVerifier.beBytes 4 (r' i).val).join :=
    List.append_inj_right countSplit.1 rfl
  have countEq : c.val = c'.val :=
    be_bytes_injective 4 _ _ (countBound c) (countBound c') countSplit.2
  refine ⟨?_, Fin.eq_of_val_eq countEq, ?_⟩
  · funext i
    exact Fin.eq_of_val_eq
      (ten_be_bytes_join_injective 4 (fun j => (r j).val) (fun j => (r' j).val)
        (regBound r) (regBound r') registryJoin i)
  · funext i
    exact Fin.eq_of_val_eq
      (ten_be_bytes_join_injective 32 (fun j => (a j).val) (fun j => (a' j).val)
        (amtBound a) (amtBound a') amountsSplit.2 i)

theorem token_funds_compared_strings_same_length (f : SettlementVerifier.CloseFields)
    (w : CloseCircuit.PrivateWitness) (shape : w.Shape) :
    (wordBytes (CloseCircuit.tokenFundsPreimage w)).length =
      (SettlementVerifier.tokenFundsPreimage f.tokenRegistry f.tokenCount
        f.channelFundAmounts).length := by
  rw [witness_token_preimage_length w shape, token_funds_preimage_length]

end Zkp.Implementation.SettlementCloseBridge
