import Zkp.Implementation.CloseCircuit
import Zkp.Implementation.ClosePublicInputs

/-!
# Shared H1 header, slot leaf and canonical Poseidon output encoding

Source-oriented handwritten semantics of both production functions in
src/circuits/channel/h1_gadget.rs, and selected 32/32 encoding operations from
src/utils/poseidon_hash_out.rs. Hash inputs are FIELD elements, not Keccak bytes.
The helpers do NOT themselves validate member/delegate capacity, registry
uniqueness, zero suffixes, ciphertext plaintext, budget, signature or backing.
These checks must not be invented from comments or native BalanceState.validate.

The header receives a root; computing/authenticating the tree is not performed
here. The native header's slot_tree_root() is an explicit supplied computation.
The canonical output split proof is derived from local modular gate equations,
u32 bounds and the high-max conditional zero. It proves neither imported gate
lowering nor Poseidon soundness. Native Bytes32->HashOut recovery is raw u64 pair
joining: its roundtrip is NOT a Goldilocks canonicity check. The target direction
adds a modular reduction and canonical encode-back equality; they differ.

No compiler/EVM refinement or whole-funds safety certificate is claimed.
-/
namespace Zkp.Implementation.H1Gadget

def fieldModulus : Nat := 18446744069414584321
def wordBase : Nat := 4294967296
def headerDomain : Nat := 0x494d4232
def leafDomain : Nat := 0x494d5332

abbrev Ten := ClosePublicInputs.Ten
abbrev Words8 := CloseCircuit.Words8
abbrev Words2 := CloseCircuit.Words2
abbrev Hash4 := CloseCircuit.Hash4

structure Words5 where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  w4 : Nat
  deriving DecidableEq, Repr

def Words5.words (a : Words5) : List Nat := [a.w0,a.w1,a.w2,a.w3,a.w4]
def Words5.read (xs : List Nat) (n : Nat) : Words5 :=
  ⟨xs.getD n 0,xs.getD (n+1) 0,xs.getD (n+2) 0,xs.getD (n+3) 0,xs.getD (n+4) 0⟩

def readTen (xs : List Nat) (n : Nat) : Ten Nat :=
  ⟨xs.getD n 0,xs.getD (n+1) 0,xs.getD (n+2) 0,xs.getD (n+3) 0,xs.getD (n+4) 0,
   xs.getD (n+5) 0,xs.getD (n+6) 0,xs.getD (n+7) 0,xs.getD (n+8) 0,xs.getD (n+9) 0⟩

def readTenDigests (xs : List Nat) (n : Nat) : Ten Words8 :=
  ⟨CloseCircuit.Words8.read xs n,CloseCircuit.Words8.read xs (n+8),CloseCircuit.Words8.read xs (n+16),
   CloseCircuit.Words8.read xs (n+24),CloseCircuit.Words8.read xs (n+32),CloseCircuit.Words8.read xs (n+40),
   CloseCircuit.Words8.read xs (n+48),CloseCircuit.Words8.read xs (n+56),CloseCircuit.Words8.read xs (n+64),
   CloseCircuit.Words8.read xs (n+72)⟩

structure Header where
  channel : Nat
  members : Nat
  delegates : Nat
  tokens : Nat
  registry : Ten Nat
  slotRoot : Hash4
  chain : Words8
  accumulator : Words8
  version : Words2
  deriving DecidableEq, Repr

def headerWords (h : Header) : List Nat :=
  [headerDomain,h.channel,h.members,h.delegates,h.tokens] ++ h.registry.values ++
  h.slotRoot.words ++ h.chain.words ++ h.accumulator.words ++ h.version.words

def readHeader (xs : List Nat) : Header := {
  channel := xs.getD 1 0, members := xs.getD 2 0, delegates := xs.getD 3 0, tokens := xs.getD 4 0
  registry := readTen xs 5
  slotRoot := ⟨xs.getD 15 0,xs.getD 16 0,xs.getD 17 0,xs.getD 18 0⟩
  chain := CloseCircuit.Words8.read xs 19
  accumulator := CloseCircuit.Words8.read xs 27
  version := CloseCircuit.Words2.read xs 35 }

structure SlotLeaf where
  publicKey : Words8
  ciphertexts : Ten Words8
  pendingAdds : Ten Nat
  recipient : Words5
  deriving DecidableEq, Repr

def leafWords (s : SlotLeaf) : List Nat :=
  [leafDomain] ++ s.publicKey.words ++
  CloseCircuit.flattenAmounts s.ciphertexts.values ++ s.pendingAdds.values ++ s.recipient.words

def readLeaf (xs : List Nat) : SlotLeaf := {
  publicKey := CloseCircuit.Words8.read xs 1
  ciphertexts := readTenDigests xs 9
  pendingAdds := readTen xs 89
  recipient := Words5.read xs 99 }

theorem header_has_exactly_37_field_elements (h : Header) : (headerWords h).length = 37 := by
  simp [headerWords,ClosePublicInputs.Ten.values,CloseCircuit.Hash4.words,
    CloseCircuit.Words8.words,CloseCircuit.Words2.words]

theorem leaf_has_exactly_104_field_elements (s : SlotLeaf) : (leafWords s).length = 104 := by
  simp [leafWords,ClosePublicInputs.Ten.values,CloseCircuit.flattenAmounts,
    CloseCircuit.Words8.words,Words5.words]

theorem header_reader_recovers_every_field (h : Header) : readHeader (headerWords h) = h := by
  cases h
  rfl

theorem leaf_reader_recovers_every_field (s : SlotLeaf) : readLeaf (leafWords s) = s := by
  cases s
  rfl

theorem exact_header_encoding_is_injective (a b : Header) (eq : headerWords a = headerWords b) : a = b := by
  have r := congrArg readHeader eq
  simpa only [header_reader_recovers_every_field] using r

theorem exact_leaf_encoding_is_injective (a b : SlotLeaf) (eq : leafWords a = leafWords b) : a = b := by
  have r := congrArg readLeaf eq
  simpa only [leaf_reader_recovers_every_field] using r

theorem header_and_leaf_inputs_cannot_alias (h : Header) (s : SlotLeaf) : headerWords h ≠ leafWords s := by
  intro eq
  have len := congrArg List.length eq
  rw [header_has_exactly_37_field_elements,leaf_has_exactly_104_field_elements] at len
  contradiction

theorem header_keeps_full_registry (h : Header) : ((headerWords h).drop 5).take 10 = h.registry.values := rfl
theorem header_keeps_raw_four_element_root (h : Header) : ((headerWords h).drop 15).take 4 = h.slotRoot.words := rfl
theorem leaf_keeps_signed_exit_recipient (s : SlotLeaf) : (leafWords s).drop 99 = s.recipient.words := rfl

/-- Source safe_split_lo_and_hi, after the imported split_low_high/is_equal/mul
    gates are lowered to these local modular relations. The critical high-max
    zero condition is retained, not replaced by the desired canonical result. -/
structure SplitGates (x hi lo : Nat) : Prop where
  hiRange : hi < wordBase
  loRange : lo < wordBase
  relation : (hi * wordBase + lo) % fieldModulus = x
  highMaxZero : hi = wordBase - 1 → lo = 0

/-- Explicit primitive results of split_low_high, is_equal, mul and assert_zero.
    These are local arithmetic semantics, not proof-system acceptance. The
    conditional highMaxZero is DERIVED below from the multiplication gate. -/
structure SplitPrimitiveGates (x hi lo indicator : Nat) : Prop where
  hiRange : hi < wordBase
  loRange : lo < wordBase
  splitRelation : (hi * wordBase + lo) % fieldModulus = x
  equalityIndicator : indicator = if hi = wordBase - 1 then 1 else 0
  multiplyAssertZero : (indicator * lo) % fieldModulus = 0

theorem primitive_split_gates_imply_safe_split {x hi lo indicator : Nat}
    (g : SplitPrimitiveGates x hi lo indicator) : SplitGates x hi lo := by
  refine ⟨g.hiRange,g.loRange,g.splitRelation,?_⟩
  intro maximum
  have one : indicator = 1 := by simpa [maximum] using g.equalityIndicator
  have zero := g.multiplyAssertZero
  rw [one,Nat.one_mul] at zero
  have low : lo < fieldModulus := by
    have range := g.loRange
    unfold fieldModulus wordBase at *
    omega
  rwa [Nat.mod_eq_of_lt low] at zero

theorem safe_split_combined_value_is_canonical {x hi lo : Nat} (g : SplitGates x hi lo) :
    hi * wordBase + lo < fieldModulus := by
  have hhi := g.hiRange
  have hlo := g.loRange
  by_cases high : hi = wordBase - 1
  · have zero := g.highMaxZero high
    simp [wordBase,fieldModulus,high,zero]
  · unfold wordBase at hhi hlo high ⊢
    unfold fieldModulus
    omega

theorem safe_split_is_integer_equality {x hi lo : Nat} (g : SplitGates x hi lo) :
    hi * wordBase + lo = x := by
  have eq := g.relation
  rw [Nat.mod_eq_of_lt (safe_split_combined_value_is_canonical g)] at eq
  exact eq

theorem safe_split_unique_parts {x hi lo : Nat} (g : SplitGates x hi lo) :
    hi = x / wordBase ∧ lo = x % wordBase := by
  have eq := safe_split_is_integer_equality g
  have hlo := g.loRange
  unfold wordBase at *
  omega

theorem primitive_split_results_are_uniquely_canonical {x hi lo indicator : Nat}
    (g : SplitPrimitiveGates x hi lo indicator) :
    hi = x / wordBase ∧ lo = x % wordBase ∧ hi * wordBase + lo < fieldModulus := by
  have safe := primitive_split_gates_imply_safe_split g
  exact ⟨(safe_split_unique_parts safe).1,(safe_split_unique_parts safe).2,
    safe_split_combined_value_is_canonical safe⟩

theorem split_join_value (x : Nat) : x / wordBase * wordBase + x % wordBase = x := by
  simpa only [Nat.mul_comm] using Nat.div_add_mod x wordBase

theorem canonical_split_satisfies_all_gates (x : Nat) (range : x < fieldModulus) :
    SplitGates x (x / wordBase) (x % wordBase) := by
  constructor
  · unfold wordBase fieldModulus at *
    omega
  · exact Nat.mod_lt _ (by decide)
  · rw [split_join_value]
    exact Nat.mod_eq_of_lt range
  · intro high
    unfold wordBase fieldModulus at *
    omega

def canonicalEncode (h : Hash4) : Words8 :=
  ⟨h.h0 / wordBase,h.h0 % wordBase,h.h1 / wordBase,h.h1 % wordBase,
   h.h2 / wordBase,h.h2 % wordBase,h.h3 / wordBase,h.h3 % wordBase⟩

/-- Rust From<PoseidonHashOut> casts BOTH parts to u32. The mathematical
    canonical encoder above is only its native realization on u64 inputs. -/
def nativeEncode (h : Hash4) : Words8 :=
  ⟨h.h0 / wordBase % wordBase,h.h0 % wordBase,h.h1 / wordBase % wordBase,h.h1 % wordBase,
   h.h2 / wordBase % wordBase,h.h2 % wordBase,h.h3 / wordBase % wordBase,h.h3 % wordBase⟩

def nativeRecover (w : Words8) : Hash4 :=
  ⟨w.w0 * wordBase + w.w1,w.w2 * wordBase + w.w3,
   w.w4 * wordBase + w.w5,w.w6 * wordBase + w.w7⟩

def targetReduce (w : Words8) : Hash4 :=
  ⟨(w.w0 * wordBase + w.w1) % fieldModulus,(w.w2 * wordBase + w.w3) % fieldModulus,
   (w.w4 * wordBase + w.w5) % fieldModulus,(w.w6 * wordBase + w.w7) % fieldModulus⟩

def OutputGates (h : Hash4) (w : Words8) : Prop :=
  SplitGates h.h0 w.w0 w.w1 ∧ SplitGates h.h1 w.w2 w.w3 ∧
  SplitGates h.h2 w.w4 w.w5 ∧ SplitGates h.h3 w.w6 w.w7

def CanonicalHash (h : Hash4) : Prop :=
  h.h0 < fieldModulus ∧ h.h1 < fieldModulus ∧ h.h2 < fieldModulus ∧ h.h3 < fieldModulus

theorem canonical_hash_fits_native_u64_cast (x : Nat) (bound : x < fieldModulus) :
    x / wordBase % wordBase = x / wordBase := by
  apply Nat.mod_eq_of_lt
  unfold fieldModulus wordBase at *
  omega

theorem native_casts_equal_canonical_encoding_on_field_outputs (h : Hash4) (bounds : CanonicalHash h) :
    nativeEncode h = canonicalEncode h := by
  simp only [nativeEncode,canonicalEncode,
    canonical_hash_fits_native_u64_cast _ bounds.1,
    canonical_hash_fits_native_u64_cast _ bounds.2.1,
    canonical_hash_fits_native_u64_cast _ bounds.2.2.1,
    canonical_hash_fits_native_u64_cast _ bounds.2.2.2]

theorem from_hash_out_gates_force_unique_encoding (h : Hash4) (w : Words8)
    (g : OutputGates h w) : w = canonicalEncode h := by
  rcases g with ⟨g0,g1,g2,g3⟩
  have h0 := safe_split_unique_parts g0
  have h1 := safe_split_unique_parts g1
  have h2 := safe_split_unique_parts g2
  have h3 := safe_split_unique_parts g3
  cases w
  simp_all [canonicalEncode]

theorem every_canonical_hash_has_satisfying_output (h : Hash4) (bounds : CanonicalHash h) :
    OutputGates h (canonicalEncode h) :=
  ⟨canonical_split_satisfies_all_gates _ bounds.1,
   canonical_split_satisfies_all_gates _ bounds.2.1,
   canonical_split_satisfies_all_gates _ bounds.2.2.1,
   canonical_split_satisfies_all_gates _ bounds.2.2.2⟩

theorem raw_pair_recovery_after_mathematical_encoding (h : Hash4) : nativeRecover (canonicalEncode h) = h := by
  cases h
  simp [nativeRecover,canonicalEncode,split_join_value]

theorem native_field_output_encoding_recovers_original (h : Hash4) (bounds : CanonicalHash h) :
    nativeRecover (nativeEncode h) = h := by
  rw [native_casts_equal_canonical_encoding_on_field_outputs h bounds,
    raw_pair_recovery_after_mathematical_encoding]

theorem native_cast_output_words_are_u32 (h : Hash4) : CloseCircuit.CheckedWords (nativeEncode h).words := by
  intro x hx
  simp only [nativeEncode,CloseCircuit.Words8.words,List.mem_cons,List.not_mem_nil,or_false] at hx
  rcases hx with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    exact Nat.mod_lt _ (by decide)

theorem native_checked_pair_roundtrip (hi lo : Nat) (hh : hi < wordBase) (hl : lo < wordBase) :
    (hi * wordBase + lo) / wordBase % wordBase = hi ∧
      (hi * wordBase + lo) % wordBase = lo := by
  unfold wordBase at *
  omega

theorem native_reencoding_checked_bytes_is_identity (w : Words8) (checked : CloseCircuit.CheckedWords w.words) :
    nativeEncode (nativeRecover w) = w := by
  have p0 := native_checked_pair_roundtrip w.w0 w.w1
    (checked w.w0 (by simp [CloseCircuit.Words8.words])) (checked w.w1 (by simp [CloseCircuit.Words8.words]))
  have p1 := native_checked_pair_roundtrip w.w2 w.w3
    (checked w.w2 (by simp [CloseCircuit.Words8.words])) (checked w.w3 (by simp [CloseCircuit.Words8.words]))
  have p2 := native_checked_pair_roundtrip w.w4 w.w5
    (checked w.w4 (by simp [CloseCircuit.Words8.words])) (checked w.w5 (by simp [CloseCircuit.Words8.words]))
  have p3 := native_checked_pair_roundtrip w.w6 w.w7
    (checked w.w6 (by simp [CloseCircuit.Words8.words])) (checked w.w7 (by simp [CloseCircuit.Words8.words]))
  cases w
  simp_all [nativeEncode,nativeRecover]

def nativeTryFrom (w : Words8) : Option Hash4 :=
  let recovered := nativeRecover w
  if w = nativeEncode recovered then some recovered else none

/-- Exact native TryFrom success, with NO claim that the resulting raw u64
    values are <p. In contrast target to_hash_out below enforces <p. -/
theorem native_try_from_checks_byte_roundtrip_only (w : Words8) (checked : CloseCircuit.CheckedWords w.words) :
    nativeTryFrom w = some (nativeRecover w) := by
  simp [nativeTryFrom,native_reencoding_checked_bytes_is_identity w checked]

theorem canonical_output_encoding_is_injective (a b : Hash4) (eq : canonicalEncode a = canonicalEncode b) : a = b := by
  have r := congrArg nativeRecover eq
  simpa only [raw_pair_recovery_after_mathematical_encoding] using r

theorem target_reduce_is_field_canonical (w : Words8) : CanonicalHash (targetReduce w) :=
  ⟨Nat.mod_lt _ (by decide),Nat.mod_lt _ (by decide),Nat.mod_lt _ (by decide),Nat.mod_lt _ (by decide)⟩

/-- Unlike native TryFrom, target to_hash_out connects the recovered bytes back
    after modular reduction. The equality below is an ACTUAL source connect. -/
def TargetToHashOutGates (w : Words8) : Prop := w = canonicalEncode (targetReduce w)

theorem to_hash_out_connect_excludes_noncanonical_pairs (w : Words8)
    (g : TargetToHashOutGates w) : nativeRecover w = targetReduce w ∧ CanonicalHash (nativeRecover w) := by
  have exact := congrArg nativeRecover g
  rw [raw_pair_recovery_after_mathematical_encoding] at exact
  exact ⟨exact, exact ▸ target_reduce_is_field_canonical w⟩

structure HashEnvironment where
  poseidon : List Nat → Hash4

def recomputeH1 (e : HashEnvironment) (h : Header) : Words8 := canonicalEncode (e.poseidon (headerWords h))
def hashSlotLeaf (e : HashEnvironment) (s : SlotLeaf) : Hash4 := e.poseidon (leafWords s)

/-- Native push/extend order is represented independently from the target
    concatenation; the tree root parameter is the result of slot_tree_root(). -/
def nativeHeaderWords (h : Header) : List Nat :=
  (((([headerDomain,h.channel,h.members,h.delegates,h.tokens] ++ h.registry.values) ++
    h.slotRoot.words) ++ h.chain.words) ++ h.accumulator.words) ++ h.version.words

def nativeLeafWords (s : SlotLeaf) : List Nat :=
  (([leafDomain] ++ s.publicKey.words) ++ CloseCircuit.flattenAmounts s.ciphertexts.values) ++
    s.pendingAdds.values ++ s.recipient.words

theorem native_and_target_header_order_are_identical (h : Header) : nativeHeaderWords h = headerWords h := rfl
theorem native_and_target_leaf_order_are_identical (s : SlotLeaf) : nativeLeafWords s = leafWords s := rfl

def nativeH1 (e : HashEnvironment) (h : Header) : Words8 := nativeEncode (e.poseidon (nativeHeaderWords h))

theorem native_and_target_h1_same_on_field_outputs (e : HashEnvironment) (h : Header)
    (fieldOutput : CanonicalHash (e.poseidon (headerWords h))) : nativeH1 e h = recomputeH1 e h :=
  native_casts_equal_canonical_encoding_on_field_outputs _ fieldOutput

theorem equal_h1_binds_every_header_field (e : HashEnvironment) (a b : Header)
    (binding : e.poseidon (headerWords a) = e.poseidon (headerWords b) → headerWords a = headerWords b)
    (eq : recomputeH1 e a = recomputeH1 e b) : a = b :=
  exact_header_encoding_is_injective a b (binding (canonical_output_encoding_is_injective _ _ eq))

theorem equal_slot_hash_binds_exit_recipient_and_all_token_rows (e : HashEnvironment) (a b : SlotLeaf)
    (binding : e.poseidon (leafWords a) = e.poseidon (leafWords b) → leafWords a = leafWords b)
    (eq : hashSlotLeaf e a = hashSlotLeaf e b) :
    a.recipient = b.recipient ∧ a.ciphertexts = b.ciphertexts ∧ a.pendingAdds = b.pendingAdds := by
  have exact := exact_leaf_encoding_is_injective a b (binding eq)
  subst b
  exact ⟨rfl,rfl,rfl⟩

theorem maximum_field_element_has_valid_zero_low_split :
    SplitGates (fieldModulus - 1) (wordBase - 1) 0 := by
  constructor <;> decide

end Zkp.Implementation.H1Gadget
