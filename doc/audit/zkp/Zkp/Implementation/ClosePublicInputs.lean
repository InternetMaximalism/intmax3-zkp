import Std

/-!
# Native close public-input codec and witness projection

Source: src/circuits/channel/close_pis.rs (472 lines), runtime 05ec7ae.
All production functions in that file are represented; its fixture/test region is
separately inventoried, not treated as a production constraint. Native scalar u64
fields use the unique two-u32 big-endian representation `Words2`; Bytes32/U256 use
eight ordered u32 limbs. `NativeWidths` states the Rust type representation domain,
NOT an asset-safety or proof-validity premise. A dummy zero ChannelId can exist in
Rust but is rejected by this decoder: roundtrip therefore needs nonzero channel.

The native decoder does NOT range-check the twelve scalar u64 limbs. It performs
the source's wrapping left-shift and raw bitwise OR, then stores a u64. Hash/U256
limbs do pass U32LimbTrait checks; member/delegate casts check only u8/u16, not
protocol member/capacity limits. No stronger circuit constraint is silently added.
`readFields` uses defaulted indexing only behind the exact 103-length guard; all
source slice/index endpoints are proved within that length. Standalone join on a
short slice retains an explicit panic result. Allocation/serde/compiler behavior,
error display strings, u64 input representation and concrete Keccak are boundaries.

Witness projection invokes an explicit CloseIntent::new boundary on the complete
represented state/withdrawal identity, propagates its error and compares the ENTIRE
intent (including ten fund lanes). Source data not read locally is retained as an
opaque structural payload in State, not assumed irrelevant to the constructor.
IMCS and 92-word IMTF preimages are executable direct-dependency translations;
hashing is neither assumed injective nor a proof of funds/signer authenticity.
memberSet is intentionally zero here: the circuit's authenticated member proof
later replaces it. These local codec results do not prove ZKP or L1 acceptance.
-/
namespace Zkp.Implementation.ClosePublicInputs

def limbBase : Nat := 2^32
def scalarLimit : Nat := 2^64
def publicInputLength : Nat := 103

structure Words2 where
  hi : Nat
  lo : Nat
  deriving DecidableEq, Repr
def Words2.words (v : Words2) : List Nat := [v.hi,v.lo]
def Words2.read (xs : List Nat) (offset : Nat) : Words2 := ⟨xs.getD offset 0,xs.getD (offset+1) 0⟩

structure Words8 where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  w4 : Nat
  w5 : Nat
  w6 : Nat
  w7 : Nat
  deriving DecidableEq, Repr
def Words8.words (v : Words8) : List Nat := [v.w0,v.w1,v.w2,v.w3,v.w4,v.w5,v.w6,v.w7]
def Words8.zero : Words8 := ⟨0,0,0,0,0,0,0,0⟩
def Words8.read (xs : List Nat) (offset : Nat) : Words8 :=
  ⟨xs.getD offset 0,xs.getD (offset+1) 0,xs.getD (offset+2) 0,xs.getD (offset+3) 0,
   xs.getD (offset+4) 0,xs.getD (offset+5) 0,xs.getD (offset+6) 0,xs.getD (offset+7) 0⟩

structure PublicInputs where
  channelId : Nat
  closeNonce : Words2
  finalEpoch : Words2
  finalSmallBlock : Words2
  freezeNonce : Words2
  stateDigest : Words8
  h1 : Words8
  genesisFund : Words8
  fundRoot : Words8
  burnHash : Words8
  withdrawalDigest : Words8
  closeId : Words8
  snapshot : Words2
  stateVersion : Words2
  settledChain : Words8
  accumulatorRoot : Words8
  memberSet : Words8
  memberCount : Nat
  delegateCount : Nat
  tokenFundsDigest : Words8
  deriving DecidableEq, Repr

def PublicInputs.words (p : PublicInputs) : List Nat :=
  [p.channelId] ++ p.closeNonce.words ++ p.finalEpoch.words ++ p.finalSmallBlock.words ++
  p.freezeNonce.words ++ p.stateDigest.words ++ p.h1.words ++ p.genesisFund.words ++
  p.fundRoot.words ++ p.burnHash.words ++ p.withdrawalDigest.words ++ p.closeId.words ++
  p.snapshot.words ++ p.stateVersion.words ++ p.settledChain.words ++ p.accumulatorRoot.words ++
  p.memberSet.words ++ [p.memberCount,p.delegateCount] ++ p.tokenFundsDigest.words

inductive Field where
  | channelId | stateDigest | h1 | genesisFund | fundRoot | burnHash
  | withdrawalDigest | closeId | settledChain | accumulatorRoot | memberSet
  | memberCount | delegateCount | tokenFundsDigest
  deriving DecidableEq, Repr

inductive Reason where
  | outOfU32 | zeroChannel | outOfU8 | outOfU16
  deriving DecidableEq, Repr

inductive Error where
  | invalidLength (expected actual : Nat)
  | invalidField (field : Field) (reason : Reason)
  | slicePanic
  | invalidCloseBinding (details : String)
  | closeIntentMismatch
  deriving DecidableEq, Repr
abbrev Result := Except Error

def splitU64 (value : Nat) : Words2 := ⟨value / limbBase, value % limbBase⟩

/-- Nat inputs represent Rust u64 words; modulus on the low word is inert for
    actual u64 inputs, and on the shifted word represents fixed-width shift. -/
def joinValue (hi lo : Nat) : Nat :=
  ((hi * limbBase) % scalarLimit) ||| (lo % scalarLimit)

def joinU64 : List Nat → Result Nat
  | hi :: lo :: _ => .ok (joinValue hi lo)
  | _ => .error .slicePanic

def normalizeScalar (v : Words2) : Words2 := splitU64 (joinValue v.hi v.lo)
def canonicalScalar (v : Words2) : Prop := v.hi < limbBase ∧ v.lo < limbBase
def canonicalDigest (v : Words8) : Prop := ∀ x ∈ v.words, x < limbBase

def NativeWidths (p : PublicInputs) : Prop :=
  p.channelId < limbBase ∧
  canonicalScalar p.closeNonce ∧ canonicalScalar p.finalEpoch ∧
  canonicalScalar p.finalSmallBlock ∧ canonicalScalar p.freezeNonce ∧
  canonicalScalar p.snapshot ∧ canonicalScalar p.stateVersion ∧
  canonicalDigest p.stateDigest ∧ canonicalDigest p.h1 ∧ canonicalDigest p.genesisFund ∧
  canonicalDigest p.fundRoot ∧ canonicalDigest p.burnHash ∧ canonicalDigest p.withdrawalDigest ∧
  canonicalDigest p.closeId ∧ canonicalDigest p.settledChain ∧ canonicalDigest p.accumulatorRoot ∧
  canonicalDigest p.memberSet ∧ p.memberCount < 256 ∧ p.delegateCount < 65536 ∧
  canonicalDigest p.tokenFundsDigest

def toU64Vec (p : PublicInputs) : List Nat := p.words

def readFields (xs : List Nat) : PublicInputs := {
  channelId := xs.getD 0 0, closeNonce := Words2.read xs 1,
  finalEpoch := Words2.read xs 3, finalSmallBlock := Words2.read xs 5,
  freezeNonce := Words2.read xs 7, stateDigest := Words8.read xs 9,
  h1 := Words8.read xs 17, genesisFund := Words8.read xs 25,
  fundRoot := Words8.read xs 33, burnHash := Words8.read xs 41,
  withdrawalDigest := Words8.read xs 49, closeId := Words8.read xs 57,
  snapshot := Words2.read xs 65, stateVersion := Words2.read xs 67,
  settledChain := Words8.read xs 69, accumulatorRoot := Words8.read xs 77,
  memberSet := Words8.read xs 85, memberCount := xs.getD 93 0,
  delegateCount := xs.getD 94 0, tokenFundsDigest := Words8.read xs 95 }

def checkDigest (field : Field) (digest : Words8) : Result Unit :=
  if digest.words.all (fun x => decide (x < limbBase)) then .ok () else .error (.invalidField field .outOfU32)

def normalizeFields (p : PublicInputs) : PublicInputs := {p with
  closeNonce := normalizeScalar p.closeNonce, finalEpoch := normalizeScalar p.finalEpoch,
  finalSmallBlock := normalizeScalar p.finalSmallBlock, freezeNonce := normalizeScalar p.freezeNonce,
  snapshot := normalizeScalar p.snapshot, stateVersion := normalizeScalar p.stateVersion}

def decodeFields (p : PublicInputs) : Result PublicInputs := do
  if p.channelId ≥ limbBase then throw (.invalidField .channelId .outOfU32)
  if p.channelId = 0 then throw (.invalidField .channelId .zeroChannel)
  let _ ← checkDigest .stateDigest p.stateDigest
  let _ ← checkDigest .h1 p.h1
  let _ ← checkDigest .genesisFund p.genesisFund
  let _ ← checkDigest .fundRoot p.fundRoot
  let _ ← checkDigest .burnHash p.burnHash
  let _ ← checkDigest .withdrawalDigest p.withdrawalDigest
  let _ ← checkDigest .closeId p.closeId
  let _ ← checkDigest .settledChain p.settledChain
  let _ ← checkDigest .accumulatorRoot p.accumulatorRoot
  let _ ← checkDigest .memberSet p.memberSet
  if p.memberCount ≥ 256 then throw (.invalidField .memberCount .outOfU8)
  if p.delegateCount ≥ 65536 then throw (.invalidField .delegateCount .outOfU16)
  let _ ← checkDigest .tokenFundsDigest p.tokenFundsDigest
  return normalizeFields p

def fromU64Slice (xs : List Nat) : Result PublicInputs :=
  if xs.length != publicInputLength then .error (.invalidLength publicInputLength xs.length)
  else decodeFields (readFields xs)

structure Ten (α : Type) where
  t0 : α
  t1 : α
  t2 : α
  t3 : α
  t4 : α
  t5 : α
  t6 : α
  t7 : α
  t8 : α
  t9 : α
  deriving DecidableEq, Repr

def Ten.values {α : Type} (v : Ten α) : List α :=
  [v.t0,v.t1,v.t2,v.t3,v.t4,v.t5,v.t6,v.t7,v.t8,v.t9]

structure Fund where
  channelId : Nat
  amounts : Ten Words8
  stateRoot : Words8
  deriving DecidableEq, Repr

structure Intent where
  channelId : Nat
  closeNonce : Words2
  epoch : Words2
  smallBlock : Words2
  freezeNonce : Words2
  stateDigest : Words8
  h1 : Words8
  fund : Fund
  burnHash : Words8
  withdrawalDigest : Words8
  snapshot : Words2
  stateVersion : Words2
  settledChain : Words8
  deriving DecidableEq, Repr

structure State where
  accumulatorRoot : Words8
  memberCount : Nat
  delegateCount : Nat
  tokenRegistry : Ten Nat
  tokenCount : Nat
  opaqueRest : List Nat
  deriving DecidableEq, Repr

structure Withdrawal where
  channelId : Nat
  stateDigest : Words8
  h1 : Words8
  stateRoot : Words8
  burnHash : Words8
  amount : Words8
  proof : List Nat
  deriving DecidableEq, Repr

structure Witness where
  state : State
  withdrawal : Withdrawal
  intent : Intent
  deriving DecidableEq, Repr

abbrev HashWords := List Nat → Words8
abbrev NewIntent := State → Withdrawal → Except String Intent

def closeStatePreimage (i : Intent) : List Nat :=
  [0x494d4353,i.channelId] ++ i.stateDigest.words ++ i.freezeNonce.words

def tokenFundsPreimage (registry : Ten Nat) (count : Nat) (amounts : Ten Words8) : List Nat :=
  [0x494d5446] ++ registry.values ++ [count] ++ (amounts.values.map Words8.words).join

def projectWitness (hash : HashWords) (w : Witness) : PublicInputs := {
  channelId := w.intent.channelId, closeNonce := w.intent.closeNonce,
  finalEpoch := w.intent.epoch, finalSmallBlock := w.intent.smallBlock,
  freezeNonce := w.intent.freezeNonce, stateDigest := w.intent.stateDigest,
  h1 := w.intent.h1, genesisFund := w.intent.fund.amounts.t0,
  fundRoot := w.intent.fund.stateRoot, burnHash := w.intent.burnHash,
  withdrawalDigest := w.intent.withdrawalDigest, closeId := hash (closeStatePreimage w.intent),
  snapshot := w.intent.snapshot, stateVersion := w.intent.stateVersion,
  settledChain := w.intent.settledChain, accumulatorRoot := w.state.accumulatorRoot,
  memberSet := Words8.zero, memberCount := w.state.memberCount, delegateCount := w.state.delegateCount,
  tokenFundsDigest := hash (tokenFundsPreimage w.state.tokenRegistry w.state.tokenCount w.intent.fund.amounts) }

def toPublicInputs (newIntent : NewIntent) (hash : HashWords) (w : Witness) : Result PublicInputs := do
  let expected ← match newIntent w.state w.withdrawal with
    | .error e => .error (.invalidCloseBinding e)
    | .ok i => .ok i
  if expected != w.intent then throw .closeIntentMismatch
  return projectWitness hash w

theorem split_then_join_u64 (value : Nat) (bound : value < scalarLimit) :
    joinValue (splitU64 value).hi (splitU64 value).lo = value := by
  have low : value % limbBase < limbBase := Nat.mod_lt _ (by decide)
  have high : value / limbBase * limbBase < scalarLimit := by
    have := Nat.mod_add_div value limbBase
    simp only [limbBase, scalarLimit] at *
    omega
  have low64 : value % limbBase < scalarLimit := by
    simp only [limbBase, scalarLimit] at *
    omega
  simp only [joinValue, splitU64, Nat.mod_eq_of_lt high, Nat.mod_eq_of_lt low64]
  rw [Nat.mul_comm (value / limbBase) limbBase]
  change 2^32 * (value / limbBase) ||| value % limbBase = value
  rw [← Nat.mul_add_lt_is_or (i := 32) low]
  exact Nat.div_add_mod value limbBase

theorem normalized_canonical_scalar (v : Words2) (h : canonicalScalar v) : normalizeScalar v = v := by
  rcases v with ⟨hi, lo⟩
  rcases h with ⟨high, low⟩
  have product : hi * limbBase < scalarLimit := by
    simp only [limbBase, scalarLimit] at *
    omega
  have low64 : lo < scalarLimit := by
    simp only [limbBase, scalarLimit] at *
    omega
  unfold normalizeScalar joinValue splitU64
  simp only [Nat.mod_eq_of_lt product, Nat.mod_eq_of_lt low64]
  rw [Nat.mul_comm hi limbBase]
  change Words2.mk ((2^32 * hi ||| lo) / limbBase) ((2^32 * hi ||| lo) % limbBase) = ⟨hi,lo⟩
  rw [← Nat.mul_add_lt_is_or (i := 32) (show lo < 2^32 from low)]
  simp only [Words2.mk.injEq]
  simp only [limbBase] at *
  constructor <;> omega

theorem short_join_panics (xs : List Nat) (h : xs.length < 2) : joinU64 xs = .error .slicePanic := by
  cases xs with
  | nil => rfl
  | cons x xs => cases xs with
    | nil => rfl
    | cons y ys => simp at h; omega

theorem all_source_slices_fit :
    ([1,3,5,7,9,17,25,33,41,49,57,65,67,69,77,85,93,94,95,103] : List Nat).all
      (fun endpoint => decide (endpoint ≤ publicInputLength)) = true := by decide

theorem exact_word_length (p : PublicInputs) : (toU64Vec p).length = publicInputLength := by
  simp [toU64Vec,PublicInputs.words,Words2.words,Words8.words,publicInputLength]

set_option maxRecDepth 4096 in
set_option maxHeartbeats 2000000 in
theorem read_encoded_fields (p : PublicInputs) : readFields (toU64Vec p) = p := by
  simp only [toU64Vec,PublicInputs.words,Words2.words,Words8.words,List.append_assoc,
    List.singleton_append,List.cons_append,List.nil_append]
  unfold readFields Words2.read Words8.read
  cases p
  rfl

theorem digest_check_exact (field : Field) (w : Words8) :
    checkDigest field w = .ok () ↔ canonicalDigest w := by
  simp [checkDigest, canonicalDigest, List.all_eq_true]

theorem decode_native_fields_roundtrip (p : PublicInputs) (widths : NativeWidths p)
    (nonzero : p.channelId ≠ 0) : decodeFields p = .ok p := by
  rcases widths with ⟨channel,h1,h2,h3,h4,h5,h6,d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,member,delegates,d11⟩
  have c1 := (digest_check_exact .stateDigest p.stateDigest).mpr d1
  have c2 := (digest_check_exact .h1 p.h1).mpr d2
  have c3 := (digest_check_exact .genesisFund p.genesisFund).mpr d3
  have c4 := (digest_check_exact .fundRoot p.fundRoot).mpr d4
  have c5 := (digest_check_exact .burnHash p.burnHash).mpr d5
  have c6 := (digest_check_exact .withdrawalDigest p.withdrawalDigest).mpr d6
  have c7 := (digest_check_exact .closeId p.closeId).mpr d7
  have c8 := (digest_check_exact .settledChain p.settledChain).mpr d8
  have c9 := (digest_check_exact .accumulatorRoot p.accumulatorRoot).mpr d9
  have c10 := (digest_check_exact .memberSet p.memberSet).mpr d10
  have c11 := (digest_check_exact .tokenFundsDigest p.tokenFundsDigest).mpr d11
  have normalized : normalizeFields p = p := by
    simp [normalizeFields, normalized_canonical_scalar p.closeNonce h1,
      normalized_canonical_scalar p.finalEpoch h2, normalized_canonical_scalar p.finalSmallBlock h3,
      normalized_canonical_scalar p.freezeNonce h4, normalized_canonical_scalar p.snapshot h5,
      normalized_canonical_scalar p.stateVersion h6]
  simp [decodeFields, Nat.not_le_of_gt channel, nonzero, c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,
    Nat.not_le_of_gt member, Nat.not_le_of_gt delegates, normalized,Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem native_codec_roundtrip (p : PublicInputs) (widths : NativeWidths p) (nonzero : p.channelId ≠ 0) :
    fromU64Slice (toU64Vec p) = .ok p := by
  simp only [fromU64Slice, exact_word_length, bne_self_eq_false, Bool.false_eq_true, if_false, read_encoded_fields]
  exact decode_native_fields_roundtrip p widths nonzero

theorem wrong_length_rejected (xs : List Nat) (h : xs.length ≠ publicInputLength) :
    fromU64Slice xs = .error (.invalidLength publicInputLength xs.length) := by simp [fromU64Slice,h]

theorem dummy_channel_rejected (p : PublicInputs) (h : p.channelId = 0) :
    decodeFields p = .error (.invalidField .channelId .zeroChannel) := by
  simp [decodeFields,h,limbBase,Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem decoder_success_has_exact_length (xs : List Nat) (p : PublicInputs)
    (h : fromU64Slice xs = .ok p) : xs.length = publicInputLength := by
  unfold fromU64Slice at h
  split at h <;> simp_all

theorem native_encoding_injective (p q : PublicInputs)
    (h : toU64Vec p = toU64Vec q) : p = q := by
  have hh := congrArg readFields h
  simpa only [read_encoded_fields] using hh

theorem accumulator_and_member_tail_positions (p : PublicInputs) :
    (toU64Vec p).drop 77 = p.accumulatorRoot.words ++ p.memberSet.words ++
      [p.memberCount,p.delegateCount] ++ p.tokenFundsDigest.words := by
  simp [toU64Vec,PublicInputs.words,Words2.words,Words8.words]

theorem token_funds_preimage_full_length (registry : Ten Nat) (count : Nat) (amounts : Ten Words8) :
    (tokenFundsPreimage registry count amounts).length = 92 := by
  simp [tokenFundsPreimage,Ten.values,Words8.words]

theorem token_funds_preimage_all_amount_lanes (registry : Ten Nat) (count : Nat) (amounts : Ten Words8) :
    (tokenFundsPreimage registry count amounts).drop 12 = (amounts.values.map Words8.words).join := by
  simp [tokenFundsPreimage,Ten.values]

theorem close_state_preimage_length (i : Intent) : (closeStatePreimage i).length = 12 := by
  simp [closeStatePreimage,Words8.words,Words2.words]

theorem successful_projection_used_exact_intent (newIntent : NewIntent) (hash : HashWords)
    (w : Witness) (p : PublicInputs) (h : toPublicInputs newIntent hash w = .ok p) :
    newIntent w.state w.withdrawal = .ok w.intent ∧ p = projectWitness hash w := by
  simp only [toPublicInputs,Bind.bind,Except.bind,Pure.pure,Except.pure] at h
  cases expected : newIntent w.state w.withdrawal with
  | error e => simp [expected] at h
  | ok i =>
    simp only [expected,Except.bind] at h
    split at h <;> try contradiction
    have same : i = w.intent := by simpa using (show ¬(i != w.intent) = true from by assumption)
    cases h
    exact ⟨by simp [same],rfl⟩

theorem projection_leaves_member_set_unfilled (hash : HashWords) (w : Witness) :
    (projectWitness hash w).memberSet = Words8.zero := rfl

theorem projection_uses_state_accumulator_and_counts (hash : HashWords) (w : Witness) :
    (projectWitness hash w).accumulatorRoot = w.state.accumulatorRoot ∧
    (projectWitness hash w).memberCount = w.state.memberCount ∧
    (projectWitness hash w).delegateCount = w.state.delegateCount := ⟨rfl,rfl,rfl⟩

theorem projection_uses_all_funds_and_exact_registry (hash : HashWords) (w : Witness) :
    (projectWitness hash w).genesisFund = w.intent.fund.amounts.t0 ∧
    (projectWitness hash w).tokenFundsDigest =
      hash (tokenFundsPreimage w.state.tokenRegistry w.state.tokenCount w.intent.fund.amounts) := ⟨rfl,rfl⟩

theorem constructor_error_propagates (newIntent : NewIntent) (hash : HashWords) (w : Witness) (e : String)
    (h : newIntent w.state w.withdrawal = .error e) :
    toPublicInputs newIntent hash w = .error (.invalidCloseBinding e) := by
  simp [toPublicInputs,h,Bind.bind,Except.bind,Pure.pure,Except.pure]

/-- A valid native layout example, not a constructed proof or hash fixture. -/
def normalPublicInputs : PublicInputs := {
  channelId := 3, closeNonce := ⟨0,1⟩, finalEpoch := ⟨0,8⟩,
  finalSmallBlock := ⟨0,22⟩, freezeNonce := ⟨0,1⟩,
  stateDigest := ⟨1,2,3,4,5,6,7,8⟩, h1 := Words8.zero,
  genesisFund := ⟨0,0,0,0,0,0,0,77⟩, fundRoot := Words8.zero,
  burnHash := Words8.zero, withdrawalDigest := Words8.zero, closeId := Words8.zero,
  snapshot := ⟨0,0⟩, stateVersion := ⟨0,12⟩, settledChain := ⟨1,0,0,0,0,0,0,0⟩,
  accumulatorRoot := ⟨0,0,0,0,0,0,0,7⟩, memberSet := ⟨1,2,3,4,5,6,7,8⟩,
  memberCount := 3, delegateCount := 0, tokenFundsDigest := ⟨9,8,7,6,5,4,3,2⟩ }

theorem normal_public_input_roundtrip :
    fromU64Slice (toU64Vec normalPublicInputs) = .ok normalPublicInputs := by
  apply native_codec_roundtrip
  · simp [NativeWidths,canonicalScalar,canonicalDigest,normalPublicInputs,Words8.words,Words8.zero,limbBase]
  · decide

theorem normal_full_tail_retained :
    (toU64Vec normalPublicInputs).drop 85 = [1,2,3,4,5,6,7,8,3,0,9,8,7,6,5,4,3,2] := by
  simp [toU64Vec,PublicInputs.words,normalPublicInputs,Words2.words,Words8.words,Words8.zero]

end Zkp.Implementation.ClosePublicInputs
