import Zkp.Implementation.CloseCircuit
import Zkp.Implementation.ClosePublicInputs

/-!
# Native cancel-close witness and public-input codec

Manual source semantics for cancel_close_pis.rs. Rust ABI/native widths, serde,
error display strings, allocation and compiler equivalence remain boundaries.
The native decoder range-checks channel/hash limbs but NOT the four scalar-pair
limbs. Raw shift/OR normalization is retained; canonical native values roundtrip.
ChannelId dummy zero remains representable but is rejected on parsing.

`Revived` and `Close` retain all locally read fields; opaqueRest identifies the
remaining complete source object for native signing-digest observation. The actual
ChannelState::signing_digest computation must justify that indexed observation;
it is not assumed to confer signer validity or balance/asset safety. No signatures
are verified in this file. The member commitment is a zero placeholder later
replaced by the circuit prover's member-auth commitment. No replay ledger or
request-generation field exists in this statement: those guards belong to Manager.
-/
namespace Zkp.Implementation.CancelClosePublicInputs

open Zkp.Implementation.CloseCircuit (Words2 Words8)
def publicInputLength : Nat := 29
def limbBase : Nat := 2^32
def scalarLimit : Nat := 2^64
def splitU64 (value : Nat) : List Nat := [value / limbBase,value % limbBase]
def joinValue : Nat → Nat → Nat := Zkp.Implementation.ClosePublicInputs.joinValue

inductive Error where
  | length (actual : Nat)
  | channelRange | channelZero | digestRange | slicePanic
  | channelMismatch | digestMismatch | stale (revived close : Nat)
  | eraMismatch (revived close : Nat) | eraOverflow (revived : Nat)
  deriving DecidableEq, Repr
abbrev Result := Except Error

structure PublicInputs where
  channelId : Nat
  closeId : Words8
  memberSet : Words8
  closeVersion : Nat
  revivedVersion : Nat
  revivedDigest : Words8
  deriving DecidableEq, Repr

def toU64Vec (p : PublicInputs) : List Nat :=
  [p.channelId] ++ p.closeId.words ++ p.memberSet.words ++ splitU64 p.closeVersion ++
    splitU64 p.revivedVersion ++ p.revivedDigest.words

def joinU64 : List Nat → Result Nat
  | hi::lo::_ => .ok (joinValue hi lo)
  | _ => .error .slicePanic

def readFields (xs : List Nat) : PublicInputs :=
  ⟨xs.getD 0 0,Words8.read xs 1,Words8.read xs 9,
    joinValue (xs.getD 17 0) (xs.getD 18 0),
    joinValue (xs.getD 19 0) (xs.getD 20 0),Words8.read xs 21⟩

def Checked (w : Words8) : Prop := ∀ v ∈ w.words, v < limbBase
def checkDigest (w : Words8) : Result Unit :=
  if w.words.all (fun v => decide (v < limbBase)) then .ok () else .error .digestRange

def fromU64Slice (xs : List Nat) : Result PublicInputs := do
  if xs.length != publicInputLength then throw (.length xs.length)
  let p := readFields xs
  if p.channelId ≥ limbBase then throw .channelRange
  if p.channelId = 0 then throw .channelZero
  let _ ← checkDigest p.closeId
  let _ ← checkDigest p.memberSet
  let _ ← checkDigest p.revivedDigest
  return p

def NativeWidths (p : PublicInputs) : Prop :=
  p.channelId < limbBase ∧ Checked p.closeId ∧ Checked p.memberSet ∧
  p.closeVersion < scalarLimit ∧ p.revivedVersion < scalarLimit ∧ Checked p.revivedDigest

structure Revived where
  channelId : Nat
  digest : Words8
  version : Nat
  freezeNonce : Nat
  opaqueRest : List Nat
  deriving DecidableEq, Repr

structure Close where
  channelId : Nat
  version : Nat
  freezeNonce : Nat
  stateDigest : Words8
  opaqueRest : List Nat
  deriving DecidableEq, Repr

structure Witness where
  revived : Revived
  close : Close
  deriving DecidableEq, Repr

def closePreimage (c : Close) : List Nat :=
  [0x494d4353,c.channelId] ++ c.stateDigest.words ++ splitU64 c.freezeNonce

structure NativeEnvironment where
  signingDigest : Revived → Words8
  hashWords : List Nat → Words8

def toPublicInputs (e : NativeEnvironment) (w : Witness) : Result PublicInputs := do
  if w.revived.channelId != w.close.channelId then throw .channelMismatch
  if w.revived.digest != e.signingDigest w.revived then throw .digestMismatch
  if w.revived.version ≤ w.close.version then throw (.stale w.revived.version w.close.version)
  if w.revived.freezeNonce + 1 ≥ scalarLimit then throw (.eraOverflow w.revived.freezeNonce)
  if w.revived.freezeNonce + 1 != w.close.freezeNonce then
    throw (.eraMismatch w.revived.freezeNonce w.close.freezeNonce)
  return ⟨w.close.channelId,e.hashWords (closePreimage w.close),Words8.zero,
    w.close.version,w.revived.version,e.signingDigest w.revived⟩

theorem scalar_split_join (value : Nat) (bound : value < scalarLimit) :
    joinValue (value / limbBase) (value % limbBase) = value :=
  Zkp.Implementation.ClosePublicInputs.split_then_join_u64 value bound

theorem word_length (p : PublicInputs) : (toU64Vec p).length = publicInputLength := by
  simp [toU64Vec,Words8.words,splitU64,publicInputLength]

theorem checked_digest_exact (w : Words8) : checkDigest w = .ok () ↔ Checked w := by
  simp [checkDigest,Checked,List.all_eq_true]

theorem read_encoded (p : PublicInputs) (close : p.closeVersion < scalarLimit)
    (revived : p.revivedVersion < scalarLimit) : readFields (toU64Vec p) = p := by
  simp only [toU64Vec,Words8.words,splitU64,List.append_assoc,List.singleton_append,
    List.cons_append,List.nil_append]
  unfold readFields Words8.read
  simp only [List.getD_cons_zero,List.getD_cons_succ]
  rw [scalar_split_join p.closeVersion close,scalar_split_join p.revivedVersion revived]

theorem native_codec_roundtrip (p : PublicInputs) (h : NativeWidths p) (nz : p.channelId ≠ 0) :
    fromU64Slice (toU64Vec p) = .ok p := by
  rcases h with ⟨channel,c1,c2,close,revived,c3⟩
  have a := (checked_digest_exact _).mpr c1
  have b := (checked_digest_exact _).mpr c2
  have c := (checked_digest_exact _).mpr c3
  simp [fromU64Slice,word_length,read_encoded p close revived,Nat.not_le_of_gt channel,nz,a,b,c,
    Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem wrong_length_rejected (xs : List Nat) (h : xs.length ≠ publicInputLength) :
    fromU64Slice xs = .error (.length xs.length) := by
  simp [fromU64Slice,h,Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem successful_native_witness (e : NativeEnvironment) (w : Witness) (p : PublicInputs)
    (h : toPublicInputs e w = .ok p) :
    w.revived.channelId = w.close.channelId ∧ w.revived.digest = e.signingDigest w.revived ∧
    w.close.version < w.revived.version ∧ w.revived.freezeNonce + 1 = w.close.freezeNonce ∧
    w.close.freezeNonce < scalarLimit ∧
    p = ⟨w.close.channelId,e.hashWords (closePreimage w.close),Words8.zero,
      w.close.version,w.revived.version,e.signingDigest w.revived⟩ := by
  simp only [toPublicInputs,Bind.bind,Except.bind,Pure.pure,Except.pure] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases h
  simp_all

theorem native_revived_version_is_strictly_newer (e : NativeEnvironment) (w : Witness) (p : PublicInputs)
    (h : toPublicInputs e w = .ok p) : w.close.version < w.revived.version :=
  (successful_native_witness e w p h).2.2.1

theorem native_nonce_successor_does_not_wrap (e : NativeEnvironment) (w : Witness) (p : PublicInputs)
    (h : toPublicInputs e w = .ok p) :
    w.revived.freezeNonce + 1 = w.close.freezeNonce ∧ w.close.freezeNonce < scalarLimit :=
  ⟨(successful_native_witness e w p h).2.2.2.1,(successful_native_witness e w p h).2.2.2.2.1⟩

theorem native_channel_mismatch_rejected (e : NativeEnvironment) (w : Witness)
    (h : w.revived.channelId ≠ w.close.channelId) : toPublicInputs e w = .error .channelMismatch := by
  simp [toPublicInputs,h,Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem close_identity_preimage_length (c : Close) : (closePreimage c).length = 12 := by
  simp [closePreimage,Words8.words,splitU64]

def normalInputs : PublicInputs :=
  ⟨3,⟨1,2,3,4,5,6,7,8⟩,⟨9,10,11,12,13,14,15,16⟩,7,9,⟨17,18,19,20,21,22,23,24⟩⟩

theorem normal_codec_roundtrip : fromU64Slice (toU64Vec normalInputs) = .ok normalInputs := by
  apply native_codec_roundtrip
  · simp [NativeWidths,Checked,normalInputs,Words8.words,limbBase,scalarLimit]
  · decide

end Zkp.Implementation.CancelClosePublicInputs
