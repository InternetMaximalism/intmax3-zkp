import Std

/-!
# Current base-balance public inputs

Handwritten implementation model of src/circuits/balance/balance_pis.rs,
all 356 lines read. This is not Rust/Plonky2/compiler refinement. Imported
helpers are represented at their actual call boundaries; no historical model
or asset-safety axiom is imported.

The native prefix parser requires exactly 29 words and rejects channel zero.
The target parser accepts a suffix and merely wraps wires; checked allocation
range-checks channel but does NOT reject zero. Neither imposes block_r <= the
public state's height. Four-word Poseidon roots have no native canonical-field
check in from_u64_slice; field conversion for full verifier data is a separate
possibly-panicking dependency. Nat is a representative domain, not a claim
that Rust u64 or field wires can hold unbounded integers.

Full inputs carry the verifier digest followed by every configured cap root.
Serialization of too-short native caps panics, and extra native cap roots are
ignored, just like the indexed vd_to_vec helper. Hash commitments below expose
the exact preimage; binding premises concern only one concrete compared pair.
-/
namespace Zkp.Implementation.BalancePublicInputs

def wordBase : Nat := 2^32
def blockLimit : Nat := 2^63
def scalarLimit : Nat := 2^64
def publicStateLength : Nat := 15
def balanceLength : Nat := 29
def verifierLength (capCount : Nat) : Nat := 4 + 4*capCount

structure Root where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  deriving DecidableEq, Repr
def Root.words (r : Root) : List Nat := [r.a,r.b,r.c,r.d]
def Root.zero : Root := ⟨0,0,0,0⟩
def Root.read (xs : List Nat) (offset : Nat) : Root :=
  ⟨xs.getD offset 0,xs.getD (offset+1) 0,xs.getD (offset+2) 0,xs.getD (offset+3) 0⟩

structure Bytes8 where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  e : Nat
  f : Nat
  g : Nat
  h : Nat
  deriving DecidableEq, Repr
def Bytes8.words (x : Bytes8) : List Nat := [x.a,x.b,x.c,x.d,x.e,x.f,x.g,x.h]
def Bytes8.zero : Bytes8 := ⟨0,0,0,0,0,0,0,0⟩
def Bytes8.read (xs : List Nat) (offset : Nat) : Bytes8 :=
  ⟨xs.getD offset 0,xs.getD (offset+1) 0,xs.getD (offset+2) 0,xs.getD (offset+3) 0,
    xs.getD (offset+4) 0,xs.getD (offset+5) 0,xs.getD (offset+6) 0,xs.getD (offset+7) 0⟩

structure PublicState where
  blockNumber : Nat
  timestampHi : Nat
  timestampLo : Nat
  accountRoot : Root
  depositRoot : Root
  previousRoot : Root
  deriving DecidableEq, Repr
def PublicState.words (p : PublicState) : List Nat :=
  [p.blockNumber,p.timestampHi,p.timestampLo] ++ p.accountRoot.words ++
    p.depositRoot.words ++ p.previousRoot.words
def PublicState.read (xs : List Nat) : PublicState :=
  ⟨xs.getD 0 0,xs.getD 1 0,xs.getD 2 0,Root.read xs 3,Root.read xs 7,Root.read xs 11⟩

structure PublicInputs where
  channelId : Nat
  publicState : PublicState
  blockR : Nat
  privateCommitment : Root
  settledChain : Bytes8
  deriving DecidableEq, Repr
def PublicInputs.words (p : PublicInputs) : List Nat :=
  [p.channelId] ++ p.publicState.words ++ [p.blockR] ++
    p.privateCommitment.words ++ p.settledChain.words
def readFields (xs : List Nat) : PublicInputs :=
  ⟨xs.getD 0 0,PublicState.read (xs.drop 1),xs.getD 16 0,Root.read xs 17,Bytes8.read xs 21⟩

inductive Fault where
  | invalidLength
  | parse (field : String)
  | boundsPanic
  | fieldConversionPanic
  deriving DecidableEq, Repr
abbrev Result (α : Type) := Except Fault α

/-- Native guards in the order actually called. Four-word roots merely copy
    u64 inputs after an exact length check in their helper. -/
def checkNativeFields (p : PublicInputs) : Result PublicInputs :=
  if p.channelId = 0 ∨ p.channelId ≥ wordBase then .error (.parse "channel_id") else
  if p.publicState.blockNumber ≥ blockLimit then .error (.parse "public_state") else
  if p.publicState.timestampHi ≥ wordBase ∨ p.publicState.timestampLo ≥ wordBase then
    .error (.parse "public_state") else
  if p.blockR ≥ blockLimit then .error (.parse "block_r") else
  if p.settledChain.words.any (fun n => decide (n ≥ wordBase)) then
    .error (.parse "settled_tx_chain") else .ok p

def fromNative (xs : List Nat) : Result PublicInputs :=
  if xs.length = balanceLength then checkNativeFields (readFields xs)
  else .error .invalidLength
def fromTarget (xs : List Nat) : Result PublicInputs :=
  if balanceLength ≤ xs.length then .ok (readFields xs) else .error .boundsPanic

def AllocationChecks (p : PublicInputs) : Prop :=
  p.channelId < wordBase ∧ p.publicState.blockNumber < blockLimit ∧
  p.publicState.timestampHi < wordBase ∧ p.publicState.timestampLo < wordBase ∧
  p.blockR < blockLimit ∧ ∀ n ∈ p.settledChain.words, n < wordBase
def NativeDomain (p : PublicInputs) : Prop :=
  AllocationChecks p ∧ ∀ n ∈ p.words, n < scalarLimit

inductive AllocationOp where
  | channel (checked : Bool)
  | publicState (checked : Bool)
  | blockR (checked : Bool)
  | privateHash
  | settledChain (checked : Bool)
  deriving DecidableEq, Repr
def allocationPlan (checked : Bool) : List AllocationOp :=
  [.channel checked,.publicState checked,.blockR checked,.privateHash,.settledChain checked]
inductive Field where
  | channel | publicState | blockR | privateCommitment | settledChain | verifierData
  deriving DecidableEq, Repr
def witnessPlan : List Field :=
  [.channel,.publicState,.blockR,.privateCommitment,.settledChain]
def connectPlan : List Field := witnessPlan
def Connect (p q : PublicInputs) : Prop :=
  p.channelId = q.channelId ∧ p.publicState = q.publicState ∧ p.blockR = q.blockR ∧
  p.privateCommitment = q.privateCommitment ∧ p.settledChain = q.settledChain

structure GenesisEnvironment where
  assetEmptyRoot : Root
  nullifierEmptyRoot : Root
  sentEmptyRoot : Root
  accountInitialRoot : Root
  depositInitialRoot : Root
  publicStateInitialRoot : Root
  hashInputs : List Nat → Root
def initialPrivateWords (e : GenesisEnvironment) (salt : Root) : List Nat :=
  e.assetEmptyRoot.words ++ e.nullifierEmptyRoot.words ++ e.sentEmptyRoot.words ++
  Root.zero.words ++ [0] ++ salt.words
def initialPublicState (e : GenesisEnvironment) : PublicState :=
  ⟨0,0,0,e.accountInitialRoot,e.depositInitialRoot,e.publicStateInitialRoot⟩
def initialInputs (e : GenesisEnvironment) (channel : Nat) (salt : Root) : PublicInputs :=
  ⟨channel,initialPublicState e,0,e.hashInputs (initialPrivateWords e salt),Bytes8.zero⟩

structure VerifierData where
  digest : Root
  cap : List Root
  deriving DecidableEq, Repr
def rootsWords (roots : List Root) : List Nat := (roots.map Root.words).join
def VerifierData.words (vd : VerifierData) : List Nat := vd.digest.words ++ rootsWords vd.cap
def VerifierData.toConfiguredWords (count : Nat) (vd : VerifierData) : Result (List Nat) :=
  if count ≤ vd.cap.length then .ok (vd.digest.words ++ rootsWords (vd.cap.take count))
  else .error .boundsPanic
def readRootPrefix : List Nat → Result (Root × List Nat)
  | a::b::c::d::rest => .ok (⟨a,b,c,d⟩,rest)
  | _ => .error .boundsPanic
def readRoots : Nat → List Nat → Result (List Root × List Nat)
  | 0,xs => .ok ([],xs)
  | n+1,xs => do
    let (root,rest) ← readRootPrefix xs
    let (roots,tail) ← readRoots n rest
    return (root::roots,tail)
def readVerifier (count : Nat) (xs : List Nat) : Result VerifierData := do
  let (digest,rest) ← readRootPrefix xs
  let (cap,_) ← readRoots count rest
  return ⟨digest,cap⟩

structure FullInputs where
  pis : PublicInputs
  vd : VerifierData
  deriving DecidableEq, Repr
def FullInputs.words (p : FullInputs) : List Nat := p.pis.words ++ p.vd.words
def FullInputs.toConfiguredWords (count : Nat) (p : FullInputs) : Result (List Nat) := do
  let tail ← p.vd.toConfiguredWords count
  return p.pis.words ++ tail
def fullFromTarget (count : Nat) (xs : List Nat) : Result FullInputs :=
  if balanceLength + verifierLength count ≤ xs.length then do
    let pis ← fromTarget (xs.take balanceLength)
    let vd ← readVerifier count ((xs.drop balanceLength).take (verifierLength count))
    return ⟨pis,vd⟩
  else .error .boundsPanic

/-- The original calls ToField::to_field_vec before decoding the VD. Supplying
    identity here is a caller representation contract, not a new parser check. -/
def fullFromNative (convertFields : List Nat → Result (List Nat))
    (count : Nat) (xs : List Nat) : Result FullInputs :=
  if xs.length = balanceLength + verifierLength count then do
    let pis ← fromNative (xs.take balanceLength)
    let converted ← convertFields ((xs.drop balanceLength).take (verifierLength count))
    let vd ← readVerifier count converted
    return ⟨pis,vd⟩
  else .error .invalidLength
def fullWitnessPlan : List Field := witnessPlan ++ [.verifierData]
def fullAllocationPlan (capCount : Nat) : List AllocationOp × Nat :=
  (allocationPlan true,capCount)
def fullCommitment (hashInputs : List Nat → Root) (count : Nat) (p : FullInputs) : Result Root := do
  let words ← p.toConfiguredWords count
  return hashInputs words

theorem public_state_word_count (p : PublicState) : p.words.length = publicStateLength := by
  simp [PublicState.words,Root.words,publicStateLength]
theorem balance_word_count (p : PublicInputs) : p.words.length = balanceLength := by
  simp [PublicInputs.words,public_state_word_count,Root.words,Bytes8.words,balanceLength,publicStateLength]

theorem read_encoded_fields_with_suffix (p : PublicInputs) (suffix : List Nat) :
    readFields (p.words ++ suffix) = p := by
  simp only [PublicInputs.words,PublicState.words,Root.words,Bytes8.words,
    List.append_assoc,List.singleton_append,List.cons_append,List.nil_append]
  unfold readFields PublicState.read Root.read Bytes8.read
  cases p with
  | mk channel state reference commitment settled =>
    cases state; cases commitment; cases settled; rfl

theorem target_roundtrip_accepts_suffix (p : PublicInputs) (suffix : List Nat) :
    fromTarget (p.words ++ suffix) = .ok p := by
  simp [fromTarget,balance_word_count,read_encoded_fields_with_suffix,Nat.le_add_right]

theorem exact_native_guard_roundtrip (p : PublicInputs) (checked : AllocationChecks p)
    (nonzero : p.channelId ≠ 0) : checkNativeFields p = .ok p := by
  rcases checked with ⟨channel,block,hi,lo,reference,settled⟩
  have chain : p.settledChain.words.any (fun n => decide (n ≥ wordBase)) = false := by
    cases h : p.settledChain.words.any (fun n => decide (n ≥ wordBase)) with
    | false => rfl
    | true =>
      obtain ⟨n,hn,large⟩ := List.any_eq_true.mp h
      exact False.elim (Nat.not_le_of_gt (settled n hn) (of_decide_eq_true large))
  simp [checkNativeFields,nonzero,Nat.not_le_of_gt channel,Nat.not_le_of_gt block,
    Nat.not_le_of_gt hi,Nat.not_le_of_gt lo,Nat.not_le_of_gt reference,chain]

theorem native_roundtrip (p : PublicInputs) (checked : AllocationChecks p)
    (nonzero : p.channelId ≠ 0) : fromNative p.words = .ok p := by
  have read := read_encoded_fields_with_suffix p []
  simp only [List.append_nil] at read
  simp [fromNative,balance_word_count,read,exact_native_guard_roundtrip p checked nonzero]

theorem native_length_guard (xs : List Nat) (wrong : xs.length ≠ balanceLength) :
    fromNative xs = .error .invalidLength := by simp [fromNative,wrong]
theorem native_zero_channel_is_rejected (p : PublicInputs) (zero : p.channelId = 0) :
    checkNativeFields p = .error (.parse "channel_id") := by simp [checkNativeFields,zero]
theorem target_short_input_panics (xs : List Nat) (short : xs.length < balanceLength) :
    fromTarget xs = .error .boundsPanic := by simp [fromTarget,Nat.not_le_of_gt short]
theorem balance_encoding_injective {p q : PublicInputs} (same : p.words = q.words) : p = q := by
  have h := congrArg (fun xs => readFields (xs ++ [])) same
  simpa only [read_encoded_fields_with_suffix] using h
theorem connected_inputs_are_equal {p q : PublicInputs} (h : Connect p q) : p = q := by
  cases p; cases q; simp_all [Connect]
theorem allocation_preserves_checked_argument (checked : Bool) :
    allocationPlan checked = [.channel checked,.publicState checked,.blockR checked,
      .privateHash,.settledChain checked] := rfl

theorem genesis_private_preimage_width (e : GenesisEnvironment) (salt : Root) :
    (initialPrivateWords e salt).length = 21 := by simp [initialPrivateWords,Root.words]
theorem genesis_has_zero_reference_and_settled_chain (e : GenesisEnvironment)
    (channel : Nat) (salt : Root) :
    (initialInputs e channel salt).blockR = 0 ∧
    (initialInputs e channel salt).publicState.blockNumber = 0 ∧
    (initialInputs e channel salt).settledChain = Bytes8.zero := ⟨rfl,rfl,rfl⟩
theorem genesis_uses_exact_private_preimage (e : GenesisEnvironment) (channel : Nat) (salt : Root) :
    (initialInputs e channel salt).privateCommitment = e.hashInputs (initialPrivateWords e salt) := rfl

theorem roots_encoding_length (roots : List Root) : (rootsWords roots).length = 4*roots.length := by
  induction roots with
  | nil => rfl
  | cons root roots ih => simp [rootsWords,Root.words] at *; omega
theorem verifier_encoding_length (vd : VerifierData) :
    vd.words.length = verifierLength vd.cap.length := by
  simp [VerifierData.words,Root.words,roots_encoding_length,verifierLength]
  omega
theorem full_encoding_length (p : FullInputs) :
    p.words.length = balanceLength + verifierLength p.vd.cap.length := by
  simp [FullInputs.words,balance_word_count,verifier_encoding_length]
theorem configured_encoding_matches_full_shape (p : FullInputs) :
    p.toConfiguredWords p.vd.cap.length = .ok p.words := by
  simp [FullInputs.toConfiguredWords,VerifierData.toConfiguredWords,
    FullInputs.words,VerifierData.words,Bind.bind,Except.bind,Pure.pure,Except.pure]
theorem short_verifier_cap_panics (vd : VerifierData) (count : Nat) (short : vd.cap.length < count) :
    vd.toConfiguredWords count = .error .boundsPanic := by
  simp [VerifierData.toConfiguredWords,Nat.not_le_of_gt short]

theorem root_prefix_roundtrip (root : Root) (suffix : List Nat) :
    readRootPrefix (root.words ++ suffix) = .ok (root,suffix) := by cases root; rfl
theorem roots_prefix_roundtrip (roots : List Root) (suffix : List Nat) :
    readRoots roots.length (rootsWords roots ++ suffix) = .ok (roots,suffix) := by
  induction roots with
  | nil => rfl
  | cons root roots ih =>
    simp [rootsWords,readRoots,List.append_assoc,root_prefix_roundtrip,
      Bind.bind,Except.bind,Pure.pure,Except.pure] at *
    rw [ih]
theorem verifier_prefix_roundtrip (vd : VerifierData) (suffix : List Nat) :
    readVerifier vd.cap.length (vd.words ++ suffix) = .ok vd := by
  simp [readVerifier,VerifierData.words,List.append_assoc,root_prefix_roundtrip,
    roots_prefix_roundtrip,Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem full_target_roundtrip (p : FullInputs) :
    fullFromTarget p.vd.cap.length p.words = .ok p := by
  have leading : p.words.take balanceLength = p.pis.words := by
    simpa only [balance_word_count] using (List.take_left p.pis.words p.vd.words)
  have tail : (p.words.drop balanceLength).take (verifierLength p.vd.cap.length) = p.vd.words := by
    simp [FullInputs.words,←balance_word_count p.pis,←verifier_encoding_length p.vd]
  have readP := target_roundtrip_accepts_suffix p.pis []
  have readV := verifier_prefix_roundtrip p.vd []
  simp only [List.append_nil] at readP readV
  simp [fullFromTarget,full_encoding_length,leading,tail,readP,readV,
    Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem full_encoding_injective {p q : FullInputs} (capShape : p.vd.cap.length = q.vd.cap.length)
    (same : p.words = q.words) : p = q := by
  have h := congrArg (fullFromTarget p.vd.cap.length) same
  rw [full_target_roundtrip,capShape,full_target_roundtrip] at h
  exact Except.ok.inj h

theorem native_full_roundtrip (convert : List Nat → Result (List Nat)) (p : FullInputs)
    (checked : AllocationChecks p.pis) (nonzero : p.pis.channelId ≠ 0)
    (fieldRepresentation : convert p.vd.words = .ok p.vd.words) :
    fullFromNative convert p.vd.cap.length p.words = .ok p := by
  have leading : p.words.take balanceLength = p.pis.words := by
    simpa only [balance_word_count] using (List.take_left p.pis.words p.vd.words)
  have tail : (p.words.drop balanceLength).take (verifierLength p.vd.cap.length) = p.vd.words := by
    simp [FullInputs.words,←balance_word_count p.pis,←verifier_encoding_length p.vd]
  have readP := native_roundtrip p.pis checked nonzero
  have readV := verifier_prefix_roundtrip p.vd []
  simp only [List.append_nil] at readV
  simp [fullFromNative,full_encoding_length,leading,tail,readP,readV,fieldRepresentation,
    Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem native_full_length_guard (convert : List Nat → Result (List Nat))
    (count : Nat) (xs : List Nat) (wrong : xs.length ≠ balanceLength + verifierLength count) :
    fullFromNative convert count xs = .error .invalidLength := by simp [fullFromNative,wrong]
theorem full_commitment_uses_all_words (hashInputs : List Nat → Root) (p : FullInputs) :
    fullCommitment hashInputs p.vd.cap.length p = .ok (hashInputs p.words) := by
  simp [fullCommitment,configured_encoding_matches_full_shape,Bind.bind,Except.bind,Pure.pure,Except.pure]
theorem concrete_commitment_binding {hashInputs : List Nat → Root} {p q : FullInputs}
    (shape : p.vd.cap.length = q.vd.cap.length)
    (binding : hashInputs p.words = hashInputs q.words → p.words = q.words)
    (same : hashInputs p.words = hashInputs q.words) : p = q :=
  full_encoding_injective shape (binding same)

def normalInputs : PublicInputs :=
  ⟨7,⟨4,0,100,Root.zero,Root.zero,Root.zero⟩,3,Root.zero,Bytes8.zero⟩
theorem normal_native_roundtrip : fromNative normalInputs.words = .ok normalInputs := by
  apply native_roundtrip
  · simp [AllocationChecks,normalInputs,Bytes8.words,Bytes8.zero,wordBase,blockLimit]
  · decide
theorem normal_target_suffix_roundtrip :
    fromTarget (normalInputs.words ++ [10,11]) = .ok normalInputs :=
  target_roundtrip_accepts_suffix _ _

end Zkp.Implementation.BalancePublicInputs
