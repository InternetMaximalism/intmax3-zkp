import Std

/-!
# ChannelCloseCircuit: handwritten implementation-level semantics

Source: src/circuits/channel/close_circuit.rs, runtime05ec7ae, 2402 lines.
Current source and direct dependencies override stale 77-limb/SPHINCS/16-member/
IMBS-keccak comments: the public statement has103 words, eight Falcon slots,
and H1 is the37-element IMB2 Poseidon header with canonical Bytes32 encoding.

This is NOT compiler refinement, cryptographic soundness, or whole-system asset
soundness. Arbitrary raw witnesses are modeled separately from native filling.
The constructor recomputes commitments but does not open individual balance
slots, decrypt balances, sum payouts, check delegate total<=1024, zero unused
token suffixes, prove asset backing/finality, enforce pending/authorized burn
high-water, or select the latest signed state. Those are callers/dependencies.
The Balance proof binds only channelId and settledTxChain in THIS circuit.
Its private commitment, block_r, public height/root and accumulator are not
connected here. Do not infer the stronger CloseAssetBacking relationship.

No global finite-hash injectivity axiom appears: hash binding and indexed-tree
opening obligations are restricted to the concrete compared inputs or finite
visited insertion trace. Falcon aggregation is an explicit pinned-proof
dependency; member distinctness is a separate consumer obligation.
The source's feature-gated fixture/proof generators and test bodies are read
but not claimed as production constraints or executed by these Lean examples.
-/

namespace Zkp.Implementation.CloseCircuit

def wordBase : Nat := 2 ^ 32
def u64Limit : Nat := 2 ^ 64
def maxMembers : Nat := 8
def maxTokens : Nat := 10
def publicInputsLength : Nat := 103
def balancePublicInputsLength : Nat := 29
def aggregatePublicInputsLength : Nat := 73
def distinctnessHeight : Nat := 4
def fixtureNativeAmount : Nat := 77
def imchDomain : Nat := 0x494d4348
def imclDomain : Nat := 0x494d434c
def imcsDomain : Nat := 0x494d4353
def imcmDomain : Nat := 0x494d434d
def imtfDomain : Nat := 0x494d5446
def imb2Domain : Nat := 0x494d4232

structure Words2 where
  hi : Nat
  lo : Nat
  deriving DecidableEq, Repr

def Words2.words (x : Words2) : List Nat := [x.hi,x.lo]
def Words2.value (x : Words2) : Nat := x.hi * wordBase + x.lo
def Words2.zero : Words2 := ⟨0,0⟩
def Words2.fromNat (n : Nat) : Words2 := ⟨n / wordBase, n % wordBase⟩
def Words2.read (xs : List Nat) (offset : Nat) : Words2 :=
  ⟨xs.getD offset 0, xs.getD (offset+1) 0⟩

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

def Words8.words (x : Words8) : List Nat :=
  [x.w0,x.w1,x.w2,x.w3,x.w4,x.w5,x.w6,x.w7]
def Words8.zero : Words8 := ⟨0,0,0,0,0,0,0,0⟩
def Words8.read (xs : List Nat) (offset : Nat) : Words8 :=
  ⟨xs.getD offset 0, xs.getD (offset+1) 0, xs.getD (offset+2) 0,
   xs.getD (offset+3) 0, xs.getD (offset+4) 0, xs.getD (offset+5) 0,
   xs.getD (offset+6) 0, xs.getD (offset+7) 0⟩
def CheckedWords (xs : List Nat) : Prop := ∀ x ∈ xs, x < wordBase

structure Hash4 where
  h0 : Nat
  h1 : Nat
  h2 : Nat
  h3 : Nat
  deriving DecidableEq, Repr
def Hash4.words (h : Hash4) : List Nat := [h.h0,h.h1,h.h2,h.h3]

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

/-- new() checks every public word to32 bits. from_slice adds NO range gates. -/
def PublicInputs.AllocationChecks (p : PublicInputs) : Prop := CheckedWords p.words

/-- Small proof-only slice utilities. The executable parser below uses source
    cursor offsets directly; these are not additional constructor operations. -/
def readWord : List Nat → Option (Nat × List Nat)
  | x::xs => some (x,xs)
  | _ => none

def readWords2 : List Nat → Option (Words2 × List Nat)
  | a::b::xs => some (⟨a,b⟩,xs)
  | _ => none

def readWords8 : List Nat → Option (Words8 × List Nat)
  | a::b::c::d::e::f::g::h::xs => some (⟨a,b,c,d,e,f,g,h⟩,xs)
  | _ => none

theorem read_one_word_before_suffix (word : Nat) (tail : List Nat) :
    readWord (word::tail) = some (word,tail) := rfl

theorem read_two_words_before_suffix (w : Words2) (tail : List Nat) :
    readWords2 (w.words ++ tail) = some (w,tail) := rfl

theorem read_eight_words_before_suffix (w : Words8) (tail : List Nat) :
    readWords8 (w.words ++ tail) = some (w,tail) := rfl

theorem read_final_eight_words (w : Words8) : readWords8 w.words = some (w,[]) := rfl

def readTargetFields (xs : List Nat) : PublicInputs := {
  channelId := xs.getD 0 0
  closeNonce := Words2.read xs 1
  finalEpoch := Words2.read xs 3
  finalSmallBlock := Words2.read xs 5
  freezeNonce := Words2.read xs 7
  stateDigest := Words8.read xs 9
  h1 := Words8.read xs 17
  genesisFund := Words8.read xs 25
  fundRoot := Words8.read xs 33
  burnHash := Words8.read xs 41
  withdrawalDigest := Words8.read xs 49
  closeId := Words8.read xs 57
  snapshot := Words2.read xs 65
  stateVersion := Words2.read xs 67
  settledChain := Words8.read xs 69
  accumulatorRoot := Words8.read xs 77
  memberSet := Words8.read xs 85
  memberCount := xs.getD 93 0
  delegateCount := xs.getD 94 0
  tokenFundsDigest := Words8.read xs 95 }

/-- Called only behind the exact length guard. getD's fallback is therefore
    unreachable for every source slice/index above; it is not source padding. -/
def parseExactTargets (xs : List Nat) : Option PublicInputs := some (readTargetFields xs)

/-- Shape failure denotes the source assert panic; it is not a soft native
    parse error. Field offsets are the source's monotonically advanced cursor. -/
def parseTargets (xs : List Nat) : Option PublicInputs :=
  if xs.length = publicInputsLength then parseExactTargets xs else none

theorem public_input_word_count (p : PublicInputs) : p.words.length = publicInputsLength := by
  simp [PublicInputs.words, Words2.words, Words8.words, publicInputsLength]

theorem public_inputs_equal_of_fields_equal (p q : PublicInputs)
    (h0 : p.channelId = q.channelId)
    (h1 : p.closeNonce = q.closeNonce)
    (h2 : p.finalEpoch = q.finalEpoch)
    (h3 : p.finalSmallBlock = q.finalSmallBlock)
    (h4 : p.freezeNonce = q.freezeNonce)
    (h5 : p.stateDigest = q.stateDigest)
    (h6 : p.h1 = q.h1)
    (h7 : p.genesisFund = q.genesisFund)
    (h8 : p.fundRoot = q.fundRoot)
    (h9 : p.burnHash = q.burnHash)
    (h10 : p.withdrawalDigest = q.withdrawalDigest)
    (h11 : p.closeId = q.closeId)
    (h12 : p.snapshot = q.snapshot)
    (h13 : p.stateVersion = q.stateVersion)
    (h14 : p.settledChain = q.settledChain)
    (h15 : p.accumulatorRoot = q.accumulatorRoot)
    (h16 : p.memberSet = q.memberSet)
    (h17 : p.memberCount = q.memberCount)
    (h18 : p.delegateCount = q.delegateCount)
    (h19 : p.tokenFundsDigest = q.tokenFundsDigest) : p = q := by
  cases p
  cases q
  cases h0
  cases h1
  cases h2
  cases h3
  cases h4
  cases h5
  cases h6
  cases h7
  cases h8
  cases h9
  cases h10
  cases h11
  cases h12
  cases h13
  cases h14
  cases h15
  cases h16
  cases h17
  cases h18
  cases h19
  rfl

set_option maxRecDepth 4096 in
theorem target_fields_round_trip (p : PublicInputs) : readTargetFields p.words = p := by
  simp only [PublicInputs.words,Words2.words,Words8.words,List.append_assoc,
    List.singleton_append,List.cons_append,List.nil_append]
  unfold readTargetFields Words2.read Words8.read
  cases p
  rfl

theorem target_public_input_round_trip (p : PublicInputs) : parseTargets p.words = some p := by
  simp only [parseTargets,public_input_word_count,ite_true,parseExactTargets,target_fields_round_trip]

theorem exact_public_input_encoding_is_injective {p q : PublicInputs}
    (h : p.words = q.words) : p = q := by
  have hp := congrArg parseTargets h
  simpa only [target_public_input_round_trip, Option.some.injEq] using hp

theorem target_parser_rejects_any_wrong_length (xs : List Nat)
    (h : xs.length ≠ publicInputsLength) : parseTargets xs = none := by
  simp [parseTargets,h]

/-- Extra native member-auth vector is not the verified signer vector. The
    actual in-circuit keys are slices of the verified aggregate proof PIs. -/
structure MemberAuth where
  pk : Words8
  deriving DecidableEq, Repr

structure PrivateWitness where
  stateFreezeNonce : Words2
  sharedNullifierRoot : Words8
  unallocatedIncoming : Words8
  previousDigest : Words8
  h2 : Words8
  slotTreeRoot : Hash4
  tokenCount : Nat
  registry : List Nat
  amounts : List Words8
  memberActive : List Bool
  tokenActive : List Bool
  deriving DecidableEq, Repr

def flattenAmounts : List Words8 → List Nat
  | [] => []
  | x::xs => x.words ++ flattenAmounts xs

def PrivateWitness.Shape (w : PrivateWitness) : Prop :=
  w.registry.length = maxTokens ∧ w.amounts.length = maxTokens ∧
  w.memberActive.length = maxMembers ∧ w.tokenActive.length = maxTokens

def PrivateWitness.Checked (w : PrivateWitness) : Prop :=
  CheckedWords (w.stateFreezeNonce.words ++ w.sharedNullifierRoot.words ++
    w.unallocatedIncoming.words ++ w.previousDigest.words ++ w.h2.words ++
    [w.tokenCount] ++ w.registry ++ flattenAmounts w.amounts)

/-- H1 uses the raw4-element Poseidon root, not its eight-word byte encoding. -/
def h1Preimage (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [imb2Domain,p.channelId,p.memberCount,p.delegateCount,w.tokenCount] ++
  w.registry ++ w.slotTreeRoot.words ++ p.settledChain.words ++
  p.accumulatorRoot.words ++ p.stateVersion.words

def imchPreimage (p : PublicInputs) (w : PrivateWitness) (computedH1 : Words8) : List Nat :=
  [imchDomain,p.channelId] ++ p.finalEpoch.words ++ p.finalSmallBlock.words ++
  w.stateFreezeNonce.words ++ [p.channelId] ++ flattenAmounts w.amounts ++
  p.fundRoot.words ++ computedH1.words ++ w.sharedNullifierRoot.words ++
  w.unallocatedIncoming.words ++ w.previousDigest.words ++ w.h2.words ++ p.stateVersion.words

def imclPreimage (p : PublicInputs) : List Nat :=
  [imclDomain,p.channelId] ++ p.stateDigest.words ++ p.h1.words ++
  p.fundRoot.words ++ p.burnHash.words ++ p.genesisFund.words

def imcsPreimage (p : PublicInputs) (computedState : Words8) : List Nat :=
  [imcsDomain,p.channelId] ++ computedState.words ++ p.freezeNonce.words

def tokenFundsPreimage (w : PrivateWitness) : List Nat :=
  [imtfDomain] ++ w.registry ++ [w.tokenCount] ++ flattenAmounts w.amounts

def selectedKeys : List Bool → List Words8 → List Words8
  | b::bs, k::ks => (if b then k else Words8.zero) :: selectedKeys bs ks
  | _,_ => []

def memberSetPreimage (count : Nat) (flags : List Bool) (keys : List Words8) : List Nat :=
  [imcmDomain,count] ++ flattenAmounts (selectedKeys flags keys)

/-- Native helper truncates/pads to8, casts len to u8, then the called
    close_member_set_commitment masks every index >= that CAST count.
    Production prove/fill validates auth length/count, but this total helper
    does not silently assume the production bound. -/
def nativeMemberSetPreimage (auth : List MemberAuth) : List Nat :=
  let keys := (auth.map MemberAuth.pk ++ List.replicate maxMembers Words8.zero).take maxMembers
  let count := auth.length % 256
  let flags := (List.range maxMembers).map (fun i => decide (i < count))
  memberSetPreimage count flags keys

theorem flattened_amounts_keep_all_eight_words (amounts : List Words8) :
    (flattenAmounts amounts).length = amounts.length * 8 := by
  induction amounts with
  | nil => rfl
  | cons a as ih => simp [flattenAmounts, Words8.words, ih, Nat.add_mul, Nat.add_comm]; omega

theorem h1_header_has_current_37_elements (p : PublicInputs) (w : PrivateWitness)
    (shape : w.Shape) : (h1Preimage p w).length = 37 := by
  simp [h1Preimage, Hash4.words, Words8.words, Words2.words, shape.1, maxTokens]

theorem imch_has_complete_139_word_preimage (p : PublicInputs) (w : PrivateWitness) (h : Words8)
    (shape : w.Shape) : (imchPreimage p w h).length = 139 := by
  simp [imchPreimage, Words8.words, Words2.words, flattened_amounts_keep_all_eight_words,
    shape.2.1, maxTokens]

theorem token_funds_preimage_has_exact_92_words (w : PrivateWitness) (shape : w.Shape) :
    (tokenFundsPreimage w).length = 92 := by
  simp [tokenFundsPreimage, flattened_amounts_keep_all_eight_words, shape.1, shape.2.1,maxTokens]

theorem imcl_preimage_has_42_words (p : PublicInputs) : (imclPreimage p).length = 42 := by
  simp [imclPreimage,Words8.words]

theorem imcs_preimage_has_12_words (p : PublicInputs) (h : Words8) :
    (imcsPreimage p h).length = 12 := by simp [imcsPreimage,Words8.words,Words2.words]

def bit (b : Bool) : Nat := if b then 1 else 0
def activeCount : List Bool → Nat
  | [] => 0
  | b::bs => bit b + activeCount bs
def NoRise : Bool → List Bool → Prop
  | _,[] => True
  | prev,b::bs => (b = true → prev = true) ∧ NoRise b bs

structure PrefixGates (width count : Nat) (flags : List Bool) : Prop where
  length : flags.length = width
  monotone : NoRise true flags
  sum : activeCount flags = count

theorem active_count_bounded_by_width (flags : List Bool) :
    activeCount flags ≤ flags.length := by
  induction flags with
  | nil => simp [activeCount]
  | cons b bs ih => cases b <;> simp_all [activeCount,bit] <;> omega

theorem no_rise_after_padding (flags : List Bool) (h : NoRise false flags) :
    flags = List.replicate flags.length false := by
  induction flags with
  | nil => rfl
  | cons b bs ih =>
      cases b with
      | false =>
          change false :: bs = false :: List.replicate bs.length false
          exact congrArg (List.cons false) (ih h.2)
      | true => have := h.1 rfl; contradiction

theorem active_count_of_false_suffix (n : Nat) :
    activeCount (List.replicate n false) = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simpa [activeCount,bit] using ih

theorem monotone_flags_are_the_exact_active_prefix (flags : List Bool) (h : NoRise true flags) :
    flags = List.replicate (activeCount flags) true ++
      List.replicate (flags.length - activeCount flags) false := by
  induction flags with
  | nil => rfl
  | cons b bs ih =>
      cases b with
      | false =>
          have hs := no_rise_after_padding bs h.2
          simp only [activeCount,bit,Bool.false_eq_true,reduceIte,Nat.zero_add]
          rw [hs,active_count_of_false_suffix]
          simp [List.replicate_succ]
      | true =>
          have ht := ih h.2
          have bound := active_count_bounded_by_width bs
          simp only [activeCount,bit,reduceIte,List.length_cons]
          rw [Nat.add_comm 1, List.replicate_succ]
          have subeq : bs.length + 1 - (activeCount bs + 1) = bs.length - activeCount bs := by omega
          rw [subeq]
          simpa using congrArg (List.cons true) ht

theorem prefix_gates_fix_every_flag {width count : Nat} {flags : List Bool}
    (g : PrefixGates width count flags) :
    count ≤ width ∧ flags = List.replicate count true ++ List.replicate (width-count) false := by
  have bound := active_count_bounded_by_width flags
  rw [g.sum,g.length] at bound
  exact ⟨bound,by simpa [g.sum,g.length] using monotone_flags_are_the_exact_active_prefix flags g.monotone⟩

def MemberFloor (flags : List Bool) : Prop := flags.getD 0 false = true ∧ flags.getD 1 false = true
def TokenFloor (flags : List Bool) : Prop := flags.getD 0 false = true

theorem member_floor_requires_two_active_flags (flags : List Bool) (g : MemberFloor flags) :
    2 ≤ activeCount flags := by
  cases flags with
  | nil => simp [MemberFloor,List.getD] at g
  | cons b bs =>
    cases bs with
    | nil => simp [MemberFloor,List.getD] at g
    | cons c cs =>
      simp only [MemberFloor,List.getD,List.getElem?_cons_zero,List.getElem?_cons_succ,
        Option.getD_some] at g
      rcases g with ⟨rfl,rfl⟩
      simp [activeCount,bit]
      omega

theorem token_floor_requires_one_active_flag (flags : List Bool) (g : TokenFloor flags) :
    1 ≤ activeCount flags := by
  cases flags with
  | nil => simp [TokenFloor,List.getD] at g
  | cons b bs =>
      change b = true at g
      subst b
      simp [activeCount,bit]
      omega

/-- Source pair checks forbid an equal registry key only when the LATER slot
    is active. There are no inactive zero-suffix checks in this callee. -/
def RegistryPairGates (registry : List Nat) (flags : List Bool) : Prop :=
  ∀ i j, i < j → j < registry.length → flags.getD j false = true →
    registry.getD i 0 ≠ registry.getD j 0

theorem prefix_gate_marks_every_in_range_slot_active {width count : Nat}
    {flags : List Bool} (g : PrefixGates width count flags) (slot : Nat) (active : slot < count) :
    flags.getD slot false = true := by
  rw [(prefix_gates_fix_every_flag g).2]
  unfold List.getD
  rw [List.get?_eq_getElem?,List.getElem?_append (by simpa using active)]
  simp [List.get?_eq_getElem?,List.getElem?_replicate,active]

/-- Local two-limb successor equations mirror U64Target::add(1), initial
    carry0 and final carry0. No whole-u64 no-overflow assumption is used. -/
def FreezeSuccessorGates (before after : Words2) : Prop :=
  ∃ carry : Nat, before.lo + 1 = after.lo + wordBase * carry ∧
    before.hi + carry = after.hi ∧
    before.hi < wordBase ∧ before.lo < wordBase ∧
    after.hi < wordBase ∧ after.lo < wordBase

theorem freeze_limb_equations_prove_exact_successor (before after : Words2)
    (g : FreezeSuccessorGates before after) :
    after.value = before.value + 1 ∧ after.value < u64Limit := by
  obtain ⟨carry,low,high,_bh,_bl,ah,al⟩ := g
  constructor
  · simp only [Words2.value]
    have scaled := congrArg (fun n => n * wordBase) high
    simp only [Nat.add_mul] at scaled
    rw [Nat.mul_comm carry wordBase] at scaled
    omega
  · simp only [Words2.value,u64Limit,wordBase] at *
    omega

structure BalanceStatement where
  channelId : Nat
  publicStateWords : List Nat
  blockR : Nat
  privateCommitment : Hash4
  settledChain : Words8
  embeddedVerifier : List Nat
  deriving DecidableEq, Repr

structure AggregateStatement where
  message : Words8
  signerCount : Nat
  keys : List Words8
  deriving DecidableEq, Repr

def AggregateStatement.words (s : AggregateStatement) : List Nat :=
  s.message.words ++ [s.signerCount] ++ flattenAmounts s.keys

/-- Pinned verifier identities are supplied by the constructor caller.
    Equal public-input arity alone does not establish a canonical verifier. -/
structure Environment (BalanceProof AggregateProof Path Root : Type) where
  h1Hash : List Nat → Words8
  keccak : List Nat → Words8
  balanceVerifier : List Nat
  aggregateVerifier : List Nat
  verifyBalance : List Nat → BalanceProof → BalanceStatement → Prop
  verifyAggregate : List Nat → AggregateProof → AggregateStatement → Prop
  emptyDistinctRoot : Root
  insertStep : Bool → Words8 → Path → Root → Root
  insertGates : Bool → Words8 → Path → Root → Prop

structure ProofWitness (BalanceProof AggregateProof Path : Type) where
  privateData : PrivateWitness
  balanceProof : BalanceProof
  balance : BalanceStatement
  aggregateProof : AggregateProof
  aggregate : AggregateStatement
  insertionPaths : List Path

def InsertionGates {BalanceProof AggregateProof Path Root : Type}
    (e : Environment BalanceProof AggregateProof Path Root) :
    List Bool → List Words8 → List Path → Root → Prop
  | [],[],[],_ => True
  | b::bs,k::ks,p::ps,root => e.insertGates b k p root ∧
      InsertionGates e bs ks ps (e.insertStep b k p root)
  | _,_,_,_ => False

structure CircuitGates {BalanceProof AggregateProof Path Root : Type}
    (e : Environment BalanceProof AggregateProof Path Root) (p : PublicInputs)
    (w : ProofWitness BalanceProof AggregateProof Path) : Prop where
  publicRanges : p.AllocationChecks
  privateRanges : w.privateData.Checked
  shape : w.privateData.Shape
  members : PrefixGates maxMembers p.memberCount w.privateData.memberActive
  memberFloor : MemberFloor w.privateData.memberActive
  tokens : PrefixGates maxTokens w.privateData.tokenCount w.privateData.tokenActive
  tokenFloor : TokenFloor w.privateData.tokenActive
  registryPairs : RegistryPairGates w.privateData.registry w.privateData.tokenActive
  genesis : w.privateData.amounts.head? = some p.genesisFund
  successor : FreezeSuccessorGates w.privateData.stateFreezeNonce p.freezeNonce
  closeNonce : p.closeNonce = p.freezeNonce
  snapshot : p.snapshot = Words2.zero
  burn : p.burnHash = Words8.zero
  unallocated : w.privateData.unallocatedIncoming = Words8.zero
  h1 : e.h1Hash (h1Preimage p w.privateData) = p.h1
  imch : e.keccak (imchPreimage p w.privateData (e.h1Hash (h1Preimage p w.privateData))) = p.stateDigest
  imcl : e.keccak (imclPreimage p) = p.withdrawalDigest
  imcs : e.keccak (imcsPreimage p p.stateDigest) = p.closeId
  tokenFunds : e.keccak (tokenFundsPreimage w.privateData) = p.tokenFundsDigest
  balanceVerified : e.verifyBalance e.balanceVerifier w.balanceProof w.balance
  cyclicKey : w.balance.embeddedVerifier = e.balanceVerifier
  balanceChannel : w.balance.channelId = p.channelId
  balanceChain : w.balance.settledChain = p.settledChain
  aggregateVerified : e.verifyAggregate e.aggregateVerifier w.aggregateProof w.aggregate
  aggregateWidth : w.aggregate.keys.length = maxMembers
  aggregateMessage : w.aggregate.message = p.stateDigest
  aggregateCount : w.aggregate.signerCount = p.memberCount
  insertion : InsertionGates e w.privateData.memberActive w.aggregate.keys
    w.insertionPaths e.emptyDistinctRoot
  memberSet : e.keccak (memberSetPreimage p.memberCount w.privateData.memberActive w.aggregate.keys) =
    p.memberSet

/-- Actual raw Plonky2 gates must lower to these local checks. This is not a
    premise that says accepted proofs already satisfy asset soundness. -/
def FieldAndGadgetLowering {BalanceProof AggregateProof Path Root : Type}
    (e : Environment BalanceProof AggregateProof Path Root)
    (raw : PublicInputs → ProofWitness BalanceProof AggregateProof Path → Prop) : Prop :=
  ∀ p w, raw p w → CircuitGates e p w

theorem close_proves_current_member_and_token_floors
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w) :
    2 ≤ p.memberCount ∧ p.memberCount ≤ 8 ∧
    1 ≤ w.privateData.tokenCount ∧ w.privateData.tokenCount ≤ 10 := by
  have m := member_floor_requires_two_active_flags _ g.memberFloor
  have t := token_floor_requires_one_active_flag _ g.tokenFloor
  rw [g.members.sum] at m
  rw [g.tokens.sum] at t
  exact ⟨m,(prefix_gates_fix_every_flag g.members).1,t,(prefix_gates_fix_every_flag g.tokens).1⟩

theorem close_metadata_is_canonical_without_new_signatures
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w) :
    p.closeNonce = p.freezeNonce ∧
    p.freezeNonce.value = w.privateData.stateFreezeNonce.value + 1 ∧
    p.freezeNonce.value < u64Limit ∧
    p.snapshot = Words2.zero ∧ p.burnHash = Words8.zero ∧
    w.privateData.unallocatedIncoming = Words8.zero := by
  have s := freeze_limb_equations_prove_exact_successor _ _ g.successor
  exact ⟨g.closeNonce,s.1,s.2,g.snapshot,g.burn,g.unallocated⟩

theorem recursive_balance_identity_and_history_are_exact
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w) :
    w.balance.channelId = p.channelId ∧ w.balance.settledChain = p.settledChain ∧
    w.balance.embeddedVerifier = e.balanceVerifier :=
  ⟨g.balanceChannel,g.balanceChain,g.cyclicKey⟩

theorem aggregate_statement_is_bound_to_all_active_members
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w) :
    w.aggregate.message = p.stateDigest ∧ w.aggregate.signerCount = p.memberCount ∧
    w.aggregate.keys.length = 8 :=
  ⟨g.aggregateMessage,g.aggregateCount,g.aggregateWidth⟩

theorem every_active_token_pair_is_distinct
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w)
    (i j : Nat) (ordered : i < j) (active : j < w.privateData.tokenCount) :
    w.privateData.registry.getD i 0 ≠ w.privateData.registry.getD j 0 := by
  have countBound := (prefix_gates_fix_every_flag g.tokens).1
  have indexBound : j < w.privateData.registry.length := by
    rw [g.shape.1]
    exact Nat.lt_of_lt_of_le active countBound
  exact g.registryPairs i j ordered indexBound (prefix_gate_marks_every_in_range_slot_active g.tokens j active)

theorem words8_encoding_is_injective {a b : Words8} (h : a.words = b.words) : a = b := by
  cases a; cases b
  simp only [Words8.words,List.cons.injEq] at h
  rcases h with ⟨rfl,rfl,rfl,rfl,rfl,rfl,rfl,rfl,_⟩
  rfl

theorem flattened_vectors_are_injective {a b : List Words8}
    (h : flattenAmounts a = flattenAmounts b) : a = b := by
  induction a generalizing b with
  | nil =>
      cases b with
      | nil => rfl
      | cons b bs => simp [flattenAmounts,Words8.words] at h
  | cons a as ih =>
      cases b with
      | nil => simp [flattenAmounts,Words8.words] at h
      | cons b bs =>
          have hh : a.words ++ flattenAmounts as = b.words ++ flattenAmounts bs := h
          have hs := List.append_inj hh (by simp [Words8.words])
          rw [words8_encoding_is_injective hs.1,ih hs.2]

theorem token_funds_preimage_binds_count_registry_and_every_amount
    (a b : PrivateWitness) (sameLength : a.registry.length = b.registry.length)
    (same : tokenFundsPreimage a = tokenFundsPreimage b) :
    a.registry = b.registry ∧ a.tokenCount = b.tokenCount ∧ a.amounts = b.amounts := by
  have he : a.registry ++ ([a.tokenCount] ++ flattenAmounts a.amounts) =
      b.registry ++ ([b.tokenCount] ++ flattenAmounts b.amounts) := by
    simpa [tokenFundsPreimage,List.append_assoc] using same
  have hr := List.append_inj he sameLength
  have ht : a.tokenCount = b.tokenCount ∧ flattenAmounts a.amounts = flattenAmounts b.amounts := by
    simpa only [List.cons_append,List.nil_append,List.cons.injEq] using hr.2
  exact ⟨hr.1,ht.1,flattened_vectors_are_injective ht.2⟩

def imchPrefix (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [imchDomain,p.channelId] ++ p.finalEpoch.words ++ p.finalSmallBlock.words ++
    w.stateFreezeNonce.words ++ [p.channelId]
def imchSuffix (p : PublicInputs) (w : PrivateWitness) (h : Words8) : List Nat :=
  p.fundRoot.words ++ h.words ++ w.sharedNullifierRoot.words ++ w.unallocatedIncoming.words ++
    w.previousDigest.words ++ w.h2.words ++ p.stateVersion.words

theorem imch_preimage_exposes_full_amount_vector (p q : PublicInputs)
    (a b : PrivateWitness) (ha hb : Words8) (lengths : a.amounts.length = b.amounts.length)
    (same : imchPreimage p a ha = imchPreimage q b hb) :
    a.amounts = b.amounts ∧ ha = hb := by
  have he : imchPrefix p a ++ (flattenAmounts a.amounts ++ imchSuffix p a ha) =
      imchPrefix q b ++ (flattenAmounts b.amounts ++ imchSuffix q b hb) := by
    simpa only [imchPreimage,imchPrefix,imchSuffix,List.append_assoc] using same
  have hp := List.append_inj_right he (by simp [imchPrefix,Words2.words])
  have hv := List.append_inj hp (by simp [flattened_amounts_keep_all_eight_words,lengths])
  have hs : p.fundRoot.words ++ (ha.words ++
      (a.sharedNullifierRoot.words ++ a.unallocatedIncoming.words ++ a.previousDigest.words ++
       a.h2.words ++ p.stateVersion.words)) =
      q.fundRoot.words ++ (hb.words ++
      (b.sharedNullifierRoot.words ++ b.unallocatedIncoming.words ++ b.previousDigest.words ++
       b.h2.words ++ q.stateVersion.words)) := by
    simpa only [imchSuffix,List.append_assoc] using hv.2
  have hh := List.append_inj_right hs (by simp [Words8.words])
  exact ⟨flattened_vectors_are_injective hv.1,
    words8_encoding_is_injective (List.append_inj_left hh (by simp [Words8.words]))⟩

def h1Prefix (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [imb2Domain,p.channelId,p.memberCount,p.delegateCount,w.tokenCount]

theorem h1_preimage_binds_registry_and_token_count (p q : PublicInputs)
    (a b : PrivateWitness) (lengths : a.registry.length = b.registry.length)
    (same : h1Preimage p a = h1Preimage q b) :
    a.registry = b.registry ∧ a.tokenCount = b.tokenCount := by
  have he : h1Prefix p a ++ (a.registry ++ (a.slotTreeRoot.words ++ p.settledChain.words ++
      p.accumulatorRoot.words ++ p.stateVersion.words)) =
    h1Prefix q b ++ (b.registry ++ (b.slotTreeRoot.words ++ q.settledChain.words ++
      q.accumulatorRoot.words ++ q.stateVersion.words)) := by
    simpa only [h1Preimage,h1Prefix,List.append_assoc] using same
  have hp := List.append_inj he (by simp [h1Prefix])
  have hc : a.tokenCount = b.tokenCount := by
    have h := hp.1
    simp only [h1Prefix,List.cons.injEq] at h
    exact h.2.2.2.2.1
  exact ⟨List.append_inj_left hp.2 lengths,hc⟩

/-- Collision/canonical-encoding premise for exactly two concrete preimages,
    not an impossible globally injective finite hash or a safety conclusion. -/
def HashBindingAt (hash : List Nat → Words8) (a b : List Nat) : Prop :=
  hash a = hash b → a = b

theorem one_signed_digest_binds_the_entire_token_vector
    {BP AP Path Root : Type} (e : Environment BP AP Path Root)
    (p q : PublicInputs) (a b : ProofWitness BP AP Path)
    (ga : CircuitGates e p a) (gb : CircuitGates e q b)
    (sameSignedDigest : p.stateDigest = q.stateDigest)
    (imchBinding : HashBindingAt e.keccak
      (imchPreimage p a.privateData (e.h1Hash (h1Preimage p a.privateData)))
      (imchPreimage q b.privateData (e.h1Hash (h1Preimage q b.privateData))))
    (h1Binding : HashBindingAt e.h1Hash
      (h1Preimage p a.privateData) (h1Preimage q b.privateData)) :
    a.privateData.registry = b.privateData.registry ∧
    a.privateData.tokenCount = b.privateData.tokenCount ∧
    a.privateData.amounts = b.privateData.amounts := by
  have he := imchBinding (ga.imch.trans (sameSignedDigest.trans gb.imch.symm))
  have hm := imch_preimage_exposes_full_amount_vector p q a.privateData b.privateData _ _
    (ga.shape.2.1.trans gb.shape.2.1.symm) he
  have hh := h1_preimage_binds_registry_and_token_count p q a.privateData b.privateData
    (ga.shape.1.trans gb.shape.1.symm) (h1Binding hm.2)
  exact ⟨hh.1,hh.2,hm.1⟩

theorem no_component_mix_under_a_fixed_signed_digest
    {BP AP Path Root : Type} (e : Environment BP AP Path Root)
    (p q : PublicInputs) (a b : ProofWitness BP AP Path)
    (ga : CircuitGates e p a) (gb : CircuitGates e q b)
    (sameSignedDigest : p.stateDigest = q.stateDigest)
    (imchBinding : HashBindingAt e.keccak
      (imchPreimage p a.privateData (e.h1Hash (h1Preimage p a.privateData)))
      (imchPreimage q b.privateData (e.h1Hash (h1Preimage q b.privateData))))
    (h1Binding : HashBindingAt e.h1Hash (h1Preimage p a.privateData) (h1Preimage q b.privateData)) :
    ∀ slot, a.privateData.registry.getD slot 0 = b.privateData.registry.getD slot 0 ∧
      a.privateData.amounts.getD slot Words8.zero = b.privateData.amounts.getD slot Words8.zero := by
  have he := one_signed_digest_binds_the_entire_token_vector e p q a b ga gb sameSignedDigest
    imchBinding h1Binding
  intro slot
  exact ⟨congrArg (fun r => r.getD slot 0) he.1,
    congrArg (fun r => r.getD slot Words8.zero) he.2.2⟩

/-- Pinned aggregate verifier statement soundness, scoped to this proof and
    its exposed statement. Signature verification, not member ownership or
    legal economic transitions, is the dependency conclusion. -/
def AggregateContractAt {BP AP Path Root : Type} (e : Environment BP AP Path Root)
    (signatureVerified : Words8 → Words8 → Prop) (proof : AP) (s : AggregateStatement) : Prop :=
  e.verifyAggregate e.aggregateVerifier proof s →
    ∀ slot, slot < s.signerCount → signatureVerified (s.keys.getD slot Words8.zero) s.message

theorem every_exposed_active_member_signed_the_exact_imch
    {BP AP Path Root : Type} (e : Environment BP AP Path Root)
    (signatureVerified : Words8 → Words8 → Prop) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w)
    (contractAt : AggregateContractAt e signatureVerified w.aggregateProof w.aggregate) :
    ∀ slot, slot < p.memberCount →
      signatureVerified (w.aggregate.keys.getD slot Words8.zero) p.stateDigest := by
  intro slot active
  have hs := contractAt g.aggregateVerified slot (by simpa [g.aggregateCount] using active)
  simpa only [g.aggregateMessage] using hs

/-- The finite visited indexed-tree contract exposes only nonmembership and
    one exact insertion/skip. It is NOT a global injectivity assumption. The
    imported predecessor-link bounds, low/empty openings and hash semantics
    must justify this contract for each concrete visited path and tree. -/
def InsertionContractAt {BP AP Path Root : Type} (e : Environment BP AP Path Root)
    (encode : List Words8 → Root) (seen : List Words8) (active : Bool) (key : Words8) (path : Path) : Prop :=
  e.insertGates active key path (encode seen) →
    if active then key ∉ seen ∧ e.insertStep active key path (encode seen) = encode (key::seen)
    else e.insertStep active key path (encode seen) = encode seen

def ScopedInsertionContracts {BP AP Path Root : Type} (e : Environment BP AP Path Root)
    (encode : List Words8 → Root) :
    List Bool → List Words8 → List Path → List Words8 → Prop
  | [],[],[],_ => True
  | b::bs,k::ks,p::ps,seen => InsertionContractAt e encode seen b k p ∧
      ScopedInsertionContracts e encode bs ks ps (if b then k::seen else seen)
  | _,_,_,_ => False

def activeKeys : List Bool → List Words8 → List Words8
  | b::bs,k::ks => if b then k::activeKeys bs ks else activeKeys bs ks
  | _,_ => []

def FreshInsertions : List Bool → List Words8 → List Words8 → Prop
  | [],[],_ => True
  | b::bs,k::ks,seen => if b then k ∉ seen ∧ FreshInsertions bs ks (k::seen)
      else FreshInsertions bs ks seen
  | _,_,_ => False

def NoDuplicates : List Words8 → Prop
  | [] => True
  | k::ks => k ∉ ks ∧ NoDuplicates ks

theorem scoped_indexed_paths_prove_each_active_insertion_is_fresh
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (encode : List Words8 → Root)
    (flags : List Bool) (keys : List Words8) (paths : List Path) (seen : List Words8)
    (contracts : ScopedInsertionContracts e encode flags keys paths seen)
    (gates : InsertionGates e flags keys paths (encode seen)) : FreshInsertions flags keys seen := by
  induction flags generalizing keys paths seen with
  | nil => cases keys <;> cases paths <;> simp_all [ScopedInsertionContracts,FreshInsertions]
  | cons b bs ih =>
      cases keys with
      | nil => simp [ScopedInsertionContracts] at contracts
      | cons k ks =>
        cases paths with
        | nil => simp [ScopedInsertionContracts] at contracts
        | cons path ps =>
          have stepContract := contracts.1 gates.1
          cases b with
          | false =>
              have root : e.insertStep false k path (encode seen) = encode seen := stepContract
              have gt := gates.2
              rw [root] at gt
              exact ih ks ps seen contracts.2 gt
          | true =>
              have h : k ∉ seen ∧ e.insertStep true k path (encode seen) = encode (k::seen) := stepContract
              have gt := gates.2
              rw [h.2] at gt
              exact ⟨h.1,ih ks ps (k::seen) contracts.2 gt⟩

theorem fresh_insertions_give_distinct_active_keys
    (flags : List Bool) (keys seen : List Words8) (fresh : FreshInsertions flags keys seen) :
    NoDuplicates (activeKeys flags keys) ∧ (∀ key ∈ activeKeys flags keys, key ∉ seen) := by
  induction flags generalizing keys seen with
  | nil => cases keys <;> simp_all [FreshInsertions,activeKeys,NoDuplicates]
  | cons b bs ih =>
      cases keys with
      | nil => simp [FreshInsertions] at fresh
      | cons k ks =>
          cases b with
          | false => exact ih ks seen fresh
          | true =>
              have ht := ih ks (k::seen) fresh.2
              refine ⟨⟨?_,ht.1⟩,?_⟩
              · intro member
                have h := ht.2 k member
                exact h (by simp)
              · intro key member
                simp only [activeKeys,reduceIte,List.mem_cons] at member
                rcases member with same | tail
                · simpa only [same] using fresh.1
                · intro before
                  exact ht.2 key tail (by simp [before])

theorem close_distinctness_authenticates_the_same_aggregate_key_vector
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w)
    (encode : List Words8 → Root) (empty : e.emptyDistinctRoot = encode [])
    (contracts : ScopedInsertionContracts e encode w.privateData.memberActive w.aggregate.keys
      w.insertionPaths []) :
    NoDuplicates (activeKeys w.privateData.memberActive w.aggregate.keys) := by
  have gi := g.insertion
  rw [empty] at gi
  exact (fresh_insertions_give_distinct_active_keys _ _ _
    (scoped_indexed_paths_prove_each_active_insertion_is_fresh e encode _ _ _ [] contracts gi)).1

inductive Error where
  | witness
  | invalidMemberAuth
  | balanceBindingMismatch
  | failedToProve
  deriving DecidableEq, Repr

inductive Fault where
  | returned (error : Error)
  | shortBalancePublicInputsPanic
  | witnessAssignmentPanic
  deriving DecidableEq, Repr

structure NativeWitness (Close BP AP : Type) where
  close : Close
  balanceProof : BP
  memberAuth : List MemberAuth
  aggregateProof : AP

structure FilledWitness (BP AP Path : Type) where
  publicInputs : PublicInputs
  privateData : PrivateWitness
  balanceProof : BP
  aggregateProof : AP
  insertionPaths : List Path

def prefixFlags (width count : Nat) : List Bool :=
  (List.range width).map (fun i => decide (i < count))

/-- Calls into close_pis/CloseIntent, BalancePublicInputs and indexed-tree
    native helpers stay explicit. A successful native mirror is not the raw
    CircuitGates soundness premise: a caller can construct raw witness wires.
    SlotTreeRoot in stateData denotes the native recomputed BalanceState root.
    The helper does not assert it reconstructs slots inside THIS close circuit. -/
structure NativeEnvironment (Close BP AP Path : Type) where
  stateData : Close → PrivateWitness
  stateMemberCount : Close → Nat
  closeToPublicInputs : Close → Except String PublicInputs
  balancePublicWords : BP → List Nat
  parseBalance : List Nat → Except String BalanceStatement
  nativeMemberHash : List Nat → Words8
  setPublicAndPrivate : PublicInputs → PrivateWitness → Except Fault Unit
  setBalanceProof : BP → Except String Unit
  setAggregateProof : AP → Except String Unit
  insertionProofs : List MemberAuth → Nat → Except String (List Path)

def fillWitnessInner {Close BP AP Path : Type} (e : NativeEnvironment Close BP AP Path)
    (p : PublicInputs) (w : NativeWitness Close BP AP) (enforceFloor : Bool) :
    Except Fault (FilledWitness BP AP Path) :=
  let count := e.stateMemberCount w.close
  let floor := if enforceFloor then 2 else 1
  if !(floor ≤ count ∧ count ≤ maxMembers) then .error (.returned .invalidMemberAuth)
  else if w.memberAuth.length ≠ count then .error (.returned .invalidMemberAuth)
  else
    let state := e.stateData w.close
    let data := { state with
      memberActive := prefixFlags maxMembers count
      tokenActive := prefixFlags maxTokens state.tokenCount }
    match e.setPublicAndPrivate p data with
    | .error f => .error f
    | .ok _ => match e.setBalanceProof w.balanceProof with
      | .error _ => .error (.returned .failedToProve)
      | .ok _ => match e.setAggregateProof w.aggregateProof with
        | .error _ => .error (.returned .failedToProve)
        | .ok _ => match e.insertionProofs w.memberAuth count with
          | .error _ => .error (.returned .invalidMemberAuth)
          | .ok paths => .ok ⟨p,data,w.balanceProof,w.aggregateProof,paths⟩

def fillWitness {Close BP AP Path : Type} (e : NativeEnvironment Close BP AP Path)
    (p : PublicInputs) (w : NativeWitness Close BP AP) := fillWitnessInner e p w true

def prove {Close BP AP Path Proof : Type} (e : NativeEnvironment Close BP AP Path)
    (backend : FilledWitness BP AP Path → Except String Proof) (w : NativeWitness Close BP AP) :
    Except Fault Proof :=
  if w.memberAuth.length ≠ e.stateMemberCount w.close then .error (.returned .invalidMemberAuth)
  else match e.closeToPublicInputs w.close with
  | .error _ => .error (.returned .witness)
  | .ok base =>
      let p := { base with memberSet := e.nativeMemberHash (nativeMemberSetPreimage w.memberAuth) }
      let words := e.balancePublicWords w.balanceProof
      if words.length < balancePublicInputsLength then .error .shortBalancePublicInputsPanic
      else match e.parseBalance (words.take balancePublicInputsLength) with
      | .error _ => .error (.returned .balanceBindingMismatch)
      | .ok balance =>
          if balance.settledChain ≠ p.settledChain then .error (.returned .balanceBindingMismatch)
          else if balance.channelId ≠ p.channelId then .error (.returned .balanceBindingMismatch)
          else match fillWitness e p w with
          | .error error => .error error
          | .ok filled => match backend filled with
            | .error _ => .error (.returned .failedToProve)
            | .ok proof => .ok proof

theorem native_fill_keeps_supplied_public_inputs_not_an_authentication_assumption
    {Close BP AP Path : Type} (e : NativeEnvironment Close BP AP Path)
    (p : PublicInputs) (w : NativeWitness Close BP AP) (floor : Bool) (filled : FilledWitness BP AP Path)
    (accepted : fillWitnessInner e p w floor = .ok filled) :
    filled.publicInputs = p ∧ filled.balanceProof = w.balanceProof ∧
    filled.aggregateProof = w.aggregateProof := by
  cases floor <;> simp only [fillWitnessInner,Bool.false_eq_true,reduceIte] at accepted
  all_goals
    first | contradiction | skip
  all_goals
    repeat' first | split at accepted | contradiction
    have he := Except.ok.inj accepted
    cases he
    exact ⟨rfl,rfl,rfl⟩

theorem native_fill_auth_count_and_floor_checked_before_assignment
    {Close BP AP Path : Type} (e : NativeEnvironment Close BP AP Path)
    (p : PublicInputs) (w : NativeWitness Close BP AP) (filled : FilledWitness BP AP Path)
    (accepted : fillWitness e p w = .ok filled) :
    2 ≤ e.stateMemberCount w.close ∧ e.stateMemberCount w.close ≤ maxMembers ∧
    w.memberAuth.length = e.stateMemberCount w.close := by
  simp only [fillWitness,fillWitnessInner,reduceIte] at accepted
  split at accepted
  · contradiction
  next range =>
    split at accepted
    · contradiction
    next lengths =>
      have hr : 2 ≤ e.stateMemberCount w.close ∧ e.stateMemberCount w.close ≤ maxMembers := by
        simpa using range
      exact ⟨hr.1,hr.2,by simpa using lengths⟩

theorem inactive_suffix_adds_no_signers (n : Nat) (keys : List Words8) :
    activeKeys (List.replicate n false) keys = [] := by
  induction n generalizing keys with
  | zero => simp [activeKeys]
  | succ n ih => cases keys <;> simp [List.replicate_succ,activeKeys,ih]

theorem active_prefix_selects_exactly_the_first_keys (n padding : Nat) (keys : List Words8) :
    activeKeys (List.replicate n true ++ List.replicate padding false) keys = keys.take n := by
  induction n generalizing keys with
  | zero => simpa using inactive_suffix_adds_no_signers padding keys
  | succ n ih => cases keys <;> simp [List.replicate_succ,activeKeys,ih]

theorem close_active_keys_are_exactly_the_verified_signer_prefix
    {BP AP Path Root : Type} (e : Environment BP AP Path Root) (p : PublicInputs)
    (w : ProofWitness BP AP Path) (g : CircuitGates e p w) :
    activeKeys w.privateData.memberActive w.aggregate.keys = w.aggregate.keys.take p.memberCount := by
  rw [(prefix_gates_fix_every_flag g.members).2]
  exact active_prefix_selects_exactly_the_first_keys _ _ _

theorem selected_key_vector_preserves_width (flags : List Bool) (keys : List Words8)
    (lengths : flags.length = keys.length) : (selectedKeys flags keys).length = flags.length := by
  induction flags generalizing keys with
  | nil => simp [selectedKeys]
  | cons flag flags ih =>
      cases keys with
      | nil => simp at lengths
      | cons key keys =>
          simp only [List.length_cons,Nat.add_right_cancel_iff] at lengths
          simpa [selectedKeys] using ih keys lengths

theorem imcm_current_preimage_is_66_words (flags : List Bool) (keys : List Words8)
    (count : Nat) (hf : flags.length = maxMembers) (hk : keys.length = maxMembers) :
    (memberSetPreimage count flags keys).length = 66 := by
  have hl := selected_key_vector_preserves_width flags keys (hf.trans hk.symm)
  simp [memberSetPreimage,flattened_amounts_keep_all_eight_words,hl,hf,maxMembers]

theorem aggregate_current_layout_is_73_words (s : AggregateStatement)
    (width : s.keys.length = maxMembers) : s.words.length = aggregatePublicInputsLength := by
  simp [AggregateStatement.words,Words8.words,flattened_amounts_keep_all_eight_words,
    width,maxMembers,aggregatePublicInputsLength]

theorem native_prove_preserves_native_admission_and_balance_binding
    {Close BP AP Path Proof : Type} (e : NativeEnvironment Close BP AP Path)
    (backend : FilledWitness BP AP Path → Except String Proof) (w : NativeWitness Close BP AP)
    (proof : Proof) (accepted : prove e backend w = .ok proof) :
    ∃ base p balance filled,
      e.closeToPublicInputs w.close = .ok base ∧
      p = { base with memberSet := e.nativeMemberHash (nativeMemberSetPreimage w.memberAuth) } ∧
      e.parseBalance ((e.balancePublicWords w.balanceProof).take balancePublicInputsLength) = .ok balance ∧
      balance.channelId = p.channelId ∧ balance.settledChain = p.settledChain ∧
      fillWitness e p w = .ok filled ∧ backend filled = .ok proof := by
  unfold prove at accepted
  split at accepted
  · contradiction
  · split at accepted
    · contradiction
    next base hb =>
      dsimp only at accepted
      split at accepted
      · contradiction
      · split at accepted
        · contradiction
        next balance hbalance =>
          split at accepted
          · contradiction
          next chain =>
            split at accepted
            · contradiction
            next channel =>
              split at accepted
              · contradiction
              next filled hf =>
                split at accepted
                · contradiction
                next output hproof =>
                  have he := Except.ok.inj accepted
                  subst proof
                  exact ⟨base,_,balance,filled,hb,rfl,hbalance,
                    by simpa using channel,by simpa using chain,hf,hproof⟩

inductive BuildOp where
  | requireAggregateWidth73
  | standardRecursionZkConfig
  | checkedPublicField (name : String) (width : Nat)
  | checkedPrivateField (name : String) (width : Nat)
  | rawSlotRoot4
  | checkedTokenCount
  | checkedRegistry (slot : Nat)
  | checkedFundU256 (slot : Nat)
  | safeMemberBoolean (slot : Nat)
  | memberMonotone (earlier : Nat)
  | connectMemberSum
  | requireMemberFlag (slot : Nat)
  | safeTokenBoolean (slot : Nat)
  | tokenMonotone (earlier : Nat)
  | connectTokenSum
  | requireTokenFlag0
  | noDuplicateActiveToken (earlier later : Nat)
  | connectGenesisAmount
  | addFreezeU64OneFinalCarryZero
  | connectFreezeSuccessor
  | connectCloseNonceToFreeze
  | zeroSnapshot2
  | zeroBurnHash8
  | zeroUnallocated8
  | recomputeH1AndConnect
  | recomputeImchAndConnect
  | recomputeImclAndConnect
  | recomputeImcsAndConnect
  | recomputeTokenFundsAndConnect
  | allocateBalanceProofAndConstantKey
  | connectBalanceEmbeddedCyclicKey
  | verifyBalanceAtConstantKey
  | connectBalanceChannel
  | connectBalanceSettledChain
  | allocateAggregateProofAndConstantKey
  | verifyAggregateAtConstantKey
  | connectAggregateMessage
  | connectAggregateCount
  | sliceAggregateKey (slot : Nat)
  | selectImcmKeyWords (slot : Nat)
  | allocateCheckedInsertionPath4 (slot : Nat)
  | constantInsertionValueOne
  | constantEmptyDistinctRoot
  | conditionalIndexedInsert (slot : Nat)
  | computeMemberSetAndConnect
  | registerPublicInputs103
  | build
  deriving DecidableEq, Repr

def publicAllocationProgram : List BuildOp :=
  [.checkedPublicField "channelId" 1, .checkedPublicField "closeNonce" 2,
   .checkedPublicField "finalEpoch" 2, .checkedPublicField "finalSmallBlock" 2,
   .checkedPublicField "freezeNonce" 2, .checkedPublicField "stateDigest" 8,
   .checkedPublicField "h1" 8, .checkedPublicField "genesisFund" 8,
   .checkedPublicField "fundRoot" 8, .checkedPublicField "burnHash" 8,
   .checkedPublicField "withdrawalDigest" 8, .checkedPublicField "closeId" 8,
   .checkedPublicField "snapshot" 2, .checkedPublicField "stateVersion" 2,
   .checkedPublicField "settledChain" 8, .checkedPublicField "accumulatorRoot" 8,
   .checkedPublicField "memberSet" 8, .checkedPublicField "memberCount" 1,
   .checkedPublicField "delegateCount" 1, .checkedPublicField "tokenFundsDigest" 8]

def constructorProgram : List BuildOp :=
  [.requireAggregateWidth73,.standardRecursionZkConfig] ++ publicAllocationProgram ++
  [.checkedPrivateField "stateFreezeNonce" 2, .checkedPrivateField "sharedNullifierRoot" 8,
   .checkedPrivateField "unallocatedIncoming" 8, .checkedPrivateField "previousDigest" 8,
   .checkedPrivateField "h2" 8, .rawSlotRoot4,.checkedTokenCount] ++
  (List.range maxTokens).map BuildOp.checkedRegistry ++
  (List.range maxTokens).map BuildOp.checkedFundU256 ++
  (List.range maxMembers).map BuildOp.safeMemberBoolean ++
  (List.range (maxMembers-1)).map BuildOp.memberMonotone ++
  [.connectMemberSum,.requireMemberFlag 0,.requireMemberFlag 1] ++
  (List.range maxTokens).map BuildOp.safeTokenBoolean ++
  (List.range (maxTokens-1)).map BuildOp.tokenMonotone ++
  [.connectTokenSum,.requireTokenFlag0] ++
  (List.range maxTokens).bind (fun i =>
    ((List.range maxTokens).filter (fun j => decide (i<j))).map (BuildOp.noDuplicateActiveToken i)) ++
  [.connectGenesisAmount,.addFreezeU64OneFinalCarryZero,.connectFreezeSuccessor,
   .connectCloseNonceToFreeze,.zeroSnapshot2,.zeroBurnHash8,.zeroUnallocated8,
   .recomputeH1AndConnect,.recomputeImchAndConnect,.recomputeImclAndConnect,
   .recomputeImcsAndConnect,.recomputeTokenFundsAndConnect,
   .allocateBalanceProofAndConstantKey,.connectBalanceEmbeddedCyclicKey,.verifyBalanceAtConstantKey,
   .connectBalanceChannel,.connectBalanceSettledChain,
   .allocateAggregateProofAndConstantKey,.verifyAggregateAtConstantKey,
   .connectAggregateMessage,.connectAggregateCount] ++
  (List.range maxMembers).map BuildOp.sliceAggregateKey ++
  (List.range maxMembers).map BuildOp.selectImcmKeyWords ++
  (List.range maxMembers).map BuildOp.allocateCheckedInsertionPath4 ++
  [.constantInsertionValueOne,.constantEmptyDistinctRoot] ++
  (List.range maxMembers).map BuildOp.conditionalIndexedInsert ++
  [.computeMemberSetAndConnect,.registerPublicInputs103,.build]

def constructorArityAdmitted (aggregateWidth : Nat) : Bool := aggregateWidth == aggregatePublicInputsLength

inductive WriteOp where
  | checkNativeMemberFloor (enforceFloor : Bool)
  | checkAuthLength
  | setMemberFlag (slot : Nat)
  | setPublicField (name : String)
  | setPrivateField (name : String)
  | setNativeSlotTreeRoot
  | setTokenCount
  | setRegistry (slot : Nat)
  | setAmount (slot : Nat)
  | setTokenFlag (slot : Nat)
  | setBalanceProof
  | setAggregateProof
  | newNativeDistinctTree4
  | activeInsertValueOneElseDummy (slot : Nat)
  | setInsertionProof (slot : Nat)
  deriving DecidableEq, Repr

def publicWriteProgram : List WriteOp := publicAllocationProgram.map (fun op => match op with
  | .checkedPublicField name _ => .setPublicField name
  | _ => .setPublicField "unreachable")

def fillProgram (enforceFloor : Bool) : List WriteOp :=
  [.checkNativeMemberFloor enforceFloor,.checkAuthLength] ++
  (List.range maxMembers).map WriteOp.setMemberFlag ++ publicWriteProgram ++
  [.setPrivateField "stateFreezeNonce",.setPrivateField "sharedNullifierRoot",
   .setPrivateField "unallocatedIncoming",.setPrivateField "previousDigest",.setPrivateField "h2",
   .setNativeSlotTreeRoot,.setTokenCount] ++
  (List.range maxTokens).map WriteOp.setRegistry ++
  (List.range maxTokens).map WriteOp.setAmount ++
  (List.range maxTokens).map WriteOp.setTokenFlag ++
  [.setBalanceProof,.setAggregateProof,.newNativeDistinctTree4] ++
  (List.range maxMembers).bind (fun i => [.activeInsertValueOneElseDummy i,.setInsertionProof i])

theorem constructor_checks_actual_aggregate_width :
    constructorProgram.take 2 = [.requireAggregateWidth73,.standardRecursionZkConfig] := by decide

set_option maxRecDepth 4096 in
theorem constructor_checks_all_45_ordered_token_pairs :
    (constructorProgram.filter (fun op => match op with
      | .noDuplicateActiveToken _ _ => true | _ => false)).length = 45 := by decide

set_option maxRecDepth 4096 in
theorem constructor_inserts_all_eight_verified_key_slots_in_order :
    constructorProgram.filter (fun op => match op with
      | .conditionalIndexedInsert _ => true | _ => false) =
        (List.range 8).map BuildOp.conditionalIndexedInsert := by decide

theorem constructor_registers_only_after_member_set_binding :
    constructorProgram.reverse.take 3 = [.build,.registerPublicInputs103,.computeMemberSetAndConnect] := by decide

theorem normal_three_member_flags_are_satisfiable :
    PrefixGates 8 3 [true,true,true,false,false,false,false,false] ∧
    MemberFloor [true,true,true,false,false,false,false,false] := by
  refine ⟨⟨rfl,?_,rfl⟩,?_⟩ <;> simp [NoRise,MemberFloor,List.getD]

theorem normal_two_token_flags_are_satisfiable :
    PrefixGates 10 2 [true,true,false,false,false,false,false,false,false,false] ∧
    TokenFloor [true,true,false,false,false,false,false,false,false,false] := by
  refine ⟨⟨rfl,?_,rfl⟩,?_⟩ <;> simp [NoRise,TokenFloor,List.getD]

theorem normal_freeze_successor_can_cross_a_limb :
    FreezeSuccessorGates ⟨0,wordBase-1⟩ ⟨1,0⟩ := by
  refine ⟨1,?_,?_,?_,?_,?_,?_⟩ <;> simp [wordBase]

theorem normal_non_genesis_funds_are_not_forced_to_zero_by_the_codec :
    flattenAmounts [⟨0,0,0,0,0,0,0,77⟩,⟨0,0,0,0,0,0,0,25⟩] =
      [0,0,0,0,0,0,0,77,0,0,0,0,0,0,0,25] := rfl

end Zkp.Implementation.CloseCircuit
