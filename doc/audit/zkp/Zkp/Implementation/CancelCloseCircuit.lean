import Zkp.Implementation.CloseCircuit
import Zkp.Implementation.CancelClosePublicInputs

/-!
# Cancel-close implementation constraints and native producer

All default-production functions of cancel_close_circuit.rs are manually represented.
Optional fixture-feature functions are untranslated; cfg(test) code is separately
inventoried, not an executed test or proof. This is NOT compiler/Plonky2 refinement.
`CircuitGates` lists actual checks for an arbitrary raw witness; native filling is
separate and is not an authentication premise. Primitive field/U64/Poseidon/Keccak,
fixed recursive Falcon verifier and indexed-tree semantics remain explicit local
dependencies. Hash binding, where needed, is only at two concrete compared inputs.

The signed H1 contains one raw four-field slot root, full ten-token registry,
counts, chain, accumulator and revived version. The revived IMCH contains ALL ten
fund amounts and may contain nonzero unallocated incoming. Cancel does not open
slots, decrypt balances, verify a Balance proof, enforce token registry uniqueness,
zero padding, tokenCount bounds or member+delegate capacity. Do not inherit those
close/claim constraints. The eight member-prefix bits independently enforce2..8.
Actual key slots are taken from the fixed-VK aggregate proof, not member_auth.
The reused Environment's balance-verifier fields are unused in this module.

IMCS closes over channel/opaque closing IMCH/freeze nonce. The closing version is
a separate PI: it is NOT reconstructed from closing IMCH here. Manager must inject
its exact stored close digest/version/member set. Request generation and consumed
cancel-version floors are NOT circuit inputs; circuit satisfiability alone neither
authorizes the current Manager nor proves replay resistance across L1 histories.

Native scalar/field encodings, exact wire IDs, PartialWitness assignment failures
(unwrap panic), helper-generated slot roots, native tree proofs and allocation
remain compiler/library boundaries. Source typed native objects are represented
by exact read projections plus opaque remainder identity in the native PI module.
-/
namespace Zkp.Implementation.CancelCloseCircuit

open Zkp.Implementation.CloseCircuit (Words2 Words8 Hash4 CheckedWords PrefixGates MemberFloor
  FreezeSuccessorGates AggregateStatement MemberAuth)
abbrev NativeInputs := Zkp.Implementation.CancelClosePublicInputs.PublicInputs
abbrev NativeCancel := Zkp.Implementation.CancelClosePublicInputs.Witness
abbrev NativePiEnvironment := Zkp.Implementation.CancelClosePublicInputs.NativeEnvironment
def maxMembers : Nat := 8
def maxTokens : Nat := 10
def publicInputLength : Nat := 29
def aggregateInputLength : Nat := 73
def distinctnessHeight : Nat := 4

structure PublicInputs where
  channelId : Nat
  closeId : Words8
  memberSet : Words8
  closeVersion : Words2
  revivedVersion : Words2
  revivedDigest : Words8
  deriving DecidableEq, Repr

def PublicInputs.words (p : PublicInputs) : List Nat :=
  [p.channelId] ++ p.closeId.words ++ p.memberSet.words ++ p.closeVersion.words ++
    p.revivedVersion.words ++ p.revivedDigest.words
def PublicInputs.AllocationChecks (p : PublicInputs) : Prop := CheckedWords p.words
def nativeTargets (p : NativeInputs) : PublicInputs :=
  ⟨p.channelId,p.closeId,p.memberSet,Words2.fromNat p.closeVersion,
    Words2.fromNat p.revivedVersion,p.revivedDigest⟩

structure Constructor where
  aggregateVerifier : List Nat
  zeroKnowledge : Bool
  publicCount : Nat
  memberWidth : Nat
  tokenWidth : Nat
  insertionHeight : Nat
  deriving DecidableEq, Repr

inductive Fault where
  | constructorArityPanic | assignmentPanic | boundsPanic
  | invalidMemberAuth | witness | failedToProve
  deriving DecidableEq, Repr
abbrev Result := Except Fault

def newCircuit (arity : Nat) (verifier : List Nat) : Result Constructor :=
  if arity != aggregateInputLength then .error .constructorArityPanic
  else .ok ⟨verifier,true,publicInputLength,maxMembers,maxTokens,distinctnessHeight⟩

structure PrivateWitness where
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : List Nat
  epoch : Words2
  smallBlock : Words2
  nonce : Words2
  amounts : List Words8
  fundRoot : Words8
  sharedNullifierRoot : Words8
  unallocated : Words8
  previousDigest : Words8
  h2 : Words8
  settledChain : Words8
  accumulatorRoot : Words8
  slotRoot : Hash4
  closeNonce : Words2
  closeStateDigest : Words8
  memberActive : List Bool
  deriving DecidableEq, Repr

def PrivateWitness.Shape (w : PrivateWitness) : Prop :=
  w.registry.length = maxTokens ∧ w.amounts.length = maxTokens ∧ w.memberActive.length = maxMembers

def PrivateWitness.Checked (w : PrivateWitness) : Prop :=
  CheckedWords ([w.memberCount,w.delegateCount,w.tokenCount] ++ w.registry ++ w.epoch.words ++
    w.smallBlock.words ++ w.nonce.words ++ Zkp.Implementation.CloseCircuit.flattenAmounts w.amounts ++
    w.fundRoot.words ++ w.sharedNullifierRoot.words ++ w.unallocated.words ++ w.previousDigest.words ++
    w.h2.words ++ w.settledChain.words ++ w.accumulatorRoot.words ++ w.closeNonce.words ++ w.closeStateDigest.words)

def h1Preimage (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [0x494d4232,p.channelId,w.memberCount,w.delegateCount,w.tokenCount] ++ w.registry ++
  w.slotRoot.words ++ w.settledChain.words ++ w.accumulatorRoot.words ++ p.revivedVersion.words

def imchPrefix (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [0x494d4348,p.channelId] ++ w.epoch.words ++ w.smallBlock.words ++ w.nonce.words ++ [p.channelId]
def imchSuffix (p : PublicInputs) (w : PrivateWitness) (h1 : Words8) : List Nat :=
  w.fundRoot.words ++ h1.words ++ w.sharedNullifierRoot.words ++ w.unallocated.words ++
    w.previousDigest.words ++ w.h2.words ++ p.revivedVersion.words
def imchPreimage (p : PublicInputs) (w : PrivateWitness) (h1 : Words8) : List Nat :=
  imchPrefix p w ++ Zkp.Implementation.CloseCircuit.flattenAmounts w.amounts ++ imchSuffix p w h1
def imcsPreimage (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [0x494d4353,p.channelId] ++ w.closeStateDigest.words ++ w.closeNonce.words

abbrev Environment (AP Path Root : Type) := Zkp.Implementation.CloseCircuit.Environment Unit AP Path Root

structure ProofWitness (AP Path : Type) where
  privateData : PrivateWitness
  aggregateProof : AP
  aggregate : AggregateStatement
  insertionPaths : List Path

/-- Each member/distinctness/hash condition below corresponds to source connects,
    assertions or imported primitive calls; none asserts total asset safety. -/
structure CircuitGates {AP Path Root : Type} (e : Environment AP Path Root)
    (p : PublicInputs) (w : ProofWitness AP Path) : Prop where
  publicRanges : p.AllocationChecks
  privateRanges : w.privateData.Checked
  shape : w.privateData.Shape
  members : PrefixGates maxMembers w.privateData.memberCount w.privateData.memberActive
  memberFloor : MemberFloor w.privateData.memberActive
  imch : e.keccak (imchPreimage p w.privateData (e.h1Hash (h1Preimage p w.privateData))) = p.revivedDigest
  imcs : e.keccak (imcsPreimage p w.privateData) = p.closeId
  newer : p.closeVersion.value < p.revivedVersion.value
  successor : FreezeSuccessorGates w.privateData.nonce w.privateData.closeNonce
  aggregateVerified : e.verifyAggregate e.aggregateVerifier w.aggregateProof w.aggregate
  aggregateWidth : w.aggregate.keys.length = maxMembers
  aggregateMessage : w.aggregate.message = p.revivedDigest
  aggregateCount : w.aggregate.signerCount = w.privateData.memberCount
  insertion : Zkp.Implementation.CloseCircuit.InsertionGates e w.privateData.memberActive
    w.aggregate.keys w.insertionPaths e.emptyDistinctRoot
  memberSet : e.keccak (Zkp.Implementation.CloseCircuit.memberSetPreimage
    w.privateData.memberCount w.privateData.memberActive w.aggregate.keys) = p.memberSet

def FieldAndGadgetLowering {AP Path Root : Type} (e : Environment AP Path Root)
    (raw : PublicInputs → ProofWitness AP Path → Prop) : Prop :=
  ∀ p w, raw p w → CircuitGates e p w

/-- Constructor-pinned aggregate key, not mere public-input-count compatibility. -/
def ConstructorBinding {AP Path Root : Type} (c : Constructor) (e : Environment AP Path Root) : Prop :=
  e.aggregateVerifier = c.aggregateVerifier

/-- Total native helper includes the u8 length cast BEFORE masking inactive slots. -/
def nativeMemberSetPreimage (auth : List MemberAuth) : List Nat :=
  let count := auth.length % 256
  let selected := (List.range maxMembers).map fun i =>
    if i < count then (auth.getD i ⟨Words8.zero⟩).pk else Words8.zero
  [0x494d434d,count] ++ Zkp.Implementation.CloseCircuit.flattenAmounts selected

def memberSetForAuth (hash : List Nat → Words8) (auth : List MemberAuth) : Words8 :=
  hash (nativeMemberSetPreimage auth)

structure Assignment where
  target : String
  index : Nat
  words : List Nat
  deriving DecidableEq, Repr

def setPublicPlan (p : NativeInputs) : List Assignment :=
  [⟨"channel_id",0,[p.channelId]⟩,⟨"close_intent_digest",0,p.closeId.words⟩,
   ⟨"member_set_commitment",0,p.memberSet.words⟩,
   ⟨"close_final_state_version",0,(Words2.fromNat p.closeVersion).words⟩,
   ⟨"revived_state_version",0,(Words2.fromNat p.revivedVersion).words⟩,
   ⟨"revived_channel_state_digest",0,p.revivedDigest.words⟩]

def assignmentPlan (p : NativeInputs) (w : PrivateWitness) : List Assignment :=
  ((List.range maxMembers).map fun i => ⟨"active_bits",i,[if i < w.memberCount then 1 else 0]⟩) ++
  setPublicPlan p ++
  [⟨"revived_member_count",0,[w.memberCount]⟩,⟨"revived_delegate_count",0,[w.delegateCount]⟩,
   ⟨"revived_epoch",0,w.epoch.words⟩,⟨"revived_small_block_number",0,w.smallBlock.words⟩,
   ⟨"revived_close_freeze_nonce",0,w.nonce.words⟩,⟨"revived_token_count",0,[w.tokenCount]⟩] ++
  (w.registry.enum.map fun (i,v) => ⟨"revived_token_registry",i,[v]⟩) ++
  (w.amounts.enum.map fun (i,v) => ⟨"revived_channel_fund_amounts",i,v.words⟩) ++
  [⟨"revived_channel_fund_intmax_state_root",0,w.fundRoot.words⟩,
   ⟨"revived_shared_native_nullifier_root",0,w.sharedNullifierRoot.words⟩,
   ⟨"revived_unallocated_confirmed_incoming",0,w.unallocated.words⟩,
   ⟨"revived_prev_digest",0,w.previousDigest.words⟩,⟨"revived_h2_tag",0,w.h2.words⟩,
   ⟨"revived_settled_tx_chain",0,w.settledChain.words⟩,
   ⟨"revived_settled_tx_accumulator_root",0,w.accumulatorRoot.words⟩,
   ⟨"revived_slot_tree_root",0,w.slotRoot.words⟩,
   ⟨"close_freeze_nonce",0,w.closeNonce.words⟩,
   ⟨"close_final_channel_state_digest",0,w.closeStateDigest.words⟩]

structure NativeWitness (AP : Type) where
  cancel : NativeCancel
  memberAuth : List MemberAuth
  aggregateProof : AP

structure NativeEnvironment (AP Path Tree : Type) where
  pi : NativePiEnvironment
  stateData : NativeCancel → PrivateWitness
  setAssignments : List Assignment → Result Unit
  setAggregateProof : AP → Except String Unit
  newTree : Nat → Tree
  insert : Tree → Words8 → Nat → Except String (Tree × Path)
  dummy : Tree → Path
  setInsertion : Nat → Path → Result Unit

def buildInsertions {AP Path Tree : Type} (e : NativeEnvironment AP Path Tree)
    (auth : List MemberAuth) (count : Nat) : Nat → Nat → Tree → Result (List Path)
  | 0,_,_ => .ok []
  | fuel+1,slot,tree => do
      let (next,path) ← if slot < count then
          match auth[slot]? with
          | none => .error .boundsPanic
          | some member => match e.insert tree member.pk 1 with
            | .error _ => .error .invalidMemberAuth
            | .ok pair => .ok pair
        else .ok (tree,e.dummy tree)
      let _ ← e.setInsertion slot path
      let rest ← buildInsertions e auth count fuel (slot+1) next
      return path::rest

structure FilledWitness (AP Path : Type) where
  publicInputs : NativeInputs
  privateData : PrivateWitness
  aggregateProof : AP
  insertionPaths : List Path

def fillWitnessInner {AP Path Tree : Type} (e : NativeEnvironment AP Path Tree)
    (p : NativeInputs) (w : NativeWitness AP) (enforceFloor : Bool) : Result (FilledWitness AP Path) := do
  let state := e.stateData w.cancel
  let count := state.memberCount
  let floor := if enforceFloor then 2 else 1
  if !(floor ≤ count ∧ count ≤ maxMembers) then throw .invalidMemberAuth
  if w.memberAuth.length != count then throw .invalidMemberAuth
  let data := {state with
    nonce := Words2.fromNat w.cancel.revived.freezeNonce,
    closeNonce := Words2.fromNat w.cancel.close.freezeNonce, closeStateDigest := w.cancel.close.stateDigest,
    memberActive := Zkp.Implementation.CloseCircuit.prefixFlags maxMembers count}
  let _ ← e.setAssignments (assignmentPlan p data)
  let _ ← match e.setAggregateProof w.aggregateProof with
    | .error _ => .error .failedToProve
    | .ok x => .ok x
  let paths ← buildInsertions e w.memberAuth count maxMembers 0 (e.newTree distinctnessHeight)
  return ⟨p,data,w.aggregateProof,paths⟩

def fillWitness {AP Path Tree : Type} (e : NativeEnvironment AP Path Tree)
    (p : NativeInputs) (w : NativeWitness AP) : Result (FilledWitness AP Path) := fillWitnessInner e p w true

def prove {AP Path Tree Proof : Type} (e : NativeEnvironment AP Path Tree)
    (backend : FilledWitness AP Path → Except String Proof) (w : NativeWitness AP) : Result Proof := do
  if w.memberAuth.length != (e.stateData w.cancel).memberCount then throw .invalidMemberAuth
  let base ← match Zkp.Implementation.CancelClosePublicInputs.toPublicInputs e.pi w.cancel with
    | .error _ => .error .witness
    | .ok p => .ok p
  let p := {base with memberSet := memberSetForAuth e.pi.hashWords w.memberAuth}
  let filled ← fillWitness e p w
  match backend filled with
    | .error _ => .error .failedToProve
    | .ok proof => .ok proof

theorem target_word_count (p : PublicInputs) : p.words.length = publicInputLength := by
  simp [PublicInputs.words,Words2.words,Words8.words,publicInputLength]

theorem native_target_order_matches (p : NativeInputs) :
    (nativeTargets p).words = Zkp.Implementation.CancelClosePublicInputs.toU64Vec p := by rfl

/-- Mathematical inverse used to prove field binding, not an extra Rust parser. -/
def readTargetFields (xs : List Nat) : PublicInputs :=
  ⟨xs.getD 0 0,Words8.read xs 1,Words8.read xs 9,Words2.read xs 17,
    Words2.read xs 19,Words8.read xs 21⟩

theorem target_fields_round_trip (p : PublicInputs) : readTargetFields p.words = p := by
  simp only [PublicInputs.words,Words2.words,Words8.words,List.append_assoc,
    List.singleton_append,List.cons_append,List.nil_append]
  unfold readTargetFields Words2.read Words8.read
  cases p
  rfl

theorem public_encoding_is_injective (a b : PublicInputs) (same : a.words = b.words) : a = b := by
  have h := congrArg readTargetFields same
  simpa only [target_fields_round_trip] using h

theorem constructor_pins_exact_key (arity : Nat) (vk : List Nat) (c : Constructor)
    (h : newCircuit arity vk = .ok c) :
    arity = 73 ∧ c.aggregateVerifier = vk ∧ c.zeroKnowledge = true ∧ c.publicCount = 29 := by
  unfold newCircuit at h
  split at h <;> simp_all [aggregateInputLength,publicInputLength]
  cases h
  exact ⟨rfl,rfl,rfl⟩

theorem h1_uses_current_37_elements (p : PublicInputs) (w : PrivateWitness)
    (shape : w.registry.length = 10) : (h1Preimage p w).length = 37 := by
  simp [h1Preimage,Hash4.words,Words8.words,Words2.words,shape]

theorem imch_uses_all_139_words (p : PublicInputs) (w : PrivateWitness) (h1 : Words8)
    (shape : w.amounts.length = 10) : (imchPreimage p w h1).length = 139 := by
  simp [imchPreimage,imchPrefix,imchSuffix,Words2.words,Words8.words,
    Zkp.Implementation.CloseCircuit.flattened_amounts_keep_all_eight_words,shape]

theorem imcs_has_exact_12_words (p : PublicInputs) (w : PrivateWitness) :
    (imcsPreimage p w).length = 12 := by simp [imcsPreimage,Words8.words,Words2.words]

theorem cancel_requires_two_through_eight_members {AP Path Root : Type} (e : Environment AP Path Root)
    (p : PublicInputs) (w : ProofWitness AP Path) (g : CircuitGates e p w) :
    2 ≤ w.privateData.memberCount ∧ w.privateData.memberCount ≤ 8 := by
  have floor := Zkp.Implementation.CloseCircuit.member_floor_requires_two_active_flags _ g.memberFloor
  rw [g.members.sum] at floor
  exact ⟨floor,(Zkp.Implementation.CloseCircuit.prefix_gates_fix_every_flag g.members).1⟩

theorem cancel_has_strict_version_and_exact_era {AP Path Root : Type} (e : Environment AP Path Root)
    (p : PublicInputs) (w : ProofWitness AP Path) (g : CircuitGates e p w) :
    p.closeVersion.value < p.revivedVersion.value ∧
    w.privateData.closeNonce.value = w.privateData.nonce.value + 1 ∧
    w.privateData.closeNonce.value < 2^64 := by
  exact ⟨g.newer,Zkp.Implementation.CloseCircuit.freeze_limb_equations_prove_exact_successor _ _ g.successor⟩

theorem every_active_member_signed_revived_imch {AP Path Root : Type} (e : Environment AP Path Root)
    (signed : Words8 → Words8 → Prop) (p : PublicInputs) (w : ProofWitness AP Path)
    (g : CircuitGates e p w)
    (contractAt : Zkp.Implementation.CloseCircuit.AggregateContractAt e signed w.aggregateProof w.aggregate) :
    ∀ slot, slot < w.privateData.memberCount →
      signed (w.aggregate.keys.getD slot Words8.zero)
        (e.keccak (imchPreimage p w.privateData (e.h1Hash (h1Preimage p w.privateData)))) := by
  intro slot active
  have h := contractAt g.aggregateVerified slot (by simpa [g.aggregateCount] using active)
  simpa [g.aggregateMessage,g.imch] using h

theorem active_keys_are_distinct_under_visited_path_contracts {AP Path Root : Type}
    (e : Environment AP Path Root) (p : PublicInputs) (w : ProofWitness AP Path)
    (g : CircuitGates e p w) (encode : List Words8 → Root) (empty : e.emptyDistinctRoot = encode [])
    (contracts : Zkp.Implementation.CloseCircuit.ScopedInsertionContracts e encode
      w.privateData.memberActive w.aggregate.keys w.insertionPaths []) :
    Zkp.Implementation.CloseCircuit.NoDuplicates
      (Zkp.Implementation.CloseCircuit.activeKeys w.privateData.memberActive w.aggregate.keys) := by
  have gates := g.insertion
  rw [empty] at gates
  exact (Zkp.Implementation.CloseCircuit.fresh_insertions_give_distinct_active_keys _ _ _
    (Zkp.Implementation.CloseCircuit.scoped_indexed_paths_prove_each_active_insertion_is_fresh
      e encode _ _ _ [] contracts gates)).1

theorem member_commitment_uses_same_verified_keys {AP Path Root : Type} (e : Environment AP Path Root)
    (p : PublicInputs) (w : ProofWitness AP Path) (g : CircuitGates e p w) :
    e.verifyAggregate e.aggregateVerifier w.aggregateProof w.aggregate ∧
    w.aggregate.signerCount = w.privateData.memberCount ∧
    e.keccak (Zkp.Implementation.CloseCircuit.memberSetPreimage
      w.privateData.memberCount w.privateData.memberActive w.aggregate.keys) = p.memberSet :=
  ⟨g.aggregateVerified,g.aggregateCount,g.memberSet⟩

structure PendingBinding where
  channelId : Nat
  closeId : Words8
  registeredMembers : Words8
  finalVersion : Words2

def MatchesPending (p : PublicInputs) (pending : PendingBinding) : Prop :=
  p.channelId = pending.channelId ∧ p.closeId = pending.closeId ∧
  p.memberSet = pending.registeredMembers ∧ p.closeVersion = pending.finalVersion

theorem cancel_orders_the_exact_injected_pending_version {AP Path Root : Type}
    (e : Environment AP Path Root) (p : PublicInputs) (w : ProofWitness AP Path)
    (g : CircuitGates e p w) (pending : PendingBinding) (bound : MatchesPending p pending) :
    pending.finalVersion.value < p.revivedVersion.value ∧
    e.keccak (imcsPreimage p w.privateData) = pending.closeId := by
  exact ⟨by simpa [bound.2.2.2] using g.newer,g.imcs.trans bound.2.1⟩

theorem close_version_is_not_rehashed_inside_imcs (p : PublicInputs) (w : PrivateWitness) (version : Words2) :
    imcsPreimage {p with closeVersion := version} w = imcsPreimage p w := rfl

theorem native_public_assignment_order (p : NativeInputs) :
    (setPublicPlan p).map Assignment.words =
      [[p.channelId],p.closeId.words,p.memberSet.words,(Words2.fromNat p.closeVersion).words,
       (Words2.fromNat p.revivedVersion).words,p.revivedDigest.words] := rfl

theorem native_insertions_have_exact_width {AP Path Tree : Type} (e : NativeEnvironment AP Path Tree)
    (auth : List MemberAuth) (count fuel slot : Nat) (tree : Tree) (paths : List Path)
    (h : buildInsertions e auth count fuel slot tree = .ok paths) : paths.length = fuel := by
  induction fuel generalizing slot tree paths with
  | zero => simp [buildInsertions] at h; subst paths; rfl
  | succ n ih =>
    simp only [buildInsertions,Bind.bind,Except.bind,Pure.pure,Except.pure] at h
    split at h
    · split at h <;> try contradiction
      split at h <;> try contradiction
      split at h <;> try contradiction
      split at h <;> try contradiction
      cases h
      simp only [List.length_cons]
      congr 1
      exact ih _ _ _ (by assumption)
    · split at h <;> try contradiction
      split at h <;> try contradiction
      cases h
      simp only [List.length_cons]
      congr 1
      exact ih _ _ _ (by assumption)

theorem native_fill_preserves_supplied_pis {AP Path Tree : Type} (e : NativeEnvironment AP Path Tree)
    (p : NativeInputs) (w : NativeWitness AP) (floor : Bool) (out : FilledWitness AP Path)
    (h : fillWitnessInner e p w floor = .ok out) : out.publicInputs = p ∧ out.aggregateProof = w.aggregateProof := by
  cases floor <;> simp only [fillWitnessInner,Bool.false_eq_true,↓reduceIte,
    Bind.bind,Except.bind,Pure.pure,Except.pure] at h
  all_goals
    split at h <;> try contradiction
    split at h <;> try contradiction
    split at h <;> try contradiction
    split at h <;> try contradiction
    split at h <;> try contradiction
    cases h
    exact ⟨rfl,rfl⟩

theorem native_fill_checks_count_and_auth {AP Path Tree : Type} (e : NativeEnvironment AP Path Tree)
    (p : NativeInputs) (w : NativeWitness AP) (out : FilledWitness AP Path)
    (h : fillWitness e p w = .ok out) :
    2 ≤ (e.stateData w.cancel).memberCount ∧ (e.stateData w.cancel).memberCount ≤ 8 ∧
    w.memberAuth.length = (e.stateData w.cancel).memberCount := by
  simp only [fillWitness,fillWitnessInner,Bind.bind,Except.bind,Pure.pure,Except.pure] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  simp_all [maxMembers]

theorem imch_preimage_exposes_full_vector (p q : PublicInputs) (a b : PrivateWitness)
    (ha hb : Words8) (lengths : a.amounts.length = b.amounts.length)
    (same : imchPreimage p a ha = imchPreimage q b hb) : a.amounts = b.amounts ∧ ha = hb := by
  have he : imchPrefix p a ++ (Zkp.Implementation.CloseCircuit.flattenAmounts a.amounts ++ imchSuffix p a ha) =
      imchPrefix q b ++ (Zkp.Implementation.CloseCircuit.flattenAmounts b.amounts ++ imchSuffix q b hb) := by
    simpa only [imchPreimage,List.append_assoc] using same
  have hp := List.append_inj_right he (by simp [imchPrefix,Words2.words])
  have hv := List.append_inj hp (by simp [Zkp.Implementation.CloseCircuit.flattened_amounts_keep_all_eight_words,lengths])
  have hs : a.fundRoot.words ++ (ha.words ++
      (a.sharedNullifierRoot.words ++ a.unallocated.words ++ a.previousDigest.words ++ a.h2.words ++ p.revivedVersion.words)) =
      b.fundRoot.words ++ (hb.words ++
      (b.sharedNullifierRoot.words ++ b.unallocated.words ++ b.previousDigest.words ++ b.h2.words ++ q.revivedVersion.words)) := by
    simpa only [imchSuffix,List.append_assoc] using hv.2
  have hh := List.append_inj_right hs (by simp [Words8.words])
  exact ⟨Zkp.Implementation.CloseCircuit.flattened_vectors_are_injective hv.1,
    Zkp.Implementation.CloseCircuit.words8_encoding_is_injective
      (List.append_inj_left hh (by simp [Words8.words]))⟩

def h1Prefix (p : PublicInputs) (w : PrivateWitness) : List Nat :=
  [0x494d4232,p.channelId,w.memberCount,w.delegateCount,w.tokenCount]

theorem h1_preimage_binds_registry_and_count (p q : PublicInputs) (a b : PrivateWitness)
    (lengths : a.registry.length = b.registry.length)
    (same : h1Preimage p a = h1Preimage q b) : a.registry = b.registry ∧ a.tokenCount = b.tokenCount := by
  have he : h1Prefix p a ++ (a.registry ++ (a.slotRoot.words ++ a.settledChain.words ++ a.accumulatorRoot.words ++ p.revivedVersion.words)) =
      h1Prefix q b ++ (b.registry ++ (b.slotRoot.words ++ b.settledChain.words ++ b.accumulatorRoot.words ++ q.revivedVersion.words)) := by
    simpa only [h1Preimage,h1Prefix,List.append_assoc] using same
  have hp := List.append_inj he (by simp [h1Prefix])
  have hc : a.tokenCount = b.tokenCount := by
    have h := hp.1
    simp only [h1Prefix,List.cons.injEq] at h
    exact h.2.2.2.2.1
  exact ⟨List.append_inj_left hp.2 lengths,hc⟩

/-- Two concrete hash-binding obligations, not global injectivity or a funds-safety premise. -/
theorem one_revived_digest_binds_full_token_vector {AP Path Root : Type} (e : Environment AP Path Root)
    (p q : PublicInputs) (a b : ProofWitness AP Path) (ga : CircuitGates e p a) (gb : CircuitGates e q b)
    (sameSignedDigest : p.revivedDigest = q.revivedDigest)
    (imchBinding : Zkp.Implementation.CloseCircuit.HashBindingAt e.keccak
      (imchPreimage p a.privateData (e.h1Hash (h1Preimage p a.privateData)))
      (imchPreimage q b.privateData (e.h1Hash (h1Preimage q b.privateData))))
    (h1Binding : Zkp.Implementation.CloseCircuit.HashBindingAt e.h1Hash
      (h1Preimage p a.privateData) (h1Preimage q b.privateData)) :
    a.privateData.registry = b.privateData.registry ∧ a.privateData.tokenCount = b.privateData.tokenCount ∧
    a.privateData.amounts = b.privateData.amounts := by
  have he := imchBinding (ga.imch.trans (sameSignedDigest.trans gb.imch.symm))
  have hm := imch_preimage_exposes_full_vector p q a.privateData b.privateData _ _
    (ga.shape.2.1.trans gb.shape.2.1.symm) he
  have hh := h1_preimage_binds_registry_and_count p q a.privateData b.privateData
    (ga.shape.1.trans gb.shape.1.symm) (h1Binding hm.2)
  exact ⟨hh.1,hh.2,hm.1⟩

theorem successful_producer_trace {AP Path Tree Proof : Type} (e : NativeEnvironment AP Path Tree)
    (backend : FilledWitness AP Path → Except String Proof) (w : NativeWitness AP) (out : Proof)
    (h : prove e backend w = .ok out) :
    ∃ base filled, Zkp.Implementation.CancelClosePublicInputs.toPublicInputs e.pi w.cancel = .ok base ∧
      fillWitness e {base with memberSet := memberSetForAuth e.pi.hashWords w.memberAuth} w = .ok filled ∧
      filled.publicInputs = {base with memberSet := memberSetForAuth e.pi.hashWords w.memberAuth} ∧
      backend filled = .ok out := by
  simp only [prove,Bind.bind,Except.bind,Pure.pure,Except.pure] at h
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  split at h <;> try contradiction
  cases h
  refine ⟨_,_,by assumption,by assumption,?_,by assumption⟩
  exact (native_fill_preserves_supplied_pis e _ w true _ (by assumption)).1

/-- Availability conditional on exact successful native operations, not circuit soundness. -/
theorem producer_returns_when_all_operations_succeed {AP Path Tree Proof : Type}
    (e : NativeEnvironment AP Path Tree) (backend : FilledWitness AP Path → Except String Proof)
    (w : NativeWitness AP) (base : NativeInputs) (filled : FilledWitness AP Path) (proof : Proof)
    (count : w.memberAuth.length = (e.stateData w.cancel).memberCount)
    (pi : Zkp.Implementation.CancelClosePublicInputs.toPublicInputs e.pi w.cancel = .ok base)
    (fill : fillWitness e {base with memberSet := memberSetForAuth e.pi.hashWords w.memberAuth} w = .ok filled)
    (finish : backend filled = .ok proof) : prove e backend w = .ok proof := by
  simp [prove,count,pi,fill,finish,Bind.bind,Except.bind,Pure.pure,Except.pure]

def normalPrivate : PrivateWitness :=
  ⟨2,0,1,List.replicate 10 0,⟨0,8⟩,⟨0,4⟩,⟨0,0⟩,List.replicate 10 Words8.zero,
    Words8.zero,Words8.zero,Words8.zero,Words8.zero,Words8.zero,Words8.zero,Words8.zero,
    ⟨0,0,0,0⟩,⟨0,1⟩,Words8.zero,[]⟩

def normalNative : NativeWitness Unit :=
  ⟨⟨⟨3,Words8.zero,9,0,[]⟩,⟨3,7,1,Words8.zero,[]⟩⟩,
    [⟨⟨1,0,0,0,0,0,0,0⟩⟩,⟨⟨2,0,0,0,0,0,0,0⟩⟩],()⟩

/-- Explicit operation-success fixture only; hashes and proof backend here are NOT cryptography. -/
def normalEnvironment : NativeEnvironment Unit Nat Nat :=
  ⟨⟨fun _ => Words8.zero,fun _ => Words8.zero⟩,fun _ => normalPrivate,
    fun _ => .ok (),fun _ => .ok (),fun _ => 0,
    fun tree _ _ => .ok (tree+1,tree),fun tree => tree,fun _ _ => .ok ()⟩

theorem normal_native_producer_finishes :
    prove normalEnvironment (fun _ => .ok (17 : Nat)) normalNative = .ok 17 := by rfl

end Zkp.Implementation.CancelCloseCircuit
