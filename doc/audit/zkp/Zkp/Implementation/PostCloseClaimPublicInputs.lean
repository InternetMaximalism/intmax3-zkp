import Zkp.Implementation.ClosePublicInputs

/-!
# Post-close incoming-claim native projection and 57-word codec

Handwritten semantics of all production functions in post_close_claim_pis.rs.
This is not Rust/compiler refinement or proof verification. Native representation
widths are distinguished from checks performed by this helper. In particular the
native helper copies the supplied nullifier, searches ANY receiver delta, and does
not verify accumulator membership, final-state channel equality, global finality,
latest-head selection, registry membership, remaining funds or replay state.
The circuit is a separate relation; its stricter checks must not be attributed to
this host helper. Delegates are in the active region, not required to be cosigners.

Array lookup panic and dependency panic are separate from the typed Rust errors.
The ordinary source arrays have 1024 entries; no invented active<=1024 host guard
is added. Cryptographic calls receive their complete represented arguments, with
otherwise unused source payloads retained. Their implementations are boundaries.
The amount decoder performs wrapping u64 shift/raw OR without u32 range checks;
hash/address/channel/token words are checked. Zero ChannelId decode is rejected.
Tests and feature fixtures are inventory only, never production proof coverage.
-/
namespace Zkp.Implementation.PostCloseClaimPublicInputs

open Zkp.Implementation.ClosePublicInputs (Words2 Words8 Ten limbBase scalarLimit
  canonicalDigest canonicalScalar)

/-- Local source-helper declarations reusing the already proved identical
    scalar semantics, so source-map ownership stays within this module. -/
abbrev splitU64 (value : Nat) : Words2 := Zkp.Implementation.ClosePublicInputs.splitU64 value
abbrev joinValue (hi lo : Nat) : Nat := Zkp.Implementation.ClosePublicInputs.joinValue hi lo
abbrev normalizeScalar (value : Words2) : Words2 :=
  Zkp.Implementation.ClosePublicInputs.normalizeScalar value

theorem split_then_join_u64 (value : Nat) (bound : value < scalarLimit) :
    joinValue (splitU64 value).hi (splitU64 value).lo = value :=
  Zkp.Implementation.ClosePublicInputs.split_then_join_u64 value bound
theorem normalized_canonical_scalar (value : Words2) (bound : canonicalScalar value) :
    normalizeScalar value = value :=
  Zkp.Implementation.ClosePublicInputs.normalized_canonical_scalar value bound

def publicInputLength : Nat := 57
structure Address where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr
def Address.words (a : Address) : List Nat := [a.a0,a.a1,a.a2,a.a3,a.a4]
def Address.read (xs : List Nat) (off : Nat) : Address :=
  ⟨xs.getD off 0,xs.getD (off+1) 0,xs.getD (off+2) 0,xs.getD (off+3) 0,xs.getD (off+4) 0⟩

structure PublicInputs where
  closeIntentDigest : Words8
  receiverChannelId : Nat
  incomingTxHash : Words8
  receiverPkG : Words8
  recipient : Address
  sharedNativeNullifier : Words8
  amount : Words2
  finalBalanceStateH1 : Words8
  finalAccumulatorRoot : Words8
  tokenIndex : Nat
  deriving DecidableEq, Repr

def PublicInputs.words (p : PublicInputs) : List Nat :=
  p.closeIntentDigest.words ++ [p.receiverChannelId] ++ p.incomingTxHash.words ++
  p.receiverPkG.words ++ p.recipient.words ++ p.sharedNativeNullifier.words ++
  p.amount.words ++ p.finalBalanceStateH1.words ++ p.finalAccumulatorRoot.words ++ [p.tokenIndex]
def toU64Vec (p : PublicInputs) : List Nat := p.words
def readFields (xs : List Nat) : PublicInputs := {
  closeIntentDigest := Words8.read xs 0
  receiverChannelId := xs.getD 8 0
  incomingTxHash := Words8.read xs 9
  receiverPkG := Words8.read xs 17
  recipient := Address.read xs 25
  sharedNativeNullifier := Words8.read xs 30
  amount := Words2.read xs 38
  finalBalanceStateH1 := Words8.read xs 40
  finalAccumulatorRoot := Words8.read xs 48
  tokenIndex := xs.getD 56 0 }

inductive Field where
  | closeIntent | channel | incomingTx | receiverPk | recipient | nullifier | h1 | accumulator | token
  deriving DecidableEq, Repr
inductive Error where
  | invalidLength (actual : Nat)
  | outOfU32 (field : Field)
  | zeroChannel
  | closeIntentDigestMismatch | incomingTxHashMismatch | txHashRecomputeMismatch
  | receiverChannelMismatch | receiverDeltaMismatch | recipientMismatch
  | invalidClaimProof (details : String)
  | panic (details : String)
  deriving DecidableEq, Repr
abbrev Result := Except Error

def checkWords (field : Field) (xs : List Nat) : Result Unit :=
  if xs.all (fun x => decide (x < limbBase)) then .ok () else .error (.outOfU32 field)
def decodeFields (p : PublicInputs) : Result PublicInputs := do
  let _ ← checkWords .closeIntent p.closeIntentDigest.words
  let _ ← checkWords .channel [p.receiverChannelId]
  if p.receiverChannelId = 0 then throw .zeroChannel
  let _ ← checkWords .incomingTx p.incomingTxHash.words
  let _ ← checkWords .receiverPk p.receiverPkG.words
  let _ ← checkWords .recipient p.recipient.words
  let _ ← checkWords .nullifier p.sharedNativeNullifier.words
  let _ ← checkWords .h1 p.finalBalanceStateH1.words
  let _ ← checkWords .accumulator p.finalAccumulatorRoot.words
  let _ ← checkWords .token [p.tokenIndex]
  return {p with amount := normalizeScalar p.amount}
def fromU64Slice (xs : List Nat) : Result PublicInputs :=
  if xs.length = publicInputLength then decodeFields (readFields xs)
  else .error (.invalidLength xs.length)
def joinU64 (xs : List Nat) : Result Nat :=
  match xs with
  | hi :: lo :: _ => .ok (joinValue hi lo)
  | _ => .error (.panic "amount slice index")

def NativeWidths (p : PublicInputs) : Prop :=
  canonicalDigest p.closeIntentDigest ∧ p.receiverChannelId < limbBase ∧
  canonicalDigest p.incomingTxHash ∧ canonicalDigest p.receiverPkG ∧
  (∀ x ∈ p.recipient.words, x < limbBase) ∧ canonicalDigest p.sharedNativeNullifier ∧
  canonicalScalar p.amount ∧ canonicalDigest p.finalBalanceStateH1 ∧
  canonicalDigest p.finalAccumulatorRoot ∧ p.tokenIndex < limbBase

structure Key where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr
structure Ciphertext where
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr
structure ReceiverDelta where
  receiverPkG : Words8
  amount : Ciphertext
  deriving DecidableEq, Repr
structure SourceTx where
  sourceChannelId : Nat
  destinationChannelId : Nat
  tokenIndex : Nat
  sourcePkG : Words8
  senderDelta : Ciphertext
  txTreeRoot : Words8
  txHash : Words8
  receiverDeltas : List ReceiverDelta
  otherSourceFields : List Nat
  deriving DecidableEq, Repr
structure Claim where
  closeIntentDigest : Words8
  incomingTxHash : Words8
  receiverPkG : Words8
  recipient : Address
  receiverAmount : Ciphertext
  sharedNativeNullifier : Words8
  proof : List Nat
  recipientMemo : List Nat
  deriving DecidableEq, Repr
structure BalanceState where
  channelId : Nat
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : Ten Nat
  encBalances : List (Ten Ciphertext)
  regevPkDigests : List Words8
  recipients : List Address
  pendingAdds : List (Ten Nat)
  settledChain : Words8
  accumulatorRoot : Words8
  stateVersion : Words2
  deriving DecidableEq, Repr
structure Witness where
  closeIntentDigest : Words8
  closedChannelId : Nat
  sourceTx : SourceTx
  claim : Claim
  receiverPk : Key
  amount : Nat
  finalState : BalanceState
  receiverMemberIndex : Nat
  deriving DecidableEq, Repr

inductive Call (α : Type) where
  | ok (value : α) | failure (details : String) | panic (details : String)
def mapCall {α : Type} (error : String → Error) : Call α → Result α
  | .ok a => .ok a
  | .failure e => .error (error e)
  | .panic e => .error (.panic e)
structure NativeEnvironment where
  computeTxHash : SourceTx → Call Words8
  verifyWithdrawClaim : Nat → Key → Ciphertext → Nat → List Nat → Call Unit
  pkDigest : Key → Call Words8
  balanceH1 : BalanceState → Call Words8

def matchingDelta (w : Witness) : Bool := w.sourceTx.receiverDeltas.any fun d =>
  d.receiverPkG == w.claim.receiverPkG && d.amount == w.claim.receiverAmount
def project (w : Witness) (h1 : Words8) : PublicInputs := {
  closeIntentDigest := w.closeIntentDigest
  receiverChannelId := w.closedChannelId
  incomingTxHash := w.sourceTx.txHash
  receiverPkG := w.claim.receiverPkG
  recipient := w.claim.recipient
  sharedNativeNullifier := w.claim.sharedNativeNullifier
  amount := splitU64 w.amount
  finalBalanceStateH1 := h1
  finalAccumulatorRoot := w.finalState.accumulatorRoot
  tokenIndex := w.sourceTx.tokenIndex }

/-- Dependency panic is not converted into a source typed witness error. Digest
    methods are infallible on their representation domain but may assert/panic. -/
def infallibleCall {α : Type} (c : Call α) : Result α :=
  mapCall (fun e => .panic e) c
def toPublicInputs (e : NativeEnvironment) (level : Nat) (w : Witness) : Result PublicInputs := do
  if w.claim.closeIntentDigest ≠ w.closeIntentDigest then throw .closeIntentDigestMismatch
  if w.claim.incomingTxHash ≠ w.sourceTx.txHash then throw .incomingTxHashMismatch
  if w.sourceTx.destinationChannelId ≠ w.closedChannelId then throw .receiverChannelMismatch
  let txHash ← mapCall (fun _ => .txHashRecomputeMismatch) (e.computeTxHash w.sourceTx)
  if txHash ≠ w.sourceTx.txHash then throw .txHashRecomputeMismatch
  if !matchingDelta w then throw .receiverDeltaMismatch
  let _ ← mapCall Error.invalidClaimProof
    (e.verifyWithdrawClaim level w.receiverPk w.claim.receiverAmount w.amount w.claim.proof)
  if w.receiverMemberIndex ≥ w.finalState.memberCount + w.finalState.delegateCount then
    throw .receiverChannelMismatch
  let committed ← match w.finalState.regevPkDigests[w.receiverMemberIndex]? with
    | some digest => pure digest
    | none => throw (.panic "regev_pk_digests index")
  let receiverDigest ← infallibleCall (e.pkDigest w.receiverPk)
  if committed ≠ receiverDigest then throw .receiverDeltaMismatch
  let recipient ← match w.finalState.recipients[w.receiverMemberIndex]? with
    | some address => pure address
    | none => throw (.panic "recipients index")
  if w.claim.recipient ≠ recipient then throw .recipientMismatch
  let h1 ← infallibleCall (e.balanceH1 w.finalState)
  return project w h1

theorem public_input_word_count (p : PublicInputs) : p.words.length = publicInputLength := by
  simp [PublicInputs.words, Words8.words, Words2.words, Address.words, publicInputLength]

set_option maxRecDepth 4096 in
set_option maxHeartbeats 2000000 in
theorem read_encoded_fields (p : PublicInputs) : readFields p.words = p := by
  cases p
  rfl

theorem all_source_slice_endpoints_fit :
    ([8,9,17,25,30,38,40,48,56,57] : List Nat).all (fun x => x ≤ publicInputLength) = true := by decide

theorem check_words_exact (field : Field) (xs : List Nat) :
    checkWords field xs = .ok () ↔ ∀ x ∈ xs, x < limbBase := by
  simp [checkWords, List.all_eq_true]

theorem codec_roundtrip (p : PublicInputs) (h : NativeWidths p) (nz : p.receiverChannelId ≠ 0) :
    fromU64Slice p.words = .ok p := by
  rcases h with ⟨hc,hr,ht,hp,ha,hn,hm,hh,hacc,hidx⟩
  have c := (check_words_exact .closeIntent _).mpr hc
  have r := (check_words_exact .channel [p.receiverChannelId]).mpr (by simpa using hr)
  have t := (check_words_exact .incomingTx _).mpr ht
  have pk := (check_words_exact .receiverPk _).mpr hp
  have a := (check_words_exact .recipient _).mpr ha
  have n := (check_words_exact .nullifier _).mpr hn
  have hd := (check_words_exact .h1 _).mpr hh
  have acc := (check_words_exact .accumulator _).mpr hacc
  have idx := (check_words_exact .token [p.tokenIndex]).mpr (by simpa using hidx)
  simp [fromU64Slice, public_input_word_count, read_encoded_fields, decodeFields,
    c,r,t,pk,a,n,hd,acc,idx,nz,Zkp.Implementation.ClosePublicInputs.normalized_canonical_scalar p.amount hm,
    Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem decoder_success_has_exact_length (xs : List Nat) (p : PublicInputs)
    (h : fromU64Slice xs = .ok p) : xs.length = publicInputLength := by
  unfold fromU64Slice at h
  split at h
  assumption
  contradiction

theorem public_input_encoding_is_injective {p q : PublicInputs} (h : p.words = q.words) : p = q := by
  have eq := congrArg readFields h
  simpa only [read_encoded_fields] using eq

theorem exact_tail_positions (p : PublicInputs) :
    p.words.getD 8 0 = p.receiverChannelId ∧ p.words.getD 38 0 = p.amount.hi ∧
    p.words.getD 39 0 = p.amount.lo ∧ p.words.getD 56 0 = p.tokenIndex := by
  cases p
  exact ⟨rfl,rfl,rfl,rfl⟩

theorem projection_copies_exact_token_and_nullifier (w : Witness) (h1 : Words8) :
    (project w h1).tokenIndex = w.sourceTx.tokenIndex ∧
    (project w h1).sharedNativeNullifier = w.claim.sharedNativeNullifier := ⟨rfl,rfl⟩

theorem projection_copies_exact_close_state (w : Witness) (h1 : Words8) :
    (project w h1).receiverChannelId = w.closedChannelId ∧
    (project w h1).finalBalanceStateH1 = h1 ∧
    (project w h1).finalAccumulatorRoot = w.finalState.accumulatorRoot := ⟨rfl,rfl,rfl⟩

/-- Proof-friendly exact successful-path trace. These are individual actual call
    results and local guards, not a funds-safety invariant assumed as a guard. -/
structure SuccessfulPath (e : NativeEnvironment) (level : Nat) (w : Witness) (p : PublicInputs) : Prop where
  closeDigest : w.claim.closeIntentDigest = w.closeIntentDigest
  txDigest : w.claim.incomingTxHash = w.sourceTx.txHash
  destination : w.sourceTx.destinationChannelId = w.closedChannelId
  recompute : e.computeTxHash w.sourceTx = .ok w.sourceTx.txHash
  delta : matchingDelta w = true
  proof : e.verifyWithdrawClaim level w.receiverPk w.claim.receiverAmount w.amount w.claim.proof = .ok ()
  active : w.receiverMemberIndex < w.finalState.memberCount + w.finalState.delegateCount
  slot : ∃ digest, w.finalState.regevPkDigests[w.receiverMemberIndex]? = some digest ∧
    e.pkDigest w.receiverPk = .ok digest
  recipient : w.finalState.recipients[w.receiverMemberIndex]? = some w.claim.recipient
  header : ∃ h1, e.balanceH1 w.finalState = .ok h1 ∧ p = project w h1

theorem successful_path_executes (e : NativeEnvironment) (level : Nat) (w : Witness) (p : PublicInputs)
    (h : SuccessfulPath e level w p) : toPublicInputs e level w = .ok p := by
  rcases h.slot with ⟨digest,hslot,hpk⟩
  rcases h.header with ⟨h1,hh1,rfl⟩
  simp [toPublicInputs,h.closeDigest,h.txDigest,h.destination,h.recompute,mapCall,
    h.delta,h.proof,Nat.not_le.mpr h.active,hslot,infallibleCall,hpk,h.recipient,hh1,
    Bind.bind,Except.bind,Pure.pure,Except.pure]

theorem native_success_has_actual_path (e : NativeEnvironment) (level : Nat) (w : Witness)
    (p : PublicInputs) (h : toPublicInputs e level w = .ok p) : SuccessfulPath e level w p := by
  simp only [toPublicInputs, Bind.bind, Except.bind, Pure.pure, Except.pure] at h
  split at h <;> try contradiction
  rename_i hc
  split at h <;> try contradiction
  rename_i ht
  split at h <;> try contradiction
  rename_i hd
  cases htx : e.computeTxHash w.sourceTx with
  | failure msg => simp [htx,mapCall] at h
  | panic msg => simp [htx,mapCall] at h
  | ok tx =>
    simp only [htx,mapCall,Except.bind] at h
    split at h <;> try contradiction
    rename_i heq
    have heq' : tx = w.sourceTx.txHash := by simpa using heq
    subst tx
    split at h <;> try contradiction
    rename_i hm
    cases hv : e.verifyWithdrawClaim level w.receiverPk w.claim.receiverAmount w.amount w.claim.proof with
    | failure msg => simp [hv,mapCall] at h
    | panic msg => simp [hv,mapCall] at h
    | ok u =>
      cases u
      simp only [hv,mapCall,Except.bind] at h
      split at h <;> try contradiction
      rename_i ha
      cases hs : w.finalState.regevPkDigests[w.receiverMemberIndex]? with
      | none => simp [hs] at h
      | some digest =>
        simp only [hs,Except.bind] at h
        cases hp : e.pkDigest w.receiverPk with
        | failure msg => simp [hp,infallibleCall,mapCall] at h
        | panic msg => simp [hp,infallibleCall,mapCall] at h
        | ok pk =>
          simp only [hp,infallibleCall,mapCall,Except.bind] at h
          split at h <;> try contradiction
          rename_i hpk
          have hpkeq : digest = pk := by simpa using hpk
          subst pk
          cases hr : w.finalState.recipients[w.receiverMemberIndex]? with
          | none => simp [hr] at h
          | some address =>
            simp only [hr,Except.bind] at h
            split at h <;> try contradiction
            rename_i hra
            have hraeq : w.claim.recipient = address := by simpa using hra
            subst address
            cases hh : e.balanceH1 w.finalState with
            | failure msg => simp [hh,infallibleCall,mapCall] at h
            | panic msg => simp [hh,infallibleCall,mapCall] at h
            | ok hash =>
              simp only [hh,infallibleCall,mapCall,Except.bind,Except.ok.injEq] at h
              exact ⟨by simpa using hc,by simpa using ht,by simpa using hd,htx,
                by simpa using hm,hv,by omega,⟨digest,hs,hp⟩,hr,⟨hash,hh,h.symm⟩⟩

theorem native_success_binds_recipient_and_active_slot (e : NativeEnvironment) (level : Nat)
    (w : Witness) (p : PublicInputs) (h : toPublicInputs e level w = .ok p) :
    w.finalState.recipients[w.receiverMemberIndex]? = some p.recipient ∧
    w.receiverMemberIndex < w.finalState.memberCount + w.finalState.delegateCount := by
  have path := native_success_has_actual_path e level w p h
  rcases path.header with ⟨_,_,rfl⟩
  exact ⟨path.recipient,path.active⟩

def normalPublicInputs : PublicInputs := {
  closeIntentDigest := Words8.zero, receiverChannelId := 7
  incomingTxHash := Words8.zero, receiverPkG := Words8.zero
  recipient := ⟨1,2,3,4,5⟩, sharedNativeNullifier := Words8.zero
  amount := ⟨0,21⟩, finalBalanceStateH1 := Words8.zero
  finalAccumulatorRoot := Words8.zero, tokenIndex := 55 }
theorem normal_codec_roundtrip : fromU64Slice normalPublicInputs.words = .ok normalPublicInputs := by
  apply codec_roundtrip
  simp [NativeWidths,canonicalScalar,canonicalDigest,normalPublicInputs,Words8.words,Words8.zero,
    Address.words,limbBase]
  decide

/-- Normal local host path with explicit dependency stubs, not a claim that the
    all-zero digest/proof payload is accepted by real cryptography. -/
def normalPolynomial : List Nat := 1 :: List.replicate 2047 0
def normalCiphertext : Ciphertext := ⟨normalPolynomial,normalPolynomial⟩
def tenConstant {α : Type} (x : α) : Ten α := ⟨x,x,x,x,x,x,x,x,x,x⟩
def normalWitness : Witness := {
  closeIntentDigest := Words8.zero,closedChannelId := 7
  sourceTx := {
    sourceChannelId := 5,destinationChannelId := 7,tokenIndex := 55
    sourcePkG := Words8.zero,senderDelta := normalCiphertext,txTreeRoot := Words8.zero
    txHash := Words8.zero,receiverDeltas := [⟨Words8.zero,normalCiphertext⟩],otherSourceFields := [] }
  claim := {
    closeIntentDigest := Words8.zero,incomingTxHash := Words8.zero,receiverPkG := Words8.zero
    recipient := ⟨1,2,3,4,5⟩,receiverAmount := normalCiphertext
    sharedNativeNullifier := Words8.zero,proof := [],recipientMemo := [] }
  receiverPk := ⟨normalPolynomial,normalPolynomial⟩,amount := 21
  finalState := {
    channelId := 7,memberCount := 2,delegateCount := 1,tokenCount := 2
    registry := ⟨0,55,0,0,0,0,0,0,0,0⟩
    encBalances := List.replicate 1024 (tenConstant normalCiphertext)
    regevPkDigests := List.replicate 1024 Words8.zero
    recipients := List.replicate 1024 ⟨1,2,3,4,5⟩
    pendingAdds := List.replicate 1024 (tenConstant 0)
    settledChain := Words8.zero,accumulatorRoot := Words8.zero,stateVersion := ⟨0,9⟩ }
  receiverMemberIndex := 2 }
def normalNativeEnvironment : NativeEnvironment := {
  computeTxHash := fun tx => .ok tx.txHash
  verifyWithdrawClaim := fun _ _ _ amount _ =>
    if amount = 21 then .ok () else .failure "unexpected modeled amount"
  pkDigest := fun _ => .ok Words8.zero
  balanceH1 := fun _ => .ok Words8.zero }
set_option maxRecDepth 4096 in
theorem normal_native_delegate_path :
    toPublicInputs normalNativeEnvironment 0 normalWitness = .ok normalPublicInputs := by
  apply successful_path_executes
  refine ⟨rfl,rfl,rfl,rfl,?_,rfl,by decide,⟨Words8.zero,?_,rfl⟩,?_,⟨Words8.zero,rfl,?_⟩⟩
  · simp [matchingDelta,normalWitness]
  · simp [normalWitness]
  · simp [normalWitness]
  · rfl

end Zkp.Implementation.PostCloseClaimPublicInputs
