import Zkp.Implementation.PostCloseClaimPublicInputs

/-!
# Post-close claim circuit: adversarial assignments and native construction

Source-oriented translation of every default-build production function in
src/circuits/channel/post_close_claim_circuit.rs. The constructor statement is
separate from fill_witness/prove and from the native PI helper. Test/feature
fixtures are not constraints; the feature-enabled fixture functions remain
explicitly untranslated, not classified as test-only. Arithmetic is specialized to the production
Goldilocks instance, not a theorem for every generic Rust F/C instantiation.
The native Rust type widths are NOT imposed on an
arbitrary field witness: member/delegate/token counts have u32 gates here, and
only member+delegate<=1024 and the opened active index are constrained locally.
No minimum member count, token-count<=10, registry uniqueness/membership/zero
suffix, recipient nonzero, receiver SPHINCS/Falcon membership, source signatures,
latest-head selection, close-digest/H1 relationship or replay/fund availability
is silently added. The receiverPkG is in the transaction and nullifier preimages;
the opened slot binds the Regev key and recipient, not a separately stored pkG.

The statement recomputes token-bearing tx_hash, verifies its height20 Poseidon
accumulator path, recomputes the IMB2 H1 header, and opens a height10 IMS2 slot.
Both member and delegate slots satisfy the SAME recipient/key leaf relation.
Decryption's exact caller arguments and amount-hi/lo connects are represented;
the internal decryption polynomial/gate system is an explicit dependency, not
an invented decrypt-to-amount boolean that presupposes overall asset safety.
The cryptographic functions are parameters, with only narrowly scoped binding
assumptions when a theorem compares two openings. There is no universal hash
injectivity assumption. Merkle fold order/leaf hashing is explicit; its tree
authentication theorem, primitive hashes, Goldilocks/gate lowering, compiler,
native writer/panic behavior and proof-system soundness remain boundaries.
Normal examples prove local modeled satisfiability, NOT a production proof run.
-/
namespace Zkp.Implementation.PostCloseClaimCircuit

open Zkp.Implementation.ClosePublicInputs (Words2 Words8 Ten limbBase scalarLimit
  canonicalDigest canonicalScalar splitU64)
open Zkp.Implementation.PostCloseClaimPublicInputs (PublicInputs Address Key Ciphertext Call)

/-- This module's target value shape is identical to the shared native codec;
    its allocation gates and arbitrary-witness domain are specified separately. -/
abbrev PublicInputsTarget := Zkp.Implementation.PostCloseClaimPublicInputs.PublicInputs
def publicInputWords (p : PublicInputsTarget) : List Nat := p.words
theorem public_input_tail_positions (p : PublicInputsTarget) :
    (publicInputWords p).getD 8 0 = p.receiverChannelId ∧
    (publicInputWords p).getD 38 0 = p.amount.hi ∧
    (publicInputWords p).getD 39 0 = p.amount.lo ∧
    (publicInputWords p).getD 56 0 = p.tokenIndex :=
  Zkp.Implementation.PostCloseClaimPublicInputs.exact_tail_positions p

def goldilocks : Nat := 18446744069414584321
def maxSlots : Nat := 1024
def maxTokens : Nat := 10
def accumulatorHeight : Nat := 20
def slotHeight : Nat := 10
def regevN : Nat := 2048
def regevQ : Nat := 2013265921
def imtl : Nat := 0x494d544c
def imtc : Nat := 0x494d5443
def imck : Nat := 0x494d434b
def imb2 : Nat := 0x494d4232
def ims2 : Nat := 0x494d5332
def imrp : Nat := 0x494d5250
def imrc : Nat := 0x494d5243

structure Hash4 where
  h0 : Nat
  h1 : Nat
  h2 : Nat
  h3 : Nat
  deriving DecidableEq, Repr
def Hash4.words (h : Hash4) : List Nat := [h.h0,h.h1,h.h2,h.h3]
def Hash4.zero : Hash4 := ⟨0,0,0,0⟩
def Hash4.canonical (h : Hash4) : Prop := ∀ x ∈ h.words, x < goldilocks
def encodeHash (h : Hash4) : Words8 :=
  ⟨h.h0 / limbBase,h.h0 % limbBase,h.h1 / limbBase,h.h1 % limbBase,
   h.h2 / limbBase,h.h2 % limbBase,h.h3 / limbBase,h.h3 % limbBase⟩
/-- Circuit reduction, unlike the native Bytes32::reduce_to_hash_out raw join. -/
def decodeHash (w : Words8) : Hash4 :=
  ⟨(w.w0*limbBase+w.w1)%goldilocks,(w.w2*limbBase+w.w3)%goldilocks,
   (w.w4*limbBase+w.w5)%goldilocks,(w.w6*limbBase+w.w7)%goldilocks⟩
def CanonicalRoot (w : Words8) : Prop := encodeHash (decodeHash w) = w

structure Header where
  channelId : Nat
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : Ten Nat
  slotRoot : Hash4
  settledChain : Words8
  accumulatorRoot : Words8
  stateVersion : Words2
  deriving DecidableEq, Repr
def Header.words (h : Header) : List Nat :=
  [imb2,h.channelId,h.memberCount,h.delegateCount,h.tokenCount] ++ h.registry.values ++
  h.slotRoot.words ++ h.settledChain.words ++ h.accumulatorRoot.words ++ h.stateVersion.words
structure Slot where
  pkDigest : Words8
  encDigests : Ten Words8
  pendingAdds : Ten Nat
  recipient : Address
  deriving DecidableEq, Repr
def Slot.words (s : Slot) : List Nat :=
  [ims2] ++ s.pkDigest.words ++ s.encDigests.values.bind Words8.words ++
  s.pendingAdds.values ++ s.recipient.words

/-- Core assignment retains all dependency-private wires as an opaque payload;
    actual polynomial equations are not claimed translated in this source map. -/
structure RawWitness where
  p : PublicInputs
  sourcePkG : Words8
  senderDeltaDigest : Words8
  receiverDeltaDigest : Words8
  txTreeRoot : Words8
  sourceChannelId : Nat
  incomingSiblings : List Hash4
  incomingIndex : Nat
  slotRoot : Hash4
  slotSiblings : List Hash4
  slotEncDigests : Ten Words8
  slotPendingAdds : Ten Nat
  tokenCount : Nat
  registry : Ten Nat
  settledChain : Words8
  stateVersion : Words2
  memberCount : Nat
  delegateCount : Nat
  receiverMemberIndex : Nat
  key : Key
  delta : Ciphertext
  coreAssignment : List Nat
  coreAmount : Words2
  deriving DecidableEq, Repr

structure Environment where
  keccak : List Nat → Words8
  poseidon : List Nat → Hash4
  twoToOne : Hash4 → Hash4 → Hash4
  decryptionCore : Key → Ciphertext → List Nat → Words2 → Prop

def txWingPreimage (pk digest : Words8) : List Nat := [imtl] ++ pk.words ++ digest.words
def txLeaf (e : Environment) (w : RawWitness) : Words8 :=
  e.keccak ((e.keccak (txWingPreimage w.sourcePkG w.senderDeltaDigest)).words ++
    (e.keccak (txWingPreimage w.p.receiverPkG w.receiverDeltaDigest)).words)
def pushPreimage (a b : Words8) : List Nat := [imtc] ++ a.words ++ b.words
def push (e : Environment) (a b : Words8) : Words8 := e.keccak (pushPreimage a b)
def txIds (w : RawWitness) : Words8 :=
  ⟨0,0,0,0,0,w.p.tokenIndex,w.p.receiverChannelId,w.sourceChannelId⟩
def recomputedTxHash (e : Environment) (w : RawWitness) : Words8 :=
  push e (txIds w) (push e w.txTreeRoot (txLeaf e w))
def nullifierPreimage (p : PublicInputs) : List Nat :=
  [imck] ++ p.closeIntentDigest.words ++ p.incomingTxHash.words ++ p.receiverPkG.words
def recomputedNullifier (e : Environment) (p : PublicInputs) : Words8 := e.keccak (nullifierPreimage p)
def keyPreimage (k : Key) : List Nat := [imrp,regevN] ++ k.a ++ k.b
def ctPreimage (c : Ciphertext) : List Nat := [imrc,regevN] ++ c.c1 ++ c.c2
def openedSlot (e : Environment) (w : RawWitness) : Slot :=
  ⟨encodeHash (e.poseidon (keyPreimage w.key)),w.slotEncDigests,w.slotPendingAdds,w.p.recipient⟩
def header (w : RawWitness) : Header :=
  ⟨w.p.receiverChannelId,w.memberCount,w.delegateCount,w.tokenCount,w.registry,w.slotRoot,
   w.settledChain,w.p.finalAccumulatorRoot,w.stateVersion⟩
def recomputedH1 (e : Environment) (w : RawWitness) : Words8 := encodeHash (e.poseidon (header w).words)

/-- Least-significant index bit is consumed first, preserving source sibling
    order. Bytes32 leaves are Poseidon-hashed; Hash4 slot leaves are identity. -/
def merkleFold (e : Environment) : List Hash4 → Nat → Hash4 → Hash4
  | [], _, leaf => leaf
  | sibling :: rest, index, leaf =>
    merkleFold e rest (index / 2)
      (if index % 2 = 0 then e.twoToOne leaf sibling else e.twoToOne sibling leaf)
def accumulatorRoot (e : Environment) (w : RawWitness) : Hash4 :=
  merkleFold e w.incomingSiblings w.incomingIndex (e.poseidon w.p.incomingTxHash.words)
def slotRoot (e : Environment) (w : RawWitness) : Hash4 :=
  merkleFold e w.slotSiblings w.receiverMemberIndex (e.poseidon (openedSlot e w).words)

/-- Integer lowering of the helper's shift/split33/high-bit/low-bit-sum test.
    This expression agrees with field operations only on the proved small input
    domain; FieldAndGadgetLowering below retains that compiler/gate obligation. -/
def lessThanU32 (a b : Nat) : Bool :=
  let shifted := limbBase + b - a
  shifted / limbBase == 1 && shifted % limbBase != 0
def checkedWords (xs : List Nat) : Prop := ∀ x ∈ xs, x < limbBase
def privateWords (w : RawWitness) : List Nat :=
  w.sourcePkG.words ++ w.senderDeltaDigest.words ++ w.receiverDeltaDigest.words ++
  w.txTreeRoot.words ++ [w.sourceChannelId,w.memberCount,w.delegateCount,w.tokenCount] ++
  w.registry.values ++ w.settledChain.words ++ w.stateVersion.words ++
  w.slotEncDigests.values.bind Words8.words ++ w.slotPendingAdds.values

/-- Exact local wire relations plus explicitly named callee relations. Shape is
    fixed by constructor allocation, not a host/native validation shortcut. -/
structure ConstructorGates (e : Environment) (w : RawWitness) : Prop where
  publicRanges : checkedWords w.p.words
  privateRanges : checkedWords (privateWords w)
  fieldRoots : w.slotRoot.canonical ∧
    (∀ h ∈ w.incomingSiblings ++ w.slotSiblings, h.canonical)
  polynomials : w.key.a.length = regevN ∧ w.key.b.length = regevN ∧
    w.delta.c1.length = regevN ∧ w.delta.c2.length = regevN
  incomingShape : w.incomingSiblings.length = accumulatorHeight
  incomingIndex : w.incomingIndex < 2^accumulatorHeight
  txConnect : recomputedTxHash e w = w.p.incomingTxHash
  canonicalAccumulator : CanonicalRoot w.p.finalAccumulatorRoot
  incomingPath : accumulatorRoot e w = decodeHash w.p.finalAccumulatorRoot
  h1Connect : recomputedH1 e w = w.p.finalBalanceStateH1
  activeRange : w.memberCount + w.delegateCount < 2^11
  activeMaximum : lessThanU32 (w.memberCount + w.delegateCount) (maxSlots+1) = true
  activeSlot : lessThanU32 w.receiverMemberIndex (w.memberCount+w.delegateCount) = true
  slotShape : w.slotSiblings.length = slotHeight
  slotIndex : w.receiverMemberIndex < 2^slotHeight
  slotPath : slotRoot e w = w.slotRoot
  ciphertextConnect : e.keccak (ctPreimage w.delta) = w.receiverDeltaDigest
  decryption : e.decryptionCore w.key w.delta w.coreAssignment w.coreAmount
  amountHigh : w.p.amount.hi = w.coreAmount.hi
  amountLow : w.p.amount.lo = w.coreAmount.lo
  nullifierConnect : recomputedNullifier e w.p = w.p.sharedNativeNullifier

/-- A genuinely unproved link from actual Plonky2 constraints/proofs to the
    hand-written relations above; never instantiated with an axiom here. -/
def FieldAndGadgetLowering (actual : RawWitness → Prop) (e : Environment) : Prop :=
  ∀ w, actual w → ConstructorGates e w

theorem exact_public_input_count (w : RawWitness) : w.p.words.length = 57 :=
  Zkp.Implementation.PostCloseClaimPublicInputs.public_input_word_count w.p
theorem header_has_exact_37_elements (h : Header) : h.words.length = 37 := by
  simp [Header.words,Ten.values,Hash4.words,Words8.words,Words2.words]
theorem slot_has_exact_104_elements (s : Slot) : s.words.length = 104 := by
  simp [Slot.words,Ten.values,Words8.words,Address.words,List.bind]
theorem nullifier_preimage_has_exact_25_words (p : PublicInputs) :
    (nullifierPreimage p).length = 25 := by simp [nullifierPreimage,Words8.words]
theorem tx_wing_has_exact_17_words (pk digest : Words8) :
    (txWingPreimage pk digest).length = 17 := by simp [txWingPreimage,Words8.words]
theorem chain_push_has_exact_17_words (a b : Words8) :
    (pushPreimage a b).length = 17 := by simp [pushPreimage,Words8.words]

theorem token_and_channel_are_the_same_ids_wires (w : RawWitness) :
    (txIds w).w5 = w.p.tokenIndex ∧ (txIds w).w6 = w.p.receiverChannelId ∧
    (txIds w).w7 = w.sourceChannelId := ⟨rfl,rfl,rfl⟩

def HashBindingAt (hash : List Nat → Words8) (a b : List Nat) : Prop := hash a = hash b → a = b
theorem a_fixed_tx_digest_fixes_token_and_channel_under_local_binding
    (e : Environment) (w v : RawWitness) (gw : ConstructorGates e w) (gv : ConstructorGates e v)
    (same : w.p.incomingTxHash = v.p.incomingTxHash)
    (binding : HashBindingAt e.keccak
      (pushPreimage (txIds w) (push e w.txTreeRoot (txLeaf e w)))
      (pushPreimage (txIds v) (push e v.txTreeRoot (txLeaf e v)))) :
    w.p.tokenIndex = v.p.tokenIndex ∧ w.p.receiverChannelId = v.p.receiverChannelId ∧
      w.sourceChannelId = v.sourceChannelId := by
  have h := binding (gw.txConnect.trans (same.trans gv.txConnect.symm))
  have token := congrArg (fun xs => xs.getD 6 0) h
  have channel := congrArg (fun xs => xs.getD 7 0) h
  have source := congrArg (fun xs => xs.getD 8 0) h
  exact ⟨token,channel,source⟩
theorem slot_recipient_is_exact_public_recipient (e : Environment) (w : RawWitness) :
    (openedSlot e w).recipient = w.p.recipient := rfl
theorem header_uses_exact_public_channel_and_accumulator (w : RawWitness) :
    (header w).channelId = w.p.receiverChannelId ∧
    (header w).accumulatorRoot = w.p.finalAccumulatorRoot := ⟨rfl,rfl⟩
theorem less_than_helper_exact_on_u32 (a b : Nat) (ha : a < limbBase) (hb : b < limbBase) :
    lessThanU32 a b = true ↔ a < b := by
  simp [lessThanU32, Bool.and_eq_true, bne_iff_ne, limbBase] at *
  omega

theorem active_gate_bounds_full_member_delegate_region (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) : w.memberCount + w.delegateCount ≤ maxSlots := by
  have small : w.memberCount + w.delegateCount < limbBase := by
    have h := g.activeRange
    simp [limbBase] at *
    omega
  have cmp := (less_than_helper_exact_on_u32 _ _ small (by decide : maxSlots+1 < limbBase)).mp g.activeMaximum
  omega
theorem opened_slot_is_active_member_or_delegate (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) :
    w.receiverMemberIndex < w.memberCount + w.delegateCount ∧ w.receiverMemberIndex < maxSlots := by
  have bound := active_gate_bounds_full_member_delegate_region e w g
  have idx := g.slotIndex
  have smallIndex : w.receiverMemberIndex < limbBase := by
    simp [slotHeight,limbBase] at *
    omega
  have smallActive : w.memberCount + w.delegateCount < limbBase := by
    simp [maxSlots,limbBase] at *
    omega
  have active := (less_than_helper_exact_on_u32 _ _ smallIndex smallActive).mp g.activeSlot
  constructor
  exact active
  omega

theorem member_or_delegate_classification (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) :
    w.receiverMemberIndex < w.memberCount ∨
      (w.memberCount ≤ w.receiverMemberIndex ∧
       w.receiverMemberIndex < w.memberCount + w.delegateCount) := by
  have h := (opened_slot_is_active_member_or_delegate e w g).1
  omega
theorem amount_is_exact_core_output (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) : w.p.amount = w.coreAmount := by
  cases h : w.p.amount with
  | mk hi lo =>
    cases hc : w.coreAmount with
    | mk chi clo =>
      have hh := g.amountHigh
      have hl := g.amountLow
      simp [h,hc] at hh hl
      cases hh
      cases hl
      rfl
theorem circuit_amount_and_token_are_u32_limbed (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) :
    w.p.amount.hi < limbBase ∧ w.p.amount.lo < limbBase ∧ w.p.tokenIndex < limbBase := by
  have h := g.publicRanges
  simp only [checkedWords,PublicInputs.words,Words2.words,List.mem_append,List.mem_cons,List.mem_singleton] at h
  exact ⟨h _ (by simp),h _ (by simp),h _ (by simp)⟩
theorem claimed_amount_value_below_u64 (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) : w.p.amount.hi * limbBase + w.p.amount.lo < scalarLimit := by
  have h := circuit_amount_and_token_are_u32_limbed e w g
  simp [limbBase,scalarLimit] at *
  omega
theorem incoming_tx_is_anchored_at_a_20_bit_position (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) :
    w.incomingIndex < 1048576 ∧ accumulatorRoot e w = decodeHash w.p.finalAccumulatorRoot ∧
    recomputedTxHash e w = w.p.incomingTxHash := ⟨g.incomingIndex,g.incomingPath,g.txConnect⟩
theorem anchored_ciphertext_is_the_decryption_ciphertext (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) :
    e.keccak (ctPreimage w.delta) = w.receiverDeltaDigest ∧
    e.decryptionCore w.key w.delta w.coreAssignment w.p.amount := by
  exact ⟨g.ciphertextConnect,(amount_is_exact_core_output e w g).symm ▸ g.decryption⟩
theorem nullifier_is_derived_not_free (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) :
    w.p.sharedNativeNullifier = e.keccak ([imck] ++ w.p.closeIntentDigest.words ++
      w.p.incomingTxHash.words ++ w.p.receiverPkG.words) := g.nullifierConnect.symm

/-- Scoped dependency contract for precisely this key/ciphertext/core output.
    It is not proof acceptance=>funds safety or a caller-supplied amount guard. -/
def DecryptionContractAt (e : Environment) (w : RawWitness)
    (plaintext : Key → Ciphertext → Words2 → Prop) : Prop :=
  e.decryptionCore w.key w.delta w.coreAssignment w.coreAmount → plaintext w.key w.delta w.coreAmount
theorem amount_matches_plaintext_under_decryption_contract (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) (plaintext : Key → Ciphertext → Words2 → Prop)
    (sound : DecryptionContractAt e w plaintext) : plaintext w.key w.delta w.p.amount := by
  rw [amount_is_exact_core_output e w g]
  exact sound g.decryption

/-- Local opening uniqueness for two compared paths and leaf tuples. No global
    finite-output hash injectivity axiom is asserted. -/
def SlotOpeningBindingAt (e : Environment) (w : RawWitness) (reference : Slot)
    (siblings : List Hash4) : Prop :=
  merkleFold e w.slotSiblings w.receiverMemberIndex (e.poseidon (openedSlot e w).words) =
    merkleFold e siblings w.receiverMemberIndex (e.poseidon reference.words) →
  openedSlot e w = reference
theorem reference_slot_fixes_recipient_and_regev_key (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) (reference : Slot) (siblings : List Hash4)
    (path : merkleFold e siblings w.receiverMemberIndex (e.poseidon reference.words) = w.slotRoot)
    (binding : SlotOpeningBindingAt e w reference siblings) :
    w.p.recipient = reference.recipient ∧
    encodeHash (e.poseidon (keyPreimage w.key)) = reference.pkDigest := by
  have eq : openedSlot e w = reference := binding (g.slotPath.trans path.symm)
  exact ⟨congrArg Slot.recipient eq,congrArg Slot.pkDigest eq⟩

structure ExpectedClose where
  closeDigest : Words8
  channelId : Nat
  h1 : Words8
  accumulator : Words8
def ConsumerBinding (p : PublicInputs) (expected : ExpectedClose) : Prop :=
  p.closeIntentDigest = expected.closeDigest ∧ p.receiverChannelId = expected.channelId ∧
  p.finalBalanceStateH1 = expected.h1 ∧ p.finalAccumulatorRoot = expected.accumulator
theorem exact_consumer_head_pins_both_opening_roots (e : Environment) (w : RawWitness)
    (g : ConstructorGates e w) (expected : ExpectedClose) (h : ConsumerBinding w.p expected) :
    recomputedH1 e w = expected.h1 ∧ accumulatorRoot e w = decodeHash expected.accumulator := by
  exact ⟨g.h1Connect.trans h.2.2.1,g.incomingPath.trans (congrArg decodeHash h.2.2.2)⟩

inductive BuildOp where
  | range (name : String) (count bits : Nat)
  | virtual (name : String) (count : Nat)
  | hash (name : String) (words : Nat)
  | connect (name : String)
  | merkle (name : String) (height : Nat)
  | decryption (exposeAmount : Bool)
  | register (count : Nat)
  | build (config : String)
  deriving DecidableEq, Repr
def publicAllocationProgram : List BuildOp :=
  [.range "closeIntent" 8 32,.range "receiverChannelId" 1 32,.range "incomingTxHash" 8 32,
   .range "receiverPkG" 8 32,.range "recipient" 5 32,.range "nullifier" 8 32,
   .range "amount.hi,lo" 2 32,.range "finalH1" 8 32,.range "finalAccumulator" 8 32,
   .range "tokenIndex" 1 32]
def constructorProgram : List BuildOp := publicAllocationProgram ++
  [.range "sourcePk,senderDigest,receiverDigest,txRoot" 32 32,.range "sourceChannel" 1 32,
   .hash "senderWing" 17,.hash "receiverWing" 17,.hash "txLeaf" 16,
   .hash "push(txRoot,leaf)" 17,.hash "push(ids,mixed)" 17,.connect "incomingTxHash",
   .merkle "incoming: hash Bytes32 leaf, canonical PI root" accumulatorHeight,
   .range "memberCount,delegateCount,tokenCount" 3 32,.range "registry" 10 32,
   .virtual "slotRoot" 4,.range "settledChain" 8 32,.range "stateVersion" 2 32,
   .virtual "receiverMemberIndex" 1,.range "slot ciphertext digests" 80 32,
   .range "slot pending adds" 10 32,.hash "IMB2" 37,.connect "finalH1",
   .range "active sum" 1 11,.connect "active<1025",
   .connect "receiverMemberIndex<active",.virtual "a,b,c1,c2" (4*regevN),
   .hash "IMRP" (2+2*regevN),.hash "IMS2" 104,
   .merkle "slot: Hash4 leaf identity" slotHeight,.hash "IMRC" (2+2*regevN),
   .connect "receiverDeltaDigest",.decryption true,.connect "amount.hi,lo",
   .hash "IMCK" 25,.connect "sharedNativeNullifier",.register 57,.build "standard_recursion_zk_config"]
def newCircuit : List BuildOp := constructorProgram
def defaultCircuit : List BuildOp := newCircuit

inductive WriteOp where
  | words (name : String) (values : List Nat)
  | canonicalU64 (name : String) (value : Nat)
  | merkle (name : String) (expectedHeight : Nat) (siblings : List Hash4)
  | hash4 (name : String) (value : Hash4)
  | polynomialZip (name : String) (targetCount : Nat) (values : List Nat)
  deriving DecidableEq, Repr
/-- Amount is native u64 splitting; these entries retain exact source PI order. -/
def publicWriteProgram (p : PublicInputs) : List WriteOp :=
  [.words "closeIntent" p.closeIntentDigest.words,.canonicalU64 "receiverChannel" p.receiverChannelId,
   .words "incomingTx" p.incomingTxHash.words,.words "receiverPkG" p.receiverPkG.words,
   .words "recipient" p.recipient.words,.words "nullifier" p.sharedNativeNullifier.words,
   .words "amount" p.amount.words,.words "finalH1" p.finalBalanceStateH1.words,
   .words "finalAccumulator" p.finalAccumulatorRoot.words,.canonicalU64 "tokenIndex" p.tokenIndex]
def fillWriteProgram (w : RawWitness) : List WriteOp := publicWriteProgram w.p ++
  [.words "sourcePkG" w.sourcePkG.words,.words "senderDeltaDigest" w.senderDeltaDigest.words,
   .words "receiverDeltaDigest" w.receiverDeltaDigest.words,.words "txRoot" w.txTreeRoot.words,
   .canonicalU64 "sourceChannel" w.sourceChannelId,.merkle "incoming" accumulatorHeight w.incomingSiblings,
   .canonicalU64 "incomingIndex" w.incomingIndex,.canonicalU64 "memberCount" w.memberCount,
   .canonicalU64 "delegateCount" w.delegateCount,.canonicalU64 "tokenCount" w.tokenCount,
   .words "registry: increasing array order" w.registry.values,.hash4 "slotRoot" w.slotRoot,
   .merkle "slot" slotHeight w.slotSiblings,.canonicalU64 "receiverIndex" w.receiverMemberIndex] ++
  (w.slotEncDigests.values.map fun d => .words "slotEncDigest: increasing array order" d.words) ++
  [.words "slotPendingAdds: increasing array order" w.slotPendingAdds.values,
   .words "settledChain" w.settledChain.words,.words "stateVersion" w.stateVersion.words,
   .polynomialZip "a" regevN w.key.a,.polynomialZip "b" regevN w.key.b,
   .polynomialZip "c1" regevN w.delta.c1,.polynomialZip "c2" regevN w.delta.c2]
def polynomialAssignedPrefix (targetCount : Nat) (values : List Nat) : List Nat := values.take targetCount

inductive NativeError where
  | memberIndexOutOfRange (index : Nat)
  | failedToProve (message : String)
  | panic (message : String)
  deriving DecidableEq, Repr
abbrev NativeResult := Except NativeError
structure NativeWitness where
  raw : RawWitness
  secret : List Int
  deriving DecidableEq, Repr
structure NativeEnvironment (Proof : Type) where
  write : WriteOp → Call Unit
  buildCore : Key → Ciphertext → List Int → Call (List Nat × Words2)
  fillCore : List Nat → Call Unit
  prove : RawWitness → Call Proof
def writerCall : Call Unit → NativeResult Unit
  | .ok _ => .ok ()
  | .failure e | .panic e => .error (.panic e)
def runWrites {Proof : Type} (e : NativeEnvironment Proof) : List WriteOp → NativeResult Unit
  | [] => .ok ()
  | op :: rest => do
    let _ ← writerCall (e.write op)
    runWrites e rest
def fillWitness {Proof : Type} (e : NativeEnvironment Proof) (w : NativeWitness) : NativeResult RawWitness := do
  if w.raw.receiverMemberIndex ≥ maxSlots then throw (.memberIndexOutOfRange w.raw.receiverMemberIndex)
  let _ ← runWrites e (fillWriteProgram w.raw)
  let (core,amount) ← match e.buildCore w.raw.key w.raw.delta w.secret with
    | .ok result => pure result
    | .failure _ => throw (.failedToProve "decryption-core witness build failed")
    | .panic msg => throw (.panic msg)
  let _ ← writerCall (e.fillCore core)
  return {w.raw with coreAssignment := core,coreAmount := amount}
def prove {Proof : Type} (e : NativeEnvironment Proof) (w : NativeWitness) : NativeResult Proof := do
  let raw ← fillWitness e w
  match e.prove raw with
  | .ok proof => pure proof
  | .failure msg => throw (.failedToProve msg)
  | .panic msg => throw (.panic msg)

/-- Only Rust representation bounds, not circuit truth or active-state validity.
    Writes/canonical field conversion may panic even for native incoming u64. -/
def NativeWidths (w : NativeWitness) : Prop :=
  Zkp.Implementation.PostCloseClaimPublicInputs.NativeWidths w.raw.p ∧
  w.raw.memberCount < 256 ∧ w.raw.delegateCount < 65536 ∧ w.raw.tokenCount < 256 ∧
  w.raw.sourceChannelId < limbBase ∧ w.raw.incomingIndex < scalarLimit ∧
  canonicalScalar w.raw.stateVersion ∧ checkedWords (privateWords w.raw) ∧
  checkedWords (w.raw.key.a ++ w.raw.key.b ++ w.raw.delta.c1 ++ w.raw.delta.c2) ∧
  (∀ x ∈ w.secret, -128 ≤ x ∧ x < 128)

theorem native_range_failure_precedes_all_writes {Proof : Type} (e : NativeEnvironment Proof)
    (w : NativeWitness) (h : w.raw.receiverMemberIndex ≥ maxSlots) :
    fillWitness e w = .error (.memberIndexOutOfRange w.raw.receiverMemberIndex) := by
  simp [fillWitness,h,Bind.bind,Except.bind]
theorem prove_preserves_member_index_error {Proof : Type} (e : NativeEnvironment Proof)
    (w : NativeWitness) (h : w.raw.receiverMemberIndex ≥ maxSlots) :
    prove e w = .error (.memberIndexOutOfRange w.raw.receiverMemberIndex) := by
  simp [prove,native_range_failure_precedes_all_writes e w h,Bind.bind,Except.bind]
theorem polynomial_zip_does_not_invent_missing_coefficients (n : Nat) (xs : List Nat) :
    (polynomialAssignedPrefix n xs).length = min n xs.length := by simp [polynomialAssignedPrefix]
theorem default_uses_identical_constructor : defaultCircuit = constructorProgram := rfl
theorem constructor_finishes_with_exact_registration :
    constructorProgram.drop (constructorProgram.length - 2) =
      [.register 57,.build "standard_recursion_zk_config"] := by decide
theorem native_success_uses_supplied_public_inputs {Proof : Type} (e : NativeEnvironment Proof)
    (w : NativeWitness) (raw : RawWitness) (h : fillWitness e w = .ok raw) : raw.p = w.raw.p := by
  simp only [fillWitness,Bind.bind,Except.bind,Pure.pure,Except.pure] at h
  split at h <;> try contradiction
  cases hw : runWrites e (fillWriteProgram w.raw) with
  | error err => simp [hw] at h
  | ok resultUnit =>
    simp only [hw,Except.bind] at h
    cases hc : e.buildCore w.raw.key w.raw.delta w.secret with
    | failure msg => simp [hc] at h
    | panic msg => simp [hc] at h
    | ok result =>
      simp only [hc,Except.bind] at h
      cases hf : writerCall (e.fillCore result.1) with
      | error err => simp [hf] at h
      | ok resultUnit =>
        simp only [hf,Except.bind,Except.ok.injEq] at h
        rw [← h]

def tenConstant {α : Type} (x : α) : Ten α := ⟨x,x,x,x,x,x,x,x,x,x⟩
def normalPolynomial : List Nat := 1 :: List.replicate (regevN-1) 0
def normalRaw : RawWitness := {
  p := Zkp.Implementation.PostCloseClaimPublicInputs.normalPublicInputs
  sourcePkG := Words8.zero,senderDeltaDigest := Words8.zero,receiverDeltaDigest := Words8.zero
  txTreeRoot := Words8.zero,sourceChannelId := 5
  incomingSiblings := List.replicate accumulatorHeight Hash4.zero,incomingIndex := 0
  slotRoot := Hash4.zero,slotSiblings := List.replicate slotHeight Hash4.zero
  slotEncDigests := tenConstant Words8.zero,slotPendingAdds := tenConstant 0
  tokenCount := 2,registry := ⟨0,55,0,0,0,0,0,0,0,0⟩
  settledChain := Words8.zero,stateVersion := ⟨0,9⟩
  memberCount := 2,delegateCount := 1,receiverMemberIndex := 2
  key := ⟨normalPolynomial,normalPolynomial⟩,delta := ⟨normalPolynomial,normalPolynomial⟩
  coreAssignment := [],coreAmount := ⟨0,21⟩ }
/-- A dependency stub demonstrates local connective satisfiability ONLY. It
    deliberately makes no cryptographic binding claim and is never production. -/
def normalEnvironment : Environment := {
  keccak := fun _ => Words8.zero,poseidon := fun _ => Hash4.zero
  twoToOne := fun _ _ => Hash4.zero
  decryptionCore := fun key delta _ amount =>
    key = normalRaw.key ∧ delta = normalRaw.delta ∧ amount = ⟨0,21⟩ }
theorem merkle_zero_stub (n index : Nat) :
    merkleFold normalEnvironment (List.replicate n Hash4.zero) index Hash4.zero = Hash4.zero := by
  induction n generalizing index with
  | zero => rfl
  | succ n ih => simpa [merkleFold,normalEnvironment] using ih (index/2)

set_option maxRecDepth 4096 in
theorem normal_active_delegate_claim_is_locally_satisfiable : ConstructorGates normalEnvironment normalRaw := by
  constructor <;>
    simp [normalEnvironment,normalRaw,Zkp.Implementation.PostCloseClaimPublicInputs.normalPublicInputs,
      checkedWords,privateWords,PublicInputs.words,Words8.words,Words8.zero,Words2.words,
      Address.words,Ten.values,tenConstant,Hash4.words,Hash4.canonical,Hash4.zero,
      limbBase,scalarLimit,goldilocks,CanonicalRoot,encodeHash,decodeHash,
      recomputedTxHash,push,txLeaf,recomputedH1,recomputedNullifier,openedSlot,
      accumulatorRoot,slotRoot,normalPolynomial,regevN,accumulatorHeight,slotHeight,
      lessThanU32,maxSlots,merkle_zero_stub]
  all_goals exact merkle_zero_stub _ _

end Zkp.Implementation.PostCloseClaimCircuit
