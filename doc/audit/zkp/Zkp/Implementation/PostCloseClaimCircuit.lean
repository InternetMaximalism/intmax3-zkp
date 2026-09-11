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
authentication theorem, primitive hashes, compiler, native writer/panic behavior
and proof-system soundness remain boundaries.
Normal examples prove local modeled satisfiability, NOT a production proof run.

The former whole-predicate gate-lowering gap is now reduced, not removed. Each
builder call of constructorProgram carries a LOCAL proposition (`OpHolds`) over
wire values read back in source allocation/registration order, and
`program_satisfied_implies_gates` derives every ConstructorGates field from those
local propositions with no further hypothesis, so ConstructorGates asserts nothing
the transcribed program does not. What remains is `PrimitiveLowering`: per
primitive, that the actual Plonky2 gate set admits only assignments satisfying
that primitive's local proposition — range gates over field limbs, virtual
allocation, gadget argument widths, connects, the two inclusion verifies and the
decryption core — plus pinning of the digest/domain constants and of the compiled
wire layout to the ones modeled here. That obligation is never instantiated here.
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
    hand-written relations above; never instantiated here. `PrimitiveLowering`
    below splits it into one obligation per builder call and discharges the step
    from those obligations to this predicate. -/
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
   .virtual "incomingTxIndex" 1,
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

/-! ### Gate lowering: one local proposition per builder call

`ConstructorGates` above is a hand-written statement of the whole constraint system. The
section below decomposes it: every entry of `constructorProgram` (the transcription of the
`new()` builder calls) gets a LOCAL proposition `OpHolds`, saying exactly what that one
primitive enforces on the wire values, with the source line it comes from. The wire values
themselves are an `Assignment`, read back into the statement by `readWitness` in the source's
allocation/registration order. `program_satisfied_implies_gates` then derives EVERY
`ConstructorGates` field from the per-primitive propositions alone, with no extra hypothesis,
so the residual obligation is no longer "the gate predicate as a whole" but, per primitive,
that Plonky2's actual gate set implies that primitive's local proposition (plus the digest /
constant pinning already listed as boundaries). Source line numbers below refer to
src/circuits/channel/post_close_claim_circuit.rs unless another file is named. -/

/-- Wire values of ONE assignment to the constructor's targets, in source allocation order.
    The `Environment` is an index, not data: it fixes the interpretation of the keccak /
    Poseidon / decryption-core gadget calls that this circuit instance was built with, exactly
    as `ConstructorGates` does. Allocation order: :113-131 (public input targets), :323-327,
    :368-372, :389-408, :446-449 (witness targets), :492 (decryption core wires). -/
structure Assignment (e : Environment) where
  /-- `PostCloseClaimPublicInputsTarget::new`, :113-131. -/
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
  /-- Stage 3 tx_hash recompute inputs, :323-327. -/
  sourcePkG : Words8
  senderDeltaDigest : Words8
  receiverDeltaDigest : Words8
  txTreeRoot : Words8
  sourceChannelId : Nat
  /-- Accumulator inclusion proof wires, :368-372. -/
  incomingSiblings : List Hash4
  incomingIndex : Nat
  /-- H1 header scalars and opened slot leaf wires, :389-408. -/
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : Ten Nat
  slotTreeRoot : Hash4
  settledChain : Words8
  stateVersion : Words2
  receiverMemberIndex : Nat
  slotEncDigests : Ten Words8
  slotPendingAdds : Ten Nat
  /-- Slot inclusion proof wires, :468-471. -/
  slotSiblings : List Hash4
  /-- Regev key / delta ciphertext coefficient wires, :446-449. -/
  regevA : List Nat
  regevB : List Nat
  deltaC1 : List Nat
  deltaC2 : List Nat
  /-- Decryption-core private wires and its exposed amount limbs, :492-494. -/
  coreAssignment : List Nat
  coreAmount : Words2

/-- The public-input fields read off the registered wires. Registration order is
    `PostCloseClaimPublicInputsTarget::to_vec`, :140-152, registered at :512. -/
def readPublicInputs {e : Environment} (a : Assignment e) : PublicInputs :=
  { closeIntentDigest := a.closeIntentDigest, receiverChannelId := a.receiverChannelId,
    incomingTxHash := a.incomingTxHash, receiverPkG := a.receiverPkG, recipient := a.recipient,
    sharedNativeNullifier := a.sharedNativeNullifier, amount := a.amount,
    finalBalanceStateH1 := a.finalBalanceStateH1,
    finalAccumulatorRoot := a.finalAccumulatorRoot, tokenIndex := a.tokenIndex }
/-- The 57-word vector handed to `register_public_inputs`, :512. -/
def registeredPublicInputs {e : Environment} (a : Assignment e) : List Nat :=
  (readPublicInputs a).words
/-- The statement wires of an assignment, in the source's wire order. -/
def readWitness {e : Environment} (a : Assignment e) : RawWitness :=
  { p := readPublicInputs a
    sourcePkG := a.sourcePkG, senderDeltaDigest := a.senderDeltaDigest
    receiverDeltaDigest := a.receiverDeltaDigest, txTreeRoot := a.txTreeRoot
    sourceChannelId := a.sourceChannelId
    incomingSiblings := a.incomingSiblings, incomingIndex := a.incomingIndex
    slotRoot := a.slotTreeRoot, slotSiblings := a.slotSiblings
    slotEncDigests := a.slotEncDigests, slotPendingAdds := a.slotPendingAdds
    tokenCount := a.tokenCount, registry := a.registry
    settledChain := a.settledChain, stateVersion := a.stateVersion
    memberCount := a.memberCount, delegateCount := a.delegateCount
    receiverMemberIndex := a.receiverMemberIndex
    key := ⟨a.regevA, a.regevB⟩, delta := ⟨a.deltaC1, a.deltaC2⟩
    coreAssignment := a.coreAssignment, coreAmount := a.coreAmount }
def assignmentOf (e : Environment) (w : RawWitness) : Assignment e :=
  { closeIntentDigest := w.p.closeIntentDigest, receiverChannelId := w.p.receiverChannelId
    incomingTxHash := w.p.incomingTxHash, receiverPkG := w.p.receiverPkG
    recipient := w.p.recipient, sharedNativeNullifier := w.p.sharedNativeNullifier
    amount := w.p.amount, finalBalanceStateH1 := w.p.finalBalanceStateH1
    finalAccumulatorRoot := w.p.finalAccumulatorRoot, tokenIndex := w.p.tokenIndex
    sourcePkG := w.sourcePkG, senderDeltaDigest := w.senderDeltaDigest
    receiverDeltaDigest := w.receiverDeltaDigest, txTreeRoot := w.txTreeRoot
    sourceChannelId := w.sourceChannelId, incomingSiblings := w.incomingSiblings
    incomingIndex := w.incomingIndex, memberCount := w.memberCount
    delegateCount := w.delegateCount, tokenCount := w.tokenCount, registry := w.registry
    slotTreeRoot := w.slotRoot, settledChain := w.settledChain, stateVersion := w.stateVersion
    receiverMemberIndex := w.receiverMemberIndex, slotEncDigests := w.slotEncDigests
    slotPendingAdds := w.slotPendingAdds, slotSiblings := w.slotSiblings
    regevA := w.key.a, regevB := w.key.b, deltaC1 := w.delta.c1, deltaC2 := w.delta.c2
    coreAssignment := w.coreAssignment, coreAmount := w.coreAmount }

/-- Wires covered by each `builder.range_check` batch, keyed by the program entry's name.
    :113-118 (`u32_limb` + `Bytes32Target::new(builder,true)` for every public limb),
    :312-314 and :323-327 (the tx-recompute witnesses), :389-394 (header scalars + registry),
    :399-400 (settled chain, state version), :405-408 (slot leaf fields), :437 (active sum). -/
def rangeWires (w : RawWitness) : String → List Nat
  | "closeIntent" => w.p.closeIntentDigest.words
  | "receiverChannelId" => [w.p.receiverChannelId]
  | "incomingTxHash" => w.p.incomingTxHash.words
  | "receiverPkG" => w.p.receiverPkG.words
  | "recipient" => w.p.recipient.words
  | "nullifier" => w.p.sharedNativeNullifier.words
  | "amount.hi,lo" => w.p.amount.words
  | "finalH1" => w.p.finalBalanceStateH1.words
  | "finalAccumulator" => w.p.finalAccumulatorRoot.words
  | "tokenIndex" => [w.p.tokenIndex]
  | "sourcePk,senderDigest,receiverDigest,txRoot" =>
      w.sourcePkG.words ++ w.senderDeltaDigest.words ++ w.receiverDeltaDigest.words ++
        w.txTreeRoot.words
  | "sourceChannel" => [w.sourceChannelId]
  | "memberCount,delegateCount,tokenCount" => [w.memberCount, w.delegateCount, w.tokenCount]
  | "registry" => w.registry.values
  | "settledChain" => w.settledChain.words
  | "stateVersion" => w.stateVersion.words
  | "slot ciphertext digests" => w.slotEncDigests.values.bind Words8.words
  | "slot pending adds" => w.slotPendingAdds.values
  | "active sum" => [w.memberCount + w.delegateCount]
  | _ => []
/-- Wires allocated by a bare `add_virtual_target` / `PoseidonHashOutTarget::new`, which carry
    a Goldilocks value and no range gate: :398 (slot tree root), :372 (accumulator leaf index),
    :404 (receiver slot index), :446-449 (the four Regev polynomials). -/
def virtualWires (w : RawWitness) : String → List Nat
  | "slotRoot" => w.slotRoot.words
  | "incomingTxIndex" => [w.incomingIndex]
  | "receiverMemberIndex" => [w.receiverMemberIndex]
  | "a,b,c1,c2" => w.key.a ++ w.key.b ++ w.delta.c1 ++ w.delta.c2
  | _ => []
/-- Exact argument list of each hashing gadget call: :331-336, :338-344, :345-346, :349, :363
    (keccak wings / leaf / chain pushes), :410-421 with h1_gadget.rs:88-109 (IMB2 header),
    :460 with decryption_gadget.rs:611-625 (IMRP), :461-467 with h1_gadget.rs:134-150 (IMS2),
    :482 with decryption_gadget.rs:578-600 (IMRC), :505-509 (IMCK nullifier). -/
def hashPreimage (e : Environment) (w : RawWitness) : String → List Nat
  | "senderWing" => txWingPreimage w.sourcePkG w.senderDeltaDigest
  | "receiverWing" => txWingPreimage w.p.receiverPkG w.receiverDeltaDigest
  | "txLeaf" => (e.keccak (txWingPreimage w.sourcePkG w.senderDeltaDigest)).words ++
      (e.keccak (txWingPreimage w.p.receiverPkG w.receiverDeltaDigest)).words
  | "push(txRoot,leaf)" => pushPreimage w.txTreeRoot (txLeaf e w)
  | "push(ids,mixed)" => pushPreimage (txIds w) (push e w.txTreeRoot (txLeaf e w))
  | "IMB2" => (header w).words
  | "IMRP" => keyPreimage w.key
  | "IMS2" => (openedSlot e w).words
  | "IMRC" => ctPreimage w.delta
  | "IMCK" => nullifierPreimage w.p
  | _ => []
/-- Each `connect` / `assert_one` the constructor emits: :365 (recomputed tx hash), :426
    (recomputed H1), :439-440 (active <= MAX_CHANNEL_MEMBERS), :442-443 (opened slot is
    active), :483 (IMRC digest is the signed receiver-delta digest), :496-497 (amount limbs),
    :510 (shared native nullifier). -/
def ConnectHolds (e : Environment) (w : RawWitness) : String → Prop
  | "incomingTxHash" => recomputedTxHash e w = w.p.incomingTxHash
  | "finalH1" => recomputedH1 e w = w.p.finalBalanceStateH1
  | "active<1025" => lessThanU32 (w.memberCount + w.delegateCount) (maxSlots + 1) = true
  | "receiverMemberIndex<active" =>
      lessThanU32 w.receiverMemberIndex (w.memberCount + w.delegateCount) = true
  | "receiverDeltaDigest" => e.keccak (ctPreimage w.delta) = w.receiverDeltaDigest
  | "amount.hi,lo" => w.p.amount.hi = w.coreAmount.hi ∧ w.p.amount.lo = w.coreAmount.lo
  | "sharedNativeNullifier" => recomputedNullifier e w.p = w.p.sharedNativeNullifier
  | _ => True
/-- `IncrementalMerkleProofTarget::new` + `verify`. The sibling count is the proof shape
    (merkle_tree.rs:174-184), the index bound is `split_le index height`
    (merkle_tree.rs:227), the fold and the root equality are `get_root` + `connect_hash`
    (merkle_tree.rs:228-248). Accumulator wing :368-386 — `to_hash_out` at :376-378 also
    connects the Bytes32 round-trip, which is the canonical-root conjunct. Slot wing
    :468-477, whose leaf value is already the Poseidon leaf hash (identity `LeafableTarget`). -/
def MerkleHolds (e : Environment) (w : RawWitness) : String → Nat → Prop
  | "incoming: hash Bytes32 leaf, canonical PI root", height =>
      w.incomingSiblings.length = height ∧ (∀ s ∈ w.incomingSiblings, s.canonical) ∧
      w.incomingIndex < 2 ^ height ∧ CanonicalRoot w.p.finalAccumulatorRoot ∧
      accumulatorRoot e w = decodeHash w.p.finalAccumulatorRoot
  | "slot: Hash4 leaf identity", height =>
      w.slotSiblings.length = height ∧ (∀ s ∈ w.slotSiblings, s.canonical) ∧
      w.receiverMemberIndex < 2 ^ height ∧ slotRoot e w = w.slotRoot
  | _, _ => True
/-- `decryption_core(builder, inputs, expose_amount)`, :486-494. Locally it pins the four
    polynomial lengths (decryption_gadget.rs:219-222), pins every coefficient strictly below
    the Regev modulus (decryption_gadget.rs:230-236 via `assert_lt_q`), rejects the degenerate
    `a`/`c1` zero polynomials (decryption_gadget.rs:239-240) and relates the private core
    wires to the exposed amount limbs. The polynomial system behind that last relation is the
    named dependency `Environment.decryptionCore`, not something re-derived here. -/
def DecryptionHolds (e : Environment) (w : RawWitness) (exposeAmount : Bool) : Prop :=
  w.key.a.length = regevN ∧ w.key.b.length = regevN ∧
  w.delta.c1.length = regevN ∧ w.delta.c2.length = regevN ∧
  (∀ x ∈ w.key.a ++ w.key.b ++ w.delta.c1 ++ w.delta.c2, x < regevQ) ∧
  (∃ x ∈ w.key.a, x ≠ 0) ∧ (∃ x ∈ w.delta.c1, x ≠ 0) ∧
  (match exposeAmount with
   | true => e.decryptionCore w.key w.delta w.coreAssignment w.coreAmount
   | false => ∃ amount, e.decryptionCore w.key w.delta w.coreAssignment amount)

/-- What ONE builder call of `constructorProgram` enforces on the statement wires. A
    `range_check(t, bits)` batch bounds exactly its own wires; a `add_virtual_target` only
    says the wire carries a Goldilocks value; a hashing gadget fixes the width of its
    argument list (a mismatch is a build-time panic, not a provable circuit) while its output
    is the `Environment` callback applied to that list, so nothing further is asserted; a
    `build` call constrains no wire. -/
def OpHolds (e : Environment) (op : BuildOp) (w : RawWitness) : Prop :=
  match op with
  | .range name count bits =>
      (rangeWires w name).length = count ∧ ∀ x ∈ rangeWires w name, x < 2 ^ bits
  | .virtual name count =>
      (virtualWires w name).length = count ∧ ∀ x ∈ virtualWires w name, x < goldilocks
  | .hash name words => (hashPreimage e w name).length = words
  | .connect name => ConnectHolds e w name
  | .merkle name height => MerkleHolds e w name height
  | .decryption exposeAmount => DecryptionHolds e w exposeAmount
  | .register count => w.p.words.length = count
  | .build _ => True
def BuildOp.holds {e : Environment} (op : BuildOp) (a : Assignment e) : Prop :=
  OpHolds e op (readWitness a)
def ProgramSatisfied {e : Environment} (prog : List BuildOp) (a : Assignment e) : Prop :=
  ∀ op ∈ prog, op.holds a

theorem forall_mem_cons_iff {α : Type} {p : α → Prop} {x : α} {xs : List α} :
    (∀ y ∈ x :: xs, p y) ↔ p x ∧ ∀ y ∈ xs, p y := by
  constructor
  · intro h
    exact ⟨h x (List.mem_cons_self _ _), fun y hy => h y (List.mem_cons_of_mem _ hy)⟩
  · intro h y hy
    rcases List.mem_cons.mp hy with rfl | hy
    · exact h.1
    · exact h.2 y hy
theorem forall_mem_nil_iff {α : Type} {p : α → Prop} :
    (∀ y ∈ ([] : List α), p y) ↔ True :=
  ⟨fun _ => trivial, fun _ y hy => absurd hy (List.not_mem_nil y)⟩
theorem checked_words_append {xs ys : List Nat} (hx : checkedWords xs) (hy : checkedWords ys) :
    checkedWords (xs ++ ys) := by
  intro v hv
  rcases List.mem_append.mp hv with h | h
  · exact hx v h
  · exact hy v h

/-- THE gate-lowering reduction, on the statement wires. Every field of `ConstructorGates` is
    derived from the local propositions of the individual builder calls; no field needs an
    extra hypothesis, so `ConstructorGates` adds nothing beyond `constructorProgram`. -/
theorem constructor_program_ops_imply_gates (e : Environment) (w : RawWitness)
    (h : ∀ op ∈ constructorProgram, OpHolds e op w) : ConstructorGates e w := by
  simp only [constructorProgram, publicAllocationProgram, List.cons_append, List.nil_append,
    forall_mem_cons_iff, forall_mem_nil_iff, and_true] at h
  obtain ⟨rCloseIntent, rChannel, rIncoming, rPk, rRecipient, rNullifier, rAmount, rH1, rAcc,
    rToken, rPrivate, rSourceChannel, _hSenderWing, _hReceiverWing, _hTxLeaf, _hPushRoot,
    _hPushIds, cTx, _vIncomingIndex, mIncoming, rCounts, rRegistry, vSlotRoot, rSettled,
    rVersion, _vIndex, rEnc, rAdds, _hImb2, cH1, rActive, cActiveMax, cActiveSlot, _vPoly,
    _hImrp, _hIms2, mSlot, _hImrc, cCt, dCore, cAmount, _hImck, cNullifier, _reg, _bld⟩ := h
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact checked_words_append (checked_words_append (checked_words_append
      (checked_words_append (checked_words_append (checked_words_append
      (checked_words_append (checked_words_append (checked_words_append
        rCloseIntent.2 rChannel.2) rIncoming.2) rPk.2) rRecipient.2) rNullifier.2)
        rAmount.2) rH1.2) rAcc.2) rToken.2
  · exact checked_words_append (checked_words_append (checked_words_append
      (checked_words_append (checked_words_append (checked_words_append rPrivate.2
        (checked_words_append rSourceChannel.2 rCounts.2)) rRegistry.2) rSettled.2)
        rVersion.2) rEnc.2) rAdds.2
  · refine ⟨vSlotRoot.2, ?_⟩
    intro s hs
    rcases List.mem_append.mp hs with hm | hm
    · exact mIncoming.2.1 s hm
    · exact mSlot.2.1 s hm
  · exact ⟨dCore.1, dCore.2.1, dCore.2.2.1, dCore.2.2.2.1⟩
  · exact mIncoming.1
  · exact mIncoming.2.2.1
  · exact cTx
  · exact mIncoming.2.2.2.1
  · exact mIncoming.2.2.2.2
  · exact cH1
  · exact rActive.2 _ (List.mem_cons_self _ _)
  · exact cActiveMax
  · exact cActiveSlot
  · exact mSlot.1
  · exact mSlot.2.2.1
  · exact mSlot.2.2.2
  · exact cCt
  · exact dCore.2.2.2.2.2.2.2
  · exact cAmount.1
  · exact cAmount.2
  · exact cNullifier
theorem program_satisfied_implies_gates (e : Environment) (a : Assignment e)
    (h : ProgramSatisfied constructorProgram a) : ConstructorGates e (readWitness a) :=
  constructor_program_ops_imply_gates e (readWitness a) h
theorem read_witness_recovers_every_witness (e : Environment) (w : RawWitness) :
    readWitness (assignmentOf e w) = w := rfl
theorem registered_public_inputs_are_the_statement (e : Environment) (a : Assignment e) :
    registeredPublicInputs a = (readWitness a).p.words := rfl

/-- The obligation that remains after the reduction: the actual Plonky2 constraint system
    admits only assignments that satisfy every primitive of `constructorProgram`, with the
    statement read back through the source's wire order. This is strictly per-primitive
    (range gates, virtual allocation, gadget argument widths, connects, the two Merkle
    verifies, the decryption core) plus the digest/domain-constant pinning already named as a
    boundary; it is never instantiated here. -/
def PrimitiveLowering (e : Environment) (actual : RawWitness → Prop) : Prop :=
  ∀ w, actual w → ∃ a : Assignment e, ProgramSatisfied constructorProgram a ∧ readWitness a = w
theorem primitive_lowering_implies_field_and_gadget_lowering (e : Environment)
    (actual : RawWitness → Prop) (h : PrimitiveLowering e actual) :
    FieldAndGadgetLowering actual e := by
  intro w hw
  obtain ⟨a, prog, read⟩ := h w hw
  have gates := program_satisfied_implies_gates e a prog
  rwa [read] at gates
theorem primitive_lowering_iff_every_primitive_holds (e : Environment)
    (actual : RawWitness → Prop) :
    PrimitiveLowering e actual ↔ ∀ w, actual w → ∀ op ∈ constructorProgram, OpHolds e op w := by
  constructor
  · intro h w hw op hop
    obtain ⟨a, prog, read⟩ := h w hw
    have single : OpHolds e op (readWitness a) := prog op hop
    rwa [read] at single
  · intro h w hw
    refine ⟨assignmentOf e w, fun op hop => ?_, read_witness_recovers_every_witness e w⟩
    show OpHolds e op (readWitness (assignmentOf e w))
    rw [read_witness_recovers_every_witness e w]
    exact h w hw op hop
theorem gate_lowering_needs_no_extra_environment_hypothesis (e : Environment)
    (a : Assignment e) (h : ∀ op ∈ constructorProgram, OpHolds e op (readWitness a)) :
    ConstructorGates e (readWitness a) :=
  constructor_program_ops_imply_gates e (readWitness a) h

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

/-! ### The same normal witness satisfies every modeled primitive

Local satisfiability of the per-primitive program, so the gate-lowering reduction above is not
vacuous. Still only the modeled relations with stub dependencies: not a production proof run,
not a claim that these all-zero digests are real keccak/Poseidon outputs. -/

theorem normal_polynomial_length : normalPolynomial.length = regevN := by
  simp [normalPolynomial, regevN]
theorem normal_polynomial_coefficients_are_small (x : Nat) (h : x ∈ normalPolynomial) :
    x < regevQ := by
  rcases List.mem_cons.mp h with rfl | hr
  · decide
  · have hz : x = 0 := List.eq_of_mem_replicate hr
    subst hz
    decide
theorem normal_polynomial_coefficients_are_field_elements (x : Nat) (h : x ∈ normalPolynomial) :
    x < goldilocks :=
  Nat.lt_trans (normal_polynomial_coefficients_are_small x h) (by decide)
theorem normal_polynomial_is_nonzero : ∃ x ∈ normalPolynomial, x ≠ 0 :=
  ⟨1, List.mem_cons_self _ _, by decide⟩
theorem normal_polynomial_quadruple (x : Nat)
    (h : x ∈ normalPolynomial ++ normalPolynomial ++ normalPolynomial ++ normalPolynomial) :
    x ∈ normalPolynomial := by
  rcases List.mem_append.mp h with h | h
  · rcases List.mem_append.mp h with h | h
    · rcases List.mem_append.mp h with h | h
      · exact h
      · exact h
    · exact h
  · exact h
theorem normal_polynomial_quadruple_length :
    (normalPolynomial ++ normalPolynomial ++ normalPolynomial ++ normalPolynomial).length =
      4 * regevN := by
  simp only [List.length_append, normal_polynomial_length]
  omega
theorem normal_key_preimage_length : (keyPreimage normalRaw.key).length = 2 + 2 * regevN := by
  show ([imrp, regevN] ++ normalPolynomial ++ normalPolynomial).length = 2 + 2 * regevN
  simp only [List.length_append, List.length_cons, List.length_nil, normal_polynomial_length]
  omega
theorem normal_ciphertext_preimage_length :
    (ctPreimage normalRaw.delta).length = 2 + 2 * regevN := by
  show ([imrc, regevN] ++ normalPolynomial ++ normalPolynomial).length = 2 + 2 * regevN
  simp only [List.length_append, List.length_cons, List.length_nil, normal_polynomial_length]
  omega

set_option maxRecDepth 8192 in
theorem normal_witness_satisfies_every_primitive :
    ∀ op ∈ constructorProgram, OpHolds normalEnvironment op normalRaw := by
  simp only [constructorProgram, publicAllocationProgram, List.cons_append, List.nil_append,
    forall_mem_cons_iff, forall_mem_nil_iff, and_true]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact tx_wing_has_exact_17_words _ _
  · exact tx_wing_has_exact_17_words _ _
  · rfl
  · exact chain_push_has_exact_17_words _ _
  · exact chain_push_has_exact_17_words _ _
  · rfl
  · exact ⟨rfl, by decide⟩
  · refine ⟨by simp [normalRaw], ?_, by decide, rfl, merkle_zero_stub _ _⟩
    intro s hs
    have hz : s = Hash4.zero := List.eq_of_mem_replicate hs
    subst hz
    show ∀ x ∈ Hash4.zero.words, x < goldilocks
    decide
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact ⟨rfl, by decide⟩
  · exact header_has_exact_37_elements _
  · rfl
  · exact ⟨rfl, by decide⟩
  · rfl
  · rfl
  · refine ⟨normal_polynomial_quadruple_length, ?_⟩
    intro x hx
    exact normal_polynomial_coefficients_are_field_elements x (normal_polynomial_quadruple x hx)
  · exact normal_key_preimage_length
  · exact slot_has_exact_104_elements _
  · refine ⟨by simp [normalRaw], ?_, by decide, merkle_zero_stub _ _⟩
    intro s hs
    have hz : s = Hash4.zero := List.eq_of_mem_replicate hs
    subst hz
    show ∀ x ∈ Hash4.zero.words, x < goldilocks
    decide
  · exact normal_ciphertext_preimage_length
  · rfl
  · refine ⟨normal_polynomial_length, normal_polynomial_length, normal_polynomial_length,
      normal_polynomial_length, ?_, normal_polynomial_is_nonzero, normal_polynomial_is_nonzero,
      ⟨rfl, rfl, rfl⟩⟩
    intro x hx
    exact normal_polynomial_coefficients_are_small x (normal_polynomial_quadruple x hx)
  · exact ⟨rfl, rfl⟩
  · exact nullifier_preimage_has_exact_25_words _
  · rfl
  · exact exact_public_input_count normalRaw
  · trivial

def normalAssignment : Assignment normalEnvironment := assignmentOf normalEnvironment normalRaw
theorem example_program_reads_back : readWitness normalAssignment = normalRaw := rfl
theorem example_program_satisfiable :
    ∃ a : Assignment normalEnvironment, ProgramSatisfied constructorProgram a :=
  ⟨normalAssignment, fun op hop => by
    show OpHolds normalEnvironment op (readWitness normalAssignment)
    rw [example_program_reads_back]
    exact normal_witness_satisfies_every_primitive op hop⟩
/-- The lowering reduction applied to the normal example: the per-primitive propositions alone
    already re-derive the full hand-written gate predicate. -/
theorem normal_program_reproduces_the_gate_predicate :
    ConstructorGates normalEnvironment normalRaw :=
  constructor_program_ops_imply_gates normalEnvironment normalRaw
    normal_witness_satisfies_every_primitive

end Zkp.Implementation.PostCloseClaimCircuit
