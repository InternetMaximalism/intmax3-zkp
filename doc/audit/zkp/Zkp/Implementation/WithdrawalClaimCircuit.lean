import Zkp.Implementation.CloseCircuit

/-!
# WithdrawalClaimCircuit: actual constructor and native filling

Handwritten source semantics of withdrawal_claim_circuit.rs (1427 lines), plus
explicit direct-dependency interfaces. NOT Rust/Plonky2 compiler refinement.
All Nat wires are integer representatives; FieldLowering is the unresolved
primitive gate/arithmetic interpretation, not an assumption of asset safety.

The callee checks H1 recomputation, active participant bound, canonical token
selection, a full slot leaf opening, Regev digest/decryption calls, and IMW2.
It does NOT verify a channel signature, finalize a close, link the close id to H1,
enforce burn highwater, or consume a nullifier. member_pk_g is informational.
token_count is u32 but has no <=10 check here; there is no registry uniqueness,
zero-padding, or member-count floor check here. The selected slot IS <10 and
<token_count. The native fill entry itself only checks member_index<1024 before
assignments, then calls the decryption witness builder; it does NOT call the
stronger WithdrawalClaimWitness::to_public_inputs admission helper.

Poseidon/Keccak assumptions below are finite compared-input obligations.
Merkle opening is scoped to one concrete committed tree, position and path;
there is no impossible global injectivity assumption for a finite hash.
The decryption core's detailed ring/digit proof remains a dependency boundary.
The amount theorem connects the caller's exact two limbs to that dependency,
not directly to an unproved ideal cryptographic decrypt function.
No source fixture or negative proof test is run or translated into constraints.
-/
namespace Zkp.Implementation.WithdrawalClaimCircuit

abbrev Words2 := CloseCircuit.Words2
abbrev Words8 := CloseCircuit.Words8
abbrev Root := CloseCircuit.Hash4
def wordBase : Nat := 2^32
def maxParticipants : Nat := 1024
def maxTokens : Nat := 10
def treeHeight : Nat := 10
def regevN : Nat := 2048
def regevQ : Nat := 2013265921
def publicInputsLength : Nat := 50
def h1Domain : Nat := 0x494d4232
def slotDomain : Nat := 0x494d5332
def nullifierDomain : Nat := 0x494d5732
def ctDomain : Nat := 0x494d5243
def pkDomain : Nat := 0x494d5250

structure Address where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr
def Address.words (a : Address) : List Nat := [a.a0,a.a1,a.a2,a.a3,a.a4]

structure PublicInputs where
  closeId : Words8
  channelId : Nat
  h1 : Words8
  memberPk : Words8
  recipient : Address
  ciphertextDigest : Words8
  nullifier : Words8
  amount : Words2
  tokenSlot : Nat
  tokenIndex : Nat
  deriving DecidableEq, Repr

def PublicInputs.words (p : PublicInputs) : List Nat :=
  p.closeId.words ++ [p.channelId] ++ p.h1.words ++ p.memberPk.words ++ p.recipient.words ++
  p.ciphertextDigest.words ++ p.nullifier.words ++ p.amount.words ++ [p.tokenSlot,p.tokenIndex]

def Checked (xs : List Nat) : Prop := ∀ x ∈ xs, x < wordBase
def PublicInputs.AllocationChecks (p : PublicInputs) : Prop := Checked p.words

theorem public_input_width_is_50 (p : PublicInputs) : p.words.length = publicInputsLength := by
  simp [PublicInputs.words,CloseCircuit.Words8.words,CloseCircuit.Words2.words,
    Address.words,publicInputsLength]

def readPublicFields (xs : List Nat) : PublicInputs := {
  closeId := CloseCircuit.Words8.read xs 0
  channelId := xs.getD 8 0
  h1 := CloseCircuit.Words8.read xs 9
  memberPk := CloseCircuit.Words8.read xs 17
  recipient := ⟨xs.getD 25 0,xs.getD 26 0,xs.getD 27 0,xs.getD 28 0,xs.getD 29 0⟩
  ciphertextDigest := CloseCircuit.Words8.read xs 30
  nullifier := CloseCircuit.Words8.read xs 38
  amount := CloseCircuit.Words2.read xs 46
  tokenSlot := xs.getD 48 0
  tokenIndex := xs.getD 49 0 }

set_option maxRecDepth 2048 in
/-- Proof-only decoder: source target type has no from_slice method. This
    utility proves to_vec injective; native from_u64_slice is another file. -/
theorem read_public_encoding (p : PublicInputs) : readPublicFields p.words = p := by
  simp only [PublicInputs.words,CloseCircuit.Words8.words,CloseCircuit.Words2.words,
    Address.words,List.append_assoc,List.singleton_append,List.cons_append,List.nil_append]
  unfold readPublicFields CloseCircuit.Words8.read CloseCircuit.Words2.read
  cases p
  rfl

theorem public_encoding_injective {p q : PublicInputs} (equal : p.words = q.words) : p = q := by
  have := congrArg readPublicFields equal
  simpa only [read_public_encoding] using this

abbrev Ten (α : Type) := Fin 10 → α
def tenList {α : Type} (xs : Ten α) : List α :=
  [xs 0,xs 1,xs 2,xs 3,xs 4,xs 5,xs 6,xs 7,xs 8,xs 9]
def digestRowWords (xs : Ten Words8) : List Nat :=
  (xs 0).words ++ (xs 1).words ++ (xs 2).words ++ (xs 3).words ++ (xs 4).words ++
  (xs 5).words ++ (xs 6).words ++ (xs 7).words ++ (xs 8).words ++ (xs 9).words
def totalRow {α : Type} (xs : Ten α) (fallback : α) (i : Nat) : α :=
  if h : i < 10 then xs ⟨i,h⟩ else fallback

structure Header where
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : Ten Nat
  slotRoot : Root
  settledChain : Words8
  accumulatorRoot : Words8
  stateVersion : Words2

structure Polynomials where
  a : List Nat
  b : List Nat
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr

structure Witness (Path Core : Type) where
  header : Header
  memberIndex : Nat
  ciphertexts : Ten Words8
  pendingAdds : Ten Nat
  path : Path
  polynomials : Polynomials
  core : Core

def headerPreimage (channel : Nat) (h : Header) : List Nat :=
  [h1Domain,channel,h.memberCount,h.delegateCount,h.tokenCount] ++ tenList h.registry ++
  h.slotRoot.words ++ h.settledChain.words ++ h.accumulatorRoot.words ++ h.stateVersion.words

def slotPreimage (pk : Words8) (row : Ten Words8) (pending : Ten Nat) (recipient : Address) : List Nat :=
  [slotDomain] ++ pk.words ++ digestRowWords row ++ tenList pending ++ recipient.words

def nullifierPreimage (closeId pk : Words8) (slot : Nat) : List Nat :=
  [nullifierDomain] ++ closeId.words ++ pk.words ++ [slot]

def pkPreimage (p : Polynomials) : List Nat := [pkDomain,regevN] ++ p.a ++ p.b
def ctPreimage (p : Polynomials) : List Nat := [ctDomain,regevN] ++ p.c1 ++ p.c2

theorem header_preimage_width (channel : Nat) (h : Header) : (headerPreimage channel h).length = 37 := by
  simp [headerPreimage,tenList,CloseCircuit.Hash4.words,CloseCircuit.Words8.words,CloseCircuit.Words2.words]

theorem full_slot_preimage_width (pk : Words8) (row : Ten Words8) (pending : Ten Nat) (a : Address) :
    (slotPreimage pk row pending a).length = 104 := by
  simp [slotPreimage,digestRowWords,tenList,Address.words,CloseCircuit.Words8.words]

theorem nullifier_preimage_width (closeId pk : Words8) (slot : Nat) :
    (nullifierPreimage closeId pk slot).length = 18 := by
  simp [nullifierPreimage,CloseCircuit.Words8.words]

def bit (b : Bool) : Nat := if b then 1 else 0
def bitsValue : List Bool → Nat
  | [] => 0
  | b::bs => bit b + 2 * bitsValue bs
def bitCount : List Bool → Nat
  | [] => 0
  | b::bs => bit b + bitCount bs

theorem packed_bits_bound (bs : List Bool) : bitsValue bs < 2^bs.length := by
  induction bs with
  | nil => simp [bitsValue]
  | cons b bs ih =>
    cases b <;> simp only [bitsValue,bit,Bool.false_eq_true,if_false,if_true,List.length_cons,Nat.pow_succ] <;> omega

theorem packed_bits_zero_iff_bit_sum_zero (bs : List Bool) : bitsValue bs = 0 ↔ bitCount bs = 0 := by
  induction bs with
  | nil => simp [bitsValue,bitCount]
  | cons b bs ih =>
    cases b <;> simp only [bitsValue,bitCount,bit,if_true,Bool.false_eq_true,if_false] <;> omega

structure Comparison33 (a b : Nat) where
  lowBits : List Bool
  topBit : Bool
  lowLength : lowBits.length = 32
  equation : b + wordBase = a + bitsValue lowBits + wordBase * bit topBit

def comparisonResult {a b : Nat} (w : Comparison33 a b) : Bool :=
  w.topBit && !(decide (bitCount w.lowBits = 0))

/-- The helper result is derived from its33-bit decomposition and sum-of-bits
    zero test. Lifting modular builder operations to equation is separate. -/
theorem comparison_result_iff_strict_less {a b : Nat} (w : Comparison33 a b) :
    comparisonResult w = true ↔ a < b := by
  have low : bitsValue w.lowBits < wordBase := by
    simpa [w.lowLength,wordBase] using packed_bits_bound w.lowBits
  have zero := packed_bits_zero_iff_bit_sum_zero w.lowBits
  have eq := w.equation
  cases top : w.topBit <;> simp [comparisonResult,top] <;> simp [top,bit] at eq <;> omega

def oneHotSum (slot : Nat) : Nat → Nat
  | 0 => 0
  | n+1 => oneHotSum slot n + if slot = n then 1 else 0

def selectLoop {α : Type} (slot : Nat) (row : Nat → α) (initial : α) : Nat → α
  | 0 => initial
  | n+1 => if slot = n then row n else selectLoop slot row initial n

theorem equality_flag_sum (slot n : Nat) : oneHotSum slot n = if slot < n then 1 else 0 := by
  induction n with
  | zero =>
    have h : ¬ slot < 0 := by omega
    simp [oneHotSum,h]
  | succ n ih =>
    by_cases equal : slot = n
    · subst slot
      simp [oneHotSum,ih]
    · by_cases lt : slot < n
      · simp [oneHotSum,ih,equal,lt,Nat.lt_succ_of_lt lt]
      · have out : ¬ slot < n+1 := by omega
        simp [oneHotSum,ih,equal,lt,out]

theorem one_hot_connection_forces_exact_slot_range (slot : Nat) :
    oneHotSum slot maxTokens = 1 ↔ slot < 10 := by
  rw [equality_flag_sum]
  by_cases h : slot < 10 <;> simp [maxTokens,h]

theorem select_loop_selects_exact_exposed_slot {α : Type} (slot n : Nat)
    (row : Nat → α) (initial : α) :
    selectLoop slot row initial n = if slot < n then row slot else initial := by
  induction n with
  | zero =>
    have h : ¬ slot < 0 := by omega
    simp [selectLoop,h]
  | succ n ih =>
    by_cases equal : slot = n
    · subst slot
      simp [selectLoop]
    · by_cases lt : slot < n
      · simp [selectLoop,ih,equal,lt,Nat.lt_succ_of_lt lt]
      · have out : ¬ slot < n+1 := by omega
        simp [selectLoop,ih,equal,lt,out]

structure Environment (Path Core : Type) where
  poseidonWords : List Nat → Words8
  poseidonRoot : List Nat → Root
  keccak : List Nat → Words8
  inclusion : Root → Nat → Path → Root → Prop
  decryption : Polynomials → Core → Nat → Nat → Prop

def computedPk {Path Core : Type} (e : Environment Path Core) (w : Witness Path Core) : Words8 :=
  e.poseidonWords (pkPreimage w.polynomials)

def selectedDigest {Path Core : Type} (p : PublicInputs) (w : Witness Path Core) : Words8 :=
  selectLoop p.tokenSlot (totalRow w.ciphertexts CloseCircuit.Words8.zero) CloseCircuit.Words8.zero 10
def selectedToken {Path Core : Type} (p : PublicInputs) (w : Witness Path Core) : Nat :=
  selectLoop p.tokenSlot (totalRow w.header.registry 0) 0 10

/-- Individual range checks and dependency calls; no structural H1/finalization
    truth is assumed. Header root is raw4 field words, not four checkedu32. -/
structure CircuitGates {Path Core : Type} (e : Environment Path Core)
    (p : PublicInputs) (w : Witness Path Core) : Prop where
  publicRanges : PublicInputs.AllocationChecks p
  privateRanges : Checked ([w.header.memberCount,w.header.delegateCount,w.header.tokenCount] ++
    tenList w.header.registry ++ w.header.settledChain.words ++ w.header.accumulatorRoot.words ++
    w.header.stateVersion.words ++ digestRowWords w.ciphertexts ++ tenList w.pendingAdds)
  h1Connect : e.poseidonWords (headerPreimage p.channelId w.header) = p.h1
  activeBits : w.header.memberCount + w.header.delegateCount < 2^11
  activeCompare : ∃ c : Comparison33 (w.header.memberCount+w.header.delegateCount) (maxParticipants+1),
    comparisonResult c = true
  memberCompare : ∃ c : Comparison33 w.memberIndex (w.header.memberCount+w.header.delegateCount),
    comparisonResult c = true
  oneHot : oneHotSum p.tokenSlot maxTokens = 1
  tokenCompare : ∃ c : Comparison33 p.tokenSlot w.header.tokenCount, comparisonResult c = true
  selectedCiphertext : selectedDigest p w = p.ciphertextDigest
  selectedBaseToken : selectedToken p w = p.tokenIndex
  polyShape : w.polynomials.a.length = regevN ∧ w.polynomials.b.length = regevN ∧
    w.polynomials.c1.length = regevN ∧ w.polynomials.c2.length = regevN
  ctConnect : e.keccak (ctPreimage w.polynomials) = p.ciphertextDigest
  inclusionCall : e.inclusion
    (e.poseidonRoot (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient))
    w.memberIndex w.path w.header.slotRoot
  merkleIndexBits : w.memberIndex < 2^treeHeight
  amountConnect : e.decryption w.polynomials w.core p.amount.lo p.amount.hi
  nullifierConnect : e.keccak (nullifierPreimage p.closeId (computedPk e w) p.tokenSlot) = p.nullifier

/-- Only primitive constructor-gate lowering, explicitly unresolved. -/
def FieldLowering {Path Core Raw : Type} (e : Environment Path Core)
    (accepts : Raw → PublicInputs → Witness Path Core → Prop) : Prop :=
  ∀ raw p w, accepts raw p w → CircuitGates e p w

theorem active_region_is_bounded {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w) :
    w.memberIndex < w.header.memberCount+w.header.delegateCount ∧
    w.header.memberCount+w.header.delegateCount ≤ 1024 ∧ w.memberIndex < 1024 := by
  obtain ⟨ac,ha⟩ := g.activeCompare
  obtain ⟨mc,hm⟩ := g.memberCompare
  have a := (comparison_result_iff_strict_less ac).mp ha
  have m := (comparison_result_iff_strict_less mc).mp hm
  simp only [maxParticipants] at a
  omega

theorem token_slot_is_active_and_local {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w) :
    p.tokenSlot < 10 ∧ p.tokenSlot < w.header.tokenCount := by
  obtain ⟨c,hc⟩ := g.tokenCompare
  exact ⟨(one_hot_connection_forces_exact_slot_range _).mp g.oneHot,
    (comparison_result_iff_strict_less c).mp hc⟩

theorem selected_payment_asset_and_ciphertext {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w) :
    ∃ i : Fin 10, i.val = p.tokenSlot ∧ w.header.registry i = p.tokenIndex ∧
      w.ciphertexts i = p.ciphertextDigest := by
  have range := (token_slot_is_active_and_local g).1
  refine ⟨⟨p.tokenSlot,range⟩,rfl,?_,?_⟩
  · simpa [selectedToken,select_loop_selects_exact_exposed_slot,range,totalRow] using g.selectedBaseToken
  · simpa [selectedDigest,select_loop_selects_exact_exposed_slot,range,totalRow] using g.selectedCiphertext

theorem amount_public_value_is_u64 {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w) :
    p.amount.value < 2^64 := by
  have high := g.publicRanges p.amount.hi (by simp [PublicInputs.words,CloseCircuit.Words2.words])
  have low := g.publicRanges p.amount.lo (by simp [PublicInputs.words,CloseCircuit.Words2.words])
  simp only [CloseCircuit.Words2.value,CloseCircuit.wordBase,wordBase] at *
  omega

/-- A scoped contract for the imported core's output, not ideal decrypt
    correctness or encryption uniqueness. The core's decoded integer is an
    explicit function of its actual witnessed input/normalization equations. -/
def CoreOutputAt {Path Core : Type} (e : Environment Path Core)
    (decoded : Polynomials → Core → Nat) (w : Witness Path Core) (lo hi : Nat) : Prop :=
  e.decryption w.polynomials w.core lo hi →
    decoded w.polynomials w.core = hi * wordBase + lo

theorem amount_equals_the_core_output {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w)
    (decoded : Polynomials → Core → Nat)
    (core : CoreOutputAt e decoded w p.amount.lo p.amount.hi) :
    p.amount.value = decoded w.polynomials w.core := by
  exact (core g.amountConnect).symm

theorem nullifier_uses_same_selected_slot_and_leaf_key {Path Core : Type}
    {e : Environment Path Core} {p : PublicInputs} {w : Witness Path Core}
    (g : CircuitGates e p w) :
    p.nullifier = e.keccak (nullifierPreimage p.closeId (computedPk e w) p.tokenSlot) :=
  g.nullifierConnect.symm

theorem same_nullifier_inputs_have_same_output {Path Core : Type} {e : Environment Path Core}
    {p q : PublicInputs} {w v : Witness Path Core} (gp : CircuitGates e p w) (gq : CircuitGates e q v)
    (close : p.closeId = q.closeId) (key : computedPk e w = computedPk e v)
    (slot : p.tokenSlot = q.tokenSlot) : p.nullifier = q.nullifier := by
  rw [nullifier_uses_same_selected_slot_and_leaf_key gp,
    nullifier_uses_same_selected_slot_and_leaf_key gq,close,key,slot]

/-- Representation injectivity, not hash injectivity. -/
theorem nullifier_preimage_binds_close_key_and_token {c d k l : Words8} {t u : Nat}
    (equal : nullifierPreimage c k t = nullifierPreimage d l u) : c = d ∧ k = l ∧ t = u := by
  simp only [nullifierPreimage,List.append_assoc,List.singleton_append,List.cons.injEq,true_and] at equal
  have first := List.append_inj equal (by simp [CloseCircuit.Words8.words])
  have second := List.append_inj first.2 (by simp [CloseCircuit.Words8.words])
  exact ⟨CloseCircuit.words8_encoding_is_injective (by simpa using first.1),
    CloseCircuit.words8_encoding_is_injective second.1,by simpa using second.2⟩

def HashBindingAt {α β : Type} (hash : α → β) (a b : α) : Prop := hash a = hash b → a = b

theorem h1_connection_authenticates_the_compared_header {Path Core : Type}
    {e : Environment Path Core} {p : PublicInputs} {w : Witness Path Core}
    (g : CircuitGates e p w) (channel : Nat) (committed : Header)
    (publicHead : p.h1 = e.poseidonWords (headerPreimage channel committed))
    (binding : HashBindingAt e.poseidonWords (headerPreimage p.channelId w.header)
      (headerPreimage channel committed)) :
    headerPreimage p.channelId w.header = headerPreimage channel committed := by
  exact binding (g.h1Connect.trans publicHead)

/-- The source H1 prefix and registry/root slices have fixed widths. This
    lemma is representation binding, not Poseidon collision resistance. -/
theorem header_preimage_binds_identity_registry_and_root {channel other : Nat} {a b : Header}
    (equal : headerPreimage channel a = headerPreimage other b) :
    channel = other ∧ a.memberCount = b.memberCount ∧ a.delegateCount = b.delegateCount ∧
    a.tokenCount = b.tokenCount ∧ tenList a.registry = tenList b.registry ∧
    a.slotRoot.words = b.slotRoot.words := by
  simp only [headerPreimage,List.append_assoc] at equal
  have leading := List.append_inj equal (by rfl)
  have registry := List.append_inj leading.2 (by simp [tenList])
  have root := List.append_inj registry.2 (by simp [CloseCircuit.Hash4.words])
  have identities : channel = other ∧ a.memberCount = b.memberCount ∧
      a.delegateCount = b.delegateCount ∧ a.tokenCount = b.tokenCount := by
    simpa only [List.cons.injEq,true_and,and_true] using leading.1
  exact ⟨identities.1,identities.2.1,identities.2.2.1,identities.2.2.2,registry.1,root.1⟩

theorem equal_nullifiers_bind_exact_claim_domain {Path Core : Type} {e : Environment Path Core}
    {p q : PublicInputs} {w v : Witness Path Core} (gp : CircuitGates e p w) (gq : CircuitGates e q v)
    (same : p.nullifier = q.nullifier)
    (binding : HashBindingAt e.keccak (nullifierPreimage p.closeId (computedPk e w) p.tokenSlot)
      (nullifierPreimage q.closeId (computedPk e v) q.tokenSlot)) :
    p.closeId = q.closeId ∧ computedPk e w = computedPk e v ∧ p.tokenSlot = q.tokenSlot := by
  apply nullifier_preimage_binds_close_key_and_token
  apply binding
  exact gp.nullifierConnect.trans (same.trans gq.nullifierConnect.symm)

/-- This explicit tuple contains no member_pk_g, amount or recipient. Their
    other constraints remain necessary; nullifier derivation does not prove them. -/
theorem informational_member_key_not_in_nullifier_preimage (closeId pk : Words8) (slot : Nat)
    (p q : PublicInputs) (hc : p.closeId = closeId) (hd : q.closeId = closeId)
    (ht : p.tokenSlot = slot) (hu : q.tokenSlot = slot) :
    nullifierPreimage p.closeId pk p.tokenSlot = nullifierPreimage q.closeId pk q.tokenSlot := by
  rw [hc,hd,ht,hu]

structure Slot where
  pk : Words8
  ciphertexts : Ten Words8
  pendingAdds : Ten Nat
  recipient : Address

def Slot.preimage (s : Slot) : List Nat := slotPreimage s.pk s.ciphertexts s.pendingAdds s.recipient

theorem slot_preimage_binds_full_ciphertext_row {pk key : Words8} {row other : Ten Words8}
    {pending adds : Ten Nat} {a b : Address}
    (equal : slotPreimage pk row pending a = slotPreimage key other adds b) :
    pk = key ∧ digestRowWords row = digestRowWords other ∧ tenList pending = tenList adds ∧
      a.words = b.words := by
  simp only [slotPreimage,List.append_assoc] at equal
  have domain := List.append_inj equal (by rfl)
  have keys := List.append_inj domain.2 (by simp [CloseCircuit.Words8.words])
  have rows := List.append_inj keys.2 (by simp [digestRowWords,CloseCircuit.Words8.words])
  have counters := List.append_inj rows.2 (by simp [tenList])
  exact ⟨CloseCircuit.words8_encoding_is_injective keys.1,rows.1,counters.1,counters.2⟩

/-- Concrete opening obligation: this one root/tree/path/position. No universal
    finite-root injectivity assumption, no desired payout equality in premise. -/
def OpeningAt {Path Core : Type} (e : Environment Path Core) (root : Root)
    (leaves : Nat → Root) (index : Nat) (path : Path) (leaf : Root) : Prop :=
  e.inclusion leaf index path root → leaf = leaves index

theorem opened_leaf_hash_is_the_committed_position {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w) (leaves : Nat → Root)
    (opening : OpeningAt e w.header.slotRoot leaves w.memberIndex w.path
      (e.poseidonRoot (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient))) :
    e.poseidonRoot (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient) =
      leaves w.memberIndex := opening g.inclusionCall

theorem slot_preimage_binds_recipient {pk key : Words8} {row other : Ten Words8}
    {pending adds : Ten Nat} {a b : Address}
    (equal : slotPreimage pk row pending a = slotPreimage key other adds b) : a = b := by
  have suffix := congrArg (fun xs : List Nat => xs.drop 99) equal
  have read : ∀ pk row pending a, (slotPreimage pk row pending a).drop 99 = a.words := by
    intros
    simp [slotPreimage,digestRowWords,tenList,CloseCircuit.Words8.words,List.append_assoc,
      List.cons_append,List.nil_append]
  dsimp only at suffix
  rw [read,read] at suffix
  cases a
  cases b
  simpa [Address.words] using suffix

theorem recipient_matches_the_concrete_committed_leaf {Path Core : Type} {e : Environment Path Core}
    {p : PublicInputs} {w : Witness Path Core} (g : CircuitGates e p w) (slots : Nat → Slot)
    (opening : OpeningAt e w.header.slotRoot
      (fun i => e.poseidonRoot (slots i).preimage) w.memberIndex w.path
      (e.poseidonRoot (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient)))
    (binding : HashBindingAt e.poseidonRoot
      (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient)
      (slots w.memberIndex).preimage) :
    p.recipient = (slots w.memberIndex).recipient := by
  apply slot_preimage_binds_recipient
  exact binding (opening g.inclusionCall)

theorem all_leaf_fields_match_the_concrete_committed_slot {Path Core : Type}
    {e : Environment Path Core} {p : PublicInputs} {w : Witness Path Core}
    (g : CircuitGates e p w) (slots : Nat → Slot)
    (opening : OpeningAt e w.header.slotRoot
      (fun i => e.poseidonRoot (slots i).preimage) w.memberIndex w.path
      (e.poseidonRoot (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient)))
    (binding : HashBindingAt e.poseidonRoot
      (slotPreimage (computedPk e w) w.ciphertexts w.pendingAdds p.recipient)
      (slots w.memberIndex).preimage) :
    computedPk e w = (slots w.memberIndex).pk ∧
    digestRowWords w.ciphertexts = digestRowWords (slots w.memberIndex).ciphertexts ∧
    tenList w.pendingAdds = tenList (slots w.memberIndex).pendingAdds ∧
    p.recipient.words = (slots w.memberIndex).recipient.words := by
  exact slot_preimage_binds_full_ciphertext_row (binding (opening g.inclusionCall))

inductive Error where
  | memberIndexOutOfRange (index : Nat)
  | failedToProve (detail : String)
  deriving DecidableEq, Repr

/-- Panic is not converted into the source Result type. -/
inductive Fault where
  | returned (e : Error)
  | witnessAssignmentPanic
  deriving DecidableEq, Repr

structure FullWitness (Path : Type) where
  publicInputs : PublicInputs
  header : Header
  memberIndex : Nat
  ciphertexts : Ten Words8
  pendingAdds : Ten Nat
  path : Path
  polynomials : Polynomials
  secret : List Int

/-- Rust value-representation domain, not additional checks performed by fill.
    Raw target Witness above intentionally has a different admission domain. -/
def FullWitness.NativeWidths {Path : Type} (w : FullWitness Path) : Prop :=
  PublicInputs.AllocationChecks w.publicInputs ∧ w.publicInputs.tokenSlot < 256 ∧
  w.header.memberCount < 256 ∧ w.header.delegateCount < 65536 ∧ w.header.tokenCount < 256 ∧
  Checked (tenList w.header.registry ++ w.header.settledChain.words ++ w.header.accumulatorRoot.words ++
    w.header.stateVersion.words ++ digestRowWords w.ciphertexts ++ tenList w.pendingAdds ++
    w.polynomials.a ++ w.polynomials.b ++ w.polynomials.c1 ++ w.polynomials.c2) ∧
  (∀ s ∈ w.secret, -128 ≤ s ∧ s < 128)

/-- Individual assignment list deliberately retains zip truncation. Subsequent
    native core construction is the separate length/canonicality gate. -/
def polyAssignments (targets values : List Nat) : List (Nat × Nat) := targets.zip values

def publicWitnessAssignments (p : PublicInputs) : List Nat := p.words

inductive FillOp where
  | checkMemberIndex1024 | allocatePartial | setPublic | setMemberCount | setDelegateCount
  | setSlotRoot | setInclusionPath | setMemberIndex | setTokenCount | setTenRegistry
  | setTenCiphertexts | setTenCounters | setSettledChain | setAccumulator | setVersion
  | zipSetA | zipSetB | zipSetC1 | zipSetC2 | buildCoreFromSameFourPolynomialsAndSecret
  | fillCore | returnPartial
  deriving DecidableEq, Repr

def fillProgram : List FillOp :=
  [.checkMemberIndex1024,.allocatePartial,.setPublic,.setMemberCount,.setDelegateCount,
   .setSlotRoot,.setInclusionPath,.setMemberIndex,.setTokenCount,.setTenRegistry,
   .setTenCiphertexts,.setTenCounters,.setSettledChain,.setAccumulator,.setVersion,
   .zipSetA,.zipSetB,.zipSetC1,.zipSetC2,.buildCoreFromSameFourPolynomialsAndSecret,
   .fillCore,.returnPartial]

structure NativeEnvironment (Path Partial Core Proof : Type) where
  assignPublicHeaderAndLeaf : FullWitness Path → Except Fault Partial
  assignPolynomials : Partial → Polynomials → Except Fault Partial
  buildCore : Polynomials → List Int → Except Unit Core
  fillCore : Partial → Core → Except Fault Partial
  proveData : Partial → Except String Proof

def fillWitness {Path Partial Core Proof : Type} (e : NativeEnvironment Path Partial Core Proof)
    (w : FullWitness Path) : Except Fault Partial := do
  if w.memberIndex ≥ maxParticipants then
    throw (.returned (.memberIndexOutOfRange w.memberIndex))
  let pw ← e.assignPublicHeaderAndLeaf w
  let pw ← e.assignPolynomials pw w.polynomials
  let core ← match e.buildCore w.polynomials w.secret with
    | .error _ => .error (.returned (.failedToProve
        "decryption-core witness build failed (inconsistent pk/sk/ct or out-of-budget noise)"))
    | .ok core => .ok core
  e.fillCore pw core

def prove {Path Partial Core Proof : Type} (e : NativeEnvironment Path Partial Core Proof)
    (w : FullWitness Path) : Except Fault Proof := do
  let pw ← fillWitness e w
  match e.proveData pw with
  | .error message => .error (.returned (.failedToProve message))
  | .ok proof => .ok proof

theorem native_out_of_capacity_stops_before_assignment {Path Partial Core Proof : Type}
    (e : NativeEnvironment Path Partial Core Proof) (w : FullWitness Path)
    (outside : w.memberIndex ≥ maxParticipants) :
    fillWitness e w = .error (.returned (.memberIndexOutOfRange w.memberIndex)) := by
  simp [fillWitness,outside,Bind.bind,Except.bind]

theorem native_success_requires_member_index_capacity {Path Partial Core Proof : Type}
    (e : NativeEnvironment Path Partial Core Proof) (w : FullWitness Path) (pw : Partial)
    (accepted : fillWitness e w = .ok pw) : w.memberIndex < maxParticipants := by
  by_cases inside : w.memberIndex < maxParticipants
  · exact inside
  · have := native_out_of_capacity_stops_before_assignment e w (by omega)
    rw [this] at accepted
    contradiction

theorem polynomial_assignment_count (targets values : List Nat) :
    (polyAssignments targets values).length = min targets.length values.length := by
  simp [polyAssignments]

theorem native_prove_uses_the_filled_witness {Path Partial Core Proof : Type}
    (e : NativeEnvironment Path Partial Core Proof) (w : FullWitness Path) (proof : Proof)
    (accepted : prove e w = .ok proof) :
    ∃ pw : Partial, fillWitness e w = .ok pw ∧ e.proveData pw = .ok proof := by
  cases filled : fillWitness e w with
  | error err => simp [prove,filled,Bind.bind,Except.bind] at accepted
  | ok pw =>
    cases proved : e.proveData pw with
    | error err => simp [prove,filled,proved,Bind.bind,Except.bind] at accepted
    | ok result =>
      simp only [prove,filled,proved,Bind.bind,Except.bind,Except.ok.injEq] at accepted
      subst result
      exact ⟨pw,rfl,proved⟩

/-- Macro order, not actual gate-count measurements. Profiling fields retain
    observation positions without fabricating numeric benchmarks. -/
inductive BuildOp where
  | zeroKnowledgeConfig
  | allocateCheckedPublic (field : Nat) (width : Nat)
  | allocateCheckedHeader
  | allocateRawRootAndMemberIndex
  | allocateTenCheckedCiphertextsAndCounters
  | observeInputs
  | recomputeH1
  | connectH1
  | activeSumAnd11Bits
  | compareActive1025
  | compareMemberActive
  | tenEqualityFlagsAndSumOne
  | compareTokenCount
  | selectEightCiphertextLimbs
  | selectBaseToken
  | observeHeaderSelectors
  | allocateFourPolynomials (length : Nat)
  | hashPkAndCiphertext
  | connectCiphertext
  | observeDigests
  | hashFullSlotLeaf
  | verifyInclusion (height : Nat)
  | observeInclusion
  | decryptExposeAmount
  | connectAmountHighThenLow
  | observeDecryption
  | deriveIMW2
  | connectNullifier
  | observeNullifier
  | registerPublic (width : Nat)
  | observeBeforePadding
  | buildCircuit
  deriving DecidableEq, Repr

def publicAllocationProgram : List BuildOp :=
  [.allocateCheckedPublic 0 8,.allocateCheckedPublic 1 1,.allocateCheckedPublic 2 8,
   .allocateCheckedPublic 3 8,.allocateCheckedPublic 4 5,.allocateCheckedPublic 5 8,
   .allocateCheckedPublic 6 8,.allocateCheckedPublic 7 2,.allocateCheckedPublic 8 1,
   .allocateCheckedPublic 9 1]

def constructorProgram : List BuildOp :=
  [.zeroKnowledgeConfig] ++ publicAllocationProgram ++
  [.allocateCheckedHeader,.allocateRawRootAndMemberIndex,.allocateTenCheckedCiphertextsAndCounters,
   .observeInputs,.recomputeH1,.connectH1,.activeSumAnd11Bits,.compareActive1025,.compareMemberActive,
   .tenEqualityFlagsAndSumOne,.compareTokenCount,.selectEightCiphertextLimbs,.selectBaseToken,
   .observeHeaderSelectors,.allocateFourPolynomials regevN,.hashPkAndCiphertext,.connectCiphertext,
   .observeDigests,.hashFullSlotLeaf,.verifyInclusion treeHeight,.observeInclusion,
   .decryptExposeAmount,.connectAmountHighThenLow,.observeDecryption,.deriveIMW2,.connectNullifier,
   .observeNullifier,.registerPublic publicInputsLength,.observeBeforePadding,.buildCircuit]

def defaultConstructor : List BuildOp := constructorProgram

structure Profile where
  inputs : Nat
  headerAndSelectors : Nat
  regevDigests : Nat
  slotInclusion : Nat
  decryption : Nat
  nullifier : Nat
  beforePadding : Nat
  deriving DecidableEq, Repr

theorem default_uses_exact_constructor : defaultConstructor = constructorProgram := rfl

theorem normal_token_selection : selectLoop 1 (fun i => if i = 1 then 7 else 0) 0 10 = 7 := by decide

theorem normal_active_delegate_slot : 2 < 2+1 ∧ 2+1 ≤ maxParticipants := by decide

theorem normal_per_token_nullifier_preimage :
    (nullifierPreimage CloseCircuit.Words8.zero CloseCircuit.Words8.zero 1).length = 18 :=
  nullifier_preimage_width _ _ _

end Zkp.Implementation.WithdrawalClaimCircuit
