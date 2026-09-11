import Zkp.Implementation.CloseCircuit

/-!
# WithdrawalClaimCircuit: actual constructor and native filling

Handwritten source semantics of withdrawal_claim_circuit.rs (1427 lines), plus
explicit direct-dependency interfaces. NOT Rust/Plonky2 compiler refinement.
All Nat wires are integer representatives; FieldLowering is the unresolved
primitive gate/arithmetic interpretation, not an assumption of asset safety.

GATE LOWERING (`BuildOp.holds` … `program_satisfied_implies_gates`): the builder
program transcribed from `WithdrawalClaimCircuit::new` is given one LOCAL
proposition per builder call, and every field of the hand-written `CircuitGates`
predicate is DERIVED from those local propositions alone — no extra premise
(`EnvironmentGates` is empty: no `CircuitGates` field needs one) and no weakening
of `CircuitGates`. `FieldLowering` therefore reduces to `PrimitiveLowering`
(`primitive_lowering_implies_field_lowering`), whose remaining, unproved content is
exactly (a) PER-PRIMITIVE: each plonky2 primitive really enforces the modeled local
relation on its wires — `range_check(t, 32)` bounds a limb, `connect` is equality,
`is_equal` yields a safe Boolean equality flag, `select` picks a limb,
`less_than_u32`'s `split_le` gives the 33-bit borrow equation, and the
`recompute_h1` / `regev_pk_poseidon_digest_gadget` / `regev_ct_digest_gadget` /
`balance_slot_leaf_hash_circuit` / `IncrementalMerkleProofTarget::verify` /
`decryption_core` / `keccak256` gadgets compute the callbacks of `Environment`;
and (b) DIGEST PINNING: the circuit whose proofs are accepted on-chain is the one
built by this constructor program. Neither is discharged here.

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

/-- Only primitive constructor-gate lowering, explicitly unresolved. Reduced below
    to `PrimitiveLowering` by `primitive_lowering_implies_field_lowering`. -/
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

/-! ## Gate lowering: the builder program read as local wire propositions

Each `BuildOp` of `constructorProgram` is given a LOCAL proposition on one
`Assignment` (the wire values of a single execution). `program_satisfied_implies_gates`
then derives the whole hand-written `CircuitGates` predicate from those local
propositions alone, so the `FieldLowering` gap shrinks to `PrimitiveLowering`:
"a real satisfying plonky2 assignment yields these wire values".
Source line numbers below refer to src/circuits/channel/withdrawal_claim_circuit.rs. -/

/-- The 33-bit borrow comparison wires of `less_than_u32` (src 701-721): the 32 low
    bits and the top bit of `split_le(b - a + 2^32, 33)`. `result` is
    `and(no_borrow, not(is_zero(low_sum)))` (src 713-720). -/
structure CompareWires where
  lowBits : List Bool
  topBit : Bool
  deriving DecidableEq, Repr

def CompareWires.result (c : CompareWires) : Bool :=
  c.topBit && !(decide (bitCount c.lowBits = 0))

/-- What the gadget plus its `connect`/`assert_one` enforce on the wires: the 33-bit
    split, the shifted-difference equation and the asserted result bit. -/
def CompareWires.Enforces (c : CompareWires) (a b : Nat) : Prop :=
  c.lowBits.length = 32 ∧
  b + wordBase = a + bitsValue c.lowBits + wordBase * bit c.topBit ∧
  c.result = true

theorem compare_wires_expose_comparison {c : CompareWires} {a b : Nat} (h : c.Enforces a b) :
    ∃ w : Comparison33 a b, comparisonResult w = true :=
  ⟨⟨c.lowBits,c.topBit,h.1,h.2.1⟩,by exact h.2.2⟩

theorem compare_wires_force_strict_less {c : CompareWires} {a b : Nat} (h : c.Enforces a b) :
    a < b := by
  obtain ⟨w,hw⟩ := compare_wires_expose_comparison h
  exact (comparison_result_iff_strict_less w).mp hw

/-- The accumulated `builder.select(flag t, row t, acc)` chain (src 419-424, 431-434):
    the last matching flag wins, the chain starts at the zero wire. -/
def selectChain {α : Type} (flag : Nat → Bool) (row : Nat → α) (initial : α) : Nat → α
  | 0 => initial
  | n+1 => if flag n = true then row n else selectChain flag row initial n

/-- The accumulated `flags_sum = builder.add(flags_sum, is_sel.target)` chain (src 399-402). -/
def flagSum (flag : Nat → Bool) : Nat → Nat
  | 0 => 0
  | n+1 => flagSum flag n + bit (flag n)

/-- `builder.is_equal(token_slot, t)` (src 400) is a safe Boolean equal to the
    equality test; that per-gate fact is a primitive obligation, not proved here. -/
def FlagsPinned (slot : Nat) (flag : Nat → Bool) (n : Nat) : Prop :=
  ∀ k, k < n → (flag k = true ↔ slot = k)

theorem flag_sum_is_one_hot_sum (slot : Nat) (flag : Nat → Bool) (n : Nat)
    (pinned : FlagsPinned slot flag n) : flagSum flag n = oneHotSum slot n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    have head := pinned n (Nat.lt_succ_self n)
    have rest : FlagsPinned slot flag n := fun k hk => pinned k (Nat.lt_succ_of_lt hk)
    by_cases h : slot = n
    · simp [flagSum,oneHotSum,ih rest,head.mpr h,h,bit]
    · have hf : flag n = false := by
        have neq : flag n ≠ true := fun hx => h (head.mp hx)
        simpa using neq
      simp [flagSum,oneHotSum,ih rest,hf,h,bit]

theorem select_chain_is_select_loop {α : Type} (slot : Nat) (flag : Nat → Bool)
    (row : Nat → α) (initial : α) (n : Nat) (pinned : FlagsPinned slot flag n) :
    selectChain flag row initial n = selectLoop slot row initial n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    have head := pinned n (Nat.lt_succ_self n)
    have rest : FlagsPinned slot flag n := fun k hk => pinned k (Nat.lt_succ_of_lt hk)
    by_cases h : slot = n
    · simp [selectChain,selectLoop,head.mpr h,h]
    · have hf : flag n = false := by
        have neq : flag n ≠ true := fun hx => h (head.mp hx)
        simpa using neq
      simp [selectChain,selectLoop,hf,h,ih rest]

/-- The wire values of ONE execution of `WithdrawalClaimCircuit::new`'s target set
    (src 306-546): the public-input targets (src 113-131), the witnessed header and
    slot targets (src 314-340), the four Regev polynomials and the decryption-core
    handle (src 451-503), plus every intermediate target the constructor creates
    (`recomputed_h1`, `active`, the three comparison bit vectors, the ten one-hot
    flags, `pk_digest`, `ct_digest`, `slot_leaf`, the exposed amount limbs and the
    keccak nullifier). Field elements are integer representatives. -/
structure Assignment {Path Core : Type} (e : Environment Path Core) where
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
  memberCount : Nat
  delegateCount : Nat
  tokenCount : Nat
  registry : Ten Nat
  slotRoot : Root
  settledChain : Words8
  accumulatorRoot : Words8
  stateVersion : Words2
  memberIndex : Nat
  ciphertexts : Ten Words8
  pendingAdds : Ten Nat
  path : Path
  polynomials : Polynomials
  core : Core
  active : Nat
  activeCompare : CompareWires
  memberCompare : CompareWires
  tokenCompare : CompareWires
  tokenFlags : Nat → Bool
  recomputedH1 : Words8
  pkDigest : Words8
  ctDigest : Words8
  slotLeaf : Root
  amountLo : Nat
  amountHi : Nat
  nullifierDigest : Words8

/-- Public-input wires in `to_vec` order (src 134-151). -/
def readPublic {Path Core : Type} {e : Environment Path Core} (a : Assignment e) : PublicInputs :=
  { closeId := a.closeId, channelId := a.channelId, h1 := a.h1, memberPk := a.memberPk,
    recipient := a.recipient, ciphertextDigest := a.ciphertextDigest, nullifier := a.nullifier,
    amount := a.amount, tokenSlot := a.tokenSlot, tokenIndex := a.tokenIndex }

/-- H1 header scalars in `recompute_h1` argument order (src 344-355). -/
def readHeader {Path Core : Type} {e : Environment Path Core} (a : Assignment e) : Header :=
  { memberCount := a.memberCount, delegateCount := a.delegateCount, tokenCount := a.tokenCount,
    registry := a.registry, slotRoot := a.slotRoot, settledChain := a.settledChain,
    accumulatorRoot := a.accumulatorRoot, stateVersion := a.stateVersion }

/-- Private wires in constructor allocation order (src 314-340, 451-503). -/
def readWitness {Path Core : Type} {e : Environment Path Core} (a : Assignment e) :
    Witness Path Core :=
  { header := readHeader a, memberIndex := a.memberIndex, ciphertexts := a.ciphertexts,
    pendingAdds := a.pendingAdds, path := a.path, polynomials := a.polynomials, core := a.core }

/-- The limb group each `allocateCheckedPublic` index range-checks (src 113-131,
    in `to_vec` order src 134-151). -/
def publicGroup {Path Core : Type} {e : Environment Path Core} (a : Assignment e) :
    Nat → List Nat
  | 0 => a.closeId.words
  | 1 => [a.channelId]
  | 2 => a.h1.words
  | 3 => a.memberPk.words
  | 4 => a.recipient.words
  | 5 => a.ciphertextDigest.words
  | 6 => a.nullifier.words
  | 7 => a.amount.words
  | 8 => [a.tokenSlot]
  | 9 => [a.tokenIndex]
  | _ => []

/-- The limbs `u32_limb`/`Bytes32Target::new(_, true)`/`U64Target::new(_, true)`
    range-check for the header (src 316-330). -/
def headerAllocationWords {Path Core : Type} {e : Environment Path Core} (a : Assignment e) :
    List Nat :=
  [a.memberCount,a.delegateCount,a.tokenCount] ++ tenList a.registry ++ a.settledChain.words ++
    a.accumulatorRoot.words ++ a.stateVersion.words

/-- The ten checked ciphertext digests and ten checked counters (src 337-340). -/
def slotRowWords {Path Core : Type} {e : Environment Path Core} (a : Assignment e) : List Nat :=
  digestRowWords a.ciphertexts ++ tenList a.pendingAdds

/-- The registered public-input vector is exactly the ten range-checked groups
    (src 134-151 against src 113-131). -/
theorem public_words_are_groups {Path Core : Type} {e : Environment Path Core}
    (a : Assignment e) :
    (readPublic a).words = publicGroup a 0 ++ publicGroup a 1 ++ publicGroup a 2 ++
      publicGroup a 3 ++ publicGroup a 4 ++ publicGroup a 5 ++ publicGroup a 6 ++
      publicGroup a 7 ++ publicGroup a 8 ++ publicGroup a 9 := by
  simp [readPublic,PublicInputs.words,publicGroup]

/-- The private range-check list of `CircuitGates` is exactly the header allocation
    limbs followed by the ten-token leaf row (src 316-340). -/
theorem private_words_are_allocations {Path Core : Type} {e : Environment Path Core}
    (a : Assignment e) :
    [a.memberCount,a.delegateCount,a.tokenCount] ++ tenList a.registry ++ a.settledChain.words ++
      a.accumulatorRoot.words ++ a.stateVersion.words ++ digestRowWords a.ciphertexts ++
      tenList a.pendingAdds = headerAllocationWords a ++ slotRowWords a := by
  simp only [headerAllocationWords,slotRowWords,List.append_assoc]

theorem checked_append {xs ys : List Nat} (hx : Checked xs) (hy : Checked ys) :
    Checked (xs ++ ys) := by
  intro x mem
  rcases List.mem_append.mp mem with h | h
  · exact hx x h
  · exact hy x h

theorem checked_of_all_words {xs : List Nat}
    (h : xs.all (fun x => decide (x < wordBase)) = true) : Checked xs :=
  fun x mem => of_decide_eq_true (List.all_eq_true.mp h x mem)

/-- What ONE builder call enforces on the wires it touches, per source line of
    src/circuits/channel/withdrawal_claim_circuit.rs:

    * `zeroKnowledgeConfig` 307-308, `observe*` 341/436/462/494/510/539/548,
      `buildCircuit` 557 — no wire constraint (config choice, `builder.num_gates()`
      profiling reads, `builder.build()`).
    * `allocateRawRootAndMemberIndex` 325-333 — ALSO no constraint: `slot_tree_root`
      is four RAW field elements (`PoseidonHashOutTarget::new`, 327) and
      `member_index` a bare `add_virtual_target` (333). The index bound comes only
      from the inclusion verify's `split_le` (493, via
      src/utils/trees/merkle_tree.rs:227).
    * `allocateCheckedPublic` 113-131 (groups in `to_vec` order, 134-151),
      `allocateCheckedHeader` 316-330, `allocateTenCheckedCiphertextsAndCounters`
      337-340 — `builder.range_check(t, 32)` on each limb (`Bytes32Target::new(_,
      true)`, `AddressTarget::new(_, true)`, `U64Target::new(_, true)`, `u32_limb`).
    * `recomputeH1` 344-355 / `connectH1` 356; `activeSumAnd11Bits` 377-379;
      `compareActive1025` 380-382; `compareMemberActive` 384-385;
      `tenEqualityFlagsAndSumOne` 396-404; `compareTokenCount` 410-411;
      `selectEightCiphertextLimbs` 417-425; `selectBaseToken` 430-435;
      `allocateFourPolynomials` 451-454 (length only: canonicality `< q` is pinned
      inside `decryption_core`, not here); `hashPkAndCiphertext` 457/460;
      `connectCiphertext` 461; `hashFullSlotLeaf` 482-488; `verifyInclusion`
      489-493; `decryptExposeAmount` 503-505; `connectAmountHighThenLow` 507-509
      (PI `to_vec` is `[hi, lo]`); `deriveIMW2` 528-537; `connectNullifier` 538;
      `registerPublic` 547.

    The eight per-limb ct select chains (419-425) are modeled at `Words8`
    granularity; `member_pk_g` is only allocated and registered (123, 140), so no
    op constrains it — matching the source, where it is informational. -/
def BuildOp.holds {Path Core : Type} {e : Environment Path Core} :
    BuildOp → Assignment e → Prop
  | .zeroKnowledgeConfig, _ => True
  | .allocateCheckedPublic field width, a =>
      Checked (publicGroup a field) ∧ (publicGroup a field).length = width
  | .allocateCheckedHeader, a => Checked (headerAllocationWords a)
  | .allocateRawRootAndMemberIndex, _ => True
  | .allocateTenCheckedCiphertextsAndCounters, a => Checked (slotRowWords a)
  | .observeInputs, _ => True
  | .recomputeH1, a => a.recomputedH1 = e.poseidonWords (headerPreimage a.channelId (readHeader a))
  | .connectH1, a => a.recomputedH1 = a.h1
  | .activeSumAnd11Bits, a => a.active = a.memberCount + a.delegateCount ∧ a.active < 2^11
  | .compareActive1025, a => a.activeCompare.Enforces a.active (maxParticipants+1)
  | .compareMemberActive, a => a.memberCompare.Enforces a.memberIndex a.active
  | .tenEqualityFlagsAndSumOne, a =>
      FlagsPinned a.tokenSlot a.tokenFlags maxTokens ∧ flagSum a.tokenFlags maxTokens = 1
  | .compareTokenCount, a => a.tokenCompare.Enforces a.tokenSlot a.tokenCount
  | .selectEightCiphertextLimbs, a =>
      selectChain a.tokenFlags (totalRow a.ciphertexts CloseCircuit.Words8.zero)
        CloseCircuit.Words8.zero maxTokens = a.ciphertextDigest
  | .selectBaseToken, a => selectChain a.tokenFlags (totalRow a.registry 0) 0 maxTokens = a.tokenIndex
  | .observeHeaderSelectors, _ => True
  | .allocateFourPolynomials length, a =>
      a.polynomials.a.length = length ∧ a.polynomials.b.length = length ∧
      a.polynomials.c1.length = length ∧ a.polynomials.c2.length = length
  | .hashPkAndCiphertext, a =>
      a.pkDigest = e.poseidonWords (pkPreimage a.polynomials) ∧
      a.ctDigest = e.keccak (ctPreimage a.polynomials)
  | .connectCiphertext, a => a.ctDigest = a.ciphertextDigest
  | .observeDigests, _ => True
  | .hashFullSlotLeaf, a =>
      a.slotLeaf = e.poseidonRoot (slotPreimage a.pkDigest a.ciphertexts a.pendingAdds a.recipient)
  | .verifyInclusion height, a =>
      e.inclusion a.slotLeaf a.memberIndex a.path a.slotRoot ∧ a.memberIndex < 2^height
  | .observeInclusion, _ => True
  | .decryptExposeAmount, a => e.decryption a.polynomials a.core a.amountLo a.amountHi
  | .connectAmountHighThenLow, a => a.amount.hi = a.amountHi ∧ a.amount.lo = a.amountLo
  | .observeDecryption, _ => True
  | .deriveIMW2, a => a.nullifierDigest = e.keccak (nullifierPreimage a.closeId a.pkDigest a.tokenSlot)
  | .connectNullifier, a => a.nullifierDigest = a.nullifier
  | .observeNullifier, _ => True
  | .registerPublic width, a => (readPublic a).words.length = width
  | .observeBeforePadding, _ => True
  | .buildCircuit, _ => True

def ProgramSatisfied {Path Core : Type} {e : Environment Path Core}
    (prog : List BuildOp) (a : Assignment e) : Prop := ∀ op ∈ prog, op.holds a

/-- Residual gate obligations NOT produced by any `BuildOp` of `constructorProgram`.
    The list is EMPTY: every field of `CircuitGates` is discharged by
    `program_satisfied_implies_gates` from program satisfaction alone, so this
    carries no content and the main theorem takes no such premise. -/
def EnvironmentGates {Path Core : Type} {e : Environment Path Core} (_a : Assignment e) : Prop :=
  True

theorem environment_gates_are_empty {Path Core : Type} {e : Environment Path Core}
    (a : Assignment e) : EnvironmentGates a := trivial

/-- Gate lowering, fully discharged inside the model: satisfying every LOCAL
    proposition of the transcribed builder program forces the hand-written
    `CircuitGates` predicate on the wires read back by `readPublic`/`readWitness`.
    No extra premise (see `EnvironmentGates`, which is empty) and `CircuitGates`
    is not weakened. What remains outside the model is per-primitive: that a real
    plonky2 satisfying assignment realizes each `BuildOp.holds` (range-check,
    connect, `is_equal`/`select`, `less_than_u32`, the Poseidon/keccak/Merkle/
    decryption-core gadget calls) — that is `PrimitiveLowering`. -/
theorem program_satisfied_implies_gates {Path Core : Type} (e : Environment Path Core)
    (a : Assignment e) (h : ProgramSatisfied constructorProgram a) :
    CircuitGates e (readPublic a) (readWitness a) := by
  have p0 : Checked (publicGroup a 0) ∧ (publicGroup a 0).length = 8 :=
    h (.allocateCheckedPublic 0 8) (by decide)
  have p1 : Checked (publicGroup a 1) ∧ (publicGroup a 1).length = 1 :=
    h (.allocateCheckedPublic 1 1) (by decide)
  have p2 : Checked (publicGroup a 2) ∧ (publicGroup a 2).length = 8 :=
    h (.allocateCheckedPublic 2 8) (by decide)
  have p3 : Checked (publicGroup a 3) ∧ (publicGroup a 3).length = 8 :=
    h (.allocateCheckedPublic 3 8) (by decide)
  have p4 : Checked (publicGroup a 4) ∧ (publicGroup a 4).length = 5 :=
    h (.allocateCheckedPublic 4 5) (by decide)
  have p5 : Checked (publicGroup a 5) ∧ (publicGroup a 5).length = 8 :=
    h (.allocateCheckedPublic 5 8) (by decide)
  have p6 : Checked (publicGroup a 6) ∧ (publicGroup a 6).length = 8 :=
    h (.allocateCheckedPublic 6 8) (by decide)
  have p7 : Checked (publicGroup a 7) ∧ (publicGroup a 7).length = 2 :=
    h (.allocateCheckedPublic 7 2) (by decide)
  have p8 : Checked (publicGroup a 8) ∧ (publicGroup a 8).length = 1 :=
    h (.allocateCheckedPublic 8 1) (by decide)
  have p9 : Checked (publicGroup a 9) ∧ (publicGroup a 9).length = 1 :=
    h (.allocateCheckedPublic 9 1) (by decide)
  have hHeader : Checked (headerAllocationWords a) := h .allocateCheckedHeader (by decide)
  have hRow : Checked (slotRowWords a) :=
    h .allocateTenCheckedCiphertextsAndCounters (by decide)
  have hRecompute : a.recomputedH1 = e.poseidonWords (headerPreimage a.channelId (readHeader a)) :=
    h .recomputeH1 (by decide)
  have hConnectH1 : a.recomputedH1 = a.h1 := h .connectH1 (by decide)
  have hActive : a.active = a.memberCount + a.delegateCount ∧ a.active < 2^11 :=
    h .activeSumAnd11Bits (by decide)
  have hActiveCmp : a.activeCompare.Enforces a.active (maxParticipants+1) :=
    h .compareActive1025 (by decide)
  have hMemberCmp : a.memberCompare.Enforces a.memberIndex a.active :=
    h .compareMemberActive (by decide)
  have hFlags : FlagsPinned a.tokenSlot a.tokenFlags maxTokens ∧
      flagSum a.tokenFlags maxTokens = 1 := h .tenEqualityFlagsAndSumOne (by decide)
  have hTokenCmp : a.tokenCompare.Enforces a.tokenSlot a.tokenCount :=
    h .compareTokenCount (by decide)
  have hSelectCt : selectChain a.tokenFlags (totalRow a.ciphertexts CloseCircuit.Words8.zero)
      CloseCircuit.Words8.zero maxTokens = a.ciphertextDigest :=
    h .selectEightCiphertextLimbs (by decide)
  have hSelectToken : selectChain a.tokenFlags (totalRow a.registry 0) 0 maxTokens = a.tokenIndex :=
    h .selectBaseToken (by decide)
  have hPoly : a.polynomials.a.length = regevN ∧ a.polynomials.b.length = regevN ∧
      a.polynomials.c1.length = regevN ∧ a.polynomials.c2.length = regevN :=
    h (.allocateFourPolynomials regevN) (by decide)
  have hDigests : a.pkDigest = e.poseidonWords (pkPreimage a.polynomials) ∧
      a.ctDigest = e.keccak (ctPreimage a.polynomials) := h .hashPkAndCiphertext (by decide)
  have hConnectCt : a.ctDigest = a.ciphertextDigest := h .connectCiphertext (by decide)
  have hLeaf : a.slotLeaf =
      e.poseidonRoot (slotPreimage a.pkDigest a.ciphertexts a.pendingAdds a.recipient) :=
    h .hashFullSlotLeaf (by decide)
  have hInclusion : e.inclusion a.slotLeaf a.memberIndex a.path a.slotRoot ∧
      a.memberIndex < 2^treeHeight := h (.verifyInclusion treeHeight) (by decide)
  have hDecrypt : e.decryption a.polynomials a.core a.amountLo a.amountHi :=
    h .decryptExposeAmount (by decide)
  have hAmount : a.amount.hi = a.amountHi ∧ a.amount.lo = a.amountLo :=
    h .connectAmountHighThenLow (by decide)
  have hNullifier : a.nullifierDigest =
      e.keccak (nullifierPreimage a.closeId a.pkDigest a.tokenSlot) := h .deriveIMW2 (by decide)
  have hConnectNullifier : a.nullifierDigest = a.nullifier := h .connectNullifier (by decide)
  have pinned : FlagsPinned a.tokenSlot a.tokenFlags maxTokens := hFlags.1
  -- fields in `CircuitGates` declaration order.
  refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩
  · -- publicRanges (src 113-131)
    show Checked (readPublic a).words
    rw [public_words_are_groups]
    exact checked_append (checked_append (checked_append (checked_append (checked_append
      (checked_append (checked_append (checked_append (checked_append p0.1 p1.1) p2.1) p3.1)
        p4.1) p5.1) p6.1) p7.1) p8.1) p9.1
  · -- privateRanges (src 316-340)
    show Checked ([a.memberCount,a.delegateCount,a.tokenCount] ++ tenList a.registry ++
      a.settledChain.words ++ a.accumulatorRoot.words ++ a.stateVersion.words ++
      digestRowWords a.ciphertexts ++ tenList a.pendingAdds)
    rw [private_words_are_allocations]
    exact checked_append hHeader hRow
  · -- h1Connect (src 344-356)
    exact hRecompute.symm.trans hConnectH1
  · -- activeBits (src 377-379)
    show a.memberCount + a.delegateCount < 2^11
    have bits := hActive.2
    rw [hActive.1] at bits
    exact bits
  · -- activeCompare (src 380-382)
    show ∃ c : Comparison33 (a.memberCount + a.delegateCount) (maxParticipants+1),
      comparisonResult c = true
    rw [← hActive.1]
    exact compare_wires_expose_comparison hActiveCmp
  · -- memberCompare (src 384-385)
    show ∃ c : Comparison33 a.memberIndex (a.memberCount + a.delegateCount),
      comparisonResult c = true
    rw [← hActive.1]
    exact compare_wires_expose_comparison hMemberCmp
  · -- oneHot (src 396-404)
    show oneHotSum a.tokenSlot maxTokens = 1
    rw [← flag_sum_is_one_hot_sum a.tokenSlot a.tokenFlags maxTokens pinned]
    exact hFlags.2
  · -- tokenCompare (src 410-411)
    show ∃ c : Comparison33 a.tokenSlot a.tokenCount, comparisonResult c = true
    exact compare_wires_expose_comparison hTokenCmp
  · -- selectedCiphertext (src 417-425)
    show selectLoop a.tokenSlot (totalRow a.ciphertexts CloseCircuit.Words8.zero)
      CloseCircuit.Words8.zero maxTokens = a.ciphertextDigest
    rw [← select_chain_is_select_loop a.tokenSlot a.tokenFlags
      (totalRow a.ciphertexts CloseCircuit.Words8.zero) CloseCircuit.Words8.zero maxTokens pinned]
    exact hSelectCt
  · -- selectedBaseToken (src 430-435)
    show selectLoop a.tokenSlot (totalRow a.registry 0) 0 maxTokens = a.tokenIndex
    rw [← select_chain_is_select_loop a.tokenSlot a.tokenFlags (totalRow a.registry 0) 0
      maxTokens pinned]
    exact hSelectToken
  · -- polyShape (src 451-454)
    exact hPoly
  · -- ctConnect (src 460-461)
    show e.keccak (ctPreimage a.polynomials) = a.ciphertextDigest
    rw [← hDigests.2]
    exact hConnectCt
  · -- inclusionCall (src 457, 482-493)
    show e.inclusion (e.poseidonRoot (slotPreimage (e.poseidonWords (pkPreimage a.polynomials))
      a.ciphertexts a.pendingAdds a.recipient)) a.memberIndex a.path a.slotRoot
    rw [← hDigests.1,← hLeaf]
    exact hInclusion.1
  · -- merkleIndexBits (src 493)
    exact hInclusion.2
  · -- amountConnect (src 503-509)
    show e.decryption a.polynomials a.core a.amount.lo a.amount.hi
    rw [hAmount.1,hAmount.2]
    exact hDecrypt
  · -- nullifierConnect (src 528-538)
    show e.keccak (nullifierPreimage a.closeId (e.poseidonWords (pkPreimage a.polynomials))
      a.tokenSlot) = a.nullifier
    rw [← hDigests.1,← hNullifier]
    exact hConnectNullifier

/-- The remaining lowering obligation after `program_satisfied_implies_gates`: a real
    accepting execution of the plonky2 circuit yields wire values satisfying every
    LOCAL builder-call proposition, and reading the public/private wires back gives
    the modeled public inputs and witness. This is per-primitive (each plonky2
    gadget's own soundness) plus digest pinning (that the deployed circuit digest is
    the one built by `constructorProgram`); no part of it is proved here. -/
def PrimitiveLowering {Path Core Raw : Type} (e : Environment Path Core)
    (accepts : Raw → PublicInputs → Witness Path Core → Prop) : Prop :=
  ∀ raw p w, accepts raw p w →
    ∃ a : Assignment e, ProgramSatisfied constructorProgram a ∧
      readPublic a = p ∧ readWitness a = w

theorem primitive_lowering_implies_field_lowering {Path Core Raw : Type}
    (e : Environment Path Core) (accepts : Raw → PublicInputs → Witness Path Core → Prop)
    (lowering : PrimitiveLowering e accepts) : FieldLowering e accepts := by
  intro raw p w accepted
  obtain ⟨a,satisfied,public,private'⟩ := lowering raw p w accepted
  have gates := program_satisfied_implies_gates e a satisfied
  rw [public,private'] at gates
  exact gates

/-! ### Non-vacuity: one concrete satisfying assignment

The normal trace of `normal_token_selection` / `normal_active_delegate_slot`
extended to a full wire assignment: one member, no delegates, the claimant at slot
0, one live token at local slot 0 mapped to base token 7, amount 77. -/

def exampleEnvironment : Environment Unit Unit :=
  { poseidonWords := fun _ => CloseCircuit.Words8.zero
    poseidonRoot := fun _ => ⟨0,0,0,0⟩
    keccak := fun _ => CloseCircuit.Words8.zero
    inclusion := fun _ _ _ _ => True
    decryption := fun _ _ _ _ => True }

def exampleCompareToOne : CompareWires := ⟨true :: List.replicate 31 false,true⟩
def exampleCompareToCapacity : CompareWires :=
  ⟨List.replicate 10 false ++ (true :: List.replicate 21 false),true⟩
def exampleRegistry : Ten Nat := fun i => if i.val = 0 then 7 else 0
def examplePolynomial : List Nat := List.replicate regevN 0
def examplePolynomials : Polynomials :=
  ⟨examplePolynomial,examplePolynomial,examplePolynomial,examplePolynomial⟩

theorem example_polynomial_length : examplePolynomial.length = regevN := by
  simp [examplePolynomial]

def examplePublicInputs : PublicInputs :=
  { closeId := CloseCircuit.Words8.zero, channelId := 1, h1 := CloseCircuit.Words8.zero,
    memberPk := CloseCircuit.Words8.zero, recipient := ⟨1,2,3,4,5⟩,
    ciphertextDigest := CloseCircuit.Words8.zero, nullifier := CloseCircuit.Words8.zero,
    amount := ⟨0,77⟩, tokenSlot := 0, tokenIndex := 7 }

def exampleWitness : Witness Unit Unit :=
  { header :=
      { memberCount := 1, delegateCount := 0, tokenCount := 1, registry := exampleRegistry,
        slotRoot := ⟨0,0,0,0⟩, settledChain := CloseCircuit.Words8.zero,
        accumulatorRoot := CloseCircuit.Words8.zero, stateVersion := ⟨0,1⟩ }
    memberIndex := 0, ciphertexts := fun _ => CloseCircuit.Words8.zero,
    pendingAdds := fun _ => 0, path := (), polynomials := examplePolynomials, core := () }

def exampleAssignment : Assignment exampleEnvironment :=
  { closeId := CloseCircuit.Words8.zero, channelId := 1, h1 := CloseCircuit.Words8.zero,
    memberPk := CloseCircuit.Words8.zero, recipient := ⟨1,2,3,4,5⟩,
    ciphertextDigest := CloseCircuit.Words8.zero, nullifier := CloseCircuit.Words8.zero,
    amount := ⟨0,77⟩, tokenSlot := 0, tokenIndex := 7,
    memberCount := 1, delegateCount := 0, tokenCount := 1, registry := exampleRegistry,
    slotRoot := ⟨0,0,0,0⟩, settledChain := CloseCircuit.Words8.zero,
    accumulatorRoot := CloseCircuit.Words8.zero, stateVersion := ⟨0,1⟩,
    memberIndex := 0, ciphertexts := fun _ => CloseCircuit.Words8.zero,
    pendingAdds := fun _ => 0, path := (), polynomials := examplePolynomials, core := (),
    active := 1, activeCompare := exampleCompareToCapacity, memberCompare := exampleCompareToOne,
    tokenCompare := exampleCompareToOne, tokenFlags := fun k => decide (k = 0),
    recomputedH1 := CloseCircuit.Words8.zero, pkDigest := CloseCircuit.Words8.zero,
    ctDigest := CloseCircuit.Words8.zero, slotLeaf := ⟨0,0,0,0⟩, amountLo := 77, amountHi := 0,
    nullifierDigest := CloseCircuit.Words8.zero }

theorem example_program_reads_back :
    readPublic exampleAssignment = examplePublicInputs ∧
    readWitness exampleAssignment = exampleWitness := ⟨rfl,rfl⟩

set_option maxRecDepth 8192 in
theorem example_program_satisfied : ProgramSatisfied constructorProgram exampleAssignment := by
  simp only [ProgramSatisfied,constructorProgram,publicAllocationProgram,List.cons_append,
    List.nil_append,List.singleton_append,List.forall_mem_cons,List.not_mem_nil,
    List.forall_mem_nil,and_true]
  repeat' apply And.intro
  all_goals
    first
      | (simp only [exampleAssignment,examplePolynomials,examplePolynomial,List.length_replicate]
         done)
      | (intro _ impossible
         exact impossible.elim)
      | exact checked_of_all_words (by rfl)
      | (intro k _
         exact ⟨fun flag => (of_decide_eq_true flag).symm,fun slot => decide_eq_true slot.symm⟩)
      | trivial
      | decide

theorem example_program_satisfiable :
    ∃ a : Assignment exampleEnvironment, ProgramSatisfied constructorProgram a :=
  ⟨exampleAssignment,example_program_satisfied⟩

theorem example_assignment_meets_circuit_gates :
    CircuitGates exampleEnvironment examplePublicInputs exampleWitness :=
  program_satisfied_implies_gates exampleEnvironment exampleAssignment example_program_satisfied

end Zkp.Implementation.WithdrawalClaimCircuit
