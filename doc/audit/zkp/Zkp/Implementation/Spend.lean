import Std

/-!
# Spend: handwritten source semantics and sequential per-token debit proofs

Source: src/circuits/balance/spend_circuit.rs, runtime 05ec7ae, all 569 lines read.
This is NOT Rust/Plonky2/compiler/EVM refinement. No historical axiomatized
model is imported. All cryptographic dependency obligations are explicit.

Important actual behaviors, not strengthened by this model:
* both PI parsers accept extra trailing words; native Tx nonce decoding uses
  `as u32` truncation and native is_valid is `word != 0`. Target parsing simply
  wraps the flag with BoolTarget::new_unsafe and adds NO Boolean assertion.
* constructor-produced is_valid IS a computed equality Boolean, but is never
  asserted true by Spend. The consumer must require true where needed.
* TransferTarget::new(true) checks recipient/amount/aux limbs but does not
  directly range-check token_index. Its u32-domain claim comes from the
  height-32 Merkle split_le dependency, kept separate below.
* native PrivateState.nonce+1 has u32 overflow behavior controlled by the Rust
  build profile; target add_const is field addition and not a u32 overflow
  check. Equality is proved only on the explicit nonoverflow domain.
* every one of the 64 transfers updates the running root, including zero
  amount padding. Duplicate token indices are allowed and debit cumulatively.
* prove invokes native to_public_inputs first, unlike CloseAssetBacking.prove.

AssetMap and Nat amounts are semantic decoded values. Native Rust u32/U256
domains and target limb/range/subtraction lowering must justify this view.
Merkle data contains NO global all-AssetMap opening/injectivity axiom.
ScopedPathContracts refer only to concrete visited old tree/path/key/value
tuples of one finite trace. Arbitrary-length theorems quantify over traces
whose individual dependency contracts have been separately supplied.

The result is per-token conservation of the modeled deductions, not proof of
sender authority, validity/finality, replay exclusion, recipient ownership,
cross-channel global conservation, or availability of a later withdrawal.
Those are independent callers, circuits, pinned verifier and hash obligations.
-/

namespace Zkp.Implementation.Spend

def wordBase : Nat := 2 ^ 32
def amountLimit : Nat := 2 ^ 256
def maxTransfers : Nat := 64
def assetTreeHeight : Nat := 32
def sentTreeHeight : Nat := 32
def transferTreeHeight : Nat := 6
def txLength : Nat := 5
def publicInputsLength : Nat := 14

structure Hash4 where
  h0 : Nat
  h1 : Nat
  h2 : Nat
  h3 : Nat
  deriving DecidableEq, Repr

def Hash4.words (h : Hash4) : List Nat := [h.h0, h.h1, h.h2, h.h3]
def zeroHash : Hash4 := ⟨0,0,0,0⟩

structure Tx where
  transferTreeRoot : Hash4
  nonce : Nat
  deriving DecidableEq, Repr

def Tx.words (t : Tx) : List Nat := t.transferTreeRoot.words ++ [t.nonce]
def emptyTx : Tx := ⟨zeroHash, 0⟩

structure PublicInputs where
  previousPrivateCommitment : Hash4
  newPrivateCommitment : Hash4
  tx : Tx
  isValid : Bool
  deriving DecidableEq, Repr

/-- Target flag is a raw wire, not the soundness assumption Bool=true. -/
structure PublicInputTargets where
  previousPrivateCommitment : Hash4
  newPrivateCommitment : Hash4
  tx : Tx
  validityWire : Nat
  deriving DecidableEq, Repr

def PublicInputTargets.words (p : PublicInputTargets) : List Nat :=
  p.previousPrivateCommitment.words ++ p.newPrivateCommitment.words ++ p.tx.words ++ [p.validityWire]

def PublicInputs.targets (p : PublicInputs) : PublicInputTargets :=
  ⟨p.previousPrivateCommitment, p.newPrivateCommitment, p.tx, if p.isValid then 1 else 0⟩

/-- Accepts >=14 words and keeps the raw target nonce/flag without checks. -/
def parseTargetPublicInputs : List Nat → Option PublicInputTargets
  | p0::p1::p2::p3::n0::n1::n2::n3::t0::t1::t2::t3::nonce::flag::_ =>
      some ⟨⟨p0,p1,p2,p3⟩, ⟨n0,n1,n2,n3⟩, ⟨⟨t0,t1,t2,t3⟩, nonce⟩, flag⟩
  | _ => none

inductive Error where
  | invalidNumInputs
  | invalidMerkleProof
  | insufficientBalance
  | invalidData
  | failedToProve
  | invalidPublicInputs
  deriving DecidableEq, Repr

/-- Tx::from_u64_slice truncates nonce with as u32. Poseidon words retain
    their supplied u64 representation; flags are interpreted as nonzero. -/
def parseNativePublicInputs (words : List Nat) : Except Error PublicInputs :=
  match parseTargetPublicInputs words with
  | none => .error .invalidPublicInputs
  | some p => .ok ⟨p.previousPrivateCommitment, p.newPrivateCommitment,
      { p.tx with nonce := p.tx.nonce % wordBase }, decide (p.validityWire ≠ 0)⟩

theorem target_encoding_has_exact_14_words (p : PublicInputTargets) :
    p.words.length = publicInputsLength := by
  simp [PublicInputTargets.words, Hash4.words, Tx.words, publicInputsLength]

theorem target_parser_round_trip_with_arbitrary_suffix (p : PublicInputTargets) (suffix : List Nat) :
    parseTargetPublicInputs (p.words ++ suffix) = some p := by
  cases p with
  | mk a b t v => cases a; cases b; cases t with
    | mk h n => cases h; rfl

theorem native_parser_keeps_actual_cast_and_nonzero_semantics
    (p : PublicInputTargets) (suffix : List Nat) :
    parseNativePublicInputs (p.words ++ suffix) =
      .ok ⟨p.previousPrivateCommitment, p.newPrivateCommitment,
        { p.tx with nonce := p.tx.nonce % wordBase }, decide (p.validityWire ≠ 0)⟩ := by
  simp [parseNativePublicInputs, target_parser_round_trip_with_arbitrary_suffix]

theorem native_public_input_round_trip_on_typed_domain (p : PublicInputs)
    (nonceRange : p.tx.nonce < wordBase) (suffix : List Nat) :
    parseNativePublicInputs (p.targets.words ++ suffix) = .ok p := by
  rw [native_parser_keeps_actual_cast_and_nonzero_semantics]
  cases p with
  | mk a b t flag =>
      cases t with
      | mk root nonce =>
          cases flag <;> simp_all [PublicInputs.targets, Nat.mod_eq_of_lt]

structure Transfer where
  recipient : List Nat
  tokenIndex : Nat
  amount : Nat
  auxData : List Nat
  deriving DecidableEq, Repr

/-- Semantic U256 byte/limb codec remains a dependency; its eight BE words are
    explicit in the transfer preimage, not replaced with a scalar hash input. -/
def u256Words (amount : Nat) : List Nat :=
  (List.range 8).map (fun i => amount / wordBase ^ (7 - i) % wordBase)

def Transfer.words (t : Transfer) : List Nat :=
  t.recipient ++ [t.tokenIndex] ++ u256Words t.amount ++ t.auxData

def Transfer.NativeTyped (t : Transfer) : Prop :=
  t.recipient.length = 8 ∧ t.auxData.length = 8 ∧ t.tokenIndex < wordBase ∧
  t.amount < amountLimit ∧ (∀ x ∈ t.recipient, x < wordBase) ∧ (∀ x ∈ t.auxData, x < wordBase)

/-- Deliberately does NOT contain tokenIndex<2^32: new(true) omits that check. -/
def Transfer.AllocationChecks (t : Transfer) : Prop :=
  t.recipient.length = 8 ∧ t.auxData.length = 8 ∧ t.amount < amountLimit ∧
  (∀ x ∈ t.recipient, x < wordBase) ∧ (∀ x ∈ t.auxData, x < wordBase)

theorem typed_transfer_preimage_is_25_words (t : Transfer) (h : t.NativeTyped) :
    t.words.length = 25 := by
  simp [Transfer.words, u256Words, h.1, h.2.1]
  decide

structure PrivateState where
  assetTreeRoot : Hash4
  nullifierTreeRoot : Hash4
  sentTxTreeRoot : Hash4
  previousPrivateCommitment : Hash4
  nonce : Nat
  salt : Hash4
  deriving DecidableEq, Repr

def PrivateState.words (p : PrivateState) : List Nat :=
  p.assetTreeRoot.words ++ p.nullifierTreeRoot.words ++ p.sentTxTreeRoot.words ++
    p.previousPrivateCommitment.words ++ [p.nonce] ++ p.salt.words

/-- Root interface is data-only. No universally exact Merkle openings assumed. -/
structure AssetMerkle (Root Path : Type) where
  encode : (Nat → Nat) → Root
  pathRoot : Path → Nat → Nat → Root

abbrev AssetMap := Nat → Nat

def putAsset (tree : AssetMap) (token amount : Nat) : AssetMap :=
  fun key => if key = token then amount else tree key

structure DebitRow (Path : Type) where
  transfer : Transfer
  beforeBalance : Nat
  path : Path

def afterBalance {Path : Type} (r : DebitRow Path) : Nat := r.beforeBalance - r.transfer.amount

def assetUpdates {Path : Type} : List (DebitRow Path) → AssetMap → AssetMap
  | [], tree => tree
  | r :: rs, tree => assetUpdates rs (putAsset tree r.transfer.tokenIndex (afterBalance r))

def debitRootFold {Root Path : Type} (m : AssetMerkle Root Path) : List (DebitRow Path) → Root → Root
  | [], root => root
  | r :: rs, _ => debitRootFold m rs (m.pathRoot r.path (afterBalance r) r.transfer.tokenIndex)

/-- Local denotation after u32/U256/Merkle gadget lowering. In particular the
    token range is supplied by split_le(height32), NOT a fabricated allocation
    check. The no-underflow clause is the final-borrow-zero sub gadget meaning. -/
def DebitGates {Root Path : Type} (m : AssetMerkle Root Path) : List (DebitRow Path) → Root → Prop
  | [], _ => True
  | r :: rs, root =>
      m.pathRoot r.path r.beforeBalance r.transfer.tokenIndex = root ∧
      r.transfer.tokenIndex < wordBase ∧ r.beforeBalance < amountLimit ∧
      r.transfer.amount < amountLimit ∧ r.transfer.amount ≤ r.beforeBalance ∧
      DebitGates m rs (m.pathRoot r.path (afterBalance r) r.transfer.tokenIndex)

/-- Scoped equality/opening plus same-path replacement for one actual old
    tree/path/old-value/key/new-value tuple, not an asset-conservation premise. -/
def PathContractAt {Root Path : Type} (m : AssetMerkle Root Path)
    (tree : AssetMap) (r : DebitRow Path) : Prop :=
  r.transfer.tokenIndex < wordBase →
  m.pathRoot r.path r.beforeBalance r.transfer.tokenIndex = m.encode tree →
  r.beforeBalance = tree r.transfer.tokenIndex ∧
  m.pathRoot r.path (afterBalance r) r.transfer.tokenIndex =
    m.encode (putAsset tree r.transfer.tokenIndex (afterBalance r))

def ScopedPathContracts {Root Path : Type} (m : AssetMerkle Root Path) :
    List (DebitRow Path) → AssetMap → Prop
  | [], _ => True
  | r :: rs, tree => PathContractAt m tree r ∧
      ScopedPathContracts m rs (putAsset tree r.transfer.tokenIndex (afterBalance r))

/-- Arithmetic/tree induction hypothesis derived from gates + scoped Merkle
    contracts; this is NOT an assumption about the untrusted before balances. -/
def AdmittedDebits {Path : Type} : List (DebitRow Path) → AssetMap → Prop
  | [], _ => True
  | r :: rs, tree => r.beforeBalance = tree r.transfer.tokenIndex ∧
      r.transfer.amount ≤ r.beforeBalance ∧
      AdmittedDebits rs (putAsset tree r.transfer.tokenIndex (afterBalance r))

theorem scoped_paths_and_gates_authenticate_each_running_balance {Root Path : Type}
    (m : AssetMerkle Root Path) (rows : List (DebitRow Path)) (tree : AssetMap)
    (contracts : ScopedPathContracts m rows tree) (gates : DebitGates m rows (m.encode tree)) :
    AdmittedDebits rows tree ∧ debitRootFold m rows (m.encode tree) = m.encode (assetUpdates rows tree) := by
  induction rows generalizing tree with
  | nil => exact ⟨True.intro, rfl⟩
  | cons r rs ih =>
      have hc := contracts.1 gates.2.1 gates.1
      have ht : DebitGates m rs (m.encode (putAsset tree r.transfer.tokenIndex (afterBalance r))) := by
        rw [← hc.2]
        exact gates.2.2.2.2.2
      have hi := ih _ contracts.2 ht
      refine ⟨⟨hc.1, gates.2.2.2.2.1, hi.1⟩, ?_⟩
      simpa only [debitRootFold, assetUpdates, hc.2] using hi.2

def debitedAt {Path : Type} (token : Nat) : List (DebitRow Path) → Nat
  | [] => 0
  | r :: rs => (if token = r.transfer.tokenIndex then r.transfer.amount else 0) + debitedAt token rs

theorem arbitrary_trace_conserves_each_token_exactly {Path : Type}
    (rows : List (DebitRow Path)) (tree : AssetMap) (admitted : AdmittedDebits rows tree) :
    ∀ token, assetUpdates rows tree token + debitedAt token rows = tree token := by
  induction rows generalizing tree with
  | nil => simp [assetUpdates, debitedAt]
  | cons r rs ih =>
      intro token
      have hi := ih _ admitted.2.2 token
      by_cases same : token = r.transfer.tokenIndex
      · subst token
        have hb := admitted.1
        have ha := admitted.2.1
        simp only [assetUpdates, debitedAt, if_pos rfl, ↓reduceIte]
        simp only [putAsset, if_pos rfl] at hi
        change assetUpdates rs (putAsset tree r.transfer.tokenIndex (afterBalance r)) r.transfer.tokenIndex +
          debitedAt r.transfer.tokenIndex rs = r.beforeBalance - r.transfer.amount at hi
        omega
      · simpa [assetUpdates, debitedAt, putAsset, same] using hi

theorem proved_asset_root_encodes_per_token_conservation {Root Path : Type}
    (m : AssetMerkle Root Path) (rows : List (DebitRow Path)) (tree : AssetMap)
    (contracts : ScopedPathContracts m rows tree) (gates : DebitGates m rows (m.encode tree)) :
    debitRootFold m rows (m.encode tree) = m.encode (assetUpdates rows tree) ∧
    ∀ token, assetUpdates rows tree token + debitedAt token rows = tree token := by
  obtain ⟨admitted, root⟩ := scoped_paths_and_gates_authenticate_each_running_balance m rows tree contracts gates
  exact ⟨root, arbitrary_trace_conserves_each_token_exactly rows tree admitted⟩

theorem aggregate_debits_never_exceed_initial_token_fund {Path : Type}
    (rows : List (DebitRow Path)) (tree : AssetMap) (admitted : AdmittedDebits rows tree) (token : Nat) :
    debitedAt token rows ≤ tree token := by
  have h := arbitrary_trace_conserves_each_token_exactly rows tree admitted token
  omega

theorem omitted_token_debit_is_zero {Path : Type} (rows : List (DebitRow Path)) (token : Nat)
    (absent : ∀ r ∈ rows, token ≠ r.transfer.tokenIndex) : debitedAt token rows = 0 := by
  induction rows with
  | nil => rfl
  | cons r rs ih =>
      have ht : ∀ s ∈ rs, token ≠ s.transfer.tokenIndex := by
        intro s hs; exact absent s (by simp [hs])
      simp [debitedAt, absent r (by simp), ih ht]

theorem absent_token_balance_is_unchanged {Path : Type} (rows : List (DebitRow Path))
    (tree : AssetMap) (admitted : AdmittedDebits rows tree) (token : Nat)
    (absent : ∀ r ∈ rows, token ≠ r.transfer.tokenIndex) : assetUpdates rows tree token = tree token := by
  have h := arbitrary_trace_conserves_each_token_exactly rows tree admitted token
  simpa [omitted_token_debit_is_zero rows token absent] using h

def amountSum {Path : Type} : List (DebitRow Path) → Nat
  | [] => 0
  | r :: rs => r.transfer.amount + amountSum rs

theorem same_token_trace_sums_all_deductions {Path : Type} (rows : List (DebitRow Path))
    (token : Nat) (same : ∀ r ∈ rows, r.transfer.tokenIndex = token) :
    debitedAt token rows = amountSum rows := by
  induction rows with
  | nil => rfl
  | cons r rs ih =>
      have ht : ∀ s ∈ rs, s.transfer.tokenIndex = token := by
        intro s hs; exact same s (by simp [hs])
      simp [debitedAt, amountSum, same r (by simp), ih ht]

theorem arbitrary_repeated_token_spends_do_not_overwrite_earlier_debits {Path : Type}
    (rows : List (DebitRow Path)) (tree : AssetMap) (token : Nat)
    (same : ∀ r ∈ rows, r.transfer.tokenIndex = token) (admitted : AdmittedDebits rows tree) :
    assetUpdates rows tree token + amountSum rows = tree token := by
  have h := arbitrary_trace_conserves_each_token_exactly rows tree admitted token
  rw [same_token_trace_sums_all_deductions rows token same] at h
  exact h

/-- Explicit u32 limb subtraction relation from sub_u32 (least-significant
    limb first): result + subtrahend + incoming borrow = minuend + B*outgoing.
    Correct gadget lowering must also provide the limb/borrow ranges. -/
structure SubLimb where
  before : Nat
  amount : Nat
  result : Nat
  outgoingBorrow : Nat

def BorrowChain : Nat → List SubLimb → Nat → Prop
  | incoming, [], finalBorrow => incoming = finalBorrow
  | incoming, s :: ss, finalBorrow =>
      s.before < wordBase ∧ s.amount < wordBase ∧ s.result < wordBase ∧
      incoming ≤ 1 ∧ s.outgoingBorrow ≤ 1 ∧
      s.result + s.amount + incoming = s.before + wordBase * s.outgoingBorrow ∧
      BorrowChain s.outgoingBorrow ss finalBorrow

def littleValue : List Nat → Nat
  | [] => 0
  | x :: xs => x + wordBase * littleValue xs

theorem borrow_chain_exact_integer_equation (steps : List SubLimb) (incoming finalBorrow : Nat)
    (h : BorrowChain incoming steps finalBorrow) :
    littleValue (steps.map SubLimb.result) + littleValue (steps.map SubLimb.amount) + incoming =
      littleValue (steps.map SubLimb.before) + wordBase ^ steps.length * finalBorrow := by
  induction steps generalizing incoming with
  | nil => simpa [littleValue] using h
  | cons s ss ih =>
      have hi := ih s.outgoingBorrow h.2.2.2.2.2.2
      have he := h.2.2.2.2.2.1
      simp only [List.map_cons, littleValue, List.length_cons, Nat.pow_succ]
      have scaled := congrArg (fun n : Nat => wordBase * n) hi
      simp only [Nat.mul_add, Nat.mul_assoc] at scaled
      rw [Nat.mul_comm (wordBase ^ ss.length) wordBase, Nat.mul_assoc]
      omega

theorem final_zero_borrow_proves_exact_nonunderflow_subtraction (steps : List SubLimb)
    (h : BorrowChain 0 steps 0) :
    littleValue (steps.map SubLimb.result) + littleValue (steps.map SubLimb.amount) =
      littleValue (steps.map SubLimb.before) ∧
    littleValue (steps.map SubLimb.amount) ≤ littleValue (steps.map SubLimb.before) := by
  have he := borrow_chain_exact_integer_equation steps 0 0 h
  simp only [Nat.add_zero, Nat.mul_zero] at he
  exact ⟨he, by omega⟩

/-- Concrete eight-limb input binding for one actual sub_u32 trace. This is
    the data extraction/lowering boundary also modeled independently in
    Implementation/U256Arithmetic.lean; no aggregate U256 safety premise. -/
def SubtractionTraceAt {Path : Type} (r : DebitRow Path) : Prop :=
  ∃ steps : List SubLimb, steps.length = 8 ∧ BorrowChain 0 steps 0 ∧
    r.beforeBalance = littleValue (steps.map SubLimb.before) ∧
    r.transfer.amount = littleValue (steps.map SubLimb.amount)

theorem concrete_subtraction_trace_derives_no_underflow {Path : Type} (r : DebitRow Path)
    (trace : SubtractionTraceAt r) : r.transfer.amount ≤ r.beforeBalance := by
  obtain ⟨steps, _, borrow, before, amount⟩ := trace
  rw [before, amount]
  exact (final_zero_borrow_proves_exact_nonunderflow_subtraction steps borrow).2

theorem concrete_subtraction_output_matches_natural_difference {Path : Type} (r : DebitRow Path)
    (steps : List SubLimb) (borrow : BorrowChain 0 steps 0)
    (before : r.beforeBalance = littleValue (steps.map SubLimb.before))
    (amount : r.transfer.amount = littleValue (steps.map SubLimb.amount)) :
    littleValue (steps.map SubLimb.result) = afterBalance r := by
  have he := (final_zero_borrow_proves_exact_nonunderflow_subtraction steps borrow).1
  simp only [afterBalance, before, amount]
  omega

/-- One concrete gadget trace includes its actual output value, so the raw
    running-root fold below is not assumed to use a precomputed safe debit. -/
def SubtractionOutputTraceAt {Path : Type} (r : DebitRow Path) (output : Nat) : Prop :=
  ∃ steps : List SubLimb, steps.length = 8 ∧ BorrowChain 0 steps 0 ∧
    r.beforeBalance = littleValue (steps.map SubLimb.before) ∧
    r.transfer.amount = littleValue (steps.map SubLimb.amount) ∧
    output = littleValue (steps.map SubLimb.result)

theorem output_trace_supplies_input_trace_and_exact_result {Path : Type}
    (r : DebitRow Path) (output : Nat) (trace : SubtractionOutputTraceAt r output) :
    SubtractionTraceAt r ∧ output = afterBalance r := by
  obtain ⟨steps, length, borrow, before, amount, result⟩ := trace
  exact ⟨⟨steps, length, borrow, before, amount⟩,
    result.trans (concrete_subtraction_output_matches_natural_difference r steps borrow before amount)⟩

/-- Local range/path constraints and the concrete eight-limb sub_u32 traces.
    There is NO amount<=before premise and no aggregate conservation premise.
    Crucially the next Merkle opening uses the actual subtraction output. -/
def RawDebitGates {Root Path : Type} (m : AssetMerkle Root Path) :
    List (DebitRow Path) → Root → Prop
  | [], _ => True
  | r :: rs, root =>
      m.pathRoot r.path r.beforeBalance r.transfer.tokenIndex = root ∧
      r.transfer.tokenIndex < wordBase ∧ r.beforeBalance < amountLimit ∧
      r.transfer.amount < amountLimit ∧
      ∃ output, SubtractionOutputTraceAt r output ∧
        RawDebitGates m rs (m.pathRoot r.path output r.transfer.tokenIndex)

theorem local_limb_traces_derive_all_sequential_debit_gates {Root Path : Type}
    (m : AssetMerkle Root Path) (rows : List (DebitRow Path)) (root : Root)
    (raw : RawDebitGates m rows root) : DebitGates m rows root := by
  induction rows generalizing root with
  | nil => trivial
  | cons r rs ih =>
      obtain ⟨opening, keyRange, beforeRange, amountRange, output, trace, tail⟩ := raw
      obtain ⟨inputTrace, result⟩ := output_trace_supplies_input_trace_and_exact_result r output trace
      refine ⟨opening, keyRange, beforeRange, amountRange,
        concrete_subtraction_trace_derives_no_underflow r inputTrace, ?_⟩
      rw [result] at tail
      exact ih _ tail

theorem scoped_paths_and_local_limb_traces_prove_conservation {Root Path : Type}
    (m : AssetMerkle Root Path) (rows : List (DebitRow Path)) (tree : AssetMap)
    (contracts : ScopedPathContracts m rows tree) (raw : RawDebitGates m rows (m.encode tree)) :
    debitRootFold m rows (m.encode tree) = m.encode (assetUpdates rows tree) ∧
    ∀ token, assetUpdates rows tree token + debitedAt token rows = tree token := by
  exact proved_asset_root_encodes_per_token_conservation m rows tree contracts
    (local_limb_traces_derive_all_sequential_debit_gates m rows (m.encode tree) raw)

structure Witness (Path SentPath : Type) where
  txNonce : Nat
  previousState : PrivateState
  transfers : List Transfer
  beforeBalances : List Nat
  assetPaths : List Path
  sentPath : SentPath

def vectorLengthsCorrect {Path SentPath : Type} (w : Witness Path SentPath) : Bool :=
  decide (w.transfers.length = maxTransfers ∧ w.beforeBalances.length = maxTransfers ∧
    w.assetPaths.length = maxTransfers)

def zipRows {Path : Type} : List Transfer → List Nat → List Path → List (DebitRow Path)
  | t :: ts, b :: bs, p :: ps => ⟨t,b,p⟩ :: zipRows ts bs ps
  | _, _, _ => []

def witnessRows {Path SentPath : Type} (w : Witness Path SentPath) : List (DebitRow Path) :=
  zipRows w.transfers w.beforeBalances w.assetPaths

theorem zip_rows_preserves_complete_equal_length_vectors {Path : Type}
    (transfers : List Transfer) (balances : List Nat) (paths : List Path)
    (hb : balances.length = transfers.length) (hp : paths.length = transfers.length) :
    (zipRows transfers balances paths).length = transfers.length := by
  induction transfers generalizing balances paths with
  | nil => simp [zipRows]
  | cons t ts ih =>
      cases balances with
      | nil => simp at hb
      | cons b bs =>
          cases paths with
          | nil => simp at hp
          | cons p ps =>
              simp only [List.length_cons, Nat.add_right_cancel_iff] at hb hp
              simpa only [zipRows, List.length_cons] using congrArg (fun n => n + 1) (ih bs ps hb hp)

theorem witness_length_gate_includes_all_64_rows {Path SentPath : Type}
    (w : Witness Path SentPath) (lengths : vectorLengthsCorrect w = true) :
    (witnessRows w).length = maxTransfers := by
  have h : w.transfers.length = maxTransfers ∧ w.beforeBalances.length = maxTransfers ∧
      w.assetPaths.length = maxTransfers := by simpa [vectorLengthsCorrect] using lengths
  exact (zip_rows_preserves_complete_equal_length_vectors w.transfers w.beforeBalances w.assetPaths
    (h.2.1.trans h.1.symm) (h.2.2.trans h.1.symm)).trans h.1

def Witness.NativeTyped {Path SentPath : Type} (w : Witness Path SentPath) : Prop :=
  w.txNonce < wordBase ∧ w.previousState.nonce < wordBase ∧
  (∀ t ∈ w.transfers, t.NativeTyped) ∧ (∀ b ∈ w.beforeBalances, b < amountLimit)

inductive OverflowMode where
  | checked
  | wrapping
  deriving DecidableEq, Repr

def nativeNonceIncrement (mode : OverflowMode) (nonce : Nat) : Option Nat :=
  match mode with
  | .checked => if nonce + 1 < wordBase then some (nonce + 1) else none
  | .wrapping => some ((nonce + 1) % wordBase)

def fieldNonceIncrement (fieldOrder nonce : Nat) : Nat := (nonce + 1) % fieldOrder

theorem native_field_nonce_agreement_requires_nonoverflow
    (mode : OverflowMode) (fieldOrder nonce : Nat)
    (nonoverflow : nonce + 1 < wordBase) (fieldLarge : wordBase ≤ fieldOrder) :
    nativeNonceIncrement mode nonce = some (nonce + 1) ∧
    fieldNonceIncrement fieldOrder nonce = nonce + 1 := by
  have hf : nonce + 1 < fieldOrder := Nat.lt_of_lt_of_le nonoverflow fieldLarge
  constructor
  · cases mode <;> simp [nativeNonceIncrement, nonoverflow, Nat.mod_eq_of_lt nonoverflow]
  · simp [fieldNonceIncrement, Nat.mod_eq_of_lt hf]

/-- Native profile panics are not silently changed into a SpendError return. -/
inductive RunFault where
  | spend (error : Error)
  | nativeNonceOverflow
  | witnessShapePanic
  deriving DecidableEq, Repr

structure Environment (Path SentPath : Type) where
  asset : AssetMerkle Hash4 Path
  nativeTransferRoot : List Transfer → Except Error Hash4
  targetTransferRoot : List Transfer → Hash4
  sentPathRoot : SentPath → Tx → Nat → Hash4
  privateHash : List Nat → Hash4
  assetPathHeight : Path → Nat
  sentPathHeight : SentPath → Nat
  fieldOrder : Nat

/-- Source native loop: verify opening BEFORE insufficient-balance test, then
    feed each computed new root directly to the next iteration. -/
def nativeDebitFold {Path : Type} (m : AssetMerkle Hash4 Path) :
    List (DebitRow Path) → Hash4 → Except Error Hash4
  | [], root => .ok root
  | r :: rs, root =>
      if m.pathRoot r.path r.beforeBalance r.transfer.tokenIndex ≠ root then
        .error .invalidMerkleProof
      else if r.beforeBalance < r.transfer.amount then .error .insufficientBalance
      else nativeDebitFold m rs (m.pathRoot r.path (afterBalance r) r.transfer.tokenIndex)

def nextPrivateState (hash : List Nat → Hash4) (previous : PrivateState)
    (assetRoot sentRoot : Hash4) (nonce : Nat) : PrivateState :=
  { assetTreeRoot := assetRoot
    nullifierTreeRoot := previous.nullifierTreeRoot
    sentTxTreeRoot := sentRoot
    previousPrivateCommitment := hash previous.words
    nonce := nonce
    salt := previous.salt }

def assemblePublicInputs (hash : List Nat → Hash4) (previous : PrivateState)
    (assetRoot sentRoot : Hash4) (tx : Tx) (newNonce : Nat) : PublicInputs :=
  { previousPrivateCommitment := hash previous.words
    newPrivateCommitment := hash (nextPrivateState hash previous assetRoot sentRoot newNonce).words
    tx := tx
    isValid := decide (tx.nonce = previous.nonce) }

/-- Pure value/error precedence translation; allocation/resource/panic effects
    inside opaque hash/proof helpers are separate refinement boundaries. -/
def nativeToPublicInputs {Path SentPath : Type} (env : Environment Path SentPath)
    (mode : OverflowMode) (w : Witness Path SentPath) : Except RunFault PublicInputs :=
  if !vectorLengthsCorrect w then .error (.spend .invalidNumInputs)
  else match nativeDebitFold env.asset (witnessRows w) w.previousState.assetTreeRoot with
  | .error error => .error (.spend error)
  | .ok assetRoot => match env.nativeTransferRoot w.transfers with
    | .error _ => .error (.spend .invalidData)
    | .ok transferRoot =>
      let tx : Tx := ⟨transferRoot, w.txNonce⟩
      if env.sentPathRoot w.sentPath emptyTx w.txNonce ≠ w.previousState.sentTxTreeRoot then
        .error (.spend .invalidMerkleProof)
      else
        let sentRoot := env.sentPathRoot w.sentPath tx w.txNonce
        match nativeNonceIncrement mode w.previousState.nonce with
        | none => .error .nativeNonceOverflow
        | some newNonce => .ok (assemblePublicInputs env.privateHash w.previousState assetRoot sentRoot tx newNonce)

def targetPublicInputs {Path SentPath : Type} (env : Environment Path SentPath)
    (w : Witness Path SentPath) : PublicInputs :=
  let assetRoot := debitRootFold env.asset (witnessRows w) w.previousState.assetTreeRoot
  let tx : Tx := ⟨env.targetTransferRoot w.transfers, w.txNonce⟩
  let sentRoot := env.sentPathRoot w.sentPath tx w.txNonce
  assemblePublicInputs env.privateHash w.previousState assetRoot sentRoot tx
    (fieldNonceIncrement env.fieldOrder w.previousState.nonce)

structure CircuitGates {Path SentPath : Type} (env : Environment Path SentPath)
    (w : Witness Path SentPath) : Prop where
  lengths : vectorLengthsCorrect w = true
  txNonceRange : w.txNonce < wordBase
  allocations : ∀ t ∈ w.transfers, t.AllocationChecks
  beforeRanges : ∀ b ∈ w.beforeBalances, b < amountLimit
  assetPaths : ∀ p ∈ w.assetPaths, env.assetPathHeight p = assetTreeHeight
  sentPath : env.sentPathHeight w.sentPath = sentTreeHeight
  debit : DebitGates env.asset (witnessRows w) w.previousState.assetTreeRoot
  sentEmpty : env.sentPathRoot w.sentPath emptyTx w.txNonce = w.previousState.sentTxTreeRoot

/-- Raw constructor denotation stops at concrete local subtraction equations,
    not at a claimed U256 nonunderflow or asset-conservation conclusion. -/
structure RawCircuitGates {Path SentPath : Type} (env : Environment Path SentPath)
    (w : Witness Path SentPath) : Prop where
  lengths : vectorLengthsCorrect w = true
  txNonceRange : w.txNonce < wordBase
  allocations : ∀ t ∈ w.transfers, t.AllocationChecks
  beforeRanges : ∀ b ∈ w.beforeBalances, b < amountLimit
  assetPaths : ∀ p ∈ w.assetPaths, env.assetPathHeight p = assetTreeHeight
  sentPath : env.sentPathHeight w.sentPath = sentTreeHeight
  debit : RawDebitGates env.asset (witnessRows w) w.previousState.assetTreeRoot
  sentEmpty : env.sentPathRoot w.sentPath emptyTx w.txNonce = w.previousState.sentTxTreeRoot

theorem raw_constructor_gates_derive_circuit_gates {Path SentPath : Type}
    (env : Environment Path SentPath) (w : Witness Path SentPath) (raw : RawCircuitGates env w) :
    CircuitGates env w := by
  exact ⟨raw.lengths, raw.txNonceRange, raw.allocations, raw.beforeRanges,
    raw.assetPaths, raw.sentPath,
    local_limb_traces_derive_all_sequential_debit_gates env.asset (witnessRows w)
      w.previousState.assetTreeRoot raw.debit, raw.sentEmpty⟩

abbrev SentMap := Nat → Tx

def putSentTx (tree : SentMap) (nonce : Nat) (tx : Tx) : SentMap :=
  fun index => if index = nonce then tx else tree index

/-- One concrete sent-tree empty opening and replacement premise. No global
    opening law for all Tx maps, and no unrelated nonce/path, is assumed. -/
def SentPathContractAt {Path SentPath : Type} (env : Environment Path SentPath)
    (encode : SentMap → Hash4) (tree : SentMap) (w : Witness Path SentPath) : Prop :=
  let tx : Tx := ⟨env.targetTransferRoot w.transfers, w.txNonce⟩
  env.sentPathRoot w.sentPath emptyTx w.txNonce = encode tree →
  tree w.txNonce = emptyTx ∧
  env.sentPathRoot w.sentPath tx w.txNonce = encode (putSentTx tree w.txNonce tx)

theorem scoped_sent_path_inserts_only_at_the_opened_empty_nonce {Path SentPath : Type}
    (env : Environment Path SentPath) (w : Witness Path SentPath) (encode : SentMap → Hash4)
    (tree : SentMap) (g : CircuitGates env w)
    (opening : w.previousState.sentTxTreeRoot = encode tree)
    (contractAt : SentPathContractAt env encode tree w) :
    tree w.txNonce = emptyTx ∧
    (∀ index, index ≠ w.txNonce →
      putSentTx tree w.txNonce ⟨env.targetTransferRoot w.transfers, w.txNonce⟩ index = tree index) ∧
    env.sentPathRoot w.sentPath ⟨env.targetTransferRoot w.transfers, w.txNonce⟩ w.txNonce =
      encode (putSentTx tree w.txNonce ⟨env.targetTransferRoot w.transfers, w.txNonce⟩) := by
  have he := contractAt (g.sentEmpty.trans opening)
  exact ⟨he.1, by intro index different; simp [putSentTx, different], he.2⟩

/-- This explicitly named obligation extracts actual allocation/range,
    split_le(height32), sub_u32 per-limb equations, hash and connection gates.
    It does NOT assume U256 no-underflow, safe aggregate deductions, or asset
    conservation; the local-limb-to-CircuitGates bridge is proved above. -/
def FieldAndGadgetLowering {Path SentPath : Type} (env : Environment Path SentPath)
    (rawSatisfied : Witness Path SentPath → Prop) : Prop :=
  ∀ w, rawSatisfied w → RawCircuitGates env w

theorem native_debit_fold_success_uses_same_ordered_root_fold {Path : Type}
    (m : AssetMerkle Hash4 Path) (rows : List (DebitRow Path)) (initial final : Hash4)
    (accepted : nativeDebitFold m rows initial = .ok final) :
    debitRootFold m rows initial = final := by
  induction rows generalizing initial with
  | nil => simpa [nativeDebitFold, debitRootFold] using accepted
  | cons r rs ih =>
      unfold nativeDebitFold at accepted
      split at accepted
      · contradiction
      · split at accepted
        · contradiction
        · exact ih _ accepted

theorem new_private_state_preserves_unrelated_roots_and_salt
    (hash : List Nat → Hash4) (previous : PrivateState) (assetRoot sentRoot : Hash4) (nonce : Nat) :
    (nextPrivateState hash previous assetRoot sentRoot nonce).nullifierTreeRoot = previous.nullifierTreeRoot ∧
    (nextPrivateState hash previous assetRoot sentRoot nonce).salt = previous.salt ∧
    (nextPrivateState hash previous assetRoot sentRoot nonce).previousPrivateCommitment = hash previous.words :=
  ⟨rfl,rfl,rfl⟩

theorem validity_bit_is_nonce_equality_not_a_required_true_gate
    (hash : List Nat → Hash4) (previous : PrivateState) (assetRoot sentRoot : Hash4)
    (tx : Tx) (newNonce : Nat) :
    (assemblePublicInputs hash previous assetRoot sentRoot tx newNonce).isValid = true ↔
      tx.nonce = previous.nonce := by simp [assemblePublicInputs]

theorem circuit_output_validity_requires_consumer_check {Path SentPath : Type}
    (env : Environment Path SentPath) (w : Witness Path SentPath) :
    (targetPublicInputs env w).isValid = true ↔ w.txNonce = w.previousState.nonce := by
  simp [targetPublicInputs, assemblePublicInputs]

theorem native_and_target_public_inputs_agree_on_nonoverflow_domain {Path SentPath : Type}
    (env : Environment Path SentPath) (mode : OverflowMode) (w : Witness Path SentPath) (p : PublicInputs)
    (accepted : nativeToPublicInputs env mode w = .ok p)
    (rootAgreement : env.nativeTransferRoot w.transfers = .ok (env.targetTransferRoot w.transfers))
    (nonoverflow : w.previousState.nonce + 1 < wordBase) (fieldLarge : wordBase ≤ env.fieldOrder) :
    p = targetPublicInputs env w := by
  unfold nativeToPublicInputs at accepted
  split at accepted
  · contradiction
  · split at accepted
    · contradiction
    next assetRoot hroot =>
      have ordered := native_debit_fold_success_uses_same_ordered_root_fold
        env.asset (witnessRows w) w.previousState.assetTreeRoot assetRoot hroot
      rw [rootAgreement] at accepted
      dsimp only at accepted
      split at accepted
      · contradiction
      · have hn := native_field_nonce_agreement_requires_nonoverflow mode env.fieldOrder
          w.previousState.nonce nonoverflow fieldLarge
        rw [hn.1] at accepted
        have hp := Except.ok.inj accepted
        rw [← hp]
        simp only [targetPublicInputs, ordered, hn.2]

theorem circuit_value_conservation_under_scoped_path_contracts {Path SentPath : Type}
    (env : Environment Path SentPath) (w : Witness Path SentPath) (tree : AssetMap)
    (g : CircuitGates env w) (opening : w.previousState.assetTreeRoot = env.asset.encode tree)
    (contracts : ScopedPathContracts env.asset (witnessRows w) tree) :
    debitRootFold env.asset (witnessRows w) w.previousState.assetTreeRoot =
      env.asset.encode (assetUpdates (witnessRows w) tree) ∧
    ∀ token, assetUpdates (witnessRows w) tree token + debitedAt token (witnessRows w) = tree token := by
  have gd := g.debit
  rw [opening] at gd ⊢
  exact proved_asset_root_encodes_per_token_conservation env.asset (witnessRows w) tree contracts gd

theorem raw_constraints_and_scoped_dependencies_prove_per_token_conservation
    {Path SentPath : Type} (env : Environment Path SentPath)
    (rawSatisfied : Witness Path SentPath → Prop) (lowering : FieldAndGadgetLowering env rawSatisfied)
    (w : Witness Path SentPath) (satisfied : rawSatisfied w) (tree : AssetMap)
    (opening : w.previousState.assetTreeRoot = env.asset.encode tree)
    (contracts : ScopedPathContracts env.asset (witnessRows w) tree) :
    debitRootFold env.asset (witnessRows w) w.previousState.assetTreeRoot =
      env.asset.encode (assetUpdates (witnessRows w) tree) ∧
    ∀ token, assetUpdates (witnessRows w) tree token + debitedAt token (witnessRows w) = tree token := by
  exact circuit_value_conservation_under_scoped_path_contracts env w tree
    (raw_constructor_gates_derive_circuit_gates env w (lowering w satisfied)) opening contracts

def targetWitnessShapeCorrect {Path SentPath : Type} (env : Environment Path SentPath)
    (w : Witness Path SentPath) : Bool :=
  vectorLengthsCorrect w && w.assetPaths.all (fun p => env.assetPathHeight p == assetTreeHeight) &&
    (env.sentPathHeight w.sentPath == sentTreeHeight)

def prove {Path SentPath Output : Type} (env : Environment Path SentPath)
    (mode : OverflowMode) (w : Witness Path SentPath)
    (backend : Witness Path SentPath → PublicInputs → Except String Output) : Except RunFault Output :=
  match nativeToPublicInputs env mode w with
  | .error error => .error error
  | .ok publicInputs =>
      if targetWitnessShapeCorrect env w then
        match backend w publicInputs with
        | .ok proof => .ok proof
        | .error _ => .error (.spend .failedToProve)
      else .error .witnessShapePanic

theorem proving_cannot_bypass_native_admission {Path SentPath Output : Type}
    (env : Environment Path SentPath) (mode : OverflowMode) (w : Witness Path SentPath)
    (backend : Witness Path SentPath → PublicInputs → Except String Output) (proof : Output)
    (accepted : prove env mode w backend = .ok proof) :
    ∃ p, nativeToPublicInputs env mode w = .ok p ∧ targetWitnessShapeCorrect env w = true ∧
      backend w p = .ok proof := by
  unfold prove at accepted
  split at accepted
  · contradiction
  next p hp =>
    split at accepted
    next hs =>
      split at accepted
      next result hb =>
        have he := Except.ok.inj accepted
        subst proof
        exact ⟨p,hp,hs,hb⟩
      · contradiction
    · contradiction

inductive BuildOp where
  | startStandardRecursion
  | allocateTxNonce
  | rangeTxNonce32
  | allocatePrivateUnchecked
  | allocateCheckedTransferExceptTokenIndex (row : Nat)
  | allocateCheckedBeforeU256 (row : Nat)
  | allocateAssetPath32 (row : Nat)
  | allocateSentPath32
  | verifyAssetBefore (row : Nat)
  | subtractU256FinalBorrowZero (row : Nat)
  | computeAssetAfterRoot (row : Nat)
  | computeTransferTree64
  | assembleTxFromRootAndWitnessNonce
  | constantEmptyTx
  | verifyEmptySentPath
  | computeInsertedSentRoot
  | hashPreviousPrivateState
  | addOneInFieldToPrivateNonce
  | assembleNewPrivateState
  | hashNewPrivateState
  | computeNonceEqualityBoolean
  | registerPublicInputs14
  | buildCircuit
  deriving DecidableEq, Repr

def constructorProgram : List BuildOp :=
  [.startStandardRecursion, .allocateTxNonce, .rangeTxNonce32, .allocatePrivateUnchecked] ++
  (List.range maxTransfers).map BuildOp.allocateCheckedTransferExceptTokenIndex ++
  (List.range maxTransfers).map BuildOp.allocateCheckedBeforeU256 ++
  (List.range maxTransfers).map BuildOp.allocateAssetPath32 ++ [.allocateSentPath32] ++
  (List.range maxTransfers).bind (fun i =>
    [.verifyAssetBefore i, .subtractU256FinalBorrowZero i, .computeAssetAfterRoot i]) ++
  [.computeTransferTree64, .assembleTxFromRootAndWitnessNonce, .constantEmptyTx,
   .verifyEmptySentPath, .computeInsertedSentRoot, .hashPreviousPrivateState,
   .addOneInFieldToPrivateNonce, .assembleNewPrivateState, .hashNewPrivateState,
   .computeNonceEqualityBoolean, .registerPublicInputs14, .buildCircuit]

inductive WitnessWriteOp where
  | assertTransfers64 | assertBeforeBalances64 | assertAssetPaths64
  | setTxNonce | setPreviousPrivateState
  | setTransfer (row : Nat) | setBeforeBalance (row : Nat) | setAssetPath (row : Nat)
  | setSentPath | setPreviousCommitment | setNewCommitment | setTx | setValidityBoolean
  deriving DecidableEq, Repr

def witnessWriteProgram : List WitnessWriteOp :=
  [.assertTransfers64, .assertBeforeBalances64, .assertAssetPaths64, .setTxNonce,
   .setPreviousPrivateState] ++
  (List.range maxTransfers).map WitnessWriteOp.setTransfer ++
  (List.range maxTransfers).map WitnessWriteOp.setBeforeBalance ++
  (List.range maxTransfers).map WitnessWriteOp.setAssetPath ++
  [.setSentPath, .setPreviousCommitment, .setNewCommitment, .setTx, .setValidityBoolean]

set_option maxRecDepth 4096 in
theorem constructor_performs_all_64_ordered_asset_updates :
    constructorProgram.filter (fun op => match op with
      | .verifyAssetBefore _ | .subtractU256FinalBorrowZero _ | .computeAssetAfterRoot _ => true
      | _ => false) =
      (List.range 64).bind (fun i =>
        [.verifyAssetBefore i, .subtractU256FinalBorrowZero i, .computeAssetAfterRoot i]) := by decide

theorem constructor_registers_flag_without_asserting_true :
    constructorProgram.reverse.take 3 =
      [.buildCircuit, .registerPublicInputs14, .computeNonceEqualityBoolean] := by decide

theorem witness_write_checks_vector_lengths_before_assignments :
    witnessWriteProgram.take 3 = [.assertTransfers64, .assertBeforeBalances64, .assertAssetPaths64] := by decide

/-- Serialization is modeled only as the actual ordered delegation/error
    mapping. The bincode consumed-byte count is intentionally discarded on
    input, as in source; no exact-end or trusted-circuit check is invented. -/
structure CircuitImage (Data Target PublicTargets : Type) where
  data : Data
  target : Target
  publicInputs : PublicTargets

structure SerializationFailure where
  stage : String
  detail : String
  deriving DecidableEq, Repr

def toBytes {Data Target PublicTargets : Type}
    (serializeData : Data → Except String (List Nat))
    (encode : CircuitImage (List Nat) Target PublicTargets → Except String (List Nat))
    (circuit : CircuitImage Data Target PublicTargets) : Except SerializationFailure (List Nat) :=
  match serializeData circuit.data with
  | .error e => .error ⟨"spend circuit data", e⟩
  | .ok data => match encode ⟨data, circuit.target, circuit.publicInputs⟩ with
    | .error e => .error ⟨"spend circuit", e⟩
    | .ok bytes => .ok bytes

def fromBytes {Data Target PublicTargets : Type}
    (decode : List Nat → Except String (CircuitImage (List Nat) Target PublicTargets × Nat))
    (deserializeData : List Nat → Except String Data) (bytes : List Nat) :
    Except SerializationFailure (CircuitImage Data Target PublicTargets) :=
  match decode bytes with
  | .error e => .error ⟨"spend circuit", e⟩
  | .ok (payload, _) => match deserializeData payload.data with
    | .error e => .error ⟨"spend circuit data", e⟩
    | .ok data => .ok ⟨data, payload.target, payload.publicInputs⟩

theorem serialization_preserves_payload_handles_after_success {Data Target PublicTargets : Type}
    (decode : List Nat → Except String (CircuitImage (List Nat) Target PublicTargets × Nat))
    (deserializeData : List Nat → Except String Data) (bytes : List Nat)
    (payload : CircuitImage (List Nat) Target PublicTargets) (consumed : Nat) (data : Data)
    (hd : decode bytes = .ok (payload, consumed)) (hc : deserializeData payload.data = .ok data) :
    fromBytes decode deserializeData bytes = .ok ⟨data, payload.target, payload.publicInputs⟩ := by
  simp [fromBytes, hd, hc]

def normalTransfer (token amount : Nat) : Transfer :=
  ⟨List.replicate 8 0, token, amount, List.replicate 8 0⟩

def normalDebitRows : List (DebitRow Unit) :=
  [⟨normalTransfer 17 7, 30, ()⟩, ⟨normalTransfer 17 9, 23, ()⟩,
   ⟨normalTransfer 3 4, 10, ()⟩]

def normalAssets : AssetMap := fun token => if token = 17 then 30 else if token = 3 then 10 else 0

theorem example_repeated_token_admission_is_nonempty : AdmittedDebits normalDebitRows normalAssets := by
  simp [AdmittedDebits, normalDebitRows, normalTransfer, normalAssets, putAsset, afterBalance]

theorem example_repeated_token_uses_running_balance :
    assetUpdates normalDebitRows normalAssets 17 = 14 ∧ debitedAt 17 normalDebitRows = 16 ∧
    assetUpdates normalDebitRows normalAssets 3 = 6 ∧ debitedAt 3 normalDebitRows = 4 ∧
    assetUpdates normalDebitRows normalAssets 5 = 0 := by decide

theorem example_normal_public_input_round_trip :
    let p : PublicInputs := ⟨zeroHash, zeroHash, ⟨zeroHash, 7⟩, true⟩
    parseNativePublicInputs p.targets.words = .ok p := by
  exact native_public_input_round_trip_on_typed_domain _ (by decide) []

theorem example_normal_borrow_chain_matches_subtraction :
    BorrowChain 0 [⟨30,7,23,0⟩, ⟨0,0,0,0⟩] 0 := by
  simp [BorrowChain, wordBase]

end Zkp.Implementation.Spend
