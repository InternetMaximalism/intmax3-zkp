import Std
import Zkp.Implementation.RollupValue

/-!
# Deposit hash chain: handwritten implementation-level semantics

Sources (runtime, current worktree):
- src/circuits/validity/deposit_hash_chain/deposit_step.rs (563 lines)
- src/circuits/validity/deposit_hash_chain/deposit_chain_pis.rs (301 lines)
- src/circuits/validity/deposit_hash_chain/deposit_hash_chain_circuit.rs (221 lines)

This is a SEMANTIC MODEL of those files, not a refinement proof of the Rust /
plonky2 code and not cryptographic soundness. Each deposit step appends one
L1 deposit to two accumulators: the Poseidon deposit tree (slot `deposit_count`
is opened as the empty leaf and re-rooted with the deposit leaf) and the keccak
deposit hash chain `keccak(prev ‖ depositor ‖ recipient ‖ token ‖ amount ‖ aux)`.
`deposit_index` and `block_number` are NOT part of the chain fold (they are part
of the Poseidon leaf / nullifier only); `deposit_index` is pinned to the running
count by a `connect`; `block_number` is copied into the public inputs and must
match the previous proof's block number on a continued step.

Native admission (`DepositStepWitness::to_public_inputs`, executable `Except`
mirroring the source order of checks) is modeled separately from arbitrary
satisfying witnesses (`CircuitGates`, the local gate equations of
`DepositStepTarget::new`). `nativeAssignment` is `set_witness`; the theorem
`native_assignment_satisfies_gates` links the two under explicit premises.
`Chain` composes step gates through the forwarding wrapper
(`DepositHashChainCircuit`) under the proof-soundness premise, and
`chain_matches_rollup_fold` states, under the named bridge premises, that the
circuit's chain value equals `RollupValue.finishDeposit`'s fold over the same
records (same initial value, same order, indices = running count).

Named boundaries (undischarged premises, all opaque callbacks or hypotheses):
- `HashCallbacks`: `Environment.keccakWords` (plonky2_keccak `solidity_keccak256`
  over u32 words), `poseidonWords` (`PoseidonHashOut::hash_inputs_u64`) and
  `twoToOne` (Poseidon 2-to-1 of the incremental Merkle tree) are opaque, never
  injective. No collision resistance is stated.
- `ProofSoundness`: `Environment.proofAccepted vd pis` is plonky2 verification of
  a proof carrying public inputs `pis` under verifier data `vd` (opaque Bool).
  `conditionally_verify_proof` checks the previous chain proof under the verifier
  data DECLARED IN THAT PROOF'S OWN PUBLIC INPUTS. "accepted ⇒ produced by a
  gate-satisfying witness" is the premise encoded by the `Chain` inductive; it is
  never stated as a theorem.
- `ConsumerVdPin`: on the initial step `new_pis.vd` is a FREE virtual verifier
  data (theorem `initial_step_vd_unconstrained`); it is forwarded unchanged by
  every continued step (`chain_declares_single_vd`). Only a consumer pins it to
  the real chain verifier data: `DepositHashChainCircuit::verify` →
  `check_cyclic_proof_verifier_data` (modeled: `chain_verify_pins_declared_vd`)
  or `block_step.rs` `add_proof_target_and_conditionally_verify_cyclic` (outside
  the modeled files).
- `FieldAndGadgetLowering`: Goldilocks arithmetic, `split_le`, range checks,
  `select`, keccak/Poseidon gadgets and `from_pis` slicing are modeled as Nat
  equations. `split_le(index, 63)` inside the Merkle gadget is what bounds the
  previous count below 2^63 (`CircuitGates.indexSplit`); the keccak gadget needs
  32-bit input limbs, which on a continued step the previous chain limbs only
  have through the previous proof's own keccak output (`KeccakOutputsChecked`).
- `SolidityKeccakPacking`: `solidity_keccak256` consumes each u32 word as four
  big-endian bytes (plonky2_keccak, not in the modeled files). Under that
  packing the circuit fold preimage is byte-identical to `RollupValue.hashPreimage
  (.deposit …)` (theorem `fold_preimage_matches_rollup_model`, kernel-checked);
  equality of the chain VALUES additionally needs both sides to call the same
  keccak (`KeccakBridge` + `RollupValue.HashEncodingAgrees`).
- `InitialStatePin`: the initial chain / root / count of a chain proof are free
  inputs of the initial step; `block_step.rs` pins them to the previous public
  state, and L1 finality of the deposits is outside every modeled file.
- `NativeMerkleHeight`: native `DepositMerkleProof::verify` uses `siblings.len()`
  as the height (`native_accepts_short_sibling_list`); the 63-sibling shape is
  enforced only by the target (`CircuitGates.siblingsHeight`) and by the
  `set_witness` length assertion.
- `NativeProofNotChecked`: `to_public_inputs` never verifies the supplied previous
  proof (it only parses its public inputs); `prove` fails later inside plonky2 if
  it is invalid. Modeled as the `hproof` premise of `native_assignment_satisfies_gates`.
- `VdCanonicity`: `vd_from_pis_slice` reads verifier-data field elements from
  u64 without a canonicity check; vd words are carried as opaque `List Nat`.
No proof soundness, hash injectivity, finality, or "accepted ⇒ funds safe" is
stated as a theorem.
-/

namespace Zkp.Implementation.DepositChain

/-! ## Pinned constants -/

def limbBase : Nat := 2 ^ 32
def u63Limit : Nat := 2 ^ 63
def u64Limit : Nat := 2 ^ 64
def goldilocks : Nat := 0xffffffff00000001
def bytes32Len : Nat := 8
def poseidonHashOutLen : Nat := 4
def addressLen : Nat := 5
def u256Len : Nat := 8
/-- constants::DEPOSIT_TREE_HEIGHT -/
def depositTreeHeight : Nat := 63
/-- DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN = 2 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN + 3 -/
def publicInputsLen : Nat := 2 * bytes32Len + 2 * poseidonHashOutLen + 3
/-- utils::cyclic::vd_vec_len = 4 + 4 * num_cap_elements -/
def vdVecLen (capElements : Nat) : Nat := 4 + 4 * capElements
/-- `generate_cd`: `common.num_public_inputs = DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN + vd_vec_len`. -/
def chainPublicInputCount (capElements : Nat) : Nat := publicInputsLen + vdVecLen capElements
/-- Number of u32 words hashed by `Deposit::hash_with_prev_hash`. -/
def foldWordCount : Nat := 38
/-- Number of u64 words hashed by `Deposit::poseidon_hash` (the tree leaf). -/
def leafWordCount : Nat := 32
/-- `generate_cd` pads with `1 << 12` noop gates. -/
def noopGates : Nat := 4096

theorem public_inputs_len_pinned : publicInputsLen = 27 := by decide
theorem deposit_tree_height_pinned : depositTreeHeight = 63 := rfl
theorem fold_word_count_pinned : foldWordCount = 8 + 5 + 8 + 1 + 8 + 8 := rfl
theorem vd_vec_len_pinned (cap : Nat) : vdVecLen cap = 4 + 4 * cap := rfl
theorem chain_public_input_count_pinned (cap : Nat) : chainPublicInputCount cap = 27 + (4 + 4 * cap) := by
  simp [chainPublicInputCount, publicInputsLen, vdVecLen, bytes32Len, poseidonHashOutLen]
theorem noop_gates_pinned : noopGates = 2 ^ 12 := by decide
theorem u63_limit_below_goldilocks : u63Limit + 1 < goldilocks := by decide

/-! ## Limb containers (u32 limbs, most significant first) -/

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

def Words8.words (x : Words8) : List Nat := [x.w0, x.w1, x.w2, x.w3, x.w4, x.w5, x.w6, x.w7]
def Words8.zero : Words8 := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩
def Words8.ofList (xs : List Nat) : Words8 :=
  ⟨xs.getD 0 0, xs.getD 1 0, xs.getD 2 0, xs.getD 3 0, xs.getD 4 0, xs.getD 5 0, xs.getD 6 0, xs.getD 7 0⟩

structure Words5 where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr

def Words5.words (x : Words5) : List Nat := [x.a0, x.a1, x.a2, x.a3, x.a4]
def Words5.zero : Words5 := ⟨0, 0, 0, 0, 0⟩

/-- PoseidonHashOut: four Goldilocks elements carried as Nat, no range gate. -/
structure Hash4 where
  h0 : Nat
  h1 : Nat
  h2 : Nat
  h3 : Nat
  deriving DecidableEq, Repr

def Hash4.words (h : Hash4) : List Nat := [h.h0, h.h1, h.h2, h.h3]
def Hash4.zero : Hash4 := ⟨0, 0, 0, 0⟩
def Hash4.ofList (xs : List Nat) : Hash4 := ⟨xs.getD 0 0, xs.getD 1 0, xs.getD 2 0, xs.getD 3 0⟩

def CheckedWords (xs : List Nat) : Prop := ∀ x ∈ xs, x < limbBase
/-- Executable form of `CheckedWords` (`U32LimbTrait::from_u64_slice` range loop). -/
def limbsChecked (xs : List Nat) : Bool := xs.all fun x => decide (x < limbBase)

theorem limbs_checked_iff (xs : List Nat) : limbsChecked xs = true ↔ CheckedWords xs := by
  simp [limbsChecked, CheckedWords]

/-- Big-endian limb value: `foldl (acc * 2^32 + limb)`. -/
def limbValue (xs : List Nat) : Nat := xs.foldl (fun acc x => acc * limbBase + x) 0
def Words8.value (x : Words8) : Nat := limbValue x.words
def Words5.value (x : Words5) : Nat := limbValue x.words

theorem words8_length (x : Words8) : x.words.length = bytes32Len := rfl
theorem words5_length (x : Words5) : x.words.length = addressLen := rfl
theorem hash4_length (h : Hash4) : h.words.length = poseidonHashOutLen := rfl
theorem words8_of_list_words (x : Words8) : Words8.ofList x.words = x := by
  cases x; rfl
theorem hash4_of_list_words (h : Hash4) : Hash4.ofList h.words = h := by
  cases h; rfl

/-! ## Deposit leaf (common::deposit::Deposit) -/

structure Deposit where
  depositIndex : Nat
  blockNumber : Nat
  depositor : Words5
  recipient : Words8
  tokenIndex : Nat
  amount : Words8
  auxData : Words8
  deriving DecidableEq, Repr

/-- `Deposit::default()` = `Deposit::empty_leaf()`. -/
def Deposit.empty : Deposit := ⟨0, 0, Words5.zero, Words8.zero, 0, Words8.zero, Words8.zero⟩

/-- `Deposit::to_u64_vec`: the Poseidon leaf / nullifier preimage (includes index and block). -/
def Deposit.toU64Vec (d : Deposit) : List Nat :=
  [d.depositIndex, d.blockNumber] ++ d.depositor.words ++ d.recipient.words ++ [d.tokenIndex] ++
    d.amount.words ++ d.auxData.words

/-- `Deposit::hash_with_prev_hash` preimage as u32 words: prev ‖ depositor ‖ recipient ‖ token ‖ amount ‖ aux.
    `deposit_index` and `block_number` are NOT included. -/
def Deposit.foldWords (prev : Words8) (d : Deposit) : List Nat :=
  prev.words ++ d.depositor.words ++ d.recipient.words ++ [d.tokenIndex] ++ d.amount.words ++ d.auxData.words

/-- Rust type widths of a native `Deposit` = the range gates of `DepositTarget::new(builder, true)`. -/
def Deposit.NativeWidths (d : Deposit) : Prop :=
  d.depositIndex < u63Limit ∧ d.blockNumber < u63Limit ∧ CheckedWords d.depositor.words ∧
    CheckedWords d.recipient.words ∧ d.tokenIndex < limbBase ∧ CheckedWords d.amount.words ∧
    CheckedWords d.auxData.words

theorem leaf_words_length (d : Deposit) : d.toU64Vec.length = leafWordCount := by
  simp [Deposit.toU64Vec, Words5.words, Words8.words, leafWordCount]

theorem fold_words_length (prev : Words8) (d : Deposit) : (Deposit.foldWords prev d).length = foldWordCount := by
  simp [Deposit.foldWords, Words5.words, Words8.words, foldWordCount]

/-- The chain fold ignores `deposit_index` and `block_number`. -/
theorem fold_omits_index_and_block (prev : Words8) (d : Deposit) (index block : Nat) :
    Deposit.foldWords prev { d with depositIndex := index, blockNumber := block } = Deposit.foldWords prev d := rfl

/-- The Poseidon leaf DOES commit to `deposit_index` (word 0) and `block_number` (word 1). -/
theorem leaf_commits_index_and_block (d : Deposit) :
    d.toU64Vec.getD 0 0 = d.depositIndex ∧ d.toU64Vec.getD 1 0 = d.blockNumber := by
  simp [Deposit.toU64Vec]

theorem empty_deposit_widths : Deposit.NativeWidths Deposit.empty := by
  simp [Deposit.NativeWidths, Deposit.empty, CheckedWords, Words5.zero, Words8.zero, Words5.words,
    Words8.words, u63Limit, limbBase]

/-- Fold preimage words are all 32-bit when the previous chain and the deposit are. -/
theorem fold_words_checked (prev : Words8) (d : Deposit) (hp : CheckedWords prev.words)
    (hd : d.NativeWidths) : CheckedWords (Deposit.foldWords prev d) := by
  obtain ⟨_, _, h1, h2, h3, h4, h5⟩ := hd
  simp only [CheckedWords, Deposit.foldWords, List.mem_append, List.mem_singleton] at *
  intro x hx
  rcases hx with ((((hx | hx) | hx) | hx) | hx) | hx
  · exact hp x hx
  · exact h1 x hx
  · exact h2 x hx
  · exact hx ▸ h3
  · exact h4 x hx
  · exact h5 x hx

/-! ## Deposit chain public inputs (deposit_chain_pis.rs) -/

structure PublicInputs where
  initialDepositHashChain : Words8
  initialDepositTreeRoot : Hash4
  initialDepositCount : Nat
  depositHashChain : Words8
  depositTreeRoot : Hash4
  depositCount : Nat
  blockNumber : Nat
  /-- `vd_to_vec`: circuit_digest (4) ++ cap elements (4 each), carried opaquely. -/
  vd : List Nat
  deriving DecidableEq, Repr

/-- `to_u64_vec` / `to_vec`: field order of the registered public inputs, vd LAST. -/
def PublicInputs.words (p : PublicInputs) : List Nat :=
  p.initialDepositHashChain.words ++ p.initialDepositTreeRoot.words ++ [p.initialDepositCount] ++
    p.depositHashChain.words ++ p.depositTreeRoot.words ++ [p.depositCount] ++ [p.blockNumber] ++ p.vd

/-- Values a native `DepositChainPublicInputs` can hold (Rust field types) = what `from_u64_slice` admits. -/
def PublicInputs.Canonical (cap : Nat) (p : PublicInputs) : Prop :=
  CheckedWords p.initialDepositHashChain.words ∧ p.initialDepositCount < u63Limit ∧
    CheckedWords p.depositHashChain.words ∧ p.depositCount < u63Limit ∧ p.blockNumber < u63Limit ∧
    p.vd.length = vdVecLen cap

/-- Range gates of `DepositChainPublicInputsTarget::new` (chain limbs u32, counts/block u63; roots and vd unchecked). -/
def PublicInputs.TargetAllocationChecks (p : PublicInputs) : Prop :=
  CheckedWords p.initialDepositHashChain.words ∧ p.initialDepositCount < u63Limit ∧
    CheckedWords p.depositHashChain.words ∧ p.depositCount < u63Limit ∧ p.blockNumber < u63Limit

/-- `DepositChainPublicInputsTarget::connect`: every field including the verifier data. -/
def PublicInputs.ConnectGates (p q : PublicInputs) : Prop :=
  p.initialDepositHashChain = q.initialDepositHashChain ∧ p.initialDepositTreeRoot = q.initialDepositTreeRoot ∧
    p.initialDepositCount = q.initialDepositCount ∧ p.depositHashChain = q.depositHashChain ∧
    p.depositTreeRoot = q.depositTreeRoot ∧ p.depositCount = q.depositCount ∧ p.blockNumber = q.blockNumber ∧
    p.vd = q.vd

/-- All-zero public inputs: the `DummyProof` fed to the proof target on an initial step. -/
def PublicInputs.dummy (cap : Nat) : PublicInputs :=
  ⟨Words8.zero, Hash4.zero, 0, Words8.zero, Hash4.zero, 0, 0, List.replicate (vdVecLen cap) 0⟩

theorem words_length (p : PublicInputs) : p.words.length = publicInputsLen + p.vd.length := by
  simp [PublicInputs.words, Words8.words, Hash4.words, publicInputsLen, bytes32Len, poseidonHashOutLen]
  omega

theorem connect_gates_iff_equal (p q : PublicInputs) : PublicInputs.ConnectGates p q ↔ p = q := by
  constructor
  · intro h
    obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7⟩ := h
    cases p; cases q
    simp only at h0 h1 h2 h3 h4 h5 h6 h7
    subst h0 h1 h2 h3 h4 h5 h6 h7
    rfl
  · intro h; subst h; exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem dummy_canonical (cap : Nat) : PublicInputs.Canonical cap (PublicInputs.dummy cap) := by
  simp [PublicInputs.Canonical, PublicInputs.dummy, CheckedWords, Words8.zero, Words8.words, limbBase, u63Limit]

/-! ### Native parser `from_u64_slice` -/

inductive ParseError where
  | invalidLength (expected actual : Nat)
  | parseError (field : String)
  deriving DecidableEq, Repr

def slice (xs : List Nat) (offset len : Nat) : List Nat := (xs.drop offset).take len

/-- `Bytes32::from_u64_slice`: every limb ≤ u32::MAX (`OutOfU32Range`), then exactly 8 limbs. -/
def parseBytes32 (field : String) (xs : List Nat) : Except ParseError Words8 :=
  if limbsChecked xs && xs.length == bytes32Len then .ok (Words8.ofList xs) else .error (.parseError field)

/-- `PoseidonHashOut::from_u64_slice`: length 4 only; NO canonicity / range check on the elements. -/
def parseHashOut (field : String) (xs : List Nat) : Except ParseError Hash4 :=
  if xs.length == poseidonHashOutLen then .ok (Hash4.ofList xs) else .error (.parseError field)

/-- `U63::new` / `BlockNumber::new`. -/
def parseU63 (field : String) (x : Nat) : Except ParseError Nat :=
  if x < u63Limit then .ok x else .error (.parseError field)

/-- `vd_from_pis_slice`: needs ≥ 4 + 4·cap elements and reads the LAST 4 + 4·cap of them
    (digest first, then cap elements); no canonicity check. -/
def parseVd (cap : Nat) (xs : List Nat) : Except ParseError (List Nat) :=
  if xs.length < vdVecLen cap then .error (.parseError "verifier data")
  else .ok (xs.drop (xs.length - vdVecLen cap))

/-- `DepositChainPublicInputs::from_u64_slice` (exact length, then cursor order of the source). -/
def parseU64 (cap : Nat) (inputs : List Nat) : Except ParseError PublicInputs := do
  let expected := publicInputsLen + vdVecLen cap
  if inputs.length ≠ expected then throw (.invalidLength expected inputs.length)
  let initialDepositHashChain ← parseBytes32 "initial_deposit_hash_chain" (slice inputs 0 bytes32Len)
  let initialDepositTreeRoot ← parseHashOut "initial_deposit_tree_root" (slice inputs 8 poseidonHashOutLen)
  let initialDepositCount ← parseU63 "initial_deposit_count" (inputs.getD 12 0)
  let depositHashChain ← parseBytes32 "deposit_hash_chain" (slice inputs 13 bytes32Len)
  let depositTreeRoot ← parseHashOut "deposit_tree_root" (slice inputs 21 poseidonHashOutLen)
  let depositCount ← parseU63 "deposit_count" (inputs.getD 25 0)
  let blockNumber ← parseU63 "block_number" (inputs.getD 26 0)
  let vd ← parseVd cap (slice inputs 27 (vdVecLen cap))
  pure { initialDepositHashChain, initialDepositTreeRoot, initialDepositCount, depositHashChain,
         depositTreeRoot, depositCount, blockNumber, vd }

/-- `from_pis` (target side): asserts `pis.len() >= 27 + vd_len` (panic = `none`), slices with NO
    range gates, ignores trailing words. -/
def parseTargets (cap : Nat) (pis : List Nat) : Option PublicInputs :=
  if pis.length < publicInputsLen + vdVecLen cap then none
  else some { initialDepositHashChain := Words8.ofList (slice pis 0 bytes32Len)
              initialDepositTreeRoot := Hash4.ofList (slice pis 8 poseidonHashOutLen)
              initialDepositCount := pis.getD 12 0
              depositHashChain := Words8.ofList (slice pis 13 bytes32Len)
              depositTreeRoot := Hash4.ofList (slice pis 21 poseidonHashOutLen)
              depositCount := pis.getD 25 0
              blockNumber := pis.getD 26 0
              vd := slice pis 27 (vdVecLen cap) }

theorem bind_ok_iff {ε α β : Type} (r : Except ε α) (f : α → Except ε β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem pure_ok_iff {ε α : Type} (a value : α) : (pure a : Except ε α) = .ok value ↔ a = value := by
  simp [Pure.pure, Except.pure]

theorem throw_ok_iff_false {ε α : Type} (err : ε) (value : α) : (throw err : Except ε α) = .ok value ↔ False := by
  simp [throw, throwThe, MonadExcept.throw, Except.error]

theorem parse_bytes32_ok_iff (field : String) (xs : List Nat) (w : Words8) :
    parseBytes32 field xs = .ok w ↔ CheckedWords xs ∧ xs.length = bytes32Len ∧ w = Words8.ofList xs := by
  unfold parseBytes32
  split
  · rename_i h
    simp only [Bool.and_eq_true, beq_iff_eq, limbs_checked_iff] at h
    simp [h, eq_comm]
  · rename_i h
    simp only [Bool.and_eq_true, beq_iff_eq, limbs_checked_iff, not_and] at h
    constructor
    · intro contra; cases contra
    · intro ⟨h1, h2, _⟩; exact absurd h2 (h h1)

theorem parse_hash_out_ok_iff (field : String) (xs : List Nat) (h : Hash4) :
    parseHashOut field xs = .ok h ↔ xs.length = poseidonHashOutLen ∧ h = Hash4.ofList xs := by
  unfold parseHashOut
  split
  · rename_i hl; simp only [beq_iff_eq] at hl; simp [hl, eq_comm]
  · rename_i hl; simp only [beq_iff_eq] at hl
    constructor
    · intro contra; cases contra
    · intro ⟨h1, _⟩; exact absurd h1 hl

theorem parse_u63_ok_iff (field : String) (x v : Nat) : parseU63 field x = .ok v ↔ x < u63Limit ∧ v = x := by
  unfold parseU63
  split
  · rename_i hl; simp [hl, eq_comm]
  · rename_i hl
    constructor
    · intro contra; cases contra
    · intro ⟨h1, _⟩; exact absurd h1 hl

theorem parse_vd_ok_iff (cap : Nat) (xs vd : List Nat) :
    parseVd cap xs = .ok vd ↔ vdVecLen cap ≤ xs.length ∧ vd = xs.drop (xs.length - vdVecLen cap) := by
  unfold parseVd
  split
  · rename_i hl
    constructor
    · intro contra; cases contra
    · intro ⟨h1, _⟩; omega
  · rename_i hl; simp [eq_comm]; omega

/-- Exact-length guard: `InvalidLength` before any field parse. -/
theorem parse_rejects_wrong_length (cap : Nat) (inputs : List Nat)
    (h : inputs.length ≠ publicInputsLen + vdVecLen cap) :
    parseU64 cap inputs = .error (.invalidLength (publicInputsLen + vdVecLen cap) inputs.length) := by
  simp [parseU64, h, throw, throwThe, MonadExcept.throw, Bind.bind, Except.bind]

/-- Whatever `from_u64_slice` returns satisfies the Rust field types (chain limbs u32, counts u63,
    exact vd length) — and nothing more: tree roots are NOT range checked. -/
theorem parse_gives_canonical (cap : Nat) (inputs : List Nat) (p : PublicInputs)
    (accepted : parseU64 cap inputs = .ok p) : p.Canonical cap ∧ p.words = inputs := by
  by_cases hl : inputs.length = publicInputsLen + vdVecLen cap
  · simp only [parseU64, hl, ne_eq, not_true_eq_false, ite_false, bind_ok_iff, pure_ok_iff,
      parse_bytes32_ok_iff, parse_hash_out_ok_iff, parse_u63_ok_iff, parse_vd_ok_iff] at accepted
    obtain ⟨_, ⟨c1, l1, e1⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨l2, e2⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨c3, e3⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨c4, l4, e4⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨l5, e5⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨c6, e6⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨c7, e7⟩, accepted⟩ := accepted
    obtain ⟨_, ⟨l8, e8⟩, accepted⟩ := accepted
    subst e1 e2 e3 e4 e5 e6 e7 e8
    subst accepted
    have hlen : publicInputsLen + vdVecLen cap = 27 + vdVecLen cap := by
      simp [publicInputsLen, bytes32Len, poseidonHashOutLen]
    rw [hlen] at hl
    -- expose the 27 leading words
    obtain ⟨x0, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x1, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x2, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x3, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x4, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x5, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x6, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x7, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x8, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x9, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x10, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x11, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x12, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x13, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x14, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x15, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x16, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x17, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x18, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x19, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x20, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x21, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x22, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x23, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x24, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x25, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    obtain ⟨x26, inputs, rfl⟩ : ∃ x xs, inputs = x :: xs := by
      cases inputs with | nil => simp at hl | cons x xs => exact ⟨x, xs, rfl⟩
    simp only [List.length_cons] at hl
    have hvd : inputs.length = vdVecLen cap := by omega
    have hsl : slice (x0 :: x1 :: x2 :: x3 :: x4 :: x5 :: x6 :: x7 :: x8 :: x9 :: x10 :: x11 :: x12 :: x13 ::
        x14 :: x15 :: x16 :: x17 :: x18 :: x19 :: x20 :: x21 :: x22 :: x23 :: x24 :: x25 :: x26 :: inputs)
        27 (vdVecLen cap) = inputs := by
      simp only [slice, List.drop_succ_cons, List.drop_zero]
      rw [← hvd, List.take_length]
    refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_⟩, ?_⟩
    · simpa [slice, Words8.ofList, Words8.words] using c1
    · simpa using c3
    · simpa [slice, Words8.ofList, Words8.words] using c4
    · simpa using c6
    · simpa using c7
    · rw [hsl] at l8 ⊢
      simp only [Nat.sub_self, List.drop_zero]
      exact hvd
    · rw [hsl]
      simp [PublicInputs.words, Words8.words, Hash4.words, Words8.ofList, Hash4.ofList, slice,
        Nat.sub_self]
  · rw [parse_rejects_wrong_length cap inputs hl] at accepted
    cases accepted

/-- Canonical values round-trip through `to_u64_vec` / `from_u64_slice`. -/
theorem parse_round_trip (cap : Nat) (p : PublicInputs) (h : p.Canonical cap) :
    parseU64 cap p.words = .ok p := by
  obtain ⟨c1, c2, c3, c4, c5, c6⟩ := h
  have hl : p.words.length = publicInputsLen + vdVecLen cap := by rw [words_length, c6]
  have c1' := (limbs_checked_iff _).mpr c1
  have c3' := (limbs_checked_iff _).mpr c3
  cases p with
  | mk ic ir icnt c r cnt blk vd =>
  simp only at c1' c2 c3' c4 c5 c6 hl ⊢
  cases ic; cases ir; cases c; cases r
  simp only [PublicInputs.words, Words8.words, Hash4.words, List.cons_append, List.nil_append] at hl ⊢
  simp only [parseU64, hl, ne_eq, not_true_eq_false, ite_false, slice, List.drop_succ_cons, List.drop_zero,
    List.take_succ_cons, List.take_zero, List.getD_cons_zero, List.getD_cons_succ, parseBytes32,
    parseHashOut, parseU63, parseVd, Words8.words] at c1' c3' ⊢
  rw [← c6, List.take_length]
  simp only [c1', c3', c2, c4, c5, Words8.ofList, Hash4.ofList, List.getD_cons_zero, List.getD_cons_succ,
    List.length_cons, List.length_nil, Bool.and_self, bytes32Len, poseidonHashOutLen, beq_self_eq_true,
    ite_true, Nat.sub_self, List.drop_zero, Bind.bind, Except.bind, pure, Except.pure]

/-- `from_pis` is a pure slice: any sufficiently long word vector parses, unchecked. -/
theorem parse_targets_of_length (cap : Nat) (pis : List Nat)
    (h : publicInputsLen + vdVecLen cap ≤ pis.length) : ∃ p, parseTargets cap pis = some p := by
  refine ⟨_, ?_⟩
  simp [parseTargets, Nat.not_lt.mpr h]

theorem parse_targets_rejects_short (cap : Nat) (pis : List Nat)
    (h : pis.length < publicInputsLen + vdVecLen cap) : parseTargets cap pis = none := by
  simp [parseTargets, h]

/-- Target slicing reads back exactly the registered layout (no gates involved). -/
theorem parse_targets_round_trip (cap : Nat) (p : PublicInputs) (h : p.vd.length = vdVecLen cap) :
    parseTargets cap p.words = some p := by
  have hl : p.words.length = publicInputsLen + vdVecLen cap := by rw [words_length, h]
  cases p with
  | mk ic ir icnt c r cnt blk vd =>
  simp only at h hl ⊢
  cases ic; cases ir; cases c; cases r
  simp only [PublicInputs.words, Words8.words, Hash4.words, List.cons_append, List.nil_append] at hl ⊢
  simp only [parseTargets, hl, Nat.lt_irrefl, ite_false, slice, List.drop_succ_cons, List.drop_zero,
    List.take_succ_cons, List.take_zero, List.getD_cons_zero, List.getD_cons_succ, Words8.ofList,
    Hash4.ofList, bytes32Len, poseidonHashOutLen, Option.some.injEq]
  rw [← h, List.take_length]

/-- Native parse success ⇒ the in-circuit slice of the same words agrees (same values, no gates). -/
theorem parse_targets_agrees_with_native (cap : Nat) (inputs : List Nat) (p : PublicInputs)
    (accepted : parseU64 cap inputs = .ok p) : parseTargets cap inputs = some p := by
  obtain ⟨hc, hw⟩ := parse_gives_canonical cap inputs p accepted
  rw [← hw]
  exact parse_targets_round_trip cap p hc.2.2.2.2.2

/-- Positive example: non-canonical tree-root words (`goldilocks` = p, not a field element) are
    accepted by `from_u64_slice`; only chain limbs and counters are range checked. -/
theorem parse_root_words_not_range_checked :
    parseU64 0 ([0, 0, 0, 0, 0, 0, 0, 0] ++ [goldilocks, 0, 0, 0] ++ [5] ++ [0, 0, 0, 0, 0, 0, 0, 0] ++
        [goldilocks, 0, 0, 0] ++ [6] ++ [7] ++ [1, 2, 3, 4]) =
      .ok ⟨Words8.zero, ⟨goldilocks, 0, 0, 0⟩, 5, Words8.zero, ⟨goldilocks, 0, 0, 0⟩, 6, 7, [1, 2, 3, 4]⟩ := by
  rfl

/-- `vd` occupies the LAST `vd_vec_len` public inputs: this is the slot `check_cyclic_proof_verifier_data`
    (plonky2 `VerifierOnlyCircuitData::from_slice`) reads. -/
def lastN (n : Nat) (xs : List Nat) : List Nat := xs.drop (xs.length - n)

theorem vd_is_last_in_layout (p : PublicInputs) : lastN p.vd.length p.words = p.vd := by
  have : p.words = (p.initialDepositHashChain.words ++ p.initialDepositTreeRoot.words ++ [p.initialDepositCount] ++
      p.depositHashChain.words ++ p.depositTreeRoot.words ++ [p.depositCount] ++ [p.blockNumber]) ++ p.vd := rfl
  rw [lastN, this, List.length_append, Nat.add_sub_cancel, List.drop_left]

/-! ## Opaque hash / recursion environment -/

structure Environment where
  /-- plonky2_keccak `solidity_keccak256` over u32 words (opaque). -/
  keccakWords : List Nat → Words8
  /-- `PoseidonHashOut::hash_inputs_u64` (opaque). -/
  poseidonWords : List Nat → Hash4
  /-- Poseidon 2-to-1 used by the incremental Merkle tree (opaque). -/
  twoToOne : Hash4 → Hash4 → Hash4
  /-- plonky2 verification of a proof carrying public inputs `pis` under verifier data `vd` (opaque). -/
  proofAccepted : (vd : List Nat) → (pis : List Nat) → Bool

def emptyLeafHash (e : Environment) : Hash4 := e.poseidonWords Deposit.empty.toU64Vec
def Deposit.leafHash (e : Environment) (d : Deposit) : Hash4 := e.poseidonWords d.toU64Vec

/-- `MerkleProof::get_root` (native `BitPath::pop`, LSB first) = `MerkleProofTarget::get_root`
    (`split_le`, bit i with sibling i): fold the siblings from the leaf, swapping on each index bit. -/
def merkleFold (two : Hash4 → Hash4 → Hash4) : List Hash4 → Hash4 → Nat → Hash4
  | [], state, _ => state
  | s :: rest, state, index =>
      merkleFold two rest (if index % 2 = 1 then two s state else two state s) (index / 2)

def merkleRoot (e : Environment) (siblings : List Hash4) (leaf : Hash4) (index : Nat) : Hash4 :=
  merkleFold e.twoToOne siblings leaf index

theorem merkle_root_no_siblings (e : Environment) (leaf : Hash4) (index : Nat) :
    merkleRoot e [] leaf index = leaf := rfl

/-! ## Native admission: `DepositStepWitness::to_public_inputs` (deposit_step.rs) -/

inductive StepError where
  | invalidInput (message : String)
  | invalidProof (message : String)
  | failedToProve (message : String)
  | merkleProofError (message : String)
  | publicInputs (error : ParseError)
  deriving DecidableEq, Repr

structure NativeWitness where
  initialValue : Option (Words8 × Hash4 × Nat)
  /-- `prev_deposit_chain_proof`: only its public inputs (as u64) influence `to_public_inputs`;
      the proof body is never verified natively. -/
  prevProofPis : Option (List Nat)
  deposit : Deposit
  siblings : List Hash4

def liftParse {α : Type} : Except ParseError α → Except StepError α
  | .ok a => .ok a
  | .error err => .error (.publicInputs err)

/-- Initial-value case of `to_public_inputs`: current = initial, `vd` = the supplied chain verifier data. -/
def initialPis (chainVd : List Nat) (d : Deposit) (chain : Words8) (root : Hash4) (count : Nat) : PublicInputs :=
  { initialDepositHashChain := chain, initialDepositTreeRoot := root, initialDepositCount := count,
    depositHashChain := chain, depositTreeRoot := root, depositCount := count,
    blockNumber := d.blockNumber, vd := chainVd }

/-- `prev_pis` selection: initial value, or parse of the previous proof's public inputs plus the
    block-number consistency check. -/
def previousPis (cap : Nat) (chainVd : List Nat) (w : NativeWitness) : Except StepError PublicInputs :=
  match w.initialValue with
  | some (chain, root, count) => .ok (initialPis chainVd w.deposit chain root count)
  | none =>
      match liftParse (parseU64 cap (w.prevProofPis.getD [])) with
      | .error err => .error err
      | .ok prev =>
          if prev.blockNumber ≠ w.deposit.blockNumber then .error (.invalidInput "Block number mismatch")
          else .ok prev

/-- `U63::add(1)`: `checked_add` then `U63::new`; fails exactly when the sum leaves 63 bits. -/
def u63Add (n : Nat) : Except StepError Nat :=
  if n + 1 < u63Limit then .ok (n + 1) else .error (.invalidInput "Deposit count overflow")

/-- Checks after `prev_pis`, in source order: index = count, empty-slot opening, count increment. -/
def finishStep (e : Environment) (prev : PublicInputs) (w : NativeWitness) : Except StepError PublicInputs :=
  if w.deposit.depositIndex ≠ prev.depositCount then
    .error (.invalidInput "Deposit index must match deposit count")
  else if merkleRoot e w.siblings (emptyLeafHash e) prev.depositCount ≠ prev.depositTreeRoot then
    .error (.merkleProofError "Failed to verify empty deposit merkle proof")
  else
    match u63Add prev.depositCount with
    | .error err => .error err
    | .ok newCount =>
        .ok { initialDepositHashChain := prev.initialDepositHashChain
              initialDepositTreeRoot := prev.initialDepositTreeRoot
              initialDepositCount := prev.initialDepositCount
              depositHashChain := e.keccakWords (Deposit.foldWords prev.depositHashChain w.deposit)
              depositTreeRoot := merkleRoot e w.siblings (w.deposit.leafHash e) prev.depositCount
              depositCount := newCount
              blockNumber := w.deposit.blockNumber
              vd := prev.vd }

def sourceCount (w : NativeWitness) : Nat := w.initialValue.isSome.toNat + w.prevProofPis.isSome.toNat

def toPublicInputs (e : Environment) (cap : Nat) (chainVd : List Nat) (w : NativeWitness) :
    Except StepError PublicInputs :=
  if sourceCount w ≠ 1 then
    .error (.invalidInput "Exactly one of initial_value or prev_deposit_chain_proof must be provided")
  else
    match previousPis cap chainVd w with
    | .error err => .error err
    | .ok prev => finishStep e prev w

/-- The native result record, as a function of the selected previous inputs. -/
def nativeOutput (e : Environment) (prev : PublicInputs) (w : NativeWitness) : PublicInputs :=
  { initialDepositHashChain := prev.initialDepositHashChain
    initialDepositTreeRoot := prev.initialDepositTreeRoot
    initialDepositCount := prev.initialDepositCount
    depositHashChain := e.keccakWords (Deposit.foldWords prev.depositHashChain w.deposit)
    depositTreeRoot := merkleRoot e w.siblings (w.deposit.leafHash e) prev.depositCount
    depositCount := prev.depositCount + 1
    blockNumber := w.deposit.blockNumber
    vd := prev.vd }

theorem finish_step_ok_iff (e : Environment) (prev : PublicInputs) (w : NativeWitness) (p : PublicInputs) :
    finishStep e prev w = .ok p ↔
      w.deposit.depositIndex = prev.depositCount ∧
      merkleRoot e w.siblings (emptyLeafHash e) prev.depositCount = prev.depositTreeRoot ∧
      prev.depositCount + 1 < u63Limit ∧ p = nativeOutput e prev w := by
  unfold finishStep
  split
  · rename_i h
    constructor
    · intro contra; cases contra
    · intro ⟨h1, _⟩; exact absurd h1 h
  · rename_i h1
    split
    · rename_i h
      constructor
      · intro contra; cases contra
      · intro ⟨_, h2, _⟩; exact absurd h2 h
    · rename_i h2
      simp only [ne_eq, not_not] at h1 h2
      unfold u63Add
      split
      · rename_i h3
        simp only [Except.ok.injEq]
        constructor
        · intro contra; cases contra
        · intro ⟨_, _, _, _⟩; assumption
      · rename_i h3
        simp only [Except.ok.injEq]
        constructor
        · intro h4; subst h4; exact ⟨h1, h2, h3, rfl⟩
        · intro ⟨_, _, _, h4⟩; subst h4; rfl

theorem source_count_one_iff (w : NativeWitness) :
    sourceCount w = 1 ↔ (w.initialValue.isSome = true ∧ w.prevProofPis = none) ∨
      (w.initialValue = none ∧ w.prevProofPis.isSome = true) := by
  unfold sourceCount
  cases w.initialValue <;> cases w.prevProofPis <;> simp

/-- Exactly one of `initial_value` / `prev_deposit_chain_proof`. -/
theorem native_requires_exactly_one_source (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : NativeWitness) (p : PublicInputs) (accepted : toPublicInputs e cap chainVd w = .ok p) :
    sourceCount w = 1 := by
  unfold toPublicInputs at accepted
  split at accepted
  · cases accepted
  · rename_i h; simpa using h

theorem native_ok_shape (e : Environment) (cap : Nat) (chainVd : List Nat) (w : NativeWitness)
    (p : PublicInputs) (accepted : toPublicInputs e cap chainVd w = .ok p) :
    ∃ prev, previousPis cap chainVd w = .ok prev ∧
      w.deposit.depositIndex = prev.depositCount ∧
      merkleRoot e w.siblings (emptyLeafHash e) prev.depositCount = prev.depositTreeRoot ∧
      prev.depositCount + 1 < u63Limit ∧ p = nativeOutput e prev w := by
  unfold toPublicInputs at accepted
  split at accepted
  · cases accepted
  · split at accepted
    · cases accepted
    · rename_i prev hprev
      exact ⟨prev, hprev, (finish_step_ok_iff e prev w p).mp accepted⟩

/-- Deposit index = previous count, new count = previous + 1 < 2^63, empty slot at the old count opened. -/
theorem native_index_equals_previous_count (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : NativeWitness) (p : PublicInputs) (accepted : toPublicInputs e cap chainVd w = .ok p) :
    p.depositCount = w.deposit.depositIndex + 1 ∧ p.depositCount < u63Limit ∧
      p.blockNumber = w.deposit.blockNumber := by
  obtain ⟨prev, _, hi, _, hb, hp⟩ := native_ok_shape e cap chainVd w p accepted
  subst hp
  simp [nativeOutput, hi, hb]

/-- Initial-value step: initial = current inputs, `vd` = the supplied verifier data, one append. -/
theorem native_initial_step (e : Environment) (cap : Nat) (chainVd : List Nat) (w : NativeWitness)
    (p : PublicInputs) (chain : Words8) (root : Hash4) (count : Nat)
    (hinit : w.initialValue = some (chain, root, count))
    (accepted : toPublicInputs e cap chainVd w = .ok p) :
    p = nativeOutput e (initialPis chainVd w.deposit chain root count) w ∧
      w.deposit.depositIndex = count ∧ count + 1 < u63Limit ∧
      merkleRoot e w.siblings (emptyLeafHash e) count = root ∧ p.vd = chainVd := by
  obtain ⟨prev, hprev, hi, hm, hb, hp⟩ := native_ok_shape e cap chainVd w p accepted
  simp only [previousPis, hinit, Except.ok.injEq] at hprev
  subst hprev
  subst hp
  simp only [initialPis] at hi hm hb ⊢
  exact ⟨rfl, hi, hb, hm, rfl⟩

/-- Continued step: previous public inputs are parsed (canonical), block numbers must agree,
    initial values and `vd` are forwarded, one append. -/
theorem native_continued_step (e : Environment) (cap : Nat) (chainVd : List Nat) (w : NativeWitness)
    (p : PublicInputs) (prevWords : List Nat) (hinit : w.initialValue = none)
    (hprev : w.prevProofPis = some prevWords)
    (accepted : toPublicInputs e cap chainVd w = .ok p) :
    ∃ prev, parseU64 cap prevWords = .ok prev ∧ prev.Canonical cap ∧ prev.words = prevWords ∧
      prev.blockNumber = w.deposit.blockNumber ∧ w.deposit.depositIndex = prev.depositCount ∧
      prev.depositCount + 1 < u63Limit ∧
      merkleRoot e w.siblings (emptyLeafHash e) prev.depositCount = prev.depositTreeRoot ∧
      p = nativeOutput e prev w := by
  obtain ⟨prev, hp, hi, hm, hb, hout⟩ := native_ok_shape e cap chainVd w p accepted
  simp only [previousPis, hinit, hprev, Option.getD_some] at hp
  split at hp
  · cases hp
  · rename_i parsed hparse
    split at hp
    · cases hp
    · rename_i hblk
      simp only [ne_eq, not_not] at hblk
      simp only [Except.ok.injEq] at hp
      subst hp
      have hparse' : parseU64 cap prevWords = .ok prev := by
        cases h : parseU64 cap prevWords <;> simp [liftParse, h] at hparse <;> simp [hparse]
      obtain ⟨hc, hw⟩ := parse_gives_canonical cap prevWords prev hparse'
      exact ⟨prev, hparse', hc, hw, hblk, hi, hb, hm, hout⟩

/-- Positive example (also `NativeMerkleHeight`): native `verify` uses `siblings.len()` as height, so an
    EMPTY sibling list with the empty-leaf hash as root is accepted natively; the target would reject it
    (`CircuitGates.siblingsHeight`). -/
theorem native_accepts_short_sibling_list (e : Environment) (cap : Nat) (chainVd : List Nat) :
    toPublicInputs e cap chainVd
        { initialValue := some (Words8.zero, emptyLeafHash e, 0), prevProofPis := none,
          deposit := Deposit.empty, siblings := [] } =
      .ok (nativeOutput e (initialPis chainVd Deposit.empty Words8.zero (emptyLeafHash e) 0)
        { initialValue := some (Words8.zero, emptyLeafHash e, 0), prevProofPis := none,
          deposit := Deposit.empty, siblings := [] }) := by
  have h1 : (1 : Nat) < u63Limit := by decide
  simp [toPublicInputs, sourceCount, previousPis, finishStep, u63Add, initialPis, Deposit.empty,
    merkleRoot, merkleFold, nativeOutput, h1]

/-- Positive example: the first step of the unit test shape (63 siblings, index 0, amount 5). -/
def exampleDeposit : Deposit :=
  { depositIndex := 0, blockNumber := 0, depositor := Words5.zero, recipient := Words8.zero,
    tokenIndex := 0, amount := ⟨0, 0, 0, 0, 0, 0, 0, 5⟩, auxData := Words8.zero }

def exampleSiblings : List Hash4 := List.replicate depositTreeHeight Hash4.zero

def exampleWitness (e : Environment) : NativeWitness :=
  { initialValue := some (Words8.zero, merkleRoot e exampleSiblings (emptyLeafHash e) 0, 0),
    prevProofPis := none, deposit := exampleDeposit, siblings := exampleSiblings }

theorem native_first_step_example (e : Environment) (cap : Nat) (chainVd : List Nat) :
    toPublicInputs e cap chainVd (exampleWitness e) =
      .ok { initialDepositHashChain := Words8.zero
            initialDepositTreeRoot := merkleRoot e exampleSiblings (emptyLeafHash e) 0
            initialDepositCount := 0
            depositHashChain := e.keccakWords (Deposit.foldWords Words8.zero exampleDeposit)
            depositTreeRoot := merkleRoot e exampleSiblings (exampleDeposit.leafHash e) 0
            depositCount := 1
            blockNumber := 0
            vd := chainVd } := by
  have h1 : (1 : Nat) < u63Limit := by decide
  simp [toPublicInputs, sourceCount, exampleWitness, previousPis, finishStep, u63Add, initialPis,
    exampleDeposit, h1]

/-! ## Arbitrary satisfying witnesses: gates of `DepositStepTarget::new` -/

structure Witness where
  /-- `add_virtual_bool_target_safe` -/
  isInitial : Bool
  initialDepositHashChain : Words8
  initialDepositTreeRoot : Hash4
  initialDepositCount : Nat
  /-- `prev_deposit_chain_proof.public_inputs` seen through `from_pis` (exactly `cd.num_public_inputs`
      words, so `parse_targets_round_trip` makes this lossless). -/
  prevPis : PublicInputs
  deposit : Deposit
  siblings : List Hash4
  /-- `deposit_chain_vd` (virtual verifier data). -/
  chainVd : List Nat

def Witness.prevChain (w : Witness) : Words8 :=
  if w.isInitial then w.initialDepositHashChain else w.prevPis.depositHashChain
def Witness.prevRoot (w : Witness) : Hash4 :=
  if w.isInitial then w.initialDepositTreeRoot else w.prevPis.depositTreeRoot
def Witness.prevCount (w : Witness) : Nat :=
  if w.isInitial then w.initialDepositCount else w.prevPis.depositCount

/-- `new_pis` as wired by the builder (selects, keccak gadget, Merkle gadget, field add mod p). -/
def stepOutput (e : Environment) (w : Witness) : PublicInputs :=
  { initialDepositHashChain := if w.isInitial then w.initialDepositHashChain else w.prevPis.initialDepositHashChain
    initialDepositTreeRoot := if w.isInitial then w.initialDepositTreeRoot else w.prevPis.initialDepositTreeRoot
    initialDepositCount := if w.isInitial then w.initialDepositCount else w.prevPis.initialDepositCount
    depositHashChain := e.keccakWords (Deposit.foldWords w.prevChain w.deposit)
    depositTreeRoot := merkleRoot e w.siblings (w.deposit.leafHash e) w.prevCount
    depositCount := (w.prevCount + 1) % goldilocks
    blockNumber := w.deposit.blockNumber
    vd := w.chainVd }

/-- Local gate equations of `DepositStepTarget::new`, source order. -/
structure CircuitGates (e : Environment) (cap : Nat) (w : Witness) (out : PublicInputs) : Prop where
  /-- `Bytes32Target::new(builder, true)` -/
  initialChainChecked : CheckedWords w.initialDepositHashChain.words
  /-- `U63Target::new(builder, true)` -/
  initialCountChecked : w.initialDepositCount < u63Limit
  /-- `DepositTarget::new(builder, true)` -/
  depositChecked : w.deposit.NativeWidths
  /-- `DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT)` -/
  siblingsHeight : w.siblings.length = depositTreeHeight
  /-- `from_pis` over `cd.num_public_inputs` words -/
  prevPisShape : w.prevPis.vd.length = vdVecLen cap
  /-- `conditionally_verify_proof(not_initial, prev_proof, prev_pis.vd, cd)` -/
  prevProofVerified : w.isInitial = false → e.proofAccepted w.prevPis.vd w.prevPis.words = true
  /-- `conditionally_connect_vd(not_initial, prev_pis.vd, deposit_chain_vd)` -/
  vdConnected : w.isInitial = false → w.prevPis.vd = w.chainVd
  /-- `connect(deposit.deposit_index, prev_deposit_count)` -/
  indexPinned : w.deposit.depositIndex = w.prevCount
  /-- `conditional_assert_eq(not_initial, prev_pis.block_number, deposit.block_number)` -/
  blockPinned : w.isInitial = false → w.prevPis.blockNumber = w.deposit.blockNumber
  /-- `split_le(prev_deposit_count, siblings.len())` inside the Merkle gadget -/
  indexSplit : w.prevCount < 2 ^ w.siblings.length
  /-- `deposit_merkle_proof.verify(empty_leaf, prev_count, prev_root)` -/
  emptyLeafOpened : merkleRoot e w.siblings (emptyLeafHash e) w.prevCount = w.prevRoot
  /-- `range_check(add_const(prev_count, 1), 63)` -/
  incrementedRange : (w.prevCount + 1) % goldilocks < u63Limit
  /-- `register_public_inputs(new_pis.to_vec())` -/
  registered : out = stepOutput e w

theorem prev_count_below_u63 {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) : w.prevCount < u63Limit := by
  have h := g.indexSplit
  rw [g.siblingsHeight] at h
  exact h

/-- The field increment cannot wrap: new count = old count + 1 < 2^63, and the deposit index is the old count. -/
theorem step_count_increments {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) :
    out.depositCount = w.prevCount + 1 ∧ out.depositCount < u63Limit ∧ w.deposit.depositIndex = w.prevCount := by
  have hlt := prev_count_below_u63 g
  have hmod : (w.prevCount + 1) % goldilocks = w.prevCount + 1 := by
    apply Nat.mod_eq_of_lt
    have := u63_limit_below_goldilocks
    omega
  have hr := g.incrementedRange
  rw [hmod] at hr
  rw [g.registered]
  simp only [stepOutput, hmod]
  exact ⟨rfl, hr, g.indexPinned⟩

/-- Chain output = keccak of the fold preimage over the SELECTED previous chain. -/
theorem step_fold_is_keccak_of_previous_chain {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) :
    out.depositHashChain = e.keccakWords (Deposit.foldWords w.prevChain w.deposit) := by
  rw [g.registered]; rfl

/-- Root output = the same 63 siblings re-rooted with the deposit leaf at the old count, whose slot was empty. -/
theorem step_root_appends_at_count {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) :
    w.siblings.length = depositTreeHeight ∧
      merkleRoot e w.siblings (emptyLeafHash e) w.prevCount = w.prevRoot ∧
      out.depositTreeRoot = merkleRoot e w.siblings (w.deposit.leafHash e) w.prevCount := by
  refine ⟨g.siblingsHeight, g.emptyLeafOpened, ?_⟩
  rw [g.registered]; rfl

theorem step_block_number_is_deposit_block {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) : out.blockNumber = w.deposit.blockNumber := by
  rw [g.registered]; rfl

/-- Continued step: the previous proof is verified under its OWN declared vd, that vd is forwarded,
    initial values are forwarded, block number pinned. -/
theorem continued_step_binds_previous_proof {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) (h : w.isInitial = false) :
    e.proofAccepted w.prevPis.vd w.prevPis.words = true ∧ out.vd = w.prevPis.vd ∧
      out.initialDepositHashChain = w.prevPis.initialDepositHashChain ∧
      out.initialDepositTreeRoot = w.prevPis.initialDepositTreeRoot ∧
      out.initialDepositCount = w.prevPis.initialDepositCount ∧
      w.prevPis.blockNumber = out.blockNumber ∧
      w.prevChain = w.prevPis.depositHashChain ∧ w.prevRoot = w.prevPis.depositTreeRoot ∧
      w.prevCount = w.prevPis.depositCount := by
  have hvd := g.vdConnected h
  have hblk := g.blockPinned h
  rw [g.registered]
  simp [stepOutput, Witness.prevChain, Witness.prevRoot, Witness.prevCount, h, g.prevProofVerified h, hvd, hblk]

/-- Initial step: initial values are the free (range-checked) inputs and `vd` is the free virtual target. -/
theorem initial_step_outputs {e : Environment} {cap : Nat} {w : Witness} {out : PublicInputs}
    (g : CircuitGates e cap w out) (h : w.isInitial = true) :
    out.initialDepositHashChain = w.initialDepositHashChain ∧
      out.initialDepositTreeRoot = w.initialDepositTreeRoot ∧
      out.initialDepositCount = w.initialDepositCount ∧ out.vd = w.chainVd ∧
      w.prevChain = w.initialDepositHashChain ∧ w.prevRoot = w.initialDepositTreeRoot ∧
      w.prevCount = w.initialDepositCount := by
  rw [g.registered]
  simp [stepOutput, Witness.prevChain, Witness.prevRoot, Witness.prevCount, h]

/-- SECURITY (ConsumerVdPin): on an initial step NOTHING in this circuit constrains `new_pis.vd`. For
    every verifier-data vector there is a gate-satisfying witness declaring it. -/
theorem initial_step_vd_unconstrained (e : Environment) (cap : Nat) (vd : List Nat) :
    ∃ w out, CircuitGates e cap w out ∧ w.isInitial = true ∧ out.vd = vd := by
  let w : Witness :=
    { isInitial := true, initialDepositHashChain := Words8.zero,
      initialDepositTreeRoot := merkleRoot e exampleSiblings (emptyLeafHash e) 0,
      initialDepositCount := 0, prevPis := PublicInputs.dummy cap, deposit := exampleDeposit,
      siblings := exampleSiblings, chainVd := vd }
  refine ⟨w, stepOutput e w, ?_, rfl, rfl⟩
  have hlen : exampleSiblings.length = depositTreeHeight := List.length_replicate _ _
  refine ⟨?_, ?_, ?_, hlen, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, rfl⟩
  · simp [w, CheckedWords, Words8.zero, Words8.words, limbBase]
  · decide
  · simp [w, exampleDeposit, Deposit.NativeWidths, CheckedWords, Words5.zero, Words8.zero, Words5.words,
      Words8.words, u63Limit, limbBase]
  · simp [w, PublicInputs.dummy]
  · intro h; cases h
  · intro h; cases h
  · rfl
  · intro h; cases h
  · simp [w, Witness.prevCount]
  · rfl
  · simp [w, Witness.prevCount]; decide

/-! ### `set_witness` and the native ⇒ gates link -/

/-- `DepositStepTarget::set_witness` + `new_pis.set_witness`: field values written for a native witness
    whose selected previous inputs are `prev` and whose result is `newPis`. Dummy proof (all-zero public
    inputs) is written when there is no previous proof. -/
def nativeAssignment (cap : Nat) (w : NativeWitness) (prev newPis : PublicInputs) : Witness :=
  { isInitial := w.initialValue.isSome
    initialDepositHashChain := match w.initialValue with | some (c, _, _) => c | none => Words8.zero
    initialDepositTreeRoot := match w.initialValue with | some (_, r, _) => r | none => Hash4.zero
    initialDepositCount := match w.initialValue with | some (_, _, n) => n | none => 0
    prevPis := if w.prevProofPis.isSome then prev else PublicInputs.dummy cap
    deposit := w.deposit
    siblings := w.siblings
    chainVd := newPis.vd }

/-- Native admission ⇒ the assigned witness satisfies every gate, given: Rust type widths of the deposit
    and initial values, the real verifier data length, the `set_witness` sibling-count assertion, and
    (`NativeProofNotChecked`) that the supplied previous proof actually verifies under its declared vd. -/
theorem native_assignment_satisfies_gates (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : NativeWitness) (p : PublicInputs)
    (hw : w.deposit.NativeWidths)
    (hinit : ∀ c r n, w.initialValue = some (c, r, n) → CheckedWords c.words ∧ n < u63Limit)
    (hvd : chainVd.length = vdVecLen cap)
    (hsib : w.siblings.length = depositTreeHeight)
    (hproof : ∀ prev, w.initialValue = none → previousPis cap chainVd w = .ok prev →
      e.proofAccepted prev.vd prev.words = true)
    (accepted : toPublicInputs e cap chainVd w = .ok p) :
    ∃ prev, previousPis cap chainVd w = .ok prev ∧ CircuitGates e cap (nativeAssignment cap w prev p) p := by
  have hsrc := (source_count_one_iff w).mp (native_requires_exactly_one_source e cap chainVd w p accepted)
  obtain ⟨prev, hprev, hi, hm, hb, hp⟩ := native_ok_shape e cap chainVd w p accepted
  refine ⟨prev, hprev, ?_⟩
  have hmod : (prev.depositCount + 1) % goldilocks = prev.depositCount + 1 := by
    apply Nat.mod_eq_of_lt
    have := u63_limit_below_goldilocks
    omega
  have hsplit : prev.depositCount < 2 ^ depositTreeHeight := by
    show prev.depositCount < u63Limit
    omega
  rcases hsrc with ⟨hsome, hnone⟩ | ⟨hnone, hsome⟩
  · -- initial-value step
    obtain ⟨⟨c, r, n⟩, hval⟩ := Option.isSome_iff_exists.mp hsome
    obtain ⟨hc, hn⟩ := hinit c r n hval
    simp only [previousPis, hval, Except.ok.injEq] at hprev
    subst hprev
    simp only [initialPis] at hi hm hb hmod hsplit
    have hnat : nativeAssignment cap w (initialPis chainVd w.deposit c r n) p =
        { isInitial := true, initialDepositHashChain := c, initialDepositTreeRoot := r,
          initialDepositCount := n, prevPis := PublicInputs.dummy cap, deposit := w.deposit,
          siblings := w.siblings, chainVd := p.vd } := by
      simp [nativeAssignment, hval, hnone]
    rw [hnat]
    refine ⟨hc, hn, hw, hsib, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simp [PublicInputs.dummy]
    · intro h; cases h
    · intro h; cases h
    · simpa [Witness.prevCount] using hi
    · intro h; cases h
    · simpa [Witness.prevCount, hsib] using hsplit
    · simpa [Witness.prevCount, Witness.prevRoot] using hm
    · simp only [Witness.prevCount, ite_true, hmod]; exact hb
    · subst hp
      simp [nativeOutput, stepOutput, initialPis, Witness.prevChain, Witness.prevCount, hmod]
  · -- continued step
    obtain ⟨prevWords, hpw⟩ := Option.isSome_iff_exists.mp hsome
    have hacc := hproof prev hnone hprev
    obtain ⟨prev', hparse, hcanon, hwords, hblk, _, _, _, hp'⟩ :=
      native_continued_step e cap chainVd w p prevWords hnone hpw accepted
    -- the previous inputs selected by `previousPis` are the parsed ones
    have hsame : prev' = prev := by
      simp only [previousPis, hnone, hpw, Option.getD_some, hparse, liftParse] at hprev
      split at hprev
      · cases hprev
      · simp only [Except.ok.injEq] at hprev; exact hprev
    subst hsame
    have hnat : nativeAssignment cap w prev' p =
        { isInitial := false, initialDepositHashChain := Words8.zero, initialDepositTreeRoot := Hash4.zero,
          initialDepositCount := 0, prevPis := prev', deposit := w.deposit,
          siblings := w.siblings, chainVd := p.vd } := by
      simp [nativeAssignment, hnone, hpw]
    rw [hnat]
    have hpvd : p.vd = prev'.vd := by subst hp; rfl
    refine ⟨?_, ?_, hw, hsib, hcanon.2.2.2.2.2, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simp [CheckedWords, Words8.zero, Words8.words, limbBase]
    · decide
    · intro _; exact hacc
    · intro _; exact hpvd.symm
    · simpa [Witness.prevCount] using hi
    · intro _; exact hblk
    · simpa [Witness.prevCount, hsib] using hsplit
    · simpa [Witness.prevCount, Witness.prevRoot] using hm
    · simp only [Witness.prevCount, ite_false, hmod]; exact hb
    · subst hp
      simp [nativeOutput, stepOutput, Witness.prevChain, Witness.prevCount, hmod]

/-! ## Forwarding wrapper and cyclic verifier-data check (deposit_hash_chain_circuit.rs) -/

/-- `DepositHashChainCircuit::new`: verify the step proof under the CONSTANT step verifier data, then
    re-register `from_pis(step.public_inputs)` unchanged as this circuit's public inputs. -/
structure WrapGates (e : Environment) (cap : Nat) (stepVd : List Nat) (stepPis out : PublicInputs) : Prop where
  stepProofVerified : e.proofAccepted stepVd stepPis.words = true
  shape : stepPis.vd.length = vdVecLen cap
  forwarded : out = stepPis

theorem wrap_forwards_step_public_inputs {e : Environment} {cap : Nat} {stepVd : List Nat}
    {stepPis out : PublicInputs} (g : WrapGates e cap stepVd stepPis out) :
    out = stepPis ∧ parseTargets cap stepPis.words = some out := by
  rw [g.forwarded]
  exact ⟨rfl, parse_targets_round_trip cap stepPis g.shape⟩

inductive ChainVerifyError where
  | cyclicCheckFailed
  | proofVerificationFailed
  deriving DecidableEq, Repr

/-- `DepositHashChainCircuit::verify`: `check_cyclic_proof_verifier_data` (the LAST `vd_vec_len` public
    inputs must equal this circuit's own verifier data) BEFORE plonky2 verification. -/
def verifyChain (e : Environment) (cap : Nat) (ownVd : List Nat) (pis : List Nat) : Except ChainVerifyError Unit :=
  if lastN (vdVecLen cap) pis ≠ ownVd then .error .cyclicCheckFailed
  else if e.proofAccepted ownVd pis then .ok () else .error .proofVerificationFailed

/-- The consumer-side pin: a chain proof accepted by `verify` declares exactly the chain circuit's vd. -/
theorem chain_verify_pins_declared_vd (e : Environment) (cap : Nat) (ownVd : List Nat) (p : PublicInputs)
    (h : p.vd.length = vdVecLen cap) (accepted : verifyChain e cap ownVd p.words = .ok ()) :
    p.vd = ownVd ∧ e.proofAccepted ownVd p.words = true := by
  unfold verifyChain at accepted
  have hlast : lastN (vdVecLen cap) p.words = p.vd := by rw [← h]; exact vd_is_last_in_layout p
  rw [hlast] at accepted
  split at accepted
  · cases accepted
  · rename_i hvd
    simp only [ne_eq, not_not] at hvd
    split at accepted
    · rename_i hacc; exact ⟨hvd, hacc⟩
    · cases accepted

theorem chain_verify_checks_vd_first (e : Environment) (cap : Nat) (ownVd : List Nat) (pis : List Nat)
    (h : lastN (vdVecLen cap) pis ≠ ownVd) : verifyChain e cap ownVd pis = .error .cyclicCheckFailed := by
  simp [verifyChain, h]

/-! ## Multi-step chains under the proof-soundness premise -/

/-- `Chain e cap baseVd out`: `out` is reachable by step gates, each continued step's previous public
    inputs being themselves reachable (the wrapper forwards them unchanged,
    `wrap_forwards_step_public_inputs`). This inductive IS the `ProofSoundness` premise: it replaces
    "`proofAccepted` = true ⇒ some gate-satisfying witness produced it". `baseVd` is whatever the
    initial step declared. -/
inductive Chain (e : Environment) (cap : Nat) (baseVd : List Nat) : PublicInputs → Prop where
  | step (w : Witness) (out : PublicInputs) (gates : CircuitGates e cap w out)
      (base : w.isInitial = true → w.chainVd = baseVd)
      (prev : w.isInitial = false → Chain e cap baseVd w.prevPis) : Chain e cap baseVd out

/-- Every proof of a chain carries the vd its initial step declared (`ConsumerVdPin` is elsewhere). -/
theorem chain_declares_single_vd {e : Environment} {cap : Nat} {baseVd : List Nat} {out : PublicInputs}
    (h : Chain e cap baseVd out) : out.vd = baseVd := by
  induction h with
  | step w out g base prev ih =>
    cases hi : w.isInitial with
    | true => rw [(initial_step_outputs g hi).2.2.2]; exact base hi
    | false =>
      rw [(continued_step_binds_previous_proof g hi).2.1]
      exact ih hi

/-- One append: slot `count` of `root` opens to the empty leaf and re-roots to `root'` with the deposit leaf. -/
def RootStep (e : Environment) (root : Hash4) (count : Nat) (d : Deposit) (root' : Hash4) : Prop :=
  ∃ siblings : List Hash4, siblings.length = depositTreeHeight ∧
    merkleRoot e siblings (emptyLeafHash e) count = root ∧ merkleRoot e siblings (d.leafHash e) count = root'

/-- `Trace e chain0 root0 count0 block ds chain root count`: `ds` appended in order from the initial
    accumulators, every deposit range-checked, indexed by the running count and stamped with `block`. -/
inductive Trace (e : Environment) (chain0 : Words8) (root0 : Hash4) (count0 block : Nat) :
    List Deposit → Words8 → Hash4 → Nat → Prop where
  | nil : Trace e chain0 root0 count0 block [] chain0 root0 count0
  | snoc (ds : List Deposit) (chain : Words8) (root : Hash4) (count : Nat) (d : Deposit) (root' : Hash4)
      (prev : Trace e chain0 root0 count0 block ds chain root count)
      (widths : d.NativeWidths) (index : d.depositIndex = count) (blk : d.blockNumber = block)
      (rootStep : RootStep e root count d root') (bound : count + 1 < u63Limit) :
      Trace e chain0 root0 count0 block (ds ++ [d]) (e.keccakWords (Deposit.foldWords chain d)) root' (count + 1)

/-- Chain public inputs are exactly an append trace from their own initial values, all at one block number. -/
theorem chain_is_trace {e : Environment} {cap : Nat} {baseVd : List Nat} {out : PublicInputs}
    (h : Chain e cap baseVd out) :
    ∃ ds, Trace e out.initialDepositHashChain out.initialDepositTreeRoot out.initialDepositCount
      out.blockNumber ds out.depositHashChain out.depositTreeRoot out.depositCount := by
  induction h with
  | step w out g base prev ih =>
    obtain ⟨hcount, _, hidx⟩ := step_count_increments g
    have hfold := step_fold_is_keccak_of_previous_chain g
    obtain ⟨hlen, hopen, hroot⟩ := step_root_appends_at_count g
    have hblk := step_block_number_is_deposit_block g
    have hrs : RootStep e w.prevRoot w.prevCount w.deposit out.depositTreeRoot :=
      ⟨w.siblings, hlen, hopen, hroot⟩
    cases hi : w.isInitial with
    | true =>
      obtain ⟨h1, h2, h3, _, hc, hr, hn⟩ := initial_step_outputs g hi
      refine ⟨[w.deposit], ?_⟩
      rw [h1, h2, h3, hcount, hfold, hn, hc]
      rw [hr, hn] at hrs
      have := Trace.snoc (e := e) (chain0 := w.initialDepositHashChain) (root0 := w.initialDepositTreeRoot)
        (count0 := w.initialDepositCount) (block := out.blockNumber) [] _ _ _ w.deposit out.depositTreeRoot
        Trace.nil g.depositChecked (hidx.trans hn) hblk.symm hrs (hn ▸ (step_count_increments g).2.1 ▸
          (by rw [hcount, hn] at *; exact (by have := (step_count_increments g).2.1; rw [hcount, hn] at this; exact this)))
      simpa using this
    | false =>
      obtain ⟨_, _, h1, h2, h3, hb, hc, hr, hn⟩ := continued_step_binds_previous_proof g hi
      obtain ⟨ds, tr⟩ := ih hi
      rw [h1, h2, h3, hb] at tr
      refine ⟨ds ++ [w.deposit], ?_⟩
      rw [hcount, hfold, hn, hc]
      rw [hr, hn] at hrs
      have hbound : w.prevPis.depositCount + 1 < u63Limit := by
        have := (step_count_increments g).2.1; rw [hcount, hn] at this; exact this
      exact Trace.snoc ds _ _ _ w.deposit out.depositTreeRoot tr g.depositChecked (hidx.trans hn)
        hblk.symm hrs hbound

/-- Iterated circuit fold. -/
def foldChain (e : Environment) (start : Words8) (ds : List Deposit) : Words8 :=
  ds.foldl (fun acc d => e.keccakWords (Deposit.foldWords acc d)) start

/-- `Indexed n ds`: consecutive deposit indices starting at `n`. -/
def Indexed : Nat → List Deposit → Prop
  | _, [] => True
  | n, d :: ds => d.depositIndex = n ∧ Indexed (n + 1) ds

theorem indexed_snoc (n : Nat) (ds : List Deposit) (d : Deposit) (h : Indexed n ds)
    (hd : d.depositIndex = n + ds.length) : Indexed n (ds ++ [d]) := by
  induction ds generalizing n with
  | nil => simp [Indexed] at hd ⊢; exact hd
  | cons x xs ih =>
    obtain ⟨hx, hxs⟩ := h
    simp only [List.length_cons] at hd
    exact ⟨hx, ih (n + 1) hxs (by omega)⟩

theorem fold_chain_snoc (e : Environment) (start : Words8) (ds : List Deposit) (d : Deposit) :
    foldChain e start (ds ++ [d]) = e.keccakWords (Deposit.foldWords (foldChain e start ds) d) := by
  simp [foldChain, List.foldl_append]

/-- A trace is the iterated fold; count = initial + length; indices consecutive; one block number. -/
theorem trace_is_fold {e : Environment} {chain0 : Words8} {root0 : Hash4} {count0 block : Nat}
    {ds : List Deposit} {chain : Words8} {root : Hash4} {count : Nat}
    (h : Trace e chain0 root0 count0 block ds chain root count) :
    chain = foldChain e chain0 ds ∧ count = count0 + ds.length ∧ Indexed count0 ds ∧
      (∀ d ∈ ds, d.NativeWidths ∧ d.blockNumber = block) := by
  induction h with
  | nil => exact ⟨rfl, rfl, trivial, fun _ h => nomatch h⟩
  | snoc ds chain root count d root' _ widths index blk _ _ ih =>
    obtain ⟨hc, hn, hix, hall⟩ := ih
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [fold_chain_snoc, hc]
    · simp [hn]
    · exact indexed_snoc count0 ds d hix (by omega)
    · intro x hx
      simp only [List.mem_append, List.mem_singleton] at hx
      rcases hx with hx | hx
      · exact hall x hx
      · subst hx; exact ⟨widths, blk⟩

/-! ## Comparison with the IntmaxRollup model (RollupValue.finishDeposit) -/

/-- The on-chain record `IntmaxRollup` folds (`RollupValue.finishDeposit`): the same five fields. -/
def Deposit.toRecord (d : Deposit) : RollupValue.DepositRecord :=
  ⟨d.depositor.value, d.recipient.value, d.tokenIndex, d.amount.value, d.auxData.value⟩

/-- `solidity_keccak256` packing (SolidityKeccakPacking): each u32 word as four big-endian bytes. -/
def wordsToBytes (ws : List Nat) : RollupValue.Bytes := ws.bind (RollupValue.wordBytes 4)

theorem words_to_bytes_append (xs ys : List Nat) : wordsToBytes (xs ++ ys) = wordsToBytes xs ++ wordsToBytes ys := by
  simp [wordsToBytes, List.append_bind]

theorem bytes32_of_limbs (x : Words8) (h : CheckedWords x.words) :
    RollupValue.wordBytes 32 x.value = wordsToBytes x.words := by
  cases x with
  | mk w0 w1 w2 w3 w4 w5 w6 w7 =>
  simp only [CheckedWords, Words8.words, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false,
    forall_eq_or_imp, forall_eq, limbBase] at h
  obtain ⟨_, h1, h2, h3, h4, h5, h6, h7⟩ := h
  have hr32 : List.range 32 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31] := rfl
  have hr4 : List.range 4 = [0,1,2,3] := rfl
  simp only [RollupValue.wordBytes, wordsToBytes, Words8.value, Words8.words, hr32, hr4, List.map,
    List.bind_cons, List.bind_nil, List.append_nil, List.cons_append, List.nil_append, limbValue,
    List.foldl, limbBase]
  simp only [List.cons.injEq, and_true]
  refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩ <;>
    (congr 1; omega)

theorem address_of_limbs (x : Words5) (h : CheckedWords x.words) :
    RollupValue.wordBytes 20 x.value = wordsToBytes x.words := by
  cases x with
  | mk a0 a1 a2 a3 a4 =>
  simp only [CheckedWords, Words5.words, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false,
    forall_eq_or_imp, forall_eq, limbBase] at h
  obtain ⟨_, h1, h2, h3, h4⟩ := h
  have hr20 : List.range 20 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19] := rfl
  have hr4 : List.range 4 = [0,1,2,3] := rfl
  simp only [RollupValue.wordBytes, wordsToBytes, Words5.value, Words5.words, hr20, hr4, List.map,
    List.bind_cons, List.bind_nil, List.append_nil, List.cons_append, List.nil_append, limbValue,
    List.foldl, limbBase]
  simp only [List.cons.injEq, and_true]
  refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩ <;>
    (congr 1; omega)

theorem token_word_bytes (t : Nat) : wordsToBytes [t] = RollupValue.wordBytes 4 t := by
  simp [wordsToBytes]

/-- Under `SolidityKeccakPacking`, the circuit's fold PREIMAGE is byte-identical to the Solidity
    `abi.encodePacked(prev, depositor, recipient, tokenIndex, amount, aux)` model preimage. Kernel-checked. -/
theorem fold_preimage_matches_rollup_model (prev : Words8) (d : Deposit) (hp : CheckedWords prev.words)
    (hd : d.NativeWidths) :
    wordsToBytes (Deposit.foldWords prev d) =
      RollupValue.hashPreimage (.deposit prev.value d.toRecord) := by
  obtain ⟨_, _, h1, h2, _, h4, h5⟩ := hd
  simp only [Deposit.foldWords, words_to_bytes_append, RollupValue.hashPreimage, Deposit.toRecord,
    bytes32_of_limbs prev hp, address_of_limbs d.depositor h1, bytes32_of_limbs d.recipient h2,
    bytes32_of_limbs d.amount h4, bytes32_of_limbs d.auxData h5, token_word_bytes, List.append_assoc]

/-- KeccakBridge: the circuit keccak over u32 words and a byte-level keccak agree on checked words. -/
def KeccakBridge (e : Environment) (keccak : RollupValue.Bytes → RollupValue.Hash) : Prop :=
  ∀ ws, CheckedWords ws → (e.keccakWords ws).value = keccak (wordsToBytes ws)

/-- The keccak gadget returns 32-bit limbs (plonky2_keccak output constraint, not in the modeled files). -/
def KeccakOutputsChecked (e : Environment) : Prop := ∀ ws, CheckedWords (e.keccakWords ws).words

theorem fold_value_matches_rollup_under_bridge (e : Environment) (re : RollupValue.Environment)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (hb : KeccakBridge e keccak)
    (ha : RollupValue.HashEncodingAgrees re keccak) (prev : Words8) (d : Deposit)
    (hp : CheckedWords prev.words) (hd : d.NativeWidths) :
    (e.keccakWords (Deposit.foldWords prev d)).value = re.hash (.deposit prev.value d.toRecord) := by
  rw [hb _ (fold_words_checked prev d hp hd), fold_preimage_matches_rollup_model prev d hp hd, ha]

/-- The Solidity-side fold: `finishDeposit` applied record by record (`pendingDepositChain` update). -/
def rollupFold (re : RollupValue.Environment) (start : RollupValue.Hash) (records : List RollupValue.DepositRecord) :
    RollupValue.Hash :=
  records.foldl (fun acc r => re.hash (.deposit acc r)) start

/-- One `finishDeposit` = one `rollupFold` step, index = count before, count + 1 (from RollupValue). -/
theorem rollup_finish_deposit_is_fold_step (re : RollupValue.Environment) (s after : RollupValue.State)
    (r : RollupValue.DepositRecord) (events : List RollupValue.Event)
    (h : RollupValue.finishDeposit re s r = .ok (after, events)) :
    after.pendingDepositChain = rollupFold re s.pendingDepositChain [r] ∧
      after.depositCount = s.depositCount + 1 ∧ after.deposits s.depositCount = some r := by
  obtain ⟨h1, h2, h3, _⟩ := RollupValue.successful_finish_deposit_record re s after r events h
  exact ⟨by simpa [rollupFold] using h3, h1, h2⟩

theorem fold_chain_checked (e : Environment) (hout : KeccakOutputsChecked e) (start : Words8)
    (h0 : CheckedWords start.words) (ds : List Deposit) : CheckedWords (foldChain e start ds).words := by
  induction ds generalizing start with
  | nil => exact h0
  | cons d ds ih => exact ih _ (hout _)

/-- Circuit fold value = Solidity fold value over the same records from the same start, under the
    named bridges (same keccak, byte packing, 32-bit gadget outputs). -/
theorem fold_chain_matches_rollup_fold (e : Environment) (re : RollupValue.Environment)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (hb : KeccakBridge e keccak)
    (ha : RollupValue.HashEncodingAgrees re keccak) (hout : KeccakOutputsChecked e)
    (start : Words8) (h0 : CheckedWords start.words) (ds : List Deposit)
    (hds : ∀ d ∈ ds, d.NativeWidths) :
    (foldChain e start ds).value = rollupFold re start.value (ds.map Deposit.toRecord) := by
  induction ds generalizing start with
  | nil => rfl
  | cons d ds ih =>
    have hd := hds d (List.mem_cons_self d ds)
    have hrest : ∀ x ∈ ds, x.NativeWidths := fun x hx => hds x (List.mem_cons_of_mem d hx)
    simp only [foldChain, List.foldl_cons, List.map_cons, rollupFold]
    have step := fold_value_matches_rollup_under_bridge e re keccak hb ha start d h0 hd
    have := ih (e.keccakWords (Deposit.foldWords start d)) (hout _) hrest
    simp only [foldChain, rollupFold] at this
    rw [this, step]

/-- MAIN COMPARISON. A chain proof's final `deposit_hash_chain` equals `IntmaxRollup`'s
    `pendingDepositChain` fold over the SAME records in the SAME order from the SAME initial value,
    with `deposit_count = initial + n`, indices = running count, one block number. Premises: proof
    soundness (`Chain`), the keccak bridges, and a 32-bit initial chain. Whether the initial value is
    the contract's actual chain and whether these deposits are final on L1 are `InitialStatePin`. -/
theorem chain_matches_rollup_fold (e : Environment) (re : RollupValue.Environment)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (hb : KeccakBridge e keccak)
    (ha : RollupValue.HashEncodingAgrees re keccak) (hout : KeccakOutputsChecked e)
    {cap : Nat} {baseVd : List Nat} {out : PublicInputs} (h : Chain e cap baseVd out)
    (h0 : CheckedWords out.initialDepositHashChain.words) :
    ∃ ds : List Deposit,
      out.depositHashChain.value =
        rollupFold re out.initialDepositHashChain.value (ds.map Deposit.toRecord) ∧
      out.depositCount = out.initialDepositCount + ds.length ∧
      Indexed out.initialDepositCount ds ∧
      (∀ d ∈ ds, d.NativeWidths ∧ d.blockNumber = out.blockNumber) ∧
      out.vd = baseVd := by
  obtain ⟨ds, tr⟩ := chain_is_trace h
  obtain ⟨hc, hn, hix, hall⟩ := trace_is_fold tr
  refine ⟨ds, ?_, hn, hix, hall, chain_declares_single_vd h⟩
  rw [hc]
  exact fold_chain_matches_rollup_fold e re keccak hb ha hout _ h0 ds (fun d hd => (hall d hd).1)

/-- Both folds ignore `deposit_index` / `block_number`: the record has no such field, and the circuit
    preimage is unchanged by them (`fold_omits_index_and_block`). -/
theorem to_record_omits_index_and_block (d : Deposit) (index block : Nat) :
    Deposit.toRecord { d with depositIndex := index, blockNumber := block } = d.toRecord := rfl

end Zkp.Implementation.DepositChain
