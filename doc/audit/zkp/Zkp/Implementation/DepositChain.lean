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
L1 deposit to two accumulators: the Poseidon deposit tree (index `deposit_count`
is opened as the empty leaf and re-rooted with the deposit leaf) and the keccak
deposit hash chain `keccak(prev ‖ depositor ‖ recipient ‖ token ‖ amount ‖ aux)`.
`deposit_index` and `block_number` are NOT part of the chain fold (they are part
of the Poseidon leaf / nullifier only); `deposit_index` is pinned to the running
count by a `connect`, `block_number` is copied into the public inputs and must
match the previous proof's block number on a continued step.

Native admission (`DepositStepWitness::to_public_inputs`, executable `Except`
mirroring the source order of checks) is modeled separately from arbitrary
satisfying witnesses (`CircuitGates`, the local gate equations of
`DepositStepTarget::new`). `nativeAssignment` is `set_witness`; the theorem
`native_assignment_satisfies_gates` links the two under explicit premises.

Named boundaries (undischarged premises, all opaque callbacks or hypotheses):
- `KeccakWords`/`PoseidonWords`/`TwoToOne` in `Environment`: solidity keccak over
  u32 words, Poseidon leaf hash and Poseidon 2-to-1 are opaque, never injective.
- `chainProofValid`: plonky2 `conditionally_verify_proof` of the previous chain
  proof under the verifier data DECLARED IN THAT PROOF'S OWN PUBLIC INPUTS.
  Proof soundness (accepted ⇒ produced by a gate-satisfying witness) is a premise
  of every multi-step statement (`Chain`).
- `ConsumerVdPin`: on the initial step `new_pis.vd` is a FREE virtual verifier
  data (theorem `initial_step_vd_unconstrained`); it is forwarded unchanged by
  every continued step (`chain_declares_single_vd`). Only the consumer
  (`DepositHashChainCircuit::verify` → `check_cyclic_proof_verifier_data`, or
  `block_step.rs` `add_proof_target_and_conditionally_verify_cyclic`) pins it to
  the real chain verifier data. That pin is outside these three files.
- `FieldAndGadgetLowering`: Goldilocks arithmetic, `split_le`, range checks,
  `select`, keccak/Poseidon gadgets and `from_pis` slicing are modeled as Nat
  equations; the 63-bit `split_le` on the Merkle index is the only reason the
  count increment cannot wrap in the field.
- `SolidityKeccakPacking`: `solidity_keccak256` consumes each u32 word as four
  big-endian bytes (plonky2_keccak, not in the modeled files). Under that packing
  the circuit fold preimage is byte-identical to `RollupValue.hashPreimage
  (.deposit …)` (theorem `fold_preimage_matches_rollup_model`); equality of the
  chain VALUES additionally needs both sides to call the same keccak
  (`KeccakBridge`, theorem `fold_value_matches_rollup_under_bridge`).
- Native `DepositMerkleProof::verify` uses `siblings.len()` as the height; the
  63-sibling shape is enforced only by the circuit target (`siblingsHeight`).
- The native path does not verify the supplied previous proof; `prove` fails
  later inside plonky2 if it is invalid. Modeled as the `chainProofValid`
  premise of `native_assignment_satisfies_gates`.
- `vd_from_pis_slice` reads verifier-data field elements from u64 without a
  canonicity check; the vd words are carried as opaque `List Nat`.
No proof soundness, hash injectivity, finality, or "accepted ⇒ funds safe" is
stated as a theorem.
-/

namespace Zkp.Implementation.DepositChain

/-! ## Pinned constants -/

def limbBase : Nat := 2 ^ 32
def u63Limit : Nat := 2 ^ 63
def u64Limit : Nat := 2 ^ 64
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
theorem noop_gates_pinned : noopGates = 2 ^ 12 := by decide

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

def CheckedWords (xs : List Nat) : Prop := ∀ x ∈ xs, x < limbBase

/-- Big-endian limb value: `foldl (acc * 2^32 + limb)`. -/
def limbValue (xs : List Nat) : Nat := xs.foldl (fun acc x => acc * limbBase + x) 0
def Words8.value (x : Words8) : Nat := limbValue x.words
def Words5.value (x : Words5) : Nat := limbValue x.words

theorem words8_length (x : Words8) : x.words.length = bytes32Len := rfl
theorem words5_length (x : Words5) : x.words.length = addressLen := rfl
theorem hash4_length (h : Hash4) : h.words.length = poseidonHashOutLen := rfl

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

/-- The Poseidon leaf DOES commit to `deposit_index` (words 0) and `block_number` (word 1). -/
theorem leaf_commits_index_and_block (d : Deposit) :
    d.toU64Vec.getD 0 0 = d.depositIndex ∧ d.toU64Vec.getD 1 0 = d.blockNumber := by
  simp [Deposit.toU64Vec]

theorem empty_deposit_widths : Deposit.NativeWidths Deposit.empty := by
  simp [Deposit.NativeWidths, Deposit.empty, CheckedWords, Words5.zero, Words8.zero, Words5.words,
    Words8.words, u63Limit, limbBase]

/-! ## Opaque hash / recursion environment -/

structure Environment where
  /-- plonky2_keccak `solidity_keccak256` over u32 words (opaque). -/
  keccakWords : List Nat → Words8
  /-- `PoseidonHashOut::hash_inputs_u64` (opaque). -/
  poseidonWords : List Nat → Hash4
  /-- Poseidon 2-to-1 used by the incremental Merkle tree (opaque). -/
  twoToOne : Hash4 → Hash4 → Hash4
  /-- `conditionally_verify_proof` accepted a proof carrying these public inputs, verified under the
      verifier data those public inputs declare (`pis.vd`). Opaque: plonky2 soundness is a premise. -/
  chainProofValid : PublicInputsShape → Prop

/-! `PublicInputsShape` is forward-declared below as `PublicInputs`; Lean needs the structure first. -/

end Zkp.Implementation.DepositChain

namespace Zkp.Implementation.DepositChain

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

end Zkp.Implementation.DepositChain
