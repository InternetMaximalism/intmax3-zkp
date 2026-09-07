import Zkp.Implementation.UpdatePublicState
import Zkp.Implementation.RollupValue

/-!
# Withdrawal chain step and withdrawal proof wrapper

Handwritten SEMANTIC MODEL of two source files, runtime 05ec7ae:

* `src/circuits/withdraw/withdrawal_step.rs` (649 lines) - the cyclic per-step
  fold of ONE single-withdrawal statement into the running withdrawal hash chain,
  its `23 + vd` word public-input codec, the native witness builder
  (`WithdrawalStepWitness::to_public_inputs`) and the in-circuit gate set
  (`WithdrawalStepTarget::new`).
* `src/circuits/withdraw/withdrawal_circuit.rs` (233 lines) - the outer wrapper
  that cyclically verifies the chain proof, binds an extended public state and a
  withdrawal prover address, keccak-hashes the 23-word preimage, masks the top
  three bits and registers the FINAL 17-word public input
  `[pis_hash(8) || ext_commitment(8) || block_number(1)]`.

This is NOT a refinement proof of the Rust source, of plonky2 circuit lowering,
of the keccak/Poseidon gadgets, or of proof-system soundness. Nothing here
proves that a verifying proof exists, that a hash is injective, that a recursive
(cyclic) proof is sound, or that an accepted withdrawal is safe. Every such fact
is an explicit opaque callback or a named `Prop` premise:

* `Keccak` / `Poseidon` - opaque digest callbacks; never assumed injective.
* `VerifierEnv.chainVerify` / `.singleVerify` - opaque plonky2 verification;
  `conditionally_verify_proof` / `add_proof_target_and_verify(_cyclic)` are
  modeled only by the STATEMENT each proof carries, never by soundness.
* `LeafHashAgrees` / `SolidityPisHashAgrees` - the boundary that the circuit's
  big-endian u32-word keccak preimage and `IntmaxRollup`'s abstract
  `HashInput.withdrawalLeaf` / `.withdrawalPis` denote the same function.
* `KeccakCanonical` - digests are 256-bit values.
* `ExtCommitmentFinalized` - the circuit does NOT prove that the emitted
  extended-state commitment is an on-chain finalized root; `IntmaxRollup` does.
* `UpdatePublicState` Merkle/history boundaries are inherited unchanged.

NATIVE admission (`stepToPublicInputs`, mirroring the Rust `Result` builder) is
kept strictly separate from ARBITRARY satisfying witnesses (`StepGates`,
`WrapperGates`), which state only the local gate equations the builder emits.
A theorem about the native path never covers adversarial witnesses.

The comparison with `Zkp.Implementation.RollupValue` is DERIVED, not assumed:
from the two hash-agreement boundaries alone, the circuit's 17-word layout, its
`remove_3bits` mask and its per-step leaf fold are proved to be exactly what
`RollupValue.verifyWithdrawalSet` recomputes (`limbsMatchBytes32` at offset 0,
`limbsToBytes32` at offset 8, `pi[16] % 2^64` and `ws.foldl (foldWithdrawalLeaf e) 0`).
-/

namespace Zkp.Implementation.WithdrawalChain

/-! ## Errors -/

/-- Union of `WithdrawalStepPublicInputsError`, `WithdrawalStepError`,
`WithdrawalCircuitError`, `PublicStateError` and the u32 range failures raised by
`U32LimbTrait::from_u64_slice`. `panicOutOfU32Range` marks the source sites that
`assert!` instead of returning an error (`Withdrawal::from_u64_slice`,
`WithdrawalProofPublicInputs::from_u64_slice`). -/
inductive Error where
  | invalidLength (expected actual : Nat)
  | outOfU32Range (index : Nat)
  | panicOutOfU32Range (index : Nat)
  | blockNumberOverflow (value : Nat)
  | maskedLimbTooLarge (limb : Nat)
  | verifierDataTooShort (expected actual : Nat)
  | invalidProof (context : String)
  | invalidInput (context : String)
  | updatePublicState (inner : UpdatePublicState.Error)
  deriving DecidableEq, Repr

abbrev Result := Except Error

def require (condition : Bool) (error : Error) : Result Unit :=
  if condition then .ok () else .error error

/-! ### Do-block peeling helpers (local copies) -/

theorem require_ok_iff (condition : Bool) (error : Error) :
    require condition error = .ok () ↔ condition = true := by
  cases condition <;> simp [require]

theorem bind_ok_iff {a b : Type} (r : Result a) (f : a → Result b) (value : b) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem unit_bind_ok_iff {a : Type} (r : Result Unit) (s : Result a) (value : a) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error e => simp [Bind.bind, Except.bind]
  | ok u => cases u; simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {a : Type} (value result : a) :
    (pure value : Result a) = .ok result ↔ value = result := by
  constructor
  · intro h; injection h
  · intro h; rw [h]; rfl

/-! ## Pinned source constants -/

def bytes32Len : Nat := 8
def addressLen : Nat := 5
def u256Len : Nat := 8
def u64Len : Nat := 2
def poseidonHashOutLen : Nat := 4
def publicStateU64Len : Nat := 15
def withdrawalLen : Nat := 30
def singleWithdrawalPublicInputsLen : Nat := 45
def withdrawalStepPublicInputsLen : Nat := 23
def blockNumberU32Len : Nat := 2
def withdrawalProofPublicInputsLen : Nat := 23
def finalPublicInputsLen : Nat := 17
def extendedPublicStateU64Len : Nat := 48
def u63Bits : Nat := 63
def maskKeptBits : Nat := 29
def limbBase : Nat := 2 ^ 32
def u63Limit : Nat := 2 ^ 63
def u256Limit : Nat := 2 ^ 256
def maskModulus : Nat := 2 ^ 253

/-- `vd_vec_len(config) = 4 + 4 * config.fri_config.num_cap_elements()`. -/
def vdVecLen (capElements : Nat) : Nat := 4 + 4 * capElements

theorem bytes32_len_pinned : bytes32Len = u256Len := rfl

theorem public_state_len_pinned :
    publicStateU64Len = 1 + u64Len + 3 * poseidonHashOutLen := rfl

theorem withdrawal_len_pinned :
    withdrawalLen = addressLen + 1 + u256Len + 2 * bytes32Len := rfl

theorem single_withdrawal_len_pinned :
    singleWithdrawalPublicInputsLen = publicStateU64Len + withdrawalLen := rfl

theorem step_public_inputs_len_pinned :
    withdrawalStepPublicInputsLen = bytes32Len + publicStateU64Len := rfl

theorem withdrawal_proof_preimage_len_pinned :
    withdrawalProofPublicInputsLen =
      bytes32Len + addressLen + bytes32Len + blockNumberU32Len := rfl

theorem final_public_inputs_len_pinned :
    finalPublicInputsLen = bytes32Len + bytes32Len + 1 := rfl

theorem extended_public_state_len_pinned :
    extendedPublicStateU64Len = publicStateU64Len + 4 * bytes32Len + 1 := rfl

theorem vd_vec_len_pinned (capElements : Nat) :
    vdVecLen capElements = 4 + 4 * capElements := rfl

theorem mask_modulus_pinned : maskModulus = 2 ^ (maskKeptBits + 224) := rfl

/-! ## Big-endian u32 limbs -/

/-- `Bytes32` / `U256` are `[u32; 8]` stored big endian. -/
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
  [x.w0, x.w1, x.w2, x.w3, x.w4, x.w5, x.w6, x.w7]

def Words8.zero : Words8 := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩

def Words8.read (xs : List Nat) (offset : Nat) : Words8 :=
  ⟨xs.getD offset 0, xs.getD (offset + 1) 0, xs.getD (offset + 2) 0, xs.getD (offset + 3) 0,
   xs.getD (offset + 4) 0, xs.getD (offset + 5) 0, xs.getD (offset + 6) 0, xs.getD (offset + 7) 0⟩

/-- Every limb fits in a u32; the Rust representation domain, not a safety claim. -/
def Words8.Canonical (x : Words8) : Prop := ∀ w ∈ x.words, w < limbBase

/-- Big-endian repacking; the same fold as `RollupValue.limbsToBytes32`. -/
def limbsValue (xs : List Nat) : Nat :=
  xs.foldl (fun acc w => acc * limbBase + w % limbBase) 0

def Words8.value (x : Words8) : Nat := limbsValue x.words

/-- Big-endian limb split of a 256-bit value, in the exact shape
`RollupValue.limbsMatchBytes32` recomputes. -/
def bytes32Of (v : Nat) : Words8 :=
  ⟨(v / 2 ^ 224) % limbBase, (v / 2 ^ 192) % limbBase, (v / 2 ^ 160) % limbBase,
   (v / 2 ^ 128) % limbBase, (v / 2 ^ 96) % limbBase, (v / 2 ^ 64) % limbBase,
   (v / 2 ^ 32) % limbBase, v % limbBase⟩

def bytes32Limbs (v : Nat) : List Nat := (bytes32Of v).words

/-- `Address` is `[u32; 5]`, big endian. -/
def addressLimbs (v : Nat) : List Nat :=
  [(v / 2 ^ 128) % limbBase, (v / 2 ^ 96) % limbBase, (v / 2 ^ 64) % limbBase,
   (v / 2 ^ 32) % limbBase, v % limbBase]

/-- `U63::to_u32_vec` = `[high, low]`, the high word carrying 31 bits. -/
def blockNumberU32Limbs (v : Nat) : List Nat := [(v / limbBase) % 2 ^ 31, v % limbBase]

/-- `Bytes32::remove_3bits`: `limbs[0] &= (1 << 29) - 1`, i.e. clear the three
most significant bits of the whole 256-bit word. -/
def Words8.removeThreeBits (x : Words8) : Words8 := { x with w0 := x.w0 % 2 ^ maskKeptBits }

theorem bytes32_limbs_length (v : Nat) : (bytes32Limbs v).length = bytes32Len := rfl

theorem address_limbs_length (v : Nat) : (addressLimbs v).length = addressLen := rfl

theorem block_number_limbs_length (v : Nat) :
    (blockNumberU32Limbs v).length = blockNumberU32Len := rfl

theorem words8_words_length (x : Words8) : x.words.length = bytes32Len := rfl

theorem words8_read_of_words (x : Words8) (rest : List Nat) :
    Words8.read (x.words ++ rest) 0 = x := by
  cases x; rfl

theorem bytes32_of_canonical (v : Nat) : (bytes32Of v).Canonical := by
  intro w hw
  have hb : 0 < limbBase := by decide
  simp only [Words8.words, bytes32Of, List.mem_cons, List.not_mem_nil, or_false] at hw
  rcases hw with h | h | h | h | h | h | h | h <;> subst h <;> exact Nat.mod_lt _ hb

/-- `remove_3bits` keeps 29 bits of the top limb, i.e. 253 bits overall. -/
theorem remove_three_bits_top_limb (x : Words8) :
    (x.removeThreeBits).w0 < 2 ^ maskKeptBits :=
  Nat.mod_lt _ (by decide)

theorem remove_three_bits_keeps_low_limbs (x : Words8) :
    (x.removeThreeBits).w1 = x.w1 ∧ (x.removeThreeBits).w2 = x.w2 ∧
    (x.removeThreeBits).w3 = x.w3 ∧ (x.removeThreeBits).w4 = x.w4 ∧
    (x.removeThreeBits).w5 = x.w5 ∧ (x.removeThreeBits).w6 = x.w6 ∧
    (x.removeThreeBits).w7 = x.w7 := by
  cases x; exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- KEY LAYOUT FACT: the circuit's limb-level `remove_3bits` is exactly the
Solidity model's integer `% 2^253` (`RollupValue.withdrawalPisHash`). -/
theorem remove_three_bits_is_mask_2_253 (v : Nat) :
    (bytes32Of v).removeThreeBits = bytes32Of (v % maskModulus) := by
  simp only [bytes32Of, Words8.removeThreeBits, maskModulus, maskKeptBits, limbBase,
    Words8.mk.injEq]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> omega

set_option maxHeartbeats 2000000 in
theorem bytes32_of_value (v : Nat) : (bytes32Of v).value = v % u256Limit := by
  simp only [Words8.value, limbsValue, Words8.words, bytes32Of, limbBase, u256Limit,
    List.foldl_cons, List.foldl_nil, Nat.zero_mul, Nat.zero_add]
  omega

theorem bytes32_of_value_of_lt (v : Nat) (h : v < u256Limit) : (bytes32Of v).value = v := by
  rw [bytes32_of_value]; exact Nat.mod_eq_of_lt h

/-! ## Withdrawal leaf and the keccak hash chain

`common/withdrawal.rs::Withdrawal::hash_with_prev_hash`, the only fold the step
circuit performs. -/

structure Withdrawal where
  recipient : Nat
  tokenIndex : Nat
  amount : Nat
  nullifier : Nat
  auxData : Nat
  deriving DecidableEq, Repr

/-- `Withdrawal::to_u32_vec`: recipient(5) || token_index(1) || amount(8) ||
nullifier(8) || aux_data(8). -/
def Withdrawal.toU32Vec (w : Withdrawal) : List Nat :=
  addressLimbs w.recipient ++ [w.tokenIndex % limbBase] ++ bytes32Limbs w.amount ++
    bytes32Limbs w.nullifier ++ bytes32Limbs w.auxData

theorem withdrawal_to_u32_vec_length (w : Withdrawal) :
    w.toU32Vec.length = withdrawalLen := rfl

/-- `plonky2_keccak::utils::solidity_keccak256` over big-endian u32 words and its
in-circuit counterpart `builder.keccak256`. Opaque: not injective, and not
assumed to agree with any other digest without an explicit premise. -/
abbrev Keccak := List Nat → Nat

/-- Digests are 256-bit values. -/
def KeccakCanonical (K : Keccak) : Prop := ∀ xs, K xs < u256Limit

/-- `Withdrawal::hash_with_prev_hash(prev)` = keccak(prev_limbs || leaf_limbs). -/
def hashWithPrevHash (K : Keccak) (prev : Nat) (w : Withdrawal) : Nat :=
  K (bytes32Limbs prev ++ w.toU32Vec)

/-- The chain fold, seeded at `Bytes32::default()`. -/
def foldChain (K : Keccak) (init : Nat) (ws : List Withdrawal) : Nat :=
  ws.foldl (hashWithPrevHash K) init

def initialHashChain : Nat := 0

theorem initial_hash_chain_is_zero : initialHashChain = 0 := rfl

theorem fold_chain_nil (K : Keccak) (init : Nat) : foldChain K init [] = init := rfl

theorem fold_chain_cons (K : Keccak) (init : Nat) (w : Withdrawal) (ws : List Withdrawal) :
    foldChain K init (w :: ws) = foldChain K (hashWithPrevHash K init w) ws := rfl

/-! ## Cross-model bridge to `IntmaxRollup` (`RollupValue`) -/

def toRollupWithdrawal (w : Withdrawal) : RollupValue.Withdrawal :=
  ⟨w.recipient, w.tokenIndex, w.amount, w.nullifier, w.auxData⟩

/-- BOUNDARY: the circuit's word-level keccak of `prev || leaf` and the contract
model's abstract `HashInput.withdrawalLeaf` denote the same function. -/
def LeafHashAgrees (K : Keccak) (e : RollupValue.Environment) : Prop :=
  ∀ prev w, hashWithPrevHash K prev w
    = RollupValue.foldWithdrawalLeaf e prev (toRollupWithdrawal w)

/-- BOUNDARY: the circuit's 23-word keccak preimage and the contract model's
abstract `HashInput.withdrawalPis` denote the same function. -/
def SolidityPisHashAgrees (K : Keccak) (e : RollupValue.Environment) : Prop :=
  ∀ (chain : Words8) (prover : Nat) (root : Words8) (block : Nat),
    K (chain.words ++ addressLimbs prover ++ root.words ++ blockNumberU32Limbs block)
      = e.hash (.withdrawalPis chain.value prover root.value block)

theorem fold_chain_matches_rollup_fold (K : Keccak) (e : RollupValue.Environment)
    (agree : LeafHashAgrees K e) :
    ∀ (ws : List Withdrawal) (init : Nat),
      foldChain K init ws
        = (ws.map toRollupWithdrawal).foldl (RollupValue.foldWithdrawalLeaf e) init := by
  intro ws
  induction ws with
  | nil => intro init; rfl
  | cons w ws ih =>
    intro init
    simp only [foldChain, List.map_cons, List.foldl_cons]
    rw [agree init w]
    exact ih _

theorem fold_chain_from_zero_matches_rollup (K : Keccak) (e : RollupValue.Environment)
    (agree : LeafHashAgrees K e) (ws : List Withdrawal) :
    foldChain K initialHashChain ws
      = (ws.map toRollupWithdrawal).foldl (RollupValue.foldWithdrawalLeaf e) 0 :=
  fold_chain_matches_rollup_fold K e agree ws 0

/-! ## `WithdrawalStepPublicInputs` codec (withdrawal_step.rs 43-196) -/

abbrev PublicState := UpdatePublicState.State

/-- `[withdrawal_hash_chain(8) || public_state(15) || vd(4 + 4*cap)]`. -/
structure StepPublicInputs where
  withdrawalHashChain : Words8
  publicState : PublicState
  vd : List Nat
  deriving DecidableEq, Repr

def StepPublicInputs.toU64Vec (p : StepPublicInputs) : List Nat :=
  p.withdrawalHashChain.words ++ p.publicState.words ++ p.vd

def firstOutOfRange : Nat → List Nat → Option Nat
  | _, [] => none
  | i, x :: xs => if limbBase ≤ x then some i else firstOutOfRange (i + 1) xs

/-- `Bytes32::from_u64_slice` range-checks every limb against `u32::MAX`. -/
def decodeBytes32 (xs : List Nat) : Result Words8 :=
  match firstOutOfRange 0 xs with
  | some i => .error (.outOfU32Range i)
  | none => .ok (Words8.read xs 0)

/-- `PublicState::from_u64_slice`: length, then a 63-bit block number, then a
u32-limb-checked timestamp, then THREE Poseidon roots that are NOT range checked
(raw `u64` field elements). -/
def decodePublicState (xs : List Nat) : Result PublicState := do
  require (xs.length == publicStateU64Len) (.invalidLength publicStateU64Len xs.length)
  let blockNumber := xs.getD 0 0
  require (blockNumber < u63Limit) (.blockNumberOverflow blockNumber)
  match firstOutOfRange 1 ((xs.drop 1).take u64Len) with
  | some i => .error (.outOfU32Range i)
  | none => pure ()
  pure (BalancePublicInputs.PublicState.read xs)

/-- `WithdrawalStepPublicInputs::from_u64_slice`, in source order. -/
def stepFromU64Slice (capElements : Nat) (inputs : List Nat) : Result StepPublicInputs := do
  require (inputs.length == withdrawalStepPublicInputsLen + vdVecLen capElements)
    (.invalidLength (withdrawalStepPublicInputsLen + vdVecLen capElements) inputs.length)
  let hashChain ← decodeBytes32 (inputs.take bytes32Len)
  let publicState ← decodePublicState ((inputs.drop bytes32Len).take publicStateU64Len)
  let vd := (inputs.drop withdrawalStepPublicInputsLen).take (vdVecLen capElements)
  require (vd.length == vdVecLen capElements)
    (.verifierDataTooShort (vdVecLen capElements) vd.length)
  pure ⟨hashChain, publicState, vd⟩

theorem step_public_inputs_length (p : StepPublicInputs) :
    p.toU64Vec.length = withdrawalStepPublicInputsLen + p.vd.length := by
  simp [StepPublicInputs.toU64Vec, Words8.words, BalancePublicInputs.PublicState.words,
    BalancePublicInputs.Root.words, withdrawalStepPublicInputsLen]
  omega

theorem step_from_u64_slice_rejects_wrong_length (capElements : Nat) (inputs : List Nat)
    (bad : ¬ inputs.length = withdrawalStepPublicInputsLen + vdVecLen capElements) :
    stepFromU64Slice capElements inputs
      = .error (.invalidLength (withdrawalStepPublicInputsLen + vdVecLen capElements)
          inputs.length) := by
  simp [stepFromU64Slice, require, bad, bind, Except.bind]

/-! ## Single-withdrawal statement (`SingleWithdawalPublicInputs`, 45 words) -/

structure SingleWithdrawalPublicInputs where
  publicState : PublicState
  withdrawal : Withdrawal
  deriving DecidableEq, Repr

/-- `Withdrawal::from_u64_slice` PANICS (`assert!`) on an out-of-u32 word rather
than returning an error; modeled by `panicOutOfU32Range`. -/
def decodeWithdrawal (xs : List Nat) : Result Withdrawal := do
  require (xs.length == withdrawalLen) (.invalidLength withdrawalLen xs.length)
  match firstOutOfRange 0 xs with
  | some i => .error (.panicOutOfU32Range i)
  | none => pure ()
  pure { recipient := limbsValue (xs.take addressLen)
       , tokenIndex := xs.getD addressLen 0
       , amount := (Words8.read xs (addressLen + 1)).value
       , nullifier := (Words8.read xs (addressLen + 1 + u256Len)).value
       , auxData := (Words8.read xs (addressLen + 1 + u256Len + bytes32Len)).value }

def decodeSingle (xs : List Nat) : Result SingleWithdrawalPublicInputs := do
  require (xs.length == singleWithdrawalPublicInputsLen)
    (.invalidLength singleWithdrawalPublicInputsLen xs.length)
  let publicState ← decodePublicState (xs.take publicStateU64Len)
  let withdrawal ← decodeWithdrawal ((xs.drop publicStateU64Len).take withdrawalLen)
  pure ⟨publicState, withdrawal⟩

/-! ## Opaque proof objects and the verification boundary -/

/-- A plonky2 proof is modeled ONLY by the public-input words it carries. No
soundness, completeness or binding property is assumed. -/
structure Proof where
  pis : List Nat
  deriving DecidableEq, Repr

/-- Verification callbacks and circuit configuration used by the native witness
builder. `chainVerify` / `singleVerify` are opaque predicates. -/
structure VerifierEnv where
  chainVerify : Proof → Bool
  singleVerify : Proof → Bool
  chainCapElements : Nat
  /-- `withdrawal_chain_vd.verifier_only`, the honest chain verifier data the
  native builder copies into its output. -/
  chainVd : List Nat
  getRoot : UpdatePublicState.RootCall
  keccak : Keccak

/-! ## Native step admission (`WithdrawalStepWitness::to_public_inputs`, 236-304) -/

structure StepWitness where
  prevChainProof : Option Proof
  singleWithdrawalProof : Proof
  update : UpdatePublicState.Update

def checkUpdate (getRoot : UpdatePublicState.RootCall) (u : UpdatePublicState.Update) :
    Result Unit :=
  match UpdatePublicState.nativeVerify getRoot u with
  | .error e => .error (.updatePublicState e)
  | .ok () => .ok ()

/-- The previous-chain branch. `None` yields `Bytes32::default()`; otherwise the
previous chain proof is verified, decoded, and its public state is forced to
equal `update_public_state.new` (source comment WDR-CRIT-001). -/
def prevChainHash (env : VerifierEnv) (w : StepWitness) : Result Nat :=
  match w.prevChainProof with
  | none => pure initialHashChain
  | some prev => do
      require (env.chainVerify prev) (.invalidProof "prev chain proof invalid")
      let prevPis ← stepFromU64Slice env.chainCapElements prev.pis
      require (prevPis.publicState == w.update.newState)
        (.invalidInput "update_public_state.new must equal prev chain public_state")
      pure prevPis.withdrawalHashChain.value

/-- Source order: (1) `update_public_state.verify()`, (2) verify the single
withdrawal proof, (3) decode its first 45 public inputs, (4) require
`update.old = single.public_state`, (5) the previous-chain branch, (6) fold the
leaf onto the previous chain hash and OUTPUT `update.new`, not `update.old`. -/
def stepToPublicInputs (env : VerifierEnv) (w : StepWitness) : Result StepPublicInputs := do
  checkUpdate env.getRoot w.update
  require (env.singleVerify w.singleWithdrawalProof)
    (.invalidProof "single withdrawal proof invalid")
  let single ← decodeSingle (w.singleWithdrawalProof.pis.take singleWithdrawalPublicInputsLen)
  require (single.publicState == w.update.oldState)
    (.invalidInput "update_public_state.old must match single withdrawal public state")
  let prevHash ← prevChainHash env w
  pure { withdrawalHashChain :=
           bytes32Of (hashWithPrevHash env.keccak prevHash single.withdrawal)
       , publicState := w.update.newState
       , vd := env.chainVd }

/-- Extract every local consequence of a successful native step in one pass. -/
theorem native_step_success (env : VerifierEnv) (w : StepWitness) (out : StepPublicInputs)
    (accepted : stepToPublicInputs env w = .ok out) :
    ∃ single prevHash,
      checkUpdate env.getRoot w.update = .ok () ∧
      env.singleVerify w.singleWithdrawalProof = true ∧
      decodeSingle (w.singleWithdrawalProof.pis.take singleWithdrawalPublicInputsLen)
        = .ok single ∧
      single.publicState = w.update.oldState ∧
      prevChainHash env w = .ok prevHash ∧
      out = { withdrawalHashChain :=
                bytes32Of (hashWithPrevHash env.keccak prevHash single.withdrawal)
            , publicState := w.update.newState
            , vd := env.chainVd } := by
  simp only [stepToPublicInputs, unit_bind_ok_iff, bind_ok_iff, exists_unit, require_ok_iff,
    pure_ok_iff, beq_iff_eq] at accepted
  obtain ⟨update, verified, single, decoded, matched, prevHash, prevOk, final⟩ := accepted
  exact ⟨single, prevHash, update, verified, decoded, matched, prevOk, final.symm⟩

/-- WDR-CRIT-001: the step publishes the chain-wide canonical target state
`update_public_state.new`, never the single withdrawal's own `.old` state. -/
theorem native_step_outputs_target_state (env : VerifierEnv) (w : StepWitness)
    (out : StepPublicInputs) (accepted : stepToPublicInputs env w = .ok out) :
    out.publicState = w.update.newState := by
  obtain ⟨_, _, _, _, _, _, _, final⟩ := native_step_success env w out accepted
  rw [final]

/-- The published verifier data is the honest chain verifier data on the native
path; nothing here constrains an arbitrary witness (see `StepGates`). -/
theorem native_step_publishes_chain_vd (env : VerifierEnv) (w : StepWitness)
    (out : StepPublicInputs) (accepted : stepToPublicInputs env w = .ok out) :
    out.vd = env.chainVd := by
  obtain ⟨_, _, _, _, _, _, _, final⟩ := native_step_success env w out accepted
  rw [final]

/-- The single-withdrawal statement's public state is pinned to `update.old`, so
the Merkle transition starts exactly where the withdrawal was proved. -/
theorem native_step_binds_single_state_to_update_old (env : VerifierEnv) (w : StepWitness)
    (out : StepPublicInputs) (accepted : stepToPublicInputs env w = .ok out) :
    ∃ single,
      decodeSingle (w.singleWithdrawalProof.pis.take singleWithdrawalPublicInputsLen)
        = .ok single ∧ single.publicState = w.update.oldState := by
  obtain ⟨single, _, _, _, decoded, matched, _, _⟩ := native_step_success env w out accepted
  exact ⟨single, decoded, matched⟩

/-- Native admission requires the locally verified public-state transition. -/
theorem native_step_requires_public_state_transition (env : VerifierEnv) (w : StepWitness)
    (out : StepPublicInputs) (accepted : stepToPublicInputs env w = .ok out) :
    UpdatePublicState.nativeVerify env.getRoot w.update = .ok () := by
  obtain ⟨_, _, update, _, _, _, _, _⟩ := native_step_success env w out accepted
  revert update
  unfold checkUpdate
  split
  · intro h; exact absurd h (by simp)
  · intro _; assumption

/-- The initial step seeds the chain at `Bytes32::default()`. -/
theorem native_step_initial_seeds_zero (env : VerifierEnv) (w : StepWitness)
    (initial : w.prevChainProof = none) :
    prevChainHash env w = .ok initialHashChain := by
  unfold prevChainHash
  rw [initial]
  rfl

/-- A non-initial step verifies the previous chain proof AND forces the previous
statement's public state to equal this step's `update_public_state.new`. -/
theorem native_step_non_initial_pins_prev_state (env : VerifierEnv) (w : StepWitness)
    (prev : Proof) (nonInitial : w.prevChainProof = some prev) (prevHash : Nat)
    (accepted : prevChainHash env w = .ok prevHash) :
    env.chainVerify prev = true ∧
    ∃ prevPis, stepFromU64Slice env.chainCapElements prev.pis = .ok prevPis ∧
      prevPis.publicState = w.update.newState ∧
      prevPis.withdrawalHashChain.value = prevHash := by
  rw [prevChainHash, nonInitial] at accepted
  simp only [unit_bind_ok_iff, bind_ok_iff, exists_unit, require_ok_iff, pure_ok_iff,
    beq_iff_eq] at accepted
  obtain ⟨verified, prevPis, decoded, matched, value⟩ := accepted
  exact ⟨verified, prevPis, decoded, matched, value⟩

/-! ## Chain-level invariants

The recursive structure is modeled at the STATEMENT level: one `Link` per step,
carrying the previous statement it claims, the leaf it folds, its public-state
transition and the statement it publishes. Proof soundness is NOT assumed; the
results below are about the constraint system's layout only. -/

structure Link where
  prev : Option StepPublicInputs
  withdrawal : Withdrawal
  update : UpdatePublicState.Update
  out : StepPublicInputs

/-- The previous chain hash a step folds onto: `Bytes32::default()` for the
initial step, the predecessor's published hash otherwise. -/
def optHash : Option StepPublicInputs → Nat
  | none => initialHashChain
  | some p => p.withdrawalHashChain.value

def Link.prevHash (l : Link) : Nat := optHash l.prev

/-- The gate equations the step imposes on its OWN output, as emitted by
`WithdrawalStepTarget::new`. Note the deliberate asymmetry: on the initial step
`conditionally_connect_vd` and `conditional_assert_eq` are disabled, so neither
the carried verifier data nor `update.new` is constrained there. -/
structure LinkValid (K : Keccak) (l : Link) : Prop where
  outState : l.out.publicState = l.update.newState
  outHash : l.out.withdrawalHashChain =
    bytes32Of (hashWithPrevHash K l.prevHash l.withdrawal)
  newMatchesPrev : ∀ p, l.prev = some p → p.publicState = l.update.newState
  vdMatchesPrev : ∀ p, l.prev = some p → l.out.vd = p.vd

/-- `Linked start ls fin`: consecutive links consume the previous statement.
`start = none` is a chain that begins at its own initial step. -/
def Linked : Option StepPublicInputs → List Link → Option StepPublicInputs → Prop
  | start, [], fin => fin = start
  | start, l :: ls, fin => l.prev = start ∧ Linked (some l.out) ls fin

/-- WDR-CRIT-001 cascade: every step of a linked, locally valid chain publishes
the SAME public state as the final statement, and every step's
`update_public_state.new` equals it. One canonical target state per batch. -/
theorem chain_states_constant (K : Keccak) :
    ∀ (ls : List Link) (start : Option StepPublicInputs) (fin : StepPublicInputs),
      Linked start ls (some fin) → (∀ l ∈ ls, LinkValid K l) →
      (∀ p, start = some p → p.publicState = fin.publicState) ∧
        ∀ l ∈ ls, l.out.publicState = fin.publicState ∧
          l.update.newState = fin.publicState := by
  intro ls
  induction ls with
  | nil =>
    intro start fin linked _
    subst linked
    exact ⟨by intro p h; rw [Option.some.inj h], by intro l hl; cases hl⟩
  | cons l ls ih =>
    intro start fin linked valid
    obtain ⟨head, rest⟩ := linked
    have hl : LinkValid K l := valid l (List.mem_cons_self _ _)
    obtain ⟨hstart, hall⟩ := ih (some l.out) fin rest
      (fun x hx => valid x (List.mem_cons_of_mem _ hx))
    have hout : l.out.publicState = fin.publicState := hstart l.out rfl
    have hnew : l.update.newState = fin.publicState := by rw [← hl.outState]; exact hout
    refine ⟨?_, ?_⟩
    · intro p h
      rw [← head] at h
      rw [hl.newMatchesPrev p h, hnew]
    · intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact ⟨hout, hnew⟩
      · exact hall x hx

/-- A linked, locally valid chain publishes exactly the keccak fold of its
leaves, provided digests are canonical 256-bit values (so the `Bytes32`
re-packing between steps is the identity). -/
theorem chain_hash_is_leaf_fold (K : Keccak) (canonical : KeccakCanonical K) :
    ∀ (ls : List Link) (start : Option StepPublicInputs) (fin : StepPublicInputs),
      Linked start ls (some fin) → (∀ l ∈ ls, LinkValid K l) →
      fin.withdrawalHashChain.value
        = foldChain K (optHash start) (ls.map Link.withdrawal) := by
  intro ls
  induction ls with
  | nil =>
    intro start fin linked _
    subst linked
    exact (fold_chain_nil K (optHash (some fin))).symm
  | cons l ls ih =>
    intro start fin linked valid
    obtain ⟨head, rest⟩ := linked
    have hl : LinkValid K l := valid l (List.mem_cons_self _ _)
    have hprev : l.prevHash = optHash start := by rw [Link.prevHash, head]
    have hout : l.out.withdrawalHashChain.value
        = hashWithPrevHash K (optHash start) l.withdrawal := by
      rw [hl.outHash, ← hprev]
      exact bytes32_of_value_of_lt _ (canonical _)
    rw [List.map_cons, fold_chain_cons, ← hout]
    exact ih (some l.out) fin rest (fun x hx => valid x (List.mem_cons_of_mem _ hx))

/-- All statements in a linked chain carry the same verifier data. Together with
the wrapper's `constant_verifier_data` anchor (`WrapperGates.cyclicVdAnchor`),
this pins every step to the genuine chain circuit. The INITIAL step's own vd
word is unconstrained in isolation; it is pinned only through its successors. -/
theorem chain_vd_constant (K : Keccak) :
    ∀ (ls : List Link) (start : Option StepPublicInputs) (fin : StepPublicInputs),
      Linked start ls (some fin) → (∀ l ∈ ls, LinkValid K l) →
      (∀ p, start = some p → p.vd = fin.vd) ∧ ∀ l ∈ ls, l.out.vd = fin.vd := by
  intro ls
  induction ls with
  | nil =>
    intro start fin linked _
    subst linked
    exact ⟨by intro p h; rw [Option.some.inj h], by intro l hl; cases hl⟩
  | cons l ls ih =>
    intro start fin linked valid
    obtain ⟨head, rest⟩ := linked
    have hl : LinkValid K l := valid l (List.mem_cons_self _ _)
    obtain ⟨hstart, hall⟩ := ih (some l.out) fin rest
      (fun x hx => valid x (List.mem_cons_of_mem _ hx))
    have hout : l.out.vd = fin.vd := hstart l.out rfl
    refine ⟨?_, ?_⟩
    · intro p h
      rw [← head] at h
      rw [← hl.vdMatchesPrev p h, hout]
    · intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact hout
      · exact hall x hx

/-- Anchoring the FINAL statement's verifier data (exactly what the wrapper's
`add_proof_target_and_verify_cyclic` does) pins every step's carried vd. -/
theorem chain_vd_anchored (K : Keccak) (ls : List Link) (start : Option StepPublicInputs)
    (fin : StepPublicInputs) (anchor : List Nat) (linked : Linked start ls (some fin))
    (valid : ∀ l ∈ ls, LinkValid K l) (anchored : fin.vd = anchor) :
    ∀ l ∈ ls, l.out.vd = anchor := by
  obtain ⟨-, hall⟩ := chain_vd_constant K ls start fin linked valid
  intro l hl
  rw [hall l hl, anchored]

/-! ## Arbitrary satisfying witness for the step target (withdrawal_step.rs 317-406)

`StepGates` is the LOCAL gate set only. It deliberately omits every recursive
verification (`conditionally_verify_proof`, `add_proof_target_and_verify`), the
keccak gadget lowering and the range checks that live in other gadgets. -/

structure StepWitnessTargets where
  isInitial : Bool
  prevPis : StepPublicInputs
  singlePis : SingleWithdrawalPublicInputs
  update : UpdatePublicState.Update
  updateWitness : UpdatePublicState.Witness
  chainVd : List Nat
  out : StepPublicInputs

structure StepGates (K : Keccak) (getRoot : UpdatePublicState.RootCall)
    (w : StepWitnessTargets) : Prop where
  /-- `update_public_state.old.connect(builder, &single_withdrawal_pis.public_state)` -/
  oldConnectedToSingle : w.update.oldState = w.singlePis.publicState
  /-- `update_public_state.new.conditional_assert_eq(.., prev_pis.public_state, not_initial)` -/
  newMatchesPrevWhenNotInitial : w.isInitial = false → w.update.newState = w.prevPis.publicState
  /-- `conditionally_connect_vd(builder, not_initial, prev_pis.vd, withdrawal_chain_vd)` -/
  vdConnectedWhenNotInitial : w.isInitial = false → w.chainVd = w.prevPis.vd
  /-- `Bytes32Target::select(is_initial, zero, prev.withdrawal_hash_chain)` then
  `single_withdrawal_pis.withdrawal.hash_with_prev_hash`. -/
  hashChain : w.out.withdrawalHashChain =
    bytes32Of (hashWithPrevHash K
      (if w.isInitial then initialHashChain else w.prevPis.withdrawalHashChain.value)
      w.singlePis.withdrawal)
  /-- `new_pis.public_state = update_public_state.new` -/
  outState : w.out.publicState = w.update.newState
  /-- `new_pis.vd = withdrawal_chain_vd` -/
  outVd : w.out.vd = w.chainVd
  /-- The nested `UpdatePublicStateTarget` gate set. -/
  updateGates : UpdatePublicState.CircuitGates getRoot w.update w.updateWitness

/-- Any satisfying witness still satisfies the source's locally verified
public-state transition; inherited from `UpdatePublicState`. -/
theorem gates_imply_public_state_transition (K : Keccak)
    (getRoot : UpdatePublicState.RootCall) (w : StepWitnessTargets)
    (gates : StepGates K getRoot w) :
    UpdatePublicState.nativeVerify getRoot w.update = .ok () :=
  UpdatePublicState.target_implies_native_local_verification gates.updateGates

/-- Even for an arbitrary witness the emitted statement is the target state. -/
theorem gates_publish_target_state (K : Keccak) (getRoot : UpdatePublicState.RootCall)
    (w : StepWitnessTargets) (gates : StepGates K getRoot w) :
    w.out.publicState = w.update.newState := gates.outState

/-- Non-initial witnesses are forced onto the predecessor's state and vd. -/
theorem gates_non_initial_binds_prev (K : Keccak) (getRoot : UpdatePublicState.RootCall)
    (w : StepWitnessTargets) (gates : StepGates K getRoot w) (nonInitial : w.isInitial = false) :
    w.out.publicState = w.prevPis.publicState ∧ w.out.vd = w.prevPis.vd := by
  refine ⟨?_, ?_⟩
  · rw [gates.outState, gates.newMatchesPrevWhenNotInitial nonInitial]
  · rw [gates.outVd, gates.vdConnectedWhenNotInitial nonInitial]

/-- BOUNDARY, stated explicitly: on the INITIAL step neither the carried verifier
data nor `update_public_state.new` is constrained by any gate. Both are free
witnesses; they are pinned only by a successor step or by the wrapper anchor. -/
theorem gates_initial_leaves_vd_free (K : Keccak) (getRoot : UpdatePublicState.RootCall)
    (w : StepWitnessTargets) (gates : StepGates K getRoot w) (initial : w.isInitial = true)
    (other : List Nat) :
    StepGates K getRoot { w with chainVd := other, out := { w.out with vd := other } } := by
  refine ⟨gates.oldConnectedToSingle, ?_, ?_, gates.hashChain, gates.outState, rfl,
    gates.updateGates⟩
  · intro h; rw [initial] at h; exact absurd h (by simp)
  · intro h; rw [initial] at h; exact absurd h (by simp)

/-- A satisfying witness for a link built from an accepting native step. -/
theorem gates_of_native_step (env : VerifierEnv) (w : StepWitness) (out : StepPublicInputs)
    (single : SingleWithdrawalPublicInputs) (prevPis : StepPublicInputs)
    (accepted : stepToPublicInputs env w = .ok out)
    (decoded : decodeSingle (w.singleWithdrawalProof.pis.take singleWithdrawalPublicInputsLen)
      = .ok single)
    (initial : w.prevChainProof = none)
    (height : w.update.proof.length = UpdatePublicState.height) :
    StepGates env.keccak env.getRoot
      { isInitial := true, prevPis := prevPis, singlePis := single, update := w.update
      , updateWitness :=
          ⟨UpdatePublicState.statesEqual w.update.newState w.update.oldState,
           !UpdatePublicState.statesEqual w.update.newState w.update.oldState,
           UpdatePublicState.expectedOldRoot env.getRoot w.update⟩
      , chainVd := env.chainVd, out := out } := by
  obtain ⟨single', prevHash, -, -, decoded', matched, prevOk, final⟩ :=
    native_step_success env w out accepted
  have hsingle : single = single' := by
    rw [decoded] at decoded'; injection decoded'
  subst hsingle
  have hprev : prevHash = initialHashChain := by
    rw [prevChainHash, initial] at prevOk; injection prevOk with h; exact h.symm
  subst hprev
  refine ⟨matched.symm, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro h; exact absurd h (by simp)
  · intro h; exact absurd h (by simp)
  · simp [final]
  · simp [final]
  · simp [final]
  · exact UpdatePublicState.target_witness_of_native_local_verification env.getRoot w.update
      height (native_step_requires_public_state_transition env w out accepted)

/-! ## Extended public state and the wrapper circuit (withdrawal_circuit.rs) -/

/-- `PoseidonHashOut::hash_inputs_u64` composed with the `Bytes32` conversion, and
its in-circuit counterpart `ExtendedPublicStateTarget::commitment`. Opaque. -/
abbrev Poseidon := List Nat → Words8

structure ExtendedPublicState where
  inner : PublicState
  blockHashChain : Words8
  depositHashChain : Words8
  depositCount : Nat
  channelRegHashChain : Words8
  bpSigChain : Words8
  deriving DecidableEq, Repr

def ExtendedPublicState.toU64Vec (x : ExtendedPublicState) : List Nat :=
  x.inner.words ++ x.blockHashChain.words ++ x.depositHashChain.words ++ [x.depositCount] ++
    x.channelRegHashChain.words ++ x.bpSigChain.words

def ExtendedPublicState.commitment (P : Poseidon) (x : ExtendedPublicState) : Words8 :=
  P x.toU64Vec

theorem extended_public_state_vec_length (x : ExtendedPublicState) :
    x.toU64Vec.length = extendedPublicStateU64Len := by
  simp [ExtendedPublicState.toU64Vec, Words8.words, BalancePublicInputs.PublicState.words,
    BalancePublicInputs.Root.words, extendedPublicStateU64Len]

/-- `WithdrawalProofPublicInputs`: the 23-word KECCAK PREIMAGE, not the registered
public input. `block_number` is spread over TWO u32 words here. -/
structure ProofPreimage where
  withdrawalHash : Words8
  withdrawalProver : Nat
  extCommitment : Words8
  blockNumber : Nat
  deriving DecidableEq, Repr

def ProofPreimage.toU32Vec (p : ProofPreimage) : List Nat :=
  p.withdrawalHash.words ++ addressLimbs p.withdrawalProver ++ p.extCommitment.words ++
    blockNumberU32Limbs p.blockNumber

theorem proof_preimage_length (p : ProofPreimage) :
    p.toU32Vec.length = withdrawalProofPublicInputsLen := rfl

/-- `WithdrawalProofPublicInputs::hash` = `remove_3bits(keccak256(preimage))`, and
the identical in-circuit `pis.hash::<F,C,D>(builder).remove_3bits(builder)`. -/
def ProofPreimage.hash (K : Keccak) (p : ProofPreimage) : Words8 :=
  (bytes32Of (K p.toU32Vec)).removeThreeBits

/-- FINAL registered layout: `[pis_hash(8) || ext_commitment(8) || block_number(1)]`. -/
structure PublicInputs where
  pisHash : Words8
  extCommitment : Words8
  blockNumber : Nat
  deriving DecidableEq, Repr

def PublicInputs.toU64Vec (p : PublicInputs) : List Nat :=
  p.pisHash.words ++ p.extCommitment.words ++ [p.blockNumber]

theorem final_layout_length (p : PublicInputs) :
    p.toU64Vec.length = finalPublicInputsLen := rfl

/-- Executable decoder for the 17 registered words. There is no Rust decoder for
this layout (the contract consumes it), so the checks are exactly the properties
the circuit guarantees: eight u32 limbs each for `pis_hash` and
`ext_commitment`, a top `pis_hash` limb masked to 29 bits by `remove_3bits`, and
a `block_number` range-checked to 63 bits by `U63Target::new(builder, true)`. -/
def fromU64Slice (inputs : List Nat) : Result PublicInputs := do
  require (inputs.length == finalPublicInputsLen)
    (.invalidLength finalPublicInputsLen inputs.length)
  let pisHash ← decodeBytes32 (inputs.take bytes32Len)
  let extCommitment ← decodeBytes32 ((inputs.drop bytes32Len).take bytes32Len)
  require (pisHash.w0 < 2 ^ maskKeptBits) (.maskedLimbTooLarge pisHash.w0)
  let blockNumber := inputs.getD (bytes32Len + bytes32Len) 0
  require (blockNumber < u63Limit) (.blockNumberOverflow blockNumber)
  pure ⟨pisHash, extCommitment, blockNumber⟩

theorem from_u64_slice_rejects_wrong_length (inputs : List Nat)
    (bad : ¬ inputs.length = finalPublicInputsLen) :
    fromU64Slice inputs = .error (.invalidLength finalPublicInputsLen inputs.length) := by
  simp [fromU64Slice, require, bad, bind, Except.bind]

theorem from_u64_slice_success (inputs : List Nat) (p : PublicInputs)
    (accepted : fromU64Slice inputs = .ok p) :
    inputs.length = finalPublicInputsLen ∧ p.pisHash.w0 < 2 ^ maskKeptBits ∧
      p.blockNumber < u63Limit ∧ p.toU64Vec = inputs := by
  simp only [fromU64Slice, unit_bind_ok_iff, bind_ok_iff, exists_unit, require_ok_iff,
    pure_ok_iff, beq_iff_eq, decide_eq_true_eq] at accepted
  obtain ⟨len, pisHash, hp, extCommitment, he, masked, block, final⟩ := accepted
  subst final
  refine ⟨len, masked, block, ?_⟩
  -- the 17 decoded words are exactly the input words
  match inputs, len with
  | [a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7, c], _ =>
    simp only [decodeBytes32] at hp he
    split at hp
    · exact absurd hp (by simp)
    · split at he
      · exact absurd he (by simp)
      · injection hp with hp
        injection he with he
        subst hp
        subst he
        rfl

/-- Round trip on canonical registered words. -/
theorem from_u64_slice_roundtrip (p : PublicInputs)
    (pisCanonical : p.pisHash.Canonical) (extCanonical : p.extCommitment.Canonical)
    (masked : p.pisHash.w0 < 2 ^ maskKeptBits) (block : p.blockNumber < u63Limit) :
    fromU64Slice p.toU64Vec = .ok p := by
  obtain ⟨a, b, n⟩ := p
  obtain ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩ := a
  obtain ⟨b0, b1, b2, b3, b4, b5, b6, b7⟩ := b
  simp only [Words8.Canonical, Words8.words, List.mem_cons, List.not_mem_nil, or_false,
    forall_eq_or_imp, forall_eq] at pisCanonical extCanonical
  obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7⟩ := pisCanonical
  obtain ⟨g0, g1, g2, g3, g4, g5, g6, g7⟩ := extCanonical
  dsimp only at masked block
  simp [PublicInputs.toU64Vec, Words8.words, fromU64Slice, require, decodeBytes32,
    firstOutOfRange, Words8.read, bind, Except.bind, pure, Except.pure,
    finalPublicInputsLen, bytes32Len, List.take, List.drop,
    Nat.not_le.mpr h0, Nat.not_le.mpr h1, Nat.not_le.mpr h2, Nat.not_le.mpr h3,
    Nat.not_le.mpr h4, Nat.not_le.mpr h5, Nat.not_le.mpr h6, Nat.not_le.mpr h7,
    Nat.not_le.mpr g0, Nat.not_le.mpr g1, Nat.not_le.mpr g2, Nat.not_le.mpr g3,
    Nat.not_le.mpr g4, Nat.not_le.mpr g5, Nat.not_le.mpr g6, Nat.not_le.mpr g7,
    masked, block]

/-- Local gate set of `WithdrawalCircuit::new`. Recursive verification of the
chain proof itself is a boundary: only its carried statement is modeled. -/
structure WrapperWitness where
  chainPis : StepPublicInputs
  ext : ExtendedPublicState
  prover : Nat
  out : PublicInputs

structure WrapperGates (K : Keccak) (P : Poseidon) (anchor : List Nat)
    (w : WrapperWitness) : Prop where
  /-- `add_proof_target_and_verify_cyclic` connects `constant_verifier_data` to
  the verifier data embedded at the TAIL of the inner proof's public inputs. -/
  cyclicVdAnchor : w.chainPis.vd = anchor
  /-- `ext_public_state.inner.connect(builder, &chain_public_state)` on the 15
  words at offset 8 of the chain proof's public inputs. -/
  extInnerConnected : w.ext.inner = w.chainPis.publicState
  /-- `ext_public_state.commitment(builder)` -/
  commitment : w.out.extCommitment = ExtendedPublicState.commitment P w.ext
  /-- `block_number = ext_public_state.inner.block_number` -/
  blockNumber : w.out.blockNumber = w.ext.inner.blockNumber
  /-- 63-bit range check from `ExtendedPublicStateTarget::new(builder, true)`. -/
  blockNumberRanged : w.out.blockNumber < u63Limit
  /-- `pis.hash(builder).remove_3bits(builder)` over the 23-word preimage
  `[chain_withdrawal_hash || prover || ext_commitment || block_number(hi,lo)]`. -/
  pisHash : w.out.pisHash =
    ProofPreimage.hash K ⟨w.chainPis.withdrawalHashChain, w.prover, w.out.extCommitment,
      w.out.blockNumber⟩

theorem wrapper_registers_seventeen_words (K : Keccak) (P : Poseidon) (anchor : List Nat)
    (w : WrapperWitness) (_gates : WrapperGates K P anchor w) :
    w.out.toU64Vec.length = finalPublicInputsLen := rfl

theorem wrapper_block_number_is_chain_block_number (K : Keccak) (P : Poseidon)
    (anchor : List Nat) (w : WrapperWitness) (gates : WrapperGates K P anchor w) :
    w.out.blockNumber = w.chainPis.publicState.blockNumber := by
  rw [gates.blockNumber, gates.extInnerConnected]

/-- The registered `ext_commitment` commits to the SAME public state the chain
proof carries; the extra extended fields are free witnesses whose only binding
is the L1 finalized-root check. -/
theorem wrapper_commitment_covers_chain_state (K : Keccak) (P : Poseidon) (anchor : List Nat)
    (w : WrapperWitness) (gates : WrapperGates K P anchor w) :
    w.out.extCommitment = P (w.chainPis.publicState.words ++ w.ext.blockHashChain.words ++
      w.ext.depositHashChain.words ++ [w.ext.depositCount] ++
      w.ext.channelRegHashChain.words ++ w.ext.bpSigChain.words) := by
  rw [gates.commitment, ExtendedPublicState.commitment, ExtendedPublicState.toU64Vec,
    gates.extInnerConnected]

/-- The masked pis hash never fills the top three bits: it is a 253-bit value. -/
theorem wrapper_pis_hash_masked (K : Keccak) (P : Poseidon) (anchor : List Nat)
    (w : WrapperWitness) (gates : WrapperGates K P anchor w) :
    w.out.pisHash.w0 < 2 ^ maskKeptBits := by
  rw [gates.pisHash, ProofPreimage.hash]
  exact remove_three_bits_top_limb _

/-- The prover address is bound ONLY through the keccak preimage; it is a free
in-circuit witness otherwise, and it is NOT among the 17 registered words.
Distinct provers therefore give distinct preimages - binding the registered hash
to a prover additionally needs the collision-resistance boundary. -/
theorem preimage_prover_slice (hash commitment : Words8) (prover block : Nat) :
    ((ProofPreimage.mk hash prover commitment block).toU32Vec.drop bytes32Len).take addressLen
      = addressLimbs prover := by
  obtain ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩ := hash
  obtain ⟨b0, b1, b2, b3, b4, b5, b6, b7⟩ := commitment
  rfl

theorem wrapper_prover_enters_preimage_only (p q : Nat) (hash commitment : Words8)
    (block : Nat) (different : addressLimbs p ≠ addressLimbs q) :
    (ProofPreimage.mk hash p commitment block).toU32Vec ≠
      (ProofPreimage.mk hash q commitment block).toU32Vec := by
  intro h
  apply different
  have slice := congrArg (fun l => (List.take addressLen (List.drop bytes32Len l))) h
  simpa only [preimage_prover_slice] using slice

/-! ## Layout equality with the Solidity model (`RollupValue.verifyWithdrawalSet`) -/

theorem limbs_match_of_bytes32_of (v : Nat) (rest : List Nat) :
    RollupValue.limbsMatchBytes32 ((bytes32Of v).words ++ rest) 0 v = true := by
  simp [RollupValue.limbsMatchBytes32, RollupValue.u32Limit, bytes32Of, Words8.words, limbBase]

theorem limbs_match_final_layout (p : PublicInputs) (v : Nat) (split : p.pisHash = bytes32Of v) :
    RollupValue.limbsMatchBytes32 p.toU64Vec 0 v = true := by
  obtain ⟨a, b, n⟩ := p
  simp only at split
  subst split
  simp [PublicInputs.toU64Vec, RollupValue.limbsMatchBytes32, RollupValue.u32Limit,
    bytes32Of, Words8.words, limbBase]

theorem limbs_to_bytes32_of_final_layout (p : PublicInputs) :
    RollupValue.limbsToBytes32 p.toU64Vec 8 = p.extCommitment.value := by
  obtain ⟨a, b, n⟩ := p
  obtain ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩ := a
  obtain ⟨b0, b1, b2, b3, b4, b5, b6, b7⟩ := b
  rfl

theorem final_layout_block_word (p : PublicInputs) :
    p.toU64Vec.getD 16 0 = p.blockNumber := by
  obtain ⟨a, b, n⟩ := p
  obtain ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩ := a
  obtain ⟨b0, b1, b2, b3, b4, b5, b6, b7⟩ := b
  rfl

/-- The contract's `% u64Limit` cast at `pi[16]` is inert: the circuit already
range-checks the block number to 63 bits. -/
theorem block_word_u64_cast_inert (p : PublicInputs) (ranged : p.blockNumber < u63Limit) :
    p.toU64Vec.getD 16 0 % RollupValue.u64Limit = p.blockNumber := by
  rw [final_layout_block_word]
  exact Nat.mod_eq_of_lt (by
    have : p.blockNumber < 2 ^ 63 := ranged
    simp only [RollupValue.u64Limit]
    omega)

/-- THE COMPARISON. Given only the two hash-agreement boundaries, an accepting
wrapper witness produces exactly the 17 words `IntmaxRollup` recomputes:
`limbsMatchBytes32` at offset 0 against `withdrawalPisHash` (fold + `% 2^253`),
`limbsToBytes32` at offset 8 as the extended-state root, and the block number at
`pi[16]`. Proof soundness, hash injectivity and the finalized-root check remain
outside. -/
theorem circuit_layout_matches_rollup_verifier
    (K : Keccak) (P : Poseidon) (e : RollupValue.Environment) (anchor : List Nat)
    (w : WrapperWitness) (gates : WrapperGates K P anchor w)
    (hashAgree : SolidityPisHashAgrees K e) :
    w.out.toU64Vec.length = finalPublicInputsLen ∧
    RollupValue.limbsMatchBytes32 w.out.toU64Vec 0
      (RollupValue.withdrawalPisHash e w.chainPis.withdrawalHashChain.value w.prover
        w.out.extCommitment.value w.out.blockNumber) = true ∧
    RollupValue.limbsToBytes32 w.out.toU64Vec 8 = w.out.extCommitment.value ∧
    w.out.toU64Vec.getD 16 0 % RollupValue.u64Limit = w.out.blockNumber := by
  refine ⟨final_layout_length w.out, ?_, limbs_to_bytes32_of_final_layout w.out, ?_⟩
  · refine limbs_match_final_layout w.out _ ?_
    rw [gates.pisHash, ProofPreimage.hash, remove_three_bits_is_mask_2_253]
    congr 1
    rw [RollupValue.withdrawalPisHash, ← hashAgree]
    rfl
  · exact block_word_u64_cast_inert w.out gates.blockNumberRanged

/-- The chain hash the wrapper commits to is exactly the contract's
`ws.foldl (foldWithdrawalLeaf e) 0` over the chain's leaves. -/
theorem chain_hash_matches_rollup_fold (K : Keccak) (e : RollupValue.Environment)
    (canonical : KeccakCanonical K) (leafAgree : LeafHashAgrees K e)
    (ls : List Link) (fin : StepPublicInputs)
    (linked : Linked none ls (some fin)) (valid : ∀ l ∈ ls, LinkValid K l) :
    fin.withdrawalHashChain.value
      = ((ls.map Link.withdrawal).map toRollupWithdrawal).foldl
          (RollupValue.foldWithdrawalLeaf e) 0 := by
  rw [chain_hash_is_leaf_fold K canonical ls none fin linked valid]
  exact fold_chain_from_zero_matches_rollup K e leafAgree _

/-! ## Named boundaries that stay undischarged -/

/-- The contract additionally requires the emitted commitment to be an on-chain
finalized root (`RollupValue.verifyWithdrawalSet`'s `s.finalizedRoot root`). The
circuit never proves this; it is the only thing tying the free extended-state
witness to real history. -/
def ExtCommitmentFinalized (s : RollupValue.State) (p : PublicInputs) : Prop :=
  s.finalizedRoot p.extCommitment.value = true

/-- The contract rejects an empty withdrawal set; the CIRCUIT does not - a chain
of length zero is a well-formed statement here. -/
theorem rollup_rejects_empty_set (e : RollupValue.Environment) (s : RollupValue.State)
    (prover : RollupValue.Address) (proof : RollupValue.Bytes) :
    RollupValue.verifyWithdrawalSet e s [] prover proof
      = .error (.revert "WithdrawalEmptySet") := by
  simp [RollupValue.verifyWithdrawalSet, RollupValue.require, bind, Except.bind]

/-! ## Non-vacuous positive examples -/

def sampleState : PublicState := ⟨7, 0, 11, ⟨1, 2, 3, 4⟩, ⟨5, 6, 7, 8⟩, ⟨9, 10, 11, 12⟩⟩

def sampleWithdrawal : Withdrawal :=
  ⟨0x1234, 3, 1000, 0xdeadbeef, 0⟩

/-- A deliberately simple stand-in digest; only used to exhibit a concrete trace. -/
def sampleKeccak : Keccak := fun xs => xs.foldl (fun acc w => (acc * 31 + w + 1) % u256Limit) 1

theorem sample_keccak_canonical : KeccakCanonical sampleKeccak := by
  intro xs
  cases xs with
  | nil => decide
  | cons x xs =>
    show List.foldl _ _ _ < u256Limit
    have : ∀ (ys : List Nat) (a : Nat),
        List.foldl (fun acc w => (acc * 31 + w + 1) % u256Limit) a ys < u256Limit ∨ ys = [] := by
      intro ys
      induction ys with
      | nil => intro _; exact Or.inr rfl
      | cons y ys ih =>
        intro a
        rcases ih ((a * 31 + y + 1) % u256Limit) with h | h
        · exact Or.inl h
        · subst h
          exact Or.inl (Nat.mod_lt _ (by decide))
    rcases this (x :: xs) 1 with h | h
    · exact h
    · exact absurd h (by simp)

def sampleUpdate : UpdatePublicState.Update :=
  ⟨sampleState, sampleState, UpdatePublicState.dummyProof⟩

def sampleSinglePis : List Nat := sampleState.words ++ sampleWithdrawal.toU32Vec

def sampleEnv : VerifierEnv :=
  { chainVerify := fun _ => true
  , singleVerify := fun _ => true
  , chainCapElements := 4
  , chainVd := [1, 2, 3, 4]
  , getRoot := fun _ _ _ => BalancePublicInputs.Root.zero
  , keccak := sampleKeccak }

def sampleWitness : StepWitness :=
  { prevChainProof := none
  , singleWithdrawalProof := ⟨sampleSinglePis⟩
  , update := sampleUpdate }

/-- A concrete initial step is accepted, publishes `update.new` and seeds the
chain at zero. -/
theorem sample_step_accepted :
    stepToPublicInputs sampleEnv sampleWitness
      = .ok { withdrawalHashChain :=
                bytes32Of (hashWithPrevHash sampleKeccak initialHashChain sampleWithdrawal)
            , publicState := sampleState
            , vd := [1, 2, 3, 4] } := by
  rfl

/-- The concrete step also satisfies the local gate set: `StepGates` is not
vacuous. -/
def sampleLink : Link :=
  { prev := none
  , withdrawal := sampleWithdrawal
  , update := sampleUpdate
  , out := { withdrawalHashChain :=
               bytes32Of (hashWithPrevHash sampleKeccak initialHashChain sampleWithdrawal)
           , publicState := sampleState
           , vd := [1, 2, 3, 4] } }

set_option maxRecDepth 40000 in
theorem sample_link_valid : LinkValid sampleKeccak sampleLink := by
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> (intro p h; simp [sampleLink] at h)

theorem sample_chain_linked : Linked none [sampleLink] (some sampleLink.out) :=
  ⟨rfl, rfl⟩

/-- Instantiating the chain theorems on the concrete one-step chain. -/
theorem sample_chain_hash_is_fold :
    sampleLink.out.withdrawalHashChain.value
      = foldChain sampleKeccak initialHashChain [sampleWithdrawal] := by
  refine chain_hash_is_leaf_fold sampleKeccak sample_keccak_canonical [sampleLink] none
    sampleLink.out sample_chain_linked ?_
  intro l hl
  rcases List.mem_cons.mp hl with rfl | hl
  · exact sample_link_valid
  · cases hl

/-! ### Final 17-word decoder examples -/

def samplePisHash : Words8 := ⟨5, 1, 2, 3, 4, 5, 6, 7⟩
def sampleExtCommitment : Words8 := ⟨9, 8, 7, 6, 5, 4, 3, 2⟩
def samplePublicInputs : PublicInputs := ⟨samplePisHash, sampleExtCommitment, 42⟩

theorem sample_final_words :
    samplePublicInputs.toU64Vec = [5, 1, 2, 3, 4, 5, 6, 7, 9, 8, 7, 6, 5, 4, 3, 2, 42] := rfl

theorem sample_decoder_accepted :
    fromU64Slice [5, 1, 2, 3, 4, 5, 6, 7, 9, 8, 7, 6, 5, 4, 3, 2, 42]
      = .ok samplePublicInputs := by
  rfl

theorem sample_decoder_rejects_short :
    fromU64Slice [5, 1, 2, 3, 4, 5, 6, 7, 9, 8, 7, 6, 5, 4, 3, 2]
      = .error (.invalidLength 17 16) := by
  rfl

/-- A pis-hash top limb above `2^29` cannot come out of `remove_3bits`. -/
theorem sample_decoder_rejects_unmasked_top_limb :
    fromU64Slice [2 ^ 29, 1, 2, 3, 4, 5, 6, 7, 9, 8, 7, 6, 5, 4, 3, 2, 42]
      = .error (.maskedLimbTooLarge (2 ^ 29)) := by
  rfl

/-- A block number at or above `2^63` cannot come out of the 63-bit range check. -/
theorem sample_decoder_rejects_wide_block_number :
    fromU64Slice [5, 1, 2, 3, 4, 5, 6, 7, 9, 8, 7, 6, 5, 4, 3, 2, 2 ^ 63]
      = .error (.blockNumberOverflow (2 ^ 63)) := by
  rfl

/-! ### Wrapper example -/

def sampleExt : ExtendedPublicState :=
  ⟨sampleState, Words8.zero, Words8.zero, 0, Words8.zero, Words8.zero⟩

def samplePoseidon : Poseidon := fun _ => sampleExtCommitment

def sampleWrapper : WrapperWitness :=
  { chainPis := sampleLink.out
  , ext := sampleExt
  , prover := 0xabcd
  , out := { pisHash := ProofPreimage.hash sampleKeccak
               ⟨sampleLink.out.withdrawalHashChain, 0xabcd, sampleExtCommitment, 7⟩
           , extCommitment := sampleExtCommitment
           , blockNumber := 7 } }

set_option maxRecDepth 40000 in
/-- `WrapperGates` is satisfiable: the concrete wrapper witness meets every local
gate, including the 63-bit block-number range check. -/
theorem sample_wrapper_gates :
    WrapperGates sampleKeccak samplePoseidon [1, 2, 3, 4] sampleWrapper := by
  refine ⟨rfl, rfl, rfl, rfl, ?_, rfl⟩
  decide

end Zkp.Implementation.WithdrawalChain
