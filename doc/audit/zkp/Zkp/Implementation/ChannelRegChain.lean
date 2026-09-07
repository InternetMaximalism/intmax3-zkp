import Std
import Zkp.Implementation.RollupValue

/-!
# Channel-registration hash chain: handwritten implementation-level semantics

Sources (runtime, current worktree):
- src/circuits/validity/channel_reg_hash_chain/channel_reg_step.rs (982 lines)
- src/circuits/validity/channel_reg_hash_chain/channel_reg_chain_pis.rs (313 lines)
- src/circuits/validity/channel_reg_hash_chain/channel_reg_hash_chain_circuit.rs (126 lines)

This is a SEMANTIC MODEL of those files. It is NOT a refinement proof of the Rust /
plonky2 code, NOT an extraction of the circuit, and NOT cryptographic soundness.
Each step consumes one on-chain `ChannelRegRecord` and advances two accumulators:
the keccak `channel_reg_hash_chain` (fold over a fixed 244-word u32 preimage) and
the Poseidon `channel_tree_root` (slot `channel_id` must currently hold the DEFAULT
`ChannelLeaf` — the R5 one-time-registration guard — and is re-rooted with a leaf whose
`member_pubkeys_root` is computed in-circuit from the 8 member slots). The member
identities are witnessed ONCE as Poseidon values and feed BOTH the keccak preimage
(via the deterministic 32/32 split `Bytes32Target::from_hash_out`) and the Poseidon
member leaves; that shared witness is the R2 cross-binding and it is modeled here by
literally deriving both from the same `Hash4` (`MemberEntry.regEntry`).

Native admission (`ChannelRegStepWitness::to_public_inputs`, an executable `Except`
mirroring the source order of checks and its error precedence) is modeled separately
from ARBITRARY satisfying witnesses (`CircuitGates`, the local gate equations of
`ChannelRegStepTarget::new`). `nativeInputs` is `set_witness`; the theorem
`native_assignment_satisfies_gates` links the two under explicit premises. `Chain`
composes step gates through the forwarding wrapper (`ChannelRegHashChainCircuit`)
under the proof-soundness premise, and `chain_matches_rollup_fold` states, under the
named bridge premises, that the circuit's chain value equals the fold that
`RollupValue.registerChannel` (IntmaxRollup.sol) performs on `pendingRegistrationChain`
over the same registrations in the same order from the same initial value.

Named boundaries (undischarged premises; all opaque callbacks or hypotheses):
- `HashCallbacks`: `Environment.keccakWords` (plonky2_keccak `solidity_keccak256` over
  u32 words / `builder.keccak256`), `poseidonWords` (`PoseidonHashOut::hash_inputs_u64`)
  and `twoToOne` (the Poseidon 2-to-1 of the Merkle gadgets) are opaque. No injectivity
  and no collision resistance is stated anywhere.
- `ProofSoundness`: `Environment.proofAccepted vd pis` is plonky2 verification (opaque
  Bool). `conditionally_verify_proof` checks the previous chain proof under the verifier
  data DECLARED IN THAT PROOF'S OWN PUBLIC INPUTS. "accepted ⇒ produced by a
  gate-satisfying witness" is the premise encoded by the `Chain` inductive; it is never
  stated as a theorem.
- `ConsumerVdPin`: on an initial step `new_pis.vd` is a FREE virtual verifier data
  (`initial_step_vd_unconstrained`); every continued step forwards it unchanged
  (`chain_declares_single_vd`). Only a consumer pins it: `ChannelRegHashChainCircuit::verify`
  → `check_cyclic_proof_verifier_data` (modeled: `chain_verify_pins_declared_vd`), or the
  block-step circuit outside these three files.
- `InitialStatePin`: `initial_channel_reg_hash_chain`, `initial_channel_tree_root`,
  `initial_channel_reg_count` and (on an initial step) `block_number` are FREE inputs
  (`initial_step_initial_values_unconstrained`, `initial_step_block_number_unconstrained`).
  Whether they are the contract's actual pending chain / channel tree / count is a
  consumer obligation outside the modeled files.
- `MerklePathBinding`: `ChannelMerkleProof` siblings are prover-supplied; that the path
  is the authentic one, and that re-rooting changes only slot `channel_id`, rests on
  Poseidon collision resistance, which is NOT assumed. Only `reroot_of_equal_leaf_is_identity`
  and the guard/write equations are proved.
- `PaddingRecipientNotPinned`: the circuit forces `pk_g = pk_b = regev = 0` on inactive
  slots but NOT `recipient` (`ChannelRegStepTarget::new` has no `conditional_assert_eq`
  for `member_recipients`), while native `validate()` rejects any non-default padding
  slot. `gates_admit_nonzero_padding_recipient` exhibits the gap; the Solidity-fold
  comparison therefore carries `PaddingZeroed` as an explicit hypothesis.
- `ContractDelegatedChecks`: nonzero and pairwise-distinct active `pk_g`, and the
  identity of the `recipient` words, are NOT constrained in-circuit; the source
  delegates them to `IntmaxRollup.registerChannel` through equality of the keccak chain.
  Modeled as `Record.validate` (native only) and as `RollupValue.validateMembers`.
- `SolidityKeccakPacking`: `solidity_keccak256` consumes each u32 word as four big-endian
  bytes (plonky2_keccak, not in the modeled files). Under that packing the circuit's fold
  preimage is byte-identical to `RollupValue.hashPreimage (.channelRegistration …)`
  (`fold_preimage_matches_rollup_model`, kernel-checked); equality of the chain VALUES
  additionally needs both sides to call the same keccak (`KeccakBridge` +
  `RollupValue.HashEncodingAgrees`).
- `FieldAndGadgetLowering`: Goldilocks arithmetic, `range_check`, `split_le`,
  `safe_split_lo_and_hi`, `select`, `is_equal`, the keccak/Poseidon gadgets and the
  `from_pis` slicing are modeled as Nat equations on already-reduced values. In
  particular the `[2, 8]` bound on `member_count` is the intended reading of two 4-bit
  range checks on field differences.
- `NativeProofNotChecked`: `to_public_inputs` never verifies the supplied previous proof;
  it only parses its public inputs. Modeled as the `hproof` premise of
  `native_assignment_satisfies_gates`.
- `VdCanonicity`: `vd_from_pis_slice` / `PoseidonHashOut::from_u64_slice` read field
  elements from u64 with no canonicity check; vd words are carried as an opaque `List Nat`.
No proof soundness, hash injectivity, signature validity, finality or
"acceptance ⇒ funds safe" is stated as a theorem.
-/

namespace Zkp.Implementation.ChannelRegChain

/-! ## Pinned constants (literals from the sources) -/

def limbBase : Nat := 2 ^ 32
def u63Limit : Nat := 2 ^ 63
def u64Limit : Nat := 2 ^ 64
def goldilocks : Nat := 0xffffffff00000001
/-- `BYTES32_LEN` -/
def bytes32Len : Nat := 8
/-- `POSEIDON_HASH_OUT_LEN` -/
def poseidonHashOutLen : Nat := 4
/-- `ADDRESS_LEN` (5 u32 limbs = 20 bytes) -/
def addressLen : Nat := 5
/-- `constants::MAX_SIG_CLUSTER` -/
def maxSigCluster : Nat := 8
/-- `constants::MEMBER_TREE_HEIGHT` -/
def memberTreeHeight : Nat := 3
/-- `constants::CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS` -/
def channelTreeHeight : Nat := 32
/-- lower bound of the in-circuit `member_count` range check -/
def minMemberCount : Nat := 2
/-- `CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN = 2*BYTES32_LEN + 2*POSEIDON_HASH_OUT_LEN + 3` -/
def publicInputsLen : Nat := 2 * bytes32Len + 2 * poseidonHashOutLen + 3
/-- `utils::cyclic::vd_vec_len = 4 + 4 * num_cap_elements` -/
def vdVecLen (capElements : Nat) : Nat := 4 + 4 * capElements
/-- `generate_cd`: `common.num_public_inputs = CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN + vd_vec_len`. -/
def chainPublicInputCount (capElements : Nat) : Nat := publicInputsLen + vdVecLen capElements
/-- one member slot of the keccak preimage: `pk_g(8) ‖ pk_b(8) ‖ regev(8) ‖ recipient(5)`. -/
def memberSlotWords : Nat := bytes32Len + bytes32Len + bytes32Len + addressLen
/-- `CHANNEL_REG_PREIMAGE_U32_LEN` -/
def regPreimageU32Len : Nat := 8 + 1 + 1 + 1 + 1 + maxSigCluster * memberSlotWords
/-- `generate_cd` pads with `1 << 12` noop gates. -/
def noopGates : Nat := 4096
/-- `key_tree::MEMBER_LEAF_DOMAIN` ("MBLF") -/
def memberLeafDomain : Nat := 0x4d424c46
/-- `channel_tree::CHANNEL_LEAF_DOMAIN` ("CHLF") -/
def channelLeafDomain : Nat := 0x43484c46

theorem public_inputs_len_pinned : publicInputsLen = 27 := by decide
theorem reg_preimage_len_pinned : regPreimageU32Len = 244 := by decide
theorem member_slot_words_pinned : memberSlotWords = 29 := by decide
theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl
theorem member_tree_height_pinned : 2 ^ memberTreeHeight = maxSigCluster := by decide
theorem channel_tree_height_pinned : channelTreeHeight = 32 := rfl
theorem min_member_count_pinned : minMemberCount = 2 := rfl
theorem vd_vec_len_pinned (cap : Nat) : vdVecLen cap = 4 + 4 * cap := rfl
theorem chain_public_input_count_pinned (cap : Nat) :
    chainPublicInputCount cap = 27 + (4 + 4 * cap) := by
  simp [chainPublicInputCount, publicInputsLen, vdVecLen, bytes32Len, poseidonHashOutLen]
theorem noop_gates_pinned : noopGates = 2 ^ 12 := by decide
theorem u63_limit_below_goldilocks : u63Limit + 1 < goldilocks := by decide
theorem channel_ids_fit_in_limb : 2 ^ channelTreeHeight = limbBase := by decide

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

/-- `PoseidonHashOut`: four Goldilocks elements carried as `Nat`. -/
structure Hash4 where
  h0 : Nat
  h1 : Nat
  h2 : Nat
  h3 : Nat
  deriving DecidableEq, Repr

def Hash4.elems (h : Hash4) : List Nat := [h.h0, h.h1, h.h2, h.h3]
def Hash4.zero : Hash4 := ⟨0, 0, 0, 0⟩

/-- Big-endian limb recomposition, `limbBase`-adic. -/
def limbValue (ws : List Nat) : Nat := ws.foldl (fun acc w => acc * limbBase + w) 0

def Words8.value (x : Words8) : Nat := limbValue x.words
def Words5.value (x : Words5) : Nat := limbValue x.words

/-- Every limb is a u32 (what `range_check(.., 32)` / `U32LimbTrait::from_u64_slice` give). -/
def CheckedWords (ws : List Nat) : Prop := ∀ w ∈ ws, w < limbBase

instance : DecidablePred CheckedWords := fun ws => List.decidableBAll _ ws

/-- Field elements are below the Goldilocks modulus (`FieldAndGadgetLowering`). -/
def Hash4.canonicalField (h : Hash4) : Prop := ∀ x ∈ h.elems, x < goldilocks

/-- `Bytes32::from(PoseidonHashOut)` / `Bytes32Target::from_hash_out`: each field element is
    split into `(high, low)` 32-bit limbs, high first. Deterministic, and the only way the
    circuit can obtain the 32-byte member identity. -/
def Hash4.toWords (h : Hash4) : Words8 :=
  ⟨h.h0 / limbBase, h.h0 % limbBase, h.h1 / limbBase, h.h1 % limbBase,
   h.h2 / limbBase, h.h2 % limbBase, h.h3 / limbBase, h.h3 % limbBase⟩

/-- `Bytes32::reduce_to_hash_out`: `high * 2^32 + low` per limb pair; MANY-TO-ONE. -/
def Words8.reduceToHash (x : Words8) : Hash4 :=
  ⟨x.w0 * limbBase + x.w1, x.w2 * limbBase + x.w3, x.w4 * limbBase + x.w5, x.w6 * limbBase + x.w7⟩

/-- `PoseidonHashOut::try_from(Bytes32)`: the bytes are the canonical re-encoding. -/
def Words8.canonical (x : Words8) : Prop := x.reduceToHash.toWords = x

instance (x : Words8) : Decidable x.canonical := by
  unfold Words8.canonical; infer_instance

theorem to_words_checked (h : Hash4) (hc : h.canonicalField) : CheckedWords h.toWords.words := by
  intro w hw
  have h0 : h.h0 < goldilocks := hc _ (by simp [Hash4.elems])
  have h1 : h.h1 < goldilocks := hc _ (by simp [Hash4.elems])
  have h2 : h.h2 < goldilocks := hc _ (by simp [Hash4.elems])
  have h3 : h.h3 < goldilocks := hc _ (by simp [Hash4.elems])
  simp only [Hash4.toWords, Words8.words, List.mem_cons, List.not_mem_nil, or_false] at hw
  simp only [goldilocks] at h0 h1 h2 h3
  simp only [limbBase]
  rcases hw with h | h | h | h | h | h | h | h <;> subst h <;> omega

/-- A hash split into limbs and read back is the same hash (`safe_split_lo_and_hi` is exact). -/
theorem reduce_to_words_roundtrip (h : Hash4) (hc : h.canonicalField) :
    h.toWords.reduceToHash = h := by
  have h0 : h.h0 < goldilocks := hc _ (by simp [Hash4.elems])
  have h1 : h.h1 < goldilocks := hc _ (by simp [Hash4.elems])
  have h2 : h.h2 < goldilocks := hc _ (by simp [Hash4.elems])
  have h3 : h.h3 < goldilocks := hc _ (by simp [Hash4.elems])
  simp only [goldilocks] at h0 h1 h2 h3
  cases h with
  | mk a b c d =>
    simp only [Hash4.toWords, Words8.reduceToHash, limbBase, Hash4.mk.injEq]
    refine ⟨?_, ?_, ?_, ?_⟩ <;> omega

/-- Anything the circuit puts into the keccak preimage for a member identity is CANONICAL:
    it is the split of a witnessed field element. A non-canonical `bytes32` registered on L1
    therefore has no satisfying witness (source comment in `common/channel_registration.rs`). -/
theorem circuit_member_words_canonical (h : Hash4) (hc : h.canonicalField) :
    h.toWords.canonical := by
  simp [Words8.canonical, reduce_to_words_roundtrip h hc]

end Zkp.Implementation.ChannelRegChain
