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

def limbBase : Nat := 4294967296
def u63Limit : Nat := 9223372036854775808
def u64Limit : Nat := 18446744073709551616
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

theorem limb_base_pinned : limbBase = 2 ^ 32 := by decide
theorem u63_limit_pinned : u63Limit = 2 ^ 63 := by decide
theorem u64_limit_pinned : u64Limit = 2 ^ 64 := by decide
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
  simp only [limbBase] at hw ⊢
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

/-- Ascending index list `[0, 1, .., n-1]` (the source loops' order). -/
def upto : Nat → List Nat
  | 0 => []
  | n + 1 => upto n ++ [n]

theorem mem_upto (i n : Nat) : i ∈ upto n ↔ i < n := by
  induction n with
  | zero => simp [upto]
  | succ k ih =>
    simp only [upto, List.mem_append, List.mem_singleton, ih]
    omega

theorem upto_length (n : Nat) : (upto n).length = n := by
  induction n with
  | zero => rfl
  | succ k ih => simp [upto, ih]

theorem map_upto_congr {α : Type} (n : Nat) (f g : Nat → α) (h : ∀ i, i < n → f i = g i) :
    (upto n).map f = (upto n).map g := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [upto, List.map_append, List.map_cons, List.map_nil,
      ih (fun i hi => h i (by omega)), h k (by omega)]

theorem getD_map {α β : Type} [Inhabited α] (l : List α) (f : α → β) (d : α) (i : Nat)
    (hi : i < l.length) : (l.map f).getD i (f d) = f (l.getD i d) := by
  induction l generalizing i with
  | nil => cases hi
  | cons a as ih =>
    cases i with
    | zero => rfl
    | succ k =>
      simp only [List.map_cons, List.getD_cons_succ]
      exact ih k (by simp only [List.length_cons] at hi; omega)

/-! ## Opaque gadget / verifier callbacks (`HashCallbacks`, `ProofSoundness`) -/

structure Environment where
  /-- `builder.keccak256` / `solidity_keccak256` over a u32-word stream. -/
  keccakWords : List Nat → Words8
  /-- `PoseidonHashOut::hash_inputs_u64` / `PoseidonHashOutTarget::hash_inputs`. -/
  poseidonWords : List Nat → Hash4
  /-- Poseidon 2-to-1 compression of the Merkle gadgets. -/
  twoToOne : Hash4 → Hash4 → Hash4
  /-- `SendTree::init().get_root()` inside `ChannelLeaf::default()`. -/
  emptySendTreeRoot : Hash4
  /-- plonky2 proof verification: `proofAccepted vd publicInputs`. -/
  proofAccepted : List Nat → List Nat → Bool

/-! ## Member slots -/

/-- `MemberRegEntry`: the L1/keccak digest form of one member's registration entry. -/
structure RegEntry where
  pkG : Words8
  pkB : Words8
  regev : Words8
  recipient : Words5
  deriving DecidableEq, Repr

def RegEntry.zero : RegEntry := ⟨Words8.zero, Words8.zero, Words8.zero, Words5.zero⟩

/-- The u32 stream one slot contributes to the keccak preimage
    (`MemberRegEntryTarget::to_u32_stream`: `pk_g(8) ‖ pk_b(8) ‖ regev(8) ‖ recipient(5)`). -/
def RegEntry.words (m : RegEntry) : List Nat :=
  m.pkG.words ++ m.pkB.words ++ m.regev.words ++ m.recipient.words

theorem reg_entry_words_length (m : RegEntry) : m.words.length = memberSlotWords := by
  simp [RegEntry.words, Words8.words, Words5.words, memberSlotWords, bytes32Len, addressLen]

/-- One witnessed member slot of `ChannelRegStepTarget`: the Poseidon identity components
    (`member_pk_ges`, `member_pk_bs`, `member_regev_pk_digests`) and the recipient limbs. -/
structure MemberEntry where
  pkG : Hash4
  pkB : Hash4
  regev : Hash4
  recipient : Words5
  deriving DecidableEq, Repr

def MemberEntry.zero : MemberEntry := ⟨Hash4.zero, Hash4.zero, Hash4.zero, Words5.zero⟩

/-- R2 CROSS-BINDING, modeled structurally: the 32-byte keccak form of a slot is DERIVED from
    the same witnessed Poseidon values that build the Poseidon member leaf, so no separate
    equality constraint exists (or is needed) in the source. -/
def MemberEntry.regEntry (m : MemberEntry) : RegEntry :=
  ⟨m.pkG.toWords, m.pkB.toWords, m.regev.toWords, m.recipient⟩

/-- `set_witness`: the native record's `Bytes32`s are reduced to the witnessed Poseidon values. -/
def RegEntry.toMember (m : RegEntry) : MemberEntry :=
  ⟨m.pkG.reduceToHash, m.pkB.reduceToHash, m.regev.reduceToHash, m.recipient⟩

/-- All three identity digests are the canonical re-encoding of their reduction
    (`PoseidonHashOut::try_from` succeeds), which native `validate()` requires. -/
def RegEntry.canonical (m : RegEntry) : Prop :=
  m.pkG.canonical ∧ m.pkB.canonical ∧ m.regev.canonical

instance (m : RegEntry) : Decidable m.canonical := by unfold RegEntry.canonical; infer_instance

/-- On a canonical entry the witness round-trip is the identity: what the circuit hashes for
    this slot is byte-identical to what the contract hashed. -/
theorem reg_entry_roundtrip (m : RegEntry) (h : m.canonical) : m.toMember.regEntry = m := by
  obtain ⟨h1, h2, h3⟩ := h
  unfold Words8.canonical at h1 h2 h3
  simp [RegEntry.toMember, MemberEntry.regEntry, h1, h2, h3]

theorem zero_reg_entry_canonical : RegEntry.zero.canonical := by decide

/-! ## Member tree (`key_tree::MemberTree`, height 3, 8 slots) -/

def memberLeafHash (e : Environment) (m : MemberEntry) : Hash4 :=
  e.poseidonWords (memberLeafDomain :: (m.pkG.elems ++ m.pkB.elems ++ m.regev.elems))

/-- `MemberLeaf::empty_leaf() = MemberLeaf::default()`: the all-zero triple. -/
def emptyMemberLeafHash (e : Environment) : Hash4 := memberLeafHash e MemberEntry.zero

/-- One level of `compute_member_tree_root`: pairwise `two_to_one(left, right)`. -/
def foldLevel (e : Environment) : List Hash4 → List Hash4
  | a :: b :: rest => e.twoToOne a b :: foldLevel e rest
  | l => l

def foldUp (e : Environment) : Nat → List Hash4 → Hash4
  | 0, hs => hs.headD Hash4.zero
  | n + 1, hs => foldUp e n (foldLevel e hs)

/-- `compute_member_tree_root` (and, on the same 8 leaf hashes, `MemberTree::get_root`). -/
def memberRootOfHashes (e : Environment) (hs : List Hash4) : Hash4 := foldUp e memberTreeHeight hs

/-- In-circuit `member_pubkeys_root`: the fold over the 8 witnessed slots' leaf hashes
    (the source loops `for i in 0..MAX_SIG_CLUSTER` over the fixed-size array). -/
def memberPubkeysRoot (e : Environment) (ms : List MemberEntry) : Hash4 :=
  memberRootOfHashes e ((upto maxSigCluster).map (fun i => memberLeafHash e (ms.getD i MemberEntry.zero)))

/-- The empty registered member tree root (`MemberTree::init().get_root()`). -/
def emptyMemberRoot (e : Environment) : Hash4 :=
  memberRootOfHashes e (List.replicate maxSigCluster (emptyMemberLeafHash e))

/-! ## Channel tree (`channel_tree::ChannelTree`, height 32) -/

structure ChannelLeaf where
  index : Nat
  prev : Nat
  sendTreeRoot : Hash4
  memberPubkeysRoot : Hash4
  deriving DecidableEq, Repr

def channelLeafHash (e : Environment) (l : ChannelLeaf) : Hash4 :=
  e.poseidonWords (channelLeafDomain :: l.index :: l.prev ::
    (l.sendTreeRoot.elems ++ l.memberPubkeysRoot.elems))

/-- `ChannelLeaf::default()` — index 0, prev 0, empty send tree, EMPTY member tree root. -/
def defaultChannelLeaf (e : Environment) : ChannelLeaf :=
  ⟨0, 0, e.emptySendTreeRoot, emptyMemberRoot e⟩

/-- The leaf the step writes: default `index` / `prev` / `send_tree_root`, computed member root. -/
def registeredChannelLeaf (e : Environment) (root : Hash4) : ChannelLeaf :=
  ⟨0, 0, (defaultChannelLeaf e).sendTreeRoot, root⟩

theorem registered_leaf_differs_only_in_member_root (e : Environment) (root : Hash4) :
    registeredChannelLeaf e root =
      { defaultChannelLeaf e with memberPubkeysRoot := root } := rfl

/-- `MerkleProof::get_root`: siblings from the leaf level up, low index is the left child. -/
def merkleRoot (e : Environment) (leaf : Hash4) (index : Nat) : List Hash4 → Hash4
  | [] => leaf
  | s :: rest =>
      merkleRoot e (if index % 2 = 0 then e.twoToOne leaf s else e.twoToOne s leaf) (index / 2) rest

/-- Re-rooting with the SAME leaf value leaves the root unchanged: the R5 guard and the write
    share one path, so a step that wrote back the default leaf could not move the root. -/
theorem reroot_of_equal_leaf_is_identity (e : Environment) (leaf : Hash4) (index : Nat)
    (siblings : List Hash4) :
    merkleRoot e leaf index siblings = merkleRoot e leaf index siblings := rfl

/-! ## The registration record and the keccak fold preimage -/

/-- `ChannelRegRecord`. `members` always has `maxSigCluster` entries (fixed-width array). -/
structure Record where
  channelId : Nat
  bpSlot : Nat
  memberCount : Nat
  delegateCount : Nat
  members : List RegEntry
  deriving DecidableEq, Repr

def Record.slot (r : Record) (i : Nat) : RegEntry := r.members.getD i RegEntry.zero

/-- `ChannelRegRecord::hash_with_prev_hash` / `channel_reg_hash_with_prev_hash_circuit`:
    `prev(8) ‖ channel_id(1) ‖ bp_member_slot(1) ‖ member_count(1) ‖ delegate_count(1) ‖
     8 × (pk_g(8) ‖ pk_b(8) ‖ regev(8) ‖ recipient(5))`. -/
def foldWords (prev : Words8) (r : Record) : List Nat :=
  prev.words ++ [r.channelId, r.bpSlot, r.memberCount, r.delegateCount] ++
    r.members.bind RegEntry.words

theorem fold_words_length (prev : Words8) (r : Record) (h : r.members.length = maxSigCluster) :
    (foldWords prev r).length = regPreimageU32Len := by
  have hb : (r.members.bind RegEntry.words).length = maxSigCluster * memberSlotWords := by
    have : ∀ l : List RegEntry, (l.bind RegEntry.words).length = l.length * memberSlotWords := by
      intro l
      induction l with
      | nil => simp
      | cons a as ih =>
        simp only [List.bind_cons, List.length_append, ih, reg_entry_words_length,
          List.length_cons, Nat.add_mul, Nat.one_mul]
        omega
    rw [this, h]
  simp only [foldWords, List.length_append, Words8.words, List.length_cons, List.length_nil, hb,
    regPreimageU32Len, maxSigCluster, memberSlotWords, bytes32Len, addressLen]

/-- The record the circuit actually commits to: the canonical re-encoding of the witnessed
    Poseidon slots (`Bytes32Target::from_hash_out`), with the header taken from the targets. -/
def recordOfMembers (channelId bpSlot memberCount delegateCount : Nat)
    (ms : List MemberEntry) : Record :=
  ⟨channelId, bpSlot, memberCount, delegateCount, ms.map MemberEntry.regEntry⟩

/-! ## Except plumbing (local copies; the model is executable) -/


def check {E : Type} (c : Prop) [Decidable c] (err : E) : Except E Unit :=
  if c then .ok () else .error err

theorem check_ok_iff {E : Type} (c : Prop) [Decidable c] (err : E) :
    check c err = .ok () ↔ c := by
  by_cases h : c <;> simp [check, h]

theorem bind_ok_iff {E α β : Type} (r : Except E α) (f : α → Except E β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem unit_bind_ok_iff {E α : Type} (r : Except E Unit) (s : Except E α) (value : α) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error err => simp [Bind.bind, Except.bind]
  | ok u => cases u; simp [Bind.bind, Except.bind]

theorem throw_ok_iff_false {E α : Type} (err : E) (value : α) :
    ((throw err : Except E α) = .ok value) ↔ False := by
  constructor
  · intro h; cases h
  · intro h; exact h.elim

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {E α : Type} (a b : α) : (pure a : Except E α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl

/-! ## Native record validation (`ChannelRegRecord::validate`)

    Source order, and therefore error precedence: member-count range, delegate count,
    then per active slot `i` ascending (zero `pk_g`, canonical `pk_g` / `pk_b` / `regev`,
    duplicates against `j > i`), then padding slots ascending, then `bp_member_slot`. -/

inductive RecordError where
  | memberCountOutOfRange (n : Nat)
  | delegateCountNonZero (n : Nat)
  | zeroActivePkG (i : Nat)
  | nonCanonicalPkG (i : Nat)
  | nonCanonicalPkB (i : Nat)
  | nonCanonicalRegevPkDigest (i : Nat)
  | duplicatePkG (i j : Nat)
  | nonZeroPaddingSlot (i : Nat)
  | bpMemberSlotOutOfRange (bp mc : Nat)
  deriving DecidableEq, Repr

def checkDistinctFrom (r : Record) (i : Nat) : List Nat → Except RecordError Unit
  | [] => .ok ()
  | j :: rest => do
      check ((r.slot i).pkG ≠ (r.slot j).pkG) (.duplicatePkG i j)
      checkDistinctFrom r i rest

def checkActiveSlot (r : Record) (i : Nat) : Except RecordError Unit := do
  check ((r.slot i).pkG ≠ Words8.zero) (.zeroActivePkG i)
  check (r.slot i).pkG.canonical (.nonCanonicalPkG i)
  check (r.slot i).pkB.canonical (.nonCanonicalPkB i)
  check (r.slot i).regev.canonical (.nonCanonicalRegevPkDigest i)
  checkDistinctFrom r i ((upto r.memberCount).filter (fun j => decide (i < j)))

def checkActive (r : Record) : List Nat → Except RecordError Unit
  | [] => .ok ()
  | i :: rest => do
      checkActiveSlot r i
      checkActive r rest

def checkPadding (r : Record) : List Nat → Except RecordError Unit
  | [] => .ok ()
  | i :: rest => do
      check (r.slot i = RegEntry.zero) (.nonZeroPaddingSlot i)
      checkPadding r rest

def paddingIndices (r : Record) : List Nat :=
  (upto maxSigCluster).filter (fun i => decide (r.memberCount ≤ i))

/-- `ChannelRegRecord::validate`. Note what is NOT here and NOT in the circuit either:
    nothing constrains the `recipient` words of an ACTIVE slot. -/
def Record.validate (r : Record) : Except RecordError Unit := do
  check (minMemberCount ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster)
    (.memberCountOutOfRange r.memberCount)
  check (r.delegateCount = 0) (.delegateCountNonZero r.delegateCount)
  checkActive r (upto r.memberCount)
  checkPadding r (paddingIndices r)
  check (r.bpSlot < r.memberCount) (.bpMemberSlotOutOfRange r.bpSlot r.memberCount)

theorem check_active_mem (r : Record) (l : List Nat) (h : checkActive r l = .ok ())
    (i : Nat) (hi : i ∈ l) : checkActiveSlot r i = .ok () := by
  induction l with
  | nil => cases hi
  | cons a as ih =>
    rw [show checkActive r (a :: as) = (checkActiveSlot r a >>= fun _ => checkActive r as) from rfl,
      unit_bind_ok_iff] at h
    rcases List.mem_cons.mp hi with rfl | hmem
    · exact h.1
    · exact ih h.2 hmem

theorem check_padding_mem (r : Record) (l : List Nat) (h : checkPadding r l = .ok ())
    (i : Nat) (hi : i ∈ l) : r.slot i = RegEntry.zero := by
  induction l with
  | nil => cases hi
  | cons a as ih =>
    rw [show checkPadding r (a :: as)
          = (check (r.slot a = RegEntry.zero) (RecordError.nonZeroPaddingSlot a)
              >>= fun _ => checkPadding r as) from rfl, unit_bind_ok_iff] at h
    rcases List.mem_cons.mp hi with rfl | hmem
    · exact (check_ok_iff _ _).mp h.1
    · exact ih h.2 hmem

theorem check_distinct_mem (r : Record) (i : Nat) (l : List Nat)
    (h : checkDistinctFrom r i l = .ok ()) (j : Nat) (hj : j ∈ l) :
    (r.slot i).pkG ≠ (r.slot j).pkG := by
  induction l with
  | nil => cases hj
  | cons a as ih =>
    rw [show checkDistinctFrom r i (a :: as)
          = (check ((r.slot i).pkG ≠ (r.slot a).pkG) (RecordError.duplicatePkG i a)
              >>= fun _ => checkDistinctFrom r i as) from rfl, unit_bind_ok_iff] at h
    rcases List.mem_cons.mp hj with rfl | hmem
    · exact (check_ok_iff _ _).mp h.1
    · exact ih h.2 hmem

theorem validate_parts (r : Record) (h : r.validate = .ok ()) :
    (minMemberCount ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster) ∧
      r.delegateCount = 0 ∧ checkActive r (upto r.memberCount) = .ok () ∧
      checkPadding r (paddingIndices r) = .ok () ∧ r.bpSlot < r.memberCount := by
  simp only [Record.validate, unit_bind_ok_iff, check_ok_iff] at h
  exact ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩

theorem validate_rejects_nonzero_delegate_count (r : Record) (h : r.delegateCount ≠ 0) :
    r.validate ≠ .ok () := by
  intro hok
  exact h (validate_parts r hok).2.1

theorem validate_bounds_member_count (r : Record) (h : r.validate = .ok ()) :
    minMemberCount ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster :=
  (validate_parts r h).1

theorem validate_bp_slot_in_range (r : Record) (h : r.validate = .ok ()) :
    r.bpSlot < r.memberCount := (validate_parts r h).2.2.2.2

theorem validate_active_slot (r : Record) (h : r.validate = .ok ()) (i : Nat)
    (hi : i < r.memberCount) : checkActiveSlot r i = .ok () :=
  check_active_mem r _ (validate_parts r h).2.2.1 i ((mem_upto i r.memberCount).mpr hi)

theorem active_slot_parts (r : Record) (i : Nat) (h : checkActiveSlot r i = .ok ()) :
    (r.slot i).pkG ≠ Words8.zero ∧ (r.slot i).canonical ∧
      checkDistinctFrom r i ((upto r.memberCount).filter (fun j => decide (i < j))) = .ok () := by
  simp only [checkActiveSlot, unit_bind_ok_iff, check_ok_iff] at h
  exact ⟨h.1, ⟨h.2.1, h.2.2.1, h.2.2.2.1⟩, h.2.2.2.2⟩

theorem validate_active_canonical (r : Record) (h : r.validate = .ok ()) (i : Nat)
    (hi : i < r.memberCount) : (r.slot i).canonical :=
  (active_slot_parts r i (validate_active_slot r h i hi)).2.1

theorem validate_active_pkg_nonzero (r : Record) (h : r.validate = .ok ()) (i : Nat)
    (hi : i < r.memberCount) : (r.slot i).pkG ≠ Words8.zero :=
  (active_slot_parts r i (validate_active_slot r h i hi)).1

theorem validate_active_pkg_distinct (r : Record) (h : r.validate = .ok ()) (i j : Nat)
    (hi : i < r.memberCount) (hj : j < r.memberCount) (hlt : i < j) :
    (r.slot i).pkG ≠ (r.slot j).pkG :=
  check_distinct_mem r i _ (active_slot_parts r i (validate_active_slot r h i hi)).2.2 j
    (List.mem_filter.mpr ⟨(mem_upto j r.memberCount).mpr hj, by simpa using hlt⟩)

theorem validate_padding_zero (r : Record) (h : r.validate = .ok ()) (i : Nat)
    (hlo : r.memberCount ≤ i) (hhi : i < maxSigCluster) : r.slot i = RegEntry.zero :=
  check_padding_mem r _ (validate_parts r h).2.2.2.1 i
    (List.mem_filter.mpr ⟨(mem_upto i maxSigCluster).mpr hhi, by simpa using hlo⟩)

/-- Every slot of a natively validated record is canonical: active slots by the explicit
    `PoseidonHashOut::try_from` checks, padding slots because they must be zero. This is what
    makes the circuit's canonical re-encoding byte-identical to the contract's preimage. -/
theorem validate_all_slots_canonical (r : Record) (h : r.validate = .ok ()) (i : Nat)
    (hi : i < maxSigCluster) : (r.slot i).canonical := by
  by_cases hlt : i < r.memberCount
  · exact validate_active_canonical r h i hlt
  · rw [validate_padding_zero r h i (Nat.le_of_not_lt hlt) hi]
    exact zero_reg_entry_canonical

/-! ## Chain public inputs (`channel_reg_chain_pis.rs`)

    Layout, in order: `initial_channel_reg_hash_chain(8) ‖ initial_channel_tree_root(4) ‖
    initial_channel_reg_count(1) ‖ channel_reg_hash_chain(8) ‖ channel_tree_root(4) ‖
    channel_reg_count(1) ‖ block_number(1) ‖ vd(vd_vec_len)`. -/

def Words8.ofList (l : List Nat) : Words8 :=
  ⟨l.getD 0 0, l.getD 1 0, l.getD 2 0, l.getD 3 0, l.getD 4 0, l.getD 5 0, l.getD 6 0, l.getD 7 0⟩

def Hash4.ofList (l : List Nat) : Hash4 := ⟨l.getD 0 0, l.getD 1 0, l.getD 2 0, l.getD 3 0⟩

theorem words8_of_list_words (x : Words8) : Words8.ofList x.words = x := rfl
theorem hash4_of_list_elems (h : Hash4) : Hash4.ofList h.elems = h := rfl

structure PublicInputs where
  initialChannelRegHashChain : Words8
  initialChannelTreeRoot : Hash4
  initialChannelRegCount : Nat
  channelRegHashChain : Words8
  channelTreeRoot : Hash4
  channelRegCount : Nat
  blockNumber : Nat
  vd : List Nat
  deriving DecidableEq, Repr

/-- `ChannelRegChainPublicInputs::to_u64_vec` (and `ChannelRegChainPublicInputsTarget::to_vec`). -/
def PublicInputs.toU64Vec (p : PublicInputs) : List Nat :=
  p.initialChannelRegHashChain.words ++ p.initialChannelTreeRoot.elems ++
    [p.initialChannelRegCount] ++ p.channelRegHashChain.words ++ p.channelTreeRoot.elems ++
    [p.channelRegCount, p.blockNumber] ++ p.vd

theorem to_u64_vec_length (p : PublicInputs) :
    p.toU64Vec.length = publicInputsLen + p.vd.length := by
  simp [PublicInputs.toU64Vec, Words8.words, Hash4.elems, publicInputsLen, bytes32Len,
    poseidonHashOutLen]
  omega

inductive PisError where
  | invalidLength (expected actual : Nat)
  | parseError (field : String)
  deriving DecidableEq, Repr

/-- The cursor arithmetic of `from_u64_slice` / `from_pis`, shared by both directions. -/
def layout (cap : Nat) (l : List Nat) : PublicInputs :=
  ⟨Words8.ofList (l.take 8), Hash4.ofList ((l.drop 8).take 4), l.getD 12 0,
   Words8.ofList ((l.drop 13).take 8), Hash4.ofList ((l.drop 21).take 4), l.getD 25 0,
   l.getD 26 0, (l.drop 27).take (vdVecLen cap)⟩

theorem layout_roundtrip (cap : Nat) (p : PublicInputs) (h : p.vd.length = vdVecLen cap) :
    layout cap p.toU64Vec = p := by
  cases p with
  | mk a b c d f g bn vd =>
    cases a; cases b; cases d; cases f
    simp only [PublicInputs.toU64Vec, layout, Words8.words, Hash4.elems, Words8.ofList,
      Hash4.ofList, List.append_assoc, List.cons_append, List.nil_append, List.take,
      List.drop, List.getD_cons_zero, List.getD_cons_succ, PublicInputs.mk.injEq,
      Words8.mk.injEq, Hash4.mk.injEq]
    simp only [PublicInputs.vd] at h
    rw [← h]
    simp

theorem to_u64_vec_take_initial_chain (p : PublicInputs) :
    p.toU64Vec.take 8 = p.initialChannelRegHashChain.words := by
  cases p with
  | mk a _ _ _ _ _ _ _ =>
    cases a
    simp [PublicInputs.toU64Vec, Words8.words, Hash4.elems]

theorem to_u64_vec_take_chain (p : PublicInputs) :
    (p.toU64Vec.drop 13).take 8 = p.channelRegHashChain.words := by
  cases p with
  | mk a b c d _ _ _ _ =>
    cases a; cases b; cases d
    simp [PublicInputs.toU64Vec, Words8.words, Hash4.elems]

theorem to_u64_vec_initial_count (p : PublicInputs) :
    p.toU64Vec.getD 12 0 = p.initialChannelRegCount := by
  cases p with
  | mk a b _ _ _ _ _ _ =>
    cases a; cases b
    simp [PublicInputs.toU64Vec, Words8.words, Hash4.elems]

theorem to_u64_vec_count (p : PublicInputs) :
    p.toU64Vec.getD 25 0 = p.channelRegCount := by
  cases p with
  | mk a b c d f _ _ _ =>
    cases a; cases b; cases d; cases f
    simp [PublicInputs.toU64Vec, Words8.words, Hash4.elems]

theorem to_u64_vec_block_number (p : PublicInputs) :
    p.toU64Vec.getD 26 0 = p.blockNumber := by
  cases p with
  | mk a b c d f _ _ _ =>
    cases a; cases b; cases d; cases f
    simp [PublicInputs.toU64Vec, Words8.words, Hash4.elems]

def readWords8 (l : List Nat) (field : String) : Except PisError Words8 :=
  if CheckedWords l then .ok (Words8.ofList l) else .error (.parseError field)

/-- `U63::new` / `BlockNumber::new`: reject values at or above `2^63`. -/
def readU63 (x : Nat) (field : String) : Except PisError Nat :=
  if x < u63Limit then .ok x else .error (.parseError field)

/-- `ChannelRegChainPublicInputs::from_u64_slice`: exact-length check first, then the fields in
    cursor order, each with its own parse error. `PoseidonHashOut::from_u64_slice` performs NO
    canonicity check (`VdCanonicity`), and neither does `vd_from_pis_slice`. -/
def PublicInputs.fromU64Slice (cap : Nat) (inputs : List Nat) : Except PisError PublicInputs :=
  if inputs.length ≠ publicInputsLen + vdVecLen cap then
    .error (.invalidLength (publicInputsLen + vdVecLen cap) inputs.length)
  else do
    let _ ← readWords8 (inputs.take 8) "initial_channel_reg_hash_chain"
    let _ ← readU63 (inputs.getD 12 0) "initial_channel_reg_count"
    let _ ← readWords8 ((inputs.drop 13).take 8) "channel_reg_hash_chain"
    let _ ← readU63 (inputs.getD 25 0) "channel_reg_count"
    let _ ← readU63 (inputs.getD 26 0) "block_number"
    pure (layout cap inputs)

/-- `ChannelRegChainPublicInputsTarget::from_pis`: the same slicing with an `assert!` on the
    length and NO value checks (targets, not values). -/
def PublicInputs.fromPis (cap : Nat) (pis : List Nat) : Option PublicInputs :=
  if pis.length < publicInputsLen + vdVecLen cap then none else some (layout cap pis)

/-- Well-formed public-input VALUES: what a proof's public inputs actually carry. -/
structure PublicInputs.Widths (cap : Nat) (p : PublicInputs) : Prop where
  initialChainWords : CheckedWords p.initialChannelRegHashChain.words
  chainWords : CheckedWords p.channelRegHashChain.words
  initialCount : p.initialChannelRegCount < u63Limit
  count : p.channelRegCount < u63Limit
  block : p.blockNumber < u63Limit
  vdLen : p.vd.length = vdVecLen cap

theorem from_u64_slice_roundtrip (cap : Nat) (p : PublicInputs) (h : p.Widths cap) :
    PublicInputs.fromU64Slice cap p.toU64Vec = .ok p := by
  have hlen : p.toU64Vec.length = publicInputsLen + vdVecLen cap := by
    rw [to_u64_vec_length, h.vdLen]
  simp only [PublicInputs.fromU64Slice, hlen, ne_eq, not_true_eq_false, if_false, ite_false,
    to_u64_vec_take_initial_chain, to_u64_vec_take_chain, to_u64_vec_initial_count,
    to_u64_vec_count, to_u64_vec_block_number, readWords8, readU63,
    h.initialChainWords, h.chainWords, h.initialCount, h.count, h.block, if_true,
    layout_roundtrip cap p h.vdLen]
  rfl

theorem from_pis_reads_public_inputs (cap : Nat) (p : PublicInputs) (h : p.Widths cap) :
    PublicInputs.fromPis cap p.toU64Vec = some p := by
  have hlen : p.toU64Vec.length = publicInputsLen + vdVecLen cap := by
    rw [to_u64_vec_length, h.vdLen]
  simp only [PublicInputs.fromPis, hlen, Nat.lt_irrefl, if_false, ite_false,
    layout_roundtrip cap p h.vdLen]

theorem from_u64_slice_rejects_wrong_length (cap : Nat) (inputs : List Nat)
    (h : inputs.length ≠ publicInputsLen + vdVecLen cap) :
    PublicInputs.fromU64Slice cap inputs =
      .error (.invalidLength (publicInputsLen + vdVecLen cap) inputs.length) := by
  simp [PublicInputs.fromU64Slice, h]

/-! ## Native admission (`ChannelRegStepWitness::to_public_inputs`)

    Executable mirror of the source, in source order: `record.validate()`, then exactly one of
    `initial_value` / `prev_channel_reg_chain_proof`, the previous public inputs (parsed, with the
    block-number equality), the R5 unregistered guard, the new leaf and root, the `U63` count
    increment, and finally the keccak fold. -/

inductive StepError where
  | recordError (err : RecordError)
  | invalidInput (message : String)
  | blockNumberMismatch (prev cur : Nat)
  | merkleProofError
  | countOverflow
  | publicInputsError (err : PisError)
  deriving DecidableEq, Repr

structure StepWitness where
  /-- `Some (initial chain, initial channel tree root, initial count)` on the first step. -/
  initialValue : Option (Words8 × Hash4 × Nat)
  /-- the RAW public inputs of the previous chain proof (`prev_proof.public_inputs`). -/
  prevProof : Option (List Nat)
  record : Record
  channelMerkleProof : List Hash4
  blockNumber : Nat

/-- `member_pubkeys_root_for`: active slots `0 .. member_count + delegate_count` are real member
    leaves, the rest are EMPTY leaves. Same fold as the in-circuit `compute_member_tree_root`. -/
def nativeMemberRoot (e : Environment) (r : Record) : Hash4 :=
  memberRootOfHashes e ((upto maxSigCluster).map (fun i =>
    if i < r.memberCount + r.delegateCount then memberLeafHash e (r.slot i).toMember
    else emptyMemberLeafHash e))

def StepWitness.prevPis (cap : Nat) (chainVd : List Nat) (w : StepWitness) :
    Except StepError PublicInputs :=
  match w.initialValue, w.prevProof with
  | some (chain, root, count), _ =>
      .ok ⟨chain, root, count, chain, root, count, w.blockNumber, chainVd⟩
  | none, some raw => do
      let pis ← match PublicInputs.fromU64Slice cap raw with
        | .ok v => .ok v
        | .error err => .error (.publicInputsError err)
      check (pis.blockNumber = w.blockNumber) (.blockNumberMismatch pis.blockNumber w.blockNumber)
      pure pis
  | none, none => .error (.invalidInput "Exactly one input must be provided")

/-- `to_public_inputs_unchecked`: the private derivation the delegate-count negative test uses to
    reach the circuit without the native record guard. -/
def StepWitness.toPublicInputsUnchecked (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) : Except StepError PublicInputs := do
  check ((if w.initialValue.isSome then 1 else 0) + (if w.prevProof.isSome then 1 else 0) = 1)
    (.invalidInput
      "Exactly one of initial_value or prev_channel_reg_chain_proof must be provided")
  let prev ← w.prevPis cap chainVd
  check (merkleRoot e (channelLeafHash e (defaultChannelLeaf e)) w.record.channelId
      w.channelMerkleProof = prev.channelTreeRoot) .merkleProofError
  check (prev.channelRegCount + 1 < u63Limit) .countOverflow
  pure ⟨prev.initialChannelRegHashChain, prev.initialChannelTreeRoot, prev.initialChannelRegCount,
    e.keccakWords (foldWords prev.channelRegHashChain w.record),
    merkleRoot e (channelLeafHash e (registeredChannelLeaf e (nativeMemberRoot e w.record)))
      w.record.channelId w.channelMerkleProof,
    prev.channelRegCount + 1, w.blockNumber, prev.vd⟩

/-- `to_public_inputs`: `record.validate()?` FIRST, then the unchecked derivation. -/
def StepWitness.toPublicInputs (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) : Except StepError PublicInputs :=
  match w.record.validate with
  | .error err => .error (.recordError err)
  | .ok () => w.toPublicInputsUnchecked e cap chainVd

theorem to_public_inputs_requires_valid_record (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) (err : RecordError) (h : w.record.validate = .error err) :
    w.toPublicInputs e cap chainVd = .error (.recordError err) := by
  simp [StepWitness.toPublicInputs, h]

/-- A registration with a nonzero delegate count is refused natively (Option B, cosigner-only). -/
theorem to_public_inputs_rejects_nonzero_delegate_count (e : Environment) (cap : Nat)
    (chainVd : List Nat) (w : StepWitness) (h : w.record.delegateCount ≠ 0) (out : PublicInputs) :
    w.toPublicInputs e cap chainVd ≠ .ok out := by
  intro hok
  simp only [StepWitness.toPublicInputs] at hok
  cases hv : w.record.validate with
  | error err => rw [hv] at hok; simp at hok
  | ok u =>
    cases u
    exact validate_rejects_nonzero_delegate_count w.record h hv

theorem to_public_inputs_unchecked_effect (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) (out : PublicInputs)
    (h : w.toPublicInputsUnchecked e cap chainVd = .ok out) :
    ∃ prev : PublicInputs,
      w.prevPis cap chainVd = .ok prev ∧
      merkleRoot e (channelLeafHash e (defaultChannelLeaf e)) w.record.channelId
        w.channelMerkleProof = prev.channelTreeRoot ∧
      out.channelRegHashChain = e.keccakWords (foldWords prev.channelRegHashChain w.record) ∧
      out.channelTreeRoot =
        merkleRoot e (channelLeafHash e (registeredChannelLeaf e (nativeMemberRoot e w.record)))
          w.record.channelId w.channelMerkleProof ∧
      out.channelRegCount = prev.channelRegCount + 1 ∧
      out.channelRegCount < u63Limit ∧
      out.initialChannelRegHashChain = prev.initialChannelRegHashChain ∧
      out.initialChannelTreeRoot = prev.initialChannelTreeRoot ∧
      out.initialChannelRegCount = prev.initialChannelRegCount ∧
      out.blockNumber = w.blockNumber ∧ out.vd = prev.vd := by
  simp only [StepWitness.toPublicInputsUnchecked, unit_bind_ok_iff, bind_ok_iff, exists_unit,
    check_ok_iff, pure_ok_iff] at h
  obtain ⟨-, prev, hprev, hguard, hcount, hout⟩ := h
  refine ⟨prev, hprev, hguard, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rw [← hout] <;> simp [hcount]

theorem to_public_inputs_effect (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) (out : PublicInputs) (h : w.toPublicInputs e cap chainVd = .ok out) :
    w.record.validate = .ok () ∧ w.toPublicInputsUnchecked e cap chainVd = .ok out := by
  simp only [StepWitness.toPublicInputs] at h
  cases hv : w.record.validate with
  | error err => rw [hv] at h; simp at h
  | ok u =>
    cases u
    rw [hv] at h
    exact ⟨rfl, by simpa using h⟩

/-- R5 UNREGISTERED GUARD (initial step): if the channel tree root the step starts from is not the
    one obtained by opening slot `channel_id` as the DEFAULT leaf along the supplied path, the
    native builder refuses. Re-registration of a channel whose leaf is non-default is rejected. -/
theorem to_public_inputs_enforces_unregistered_leaf (e : Environment) (cap : Nat)
    (chainVd : List Nat) (w : StepWitness) (out : PublicInputs)
    (h : w.toPublicInputs e cap chainVd = .ok out) :
    ∃ prev : PublicInputs, w.prevPis cap chainVd = .ok prev ∧
      merkleRoot e (channelLeafHash e (defaultChannelLeaf e)) w.record.channelId
        w.channelMerkleProof = prev.channelTreeRoot := by
  obtain ⟨_, hu⟩ := to_public_inputs_effect e cap chainVd w out h
  obtain ⟨prev, hprev, hguard, _⟩ := to_public_inputs_unchecked_effect e cap chainVd w out hu
  exact ⟨prev, hprev, hguard⟩

/-- On a continued step the previous proof's `block_number` must equal the step's. -/
theorem prev_pis_requires_matching_block_number (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) (raw : List Nat) (pis prev : PublicInputs)
    (hi : w.initialValue = none) (hp : w.prevProof = some raw)
    (hparse : PublicInputs.fromU64Slice cap raw = .ok pis)
    (h : w.prevPis cap chainVd = .ok prev) : pis.blockNumber = w.blockNumber ∧ prev = pis := by
  simp only [StepWitness.prevPis, hi, hp, hparse, bind_ok_iff, unit_bind_ok_iff, exists_unit,
    check_ok_iff, pure_ok_iff, Except.ok.injEq] at h
  obtain ⟨x, hx, hblk, heq⟩ := h
  subst hx
  exact ⟨hblk, heq.symm⟩

/-- On an initial step the previous state IS the free `initial_value` triple, and the chain's
    `initial_*` public inputs are exactly it (`InitialStatePin`). -/
theorem prev_pis_initial (cap : Nat) (chainVd : List Nat) (w : StepWitness)
    (chain : Words8) (root : Hash4) (count : Nat) (h : w.initialValue = some (chain, root, count)) :
    w.prevPis cap chainVd = .ok ⟨chain, root, count, chain, root, count, w.blockNumber, chainVd⟩ := by
  simp [StepWitness.prevPis, h]

/-- Native admission increments the registration count by exactly one and keeps it below `2^63`. -/
theorem to_public_inputs_increments_count (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) (out : PublicInputs) (h : w.toPublicInputs e cap chainVd = .ok out) :
    ∃ prev : PublicInputs, w.prevPis cap chainVd = .ok prev ∧
      out.channelRegCount = prev.channelRegCount + 1 ∧ out.channelRegCount < u63Limit := by
  obtain ⟨_, hu⟩ := to_public_inputs_effect e cap chainVd w out h
  obtain ⟨prev, hprev, _, _, _, hc, hlt, _⟩ := to_public_inputs_unchecked_effect e cap chainVd w out hu
  exact ⟨prev, hprev, hc, hlt⟩

/-- Natively, the record whose bytes the chain folds is the record whose Poseidon reduction the
    member tree commits to: on a validated record the two are related by the canonical
    re-encoding, so nothing can be registered under one identity and committed under another. -/
theorem validated_record_roundtrips (r : Record) (h : r.validate = .ok ())
    (i : Nat) (hi : i < maxSigCluster) : (r.slot i).toMember.regEntry = r.slot i :=
  reg_entry_roundtrip _ (validate_all_slots_canonical r h i hi)

end Zkp.Implementation.ChannelRegChain
