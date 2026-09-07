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
  (`initial_step_initial_chain_unconstrained`). Whether they are the contract's actual
  pending chain / channel tree / count is a consumer obligation outside the modeled files.
- `MerklePathBinding`: `ChannelMerkleProof` siblings are prover-supplied; that the path
  is the authentic one, and that re-rooting changes only slot `channel_id`, rests on
  Poseidon collision resistance, which is NOT assumed. Only `reroot_of_equal_leaf_is_identity`
  and the guard/write equations are proved.
- `PaddingRecipientNotPinned`: the circuit forces `pk_g = pk_b = regev = 0` on inactive
  slots but NOT `recipient` (`ChannelRegStepTarget::new` has no `conditional_assert_eq`
  for `member_recipients`), while native `validate()` rejects any non-default padding
  slot. `gates_leave_recipients_free` exhibits the gap (recipients move the chain value
  and nothing else); the Solidity-fold comparison therefore carries the padding
  hypothesis explicitly (`record_slots_are_padded`, `MatchesRegistration`).
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

instance : DecidablePred Hash4.canonicalField := fun h => List.decidableBAll _ h.elems

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

theorem getD_map {α β : Type} (l : List α) (f : α → β) (d : α) (i : Nat)
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

/-- Re-rooting with the same leaf value leaves the root unchanged: the R5 guard and the write
    share ONE path and ONE index, so the step can only move slot `channel_id` — that no OTHER slot
    changes is `MerklePathBinding` (Poseidon collision resistance), which is not assumed. -/
theorem reroot_of_equal_leaf_is_identity (e : Environment) (leaf leaf' : Hash4) (index : Nat)
    (siblings : List Hash4) (h : leaf = leaf') :
    merkleRoot e leaf index siblings = merkleRoot e leaf' index siblings := by rw [h]

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

def parsePrev (cap : Nat) (raw : List Nat) : Except StepError PublicInputs :=
  match PublicInputs.fromU64Slice cap raw with
  | .ok v => .ok v
  | .error err => .error (.publicInputsError err)

def StepWitness.prevPis (cap : Nat) (chainVd : List Nat) (w : StepWitness) :
    Except StepError PublicInputs :=
  match w.initialValue, w.prevProof with
  | some (chain, root, count), _ =>
      .ok ⟨chain, root, count, chain, root, count, w.blockNumber, chainVd⟩
  | none, some raw => do
      let pis ← parsePrev cap raw
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
    (hparse : parsePrev cap raw = .ok pis)
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

/-! ## Arbitrary satisfying witnesses: the gate equations of `ChannelRegStepTarget::new` -/

/-- `lt_const_threshold i c = Σ_{t = i+1..MAX_SIG_CLUSTER} [c = t]` (the source's unrolled sum of
    `is_equal` bits, wrapped as a `BoolTarget` with an explicit `assert_bool`). -/
def ltConstThreshold (i c : Nat) : Nat :=
  ((((upto (maxSigCluster + 1)).filter (fun t => decide (i < t))).map
    (fun t => if c = t then 1 else 0)).foldl (· + ·) 0)

/-- The thermometer mask is exactly `i < active_count`, and is 0/1, for every `active_count` the
    range checks allow (`[2, MAX_SIG_CLUSTER]`). Kernel-checked over the whole finite domain. -/
theorem lt_const_threshold_correct :
    ∀ i ∈ upto maxSigCluster, ∀ c ∈ upto (maxSigCluster + 1), minMemberCount ≤ c →
      ltConstThreshold i c = (if i < c then 1 else 0) := by decide

theorem lt_const_threshold_is_boolean :
    ∀ i ∈ upto maxSigCluster, ∀ c ∈ upto (maxSigCluster + 1),
      ltConstThreshold i c = 0 ∨ ltConstThreshold i c = 1 := by decide

/-- The witnessed targets of one step. `members` are the 8 slots witnessed ONCE as Poseidon
    values (`member_pk_ges` / `member_pk_bs` / `member_regev_pk_digests`) plus the recipient limbs. -/
structure StepInputs where
  isInitial : Bool
  initialChain : Words8
  initialRoot : Hash4
  initialCount : Nat
  prevPis : PublicInputs
  channelId : Nat
  bpSlot : Nat
  memberCount : Nat
  delegateCount : Nat
  members : List MemberEntry
  siblings : List Hash4
  blockNumber : Nat
  chainVd : List Nat
  out : PublicInputs

def StepInputs.slot (x : StepInputs) (i : Nat) : MemberEntry := x.members.getD i MemberEntry.zero
def StepInputs.activeCount (x : StepInputs) : Nat := x.memberCount + x.delegateCount

/-- `Bytes32Target::select(is_initial, initial, prev.channel_reg_hash_chain)` and friends. -/
def StepInputs.prevChain (x : StepInputs) : Words8 :=
  if x.isInitial then x.initialChain else x.prevPis.channelRegHashChain
def StepInputs.prevRoot (x : StepInputs) : Hash4 :=
  if x.isInitial then x.initialRoot else x.prevPis.channelTreeRoot
def StepInputs.prevCount (x : StepInputs) : Nat :=
  if x.isInitial then x.initialCount else x.prevPis.channelRegCount
def StepInputs.selectedInitialChain (x : StepInputs) : Words8 :=
  if x.isInitial then x.initialChain else x.prevPis.initialChannelRegHashChain
def StepInputs.selectedInitialRoot (x : StepInputs) : Hash4 :=
  if x.isInitial then x.initialRoot else x.prevPis.initialChannelTreeRoot
def StepInputs.selectedInitialCount (x : StepInputs) : Nat :=
  if x.isInitial then x.initialCount else x.prevPis.initialChannelRegCount

/-- The registration record the keccak preimage commits to: the header targets plus the CANONICAL
    32-byte re-encoding of the witnessed Poseidon identities (R2: same targets, both consumers). -/
def StepInputs.record (x : StepInputs) : Record :=
  recordOfMembers x.channelId x.bpSlot x.memberCount x.delegateCount x.members

/-- The local gate equations of `ChannelRegStepTarget::new`. Everything here is a constraint the
    source actually emits; nothing about proof soundness or hashing is assumed. -/
structure CircuitGates (e : Environment) (cap : Nat) (x : StepInputs) : Prop where
  /-- fixed-size arrays / gadget heights, fixed at build time -/
  memberSlots : x.members.length = maxSigCluster
  siblingsHeight : x.siblings.length = channelTreeHeight
  vdLen : x.chainVd.length = vdVecLen cap
  /-- `from_pis` of the previous chain proof reads `CHANNEL_REG_CHAIN_PUBLIC_INPUTS_LEN + vd` limbs -/
  prevWidths : x.prevPis.Widths cap
  /-- `ChannelIdTarget::new(builder, true)`: 32-bit range check -/
  channelIdRange : x.channelId < limbBase
  /-- `range_check(bp_member_slot, 32)`, `range_check(member_count, 32)`, `range_check(delegate_count, 32)` -/
  bpSlotRange : x.bpSlot < limbBase
  memberCountRange : x.memberCount < limbBase
  delegateCountRange : x.delegateCount < limbBase
  /-- `Bytes32Target::new(builder, true)` / `U63Target::new(builder, true)` on the initial values -/
  initialChainWords : CheckedWords x.initialChain.words
  initialCountRange : x.initialCount < u63Limit
  blockNumberRange : x.blockNumber < u63Limit
  /-- `AddressTarget::new(builder, true)`: the recipient limbs are 32-bit, and NOTHING else -/
  recipientWords : ∀ i, i < maxSigCluster → CheckedWords (x.slot i).recipient.words
  /-- Goldilocks range of the witnessed identity elements (`FieldAndGadgetLowering`) -/
  identityFields : ∀ i, i < maxSigCluster →
    (x.slot i).pkG.canonicalField ∧ (x.slot i).pkB.canonicalField ∧ (x.slot i).regev.canonicalField
  /-- `builder.assert_zero(delegate_count)`: cosigner-only L1 registration (Option B) -/
  delegateZero : x.delegateCount = 0
  /-- `range_check(member_count - 2, 4)` -/
  memberCountLower : minMemberCount ≤ x.memberCount
  /-- `range_check(MAX_SIG_CLUSTER - member_count, 4)` -/
  memberCountUpper : x.memberCount ≤ maxSigCluster
  /-- `range_check(MAX_SIG_CLUSTER - active_count, 4)` (retained redundant bound) -/
  activeUpper : x.activeCount ≤ maxSigCluster
  /-- `range_check(member_count - 1 - bp_member_slot, 4)` -/
  bpSlotLtMemberCount : x.bpSlot < x.memberCount
  /-- `conditional_assert_eq(.., zero_hash, not_active)` on the three identity components -/
  paddingEmpty : ∀ i, x.activeCount ≤ i → i < maxSigCluster →
    (x.slot i).pkG = Hash4.zero ∧ (x.slot i).pkB = Hash4.zero ∧ (x.slot i).regev = Hash4.zero
  /-- `conditional_assert_eq(not_initial, prev_pis.block_number, block_number)` -/
  blockNumberMatch : x.isInitial = false → x.prevPis.blockNumber = x.blockNumber
  /-- `conditionally_connect_vd(not_initial, prev_pis.vd, channel_reg_chain_vd)` -/
  vdConnected : x.isInitial = false → x.chainVd = x.prevPis.vd
  /-- `conditionally_verify_proof(not_initial, prev_proof, prev_pis.vd, cd)`: the previous proof is
      verified under the verifier data DECLARED IN ITS OWN public inputs -/
  prevProofVerified : x.isInitial = false → e.proofAccepted x.prevPis.vd x.prevPis.toU64Vec = true
  /-- R5: `channel_merkle_proof.verify(default_leaf, channel_id, prev_tree_root)` -/
  unregisteredGuard :
    merkleRoot e (channelLeafHash e (defaultChannelLeaf e)) x.channelId x.siblings = x.prevRoot
  outInitialChain : x.out.initialChannelRegHashChain = x.selectedInitialChain
  outInitialRoot : x.out.initialChannelTreeRoot = x.selectedInitialRoot
  outInitialCount : x.out.initialChannelRegCount = x.selectedInitialCount
  /-- `channel_reg_hash_with_prev_hash_circuit(prev_hash, channel_id, bp, mc, dc, entries)` -/
  outChain : x.out.channelRegHashChain = e.keccakWords (foldWords x.prevChain x.record)
  /-- `channel_merkle_proof.get_root(new_leaf, channel_id)` with the in-circuit member root -/
  outRoot : x.out.channelTreeRoot =
    merkleRoot e (channelLeafHash e (registeredChannelLeaf e (memberPubkeysRoot e x.members)))
      x.channelId x.siblings
  /-- `add_const(prev_count, 1)` + `range_check(.., 63)` -/
  outCount : x.out.channelRegCount = x.prevCount + 1
  outCountRange : x.out.channelRegCount < u63Limit
  outBlock : x.out.blockNumber = x.blockNumber
  outVd : x.out.vd = x.chainVd

/-- Cosigner-only registration is a CIRCUIT fact, not a convention: the active region is exactly
    `member_count` wide, so a consumer reading `member_count` reads the width of the region the
    written `member_pubkeys_root` commits to. -/
theorem gates_force_active_equals_member_count (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) : x.activeCount = x.memberCount := by
  simp [StepInputs.activeCount, g.delegateZero]

theorem gates_bound_member_count (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) : 2 ≤ x.memberCount ∧ x.memberCount ≤ maxSigCluster :=
  ⟨g.memberCountLower, g.memberCountUpper⟩

theorem gates_bp_slot_indexes_an_active_member (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) : x.bpSlot < x.memberCount := g.bpSlotLtMemberCount

/-- Slots at or above `member_count` hash to the EMPTY member leaf, so the computed root is the
    root of a tree with exactly `member_count` occupied slots. -/
theorem gates_padding_slots_hash_to_empty_leaf (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) (i : Nat) (hlo : x.memberCount ≤ i) (hhi : i < maxSigCluster) :
    memberLeafHash e (x.slot i) = emptyMemberLeafHash e := by
  have hact : x.activeCount ≤ i := by
    rw [gates_force_active_equals_member_count e cap x g]; exact hlo
  obtain ⟨h1, h2, h3⟩ := g.paddingEmpty i hact hhi
  simp [memberLeafHash, emptyMemberLeafHash, MemberEntry.zero, h1, h2, h3]

theorem member_leaf_hash_congr (e : Environment) (m m' : MemberEntry)
    (h1 : m.pkG = m'.pkG) (h2 : m.pkB = m'.pkB) (h3 : m.regev = m'.regev) :
    memberLeafHash e m = memberLeafHash e m' := by
  simp [memberLeafHash, h1, h2, h3]

/-- The written `member_pubkeys_root` is the root over exactly the `member_count` active slots,
    with every other slot the empty leaf. -/
theorem gates_member_root_commits_exactly_member_count (e : Environment) (cap : Nat)
    (x : StepInputs) (g : CircuitGates e cap x) :
    memberPubkeysRoot e x.members =
      memberRootOfHashes e ((upto maxSigCluster).map (fun i =>
        if i < x.memberCount then memberLeafHash e (x.slot i) else emptyMemberLeafHash e)) := by
  simp only [memberPubkeysRoot]
  congr 1
  refine map_upto_congr maxSigCluster _ _ ?_
  intro i hi
  by_cases hlt : i < x.memberCount
  · simp [hlt, StepInputs.slot]
  · simp only [hlt, if_false]
    exact gates_padding_slots_hash_to_empty_leaf e cap x g i (Nat.le_of_not_lt hlt) hi

/-- `x` with a different declared verifier data (initial step). -/
def StepInputs.withVd (x : StepInputs) (vd : List Nat) : StepInputs :=
  { x with chainVd := vd, out := { x.out with vd := vd } }

/-- `x` with a different free initial chain value (initial step); the fold output moves with it. -/
def StepInputs.withInitialChain (e : Environment) (x : StepInputs) (chain : Words8) : StepInputs :=
  { x with
      initialChain := chain,
      out := { x.out with
                 initialChannelRegHashChain := chain,
                 channelRegHashChain := e.keccakWords (foldWords chain x.record) } }

/-- `x` with different member slots; the fold output moves with them. -/
def StepInputs.withMembers (e : Environment) (x : StepInputs) (ms : List MemberEntry) : StepInputs :=
  { x with
      members := ms,
      out := { x.out with
                 channelRegHashChain := e.keccakWords (foldWords x.prevChain
                   (recordOfMembers x.channelId x.bpSlot x.memberCount x.delegateCount ms)) } }

/-- CONSUMER-VD BOUNDARY. On an initial step nothing constrains the verifier data the proof
    declares: any correctly sized `vd` extends to a satisfying witness. Only
    `check_cyclic_proof_verifier_data` (or the block step) pins it. -/
theorem initial_step_vd_unconstrained (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) (hi : x.isInitial = true) (vd : List Nat)
    (hlen : vd.length = vdVecLen cap) : CircuitGates e cap (x.withVd vd) := by
  refine ⟨g.memberSlots, g.siblingsHeight, hlen, g.prevWidths, g.channelIdRange, g.bpSlotRange,
    g.memberCountRange, g.delegateCountRange, g.initialChainWords, g.initialCountRange,
    g.blockNumberRange, g.recipientWords, g.identityFields, g.delegateZero, g.memberCountLower,
    g.memberCountUpper, g.activeUpper, g.bpSlotLtMemberCount, g.paddingEmpty, g.blockNumberMatch,
    ?_, ?_, g.unregisteredGuard, g.outInitialChain, g.outInitialRoot, g.outInitialCount,
    g.outChain, g.outRoot, g.outCount, g.outCountRange, g.outBlock, rfl⟩ <;>
    (intro h; simp [StepInputs.withVd, hi] at h)

/-- INITIAL-STATE BOUNDARY. On an initial step the anchor triple is a free input: any 32-bit
    initial chain extends to a satisfying witness (the chain output moves with it). Binding it to
    the contract's `pendingRegistrationChain` is a consumer obligation outside these files. -/
theorem initial_step_initial_chain_unconstrained (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) (hi : x.isInitial = true) (chain : Words8)
    (hc : CheckedWords chain.words) : CircuitGates e cap (x.withInitialChain e chain) := by
  refine ⟨g.memberSlots, g.siblingsHeight, g.vdLen, g.prevWidths, g.channelIdRange, g.bpSlotRange,
    g.memberCountRange, g.delegateCountRange, hc, g.initialCountRange,
    g.blockNumberRange, g.recipientWords, g.identityFields, g.delegateZero, g.memberCountLower,
    g.memberCountUpper, g.activeUpper, g.bpSlotLtMemberCount, g.paddingEmpty, g.blockNumberMatch,
    g.vdConnected, g.prevProofVerified, ?_, ?_, g.outInitialRoot, g.outInitialCount, ?_,
    g.outRoot, g.outCount, g.outCountRange, g.outBlock, g.outVd⟩
  · have := g.unregisteredGuard
    simpa [StepInputs.withInitialChain, StepInputs.prevRoot, hi] using
      (by simpa [StepInputs.prevRoot, hi] using this)
  · simp [StepInputs.withInitialChain, StepInputs.selectedInitialChain, hi]
  · simp [StepInputs.withInitialChain, StepInputs.prevChain, StepInputs.record, hi]

/-- RECIPIENT BOUNDARY. The circuit constrains the member RECIPIENT limbs only to be 32-bit:
    neither the active ones nor (unlike native `validate()`) the padding ones are pinned. Any
    recipient assignment extends to a satisfying witness with the SAME `member_pubkeys_root`; only
    the keccak chain value moves, so recipients are bound solely by equality with the L1 chain. -/
theorem gates_leave_recipients_free (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) (ms : List MemberEntry) (hlen : ms.length = maxSigCluster)
    (hid : ∀ i, i < maxSigCluster →
      (ms.getD i MemberEntry.zero).pkG = (x.slot i).pkG ∧
      (ms.getD i MemberEntry.zero).pkB = (x.slot i).pkB ∧
      (ms.getD i MemberEntry.zero).regev = (x.slot i).regev)
    (hrec : ∀ i, i < maxSigCluster → CheckedWords (ms.getD i MemberEntry.zero).recipient.words) :
    CircuitGates e cap (x.withMembers e ms) := by
  have hroot : memberPubkeysRoot e ms = memberPubkeysRoot e x.members := by
    simp only [memberPubkeysRoot]
    congr 1
    refine map_upto_congr maxSigCluster _ _ ?_
    intro i hi
    obtain ⟨h1, h2, h3⟩ := hid i hi
    exact member_leaf_hash_congr e _ _ h1 h2 h3
  refine ⟨hlen, g.siblingsHeight, g.vdLen, g.prevWidths, g.channelIdRange, g.bpSlotRange,
    g.memberCountRange, g.delegateCountRange, g.initialChainWords, g.initialCountRange,
    g.blockNumberRange, hrec, ?_, g.delegateZero, g.memberCountLower,
    g.memberCountUpper, g.activeUpper, g.bpSlotLtMemberCount, ?_, g.blockNumberMatch,
    g.vdConnected, g.prevProofVerified, g.unregisteredGuard, g.outInitialChain, g.outInitialRoot,
    g.outInitialCount, rfl, ?_, g.outCount, g.outCountRange, g.outBlock, g.outVd⟩
  · intro i hi
    obtain ⟨h1, h2, h3⟩ := hid i hi
    have hs : (StepInputs.withMembers e x ms).slot i = ms.getD i MemberEntry.zero := rfl
    rw [hs, h1, h2, h3]
    exact g.identityFields i hi
  · intro i hlo hhi
    obtain ⟨h1, h2, h3⟩ := hid i hhi
    have hs : (StepInputs.withMembers e x ms).slot i = ms.getD i MemberEntry.zero := rfl
    rw [hs, h1, h2, h3]
    exact g.paddingEmpty i hlo hhi
  · show x.out.channelTreeRoot =
      merkleRoot e (channelLeafHash e (registeredChannelLeaf e (memberPubkeysRoot e ms)))
        x.channelId x.siblings
    rw [hroot]
    exact g.outRoot

/-! ## What the native canonicality check actually rejects

    `PoseidonHashOut::try_from(Bytes32)` splits each 64-bit half into `(high, low)` u32 limbs and
    recombines them; that round trip is the identity on ANY `Bytes32`, so the native
    `NonCanonicalPkG` / `NonCanonicalPkB` / `NonCanonicalRegevPkDigest` errors cannot fire. The
    GOLDILOCKS canonicality the comments describe is enforced only in-circuit, by the identity
    being witnessed as a field element: a registration whose 64-bit halves are `>= p` passes
    native validation and is simply UNPROVABLE. -/

theorem native_canonicality_check_cannot_fail (x : Words8) (h : CheckedWords x.words) :
    x.canonical := by
  cases x with
  | mk w0 w1 w2 w3 w4 w5 w6 w7 =>
    have h1 : w1 < limbBase := h _ (by simp [Words8.words])
    have h3 : w3 < limbBase := h _ (by simp [Words8.words])
    have h5 : w5 < limbBase := h _ (by simp [Words8.words])
    have h7 : w7 < limbBase := h _ (by simp [Words8.words])
    simp only [limbBase] at h1 h3 h5 h7
    simp only [Words8.canonical, Words8.reduceToHash, Hash4.toWords, limbBase, Words8.mk.injEq]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> omega

/-- The intended (Goldilocks) canonicality of a registered identity half. -/
def Words8.goldilocksCanonical (x : Words8) : Prop := x.reduceToHash.canonicalField

/-- A registered identity the native validator accepts but no witness can satisfy: its halves are
    u32 limbs (so `try_from` succeeds) yet the recombined element is above the Goldilocks modulus,
    which `Bytes32Target::from_hash_out` can never produce. -/
def nonGoldilocksWords : Words8 := ⟨4294967295, 4294967295, 0, 0, 0, 0, 0, 0⟩

theorem non_goldilocks_words_accepted_natively :
    CheckedWords nonGoldilocksWords.words ∧ nonGoldilocksWords.canonical ∧
      ¬ nonGoldilocksWords.goldilocksCanonical := by
  refine ⟨by decide, by decide, ?_⟩
  intro h
  have := h nonGoldilocksWords.reduceToHash.h0 (by simp [Hash4.elems])
  simp only [nonGoldilocksWords, Words8.reduceToHash, limbBase, goldilocks] at this
  omega

/-! ## `set_witness`: the native assignment, and that it satisfies the gates -/

def initialChainOf (w : StepWitness) : Words8 :=
  match w.initialValue with | some (c, _, _) => c | none => Words8.zero
def initialRootOf (w : StepWitness) : Hash4 :=
  match w.initialValue with | some (_, r, _) => r | none => Hash4.zero
def initialCountOf (w : StepWitness) : Nat :=
  match w.initialValue with | some (_, _, n) => n | none => 0

/-- `ChannelRegStepTarget::set_witness` (plus `public_inputs.set_witness`). -/
def nativeInputs (chainVd : List Nat) (w : StepWitness) (prev out : PublicInputs) : StepInputs :=
  { isInitial := w.initialValue.isSome,
    initialChain := initialChainOf w,
    initialRoot := initialRootOf w,
    initialCount := initialCountOf w,
    prevPis := prev,
    channelId := w.record.channelId,
    bpSlot := w.record.bpSlot,
    memberCount := w.record.memberCount,
    delegateCount := w.record.delegateCount,
    members := w.record.members.map RegEntry.toMember,
    siblings := w.channelMerkleProof,
    blockNumber := w.blockNumber,
    chainVd := chainVd,
    out := out }

/-- Width / range invariants of the native values (Rust types), plus the two obligations
    `to_public_inputs` does NOT discharge: that the previous proof verifies
    (`NativeProofNotChecked`) and that its declared verifier data is the chain's
    (`ConsumerVdPin`), and the Goldilocks range of the witnessed identities. -/
structure NativeWidths (e : Environment) (cap : Nat) (chainVd : List Nat) (w : StepWitness)
    (prev : PublicInputs) : Prop where
  membersLen : w.record.members.length = maxSigCluster
  siblingsLen : w.channelMerkleProof.length = channelTreeHeight
  vdLen : chainVd.length = vdVecLen cap
  prevWidths : prev.Widths cap
  channelIdRange : w.record.channelId < limbBase
  blockNumberRange : w.blockNumber < u63Limit
  initialChainWords : CheckedWords (initialChainOf w).words
  initialCountRange : initialCountOf w < u63Limit
  recipientWords : ∀ i, i < maxSigCluster → CheckedWords (w.record.slot i).recipient.words
  /-- `GoldilocksWitnessRange`: `set_witness` calls `F::from_canonical_u64` on the reduced halves. -/
  identityFields : ∀ i, i < maxSigCluster →
    (w.record.slot i).toMember.pkG.canonicalField ∧ (w.record.slot i).toMember.pkB.canonicalField ∧
      (w.record.slot i).toMember.regev.canonicalField
  vdMatch : w.initialValue = none → chainVd = prev.vd
  proofVerifies : w.initialValue = none → e.proofAccepted prev.vd prev.toU64Vec = true

theorem native_slot (w : StepWitness) (chainVd : List Nat) (prev out : PublicInputs)
    (hlen : w.record.members.length = maxSigCluster) (i : Nat) (hi : i < maxSigCluster) :
    (nativeInputs chainVd w prev out).slot i = (w.record.slot i).toMember :=
  getD_map w.record.members RegEntry.toMember RegEntry.zero i (by rw [hlen]; exact hi)

theorem native_prev_selection (cap : Nat) (chainVd : List Nat) (w : StepWitness)
    (prev out : PublicInputs) (h : w.prevPis cap chainVd = .ok prev) :
    (nativeInputs chainVd w prev out).prevChain = prev.channelRegHashChain ∧
    (nativeInputs chainVd w prev out).prevRoot = prev.channelTreeRoot ∧
    (nativeInputs chainVd w prev out).prevCount = prev.channelRegCount ∧
    (nativeInputs chainVd w prev out).selectedInitialChain = prev.initialChannelRegHashChain ∧
    (nativeInputs chainVd w prev out).selectedInitialRoot = prev.initialChannelTreeRoot ∧
    (nativeInputs chainVd w prev out).selectedInitialCount = prev.initialChannelRegCount ∧
    ((nativeInputs chainVd w prev out).isInitial = false →
      prev.blockNumber = w.blockNumber ∧ w.initialValue = none) ∧
    (prev.vd = chainVd ∨ w.initialValue = none) := by
  cases hv : w.initialValue with
  | some triple =>
    obtain ⟨c, r, n⟩ := triple
    rw [prev_pis_initial cap chainVd w c r n hv] at h
    have hp : prev = ⟨c, r, n, c, r, n, w.blockNumber, chainVd⟩ := (Except.ok.inj h).symm
    subst hp
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, Or.inl rfl⟩ <;>
      simp [nativeInputs, StepInputs.prevChain, StepInputs.prevRoot, StepInputs.prevCount,
        StepInputs.selectedInitialChain, StepInputs.selectedInitialRoot,
        StepInputs.selectedInitialCount, initialChainOf, initialRootOf, initialCountOf, hv]
  | none =>
    cases hpp : w.prevProof with
    | none => rw [StepWitness.prevPis, hv, hpp] at h; simp at h
    | some raw =>
      refine ⟨by simp [nativeInputs, StepInputs.prevChain, hv],
        by simp [nativeInputs, StepInputs.prevRoot, hv],
        by simp [nativeInputs, StepInputs.prevCount, hv],
        by simp [nativeInputs, StepInputs.selectedInitialChain, hv],
        by simp [nativeInputs, StepInputs.selectedInitialRoot, hv],
        by simp [nativeInputs, StepInputs.selectedInitialCount, hv], fun _ => ⟨?_, rfl⟩, Or.inr rfl⟩
      cases hparse : parsePrev cap raw with
      | error err =>
        rw [StepWitness.prevPis, hv, hpp] at h
        simp only [hparse, bind_ok_iff] at h
        simp at h
      | ok pis =>
        obtain ⟨hblk, heq⟩ := prev_pis_requires_matching_block_number cap chainVd w raw pis prev
          hv hpp hparse h
        rw [heq]; exact hblk

theorem map_roundtrip_of_index (l : List RegEntry)
    (h : ∀ i, i < l.length → (l.getD i RegEntry.zero).canonical) :
    (l.map RegEntry.toMember).map MemberEntry.regEntry = l := by
  induction l with
  | nil => rfl
  | cons a as ih =>
    have ha : a.canonical := h 0 (by simp)
    have hrest : ∀ i, i < as.length → (as.getD i RegEntry.zero).canonical := by
      intro i hi
      have := h (i + 1) (by simp only [List.length_cons]; omega)
      simpa using this
    simp only [List.map_cons, reg_entry_roundtrip a ha, ih hrest]

/-- On a validated record the circuit's canonical re-encoding reproduces the record exactly, so
    `x.record` (what the keccak preimage commits to) IS the on-chain record. -/
theorem native_record_is_the_record (chainVd : List Nat) (w : StepWitness) (prev out : PublicInputs)
    (hvalid : w.record.validate = .ok ()) (hlen : w.record.members.length = maxSigCluster) :
    (nativeInputs chainVd w prev out).record = w.record := by
  have hcan : ∀ i, i < w.record.members.length →
      (w.record.members.getD i RegEntry.zero).canonical := by
    intro i hi
    exact validate_all_slots_canonical w.record hvalid i (by rw [hlen] at hi; exact hi)
  simp only [nativeInputs, StepInputs.record, recordOfMembers]
  rw [map_roundtrip_of_index w.record.members hcan]

/-- The in-circuit member root equals the native `member_pubkeys_root_for` on a validated record. -/
theorem native_member_root_matches (chainVd : List Nat) (e : Environment) (w : StepWitness)
    (prev out : PublicInputs) (hvalid : w.record.validate = .ok ())
    (hlen : w.record.members.length = maxSigCluster) :
    memberPubkeysRoot e (nativeInputs chainVd w prev out).members = nativeMemberRoot e w.record := by
  have hdc : w.record.delegateCount = 0 := (validate_parts w.record hvalid).2.1
  simp only [memberPubkeysRoot, nativeMemberRoot, nativeInputs]
  congr 1
  refine map_upto_congr maxSigCluster _ _ ?_
  intro i hi
  have hslot : (w.record.members.map RegEntry.toMember).getD i MemberEntry.zero
      = (w.record.slot i).toMember := by
    rw [show MemberEntry.zero = RegEntry.toMember RegEntry.zero from rfl]
    exact getD_map w.record.members RegEntry.toMember RegEntry.zero i (by rw [hlen]; exact hi)
  rw [hslot, hdc]
  by_cases hlt : i < w.record.memberCount
  · simp [hlt]
  · have hz : w.record.slot i = RegEntry.zero :=
      validate_padding_zero w.record hvalid i (Nat.le_of_not_lt hlt) hi
    simp only [Nat.add_zero, hlt, if_false, hz]
    rfl

/-- NATIVE ⇒ GATES. A witness the native builder admits, assigned by `set_witness`, satisfies the
    step's gate equations — under the width invariants of the Rust types, the Goldilocks range of
    the witnessed identities, and the two obligations the native path does NOT discharge (the
    previous proof actually verifying, and its declared verifier data being the chain's). -/
theorem native_assignment_satisfies_gates (e : Environment) (cap : Nat) (chainVd : List Nat)
    (w : StepWitness) (prev out : PublicInputs)
    (hvalid : w.record.validate = .ok ())
    (hprev : w.prevPis cap chainVd = .ok prev)
    (hout : w.toPublicInputs e cap chainVd = .ok out)
    (hw : NativeWidths e cap chainVd w prev) :
    CircuitGates e cap (nativeInputs chainVd w prev out) := by
  obtain ⟨-, hu⟩ := to_public_inputs_effect e cap chainVd w out hout
  obtain ⟨prev', hprev', hguard, hchain, hroot, hcount, hcrange, hic, hir, hicount, hblk, hvdout⟩ :=
    to_public_inputs_unchecked_effect e cap chainVd w out hu
  have hpe : prev = prev' := by
    rw [hprev'] at hprev; exact (Except.ok.inj hprev).symm
  subst hpe
  obtain ⟨sChain, sRoot, sCount, sIChain, sIRoot, sICount, sBlock, sVd⟩ :=
    native_prev_selection cap chainVd w prev out hprev
  obtain ⟨hmcLo, hmcHi⟩ := validate_bounds_member_count w.record hvalid
  have hdc : w.record.delegateCount = 0 := (validate_parts w.record hvalid).2.1
  have hbp : w.record.bpSlot < w.record.memberCount := validate_bp_slot_in_range w.record hvalid
  have hrec : (nativeInputs chainVd w prev out).record = w.record :=
    native_record_is_the_record chainVd w prev out hvalid hw.membersLen
  have hmr : memberPubkeysRoot e (nativeInputs chainVd w prev out).members
      = nativeMemberRoot e w.record :=
    native_member_root_matches chainVd e w prev out hvalid hw.membersLen
  have hslot : ∀ i, i < maxSigCluster →
      (nativeInputs chainVd w prev out).slot i = (w.record.slot i).toMember :=
    fun i hi => native_slot w chainVd prev out hw.membersLen i hi
  have hvd : (nativeInputs chainVd w prev out).chainVd = prev.vd := by
    rcases sVd with h | h
    · exact h.symm
    · exact (hw.vdMatch h)
  refine ⟨?_, hw.siblingsLen, hw.vdLen, hw.prevWidths, hw.channelIdRange, ?_, ?_, ?_,
    hw.initialChainWords, hw.initialCountRange, hw.blockNumberRange, ?_, ?_, hdc, hmcLo, hmcHi,
    ?_, hbp, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [nativeInputs, hw.membersLen]
  · simp only [nativeInputs, maxSigCluster, limbBase] at *; omega
  · simp only [nativeInputs, maxSigCluster, limbBase] at *; omega
  · simp only [nativeInputs, hdc, limbBase]; omega
  · intro i hi; rw [hslot i hi]; exact hw.recipientWords i hi
  · intro i hi; rw [hslot i hi]; exact hw.identityFields i hi
  · simp only [StepInputs.activeCount, nativeInputs, hdc, Nat.add_zero]; exact hmcHi
  · intro i hlo hhi
    have hmc : (nativeInputs chainVd w prev out).activeCount = w.record.memberCount := by
      simp [StepInputs.activeCount, nativeInputs, hdc]
    rw [hmc] at hlo
    rw [hslot i hhi, validate_padding_zero w.record hvalid i hlo hhi]
    exact ⟨rfl, rfl, rfl⟩
  · intro h; exact (sBlock h).1
  · intro h; exact hw.vdMatch (sBlock h).2
  · intro h; exact hw.proofVerifies (sBlock h).2
  · rw [sRoot]; exact hguard
  · rw [sIChain]; exact hic
  · rw [sIRoot]; exact hir
  · rw [sICount]; exact hicount
  · rw [sChain, hrec]; exact hchain
  · rw [hmr]; exact hroot
  · rw [sCount]; exact hcount
  · exact hcrange
  · exact hblk
  · rw [hvd]; exact hvdout

/-! ## Cyclic composition (`ChannelRegHashChainCircuit`) and the chain fold

    The wrapper circuit verifies ONE step proof and re-registers its public inputs unchanged, so a
    chain proof's public inputs are the last step's. The `Chain` inductive is the PROOF-SOUNDNESS
    PREMISE: an accepted previous chain proof is assumed to come from a gate-satisfying step. -/

def foldChain (e : Environment) (start : Words8) (rs : List Record) : Words8 :=
  rs.foldl (fun acc r => e.keccakWords (foldWords acc r)) start

theorem fold_chain_snoc (e : Environment) (start : Words8) (rs : List Record) (r : Record) :
    foldChain e start (rs ++ [r]) = e.keccakWords (foldWords (foldChain e start rs) r) := by
  simp [foldChain, List.foldl_append]

/-- `ChannelRegHashChainCircuit::new`: verify the step proof, forward its public inputs verbatim. -/
def wrapperOutput (stepPis : PublicInputs) : PublicInputs := stepPis

theorem wrapper_forwards_step_public_inputs (p : PublicInputs) : wrapperOutput p = p := rfl

theorem wrapper_public_input_count (cap : Nat) :
    chainPublicInputCount cap = publicInputsLen + vdVecLen cap := rfl

inductive Chain (e : Environment) (cap : Nat) (baseVd : List Nat) :
    List Record → PublicInputs → Prop where
  | initial (x : StepInputs) (g : CircuitGates e cap x) (hi : x.isInitial = true)
      (hvd : x.chainVd = baseVd) : Chain e cap baseVd [x.record] x.out
  | step (rs : List Record) (prev : PublicInputs) (h : Chain e cap baseVd rs prev)
      (x : StepInputs) (g : CircuitGates e cap x) (hi : x.isInitial = false)
      (hp : x.prevPis = prev) : Chain e cap baseVd (rs ++ [x.record]) x.out

/-- Structural invariants every record in a chain satisfies, as CIRCUIT facts. -/
structure Record.CosignerOnly (r : Record) : Prop where
  delegates : r.delegateCount = 0
  lower : minMemberCount ≤ r.memberCount
  upper : r.memberCount ≤ maxSigCluster
  bp : r.bpSlot < r.memberCount
  slots : r.members.length = maxSigCluster

theorem gates_record_cosigner_only (e : Environment) (cap : Nat) (x : StepInputs)
    (g : CircuitGates e cap x) : x.record.CosignerOnly := by
  refine ⟨g.delegateZero, g.memberCountLower, g.memberCountUpper, g.bpSlotLtMemberCount, ?_⟩
  simp [StepInputs.record, recordOfMembers, g.memberSlots]

/-- The declared verifier data is forwarded unchanged by every step: a whole chain declares ONE
    verifier data, the one the initial step freely chose (`ConsumerVdPin`). -/
theorem chain_declares_single_vd (e : Environment) (cap : Nat) (baseVd : List Nat)
    (rs : List Record) (out : PublicInputs) (h : Chain e cap baseVd rs out) : out.vd = baseVd := by
  induction h with
  | initial x g hi hvd => rw [g.outVd, hvd]
  | step rs prev hc x g hi hp ih => rw [g.outVd, g.vdConnected hi, hp]; exact ih

/-- MAIN CHAIN FACT. A chain proof's `channel_reg_hash_chain` is the keccak fold over the
    consumed registration records from its own `initial_channel_reg_hash_chain`, its
    `channel_reg_count` is the initial count plus the number of records, every record is
    cosigner-only with `member_count ∈ [2, 8]`, and the chain declares one verifier data. -/
theorem chain_is_fold (e : Environment) (cap : Nat) (baseVd : List Nat) (rs : List Record)
    (out : PublicInputs) (h : Chain e cap baseVd rs out) :
    out.channelRegHashChain = foldChain e out.initialChannelRegHashChain rs ∧
      out.channelRegCount = out.initialChannelRegCount + rs.length ∧
      rs ≠ [] ∧ (∀ r ∈ rs, r.CosignerOnly) ∧ out.vd = baseVd := by
  induction h with
  | initial x g hi hvd =>
    have hchain : x.prevChain = x.initialChain := by simp [StepInputs.prevChain, hi]
    have hcount : x.prevCount = x.initialCount := by simp [StepInputs.prevCount, hi]
    have hic : x.out.initialChannelRegHashChain = x.initialChain := by
      rw [g.outInitialChain]; simp [StepInputs.selectedInitialChain, hi]
    have hicount : x.out.initialChannelRegCount = x.initialCount := by
      rw [g.outInitialCount]; simp [StepInputs.selectedInitialCount, hi]
    refine ⟨?_, ?_, by simp, ?_, by rw [g.outVd, hvd]⟩
    · rw [g.outChain, hchain, hic]; simp [foldChain]
    · rw [g.outCount, hcount, hicount]; simp
    · intro r hr
      rcases List.mem_singleton.mp hr with rfl
      exact gates_record_cosigner_only e cap x g
  | step rs prev hc x g hi hp ih =>
    obtain ⟨ihchain, ihcount, ihne, ihall, ihvd⟩ := ih
    have hchain : x.prevChain = prev.channelRegHashChain := by
      simp [StepInputs.prevChain, hi, hp]
    have hcount : x.prevCount = prev.channelRegCount := by simp [StepInputs.prevCount, hi, hp]
    have hic : x.out.initialChannelRegHashChain = prev.initialChannelRegHashChain := by
      rw [g.outInitialChain]; simp [StepInputs.selectedInitialChain, hi, hp]
    have hicount : x.out.initialChannelRegCount = prev.initialChannelRegCount := by
      rw [g.outInitialCount]; simp [StepInputs.selectedInitialCount, hi, hp]
    refine ⟨?_, ?_, by simp, ?_, by rw [g.outVd, g.vdConnected hi, hp]; exact ihvd⟩
    · rw [g.outChain, hchain, hic, fold_chain_snoc, ← ihchain]
    · rw [g.outCount, hcount, hicount, ihcount, List.length_append]
      simp [Nat.add_assoc]
    · intro r hr
      rcases List.mem_append.mp hr with hmem | hmem
      · exact ihall r hmem
      · rcases List.mem_singleton.mp hmem with rfl
        exact gates_record_cosigner_only e cap x g

/-! ## `ChannelRegHashChainCircuit::verify` -/

inductive VerifyError where
  | cyclicVerifierDataMismatch
  | proofInvalid
  deriving DecidableEq, Repr

/-- `check_cyclic_proof_verifier_data(proof, data.verifier_only, data.common)?` then `data.verify`. -/
def verifyChainProof (e : Environment) (dataVd : List Nat) (p : PublicInputs) :
    Except VerifyError Unit := do
  check (p.vd = dataVd) .cyclicVerifierDataMismatch
  check (e.proofAccepted dataVd p.toU64Vec = true) .proofInvalid

theorem chain_verify_pins_declared_vd (e : Environment) (dataVd : List Nat) (p : PublicInputs)
    (h : verifyChainProof e dataVd p = .ok ()) : p.vd = dataVd := by
  simp only [verifyChainProof, unit_bind_ok_iff, check_ok_iff] at h
  exact h.1

theorem chain_verify_requires_accepted_proof (e : Environment) (dataVd : List Nat)
    (p : PublicInputs) (h : verifyChainProof e dataVd p = .ok ()) :
    e.proofAccepted dataVd p.toU64Vec = true := by
  simp only [verifyChainProof, unit_bind_ok_iff, check_ok_iff] at h
  exact h.2

/-- The free initial verifier data becomes pinned exactly when a consumer runs the cyclic check. -/
theorem verified_chain_uses_the_circuit_verifier_data (e : Environment) (cap : Nat)
    (baseVd dataVd : List Nat) (rs : List Record) (out : PublicInputs)
    (h : Chain e cap baseVd rs out) (hv : verifyChainProof e dataVd out = .ok ()) :
    baseVd = dataVd := by
  rw [← chain_declares_single_vd e cap baseVd rs out h]
  exact chain_verify_pins_declared_vd e dataVd out hv

/-! ## Comparison with the IntmaxRollup model (`RollupValue.registerChannel`)

    `SolidityKeccakPacking`: `plonky2_keccak::solidity_keccak256` consumes each u32 word as four
    big-endian bytes. Under that packing the circuit's fold preimage is byte-identical to
    `RollupValue.hashPreimage (.channelRegistration ..)`, which is the preimage
    `IntmaxRollup._channelRegHashChain` builds with `abi.encodePacked`. -/

theorem upto_succ_cons (n : Nat) : upto (n + 1) = 0 :: (upto n).map (· + 1) := by
  induction n with
  | zero => rfl
  | succ k ih =>
    show upto (k + 1) ++ [k + 1] = 0 :: (upto (k + 1)).map (· + 1)
    have key : upto (k + 1) ++ [k + 1] = 0 :: ((upto k).map (· + 1) ++ [k + 1]) := by
      rw [ih]; rfl
    rw [key]
    simp [upto, List.map_append]

theorem map_eq_upto_getD {α β : Type} (l : List α) (d : α) (f : α → β) :
    l.map f = (upto l.length).map (fun i => f (l.getD i d)) := by
  induction l with
  | nil => rfl
  | cons a as ih =>
    rw [List.length_cons, upto_succ_cons]
    simp only [List.map_cons, List.map_map]
    rw [ih]
    rfl

def wordsToBytes (ws : List Nat) : RollupValue.Bytes := ws.bind (RollupValue.wordBytes 4)

theorem words_to_bytes_append (xs ys : List Nat) :
    wordsToBytes (xs ++ ys) = wordsToBytes xs ++ wordsToBytes ys := by
  simp [wordsToBytes, List.append_bind]

theorem bytes32_of_limbs_raw (w0 w1 w2 w3 w4 w5 w6 w7 : Nat)
    (h1 : w1 < limbBase) (h2 : w2 < limbBase) (h3 : w3 < limbBase)
    (h4 : w4 < limbBase) (h5 : w5 < limbBase) (h6 : w6 < limbBase) (h7 : w7 < limbBase) :
    RollupValue.wordBytes 32 (limbValue [w0, w1, w2, w3, w4, w5, w6, w7]) =
      [w0, w1, w2, w3, w4, w5, w6, w7].bind (RollupValue.wordBytes 4) := by
  have hr32 : List.range 32 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31] := rfl
  have hr4 : List.range 4 = [0,1,2,3] := rfl
  simp only [RollupValue.wordBytes, hr32, hr4, List.map, List.bind_cons, List.bind_nil,
    List.append_nil, List.cons_append, List.nil_append, limbValue, List.foldl, limbBase] at *
  simp only [List.cons.injEq, and_true]
  refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩ <;>
    (congr 1; omega)

theorem address_of_limbs_raw (a0 a1 a2 a3 a4 : Nat)
    (h1 : a1 < limbBase) (h2 : a2 < limbBase) (h3 : a3 < limbBase) (h4 : a4 < limbBase) :
    RollupValue.wordBytes 20 (limbValue [a0, a1, a2, a3, a4]) =
      [a0, a1, a2, a3, a4].bind (RollupValue.wordBytes 4) := by
  have hr20 : List.range 20 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19] := rfl
  have hr4 : List.range 4 = [0,1,2,3] := rfl
  simp only [RollupValue.wordBytes, hr20, hr4, List.map, List.bind_cons, List.bind_nil,
    List.append_nil, List.cons_append, List.nil_append, limbValue, List.foldl, limbBase] at *
  simp only [List.cons.injEq, and_true]
  refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩ <;> (congr 1; omega)

theorem bytes32_of_limbs (x : Words8) (h : CheckedWords x.words) :
    RollupValue.wordBytes 32 x.value = wordsToBytes x.words := by
  cases x with
  | mk w0 w1 w2 w3 w4 w5 w6 w7 =>
    exact bytes32_of_limbs_raw w0 w1 w2 w3 w4 w5 w6 w7 (h _ (by simp [Words8.words]))
      (h _ (by simp [Words8.words])) (h _ (by simp [Words8.words])) (h _ (by simp [Words8.words]))
      (h _ (by simp [Words8.words])) (h _ (by simp [Words8.words])) (h _ (by simp [Words8.words]))

theorem address_of_limbs (x : Words5) (h : CheckedWords x.words) :
    RollupValue.wordBytes 20 x.value = wordsToBytes x.words := by
  cases x with
  | mk a0 a1 a2 a3 a4 =>
    exact address_of_limbs_raw a0 a1 a2 a3 a4 (h _ (by simp [Words5.words]))
      (h _ (by simp [Words5.words])) (h _ (by simp [Words5.words])) (h _ (by simp [Words5.words]))

/-- One member slot as the contract sees it. -/
def RegEntry.toSlot (m : RegEntry) : RollupValue.MemberSlot :=
  ⟨m.pkG.value, m.pkB.value, m.regev.value, m.recipient.value⟩

def RegEntry.Checked (m : RegEntry) : Prop :=
  CheckedWords m.pkG.words ∧ CheckedWords m.pkB.words ∧ CheckedWords m.regev.words ∧
    CheckedWords m.recipient.words

theorem zero_entry_to_slot : RegEntry.zero.toSlot = ⟨0, 0, 0, 0⟩ := by decide

theorem slot_words_to_bytes (m : RegEntry) (h : m.Checked) :
    wordsToBytes m.words = RollupValue.encodeMemberSlot m.toSlot := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  simp only [RegEntry.words, RegEntry.toSlot, RollupValue.encodeMemberSlot, words_to_bytes_append,
    bytes32_of_limbs _ h1, bytes32_of_limbs _ h2, bytes32_of_limbs _ h3, address_of_limbs _ h4]

theorem slots_words_to_bytes (ms : List RegEntry) (h : ∀ m ∈ ms, m.Checked) :
    wordsToBytes (ms.bind RegEntry.words) =
      (ms.map RegEntry.toSlot).bind RollupValue.encodeMemberSlot := by
  induction ms with
  | nil => rfl
  | cons a as ih =>
    simp only [List.bind_cons, List.map_cons, words_to_bytes_append,
      slot_words_to_bytes a (h a (List.mem_cons_self a as)),
      ih (fun m hm => h m (List.mem_cons_of_mem a hm))]

/-- All limbs of a record are u32 (the Rust types) — needed for the byte-packing comparison. -/
structure Record.CheckedRecord (r : Record) : Prop where
  channel : r.channelId < limbBase
  bp : r.bpSlot < limbBase
  count : r.memberCount < limbBase
  delegates : r.delegateCount < limbBase
  slots : ∀ m ∈ r.members, m.Checked

/-- KERNEL-CHECKED. Under `SolidityKeccakPacking` the step's keccak preimage is byte-identical to
    the `IntmaxRollup._channelRegHashChain` preimage of `RollupValue`. -/
theorem fold_preimage_matches_rollup_model (prev : Words8) (r : Record)
    (hp : CheckedWords prev.words) (hr : r.CheckedRecord) :
    wordsToBytes (foldWords prev r) =
      RollupValue.hashPreimage (.channelRegistration prev.value r.channelId r.bpSlot
        r.memberCount r.delegateCount (r.members.map RegEntry.toSlot)) := by
  simp only [foldWords, words_to_bytes_append, RollupValue.hashPreimage, bytes32_of_limbs _ hp,
    slots_words_to_bytes r.members hr.slots, List.append_assoc]
  rfl

/-- The two `HashInput` shapes `RollupValue` uses for a registration have the SAME preimage:
    `registerChannel` builds the header bytes explicitly, `channelRegHashChain` structurally. -/
theorem rollup_registration_preimage_forms_agree (prev channel bp count delegates : Nat)
    (slots : List RollupValue.MemberSlot) :
    RollupValue.hashPreimage (.channelRegistration prev channel bp count delegates slots) =
      RollupValue.hashPreimage (.registrationBytes
        (RollupValue.wordBytes 32 prev ++ RollupValue.wordBytes 4 channel ++
          RollupValue.wordBytes 4 bp ++ RollupValue.wordBytes 4 count ++
          RollupValue.wordBytes 4 delegates) slots) := by
  simp [RollupValue.hashPreimage, List.append_assoc]

/-- KeccakBridge: the in-circuit keccak over u32 words and a byte-level keccak agree on u32 words. -/
def KeccakBridge (e : Environment) (keccak : RollupValue.Bytes → RollupValue.Hash) : Prop :=
  ∀ ws, CheckedWords ws → (e.keccakWords ws).value = keccak (wordsToBytes ws)

/-- The keccak gadget returns 32-bit limbs (plonky2_keccak, outside the modeled files). -/
def KeccakOutputsChecked (e : Environment) : Prop := ∀ ws, CheckedWords (e.keccakWords ws).words

theorem fold_words_checked (prev : Words8) (r : Record) (hp : CheckedWords prev.words)
    (hr : r.CheckedRecord) : CheckedWords (foldWords prev r) := by
  intro v hv
  simp only [foldWords, List.mem_append] at hv
  rcases hv with (hv | hv) | hv
  · exact hp v hv
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at hv
    rcases hv with rfl | rfl | rfl | rfl
    · exact hr.channel
    · exact hr.bp
    · exact hr.count
    · exact hr.delegates
  · obtain ⟨m, hm, hvm⟩ := List.mem_bind.mp hv
    obtain ⟨h1, h2, h3, h4⟩ := hr.slots m hm
    simp only [RegEntry.words, List.mem_append] at hvm
    rcases hvm with ((hvm | hvm) | hvm) | hvm
    · exact h1 v hvm
    · exact h2 v hvm
    · exact h3 v hvm
    · exact h4 v hvm

/-- The Solidity-side fold: `pendingRegistrationChain := keccak(prev ‖ header ‖ 8 slots)`. -/
def rollupRegFold (re : RollupValue.Environment) (start : RollupValue.Hash) (rs : List Record) :
    RollupValue.Hash :=
  rs.foldl (fun acc r => re.hash (.channelRegistration acc r.channelId r.bpSlot r.memberCount
    r.delegateCount (r.members.map RegEntry.toSlot))) start

theorem fold_value_matches_rollup_under_bridge (e : Environment) (re : RollupValue.Environment)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (hb : KeccakBridge e keccak)
    (ha : RollupValue.HashEncodingAgrees re keccak) (prev : Words8) (r : Record)
    (hp : CheckedWords prev.words) (hr : r.CheckedRecord) :
    (e.keccakWords (foldWords prev r)).value =
      re.hash (.channelRegistration prev.value r.channelId r.bpSlot r.memberCount r.delegateCount
        (r.members.map RegEntry.toSlot)) := by
  rw [hb _ (fold_words_checked prev r hp hr), fold_preimage_matches_rollup_model prev r hp hr, ha]

theorem fold_chain_matches_rollup_fold (e : Environment) (re : RollupValue.Environment)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (hb : KeccakBridge e keccak)
    (ha : RollupValue.HashEncodingAgrees re keccak) (hout : KeccakOutputsChecked e)
    (start : Words8) (h0 : CheckedWords start.words) (rs : List Record)
    (hrs : ∀ r ∈ rs, r.CheckedRecord) :
    (foldChain e start rs).value = rollupRegFold re start.value rs := by
  induction rs generalizing start with
  | nil => simp [foldChain, rollupRegFold]
  | cons r rest ih =>
    have hr := hrs r (List.mem_cons_self r rest)
    have hrest : ∀ x ∈ rest, x.CheckedRecord := fun x hx => hrs x (List.mem_cons_of_mem r hx)
    simp only [foldChain, rollupRegFold, List.foldl_cons]
    have step := fold_value_matches_rollup_under_bridge e re keccak hb ha start r h0 hr
    have rest' := ih (e.keccakWords (foldWords start r)) (hout _) hrest
    simp only [foldChain, rollupRegFold] at rest'
    rw [rest', step]

/-- MAIN COMPARISON. A chain proof's final `channel_reg_hash_chain` equals `IntmaxRollup`'s
    `pendingRegistrationChain` fold over the SAME registrations, in the SAME order, from the SAME
    initial value; the count is the initial count plus the number of registrations; every record is
    cosigner-only with `member_count ∈ [2, 8]`; and the chain declares one verifier data.
    Premises: proof soundness (`Chain`), the keccak bridges (`SolidityKeccakPacking`,
    `KeccakBridge`, `RollupValue.HashEncodingAgrees`), 32-bit gadget outputs, and u32 record limbs.
    Whether the initial value is the contract's actual pending chain is `InitialStatePin`. -/
theorem chain_matches_rollup_fold (e : Environment) (re : RollupValue.Environment) (cap : Nat)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (hb : KeccakBridge e keccak)
    (ha : RollupValue.HashEncodingAgrees re keccak) (hout : KeccakOutputsChecked e)
    (baseVd : List Nat) (rs : List Record) (out : PublicInputs) (h : Chain e cap baseVd rs out)
    (h0 : CheckedWords out.initialChannelRegHashChain.words)
    (hrs : ∀ r ∈ rs, r.CheckedRecord) :
    out.channelRegHashChain.value =
        rollupRegFold re out.initialChannelRegHashChain.value rs ∧
      out.channelRegCount = out.initialChannelRegCount + rs.length ∧
      (∀ r ∈ rs, r.CosignerOnly) ∧ out.vd = baseVd := by
  obtain ⟨hchain, hcount, -, hall, hvd⟩ := chain_is_fold e cap baseVd rs out h
  refine ⟨?_, hcount, hall, hvd⟩
  rw [hchain]
  exact fold_chain_matches_rollup_fold e re keccak hb ha hout _ h0 rs hrs

/-! ## Relating a record to the L1 registration calldata -/

/-- The record's 8 slots are the contract's padded slot list: active entries first, ZERO slots
    afterwards. The circuit forces the identity components of a padding slot to zero but NOT its
    recipient (`gates_leave_recipients_free`), so this is a hypothesis, not a gate consequence. -/
theorem record_slots_are_padded (r : Record) (hlen : r.members.length = maxSigCluster)
    (hpad : ∀ i, r.memberCount ≤ i → i < maxSigCluster → r.slot i = RegEntry.zero) :
    r.members.map RegEntry.toSlot =
      (upto maxSigCluster).map (fun i =>
        if i < r.memberCount then (r.slot i).toSlot else ⟨0, 0, 0, 0⟩) := by
  rw [map_eq_upto_getD r.members RegEntry.zero RegEntry.toSlot, hlen]
  refine map_upto_congr maxSigCluster _ _ ?_
  intro i hi
  by_cases hlt : i < r.memberCount
  · simp [hlt, Record.slot]
  · simp only [hlt, if_false]
    rw [show r.members.getD i RegEntry.zero = r.slot i from rfl,
      hpad i (Nat.le_of_not_lt hlt) hi, zero_entry_to_slot]

/-- "This registration record IS that L1 `registerChannel` calldata": same channel, same bp slot,
    zero delegates, same member count, and the contract's padded slot list is the record's. -/
def MatchesRegistration (r : Record) (reg : RollupValue.Registration) : Prop :=
  reg.channel = r.channelId ∧ reg.bpSlot = r.bpSlot ∧ reg.delegates = 0 ∧
    reg.pkGs.length = r.memberCount ∧
    (upto maxSigCluster).map (fun i =>
      if i < r.memberCount then
        RollupValue.MemberSlot.mk (reg.pkGs.getD i 0) (reg.pkBs.getD i 0) (reg.regev.getD i 0)
          (reg.recipients.getD i 0)
      else ⟨0, 0, 0, 0⟩) = r.members.map RegEntry.toSlot

theorem range_eight_is_upto : List.range 8 = upto maxSigCluster := by decide

/-- One `RollupValue.channelRegHashChain` step on matching calldata IS one step of the fold the
    circuit performs (same `HashInput`), given the circuit-enforced `delegate_count = 0`. -/
theorem rollup_chain_step_matches_record (re : RollupValue.Environment) (r : Record)
    (reg : RollupValue.Registration) (hm : MatchesRegistration r reg) (hdc : r.delegateCount = 0)
    (prev : RollupValue.Hash) :
    RollupValue.channelRegHashChain re prev reg =
      re.hash (.channelRegistration prev r.channelId r.bpSlot r.memberCount r.delegateCount
        (r.members.map RegEntry.toSlot)) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := hm
  simp only [RollupValue.channelRegHashChain, h1, h2, h4, hdc, range_eight_is_upto, h5]

theorem rollup_require_ok_iff (c : Bool) (err : RollupValue.Error) :
    (RollupValue.require c err = .ok ()) ↔ c = true := by
  cases c <;> simp [RollupValue.require]

/-- `IntmaxRollup.registerChannel` folds `pendingRegistrationChain` by exactly one registration
    hash and bumps `registrationCount` by one; the checks it enforces are `delegates = 0`,
    `2 <= count <= 8` and `bp_member_slot < count` — the same shape the step circuit enforces. -/
theorem rollup_register_channel_folds_pending_chain (re : RollupValue.Environment)
    (keccak : RollupValue.Bytes → RollupValue.Hash) (ha : RollupValue.HashEncodingAgrees re keccak)
    (s after : RollupValue.State) (reg : RollupValue.Registration)
    (ev : List RollupValue.Event) (h : RollupValue.registerChannel re s reg = .ok (after, ev)) :
    ∃ slots, RollupValue.registrationSlots reg.pkGs.length reg.pkGs reg.pkBs reg.regev
        reg.recipients 8 = .ok slots ∧
      after.pendingRegistrationChain = re.hash (.channelRegistration s.pendingRegistrationChain
        reg.channel reg.bpSlot reg.pkGs.length 0 slots) ∧
      after.registrationCount = s.registrationCount + 1 ∧ reg.delegates = 0 ∧
      2 ≤ reg.pkGs.length ∧ reg.pkGs.length ≤ 8 ∧ reg.bpSlot < reg.pkGs.length := by
  simp only [RollupValue.registerChannel, RollupValue.channelRegHashChainRaw, RollupValue.checkedAdd,
    bind_ok_iff, unit_bind_ok_iff, exists_unit, pure_ok_iff, rollup_require_ok_iff,
    Prod.mk.injEq] at h
  obtain ⟨-, -, -, hdel, -, hcounts, hbp, -, chain, ⟨slots, hslots, hhash⟩, cnt, ⟨-, hcnt⟩,
    hstate⟩ := h
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at hcounts hdel hbp
  refine ⟨slots, hslots, ?_, ?_, hdel, hcounts.1.1.1.1, hcounts.1.1.1.2, hbp⟩
  · rw [← hstate.1]
    simp only [RollupValue.recordCheckpoint, ← hhash]
    rw [ha, ha, rollup_registration_preimage_forms_agree]
  · rw [← hstate.1]
    simp only [RollupValue.recordCheckpoint, ← hcnt]

/-! ## A concrete, non-vacuous accepted step

    Small opaque callbacks stand in for keccak / Poseidon; the point is that the native admission,
    the gate equations and the one-step chain are simultaneously satisfiable. -/

def demoEnv : Environment where
  keccakWords := fun ws => ⟨ws.length, ws.foldl (· + ·) 0 % 1000003, 0, 0, 0, 0, 0, 0⟩
  poseidonWords := fun ws => ⟨ws.foldl (· + ·) 0 % 1000003, ws.length, 0, 0⟩
  twoToOne := fun a b => ⟨(a.h0 + 2 * b.h0 + 1) % 1000003, 0, 0, 0⟩
  emptySendTreeRoot := ⟨7, 0, 0, 0⟩
  proofAccepted := fun _ _ => true

def demoEntry (k : Nat) : RegEntry :=
  ⟨⟨0, k, 0, 0, 0, 0, 0, 0⟩, ⟨0, k + 16, 0, 0, 0, 0, 0, 0⟩, ⟨0, k + 32, 0, 0, 0, 0, 0, 0⟩,
   ⟨k, 0, 0, 0, 0⟩⟩

def demoMembers : List RegEntry :=
  [demoEntry 1, demoEntry 2, RegEntry.zero, RegEntry.zero, RegEntry.zero, RegEntry.zero,
   RegEntry.zero, RegEntry.zero]

def demoRecord : Record := ⟨5, 1, 2, 0, demoMembers⟩

set_option maxRecDepth 20000 in
theorem demo_record_validates : demoRecord.validate = .ok () := by rfl

def demoSiblings : List Hash4 := List.replicate channelTreeHeight Hash4.zero
def demoVd : List Nat := [1, 2, 3, 4]

def demoInitialRoot : Hash4 :=
  merkleRoot demoEnv (channelLeafHash demoEnv (defaultChannelLeaf demoEnv)) 5 demoSiblings

def demoWitness : StepWitness :=
  ⟨some (Words8.zero, demoInitialRoot, 0), none, demoRecord, demoSiblings, 7⟩

def demoPrev : PublicInputs :=
  ⟨Words8.zero, demoInitialRoot, 0, Words8.zero, demoInitialRoot, 0, 7, demoVd⟩

theorem demo_prev_pis : demoWitness.prevPis 0 demoVd = .ok demoPrev := rfl

set_option maxRecDepth 20000 in
theorem demo_native_accepts :
    ∃ out, demoWitness.toPublicInputs demoEnv 0 demoVd = .ok out ∧
      out.channelRegCount = 1 ∧ out.initialChannelRegCount = 0 ∧ out.blockNumber = 7 ∧
      out.channelTreeRoot =
        merkleRoot demoEnv
          (channelLeafHash demoEnv (registeredChannelLeaf demoEnv (nativeMemberRoot demoEnv demoRecord)))
          5 demoSiblings :=
  ⟨_, rfl, rfl, rfl, rfl, rfl⟩

set_option maxRecDepth 20000 in
theorem demo_native_widths : NativeWidths demoEnv 0 demoVd demoWitness demoPrev := by
  refine ⟨rfl, rfl, rfl, ⟨by decide, by decide, by decide,
    by decide, by decide, rfl⟩, by decide, by decide, by decide, by decide, ?_, ?_,
    fun h => absurd h (by decide), fun h => absurd h (by decide)⟩
  · intro i hi
    have hd : ∀ j ∈ upto maxSigCluster,
        CheckedWords (demoWitness.record.slot j).recipient.words := by decide
    exact hd i ((mem_upto i maxSigCluster).mpr hi)
  · intro i hi
    have hd : ∀ j ∈ upto maxSigCluster,
        (demoWitness.record.slot j).toMember.pkG.canonicalField ∧
        (demoWitness.record.slot j).toMember.pkB.canonicalField ∧
        (demoWitness.record.slot j).toMember.regev.canonicalField := by decide
    exact hd i ((mem_upto i maxSigCluster).mpr hi)

set_option maxRecDepth 20000 in
/-- NON-VACUOUS. One concrete registration is natively admitted, its `set_witness` assignment
    satisfies every gate of `ChannelRegStepTarget::new`, and it forms a one-record chain whose
    count is 1. -/
theorem demo_chain_nonvacuous :
    ∃ out, demoWitness.toPublicInputs demoEnv 0 demoVd = .ok out ∧
      CircuitGates demoEnv 0 (nativeInputs demoVd demoWitness demoPrev out) ∧
      Chain demoEnv 0 demoVd [demoRecord] out ∧ out.channelRegCount = 1 := by
  obtain ⟨out, hout, hcount, -⟩ := demo_native_accepts
  have hg := native_assignment_satisfies_gates demoEnv 0 demoVd demoWitness demoPrev out
    demo_record_validates demo_prev_pis hout demo_native_widths
  have hrec : (nativeInputs demoVd demoWitness demoPrev out).record = demoRecord :=
    native_record_is_the_record demoVd demoWitness demoPrev out demo_record_validates rfl
  refine ⟨out, hout, hg, ?_, hcount⟩
  have hc := Chain.initial (e := demoEnv) (cap := 0) (baseVd := demoVd) _ hg rfl rfl
  rwa [hrec] at hc

set_option maxRecDepth 20000 in
/-- The demo record's member root is the root over exactly its 2 active slots. -/
theorem demo_member_root_is_two_slots :
    nativeMemberRoot demoEnv demoRecord =
      memberRootOfHashes demoEnv ((upto maxSigCluster).map (fun i =>
        if i < 2 then memberLeafHash demoEnv (demoRecord.slot i).toMember
        else emptyMemberLeafHash demoEnv)) := rfl

end Zkp.Implementation.ChannelRegChain
