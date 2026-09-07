import Std
import Zkp.Implementation.PrivateState
import Zkp.Implementation.U256Arithmetic

/-!
# Balance-circuit common witnesses: recipient, account state, deposit and transfer witnesses

Handwritten semantic model of four source files:

* `src/circuits/balance/common/recipient.rs`        (tagged recipient encoding / extraction)
* `src/circuits/balance/common/account_state.rs`    (send-leaf + channel-leaf inclusion witness)
* `src/circuits/balance/common/deposit_witness.rs`  (deposit inclusion + recipient binding)
* `src/circuits/balance/common/transfer_witness.rs` (transfer inclusion)

This is NOT a refinement proof of the Rust source, of plonky2 circuit lowering, or of the
Solidity side. Nothing here shows that the Lean definitions compile to the same constraint
system the Rust builder emits. What the module does give is a kernel-checked account of the
field layouts, word counts, the order and precedence of the native checks, the byte-level
tagged-recipient codec, and the exact difference between the native `new`/`verify` admission
path and an arbitrary witness satisfying the circuit's local gate equations.

Explicitly NOT proved and carried as opaque callbacks or premises (see the line maps'
`boundaries`):

* `hash` (Poseidon over Goldilocks, native `PoseidonHashOut::hash_inputs_u64` and the in-circuit
  `PoseidonHashOutTarget::hash_inputs`) is an opaque `List Nat -> Hash4`. No collision resistance
  and no injectivity is assumed; where injectivity is needed it is an explicit premise about the
  concrete compared pair.
* Merkle openings (`IncrementalMerkleProof::verify`, `SparseMerkleProof::verify` and their
  `*Target` counterparts) are opaque decision callbacks. Their only modelled property is the
  index-truncation premise `MerkleEnv.truncates`, transcribed from `BitPath::pop` which consumes
  exactly `siblings.len()` low bits of the index.
* Goldilocks canonicality of `PoseidonHashOutTarget` elements, `safe_split_lo_and_hi`,
  `split_le`, `range_check` and every other builder primitive are uninterpreted; range checks are
  recorded as a declarative table, not as emitted gates.
* Proof-system soundness, signature validity and freshness are out of scope entirely.

Word arithmetic uses plain `Nat` with explicit numeric moduli (`4294967296 = 2 ^ 32`,
`16777216 = 2 ^ 24`) so that `omega` can discharge the byte-splitting obligations.
-/

namespace Zkp.Implementation.BalanceWitnesses

open Zkp.Implementation.PrivateState (Hash4 hashWords)

/-! ## Pinned constants

All literals below are transcribed from `src/constants.rs`, `src/ethereum_types/*.rs`,
`src/utils/poseidon_hash_out.rs` and the three `const`s at the top of `recipient.rs`. -/

/-- `BYTES32_LEN` (= `U256_LEN`), u32 limbs. -/
def bytes32Len : Nat := 8
/-- `ADDRESS_LEN`, u32 limbs. -/
def addressLen : Nat := 5
/-- `POSEIDON_HASH_OUT_LEN` (also `SALT_LEN`), u64 words. -/
def poseidonHashOutLen : Nat := 4
/-- `U256_LEN`, u32 limbs. -/
def u256Len : Nat := 8
/-- `USER_ID_DOMAIN` from recipient.rs line 19, ASCII `"UID\0"`. -/
def userIdDomain : Nat := 0x55494400
/-- `USER_ID_TAG` from recipient.rs line 20. -/
def userIdTag : Nat := 1
/-- `ADDRESS_TAG` from recipient.rs line 21. -/
def addressTag : Nat := 2
/-- `CHANNEL_ID_BITS`. -/
def channelIdBits : Nat := 32
/-- `SEND_TREE_HEIGHT`. -/
def sendTreeHeight : Nat := 32
/-- `CHANNEL_TREE_HEIGHT` (= `CHANNEL_ID_BITS`). -/
def channelTreeHeight : Nat := 32
/-- `DEPOSIT_TREE_HEIGHT`. -/
def depositTreeHeight : Nat := 63
/-- `TRANSFER_TREE_HEIGHT`. -/
def transferTreeHeight : Nat := 6
/-- `TRANSFER_LEN = BYTES32_LEN + 1 + U256_LEN + BYTES32_LEN` (transfer.rs line 26). -/
def transferLen : Nat := bytes32Len + 1 + u256Len + bytes32Len
/-- `2 ^ 32`, the u32 limb modulus. -/
def limbModulus : Nat := 4294967296
/-- `2 ^ 24`, the weight of the leading byte of a u32 limb. -/
def tagWeight : Nat := 16777216

theorem bytes32_len_pinned : bytes32Len = 8 := rfl
theorem address_len_pinned : addressLen = 5 := rfl
theorem poseidon_hash_out_len_pinned : poseidonHashOutLen = 4 := rfl
theorem user_id_domain_pinned : userIdDomain = 0x55494400 := rfl
theorem user_id_tag_pinned : userIdTag = 1 := rfl
theorem address_tag_pinned : addressTag = 2 := rfl
theorem channel_id_bits_pinned : channelIdBits = 32 := rfl
theorem send_tree_height_pinned : sendTreeHeight = 32 := rfl
theorem channel_tree_height_pinned : channelTreeHeight = 32 := rfl
theorem deposit_tree_height_pinned : depositTreeHeight = 63 := rfl
theorem transfer_tree_height_pinned : transferTreeHeight = 6 := rfl
theorem transfer_len_pinned : transferLen = 25 := rfl
theorem limb_modulus_pinned : limbModulus = 2 ^ 32 := by decide
theorem tag_weight_pinned : tagWeight = 2 ^ 24 := by decide

/-- The domain separator really is the big-endian ASCII of `"UID\0"`. -/
theorem user_id_domain_is_uid_ascii :
    userIdDomain = 0x55 * 16777216 + 0x49 * 65536 + 0x44 * 256 + 0x00 := by decide

/-- The two tags are distinct; this is the only thing that keeps an internal (user-id) recipient
from being read back as an L1 address. -/
theorem recipient_tags_distinct : userIdTag ≠ addressTag := by decide

/-! ## Big-endian u32-limb codec

Models `U32LimbTrait::to_bytes_be` / `from_bytes_be` (native, src/ethereum_types/u32limb_trait.rs
lines 55-75) and `U32LimbTargetTrait::to_bytes_be` / `from_bytes_be` (lines 217-263). The target
versions additionally emit `split_le` and 8-bit `range_check` gates; those are boundaries, and the
*value* semantics of both directions is the one transcribed here. -/

/-- Big-endian byte split of one u32 limb. -/
def u32ToBytesBe (x : Nat) : List Nat :=
  [x / 16777216 % 256, x / 65536 % 256, x / 256 % 256, x % 256]

/-- Big-endian recomposition of four bytes into one limb. -/
def be4 (a b c d : Nat) : Nat := ((a * 256 + b) * 256 + c) * 256 + d

/-- `to_bytes_be`: concatenate the big-endian bytes of every limb, most significant limb first. -/
def bytesOfLimbs : List Nat → List Nat
  | [] => []
  | x :: xs => u32ToBytesBe x ++ bytesOfLimbs xs

/-- `from_bytes_be`: chunk into groups of four bytes, most significant first. A trailing partial
chunk is dropped; every call site in the four modelled files supplies a multiple of four. -/
def limbsOfBytes : List Nat → List Nat
  | a :: b :: c :: d :: rest => be4 a b c d :: limbsOfBytes rest
  | _ => []

/-- Every produced byte is a byte. -/
theorem u32_to_bytes_be_are_bytes (x : Nat) : ∀ b ∈ u32ToBytesBe x, b < 256 := by
  intro b hb
  simp only [u32ToBytesBe, List.mem_cons, List.not_mem_nil, or_false] at hb
  rcases hb with h | h | h | h <;> subst h <;> omega

theorem u32_to_bytes_be_length (x : Nat) : (u32ToBytesBe x).length = 4 := rfl

theorem bytes_of_limbs_length (l : List Nat) : (bytesOfLimbs l).length = 4 * l.length := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
      show (u32ToBytesBe x ++ bytesOfLimbs xs).length = _
      simp only [List.length_append, u32_to_bytes_be_length, ih, List.length_cons]
      omega

/-- One limb round-trips through its four big-endian bytes. -/
theorem be4_of_u32_to_bytes_be {x : Nat} (h : x < 4294967296) :
    be4 (x / 16777216 % 256) (x / 65536 % 256) (x / 256 % 256) (x % 256) = x := by
  simp only [be4]
  omega

/-- `from_bytes_be ∘ to_bytes_be = id` on well-formed (32-bit) limbs. This is the injectivity of
the byte encoder used by both recipient constructors. -/
theorem limbs_of_bytes_of_limbs {l : List Nat} (h : ∀ x ∈ l, x < 4294967296) :
    limbsOfBytes (bytesOfLimbs l) = l := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
      have hx : x < 4294967296 := h x (List.mem_cons_self _ _)
      have hxs : ∀ y ∈ xs, y < 4294967296 := fun y hy => h y (List.mem_cons_of_mem _ hy)
      show limbsOfBytes (u32ToBytesBe x ++ bytesOfLimbs xs) = x :: xs
      simp only [u32ToBytesBe, List.cons_append, List.append_eq, List.nil_append, limbsOfBytes]
      rw [ih hxs, be4_of_u32_to_bytes_be hx]

/-- `to_bytes_be` is injective on well-formed limb vectors. -/
theorem bytes_of_limbs_injective {l m : List Nat}
    (hl : ∀ x ∈ l, x < 4294967296) (hm : ∀ x ∈ m, x < 4294967296)
    (h : bytesOfLimbs l = bytesOfLimbs m) : l = m := by
  have := limbs_of_bytes_of_limbs hl
  rw [h, limbs_of_bytes_of_limbs hm] at this
  exact this.symm

/-! ## Tag replacement

Both native recipient constructors serialise to 32 bytes, overwrite byte 0 with the tag, and
parse the bytes back (`recipient.rs` lines 34-36 and 61-63). The circuit constructor for the
address form builds the 32 bytes directly (lines 73-77). -/

/-- `bytes[0] = tag; Bytes32::from_bytes_be(&bytes)`. -/
def retag (tag : Nat) (limbs : List Nat) : List Nat :=
  limbsOfBytes (tag :: (bytesOfLimbs limbs).drop 1)

/-- Closed form of the tag replacement: the tag lands in the top byte of limb 0 and the low 24
bits of limb 0 survive; every other limb is untouched.

SECURITY: the top 8 bits of the first limb are DESTROYED, so a tagged recipient commits to at
most 248 bits of whatever it was built from. -/
theorem retag_cons {tag x : Nat} {xs : List Nat} (hxs : ∀ y ∈ xs, y < 4294967296) :
    retag tag (x :: xs) = (tag * 16777216 + x % 16777216) :: xs := by
  show limbsOfBytes (tag :: (u32ToBytesBe x ++ bytesOfLimbs xs).drop 1) = _
  simp only [u32ToBytesBe, List.cons_append, List.append_eq, List.nil_append, List.drop_succ_cons,
    List.drop_zero, limbsOfBytes]
  rw [limbs_of_bytes_of_limbs hxs]
  have : be4 tag (x / 65536 % 256) (x / 256 % 256) (x % 256)
      = tag * 16777216 + x % 16777216 := by
    simp only [be4]; omega
  rw [this]

/-- Two limb vectors that agree except on the top byte of limb 0 retag to the SAME value. -/
theorem retag_ignores_top_byte {tag x y : Nat} {xs : List Nat}
    (hxs : ∀ z ∈ xs, z < 4294967296) (h : x % 16777216 = y % 16777216) :
    retag tag (x :: xs) = retag tag (y :: xs) := by
  rw [retag_cons hxs, retag_cons hxs, h]


/-! ## Except plumbing

The native `verify` methods are sequences of early-returning checks; they are modelled as
`Except` do-blocks so that error precedence is part of the model rather than a comment. -/

/-- One early-returning check. -/
def check {ε : Type} (c : Bool) (e : ε) : Except ε Unit := if c then .ok () else .error e

theorem check_ok_iff {ε : Type} {c : Bool} {e : ε} : check c e = .ok () ↔ c = true := by
  cases c <;> simp [check]

theorem check_error_iff {ε : Type} {c : Bool} {e f : ε} :
    check c e = .error f ↔ (c = false ∧ e = f) := by
  cases c <;> simp [check]

theorem unit_bind_ok_iff {ε α : Type} {x : Except ε Unit} {f : Unit → Except ε α} {a : α} :
    (x >>= f) = .ok a ↔ (x = .ok () ∧ f () = .ok a) := by
  cases x with
  | error e => simp [Bind.bind, Except.bind]
  | ok u => cases u; simp [Bind.bind, Except.bind]

/-! ## Merkle opening interface (boundary)

Neither the leaf hashing nor the path folding is modelled: `IncrementalMerkleProof::verify`,
`SparseMerkleProof::verify` and `MerkleProofTarget::verify` are opaque decision procedures. The
one structural fact transcribed here is the index truncation of `BitPath`
(src/utils/trees/bit_path.rs lines 33-41): `get_root` pops exactly `siblings.len()` bits off the
low end of the index, so the native verifier cannot distinguish `i` from `i % 2 ^ height`. -/

structure MerkleProof where
  siblings : List Hash4
  deriving Repr

/-- `MerkleProof::height()` is `siblings.len()`; the `*Target::new(builder, h)` constructors
allocate exactly `h` sibling hashes. -/
def MerkleProof.height (p : MerkleProof) : Nat := p.siblings.length

/-- Opaque leaf-hash and opening callbacks for one tree. -/
structure MerkleEnv (Leaf : Type) where
  leafHash : Leaf → Hash4
  verify : MerkleProof → Leaf → Nat → Hash4 → Bool
  truncates : ∀ p l i r, verify p l i r = verify p l (i % 2 ^ p.height) r

/-- The always-accepting opening oracle, used only to exhibit satisfying witnesses. -/
def acceptingEnv (Leaf : Type) (lh : Leaf → Hash4) : MerkleEnv Leaf where
  leafHash := lh
  verify := fun _ _ _ _ => true
  truncates := by intro p l i r; rfl

/-! ## `account_state.rs`

`AccountState` (source lines 33-43) witnesses that a channel's `SendLeaf` sits at
`send_leaf_index` of the send tree whose root is stored in the channel's `ChannelLeaf`, and that
this `ChannelLeaf` sits at index `channel_id` of the account tree. The leaf structures come from
src/common/trees/channel_tree.rs; only the fields this file reads are modelled. -/

structure SendLeaf where
  prev : Nat
  cur : Nat
  txTreeRoot : List Nat
  deriving DecidableEq, Repr

structure ChannelLeaf where
  index : Nat
  prev : Nat
  sendTreeRoot : Hash4
  memberPubkeysRoot : Hash4
  deriving DecidableEq, Repr

/-- Source lines 34-43, in declaration order. -/
structure AccountState where
  channelId : Nat
  accountTreeRoot : Hash4
  sendLeaf : SendLeaf
  sendLeafIndex : Nat
  sendMerkleProof : MerkleProof
  channelLeaf : ChannelLeaf
  userMerkleProof : MerkleProof

inductive AccountStateError where
  | invalidSendMerkleProof (message : String)
  | invalidUserMerkleProof (message : String)
  deriving DecidableEq, Repr

/-- `AccountState::verify`, source lines 68-87: send-leaf inclusion first (against the CHANNEL
LEAF's `send_tree_root`), then channel-leaf inclusion at index `channel_id` against
`account_tree_root`. -/
def AccountState.verify (envSend : MerkleEnv SendLeaf) (envChannel : MerkleEnv ChannelLeaf)
    (s : AccountState) : Except AccountStateError Unit := do
  check (envSend.verify s.sendMerkleProof s.sendLeaf s.sendLeafIndex s.channelLeaf.sendTreeRoot)
    (.invalidSendMerkleProof "send leaf is not in the channel leaf's send tree")
  check (envChannel.verify s.userMerkleProof s.channelLeaf s.channelId s.accountTreeRoot)
    (.invalidUserMerkleProof "channel leaf is not in the account tree")

/-- `AccountState::new`, source lines 46-66: assemble, verify, return unchanged. -/
def AccountState.new (envSend : MerkleEnv SendLeaf) (envChannel : MerkleEnv ChannelLeaf)
    (channelId : Nat) (accountTreeRoot : Hash4) (sendLeaf : SendLeaf) (sendLeafIndex : Nat)
    (sendMerkleProof : MerkleProof) (channelLeaf : ChannelLeaf) (userMerkleProof : MerkleProof) :
    Except AccountStateError AccountState := do
  let state : AccountState :=
    { channelId, accountTreeRoot, sendLeaf, sendLeafIndex, sendMerkleProof, channelLeaf,
      userMerkleProof }
  state.verify envSend envChannel
  pure state

theorem account_state_verify_ok_iff (envS : MerkleEnv SendLeaf) (envC : MerkleEnv ChannelLeaf)
    (s : AccountState) :
    s.verify envS envC = .ok () ↔
      (envS.verify s.sendMerkleProof s.sendLeaf s.sendLeafIndex s.channelLeaf.sendTreeRoot = true ∧
       envC.verify s.userMerkleProof s.channelLeaf s.channelId s.accountTreeRoot = true) := by
  simp only [AccountState.verify, unit_bind_ok_iff, check_ok_iff]

/-- Error precedence: a failing send-leaf opening is reported even when the channel-leaf opening
would also fail. -/
theorem account_state_send_proof_checked_first (envS : MerkleEnv SendLeaf)
    (envC : MerkleEnv ChannelLeaf) (s : AccountState)
    (h : envS.verify s.sendMerkleProof s.sendLeaf s.sendLeafIndex s.channelLeaf.sendTreeRoot
        = false) :
    s.verify envS envC =
      .error (.invalidSendMerkleProof "send leaf is not in the channel leaf's send tree") := by
  simp [AccountState.verify, check, h, Bind.bind, Except.bind]

/-- The send opening is checked against the channel leaf's own `send_tree_root` field, so a
prover cannot supply an unrelated send-tree root. -/
theorem account_state_send_root_comes_from_channel_leaf (envS : MerkleEnv SendLeaf)
    (envC : MerkleEnv ChannelLeaf) (s : AccountState) (h : s.verify envS envC = .ok ()) :
    envS.verify s.sendMerkleProof s.sendLeaf s.sendLeafIndex s.channelLeaf.sendTreeRoot = true :=
  ((account_state_verify_ok_iff envS envC s).mp h).1

/-- The channel-leaf opening index is the `channel_id` field itself, not a free index. -/
theorem account_state_user_proof_index_is_channel_id (envS : MerkleEnv SendLeaf)
    (envC : MerkleEnv ChannelLeaf) (s : AccountState) (h : s.verify envS envC = .ok ()) :
    envC.verify s.userMerkleProof s.channelLeaf s.channelId s.accountTreeRoot = true :=
  ((account_state_verify_ok_iff envS envC s).mp h).2

/-- `new` performs no normalisation: the returned value is exactly the argument tuple. -/
theorem account_state_new_returns_arguments (envS : MerkleEnv SendLeaf)
    (envC : MerkleEnv ChannelLeaf) (cid : Nat) (root : Hash4) (sl : SendLeaf) (sli : Nat)
    (smp : MerkleProof) (cl : ChannelLeaf) (ump : MerkleProof) (s : AccountState)
    (h : AccountState.new envS envC cid root sl sli smp cl ump = .ok s) :
    s = { channelId := cid, accountTreeRoot := root, sendLeaf := sl, sendLeafIndex := sli,
          sendMerkleProof := smp, channelLeaf := cl, userMerkleProof := ump } := by
  simp only [AccountState.new, unit_bind_ok_iff] at h
  exact (Except.ok.inj h.2).symm

theorem account_state_new_ok_implies_verify (envS : MerkleEnv SendLeaf)
    (envC : MerkleEnv ChannelLeaf) (cid : Nat) (root : Hash4) (sl : SendLeaf) (sli : Nat)
    (smp : MerkleProof) (cl : ChannelLeaf) (ump : MerkleProof) (s : AccountState)
    (h : AccountState.new envS envC cid root sl sli smp cl ump = .ok s) :
    s.verify envS envC = .ok () := by
  have hs := account_state_new_returns_arguments envS envC cid root sl sli smp cl ump s h
  simp only [AccountState.new, unit_bind_ok_iff] at h
  subst hs
  exact h.1

end Zkp.Implementation.BalanceWitnesses
