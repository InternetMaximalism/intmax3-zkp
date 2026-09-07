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
tagged-recipient codec, and the exact difference between the native `new`/`verify` acceptance
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
def check {ε : Type} (c : Prop) [Decidable c] (e : ε) : Except ε Unit :=
  if c then .ok () else .error e

theorem check_ok_iff {ε : Type} {c : Prop} [Decidable c] {e : ε} : check c e = .ok () ↔ c := by
  by_cases h : c <;> simp [check, h]

theorem check_error_iff {ε : Type} {c : Prop} [Decidable c] {e f : ε} :
    check c e = .error f ↔ (¬ c ∧ e = f) := by
  by_cases h : c <;> simp [check, h]

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
  check (envSend.verify s.sendMerkleProof s.sendLeaf s.sendLeafIndex s.channelLeaf.sendTreeRoot
      = true)
    (.invalidSendMerkleProof "send leaf is not in the channel leaf's send tree")
  check (envChannel.verify s.userMerkleProof s.channelLeaf s.channelId s.accountTreeRoot = true)
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


/-! ## `recipient.rs`

A `recipient` is a `Bytes32` (8 u32 limbs) whose leading byte is a domain tag. Tag `1` marks an
intmax-internal recipient derived from `(channel_id, salt)`; tag `2` marks an L1 address in the
low 20 bytes with 11 zero padding bytes in between. -/

/-- Poseidon, opaque. Native `PoseidonHashOut::hash_inputs_u64` and in-circuit
`PoseidonHashOutTarget::hash_inputs` are both instances of this callback; that they agree is a
premise, never a conclusion. -/
abbrev HashFn := List Nat → Hash4

/-- Goldilocks elements are stored as `u64`; this is the only bound the model needs and it is NOT
a canonicality (`< p`) claim. -/
def Hash4Bounded (h : Hash4) : Prop :=
  h.a < 18446744073709551616 ∧ h.b < 18446744073709551616 ∧
  h.c < 18446744073709551616 ∧ h.d < 18446744073709551616

/-- `impl From<PoseidonHashOut> for Bytes32` (src/utils/poseidon_hash_out.rs lines 239-252):
each u64 element becomes the limb pair `[high, low]`. -/
def hashOutToBytes32Limbs (h : Hash4) : List Nat :=
  [h.a / 4294967296, h.a % 4294967296, h.b / 4294967296, h.b % 4294967296,
   h.c / 4294967296, h.c % 4294967296, h.d / 4294967296, h.d % 4294967296]

/-- `Bytes32Target::from_hash_out` (src/utils/poseidon_hash_out.rs lines 288-301): the same
`[high, low]` order, obtained by `safe_split_lo_and_hi`. Transcribed separately so the agreement
below compares two transcriptions. -/
def fromHashOutTargetLimbs (h : Hash4) : List Nat :=
  [h.a / 4294967296, h.a % 4294967296, h.b / 4294967296, h.b % 4294967296,
   h.c / 4294967296, h.c % 4294967296, h.d / 4294967296, h.d % 4294967296]

theorem hash_out_limb_order_agrees (h : Hash4) :
    hashOutToBytes32Limbs h = fromHashOutTargetLimbs h := rfl

theorem hash_out_to_bytes32_limbs_length (h : Hash4) :
    (hashOutToBytes32Limbs h).length = bytes32Len := rfl

theorem hash_out_limbs_are_u32 {h : Hash4} (hb : Hash4Bounded h) :
    ∀ x ∈ hashOutToBytes32Limbs h, x < 4294967296 := by
  obtain ⟨ha, hbb, hc, hd⟩ := hb
  intro x hx
  simp only [hashOutToBytes32Limbs, List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases hx with h1 | h1 | h1 | h1 | h1 | h1 | h1 | h1 <;> subst h1 <;> omega

/-- `calculate_recipient_from_user_id`, source line 30: `[USER_ID_DOMAIN, channel_id] ++ salt`. -/
def userIdHashInputsNative (channelId : Nat) (salt : Hash4) : List Nat :=
  [userIdDomain, channelId] ++ hashWords salt

/-- `calculate_recipient_from_user_id_circuit`, source lines 44-48: the constant domain, the
channel-id target, then the four salt targets. Transcribed separately. -/
def userIdHashInputsTarget (channelId : Nat) (salt : Hash4) : List Nat :=
  [userIdDomain, channelId] ++ hashWords salt

theorem user_id_hash_inputs_order_agrees (channelId : Nat) (salt : Hash4) :
    userIdHashInputsNative channelId salt = userIdHashInputsTarget channelId salt := rfl

/-- The Poseidon preimage is exactly six field elements: domain, channel id, four salt words. -/
theorem user_id_hash_inputs_length (channelId : Nat) (salt : Hash4) :
    (userIdHashInputsNative channelId salt).length = 6 := by
  simp [userIdHashInputsNative, hashWords]

theorem user_id_hash_inputs_domain_first (channelId : Nat) (salt : Hash4) :
    (userIdHashInputsNative channelId salt).head? = some userIdDomain := rfl

theorem user_id_hash_inputs_channel_id_second (channelId : Nat) (salt : Hash4) :
    (userIdHashInputsNative channelId salt)[1]? = some channelId := by simp [userIdHashInputsNative]

theorem user_id_hash_inputs_salt_last (channelId : Nat) (salt : Hash4) :
    (userIdHashInputsNative channelId salt).drop 2 = hashWords salt := by
  simp [userIdHashInputsNative, hashWords]

/-- `calculate_recipient_from_user_id`, source lines 29-37. -/
def recipientFromUserIdNative (hash : HashFn) (channelId : Nat) (salt : Hash4) : List Nat :=
  retag userIdTag (hashOutToBytes32Limbs (hash (userIdHashInputsNative channelId salt)))

/-- `calculate_recipient_from_user_id_circuit`, source lines 39-55. -/
def recipientFromUserIdTarget (hash : HashFn) (channelId : Nat) (salt : Hash4) : List Nat :=
  retag userIdTag (fromHashOutTargetLimbs (hash (userIdHashInputsTarget channelId salt)))

/-- Native and circuit constructions agree AS VALUE FUNCTIONS, for any single hash callback. That
the native Poseidon and the in-circuit Poseidon gadget are the same function is a boundary. -/
theorem recipient_from_user_id_native_target_agree (hash : HashFn) (channelId : Nat)
    (salt : Hash4) :
    recipientFromUserIdNative hash channelId salt = recipientFromUserIdTarget hash channelId salt :=
  rfl

/-- `calculate_recipient_from_address`, source lines 57-64: three zero limbs, then the five
address limbs, then byte 0 is overwritten with `ADDRESS_TAG`. -/
def recipientFromAddressNative (addr : List Nat) : List Nat :=
  retag addressTag ([0, 0, 0] ++ addr)

/-- `calculate_recipient_from_address_circuit`, source lines 69-78: 32 zero bytes, byte 0 set to
`ADDRESS_TAG`, bytes 12.. set to the address bytes. Transcribed separately from the native form. -/
def recipientFromAddressTarget (addr : List Nat) : List Nat :=
  limbsOfBytes (addressTag :: (List.replicate 11 0 ++ bytesOfLimbs addr))

theorem recipient_from_address_native_form {addr : List Nat}
    (h : ∀ x ∈ addr, x < 4294967296) :
    recipientFromAddressNative addr = 33554432 :: 0 :: 0 :: addr := by
  have h' : ∀ y ∈ (0 :: 0 :: addr), y < 4294967296 := by
    intro y hy
    simp only [List.mem_cons] at hy
    rcases hy with h1 | h1 | h1
    · omega
    · omega
    · exact h y h1
  show retag addressTag (0 :: (0 :: 0 :: addr)) = _
  rw [retag_cons h']
  rfl

theorem recipient_from_address_target_form {addr : List Nat}
    (h : ∀ x ∈ addr, x < 4294967296) :
    recipientFromAddressTarget addr = 33554432 :: 0 :: 0 :: addr := by
  have hrep : List.replicate 11 (0 : Nat) = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] := rfl
  show limbsOfBytes (addressTag :: (List.replicate 11 0 ++ bytesOfLimbs addr)) = _
  rw [hrep]
  simp only [List.cons_append, List.nil_append, List.append_eq, limbsOfBytes]
  rw [limbs_of_bytes_of_limbs h]
  rfl

/-- The two constructions of the tagged address recipient coincide. This is exactly the property
the source docstring (lines 66-68) relies on to forbid non-zero padding. -/
theorem recipient_from_address_native_target_agree {addr : List Nat}
    (h : ∀ x ∈ addr, x < 4294967296) :
    recipientFromAddressNative addr = recipientFromAddressTarget addr := by
  rw [recipient_from_address_native_form h, recipient_from_address_target_form h]

theorem recipient_from_address_length {addr : List Nat} (hlen : addr.length = addressLen)
    (h : ∀ x ∈ addr, x < 4294967296) :
    (recipientFromAddressNative addr).length = bytes32Len := by
  rw [recipient_from_address_native_form h]
  simp [bytes32Len, addressLen] at hlen ⊢
  omega

/-- The canonical address recipient has tag byte 2 and eleven zero padding bytes. -/
theorem recipient_from_address_padding_is_zero {addr : List Nat}
    (h : ∀ x ∈ addr, x < 4294967296) :
    (recipientFromAddressNative addr).take 3 = [33554432, 0, 0] := by
  rw [recipient_from_address_native_form h]
  rfl

/-- The address is recoverable from the recipient, so the encoding is injective on addresses. -/
theorem recipient_from_address_injective {a b : List Nat}
    (ha : ∀ x ∈ a, x < 4294967296) (hb : ∀ x ∈ b, x < 4294967296)
    (h : recipientFromAddressNative a = recipientFromAddressNative b) : a = b := by
  rw [recipient_from_address_native_form ha, recipient_from_address_native_form hb] at h
  exact (List.cons.inj (List.cons.inj (List.cons.inj h).2).2).2

/-- The leading byte of a limb vector whose first limb is `tag * 2 ^ 24 + r`. -/
theorem head_byte_of_tagged {t r : Nat} {xs : List Nat} (ht : t < 256) (hr : r < 16777216) :
    (bytesOfLimbs ((t * 16777216 + r) :: xs)).head? = some t := by
  show (u32ToBytesBe (t * 16777216 + r) ++ bytesOfLimbs xs).head? = some t
  simp only [u32ToBytesBe, List.cons_append, List.head?_cons, Option.some.injEq]
  omega

inductive RecipientError where
  | invalidRecipient (message : String)
  deriving DecidableEq, Repr

/-- `extract_address_from_recipient`, source lines 80-96. Check the tag byte, take bytes 12..32 as
the address, then re-derive the canonical recipient and compare: the second check is what rejects
non-zero padding in bytes 1..11. -/
def extractAddressFromRecipient (recipient : List Nat) : Except RecipientError (List Nat) :=
  if (bytesOfLimbs recipient).head? ≠ some addressTag then
    .error (.invalidRecipient "Invalid recipient tag")
  else if recipient ≠ recipientFromAddressNative
      (limbsOfBytes (((bytesOfLimbs recipient).drop 12).take 20)) then
    .error (.invalidRecipient "non-canonical ADDRESS_TAG recipient: bytes 1..11 must be zero")
  else
    .ok (limbsOfBytes (((bytesOfLimbs recipient).drop 12).take 20))

/-- Whatever the extractor accepts is exactly the canonical encoding of the address it returns.
This is the fund-safety property the withdrawal path depends on: the L1 payee is a function of
the recipient, and the recipient is a function of the payee. -/
theorem extract_ok_implies_canonical {recipient addr : List Nat}
    (h : extractAddressFromRecipient recipient = .ok addr) :
    recipient = recipientFromAddressNative addr := by
  unfold extractAddressFromRecipient at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · rename_i h2
      have haddr : limbsOfBytes (((bytesOfLimbs recipient).drop 12).take 20) = addr :=
        Except.ok.inj h
      rw [haddr] at h2
      simpa using h2

/-- Two different recipients can never extract to the same address. -/
theorem extract_ok_recipient_unique {r1 r2 addr : List Nat}
    (h1 : extractAddressFromRecipient r1 = .ok addr)
    (h2 : extractAddressFromRecipient r2 = .ok addr) : r1 = r2 := by
  rw [extract_ok_implies_canonical h1, extract_ok_implies_canonical h2]

/-- Round trip: a canonically built address recipient extracts back to the address. -/
theorem extract_of_recipient_from_address {addr : List Nat} (hlen : addr.length = 5)
    (h : ∀ x ∈ addr, x < 4294967296) :
    extractAddressFromRecipient (recipientFromAddressNative addr) = .ok addr := by
  have hform := recipient_from_address_native_form h
  have hbytes : bytesOfLimbs (recipientFromAddressNative addr)
      = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] ++ bytesOfLimbs addr := by
    rw [hform]; rfl
  have hlen20 : (bytesOfLimbs addr).length = 20 := by
    rw [bytes_of_limbs_length, hlen]
  have hextract :
      limbsOfBytes (((bytesOfLimbs (recipientFromAddressNative addr)).drop 12).take 20) = addr := by
    rw [hbytes]
    have hdrop : ([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] ++ bytesOfLimbs addr).drop 12
        = bytesOfLimbs addr := by simp
    rw [hdrop, ← hlen20, List.take_length, limbs_of_bytes_of_limbs h]
  have hhead : (bytesOfLimbs (recipientFromAddressNative addr)).head? = some addressTag := by
    rw [hbytes]; rfl
  unfold extractAddressFromRecipient
  rw [hextract, hhead]
  simp

/-- Any tag-1 recipient is rejected by the address extractor, whatever its remaining limbs. -/
theorem extract_rejects_tag_one {x : Nat} {xs : List Nat} (hxs : ∀ y ∈ xs, y < 4294967296) :
    extractAddressFromRecipient (retag userIdTag (x :: xs))
      = .error (.invalidRecipient "Invalid recipient tag") := by
  rw [retag_cons hxs]
  have hhead := head_byte_of_tagged (t := userIdTag) (r := x % 16777216) (xs := xs)
    (by decide) (by omega)
  unfold extractAddressFromRecipient
  rw [hhead]
  simp [userIdTag, addressTag]

/-- A tag-1 (user-id) recipient is NEVER accepted as an address recipient. Without this the
withdrawal path could pay an L1 address derived from an intmax-internal recipient. -/
theorem extract_rejects_user_id_recipient (hash : HashFn) (channelId : Nat) (salt : Hash4)
    (hb : Hash4Bounded (hash (userIdHashInputsNative channelId salt))) :
    extractAddressFromRecipient (recipientFromUserIdNative hash channelId salt)
      = .error (.invalidRecipient "Invalid recipient tag") := by
  have htail : ∀ y ∈ (hashOutToBytes32Limbs (hash (userIdHashInputsNative channelId salt))).drop 1,
      y < 4294967296 := by
    intro y hy
    obtain ⟨_ha, hbb, hc, hd⟩ := hb
    simp only [hashOutToBytes32Limbs, List.drop_succ_cons, List.drop_zero, List.mem_cons,
      List.not_mem_nil, or_false] at hy
    rcases hy with h1 | h1 | h1 | h1 | h1 | h1 | h1 <;> subst h1 <;> omega -- uses hbb..hd
  exact extract_rejects_tag_one
    (x := (hash (userIdHashInputsNative channelId salt)).a / 4294967296) htail

/-- SECURITY: the tag byte overwrites the top byte of the Poseidon output, so a user-id recipient
commits to only 248 of the 256 bits. Two DISTINCT hash outputs give the SAME recipient. -/
theorem user_id_recipient_forgets_top_hash_byte :
    (⟨72057594037927936, 0, 0, 0⟩ : Hash4) ≠ (⟨0, 0, 0, 0⟩ : Hash4) ∧
      retag userIdTag (hashOutToBytes32Limbs ⟨72057594037927936, 0, 0, 0⟩)
        = retag userIdTag (hashOutToBytes32Limbs ⟨0, 0, 0, 0⟩) := by
  constructor
  · intro h; exact absurd (congrArg Hash4.a h) (by decide)
  · decide

/-- Circuit form of `extract_address_from_recipient_circuit` (source lines 98-107). The address
limbs are 32-bit because `AddressTarget::from_bytes_be` 8-bit range-checks every byte; the final
`connect` is the `canonical` equality. -/
structure ExtractAddressGates (recipient address : List Nat) : Prop where
  addressLength : address.length = addressLen
  addressLimbsChecked : ∀ x ∈ address, x < limbModulus
  addressFromBytes : address = limbsOfBytes (((bytesOfLimbs recipient).drop 12).take 20)
  connected : recipient = recipientFromAddressTarget address

/-- Any witness satisfying the extraction gates is accepted by the native extractor with the same
address: the circuit is at least as strict as `extract_address_from_recipient`. -/
theorem extract_gates_imply_native_ok {recipient address : List Nat}
    (g : ExtractAddressGates recipient address) :
    extractAddressFromRecipient recipient = .ok address := by
  have hb : ∀ x ∈ address, x < 4294967296 := g.addressLimbsChecked
  have hrec : recipient = recipientFromAddressNative address := by
    rw [recipient_from_address_native_target_agree hb]; exact g.connected
  rw [hrec]
  exact extract_of_recipient_from_address (by rw [g.addressLength]; rfl) hb

/-! ### Concrete traces (recipient) -/

/-- `Address::from_hex("0x1234567890abcdef1234567890abcdef12345678")` as five u32 limbs. -/
def exampleAddress : List Nat :=
  [305419896, 2427178479, 305419896, 2427178479, 305419896]

/-- The expected recipient from the source test at lines 155-160:
`0x0200000000000000000000001234567890abcdef1234567890abcdef12345678`. -/
def exampleAddressRecipient : List Nat :=
  [33554432, 0, 0, 305419896, 2427178479, 305419896, 2427178479, 305419896]

theorem example_address_recipient_matches_source_test :
    recipientFromAddressNative exampleAddress = exampleAddressRecipient := by decide

theorem example_address_recipient_extracts :
    extractAddressFromRecipient exampleAddressRecipient = .ok exampleAddress := by rfl

/-- The source test at lines 175-199 flips a bit of padding byte 7; both the native extractor and
the circuit must reject it. Byte 7 is the low byte of limb 1. -/
def exampleMalformedRecipient : List Nat :=
  [33554432, 1, 0, 305419896, 2427178479, 305419896, 2427178479, 305419896]

theorem example_nonzero_padding_rejected :
    extractAddressFromRecipient exampleMalformedRecipient
      = .error (.invalidRecipient
          "non-canonical ADDRESS_TAG recipient: bytes 1..11 must be zero") := by rfl

/-- The same malformed recipient cannot satisfy the circuit gates either. -/
theorem example_nonzero_padding_unsatisfiable (address : List Nat) :
    ¬ ExtractAddressGates exampleMalformedRecipient address := by
  intro g
  have := extract_gates_imply_native_ok g
  rw [example_nonzero_padding_rejected] at this
  exact absurd this (by simp)


/-! ## Deposit leaf and its nullifier preimage

`src/common/deposit.rs` is not one of the modelled files, but `deposit_witness.rs` reads the leaf
field by field and the nullifier preimage is the security-relevant part of the witness, so the
layout is transcribed here. -/

/-- `Deposit` (src/common/deposit.rs lines 32-53) in declaration order. -/
structure Deposit where
  depositIndex : Nat
  blockNumber : Nat
  depositor : List Nat
  recipient : List Nat
  tokenIndex : Nat
  amount : List Nat
  auxData : List Nat
  deriving DecidableEq, Repr

structure DepositWellFormed (d : Deposit) : Prop where
  depositorLen : d.depositor.length = addressLen
  recipientLen : d.recipient.length = bytes32Len
  amountLen : d.amount.length = u256Len
  auxLen : d.auxData.length = bytes32Len

/-- `Deposit::to_u64_vec` (src/common/deposit.rs lines 68-78). -/
def Deposit.wordsNative (d : Deposit) : List Nat :=
  [d.depositIndex, d.blockNumber] ++ d.depositor ++ d.recipient ++ [d.tokenIndex] ++ d.amount ++
    d.auxData

/-- `DepositTarget::to_u64_vec` (src/common/deposit.rs lines 116-126), transcribed separately. -/
def Deposit.wordsTarget (d : Deposit) : List Nat :=
  [d.depositIndex, d.blockNumber] ++ d.depositor ++ d.recipient ++ [d.tokenIndex] ++ d.amount ++
    d.auxData

theorem deposit_words_order_agrees (d : Deposit) : d.wordsNative = d.wordsTarget := rfl

theorem deposit_nullifier_preimage_length {d : Deposit} (h : DepositWellFormed d) :
    d.wordsNative.length = 32 := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  simp only [Deposit.wordsNative, List.length_append, List.length_cons, List.length_nil,
    h1, h2, h3, h4, addressLen, bytes32Len, u256Len]

/-- `Deposit::nullifier` = `Bytes32::from(self.poseidon_hash())`. -/
def Deposit.nullifier (hash : HashFn) (d : Deposit) : List Nat :=
  hashOutToBytes32Limbs (hash d.wordsNative)

theorem deposit_preimage_starts_with_index (d : Deposit) :
    d.wordsNative.head? = some d.depositIndex := rfl

theorem deposit_preimage_block_number_second (d : Deposit) :
    d.wordsNative[1]? = some d.blockNumber := by simp [Deposit.wordsNative]

theorem hash_out_to_bytes32_limbs_injective {h1 h2 : Hash4}
    (h : hashOutToBytes32Limbs h1 = hashOutToBytes32Limbs h2) : h1 = h2 := by
  obtain ⟨a1, b1, c1, d1⟩ := h1
  obtain ⟨a2, b2, c2, d2⟩ := h2
  simp only [hashOutToBytes32Limbs, List.cons.injEq, and_true] at h
  obtain ⟨e1, e2, e3, e4, e5, e6, e7, e8⟩ := h
  have ha : a1 = a2 := by omega
  have hb : b1 = b2 := by omega
  have hc : c1 = c2 := by omega
  have hd : d1 = d2 := by omega
  subst ha; subst hb; subst hc; subst hd; rfl

/-- SECURITY (deposit.rs lines 36-39): `deposit_index` is the field that makes the nullifier
unique per real deposit. Two deposits that differ only in the index have different preimages, so
under an injectivity premise ON THIS PAIR they have different nullifiers. -/
theorem deposit_nullifier_binds_deposit_index (hash : HashFn) (a b : Deposit)
    (hinj : hash a.wordsNative = hash b.wordsNative → a.wordsNative = b.wordsNative)
    (hne : a.depositIndex ≠ b.depositIndex) :
    Deposit.nullifier hash a ≠ Deposit.nullifier hash b := by
  intro heq
  have hh : hash a.wordsNative = hash b.wordsNative :=
    hash_out_to_bytes32_limbs_injective heq
  have hw := hinj hh
  have : a.depositIndex = b.depositIndex := by
    have := congrArg List.head? hw
    simpa [Deposit.wordsNative] using this
  exact hne this

/-! ## `deposit_witness.rs` -/

/-- `DepositWitness` (source lines 39-46) and `DepositWitnessTarget` (lines 48-55) carry the same
five fields in the same order. -/
structure DepositWitness where
  channelId : Nat
  depositTreeRoot : Hash4
  depositSalt : Hash4
  deposit : Deposit
  depositMerkleProof : MerkleProof

inductive DepositWitnessError where
  | invalidDepositIndex (message : String)
  | invalidDepositMerkleProof (message : String)
  | invalidRecipient (message : String)
  deriving DecidableEq, Repr

/-- `DepositWitness::verify`, source lines 76-100: index range, then the deposit-tree opening AT
THE LEAF'S OWN `deposit_index`, then the recipient binding to `(channel_id, deposit_salt)`. -/
def DepositWitness.verify (env : MerkleEnv Deposit) (hash : HashFn) (w : DepositWitness) :
    Except DepositWitnessError Unit := do
  check (w.deposit.depositIndex < 2 ^ depositTreeHeight)
    (.invalidDepositIndex "index is out of range")
  check (env.verify w.depositMerkleProof w.deposit w.deposit.depositIndex w.depositTreeRoot = true)
    (.invalidDepositMerkleProof "deposit is not in the deposit tree")
  check (w.deposit.recipient = recipientFromUserIdNative hash w.channelId w.depositSalt)
    (.invalidRecipient "deposit recipient does not match (channel_id, salt)")

/-- `DepositWitness::new`, source lines 58-74. -/
def DepositWitness.new (env : MerkleEnv Deposit) (hash : HashFn) (channelId : Nat)
    (depositTreeRoot : Hash4) (depositSalt : Hash4) (deposit : Deposit)
    (depositMerkleProof : MerkleProof) : Except DepositWitnessError DepositWitness := do
  let witness : DepositWitness :=
    { channelId, depositTreeRoot, depositSalt, deposit, depositMerkleProof }
  witness.verify env hash
  pure witness

theorem deposit_witness_verify_ok_iff (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) :
    w.verify env hash = .ok () ↔
      (w.deposit.depositIndex < 2 ^ depositTreeHeight ∧
       env.verify w.depositMerkleProof w.deposit w.deposit.depositIndex w.depositTreeRoot = true ∧
       w.deposit.recipient = recipientFromUserIdNative hash w.channelId w.depositSalt) := by
  simp only [DepositWitness.verify, unit_bind_ok_iff, check_ok_iff, and_assoc]

/-- Error precedence: an out-of-range deposit index is reported before the Merkle proof is even
consulted. -/
theorem deposit_index_checked_before_merkle (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) (h : ¬ w.deposit.depositIndex < 2 ^ depositTreeHeight) :
    w.verify env hash = .error (.invalidDepositIndex "index is out of range") := by
  simp [DepositWitness.verify, check, h, Bind.bind, Except.bind]

theorem deposit_witness_ok_implies_index_in_range (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) (h : w.verify env hash = .ok ()) :
    w.deposit.depositIndex < 2 ^ depositTreeHeight :=
  ((deposit_witness_verify_ok_iff env hash w).mp h).1

/-- The tree position proved is the leaf's OWN `deposit_index` field, not an independent witness
value; this is what ties the nullifier's uniqueness field to the tree. -/
theorem deposit_witness_opening_index_is_leaf_field (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) (h : w.verify env hash = .ok ()) :
    env.verify w.depositMerkleProof w.deposit w.deposit.depositIndex w.depositTreeRoot = true :=
  ((deposit_witness_verify_ok_iff env hash w).mp h).2.1

/-- An accepted deposit witness pins the deposit's recipient to this channel and salt. -/
theorem deposit_witness_ok_binds_recipient (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) (h : w.verify env hash = .ok ()) :
    w.deposit.recipient = recipientFromUserIdNative hash w.channelId w.depositSalt :=
  ((deposit_witness_verify_ok_iff env hash w).mp h).2.2

/-- Cross-check with the withdrawal path: a deposit accepted by this witness carries a tag-1
recipient, which `extract_address_from_recipient` always rejects. -/
theorem deposit_witness_recipient_is_never_an_address (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) (h : w.verify env hash = .ok ())
    (hb : Hash4Bounded (hash (userIdHashInputsNative w.channelId w.depositSalt))) :
    extractAddressFromRecipient w.deposit.recipient
      = .error (.invalidRecipient "Invalid recipient tag") := by
  rw [deposit_witness_ok_binds_recipient env hash w h]
  exact extract_rejects_user_id_recipient hash w.channelId w.depositSalt hb

theorem deposit_witness_new_returns_arguments (env : MerkleEnv Deposit) (hash : HashFn)
    (cid : Nat) (root salt : Hash4) (d : Deposit) (p : MerkleProof) (w : DepositWitness)
    (h : DepositWitness.new env hash cid root salt d p = .ok w) :
    w = { channelId := cid, depositTreeRoot := root, depositSalt := salt, deposit := d,
          depositMerkleProof := p } := by
  simp only [DepositWitness.new, unit_bind_ok_iff] at h
  exact (Except.ok.inj h.2).symm

/-- `DepositWitnessTarget::new` (source lines 104-135) with `is_checked` threaded through
`ChannelIdTarget::new` and `DepositTarget::new`. The range bounds are the ones those constructors
emit; the Merkle opening and the recipient `connect` are unconditional. -/
structure DepositWitnessGates (env : MerkleEnv Deposit) (hash : HashFn) (isChecked : Bool)
    (w : DepositWitness) : Prop where
  channelIdRange : isChecked = true → w.channelId < 2 ^ channelIdBits
  depositIndexRange : isChecked = true → w.deposit.depositIndex < 2 ^ depositTreeHeight
  blockNumberRange : isChecked = true → w.deposit.blockNumber < 2 ^ depositTreeHeight
  tokenIndexRange : isChecked = true → w.deposit.tokenIndex < 2 ^ 32
  proofHeight : w.depositMerkleProof.height = depositTreeHeight
  inclusion :
    env.verify w.depositMerkleProof w.deposit w.deposit.depositIndex w.depositTreeRoot = true
  recipientConnected :
    w.deposit.recipient = recipientFromUserIdTarget hash w.channelId w.depositSalt

/-- With `is_checked = true` (every production caller) a satisfying circuit witness is also
accepted by the native `verify`. -/
theorem deposit_witness_gates_imply_native_verify (env : MerkleEnv Deposit) (hash : HashFn)
    (w : DepositWitness) (g : DepositWitnessGates env hash true w) :
    w.verify env hash = .ok () := by
  refine (deposit_witness_verify_ok_iff env hash w).mpr ⟨g.depositIndexRange rfl, g.inclusion, ?_⟩
  rw [g.recipientConnected, recipient_from_user_id_native_target_agree]

/-- With `is_checked = false` the 63-bit bound disappears: there is a witness satisfying the gates
that the native `verify` rejects as an out-of-range deposit index. -/
theorem deposit_witness_unchecked_accepts_out_of_range_index :
    ∃ (env : MerkleEnv Deposit) (hash : HashFn) (w : DepositWitness),
      DepositWitnessGates env hash false w ∧
      w.verify env hash = .error (.invalidDepositIndex "index is out of range") := by
  refine ⟨acceptingEnv Deposit (fun _ => ⟨0, 0, 0, 0⟩), (fun _ => ⟨0, 0, 0, 0⟩),
    { channelId := 1, depositTreeRoot := ⟨0, 0, 0, 0⟩, depositSalt := ⟨0, 0, 0, 0⟩,
      deposit := { depositIndex := 2 ^ depositTreeHeight, blockNumber := 0, depositor := [],
                   recipient := retag userIdTag (hashOutToBytes32Limbs ⟨0, 0, 0, 0⟩),
                   tokenIndex := 0, amount := [], auxData := [] },
      depositMerkleProof := { siblings := List.replicate depositTreeHeight ⟨0, 0, 0, 0⟩ } },
    ?_, ?_⟩
  · exact { channelIdRange := by intro h; exact absurd h (by decide)
            depositIndexRange := by intro h; exact absurd h (by decide)
            blockNumberRange := by intro h; exact absurd h (by decide)
            tokenIndexRange := by intro h; exact absurd h (by decide)
            proofHeight := by simp [MerkleProof.height]
            inclusion := rfl
            recipientConnected := rfl }
  · exact deposit_index_checked_before_merkle _ _ _ (by simp)

/-! ## Transfer leaf, settled transfer, and `transfer_witness.rs` -/

/-- `Transfer` (src/common/transfer.rs lines 31-36). -/
structure Transfer where
  recipient : List Nat
  tokenIndex : Nat
  amount : List Nat
  auxData : List Nat
  deriving DecidableEq, Repr

structure TransferWellFormed (t : Transfer) : Prop where
  recipientLen : t.recipient.length = bytes32Len
  amountLen : t.amount.length = u256Len
  auxLen : t.auxData.length = bytes32Len

/-- `Transfer::to_u64_vec` (src/common/transfer.rs lines 73-84). -/
def Transfer.wordsNative (t : Transfer) : List Nat :=
  t.recipient ++ [t.tokenIndex] ++ t.amount ++ t.auxData

/-- `TransferTarget::to_vec` (src/common/transfer.rs lines 130-141), transcribed separately. -/
def Transfer.wordsTarget (t : Transfer) : List Nat :=
  t.recipient ++ [t.tokenIndex] ++ t.amount ++ t.auxData

theorem transfer_words_order_agrees (t : Transfer) : t.wordsNative = t.wordsTarget := rfl

/-- Both `to_u64_vec` implementations `assert_eq!(vec.len(), TRANSFER_LEN)`. -/
theorem transfer_words_length {t : Transfer} (h : TransferWellFormed t) :
    t.wordsNative.length = transferLen := by
  obtain ⟨h1, h2, h3⟩ := h
  simp only [Transfer.wordsNative, List.length_append, List.length_cons, List.length_nil,
    h1, h2, h3, transferLen, bytes32Len, u256Len]

/-- `SettledTransfer` (src/common/transfer.rs lines 49-54): the nullifier preimage of a settled
transfer. `from` is the sender channel id. -/
structure SettledTransfer where
  inner : Transfer
  fromChannel : Nat
  transferIndex : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- `SettledTransfer::to_u64_vec` (src/common/transfer.rs lines 110-118). -/
def SettledTransfer.wordsNative (st : SettledTransfer) : List Nat :=
  st.inner.wordsNative ++ [st.fromChannel] ++ [st.transferIndex] ++ [st.nonce]

/-- `SettledTransferTarget::to_vec` (src/common/transfer.rs lines 224-232), transcribed
separately. -/
def SettledTransfer.wordsTarget (st : SettledTransfer) : List Nat :=
  st.inner.wordsTarget ++ [st.fromChannel] ++ [st.transferIndex] ++ [st.nonce]

theorem settled_transfer_words_order_agrees (st : SettledTransfer) :
    st.wordsNative = st.wordsTarget := rfl

theorem settled_transfer_words_length {st : SettledTransfer} (h : TransferWellFormed st.inner) :
    st.wordsNative.length = 28 := by
  simp only [SettledTransfer.wordsNative, List.length_append, List.length_cons, List.length_nil,
    transfer_words_length h, transferLen, bytes32Len, u256Len]

def SettledTransfer.nullifier (hash : HashFn) (st : SettledTransfer) : List Nat :=
  hashOutToBytes32Limbs (hash st.wordsNative)

/-- SECURITY (F-WD-2): the settled-transfer nullifier preimage contains the sender nonce and no
settlement-block field, so it is a function of `(transfer, from, transfer_index, nonce)` only.
Settling the same deduction into two different blocks therefore yields the SAME nullifier. -/
theorem settled_transfer_nullifier_is_settlement_independent (hash : HashFn)
    (a b : SettledTransfer) (hi : a.inner = b.inner) (hf : a.fromChannel = b.fromChannel)
    (hx : a.transferIndex = b.transferIndex) (hn : a.nonce = b.nonce) :
    SettledTransfer.nullifier hash a = SettledTransfer.nullifier hash b := by
  simp only [SettledTransfer.nullifier, SettledTransfer.wordsNative, hi, hf, hx, hn]

/-- The nonce really is part of the preimage: changing only the nonce changes the preimage. -/
theorem settled_transfer_preimage_binds_nonce (a b : SettledTransfer) (hi : a.inner = b.inner)
    (hf : a.fromChannel = b.fromChannel) (hx : a.transferIndex = b.transferIndex)
    (hn : a.nonce ≠ b.nonce) : a.wordsNative ≠ b.wordsNative := by
  intro heq
  simp only [SettledTransfer.wordsNative, hi, hf, hx, List.append_assoc] at heq
  have h2 := List.append_cancel_left heq
  simp at h2
  exact hn h2

/-- `TransferWitness` (source lines 28-33) and `TransferWitnessTarget` (lines 65-70). -/
structure TransferWitness where
  transferTreeRoot : Hash4
  transfer : Transfer
  transferIndex : Nat
  transferMerkleProof : MerkleProof

inductive TransferWitnessError where
  | invalidTransferMerkleProof (message : String)
  deriving DecidableEq, Repr

/-- `TransferWitness::verify`, source lines 52-61: a single Merkle opening and nothing else. -/
def TransferWitness.verify (env : MerkleEnv Transfer) (w : TransferWitness) :
    Except TransferWitnessError Unit := do
  check (env.verify w.transferMerkleProof w.transfer w.transferIndex w.transferTreeRoot = true)
    (.invalidTransferMerkleProof "transfer is not in the transfer tree")

/-- `TransferWitness::new`, source lines 36-50. -/
def TransferWitness.new (env : MerkleEnv Transfer) (transferTreeRoot : Hash4) (transfer : Transfer)
    (transferIndex : Nat) (transferMerkleProof : MerkleProof) :
    Except TransferWitnessError TransferWitness := do
  let witness : TransferWitness :=
    { transferTreeRoot, transfer, transferIndex, transferMerkleProof }
  witness.verify env
  pure witness

theorem transfer_witness_verify_ok_iff (env : MerkleEnv Transfer) (w : TransferWitness) :
    w.verify env = .ok () ↔
      env.verify w.transferMerkleProof w.transfer w.transferIndex w.transferTreeRoot = true := by
  simp only [TransferWitness.verify, unit_bind_ok_iff, check_ok_iff, and_true]

theorem transfer_witness_new_returns_arguments (env : MerkleEnv Transfer) (root : Hash4)
    (t : Transfer) (i : Nat) (p : MerkleProof) (w : TransferWitness)
    (h : TransferWitness.new env root t i p = .ok w) :
    w = { transferTreeRoot := root, transfer := t, transferIndex := i,
          transferMerkleProof := p } := by
  simp only [TransferWitness.new, unit_bind_ok_iff] at h
  exact (Except.ok.inj h.2).symm

/-- SECURITY: the native transfer witness performs NO index range check (contrast
`DepositWitness::verify`, which rejects `deposit_index >= 2 ^ 63` explicitly). Because the Merkle
path consumes only `height` low bits of the index, `TransferWitness::new` accepts an index and
that index plus `2 ^ TRANSFER_TREE_HEIGHT` interchangeably. The 6-bit bound comes only from the
circuit. -/
theorem transfer_witness_native_accepts_aliased_index (env : MerkleEnv Transfer)
    (w : TransferWitness) (hh : w.transferMerkleProof.height = transferTreeHeight)
    (h : w.verify env = .ok ()) :
    TransferWitness.verify env
        { w with transferIndex := w.transferIndex + 2 ^ transferTreeHeight } = .ok () := by
  rw [transfer_witness_verify_ok_iff] at h ⊢
  rw [env.truncates, hh] at h
  rw [env.truncates, hh]
  simpa [Nat.add_mod_right] using h

/-- `TransferWitnessTarget::new` (source lines 73-101). The 6-bit index bound is emitted only when
`is_checked`; note that `TransferTarget::new` does NOT range-check `token_index` at all. -/
structure TransferWitnessGates (env : MerkleEnv Transfer) (isChecked : Bool)
    (w : TransferWitness) : Prop where
  indexRange : isChecked = true → w.transferIndex < 2 ^ transferTreeHeight
  recipientChecked : isChecked = true → ∀ x ∈ w.transfer.recipient, x < limbModulus
  amountChecked : isChecked = true → ∀ x ∈ w.transfer.amount, x < limbModulus
  auxDataChecked : isChecked = true → ∀ x ∈ w.transfer.auxData, x < limbModulus
  proofHeight : w.transferMerkleProof.height = transferTreeHeight
  inclusion :
    env.verify w.transferMerkleProof w.transfer w.transferIndex w.transferTreeRoot = true

theorem transfer_witness_gates_imply_native_verify (env : MerkleEnv Transfer) (b : Bool)
    (w : TransferWitness) (g : TransferWitnessGates env b w) : w.verify env = .ok () :=
  (transfer_witness_verify_ok_iff env w).mpr g.inclusion

theorem transfer_witness_gates_bound_index (env : MerkleEnv Transfer) (w : TransferWitness)
    (g : TransferWitnessGates env true w) : w.transferIndex < 2 ^ transferTreeHeight :=
  g.indexRange rfl

/-- With `is_checked = false` the circuit imposes no index bound either. -/
theorem transfer_witness_unchecked_accepts_out_of_range_index :
    ∃ (env : MerkleEnv Transfer) (w : TransferWitness),
      TransferWitnessGates env false w ∧ ¬ w.transferIndex < 2 ^ transferTreeHeight := by
  refine ⟨acceptingEnv Transfer (fun _ => ⟨0, 0, 0, 0⟩),
    { transferTreeRoot := ⟨0, 0, 0, 0⟩,
      transfer := { recipient := [], tokenIndex := 0, amount := [], auxData := [] },
      transferIndex := 2 ^ transferTreeHeight,
      transferMerkleProof := { siblings := List.replicate transferTreeHeight ⟨0, 0, 0, 0⟩ } },
    ?_, ?_⟩
  · exact { indexRange := by intro h; exact absurd h (by decide)
            recipientChecked := by intro h; exact absurd h (by decide)
            amountChecked := by intro h; exact absurd h (by decide)
            auxDataChecked := by intro h; exact absurd h (by decide)
            proofHeight := by simp [MerkleProof.height]
            inclusion := rfl }
  · simp


/-! ## Target-side gates for `AccountStateTarget::new` (account_state.rs lines 102-146) -/

/-- The local gate content of `AccountStateTarget::new`. The two openings are emitted
unconditionally; only the scalar bounds depend on `is_checked`. -/
structure AccountStateGates (envSend : MerkleEnv SendLeaf) (envChannel : MerkleEnv ChannelLeaf)
    (isChecked : Bool) (s : AccountState) : Prop where
  channelIdRange : isChecked = true → s.channelId < 2 ^ channelIdBits
  sendLeafIndexRange : isChecked = true → s.sendLeafIndex < 2 ^ sendTreeHeight
  channelLeafIndexRange : isChecked = true → s.channelLeaf.index < 2 ^ sendTreeHeight
  sendProofHeight : s.sendMerkleProof.height = sendTreeHeight
  userProofHeight : s.userMerkleProof.height = channelTreeHeight
  sendInclusion :
    envSend.verify s.sendMerkleProof s.sendLeaf s.sendLeafIndex s.channelLeaf.sendTreeRoot = true
  userInclusion :
    envChannel.verify s.userMerkleProof s.channelLeaf s.channelId s.accountTreeRoot = true

theorem account_state_gates_imply_native_verify (envS : MerkleEnv SendLeaf)
    (envC : MerkleEnv ChannelLeaf) (b : Bool) (s : AccountState)
    (g : AccountStateGates envS envC b s) : s.verify envS envC = .ok () :=
  (account_state_verify_ok_iff envS envC s).mpr ⟨g.sendInclusion, g.userInclusion⟩

/-- SECURITY GAP: `ChannelId::new` rejects the reserved dummy id `0` natively, but nothing in
`AccountStateTarget::new` does — the circuit only range-checks 32 bits. A satisfying witness with
`channel_id = 0` exists. -/
theorem account_state_gates_accept_dummy_channel_id :
    ∃ (envS : MerkleEnv SendLeaf) (envC : MerkleEnv ChannelLeaf) (s : AccountState),
      AccountStateGates envS envC true s ∧ s.channelId = 0 := by
  refine ⟨acceptingEnv SendLeaf (fun _ => ⟨0, 0, 0, 0⟩),
    acceptingEnv ChannelLeaf (fun _ => ⟨0, 0, 0, 0⟩),
    { channelId := 0, accountTreeRoot := ⟨0, 0, 0, 0⟩,
      sendLeaf := { prev := 0, cur := 0, txTreeRoot := [] }, sendLeafIndex := 0,
      sendMerkleProof := { siblings := List.replicate sendTreeHeight ⟨0, 0, 0, 0⟩ },
      channelLeaf := { index := 0, prev := 0, sendTreeRoot := ⟨0, 0, 0, 0⟩,
                       memberPubkeysRoot := ⟨0, 0, 0, 0⟩ },
      userMerkleProof := { siblings := List.replicate channelTreeHeight ⟨0, 0, 0, 0⟩ } },
    ?_, rfl⟩
  exact { channelIdRange := by intro _; decide
          sendLeafIndexRange := by intro _; decide
          channelLeafIndexRange := by intro _; decide
          sendProofHeight := by simp [MerkleProof.height]
          userProofHeight := by simp [MerkleProof.height]
          sendInclusion := rfl
          userInclusion := rfl }

/-! ## Allocation and witness-write order

`*Target::new` allocates the fields in one order and `*Target::set_witness` writes them in
another; a mismatch would silently mis-bind a witness. Both orders are transcribed separately. -/

inductive AccountField where
  | channelId | accountTreeRoot | sendLeaf | sendLeafIndex | sendMerkleProof | channelLeaf
  | userMerkleProof
  deriving DecidableEq, Repr

/-- `AccountStateTarget::new`, source lines 110-121. -/
def accountStateAllocationOrder : List AccountField :=
  [.channelId, .accountTreeRoot, .sendLeaf, .sendLeafIndex, .sendMerkleProof, .channelLeaf,
   .userMerkleProof]

/-- `AccountStateTarget::set_witness`, source lines 148-161. -/
def accountStateWitnessOrder : List AccountField :=
  [.channelId, .accountTreeRoot, .sendLeaf, .sendLeafIndex, .sendMerkleProof, .channelLeaf,
   .userMerkleProof]

theorem account_state_witness_order_matches_allocation :
    accountStateWitnessOrder = accountStateAllocationOrder := rfl

theorem account_state_has_seven_fields : accountStateAllocationOrder.length = 7 := rfl

inductive DepositWitnessField where
  | channelId | depositTreeRoot | depositSalt | deposit | depositMerkleProof
  deriving DecidableEq, Repr

/-- `DepositWitnessTarget::new`, source lines 111-115. -/
def depositWitnessAllocationOrder : List DepositWitnessField :=
  [.channelId, .depositTreeRoot, .depositSalt, .deposit, .depositMerkleProof]

/-- `DepositWitnessTarget::set_witness`, source lines 142-148. -/
def depositWitnessWitnessOrder : List DepositWitnessField :=
  [.channelId, .depositTreeRoot, .depositSalt, .deposit, .depositMerkleProof]

theorem deposit_witness_order_matches_allocation :
    depositWitnessWitnessOrder = depositWitnessAllocationOrder := rfl

theorem deposit_witness_has_five_fields : depositWitnessAllocationOrder.length = 5 := rfl

inductive TransferWitnessField where
  | transferTreeRoot | transfer | transferIndex | transferMerkleProof
  deriving DecidableEq, Repr

/-- `TransferWitnessTarget::new`, source lines 80-86. -/
def transferWitnessAllocationOrder : List TransferWitnessField :=
  [.transferTreeRoot, .transfer, .transferIndex, .transferMerkleProof]

/-- `TransferWitnessTarget::set_witness`, source lines 108-116. -/
def transferWitnessWitnessOrder : List TransferWitnessField :=
  [.transferTreeRoot, .transfer, .transferIndex, .transferMerkleProof]

theorem transfer_witness_order_matches_allocation :
    transferWitnessWitnessOrder = transferWitnessAllocationOrder := rfl

theorem transfer_witness_has_four_fields : transferWitnessAllocationOrder.length = 4 := rfl

/-! ## Which fields are range-checked

Declarative transcription of the `range_check` calls reachable from each `*Target::new` when
`is_checked` is passed down. This is a table, NOT a claim about emitted gates. Every production
caller (`receive_deposit_circuit.rs:287-288`, `receive_transfer_circuit.rs:396-398`,
`send_tx_circuit.rs:232`, `single_withdrawal_circuit.rs:434,442`, and `tx_settlement.rs:274` whose
own callers all pass `true`) uses `is_checked = true`. -/

inductive RangeCheckedField where
  | accountChannelId | accountSendLeafPrev | accountSendLeafCur | accountSendLeafTxTreeRootLimb
  | accountSendLeafIndex | accountChannelLeafIndex | accountChannelLeafPrev
  | depositChannelId | depositIndex | depositBlockNumber | depositDepositorLimb
  | depositRecipientLimb | depositTokenIndex | depositAmountLimb | depositAuxDataLimb
  | transferIndex | transferRecipientLimb | transferAmountLimb | transferAuxDataLimb
  | transferTokenIndex
  deriving DecidableEq, Repr

/-- From `AccountStateTarget::new` lines 110-121 via `ChannelIdTarget::new`, `SendLeafTarget::new`
and `ChannelLeafTarget::new`. `account_tree_root`, `channel_leaf.send_tree_root`,
`channel_leaf.member_pubkeys_root` and all Merkle siblings are raw field targets with NO bound. -/
def accountStateRangeChecks (isChecked : Bool) : List (RangeCheckedField × Nat) :=
  if isChecked then
    [(.accountChannelId, channelIdBits), (.accountSendLeafPrev, 63), (.accountSendLeafCur, 63),
     (.accountSendLeafTxTreeRootLimb, 32), (.accountSendLeafIndex, sendTreeHeight),
     (.accountChannelLeafIndex, sendTreeHeight), (.accountChannelLeafPrev, 63)]
  else []

/-- From `DepositWitnessTarget::new` lines 111-115 via `ChannelIdTarget::new` and
`DepositTarget::new`. `deposit_tree_root` and `deposit_salt` are unbounded field targets. -/
def depositWitnessRangeChecks (isChecked : Bool) : List (RangeCheckedField × Nat) :=
  if isChecked then
    [(.depositChannelId, channelIdBits), (.depositIndex, depositTreeHeight),
     (.depositBlockNumber, 63), (.depositDepositorLimb, 32), (.depositRecipientLimb, 32),
     (.depositTokenIndex, 32), (.depositAmountLimb, 32), (.depositAuxDataLimb, 32)]
  else []

/-- From `TransferWitnessTarget::new` lines 80-86 via `TransferTarget::new`. -/
def transferWitnessRangeChecks (isChecked : Bool) : List (RangeCheckedField × Nat) :=
  if isChecked then
    [(.transferRecipientLimb, 32), (.transferAmountLimb, 32), (.transferAuxDataLimb, 32),
     (.transferIndex, transferTreeHeight)]
  else []

theorem account_state_range_checks_pinned :
    accountStateRangeChecks true =
      [(.accountChannelId, 32), (.accountSendLeafPrev, 63), (.accountSendLeafCur, 63),
       (.accountSendLeafTxTreeRootLimb, 32), (.accountSendLeafIndex, 32),
       (.accountChannelLeafIndex, 32), (.accountChannelLeafPrev, 63)] := rfl

theorem deposit_witness_range_checks_pinned :
    depositWitnessRangeChecks true =
      [(.depositChannelId, 32), (.depositIndex, 63), (.depositBlockNumber, 63),
       (.depositDepositorLimb, 32), (.depositRecipientLimb, 32), (.depositTokenIndex, 32),
       (.depositAmountLimb, 32), (.depositAuxDataLimb, 32)] := rfl

theorem transfer_witness_range_checks_pinned :
    transferWitnessRangeChecks true =
      [(.transferRecipientLimb, 32), (.transferAmountLimb, 32), (.transferAuxDataLimb, 32),
       (.transferIndex, 6)] := rfl

theorem unchecked_targets_emit_no_range_checks :
    accountStateRangeChecks false = [] ∧ depositWitnessRangeChecks false = [] ∧
      transferWitnessRangeChecks false = [] := ⟨rfl, rfl, rfl⟩

/-- The circuit's 63-bit bound on `deposit_index` is exactly the bound the native `verify`
enforces at source line 78. -/
theorem deposit_index_circuit_bound_matches_native :
    (RangeCheckedField.depositIndex, depositTreeHeight) ∈ depositWitnessRangeChecks true := by
  simp [depositWitnessRangeChecks]

/-- `DepositTarget::new` range-checks `token_index` to 32 bits. -/
theorem deposit_token_index_is_range_checked :
    (RangeCheckedField.depositTokenIndex, 32) ∈ depositWitnessRangeChecks true := by
  simp [depositWitnessRangeChecks]

/-- ASYMMETRY: `TransferTarget::new` allocates `token_index` with a bare `add_virtual_target()`,
so no bound on a transfer's token index is emitted here for ANY value of `is_checked`. Any bound
must come from the caller (e.g. the asset-tree index used by `update_private_state`). -/
theorem transfer_token_index_is_not_range_checked (b : Bool) :
    ¬ ∃ n, (RangeCheckedField.transferTokenIndex, n) ∈ transferWitnessRangeChecks b := by
  cases b <;> simp [transferWitnessRangeChecks]

/-! ## Concrete accepted traces

Non-vacuous positive examples: each of the three native acceptance paths accepts a concrete
witness under an always-accepting Merkle oracle and a constant hash callback. -/

def exampleHash : HashFn := fun _ => ⟨1, 2, 3, 4⟩

def exampleSendEnv : MerkleEnv SendLeaf := acceptingEnv SendLeaf (fun _ => ⟨0, 0, 0, 0⟩)
def exampleChannelEnv : MerkleEnv ChannelLeaf := acceptingEnv ChannelLeaf (fun _ => ⟨0, 0, 0, 0⟩)
def exampleDepositEnv : MerkleEnv Deposit := acceptingEnv Deposit (fun _ => ⟨0, 0, 0, 0⟩)
def exampleTransferEnv : MerkleEnv Transfer := acceptingEnv Transfer (fun _ => ⟨0, 0, 0, 0⟩)

def exampleAccountState : AccountState :=
  { channelId := 7, accountTreeRoot := ⟨11, 12, 13, 14⟩,
    sendLeaf := { prev := 2, cur := 5, txTreeRoot := [0, 0, 0, 0, 0, 0, 0, 9] },
    sendLeafIndex := 3,
    sendMerkleProof := { siblings := List.replicate sendTreeHeight ⟨0, 0, 0, 0⟩ },
    channelLeaf := { index := 4, prev := 2, sendTreeRoot := ⟨21, 22, 23, 24⟩,
                     memberPubkeysRoot := ⟨31, 32, 33, 34⟩ },
    userMerkleProof := { siblings := List.replicate channelTreeHeight ⟨0, 0, 0, 0⟩ } }

theorem example_account_state_accepted :
    exampleAccountState.verify exampleSendEnv exampleChannelEnv = .ok () := rfl

theorem example_account_state_gates_satisfied :
    AccountStateGates exampleSendEnv exampleChannelEnv true exampleAccountState :=
  { channelIdRange := by intro _; decide
    sendLeafIndexRange := by intro _; decide
    channelLeafIndexRange := by intro _; decide
    sendProofHeight := by simp [exampleAccountState, MerkleProof.height]
    userProofHeight := by simp [exampleAccountState, MerkleProof.height]
    sendInclusion := rfl
    userInclusion := rfl }

def exampleDepositWitness : DepositWitness :=
  { channelId := 7, depositTreeRoot := ⟨41, 42, 43, 44⟩, depositSalt := ⟨9, 9, 9, 9⟩,
    deposit :=
      { depositIndex := 5, blockNumber := 3, depositor := [1, 2, 3, 4, 5],
        recipient := recipientFromUserIdNative exampleHash 7 ⟨9, 9, 9, 9⟩,
        tokenIndex := 2, amount := [0, 0, 0, 0, 0, 0, 0, 100],
        auxData := [0, 0, 0, 0, 0, 0, 0, 0] },
    depositMerkleProof := { siblings := List.replicate depositTreeHeight ⟨0, 0, 0, 0⟩ } }

theorem example_deposit_witness_accepted :
    exampleDepositWitness.verify exampleDepositEnv exampleHash = .ok () := by
  rw [deposit_witness_verify_ok_iff]
  exact ⟨by decide, rfl, rfl⟩

theorem example_deposit_witness_gates_satisfied :
    DepositWitnessGates exampleDepositEnv exampleHash true exampleDepositWitness :=
  { channelIdRange := by intro _; decide
    depositIndexRange := by intro _; decide
    blockNumberRange := by intro _; decide
    tokenIndexRange := by intro _; decide
    proofHeight := by simp [exampleDepositWitness, MerkleProof.height]
    inclusion := rfl
    recipientConnected := rfl }

def exampleTransferWitness : TransferWitness :=
  { transferTreeRoot := ⟨51, 52, 53, 54⟩,
    transfer := { recipient := recipientFromAddressNative exampleAddress, tokenIndex := 2,
                  amount := [0, 0, 0, 0, 0, 0, 0, 100], auxData := [0, 0, 0, 0, 0, 0, 0, 0] },
    transferIndex := 3,
    transferMerkleProof := { siblings := List.replicate transferTreeHeight ⟨0, 0, 0, 0⟩ } }

theorem example_transfer_witness_accepted :
    exampleTransferWitness.verify exampleTransferEnv = .ok () := rfl

/-- The example transfer is a withdrawal-shaped one: its recipient extracts to the L1 address. -/
theorem example_transfer_recipient_extracts :
    extractAddressFromRecipient exampleTransferWitness.transfer.recipient = .ok exampleAddress := by
  rfl

end Zkp.Implementation.BalanceWitnesses
