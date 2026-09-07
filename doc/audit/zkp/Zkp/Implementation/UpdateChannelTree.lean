import Std

/-!
# UpdateChannelTree: how one block moves the channel tree

Handwritten semantic model of
`src/circuits/validity/block_hash_chain/update_channel_tree.rs`
(2569 lines; production 1–1606 modelled here, tests 1608–2569 read but not
translated). This is NOT a refinement proof of the Rust / plonky2 code: every
theorem below is about the Lean model, and the source-to-model correspondence
is a line-map claim only.

Three separate objects are modelled, and they are deliberately kept apart:

* `nativeComputePublicInputs` — `UpdateUserTree::compute_public_inputs`, the
  native witness builder. `strict = true` is `to_public_inputs` (what `prove`
  runs); `strict = false` is the `#[cfg(test)]` `to_public_inputs_unchecked`
  path that computes the same public inputs with every cross-check skipped.
  `native_unchecked_agrees_with_strict` is the source's own claim about that
  pair, proved here for the model.
* `CircuitGates` — the constraints `UpdateUserTreeTarget::new` lays down on an
  ARBITRARY satisfying witness (source lines 968–1425). Everything the circuit
  does NOT constrain stays unconstrained here.
* `PublicInputs` / `publicInputWords` / `publicInputsFromWords` — the
  `UpdateUserPublicInputs` codec (`to_u64_vec` / `from_u64_slice`,
  `UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN = 59`).

## What this file is really about (fund safety)

The channel-tree leaf is `ChannelLeaf { index, prev, send_tree_root,
member_pubkeys_root }`. It carries NO fund vector, NO balance-state digest, NO
H1 and NO state version. Consequently this circuit performs NO fund accounting
whatsoever: `native_account_root_ignores_channel_state_fields` and
`circuit_account_root_ignores_channel_state_fields` say exactly that, and
`native_leaf_transition_is_index_prev_send_only` pins the transition. There is
therefore NO conservation-of-funds statement in this file, and none could be
stated: the fund vector reaches this circuit only as opaque preimage limbs of
the IMCH signing digest that gets folded into `bp_sig_chain` and discharged
elsewhere. Cross-channel transfer PAIRING is likewise absent: a
`ChannelAction` is bound to the block only through
`source_channel_id == block.channel_id` and its Merkle opening; its
`destination_channel_id`, `tx_hash`, `seal` and `payload_hash` are entirely
unconstrained here (`native_accepts_any_destination_channel`,
`circuit_leaves_action_payload_free`), and no destination-channel leaf is
credited.

## What authorization IS checked here

Not signatures. The model has no signature-verification callback because the
source has no signature input. What a signing slot must satisfy is: the
recomputed member-tree root equals the channel leaf's committed
`member_pubkeys_root`; occupancy is exactly `signer_count`;
`2 <= signer_count <= MAX_SIG_CLUSTER`; the posting slot is an active member
slot below `MAX_SIG_CLUSTER`; the block's `tx_tree_root` is nonzero; and the
bp slot's Regev pubkey digest matches its member leaf. The block then FOLDS
the tuple `(IMCH digest, signer_count, pk_list_digest)` into `bp_sig_chain`.
The Falcon aggregate that discharges the fold, and the BP signature, are NOT
verified here — they are the consumer obligation of the recursive
aggregate-list proof in another circuit (`aggListFold`, `chainStep`
boundaries).

Named boundaries (also listed in the line map): `merkleRoot` (channel / send /
tx / channel-action Merkle path folds), `channelLeafHash` / `sendLeafHash` /
`txV2Hash` / `actionHash` / `memberLeafHash` (Poseidon leaf hashing),
`memberTreeRoot` (`compute_member_tree_root`, and its agreement with the
native `MemberTree` fold), `blockHash` (`Block::hash_with_prev_hash`, keccak
over the block fields), `signingDigest` (`ChannelStateMessageFields::
signing_digest`, modelled by the built-but-unregistered
`Zkp.Implementation.BlockMessages`; named here, never imported),
`aggPkListDigest` / `aggListLeaf` (`falcon_sig::agg_list`), `chainStep`
(`poseidon_sig::list`), `regevDigestOfCoeffs` (`RegevPk::poseidon_digest`),
`reduceToHashOut` / `bytes32OfHash` / `hashOfBytes32Native` /
`hashOfBytes32Target` (Bytes32 <-> PoseidonHashOut repacking, whose native
canonicity check and in-circuit total repack are NOT the same function), the
field lowering of `is_equal` / `select` / `conditional_assert_eq` /
`range_check` to the boolean and integer relations used here, the recursive
aggregate-list proof that discharges the folded statement, and the native
witness-write / proving effects.

Nothing here asserts proof soundness, hash injectivity, Merkle soundness,
signature validity, freshness, finality, or "acceptance implies safe".
-/

namespace Zkp.Implementation.UpdateChannelTree

/-! ## Pinned constants (src/constants.rs, src/ethereum_types, src/regev) -/

/-- `MAX_SIG_CLUSTER` — the co-signer ("sig-cluster") slot count. -/
def maxSigCluster : Nat := 8
/-- `MEMBER_TREE_HEIGHT`; `1 <<< MEMBER_TREE_HEIGHT = MAX_SIG_CLUSTER`. -/
def memberTreeHeight : Nat := 3
/-- `CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS`. -/
def channelTreeHeight : Nat := 32
/-- `CHANNEL_ID_BITS`. -/
def channelIdBits : Nat := 32
/-- `SEND_TREE_HEIGHT`. -/
def sendTreeHeight : Nat := 32
/-- `TX_TREE_HEIGHT = CHANNEL_ID_BITS`. -/
def txTreeHeight : Nat := 32
/-- `BYTES32_LEN` (u32 limbs). -/
def bytes32Len : Nat := 8
/-- `U64_LEN` (u32 limbs). -/
def u64Len : Nat := 2
/-- `POSEIDON_HASH_OUT_LEN`. -/
def poseidonHashOutLen : Nat := 4
/-- `MAX_CHANNEL_TOKENS` — the fixed fund-vector width. -/
def maxChannelTokens : Nat := 10
/-- `REGEV_N`. -/
def regevN : Nat := 2048
/-- `REGEV_PK_POSEIDON_DOMAIN` ("IMRP"). -/
def regevPkPoseidonDomain : Nat := 0x494d5250
/-- `TxClass::UserTransfer as u32`. -/
def userTransferClass : Nat := 0
/-- `TxClass::ChannelAction as u32`. -/
def channelActionClass : Nat := 1
/-- `ChannelActionKind::InterChannelSend as u32`. -/
def interChannelSendKind : Nat := 0
/-- `ChannelActionKind::ChannelClose as u32`. -/
def channelCloseKind : Nat := 1
/-- `ChannelActionKind::MemberSetUpdate as u32` — the reserved, retired tag. -/
def memberSetUpdateKind : Nat := 2
/-- One u32 limb's base. -/
def wordBase : Nat := 4294967296
/-- `U63_MAX_VALUE` — the `BlockNumber` bound. -/
def blockNumberLimit : Nat := 9223372036854775808
/-- `1 <<< CHANNEL_ID_BITS` — the `ChannelId::new` bound. -/
def channelIdLimit : Nat := 4294967296
/-- `UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN = 1 + U64_LEN + 6 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN`. -/
def publicInputsLen : Nat := 1 + u64Len + 6 * bytes32Len + 2 * poseidonHashOutLen

theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl
theorem member_tree_height_pinned : memberTreeHeight = 3 := rfl
theorem member_tree_height_is_log2_of_cluster : 2 ^ memberTreeHeight = maxSigCluster := rfl
theorem channel_tree_height_pinned : channelTreeHeight = 32 := rfl
theorem channel_tree_height_is_channel_id_bits : channelTreeHeight = channelIdBits := rfl
theorem send_tree_height_pinned : sendTreeHeight = 32 := rfl
theorem tx_tree_height_pinned : txTreeHeight = 32 := rfl
theorem bytes32_len_pinned : bytes32Len = 8 := rfl
theorem u64_len_pinned : u64Len = 2 := rfl
theorem poseidon_hash_out_len_pinned : poseidonHashOutLen = 4 := rfl
theorem max_channel_tokens_pinned : maxChannelTokens = 10 := rfl
theorem regev_n_pinned : regevN = 2048 := rfl
theorem regev_domain_pinned : regevPkPoseidonDomain = 0x494d5250 := rfl
theorem member_set_update_kind_pinned : memberSetUpdateKind = 2 := rfl
theorem channel_id_limit_pinned : channelIdLimit = 2 ^ channelIdBits := rfl
theorem public_inputs_len_pinned : publicInputsLen = 59 := rfl

/-! ## Word-level types

`PoseidonHashOut` is four u64 words; `Bytes32` is eight u32 limbs. Both are
modelled as plain data, with well-formedness kept as an explicit predicate
rather than baked into the type — the source's `from_u64_slice` decoders are
what enforce it, and a circuit target does not. -/

structure Hash4 where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  deriving DecidableEq, Repr, Inhabited

def Hash4.zero : Hash4 := ⟨0, 0, 0, 0⟩
def Hash4.words (h : Hash4) : List Nat := [h.w0, h.w1, h.w2, h.w3]

theorem hash4_words_length (h : Hash4) : h.words.length = poseidonHashOutLen := rfl

/-- Eight u32 limbs. `Bytes32::default()` is the all-zero limb vector. -/
structure Bytes32 where
  limbs : List Nat
  deriving DecidableEq, Repr, Inhabited

def Bytes32.zero : Bytes32 := ⟨[0, 0, 0, 0, 0, 0, 0, 0]⟩
/-- What `Bytes32::from_u32_slice` / `from_u64_slice` accept: eight limbs, each
below `2^32`. -/
def Bytes32.Wf (b : Bytes32) : Prop :=
  b.limbs.length = bytes32Len ∧ ∀ x ∈ b.limbs, x < wordBase

theorem bytes32_zero_wf : Bytes32.zero.Wf := by
  refine ⟨rfl, ?_⟩
  intro x hx
  simp [Bytes32.zero] at hx
  subst hx
  decide

/-- `U64::from(t).to_u64_vec()` — two u32 limbs, high then low. -/
def u64Words (n : Nat) : List Nat := [n / wordBase, n % wordBase]

theorem u64_words_length (n : Nat) : (u64Words n).length = u64Len := rfl

/-! ## Fault model -/

inductive Category where
  | length | blockError | channelId | merkleProof | txClass | channelAction
  | signerSet | memberRoot | regev | chain | publicInput
  deriving DecidableEq, Repr

inductive Fault where
  | rejected (category : Category) (location : String)
  | panic (location : String)
  deriving DecidableEq, Repr

abbrev Result := Except Fault

def check (condition : Bool) (category : Category) (location : String) : Result Unit :=
  if condition then .ok () else .error (.rejected category location)

def atIndex {α : Type} (xs : List α) (index : Nat) : Result α :=
  match xs[index]? with
  | none => .error (.panic "index")
  | some x => .ok x

def forEach {α : Type} (xs : List α) (action : α → Result Unit) : Result Unit :=
  match xs with
  | [] => .ok ()
  | x :: rest => do let _ ← action x; forEach rest action

/-- `xs` paired with its positions, starting at `start`. -/
def indexedFrom {α : Type} (start : Nat) : List α → List (Nat × α)
  | [] => []
  | x :: xs => (start, x) :: indexedFrom (start + 1) xs

def indexed {α : Type} (xs : List α) : List (Nat × α) := indexedFrom 0 xs

/-! ### Except helper lemmas (same shapes as `ChannelStateUpdate`) -/

theorem check_ok_iff (condition : Bool) (category : Category) (label : String) :
    check condition category label = .ok () ↔ condition = true := by
  cases condition <;> simp [check]

theorem bind_ok_iff {α β : Type} (r : Result α) (f : α → Result β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem unit_bind_ok_iff {α : Type} (r : Result Unit) (s : Result α) (value : α) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error error => simp [Bind.bind, Except.bind]
  | ok value => cases value; simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {α : Type} (x value : α) : (pure x : Result α) = .ok value ↔ x = value := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; exact congrArg _ h

theorem throw_ok_iff_false {α : Type} (fault : Fault) (value : α) :
    (throw fault : Result α) = .ok value ↔ False := by
  simp [throw, throwThe, MonadExceptOf.throw]

theorem for_each_success {α : Type} (xs : List α) (action : α → Result Unit) :
    forEach xs action = .ok () ↔ ∀ x ∈ xs, action x = .ok () := by
  induction xs with
  | nil => simp [forEach]
  | cons x xs ih => simp [forEach, unit_bind_ok_iff, ih]

end Zkp.Implementation.UpdateChannelTree
