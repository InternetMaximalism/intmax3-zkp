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

One deliberate simplification of ERROR SHAPE (not of behaviour): the source's
ten parallel per-block-slot vectors and their ten-way length gate become one
list of slot records and one length check. Untranslated on purpose: the
plonky2 builder plumbing (`UpdateUserPublicInputsTarget::new` / `to_vec` /
`from_slice` / `select` / `set_witness`, `UpdateUserTreeTarget::set_witness`,
`UpdateUserCircuit::new` / `prove`), the retired
`validate_member_set_delta` tombstone (a `#[cfg(feature = "deprecated-msu")]`
dead path), and the whole `#[cfg(test)]` module.

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
aggregate-list proof in another circuit (the `aggListLeaf`,
`aggPkListDigest` and `chainStep` boundaries).

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

/-! ## The data this file moves

`ChannelLeaf` is the whole per-channel state the channel tree holds. Note what
is absent: no fund vector, no balance digest, no H1, no state version, no
epoch. -/

/-- `common::trees::channel_tree::ChannelLeaf`. -/
structure ChannelLeaf where
  /-- Next send-tree index; also the base-account send nonce cursor. -/
  index : Nat
  /-- Block number of this channel's previous update. -/
  prev : Nat
  sendTreeRoot : Hash4
  memberPubkeysRoot : Hash4
  deriving DecidableEq, Repr, Inhabited

/-- `common::trees::channel_tree::SendLeaf`. -/
structure SendLeaf where
  prev : Nat
  cur : Nat
  txTreeRoot : Bytes32
  deriving DecidableEq, Repr, Inhabited

/-- `SendLeaf::empty_leaf()` = `SendLeaf::default()`. -/
def SendLeaf.empty : SendLeaf := ⟨0, 0, Bytes32.zero⟩

/-- `common::trees::key_tree::MemberLeaf`. -/
structure MemberLeaf where
  pkG : Hash4
  pkB : Hash4
  regevPkDigest : Hash4
  deriving DecidableEq, Repr, Inhabited

/-- `MemberLeaf::empty_leaf()` = `MemberLeaf::default()`. -/
def MemberLeaf.empty : MemberLeaf := ⟨Hash4.zero, Hash4.zero, Hash4.zero⟩

inductive TxClass where
  | userTransfer
  | channelAction
  deriving DecidableEq, Repr, Inhabited

def TxClass.code : TxClass → Nat
  | .userTransfer => userTransferClass
  | .channelAction => channelActionClass

inductive ChannelActionKind where
  | interChannelSend
  | channelClose
  | memberSetUpdate
  deriving DecidableEq, Repr, Inhabited

def ChannelActionKind.code : ChannelActionKind → Nat
  | .interChannelSend => interChannelSendKind
  | .channelClose => channelCloseKind
  | .memberSetUpdate => memberSetUpdateKind

/-- `common::tx::TxV2` on the NATIVE side: `tx_class` is a Rust enum, so only
two codes exist. The circuit's twin below carries a free field element. -/
structure TxV2 where
  txClass : TxClass
  transferTreeRoot : Hash4
  nonce : Nat
  channelActionRoot : Hash4
  deriving DecidableEq, Repr, Inhabited

/-- `common::tx::ChannelAction` on the NATIVE side. -/
structure ChannelAction where
  kind : ChannelActionKind
  sourceChannelId : Nat
  destinationChannelId : Nat
  txHash : Bytes32
  sealValue : Bytes32
  payloadHash : Hash4
  deriving DecidableEq, Repr, Inhabited

/-- `TxV2Target` — `tx_class` is an unconstrained `Target`. -/
structure TxV2T where
  txClass : Nat
  transferTreeRoot : Hash4
  nonce : Nat
  channelActionRoot : Hash4
  deriving DecidableEq, Repr, Inhabited

/-- `ChannelActionTarget` — `kind` is an unconstrained `Target`. -/
structure ChannelActionT where
  kind : Nat
  sourceChannelId : Nat
  destinationChannelId : Nat
  txHash : Bytes32
  sealValue : Bytes32
  payloadHash : Hash4
  deriving DecidableEq, Repr, Inhabited

/-- `common::block::Block`. `key_ids` marks the ACTIVE MEMBER SLOT of each
block slot; zero is padding. All slots of a block share ONE `channel_id`. -/
structure Block where
  numUsers : Nat
  channelId : Nat
  timestamp : Nat
  keyIds : List Nat
  txTreeRoot : Bytes32
  depositHashChain : Bytes32
  channelRegHashChain : Bytes32
  deriving DecidableEq, Repr, Inhabited

/-- `regev::RegevPk` — the two coefficient vectors, each `REGEV_N` wide. -/
structure RegevPk where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr, Inhabited

/-- `RegevPk::poseidon_digest`'s preimage tail, in source order (`a` then `b`). -/
def RegevPk.coeffs (pk : RegevPk) : List Nat := pk.a ++ pk.b

/-- `ChannelStateMessageFields` (src/circuits/validity/block_hash_chain/
channel_state_message.rs, modelled by the built-but-UNREGISTERED
`Zkp.Implementation.BlockMessages`; carried here as opaque preimage data, and
NEVER interpreted). `fundAmounts` is `channel_fund.amounts`, the
`MAX_CHANNEL_TOKENS`-wide fund vector; `balanceStateH1` is `balance_state.h1()`. -/
structure ChannelStateFields where
  epoch : Nat
  smallBlockNumber : Nat
  closeFreezeNonce : Nat
  fundAmounts : List Nat
  fundIntmaxStateRoot : Bytes32
  balanceStateH1 : Bytes32
  sharedNativeNullifierRoot : Bytes32
  unallocatedConfirmedIncoming : Nat
  prevDigest : Bytes32
  stateVersion : Nat
  deriving DecidableEq, Repr, Inhabited

/-- An opaque Merkle path witness; its semantics is `Env.merkleRoot`. -/
structure MerklePath where
  id : Nat
  deriving DecidableEq, Repr, Inhabited

/-! ## The environment: every hash / Merkle / aggregate callback

None of these is given any property. In particular `merkleRoot` is NOT assumed
injective, `memberTreeRoot` is NOT assumed collision-resistant, and there is
NO signature-verification callback because the source verifies no signature. -/

structure Env where
  /-- `Block::hash_with_prev_hash` — keccak over
  `prev || channel_id || timestamp || key_ids || tx_tree_root ||
  deposit_hash_chain || channel_reg_hash_chain`. -/
  blockHash : Bytes32 → Block → Bytes32
  /-- A Merkle path fold: `proof.get_root(leaf_hash, index)`. -/
  merkleRoot : MerklePath → Hash4 → Nat → Hash4
  channelLeafHash : ChannelLeaf → Hash4
  sendLeafHash : SendLeaf → Hash4
  txV2Hash : TxV2 → Hash4
  txV2HashT : TxV2T → Hash4
  actionHash : ChannelAction → Hash4
  actionHashT : ChannelActionT → Hash4
  memberLeafHash : MemberLeaf → Hash4
  /-- `compute_member_tree_root` over the `MAX_SIG_CLUSTER` leaf hashes; also
  stands for the native `MemberTree::push`-then-`get_root` fold (their
  agreement is a premise, not a theorem). -/
  memberTreeRoot : List Hash4 → Hash4
  /-- `RegevPk::poseidon_digest` / its in-circuit recompute over the raw
  coefficient list (domain and length constants are part of the callback). -/
  regevDigestOfCoeffs : List Nat → Hash4
  /-- `ChannelStateMessageFields::signing_digest(channel_id, h2_tag)`. -/
  signingDigest : ChannelStateFields → Nat → Bytes32 → Bytes32
  /-- `falcon_sig::agg_list::agg_pk_list_digest` over ALL slots' `pk_g`. -/
  aggPkListDigest : List Bytes32 → Hash4
  /-- `falcon_sig::agg_list::agg_list_leaf(message, signer_count, pk_digest)`. -/
  aggListLeaf : Bytes32 → Nat → Hash4 → Hash4
  /-- `poseidon_sig::list::list_chain_step`. -/
  chainStep : Hash4 → Hash4 → Hash4
  /-- `Bytes32::reduce_to_hash_out`. -/
  reduceToHashOut : Bytes32 → Hash4
  /-- `Bytes32::from_hash_out`. -/
  bytes32OfHash : Hash4 → Bytes32
  /-- Native `Bytes32: TryInto<PoseidonHashOut>` — CAN FAIL on a non-canonical
  value. -/
  hashOfBytes32Native : Bytes32 → Option Hash4
  /-- In-circuit `Bytes32Target::to_hash_out` — a TOTAL repack, with no
  canonicity check. The gap between this and `hashOfBytes32Native` is a
  deliberate, unproved asymmetry (a boundary, not a theorem). -/
  hashOfBytes32Target : Bytes32 → Hash4

/-! ## Public inputs (`UpdateUserPublicInputs`) -/

structure PublicInputs where
  blockNumber : Nat
  blockTimestamp : Nat
  prevBlockHashChain : Bytes32
  prevAccountTreeRoot : Hash4
  newBlockHashChain : Bytes32
  newAccountTreeRoot : Hash4
  depositHashChain : Bytes32
  channelRegHashChain : Bytes32
  prevBpSigChain : Bytes32
  newBpSigChain : Bytes32
  deriving DecidableEq, Repr, Inhabited

/-- `UpdateUserPublicInputs::to_u64_vec` — the exact wire order. The same
order is `UpdateUserPublicInputsTarget::to_vec`, which is what
`register_public_inputs` publishes. -/
def publicInputWords (p : PublicInputs) : List Nat :=
  [p.blockNumber] ++ u64Words p.blockTimestamp ++ p.prevBlockHashChain.limbs ++
    p.prevAccountTreeRoot.words ++ p.newBlockHashChain.limbs ++ p.newAccountTreeRoot.words ++
    p.depositHashChain.limbs ++ p.channelRegHashChain.limbs ++ p.prevBpSigChain.limbs ++
    p.newBpSigChain.limbs

/-- Well-formed public inputs: every `Bytes32` has its eight canonical limbs. -/
def PublicInputs.Wf (p : PublicInputs) : Prop :=
  p.prevBlockHashChain.Wf ∧ p.newBlockHashChain.Wf ∧ p.depositHashChain.Wf ∧
    p.channelRegHashChain.Wf ∧ p.prevBpSigChain.Wf ∧ p.newBpSigChain.Wf

theorem public_input_words_length {p : PublicInputs} (wf : p.Wf) :
    (publicInputWords p).length = publicInputsLen := by
  obtain ⟨⟨h1, _⟩, ⟨h2, _⟩, ⟨h3, _⟩, ⟨h4, _⟩, ⟨h5, _⟩, ⟨h6, _⟩⟩ := wf
  simp [publicInputWords, u64Words, Hash4.words, h1, h2, h3, h4, h5, h6, publicInputsLen,
    bytes32Len, u64Len, poseidonHashOutLen]

/-- `U64::from_u64_slice` at the cursor — two canonical u32 limbs, high then
low, and the rest of the slice. -/
def takeU64 (xs : List Nat) : Result (Nat × List Nat) :=
  match xs with
  | hi :: lo :: rest =>
      if hi < wordBase ∧ lo < wordBase then .ok (hi * wordBase + lo, rest)
      else .error (.rejected .publicInput "U64::from_u64_slice")
  | _ => .error (.rejected .publicInput "U64::from_u64_slice")

/-- `Bytes32::from_u64_slice` at the cursor — eight limbs, each at most
`u32::MAX` (`U32LimbTrait::from_u64_slice`'s `OutOfU32Range` gate). -/
def takeBytes32 (xs : List Nat) : Result (Bytes32 × List Nat) :=
  match xs with
  | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: a7 :: rest =>
      if [a0, a1, a2, a3, a4, a5, a6, a7].all (fun x => decide (x < wordBase)) then
        .ok (⟨[a0, a1, a2, a3, a4, a5, a6, a7]⟩, rest)
      else .error (.rejected .publicInput "Bytes32::from_u64_slice")
  | _ => .error (.rejected .publicInput "Bytes32::from_u64_slice")

/-- `PoseidonHashOut::from_u64_slice` at the cursor — length only; the words
are field elements and are NOT range-checked (utils/poseidon_hash_out.rs
lines 55–66). -/
def takeHash4 (xs : List Nat) : Result (Hash4 × List Nat) :=
  match xs with
  | a :: b :: c :: d :: rest => .ok (⟨a, b, c, d⟩, rest)
  | _ => .error (.rejected .merkleProof "PoseidonHashOut::from_u64_slice")

/-- `UpdateUserPublicInputs::from_u64_slice`: the length gate first, then
`BlockNumber::new`, then the cursor walk in source field order. -/
def publicInputsFromWords (values : List Nat) : Result PublicInputs := do
  let _ ← check (decide (values.length = publicInputsLen)) .length
    "invalid update-account public inputs length"
  match values with
  | bn :: rest0 => do
      let _ ← check (decide (bn < blockNumberLimit)) .publicInput "invalid block number"
      let (timestamp, rest1) ← takeU64 rest0
      let (prevBlockHashChain, rest2) ← takeBytes32 rest1
      let (prevAccountTreeRoot, rest3) ← takeHash4 rest2
      let (newBlockHashChain, rest4) ← takeBytes32 rest3
      let (newAccountTreeRoot, rest5) ← takeHash4 rest4
      let (depositHashChain, rest6) ← takeBytes32 rest5
      let (channelRegHashChain, rest7) ← takeBytes32 rest6
      let (prevBpSigChain, rest8) ← takeBytes32 rest7
      let (newBpSigChain, _) ← takeBytes32 rest8
      pure { blockNumber := bn, blockTimestamp := timestamp, prevBlockHashChain,
             prevAccountTreeRoot, newBlockHashChain, newAccountTreeRoot, depositHashChain,
             channelRegHashChain, prevBpSigChain, newBpSigChain }
  | [] => .error (.rejected .length "invalid update-account public inputs length")

theorem public_inputs_decoder_rejects_wrong_length (values : List Nat)
    (h : values.length ≠ publicInputsLen) :
    publicInputsFromWords values = .error (.rejected .length
      "invalid update-account public inputs length") := by
  have hc : check (decide (values.length = publicInputsLen)) Category.length
      "invalid update-account public inputs length" =
      .error (.rejected .length "invalid update-account public inputs length") := by
    simp [check, h]
  simp only [publicInputsFromWords, hc, Bind.bind, Except.bind]

theorem public_inputs_codec_round_trips {p : PublicInputs} (wf : p.Wf)
    (bn : p.blockNumber < blockNumberLimit) (ts : p.blockTimestamp < wordBase * wordBase) :
    publicInputsFromWords (publicInputWords p) = .ok p := by
  obtain ⟨⟨l1, r1⟩, ⟨l2, r2⟩, ⟨l3, r3⟩, ⟨l4, r4⟩, ⟨l5, r5⟩, ⟨l6, r6⟩⟩ := wf
  obtain ⟨b0, t0, c1, hh1, c2, hh2, c3, c4, c5, c6⟩ := p
  simp only at l1 l2 l3 l4 l5 l6 r1 r2 r3 r4 r5 r6 bn ts
  obtain ⟨x1⟩ := c1; obtain ⟨x2⟩ := c2; obtain ⟨x3⟩ := c3
  obtain ⟨x4⟩ := c4; obtain ⟨x5⟩ := c5; obtain ⟨x6⟩ := c6
  match x1, l1 with
  | [a0, a1, a2, a3, a4, a5, a6, a7], _ =>
  match x2, l2 with
  | [b1, b2, b3, b4, b5, b6, b7, b8], _ =>
  match x3, l3 with
  | [c10, c11, c12, c13, c14, c15, c16, c17], _ =>
  match x4, l4 with
  | [d0, d1, d2, d3, d4, d5, d6, d7], _ =>
  match x5, l5 with
  | [e0, e1, e2, e3, e4, e5, e6, e7], _ =>
  match x6, l6 with
  | [f0, f1, f2, f3, f4, f5, f6, f7], _ =>
    have tlo : t0 % wordBase < wordBase := Nat.mod_lt _ (by decide)
    have thi : t0 / wordBase < wordBase := (Nat.div_lt_iff_lt_mul (by decide)).2 ts
    have trec : t0 / wordBase * wordBase + t0 % wordBase = t0 := by
      rw [Nat.mul_comm]; exact Nat.div_add_mod t0 wordBase
    simp only [List.mem_cons, List.not_mem_nil, or_false, forall_eq_or_imp, forall_eq]
      at r1 r2 r3 r4 r5 r6
    obtain ⟨p1, p2, p3, p4, p5, p6, p7, p8⟩ := r1
    obtain ⟨q1, q2, q3, q4, q5, q6, q7, q8⟩ := r2
    obtain ⟨s1, s2, s3, s4, s5, s6, s7, s8⟩ := r3
    obtain ⟨u1, u2, u3, u4, u5, u6, u7, u8⟩ := r4
    obtain ⟨v1, v2, v3, v4, v5, v6, v7, v8⟩ := r5
    obtain ⟨y1, y2, y3, y4, y5, y6, y7, y8⟩ := r6
    simp only [publicInputWords, Hash4.words, u64Words, List.cons_append, List.nil_append,
      publicInputsFromWords, takeU64, takeBytes32, takeHash4, check, publicInputsLen, u64Len,
      bytes32Len, poseidonHashOutLen, List.length_cons, List.length_nil, List.all_cons,
      List.all_nil, Bind.bind, Except.bind, if_pos, decide_True, Bool.and_true,
      decide_eq_true_eq]
    rw [if_pos bn, if_pos (And.intro thi tlo)]
    simp only [p1, p2, p3, p4, p5, p6, p7, p8, q1, q2, q3, q4, q5, q6, q7, q8,
      s1, s2, s3, s4, s5, s6, s7, s8, u1, u2, u3, u4, u5, u6, u7, u8,
      v1, v2, v3, v4, v5, v6, v7, v8, y1, y2, y3, y4, y5, y6, y7, y8,
      decide_True, Bool.and_true, if_true, trec]
    rfl

/-! ## The witness (`UpdateUserTree`)

The source carries ten parallel per-block-slot vectors and gates all ten
lengths against `block.num_users` in one `if`. The model collapses them into
one list of slot records and one length check; that is a deliberate
simplification of the ERROR SHAPE, not of the behaviour (a witness that passes
the ten-way gate is exactly one whose slot list has that length). -/

structure Slot where
  prevLeaf : ChannelLeaf
  channelProof : MerklePath
  sendProof : MerklePath
  txIndex : Nat
  tx : TxV2
  txProof : MerklePath
  actionIndex : Nat
  action : ChannelAction
  actionProof : MerklePath
  /-- `member_regev_pks[i]` — the Regev pubkey witnessed at this BLOCK slot. -/
  regevPk : RegevPk
  deriving Repr, Inhabited

structure Witness where
  prevBlockHashChain : Bytes32
  prevAccountTreeRoot : Hash4
  blockNumber : Nat
  block : Block
  slots : List Slot
  prevBpSigChain : Bytes32
  /-- ALL `MAX_SIG_CLUSTER` registered member leaves in slot order. -/
  memberLeaves : List MemberLeaf
  /-- Retired direct-MSU wire tombstone; production witnesses leave it empty. -/
  newMemberLeaves : List MemberLeaf
  signerCount : Nat
  /-- IMCH signing-digest preimage limbs, `channel_id` and `h2_tag` excluded. -/
  fields : ChannelStateFields
  deriving Repr, Inhabited

/-- The running state of the source's slot loop: the channel-tree root and the
N-of-N signature-list accumulator. -/
structure NState where
  root : Hash4
  chain : Bytes32
  deriving DecidableEq, Repr, Inhabited

/-! ### The block statement that gets folded

`signing_digest` takes `channel_id` and `h2_tag` from THIS block, so a digest
collected for another channel or another tx root is a different digest. The
pk list covers ALL `MAX_SIG_CLUSTER` slots, padding included — deliberately,
so that a rejected witness's mirror value still matches what the circuit
computes. -/

def nativeSignerPks (e : Env) (w : Witness) : List Bytes32 :=
  w.memberLeaves.map (fun leaf => e.bytes32OfHash leaf.pkG)

def nativeSignedDigest (e : Env) (w : Witness) : Bytes32 :=
  e.signingDigest w.fields w.block.channelId w.block.txTreeRoot

def nativeSigLeaf (e : Env) (w : Witness) : Hash4 :=
  e.aggListLeaf (nativeSignedDigest e w) w.signerCount (e.aggPkListDigest (nativeSignerPks e w))

/-! ### `check_n_of_n_witness` (source lines 253–326)

Every check here has an in-circuit twin; this is the honest-prover error path,
NOT the security boundary. No signature is verified. -/

/-- Occupancy: nothing at or above `signer_count`, nothing missing below it. -/
def nativeOccupancyCheck (w : Witness) (item : Nat × MemberLeaf) : Result Unit := do
  let slot := item.1
  let leaf := item.2
  let _ ← check (decide (slot < w.signerCount) || decide (leaf = MemberLeaf.empty))
    .signerSet "member slot at or above signer_count is not the empty leaf"
  check (!decide (slot < w.signerCount) || decide (leaf.pkG ≠ Hash4.zero))
    .signerSet "member slot below signer_count carries no pk_g"

def nativeCheckNOfN (e : Env) (w : Witness) (i : Nat) (slot : Slot) : Result Unit := do
  let _ ← check (decide (w.block.txTreeRoot ≠ Bytes32.zero)) .signerSet
    "tx_tree_root must be nonzero when a member signature is applied"
  let _ ← check (decide (i < maxSigCluster)) .signerSet
    "signing block slot is outside the member slots"
  let _ ← check (decide (2 ≤ w.signerCount) && decide (w.signerCount ≤ maxSigCluster))
    .signerSet "signer_count out of range"
  let _ ← forEach (indexed w.memberLeaves) (nativeOccupancyCheck w)
  let _ ← check (decide (i < w.signerCount)) .signerSet
    "signing block slot is not an active member slot"
  let _ ← check
    (decide (e.memberTreeRoot (w.memberLeaves.map e.memberLeafHash) = slot.prevLeaf.memberPubkeysRoot))
    .memberRoot "recomputed member_pubkeys_root does not match the channel leaf's committed root"
  let leaf ← atIndex w.memberLeaves i
  check (decide (e.regevDigestOfCoeffs slot.regevPk.coeffs = leaf.regevPkDigest)) .regev
    "witnessed Regev pubkey does not match that slot's member leaf"

/-! ### The per-slot checks, split by what they read -/

/-- `ChannelId::new` plus the account-tree inclusion of the previous leaf.
This is the only check that reads the running root. -/
def nativeChecksA (e : Env) (w : Witness) (strict : Bool) (slot : Slot) (root : Hash4) :
    Result Unit := do
  let _ ← check (decide (w.block.channelId < channelIdLimit)) .channelId "ChannelId::new"
  if strict then
    check (decide (e.merkleRoot slot.channelProof (e.channelLeafHash slot.prevLeaf)
      w.block.channelId = root)) .merkleProof "failed to verify account merkle proof"
  else pure ()

/-- The N-of-N witness restatement, applied only on a slot that updates. -/
def nativeChecksB (e : Env) (w : Witness) (strict : Bool) (i : Nat) (slot : Slot) :
    Result Unit :=
  if strict then nativeCheckNOfN e w i slot else pure ()

/-- The tx-class rules and the send-tree opening (source lines 486–585). -/
def nativeChecksC (e : Env) (w : Witness) (strict : Bool) (slot : Slot) : Result Unit :=
  if strict then do
    let _ ← check (decide (e.merkleRoot slot.txProof (e.txV2Hash slot.tx) slot.txIndex =
      e.reduceToHashOut w.block.txTreeRoot)) .merkleProof "failed to verify tx_v2 merkle proof"
    let _ ← check (decide (slot.tx.nonce = slot.prevLeaf.index)) .txClass
      "tx_v2 nonce must equal the previous channel send index"
    let _ ← (match slot.tx.txClass with
      | .userTransfer =>
          check (decide (slot.tx.channelActionRoot = Hash4.zero)) .txClass
            "user-transfer tx must have zero channel_action_root"
      | .channelAction => do
          let _ ← check (decide (slot.tx.transferTreeRoot = Hash4.zero)) .txClass
            "channel-action tx must have zero transfer_tree_root"
          let _ ← check (decide (e.merkleRoot slot.actionProof (e.actionHash slot.action)
            slot.actionIndex = slot.tx.channelActionRoot)) .merkleProof
            "failed to verify channel action merkle proof"
          let _ ← check (decide (slot.action.sourceChannelId = w.block.channelId)) .channelAction
            "channel action source_channel_id mismatch"
          match slot.action.kind with
          | .interChannelSend => pure ()
          | .channelClose => pure ()
          | .memberSetUpdate =>
              throw (.rejected .channelAction "member-set update is permanently retired"))
    check (decide (e.merkleRoot slot.sendProof (e.sendLeafHash SendLeaf.empty)
      slot.prevLeaf.index = slot.prevLeaf.sendTreeRoot)) .merkleProof
      "failed to verify send merkle proof"
  else pure ()

/-- `bp_sig_chain.try_into()` then one `list_chain_step`. The `try_into` CAN
fail natively; the circuit's repack cannot. -/
def nativeChainFold (e : Env) (chain : Bytes32) (sigLeaf : Hash4) : Result Bytes32 :=
  match e.hashOfBytes32Native chain with
  | none => .error (.rejected .chain "bp_sig_chain is not a canonical Poseidon hash out")
  | some prev => .ok (e.bytes32OfHash (e.chainStep prev sigLeaf))

/-! ### The leaf transition

This is the WHOLE per-channel state change: the send cursor advances by one,
`prev` becomes this block, the send tree gets a leaf recording
`(prev, cur, tx_tree_root)`, and `member_pubkeys_root` is COPIED. No fund
vector, no balance digest, no version — the leaf has no such field. -/

def nativeNewSendLeaf (bn : Nat) (blk : Block) (slot : Slot) : SendLeaf :=
  ⟨slot.prevLeaf.prev, bn, blk.txTreeRoot⟩

def nativeNewLeaf (e : Env) (bn : Nat) (blk : Block) (slot : Slot) : ChannelLeaf :=
  ⟨slot.prevLeaf.index + 1, bn,
    e.merkleRoot slot.sendProof (e.sendLeafHash (nativeNewSendLeaf bn blk slot)) slot.prevLeaf.index,
    slot.prevLeaf.memberPubkeysRoot⟩

def nativeNewRoot (e : Env) (bn : Nat) (blk : Block) (slot : Slot) : Hash4 :=
  e.merkleRoot slot.channelProof (e.channelLeafHash (nativeNewLeaf e bn blk slot)) blk.channelId

/-! ### The slot loop -/

def nativeStep (e : Env) (w : Witness) (strict : Bool) (sigLeaf : Hash4)
    (item : Nat × Nat × Slot) (st : NState) : Result NState :=
  if item.2.1 = 0 then .ok st
  else
    nativeChecksA e w strict item.2.2 st.root >>= fun _ =>
      if item.2.2.prevLeaf.prev = w.blockNumber then .ok st
      else
        nativeChecksB e w strict item.1 item.2.2 >>= fun _ =>
          nativeChainFold e st.chain sigLeaf >>= fun chain =>
            nativeChecksC e w strict item.2.2 >>= fun _ =>
              .ok ⟨nativeNewRoot e w.blockNumber w.block item.2.2, chain⟩

def nativeLoop (e : Env) (w : Witness) (strict : Bool) (sigLeaf : Hash4) :
    List (Nat × Nat × Slot) → NState → Result NState
  | [], st => .ok st
  | item :: rest, st => nativeStep e w strict sigLeaf item st >>= nativeLoop e w strict sigLeaf rest

/-- The channel-tree root after the loop, as a PURE fold that reads only the
block, the slots and the previous root — never the signature accumulator,
never the channel-state fields. -/
def nativeRootStep (e : Env) (bn : Nat) (blk : Block) (item : Nat × Nat × Slot) (root : Hash4) :
    Hash4 :=
  if item.2.1 = 0 then root
  else if item.2.2.prevLeaf.prev = bn then root
  else nativeNewRoot e bn blk item.2.2

def nativeRootFold (e : Env) (bn : Nat) (blk : Block) :
    List (Nat × Nat × Slot) → Hash4 → Hash4
  | [], root => root
  | item :: rest, root => nativeRootFold e bn blk rest (nativeRootStep e bn blk item root)

def nativeSlotItems (w : Witness) : List (Nat × Nat × Slot) :=
  indexed (List.zip w.block.keyIds w.slots)

/-- `UpdateUserTree::compute_public_inputs` (source lines 356–620). -/
def nativeComputePublicInputs (e : Env) (w : Witness) (strict : Bool) : Result PublicInputs := do
  let _ ← check (decide (w.slots.length = w.block.numUsers)) .length
    "per-slot witness vectors must all have block.num_users entries"
  let _ ← check (decide (w.block.keyIds.length = w.block.numUsers)) .blockError
    "key_ids length is not num_users"
  let newBlockHashChain := e.blockHash w.prevBlockHashChain w.block
  let _ ← check (decide (w.memberLeaves.length = maxSigCluster)) .length
    "member_leaves must cover all MAX_SIG_CLUSTER slots"
  let _ ← check (!strict || decide (w.newMemberLeaves = [])) .length
    "new_member_leaves is a retired direct-MSU wire and must be empty"
  let final ← nativeLoop e w strict (nativeSigLeaf e w) (nativeSlotItems w)
    ⟨w.prevAccountTreeRoot, w.prevBpSigChain⟩
  pure { blockNumber := w.blockNumber
         blockTimestamp := w.block.timestamp
         prevBlockHashChain := w.prevBlockHashChain
         prevAccountTreeRoot := w.prevAccountTreeRoot
         newBlockHashChain
         newAccountTreeRoot := final.root
         depositHashChain := w.block.depositHashChain
         channelRegHashChain := w.block.channelRegHashChain
         prevBpSigChain := w.prevBpSigChain
         newBpSigChain := final.chain }

/-- `to_public_inputs` — the validating mirror `prove` runs. -/
def nativeToPublicInputs (e : Env) (w : Witness) : Result PublicInputs :=
  nativeComputePublicInputs e w true

/-- `to_public_inputs_unchecked` — TEST-ONLY, every cross-check skipped. -/
def nativeToPublicInputsUnchecked (e : Env) (w : Witness) : Result PublicInputs :=
  nativeComputePublicInputs e w false

/-! ## What the leaf transition is

The only per-channel state this file writes. `member_pubkeys_root` is COPIED —
direct in-place member-set updates are retired — and there is no other field to
write, because `ChannelLeaf` has none. -/

theorem native_leaf_index_increments (e : Env) (bn : Nat) (blk : Block) (slot : Slot) :
    (nativeNewLeaf e bn blk slot).index = slot.prevLeaf.index + 1 := rfl

theorem native_leaf_prev_becomes_this_block (e : Env) (bn : Nat) (blk : Block) (slot : Slot) :
    (nativeNewLeaf e bn blk slot).prev = bn := rfl

theorem native_leaf_preserves_member_root (e : Env) (bn : Nat) (blk : Block) (slot : Slot) :
    (nativeNewLeaf e bn blk slot).memberPubkeysRoot = slot.prevLeaf.memberPubkeysRoot := rfl

theorem native_send_leaf_records_block_tx_root (bn : Nat) (blk : Block) (slot : Slot) :
    nativeNewSendLeaf bn blk slot = ⟨slot.prevLeaf.prev, bn, blk.txTreeRoot⟩ := rfl

/-- The new leaf is a function of `(prevLeaf, blockNumber, block.txTreeRoot,
sendProof)` ALONE: the channel-state fields, the signer set, the signature
accumulator, the tx class and the channel action do not appear. -/
theorem native_leaf_transition_is_index_prev_send_only (e : Env) (bn : Nat) (blk blk' : Block)
    (slot : Slot) (ht : blk.txTreeRoot = blk'.txTreeRoot) :
    nativeNewLeaf e bn blk slot = nativeNewLeaf e bn blk' slot := by
  simp [nativeNewLeaf, nativeNewSendLeaf, ht]

/-! ## The account root is a pure fold

The channel-tree root the block publishes never reads the signature
accumulator, the folded statement, or the channel-state fields. -/

theorem native_step_root (e : Env) (w : Witness) (strict : Bool) (sigLeaf : Hash4)
    {item : Nat × Nat × Slot} {st st' : NState}
    (h : nativeStep e w strict sigLeaf item st = .ok st') :
    st'.root = nativeRootStep e w.blockNumber w.block item st.root := by
  simp only [nativeStep, nativeRootStep] at h ⊢
  split at h
  · rw [if_pos ‹_›]; exact congrArg NState.root (Except.ok.inj h).symm
  · rw [if_neg ‹_›]
    simp only [bind_ok_iff, exists_unit] at h
    obtain ⟨-, h⟩ := h
    split at h
    · rw [if_pos ‹_›]; exact congrArg NState.root (Except.ok.inj h).symm
    · rw [if_neg ‹_›]
      simp only [bind_ok_iff, exists_unit] at h
      obtain ⟨-, chain, -, -, h⟩ := h
      exact congrArg NState.root (Except.ok.inj h).symm

theorem native_loop_root (e : Env) (w : Witness) (strict : Bool) (sigLeaf : Hash4) :
    ∀ (items : List (Nat × Nat × Slot)) (st r : NState),
      nativeLoop e w strict sigLeaf items st = .ok r →
        r.root = nativeRootFold e w.blockNumber w.block items st.root := by
  intro items
  induction items with
  | nil =>
      intro st r h
      simp only [nativeLoop] at h
      exact congrArg NState.root (Except.ok.inj h).symm
  | cons item rest ih =>
      intro st r h
      simp only [nativeLoop, bind_ok_iff] at h
      obtain ⟨st', hstep, hrest⟩ := h
      rw [nativeRootFold, ← native_step_root e w strict sigLeaf hstep]
      exact ih st' r hrest

theorem native_account_root_is_pure_fold (e : Env) (w : Witness) (strict : Bool)
    {p : PublicInputs} (h : nativeComputePublicInputs e w strict = .ok p) :
    p.newAccountTreeRoot =
      nativeRootFold e w.blockNumber w.block (nativeSlotItems w) w.prevAccountTreeRoot := by
  simp only [nativeComputePublicInputs, bind_ok_iff, exists_unit, unit_bind_ok_iff,
    pure_ok_iff] at h
  obtain ⟨-, -, -, -, final, hloop, hp⟩ := h
  subst hp
  exact native_loop_root e w strict (nativeSigLeaf e w) (nativeSlotItems w) _ final hloop

/-- FUND SAFETY, stated exactly: the published channel-tree root does not
depend on the channel-state fields at all — the fund vector, the balance H1,
the state version and the epoch are invisible to the tree update. There is
consequently NO sum-of-funds conservation enforced by this file. -/
theorem native_account_root_ignores_channel_state_fields (e : Env) (w : Witness) (strict : Bool)
    (f : ChannelStateFields) {p q : PublicInputs}
    (h1 : nativeComputePublicInputs e w strict = .ok p)
    (h2 : nativeComputePublicInputs e { w with fields := f } strict = .ok q) :
    p.newAccountTreeRoot = q.newAccountTreeRoot := by
  rw [native_account_root_is_pure_fold e w strict h1,
    native_account_root_is_pure_fold e { w with fields := f } strict h2]
  rfl

/-! ## `to_public_inputs_unchecked` really is the same computation

Source lines 335–354 claim the unchecked mirror returns exactly what the strict
mirror would for any witness the strict mirror accepts. Proved here for the
model. -/

theorem native_checks_a_relax (e : Env) (w : Witness) (slot : Slot) (root : Hash4)
    (h : nativeChecksA e w true slot root = .ok ()) :
    nativeChecksA e w false slot root = .ok () := by
  simp only [nativeChecksA, unit_bind_ok_iff] at h ⊢
  exact ⟨h.1, rfl⟩

theorem native_step_relax (e : Env) (w : Witness) (sigLeaf : Hash4)
    {item : Nat × Nat × Slot} {st st' : NState}
    (h : nativeStep e w true sigLeaf item st = .ok st') :
    nativeStep e w false sigLeaf item st = .ok st' := by
  simp only [nativeStep] at h ⊢
  split at h
  · rw [if_pos ‹_›]; exact h
  · rw [if_neg ‹_›]
    simp only [bind_ok_iff, exists_unit] at h ⊢
    refine ⟨native_checks_a_relax e w _ _ h.1, ?_⟩
    obtain ⟨-, h⟩ := h
    split at h
    · rw [if_pos ‹_›]; exact h
    · rw [if_neg ‹_›]
      simp only [bind_ok_iff, exists_unit] at h ⊢
      obtain ⟨-, chain, hchain, -, h⟩ := h
      exact ⟨rfl, chain, hchain, rfl, h⟩

theorem native_loop_relax (e : Env) (w : Witness) (sigLeaf : Hash4) :
    ∀ (items : List (Nat × Nat × Slot)) (st r : NState),
      nativeLoop e w true sigLeaf items st = .ok r →
        nativeLoop e w false sigLeaf items st = .ok r := by
  intro items
  induction items with
  | nil => intro st r h; exact h
  | cons item rest ih =>
      intro st r h
      simp only [nativeLoop, bind_ok_iff] at h ⊢
      obtain ⟨st', hstep, hrest⟩ := h
      exact ⟨st', native_step_relax e w sigLeaf hstep, ih st' r hrest⟩

theorem native_unchecked_agrees_with_strict (e : Env) (w : Witness) {p : PublicInputs}
    (h : nativeToPublicInputs e w = .ok p) : nativeToPublicInputsUnchecked e w = .ok p := by
  simp only [nativeToPublicInputs, nativeToPublicInputsUnchecked, nativeComputePublicInputs,
    bind_ok_iff, exists_unit, unit_bind_ok_iff, pure_ok_iff] at h ⊢
  obtain ⟨hslots, hkeys, hmem, -, final, hloop, hp⟩ := h
  exact ⟨hslots, hkeys, hmem, by simp [check], final,
    native_loop_relax e w (nativeSigLeaf e w) _ _ _ hloop, hp⟩

/-! ## What a signing slot must satisfy (`check_n_of_n_witness`) -/

theorem native_n_of_n_facts (e : Env) (w : Witness) (i : Nat) (slot : Slot)
    (h : nativeCheckNOfN e w i slot = .ok ()) :
    w.block.txTreeRoot ≠ Bytes32.zero ∧ i < maxSigCluster ∧
      2 ≤ w.signerCount ∧ w.signerCount ≤ maxSigCluster ∧ i < w.signerCount ∧
      e.memberTreeRoot (w.memberLeaves.map e.memberLeafHash) = slot.prevLeaf.memberPubkeysRoot ∧
      (∀ item ∈ indexed w.memberLeaves, nativeOccupancyCheck w item = .ok ()) := by
  simp only [nativeCheckNOfN, unit_bind_ok_iff, bind_ok_iff, exists_unit, check_ok_iff,
    for_each_success, decide_eq_true_eq, Bool.and_eq_true] at h
  obtain ⟨h1, h2, ⟨h3, h4⟩, h5, h6, h7, -⟩ := h
  exact ⟨h1, h2, h3, h4, h6, h7, h5⟩

/-- Occupancy is EXACTLY `signer_count`: nothing above it, nothing empty below
it. Together with the root connect this is what makes
`signer_count == member_count` a consequence rather than an assumption about
left-packing. -/
theorem native_occupancy_is_exact (w : Witness) (idx : Nat) (leaf : MemberLeaf)
    (h : nativeOccupancyCheck w (idx, leaf) = .ok ()) :
    (idx < w.signerCount → leaf.pkG ≠ Hash4.zero) ∧
      (¬ idx < w.signerCount → leaf = MemberLeaf.empty) := by
  simp only [nativeOccupancyCheck, unit_bind_ok_iff, check_ok_iff, Bool.or_eq_true,
    decide_eq_true_eq, Bool.not_eq_true', decide_eq_false_iff_not] at h
  obtain ⟨h1, h2⟩ := h
  constructor
  · intro hi
    rcases h2 with h2 | h2
    · exact absurd hi h2
    · exact h2
  · intro hi
    rcases h1 with h1 | h1
    · exact absurd h1 hi
    · exact h1

/-! ## What the strict slot checks enforce -/

theorem native_checks_c_nonce (e : Env) (w : Witness) (slot : Slot)
    (h : nativeChecksC e w true slot = .ok ()) : slot.tx.nonce = slot.prevLeaf.index := by
  simp only [nativeChecksC, if_pos, unit_bind_ok_iff, check_ok_iff, decide_eq_true_eq] at h
  exact h.2.1

theorem native_checks_c_binds_tx_to_block_root (e : Env) (w : Witness) (slot : Slot)
    (h : nativeChecksC e w true slot = .ok ()) :
    e.merkleRoot slot.txProof (e.txV2Hash slot.tx) slot.txIndex =
      e.reduceToHashOut w.block.txTreeRoot := by
  simp only [nativeChecksC, if_pos, unit_bind_ok_iff, check_ok_iff, decide_eq_true_eq] at h
  exact h.1

theorem native_checks_c_binds_action_to_source_channel (e : Env) (w : Witness) (slot : Slot)
    (hclass : slot.tx.txClass = .channelAction)
    (h : nativeChecksC e w true slot = .ok ()) :
    slot.action.sourceChannelId = w.block.channelId := by
  simp only [nativeChecksC, if_pos, unit_bind_ok_iff, check_ok_iff, hclass,
    decide_eq_true_eq] at h
  exact h.2.2.1.2.2.1

/-- The reserved `MemberSetUpdate` tag is refused at the slot where the action
is authenticated. Direct in-place member-set updates are permanently retired. -/
theorem native_rejects_member_set_update (e : Env) (w : Witness) (slot : Slot)
    (hclass : slot.tx.txClass = .channelAction)
    (hkind : slot.action.kind = .memberSetUpdate) :
    nativeChecksC e w true slot ≠ .ok () := by
  intro h
  simp only [nativeChecksC, if_pos, unit_bind_ok_iff, check_ok_iff, hclass, hkind,
    throw_ok_iff_false, and_false, false_and] at h

/-- Both surviving action kinds are admitted with NO further condition: nothing
about the destination channel, the tx hash, the seal or the payload. -/
theorem native_admits_inter_channel_send_and_close (kind : ChannelActionKind)
    (h : kind ≠ .memberSetUpdate) :
    kind = .interChannelSend ∨ kind = .channelClose := by
  cases kind with
  | interChannelSend => exact Or.inl rfl
  | channelClose => exact Or.inr rfl
  | memberSetUpdate => exact absurd rfl h

theorem native_strict_rejects_retired_msu_wire (e : Env) (w : Witness) (p : PublicInputs)
    (h : w.newMemberLeaves ≠ []) : nativeToPublicInputs e w ≠ .ok p := by
  intro hok
  simp only [nativeToPublicInputs, nativeComputePublicInputs, bind_ok_iff, exists_unit,
    unit_bind_ok_iff, check_ok_iff, Bool.or_eq_true, Bool.not_eq_true', decide_eq_true_eq,
    decide_eq_false_iff_not] at hok
  obtain ⟨-, -, -, hne, -⟩ := hok
  rcases hne with hne | hne
  · exact hne
  · exact h hne

/-! ## The signature accumulator

The block folds AT MOST ONE statement per slot, and that statement is exactly
the shared `falcon_sig::agg_list` leaf over `(IMCH digest, signer_count,
pk_list_digest)`. Whether `signer_count` real Falcon signatures over that
digest exist is decided by the recursive aggregate-list proof another circuit
consumes, NOT here. -/

theorem native_sig_leaf_is_the_shared_agg_list_leaf (e : Env) (w : Witness) :
    nativeSigLeaf e w =
      e.aggListLeaf (e.signingDigest w.fields w.block.channelId w.block.txTreeRoot) w.signerCount
        (e.aggPkListDigest (w.memberLeaves.map (fun leaf => e.bytes32OfHash leaf.pkG))) := rfl

/-- Only ONE channel-tree index is ever written: the block's own
`channel_id`. -/
theorem native_root_step_uses_only_the_block_channel (e : Env) (bn : Nat) (blk : Block)
    (slot : Slot) :
    nativeNewRoot e bn blk slot =
      e.merkleRoot slot.channelProof (e.channelLeafHash (nativeNewLeaf e bn blk slot))
        blk.channelId := rfl

theorem native_step_chain (e : Env) (w : Witness) (strict : Bool) (sigLeaf : Hash4)
    {item : Nat × Nat × Slot} {st st' : NState}
    (h : nativeStep e w strict sigLeaf item st = .ok st') :
    st'.chain = st.chain ∨
      ∃ prev, e.hashOfBytes32Native st.chain = some prev ∧
        st'.chain = e.bytes32OfHash (e.chainStep prev sigLeaf) := by
  simp only [nativeStep] at h
  split at h
  · exact Or.inl (congrArg NState.chain (Except.ok.inj h).symm)
  · simp only [bind_ok_iff, exists_unit] at h
    obtain ⟨-, h⟩ := h
    split at h
    · exact Or.inl (congrArg NState.chain (Except.ok.inj h).symm)
    · simp only [bind_ok_iff, exists_unit] at h
      obtain ⟨-, chain, hchain, -, h⟩ := h
      refine Or.inr ?_
      simp only [nativeChainFold] at hchain
      split at hchain
      · exact absurd hchain (by simp)
      · rename_i prev hprev
        exact ⟨prev, hprev, by
          rw [congrArg NState.chain (Except.ok.inj h).symm]
          exact (Except.ok.inj hchain).symm⟩

/-! ## The public inputs are the block's own fields -/

theorem native_public_inputs_copy_block_fields (e : Env) (w : Witness) (strict : Bool)
    {p : PublicInputs} (h : nativeComputePublicInputs e w strict = .ok p) :
    p.blockNumber = w.blockNumber ∧ p.blockTimestamp = w.block.timestamp ∧
      p.prevBlockHashChain = w.prevBlockHashChain ∧
      p.prevAccountTreeRoot = w.prevAccountTreeRoot ∧
      p.newBlockHashChain = e.blockHash w.prevBlockHashChain w.block ∧
      p.depositHashChain = w.block.depositHashChain ∧
      p.channelRegHashChain = w.block.channelRegHashChain ∧
      p.prevBpSigChain = w.prevBpSigChain := by
  simp only [nativeComputePublicInputs, bind_ok_iff, exists_unit, unit_bind_ok_iff,
    pure_ok_iff] at h
  obtain ⟨-, -, -, -, final, -, hp⟩ := h
  subst hp
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-! ## The circuit (`UpdateUserTreeTarget::new`, source lines 968–1425)

An ARBITRARY satisfying witness, not the native path. Class tags and action
kinds are free field elements here, not Rust enums. -/

structure SlotT where
  keyId : Nat
  prevLeaf : ChannelLeaf
  channelProof : MerklePath
  sendProof : MerklePath
  txIndex : Nat
  tx : TxV2T
  txProof : MerklePath
  actionIndex : Nat
  action : ChannelActionT
  actionProof : MerklePath
  /-- The `2 * REGEV_N` witnessed Regev coefficients; only block slots below
  `MAX_SIG_CLUSTER` get these targets. -/
  regevCoeffs : List Nat
  deriving Repr, Inhabited

structure CircuitWitness where
  blockNumber : Nat
  prevBlockHashChain : Bytes32
  prevAccountTreeRoot : Hash4
  block : Block
  slots : List SlotT
  prevBpSigChain : Bytes32
  memberLeaves : List MemberLeaf
  signerCount : Nat
  fields : ChannelStateFields
  publicInputs : PublicInputs
  deriving Repr, Inhabited

/-- `is_dummy = is_equal(key_id, 0)`; `should_check_account = not is_dummy`. -/
def circuitIsDummy (s : SlotT) : Bool := decide (s.keyId = 0)

/-- `should_update = should_check_account and (prev != block_number)` —
COMPUTED from witnessed values, never a prover flag. -/
def circuitShouldUpdate (w : CircuitWitness) (s : SlotT) : Bool :=
  !circuitIsDummy s && !decide (s.prevLeaf.prev = w.blockNumber)

/-- `any_sign`, the OR of every slot's `should_update` (source line 1263). -/
def circuitAnySign (w : CircuitWitness) : Bool := w.slots.any (circuitShouldUpdate w)

/-- `is_signer[i] = lt_const_threshold(i, signer_count)`, the shared
thermometer. -/
def circuitIsSigner (w : CircuitWitness) (i : Nat) : Bool := decide (i < w.signerCount)

def circuitNewLeaf (e : Env) (w : CircuitWitness) (s : SlotT) : ChannelLeaf :=
  ⟨s.prevLeaf.index + 1, w.blockNumber,
    e.merkleRoot s.sendProof
      (e.sendLeafHash ⟨s.prevLeaf.prev, w.blockNumber, w.block.txTreeRoot⟩) s.prevLeaf.index,
    s.prevLeaf.memberPubkeysRoot⟩

/-- `account_tree_root = select(should_update, updated_root, current_root)`. -/
def circuitRootStep (e : Env) (w : CircuitWitness) (s : SlotT) (root : Hash4) : Hash4 :=
  if circuitShouldUpdate w s then
    e.merkleRoot s.channelProof (e.channelLeafHash (circuitNewLeaf e w s)) w.block.channelId
  else root

def circuitRootAfter (e : Env) (w : CircuitWitness) (n : Nat) : Hash4 :=
  (w.slots.take n).foldl (fun root s => circuitRootStep e w s root) w.prevAccountTreeRoot

def circuitAccountRoot (e : Env) (w : CircuitWitness) : Hash4 :=
  w.slots.foldl (fun root s => circuitRootStep e w s root) w.prevAccountTreeRoot

def circuitSignedDigest (e : Env) (w : CircuitWitness) : Bytes32 :=
  e.signingDigest w.fields w.block.channelId w.block.txTreeRoot

def circuitSigLeaf (e : Env) (w : CircuitWitness) : Hash4 :=
  e.aggListLeaf (circuitSignedDigest e w) w.signerCount
    (e.aggPkListDigest (w.memberLeaves.map (fun leaf => e.bytes32OfHash leaf.pkG)))

/-- `bp_sig_chain = select(should_verify_sig, chain_step(...), bp_sig_chain)`.
The in-circuit `to_hash_out` repack is TOTAL — unlike the native `try_into`. -/
def circuitChainStep (e : Env) (w : CircuitWitness) (sigLeaf : Hash4) (s : SlotT)
    (chain : Bytes32) : Bytes32 :=
  if circuitShouldUpdate w s then
    e.bytes32OfHash (e.chainStep (e.hashOfBytes32Target chain) sigLeaf)
  else chain

def circuitChain (e : Env) (w : CircuitWitness) (sigLeaf : Hash4) : Bytes32 :=
  w.slots.foldl (fun chain s => circuitChainStep e w sigLeaf s chain) w.prevBpSigChain

/-- The local constraint system, one field per source connection. `is_equal`,
`not`, `and`, `or`, `select`, `conditional_assert_eq`, `assert_zero` and
`range_check` are read as their boolean / integer relations; that lowering is a
boundary. -/
structure CircuitGates (e : Env) (w : CircuitWitness) : Prop where
  /-- 1132–1135: a non-dummy slot's previous leaf opens the running root at
  `channel_id` — the ONLY channel-tree index this circuit ever touches. -/
  channelOpens : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitIsDummy s = false →
    e.merkleRoot s.channelProof (e.channelLeafHash s.prevLeaf) w.block.channelId =
      circuitRootAfter e w i
  /-- 1141–1142: the slot's TxV2 is in the block's tx tree. -/
  txBound : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    e.merkleRoot s.txProof (e.txV2HashT s.tx) s.txIndex = e.reduceToHashOut w.block.txTreeRoot
  /-- 1148: base-send replay gate — the tx nonce is the leaf's send cursor. -/
  nonceBound : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    s.tx.nonce = s.prevLeaf.index
  /-- 1154–1163. -/
  validClass : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    s.tx.txClass = userTransferClass ∨ s.tx.txClass = channelActionClass
  /-- 1165–1169. -/
  userTransferZeroActionRoot : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s →
    circuitShouldUpdate w s = true → s.tx.txClass = userTransferClass →
    s.tx.channelActionRoot = Hash4.zero
  /-- 1170–1174. -/
  channelActionZeroTransferRoot : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s →
    circuitShouldUpdate w s = true → s.tx.txClass = channelActionClass →
    s.tx.transferTreeRoot = Hash4.zero
  /-- 1176–1185. -/
  actionBound : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    s.tx.txClass = channelActionClass →
    e.merkleRoot s.actionProof (e.actionHashT s.action) s.actionIndex = s.tx.channelActionRoot
  /-- 1186–1190: the ONLY thing tying the action to a channel. Nothing here
  constrains `destination_channel_id`, `tx_hash`, `seal` or `payload_hash`. -/
  actionSourceChannel : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    s.tx.txClass = channelActionClass → s.action.sourceChannelId = w.block.channelId
  /-- 1197–1202: the reserved `MemberSetUpdate` tag is refused. -/
  noMemberSetUpdate : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    s.tx.txClass = channelActionClass → s.action.kind ≠ memberSetUpdateKind
  /-- 1204–1210: the send slot being written was empty (append-only). -/
  sendOpens : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    e.merkleRoot s.sendProof (e.sendLeafHash SendLeaf.empty) s.prevLeaf.index =
      s.prevLeaf.sendTreeRoot
  /-- 1268–1272: `H2 = 0` is reserved for in-channel updates and must never
  carry a member signature. -/
  txRootNonzeroWhenSigning : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → circuitShouldUpdate w s = true →
    w.block.txTreeRoot ≠ Bytes32.zero
  /-- 1274–1286: a block slot beyond the member tree cannot sign. -/
  outOfRangeCannotSign : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → maxSigCluster ≤ i →
    circuitShouldUpdate w s = false
  /-- 1289–1293: THE N-of-N binding — the recomputed member root IS the
  channel leaf's committed `member_pubkeys_root`. -/
  memberRootConnect : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → i < maxSigCluster →
    circuitShouldUpdate w s = true →
    s.prevLeaf.memberPubkeysRoot = e.memberTreeRoot (w.memberLeaves.map e.memberLeafHash)
  /-- 1297–1299: the posting slot is itself an active member slot. -/
  postsFromActiveSlot : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → i < maxSigCluster →
    circuitShouldUpdate w s = true → i < w.signerCount
  /-- 1306: `2 * REGEV_N` coefficient targets per in-range block slot. -/
  regevWidth : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → i < maxSigCluster →
    s.regevCoeffs.length = 2 * regevN
  /-- 1309–1311: each coefficient range-checked to 32 bits (digest
  malleability F1-A). -/
  regevRangeChecked : ∀ (i : Nat) (s : SlotT), w.slots[i]? = some s → i < maxSigCluster →
    ∀ c ∈ s.regevCoeffs, c < wordBase
  /-- 1317–1322: the bp slot's Regev digest is bound to ITS member leaf. The
  other slots' `regev_pk_digest` ride on the root connect alone. -/
  regevDigestConnect : ∀ (i : Nat) (s : SlotT) (leaf : MemberLeaf), w.slots[i]? = some s → i < maxSigCluster →
    circuitShouldUpdate w s = true → w.memberLeaves[i]? = some leaf →
    e.regevDigestOfCoeffs s.regevCoeffs = leaf.regevPkDigest
  /-- The circuit allocates exactly `MAX_SIG_CLUSTER` member-leaf targets. -/
  memberLeafCount : w.memberLeaves.length = maxSigCluster
  /-- 1356–1362: `2 <= signer_count <= MAX_SIG_CLUSTER`, gated on `any_sign`. -/
  signerCountRange : circuitAnySign w = true → 2 ≤ w.signerCount ∧ w.signerCount ≤ maxSigCluster
  /-- 1364–1379: slots at or above `signer_count` are the EMPTY leaf. -/
  paddingSlotsEmpty : circuitAnySign w = true → ∀ (i : Nat) (leaf : MemberLeaf), w.memberLeaves[i]? = some leaf →
    ¬ i < w.signerCount → leaf = MemberLeaf.empty
  /-- 1380–1388: an ACTIVE slot must carry a real key. -/
  activeSlotsOccupied : circuitAnySign w = true → ∀ (i : Nat) (leaf : MemberLeaf), w.memberLeaves[i]? = some leaf →
    i < w.signerCount → leaf.pkG ≠ Hash4.zero
  /-- 1391–1402: the registered public inputs. -/
  pisBlockNumber : w.publicInputs.blockNumber = w.blockNumber
  pisTimestamp : w.publicInputs.blockTimestamp = w.block.timestamp
  pisPrevBlockHashChain : w.publicInputs.prevBlockHashChain = w.prevBlockHashChain
  pisPrevAccountTreeRoot : w.publicInputs.prevAccountTreeRoot = w.prevAccountTreeRoot
  pisNewBlockHashChain : w.publicInputs.newBlockHashChain = e.blockHash w.prevBlockHashChain w.block
  pisNewAccountTreeRoot : w.publicInputs.newAccountTreeRoot = circuitAccountRoot e w
  pisDepositHashChain : w.publicInputs.depositHashChain = w.block.depositHashChain
  pisChannelRegHashChain : w.publicInputs.channelRegHashChain = w.block.channelRegHashChain
  pisPrevBpSigChain : w.publicInputs.prevBpSigChain = w.prevBpSigChain
  pisNewBpSigChain : w.publicInputs.newBpSigChain = circuitChain e w (circuitSigLeaf e w)

section CircuitFacts
variable {e : Env} {w : CircuitWitness}

/-! ### The leaf transition the circuit builds -/

theorem circuit_leaf_index_increments (s : SlotT) :
    (circuitNewLeaf e w s).index = s.prevLeaf.index + 1 := rfl

theorem circuit_leaf_prev_becomes_this_block (s : SlotT) :
    (circuitNewLeaf e w s).prev = w.blockNumber := rfl

/-- Every release transition preserves the registered member root; there is no
in-place root select left in the circuit. -/
theorem circuit_leaf_preserves_member_root (s : SlotT) :
    (circuitNewLeaf e w s).memberPubkeysRoot = s.prevLeaf.memberPubkeysRoot := rfl

/-! ### FUND SAFETY: the tree update cannot see the funds -/

/-- The published channel-tree root is independent of the channel-state
fields, hence of `fund_amounts`, `balance_state_h1` and `state_version`. No
sum-of-funds conservation is enforced anywhere in this circuit — there is no
fund quantity in the channel-tree leaf to conserve. -/
theorem circuit_account_root_ignores_channel_state_fields (f : ChannelStateFields) :
    circuitAccountRoot e { w with fields := f } = circuitAccountRoot e w := rfl

/-- ... and neither is it affected by the signature accumulator or the folded
statement: the root fold never reads them. -/
theorem circuit_account_root_ignores_prev_chain (c : Bytes32) :
    circuitAccountRoot e { w with prevBpSigChain := c } = circuitAccountRoot e w := rfl

/-- Only ONE channel-tree index is ever opened or written: the block's own
`channel_id`. No destination-channel leaf is credited, so a cross-channel
transfer's debit side is unpaired here. -/
theorem circuit_root_step_uses_only_the_block_channel (s : SlotT) (root : Hash4) :
    circuitRootStep e w s root =
      if circuitShouldUpdate w s then
        e.merkleRoot s.channelProof (e.channelLeafHash (circuitNewLeaf e w s)) w.block.channelId
      else root := rfl

/-! ### Authorization: what a signing slot is forced to prove -/

theorem circuit_signing_binds_registered_member_root (g : CircuitGates e w)
    (i : Nat) (s : SlotT) (hs : w.slots[i]? = some s) (hi : i < maxSigCluster)
    (hu : circuitShouldUpdate w s = true) :
    s.prevLeaf.memberPubkeysRoot = e.memberTreeRoot (w.memberLeaves.map e.memberLeafHash) :=
  g.memberRootConnect i s hs hi hu

theorem circuit_signing_requires_nonzero_tx_root (g : CircuitGates e w)
    (i : Nat) (s : SlotT) (hs : w.slots[i]? = some s) (hu : circuitShouldUpdate w s = true) :
    w.block.txTreeRoot ≠ Bytes32.zero :=
  g.txRootNonzeroWhenSigning i s hs hu

theorem circuit_out_of_range_slot_cannot_sign (g : CircuitGates e w)
    (i : Nat) (s : SlotT) (hs : w.slots[i]? = some s) (hi : maxSigCluster ≤ i) :
    circuitShouldUpdate w s = false :=
  g.outOfRangeCannotSign i s hs hi

theorem circuit_signer_count_between_two_and_cluster (g : CircuitGates e w)
    (h : circuitAnySign w = true) : 2 ≤ w.signerCount ∧ w.signerCount ≤ maxSigCluster :=
  g.signerCountRange h

/-- Occupancy is exactly `signer_count` on a signing block: a real member
parked above it, or an empty slot below it, is refused. -/
theorem circuit_occupancy_is_exact (g : CircuitGates e w) (h : circuitAnySign w = true)
    (i : Nat) (leaf : MemberLeaf) (hl : w.memberLeaves[i]? = some leaf) :
    (i < w.signerCount → leaf.pkG ≠ Hash4.zero) ∧
      (¬ i < w.signerCount → leaf = MemberLeaf.empty) :=
  ⟨fun hi => g.activeSlotsOccupied h i leaf hl hi, fun hi => g.paddingSlotsEmpty h i leaf hl hi⟩

/-- The reserved `MemberSetUpdate` tag is rejected in-circuit, so the retired
transition cannot be revived through the unchecked public-input path. -/
theorem circuit_rejects_member_set_update (g : CircuitGates e w)
    (i : Nat) (s : SlotT) (hs : w.slots[i]? = some s) (hu : circuitShouldUpdate w s = true)
    (hc : s.tx.txClass = channelActionClass) : s.action.kind ≠ memberSetUpdateKind :=
  g.noMemberSetUpdate i s hs hu hc

/-- The signed digest's channel id and `h2_tag` are the BLOCK's own targets:
a signature collected for another channel, or over another tx root, is a
signature over a different digest. -/
theorem circuit_signed_digest_is_bound_to_this_block :
    circuitSignedDigest e w = e.signingDigest w.fields w.block.channelId w.block.txTreeRoot := rfl

/-- Exactly one chain step per updating slot, using the shared aggregate-list
leaf. Whether `signer_count` real Falcon signatures over that digest exist is
NOT decided here: it is the recursive aggregate-list proof's obligation. -/
theorem circuit_chain_step_folds_the_agg_list_leaf (sigLeaf : Hash4) (s : SlotT) (chain : Bytes32)
    (hu : circuitShouldUpdate w s = true) :
    circuitChainStep e w sigLeaf s chain =
      e.bytes32OfHash (e.chainStep (e.hashOfBytes32Target chain) sigLeaf) := by
  simp [circuitChainStep, hu]

theorem circuit_chain_step_is_identity_on_a_non_updating_slot (sigLeaf : Hash4) (s : SlotT)
    (chain : Bytes32) (hu : circuitShouldUpdate w s = false) :
    circuitChainStep e w sigLeaf s chain = chain := by
  simp [circuitChainStep, hu]

/-- A block that applies no member signature folds nothing, whatever the
witnessed `signer_count` and member leaves are: the well-formedness of the
signer set is gated on the COMPUTED `any_sign`. -/
theorem circuit_non_signing_block_folds_nothing (sigLeaf : Hash4)
    (h : circuitAnySign w = false) : circuitChain e w sigLeaf = w.prevBpSigChain := by
  have hall : ∀ s ∈ w.slots, circuitShouldUpdate w s = false := by
    intro s hs
    cases hb : circuitShouldUpdate w s with
    | false => rfl
    | true =>
        exfalso
        have hany : circuitAnySign w = true := by
          simp only [circuitAnySign, List.any_eq_true]
          exact ⟨s, hs, hb⟩
        rw [hany] at h
        exact Bool.noConfusion h
  simp only [circuitChain]
  revert hall
  generalize w.prevBpSigChain = start
  induction w.slots generalizing start with
  | nil => intro _; rfl
  | cons s rest ih =>
      intro hall
      simp only [List.foldl_cons]
      rw [circuit_chain_step_is_identity_on_a_non_updating_slot sigLeaf s start
        (hall s (List.mem_cons_self _ _))]
      exact ih start (fun x hx => hall x (List.mem_cons_of_mem _ hx))

end CircuitFacts

/-! ## A concrete accepted block

A 2-of-2 signing block on channel 9: one block slot (the bp, slot 0), a
`ChannelAction` tx of kind `InterChannelSend`, and the channel's whole
registered member set. Both the destination channel id and the whole
channel-state preimage (fund vector, balance H1, state version) are left FREE
parameters of the example, which is precisely the point: neither is checked. -/

def exampleEnv : Env where
  blockHash := fun prev _ => prev
  merkleRoot := fun _ _ _ => Hash4.zero
  channelLeafHash := fun _ => Hash4.zero
  sendLeafHash := fun _ => Hash4.zero
  txV2Hash := fun _ => Hash4.zero
  txV2HashT := fun _ => Hash4.zero
  actionHash := fun _ => Hash4.zero
  actionHashT := fun _ => Hash4.zero
  memberLeafHash := fun _ => Hash4.zero
  memberTreeRoot := fun _ => Hash4.zero
  regevDigestOfCoeffs := fun _ => Hash4.zero
  signingDigest := fun f _ _ => ⟨[f.stateVersion, 0, 0, 0, 0, 0, 0, 0]⟩
  aggPkListDigest := fun _ => Hash4.zero
  aggListLeaf := fun _ n _ => ⟨n, 0, 0, 0⟩
  chainStep := fun a b => ⟨a.w0 + b.w0, 0, 0, 0⟩
  reduceToHashOut := fun _ => Hash4.zero
  bytes32OfHash := fun h => ⟨[h.w0, h.w1, h.w2, h.w3, 0, 0, 0, 0]⟩
  hashOfBytes32Native := fun _ => some Hash4.zero
  hashOfBytes32Target := fun _ => Hash4.zero

def exampleBlock : Block :=
  ⟨1, 9, 1234, [7], ⟨[1, 0, 0, 0, 0, 0, 0, 0]⟩, ⟨[5, 0, 0, 0, 0, 0, 0, 0]⟩,
    ⟨[6, 0, 0, 0, 0, 0, 0, 0]⟩⟩

def exampleMemberLeaves : List MemberLeaf :=
  [⟨⟨1, 0, 0, 0⟩, Hash4.zero, Hash4.zero⟩, ⟨⟨2, 0, 0, 0⟩, Hash4.zero, Hash4.zero⟩,
    MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty,
    MemberLeaf.empty, MemberLeaf.empty]

def examplePrevLeaf : ChannelLeaf := ⟨0, 4, Hash4.zero, Hash4.zero⟩

/-- The IMCH preimage, with the fund vector and state version as parameters. -/
def exampleFields (version : Nat) : ChannelStateFields :=
  ⟨3, 30, 0, List.replicate maxChannelTokens 1000, Bytes32.zero, Bytes32.zero, Bytes32.zero,
    7, Bytes32.zero, version⟩

def exampleSlot (dest : Nat) : Slot :=
  ⟨examplePrevLeaf, ⟨0⟩, ⟨1⟩, 0, ⟨.channelAction, Hash4.zero, 0, Hash4.zero⟩, ⟨2⟩, 0,
    ⟨.interChannelSend, 9, dest, Bytes32.zero, Bytes32.zero, Hash4.zero⟩, ⟨3⟩, ⟨[], []⟩⟩

def exampleWitness (dest version : Nat) : Witness :=
  ⟨⟨[3, 0, 0, 0, 0, 0, 0, 0]⟩, Hash4.zero, 30, exampleBlock, [exampleSlot dest], Bytes32.zero,
    exampleMemberLeaves, [], 2, exampleFields version⟩

def examplePublicInputs : PublicInputs :=
  ⟨30, 1234, ⟨[3, 0, 0, 0, 0, 0, 0, 0]⟩, Hash4.zero, ⟨[3, 0, 0, 0, 0, 0, 0, 0]⟩, Hash4.zero,
    ⟨[5, 0, 0, 0, 0, 0, 0, 0]⟩, ⟨[6, 0, 0, 0, 0, 0, 0, 0]⟩, Bytes32.zero,
    ⟨[2, 0, 0, 0, 0, 0, 0, 0]⟩⟩

/-- Non-vacuous positive: the STRICT native mirror accepts this block, for
EVERY destination channel id and EVERY channel-state preimage. -/
theorem native_accepts_example_block (dest version : Nat) :
    nativeToPublicInputs exampleEnv (exampleWitness dest version) = .ok examplePublicInputs := by
  rfl

/-- Consequence, stated separately because it is the fund-safety point: the
destination channel of an `InterChannelSend` is not checked against anything,
and no destination leaf is credited. -/
theorem native_accepts_any_destination_channel (dest : Nat) :
    nativeToPublicInputs exampleEnv (exampleWitness dest 11) = .ok examplePublicInputs :=
  native_accepts_example_block dest 11

/-- Consequence: the fund vector and state version in the signed preimage are
opaque to this circuit; the same public inputs come out for every version. -/
theorem native_accepts_any_channel_state_version (version : Nat) :
    nativeToPublicInputs exampleEnv (exampleWitness 10 version) = .ok examplePublicInputs :=
  native_accepts_example_block 10 version

def exampleSlotT (dest : Nat) : SlotT :=
  ⟨7, examplePrevLeaf, ⟨0⟩, ⟨1⟩, 0, ⟨channelActionClass, Hash4.zero, 0, Hash4.zero⟩, ⟨2⟩, 0,
    ⟨interChannelSendKind, 9, dest, Bytes32.zero, Bytes32.zero, Hash4.zero⟩, ⟨3⟩,
    List.replicate (2 * regevN) 0⟩

def exampleCircuitWitness (dest version : Nat) : CircuitWitness :=
  ⟨30, ⟨[3, 0, 0, 0, 0, 0, 0, 0]⟩, Hash4.zero, exampleBlock, [exampleSlotT dest], Bytes32.zero,
    exampleMemberLeaves, 2, exampleFields version, examplePublicInputs⟩

theorem example_circuit_slot_updates (dest version : Nat) :
    circuitShouldUpdate (exampleCircuitWitness dest version) (exampleSlotT dest) = true := rfl

theorem example_circuit_block_signs (dest version : Nat) :
    circuitAnySign (exampleCircuitWitness dest version) = true := rfl

theorem example_circuit_slots (dest version : Nat) :
    ∀ (i : Nat) (s : SlotT), (exampleCircuitWitness dest version).slots[i]? = some s →
      i = 0 ∧ s = exampleSlotT dest := by
  intro i s h
  cases i with
  | zero => exact ⟨rfl, by simpa [exampleCircuitWitness] using h.symm⟩
  | succ n => simp [exampleCircuitWitness] at h

/-- Non-vacuous positive for the ARBITRARY-witness side: the same block is a
satisfying witness of every gate the circuit lays down, again for every
destination channel id and every channel-state preimage. -/
theorem circuit_gates_hold_for_example (dest version : Nat) :
    CircuitGates exampleEnv (exampleCircuitWitness dest version) where
  channelOpens := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  txBound := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  nonceBound := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  validClass := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    exact Or.inr rfl
  userTransferZeroActionRoot := by
    intro i s hs _ hc; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    exact absurd hc (by simp [exampleSlotT, channelActionClass, userTransferClass])
  channelActionZeroTransferRoot := by
    intro i s hs _ _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  actionBound := by
    intro i s hs _ _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  actionSourceChannel := by
    intro i s hs _ _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  noMemberSetUpdate := by
    intro i s hs _ _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    simp [exampleSlotT, interChannelSendKind, memberSetUpdateKind]
  sendOpens := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  txRootNonzeroWhenSigning := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    simp [exampleCircuitWitness, exampleBlock, Bytes32.zero]
  outOfRangeCannotSign := by
    intro i s hs hi; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    exact absurd hi (by simp [maxSigCluster])
  memberRootConnect := by
    intro i s hs _ _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs; rfl
  postsFromActiveSlot := by
    intro i s hs _ _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    simp [exampleCircuitWitness]
  regevWidth := by
    intro i s hs _; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    simp [exampleSlotT]
  regevRangeChecked := by
    intro i s hs _ c hc; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    have hc0 : c = 0 := by simpa [exampleSlotT] using List.eq_of_mem_replicate hc
    subst hc0
    simp [wordBase]
  regevDigestConnect := by
    intro i s leaf hs _ _ hl; obtain ⟨rfl, rfl⟩ := example_circuit_slots dest version i s hs
    simp only [exampleCircuitWitness, exampleMemberLeaves] at hl
    cases hl; rfl
  memberLeafCount := rfl
  signerCountRange := by
    intro _
    exact ⟨by simp [exampleCircuitWitness], by simp [exampleCircuitWitness, maxSigCluster]⟩
  paddingSlotsEmpty := by
    intro hany i leaf hl hi
    clear hany
    rcases i with _ | _ | _ | _ | _ | _ | _ | _ | i <;>
      simp_all [exampleCircuitWitness, exampleMemberLeaves, MemberLeaf.empty]
  activeSlotsOccupied := by
    intro hany i leaf hl hi
    clear hany
    rcases i with _ | _ | i <;>
      simp_all [exampleCircuitWitness, exampleMemberLeaves, Hash4.zero] <;>
      first
        | (subst hl; decide)
        | exact absurd hi (by omega)
  pisBlockNumber := rfl
  pisTimestamp := rfl
  pisPrevBlockHashChain := rfl
  pisPrevAccountTreeRoot := rfl
  pisNewBlockHashChain := rfl
  pisNewAccountTreeRoot := rfl
  pisDepositHashChain := rfl
  pisChannelRegHashChain := rfl
  pisPrevBpSigChain := rfl
  pisNewBpSigChain := rfl

/-- The action's `destination_channel_id` (and, by the same construction, its
`tx_hash`, `seal` and `payload_hash`) is free: the gate system is satisfied for
every value, because no gate mentions it. Cross-channel PAIRING — matching a
source debit with a destination credit — does not happen in this circuit. -/
theorem circuit_leaves_action_payload_free (dest : Nat) :
    CircuitGates exampleEnv (exampleCircuitWitness dest 11) :=
  circuit_gates_hold_for_example dest 11

/-- The example's public inputs decode back through the source's decoder. -/
theorem example_public_inputs_round_trip :
    publicInputsFromWords (publicInputWords examplePublicInputs) = .ok examplePublicInputs := by
  rfl

end Zkp.Implementation.UpdateChannelTree
