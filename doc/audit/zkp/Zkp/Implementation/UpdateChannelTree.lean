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

def nativeNewSendLeaf (w : Witness) (slot : Slot) : SendLeaf :=
  ⟨slot.prevLeaf.prev, w.blockNumber, w.block.txTreeRoot⟩

def nativeNewLeaf (e : Env) (w : Witness) (slot : Slot) : ChannelLeaf :=
  ⟨slot.prevLeaf.index + 1, w.blockNumber,
    e.merkleRoot slot.sendProof (e.sendLeafHash (nativeNewSendLeaf w slot)) slot.prevLeaf.index,
    slot.prevLeaf.memberPubkeysRoot⟩

def nativeNewRoot (e : Env) (w : Witness) (slot : Slot) : Hash4 :=
  e.merkleRoot slot.channelProof (e.channelLeafHash (nativeNewLeaf e w slot)) w.block.channelId

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
              .ok ⟨nativeNewRoot e w item.2.2, chain⟩

def nativeLoop (e : Env) (w : Witness) (strict : Bool) (sigLeaf : Hash4) :
    List (Nat × Nat × Slot) → NState → Result NState
  | [], st => .ok st
  | item :: rest, st => nativeStep e w strict sigLeaf item st >>= nativeLoop e w strict sigLeaf rest

/-- The channel-tree root after the loop, as a PURE fold that reads only the
block, the slots and the previous root — never the signature accumulator,
never the channel-state fields. -/
def nativeRootStep (e : Env) (w : Witness) (item : Nat × Nat × Slot) (root : Hash4) : Hash4 :=
  if item.2.1 = 0 then root
  else if item.2.2.prevLeaf.prev = w.blockNumber then root
  else nativeNewRoot e w item.2.2

def nativeRootFold (e : Env) (w : Witness) : List (Nat × Nat × Slot) → Hash4 → Hash4
  | [], root => root
  | item :: rest, root => nativeRootFold e w rest (nativeRootStep e w item root)

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
  let _ ← check (!strict || w.newMemberLeaves.isEmpty) .length
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

end Zkp.Implementation.UpdateChannelTree
