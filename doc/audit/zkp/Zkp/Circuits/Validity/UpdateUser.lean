import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Per-block user/channel-tree update (`UpdateUserCircuit`)
  ========================================================

  Source: `src/circuits/validity/block_hash_chain/update_channel_tree.rs`
          (base-layer per-block circuit; previously mislabeled "channel
          scope" and excluded — this file closes that gap)
        + `src/circuits/validity/block_hash_chain/block_step.rs`
          (the `channel_reg` branch, modeled in `RegBranch` below)

  ## Protocol role

  This is the sub-proof `block_step.rs` verifies once per block. It is
  BASE-LAYER, not channel-scope: it performs
    (1) the account-tree-root update for the block (the root every
        balance/withdrawal theorem anchors to),
    (2) the block-hash-chain fold (committing the whole block — including
        `deposit_hash_chain` and `channel_reg_hash_chain` — on-chain), and
    (3) the `bp_sig_chain` advancement: on a signing block it folds the
        block producer's `(IMSB_digest, bp_pk_g)` pair into the running
        Poseidon list accumulator.

  Two headline obligations are discharged here:

  * **Obligation 1 (signing block ⇒ accumulator advancement).**
    `ValidityCircuit.signatures_not_skippable` gates signature-list
    verification on the COMPUTED `final.bp_sig_chain`; `BlockStep.lean`
    proves the accumulator is threaded unbroken across blocks; what
    remained unproven was that the per-block update proof actually
    ADVANCES `new_bp_sig_chain` on any signing block and cannot leave it
    unchanged or reset it. Proved below (`signing_block_advances`,
    `account_update_forces_fold`).

  * **Obligation 2 (channel_reg branch account-root rewrite).**
    On a registration block, `block_step.rs` REPLACES the account tree
    root with `channel_reg_inputs.channel_tree_root` from the
    channel-reg chain proof. `RegBranch` below models exactly what that
    branch binds; the residual dependence on the (still-excluded)
    channel_reg chain circuit is surfaced as finding **F-UPDU-1**.

  A third load-bearing binding, previously unflagged, is also modeled:
  **member-set immutability** (`member_set_immutable`): the update
  writes a new channel leaf whose `member_pubkeys_root` is COPIED from
  the proven previous leaf (:922), so a block producer can never rotate
  a channel's registered member set through the update path — only the
  registration chain defines member sets.

  ## Constraint inventory — update_channel_tree.rs (Target::new, :730-1067)

  | line       | gate                                                          | meaning |
  |------------|---------------------------------------------------------------|---------|
  | :780-781   | `new_block_hash_chain = block.hash_with_prev_hash(prev)`      | block-hash fold (commits ALL block fields) |
  | :792-799   | `signed_digest = msg_fields.compute_signing_digest(channel_id, block.tx_tree_root)` | one digest per block, bound to block wires |
  | :802       | `tx_tree_root_is_zero = block.tx_tree_root.is_zero()`         | C-2 zero-root flag |
  | :807-808   | `bp_sig_chain := prev_bp_sig_chain` (witness, then folded)    | accumulator init |
  | :839-841   | `is_dummy = is_equal(key_id, 0)`; `should_check = not`        | padding-slot flag |
  | :843-846   | `current_root ==cond prev_root(prev_leaf @ channel_id)`       | prev-leaf inclusion |
  | :848-850   | `should_update = should_check AND prev != block_number`       | the transition flag |
  | :916-923   | new leaf `{index+1, prev := block_number, new_send_root, member_pubkeys_root := prev.member_pubkeys_root}` | leaf transition |
  | :925-929   | `account_tree_root = select(should_update, updated_root, current_root)` | root advance |
  | :950       | `should_verify_sig = should_update`                           | sig branch shares the SAME flag |
  | :955-959   | `should_verify_sig → tx_tree_root != 0`                       | C-2: H2 = 0 reserved |
  | :972-977   | `should_verify_sig → msg_fields.bp_member_slot == i`          | updating slot IS the bp slot |
  | :993-1016  | `MemberLeaf{pk_g = bp_pk_g, pk_b, regev_digest} ∈ member_pubkeys_root @ slot i` (cond) | folded pk is a registered member |
  | :1021-1026 | `bp_sig_chain = select(should_verify_sig, Poseidon(prev ‖ Poseidon([IMLL]‖digest‖pk)), bp_sig_chain)` | **the fold** |
  | :1033-1044 | PIs: `new_account_tree_root`, `new_bp_sig_chain`, `channel_reg_hash_chain := block.channel_reg_hash_chain` (:1041) | statement |

  (Native mirror: to_public_inputs :176-380 — digest :186-188, bp-slot
  guard :225-230, member leaf :234-252, zero-root guard :257-261, fold
  :263-272, PI assembly :368-379.)

  Not modeled (out of these obligations' scope, no effect on them): the
  per-slot tx-attribution constraints (:852-895 — tx_v2 inclusion in the
  block tx root, tx-class exclusivity, channel-action source binding)
  and the send-tree sub-update (:897-914); both only ADD constraints on
  updating slots and cannot weaken the properties proved here. The
  Regev-pubkey digest recomputation (:980-991) is folded into the
  witnessed `regevDigest` leaf component (its 32-bit range checks guard
  digest canonicity, not these obligations).

  ## Constraint inventory — block_step.rs channel_reg branch (Target::new)

  | line      | gate                                                            | meaning |
  |-----------|-----------------------------------------------------------------|---------|
  | :507      | `has_channel_reg_proof` boolean                                 | branch flag |
  | :508-512  | conditionally verify channel-reg chain proof (pinned VK)        | proof gate |
  | :612-616  | `has_reg → prev_account_tree_root == new_account_tree_root` (on update PIs) | R6 exclusion |
  | :619-625  | `has_reg → reg.initial_channel_reg_hash_chain == prev.channel_reg_hash_chain` | chain continuity |
  | :628-634  | `has_reg → reg.initial_channel_tree_root == prev.account_tree_root` | root continuity |
  | :635-639  | `has_reg → reg.block_number == next_block_number`               | block binding |
  | :643-648  | `account_root = select(has_reg, reg.channel_tree_root, upd.new_account_tree_root)` | **the root swap** |
  | :650-655  | `reg_chain = select(has_reg, reg.channel_reg_hash_chain, prev)` | chain advance |
  | :658-662  | `has_reg == (reg_chain != prev)`                                | change ⇔ proof |
  | :668-670  | `upd.channel_reg_hash_chain == reg_chain` (G6)                  | anchor into block hash |

  (Native mirror: block_step.rs :261-338.)
-/

namespace Zkp
namespace Circuits.UpdateUser

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

/-- `constants.rs:47` — member tree height (16 slots per channel). -/
def MEMBER_TREE_HEIGHT : Nat := 4

/-- `constants.rs:60` — `MAX_CHANNEL_MEMBERS = 16`, the static circuit
    size bounding `num_users` and hence the slot-loop length (the
    member tree has `2^MEMBER_TREE_HEIGHT = 16` leaf slots). -/
def MAX_CHANNEL_MEMBERS : Nat := 16

/-- `constants.rs:16,:21` — channel (account) tree height = CHANNEL_ID_BITS. -/
def CHANNEL_TREE_HEIGHT : Nat := 32

/-- `Bytes32::default()` — the all-zero 32-byte value. It is BOTH the
    empty `bp_sig_chain` (genesis accumulator, cf.
    `ValidityCircuit.zeroChain`) and the reserved in-channel-update
    `tx_tree_root` (detail2 §C-2). -/
def zeroBytes (F : Type) [CField F] : Bytes32 F := List.replicate 32 0

/-- The IMSB signing-message fields consumed by this circuit
    (`SmallBlockMessageFieldsTarget`, :792): the declared bp slot and the
    bp's Goldilocks pubkey. The remaining message fields are modeled in
    `Zkp/Circuits/Validity/SmallBlockMessage.lean`; only these two are
    load-bearing for the fold. -/
structure MsgFields (F : Type) where
  bpMemberSlot : F
  bpPkG : Bytes32 F

/-- `msg_fields.compute_signing_digest(channel_id, tx_tree_root)`
    (:795-799) — keccak digest over the message with the `channel_id`
    and `tx_tree_root` components taken from the BLOCK's own wires
    (mirrors `SmallBlockMessage.signingDigest`). Uninterpreted.

    WARNING — single-instance use only. The Lean symbol takes only
    `(MsgFields, channel_id, tx_tree_root)`, but the real digest
    preimage also covers the remaining message fields (modeled in
    Zkp/Circuits/Validity/SmallBlockMessage.lean) that `MsgFields`
    deliberately elides. Determinism within ONE instantiation is all
    the theorems here consume; CROSS-INSTANCE reasoning of the form
    "equal digests ⇒ equal messages" (or "different messages ⇒
    different digests") over this symbol would be UNSOUND, because
    two messages differing only in an elided field map to the same
    Lean arguments. -/
opaque signingDigest {F : Type} [CField F] : MsgFields F → F → Bytes32 F → Bytes32 F

/-- `list_leaf` / `leaf_target` (`poseidon_sig/list.rs:54-60,:90-101`):
    `Poseidon([LIST_LEAF_DOMAIN "IMLL"] ‖ message ‖ pk)`. Uninterpreted. -/
opaque listLeaf {F : Type} [CField F] : Bytes32 F → Bytes32 F → HashOut F

/-- `list_chain_step` / `chain_step_target` (`poseidon_sig/list.rs:63-68,
    :105-111`): two-to-one `Poseidon(prev ‖ leaf)`. Uninterpreted. -/
opaque chainStep {F : Type} [CField F] : HashOut F → HashOut F → HashOut F

/-- `Bytes32Target::to_hash_out` (:1022): decode a canonical Bytes32 into
    4 Goldilocks limbs (also constrains canonicity — determinism is all
    these proofs need). Uninterpreted. -/
opaque toHashOut {F : Type} [CField F] : Bytes32 F → HashOut F

/-- One accumulator step, exactly as emitted at :1021-1024:
    `Bytes32::from_hash_out(Poseidon(to_hash_out(prev) ‖
    Poseidon([IMLL] ‖ digest ‖ pk)))`. The SAME gadget chain is used by
    the producer (`ListStepCircuit`) and the consumer (validity), so the
    rebuilt chains match bit-for-bit. -/
def accumulate (prev digest pk : Bytes32 F) : Bytes32 F :=
  fromHashOut (chainStep (toHashOut prev) (listLeaf digest pk))

/-- `common/trees/channel_tree::ChannelLeaf` — the per-channel account
    leaf: `{index, prev, send_tree_root, member_pubkeys_root}`. -/
structure ChannelLeaf (F : Type) where
  index : F
  prev : F
  sendTreeRoot : HashOut F
  memberPubkeysRoot : HashOut F

/-- Leaf digest of a `ChannelLeaf` (Poseidon; uninterpreted). -/
opaque channelLeafHash {F : Type} [CField F] : ChannelLeaf F → HashOut F

/-- `common/trees/key_tree::MemberLeaf` — `{pk_g, pk_b, regev_pk_digest}`
    (:1005-1009). -/
structure MemberLeaf (F : Type) where
  pkG : HashOut F
  pkB : HashOut F
  regevPkDigest : HashOut F

/-- Leaf digest of a `MemberLeaf` (Poseidon; uninterpreted). -/
opaque memberLeafHash {F : Type} [CField F] : MemberLeaf F → HashOut F

/-- `block.hash_with_prev_hash` (:780-781): folds the ENTIRE block
    into the block-hash chain (keccak; uninterpreted). The real
    preimage (block.rs:262-269) is
    `prev_hash ‖ channel_id ‖ timestamp ‖ key_ids ‖ tx_tree_root ‖
    deposit_hash_chain ‖ channel_reg_hash_chain`; the Lean symbol
    keeps only `(prev, tx_tree_root, deposit_hash_chain,
    channel_reg_hash_chain)` — the fields the theorems here consume.
    This is what commits `channel_reg_hash_chain` on-chain (G6
    anchor).

    WARNING — single-instance use only. Because the symbol DROPS real
    preimage fields (`channel_id`, `timestamp`, `key_ids`,
    block.rs:262-269), cross-instance hash-equality reasoning over it
    would be unsound: two blocks differing only in a dropped field
    map to identical Lean arguments, so "equal Lean hashes ⇒ equal
    blocks" does NOT hold, and injectivity-style hypotheses must
    never be stated over this symbol. The theorems in this file use
    it only for single-instantiation determinism (the G6 "same wire"
    fact `reg_chain_committed_in_block_hash`). -/
opaque blockHashWithPrev {F : Type} [CField F] :
    Bytes32 F → Bytes32 F → Bytes32 F → Bytes32 F → Bytes32 F

/-- Per-slot wires of the update loop (:824-1031). Advice/witnessed
    wires (`isDummy`, `prevMatches`, `memberPkB`, sibling paths) are
    fields — the prover chooses them subject to `SlotConstraints`. -/
structure Slot (F : Type) where
  keyId : F
  /-- `is_equal(key_id, 0)` advice bit (:840). -/
  isDummy : F
  /-- `prev_user_leaf.prev.is_equal(block_number)` advice bit (:848). -/
  prevMatches : F
  /-- `should_update` (:850) — also `should_verify_sig` (:950). -/
  shouldUpdate : F
  prevLeaf : ChannelLeaf F
  /-- New send-tree root (:910-914; send-tree sub-update not modeled). -/
  newSendRoot : HashOut F
  chanSibs : List (HashOut F)
  /-- `get_root(new_user_leaf, channel_id)` output (:925-926). -/
  updatedRoot : HashOut F
  rootIn : HashOut F
  rootOut : HashOut F
  memberPkB : HashOut F
  regevDigest : HashOut F
  memberSibs : List (HashOut F)
  chainIn : Bytes32 F
  chainOut : Bytes32 F

/-- Block-level parameters shared by every slot. -/
structure BlockParams (F : Type) where
  blockNumber : F
  channelId : F
  txTreeRoot : Bytes32 F
  /-- `tx_tree_root_is_zero` advice bit (:802). -/
  txRootIsZero : F
  msg : MsgFields F
  /-- `signed_digest` wire (:795-799), one per block. -/
  digest : Bytes32 F

/-- `new_user_leaf` (:916-923): `index + 1`, `prev := block_number`,
    the new send root, and — load-bearing — `member_pubkeys_root`
    COPIED from the previous leaf (:922). -/
def newLeaf (blockNumber : F) (s : Slot F) : ChannelLeaf F :=
  { index := s.prevLeaf.index + 1
    prev := blockNumber
    sendTreeRoot := s.newSendRoot
    memberPubkeysRoot := s.prevLeaf.memberPubkeysRoot }

/-- The constraints the circuit emits for slot `idx`
    (update_channel_tree.rs, Target::new loop body). Every conjunct cites
    the line that emits it. -/
structure SlotConstraints (p : BlockParams F) (idx : Nat) (s : Slot F) : Prop where
  /-- :839-840 `is_dummy = is_equal(key_id, zero)`. -/
  isDummySpec : IsEqualSpec s.keyId 0 s.isDummy
  /-- :848 `prev_matches_block = prev_user_leaf.prev.is_equal(block_number)`. -/
  prevMatchesSpec : IsEqualSpec s.prevLeaf.prev p.blockNumber s.prevMatches
  /-- :841,:849-850 `should_update = and(not(is_dummy), not(prev_matches_block))`. -/
  shouldUpdateDef : s.shouldUpdate = andGate (notGate s.isDummy) (notGate s.prevMatches)
  /-- :843-846 (prev-leaf inclusion at index `channel_id`, gated on
      `should_check_account` — implied whenever `should_update = 1`
      since `should_update = should_check AND prev_differs`) together
      with :925-926 (new-leaf root): both are `get_root` calls on the
      SAME `user_merkle_proof` object with the SAME `channel_id` index
      wire — so ONE shared sibling vector (the wires allocated by
      `MerkleProofTarget::new`, merkle_tree.rs:174-183) — but each
      call runs its OWN `split_le(channel_id, CHANNEL_TREE_HEIGHT)`
      (merkle_tree.rs:227), i.e. TWO independent height-32 boolean
      decompositions, which also give the canonical `length`
      obligations. Mirrored as separate `bitsR` (read) / `bitsW`
      (write) existentials; their identification is proved by
      consumers from `Merkle.PowTwoInj F 32`
      (see `member_set_immutable`), never baked in. -/
  treeUpdate : s.shouldUpdate = 1 →
      (∃ bitsR : List Bool,
        bitsR.length = CHANNEL_TREE_HEIGHT ∧
        p.channelId = bitsValue bitsR ∧
        fold (channelLeafHash s.prevLeaf) bitsR s.chanSibs = s.rootIn)
      ∧ (∃ bitsW : List Bool,
        bitsW.length = CHANNEL_TREE_HEIGHT ∧
        p.channelId = bitsValue bitsW ∧
        fold (channelLeafHash (newLeaf p.blockNumber s)) bitsW s.chanSibs
          = s.updatedRoot)
      ∧ s.chanSibs.length = CHANNEL_TREE_HEIGHT
  /-- :928-929 `account_tree_root = select(should_update, updated_root, current_root)`. -/
  rootSelect : SelectSpec s.shouldUpdate s.updatedRoot s.rootIn s.rootOut
  /-- :955-959 `should_verify_sig → tx_tree_root_is_zero = 0` (C-2). -/
  txRootNonzeroGate : condAssertEq s.shouldUpdate p.txRootIsZero 0
  /-- :972-977 `should_verify_sig → msg_fields.bp_member_slot = i`. -/
  bpSlotBind : condAssertEq s.shouldUpdate p.msg.bpMemberSlot (natLit F idx)
  /-- :993-1016 conditional MemberLeaf inclusion at slot `i` of the
      channel's `member_pubkeys_root`. The leaf's `pk_g` is
      `to_hash_out` of the SAME `bp_pk_g` wire folded into the chain
      (:811,:998), which is what binds the folded pair to a registered
      member. -/
  memberIncl : CondMerkleVerify s.shouldUpdate MEMBER_TREE_HEIGHT
      (memberLeafHash ⟨toHashOut p.msg.bpPkG, s.memberPkB, s.regevDigest⟩)
      (natLit F idx) s.memberSibs s.prevLeaf.memberPubkeysRoot
  /-- :1018-1026 the fold-or-preserve select on the accumulator:
      `bp_sig_chain = select(should_verify_sig,
      from_hash_out(Poseidon(to_hash_out(prev) ‖ leaf(digest, pk))),
      bp_sig_chain)`. -/
  chainSelect : SelectSpec s.shouldUpdate
      (accumulate s.chainIn p.digest p.msg.bpPkG) s.chainIn s.chainOut

/-- The loop threading (:808 `bp_sig_chain` init, :784 `account_tree_root`
    init, :928/:1025 per-slot re-binding, :1039/:1043 PI extraction):
    slot `i+1`'s inputs are slot `i`'s outputs, and the block PIs are the
    final values. -/
def Threaded (p : BlockParams F) : Nat → Bytes32 F → HashOut F → List (Slot F) →
    Bytes32 F → HashOut F → Prop
  | _idx, cIn, rIn, [], cOut, rOut => cOut = cIn ∧ rOut = rIn
  | idx, cIn, rIn, s :: rest, cOut, rOut =>
      s.chainIn = cIn ∧ s.rootIn = rIn ∧ SlotConstraints p idx s ∧
      Threaded p (idx + 1) s.chainOut s.rootOut rest cOut rOut

/-- Public-input-facing wires of one `UpdateUserCircuit` instance. -/
structure BlockIO (F : Type) where
  prevBpSigChain : Bytes32 F
  newBpSigChain : Bytes32 F
  prevAccountRoot : HashOut F
  newAccountRoot : HashOut F
  prevBlockHashChain : Bytes32 F
  newBlockHashChain : Bytes32 F
  /-- The block's own `channel_reg_hash_chain` field (folded into the
      block hash). -/
  blockChannelRegHashChain : Bytes32 F
  /-- PI `channel_reg_hash_chain` (:1041). -/
  piChannelRegHashChain : Bytes32 F
  blockDepositHashChain : Bytes32 F
  /-- PI `deposit_hash_chain` (:1040). -/
  piDepositHashChain : Bytes32 F
  slots : List (Slot F)

/-- Block-level constraints of `UpdateUserCircuit` (Target::new). -/
structure Constraints (p : BlockParams F) (io : BlockIO F) : Prop where
  /-- :802 `tx_tree_root_is_zero = block.tx_tree_root.is_zero()`. -/
  txZeroSpec : IsEqualSpecG p.txTreeRoot (zeroBytes F) p.txRootIsZero
  /-- :792-799 the per-block signing digest, with `channel_id` and
      `tx_tree_root` taken from the block's own wires. -/
  digestDef : p.digest = signingDigest p.msg p.channelId p.txTreeRoot
  /-- :780-781 the block-hash fold — commits `tx_tree_root`,
      `deposit_hash_chain` AND `channel_reg_hash_chain` into the chain
      the L1 contract snapshots. -/
  blockHashFold : io.newBlockHashChain = blockHashWithPrev io.prevBlockHashChain
      p.txTreeRoot io.blockDepositHashChain io.blockChannelRegHashChain
  /-- :1041 the PI surfaces the SAME `block.channel_reg_hash_chain` wire
      that :780-781 folds into the block hash (G6 anchor for
      `block_step.rs:668-670`). -/
  regChainPi : io.piChannelRegHashChain = io.blockChannelRegHashChain
  /-- :1040 likewise for the deposit chain. -/
  depositChainPi : io.piDepositHashChain = io.blockDepositHashChain
  /-- :808,:824-1031,:1039,:1043 the threaded slot loop, from the
      witnessed `prev_bp_sig_chain` / `prev_account_tree_root` to the
      `new_bp_sig_chain` / `new_account_tree_root` PIs. -/
  threaded : Threaded p 0 io.prevBpSigChain io.prevAccountRoot io.slots
      io.newBpSigChain io.newAccountRoot
  /-- The slot loop is a STATIC circuit loop of `num_users` iterations
      (`for i in 0..num_users`, update_channel_tree.rs:824; allocation
      at :742-777), and `num_users ≤ MAX_CHANNEL_MEMBERS = 16`
      (constants.rs:60 — the member tree addressed by `bp_member_slot`
      has exactly 16 leaf slots). This bound is what makes the slot
      indices small enough for the BOUNDED numeral injectivity
      `NatLitInj` (`< 16 < 2^63`) in the single-fold argument. -/
  slotCount : io.slots.length ≤ MAX_CHANNEL_MEMBERS

/-! ### Named hypotheses (explicit trust, never silent)

The abstract field does not fix a characteristic and `poseidon` /
`natLit` are uninterpreted, so the facts below must be NAMED wherever
a theorem depends on them (same discipline as `Bytes.PoseidonCR`).
Their statuses differ and are stated per definition: `NatLitInj`
(bounded) is genuinely TRUE of the concrete Goldilocks embedding,
while the two `Accumulate*` facts are `CompressCR`-style symbolic
idealizations — literally false-by-counting for the real Poseidon,
read as "no such instance exhibited in this execution". -/

/-- BOUNDED injectivity of the numeral embedding `natLit` below `2^63`
    — genuinely true in Goldilocks (`p > 2^63`) and derivable from
    `Builder.ReprFaithful` (`ReprFaithful.toNatLitInj`); the unbounded
    statement is pigeonhole-false at any finite field and is never
    assumed. The only uses here are slot indices
    `< MAX_CHANNEL_MEMBERS = 16 < 2^63` (constants.rs:60), whose
    bounds the theorems below discharge from `Constraints.slotCount`.
    Centralized as `Builder.NatLitInj` (Core/Builder.lean);
    re-exported here so existing consumers keep the unqualified name. -/
abbrev NatLitInj (F : Type) [CField F] : Prop := Builder.NatLitInj F (2 ^ 63)

/-- The accumulator step has no fixed point: `Poseidon(prev ‖ leaf)`
    never re-encodes to `prev`. Stated explicitly because `poseidon`
    is uninterpreted; a fixed point would be a structured Poseidon
    PREIMAGE relation (`f(c, ·) = c` — not a collision: no two
    preimages are involved).

    IDEALIZATION CAVEAT (`Merkle.CompressCR`-style, stated honestly):
    the universally-quantified statement is literally
    UNSATISFIABLE-BY-COUNTING for the real Poseidon — for each
    `(d, pk)` the map `c ↦ accumulate c d pk` behaves like a random
    function on a `2^256`-point domain, which has fixed points in
    expectation, so SOME `(c, d, pk)` with `accumulate c d pk = c`
    exists. Read it symbolically: "no fixed-point instance has been
    exhibited / occurs in this execution". A theorem proved under it
    can only fail on a trace that EXHIBITS such an instance. Named
    hypothesis, never an axiom, so every consumer displays the trust
    assumption in its signature. -/
def AccumulateNoFixpoint (F : Type) [CField F] : Prop :=
  ∀ c d pk : Bytes32 F, accumulate c d pk ≠ c

/-- The accumulator step never outputs the all-zero `Bytes32` (the empty
    chain / `ValidityCircuit.zeroChain`). A zero output would be a
    Poseidon preimage of the fixed zero digest.

    IDEALIZATION CAVEAT (same status as `AccumulateNoFixpoint`): by
    counting, the real compressing Poseidon has ~`2^{input-output}`
    preimages of the zero digest, so the universally-quantified
    statement is literally false for the concrete hash; read it as the
    symbolic "no zero-preimage instance exhibited in this execution"
    assumption — named, never an axiom. -/
def AccumulateNeverEmpty (F : Type) [CField F] : Prop :=
  ∀ c d pk : Bytes32 F, accumulate c d pk ≠ zeroBytes F

/-! ### Slot-level soundness -/

/-- `should_update` is a well-formed boolean: it is the AND of negations
    of two `is_equal` advice bits, each pinned boolean by its gate. -/
theorem shouldUpdate_bool {p : BlockParams F} {idx : Nat} {s : Slot F}
    (h : SlotConstraints p idx s) : s.shouldUpdate = 0 ∨ s.shouldUpdate = 1 := by
  have hd : s.isDummy = 0 ∨ s.isDummy = 1 := h.isDummySpec.1
  have hm : s.prevMatches = 0 ∨ s.prevMatches = 1 := h.prevMatchesSpec.1
  rw [h.shouldUpdateDef]
  rcases notGate_bool hd with ha | ha
  · rcases notGate_bool hm with hb | hb
    · right; rw [ha, hb]; unfold andGate; rw [one_mul']
    · left; rw [hb]; exact andGate_zero_right _
  · left; rw [ha]; exact andGate_zero_left _

/-- **Signing-slot semantics.** `should_update = 1` exactly when the slot
    is active (`key_id ≠ 0`) and the channel leaf was not already
    updated in this block (`prev ≠ block_number`). This is the circuit's
    definition of "this block carries the bp signature". -/
theorem signing_iff {p : BlockParams F} {idx : Nat} {s : Slot F}
    (h : SlotConstraints p idx s) :
    s.shouldUpdate = 1 ↔ (s.keyId ≠ 0 ∧ s.prevLeaf.prev ≠ p.blockNumber) := by
  have hd := h.isDummySpec
  have hm := h.prevMatchesSpec
  constructor
  · intro h1
    rw [h.shouldUpdateDef] at h1
    have hb := (andGate_eq_one_iff (Or.symm (notGate_bool hd.1))
      (Or.symm (notGate_bool hm.1))).mp h1
    have hd0 : s.isDummy = 0 := (notGate_eq_one_iff hd.1).mp hb.1
    have hm0 : s.prevMatches = 0 := (notGate_eq_one_iff hm.1).mp hb.2
    refine ⟨fun hk => ?_, fun hp => ?_⟩
    · have h1' : s.isDummy = 1 := hd.2.mpr hk
      rw [hd0] at h1'
      exact one_ne_zero h1'.symm
    · have h1' : s.prevMatches = 1 := hm.2.mpr hp
      rw [hm0] at h1'
      exact one_ne_zero h1'.symm
  · rintro ⟨hk, hp⟩
    have hd0 : s.isDummy = 0 := by
      rcases hd.1 with h0 | h1
      · exact h0
      · exact absurd (hd.2.mp h1) hk
    have hm0 : s.prevMatches = 0 := by
      rcases hm.1 with h0 | h1
      · exact h0
      · exact absurd (hm.2.mp h1) hp
    rw [h.shouldUpdateDef, hd0, hm0]
    unfold notGate andGate
    simp

/-- **Signing slot: everything that is bound.** On the updating slot the
    circuit forces (a) the declared bp slot to be THIS slot, (b) a
    nonzero `tx_tree_root` (C-2), (c) the folded `bp_pk_g` to be a
    registered member at this slot of the channel's member tree, and
    (d) the accumulator to advance by exactly one `accumulate` step. -/
theorem slot_signing_bindings {p : BlockParams F} {idx : Nat} {s : Slot F}
    (h : SlotConstraints p idx s)
    (htx : IsEqualSpecG p.txTreeRoot (zeroBytes F) p.txRootIsZero)
    (h1 : s.shouldUpdate = 1) :
    p.msg.bpMemberSlot = natLit F idx
    ∧ p.txTreeRoot ≠ zeroBytes F
    ∧ MerkleVerify MEMBER_TREE_HEIGHT
        (memberLeafHash ⟨toHashOut p.msg.bpPkG, s.memberPkB, s.regevDigest⟩)
        (natLit F idx) s.memberSibs s.prevLeaf.memberPubkeysRoot
    ∧ s.chainOut = accumulate s.chainIn p.digest p.msg.bpPkG := by
  refine ⟨h.bpSlotBind h1, ?_, h.memberIncl h1, h.chainSelect.1 h1⟩
  have hz : p.txRootIsZero = 0 := h.txRootNonzeroGate h1
  intro heq
  have h1' : p.txRootIsZero = 1 := htx.2.mpr heq
  rw [hz] at h1'
  exact one_ne_zero h1'.symm

/-- Non-updating slot: the accumulator AND the account root pass through
    unchanged — no fold, no root change (:929,:1026 select false arms). -/
theorem slot_preserves {p : BlockParams F} {idx : Nat} {s : Slot F}
    (h : SlotConstraints p idx s) (h0 : s.shouldUpdate = 0) :
    s.chainOut = s.chainIn ∧ s.rootOut = s.rootIn :=
  ⟨h.chainSelect.2 h0, h.rootSelect.2 h0⟩

/-- **Member-set immutability (third load-bearing binding, previously
    unflagged).** The new channel leaf written by an update carries the
    SAME `member_pubkeys_root` as the proven previous leaf (:922), over
    the same Merkle path. A block producer therefore cannot rotate a
    channel's member set through the update path — only the (separately
    anchored) registration chain ever defines `member_pubkeys_root`.
    Without this copy the bp could install attacker keys and sign all
    future blocks of the channel.

    The single-bits conclusion identifies the two independent
    `split_le` decompositions of `treeUpdate` (`bitsR = bitsW`) from
    the named characteristic hypothesis
    `Merkle.PowTwoInj F CHANNEL_TREE_HEIGHT` (Goldilocks-true; both
    decompose the SAME connected `channel_id` wire,
    update_channel_tree.rs:837/:845/:926, merkle_tree.rs:227). -/
theorem member_set_immutable {p : BlockParams F} {idx : Nat} {s : Slot F}
    (hpow : PowTwoInj F CHANNEL_TREE_HEIGHT)
    (h : SlotConstraints p idx s) (h1 : s.shouldUpdate = 1) :
    (newLeaf p.blockNumber s).memberPubkeysRoot = s.prevLeaf.memberPubkeysRoot
    ∧ ∃ bits : List Bool,
        bits.length = CHANNEL_TREE_HEIGHT
        ∧ p.channelId = bitsValue bits
        ∧ fold (channelLeafHash s.prevLeaf) bits s.chanSibs = s.rootIn
        ∧ fold (channelLeafHash (newLeaf p.blockNumber s)) bits s.chanSibs = s.updatedRoot
        ∧ s.rootOut = s.updatedRoot := by
  obtain ⟨⟨bitsR, hlenR, hidxR, hprev⟩, ⟨bitsW, hlenW, hidxW, hnew⟩, _hslen⟩ :=
    h.treeUpdate h1
  have hbits : bitsR = bitsW :=
    hpow bitsR bitsW hlenR hlenW (by rw [← hidxR, ← hidxW])
  exact ⟨rfl, bitsR, hlenR, hidxR, hprev,
    by rw [hbits]; exact hnew, h.rootSelect.1 h1⟩

/-! ### Block-level soundness (the loop) -/

/-- If no slot updates, both accumulator and account root are unchanged
    across the whole block. -/
theorem no_signing_preserves {p : BlockParams F} :
    ∀ {slots : List (Slot F)} {idx : Nat} {cIn : Bytes32 F} {rIn : HashOut F}
      {cOut : Bytes32 F} {rOut : HashOut F},
      Threaded p idx cIn rIn slots cOut rOut →
      (∀ s, s ∈ slots → s.shouldUpdate = 0) →
      cOut = cIn ∧ rOut = rIn := by
  intro slots
  induction slots with
  | nil =>
      intro idx cIn rIn cOut rOut h _
      simp only [Threaded] at h
      exact h
  | cons s rest ih =>
      intro idx cIn rIn cOut rOut h hall
      simp only [Threaded] at h
      obtain ⟨hcin, hrin, hsc, hrest⟩ := h
      have hs0 : s.shouldUpdate = 0 := hall s (List.mem_cons_self s rest)
      obtain ⟨hcout, hrout⟩ := slot_preserves hsc hs0
      have h2 := ih hrest (fun t ht => hall t (List.mem_cons_of_mem s ht))
      exact ⟨by rw [h2.1, hcout, hcin], by rw [h2.2, hrout, hrin]⟩

/-- Every slot in a threaded loop satisfies `SlotConstraints` at some
    index. -/
theorem threaded_slot_constraints {p : BlockParams F} :
    ∀ {slots : List (Slot F)} {idx : Nat} {cIn : Bytes32 F} {rIn : HashOut F}
      {cOut : Bytes32 F} {rOut : HashOut F},
      Threaded p idx cIn rIn slots cOut rOut →
      ∀ {s : Slot F}, s ∈ slots → ∃ j, SlotConstraints p j s := by
  intro slots
  induction slots with
  | nil =>
      intro idx cIn rIn cOut rOut _ s hs
      exact absurd hs (List.not_mem_nil s)
  | cons a rest ih =>
      intro idx cIn rIn cOut rOut h s hs
      simp only [Threaded] at h
      obtain ⟨_, _, hsc, hrest⟩ := h
      rcases List.mem_cons.mp hs with rfl | htr
      · exact ⟨idx, hsc⟩
      · exact ih hrest htr

/-- Once the bp slot has folded (pinning `bp_member_slot = natLit idx0`),
    every LATER slot must pass the accumulator through unchanged: a
    second fold at index `idx > idx0` would pin `bp_member_slot` to a
    different numeral. This is the machine-check of the circuit's
    single-fold INVARIANT comment (:966-971). The `2^63` side
    conditions feed the BOUNDED `NatLitInj`; they are discharged at
    the block level from `Constraints.slotCount` (loop length
    `≤ MAX_CHANNEL_MEMBERS = 16`). -/
theorem later_slots_preserve {p : BlockParams F} (hinj : NatLitInj F) {idx0 : Nat}
    (hbp : p.msg.bpMemberSlot = natLit F idx0) (hidx0 : idx0 < 2 ^ 63) :
    ∀ {slots : List (Slot F)} {idx : Nat} {cIn : Bytes32 F} {rIn : HashOut F}
      {cOut : Bytes32 F} {rOut : HashOut F},
      idx0 < idx →
      idx + slots.length ≤ 2 ^ 63 →
      Threaded p idx cIn rIn slots cOut rOut →
      cOut = cIn := by
  intro slots
  induction slots with
  | nil =>
      intro idx cIn rIn cOut rOut _ _ h
      simp only [Threaded] at h
      exact h.1
  | cons s rest ih =>
      intro idx cIn rIn cOut rOut hlt hbound h
      simp only [List.length_cons] at hbound
      simp only [Threaded] at h
      obtain ⟨hcin, _hrin, hsc, hrest⟩ := h
      have hs0 : s.shouldUpdate = 0 := by
        rcases shouldUpdate_bool hsc with h0 | h1
        · exact h0
        · exfalso
          have hslot : p.msg.bpMemberSlot = natLit F idx := hsc.bpSlotBind h1
          have heq : idx0 = idx :=
            hinj idx0 idx hidx0 (by omega) (hbp.symm.trans hslot)
          omega
      have hcout : s.chainOut = s.chainIn := hsc.chainSelect.2 hs0
      have h2 := ih (by omega) (by omega) hrest
      rw [h2, hcout, hcin]

/-- Loop-level advancement: if SOME slot signs, the outgoing accumulator
    is EXACTLY one `accumulate` step over the incoming one — earlier
    slots passed it through (they cannot have signed, by the
    `bp_member_slot` pin) and later slots pass it through likewise. -/
theorem signing_advances_aux {p : BlockParams F} (hinj : NatLitInj F) :
    ∀ {slots : List (Slot F)} {idx : Nat} {cIn : Bytes32 F} {rIn : HashOut F}
      {cOut : Bytes32 F} {rOut : HashOut F},
      idx + slots.length ≤ 2 ^ 63 →
      Threaded p idx cIn rIn slots cOut rOut →
      (∃ s, s ∈ slots ∧ s.shouldUpdate = 1) →
      cOut = accumulate cIn p.digest p.msg.bpPkG := by
  intro slots
  induction slots with
  | nil =>
      intro idx cIn rIn cOut rOut _ _ hex
      obtain ⟨s, hs, _⟩ := hex
      exact absurd hs (List.not_mem_nil s)
  | cons s rest ih =>
      intro idx cIn rIn cOut rOut hbound h hex
      simp only [List.length_cons] at hbound
      simp only [Threaded] at h
      obtain ⟨hcin, _hrin, hsc, hrest⟩ := h
      rcases shouldUpdate_bool hsc with hs0 | hs1
      · -- head does not sign: the signer is in the tail
        have hcout : s.chainOut = s.chainIn := hsc.chainSelect.2 hs0
        obtain ⟨t, ht, ht1⟩ := hex
        rcases List.mem_cons.mp ht with rfl | htr
        · exact absurd (hs0.symm.trans ht1) (fun hc => one_ne_zero hc.symm)
        · have h2 := ih (by omega) hrest ⟨t, htr, ht1⟩
          rw [h2, hcout, hcin]
      · -- head signs: fold once, everything after preserves
        have hbp : p.msg.bpMemberSlot = natLit F idx := hsc.bpSlotBind hs1
        have hcout : s.chainOut = accumulate s.chainIn p.digest p.msg.bpPkG :=
          hsc.chainSelect.1 hs1
        have htail : cOut = s.chainOut :=
          later_slots_preserve hinj hbp (by omega) (Nat.lt_succ_self idx)
            (by omega) hrest
        rw [htail, hcout, hcin]

/-- The static loop bound (`slotCount`, ≤ 16) sits comfortably inside
    the `2^63` numeral-injectivity range, discharging the loop lemmas'
    side conditions at the block level. -/
theorem slots_in_range {p : BlockParams F} {io : BlockIO F}
    (h : Constraints p io) : 0 + io.slots.length ≤ 2 ^ 63 := by
  have h16 : io.slots.length ≤ MAX_CHANNEL_MEMBERS := h.slotCount
  have hlt : MAX_CHANNEL_MEMBERS ≤ 2 ^ 63 := by
    show (16 : Nat) ≤ 2 ^ 63
    decide
  omega

/-- **OBLIGATION 1 (headline). Signing block ⇒ accumulator advancement.**
    If the block updates a channel leaf (i.e. it carries the bp
    signature), the `new_bp_sig_chain` PI equals EXACTLY ONE Poseidon
    chain step over the `prev_bp_sig_chain` PI, absorbing
    `(signed_digest, bp_pk_g)` — where `signed_digest` is bound to the
    block's own `channel_id`/`tx_tree_root` (`digestDef`). The prover
    cannot leave the accumulator unchanged, reset it, or fold more than
    once. This discharges the premise `BlockStep.lean` (threading) and
    `ValidityCircuit.signatures_not_skippable` (gating) rely on. -/
theorem signing_block_advances {p : BlockParams F} {io : BlockIO F}
    (hinj : NatLitInj F) (h : Constraints p io)
    (hsig : ∃ s, s ∈ io.slots ∧ s.shouldUpdate = 1) :
    io.newBpSigChain = accumulate io.prevBpSigChain p.digest p.msg.bpPkG
    ∧ p.digest = signingDigest p.msg p.channelId p.txTreeRoot :=
  ⟨signing_advances_aux hinj (slots_in_range h) h.threaded hsig, h.digestDef⟩

/-- Non-signing block: the accumulator (and account root) are unchanged —
    exactly the "unchanged otherwise" half of the P2b contract. -/
theorem non_signing_block_preserves {p : BlockParams F} {io : BlockIO F}
    (h : Constraints p io)
    (hno : ∀ s, s ∈ io.slots → s.shouldUpdate = 0) :
    io.newBpSigChain = io.prevBpSigChain
    ∧ io.newAccountRoot = io.prevAccountRoot :=
  no_signing_preserves h.threaded hno

/-- **No state transition without a fold.** If the account root changed
    at all (`new ≠ prev`), some slot updated, hence the accumulator
    advanced by exactly one step. Contrapositive: a prover cannot apply
    a channel-leaf transition while keeping `bp_sig_chain` untouched —
    the root select and the chain select share the SAME `should_update`
    wire (:929,:950,:1026). -/
theorem account_update_forces_fold {p : BlockParams F} {io : BlockIO F}
    (hinj : NatLitInj F) (h : Constraints p io)
    (hne : io.newAccountRoot ≠ io.prevAccountRoot) :
    io.newBpSigChain = accumulate io.prevBpSigChain p.digest p.msg.bpPkG := by
  rcases Classical.em (∃ s, s ∈ io.slots ∧ s.shouldUpdate = 1) with hex | hno
  · exact signing_advances_aux hinj (slots_in_range h) h.threaded hex
  · exfalso
    have hall : ∀ s, s ∈ io.slots → s.shouldUpdate = 0 := by
      intro s hs
      obtain ⟨j, hsc⟩ := threaded_slot_constraints h.threaded hs
      rcases shouldUpdate_bool hsc with h0 | h1
      · exact h0
      · exact absurd ⟨s, hs, h1⟩ hno
    exact hne (no_signing_preserves h.threaded hall).2

/-- A signing block CHANGES the accumulator (given the named
    no-fixed-point hypothesis on the Poseidon chain step). -/
theorem signing_block_changes_chain {p : BlockParams F} {io : BlockIO F}
    (hinj : NatLitInj F) (hnf : AccumulateNoFixpoint F) (h : Constraints p io)
    (hsig : ∃ s, s ∈ io.slots ∧ s.shouldUpdate = 1) :
    io.newBpSigChain ≠ io.prevBpSigChain := by
  rw [(signing_block_advances hinj h hsig).1]
  exact hnf _ _ _

/-- A signing block leaves a NON-EMPTY accumulator (given the named
    never-zero hypothesis) — this is precisely what makes the computed
    `is_zero` gate in `ValidityCircuit.signatures_not_skippable` fire:
    combined with `BlockStep.bp_sig_chain_threaded` (continuity) and
    `non_signing_block_preserves`, `final.bp_sig_chain = 0` over a span
    starting from the zero chain iff NO block in the span signed. -/
theorem signing_block_nonempty {p : BlockParams F} {io : BlockIO F}
    (hinj : NatLitInj F) (hne : AccumulateNeverEmpty F) (h : Constraints p io)
    (hsig : ∃ s, s ∈ io.slots ∧ s.shouldUpdate = 1) :
    io.newBpSigChain ≠ zeroBytes F := by
  rw [(signing_block_advances hinj h hsig).1]
  exact hne _ _ _

/-- Block-level bindings for the signing slot: nonzero `tx_tree_root`
    and registered-member inclusion of the folded pubkey. -/
theorem signing_block_bindings {p : BlockParams F} {io : BlockIO F}
    (h : Constraints p io) {s : Slot F} (hs : s ∈ io.slots)
    (h1 : s.shouldUpdate = 1) :
    p.txTreeRoot ≠ zeroBytes F
    ∧ ∃ j, p.msg.bpMemberSlot = natLit F j
        ∧ MerkleVerify MEMBER_TREE_HEIGHT
            (memberLeafHash ⟨toHashOut p.msg.bpPkG, s.memberPkB, s.regevDigest⟩)
            (natLit F j) s.memberSibs s.prevLeaf.memberPubkeysRoot := by
  obtain ⟨j, hsc⟩ := threaded_slot_constraints h.threaded hs
  obtain ⟨hslot, htx, hmem, _⟩ := slot_signing_bindings hsc h.txZeroSpec h1
  exact ⟨htx, j, hslot, hmem⟩

/-- G6 anchor (update_user side): the `channel_reg_hash_chain` PI that
    `block_step.rs:668-670` pins to the resulting ext-state reg chain is
    the SAME wire this circuit folds into the on-chain block hash. So a
    reg-chain advance accepted by block_step is necessarily committed in
    the block hash the contract snapshots. -/
theorem reg_chain_committed_in_block_hash {p : BlockParams F} {io : BlockIO F}
    (h : Constraints p io) :
    io.piChannelRegHashChain = io.blockChannelRegHashChain
    ∧ io.newBlockHashChain = blockHashWithPrev io.prevBlockHashChain
        p.txTreeRoot io.blockDepositHashChain io.blockChannelRegHashChain :=
  ⟨h.regChainPi, h.blockHashFold⟩

/-! ### Satisfiability

The constraint model is not vacuous: we exhibit a satisfying
non-signing block, and — under the explicit numeral-embedding fact
`natLit F 0 = 0` (true in Goldilocks) — a satisfying SIGNING block, so
the signing-branch conjuncts are mutually consistent (the model does
not over-constrain the prover and thereby hide a gap). -/

private def vac1 {α : Sort _} (h : (0 : F) = 1) : α := absurd h.symm one_ne_zero

/-- `bitsValue` of an all-`false` index decomposition is `0`. -/
theorem bitsValue_replicate_false (n : Nat) :
    bitsValue (List.replicate n false) = (0 : F) := by
  induction n with
  | zero => rfl
  | succ n ih =>
      show bitsValue (false :: List.replicate n false) = (0 : F)
      simp only [bitsValue]
      rw [ih]
      simp

/-- A non-signing (all-padding) block satisfies `Constraints`. -/
theorem constraints_satisfiable :
    ∃ (p : BlockParams F) (io : BlockIO F), Constraints p io := by
  let msg : MsgFields F := ⟨0, []⟩
  let leaf : ChannelLeaf F := ⟨0, 0, [], []⟩
  let s : Slot F :=
    { keyId := 0, isDummy := 1, prevMatches := 1, shouldUpdate := 0
      prevLeaf := leaf, newSendRoot := [], chanSibs := []
      updatedRoot := [], rootIn := [], rootOut := []
      memberPkB := [], regevDigest := [], memberSibs := []
      chainIn := zeroBytes F, chainOut := zeroBytes F }
  let p : BlockParams F :=
    { blockNumber := 0, channelId := 0, txTreeRoot := zeroBytes F
      txRootIsZero := 1, msg := msg
      digest := signingDigest msg 0 (zeroBytes F) }
  refine ⟨p,
    { prevBpSigChain := zeroBytes F, newBpSigChain := zeroBytes F
      prevAccountRoot := [], newAccountRoot := []
      prevBlockHashChain := zeroBytes F
      newBlockHashChain := blockHashWithPrev (zeroBytes F) (zeroBytes F)
        (zeroBytes F) (zeroBytes F)
      blockChannelRegHashChain := zeroBytes F
      piChannelRegHashChain := zeroBytes F
      blockDepositHashChain := zeroBytes F
      piDepositHashChain := zeroBytes F
      slots := [s] }, ?_, rfl, rfl, rfl, rfl, ?_, ?_⟩
  · -- txZeroSpec : IsEqualSpecG (zeroBytes F) (zeroBytes F) 1
    exact ⟨Or.inr rfl, ⟨fun _ => rfl, fun _ => rfl⟩⟩
  · -- Threaded p 0 zero [] [s] zero []
    refine ⟨rfl, rfl, ?_, rfl, rfl⟩
    exact
      { isDummySpec := ⟨Or.inr rfl, ⟨fun _ => rfl, fun _ => rfl⟩⟩
        prevMatchesSpec := ⟨Or.inr rfl, ⟨fun _ => rfl, fun _ => rfl⟩⟩
        shouldUpdateDef := by unfold notGate andGate; simp
        treeUpdate := fun h => vac1 h
        rootSelect := ⟨fun h => vac1 h, fun _ => rfl⟩
        txRootNonzeroGate := fun h => vac1 h
        bpSlotBind := fun h => vac1 h
        memberIncl := fun h => vac1 h
        chainSelect := ⟨fun h => vac1 h, fun _ => rfl⟩ }
  · -- slotCount : one slot ≤ MAX_CHANNEL_MEMBERS
    show 1 ≤ MAX_CHANNEL_MEMBERS
    decide

/-- A SIGNING block satisfies `Constraints` — the fold, the bp-slot pin,
    the member inclusion, the nonzero tx root and the tree update are
    mutually consistent. `h0 : natLit F 0 = 0` is the explicit numeral
    embedding fact (Goldilocks: trivially true) needed because `natLit`
    is uninterpreted. -/
theorem signing_constraints_satisfiable (h0 : natLit F 0 = 0) :
    ∃ (p : BlockParams F) (io : BlockIO F),
      Constraints p io ∧ ∃ s, s ∈ io.slots ∧ s.shouldUpdate = 1 := by
  let msg : MsgFields F := ⟨natLit F 0, zeroBytes F⟩
  let memberBits : List Bool := List.replicate MEMBER_TREE_HEIGHT false
  let memberSibs : List (HashOut F) := List.replicate MEMBER_TREE_HEIGHT []
  let mLeaf : MemberLeaf F := ⟨toHashOut (zeroBytes F), [], []⟩
  let memberRoot : HashOut F := fold (memberLeafHash mLeaf) memberBits memberSibs
  -- prev leaf: prev = 0 ≠ blockNumber = 1
  let leaf : ChannelLeaf F := ⟨0, 0, [], memberRoot⟩
  let chanBits : List Bool := List.replicate CHANNEL_TREE_HEIGHT false
  let chanSibs : List (HashOut F) := List.replicate CHANNEL_TREE_HEIGHT []
  let rootIn : HashOut F := fold (channelLeafHash leaf) chanBits chanSibs
  let txRoot : Bytes32 F := [1]
  let digest : Bytes32 F := signingDigest msg 0 txRoot
  let chainIn : Bytes32 F := zeroBytes F
  let newLf : ChannelLeaf F := ⟨(0 : F) + 1, 1, [], memberRoot⟩
  let updated : HashOut F := fold (channelLeafHash newLf) chanBits chanSibs
  let s : Slot F :=
    { keyId := 1, isDummy := 0, prevMatches := 0, shouldUpdate := 1
      prevLeaf := leaf, newSendRoot := [], chanSibs := chanSibs
      updatedRoot := updated, rootIn := rootIn, rootOut := updated
      memberPkB := [], regevDigest := [], memberSibs := memberSibs
      chainIn := chainIn
      chainOut := accumulate chainIn digest (zeroBytes F) }
  let p : BlockParams F :=
    { blockNumber := 1, channelId := 0, txTreeRoot := txRoot
      txRootIsZero := 0, msg := msg, digest := digest }
  have htxne : txRoot ≠ zeroBytes F := by
    intro h
    have hl := congrArg List.length h
    simp [zeroBytes, txRoot] at hl
  refine ⟨p,
    { prevBpSigChain := chainIn
      newBpSigChain := accumulate chainIn digest (zeroBytes F)
      prevAccountRoot := rootIn, newAccountRoot := updated
      prevBlockHashChain := zeroBytes F
      newBlockHashChain := blockHashWithPrev (zeroBytes F) txRoot
        (zeroBytes F) (zeroBytes F)
      blockChannelRegHashChain := zeroBytes F
      piChannelRegHashChain := zeroBytes F
      blockDepositHashChain := zeroBytes F
      piDepositHashChain := zeroBytes F
      slots := [s] },
    ⟨?_, rfl, rfl, rfl, rfl, ?_, ?_⟩, s, List.mem_cons_self s [], rfl⟩
  · -- txZeroSpec : IsEqualSpecG txRoot (zeroBytes F) 0
    exact ⟨Or.inl rfl, ⟨fun h => vac1 h, fun h => absurd h htxne⟩⟩
  · -- Threaded p 0 chainIn rootIn [s] chainOut updated
    refine ⟨rfl, rfl, ?_, rfl, rfl⟩
    refine
      { isDummySpec := ⟨Or.inl rfl,
          ⟨fun h => vac1 h, fun h => (one_ne_zero h).elim⟩⟩
        prevMatchesSpec := ⟨Or.inl rfl, Iff.rfl⟩
        shouldUpdateDef := by unfold notGate andGate; simp
        treeUpdate := fun _ =>
          ⟨⟨chanBits, ?_, ?_, rfl⟩, ⟨chanBits, ?_, ?_, rfl⟩, ?_⟩
        rootSelect := ⟨fun _ => rfl, fun h => vac1 h.symm⟩
        txRootNonzeroGate := fun _ => rfl
        bpSlotBind := fun _ => rfl
        memberIncl := fun _ => ⟨memberBits, ?_, ?_, ?_, rfl⟩
        chainSelect := ⟨fun _ => rfl, fun h => vac1 h.symm⟩ }
    · simp [chanBits, CHANNEL_TREE_HEIGHT]
    · exact (bitsValue_replicate_false CHANNEL_TREE_HEIGHT).symm
    · simp [chanBits, CHANNEL_TREE_HEIGHT]
    · exact (bitsValue_replicate_false CHANNEL_TREE_HEIGHT).symm
    · simp [chanSibs, CHANNEL_TREE_HEIGHT]
    · simp [memberBits, MEMBER_TREE_HEIGHT]
    · simp [memberSibs, MEMBER_TREE_HEIGHT]
    · rw [h0]
      exact (bitsValue_replicate_false MEMBER_TREE_HEIGHT).symm
  · -- slotCount : one slot ≤ MAX_CHANNEL_MEMBERS
    show 1 ≤ MAX_CHANNEL_MEMBERS
    decide

/-! ### The channel_reg branch of block_step.rs (OBLIGATION 2) -/

namespace RegBranch

/-- The update-user proof's PIs consumed by the branch. -/
structure UpdatePis (F : Type) where
  prevAccountTreeRoot : HashOut F
  newAccountTreeRoot : HashOut F
  channelRegHashChain : Bytes32 F

/-- The channel-reg chain proof's PIs
    (`channel_reg_chain_pis.rs:51-66`). -/
structure RegPis (F : Type) where
  initialChannelRegHashChain : Bytes32 F
  initialChannelTreeRoot : HashOut F
  channelRegHashChain : Bytes32 F
  channelTreeRoot : HashOut F
  blockNumber : F

/-- The constraints `block_step.rs` emits around the registration branch
    (target :507-516, :605-670; native mirror :261-338). `regVerified`
    stands for "the embedded proof verifies against the pinned
    channel-reg chain VK" (the sub-proof convention used throughout the
    audit, cf. `ValidityCircuit.Constraints.condVerify`). -/
structure Constraints
    (prevAccountRoot : HashOut F) (prevRegChain : Bytes32 F) (nextBlockNumber : F)
    (upd : UpdatePis F) (reg : RegPis F)
    (hasReg rootEq regEq : F)
    (newAccountRoot : HashOut F) (newRegChain : Bytes32 F)
    (regVerified : Prop) : Prop where
  /-- :507 `has_channel_reg_proof = add_virtual_bool_target_safe()`. -/
  hasRegBool : hasReg = 0 ∨ hasReg = 1
  /-- :508-512 conditionally verify the reg chain proof (pinned VK). -/
  condVerify : hasReg = 1 → regVerified
  /-- :612-614 `account_root_eq = is_equal(upd.prev_root, upd.new_root)`. -/
  rootEqSpec : IsEqualSpecG upd.prevAccountTreeRoot upd.newAccountTreeRoot rootEq
  /-- :616 R6: a registration block's update proof must be a no-op on
      the account tree. -/
  r6Exclusion : hasReg = 1 → rootEq = 1
  /-- :619-625 reg proof continues the previous ext-state reg chain. -/
  initRegChainBind : hasReg = 1 → reg.initialChannelRegHashChain = prevRegChain
  /-- :628-634 reg proof starts from the block's previous account root. -/
  initRootBind : hasReg = 1 → reg.initialChannelTreeRoot = prevAccountRoot
  /-- :635-639 reg proof is bound to THIS block number. -/
  blockNumBind : hasReg = 1 → reg.blockNumber = nextBlockNumber
  /-- :643-648 **the root swap**: the block's account root is the reg
      proof's `channel_tree_root` on a registration block, else the
      update proof's. -/
  rootSelect : SelectSpec hasReg reg.channelTreeRoot upd.newAccountTreeRoot newAccountRoot
  /-- :650-655 the resulting reg chain. -/
  regChainSelect : SelectSpec hasReg reg.channelRegHashChain prevRegChain newRegChain
  /-- :658-660 `reg_eq = is_equal(prev_reg_chain, new_reg_chain)`. -/
  regEqSpec : IsEqualSpecG prevRegChain newRegChain regEq
  /-- :661-662 `has_reg == not(reg_eq)` — the chain changes iff the
      proof is present (mirror of the deposit guard). -/
  changeGuard : hasReg = notGate regEq
  /-- :668-670 G6: the block-hash-committed `channel_reg_hash_chain`
      (an `update_user` PI, see `reg_chain_committed_in_block_hash`)
      equals the resulting ext-state reg chain. -/
  g6Bind : upd.channelRegHashChain = newRegChain

/-
  ## SECURITY FINDING F-UPDU-1 (residual, expected)

  On a registration block the account tree root is REPLACED by
  `reg.channelTreeRoot` (`rootSelect`, block_step.rs:643-648 /
  native :314). What block_step binds — proved sound below — is:

    (a) the reg proof verifies against the pinned channel-reg VK,
    (b) it CONTINUES the previous state
        (`initial_channel_tree_root = prev.account_tree_root`,
         `initial_channel_reg_hash_chain = prev.channel_reg_hash_chain`),
    (c) it is bound to this block number,
    (d) the update proof is an account-tree no-op (R6), and
    (e) the resulting `channel_reg_hash_chain` is committed into the
        on-chain block hash (G6, via the `update_user` PI).

  What block_step does NOT (and cannot) bind is the RELATION between
  `reg.channelRegHashChain` and `reg.channelTreeRoot`: that the Poseidon
  channel tree root is exactly the previous tree with the registration
  leaves folded into the keccak chain written at their channel ids —
  fresh leaves with `index = 0`, `prev = 0`, empty send root, and
  `member_pubkeys_root` recomputed from the SAME member keys the keccak
  chain (and hence the L1 contract) committed (R2 cross-binding), with
  re-registration of an active channel rejected (R5). Those constraints
  live INSIDE the `channel_reg_hash_chain/channel_reg_step.rs` circuit
  (leaf write :432-447, R5 guard :433-437, R2 shared-target binding per
  its module header).

  **STATUS: DISCHARGED (2026-07-06).** That circuit is now in scope —
  `Circuits.ChannelRegStep` (Zkp/Circuits/Validity/ChannelRegStep.lean).
  `tree_and_chain_share_member_set` proves the closing constraint below
  (all three conjuncts, by construction — one shared `members` list feeds
  both the tree leaf's `memberRoot` and the chain's `regDigest`), and
  `chain_determines_tree` proves the anti-tamper direction: the
  L1-committed `channel_reg_hash_chain` PINS the Poseidon `channel_tree_root`
  the account root is swapped to (under the two named keccak-CR hypotheses
  + `PowTwoInj F 32`). The base-layer registration-root exposure is thus
  closed to standard, Goldilocks-true assumptions.

  Closing constraint (now MODELED AND PROVED in `Circuits.ChannelRegStep`):
  `channel_reg_step.rs` per-step soundness
    `regTreeRoot' = writeLeaf regTreeRoot channelId
        (freshLeaf memberRoot)  ∧
     regChain' = keccakFold regChain (regRecord with the SAME member
        keys hashed into memberRoot)  ∧
     prevLeaf@channelId = defaultLeaf (R5)`.
-/

/-- **OBLIGATION 2 (headline). The registration root swap binds exactly
    (a)-(e) above.** Everything block_step CAN pin about the swap is
    pinned; the reg-chain↔tree-root relation itself is the F-UPDU-1
    residual. -/
theorem registration_root_swap_anchored
    {prevAccountRoot : HashOut F} {prevRegChain : Bytes32 F} {nextBlockNumber : F}
    {upd : UpdatePis F} {reg : RegPis F} {hasReg rootEq regEq : F}
    {newAccountRoot : HashOut F} {newRegChain : Bytes32 F} {regVerified : Prop}
    (h : Constraints prevAccountRoot prevRegChain nextBlockNumber upd reg
      hasReg rootEq regEq newAccountRoot newRegChain regVerified)
    (h1 : hasReg = 1) :
    newAccountRoot = reg.channelTreeRoot
    ∧ regVerified
    ∧ reg.initialChannelTreeRoot = prevAccountRoot
    ∧ reg.initialChannelRegHashChain = prevRegChain
    ∧ reg.blockNumber = nextBlockNumber
    ∧ upd.newAccountTreeRoot = upd.prevAccountTreeRoot
    ∧ upd.channelRegHashChain = reg.channelRegHashChain := by
  have hr6 : upd.prevAccountTreeRoot = upd.newAccountTreeRoot :=
    h.rootEqSpec.2.mp (h.r6Exclusion h1)
  have hg6 : upd.channelRegHashChain = reg.channelRegHashChain := by
    rw [h.g6Bind, h.regChainSelect.1 h1]
  exact ⟨h.rootSelect.1 h1, h.condVerify h1, h.initRootBind h1,
    h.initRegChainBind h1, h.blockNumBind h1, hr6.symm, hg6⟩

/-- Without the proof, the branch is inert: the account root comes from
    the update proof, and the reg chain — including its block-hash-
    committed copy (G6) — is unchanged. A prover cannot silently advance
    or rewrite the reg chain outside a registration block. -/
theorem no_proof_no_swap
    {prevAccountRoot : HashOut F} {prevRegChain : Bytes32 F} {nextBlockNumber : F}
    {upd : UpdatePis F} {reg : RegPis F} {hasReg rootEq regEq : F}
    {newAccountRoot : HashOut F} {newRegChain : Bytes32 F} {regVerified : Prop}
    (h : Constraints prevAccountRoot prevRegChain nextBlockNumber upd reg
      hasReg rootEq regEq newAccountRoot newRegChain regVerified)
    (h0 : hasReg = 0) :
    newAccountRoot = upd.newAccountTreeRoot
    ∧ newRegChain = prevRegChain
    ∧ upd.channelRegHashChain = prevRegChain := by
  have hchain : newRegChain = prevRegChain := h.regChainSelect.2 h0
  exact ⟨h.rootSelect.2 h0, hchain, by rw [h.g6Bind, hchain]⟩

/-- Advancing the reg chain REQUIRES the verified proof: the change
    guard (:658-662) forces `has_reg = 1` whenever the resulting chain
    differs from the previous one. -/
theorem reg_chain_advance_requires_proof
    {prevAccountRoot : HashOut F} {prevRegChain : Bytes32 F} {nextBlockNumber : F}
    {upd : UpdatePis F} {reg : RegPis F} {hasReg rootEq regEq : F}
    {newAccountRoot : HashOut F} {newRegChain : Bytes32 F} {regVerified : Prop}
    (h : Constraints prevAccountRoot prevRegChain nextBlockNumber upd reg
      hasReg rootEq regEq newAccountRoot newRegChain regVerified)
    (hne : newRegChain ≠ prevRegChain) :
    hasReg = 1 ∧ regVerified := by
  have hreg0 : regEq = 0 := by
    rcases h.regEqSpec.1 with h0 | h1
    · exact h0
    · exact absurd (h.regEqSpec.2.mp h1).symm hne
  have h1 : hasReg = 1 := by
    rw [h.changeGuard, hreg0]
    unfold notGate
    simp
  exact ⟨h1, h.condVerify h1⟩

/-- Satisfiability of the branch constraints WITH the proof present
    (`has_reg = 1`): the R6/G6/continuity conjuncts are mutually
    consistent. -/
theorem constraints_satisfiable :
    ∃ (prevAccountRoot : HashOut F) (prevRegChain : Bytes32 F) (nextBlockNumber : F)
      (upd : UpdatePis F) (reg : RegPis F) (hasReg rootEq regEq : F)
      (newAccountRoot : HashOut F) (newRegChain : Bytes32 F) (regVerified : Prop),
      Constraints prevAccountRoot prevRegChain nextBlockNumber upd reg
        hasReg rootEq regEq newAccountRoot newRegChain regVerified
      ∧ hasReg = 1 := by
  have hlen : (zeroBytes F) ≠ ([1] : Bytes32 F) := by
    intro h
    have hl := congrArg List.length h
    simp [zeroBytes] at hl
  refine ⟨[], zeroBytes F, 0,
    ⟨[], [], [1]⟩,                        -- upd: no-op roots, G6 chain = [1]
    ⟨zeroBytes F, [], [1], [], 0⟩,        -- reg
    1, 1, 0, [], [1], True, ?_, rfl⟩
  exact
    { hasRegBool := Or.inr rfl
      condVerify := fun _ => trivial
      rootEqSpec := ⟨Or.inr rfl, ⟨fun _ => rfl, fun _ => rfl⟩⟩
      r6Exclusion := fun _ => rfl
      initRegChainBind := fun _ => rfl
      initRootBind := fun _ => rfl
      blockNumBind := fun _ => rfl
      rootSelect := ⟨fun _ => rfl, fun h => vac1 h.symm⟩
      regChainSelect := ⟨fun _ => rfl, fun h => vac1 h.symm⟩
      regEqSpec := ⟨Or.inl rfl, ⟨fun h => vac1 h, fun h => absurd h hlen⟩⟩
      changeGuard := by unfold notGate; simp
      g6Bind := rfl }

end RegBranch

/-!
  ## SECURITY OBSERVATIONS

  * **Obligation 1 discharged.** `signing_block_advances` +
    `account_update_forces_fold` prove: any channel-leaf transition
    forces `new_bp_sig_chain = accumulate(prev, signed_digest, bp_pk_g)`
    — exactly one fold, with the digest bound to the block's own
    `channel_id`/`tx_tree_root` (:795-799) and the pubkey bound to a
    registered member of the channel (`signing_block_bindings`). The
    fold-or-preserve select shares the SAME `should_update` wire as the
    root select (:929,:950,:1026), so "state changed but accumulator
    untouched" is unsatisfiable. Combined with
    `BlockStep.bp_sig_chain_threaded` (cross-block continuity) and
    `ValidityCircuit.signatures_not_skippable` (computed gate), the
    validity span cannot contain a signing block whose signature list
    goes unverified. `signing_block_nonempty` makes the gate's
    non-zero premise explicit under `AccumulateNeverEmpty`.

  * **At most one fold per block** (`later_slots_preserve`, the
    INVARIANT comment at :966-971): a second updating slot would pin
    `msg_fields.bp_member_slot` to two distinct slot numerals
    (`NatLitInj`). Note the circuit design folds AT MOST ONE signature
    per block; if the block layout ever permits two distinct
    channel-leaf updates per block, `signing_block_advances` (one fold)
    would leave the second signature unfolded — revisit the loop before
    such a change (already flagged in the Rust INVARIANT comment).

  * **Third load-bearing binding — member-set immutability**
    (`member_set_immutable`): the update path copies
    `member_pubkeys_root` from the proven previous leaf (:922). This was
    previously unflagged: had the new leaf's member root been witnessed
    freely, a block producer could rotate the channel's member set and
    self-authorize all future signing blocks. Only the registration
    chain (F-UPDU-1 scope) defines member sets.

  * **Obligation 2: what IS bound** (`registration_root_swap_anchored`,
    `no_proof_no_swap`, `reg_chain_advance_requires_proof`): the
    registration-block root swap requires a verified reg-chain proof
    continuing the previous account root and reg chain, bound to this
    block number, with the update proof forced to a no-op (R6) and the
    resulting reg chain committed into the on-chain block hash (G6 —
    the update_user side is `reg_chain_committed_in_block_hash`).

  * **F-UPDU-1 (residual, see the finding block in `RegBranch`):** the
    reg proof's `channel_tree_root ↔ channel_reg_hash_chain` relation
    is internal to the excluded `channel_reg_step.rs`. Until that
    circuit is audited, account-tree soundness on registration blocks
    is conditional on it — base-layer fund risk, NOT channel scope.
    (That circuit must also pin fresh leaves' `prev = 0` — it does at
    :441-443 — since a leaf pre-set to a FUTURE block number would make
    that block's slot read as "already updated", suppressing the
    signature fold for its first real transition.)

  * **Modeled-out constraints:** tx-attribution (:852-895) and the
    send-tree sub-update (:897-914) only ADD constraints on updating
    slots; the Regev digest recomputation (:980-991) feeds the witnessed
    `regevDigest` leaf component. None can weaken the theorems above.
    Sub-proof verification (`block_step` verifying THIS circuit, and the
    reg-chain proof) follows the audit-wide verified-sub-proof
    convention.
-/

end Circuits.UpdateUser
end Zkp
