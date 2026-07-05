import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Single withdrawal extraction  — L1 exit provenance
  ==================================================

  Source: `src/circuits/withdraw/single_withdrawal_circuit.rs`

  ## Protocol role

  Extracts ONE L1 withdrawal from a user's balance proof. It proves the
  withdrawn transfer is one the user actually SENT (it lives in a tx
  committed in the user's `sent_tx_tree`, which is itself committed in
  the balance proof's `private_commitment`) and that the same tx is
  included — via the account-state send leaf — in a block tx tree for
  this user's `channel_id`. The emitted `Withdrawal { recipient,
  token_index, amount, nullifier, aux_data }` is what the L1 contract
  pays out; the `nullifier` makes each withdrawal one-shot PER SENT TX.
  Its preimage keys on `(channel_id, transfer_index, tx.nonce)` — all
  bound to the deduction — so it is SETTLEMENT-INDEPENDENT: settling one
  deduction into two blocks now yields the SAME nullifier (F-WD-2 closed
  by Option B; see the SECURITY OBSERVATIONS). One-shot-ness then rests
  on the on-chain single-use map, not on any settlement-uniqueness
  invariant.

  Uses `add_proof_target_and_verify_cyclic` (`:422`) — the PROPER
  cyclic verifier, not the verify-by-PI shortcut — so C-M3 does not
  apply to the withdrawal path.

  ## Constraint inventory (single_withdrawal_circuit.rs:422-525)

  | line     | gate                                                    | meaning |
  |----------|---------------------------------------------------------|---------|
  | :422     | `add_proof_target_and_verify_cyclic(balance_vd)`        | verify balance proof (cyclic) |
  | :423-427 | `balance_pis := parse(balance_proof.public_inputs)`     | boundary: verified balance PIs |
  | :433     | `range_check(tx.nonce, SENT_TX_TREE_HEIGHT)`            | nonce canonical (redundant w/ split_le, see note) |
  | :435     | `use_tx_v2 = add_virtual_bool_target_safe()`            | v2/legacy selector is boolean |
  | :441-442 | `private_state.commitment() == balance_pis.private_commitment` | bind FULL private state (incl. sent_tx_tree_root) |
  | :444-446 | `update_public_state.old == balance_pis.public_state`   | update starts at the proof's state |
  | :447     | `public_state := update_public_state.new` (emitted PI)  | emitted state = update target |
  | :430 (internal, update_public_state.rs:97-106) | old ∈ new.prev_public_state_root, or new == old | history link |
  | :449-451 | `account_state.channel_id == balance_pis.channel_id`    | account state ↔ this user |
  | :452-454 | `account_state.account_tree_root == public_state.account_tree_root` | account state ↔ emitted state |
  | :431 (internal, account_state.rs:123-135) | send leaf ∈ channel leaf ∈ account root | two-level membership |
  | :456-461 | `sent_tx_merkle_proof.verify(tx, tx.nonce, private_state.sent_tx_tree_root)` | user actually SENT this tx |
  | :463-465 | `transfer_witness.transfer_tree_root == tx.transfer_tree_root` | transfer tree = the tx's tree |
  | :439 (internal, transfer_witness.rs:88-93) | transfer ∈ transfer_tree_root at transfer_index | transfer ∈ tx |
  | :467-470 | `tx_tree_root := reduce_to_hash_out(send_leaf.tx_tree_root)` | deterministic gate (poseidon_hash_out.rs:303-317) |
  | :473     | `tx_index := balance_pis.channel_id` (channel_id.rs:216-222) | one tx slot per user/block |
  | :474-481 | `tx_merkle_proof.conditional_verify(!use_tx_v2, tx, tx_index, tx_tree_root)` | legacy inclusion |
  | :482-488 | `tx_v2_merkle_proof.conditional_verify(use_tx_v2, tx_v2, tx_index, tx_tree_root)` | v2 inclusion |
  | :490-493 | if v2: `tx_v2.tx_class == UserTransfer`                 | v2 is a user transfer |
  | :494-495 | if v2: `tx_v2.channel_action_root == 0`                 | no channel action |
  | :496-500 | if v2: `tx_v2.transfer_tree_root == tx.transfer_tree_root` | v2 ↔ tx consistency |
  | :501     | if v2: `tx_v2.nonce == tx.nonce`                        | v2 ↔ tx consistency |
  | :503-504 | `recipient = extract_address(transfer.recipient)`       | L1 address (F-RECIP-1, informational) |
  | :506-512 | `nullifier = SettledTransfer{transfer, channel_id, transfer_index, tx.nonce}.nullifier()` | one-shot key (F-WD-2 B: nonce, not block) |
  | :514-520 | build `Withdrawal` from transfer fields                 | payout |
  | :522-525, :609 | register `public_state ++ withdrawal` as PIs      | on-chain interface |

  ## Modeling notes

  * The sent-tx leaf and the legacy block-tx leaf are the SAME
    deterministic hash of `(transfer_tree_root, nonce)` — both trees
    store `Tx` leaves hashed by `Tx::hash` (tx.rs:94-103, :163-172),
    and the Merkle gadget hashes the leaf in-circuit
    (merkle_tree.rs:228). There is no free "leaf digest" wire, so
    `txLeafHash` appears directly as the leaf argument of the
    inclusion constraints.
  * `private_state.commitment()` (private_state.rs:134-139) is
    Poseidon over `to_vec()` (private_state.rs:122-132) = ALL six
    fields — asset root, nullifier root, `sent_tx_tree_root`,
    prev commitment, nonce, salt. `privateCommitment` is opaque over
    exactly that record, so the commitment is a deterministic function
    of (in particular) the sent-tx root used by `sentTx`.
  * Range checks (`:433` on `tx.nonce`; limb checks inside the
    `is_checked = true` targets) are NOT separate conjuncts: every
    Merkle index already carries its height-length boolean
    decomposition inside `MerkleVerify` (split_le at
    merkle_tree.rs:227), and omitting the redundant checks only
    WEAKENS the soundness hypothesis (safe direction) while keeping
    the satisfiability witness constructible.
-/

namespace Zkp
namespace Circuits.SingleWithdrawalCircuit

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

/-- `SENT_TX_TREE_HEIGHT = 32` (constants.rs:39). -/
def SENT_TX_TREE_HEIGHT : Nat := 32
/-- `TX_TREE_HEIGHT = CHANNEL_ID_BITS = 32` (constants.rs:16,74). -/
def TX_TREE_HEIGHT : Nat := 32
/-- `TRANSFER_TREE_HEIGHT = 6` (constants.rs:71). -/
def TRANSFER_TREE_HEIGHT : Nat := 6
/-- `SEND_TREE_HEIGHT = 32` (constants.rs:17). -/
def SEND_TREE_HEIGHT : Nat := 32
/-- `CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS = 32` (constants.rs:16,21). -/
def CHANNEL_TREE_HEIGHT : Nat := 32
/-- `PUBLIC_STATE_TREE_HEIGHT = BLOCK_NUMBER_BITS = 63` (constants.rs:13-14). -/
def PUBLIC_STATE_TREE_HEIGHT : Nat := 63

/-- The transfer being withdrawn (transfer.rs:34-39; U256 amount kept
    abstract as one value). `transferLeaf` is its Poseidon leaf digest
    (transfer.rs:251-258 / the in-circuit LeafableTarget hash). -/
structure Transfer (F : Type) where
  recipient : Bytes32 F
  tokenIndex : F
  amount : F
  auxData : Bytes32 F
opaque transferLeaf {F : Type} [CField F] : Transfer F → HashOut F

/-- The emitted withdrawal record (withdrawal.rs:25-31). -/
structure Withdrawal (F : Type) where
  recipient : Bytes32 F   -- extract_address(transfer.recipient) (low 20 bytes)
  tokenIndex : F
  amount : F
  nullifier : Bytes32 F
  auxData : Bytes32 F

/-- The balance proof's private state (private_state.rs:23-41):
    asset root, nullifier root, sent-tx root, previous commitment,
    nonce, blinding salt (salt.rs:20 — a 4-limb Poseidon digest). -/
structure PrivateState (F : Type) where
  assetTreeRoot : HashOut F
  nullifierTreeRoot : HashOut F
  sentTxTreeRoot : HashOut F
  prevPrivateCommitment : HashOut F
  nonce : F
  salt : HashOut F

/-- `PrivateStateTarget::commitment` (private_state.rs:134-139):
    Poseidon over `to_vec()` (private_state.rs:122-132) — ALL six
    fields, including `sent_tx_tree_root`. Opaque (deterministic
    in-circuit hash); collision resistance, where a proof needs it, is
    named separately (`Bytes.PoseidonCR` pattern). -/
opaque privateCommitment {F : Type} [CField F] : PrivateState F → HashOut F

/-- A transaction (tx.rs:34-40): transfer-tree root + sender nonce. -/
structure Tx (F : Type) where
  transferTreeRoot : HashOut F
  nonce : F

/-- `Tx`'s Poseidon leaf digest: `Poseidon(transfer_tree_root ‖ nonce)`
    (tx.rs:94-103 `to_vec`, tx.rs:163-172 in-circuit hash). Used both
    as the sent-tx-tree leaf and the legacy block-tx-tree leaf; the
    Merkle gadget computes it in-circuit (merkle_tree.rs:228), so the
    leaf is a deterministic function of exactly these two wires. -/
opaque txLeafHash {F : Type} [CField F] : HashOut F → F → HashOut F

/-- A v2 transaction (tx.rs:395-400). -/
structure TxV2 (F : Type) where
  txClass : F
  transferTreeRoot : HashOut F
  nonce : F
  channelActionRoot : HashOut F
/-- `TxV2`'s Poseidon leaf digest (tx.rs:403-411, :518-527). -/
opaque txv2Leaf {F : Type} [CField F] : TxV2 F → HashOut F

/-- `TxClass::UserTransfer = 0` (tx.rs:177-180; constant at :490-491). -/
def USER_TRANSFER (F : Type) [CField F] : F := natLit F 0

/-- The zero Poseidon digest (`PoseidonHashOut::default()`, :494). -/
opaque zeroHash (F : Type) [CField F] : HashOut F

/-- Send-tree leaf (channel_tree.rs:44-49): block-number span
    (`prev`/`cur`, each a single U63 limb) + the block's tx-tree root
    as Bytes32. `sendLeafHash` is its Poseidon digest
    (channel_tree.rs:58-90). -/
structure SendLeaf (F : Type) where
  prev : F
  cur : F
  txTreeRoot : Bytes32 F
opaque sendLeafHash {F : Type} [CField F] : SendLeaf F → HashOut F

/-- Channel-tree leaf (channel_tree.rs:94-105): next send index, prev
    block number, send-tree root, member-pubkeys root.
    `channelLeafHash` is its domain-tagged ("CHLF",
    channel_tree.rs:92, :144-147) Poseidon digest. -/
structure ChannelLeaf (F : Type) where
  index : F
  prev : F
  sendTreeRoot : HashOut F
  memberPubkeysRoot : HashOut F
opaque channelLeafHash {F : Type} [CField F] : ChannelLeaf F → HashOut F

/-- The rollup public state (public_state.rs:71-77). It has EXACTLY
    these FIVE fields — `block_number`, `timestamp`,
    `account_tree_root`, `deposit_tree_root`,
    `prev_public_state_root` — so Lean structural equality is
    full-record equality, which is what `PublicStateTarget::is_equal`
    (public_state.rs:307-328) compares: five per-field equality bits
    ANDed in a left-leaning tree, proved exact field-by-field in
    Zkp/Circuits/Common/PublicStateEq.lean (F-PUBST-1 discharge).
    `timestamp` is a `U64Target` (2 u32 limbs) abstracted here as one
    value, like `blockNumber`; the three roots are Poseidon digests. -/
structure PublicState (F : Type) where
  blockNumber : F
  timestamp : F
  accountTreeRoot : HashOut F
  depositTreeRoot : HashOut F
  prevPublicStateRoot : HashOut F

/-- The public state's leaf digest in the history tree (Poseidon of
    the full record; public_state_tree leaf hashing). -/
opaque psLeaf {F : Type} [CField F] : PublicState F → HashOut F

/-- `Bytes32Target::reduce_to_hash_out` (poseidon_hash_out.rs:303-317):
    deterministic limb recombination `hi·2^32 + lo` per element. A pure
    gate (mul_const_add) — no prover freedom — so modeled as a
    function. NOTE it is NOT injective on arbitrary Bytes32 (limb
    pairs ≥ p alias mod p); here the input is pinned by the committed
    send leaf, so the reduced root is determined — canonicity of the
    stored bytes is the validity circuit's obligation where the leaf
    is written, not this circuit's. -/
opaque reduceToHashOut {F : Type} [CField F] : Bytes32 F → HashOut F

/-- `extract_address` low-20-byte projection (recipient.rs, used at
    :503-504; informational F-RECIP-1).

    DROPPED CONJUNCT (documented, verified in the Rust): THIS
    instantiation calls `extract_address_from_recipient_circuit`
    (single_withdrawal_circuit.rs:503-504), which additionally emits
    `connect(bytes[0], ADDRESS_TAG)` (recipient.rs:83-84) — a tag
    check on the recipient's leading byte. The model omits that
    conjunct: omission only WEAKENS the modeled constraint set (safe
    direction for every soundness theorem here, none of which relies
    on the tag), and keeps the satisfiability witness constructible
    for an arbitrary `transfer.recipient`. Tag-byte semantics are
    adjudicated at the F-RECIP-1 finding site
    (Balance/Common/Recipient.lean, incl. `tag_separation`). -/
opaque extractAddress {F : Type} [CField F] : Bytes32 F → Bytes32 F

/-- `SettledTransferTarget::nullifier` (transfer.rs:228-234):
    Poseidon over `to_vec()` (transfer.rs:218-226) = FULL transfer
    (recipient included, transfer.rs:130-138) ‖ from-channel ‖
    transfer index ‖ NONCE — the sender-account tx nonce (u32, 1 limb),
    same preimage length as before (F-WD-2 Option B; block number was
    the previous 4th field). The 4th argument here is `tx.nonce`, a wire
    already bound by the sent-tx membership (`sentTx`) at index=nonce, so
    the key is SETTLEMENT-INDEPENDENT: it no longer varies with the
    settling block. Two withdrawals backed by the SAME deduction now
    collide on this key (see the F-WD-2 closure in SECURITY
    OBSERVATIONS). -/
opaque settledNullifier {F : Type} [CField F] :
  Transfer F → F → F → F → Bytes32 F

/-- The constraint system emitted by `SingleWithdawalTarget::new`
    (single_withdrawal_circuit.rs:412-541). Parameters:

    * `balancePrivCommit`, `balancePublicState`, `channelId` — public
      inputs of the cyclically VERIFIED balance proof (:422-427).
      Boundary: their truthfulness w.r.t. the user's history is the
      balance circuit's soundness (Balance/*), consumed here as given.
    * `priv` — prover-supplied private state witness (:429).
    * `updNew`, `updOld`, `updEqWire`, `updSib` — the public-state
      update gadget's wires (:430; update_public_state.rs:86-113).
      `updNew` is also the EMITTED public-state PI (:447, :522-525).
    * `accChannelId`, `accAccountTreeRoot`, `sendLeaf`,
      `sendLeafIndex`, `sendSib`, `chanLeaf`, `userSib` — the
      account-state gadget's wires (:431, `is_checked = true`;
      account_state.rs:102-146).
    * `tx`, `txv2`, `useTxV2`, `sentSib`, `txSib`, `txv2Sib` — the tx
      and its inclusion paths (:432-438).
    * `transfer`, `transferIndex`, `transferSib`, `twRoot` — the
      transfer witness (:439; transfer_witness.rs:72-101).
    * `w` — the emitted withdrawal PI (:514-520, :522-525). -/
structure Constraints
    (balancePrivCommit : HashOut F) (balancePublicState : PublicState F)
    (channelId : F)
    (priv : PrivateState F)
    (updNew updOld : PublicState F) (updEqWire : F) (updSib : List (HashOut F))
    (accChannelId : F) (accAccountTreeRoot : HashOut F)
    (sendLeaf : SendLeaf F) (sendLeafIndex : F) (sendSib : List (HashOut F))
    (chanLeaf : ChannelLeaf F) (userSib : List (HashOut F))
    (tx : Tx F) (txv2 : TxV2 F) (useTxV2 : F)
    (sentSib txSib txv2Sib : List (HashOut F))
    (transfer : Transfer F) (transferIndex : F) (transferSib : List (HashOut F))
    (twRoot : HashOut F)
    (w : Withdrawal F) : Prop where
  /-- :441-442 — `private_state.commitment(builder)` (a deterministic
      hash of ALL six fields incl. `sent_tx_tree_root`,
      private_state.rs:122-139) is `connect`-ed to the verified
      balance proof's `private_commitment` PI. -/
  bindPriv : privateCommitment priv = balancePrivCommit
  /-- :444-446 — `update_public_state.old` is `connect`-ed to the
      verified balance proof's `public_state` PI. -/
  bindUpdOld : updOld = balancePublicState
  /-- update_public_state.rs:97 (instantiated at :430) —
      `is_equal(new, old)` advice wire over the FULL five-field record
      (`PublicStateTarget::is_equal`, public_state.rs:307-328, ANDs
      per-field equality of block_number, timestamp,
      account_tree_root, deposit_tree_root, prev_public_state_root —
      see Zkp/Circuits/Common/PublicStateEq.lean). The ← direction of
      `IsEqualSpecG` (records equal ⇒ wire = 1) is faithful only
      because the model's `PublicState` carries ALL five Rust fields:
      a witness with some fields equal and others differing is
      representable and correctly forces the wire to 0. -/
  updEq : IsEqualSpecG updNew updOld updEqWire
  /-- update_public_state.rs:98-106 (instantiated at :430) — when the
      states differ, `old` is included at index `old.block_number`
      under `new.prev_public_state_root`. -/
  updHist : notGate updEqWire = 1 →
    MerkleVerify PUBLIC_STATE_TREE_HEIGHT (psLeaf updOld)
      updOld.blockNumber updSib updNew.prevPublicStateRoot
  /-- :449-451 — `account_state.channel_id` is `connect`-ed to the
      balance proof's `channel_id` PI. -/
  bindAccChan : accChannelId = channelId
  /-- :447, :452-454 — `account_state.account_tree_root` is
      `connect`-ed to `update_public_state.new.account_tree_root`
      (the emitted public state). -/
  bindAccRoot : accAccountTreeRoot = updNew.accountTreeRoot
  /-- account_state.rs:123-128 (instantiated at :431) — the send leaf
      is included at `send_leaf_index` under the channel leaf's
      `send_tree_root`. -/
  accSend : MerkleVerify SEND_TREE_HEIGHT (sendLeafHash sendLeaf)
    sendLeafIndex sendSib chanLeaf.sendTreeRoot
  /-- account_state.rs:130-135 (instantiated at :431) — the channel
      leaf is included at `channel_id` under `account_tree_root`. -/
  accUser : MerkleVerify CHANNEL_TREE_HEIGHT (channelLeafHash chanLeaf)
    accChannelId userSib accAccountTreeRoot
  /-- :456-461 — the tx leaf `Poseidon(transfer_tree_root ‖ nonce)`
      (hashed in-gadget, merkle_tree.rs:228; tx.rs:94-103,:163-172) is
      included at index `tx.nonce` under `private_state.sent_tx_tree_root`
      — the SAME private state committed by `bindPriv`. -/
  sentTx : MerkleVerify SENT_TX_TREE_HEIGHT
    (txLeafHash tx.transferTreeRoot tx.nonce) tx.nonce
    sentSib priv.sentTxTreeRoot
  /-- :463-465 — the transfer witness's tree root is `connect`-ed to
      `tx.transfer_tree_root`, chaining the transfer into the tx. -/
  bindTwRoot : twRoot = tx.transferTreeRoot
  /-- transfer_witness.rs:88-93 (instantiated at :439) — the transfer
      is included at `transfer_index` under the witness root. -/
  inTransfer : MerkleVerify TRANSFER_TREE_HEIGHT (transferLeaf transfer)
    transferIndex transferSib twRoot
  /-- :435 — `add_virtual_bool_target_safe` pins the selector. -/
  v2bool : useTxV2 = 0 ∨ useTxV2 = 1
  /-- :467-481 — legacy path: the tx leaf is included at
      `channel_id` (:473) under `reduce_to_hash_out(send_leaf.tx_tree_root)`
      (:467-470) when `use_tx_v2 = 0` (:474). -/
  vLegacy : CondMerkleVerify (notGate useTxV2) TX_TREE_HEIGHT
    (txLeafHash tx.transferTreeRoot tx.nonce) channelId txSib
    (reduceToHashOut sendLeaf.txTreeRoot)
  /-- :482-488 — v2 path: the tx_v2 leaf is included at `channel_id`
      under the same root when `use_tx_v2 = 1`. -/
  vV2 : CondMerkleVerify useTxV2 TX_TREE_HEIGHT (txv2Leaf txv2)
    channelId txv2Sib (reduceToHashOut sendLeaf.txTreeRoot)
  /-- :490-493 — if v2: `tx_v2.tx_class == UserTransfer` (is_equal at
      :492 composed with conditional_assert_eq at :493). -/
  cClass : useTxV2 = 1 → txv2.txClass = USER_TRANSFER F
  /-- :494-495 — if v2: `tx_v2.channel_action_root == 0`. -/
  cAction : useTxV2 = 1 → txv2.channelActionRoot = zeroHash F
  /-- :496-500 — if v2: `tx_v2.transfer_tree_root == tx.transfer_tree_root`. -/
  cTransfer : useTxV2 = 1 → txv2.transferTreeRoot = tx.transferTreeRoot
  /-- :501 — if v2: `tx_v2.nonce == tx.nonce`. -/
  cNonce : useTxV2 = 1 → txv2.nonce = tx.nonce
  /-- :503-504, :515 — recipient is the address projection of the
      withdrawn transfer's recipient. -/
  wRecip : w.recipient = extractAddress transfer.recipient
  /-- :516 — token index copied from the transfer. -/
  wTok : w.tokenIndex = transfer.tokenIndex
  /-- :517 — amount copied from the transfer. -/
  wAmt : w.amount = transfer.amount
  /-- :506-512, :518 — nullifier of the SETTLED transfer: from-channel
      = `balance_pis.channel_id` (:508), index =
      `transfer_witness.transfer_index` (:509), NONCE = `tx.nonce`
      (:510, F-WD-2 Option B — replaces the former `send_leaf.cur` block
      number). `tx.nonce` is bound to the deduction via `sentTx` (sent-tx
      membership at index=nonce), so this key is settlement-independent. -/
  wNul : w.nullifier = settledNullifier transfer channelId transferIndex tx.nonce
  /-- :519 — aux data copied from the transfer. -/
  wAux : w.auxData = transfer.auxData

/-- **Withdrawal provenance chain.** For every satisfying witness, the
    emitted withdrawal `w` (a registered PI, :522-525) reflects a
    transfer whose provenance chains all the way to the verified
    balance proof and to a block tx tree:

    1. the prover's private state hashes (over ALL its fields,
       including `sentTxTreeRoot`) to the verified balance proof's
       `private_commitment`;
    2. the tx leaf — the deterministic hash of
       `(tx.transferTreeRoot, tx.nonce)` — is Merkle-included at index
       `tx.nonce` in THAT private state's sent-tx tree;
    3. the withdrawn transfer is Merkle-included at `transferIndex`
       in the transfer tree whose root is THE root committed inside
       that tx leaf (`tx.transferTreeRoot`);
    4. the same tx leaf (legacy path) — or a v2 leaf constrained to
       carry the same `transfer_tree_root` and `nonce`, be a plain
       `UserTransfer`, and have zero channel-action root — is
       Merkle-included at `channelId` in the block tx tree whose root
       is the (deterministic reduction of the) account-state send
       leaf's `tx_tree_root`;
    5. that send leaf is Merkle-included under the channel leaf's send
       tree, which is Merkle-included at `channelId` under
       `updNew.accountTreeRoot` — the account root of the EMITTED
       public state;
    6. the emitted public state `updNew` either equals the balance
       proof's public state — full five-field record equality
       (block number, timestamp, account root, deposit root, prev
       history root), per `PublicStateTarget::is_equal`
       (public_state.rs:307-328) — or commits it in its own history
       root;
    7. `w`'s recipient/token/amount/aux equal the transfer's (address
       via `extract_address`), and `w.nullifier` is the one-shot key
       of the deduction
       `(transfer, channelId, transferIndex, tx.nonce)` — keyed on the
       nonce, NOT the settling block (F-WD-2 Option B), hence identical
       across any two settlements of the same deduction.

    What this does NOT claim (boundaries, see SECURITY OBSERVATIONS):
    the truthfulness of the balance PIs (balance circuit's soundness),
    injectivity/CR of the opaque hashes (named where needed), and the
    genuineness of `updNew` itself, which the L1 contract must re-pin
    against its recorded block state. -/
theorem withdrawal_sound
    {balancePrivCommit : HashOut F} {balancePublicState : PublicState F}
    {channelId : F} {priv : PrivateState F}
    {updNew updOld : PublicState F} {updEqWire : F} {updSib : List (HashOut F)}
    {accChannelId : F} {accAccountTreeRoot : HashOut F}
    {sendLeaf : SendLeaf F} {sendLeafIndex : F} {sendSib : List (HashOut F)}
    {chanLeaf : ChannelLeaf F} {userSib : List (HashOut F)}
    {tx : Tx F} {txv2 : TxV2 F} {useTxV2 : F}
    {sentSib txSib txv2Sib : List (HashOut F)}
    {transfer : Transfer F} {transferIndex : F} {transferSib : List (HashOut F)}
    {twRoot : HashOut F} {w : Withdrawal F}
    (h : Constraints balancePrivCommit balancePublicState channelId priv
          updNew updOld updEqWire updSib accChannelId accAccountTreeRoot
          sendLeaf sendLeafIndex sendSib chanLeaf userSib tx txv2 useTxV2
          sentSib txSib txv2Sib transfer transferIndex transferSib twRoot w) :
    -- (1) balance-proof binding of the FULL private state
    privateCommitment priv = balancePrivCommit
    -- (2) the tx lives in THAT private state's sent-tx tree, at its nonce
    ∧ MerkleVerify SENT_TX_TREE_HEIGHT
        (txLeafHash tx.transferTreeRoot tx.nonce) tx.nonce
        sentSib priv.sentTxTreeRoot
    -- (3) the withdrawn transfer lives in THAT tx's transfer tree
    ∧ MerkleVerify TRANSFER_TREE_HEIGHT (transferLeaf transfer)
        transferIndex transferSib tx.transferTreeRoot
    -- (4) the tx (or its consistency-constrained v2 image) is in the
    --     block tx tree pinned by the account-state send leaf
    ∧ (MerkleVerify TX_TREE_HEIGHT (txLeafHash tx.transferTreeRoot tx.nonce)
         channelId txSib (reduceToHashOut sendLeaf.txTreeRoot)
       ∨ (MerkleVerify TX_TREE_HEIGHT (txv2Leaf txv2)
            channelId txv2Sib (reduceToHashOut sendLeaf.txTreeRoot)
          ∧ txv2.transferTreeRoot = tx.transferTreeRoot
          ∧ txv2.nonce = tx.nonce
          ∧ txv2.txClass = USER_TRANSFER F
          ∧ txv2.channelActionRoot = zeroHash F))
    -- (5) the send leaf is committed under the emitted state's account
    --     root, at THIS user's channel id
    ∧ MerkleVerify SEND_TREE_HEIGHT (sendLeafHash sendLeaf)
        sendLeafIndex sendSib chanLeaf.sendTreeRoot
    ∧ MerkleVerify CHANNEL_TREE_HEIGHT (channelLeafHash chanLeaf)
        channelId userSib updNew.accountTreeRoot
    -- (6) emitted-state provenance w.r.t. the balance proof's state
    ∧ (updNew = balancePublicState
       ∨ MerkleVerify PUBLIC_STATE_TREE_HEIGHT (psLeaf balancePublicState)
           balancePublicState.blockNumber updSib updNew.prevPublicStateRoot)
    -- (7) the emitted withdrawal fields are exactly the transfer's
    ∧ w.recipient = extractAddress transfer.recipient
    ∧ w.tokenIndex = transfer.tokenIndex
    ∧ w.amount = transfer.amount
    ∧ w.nullifier = settledNullifier transfer channelId transferIndex tx.nonce
    ∧ w.auxData = transfer.auxData := by
  refine ⟨h.bindPriv, h.sentTx, ?_, ?_, h.accSend, ?_, ?_,
          h.wRecip, h.wTok, h.wAmt, h.wNul, h.wAux⟩
  · -- (3): rewrite the connected transfer-tree root
    have hi := h.inTransfer
    rw [h.bindTwRoot] at hi
    exact hi
  · -- (4): the safe boolean selector makes one inclusion unavoidable
    rcases h.v2bool with h0 | h1
    · exact Or.inl (h.vLegacy (by rw [notGate_eq_one_iff (Or.inl h0)]; exact h0))
    · exact Or.inr ⟨h.vV2 h1, h.cTransfer h1, h.cNonce h1, h.cClass h1, h.cAction h1⟩
  · -- (5b): rewrite the account-state bindings
    have hu := h.accUser
    rw [h.bindAccChan, h.bindAccRoot] at hu
    exact hu
  · -- (6): either a genuine no-op or a history inclusion
    obtain ⟨hbool, hiff⟩ := h.updEq
    rcases hbool with h0 | h1
    · right
      have hm := h.updHist (by rw [notGate_eq_one_iff (Or.inl h0)]; exact h0)
      rw [h.bindUpdOld] at hm
      exact hm
    · left
      rw [← h.bindUpdOld]
      exact hiff.mp h1

/-! ### Satisfiability (vacuity guard)

  The soundness theorem above is worthless if `Constraints` were
  contradictory (an over-constrained model proves anything). We
  exhibit an explicit witness satisfying EVERY conjunct.

  One link cannot be discharged internally: the block-inclusion leg
  requires `fold (txLeafHash …) … = reduceToHashOut sendLeaf.txTreeRoot`,
  where both sides are outputs of DISTINCT opaque hash-level functions
  — no constructive witness can equate them, exactly mirroring that an
  honest prover obtains this fact from real chain data (the block
  builder put the tx into the tx tree whose root the send leaf
  records). We therefore take ONE such inclusion as a hypothesis and
  show every remaining conjunct is simultaneously satisfiable on top
  of it — i.e. no conjunct of the model over-constrains the system. -/

/-- All-`false` index bits (index 0). -/
def zeroBits (h : Nat) : List Bool := List.replicate h false

/-- Height-many placeholder sibling digests. -/
def zeroSib (F : Type) [CField F] (h : Nat) : List (HashOut F) :=
  List.replicate h ([] : HashOut F)

/-- The all-`false` bit string has field value 0. -/
theorem bitsValue_zeroBits : ∀ h : Nat, bitsValue (zeroBits h) = (0 : F)
  | 0 => rfl
  | n + 1 => by
      show (if false then (1 : F) else 0) + (1 + 1) * bitsValue (zeroBits n) = 0
      rw [bitsValue_zeroBits n, mul_zero', if_neg (by simp), add_zero']

/-- A Merkle inclusion at index 0 whose root is DEFINED as the fold of
    the leaf up the zero path — trivially satisfiable. -/
theorem merkleVerify_zeroPath (h : Nat) (leaf : HashOut F) :
    MerkleVerify h leaf (0 : F) (zeroSib F h)
      (fold leaf (zeroBits h) (zeroSib F h)) :=
  ⟨zeroBits h, by simp [zeroBits], by simp [zeroSib],
    (bitsValue_zeroBits h).symm, rfl⟩

/-- Transfer-tree root used by the satisfiability witness. -/
def satTransferRoot (transfer : Transfer F) : HashOut F :=
  fold (transferLeaf transfer) (zeroBits TRANSFER_TREE_HEIGHT)
    (zeroSib F TRANSFER_TREE_HEIGHT)

/-- **Completeness direction / vacuity guard.** Given any transfer,
    any send leaf, and one block-tx-tree inclusion of the
    corresponding tx leaf under the send leaf's reduced root (the
    honest-chain-data fact discussed above), the FULL `Constraints`
    is satisfiable. In particular no conjunct of the model is an
    unprovable strengthening: the hypothesis list cannot be
    contradictory. -/
theorem constraints_satisfiable
    (transfer : Transfer F) (sendLeaf : SendLeaf F) (txSib : List (HashOut F))
    (hinc : MerkleVerify TX_TREE_HEIGHT
      (txLeafHash (satTransferRoot transfer) (0 : F)) (0 : F) txSib
      (reduceToHashOut sendLeaf.txTreeRoot)) :
    ∃ (balancePrivCommit : HashOut F) (balancePublicState : PublicState F)
      (channelId : F) (priv : PrivateState F)
      (updNew updOld : PublicState F) (updEqWire : F) (updSib : List (HashOut F))
      (accChannelId : F) (accAccountTreeRoot : HashOut F)
      (sendLeafIndex : F) (sendSib : List (HashOut F))
      (chanLeaf : ChannelLeaf F) (userSib : List (HashOut F))
      (tx : Tx F) (txv2 : TxV2 F) (useTxV2 : F)
      (sentSib txv2Sib : List (HashOut F))
      (transferIndex : F) (transferSib : List (HashOut F))
      (twRoot : HashOut F) (w : Withdrawal F),
      Constraints balancePrivCommit balancePublicState channelId priv
        updNew updOld updEqWire updSib accChannelId accAccountTreeRoot
        sendLeaf sendLeafIndex sendSib chanLeaf userSib tx txv2 useTxV2
        sentSib txSib txv2Sib transfer transferIndex transferSib twRoot w :=
  let troot : HashOut F := satTransferRoot transfer
  let tx0 : Tx F := ⟨troot, 0⟩
  let priv0 : PrivateState F :=
    ⟨[], [],
      fold (txLeafHash troot (0 : F)) (zeroBits SENT_TX_TREE_HEIGHT)
        (zeroSib F SENT_TX_TREE_HEIGHT),
      [], 0, []⟩
  let chan0 : ChannelLeaf F :=
    ⟨0, 0,
      fold (sendLeafHash sendLeaf) (zeroBits SEND_TREE_HEIGHT)
        (zeroSib F SEND_TREE_HEIGHT),
      []⟩
  let acctRoot : HashOut F :=
    fold (channelLeafHash chan0) (zeroBits CHANNEL_TREE_HEIGHT)
      (zeroSib F CHANNEL_TREE_HEIGHT)
  let ps0 : PublicState F := ⟨0, 0, acctRoot, [], []⟩
  let w0 : Withdrawal F :=
    ⟨extractAddress transfer.recipient, transfer.tokenIndex, transfer.amount,
      settledNullifier transfer 0 0 0, transfer.auxData⟩
  ⟨privateCommitment priv0, ps0, 0, priv0, ps0, ps0, 1,
    zeroSib F PUBLIC_STATE_TREE_HEIGHT, 0, acctRoot, 0,
    zeroSib F SEND_TREE_HEIGHT, chan0, zeroSib F CHANNEL_TREE_HEIGHT,
    tx0, ⟨0, [], 0, []⟩, 0, zeroSib F SENT_TX_TREE_HEIGHT,
    zeroSib F TX_TREE_HEIGHT, 0, zeroSib F TRANSFER_TREE_HEIGHT, troot, w0,
    { bindPriv := rfl
      bindUpdOld := rfl
      updEq := ⟨Or.inr rfl, Iff.intro (fun _ => rfl) (fun _ => rfl)⟩
      updHist := by
        intro hcontra
        unfold notGate at hcontra
        rw [sub_self'] at hcontra
        exact absurd hcontra.symm one_ne_zero
      bindAccChan := rfl
      bindAccRoot := rfl
      accSend := merkleVerify_zeroPath SEND_TREE_HEIGHT (sendLeafHash sendLeaf)
      accUser := merkleVerify_zeroPath CHANNEL_TREE_HEIGHT (channelLeafHash chan0)
      sentTx := merkleVerify_zeroPath SENT_TX_TREE_HEIGHT
        (txLeafHash troot (0 : F))
      bindTwRoot := rfl
      inTransfer := merkleVerify_zeroPath TRANSFER_TREE_HEIGHT
        (transferLeaf transfer)
      v2bool := Or.inl rfl
      vLegacy := fun _ => hinc
      vV2 := fun habs => absurd habs.symm one_ne_zero
      cClass := fun habs => absurd habs.symm one_ne_zero
      cAction := fun habs => absurd habs.symm one_ne_zero
      cTransfer := fun habs => absurd habs.symm one_ne_zero
      cNonce := fun habs => absurd habs.symm one_ne_zero
      wRecip := rfl
      wTok := rfl
      wAmt := rfl
      wNul := rfl
      wAux := rfl }⟩

/-!
  ## SECURITY OBSERVATIONS

  * **Provenance is the anti-mint property, and it now CHAINS.** The
    withdrawal fields come from a transfer that is (a) a leaf of the
    transfer tree whose root is committed — together with the nonce —
    inside the tx leaf; (b) that tx leaf sits in the sent-tx tree
    whose root is a hashed field of the private state committed by the
    VERIFIED balance proof's `private_commitment`; and (c) the same tx
    leaf sits in a block tx tree pinned by an account-state send leaf
    committed under the emitted public state's account root at this
    user's `channel_id`. Turning these Merkle facts into "unique real
    transfer" additionally needs Poseidon collision resistance
    (`Bytes.PoseidonCR`-style, for `txLeafHash`/`transferLeaf`/
    `privateCommitment`/`sendLeafHash`/`channelLeafHash`) — named
    here, not silently assumed.

  * **Boundary: balance PIs.** `balancePrivCommit`,
    `balancePublicState`, `channelId` are public inputs of the
    balance proof verified at :422. That the private commitment
    reflects a legitimately evolved private state (spends solvent,
    nonces monotone) is the balance circuits' soundness — modeled in
    Balance/* — and is consumed here as an interface fact.

  * **Boundary: genuineness of the emitted public state.** `updNew`
    is prover-supplied. In-circuit it is only constrained to (i) equal
    the balance proof's state, or (ii) commit that state in its own
    `prev_public_state_root` history (update_public_state.rs:97-106).
    Nothing in THIS circuit proves `updNew` is a real chain state; the
    completion point is the L1 contract re-pinning the withdrawal
    proof's emitted public state / commitment against the block it
    recorded (same completion pattern as F-WITHDRAW-1 in
    WithdrawalCircuit.lean). If the contract consumed
    `updNew.account_tree_root` as ground truth without that check, a
    prover could fabricate an account tree containing an arbitrary
    send leaf and "settle" a tx in a fictitious block.

  * **Double-withdraw prevented** by the per-deduction `nullifier`
    (covers the full transfer incl. recipient + from channel +
    transfer index + NONCE, transfer.rs:218-234, F-WD-2 Option B).
    The L1 contract rejects a reused nullifier (contract-side,
    audit622 Part A — out of this scope, but the circuit emits the
    unique key).

  * **F-WD-2 CLOSED by Option B — settlement-independence of the
    nullifier.** `wNul` proves the emitted nullifier is a function of
    ONLY `(channelId, transferIndex, tx.nonce)` (transfer fields plus
    those three), and EVERY one of those inputs is bound to the
    one-time balance deduction, NOT to the settling block:
      - `channelId` is `bindAccChan`-bound to the verified balance
        proof's `channel_id` PI;
      - `transfer` and `transferIndex` are pinned by `inTransfer`
        (transfer-tree membership) under `bindTwRoot`/`bindPriv`;
      - `tx.nonce` is pinned by `sentTx`: the tx leaf
        `Poseidon(transfer_tree_root ‖ nonce)` is Merkle-included at
        index `tx.nonce` in `priv.sentTxTreeRoot`, the sent-tx root
        committed by the balance proof's `private_commitment`
        (`bindPriv`). On the sender side, `spend_circuit` writes each
        tx at index=nonce only after an empty-slot check and with a
        sequential nonce, so `(from, nonce, transfer_index)` is a
        one-time identifier of the deduction (transfer.rs SettledTransfer
        preimage; F-WD-2-threatmodel.md §"Sender-side facts").
    The former 4th field `send_leaf.cur` (the SETTLING BLOCK number) is
    GONE. Consequence: settling the SAME deduction into two DIFFERENT
    blocks — two distinct send leaves — now produces the IDENTICAL
    nullifier (nothing settlement-varying remains in the preimage), so
    the two payouts NECESSARILY collide on the on-chain
    `withdrawalNullifierUsed` set (and the recipient indexed-merkle for
    receive). The settle-twice attack is therefore caught by the SAME
    single-use map that catches an ordinary double-withdraw.

    WHAT IS PROVED HERE vs WHAT THE MAP DOES. Lean proves settlement-
    INDEPENDENCE (the collision): two settlements of one deduction map
    to one key. The one-shot ENFORCEMENT of that key — rejecting the
    second use — is the on-chain single-use map, exactly as for an
    ordinary double-withdraw; it is NOT re-proved in this circuit (the
    circuit's job ends at emitting the unique key). This is the
    nonce-binding closure, distinct from the (now removed) reliance on a
    validity-side settlement-uniqueness induction.

  -- SECURITY FINDING (F-WD-2): settle-twice nullifier.
  -- STATUS: CLOSED by Option B (nonce-binding closure). The nullifier
  -- preimage's block-number field (`send_leaf.cur`) is replaced by the
  -- sender-account tx nonce (`tx.nonce`), making the key settlement-
  -- INDEPENDENT. Two settlements of one deduction now yield BYTE-
  -- IDENTICAL nullifiers, caught by the existing on-chain single-use
  -- map — so fund-safety no longer depends on any validity-side
  -- settlement-uniqueness invariant (which the Lean `UpdateUser` model
  -- does NOT establish, as the send-tree sub-update / tx-attribution
  -- constraints, update_channel_tree.rs:852-914, are out of modeled
  -- scope). HONEST NOTE: this closure is on the WITHDRAWAL side; the
  -- single-use ENFORCEMENT remains the on-chain map (unchanged pattern
  -- for any double-withdraw). OPTIONAL FOLLOW-UP (defense-in-depth, NOT
  -- required for the fund-safety closure): Option A — a per-channel
  -- settled-nonce SET in the settlement circuit (corrected from the
  -- naive strictly-increasing form, which was a liveness blocker; see
  -- F-WD-2-threatmodel.md §"Attacker red-team verdict"). Option A would
  -- make double-settle UNREACHABLE on-chain and give a settlement-side
  -- Lean fact, but it is an F-UPDU-1-entangled protocol change and is
  -- deliberately deferred (DECISION 2026-07-04).

  * **v2 path is as good as legacy.** When `use_tx_v2 = 1`, the
    included leaf is a `TxV2` constrained to carry the SAME
    `transfer_tree_root` and `nonce` as the tx whose sent-tx-tree
    membership was proved (:496-501), to be a plain `UserTransfer`
    (:490-493), and to have zero channel-action root (:494-495) — so
    block inclusion of the v2 image certifies settlement of the same
    spend. The `add_virtual_bool_target_safe` selector (:435) makes
    skipping BOTH inclusion checks impossible.

  * **No tx.nonce ↔ private_state.nonce constraint (by design).** The
    circuit does NOT relate `tx.nonce` to `priv.nonce`; the sent-tx
    tree is indexed by nonce, so the balance proof's send circuit is
    what guarantees one sent tx per nonce slot. Adding such a conjunct
    here would be an unprovable strengthening with no Rust
    counterpart — deliberately omitted.

  * **F-RECIP-1 (informational here).** `extract_address` ignores
    recipient padding bytes[1..12]; adjudicated non-exploitable (see
    Balance/Common/Recipient.lean) because the nullifier covers the
    full recipient and funds are bounded by sender solvency.
-/

end Circuits.SingleWithdrawalCircuit
end Zkp
