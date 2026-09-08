import Std
import Zkp.Implementation.CommonValues
import Zkp.Implementation.UtilGadgets
import Zkp.Implementation.MerkleTrees
import Zkp.Implementation.SparseTrees
import Zkp.Implementation.IndexedMerkleTree
import Zkp.Implementation.PrivateState

/-!
# Tree instantiations and the generic hash-chain circuit family

A HANDWRITTEN SEMANTIC MODEL of

* `src/common/trees/` — the concrete Merkle-tree instantiations of the protocol:
  `channel_tree.rs`, `key_tree.rs`, `nullifier_tree.rs`, `tx_v2_tree.rs`, `tx_tree.rs`,
  `transfer_tree.rs`, `sent_tx_tree.rs`, `public_state_tree.rs`, `deposit_tree.rs`,
  `asset_tree.rs`, `mod.rs`; and
* `src/utils/hash_chain/` — the generic keccak hash-chain circuit family:
  `mod.rs`, `hash_inner_circuit.rs`, `cyclic_chain_circuit.rs`, `chain_end_circuit.rs`,
  `hash_chain_processor.rs`, `error.rs`.

THIS IS NOT A REFINEMENT PROOF of the Rust sources, of the plonky2 circuit compiler, of
Poseidon/keccak, or of the on-chain verifier. Nothing here proves that a plonky2 proof exists,
is sound, or that any hash is collision resistant. The model is a Lean transcription of the
*data layout and control flow* those files describe, plus kernel-checked theorems about that
transcription.

## What is modelled

* Every tree instantiation as a `(height, backing structure, leaf type, empty leaf)` record,
  with the heights taken from `src/constants.rs` through the already-registered
  `Zkp.Implementation.UtilGadgets` constants, so a drift between this file and the rest of the
  audit is a broken `rfl`.
* The three leaf types that `src/common/trees/` actually DEFINES (`SendLeaf`, `ChannelLeaf`,
  `MemberLeaf`) down to their Poseidon preimage word lists, including the domain tags.
  Leaves defined in other source files (`Tx`, `TxV2`, `Transfer`, `Deposit`, `PublicState`,
  `U256`) stay opaque; only `TxV2`'s preimage is spelled out, because it is needed for the
  cross-tree observation below.
* The empty (`init`) tree of every instantiation, reusing `Zkp.Implementation.SparseTrees`
  (`SparseMerkleTree`/`IncrementalMerkleTree`) and `Zkp.Implementation.IndexedMerkleTree`
  (the nullifier tree's backing structure).
* The hash-chain fold `h_{i+1} = keccak(h_i ++ content_i)` with `h_0 = 0`, the inner step
  circuit's public-input layout, the cyclic wrapper's accept relation, the chain-end
  statement `keccak(last_hash ++ proof_submitter)`, its codec, and its error enum.

## Opaque callbacks and undischarged premises (see `boundaries` in the line maps)

* `Env.poseidon` / `Env.twoToOne` / `ChainEnv.keccak` — Poseidon and keccak are opaque
  functions. NO injectivity, collision resistance or preimage resistance is assumed anywhere;
  where two digests must differ that is an explicit hypothesis on the concrete compared pair.
* plonky2 proof soundness, recursive verification, `conditionally_verify_cyclic_proof_or_dummy`,
  `add_verifier_data_public_inputs`, and the `common_data_for_hash_chain_circuit` gate-count
  padding are all outside the model: the cyclic wrapper is modelled by its accept RELATION on
  public inputs, not by a proof system.
* Gadget lowering: the native `to_u64_vec` word lists and the in-circuit `to_vec` target lists
  are modelled by the same Lean lists; that the plonky2 builder emits exactly those wires is
  not proved.
* Field/range discipline: `Nat` stands for Goldilocks/`u32`/`u64` values. Range checks appear
  as explicit `Prop`s, never as type invariants.
* `panics`: Rust `assert!`/`unwrap` sites are modelled as explicit outcomes
  (`U64ParseOutcome.panicked`), not as Lean errors.
-/

namespace Zkp.Implementation.TreeInstances

/-! ## 1. The instantiation table

`src/common/trees/mod.rs` is a bare list of ten submodules; nine of them are nothing but a
`pub type` alias plus an `init()` that pins a height from `src/constants.rs`. The table below
is the whole content of those files. -/

/-- Which of the three backing structures of `src/utils/trees/` a tree is built on.
`sparse` = `SparseMerkleTree` (random-access, `HashMap` of written leaves);
`incremental` = `IncrementalMerkleTree` (append-only frontier, `Vec` of leaves);
`indexed` = `IndexedMerkleTree` (an ordered key set with low-leaf non-membership proofs). -/
inductive Backing where
  | sparse
  | incremental
  | indexed
  deriving DecidableEq, Repr

/-- Every tree instantiated under `src/common/trees/`. `channelActionTree` and `txV2Tree`
both live in `tx_v2_tree.rs`; `memberTree` and `walletMemberTree` are the two DISTINCT
instantiations of `key_tree.rs`'s `MemberTree` alias. -/
inductive TreeInstance where
  | sendTree
  | channelTree
  | memberTree
  | walletMemberTree
  | nullifierTree
  | txTree
  | txV2Tree
  | channelActionTree
  | transferTree
  | sentTxTree
  | publicStateTree
  | depositTree
  | assetTree
  deriving DecidableEq, Repr

/-- The height each `init()` passes to its backing constructor. Every value is taken from the
registered `UtilGadgets` transcription of `src/constants.rs`, so this file cannot drift from
the rest of the audit without breaking a `rfl`. -/
def heightOf : TreeInstance → Nat
  | .sendTree => UtilGadgets.sendTreeHeight
  | .channelTree => UtilGadgets.channelTreeHeight
  | .memberTree => UtilGadgets.memberTreeHeight
  | .walletMemberTree => UtilGadgets.walletMemberTreeHeight
  | .nullifierTree => UtilGadgets.nullifierTreeHeight
  | .txTree => UtilGadgets.txTreeHeight
  | .txV2Tree => UtilGadgets.txTreeHeight
  | .channelActionTree => UtilGadgets.txTreeHeight
  | .transferTree => UtilGadgets.transferTreeHeight
  | .sentTxTree => UtilGadgets.sentTxTreeHeight
  | .publicStateTree => UtilGadgets.publicStateTreeHeight
  | .depositTree => UtilGadgets.depositTreeHeight
  | .assetTree => UtilGadgets.assetTreeHeight

/-- The backing structure each alias selects. -/
def backingOf : TreeInstance → Backing
  | .sendTree => .incremental
  | .channelTree => .sparse
  | .memberTree => .incremental
  | .walletMemberTree => .incremental
  | .nullifierTree => .indexed
  | .txTree => .sparse
  | .txV2Tree => .sparse
  | .channelActionTree => .sparse
  | .transferTree => .incremental
  | .sentTxTree => .incremental
  | .publicStateTree => .incremental
  | .depositTree => .incremental
  | .assetTree => .sparse

/-- `2 ^ height`: the number of leaf slots, and the bound of `IncrementalMerkleTree::push`'s
`assert!`. -/
def capacityOf (t : TreeInstance) : Nat := 2 ^ heightOf t

/-- The source file each instantiation comes from. -/
def sourceFileOf : TreeInstance → String
  | .sendTree => "channel_tree.rs"
  | .channelTree => "channel_tree.rs"
  | .memberTree => "key_tree.rs"
  | .walletMemberTree => "key_tree.rs"
  | .nullifierTree => "nullifier_tree.rs"
  | .txTree => "tx_tree.rs"
  | .txV2Tree => "tx_v2_tree.rs"
  | .channelActionTree => "tx_v2_tree.rs"
  | .transferTree => "transfer_tree.rs"
  | .sentTxTree => "sent_tx_tree.rs"
  | .publicStateTree => "public_state_tree.rs"
  | .depositTree => "deposit_tree.rs"
  | .assetTree => "asset_tree.rs"

/-- Enumeration of the table, used to state completeness. -/
def allInstances : List TreeInstance :=
  [.sendTree, .channelTree, .memberTree, .walletMemberTree, .nullifierTree,
   .txTree, .txV2Tree, .channelActionTree, .transferTree, .sentTxTree,
   .publicStateTree, .depositTree, .assetTree]

theorem all_instances_length : allInstances.length = 13 := by decide

theorem all_instances_is_complete (t : TreeInstance) : t ∈ allInstances := by
  cases t <;> decide

theorem all_instances_lists_each_tree_once (t : TreeInstance) :
    (allInstances.filter (fun u => u == t)).length = 1 := by
  cases t <;> decide

/-! ### Pinned heights, one theorem per instantiation -/

theorem send_tree_height_pinned : heightOf .sendTree = 32 := rfl

theorem channel_tree_height_pinned : heightOf .channelTree = 32 := rfl

theorem member_tree_height_pinned : heightOf .memberTree = 3 := rfl

theorem wallet_member_tree_height_pinned : heightOf .walletMemberTree = 10 := rfl

theorem nullifier_tree_height_pinned : heightOf .nullifierTree = 32 := rfl

theorem tx_tree_height_pinned : heightOf .txTree = 32 := rfl

theorem tx_v2_tree_height_pinned : heightOf .txV2Tree = 32 := rfl

theorem channel_action_tree_height_pinned : heightOf .channelActionTree = 32 := rfl

theorem transfer_tree_height_pinned : heightOf .transferTree = 6 := rfl

theorem sent_tx_tree_height_pinned : heightOf .sentTxTree = 32 := rfl

theorem public_state_tree_height_pinned : heightOf .publicStateTree = 63 := rfl

theorem deposit_tree_height_pinned : heightOf .depositTree = 63 := rfl

theorem asset_tree_height_pinned : heightOf .assetTree = 32 := rfl

/-! ### Pinned backing structures -/

theorem backing_of_each_instance :
    backingOf .sendTree = .incremental ∧
    backingOf .channelTree = .sparse ∧
    backingOf .memberTree = .incremental ∧
    backingOf .walletMemberTree = .incremental ∧
    backingOf .nullifierTree = .indexed ∧
    backingOf .txTree = .sparse ∧
    backingOf .txV2Tree = .sparse ∧
    backingOf .channelActionTree = .sparse ∧
    backingOf .transferTree = .incremental ∧
    backingOf .sentTxTree = .incremental ∧
    backingOf .publicStateTree = .incremental ∧
    backingOf .depositTree = .incremental ∧
    backingOf .assetTree = .sparse := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Exactly one instantiation uses the indexed (ordered-set) structure: the nullifier tree.
Non-membership is therefore provable only there. -/
theorem nullifier_tree_is_the_only_indexed_tree (t : TreeInstance) :
    backingOf t = .indexed ↔ t = .nullifierTree := by
  cases t <;> exact ⟨by decide, by decide⟩

/-! ### Cross-checks against the already-registered modules

Every one of these is `rfl`, i.e. the constant this file pins is DEFINITIONALLY the constant
the other module pins. A future edit that changes one and not the other fails to compile. -/

theorem deposit_height_agrees_with_merkle_trees :
    heightOf .depositTree = MerkleTrees.depositTreeHeight := rfl

theorem send_height_agrees_with_merkle_trees :
    heightOf .sendTree = MerkleTrees.sendTreeHeight := rfl

theorem asset_height_agrees_with_util_gadgets :
    heightOf .assetTree = UtilGadgets.assetTreeHeight := rfl

theorem nullifier_height_agrees_with_util_gadgets :
    heightOf .nullifierTree = UtilGadgets.nullifierTreeHeight := rfl

theorem sent_tx_height_agrees_with_util_gadgets :
    heightOf .sentTxTree = UtilGadgets.sentTxTreeHeight := rfl

theorem public_state_height_agrees_with_util_gadgets :
    heightOf .publicStateTree = UtilGadgets.publicStateTreeHeight := rfl

theorem member_height_agrees_with_util_gadgets :
    heightOf .memberTree = UtilGadgets.memberTreeHeight := rfl

theorem wallet_member_height_agrees_with_util_gadgets :
    heightOf .walletMemberTree = UtilGadgets.walletMemberTreeHeight := rfl

/-- `PUBLIC_STATE_TREE_HEIGHT = BLOCK_NUMBER_BITS` (constants.rs:13-14): the public-state tree
is indexed by block number, so its capacity is exactly the block-number space. -/
theorem public_state_tree_is_indexed_by_block_number :
    heightOf .publicStateTree = UtilGadgets.blockNumberBits := rfl

/-- `ASSET_TREE_HEIGHT = TOKEN_INDEX_BITS` (constants.rs:37): one asset slot per token index. -/
theorem asset_tree_is_indexed_by_token_index :
    heightOf .assetTree = UtilGadgets.tokenIndexBits := rfl

/-- `CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS` (constants.rs:21) and
`TX_TREE_HEIGHT = CHANNEL_ID_BITS` (constants.rs:282): BOTH the channel tree and the tx tree
are indexed by a 32-bit channel id, so a channel id is simultaneously a valid index into
either. Nothing in the tree layer distinguishes them; separation rests on the leaf preimages
and on the circuits that open them. -/
theorem channel_tree_and_tx_tree_share_the_channel_id_index_space :
    heightOf .channelTree = UtilGadgets.channelIdBits ∧
      heightOf .txTree = UtilGadgets.channelIdBits ∧
      heightOf .channelTree = heightOf .txTree := ⟨rfl, rfl, rfl⟩

/-- Six of the thirteen instantiations sit at height 32. Same height ⇒ same Merkle path
shape, so a path for one is structurally a path for another; only the leaf preimage and the
opening circuit tell them apart. -/
theorem height_thirty_two_family :
    (allInstances.filter (fun t => heightOf t == 32)).length = 8 := by decide

theorem deposit_and_public_state_are_the_two_height_63_trees :
    allInstances.filter (fun t => heightOf t == 63) = [.publicStateTree, .depositTree] := by
  decide

/-- `TRANSFER_TREE_HEIGHT = 6` (constants.rs:279) is the only single-digit height, and
`MAX_NUM_TRANSFERS_PER_TX = 1 << 6 = 64`. -/
theorem transfer_tree_capacity_is_max_transfers_per_tx :
    capacityOf .transferTree = UtilGadgets.maxNumTransfersPerTx := rfl

theorem transfer_tree_capacity_is_64 : capacityOf .transferTree = 64 := by decide

/-! ### The two `MemberTree` instantiations (`key_tree.rs:176-189`)

`MemberTree` is ONE alias with TWO constructors at DIFFERENT heights. `init()` builds the
registered cosigner tree whose root goes into `ChannelLeaf.member_pubkeys_root`;
`init_wallet_membership()` builds the wallet-side live membership tree. The source comment
says the heights differ deliberately "so conflation fails loudly". -/

theorem registered_member_tree_capacity_is_the_sig_cluster :
    capacityOf .memberTree = UtilGadgets.maxSigCluster := by decide

theorem wallet_member_tree_capacity_is_max_channel_members :
    capacityOf .walletMemberTree = UtilGadgets.maxChannelMembers := by decide

/-- The "fails loudly" property, as a proposition: the two instantiations of the SAME leaf
type have different heights, hence different Merkle path lengths. -/
theorem member_tree_instantiations_have_different_heights :
    heightOf .memberTree ≠ heightOf .walletMemberTree := by decide

theorem member_tree_instantiations_have_different_capacities :
    capacityOf .memberTree ≠ capacityOf .walletMemberTree := by decide

/-- The wallet membership tree and the H1 balance-slot tree DO share a height (both 10), so
a balance-slot path and a wallet-member path are structurally interchangeable; only the
registered cosigner tree (height 3) is structurally distinct. -/
theorem wallet_member_tree_and_balance_slot_tree_share_a_height :
    heightOf .walletMemberTree = UtilGadgets.balanceSlotTreeHeight := rfl

/-- DOCUMENTATION/CODE DISAGREEMENT (`channel_tree.rs:99-104` vs `key_tree.rs:176-182`).
The `ChannelLeaf.member_pubkeys_root` comment says the committed member leaves occupy
"slot 0..MAX_CHANNEL_MEMBERS (active members first, padding slots empty; pad-to-MAX D6)",
i.e. 1024 slots. The constructor actually used for that root, `MemberTree::init()`, is
`MEMBER_TREE_HEIGHT = 3`, i.e. 8 slots = `MAX_SIG_CLUSTER`. The comment overstates the tree
by a factor of 128; `key_tree.rs`'s own module docstring is the correct one. -/
theorem channel_leaf_member_root_is_the_sig_cluster_tree_not_the_channel_member_tree :
    capacityOf .memberTree = UtilGadgets.maxSigCluster ∧
      capacityOf .memberTree ≠ UtilGadgets.maxChannelMembers := by
  exact ⟨by decide, by decide⟩

/-! ## 2. Leaf layouts and domain separation

Only three leaf TYPES are defined under `src/common/trees/`: `SendLeaf` and `ChannelLeaf`
(`channel_tree.rs`) and `MemberLeaf` (`key_tree.rs`). Their Poseidon preimages are the word
lists below. `TxV2`'s preimage (`src/common/tx.rs:425-433`) is spelled out too, because the
empty-leaf comparison at the end of this section needs it; every other leaf type stays
opaque. -/

/-- `SendLeaf { prev: BlockNumber, cur: BlockNumber, tx_tree_root: Bytes32 }`
(`channel_tree.rs:44-49`). A `BlockNumber` is a `u63` whose `to_u64_vec` is a SINGLE word
(`src/common/u63.rs:79-81`), and `Bytes32::to_u64_vec` is eight `u32` limbs. -/
structure SendLeaf where
  prev : Nat
  cur : Nat
  txTreeRoot : CommonValues.Limbs8
  deriving DecidableEq, Repr

/-- `ChannelLeaf { index: u32, prev: BlockNumber, send_tree_root, member_pubkeys_root }`
(`channel_tree.rs:94-105`). -/
structure ChannelLeaf where
  index : Nat
  prev : Nat
  sendTreeRoot : CommonValues.Hash4
  memberPubkeysRoot : CommonValues.Hash4
  deriving DecidableEq, Repr

/-- `MemberLeaf { pk_g, pk_b, regev_pk_digest }` (`key_tree.rs:71-76`). The three components
live in ONE leaf so the channel's `member_pubkeys_root` commits the triple jointly (A11). -/
structure MemberLeaf where
  pkG : CommonValues.Hash4
  pkB : CommonValues.Hash4
  regevPkDigest : CommonValues.Hash4
  deriving DecidableEq, Repr

/-- `CHANNEL_LEAF_DOMAIN` (`channel_tree.rs:92`), ASCII "CHLF". -/
def channelLeafDomain : Nat := 0x43484c46

/-- `MEMBER_LEAF_DOMAIN` (`key_tree.rs:51`), ASCII "MBLF". -/
def memberLeafDomain : Nat := 0x4d424c46

theorem channel_leaf_domain_is_chlf :
    channelLeafDomain = UtilGadgets.asciiBE 67 72 76 70 := by decide

theorem member_leaf_domain_is_mblf :
    memberLeafDomain = UtilGadgets.asciiBE 77 66 76 70 := by decide

theorem leaf_domain_tags_are_distinct : channelLeafDomain ≠ memberLeafDomain := by decide

/-- Both tags fit in a `u32`, so `F::from_canonical_u64` of either is a canonical Goldilocks
element and the in-circuit constant equals the native word. -/
theorem leaf_domain_tags_fit_in_a_u32_limb :
    channelLeafDomain ≤ CommonValues.u32Max ∧ memberLeafDomain ≤ CommonValues.u32Max := by
  exact ⟨by decide, by decide⟩

/-- `SendLeaf::to_u64_vec` (`channel_tree.rs:164-173`). NO DOMAIN TAG. -/
def sendLeafWords (l : SendLeaf) : List Nat :=
  [l.prev, l.cur] ++ CommonValues.limbWords l.txTreeRoot

/-- `ChannelLeaf::to_u64_vec` (`channel_tree.rs:229-239`): the domain tag leads. -/
def channelLeafWords (l : ChannelLeaf) : List Nat :=
  [channelLeafDomain, l.index, l.prev] ++ CommonValues.hashWords l.sendTreeRoot
    ++ CommonValues.hashWords l.memberPubkeysRoot

/-- `MemberLeaf::to_u64_vec` (`key_tree.rs:85-95`): the domain tag leads. -/
def memberLeafWords (l : MemberLeaf) : List Nat :=
  memberLeafDomain :: (CommonValues.hashWords l.pkG ++ CommonValues.hashWords l.pkB
    ++ CommonValues.hashWords l.regevPkDigest)

/-- `SendLeafTarget::to_vec` (`channel_tree.rs:190-197`); `BlockNumberTarget::to_vec` is one
target (`u63.rs:155-157`), matching the native single-word encoding. -/
def sendLeafTargetWords (l : SendLeaf) : List Nat :=
  [l.prev, l.cur] ++ CommonValues.limbWords l.txTreeRoot

/-- `ChannelLeafTarget::to_vec` (`channel_tree.rs:262-270`): field targets WITHOUT the tag;
`LeafableTarget::hash` prepends it in-circuit (`channel_tree.rs:144-147`). -/
def channelLeafTargetWords (l : ChannelLeaf) : List Nat :=
  [l.index, l.prev] ++ CommonValues.hashWords l.sendTreeRoot
    ++ CommonValues.hashWords l.memberPubkeysRoot

/-- `MemberLeafTarget::to_vec` (`key_tree.rs:121-128`), tag prepended in
`LeafableTarget::hash` (`key_tree.rs:165-168`). -/
def memberLeafTargetWords (l : MemberLeaf) : List Nat :=
  CommonValues.hashWords l.pkG ++ CommonValues.hashWords l.pkB
    ++ CommonValues.hashWords l.regevPkDigest

/-- The in-circuit preimage of a `ChannelLeaf` is the native one: the tag prepended in
`LeafableTarget::hash` sits exactly where `to_u64_vec` puts it. (LAYOUT agreement only; that
the plonky2 builder emits these wires is a `gadget-lowering` boundary.) -/
theorem channel_leaf_circuit_preimage_matches_native (l : ChannelLeaf) :
    channelLeafDomain :: channelLeafTargetWords l = channelLeafWords l := rfl

theorem member_leaf_circuit_preimage_matches_native (l : MemberLeaf) :
    memberLeafDomain :: memberLeafTargetWords l = memberLeafWords l := rfl

/-- `SendLeaf` has no tag on either side, so the two encodings coincide verbatim. -/
theorem send_leaf_circuit_preimage_matches_native (l : SendLeaf) :
    sendLeafTargetWords l = sendLeafWords l := rfl

theorem send_leaf_preimage_length (l : SendLeaf) : (sendLeafWords l).length = 10 := by
  simp [sendLeafWords, CommonValues.limbWords]

theorem channel_leaf_preimage_length (l : ChannelLeaf) : (channelLeafWords l).length = 11 := by
  simp [channelLeafWords, CommonValues.hashWords]

theorem member_leaf_preimage_length (l : MemberLeaf) : (memberLeafWords l).length = 13 := by
  simp [memberLeafWords, CommonValues.hashWords]

/-- Cross-tree separation between the two DOMAIN-TAGGED leaf types is structural: the tags
differ, so no `ChannelLeaf` preimage is ever a `MemberLeaf` preimage. No hash assumption. -/
theorem channel_and_member_leaf_preimages_never_coincide (c : ChannelLeaf) (m : MemberLeaf) :
    channelLeafWords c ≠ memberLeafWords m := by
  intro h
  have hlen : (channelLeafWords c).length = (memberLeafWords m).length := by rw [h]
  rw [channel_leaf_preimage_length, member_leaf_preimage_length] at hlen
  exact absurd hlen (by decide)

/-- The untagged `SendLeaf` is separated from `ChannelLeaf` only by preimage LENGTH
(10 vs 11), not by a tag. -/
theorem send_and_channel_leaf_preimages_never_coincide (s : SendLeaf) (c : ChannelLeaf) :
    sendLeafWords s ≠ channelLeafWords c := by
  intro h
  have hlen : (sendLeafWords s).length = (channelLeafWords c).length := by rw [h]
  rw [send_leaf_preimage_length, channel_leaf_preimage_length] at hlen
  exact absurd hlen (by decide)

/-! ### Empty leaves -/

/-- `<SendLeaf as Leafable>::empty_leaf() = SendLeaf::default()` (`channel_tree.rs:61-63`,
`#[derive(Default)]` at line 44): all zeros. -/
def emptySendLeaf : SendLeaf := ⟨0, 0, CommonValues.zeroLimbs8⟩

/-- `<MemberLeaf as Leafable>::empty_leaf() = MemberLeaf::default()` (`key_tree.rs:100-102`):
all three digests zero. -/
def emptyMemberLeaf : MemberLeaf := ⟨CommonValues.zeroHash, CommonValues.zeroHash,
  CommonValues.zeroHash⟩

theorem empty_send_leaf_words : sendLeafWords emptySendLeaf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] :=
  rfl

/-- The empty `MemberLeaf`'s preimage is NOT all zeros: the domain tag leads it. So the empty
slot of the member tree cannot be confused with the empty slot of an untagged tree. -/
theorem empty_member_leaf_words :
    memberLeafWords emptyMemberLeaf = memberLeafDomain :: List.replicate 12 0 := rfl

theorem empty_member_leaf_preimage_is_not_all_zero :
    memberLeafWords emptyMemberLeaf ≠ List.replicate 13 0 := by decide

/-! ### `TxV2` and the untagged 10-word family (`tx_v2_tree.rs`) -/

/-- `TxV2::to_u64_vec` (`src/common/tx.rs:425-433`): `[tx_class] ++ transfer_tree_root ++
[nonce] ++ channel_action_root`. NO DOMAIN TAG, and exactly ten words — the same width as a
`SendLeaf` preimage. -/
def txV2Words (txClass : Nat) (transferTreeRoot : CommonValues.Hash4) (nonce : Nat)
    (channelActionRoot : CommonValues.Hash4) : List Nat :=
  txClass :: (CommonValues.hashWords transferTreeRoot ++ [nonce]
    ++ CommonValues.hashWords channelActionRoot)

theorem tx_v2_preimage_length (c : Nat) (r : CommonValues.Hash4) (n : Nat)
    (a : CommonValues.Hash4) : (txV2Words c r n a).length = CommonValues.txV2Len := by
  simp [txV2Words, CommonValues.hashWords, CommonValues.txV2Len,
    CommonValues.poseidonHashOutLen]

/-- `TxV2::empty_leaf() = TxV2::default()` (`tx.rs:464-466`); `TxClass` derives `Default` with
`UserTransfer = 0` (`tx.rs:174-181`) and both roots default to the zero `PoseidonHashOut`. -/
def emptyTxV2Words : List Nat :=
  txV2Words 0 CommonValues.zeroHash 0 CommonValues.zeroHash

/-- CROSS-TREE FINDING (unconditional, no hash assumption). Neither `SendLeaf` nor `TxV2`
carries a domain tag, and both preimages are ten words. Their EMPTY leaves have literally the
same preimage — ten zeros — so `<SendLeaf as Leafable>::empty_leaf().hash()` and
`<TxV2 as Leafable>::empty_leaf().hash()` are the same digest for ANY hash function. -/
theorem empty_send_leaf_and_empty_tx_v2_share_a_preimage :
    sendLeafWords emptySendLeaf = emptyTxV2Words := rfl

/-- The general form: the untagged 10-word encodings are not injective ACROSS the two leaf
types, so an equal-preimage pair exists without breaking any hash. -/
theorem untagged_ten_word_leaf_encodings_can_coincide :
    ∃ (s : SendLeaf) (c : Nat) (r : CommonValues.Hash4) (n : Nat) (a : CommonValues.Hash4),
      sendLeafWords s = txV2Words c r n a :=
  ⟨emptySendLeaf, 0, CommonValues.zeroHash, 0, CommonValues.zeroHash, rfl⟩

/-! ## 3. The `init()` constructors

`MerkleTree::new(height)` (`src/utils/trees/merkle_tree.rs:39-53`) derives its whole empty
state from `V::empty_leaf().hash()` and `two_to_one`; both `SparseMerkleTree::new` and
`IncrementalMerkleTree::new` are thin wrappers over it. That is exactly
`Zkp.Implementation.SparseTrees.mtNew`, so the instantiations below reuse the registered
model rather than restating it. -/

/-- The two opaque hash callbacks the trees are generic over: `PoseidonHashOut::hash_inputs_u64`
and `PoseidonLeafableHasher::two_to_one`. NOTHING is assumed about either. -/
structure Env where
  poseidon : List Nat → CommonValues.Hash4
  twoToOne : CommonValues.Hash4 → CommonValues.Hash4 → CommonValues.Hash4

/-- `<SendLeaf as Leafable>` (`channel_tree.rs:58-68`). -/
def sendSpec (e : Env) : SparseTrees.HashSpec SendLeaf CommonValues.Hash4 :=
  { emptyLeaf := emptySendLeaf
    leafHash := fun l => e.poseidon (sendLeafWords l)
    twoToOne := e.twoToOne }

/-- `<MemberLeaf as Leafable>` (`key_tree.rs:97-107`). -/
def memberSpec (e : Env) : SparseTrees.HashSpec MemberLeaf CommonValues.Hash4 :=
  { emptyLeaf := emptyMemberLeaf
    leafHash := fun l => e.poseidon (memberLeafWords l)
    twoToOne := e.twoToOne }

/-- `<TxV2 as Leafable>` (`tx.rs:461-471`), with the leaf modelled by its preimage words. -/
def txV2Spec (e : Env) : SparseTrees.HashSpec (List Nat) CommonValues.Hash4 :=
  { emptyLeaf := emptyTxV2Words
    leafHash := fun w => e.poseidon w
    twoToOne := e.twoToOne }

/-- `SendTree::init()` (`channel_tree.rs:38-42`): `IncrementalMerkleTree<SendLeaf>` at
`SEND_TREE_HEIGHT`. -/
def sendTreeInit (e : Env) : SparseTrees.IncTree SendLeaf CommonValues.Hash4 :=
  SparseTrees.incNew (sendSpec e) (heightOf .sendTree)

/-- `MemberTree::init()` (`key_tree.rs:180-182`): the REGISTERED cosigner tree. -/
def memberTreeInit (e : Env) : SparseTrees.IncTree MemberLeaf CommonValues.Hash4 :=
  SparseTrees.incNew (memberSpec e) (heightOf .memberTree)

/-- `MemberTree::init_wallet_membership()` (`key_tree.rs:187-189`): the wallet-side LIVE tree.
Same leaf type, different height. -/
def walletMemberTreeInit (e : Env) : SparseTrees.IncTree MemberLeaf CommonValues.Hash4 :=
  SparseTrees.incNew (memberSpec e) (heightOf .walletMemberTree)

/-- `TxV2Tree::init()` (`tx_v2_tree.rs:17-21`) — and, at the same height and with the same
leaf hasher shape, `ChannelActionTree::init()` (`tx_v2_tree.rs:23-27`). -/
def txV2TreeInit (e : Env) : SparseTrees.SparseTree (List Nat) CommonValues.Hash4 :=
  SparseTrees.sparseNew (txV2Spec e) (heightOf .txV2Tree)

/-- `ChannelLeaf::default()` (`channel_tree.rs:217-227`). NOT all zeros: the two root fields
are the EMPTY-TREE ROOTS of the send tree and of the registered member tree. -/
def defaultChannelLeaf (e : Env) : ChannelLeaf :=
  { index := 0
    prev := 0
    sendTreeRoot := SparseTrees.incRoot (sendSpec e) (sendTreeInit e)
    memberPubkeysRoot := SparseTrees.incRoot (memberSpec e) (memberTreeInit e) }

/-- `<ChannelLeaf as Leafable>` (`channel_tree.rs:115-125`). -/
def channelSpec (e : Env) : SparseTrees.HashSpec ChannelLeaf CommonValues.Hash4 :=
  { emptyLeaf := defaultChannelLeaf e
    leafHash := fun l => e.poseidon (channelLeafWords l)
    twoToOne := e.twoToOne }

/-- `ChannelTree::init()` (`channel_tree.rs:158-162`): `SparseMerkleTree<ChannelLeaf>` at
`CHANNEL_TREE_HEIGHT`, indexed by channel id. -/
def channelTreeInit (e : Env) : SparseTrees.SparseTree ChannelLeaf CommonValues.Hash4 :=
  SparseTrees.sparseNew (channelSpec e) (heightOf .channelTree)

/-! ### Heights and emptiness of the constructed trees -/

theorem send_tree_init_height (e : Env) : SparseTrees.incHeight (sendTreeInit e) = 32 := rfl

theorem member_tree_init_height (e : Env) : SparseTrees.incHeight (memberTreeInit e) = 3 := rfl

theorem wallet_member_tree_init_height (e : Env) :
    SparseTrees.incHeight (walletMemberTreeInit e) = 10 := rfl

theorem channel_tree_init_height (e : Env) :
    SparseTrees.sparseHeight (channelTreeInit e) = 32 := rfl

theorem tx_v2_tree_init_height (e : Env) :
    SparseTrees.sparseHeight (txV2TreeInit e) = 32 := rfl

theorem send_tree_init_is_empty (e : Env) : SparseTrees.incLen (sendTreeInit e) = 0 := rfl

theorem member_tree_init_is_empty (e : Env) : SparseTrees.incLen (memberTreeInit e) = 0 := rfl

theorem channel_tree_init_is_empty (e : Env) :
    SparseTrees.sparseLen (channelTreeInit e) = 0 := rfl

/-- The registered member tree holds at most `MAX_SIG_CLUSTER = 8` leaves: the ninth `push`
hits `IncrementalMerkleTree::push`'s `assert!`. This is the invariant `constants.rs:58-66`
const-asserts (`1 << MEMBER_TREE_HEIGHT == MAX_SIG_CLUSTER`). -/
theorem member_tree_push_fails_past_the_sig_cluster (e : Env)
    (t : SparseTrees.IncTree MemberLeaf CommonValues.Hash4) (l : MemberLeaf)
    (hh : SparseTrees.incHeight t = heightOf .memberTree)
    (hfull : SparseTrees.incLen t = UtilGadgets.maxSigCluster) :
    SparseTrees.incPush (memberSpec e) t l = .error .capacityExceeded := by
  have hlen : t.leaves.length = 8 := hfull
  have hht : 2 ^ SparseTrees.incHeight t = 8 := by rw [hh]; rfl
  simp only [SparseTrees.incPush, hlen, hht]
  simp

/-! ### The empty root is a function of the empty-leaf digest and the height only -/

theorem send_tree_init_root (e : Env) :
    SparseTrees.incRoot (sendSpec e) (sendTreeInit e)
      = SparseTrees.zeroAt (sendSpec e) (heightOf .sendTree) :=
  SparseTrees.mt_new_root (sendSpec e) (heightOf .sendTree)

theorem member_tree_init_root (e : Env) :
    SparseTrees.incRoot (memberSpec e) (memberTreeInit e)
      = SparseTrees.zeroAt (memberSpec e) (heightOf .memberTree) :=
  SparseTrees.mt_new_root (memberSpec e) (heightOf .memberTree)

theorem tx_v2_tree_init_root (e : Env) :
    SparseTrees.sparseRoot (txV2Spec e) (txV2TreeInit e)
      = SparseTrees.zeroAt (txV2Spec e) (heightOf .txV2Tree) :=
  SparseTrees.mt_new_root (txV2Spec e) (heightOf .txV2Tree)

/-- `zero_hashes` depends on nothing but the empty-leaf digest and `two_to_one`; two
instantiations agreeing on those agree at every level. -/
theorem zero_at_congr {V₁ V₂ : Type} (hs₁ : SparseTrees.HashSpec V₁ CommonValues.Hash4)
    (hs₂ : SparseTrees.HashSpec V₂ CommonValues.Hash4)
    (hbase : hs₁.leafHash hs₁.emptyLeaf = hs₂.leafHash hs₂.emptyLeaf)
    (hstep : hs₁.twoToOne = hs₂.twoToOne) :
    ∀ n, SparseTrees.zeroAt hs₁ n = SparseTrees.zeroAt hs₂ n := by
  intro n
  induction n with
  | zero => exact hbase
  | succ k ih =>
      show hs₁.twoToOne (SparseTrees.zeroAt hs₁ k) (SparseTrees.zeroAt hs₁ k)
        = hs₂.twoToOne (SparseTrees.zeroAt hs₂ k) (SparseTrees.zeroAt hs₂ k)
      rw [ih, hstep]

/-- CROSS-TREE FINDING, propagated to the roots. `SendTree` (incremental, height 32) and
`TxV2Tree` (sparse, height 32) have equal empty-leaf preimages, the same `two_to_one`, and the
same height, so `SendTree::init().get_root() = TxV2Tree::init().get_root()` UNCONDITIONALLY.
A statement "this is the empty send tree" is therefore simultaneously a statement "this is the
empty TxV2 tree"; separating them is the job of the circuits that consume the root, not of the
tree layer. -/
theorem empty_send_tree_root_equals_empty_tx_v2_tree_root (e : Env) :
    SparseTrees.incRoot (sendSpec e) (sendTreeInit e)
      = SparseTrees.sparseRoot (txV2Spec e) (txV2TreeInit e) := by
  rw [send_tree_init_root, tx_v2_tree_init_root]
  exact zero_at_congr (sendSpec e) (txV2Spec e)
    (congrArg e.poseidon empty_send_leaf_and_empty_tx_v2_share_a_preimage) rfl
    (heightOf .sendTree)

/-- The registered and the wallet member trees share the SAME empty-leaf digest but differ in
height, so their empty roots differ by exactly the seven extra `two_to_one` doublings. -/
theorem wallet_member_tree_init_root_extends_the_registered_one (e : Env) :
    SparseTrees.incRoot (memberSpec e) (walletMemberTreeInit e)
      = SparseTrees.zeroAt (memberSpec e) 10 :=
  SparseTrees.mt_new_root (memberSpec e) (heightOf .walletMemberTree)

/-! ### The default `ChannelLeaf` (`channel_tree.rs:217-227`) -/

theorem default_channel_leaf_index_and_prev_are_zero (e : Env) :
    (defaultChannelLeaf e).index = 0 ∧ (defaultChannelLeaf e).prev = 0 := ⟨rfl, rfl⟩

theorem default_channel_leaf_send_root_is_the_empty_send_tree_root (e : Env) :
    (defaultChannelLeaf e).sendTreeRoot
      = SparseTrees.zeroAt (sendSpec e) (heightOf .sendTree) :=
  send_tree_init_root e

/-- The unregistered channel's `member_pubkeys_root` is the empty REGISTERED member tree root
(height 3), NOT the empty wallet membership tree root (height 10). -/
theorem default_channel_leaf_member_root_is_the_registered_member_tree_root (e : Env) :
    (defaultChannelLeaf e).memberPubkeysRoot
      = SparseTrees.zeroAt (memberSpec e) (heightOf .memberTree) :=
  member_tree_init_root e

/-- The default channel leaf is NOT the all-zero record — it embeds two tree roots. Stated
against an explicit premise on the compared pair, because nothing here proves a Poseidon
output is nonzero. -/
theorem default_channel_leaf_is_not_the_all_zero_record (e : Env)
    (h : SparseTrees.zeroAt (sendSpec e) (heightOf .sendTree) ≠ CommonValues.zeroHash) :
    defaultChannelLeaf e ≠
      { index := 0, prev := 0, sendTreeRoot := CommonValues.zeroHash,
        memberPubkeysRoot := CommonValues.zeroHash } := by
  intro hEq
  exact h (by
    have := congrArg ChannelLeaf.sendTreeRoot hEq
    simpa [defaultChannelLeaf, send_tree_init_root e] using this)

/-- FUND-SAFETY SURFACE. An unregistered channel's `member_pubkeys_root` is the root of a tree
whose EVERY slot reads back as the all-zero `MemberLeaf` (`pk_g = pk_b = regev_pk_digest = 0`).
So all eight cosigner slots of an unregistered channel are openable to the zero identity; the
validity circuit's activeness gating, not this tree, is what must reject them. -/
theorem unregistered_channel_member_slots_all_read_as_the_zero_leaf (e : Env) (i : Nat) :
    SparseTrees.incGetLeaf (memberSpec e) (memberTreeInit e) i = emptyMemberLeaf :=
  SparseTrees.inc_get_leaf_out_of_range (memberSpec e) (memberTreeInit e) i (by
    show SparseTrees.incLen (memberTreeInit e) ≤ i
    rw [member_tree_init_is_empty]
    exact Nat.zero_le i)

/-! ## 4. The nullifier tree (`nullifier_tree.rs`)

`NullifierTree` is the ONLY newtype in `src/common/trees/` with real behaviour: it wraps
`IndexedMerkleTree` and always inserts with `value = 0`, using the nullifier's `Bytes32` as
the `U256` key. The ordered-set semantics come from the registered
`Zkp.Implementation.IndexedMerkleTree`. -/

/-- `NullifierTree::init()` (`nullifier_tree.rs:36-38`). -/
def nullifierTreeInit : IndexedMerkleTree.Tree :=
  IndexedMerkleTree.Tree.new (heightOf .nullifierTree)

theorem nullifier_tree_init_height : nullifierTreeInit.height = 32 := rfl

theorem nullifier_tree_init_capacity : nullifierTreeInit.capacity = capacityOf .nullifierTree :=
  rfl

theorem nullifier_tree_capacity_is_two_pow_32 : capacityOf .nullifierTree = 4294967296 := by
  decide

/-- `IndexedMerkleTree::new` pushes the all-zero SENTINEL leaf at index 0. -/
theorem nullifier_tree_init_holds_only_the_sentinel : nullifierTreeInit.size = 1 := rfl

theorem nullifier_tree_init_is_well_formed : IndexedMerkleTree.Wf nullifierTreeInit :=
  IndexedMerkleTree.wf_new _

/-- The `0` literal `prove_and_insert(nullifier.into(), 0)` passes as the leaf VALUE
(`nullifier_tree.rs:59`): the nullifier set stores no payload. -/
def nullifierInsertValue : Nat := 0

theorem nullifier_insert_value_pinned : nullifierInsertValue = 0 := rfl

/-- `NullifierTree::prove_and_insert` (`nullifier_tree.rs:53-62`), with the Merkle-proof
production abstracted away (the `Commitment` layer of `IndexedMerkleTree`) and only the
key-set effect retained. Any `IndexedMerkleTree` error is remapped to
`CommonError::NullifierAlreadyExists` by the source. -/
def insertNullifier (t : IndexedMerkleTree.Tree) (nullifier : Nat) :
    Except IndexedMerkleTree.Error IndexedMerkleTree.Tree :=
  IndexedMerkleTree.insert t nullifier nullifierInsertValue

/-- `NullifierTree::nullifiers` (`nullifier_tree.rs:44-51`): the leaf keys with the default
leaf at index 0 skipped. -/
def nullifiersOf (t : IndexedMerkleTree.Tree) : List Nat :=
  (t.leaves.drop 1).map (fun l => l.key)

theorem nullifier_tree_init_has_no_nullifiers : nullifiersOf nullifierTreeInit = [] := rfl

/-- DOUBLE-SPEND PREVENTION, as far as the native tree provides it: re-inserting a nullifier
already in the set fails. (The circuit-side insertion proof is `IndexedMerkleTree`'s
`Gates`/`Binding` layer, not this file.) -/
theorem nullifier_reinsertion_fails {t : IndexedMerkleTree.Tree} {n : Nat}
    (hw : IndexedMerkleTree.Wf t) (h : IndexedMerkleTree.MemKey t n) :
    insertNullifier t n = .error (.keyAlreadyExists n) :=
  IndexedMerkleTree.insert_present_key_fails hw h

theorem nullifier_insert_ok_implies_the_nullifier_was_absent {t t' : IndexedMerkleTree.Tree}
    {n : Nat} (hw : IndexedMerkleTree.Wf t) (h : insertNullifier t n = .ok t') :
    ¬ IndexedMerkleTree.MemKey t n :=
  IndexedMerkleTree.insert_ok_implies_absent hw h

/-- FUND-SAFETY FINDING (inherited from the indexed-tree encoding, surfaced here for the
nullifier instantiation). `next_key = 0` is the "no successor" marker and slot 0 holds the
zero sentinel, so the ALL-ZERO nullifier can never be inserted into any well-formed nullifier
tree: `Bytes32::default()` is an unusable nullifier value, permanently rejected rather than
consumed. -/
theorem the_all_zero_nullifier_can_never_be_inserted {t : IndexedMerkleTree.Tree}
    (hw : IndexedMerkleTree.Wf t) : insertNullifier t 0 = .error (.keyAlreadyExists 0) :=
  IndexedMerkleTree.zero_key_can_never_be_inserted hw

/-- Every accepted insertion keeps the ordered-set invariant, so the two theorems above apply
at every step of a chain of nullifier insertions. The `key < 2^256` premise is the `U256`
range of `Bytes32`; the capacity premise is `IncrementalMerkleTree::push`'s `assert!`. -/
theorem nullifier_tree_stays_well_formed {t t' : IndexedMerkleTree.Tree} {n : Nat}
    (hw : IndexedMerkleTree.Wf t) (hkey : n < IndexedMerkleTree.keyBound)
    (hcap : t.size < t.capacity) (h : insertNullifier t n = .ok t') :
    IndexedMerkleTree.Wf t' :=
  IndexedMerkleTree.wf_insert hw hkey hcap h

/-- The tree after a first nullifier `7` has been consumed. -/
def nullifierExampleTree : IndexedMerkleTree.Tree :=
  IndexedMerkleTree.insertResult nullifierTreeInit 0 7 nullifierInsertValue

/-- Non-vacuous positive trace: a fresh nullifier tree accepts a first nullifier. -/
theorem nullifier_first_insert_example :
    insertNullifier nullifierTreeInit 7 = .ok nullifierExampleTree := rfl

theorem nullifier_example_tree_is_well_formed : IndexedMerkleTree.Wf nullifierExampleTree :=
  IndexedMerkleTree.wf_insert (IndexedMerkleTree.wf_new _) (by decide) (by decide)
    nullifier_first_insert_example

theorem nullifier_example_tree_records_the_nullifier :
    nullifiersOf nullifierExampleTree = [7] := rfl

/-- ... and then rejects the very same one: the double-spend attempt. -/
theorem nullifier_reinsert_example :
    insertNullifier nullifierExampleTree 7 = .error (.keyAlreadyExists 7) :=
  nullifier_reinsertion_fails nullifier_example_tree_is_well_formed ⟨1, by decide, by decide⟩

/-! ## 5. The three private-state trees

`asset_tree.rs`, `nullifier_tree.rs` and `sent_tx_tree.rs` are exactly the three trees whose
roots a `PrivateState` commits (`Zkp.Implementation.PrivateState.State`). They are all at
height 32 but on THREE DIFFERENT backing structures, so a path in one is structurally a path
in another. -/

/-- `PoseidonHashOut` in the `PrivateState` model is the same four-word record under another
field naming. -/
def toPrivateHash (h : CommonValues.Hash4) : PrivateState.Hash4 := ⟨h.w0, h.w1, h.w2, h.w3⟩

theorem to_private_hash_preserves_words (h : CommonValues.Hash4) :
    PrivateState.hashWords (toPrivateHash h) = CommonValues.hashWords h := rfl

theorem to_private_hash_zero : toPrivateHash CommonValues.zeroHash = PrivateState.zeroHash := rfl

/-- The three private-state trees, instantiated at their pinned heights. The asset leaf
(`U256`) and the sent-tx leaf (`Tx`) are defined outside `src/common/trees/`, so they stay
type parameters with an opaque `HashSpec`. -/
def privateStateTreeEnv {A T : Type} (assetSpec : SparseTrees.HashSpec A CommonValues.Hash4)
    (sentSpec : SparseTrees.HashSpec T CommonValues.Hash4)
    (nullifierRoot : IndexedMerkleTree.Tree → CommonValues.Hash4) :
    PrivateState.TreeEnvironment (SparseTrees.SparseTree A CommonValues.Hash4)
      IndexedMerkleTree.Tree (SparseTrees.IncTree T CommonValues.Hash4) :=
  { emptyAsset := SparseTrees.sparseNew assetSpec (heightOf .assetTree)
    emptyNullifiers := nullifierTreeInit
    emptySent := SparseTrees.incNew sentSpec (heightOf .sentTxTree)
    assetRoot := fun t => toPrivateHash (SparseTrees.sparseRoot assetSpec t)
    nullifierRoot := fun t => toPrivateHash (nullifierRoot t)
    sentRoot := fun t => toPrivateHash (SparseTrees.incRoot sentSpec t) }

theorem private_state_trees_share_height_32 :
    heightOf .assetTree = 32 ∧ heightOf .nullifierTree = 32 ∧ heightOf .sentTxTree = 32 :=
  ⟨rfl, rfl, rfl⟩

/-- Same height, three different backing structures: sparse (random-access by token index),
indexed (ordered nullifier set), incremental (append-only sent-tx frontier). -/
theorem private_state_trees_use_three_different_backings :
    backingOf .assetTree = .sparse ∧ backingOf .nullifierTree = .indexed ∧
      backingOf .sentTxTree = .incremental := ⟨rfl, rfl, rfl⟩

/-- Non-vacuous positive example: the genesis private state built from these instantiations
has nonce 0, zero previous commitment, and keeps the salt it was given. -/
theorem genesis_private_state_from_these_trees {A T : Type}
    (assetSpec : SparseTrees.HashSpec A CommonValues.Hash4)
    (sentSpec : SparseTrees.HashSpec T CommonValues.Hash4)
    (nullifierRoot : IndexedMerkleTree.Tree → CommonValues.Hash4) (salt : PrivateState.Hash4) :
    (PrivateState.newState (privateStateTreeEnv assetSpec sentSpec nullifierRoot) salt).nonce = 0
      ∧ (PrivateState.newState (privateStateTreeEnv assetSpec sentSpec nullifierRoot)
          salt).prevCommitment = PrivateState.zeroHash
      ∧ (PrivateState.newState (privateStateTreeEnv assetSpec sentSpec nullifierRoot)
          salt).salt = salt :=
  ⟨PrivateState.genesis_nonce_zero _ salt, PrivateState.genesis_previous_commitment_zero _ salt,
    PrivateState.genesis_preserves_salt _ salt⟩

/-- The genesis nullifier root is the root of the tree that already contains the zero
sentinel, not of a truly empty tree. -/
theorem genesis_nullifier_tree_is_the_sentinel_tree {A T : Type}
    (assetSpec : SparseTrees.HashSpec A CommonValues.Hash4)
    (sentSpec : SparseTrees.HashSpec T CommonValues.Hash4)
    (nullifierRoot : IndexedMerkleTree.Tree → CommonValues.Hash4) :
    (privateStateTreeEnv assetSpec sentSpec nullifierRoot).emptyNullifiers = nullifierTreeInit :=
  rfl

/-! ## 6. The generic hash-chain circuit family (`src/utils/hash_chain/`)

Three circuits stacked by `HashChainProcessor`:

* `HashInnerCircuit` — verifies ONE "single" proof and emits `(prev_hash, keccak(prev_hash ++
  single.public_inputs))` as its own public inputs.
* `CyclicChainCircuit` — verifies an inner proof, republishes only the NEW hash, and either
  (first step) asserts `prev_hash = 0` or (later step) recursively verifies the previous cyclic
  proof and connects its published hash to `prev_hash`.
* `ChainEndCircuit` — verifies a cyclic proof and publishes
  `keccak(last_hash ++ proof_submitter)` as a single digest.

The proof system itself is OUT OF SCOPE: recursion is modelled by the ACCEPT RELATION on
public inputs, never by a proof object. -/

/-- `solidity_keccak256` reduced to a `Bytes32`. Opaque: no collision resistance, no preimage
resistance, no injectivity is assumed anywhere below. -/
structure ChainEnv where
  keccak : List Nat → CommonValues.Limbs8

/-- `hash_with_prev_hash` (`hash_chain/mod.rs:23-26`) and, with the same argument order,
`hash_with_prev_hash_circuit` (`mod.rs:28-42`): the previous hash's limbs lead, the content
follows. -/
def hashWithPrevHash (e : ChainEnv) (content : List Nat) (prevHash : CommonValues.Limbs8) :
    CommonValues.Limbs8 := e.keccak (CommonValues.limbWords prevHash ++ content)

/-- The keccak PREIMAGE the step hashes. Native and in-circuit build the same list
(`mod.rs:24` vs `mod.rs:40`); that the builder emits those wires is a lowering boundary. -/
def stepPreimage (content : List Nat) (prevHash : CommonValues.Limbs8) : List Nat :=
  CommonValues.limbWords prevHash ++ content

theorem step_preimage_puts_prev_hash_first (content : List Nat)
    (prevHash : CommonValues.Limbs8) :
    (stepPreimage content prevHash).take 8 = CommonValues.limbWords prevHash := by
  simp [stepPreimage, CommonValues.limbWords]

theorem step_preimage_length (content : List Nat) (prevHash : CommonValues.Limbs8) :
    (stepPreimage content prevHash).length = CommonValues.bytes32Len + content.length := by
  simp [stepPreimage, CommonValues.limbWords, CommonValues.bytes32Len]
  omega

theorem native_and_circuit_step_preimages_agree (e : ChainEnv) (content : List Nat)
    (prevHash : CommonValues.Limbs8) :
    hashWithPrevHash e content prevHash = e.keccak (stepPreimage content prevHash) := rfl

/-! ### The chain fold -/

/-- The running hash after folding `contents` starting from `start`. -/
def chainFoldFrom (e : ChainEnv) (start : CommonValues.Limbs8) (contents : List (List Nat)) :
    CommonValues.Limbs8 :=
  contents.foldl (fun h c => hashWithPrevHash e c h) start

/-- The chain hash of a whole run: the initial condition of `CyclicChainCircuit::new`
(`cyclic_chain_circuit.rs:71-73`) is `prev_hash = 0`, matching
`HashChainProcessor::prove_chain`'s `Bytes32::default()` (`hash_chain_processor.rs:65`). -/
def chainHash (e : ChainEnv) (contents : List (List Nat)) : CommonValues.Limbs8 :=
  chainFoldFrom e CommonValues.zeroLimbs8 contents

theorem chain_fold_nil (e : ChainEnv) (s : CommonValues.Limbs8) :
    chainFoldFrom e s [] = s := rfl

theorem chain_fold_cons (e : ChainEnv) (s : CommonValues.Limbs8) (c : List Nat)
    (cs : List (List Nat)) :
    chainFoldFrom e s (c :: cs) = chainFoldFrom e (hashWithPrevHash e c s) cs := rfl

theorem chain_fold_append (e : ChainEnv) (s : CommonValues.Limbs8)
    (a b : List (List Nat)) :
    chainFoldFrom e s (a ++ b) = chainFoldFrom e (chainFoldFrom e s a) b := by
  simp [chainFoldFrom, List.foldl_append]

theorem chain_hash_nil (e : ChainEnv) : chainHash e [] = CommonValues.zeroLimbs8 := rfl

theorem chain_hash_singleton (e : ChainEnv) (c : List Nat) :
    chainHash e [c] = hashWithPrevHash e c CommonValues.zeroLimbs8 := rfl

/-- The step law of the whole family: appending one more step keccaks the running hash with
the new content. -/
theorem chain_hash_snoc (e : ChainEnv) (cs : List (List Nat)) (c : List Nat) :
    chainHash e (cs ++ [c]) = hashWithPrevHash e c (chainHash e cs) := by
  simp [chainHash, chain_fold_append, chainFoldFrom]

/-! ### `HashInnerCircuit` (`hash_inner_circuit.rs`) -/

/-- `builder.register_public_inputs(&[prev_hash.to_vec(), hash.to_vec()].concat())`
(`hash_inner_circuit.rs:46-47`). -/
def innerPublicInputs (prevHash hash : CommonValues.Limbs8) : List Nat :=
  CommonValues.limbWords prevHash ++ CommonValues.limbWords hash

theorem inner_public_inputs_length (prevHash hash : CommonValues.Limbs8) :
    (innerPublicInputs prevHash hash).length = 16 := by
  simp [innerPublicInputs, CommonValues.limbWords]

theorem inner_public_inputs_prev_hash_comes_first (prevHash hash : CommonValues.Limbs8) :
    (innerPublicInputs prevHash hash).take CommonValues.bytes32Len
      = CommonValues.limbWords prevHash := by
  simp [innerPublicInputs, CommonValues.limbWords, CommonValues.bytes32Len]

theorem inner_public_inputs_hash_comes_second (prevHash hash : CommonValues.Limbs8) :
    (innerPublicInputs prevHash hash).drop CommonValues.bytes32Len
      = CommonValues.limbWords hash := by
  simp [innerPublicInputs, CommonValues.limbWords, CommonValues.bytes32Len]

/-- One inner-step witness. `content` stands for the verified single proof's public inputs
(`hash_inner_circuit.rs:43`); that a plonky2 proof for them exists is the
`recursive-verification` boundary, not a fact of this model. -/
structure InnerWitness where
  prevHash : CommonValues.Limbs8
  content : List Nat
  hash : CommonValues.Limbs8

/-- The ARBITRARY-WITNESS side: the single local gate equation the inner circuit imposes. -/
def InnerGates (e : ChainEnv) (w : InnerWitness) : Prop :=
  w.hash = hashWithPrevHash e w.content w.prevHash

/-- The NATIVE side: `HashInnerCircuit::prove` (`hash_inner_circuit.rs:56-69`) sets `prev_hash`
from the caller and lets the circuit compute the new hash. -/
def innerProve (e : ChainEnv) (prevHash : CommonValues.Limbs8) (content : List Nat) :
    InnerWitness := ⟨prevHash, content, hashWithPrevHash e content prevHash⟩

theorem native_inner_prove_satisfies_the_gates (e : ChainEnv) (prevHash : CommonValues.Limbs8)
    (content : List Nat) : InnerGates e (innerProve e prevHash content) := rfl

/-- `Bytes32Target::new(&mut builder, false)` (`hash_inner_circuit.rs:44`): `is_checked = false`,
so the inner circuit does NOT range-check the `prev_hash` limbs; the comment says "connect
later". Taken alone the inner statement therefore accepts any `prev_hash` whatsoever, including
non-canonical (non-`u32`) limbs. -/
def innerPrevHashIsRangeChecked : Bool := false

theorem inner_prev_hash_is_not_range_checked : innerPrevHashIsRangeChecked = false := rfl

theorem inner_gates_accept_any_prev_hash (e : ChainEnv) (prevHash : CommonValues.Limbs8)
    (content : List Nat) :
    ∃ w, InnerGates e w ∧ w.prevHash = prevHash ∧ w.content = content :=
  ⟨innerProve e prevHash content, rfl, rfl, rfl⟩

/-- The recovery: the cyclic wrapper is what pins `prev_hash`, either to zero (first step) or
to a verified previous proof's published hash. -/
theorem inner_prev_hash_is_pinned_only_by_the_cyclic_wrapper (e : ChainEnv)
    (limb : Nat) (content : List Nat) :
    ∃ w, InnerGates e w ∧ w.prevHash.l0 = limb :=
  ⟨innerProve e ⟨limb, 0, 0, 0, 0, 0, 0, 0⟩ content, rfl, rfl⟩

/-! ### `CyclicChainCircuit` (`cyclic_chain_circuit.rs`)

`builder.register_public_inputs(&hash.to_vec())` (line 56) publishes ONLY the new hash;
`add_verifier_data_public_inputs()` (line 59) appends the verifier data, and
`common.num_public_inputs = BYTES32_LEN + vd_vec_len(...)` (line 147) pins the layout. So the
running hash is public input `0..8` — which is exactly the slice `ChainEndCircuit` and
`HashChainProcessor::prove_chain` read back. -/

/-- The published-hash slice offset, `BYTES32_LEN`. -/
def cyclicHashPublicInputLen : Nat := CommonValues.bytes32Len

theorem cyclic_hash_public_input_len_pinned : cyclicHashPublicInputLen = 8 := by decide

/-- The number of cyclic public inputs is `BYTES32_LEN + vd_vec_len(config)`
(`cyclic_chain_circuit.rs:147`), with `vd_vec_len = 4 + 4 * num_cap_elements`
(`src/utils/cyclic.rs:26-28`). The cap size is a plonky2 config value, kept as a parameter. -/
def cyclicPublicInputCount (numCapElements : Nat) : Nat :=
  CommonValues.bytes32Len + (4 + 4 * numCapElements)

theorem cyclic_public_inputs_start_with_the_running_hash (numCapElements : Nat) :
    cyclicHashPublicInputLen ≤ cyclicPublicInputCount numCapElements := by
  simp only [cyclicHashPublicInputLen, cyclicPublicInputCount, CommonValues.bytes32Len]
  omega

/-- The cyclic wrapper's accept relation on `(published hash, the contents folded so far)`.
The circuit has exactly two branches, and both are reproduced by the two closure lemmas below;
`is_first_step` selects between them (`cyclic_chain_circuit.rs:51-73`). -/
def CyclicAccepts (e : ChainEnv) (h : CommonValues.Limbs8) (contents : List (List Nat)) :
    Prop := contents ≠ [] ∧ h = chainHash e contents

/-- The `is_first_step = true` branch: the previous proof is a dummy and the initial condition
`prev_hash = 0` is asserted (`cyclic_chain_circuit.rs:72-73`). -/
theorem cyclic_accepts_first_step (e : ChainEnv) (c : List Nat) :
    CyclicAccepts e (hashWithPrevHash e c CommonValues.zeroLimbs8) [c] :=
  ⟨by simp, rfl⟩

/-- The `is_first_step = false` branch: the previous cyclic proof is verified and its
published hash is connected to the inner proof's `prev_hash`
(`cyclic_chain_circuit.rs:61-70`). -/
theorem cyclic_accepts_later_step (e : ChainEnv) {h : CommonValues.Limbs8}
    {contents : List (List Nat)} (c : List Nat) (hacc : CyclicAccepts e h contents) :
    CyclicAccepts e (hashWithPrevHash e c h) (contents ++ [c]) := by
  refine ⟨by simp, ?_⟩
  rw [chain_hash_snoc, hacc.2]

/-- A cyclic proof always verifies exactly ONE inner proof, so an accepted chain has at least
one step: the empty chain is not a statement this circuit can make. -/
theorem cyclic_chain_is_never_empty (e : ChainEnv) (h : CommonValues.Limbs8) :
    ¬ CyclicAccepts e h [] := by
  rintro ⟨hne, -⟩
  exact hne rfl

theorem cyclic_accepts_determines_the_hash (e : ChainEnv) {h : CommonValues.Limbs8}
    {contents : List (List Nat)} (hacc : CyclicAccepts e h contents) :
    h = chainHash e contents := hacc.2

/-- A single-step chain is exactly the initial condition: the published hash is
`keccak(0 ++ content)`. -/
theorem first_step_hash_is_keccak_of_zero_prev_hash (e : ChainEnv) {h : CommonValues.Limbs8}
    {c : List Nat} (hacc : CyclicAccepts e h [c]) :
    h = e.keccak (CommonValues.limbWords CommonValues.zeroLimbs8 ++ c) := hacc.2

/-- TRUNCATION. `is_first_step` is a prover-chosen boolean witness, and nothing outside the
circuit forces it to be true only at the genuine start. Any nonempty SUFFIX of a run is
therefore itself an accepted chain, with a chain hash that mentions nothing of the prefix. The
chain statement means "these contents, in this order, from a zero start" — not "these are all
the contents that ever existed". -/
theorem any_nonempty_suffix_is_itself_an_accepted_chain (e : ChainEnv)
    (prefixContents suffixContents : List (List Nat)) (hne : suffixContents ≠ []) :
    CyclicAccepts e (chainHash e suffixContents) suffixContents ∧
      CyclicAccepts e (chainHash e (prefixContents ++ suffixContents))
        (prefixContents ++ suffixContents) := by
  refine ⟨⟨hne, rfl⟩, ⟨?_, rfl⟩⟩
  intro h
  exact hne (List.append_eq_nil.mp h).2

/-- The chain LENGTH is not a public input and is not bounded by any gate, so the statement
does not pin it. Demonstrated with a degenerate (constant) keccak, exactly as
`SparseTrees.constant_hash_forges_membership` does for Merkle membership: without collision
resistance the same hash is reached by chains of different lengths. -/
def constantChainEnv : ChainEnv := { keccak := fun _ => ⟨1, 1, 1, 1, 1, 1, 1, 1⟩ }

theorem chain_hash_does_not_commit_the_chain_length :
    ∃ (cs ds : List (List Nat)), cs.length ≠ ds.length ∧
      chainHash constantChainEnv cs = chainHash constantChainEnv ds := by
  refine ⟨[[0]], [[0], [1]], by decide, rfl⟩

theorem chain_hash_does_not_commit_the_contents :
    ∃ (cs ds : List (List Nat)), cs ≠ ds ∧
      chainHash constantChainEnv cs = chainHash constantChainEnv ds := by
  refine ⟨[[0]], [[1]], by decide, rfl⟩

/-! ### `ChainEndCircuit` (`chain_end_circuit.rs`) -/

/-- `CHAIN_END_PROOF_PUBLIC_INPUTS_LEN = BYTES32_LEN + ADDRESS_LEN` (`chain_end_circuit.rs:29`). -/
def chainEndPublicInputsLen : Nat := CommonValues.bytes32Len + CommonValues.addressLen

theorem chain_end_public_inputs_len_pinned : chainEndPublicInputsLen = 13 := by decide

/-- `ChainEndProofPublicInputs { last_hash: Bytes32, proof_submitter: Address }`
(`chain_end_circuit.rs:31-36`). -/
structure ChainEndPublicInputs where
  lastHash : CommonValues.Limbs8
  proofSubmitter : CommonValues.Limbs5
  deriving DecidableEq, Repr

/-- `ChainEndProofPublicInputs::to_u32_vec` (`chain_end_circuit.rs:39-47`), and the identical
target-side `ChainEndProofPublicInputsTarget::to_vec` (lines 99-101). -/
def chainEndToU32Vec (p : ChainEndPublicInputs) : List Nat :=
  CommonValues.limbWords p.lastHash ++ CommonValues.addrWords p.proofSubmitter

theorem chain_end_to_u32_vec_length (p : ChainEndPublicInputs) :
    (chainEndToU32Vec p).length = chainEndPublicInputsLen := by
  simp [chainEndToU32Vec, CommonValues.limbWords, CommonValues.addrWords,
    chainEndPublicInputsLen, CommonValues.bytes32Len, CommonValues.addressLen]

/-- `HashChainError` (`hash_chain/error.rs:1-20`). -/
inductive HashChainError where
  | invalidData
  | innerProofError
  | cyclicProofError
  | chainEndProofError
  | invalidState
  | plonky2Error
  deriving DecidableEq, Repr

def hashChainErrorTag : HashChainError → Nat
  | .invalidData => 0
  | .innerProofError => 1
  | .cyclicProofError => 2
  | .chainEndProofError => 3
  | .invalidState => 4
  | .plonky2Error => 5

def hashChainErrorSamples : List HashChainError :=
  [.invalidData, .innerProofError, .cyclicProofError, .chainEndProofError, .invalidState,
   .plonky2Error]

theorem hash_chain_error_has_six_variants : hashChainErrorSamples.length = 6 := by decide

theorem hash_chain_error_tags_are_distinct :
    ∀ a ∈ hashChainErrorSamples, ∀ b ∈ hashChainErrorSamples,
      hashChainErrorTag a = hashChainErrorTag b → a = b := by decide

/-- `ChainEndProofPublicInputs::from_u32_slice` (`chain_end_circuit.rs:49-63`): a length check
that returns `InvalidData`, then a fixed 8/5 split. -/
def chainEndFromU32Slice : List Nat → Except HashChainError ChainEndPublicInputs
  | [h0, h1, h2, h3, h4, h5, h6, h7, a0, a1, a2, a3, a4] =>
      .ok ⟨⟨h0, h1, h2, h3, h4, h5, h6, h7⟩, ⟨a0, a1, a2, a3, a4⟩⟩
  | _ => .error .invalidData

theorem chain_end_codec_roundtrips (p : ChainEndPublicInputs) :
    chainEndFromU32Slice (chainEndToU32Vec p) = .ok p := rfl

theorem chain_end_parse_ok_pins_the_layout {s : List Nat} {p : ChainEndPublicInputs}
    (h : chainEndFromU32Slice s = .ok p) : s = chainEndToU32Vec p := by
  unfold chainEndFromU32Slice at h
  split at h
  · injection h with h; subst h; rfl
  · exact absurd h (by simp)

theorem chain_end_parse_ok_forces_length_13 {s : List Nat} {p : ChainEndPublicInputs}
    (h : chainEndFromU32Slice s = .ok p) : s.length = 13 := by
  rw [chain_end_parse_ok_pins_the_layout h]
  have := chain_end_to_u32_vec_length p
  rw [chain_end_public_inputs_len_pinned] at this
  exact this

/-- The only error `from_u32_slice` can produce. -/
theorem chain_end_parse_error_is_always_invalid_data {s : List Nat} {err : HashChainError}
    (h : chainEndFromU32Slice s = .error err) : err = .invalidData := by
  unfold chainEndFromU32Slice at h
  split at h
  · exact absurd h (by simp)
  · injection h with h; exact h.symm

/-- `from_u64_slice` (`chain_end_circuit.rs:65-81`) does NOT return an error for an oversized
word: after the length check it PANICS (`assert!(x <= u32::MAX as u64)`). Modelled as an
explicit outcome so the panic is not silently turned into an error value. -/
inductive U64ParseOutcome where
  | panicked
  | value (r : Except HashChainError ChainEndPublicInputs)
  deriving Repr, DecidableEq

def chainEndFromU64Slice (s : List Nat) : U64ParseOutcome :=
  if s.length ≠ chainEndPublicInputsLen then .value (.error .invalidData)
  else if s.any (fun x => decide (CommonValues.u32Max < x)) then .panicked
  else .value (chainEndFromU32Slice s)

theorem chain_end_from_u64_slice_matches_u32_on_canonical_input (p : ChainEndPublicInputs)
    (hcanon : (chainEndToU32Vec p).all (fun x => decide (x ≤ CommonValues.u32Max)) = true) :
    chainEndFromU64Slice (chainEndToU32Vec p) = .value (.ok p) := by
  have hlen : (chainEndToU32Vec p).length = chainEndPublicInputsLen :=
    chain_end_to_u32_vec_length p
  have hno : (chainEndToU32Vec p).any (fun x => decide (CommonValues.u32Max < x)) = false := by
    simp only [List.all_eq_true, decide_eq_true_eq] at hcanon
    cases hb : (chainEndToU32Vec p).any (fun x => decide (CommonValues.u32Max < x)) with
    | false => rfl
    | true =>
        obtain ⟨x, hx, hlt⟩ := List.any_eq_true.mp hb
        simp only [decide_eq_true_eq] at hlt
        exact absurd hlt (Nat.not_lt.mpr (hcanon x hx))
  simp [chainEndFromU64Slice, hlen, hno, chain_end_codec_roundtrips]

/-- PANIC-VS-ERROR ASYMMETRY: a correctly sized slice carrying a word above `u32::MAX` aborts
the process instead of returning `InvalidData`. -/
theorem chain_end_from_u64_slice_panics_on_an_oversized_word :
    chainEndFromU64Slice [4294967296, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = .panicked := rfl

/-- Precedence: the LENGTH check runs first, so a wrong-length slice errors cleanly even when
it also contains an oversized word. -/
theorem chain_end_length_error_precedes_the_panic :
    chainEndFromU64Slice [4294967296] = .value (.error .invalidData) := rfl

/-- `ChainEndProofPublicInputs::hash` (`chain_end_circuit.rs:87-89`) and the in-circuit
`pis.hash` registered as the ONLY public input (`chain_end_circuit.rs:140-141`). -/
def chainEndStatement (e : ChainEnv) (p : ChainEndPublicInputs) : CommonValues.Limbs8 :=
  e.keccak (chainEndToU32Vec p)

/-- The gates of `ChainEndCircuit::new`: the cyclic proof is verified against the cyclic
verifier data, and `last_hash` is READ OFF its public inputs `0..BYTES32_LEN`
(`chain_end_circuit.rs:133-134`). `proof_submitter` is a FRESH range-checked witness
(line 135), connected to nothing else. -/
structure ChainEndGates (e : ChainEnv) (p : ChainEndPublicInputs)
    (contents : List (List Nat)) : Prop where
  chainAccepted : CyclicAccepts e p.lastHash contents

theorem chain_end_binds_the_last_hash_to_the_chain_fold {e : ChainEnv}
    {p : ChainEndPublicInputs} {contents : List (List Nat)}
    (g : ChainEndGates e p contents) : p.lastHash = chainHash e contents := g.chainAccepted.2

theorem chain_end_requires_at_least_one_step {e : ChainEnv} {p : ChainEndPublicInputs}
    {contents : List (List Nat)} (g : ChainEndGates e p contents) : contents ≠ [] :=
  g.chainAccepted.1

/-- REWARD ATTRIBUTION IS PROVER-CHOSEN. `proof_submitter` is an unconstrained witness, so for
one and the same chain the circuit is satisfied by EVERY address. Whoever is entitled to the
aggregation reward must therefore be decided by whatever consumes this proof (the settlement
contract), never by the chain-end statement itself. -/
theorem chain_end_accepts_any_proof_submitter (e : ChainEnv) (contents : List (List Nat))
    (hne : contents ≠ []) (a : CommonValues.Limbs5) :
    ChainEndGates e ⟨chainHash e contents, a⟩ contents := ⟨⟨hne, rfl⟩⟩

/-- ... and the published digest does depend on the chosen address, so two submitters produce
two different statements over the SAME chain (they are different only if keccak separates
them, which is not assumed: the premise names the compared pair). -/
theorem chain_end_statement_covers_the_submitter (e : ChainEnv)
    (h : CommonValues.Limbs8) (a b : CommonValues.Limbs5)
    (hsep : e.keccak (CommonValues.limbWords h ++ CommonValues.addrWords a)
      ≠ e.keccak (CommonValues.limbWords h ++ CommonValues.addrWords b)) :
    chainEndStatement e ⟨h, a⟩ ≠ chainEndStatement e ⟨h, b⟩ := hsep

/-! ### `HashChainProcessor` (`hash_chain_processor.rs`) -/

/-- `HashChainProcessor::prove_chain` (`hash_chain_processor.rs:54-76`): the previous hash is
read from the previous cyclic proof's public inputs `0..BYTES32_LEN`, or is
`Bytes32::default()` (zero) when there is no previous proof. -/
def proveChainStep (e : ChainEnv) (prev : Option CommonValues.Limbs8) (content : List Nat) :
    CommonValues.Limbs8 :=
  hashWithPrevHash e content (prev.getD CommonValues.zeroLimbs8)

theorem prove_chain_none_uses_a_zero_prev_hash (e : ChainEnv) (content : List Nat) :
    proveChainStep e none content = hashWithPrevHash e content CommonValues.zeroLimbs8 := rfl

theorem prove_chain_some_uses_the_previous_published_hash (e : ChainEnv)
    (h : CommonValues.Limbs8) (content : List Nat) :
    proveChainStep e (some h) content = hashWithPrevHash e content h := rfl

/-- Driving the processor over a whole run of single proofs. -/
def proveChainAll (e : ChainEnv) (contents : List (List Nat)) : Option CommonValues.Limbs8 :=
  contents.foldl (fun acc c => some (proveChainStep e acc c)) none

theorem prove_chain_all_from_some (e : ChainEnv) :
    ∀ (contents : List (List Nat)) (h : CommonValues.Limbs8),
      contents.foldl (fun acc c => some (proveChainStep e acc c)) (some h)
        = some (chainFoldFrom e h contents) := by
  intro contents
  induction contents with
  | nil => intro h; rfl
  | cons c cs ih => intro h; simpa using ih (hashWithPrevHash e c h)

/-- The native prover reproduces the fold that the cyclic circuit's accept relation states. -/
theorem prove_chain_all_matches_the_chain_hash (e : ChainEnv) (contents : List (List Nat))
    (hne : contents ≠ []) : proveChainAll e contents = some (chainHash e contents) := by
  match contents, hne with
  | c :: cs, _ =>
      show (cs.foldl (fun acc x => some (proveChainStep e acc x))
        (some (hashWithPrevHash e c CommonValues.zeroLimbs8))) = _
      rw [prove_chain_all_from_some e cs]
      rfl

theorem prove_chain_all_of_the_empty_run_is_none (e : ChainEnv) :
    proveChainAll e [] = none := rfl

/-- Every prefix of a native run is itself an accepted cyclic statement, so the processor's
intermediate proofs are exactly the chain statements of the prefixes. -/
theorem native_run_is_accepted_at_every_step (e : ChainEnv) (contents : List (List Nat))
    (hne : contents ≠ []) :
    ∃ h, proveChainAll e contents = some h ∧ CyclicAccepts e h contents :=
  ⟨chainHash e contents, prove_chain_all_matches_the_chain_hash e contents hne, hne, rfl⟩

/-- `HashChainProcessor::prove_end` (`hash_chain_processor.rs:78-88`) just wraps the cyclic
proof; the resulting statement is the keccak of the last hash and the chosen submitter. -/
def proveEnd (e : ChainEnv) (lastHash : CommonValues.Limbs8)
    (proofSubmitter : CommonValues.Limbs5) : CommonValues.Limbs8 :=
  chainEndStatement e ⟨lastHash, proofSubmitter⟩

theorem prove_end_of_a_native_run (e : ChainEnv) (contents : List (List Nat))
    (hne : contents ≠ []) (a : CommonValues.Limbs5) :
    ∃ h, proveChainAll e contents = some h ∧
      ChainEndGates e ⟨h, a⟩ contents ∧
      proveEnd e h a = chainEndStatement e ⟨chainHash e contents, a⟩ := by
  refine ⟨chainHash e contents, prove_chain_all_matches_the_chain_hash e contents hne,
    chain_end_accepts_any_proof_submitter e contents hne a, rfl⟩

/-! ### A concrete non-vacuous trace -/

/-- A toy keccak: not collision resistant, used only to show the definitions compute. No
security claim is attached to it. -/
def toyChainEnv : ChainEnv :=
  { keccak := fun l => ⟨l.length, l.foldl (fun a x => a + x) 0, 0, 0, 0, 0, 0, 0⟩ }

theorem toy_chain_first_step :
    chainHash toyChainEnv [[5]] = ⟨9, 5, 0, 0, 0, 0, 0, 0⟩ := by decide

theorem toy_chain_two_steps :
    chainHash toyChainEnv [[5], [7]] = ⟨9, 21, 0, 0, 0, 0, 0, 0⟩ := by decide

theorem toy_chain_two_steps_is_accepted :
    CyclicAccepts toyChainEnv ⟨9, 21, 0, 0, 0, 0, 0, 0⟩ [[5], [7]] := by
  exact ⟨by decide, by decide⟩

theorem toy_native_run_reaches_the_accepted_hash :
    proveChainAll toyChainEnv [[5], [7]] = some ⟨9, 21, 0, 0, 0, 0, 0, 0⟩ := by decide

theorem toy_chain_end_statement :
    proveEnd toyChainEnv ⟨9, 21, 0, 0, 0, 0, 0, 0⟩ ⟨1, 2, 3, 4, 5⟩
      = ⟨13, 45, 0, 0, 0, 0, 0, 0⟩ := by decide

/-- Reordering the two steps changes the chain hash under this toy env only if the toy hash
separates them; here it does not (the toy fold is additive), which is precisely why ORDER
sensitivity is a property of keccak and not of the fold algebra. -/
theorem toy_chain_order_is_not_separated_by_a_weak_hash :
    chainHash toyChainEnv [[5], [7]] = chainHash toyChainEnv [[7], [5]] := by decide

end Zkp.Implementation.TreeInstances
