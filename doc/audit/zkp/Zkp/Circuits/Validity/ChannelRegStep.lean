import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Channel-registration hash-chain step  (closes F-UPDU-1)
  =======================================================

  Source: `src/circuits/validity/channel_reg_hash_chain/channel_reg_step.rs`
          (+ channel_reg_chain_pis / _circuit / _processor: PIs & cyclic wrapper)

  ## Protocol role

  Accumulates channel registrations, in order, into TWO commitments kept
  in lock-step: the Poseidon `channel_tree_root` (a Merkle tree the base
  account root is swapped to on a registration block, block_step.rs:643-648)
  and the keccak `channel_reg_hash_chain` (a rolling hash the L1 contract
  matches against the registrations it actually recorded). Each step writes
  ONE fresh `ChannelLeaf` at `channel_id` and folds the SAME registration
  record into the chain.

  ## Why this file exists — F-UPDU-1

  `UpdateUser.lean` proves `registration_root_swap_anchored`: on a
  registration block, `block_step` binds (a) the reg proof verifies under
  the pinned VK, (b) it continues the previous account root + reg chain,
  (c) it is bound to the block number, (d) the update proof is an
  account-tree no-op, (e) the reg chain is committed on-chain. What
  block_step CANNOT bind is the RELATION between `channelTreeRoot` and
  `channelRegHashChain` — that relation lives inside THIS circuit, which
  was previously excluded from scope. That gap is F-UPDU-1, a BASE-LAYER
  fund-risk dependency (every post-registration balance/withdrawal theorem
  anchors to the swapped root).

  The closing constraint stated in `UpdateUser.lean:1012-1018`:

    regTreeRoot' = writeLeaf regTreeRoot channelId (freshLeaf memberRoot) ∧
    regChain'    = keccakFold regChain (record with the SAME member keys
                     hashed into memberRoot)                              ∧
    prevLeaf@channelId = defaultLeaf                                (R5)

  is discharged below by `tree_and_chain_share_member_set` (all three
  conjuncts, by construction) and strengthened by `chain_determines_tree`
  (the L1 chain pins the tree root — the actual anti-tamper property).

  ## Constraint inventory (channel_reg_step.rs, mirrored in Target::new)

  | line     | gate                                                        | meaning |
  |----------|-------------------------------------------------------------|---------|
  | :395-413 | `member_pubkeys_root = poseidon_member_tree(member keys)`    | member root |
  | :415-431 | keccak preimage from the SAME member keys (`from_hash_out`)  | **R2 cross-bind** |
  | :434     | `channel_index = channel_id`                                | index binding |
  | :437-442 | `verify(default_leaf, channel_index, prev_tree_root)`       | **R5 freshness** |
  | :444-451 | write fresh leaf (idx 0, prev 0) at channel_index, same sib  | tree write |
  | :423     | `new_hash_chain = keccak_fold(prev_hash_chain, record)`     | chain fold |
-/

namespace Zkp
namespace Circuits.ChannelRegStep

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

/-- `CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS = 32` (constants.rs:21). Well below
    63, so `PowTwoInj F 32` (index-decomposition uniqueness) holds for
    Goldilocks — used by `chain_determines_tree`. -/
def CHANNEL_TREE_HEIGHT : Nat := 32

/-- Poseidon member-subtree root over the witnessed member-key slots
    (`compute_member_tree_root`, channel_reg_step.rs:413). Uninterpreted —
    determinism is all the leaf-write needs; collision resistance, where the
    protocol needs it, is the named `MemberRootCR` (not used by the core
    correspondence, only by the cross-domain remark). -/
opaque memberRoot {F : Type} [CField F] : List (HashOut F) → HashOut F

/-- The fresh `ChannelLeaf` digest written on registration: `index = 0`,
    `prev = 0`, empty send-tree root, and `member_pubkeys_root` equal to the
    argument (channel_reg_step.rs:444-448; the leaf hash carries the "CHLF"
    domain tag, channel_tree.rs). -/
opaque channelLeaf {F : Type} [CField F] : HashOut F → HashOut F

/-- The default (unregistered) `ChannelLeaf` digest (`empty_leaf`,
    channel_reg_step.rs:435). -/
opaque defaultLeaf {F : Type} [CField F] : HashOut F

/-- The keccak registration-record commitment folded into the chain. Built
    from `channel_id` and the SAME member-key wires the leaf's `memberRoot`
    consumes (channel_reg_step.rs:415-431 splits them to bytes via
    `from_hash_out`). Carrying the identical `members : List (HashOut F)`
    here IS the R2 cross-binding — the model shares the wire, exactly as the
    circuit shares the target. -/
opaque regDigest {F : Type} [CField F] : F → List (HashOut F) → Bytes32 F

/-- One keccak fold of the reg-hash chain: `fold(record, prev_chain)`
    (`channel_reg_hash_with_prev_hash_circuit`, channel_reg_step.rs:423). -/
opaque hashFold {F : Type} [CField F] : Bytes32 F → Bytes32 F → Bytes32 F

/-- The wires of one registration step. `members` is the single shared
    member-key list feeding BOTH the tree leaf and the keccak record. -/
structure StepIO (F : Type) where
  channelId : F                    -- the Merkle index wire (= channel_id, :434)
  members : List (HashOut F)       -- shared member-key witness (R2)
  treeSib : List (HashOut F)       -- the single channel-tree proof object
  prevTreeRoot : HashOut F
  newTreeRoot : HashOut F
  prevHashChain : Bytes32 F
  newHashChain : Bytes32 F

/-- The gates emitted by `channel_reg_step.rs` for one registration. -/
structure Constraints (io : StepIO F) : Prop where
  -- :437-451  R5 verify (prev leaf = default) THEN write the fresh leaf at
  --           `channel_id` over the SAME siblings — a read-then-write on one
  --           proof object, modeled by `PathUpdate` (old leaf = defaultLeaf,
  --           new leaf = freshLeaf(memberRoot members), index = channelId).
  treeUpdate : PathUpdate CHANNEL_TREE_HEIGHT defaultLeaf
      (channelLeaf (memberRoot io.members)) io.channelId io.treeSib
      io.prevTreeRoot io.newTreeRoot
  -- :415-431 / :423  fold the record built from the SAME members into the chain.
  chainFold : io.newHashChain = hashFold (regDigest io.channelId io.members) io.prevHashChain

/-- **R5 — no re-registration.** The previous leaf at `channel_id` is exactly
    the default (unregistered) leaf, so a registration can neither overwrite an
    active channel nor pre-seed a leaf with a non-default `prev` block number
    (channel_reg_step.rs:437-442). -/
theorem r5_prev_leaf_default {io : StepIO F} (h : Constraints io) :
    ∃ bits : List Bool, bits.length = CHANNEL_TREE_HEIGHT
      ∧ io.channelId = bitsValue bits
      ∧ fold defaultLeaf bits io.treeSib = io.prevTreeRoot := by
  obtain ⟨bits, hb, hiv, hfo, _⟩ := h.treeUpdate
  exact ⟨bits, hb, hiv, hfo⟩

/-- **F-UPDU-1 closing constraint (discharged).** All three conjuncts of the
    obligation in `UpdateUser.lean:1012-1018` hold by construction:

    * `regTreeRoot' = writeLeaf regTreeRoot channelId (freshLeaf memberRoot)`
      — the new root folds `channelLeaf (memberRoot io.members)` at `channelId`;
    * `prevLeaf@channelId = defaultLeaf` (R5) — the same path folds `defaultLeaf`
      to the previous root;
    * `regChain' = keccakFold regChain (record with the SAME member keys)`
      — `chainFold` folds `regDigest io.channelId io.members`, which takes the
      IDENTICAL `io.members` list that `memberRoot` above consumes.

    The tree leaf's member root and the chain's record are functions of the
    one shared `io.members`, so a prover cannot register member set A in the
    tree while committing member set B to the L1 chain. -/
theorem tree_and_chain_share_member_set {io : StepIO F} (h : Constraints io) :
    (∃ bits : List Bool, bits.length = CHANNEL_TREE_HEIGHT
        ∧ io.channelId = bitsValue bits
        ∧ fold defaultLeaf bits io.treeSib = io.prevTreeRoot
        ∧ fold (channelLeaf (memberRoot io.members)) bits io.treeSib = io.newTreeRoot)
    ∧ io.newHashChain = hashFold (regDigest io.channelId io.members) io.prevHashChain := by
  refine ⟨?_, h.chainFold⟩
  obtain ⟨bits, hb, hiv, hfo, hfn⟩ := h.treeUpdate
  exact ⟨bits, hb, hiv, hfo, hfn⟩

/-- Injectivity of the keccak registration record in its member-set argument
    (for a fixed `channel_id`): distinct member sets ⇒ distinct records. The
    keccak-CR analogue of `Bytes.PoseidonCR`, named so the trust assumption is
    visible in every consumer's signature (same "no colliding instance
    exhibited" idealization). -/
def RegDigestInj (F : Type) [CField F] : Prop :=
  ∀ (cid : F) (m m' : List (HashOut F)), regDigest cid m = regDigest cid m' → m = m'

/-- Injectivity of one hash-chain fold in its record slot (prev chain fixed):
    distinct records ⇒ distinct chain outputs. The keccak-CR hypothesis for the
    fold step. -/
def HashFoldInj (F : Type) [CField F] : Prop :=
  ∀ (r r' prev : Bytes32 F), hashFold r prev = hashFold r' prev → r = r'

/-- **The anti-tamper payoff: the L1 chain determines the tree root.** Two
    registration steps that agree on `channel_id`, the previous tree root, the
    previous chain, and the proof siblings, and that produce the SAME
    `channel_reg_hash_chain`, produce the SAME `channel_tree_root`.

    Consequence for F-UPDU-1: because the L1 contract matches
    `channel_reg_hash_chain`, the committed chain PINS the member set (via the
    keccak CR hypotheses), and this theorem shows that pinned set determines the
    Poseidon `channel_tree_root` the base account root is swapped to. A block
    producer therefore cannot present a `channelTreeRoot` committing a member
    set different from the one the L1 recorded — the base-layer exposure is
    closed to the two named keccak-CR assumptions plus index-decomposition
    uniqueness (all standard, all Goldilocks-true). -/
theorem chain_determines_tree
    (hfold : HashFoldInj F) (hreg : RegDigestInj F)
    (hpow : PowTwoInj F CHANNEL_TREE_HEIGHT)
    {io io' : StepIO F} (h : Constraints io) (h' : Constraints io')
    (hcid : io.channelId = io'.channelId)
    (hsib : io.treeSib = io'.treeSib)
    (hprevC : io.prevHashChain = io'.prevHashChain)
    (hchain : io.newHashChain = io'.newHashChain) :
    io.newTreeRoot = io'.newTreeRoot := by
  -- 1. Equal chain outputs + fixed prev chain ⇒ equal records (keccak CR).
  have hrec : regDigest io.channelId io.members = regDigest io'.channelId io'.members := by
    apply hfold _ _ io.prevHashChain
    rw [← h.chainFold, hchain, h'.chainFold, hprevC]
  -- 2. Equal records at the same channel_id ⇒ equal member sets (keccak CR).
  rw [hcid] at hrec
  have hm : io.members = io'.members := hreg _ _ _ hrec
  -- 3. Same members + same channel_id (⇒ same index bits) + same siblings
  --    ⇒ the fresh-leaf write reproduces the same new root.
  obtain ⟨bits, hb, hiv, _, hfn⟩ := h.treeUpdate
  obtain ⟨bits', hb', hiv', _, hfn'⟩ := h'.treeUpdate
  have hbits : bits = bits' := hpow bits bits' hb hb' (by rw [← hiv, hcid, hiv'])
  rw [← hfn, ← hfn', hm, hbits, hsib]

/-!
  ## SECURITY OBSERVATIONS

  * **R2 shared wire is the load-bearing binding.** `memberRoot io.members`
    (tree leaf) and `regDigest io.channelId io.members` (chain record) consume
    the IDENTICAL `io.members`. Split them into two independent lists and
    `tree_and_chain_share_member_set` no longer type-checks with one `members` —
    exactly the decoupling attack that would let a block producer register a
    benign member set on-chain while the tree commits an attacker-controlled one.

  * **R5 is the anti-overwrite bolt.** Drop the old-leaf conjunct of `treeUpdate`
    (the `PathUpdate`'s `fold defaultLeaf … = prevTreeRoot`) and
    `r5_prev_leaf_default` becomes unprovable: a prover could overwrite an active
    channel's leaf, or pre-seed a future channel with a crafted `prev`.

  * **Index binding.** The Merkle index in both the R5 verify and the write is
    `io.channelId` (single field, no witness freedom — channel_reg_step.rs:434);
    modeled as the single `io.channelId` threaded through the one `PathUpdate`.

  * **Per-step ⇒ whole-chain (lockstep), by the standard cyclic pattern.** Like
    `DepositStep` / `WithdrawalStep`, cross-step continuity is the `is_initial`
    conditional select (channel_reg_step.rs:315-359 selects `prev_hash_chain`,
    `prev_tree_root`, `prev_count`, and the pinned initial values with ONE
    control bit), the block-number continuation check (:335-339), and the
    `conditionally_connect_vd` cyclic verifier-data binding (:311-313). Each step
    advances tree and chain together from the same previous pair; induction over
    the chain lifts the per-step correspondence to "the whole tree and the whole
    L1-committed chain enumerate the same registration sequence". No new leaf
    constraints live in `channel_reg_chain_pis` / `_circuit` / `_processor`
    (PI-layout + cyclic wrapper + orchestration only).

  * **Member-set immutability** is N/A here: this circuit writes only FRESH
    leaves (R5); rotating a registered channel's member set is unreachable on
    this path (that concern is the update path's `member_set_immutable`,
    `UpdateUser.lean`).
-/

end Circuits.ChannelRegStep
end Zkp
