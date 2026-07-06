# F-UPDU-1 — soundness memo for `channel_reg_step.rs`

Status: **CLOSED via Path A — Lean proof (2026-07-06).** This memo was the manual
soundness analysis; it has since been transcribed into machine-checked Lean as
`Circuits.ChannelRegStep` (`tree_and_chain_share_member_set`, `chain_determines_tree`;
whole `Zkp` project `lake build` green, zero `sorry`/`axiom`). The finding is marked
CLOSED in `SUMMARY.md` and `UpdateUser.lean`. This memo is retained as the prose
companion to the proof.

## The finding

On a registration block, `block_step` REPLACES the base account tree root with
`reg.channelTreeRoot` (proven anchored: verified reg-chain proof under the pinned
VK, continuing the previous account root + reg chain, bound to the block number,
update proof forced to no-op — see `UpdateUser.lean` `registration_root_swap_anchored`).
Every post-registration balance/withdrawal theorem is therefore conditional on:

> the reg proof's `channel_tree_root` genuinely corresponds to the same sequence of
> registration records as `channel_reg_hash_chain` (the keccak chain the L1 commits to).

That correspondence is internal to `channel_reg_step.rs`, which is excluded from the
Lean formalization — hence F-UPDU-1: **base-layer fund exposure, not channel-scoped**,
conditional on this one circuit.

## Verdict: the correspondence is SOUND by construction

Verified by direct reading of `src/circuits/validity/channel_reg_hash_chain/channel_reg_step.rs`
(the `add_targets`/circuit path, not comments). Four load-bearing bindings:

### 1. The tree leaf and the hash-chain fold use the SAME member-key wires
The member keys are witnessed once as `PoseidonHashOutTarget` arrays and reused in both places:

- **Poseidon member tree** (feeds the channel-tree leaf): lines 406–413 build
  `MemberLeafTarget { pk_g: member_pk_ges[i], pk_b: member_pk_bs[i], regev_pk_digest:
  member_regev_pk_digests[i] }`, hash each, and `compute_member_tree_root(...)` →
  `member_pubkeys_root`, which is written into `new_leaf` (line 448) and inserted to
  give `new_channel_tree_root` (lines 450–451).
- **Keccak preimage** (feeds the hash chain): lines 416–422 build `MemberRegEntryTarget`
  via `Bytes32Target::from_hash_out(builder, member_pk_ges[i])` (and `pk_b`, `regev`) —
  **the same `member_pk_ges[i]` targets** — then `channel_reg_hash_with_prev_hash_circuit(...)`
  folds them into `new_hash_chain` (lines 423–431).

Because both consume the identical wires, a prover CANNOT put member set A in the tree
leaf and hash member set B into the chain. Note `from_hash_out` is the canonical
`HashOut→Bytes32` split (`safe_split_lo_and_hi`, unique representation) — consistent with
the TODO-2 fix; the preimage bytes are the canonical serialization of the same values.
Padding slots are forced empty (`conditional_assert_eq(zero_hash, !is_active)`, 402–404).

### 2. Insertion index is bound to the channel_id in the record
`channel_index = channel_id.channel_id(builder)` (line 434) is the channel_id value
directly (no witness freedom). The same `channel_index` is used for the R5 verify (line 440)
and the new-leaf `get_root` (line 451). The channel_id is also part of the keccak preimage
(`channel_registration.rs`), so tree index and chain both bind the same channel_id.

### 3. R5 freshness guard prevents overwrite / pre-seeding
Lines 437–442: `channel_merkle_proof.verify(&default_leaf, channel_index, prev_tree_root)`
forces the PREVIOUS leaf at that index to be exactly `ChannelLeaf::default()` (all fields
default, incl. `prev = 0`). So a registration cannot overwrite an existing channel, nor
pre-seed a leaf with a future `prev` block number. The new leaf is fresh (`index=0`,
`prev=0`, empty send tree; lines 444–448). The same merkle proof (siblings) is reused for
the recompute — the standard sound sparse-merkle update.

### 4. Tree and chain advance in lockstep across steps
A single `is_initial` bit drives the `select` for `prev_hash_chain`, `prev_tree_root`,
and `prev_count` together (lines 316–333); block-number continuity is asserted when
chaining (335–339); the per-block initial values are pinned once and carried via
`selected_initial_*` (341–359); and the cyclic verifier-data binding
(`conditionally_connect_vd`, 311–313) forces chained steps to be over this same circuit.
There is no seam to desync the chain from the tree across steps.

### Member-set immutability
Out of scope for this circuit: it only writes FRESH leaves (R5). Rotating a registered
channel's member set is not reachable here (that concern lives in the update path, already
modeled in `UpdateUser.lean` `member_set_immutable`).

## Closing constraint (matches `UpdateUser.lean` obligation)
```
regTreeRoot' = writeLeaf regTreeRoot channelId (freshLeaf memberRoot)
∧ regChain'  = keccakFold regChain (record whose member keys are the SAME wires as memberRoot)
∧ prevLeaf@channelId = defaultLeaf            (R5)
```
All three conjuncts are enforced by construction (evidence above).

## Recommendation
- **Path A (full close):** transcribe the four bindings above into a Lean theorem for
  `channel_reg_step` and discharge the F-UPDU-1 residual in `UpdateUser.lean`. Removes the
  conditional entirely. This is the proper close; it is specialized formal-methods work.
- **Path B (gated launch):** accept F-UPDU-1 as residual on the basis of this code-verified
  analysis, with Path A tracked as a follow-up. Defensible for a gated/capped launch given
  the correspondence is enforced by shared wires + R5, not by an unverified assumption.

Either way, this is a maintainer decision, not a code change — the circuit itself needs no
fix.
