# MVP spec: channel multi-key signature verification over FIXED identity trees

Status: MVP SPEC (separate from the full design in `tasks/channel-key-tree-design.md`).

This is the minimum viable cut of the "channel = base user, authorized iff every member keyID clears
its threshold" mechanism. It is implemented in its OWN self-contained module/files so it does not
depend on (and is not blocked by) the larger in-place refactor of the recursive validity pipeline.

## 1. Core simplification (what makes this an MVP)

- **KeyTree and ChannelTree are pre-registered at genesis and IMMUTABLE.** Their roots are fixed
  inputs (trusted at genesis). NO registration is consumed in-proof, and NO registration occurs
  after genesis.
- Consequently these full-design parts are **OUT of MVP scope (deferred)**:
  - On-chain registration consumption / binding (design §2, and the ZKP side of `registerKey` /
    `registerChannel`). The Solidity `registerKey`/`registerChannel` functions already added in
    Step 3 are RECORD-ONLY and are not consumed by the MVP proof.
  - The registration-application circuit (design §6) and its ValidityPublicInputs additions.
  - The shared-ChannelTree ordering constraint (design §6.2) — irrelevant with no registration.
  - Mutability / rotation / revocation (design §2.4).
- **MVP TRUST ASSUMPTION (explicit):** the genesis KeyTree/ChannelTree are trusted to be the correct
  Poseidon trees of the intended registered set. Registration soundness (threat-model T1/T5/T7) is
  therefore NOT enforced by the MVP — it is deferred to the full design. This is a deliberate,
  documented MVP limitation, NOT a silent workaround.

## 2. Scope IN — the signature-verification rule (B2=A) over fixed trees

A self-contained circuit proving: for a channel `C` authorizing a message `m` (e.g. a block/small
block digest), EVERY member keyID of `C` clears its own M-of-N SPHINCS+ threshold.

Reuses the Step-2 types (already implemented): `ChannelLeaf{..., member_key_ids_root}` and
`ChannelTree` (channel_tree.rs); `KeyLeaf{pk_set_root,threshold,num_keys}` + `KeyTree`,
`MemberKeyLeaf` + `MemberKeyTree` (key_tree.rs); `PkLeaf`/`KeySetTree` (key_set.rs).

Inputs:
- Public: `channel_tree_root` (fixed), `key_tree_root` (fixed), `channel_id`, `message`.
- Private witness: `ChannelLeaf(C)` + ChannelTree inclusion proof at `channel_id`; the ordered member
  `key_id` list + per-member MemberKeyTree inclusion proofs; per member: `KeyLeaf` + KeyTree inclusion
  proof at `key_id`; the signing pubkeys (pub_seed/pub_root) + KeySetTree inclusion proofs + SPHINCS+
  signatures over `message`.

Constraints (the conjunction must hold):
1. `ChannelLeaf(C)` is included in `channel_tree_root` at index `channel_id` → yields
   `member_key_ids_root`.
2. For each member keyID `k`: included in `member_key_ids_root` (binds k to C). Enforce the set is
   strictly ascending & unique and that the processed count == the channel's member count
   (cardinality ⇒ no member omitted).
3. For each member keyID `k`: `KeyLeaf(k)` included in `key_tree_root` at index `k` → `(pk_set_root_k,
   threshold_k)`.
4. For each `k`: at least `threshold_k` DISTINCT valid SPHINCS+ signatures over `message` against
   `pk_set_root_k` (distinctness via unique KeySetTree leaf indices).
5. ALL member keyIDs satisfied (logical AND over the full member set).

## 3. Threat-model coverage (subset of design §4)

Enforced by MVP: T2 (omission/cardinality), T3 (threshold underflow), T4 (cross-channel key reuse),
T6 (double-count), T8 (dummy/threshold=0). Domain separation of the leaves (KYLF/MKLF/CHLF) carries
over from Step 2.

Deferred (trusted in MVP): T1 (unregistered injection), T5 (fabricated root vs on-chain), T7
(registration replay) — these are registration-integrity properties, N/A while trees are fixed at
genesis. Re-enabled by the full design's registration-application circuit.

## 4. Scope OUT (post-MVP)

Registration consumption + binding; registration-application circuit; ValidityPublicInputs additions
& Groth16 limb changes; contract `finalize()` reg-chain binding; mutability; FULL integration into
the recursive validity pipeline (block_step / block_hash_chain) and greening the whole crate; the
remaining in-place W1/W3 compile-error sites in the existing flow (those are tracked in tasks/todo.md
and are NOT a prerequisite for the standalone MVP circuit).

## 5. Implementation (separate files)

Implement as a NEW self-contained module, e.g. `src/circuits/validity/channel_sig_mvp/` (exact path
TBD at implementation), with its own `*_pis.rs` + circuit + a native witness generator + tests for
§3. It must NOT modify the existing (mid-refactor, currently non-compiling) recursive validity files;
it depends only on the Step-2 tree types + key_set + SPHINCS+ verification primitives.

Tests: happy path (all members meet threshold), plus negative tests for T2/T3/T4/T6/T8 (each MUST
fail to prove). Per CLAUDE.md: a dedicated security-review pass separate from the implementer; never
weaken a check to make a test pass.
