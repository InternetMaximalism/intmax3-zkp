# Design + Threat Model: Channel / KeyID two-tier identity & signature trees

Status: DESIGN (pre-implementation). Step 1 of the W3 consensus rewrite. No circuit code yet.

Context: base intmax native user = channel (keyed by `channel_id`, u32). A channel authorizes a
block iff EVERY member keyID clears its own M-of-N threshold. This requires a two-tier tree
structure, both tiers registered ON-CHAIN and proven correct in ZKP.

Prerequisite memories: [[project_channel_base_identity]], [[project_channel_close_unification]].

> **MVP NOTE — separate spec & implementation file.** This document is the FULL design. The first
> cut is an MVP specified in a SEPARATE file: **`tasks/channel-key-tree-mvp.md`**, implemented in its
> own self-contained module (not threaded into the in-place recursive validity refactor). The MVP
> treats the KeyTree and ChannelTree as ALREADY-registered at genesis and IMMUTABLE (fixed roots);
> it consumes NO registration in-proof and assumes NO registration occurs after genesis. Thus the
> on-chain registration consumption (§2), the registration-application circuit (§6), and the
> shared-tree ordering (§6.2) are OUT of MVP scope (deferred). See the MVP file for what is in/out.

---

## 1. Data structures

### 1.1 KeySetTree (EXISTING — unchanged)
Per keyID. Merkle tree of up to 8 `PkLeaf { pk_hash = Poseidon(pub_seed || pub_root) }`
(`KEY_SET_TREE_HEIGHT = 3`). Root = `pk_set_root`.

### 1.2 KeyLeaf (NEW) + KeyTree (NEW)
`KeyLeaf` = the per-keyID registered record (moves the crypto fields out of today's ChannelLeaf):
```
KeyLeaf {
    pk_set_root: PoseidonHashOut,   // root of this keyID's KeySetTree (its pubkey set)
    threshold:   u32,               // M: min valid signatures for this keyID
    num_keys:    u32,               // N: registered key count (range-checked, threshold<=num_keys<=8)
}
```
`KeyTree`: Merkle tree indexed by `key_id` (height `KEY_ID_BITS = 32`). Leaf = `KeyLeaf`.
Root = `key_tree_root`. Empty slot = default leaf (pk_set_root=0 ⇒ "unregistered keyID").

### 1.3 ChannelLeaf (RESTRUCTURED) + ChannelTree (= today's channel/account tree)
```
ChannelLeaf {
    index:               u32,              // next send leaf index   (KEEP — tx ordering)
    prev:                BlockNumber,      // previous block number  (KEEP)
    send_tree_root:      PoseidonHashOut,  // send tree root         (KEEP)
    member_key_ids_root: PoseidonHashOut,  // NEW: root over the channel's member keyID set
    // REMOVED: pk_set_root, threshold   → moved to KeyLeaf (per keyID)
}
```
`ChannelTree`: indexed by `channel_id` (height `CHANNEL_TREE_HEIGHT = 32`). Root = `channel_tree_root`.
No channel-level threshold: the rule is "ALL member keyIDs satisfied" (= N-of-N over members, each
member being its own M-of-N). (If a configurable channel quorum is wanted later, add a field; out of
scope now.)

### 1.4 MemberKeyTree (NEW, per channel)
Commits the channel's ordered, unique member keyID set. `member_key_ids_root` = root of a Merkle tree
whose leaves are the member `key_id`s (strictly ascending & unique, mirroring
`ChannelRecord::validate`). Used to (a) bind which keyIDs belong to a channel, (b) enforce cardinality
(no member omitted) during signature verification.

### Hierarchy
```
ChannelTree(channel_id) → ChannelLeaf{ member_key_ids_root } → MemberKeyTree[ key_id ]
                                                                     → KeyTree(key_id) → KeyLeaf{ pk_set_root, threshold }
                                                                                              → KeySetTree(pubkey hashes)
```

---

## 2. On-chain registration + ZKP binding (BOTH tiers)

### 2.1 On-chain registration functions (DA)
- `registerKey(key_id, pubkeys[] /* (pub_seed, pub_root) */, threshold)`
- `registerChannel(channel_id, member_key_ids[])`

Each appends to a per-tier **registration hash chain** (keccak rolling hash, ordered) and stores
calldata for DA. The contract holds the current `key_tree_root` / `channel_tree_root` and the
registration-chain heads, all bound to ZKP public inputs.

### 2.2 ZKP binding (mirror deposit_hash_chain / block_hash_chain → keccak(ValidityPIs))
A registration-application circuit proves, for each tier:
- it consumed a witnessed registration list whose recomputed keccak chain == the on-chain chain head;
- it applied each registration to the tree in order (Merkle update), proving
  `prev_root → new_root` exactly;
- public inputs expose `(prev_root, new_root, reg_chain_head)` so the contract binds them via
  `keccak(PI)`.

### 2.3 SECURITY INVARIANT (must hold)
The Poseidon tree contents equal EXACTLY the on-chain-registered set — no unregistered entry, no
omitted entry, no substitution, applied in the registered order.

### 2.4 Open decision — mutability
Registration update/revocation semantics (rotate a keyID's keys, change a channel's members,
revoke). Default for step 1: **append/initialize only** (a slot, once registered, is immutable);
membership/key rotation is a later, separately-threat-modeled feature. Flag in code with
`// INTENTIONALLY SIMPLE`.

---

## 3. Signature verification rule (new, in signature_aggregation)

For a block authored by channel `C` with witnessed member signatures:
1. Prove `ChannelLeaf(C)` inclusion in `channel_tree_root` → obtain `member_key_ids_root`.
2. For EACH member keyID `k` in `C`'s member set:
   a. prove `k` inclusion in `member_key_ids_root` (binds k to C);
   b. prove `KeyLeaf(k)` inclusion in `key_tree_root` → `(pk_set_root_k, threshold_k)`;
   c. verify `≥ threshold_k` distinct valid SPHINCS+ sigs against `pk_set_root_k` (distinct via
      unique KeySetTree leaf indices — no double-count).
3. Enforce the conjunction: ALL member keyIDs satisfied AND processed member set == the full
   `member_key_ids_root` (cardinality: `processed_count == member_count`) so none is omitted.

---

## 4. Threat model (short, falsifiable). Each item ⇒ a negative test that MUST fail to prove.

| # | Attack | Defense | Falsifiable test (must FAIL to prove / be rejected) |
|---|--------|---------|------------------------------------------------------|
| T1 | Unregistered key/pubkey injected into a tree | reg-chain in circuit == on-chain chain; every leaf ⇐ a registration | add a KeyLeaf/PkLeaf absent from the reg chain |
| T2 | Registered member omitted (sign with subset) | `processed_count == member_count` + member_key_ids_root binding | verify channel with one member dropped |
| T3 | keyID threshold underflow | in-circuit `sigs_verified ≥ threshold` | supply `threshold-1` valid sigs |
| T4 | Cross-channel key reuse (C' key authorizes C) | member_key_ids_root binds keys to channel; channel_id bound | substitute a C' member key into C |
| T5 | Fabricated tree root (not on-chain) | keccak(PI) binds prev/new root to on-chain stored root | submit proof with mismatched root |
| T6 | Double-count one key as multiple sigs | unique KeySetTree leaf indices; strict-ordered unique members | reuse a pubkey index twice |
| T7 | Registration replay / reorder mutates tree | ordered keccak chain; once-only slot init (§2.4) | re-apply or reorder a registration |
| T8 | Empty/dummy member or threshold=0 accepted | reject `key_id==0`, `threshold==0`, `threshold>num_keys` | register threshold=0 / num_keys<threshold |

Domain separation: KeyTree / ChannelTree / MemberKeyTree / KeySetTree leaf hashes and the two
registration chains MUST be domain-separated (distinct tags) to prevent cross-tree confusion.

---

## 5. Implementation order (after this design is approved)

1. (this doc) design + threat model.
2. `KeyLeaf`/`KeyTree` types; restructure `ChannelLeaf` (drop pk_set_root/threshold, add
   member_key_ids_root); `MemberKeyTree`. Update Poseidon leaf hashing + domain tags.
3. On-chain `registerKey`/`registerChannel` + registration hash chains + roots storage.
4. Registration-application circuit (reg chain == on-chain; prev_root→new_root); bind via keccak(PI).
5. Rewrite signature_aggregation to §3 rule.
6. Rewrite block processing (update_channel_tree etc.) to "1 channel = 1 leaf + member keys".
7. Fix remaining W1 sites (tx-tree index → channel_id, balance/withdrawal) consistently.
8. Tests per §4 (each Tn) + happy/boundary/property. Reach green build.

CLAUDE.md: keep implementer and security-reviewer subagents separate; do not weaken any §4 check to
make a test pass.

---

## 6. Step 4 detailed design — registration-application circuit

### 6.1 Existing topology (integration targets, verified by code read)
- Validity proof is a recursive composition, NOT one circuit:
  `DepositChainProcessor` (cyclic) + per-block `UpdateUserCircuit` (channel tree send-leaf update +
  SPHINCS+) + `BlockStepCircuit` (folds prev block + update + deposit) + `BlockHashChainCircuit`
  (cyclic) + `ValidityCircuit` (finalizer → `keccak(ValidityPublicInputs)`).
- `ValidityPublicInputs` (validity_circuit.rs:31): initial/final `{block_number, block_chain,
  ext_commitment}` + `prover`. `ext_commitment = Poseidon(ExtendedPublicState)` which already holds
  the deposit_hash_chain and the channel(account) tree root. On-chain binding:
  `_computeValidityPIHash` in IntmaxRollup.sol (u32 big-endian, abi.encodePacked).
- Closest analogue = deposit chain: `Deposit::hash_with_prev_hash` recomputes the keccak chain
  in-circuit via `builder.keccak256::<C>(&inputs)`; a `SparseMerkleProof.get_root` proves
  prev_root→new_root (deposit_step.rs:277-296). MIRROR THIS.

### 6.2 KEY DESIGN POINT — the ChannelTree is SHARED (ordering constraint)
- `KeyTree` is registration-only → can be a clean independent cyclic processor.
- `ChannelTree` is shared: **registration CREATES** a `ChannelLeaf(channel_id)` (with
  `member_key_ids_root`, empty send tree); **block processing UPDATES** that leaf's send_tree_root.
  A channel must be registered before it can post a block.
- Therefore a state transition is ordered: **(phase A) apply pending registrations to KeyTree &
  ChannelTree → (phase B) apply blocks on the resulting ChannelTree root.** The registration phase
  output channel_tree_root becomes the block phase input root. (Deposits stay independent.)

### 6.3 RegistrationChain processor (new module src/circuits/validity/registration_chain/)
Per the deposit pattern: `registration_step` (one registration) → `registration_chain_circuit`
(cyclic) → `registration_chain_processor`. Handles BOTH key and channel registrations.
Per-step in-circuit:
- recompute the keccak chain head:
  - key:    `keccak( prev(8u32) ‖ key_id(1u32) ‖ threshold(1u32) ‖ num_keys(1u32) ‖ pk_hashes(8u32 each) )`
  - channel:`keccak( prev(8u32) ‖ channel_id(1u32) ‖ member_count(1u32) ‖ member_key_ids(1u32 each) )`
  using `builder.keccak256::<C>`. MUST match the Solidity preimage in §Step3 (registerKey/
  registerChannel). NOTE: `solidity_keccak256(&[u32])` hashes each u32 as 4 big-endian bytes ⇒
  matches `abi.encodePacked(uint32)`; a `pk_hash` bytes32 = its 4 Goldilocks limbs big-endian =
  8 u32 words = 32 bytes ⇒ matches `abi.encodePacked(bytes32)`. **Binding requirement:** registrant
  supplies `pkHashes` in canonical 4×u64-BE PoseidonHashOut form.
- key registration: build `KeySetTree` from `pk_hashes` → `pk_set_root`; insert
  `KeyLeaf{pk_set_root, threshold, num_keys}` at `key_id` in KeyTree (verify empty prev-leaf, then
  `get_root` for new root).
- channel registration: build `MemberKeyTree` from `member_key_ids` (assert strictly ascending,
  unique, non-zero in-circuit — matches the contract) → `member_key_ids_root`; insert
  `ChannelLeaf{index:0, prev:0, send_tree_root: empty, member_key_ids_root}` at `channel_id`.
- once-only slot init (§2.4): assert the prev leaf at the slot is the empty/default leaf.

### 6.4 ValidityPublicInputs additions (for on-chain binding)
- Put `key_tree_root` into `ExtendedPublicState` (so `ext_commitment` covers it and downstream
  signature verification uses it). `channel_tree_root` is already in ext state.
- Expose, as TOP-LEVEL ValidityPublicInputs fields (so the contract can match its own records):
  `initial_key_reg_chain, final_key_reg_chain, initial_channel_reg_chain, final_channel_reg_chain`.
- Update `_computeValidityPIHash` (Rust + Solidity) and the Groth16 public-input limb count to
  include these (keccak preimage grows; keep both sides in lockstep — see CLAUDE.md FS checklist).

### 6.5 Contract finalize() binding
- `require(proof.final_key_reg_chain == keyRegHashChain_recorded)` and the channel equivalent: the
  proof consumed EXACTLY the on-chain-recorded registrations.
- `require(proof.initial_key_reg_chain == lastAppliedKeyRegChain)` (continuity, no skip/replay);
  then advance `lastAppliedKeyRegChain = final_key_reg_chain` (+ channel). Add these "applied"
  pointers to contract state. (The recorded `_pending*` head becomes the applied head once proven.)

### 6.6 Threat-model → circuit check mapping (from §4)
T1 unregistered injection → keccak chain recompute == on-chain (§6.3) + once-only slot init.
T2 omission → block/sig phase requires processed member set == member_key_ids_root (§3) + cardinality.
T3 threshold underflow → in-circuit `sigs_verified ≥ threshold` (sig phase).
T4 cross-channel reuse → member_key_ids_root binds keys to channel; KeyTree lookup by key_id.
T5 fabricated root → ext_commitment + reg-chain heads bound via keccak(ValidityPIs) to on-chain state.
T6 double-count → unique KeySetTree leaf indices; strict-ascending member set asserted in-circuit.
T7 replay/reorder → ordered keccak chain + initial/final continuity pointers (§6.5) + once-only init.
T8 dummy/threshold=0 → assert key_id≠0, threshold∈[1,num_keys], num_keys≤2^KEY_SET_TREE_HEIGHT.

### 6.7 Step 4 implementation checklist
1. ExtendedPublicState: add `key_tree_root`; thread through ext_commitment.
2. registration_chain/ module (step + cyclic + processor + pis), mirroring deposit_hash_chain/.
3. Order phase A (registration) before phase B (blocks) on the shared ChannelTree.
4. ValidityPublicInputs + Solidity struct + _computeValidityPIHash + Groth16 limb count (lockstep).
5. finalize() reg-chain binding + applied pointers.
6. Tests T1–T8 + happy/boundary/property.
