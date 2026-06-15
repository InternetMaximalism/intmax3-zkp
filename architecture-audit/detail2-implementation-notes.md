# detail2.md Implementation Notes — Approved Deviations & Outcomes

Status: implementation of the detail2.md (SIS → Regev) migration is complete on branch
`enshrined-paymentchannel` (phases P0–P9). This document records every approved deviation
from the detail2.md spec text, the rationale, and the concrete implementation outcomes,
with section references into `architecture-audit/detail2.md`.

All deviations below were surfaced during implementation, reviewed adversarially, and
approved before merging. The spec file itself (`architecture-audit/detail2.md`) is kept
as-written; this file is the authoritative delta.

---

## D1 — Amount encoding: 1 bit/coefficient, not §B-1's "8 bits × 8 coefficients"

**Spec (§B-1):** encode a 64-bit amount as 8 base-256 digits across 8 polynomial
coefficients (8 bits per coefficient, plaintext modulus t = 256).

**Problem:** with 8-bit digits and t = 256, a *single* homomorphic add can overflow a
digit (255 + 255 = 510 > 255), corrupting the plaintext with no carry mechanism. The
upstream SIS-lattice-paymentchannel port's *code* (as opposed to its spec text) already
used bit encoding; the divergence was caught by reading the port source rather than the
spec.

**Implemented:** 1 bit per coefficient, 64 coefficients, plaintext modulus t = 256
(`REGEV_PLAIN_BITS = 8`, `REGEV_N = 128` in `src/regev/params.rs`). Each coefficient
holds a {0,1} digit, so up to 255 homomorphic adds fit in a digit before overflow.

**Approved budget:** `MAX_HOMO_ADDS_BEFORE_REFRESH = 64` (`src/regev/params.rs`),
enforced via D3's `pending_adds` counters. Margin analysis in
`docs/regev-noise-analysis.md`: digit headroom ≈ 4× (64 adds vs. 255 capacity), noise
headroom ≈ 120×, decryption failure probability 0 within the budget (worst-case bound,
not probabilistic).

---

## D2 — Refresh is a combined Decryption+Encryption AIR, not "channelTxZKP with delta = 0"

**Spec (§B-3):** model balance refresh as a channelTxZKP (E-1) invocation with a zero
delta.

**Problem:** impossible as specified. E-1 requires the *encryption witness* (message,
randomness, error terms) of the input ciphertext. A balance that has absorbed
homomorphic adds is a sum of ciphertexts; nobody holds a single encryption witness for
the sum, so the E-1 statement cannot be instantiated for refresh.

**Implemented:** `RefreshAir` in `src/regev/transfer_stark.rs` — a combined
Decryption + Encryption AIR proving *plaintext equality in-circuit*: the prover decrypts
`old_ct` with the secret key (private witness) and proves the fresh `new_ct` encrypts
the same plaintext, without revealing it. The decryption core is shared with E-3.

**Related (E-3):** withdrawClaimZKP uses the `DecryptionAir` directly — "`ct` decrypts
to the *public* amount", with the Regev secret key as a private witness. Both AIRs went
through the adversarial test battery (tampered statements, replayed transcripts,
non-canonical encodings) in P2.

The four shipped STARK statements (`src/regev/transfer_stark.rs`):

| Statement | AIR | Purpose |
|---|---|---|
| E-1 channelTxZKP | `DualKeyTransferAir` | sender's fresh re-encryptions well-formed under both keys, delta consistent |
| E-2 channelUpdateZKP | `ChannelUpdateAir` | before/after ciphertext transition consistency (4 ciphertexts) |
| E-3 withdrawClaimZKP | `DecryptionAir` | ciphertext decrypts to a public amount (sk private) |
| §B-3 refresh | `RefreshAir` | old/new ciphertexts encrypt the same hidden plaintext |

---

## D3 — `BalanceState.pending_adds: [u32; 3]`, hashed into H1 (deviation from §C-2)

**Spec (§C-2):** minimal `BalanceState` field set (`encBalances`, `settledTxChain`,
`stateVersion`).

**Problem (adversarial review finding F5-A):** without an enforced add counter, an
adversary can flood a victim slot with homomorphic adds, driving digit sums or
accumulated noise past the decryption bound. The victim's balance ciphertext becomes
undecryptable → E-3 withdrawClaimZKP unprovable → *exit-liveness DoS*.

**Implemented:** `pending_adds: [u32; CHANNEL_MEMBERS]` *(D6: widened to
`[u32; MAX_CHANNEL_MEMBERS]` = 16, all 16 hashed into H1)* in
`src/common/balance_state.rs`, included in the H1 preimage
(`[BALANCE_STATE_DOMAIN, channel_id, d0, d1, d2, settled_tx_chain, split_u64(state_version),
pending_adds[0..3]]` *(D6: all 16 slots)*), so the counters are co-signed and cannot be silently rewound.

**Co-sign rules:** +1 on the receiving slot per homomorphic add; co-signers MUST reject
an add when the slot counter is at `MAX_HOMO_ADDS_BEFORE_REFRESH` (64); the counter
resets to 0 on any fresh re-encryption of that slot (E-1 sender-side re-encryption or a
refresh proof).

---

## D4 — Close circuit: full recursive balance-proof verification + 3/3 SPHINCS+ signatures

The close circuit (`src/circuits/channel/close_circuit.rs`, 77 public inputs *(→85 in D5, →86 in D6)*) goes
beyond the minimal §F-3 sketch and fully internalizes the close validity argument:

- **Recursive verification of `finalBalanceProof`:** the balance circuit's verifier key
  is baked into the close circuit as constants; the circuit checks
  `settled_tx_chain` and `channel_id` equality between the recursively verified balance
  PIs and the close statement.
- **H1 recompute:** the circuit recomputes `BalanceState::h1()` from the witnessed
  fields (including `pending_adds`, D3) rather than trusting a claimed digest.
- **IMCH digest recompute:** `ChannelState::signing_digest()` is recomputed in-circuit
  (keccak), internalizing `hash(H1, H2)` via the balance-root slot.
- **3/3 member SPHINCS+ signatures** *(→ N-of-N gated over 16 slots in D6)* over the recomputed IMCH digest are verified
  in-circuit (7856-byte signatures, 8 u32-limb digest serialization).

Shared mutually-binding structure: the in-circuit keccak preimages (IMBS/IMCH/IMCL/IMCI)
and the balance-PI equality constraints are tied to the same witnessed limbs, so no pair
of bindings can be satisfied with divergent values.

---

## D5 — one SPHINCS+ key per member (multisig / threshold / KeyId / UserId removed)

**Context (user directive, 2026-06-13):** the channel layer had inherited a two-layer
identity with multisig/threshold (`KeyId`/`UserId`; `KeyTree`→`MemberKeyTree`→`KeySetTree`;
`threshold`/`num_keys`; a `signature_aggregation/` pipeline). This **deviated from
abstract2.md §1** ("1 person 1 key 1 account, address == pubkey",
`memberKeys: Map<ChannelId,[(Address,RegevPk);3]>`) and — worse — the SPHINCS+ signing
gadget's `KeyLeaf ↔ KeyTree` binding was **never enforced in-circuit**, so a prover could
choose any key (a soundness hole). D5 removes the multisig machinery and closes that hole.
abstract2.md needs no change; detail2.md was rewritten (§A-2, §C-2..C-9, §E, §F-3 + PI
tables, §G, §H-1, §K-6).

**DA — identity = SPHINCS+ pubkey hash.** Member identity is the SPHINCS+ public-key hash
`Bytes32` (= `Poseidon(pub_seed || pub_root)` rendered as `Bytes32`) everywhere: digests,
withdrawal/post-close claims, nullifiers, contract params. The `slot` (0/1/2) is **only**
the `enc_balances`/`pending_adds` array index — it is not an identity. `ChannelRecord`
now carries `member_sphincs_pubkey_hashes: [Bytes32; 3]` + `member_pubkeys_root` +
`bp_member_slot: u8` (no `bp_key_id`/`member_key_ids`); `MemberSignature` is
`{ member_slot, sphincs_pubkey_hash, signature }`. `KeyId`/`UserId`/`KeyRecord`/
`KEY_RECORD_DOMAIN` ("IMKR") are deleted. `Block.key_ids` is retained by name but
re-interpreted as "active member slots" (still in the block-hash preimage).

**DB — Poseidon in-circuit member tree + keccak `ChannelRecord` L1 anchor.** The Regev/key
binding is a **Poseidon `MemberTree`** (`src/common/trees/key_tree.rs`,
`MEMBER_TREE_HEIGHT = 2` *(superseded by D6: height 4 = 16 leaves)*, leaf `MemberLeaf { sphincs_pk_hash, regev_pk_digest }`,
`MEMBER_LEAF_DOMAIN` "MBLF"); its root is `ChannelLeaf.member_pubkeys_root`. The L1 anchor
stays the existing **keccak** `ChannelRecord` digest (IMCR) plus the close PI
`member_set_commitment` (keccak, `CLOSE_MEMBER_SET_DOMAIN` "IMCM" `0x494d434d`). Both are
built from the same member set at registration. **keccak is confined to the L1 boundary**
(in-circuit keccak would be ruinous under recursive STARK); the in-circuit binding is all
Poseidon. The Regev digest in the leaf uses `REGEV_PK_POSEIDON_DOMAIN` "IMRP" `0x494d5250`.

**DC — `signature_aggregation/` was dead code, deleted.** The ~6.3K-LOC
`src/circuits/validity/signature_aggregation/` (16 files) and `src/common/key_set.rs`
(`KeySetTree`/`PkLeaf`) were **not on the live validity path** — `BlockHashChainProcessor`
composes only Deposit + UpdateUser + BlockStep + BlockHashChain, and the real signature
verification lives in `update_channel_tree.rs` (UpdateUserTree). Both are deleted.

**DD — N-of-N (3/3 unanimous).** No threshold. `signatures[i].member_slot == i` and
`signatures[i].sphincs_pubkey_hash == record.member_sphincs_pubkey_hashes[i]`; the close
circuit already verified 3/3.

**Soundness binding (the hole-closing core) + verified negative tests.**
- *Validity (in-circuit, Poseidon):* `update_channel_tree.rs` recomputes
  `sphincs_pk_hash = Poseidon(pub_seed || pub_root)` from the **same** pubkey targets fed to
  the SPHINCS+ verify gadget, computes `regev_pk_digest` from the witnessed Regev pk, and
  proves slot inclusion of `MemberLeaf{…}` under the channel's trusted
  `member_pubkeys_root` (itself merkle-bound under `account_tree_root`). The prover-choice
  `pk_set_root` equality check and the standalone `KeyLeafTarget` are removed; `should_verify_sig
  := should_update`.
  Negative test: **`update_user_tree_rejects_pubkey_not_in_member_tree`** — signing with a
  pubkey absent from the member tree fails inclusion and proof generation errors,
  demonstrating the prior any-pubkey-accepted hole is closed.
- *Close (PI + L1, keccak):* the close circuit exposes
  `member_set_commitment = keccak([IMCM, sphincs_pk_hash_0..2])`; L1
  (`ChannelSettlementManager`) matches it against the registered members.
  Negative tests in `close_circuit.rs`:
  **`channel_close_circuit_binds_member_set_commitment`**,
  **`channel_close_circuit_rejects_invalid_member_signature`**,
  **`channel_close_circuit_rejects_balance_chain_mismatch`**,
  **`channel_close_circuit_rejects_tampered_final_state_version`**.

**Solidity mirror.** `ChannelSettlementVerifier.closePIHash` is 85 limbs
(`memberSetCommitment` appended at the end); `ChannelSettlementManager` stores
`registeredMemberSetCommitment()` and matches it on close; registration is simplified to
`channel ⇒ [(sphincsPubkeyHash bytes32, regevPkDigest bytes32, recipient address); 3]`
(no `registerKey`/`bytes8 userId`); claims carry the `bytes32` pubkey hash;
`bpKeyId → bpMemberSlot + bpSphincsPubkeyHash`. The Rust↔Solidity shared vector
`test_member_set_commitment_matches_rust_shared_vector`
(↔ `close_member_set_commitment_matches_solidity_shared_vector`) and
`SKIP_GROTH16=true forge test` pass; the withdrawal/post-close/special-close close-intent
shared vectors are re-pinned and pass.

**Registration-reconciliation follow-up (deferred; detail2 §K-6) — (resolved by D7).** The in-circuit binding
is implemented and unit-tested, but the **registration mechanism that populates
`member_pubkeys_root` into the genesis/account tree** so the binding has a real registered
root to open against is **not** wired up: the balance circuit's genesis hardcodes an empty
account tree (`switch_board.rs:230`, `default_pis.public_state`). Reconciling that with a
registered genesis is deferred; **registration soundness stays genesis-trust per channel**
(`intmax3-channel-mvp.md`). Consequence: the **full-stack close e2e is red on the
registration block** until this follow-up lands — the binding's own negative/positive unit
tests are green, but the end-to-end registered-genesis path is not yet built.

---

## D6 — N members (pad-to-MAX=16) + on-chain verification switched to MLE/WHIR (Groth16 removed)

**Context (phase F7):** up to D5, channel members were a fixed 3 (following abstract2.md §2.1
`memberKeys: Map<ChannelId,[(Address,RegevPk);3]>`). F7 (A) generalizes the member count to
a **variable N in 2..16** (pad-to-MAX scheme), and (B) switches on-chain verification to **MLE/WHIR alone**,
fully removing Groth16. abstract2.md is unchanged (N members is recorded as a spec deviation).

### Change A — N members (pad-to-MAX=16)

**spec deviation:** abstract2.md §2.1's `[(Address,RegevPk);3]` is fixed at 3, so N-member generalization is
a deviation from abstract2. detail2.md §C-2 / §G constants / §H-1 are updated with N-member notes (the authoritative delta is
this D6).

- **pad-to-MAX single circuit.** `MAX_CHANNEL_MEMBERS = 16` (member tree height 4 = 16 leaves). The circuit does not branch;
  it is a single circuit that always processes 16 slots. It carries a per-channel `member_count: u8`, with active = slot
  `0..member_count` and padding slots (`member_count..16`) being default/zero. All member arrays are `[_; 16]`.
  A `member_count` field is added to `BalanceState` and `ChannelRecord`.
- **The close circuit verifies all 16 slots' SPHINCS+ behind a `slot < member_count` gate.** Signature verification for padding slots is
  disabled by the gate (only active slots are really verified). The degree is measured at **2^19**, feasible.
- **`validate()` constraints.** `ChannelRecord::validate` / `BalanceState::validate`:
  `2 <= member_count <= 16`, active slots are distinct and non-zero, padding slots are default,
  `bp_member_slot < member_count`. The withdrawal's `member_index` is bound to `< member_count`.

**Forced sub-deviation — `member_set_commitment` is a fixed-length keccak (not a variable-length active-only one).**
`close_member_set_commitment` (L1) and the in-circuit `member_set_commitment` are **not a variable-length keccak** packing only
the active members, but rather

```
keccak([CLOSE_MEMBER_SET_DOMAIN/IMCM 0x494d434d, member_count, h_0 .. h_15])   // 130 u32 words
```

a **fixed-length keccak** (the hash of the padding is zero-filled, 130 u32 words total). The reason is that the plonky2_keccak gadget
requires a build-time-fixed input length (variable length is not possible). **Injectivity** is preserved with respect to the active
set via the `member_count` in the preimage plus the padding zero-fill (a different member_count yields a different preimage, and for the
same member_count the active hashes are laid out uniquely). Rust / circuit / Solidity all three mirror the same fixed form.
The Rust↔Solidity shared vector is re-pinned to
`0x12450612c5f67b7ff613b705f6e5efccf4bdd43e647570fcb207076f447236cc`.

**Exact layout changes:**
- Add `member_count` (1 limb immediately after channel_id) to the `BalanceState::h1()` preimage, and hash all 16
  `enc_balance` digests + 16 `pending_adds` (a fixed 16, regardless of active/padding).
- Add `member_count` + all 16 hashes to the `ChannelRecord` IMCR digest.
- close PI: **85 → 86** (`member_count` appended at the end).
- The withdrawal's `member_index` is bound to `< member_count`.

**Solidity mirror.** `registerChannel` accepts a variable 2..16 members. `ChannelSettlementManager` stores
`bytes32[16]` + `activeMemberCount` and mirrors the fixed-length commitment at close time in the fixed form above.

**Tests (all green):**
- multi-N close prove+verify: **N = 2 / 3 / 16**(degree 2^19)。
- native `validate` / `h1` / `member_set_commitment` multi-N + negative tests.
- Forge variable-member-count test.

### Change B — on-chain verification switched to MLE/WHIR alone (Groth16 removed)

`IntmaxRollup`'s `finalize` / `fraudProof` / `verify` / `fullVerify` **no longer take** `Groth16Params` and
**no longer call** Groth16.

**Soundness-critical — replacement of the validity-PI binding.** Previously, the binding of the validity public inputs was secured **only by the Groth16
PI-hash check**. This is replaced with

```
_mlePublicInputsMatch(mleProof.publicInputs, keccak256(ValidityPublicInputs))
```

— it binds the MLE proof's `publicInputs` (the 8 keccak limbs of the wrapped validity circuit) by matching them against the on-chain
validity PIs. This way, even with Groth16 removed, the on-chain binding of the validity-PI is maintained.

**The v2 MleVerifier is already active in the pinned submodule.** The v2 MleVerifier including R2-#1 gate binding / R2-#2 logUp
is already active in the target submodule. The MLE fixture is regenerated for the current circuit.

**Removed:** `Groth16Verifier.sol`, `GnarkGroth16Verifier.sol`, `E2E_RealGroth16.t.sol`,
`src/utils/groth16_wrapper.rs`.

**Verified (confirmed that the on-chain path actually goes through):**
- Forge MLE / finalize / fraudProof **20 tests** pass. This includes negative tests showing that the new MLE PI binding
  actually rejects unbound/tampered PI:
  - **`test_finalize_tamperedValidityPIs_rejected`**
  - **`test_finalize_unboundMlePublicInputs`**
- **`test_mleVerify_realProof`** — on-chain MLE+WHIR verify of a real proof (gas ~11.2M).
- **`tests/mle_onchain_e2e.rs`** pass.

**Note (remaining items):** D5's **one-key registration follow-up (§K-6, registration soundness = genesis-trust) is
still outstanding**, and applies equally to N members. The updating-block path in `e2e.rs` is still red due to that
registration gap (not resolved in this F7) *(resolved in D7)*.

---

## Additional recorded outcomes

### Hash-chain leaf definitions (§C-6)
- **Deposit chain leaf** = `Deposit::nullifier()`.
- **Fund-import chain leaf** = `inter_channel_tx.tx_hash`.
- Chain update: `chain' = keccak256([IMTC domain, chain, leaf])`
  (`settled_tx_chain_push` / `settled_tx_chain_push_circuit` in
  `src/common/balance_state.rs`), with a cross-language golden vector pinning the
  preimage layout.

### `Transfer.aux_data` semantics (threat-model note F3-A)
`Transfer.aux_data` carries `tx_leaf_hash`. The *semantic* correctness of that value
(that it really is the hash of the corresponding tx leaf) is checked off-circuit at
co-sign time and again at E-2 verification; the circuit itself chains the merkle-bound
value as an opaque 32-byte word. This is sound because any aux_data accepted into the
chain was co-signed by all members and merkle-bound at settlement.

### Confidentiality boundary (abstract2 §4.5; dummy-delta removal)
The SIS-era dummy-delta receiver-set obfuscation is retired (detail2 §C-1/§A-1).
Resulting boundary, stated explicitly:
- **Public:** inter-channel sender/receiver channel ids and inter-channel amounts.
- **Encrypted (Regev):** in-channel balances and in-channel transfer amounts.

A secondary rationale for the removal: published evaluations of private polynomials
under dummy deltas acted as a dictionary-attack oracle against low-entropy amounts.

### Close-game public-input corrections found during migration
The pre-existing channel PI layouts still assumed a 2-limb `ChannelId`; the migration
to the 1-limb (4-byte) `ChannelId` was applied and the layouts re-pinned. Final lengths
(constants in `src/circuits/channel/*_pis.rs`, mirrored by Solidity and shared Rust↔
Solidity test vectors):

| Circuit | Public inputs (at this migration) |
|---|---|
| close | 77 (`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`) |
| withdrawal claim | 42 |
| post-close claim | 34 — `receiverAmountDigest` dropped from the L1 hash |
| cancel close | 41 |

> **Superseded by D5.** The subsequent one-key-per-member refactor (D5) appended
> `member_set_commitment` to close (→ **85**) and widened the claim member identifier from
> a 2-limb id to an 8-limb pubkey hash: withdrawal claim **42 → 48**, post-close claim
> **34 → 40**; cancel close stays **41**. The Solidity mirror and shared vectors track the
> D5 values.

### Validity-circuit additions (§F-2)
Block producers sign the IMSB `SmallBlockRootMessage::signing_digest()`
(`src/circuits/validity/block_hash_chain/sphincs_sig.rs`); the circuit enforces
`tx_tree_root != 0` so an empty/placeholder root cannot be signed into the chain.
A golden test guards drift between the circuit-side IMSB preimage and the off-chain
serializer.

---

## Known deferred items (documented, intentionally not implemented here)

1. **KeyLeaf ↔ KeyTree binding** — **RESOLVED by D5.** The prior prover-chooses-the-key
   hole is closed: the validity circuit now proves slot inclusion of the signing pubkey
   under the channel's Poseidon `member_pubkeys_root` (negative test
   `update_user_tree_rejects_pubkey_not_in_member_tree`). The residual piece is the
   registration mechanism that anchors that root into the genesis/account tree — see D5's
   "Registration-reconciliation follow-up" and §K-6 — **(resolved by D7).**
2. **M7 signed-but-unsettled race (§K-1)** — semantics to be fixed in abstract3.
3. **`publishRegevPk` full registration ceremony (§K-4)** — current state: pk
   validation + `regev_pk_root` anchoring only.
4. **Lean safety model v3 (§K-5)** — the Lean proofs cover the v1/v2 lattice models;
   the Regev migration is not yet reflected.
5. **Nonzero-chain full-stack close e2e** — the end-to-end close test with a non-genesis
   `settled_tx_chain` across Rust proof generation and Foundry settlement is pending.
6. **requestClose iterated-freeze griefing by a member** — residual risk as designed in
   abstract2; documented, not mitigated.

---

## SETUP — integration-test build fix (macOS `[patch]` / nested-workspace collision)

The pre-existing macOS "output filename collision" that broke `cargo test`/`cargo build`
on integration-test targets (E0463: `plonky2_keccak` / `sphincsplus_*` / `intmax3_zkp` not
found) is **resolved**, not just sidestepped. Two coordinated changes are required:

1. **Root `Cargo.toml`** — explicit single-member workspace with `resolver = "2"` and
   `exclude = ["contracts/lib/polygon-plonky2", "vendor", "gnark"]`. The `exclude` keeps the
   nested submodule workspace intact (so its `{ workspace = true }` inheritance still
   resolves) while pinning OUR resolver to "2" (edition 2024 would otherwise default to "3").

2. **Submodule `contracts/lib/polygon-plonky2/plonky2/Cargo.toml`** — `crate-type = ["rlib"]`
   (drop `cdylib`). The submodule's `cdylib` exists only for its OWN WASM-Merkle test (comment
   `# For WASM Merkle tree test case`); it is unused by the intmax3-zkp native AND wasm-pack
   flows (our crate supplies its own `cdylib`). With `cdylib` present, macOS builds
   `libplonky2.dylib` twice (feature-variant units) and they collide on filename, cascading to
   the E0463 sibling-resolution failure.

**DURABILITY NOTE:** change (2) lives in the submodule working tree. It is NOT tracked by the
parent repo (which only records the submodule commit). To persist it: commit it inside the
submodule (`contracts/lib/polygon-plonky2`, currently on branch `codex/translate-whir-report`)
or re-apply after any `git submodule update`. Without (2), integration tests fail to compile on
macOS again. The native lib build + lib unit tests work with or without (2) (rlib-only sidesteps
the collision for single-target builds); (2) is needed specifically for integration-test and
`--tests`/`--benches` multi-target builds.

After both changes: `cargo build --release --tests --benches` is clean, and integration tests
run (e.g. `nullifier_duplicate_insertion_poc`: 2 passed). e2e.rs / mle_onchain_e2e.rs exercise
the MLE/WHIR/Groth16 wrapper pipeline (separate-PR scope per CLAUDE.md) but now compile.

---

## D7 — on-chain registration consumed by the validity proof (closes the D5 follow-up)

**Context:** D5 introduced the per-block member-signature binding (the signing pubkey must be
included at its slot in the channel's Poseidon `member_pubkeys_root`), but nothing SET that
root — it was only preserved, so it was empty for real channels and the binding was inert
(security-review Finding D), and the in-circuit Poseidon root was never cross-bound to the
keccak `ChannelRecord` (Finding C). D7 closes both: channels register on-chain and the validity
(block) ZK proof deterministically rebuilds the channel tree from the on-chain registration hash
chain, mirroring the DEPOSIT mechanism.

**R1 — deposit-pattern registration step.** New `channel_reg_step` circuit
(`src/circuits/validity/channel_reg_hash_chain/`, cloned from `deposit_hash_chain/`) consumes a
keccak registration hash chain and, per registration, deterministically builds the Poseidon
`MemberTree` and writes the channel's `ChannelLeaf{member_pubkeys_root}` into the channel tree.
`ExtendedPublicState` gained `channel_reg_hash_chain`; `block_step` conditionally verifies the
reg-chain proof (like deposits) and updates `account_tree_root`.

**R2 — keccak↔Poseidon cross-binding (closes Finding C).** The SAME witnessed `PoseidonHashOut`
member values feed BOTH the keccak preimage (via `Bytes32Target::from_hash_out`, an injective
canonical split) AND the Poseidon `MemberLeaf{sphincs_pk_hash, regev_pk_digest}`. Reusing the
identical targets IS the binding — no separate equality constraint. The consumption side
(`update_channel_tree`) opens the identical `MemberLeaf` encoding against the same root.

**R3 — word-aligned fixed-16 preimage.** `ChannelRegRecord::hash_with_prev_hash`
(`src/common/channel_registration.rs`) and `IntmaxRollup.registerChannel` both keccak the
word-aligned u32-limb stream `[prev(8), channel_id(1), bp_member_slot(1), member_count(1),
16×(sphincs_pk_hash(8), regev_pk_digest(8), recipient(5))]` (padding zeroed) — one in-circuit
keccak, no byte-straddling. Rust↔Solidity byte-exactness pinned by a differential test
(member_count 2/8/16).

**R4 (REVISED) — block-hash authenticity anchor.** `channel_reg_hash_chain` is folded into the
BLOCK HASH (`Block` + `_computeBlockHash`), exactly like `deposit_hash_chain`. The initial R4
(ext-commitment only) was found INSUFFICIENT in review: without an on-chain-built anchor a prover
could fabricate a registration in-proof and hijack a `channel_id`. The block-hash chain
(`blockHashChainAt`, postBlock-built from `_pendingChannelRegHashChain`) is the authenticity
anchor `finalize` matches; a second byte-exact differential test pins the block hash.

**R5 — one-time registration.** The step asserts the prior `ChannelLeaf == ChannelLeaf::default()`
(full default, not just empty member root) before writing, preventing overwrite of an active
channel.

**R6 — intra-block exclusion.** A registration block carries no user updates
(`has_channel_reg_proof ⇒ prev_account_tree_root == new_account_tree_root`), so the registration's
channel-tree root is the sole account-tree update that block.

**Genesis reconciliation.** Registration-via-blocks keeps BOTH balance and validity genesis empty
(channels enter the tree through a registration block, not genesis) — this RESOLVES the prior
F6/e2e blocker. The full-stack e2e (`tests/e2e.rs`: register block → deposit → transfer → close)
now PASSES; the validity-path member binding is FUNCTIONAL.

**Verified:** `cargo test --lib` 253 passed; e2e PASS; forge MLE/finalize (incl.
`test_mleVerify_realProof`, tampered/unbound-PI rejection) + the differential tests green; MLE
fixture regenerated. Independent security review: the validity-path member binding is SOUND — a
prover can only bind to on-chain-registered members; Finding C closed; the block-hash anchor is
airtight.

**Residual (escalated):**
- **MEDIUM** — the validity-path registration (`IntmaxRollup.registerChannel` → `member_pubkeys_root`)
  and the close-path member set (`ChannelSettlementManager` constructor → `registeredMemberSetCommitment`)
  are INDEPENDENT registration surfaces with no enforced equality; `bp_member_slot` is authenticated
  on-chain but not re-bound in the validity circuit. Unify (have the settlement manager derive its
  set from the rollup registration) or document the trust assumption.
- **LOW** — `registerChannel` has no access control → `channel_id` squatting/DoS (not a soundness
  break under one-time R5). Confirm the intended channel-id allocation trust model.
