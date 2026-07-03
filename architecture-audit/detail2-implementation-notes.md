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

> **Signature part SUPERSEDED by D8 (2026-06-15):** the "3/3 (→ N-of-N) SPHINCS+ signatures" are
> replaced by a recursively-verified Goldilocks `ListCircuit` proof over `(IMCH_digest, pk_g_i)`. The
> recursive `finalBalanceProof` verification, H1/IMCH recomputes, and shared-binding structure stand.

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

> **SUPERSEDED by D8 (2026-06-15):** the signature primitive is no longer SPHINCS+. The multisig /
> threshold / KeyId / UserId removal (one identity per member, no aggregation pipeline) STANDS; but
> **DA "identity = SPHINCS+ pubkey hash"** becomes the two-key identity `pk_g` (Goldilocks
> Poseidon-preimage pubkey, same `Bytes32` slot) + `pk_b` (BabyBear), see D8.

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

> **Partially SUPERSEDED by D11–D14 (2026-07):** the single `MAX_CHANNEL_MEMBERS = 16` was split into
> `MAX_COSIGNERS = 16` (close signers = `member_count`) and `MAX_CHANNEL_MEMBERS = 1024` (balance-slot
> capacity), with `MEMBER_TREE_HEIGHT` 4 → 10 (D12); the 16-slot SPHINCS+/sign-zkp gating became the
> binary-tree aggregated sign-zkp (D13); the flat-keccak H1 became the Poseidon slot-tree-root form
> (D14); and the degree-2^19 measurement is superseded (close is 2^17 after D14). The pad-to-MAX
> scheme, the fixed-length IMCM commitment form (now sized `MAX_COSIGNERS`), and the `validate()`
> constraint pattern STAND.

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

---

## D8 — SPHINCS+ → two-key Poseidon-preimage ZK signature (branch `paymentchannel-delegate`, 2026-06-15)

**Context (user directive):** replace the SPHINCS+ (Poseidon) member signatures — which §B-4 lists as
"Existing / No change" and which D4/D5 use — with a ZK-friendly **Poseidon-preimage signature**
verified only inside ZK proofs, and remove SPHINCS+ entirely. This **supersedes** the SPHINCS+ parts of
D4 (close "3/3 SPHINCS+ signatures") and D5/DA ("identity = SPHINCS+ pubkey hash"). abstract2.md needs
no change; this is the authoritative delta. Done in phases P1–P4 (commits `99af590`, `afd500d`,
`5df2f6f`, `049c768`, `11393d4`, `a4101fe`, `b0a29fa`).

### Scheme (replaces §B-4 "Signature: SPHINCS+ (Poseidon)")
A "signature" is a **ZK proof of knowledge** of a secret key `sk` with `pk = Poseidon(DOMAIN_PK ‖ sk)`,
with the message `m` (an existing domain-separated signing digest, IMSB/IMCH/IMPA/…) bound as a public
input. Unforgeability reduces to **Poseidon preimage resistance** on `sk` (≥256-bit; classical 2^256 /
quantum 2^128). SECURITY (approved): this is a bespoke "preimage-as-signature" on an algebraic hash,
not a standardized PQ signature — the trade-off (cheap in-circuit, recursively aggregatable, still
plausibly post-quantum) was accepted; `SECRET_KEY_LEN`/digest width are approved parameters. `sig` is
witness-only (never published; A6). Full threat model: `tasks/poseidon-signature-threat-model.md`.

### Two keys per member (no field unification — each native to its proof system)
- **Goldilocks key** `pk_g = Poseidon_Goldilocks(DOMAIN_PK_G ‖ sk_g)` (`src/poseidon_sig/`): signs
  channel-state agreement (IMCH), close, and intmax-tx / small-block (IMSB). Verified **natively in
  Plonky2** via `SingleSigCircuit` (`circuit.rs`), aggregated by a recursive order-sensitive Poseidon
  hash-chain **`ListCircuit`** (`list.rs`, reuses the in-tree `CyclicChainCircuit`); consumers rebuild
  the commitment and check membership/distinctness (`consumer.rs`). `pk_g` is the same `PoseidonHashOut`/
  `Bytes32` slot the SPHINCS+ pubkey hash (D5/DA) occupied — a semantic rename, not a width change.
- **BabyBear key** `pk_b = Poseidon2_BabyBear(DOMAIN_PK_B ‖ sk_b)` (`src/regev/hash_sig.rs`): signs the
  in-channel channel-tx sender authorization. Verified **natively in Plonky3** by `Poseidon2HashSigAir`
  (a SEPARATE Poseidon2-BabyBear STARK — the channelTxZKP is single-AIR/128-row-fixed, so same-proof
  integration was infeasible), bound to the channelTxZKP by the off-chain verifier (see A11). The AIR
  reuses the audited upstream Poseidon2 round constraints via `vendor/p3-poseidon2-air-0.5.3` with a
  **visibility-only** change (`pub(crate) fn eval → pub fn eval`; round-constraint body byte-for-byte
  upstream); the message digest (8×u32, which would alias mod the BabyBear prime ≈ 2^31) is
  re-decomposed into 16×16-bit limbs for injective absorption.

### Validity (§F-2) — supersedes the inline SPHINCS+ `verify_circuit`
`update_channel_tree` no longer verifies SPHINCS+ inline. A `bp_sig_chain: Bytes32` accumulator is
threaded through `ExtendedPublicState` (mirroring `channel_reg_hash_chain`): the bp slot folds
`(IMSB_digest, bp_pk_g)` into it via the shared `poseidon_sig::list` gadgets, using the SAME wires bound
to `member_pubkeys_root` and `tx_tree_root`. `validity_circuit` **conditionally** verifies the
`ListCircuit` proof gated on the COMPUTED `final.bp_sig_chain != 0` (not a prover flag), asserting
`C == final.bp_sig_chain` and `initial == 0`. `bp_sig_chain` is bound into `ValidityPublicInputs`.

### Close (§F-3) — supersedes D4's "3/3 (→ N-of-N) SPHINCS+ signatures"

> **SUPERSEDED by D13 (2026-07) for the close/cancel path:** the `ListCircuit` verification + the
> in-circuit `C'` fold described below were replaced by ONE recursively verified level-`AGG_LEVELS`
> binary-tree aggregated sign-zkp proof whose PI signer list IS the cosigner key vector. The
> `ListCircuit` itself STANDS on the validity `bp_sig_chain` path (previous subsection).

`close_circuit` removes per-slot SPHINCS+ verify; it recursively verifies a `ListCircuit` proof,
rebuilds `C'` over ACTIVE member slots `(IMCH_digest, pk_g_i)` (select prev on padding), asserts
`C' == C` + pubkey distinctness, and keeps `member_set_commitment` (IMCM keccak) over `pk_g_i` only.

### MemberLeaf / registration / A11 (two-key binding) — supersedes D5/DA single-hash leaf
`MemberLeaf` is now `{pk_g, pk_b, regev_pk_digest}` (`key_tree.rs`). `pk_b` enters the registration
keccak reg-chain preimage between `pk_g` and `regev_pk_digest` (`CHANNEL_REG_PREIMAGE_U32_LEN` updated;
Rust↔Solidity `channelRegPreimage` differential re-pinned + passing; Solidity `registerChannel` takes
`pkBs`). `member_set_commitment` (IMCM, close) stays `pk_g`-only. **A11 (two-key binding) is off-chain:**
the channel-tx verifier checks `(pk_g, pk_b, regev_pk)` belong to one registered `MemberLeaf` — closed
in the wallet (P4-1) by making the wallet `member_pubkeys_root` the canonical Poseidon 3-field leaf root
AND binding `payload.record` to the session's trusted record (`verify_send_transition`'s
`trusted_record`). end-to-end the SAME `pk_b` is bound at wallet / in-circuit Poseidon root / L1 keccak
reg chain. The off-chain dependency (every co-signer runs the check) is a LOCKED/documented assumption.

### Wallet co-signing (P4-2) and SPHINCS+ removal (P4-3)
Wallet member channel-state co-signing moved from SPHINCS+ to Goldilocks: each member produces a
`SingleSigCircuit` proof over the IMCH digest; `verify_all_signatures` verifies each individually
(binding `pk_g ∈ member set` + the exact digest). SPHINCS+ is **fully removed**:
`sphincsplus-{circuits,params,poseidon}` deps gone (`Cargo.lock` count 0), `test_utils/sphincs_sign.rs`
+ `validity/block_hash_chain/sphincs_sig.rs` + `tests/sphincs_timing.rs` deleted; `SmallBlockMessageFields`
moved to `block_hash_chain/small_block_message.rs` (byte-identical IMSB digest).

### New domain constants (extends §G-2)
`DOMAIN_PK_G = 0x494d5047` ("IMPG"), `DOMAIN_SIG_G = 0x494d5347` ("IMSG"),
`LIST_LEAF_DOMAIN = 0x494d4c4c` ("IMLL"); BabyBear `DOMAIN_PK_B`/`DOMAIN_SIG_B` (`src/regev/hash_sig.rs`).
All proven non-colliding with the existing IMxx set.

### Verification & review
Per-phase independent security reviews (separate agents) found no fund-theft/forgery soundness hole;
the P4 review's residual caller-layer A11 gap was fixed (trusted-record binding) with negative tests
(`p4_1_attacker_pk_b_swap_is_rejected`, `p4_1_foreign_self_consistent_record_is_rejected`). Green: forge
99/99; `cargo test --test e2e` 1/1; `wallet_core_e2e` 3/3; `poseidon_sig` 25/25; `regev::hash_sig` 20/20;
WASM lib check clean; Groth16/gnark not run (project rule).

### Degree-hint note (P3-3)
`Poseidon2HashSigAir::max_constraint_degree()` returns `Some(3)` (the true committed degree with
`SBOX_REGISTERS=1`); the batch-stark's hint≥actual guard is a `debug_assert` (compiled out in release),
so the hint is load-bearing — the prove/verify + native-equality tests are the regression sentinel, and
production verification must use `default_config` (84 queries), not `test_config` (8 queries).

---

## D9 — Delegate account (send-only participant; branch `real-delegate-paymentchannel`, 2026-06-16)

**Spec:** detail2.md §L. **Threat model + adversarial review:** `tasks/delegate-account-threat-model.md`
(DA1–DA6) — independent security-review agent: **GO**, no CRITICAL/HIGH; all DA1–DA6 blocked or
accepted-as-designed. **abstract2.md needs a new section** (the original is fixed at 3 co-signing members).

### Why a deviation
abstract2.md's channel is N co-signing members, all equal. A **delegate** has a Regev balance and uses the
identical send/receive/withdraw/refresh proofs, but is EXCLUDED from the N-of-N state co-signing. It trusts
the members for state maintenance (DLG-2). This splits the previously-fused "has a balance / can send" role
from the "must co-sign" role.

### What changed (authoritative)
- **`delegate_count: u8`** added next to `member_count` on `BalanceState` / `ChannelRecord` /
  `ChannelRegRecord`. Regions (in the one fixed-MAX array — 16 slots at the time of D9, **1024 since
  D12**): members `0..member_count`, delegates `member_count..member_count+delegate_count`, padding
  the rest. `active = member_count + delegate_count`, `2 <= member_count` (`<= MAX_COSIGNERS = 16`
  since D12), `active <= MAX_CHANNEL_MEMBERS`.
- **Committed IMMEDIATELY AFTER `member_count`** (one u32 limb) in `BalanceState::h1` (IMBS) + close-circuit
  H1 recompute, `ChannelRecord::signing_digest` (IMCR, native-only), and the registration reg-chain keccak
  preimage (native + `channel_reg_step` circuit twin + Solidity `registerChannel`); `CHANNEL_REG_PREIMAGE_U32_LEN`
  475→476. Close PI: `delegate_count` appended at the END (limb 86); `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN` 86→87;
  Solidity `closePIHash` packs `(memberCount<<8)|delegateCount`. **IMCM close member-set commitment stays
  member-only** (delegates don't co-sign); `member_pubkeys_root` / reg `MemberTree` cover active.
- **Send/receive/withdraw/refresh** widened to the active region in `wallet_core` (`check_slot`,
  `member_pubkeys_root`, the member-list bijection, `verify_send_transition`/A11, `build_send` self-signs
  for members only, `withdrawal_claim_pis` claimant gate `< active`, new `build_refresh` /
  `verify_refresh_transition` + `prove_balance_refresh_witnessed` + wasm `wallet_refresh` + CLI
  `cosign-refresh`). In-circuit E-1/E-3/refresh were already slot-agnostic. **Co-sign paths stay
  `0..member_count`** (`verify_all_signatures`, close `active_bits` + IMCM, validity bp set).
- **Solidity:** `IntmaxRollup.registerChannel(..., delegateCount, ...)` (active arrays, members first);
  4 require-strings → custom errors (EIP-170). `ChannelSettlementManager` ctor takes `delegateBindings`;
  `_registerDelegates` records `(pk_g→recipient)` in the withdrawal-lookup maps but NOT in `registeredMemberPkGs`
  / IMCM (member-only). `closePIHash` takes the `CloseProofFields` struct (byte-identical 87-limb preimage).

### Trust residuals (within the user-confirmed model — NOT theft)
- **DLG-1** (honest-member transition-layer protection): members refuse to co-sign a delegate debit lacking
  the delegate's send signature. Honest-member-only, not enforced at close.
- **DLG-2** (final balance trusted to members): fully colluding members can forge a delegate's final balance.
  Accepted. On-chain solvency + no-double-withdraw still bind delegates.
- **DLG-3** (censorship/liveness OUT OF SCOPE; deployer-misbind griefing): the manager's delegate
  `(pk_g→recipient)` bindings are deployer-asserted (not re-checked vs the member-only registry IMCM). A
  misbind only DENIES the delegate's honest claim (E-3 withdraw needs the delegate's Regev secret key;
  `activeDelegateCount` is pinned to the signed H1) — griefing, not theft.

### Gotcha (baked fixtures)
Adding the `delegate_count` reg-preimage limb changes the validity block-hash-chain EVEN when 0, so ALL baked
validity/c2c/withdrawal/close MLE fixtures were regenerated (`generate_withdrawal_fixture` default + `close_`
prefix to the new manager CREATE2 addr; `generate_c2c_fixture`). "delegate_count=0 ⇒ byte-identical" holds for
newly-generated artifacts, NOT baked proofs. Conditional-omit-when-0 rejected (breaks R3 fixed-length single-
keccak preimage). The manager constructor change also shifts its CREATE2 address → re-bake `close_*` fixtures.

### Status
GREEN: Rust native + circuits, Solidity forge full suite, and a real 2-session browser test (Playwright) of
the wallet-live delegate demo (open distinct delegate slots → send → receive → balance-refresh → send again).
Demo: 3 CLI co-signing members + browsers as send-only delegates (`channel_member` / `wallet-relay.js` /
`wallet-live.html`).

## D10 — A-3 close lifecycle (close / settle / withdraw / claim) + C2/C3 disable (2026-06)

Master: `tasks/a3-close-lifecycle-spec.md` / `tasks/a3-impl-todo.md`. The L1 exit lifecycle is now wired
end to end from the CLI (`channel_member close|settle|withdraw|claim`) + relay (`/api/close|settle|withdraw|claim`).

### Approved deviation — §K-4 anchor on-chain check NOT adopted (user decision A, P1)
detail2 §K-4 suggested an OPTIONAL on-chain consistency check in `finalizeClose` (require
`IntmaxRollup.finalizedStateRoots(channelFundIntmaxStateRoot)` when nonzero). **Disposition: NOT adopted**
(user-approved). Rationale: (1) it does NOT improve fund safety — the actual custody gate is the withdrawal
proof's `finalizedStateRoots[ext_commitment]` check in `IntmaxRollup.withdrawNative`, which independently proves
funds against a finalized rollup state (adversarial review: a zero/forged anchor is fund-safe; the anchor is a
channel-internal member-signed value only); (2) it would change `ChannelSettlementManager` bytecode (CREATE2
manager drift → close-fixture regeneration) for a redundant defensive check; (3) EIP-170 margin. The anchor is
still sourced REAL (`latestFinalizedStateRoot()`) at `setup-backing` for correct semantics + future post-close
use. The eventual liveness caveat (zero anchor when the rollup has no finalized block yet) is documented in the
spec threat model (Threat 7).

### C2/C3 disabled (P6-A) — see detail2 §H-3
`submitSpecialClose` (C2) and `submitLateOutgoingDebitCorrection` (C3) entry points now revert
(`SpecialCloseDisabled` / `LateOutgoingDebitDisabled`); their on-chain gates were forgeable `_matches` stubs.
Adversarial-reviewed: no member funds move, freeze-grief removed, double-pay still prevented by the in-circuit
nullifier used-sets + `cancelClose` (C1). Dead-code removal of the now-unused C2/C3 apparatus is a deferred
non-security cleanup (changing Manager bytecode again forces a fixture regen).

### Status (D10)
- `withdraw` full pipeline (register → deposit → postBlock×3 blob → finalize → withdrawNative → pullChannelFunds)
  verified on anvil (manager received real ETH). MLE/WHIR proofs are nondeterministic (ZK blinding) — fixtures are
  validated semantically, not by byte-parity.
- Remaining (P5-B): a full CLI close→settle→withdraw→claim live E2E requires binding the withdraw pipeline to the
  channel's REAL registered members + deposit (so ONE on-chain registration serves both close and withdraw). The
  close-intent on-chain step is otherwise blocked by the same member-set mismatch that `CloseLifecycleE2E.t.sol`
  currently skips. Tracked as the P5-B integration.

---

## D11 — A5 pk_g distinctness: indexed-Merkle insertion chain (replaces the O(N²) all-pairs loop; commit `ca1f8c6`, branch `feat/channel-api-impl`, 2026-07)

**Spec text superseded:** D6/D8's close-circuit distinctness ("asserts … pubkey distinctness") was an
O(MAX²) all-pairs `pk_g` equality loop over the member slots in the close and cancel-close circuits.

**What changed:** the close/cancel circuits now insert each ACTIVE slot's `pk_g` (as a U256 key, in
slot order, gated by the SAME `active_bits` used by `member_set_commitment`) into a fresh in-circuit
`IndexedMerkleTree` via the existing audited `IndexedInsertionProofTarget::conditional_get_new_root`
gadget — an O(MAX·height) insertion chain. A duplicate key has no valid low-leaf
(`prev_low.key < key < next_key` is unsatisfiable), so a duplicate identity is UNPROVABLE. New
derived constant `MEMBER_DISTINCTNESS_TREE_HEIGHT = ceil(log2(MAX + 1))` (MAX-agnostic; = 5 for
`MAX_COSIGNERS = 16` after D12 — one sentinel leaf + up to 16 inserts ⇒ 32 leaf slots).
`member_set_commitment`, the (then-current) C' fold, slot order, and the PI layouts are unchanged.

**Why:** linearize the distinctness cost so a member-cap bump does not blow up circuit size — the
enabling step for the D12 capacity split.

**Security argument:** proves the SAME A5 property (no two ACTIVE slots share a `pk_g`, so one key
cannot satisfy two of the N-of-N close signatures). The tree height only bounds CAPACITY, never which
keys are checked; under-sizing panics at witness generation (fail-closed), over-sizing is sound.
Independent adversarial review verdict: **SOUND**. Tests: per-circuit duplicate-identity rejection +
a gadget-level in-circuit lock that a forged non-membership proof for a present key is unprovable.

**Status:** implemented (all close/cancel suites green). The close/cancel circuit VKs changed —
**VK re-pin + fixture regeneration PENDING** (batched with D12–D14 before deploy).

---

## D12 — `MAX_COSIGNERS = 16` split from `MAX_CHANNEL_MEMBERS = 1024` (commits `3b5a9f1`, `2c2c5fb`)

**Spec text superseded:** D6's single `MAX_CHANNEL_MEMBERS = 16` conflated the N-of-N close SIGNERS
(cosigners) with the balance-slot capacity (cosigners + delegates), and sized the close/cancel
SIGNATURE work (member pk slots, active-bits unary decomposition, `member_set_commitment` keccak,
signature fold, A5 distinctness) to the full slot capacity.

**What changed (authoritative for detail2 §C-2/§G-1/§F-3/§L):**
- New `MAX_COSIGNERS = 16`: `member_count` is capped `2..=MAX_COSIGNERS` — natively
  (`BalanceState::validate` / `ChannelRecord::validate` / `ChannelRegRecord::validate`), by witness
  guards, and IN-CIRCUIT via the 16-bit unary active-bits sum. All close/cancel signature-side
  arrays/circuits are sized `MAX_COSIGNERS`.
- `MAX_CHANNEL_MEMBERS` raised to **1024** (delegate capacity): the balance/H1 arrays
  (`enc_balances`, `regev_pk_digests`, `pending_adds`, `ChannelRecord.member_pk_gs`) stay `[_; 1024]`
  (serde-big-array on `[T; MAX > 32]` fields; `std::array::from_fn` at array-Default sites) —
  delegates hold balances but never sign. `MEMBER_TREE_HEIGHT = 10` (invariant
  `1 << height == MAX_CHANNEL_MEMBERS`).
- `member_set_commitment` stays the FIXED 16-slot keccak, now sized `MAX_COSIGNERS`
  (`keccak([IMCM, member_count, h_0..h_15])`, 2 + 16×8 = 130 u32 words) — byte-identical to the
  deployed Solidity mirror (whose internal constant is 16); the Rust↔Solidity shared-vector
  cross-check (`close_member_set_commitment_matches_solidity_shared_vector`) passes unchanged.
- Follow-up fix (`2c2c5fb`): `BalanceState::validate` still capped `member_count` at
  `MAX_CHANNEL_MEMBERS` (unreachable with a `u8` field) — aligned to `MAX_COSIGNERS`; three boundary
  tests that silently degenerated at MAX = 1024 (u8 truncation, empty loop range, unreachable
  delegate-overflow assertion) were repaired.

**Why (measured, 2-member close):** degree bits 19 → 18, peak RSS ~14.5 GB → ~9.6 GB, proof
43 s → 21 s. Sizing the signature work to 16 rather than 1024 is what keeps close/cancel tractable;
the H1/balance work legitimately stays 1024 (delegates have balances) and is addressed by D14.

**Security argument:** the cosigner cap is enforced in-circuit (unary sum), not just natively;
`member_count + delegate_count <= MAX_CHANNEL_MEMBERS` still bounds the total active balance
participants; the D11 distinctness chain and the IMCM member-set binding are unchanged in mechanism.
All 17 close/cancel tests pass (honest proves, A5 duplicate rejection, Phase-1 in-circuit locks).

**Status:** Rust native + circuits implemented. **PENDING (Phase 2c — Solidity 1024 alignment):**
the on-chain registration reg-hash-chain preimage and the H1 slot mirrors still assume 16 balance
slots (the Rust `CHANNEL_REG_PREIMAGE_U32_LEN` now scales with `MAX_CHANNEL_MEMBERS = 1024`);
contract-side alignment is a coordinated follow-up before on-chain settlement works at 1024.
Fixture/VK regeneration PENDING (batched).

---

## D13 — binary-tree aggregated sign-zkp; close/cancel consume it (commits `683b4bc`, `76a4dd0`)

**Spec text superseded:** D8's close/cancel consumption — recursive verification of ONE linear
`ListCircuit` proof plus the in-circuit `C'` hash-chain fold over active slots. The `ListCircuit`
itself STANDS on the validity `bp_sig_chain` path (D8); only close/cancel moved.

**What changed (authoritative for detail2 §A-3/§D D-4/§F-3):**
- New `src/poseidon_sig/aggregate.rs` (owner-specified design): cosigner sign-zkps
  (`SingleSigCircuit` proofs) are aggregated PAIRWISE per level — combining two aggregated proofs
  yields one whose PI signer list is the CONCATENATION of the children's lists (2 → 4 → 8 → 16), all
  over one common message. One circuit per level (`AggLevelCircuit` × `AGG_LEVELS = 4`; plonky2 PIs
  are fixed-length), PI layout `[message(8), signer_count(1), pk_0..pk_{2^k−1} (8 each)]`. Each level
  bakes the child VK as a CONSTANT (A7). Absent right children: `is_right_present` boolean +
  conditional verify + dummy proof; every right-side read is gated. `aggregate_to_level` lifts any
  aggregation to the fixed level 4 the consumers need. All aggregation circuits are degree 13.
- Close/cancel: the `ListCircuit` verification + `C'` fold are REPLACED by ONE recursively verified
  level-`AGG_LEVELS` (16-slot) proof at constant VK (`const`-asserted
  `MAX_COSIGNERS == MAX_AGG_SIGNERS`). The cosigner key vector is WIRED from the verified proof's PI
  signer list (zero witnessed freedom) and feeds the unchanged `member_set_commitment` keccak and the
  D11 A5 distinctness chain.
- Consumer obligations from the aggregation adversarial review, enforced in-circuit at the consumer:
  `message == recomputed IMCH state digest`; `signer_count == member_count`; distinctness via the A5
  insertion chain (the aggregator deliberately ACCEPTS duplicate leaves — a duplicate-signer tree is
  rejected HERE); member-set binding via the registered-commitment keccak; pinned top-level VK. Close
  PI layout (95 limbs) unchanged.

**Why (measured, 2-member close):** degree 18, proof 18.7 s (from 21 s); constant-VK consumption
independent of N, and the aggregation tree is parallelizable/incremental off-circuit.

**Security argument:** independent adversarial review verdict **SOUND-UNDER-CONDITION**; its one
finding — left-packing not enforced, allowing a zero pk in a NON-suffix slot via two half-full
nodes — is FIXED in-circuit: a present right child forces the left child FULL
(`count_l == 2^{level−1}`), so by induction padding is provably a suffix; regression test
`non_left_packed_aggregation_is_unprovable`. `signer_count` counts exactly the verified leaf
signatures; a zero pk cannot be a real signer (it would need a Poseidon preimage of `pk = 0`). The
review's consumer conditions are all discharged in the close/cancel circuits (list above).

**Status:** implemented; aggregation suite + all close/cancel suites green. VK re-pin + fixture
regeneration PENDING (batched with D11/D12/D14).

---

## D14 — H1 = Poseidon balance-slot tree root (replaces the flat keccak over all slots; commit `a43e16f`)

**Spec text superseded:** detail2 §C-2's `h1()` as amended by D3/D6/D9 — a flat keccak over the
header AND all `MAX_CHANNEL_MEMBERS` slot components (`enc_balances[*].digest()`, `regev_pk_digests`,
`pending_adds`), recomputed in-circuit by all four settlement circuits.

**What changed (authoritative for detail2 §C-2/§F-3/§G-2; owner directive "the tree lives in
storage, state carries only the root"):**
- Per-slot leaf: `balance_slot_leaf_hash = Poseidon([BALANCE_SLOT_LEAF_DOMAIN "IMSL" 0x494d534c,
  regev_pk_digest (8 u32 limbs), enc_balance_digest (8), pending_adds (1)])` — 18 elements, fixed
  width; the leaf INDEX is the Merkle position, so slot order is bound structurally.
- Slot tree: height-`BALANCE_SLOT_TREE_HEIGHT = 10` (const-asserted `== log2(MAX_CHANNEL_MEMBERS)`)
  `IncrementalMerkleTree<PoseidonHashOut>`, ALL 1024 leaves populated (padding slots hash their
  canonical padding values — the root is a function of the FULL slot array, exactly like the retired
  flat keccak).
- `H1 = Bytes32::from(Poseidon([IMBS, channel_id, member_count, delegate_count, slot_tree_root
  (4 Goldilocks elements), settled_tx_chain (8), settled_tx_accumulator_root (8),
  split_u64(state_version) (hi, lo)]))` — a FIXED 26-element header, O(1) in-circuit regardless of
  slot capacity. NOTE: H1's outer hash moved keccak → Poseidon ("IMBS" is now a Poseidon domain);
  `balance_state_hash` (IMBH) and the L1-boundary keccaks are unchanged.
- Consumers: close/cancel delete the 1024-slot target vectors + giant keccak; the `slot_tree_root`
  is witnessed (bound by the cosigner signatures over H1) and the O(1) header is recomputed
  in-circuit (`h1_gadget::recompute_h1`). withdrawal-claim/post-close-claim replace the 1024-wide
  one-hot slot select with a height-10 Merkle INCLUSION proof of the claimed slot against
  `slot_tree_root` (`split_le(index, height)` bounds the opened index `< MAX_CHANNEL_MEMBERS`).
- Semantics unchanged: the same values are bound (per-slot triples via the root, scalars via the
  header) and H1 keeps the same signing/anchoring role everywhere (IMCH/IMCL/IMCI,
  `state_commitment_root`, L1 `finalizedBalanceStateH1`) — only the commitment STRUCTURE became a
  tree root.

**Why (measured, 2-member close):** the flat keccak (~17×1024 u32 words) was the sole remaining
degree-18 driver after D12/D13. Degree bits 18 → 17, proof 18.7 s → 8.7 s, peak RSS ~9.1 GB.
Cumulative D11–D14 (2-member close): degree 19 → 17, proof 43 s → 8.7 s.

**Security argument:** full threat model in `tasks/h1-poseidon-root-threat-model.md` (leaf/header
injectivity — fixed widths, leading domain constants, canonical limb encodings; slot-index binding
via Merkle position; cross-channel/version reuse; every H1 consumer enumerated). Native ↔ circuit
randomized equivalence test for the h1 gadget; all settlement suites green (close/cancel degree 17,
withdrawal-claim 7, post-close 7).

**Status:** implemented. Solidity only pins/compares H1 VALUES (no on-chain slot recompute), so no
immediate contract change from D14 itself — but fixture/VK regeneration is PENDING (regenerated
together with the D11–D13 settlement artifacts), and the D12 Solidity 1024-slot alignment
(registration reg-chain / H1 slot mirrors) remains a separate PENDING follow-up.
