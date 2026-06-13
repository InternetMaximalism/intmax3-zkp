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

**Implemented:** `pending_adds: [u32; CHANNEL_MEMBERS]` in
`src/common/balance_state.rs`, included in the H1 preimage
(`[BALANCE_STATE_DOMAIN, channel_id, d0, d1, d2, settled_tx_chain, split_u64(state_version),
pending_adds[0..3]]`), so the counters are co-signed and cannot be silently rewound.

**Co-sign rules:** +1 on the receiving slot per homomorphic add; co-signers MUST reject
an add when the slot counter is at `MAX_HOMO_ADDS_BEFORE_REFRESH` (64); the counter
resets to 0 on any fresh re-encryption of that slot (E-1 sender-side re-encryption or a
refresh proof).

---

## D4 — Close circuit: full recursive balance-proof verification + 3/3 SPHINCS+ signatures

The close circuit (`src/circuits/channel/close_circuit.rs`, 77 public inputs) goes
beyond the minimal §F-3 sketch and fully internalizes the close validity argument:

- **Recursive verification of `finalBalanceProof`:** the balance circuit's verifier key
  is baked into the close circuit as constants; the circuit checks
  `settled_tx_chain` and `channel_id` equality between the recursively verified balance
  PIs and the close statement.
- **H1 recompute:** the circuit recomputes `BalanceState::h1()` from the witnessed
  fields (including `pending_adds`, D3) rather than trusting a claimed digest.
- **IMCH digest recompute:** `ChannelState::signing_digest()` is recomputed in-circuit
  (keccak), internalizing `hash(H1, H2)` via the balance-root slot.
- **3/3 member SPHINCS+ signatures** over the recomputed IMCH digest are verified
  in-circuit (7856-byte signatures, 8 u32-limb digest serialization).

Shared mutually-binding structure: the in-circuit keccak preimages (IMBS/IMCH/IMCL/IMCI)
and the balance-PI equality constraints are tied to the same witnessed limbs, so no pair
of bindings can be satisfied with divergent values.

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

| Circuit | Public inputs |
|---|---|
| close | 77 (`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`) |
| withdrawal claim | 42 |
| post-close claim | 34 — `receiverAmountDigest` dropped from the L1 hash |
| cancel close | 41 |

### Validity-circuit additions (§F-2)
Block producers sign the IMSB `SmallBlockRootMessage::signing_digest()`
(`src/circuits/validity/block_hash_chain/sphincs_sig.rs`); the circuit enforces
`tx_tree_root != 0` so an empty/placeholder root cannot be signed into the chain.
A golden test guards drift between the circuit-side IMSB preimage and the off-chain
serializer.

---

## Known deferred items (documented, intentionally not implemented here)

1. **KeyLeaf ↔ KeyTree binding** — SECURITY TODO inherited from the prior
   two-layer-identity refactor; the binding between a member's key leaf and the channel
   key tree is not yet enforced in-circuit.
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
