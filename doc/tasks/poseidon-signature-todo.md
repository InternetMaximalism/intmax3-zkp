# Task: Replace SPHINCS+ with a Poseidon2-preimage ZK signature

Status: P1 + P2a + P2b-0 COMPLETE. **P2b-1/2/3 IN PROGRESS** (this session) — the atomic
identity-swap + validity/close list-proof wiring.

Branch: `paymentchannel-delegate`. Threat model: `doc/tasks/poseidon-signature-threat-model.md`.

LOCKED decisions (do not deviate):
1. pk_b DEFERRED to P3. `MemberLeaf` is a PURE RENAME `sphincs_pk_hash` -> `pk_g` (same type,
   same leaf-hash preimage, same registration keccak). No new field.
2. One shared SingleSig/List family for validity (IMSB) and close (IMCH); isolation via message
   domain separation.
3. Validity empty-span = CONDITIONAL verify gated on COMPUTED `final.bp_sig_chain != 0`.
   When non-zero: verify list proof AND assert `C == final.bp_sig_chain`. Also assert
   `initial.bp_sig_chain == 0`. Use `add_proof_target_and_conditionally_verify`.
4. Close folds C' over active slots only (select prev on padding).
5. Exactly ONE IMSB sig per signing block (the bp's; should_verify_sig true only for bp slot).

## Plan (falsifiable steps)

### Phase A — primitive plumbing (foundational, low risk)
- [ ] A1. `key_tree.rs`: rename `MemberLeaf.sphincs_pk_hash` -> `pk_g` (field + target + accessors),
      leaf preimage byte-identical.
- [ ] A2. `channel_registration.rs`: rename `sphincs_pk_hash` -> `pk_g`, keccak preimage identical.
- [ ] A3. `common/channel.rs`: rename all `*sphincs_pubkey_hash*` -> `*pk_g`, preserving prefixes
      (`member_`/`bp_`/`sender_`/`recipient_`/`source_`/`receiver_`/`offending_bp_`). Keccak identical.
- [ ] A4. Ripple renames across close_pis, cancel_close_pis, post_close_claim_pis,
      withdrawal_claim_pis, balance_state, state_update_verifier, channel_tree, constants,
      channel_reg_step/processor, e2e_flow, wallet_core, wasm_wallet, bins.

### Phase B — validity accumulator threading (soundness-critical)
- [ ] B1. `ext_public_state.rs`: add `bp_sig_chain: Bytes32` mirroring `channel_reg_hash_chain`
      end-to-end (struct, target, len, to_u64_vec, from_u64_slice, new/constant/set_witness/
      connect/select/to_vec/from_slice). LEN += BYTES32_LEN.
- [ ] B2. `update_channel_tree.rs`: remove SPHINCS+ verify_circuit + SpxSig plumbing. Keep
      MemberLeaf{pk_g, regev_pk_digest} slot inclusion, IMSB signed_digest recompute, tx_tree_root!=0.
      Only the bp slot signs: fold leaf=leaf_target(signed_digest, bp_pk_g);
      new_bp_sig_chain = should_verify_sig ? chain_step_target(prev, leaf) : prev. bp_pk_g/
      signed_digest are the SAME wires bound to member_pubkeys_root/tx_tree_root. Surface
      prev/new bp_sig_chain in UpdateUserPublicInputs(+Target).
- [ ] B3. `block_step.rs`: thread prev/new bp_sig_chain through ext-state (mirror reg chain).
- [ ] B4. `block_chain_pis.rs` / `block_hash_chain_circuit.rs` / processor: thread; initial=0.
- [ ] B5. `validity_circuit.rs`: conditionally verify ListCircuit proof gated on
      final.bp_sig_chain!=0; assert C==final.bp_sig_chain; assert initial.bp_sig_chain==0.
      ListCircuit vd is a build-time constant.

### Phase C — close wiring (soundness-critical)
- [ ] C1. `close_circuit.rs`: remove per-slot verify_circuit. Recursively verify a ListCircuit proof;
      rebuild C' folding (IMCH state_digest, pk_g_i) over active slots only (select prev on padding);
      assert C'==C; assert pk_g distinctness over active set. Keep member_set_commitment keccak.

### Phase D — registration + e2e + signing
- [ ] D1. Registration: build MemberLeaf{pk_g, regev_pk_digest} from registered pk_g.
- [ ] D2. e2e/signing: replace SPHINCS+ keygen+sign with GoldilocksSecretKey. Per signing block
      produce bp SingleSig proof over IMSB digest; aggregate into one ListCircuit proof threaded into
      validity. For close produce N member SingleSig proofs over IMCH; aggregate into one ListCircuit.
- [ ] D3. Solidity `ChannelSettlementManager.sol`: rename semantics only; keccak byte-identical.

### Phase E — build/test
- [ ] E1. cargo build --release green.
- [ ] E2. channel + validity lib tests + e2e green. (NO Groth16/gnark.)

## STATUS: P2b COMPLETE — implementation + green tests + independent security review PASSED

Independent security review (separate agent, read-only diff vs afd500d): **NO real soundness hole**
within P2b's locked scope. All 8 attack vectors OK; all 5 flagged uncertainties confirmed/dispositioned.
Verified: accumulator ≡ `list_commitment` bit-for-bit; conditional-verify gated on the COMPUTED
`bp_sig_chain` (not a prover flag) with `initial==0` and `C==final` asserted; both old SPHINCS+ bindings
survive (signer ∈ member tree AND signer actually signed the exact domain-separated message, now via the
recursively-verified ListCircuit); close `C'==C` + active-set distinctness + `member_set_commitment`
byte-identical to L1; IMSB/IMCH domain separation prevents cross-consumer replay (A4). `bp_sig_chain` is
bound into `ValidityPublicInputs` (on-chain). Added a greppable `// INVARIANT (single-fold soundness)`
note at the bp-slot assertion per the reviewer's regression-guard recommendation. Tests re-run by the
main agent: all scoped lib modules green + full `cargo test --test e2e` 1/1 (114s).

Phases A–E all done. Lib builds clean; all scoped tests green:
- poseidon_sig 25/25; update_channel_tree 3/3; validity_circuit 1/1; block_step 1/1;
  channel_reg 3/3; channel native 14/14; close_circuit 9/9; e2e_flow 12/12;
  state_update_verifier 9/9; balance_state 8/8; `cargo test --test e2e` 1/1.
- Solidity: forge build clean; reg-preimage + member-set differential tests pass (byte-identical).
- Groth16/gnark fixture tests intentionally NOT run (project rule).

## Soundness uncertainties / pressure points (for separate security review)
1. `bp_member_slot == updating slot` assumption: the circuit asserts (gated on should_verify_sig)
   that the updating slot index == msg_fields.bp_member_slot, relying on the invariant that exactly
   ONE slot updates per block (all slots reference the same channel leaf). If a future block layout
   allowed two distinct channel leaves to update in one block, the single-fold accumulator would
   miss the second signature. CURRENTLY SOUND under the one-channel-leaf-per-block model; flagged.
2. Close C' rebuild uses `select prev on padding` and verifies the ListCircuit unconditionally via
   `_true`. A close always has >=2 active members so C != 0; if member_count could be 0/1 the empty
   list (C==0, no proof) would be unrepresentable — but member_count is range-checked 2..=MAX.
3. The validity gate `final.bp_sig_chain != 0` assumes the empty list commits to exactly
   Bytes32::default(). `list_commitment(&[])` = PoseidonHashOut::default().into() = zero — confirmed
   by `current_bp_sig_chain` over empty events. A (vanishingly unlikely) Poseidon collision to zero
   on a non-empty list would skip verification; standard Poseidon preimage assumption covers this.
4. No new domain separation gap found: IMSB digest (validity) vs IMCH digest (close) differ by their
   keccak domain bytes, and each consumer matches the exact m it computed (A4 holds).
5. pk_b deferred to P3 (LOCKED): MemberLeaf is a pure rename; no two-key binding yet. A11 is a P3
   obligation, explicitly out of scope here.

---

# Phase 3 — Plonky3 BabyBear sender hash-signature + SPHINCS+ removal

Status: DESIGN LOCKED, implementation pending. The channel-tx sender authorization is today a
SPHINCS+ sig verified OFF-CIRCUIT in `wallet_core.rs:593`. P3 moves it to a native Poseidon2-BabyBear
ZK hash-signature and removes SPHINCS+ entirely.

## LOCKED decisions (2026-06-15)
- **Separate bound proof** (NOT same-proof): the sender hash-sig is its OWN Poseidon2-BabyBear STARK
  (the regev channelTxZKP is single-AIR / 128-row-fixed / homogeneous-batch — same-proof integration
  is too invasive). The off-chain verifier requires BOTH the channelTxZKP and the hash-sig proof and
  binds them — atomicity ("a channel-tx is accepted only with a valid owner sig") is verifier-enforced.
- **A11 binding off-chain**: the hash-sig AIR exposes `pk_b` as a public value; the co-signer's
  verifier checks `pk_b` + the sender's regev_pk belong to the SAME registered `MemberLeaf` (MemberTree
  lookup in software). Matches the existing off-chain-verification trust model for channelTxZKP.
- **Use upstream `p3-poseidon2-air@0.5.3`** (confirmed available on crates.io) for the Poseidon2 round
  constraints — do NOT hand-author them. Width-16 BabyBear, the SAME audited instance
  (`default_babybear_poseidon2_16`) used as the regev transcript permutation.
- **Message encoding**: the IMPA digest is 8×u32 (each <2^32) but BabyBear q≈2^31, so `from_u32`
  aliases. Re-decompose the digest into sub-31-bit limbs (16-bit ⇒ ~16 limbs) for INJECTIVE absorption,
  mirroring the existing 16-bit amount-limb workaround (`transfer_stark.rs:662-670`).
- **BabyBear key entropy**: `sk_b` ~9 BabyBear limbs (≥256-bit / 128-bit-PQ, D2). `DOMAIN_PK_B`/
  `DOMAIN_SIG_B` BabyBear domain constants (non-colliding).
- **MemberLeaf** gains `pk_b` now (the deferred field), bound via `member_pubkeys_root` (the verifier's
  membership check reads it). Registration carries `pk_b`.

## Falsifiable steps
- [x] P3-1. `p3-poseidon2-air@0.5.3` integrated; Poseidon2Air PoC proves+verifies via the regev 0.5.3
      batch-stark and matches `default_babybear_poseidon2_16().permute()` bit-for-bit. (commit `049c768`)
- [x] P3-2. Native BabyBear primitive: `sk_b` 9 limbs (all-zero/non-canonical rejected), `pk_b`,
      `sig_b` rate-8 sponge (witness-only), injective 16×16-bit digest decomposition. (commit `049c768`)
- [x] P3-3. `Poseidon2HashSigAir` (binding AIR) — **DONE + security-reviewed (no soundness hole)**.
      Vendor route (composition needed extra binding-tail columns; the upstream whole-row `eval` /
      `Poseidon2Cols` fixed width can't hold them): `vendor/p3-poseidon2-air-0.5.3` with a
      VISIBILITY-ONLY diff (`pub(crate) fn eval` → `pub fn eval`, audited body byte-for-byte upstream).
      Row = `[Poseidon2Cols | selectors(6)+sk(9)]`; calls the audited `eval` per row, adds one-hot-gated
      cross-row binding (pk input/output, sponge chaining over all 16 m-limbs, sk broadcast). sk≠0 is
      OUT of the AIR (keygen/verifier, locked). Independent review verdict: selector schedule forced,
      all PVs bound, degree-3 override correct (actual==3, not attacker-controlled), padding non-forging,
      native≡in-circuit. Hardening applied from review: `verify_hash_sig` degree_bits/height shape check
      (mirrors `verify_one`); +3 constraint-level negative tests (selector-tamper, sk-not-broadcast,
      chaining-tamper). 20/20 `regev::hash_sig` tests green.
      Review notes carried to P3-5: production verify path must use `default_config` (84 queries), not
      `test_config` (8 queries ≈ 8-bit, tests only); `max_constraint_degree==Some(3)` is load-bearing
      (release-mode guard is `debug_assert`) — the prove/verify + native-equality tests are the sentinel.
- [x] P3-4. `ChannelTx`: `sender_signature` → `sender_hash_sig: Vec<u8>` + `sender_pk_b: Bytes32`
      (keep `sender_pk_g`). IMPA `signing_digest` preimage unchanged. (Chunk 1)
- [~] P3-5. Off-chain verifier `verify_channel_tx_sender_hash_sig` (wallet_core): requires the hash-sig,
      verifies it, binds `m == decompose(channelTx digest)` and `pk_b == sender_pk_b`. **⚠ A11 BINDING
      UNSOUND — MUST FIX in Chunk 2 (P4):** `registered_pk_b` is read from the UNAUTHENTICATED
      `payload.members[slot].pk_b` (the wallet's `member_pubkeys_root` is keccak-over-pk_g-only and does
      NOT commit pk_b), and `verify_channel_tx_sender_hash_sig` is passed `sender.regev_pk` for both the
      registered AND sender regev_pk (check trivial). An attacker can set both `sender_pk_b` and
      `members[slot].pk_b` to their own key and pass. The validity-LAYER pk_b binding (member_pubkeys_root
      Poseidon 3-field leaf + L1 keccak reg chain) IS sound; the gap is wallet-only.
- [x] P3-6. `MemberLeaf{pk_g, pk_b, regev_pk_digest}` + registration (`pk_b` in the keccak reg-chain
      preimage, `CHANNEL_REG_PREIMAGE_U32_LEN` updated, Rust↔Solidity differential re-pinned + PASS) +
      `update_channel_tree` 3-field leaf (`bp_pk_b` witness). Solidity `registerChannel` takes `pkBs`. (Chunk 1)
- [ ] P3-7. Remove off-circuit SPHINCS+. **BLOCKED → expanded to P4:** the wallet uses SPHINCS+ for
      member channel-STATE co-signing (`sign_state`/`verify_all_signatures` over IMCH), the Goldilocks
      key path. Full removal needs the wallet co-signing reworked to Goldilocks (see P4).
- [ ] P3-8. Tests: e2e fixture generators must emit `member_pk_bs` (forge E2E callers parse it but the
      JSON fixtures + Rust generators don't emit it yet → regenerate). WASM green.
- [ ] P3-9. detail2 / detail2-implementation-notes: record the full signature-scheme delta.
- [ ] P3-10. Separate security review + attacker pass.

## Phase 4 (this session, user-approved scope expansion) — wallet Goldilocks co-signing + SPHINCS+ removal
- [x] **P4-1 DONE.** Wallet `member_pubkeys_root` (`src/wallet_core.rs`) is now the canonical Poseidon
      `MemberTree` root over `MemberLeaf{pk_g, pk_b, regev_pk_digest}` (matching circuit/registration),
      re-bound in `verify_snapshot` AND independently in `verify_send_transition` (the payload has its
      own record/members). The A11 check reads `pk_b` from this AUTHENTICATED set; regev_pk double-use
      fixed (registered = member-root-anchored slot key; sender's claimed = the array fed to the E-1
      witness, re-bound to `regev_pk_root` by `InChannelTransferUpdateWitness::verify`). Negative test
      `p4_1_attacker_pk_b_swap_is_rejected` (tests/wallet_core_e2e.rs): attacker pk_b + self-consistent
      forged hash-sig is REJECTED at the member-root anchoring check. Both wallet_core_e2e tests green.
- [ ] **P4-1 (soundness, top priority): fix the P3-5 wallet A11 gap.** Make the wallet's registered
      member set commit `pk_b` (e.g. the wallet `member_pubkeys_root` becomes the Poseidon 3-field leaf
      root matching the circuit, or pk_b is otherwise bound by `verify_snapshot`), so the A11 check reads
      `pk_b` from an AUTHENTICATED source, not the raw payload. Fix the regev_pk double-use (pass the
      sender's actual regev_pk vs the registered one). Add a payload-tamper negative test.
- [x] P4-2 DONE (wallet co-signing → Goldilocks). `MemberKeys.signing_key: GoldilocksSecretKey`
      (replaces `kp: SpxKeyPair`); kept `baby_key`. `sign_state` produces a `SingleSigCircuit` proof
      over the IMCH `signing_digest` (proof bytes = the `MemberSignature.signature`); shared circuit
      via `OnceLock`. `verify_all_signatures` verifies each member's proof INDIVIDUALLY, binding the
      proof's `[pk_g(8), m(8)]` PIs to `record.member_pk_gs[slot]` + the recomputed digest (pk_g ∈
      member set). `MemberInfo.sphincs_pk_hex` → `pk_g: Bytes32`. wasm_wallet/channel_member updated
      (Identity/GenesisContribution/BrowserContribution emit `pk_g`, sign_state `?`/`.expect`).
      `sign_state` now returns `WResult<MemberSignature>`. wallet_core_e2e 2/2 green (0.08s).
- [ ] P4-2. Wallet channel-state co-signing → Goldilocks: each member produces a Goldilocks
      `SingleSigCircuit` proof over the `ChannelState` IMCH digest (= their signature); the wallet's
      `verify_all_signatures` verifies each proof individually (+ pk_g ∈ member set). The on-chain
      aggregation into the list proof (close/validity, slot order) is the existing P2b path. Replace
      `MemberKeys.kp` (SPHINCS+) with `GoldilocksSecretKey`.
- [x] P4-3 DONE. Removed `sphincsplus-{circuits,params,poseidon}` from Cargo.toml (gone from
      Cargo.lock); deleted `src/circuits/test_utils/sphincs_sign.rs` (+ mod decl) and
      `tests/sphincs_timing.rs`; deleted `sphincs_sig.rs` after MOVING `SmallBlockMessageFields`/
      `SmallBlockMessageFieldsTarget` (+ its differential test) into new
      `block_hash_chain/small_block_message.rs` and dropping the dead `SpxSigWitness`/`SpxSigTargets`/
      `SPX_*` residue. All `sphincs_sig::` import sites repointed. grep for
      sphincsplus/SpxSig/SpxKeyPair/verify_sphincs/sphincs_sign/sphincs_keygen → ZERO active refs
      (only historical prose in wallet_core.rs:179). Native lib + bins + tests build clean.
- [ ] P4-3. Remove SPHINCS+ entirely: deps `sphincsplus-{circuits,params,poseidon}`,
      `test_utils/sphincs_sign.rs`, `SpxSig*` residue (move `SmallBlockMessageFields` out if still used);
      grep → zero refs. Native + WASM build clean.
- [~] P4-4 IN PROGRESS. Generators emit `member_pk_bs` (`MemberFixture` in generate_c2c_fixture.rs +
      generate_withdrawal_fixture.rs). Fixed STALE forge JSON keys `.member_sphincs_pubkey_hashes` →
      `.member_pk_gs` (C2CFullE2E, C2CBlockHash, ReclaimStake, WithdrawNativeE2E — predated the P2b
      rename; fixtures had neither key). Regenerated lifecycle.json/withdrawal_* (plain). WithdrawNativeE2E
      6/6 PASS. Rust `cargo test --test e2e` 1/1 PASS. c2c_* regen IN PROGRESS. close_* needs
      WD_RECIPIENT=0xb83a993604b0c7438F5Ce1D5a1e1787D34CB5C96 (fresh CloseManagerAddr — rollup initcode
      changed) WD_OUT_PREFIX=close_. mle_fixture.json (generate_e2e_fixture) has no MemberFixture (no regen
      needed for member_pk_bs).
- [x] P4-4 DONE. All fixtures regenerated with `member_pk_bs`: lifecycle/withdrawal (plain),
      c2c_* (generate_c2c_fixture), close_* (WD_RECIPIENT=0xb83a99...5C96 WD_OUT_PREFIX=close_). Stale
      forge JSON keys `.member_sphincs_pubkey_hashes` → `.member_pk_gs` fixed (4 tests). FULL FORGE
      SUITE: 99/99 pass, 0 fail, 0 skip (Groth16/gnark not run, project rule). Rust `cargo test --test
      e2e` 1/1. WASM lib `cargo check --target wasm32` clean.
- [ ] P4-4. e2e fixture regeneration (`member_pk_bs`); full Rust e2e + forge E2E green; WASM green.
- [ ] P4-5. Separate security review + attacker pass (A11 end-to-end, wallet co-sign, SPHINCS+ gone).

## New threat considerations (P3)
- **Message-encoding injectivity** (BabyBear u32 aliasing) — the new A-item; the sub-31-bit
  re-decomposition must be injective and bound into both the hash-sig PVs and the channelTx digest.
- **Separate-proof binding**: the verifier MUST require the hash-sig proof AND bind its `m` to the
  exact channelTx digest, else the balance-reduction proof is accepted without authorization.
- **A11 off-chain dependency**: security now relies on every co-signer running the membership check;
  document this as an explicit trust assumption.

---

## FINAL STATUS — P4 COMPLETE (2026-06-15), migration P1→P4 done

- **P4-1 fully closed (member-root + caller-layer).** The implementation agent made the wallet
  `member_pubkeys_root` the canonical Poseidon 3-field `MemberLeaf` root (so `pk_b` is authenticated,
  not read from a raw payload). The independent P4 security review then found a RESIDUAL caller-layer
  gap (the A11 check ran against `payload.record`, not the session's trusted record). Fixed here:
  `verify_send_transition` now takes `trusted_record: &ChannelRecord` and rejects unless
  `payload.record.signing_digest() == trusted_record.signing_digest()` (callers pass
  `snapshot.record`). The cosmetic regev self-check was removed (regev is authenticated via the
  member-root anchoring + the E-1 statement). Negative tests: `p4_1_attacker_pk_b_swap_is_rejected`
  (rejects at member_pubkeys_root) + `p4_1_foreign_self_consistent_record_is_rejected` (rejects at the
  trusted-record binding). Both green.
- **P4-2/3/4 done**: wallet co-signing = per-member Goldilocks `SingleSigCircuit` proof verified
  individually; SPHINCS+ fully removed (deps + sphincs_sign.rs + sphincs_sig.rs gone, 0 active refs;
  `SmallBlockMessageFields` moved to `small_block_message.rs`); e2e fixtures regenerated with
  `member_pk_bs`.
- **Verified**: full forge 99/99 (agent); Rust `cargo test --test e2e` 1/1; `wallet_core_e2e` 3/3;
  all test targets compile; WASM lib check clean; SPHINCS+ grep = 0 active + Cargo.lock 0.
- **Independent P4 security review**: NO real fund-theft/forgery hole; P4-1 gap closed (member-root +
  the trusted-record fix above); end-to-end A11 (wallet → MemberLeaf Poseidon root → L1 keccak reg
  chain) binds the same pk_b at every layer; co-signing forgery paths (reuse/skip/wrong-state) rejected.
- **Remaining (non-blocking)**: P4-5 broader attacker pass if desired; detail2 doc delta (P3-9). The
  off-chain A11 trust assumption (every co-signer runs the check) is LOCKED/documented.
