# Task: Replace SPHINCS+ with a Poseidon2-preimage ZK signature

Status: P1 + P2a + P2b-0 COMPLETE. **P2b-1/2/3 IN PROGRESS** (this session) — the atomic
identity-swap + validity/close list-proof wiring.

Branch: `paymentchannel-delegate`. Threat model: `tasks/poseidon-signature-threat-model.md`.

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
- [ ] **P4-1 (soundness, top priority): fix the P3-5 wallet A11 gap.** Make the wallet's registered
      member set commit `pk_b` (e.g. the wallet `member_pubkeys_root` becomes the Poseidon 3-field leaf
      root matching the circuit, or pk_b is otherwise bound by `verify_snapshot`), so the A11 check reads
      `pk_b` from an AUTHENTICATED source, not the raw payload. Fix the regev_pk double-use (pass the
      sender's actual regev_pk vs the registered one). Add a payload-tamper negative test.
- [ ] P4-2. Wallet channel-state co-signing → Goldilocks: each member produces a Goldilocks
      `SingleSigCircuit` proof over the `ChannelState` IMCH digest (= their signature); the wallet's
      `verify_all_signatures` verifies each proof individually (+ pk_g ∈ member set). The on-chain
      aggregation into the list proof (close/validity, slot order) is the existing P2b path. Replace
      `MemberKeys.kp` (SPHINCS+) with `GoldilocksSecretKey`.
- [ ] P4-3. Remove SPHINCS+ entirely: deps `sphincsplus-{circuits,params,poseidon}`,
      `test_utils/sphincs_sign.rs`, `SpxSig*` residue (move `SmallBlockMessageFields` out if still used);
      grep → zero refs. Native + WASM build clean.
- [ ] P4-4. e2e fixture regeneration (`member_pk_bs`); full Rust e2e + forge E2E green; WASM green.
- [ ] P4-5. Separate security review + attacker pass (A11 end-to-end, wallet co-sign, SPHINCS+ gone).

## New threat considerations (P3)
- **Message-encoding injectivity** (BabyBear u32 aliasing) — the new A-item; the sub-31-bit
  re-decomposition must be injective and bound into both the hash-sig PVs and the channelTx digest.
- **Separate-proof binding**: the verifier MUST require the hash-sig proof AND bind its `m` to the
  exact channelTx digest, else the balance-reduction proof is accepted without authorization.
- **A11 off-chain dependency**: security now relies on every co-signer running the membership check;
  document this as an explicit trust assumption.
