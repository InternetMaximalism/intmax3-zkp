# A1 fix — replace ALL 6 channel-settlement ZK stubs with real on-chain WHIR verification

Status: **DECIDED — implementing Phase A (close intent).**

## FINAL ARCHITECTURE DECISION (user, 2026-06-17)
- **plonky2 ONLY.** All 6 statements reduce to (a) signature verification and (b) lattice
  (Regev) encrypted-balance verification — both expressible in plonky2. Unify on the SINGLE
  existing on-chain verifier `@mle/MleVerifier.sol` (Rail A, gas-optimized, proven by
  validity/withdrawal). No plonky3/Spartan-WHIR rail. Lowest new attack surface (CLAUDE.md).
- **Rail B (plonky3/sol-spartan-whir) is DROPPED/DEFERRED** — re-decide only if a plonky2
  re-expression of the Regev decryption statement proves infeasible (revisit after Phase A).
- **Build order:** Phase A = `verifyCloseIntent` real via Rail A (close circuit EXISTS) NOW.
  The other 5 statements become plonky2 circuits on the SAME `@mle` rail in later phases
  (detailed design after Phase A). Heavy proving: USER runs after impl.

Scope: FULL (user directive 2026-06-17) — all 6 `verify*` made real, ALL via plonky2 `@mle`.
Spec authority: detail2.md (TOP priority) §D4 / §E-3 / §F-3 / §H-2 / §H-3, abstract2.md §2.4 / §3.5.
Audit ref: A1 — `ChannelSettlementVerifier._matches` is a tautological keccak-equality stub.

## VERIFIER-RAIL INVENTORY (measured 2026-06-17)
- Rail A — plonky2 WHIR (intmax, gas-optimized): `contracts/lib/polygon-plonky2/mle/contracts/src/`
  (`@mle/MleVerifier.sol` + SpongefishWhir + Sumcheck). IN-REPO, proven (validity/withdrawal).
  Verifies a Goldilocks→BN254 `WrapperCircuit` proof committed via `plonky2_mle`. ~11M gas/verify.
- Rail B — 31-bit-field WHIR on EVM: **EXISTS as research-grade third-party Solidity (privacy-ethereum)**,
  corrected 2026-06-17 after the initial scan missed it:
  - `privacy-ethereum/sol-whir` — generic WHIR PCS opening verifier on EVM (experimental; no release/audit).
  - `privacy-ethereum/sol-spartan-whir` — Solidity verifier for the **Spartan-WHIR SNARK over KoalaBear**
    (p = 2^31 − 2^24 + 1), verifies **R1CS via Spartan + WHIR**. Quintic ext, ~100-bit; ~4.77M exec gas,
    ~54KB calldata, fixed `num_variables = 2^22`; EIP-170 split needed. Rust source of truth = `spartan-whir`
    + `spartan-whir-export`. No audit.
  - upstream `Plonky3/Plonky3` HAS `p3-whir` (v0.5.1) + `bn254` (Rust), but **no `.sol`** (Rust-only).
  - intmax Regev STARKs today = **FRI over BabyBear** (`p3-fri`, regv-plonky3 3b17b8e), verified IN-PROCESS.
  ⇒ Rail B is VIABLE but requires: (1) re-express the Regev/claim statements as **R1CS** (not AIR);
  (2) reconcile **BabyBear→KoalaBear** field (Regev `REGEV_Q` is BabyBear — touches the noise-budget
  analysis §B-3/§K-3); (3) integrate a **research-grade, unaudited** verifier into a value path
  (CLAUDE.md "use audited libraries / no new attack surface" tension — must be surfaced & approved).

## STATEMENT → RAIL → READINESS
| verify* | statement | rail | backing proof today | readiness |
|---|---|---|---|---|
| verifyCloseIntent | members signed final state; signing keys ∈ memberSetCommitment | A (plonky2) | `ChannelCloseCircuit` EXISTS (close_circuit.rs) | **READY to wrap+wire** |
| verifyWithdrawalClaim | own H1 slot ct decrypts to public `amount` (§E-3) | B (plonky3) | `DecryptionAir` EXISTS (FRI, in-process) | needs Rail B + WHIR-wrap |
| verifyPostCloseClaim | late inbound ct decrypts to public `amount` (§3.5.5/E-3) | B (plonky3) | `DecryptionAir` EXISTS (FRI, in-process) | needs Rail B + WHIR-wrap |
| verifyCancelClose | a later signed InterChannelTx revives the channel | C | **NO circuit** (data only) | design decision needed |
| verifySpecialClose | BP signed a small block but missed finalize window | C | **NO circuit/PI** (liveness fault) | likely on-chain-data, not ZK |
| verifyLateOutgoingDebit | a signed outgoing debit was omitted from close | C | **NO circuit/PI** (data only) | design decision needed |

## 0. Scope decision (derived from the code, not assumed)

- Only the **close circuit** (`src/circuits/channel/close_circuit.rs`, `PoseidonGoldilocksConfig`,
  D=2) is a real plonky2 recursion circuit ⇒ it can be `WrapperCircuit`-wrapped + MLE/WHIR-proven
  with the EXISTING `src/utils/mle_prover.rs` recipe (same as validity/withdrawal) and verified
  on-chain by `@mle/MleVerifier.sol`.
- `withdrawal_claim_pis.rs` / `post_close_claim_pis.rs` / `cancel_close_pis.rs` are **PI structs
  with NO plonky2 circuit**. withdrawClaimZKP (§E-3) is a **Plonky3 Regev STARK**
  (`transfer_stark.rs::prove_withdraw_claim`), verified in-process — there is NO on-chain verifier
  for it. `verifySpecialClose` / `verifyLateOutgoingDebit` are "additional defenses outside
  abstract2" (detail2 §H-3).
- THEREFORE the detail2-faithful, on-chain-feasible fix for A1 is: **make `verifyCloseIntent`
  real**. The only path into the value-bearing `Closed` state is
  `submitCloseIntent → _checkCloseProof → verifyCloseIntent → finalizeClose` (verified by grep),
  so this is the correct chokepoint. The other `verify*` stubs stay as-is (gated by the
  `receivedChannelFunds` ETH ceiling) and are explicitly out of scope — documented, not silently.

## 1. Threat model (close-intent path)

Adversary = a single channel member (or the BP) who wants to (a) close on a stale/forged final
state, (b) close with non-member signing keys, (c) replay another channel's close, (d) win the
challenge-replace race with a state nobody signed, (e) bypass verification entirely.

Mitigations the fix must guarantee (all confirmed against an attacker-subagent review):
- T-A stale/forged state: bind PI limbs `final_state_version`(67–68), `final_epoch`(3–4),
  `final_settled_tx_chain`(69–76), `final_balance_state_h1`(17–24), `final_channel_state_digest`(9–16).
- T-B non-member keys: bind `member_set_commitment`(77–84) + `member_count`(85); L1
  re-reconciles against `registeredMemberSetCommitment()` (already wired in the manager).
- T-C cross-channel replay: bind `channel_id`(limb 0).
- T-D challenge race: ordering keys `(final_epoch, final_state_version)` are in the bound set
  (subset of T-A). NOTE residual: stub `cancelClose`/`lateOutgoingDebit` can still reset a real
  pendingClose — in-scope-by-design, documented as residual.
- T-E verification bypass: NO `degreeBits==0 ⇒ return true` seam; revert until VK set; set-once.

### Cryptographic invariant checklist (must all hold)
- [ ] `MleProof.publicInputs.length == CHANNEL_CLOSE_PUBLIC_INPUTS_LEN (87)` asserted on-chain.
- [ ] All 87 limbs bound **limb-by-limb, strict equality, no masking**; reject any limb ≥ 2³².
      (The withdrawal-style 8-limb `_limbsMatchBytes32(pi,0,closePIHash)` is WRONG here — the
      close circuit registers 87 RAW limbs, not a keccak. `WrapperCircuit` re-registers verbatim.)
- [ ] Expected 87-limb vector recomputed on-chain from `CloseProofFields` (+ recomputed
      `memberSetCommitment` + `closeIntentDigest`) in the SAME limb order as
      `ChannelClosePublicInputs::to_u64_vec()` — pin with a Rust↔Solidity golden vector.
- [ ] Close VK is independent + complete: own `degreeBits`, `preprocessedRoot`, `gatesDigest`,
      `numConstants`, `numRoutedWires`, `kIs`, `subgroupGenPowers`, WHIR params, protocolId,
      sessionId. NOT shared with the withdrawal/validity WHIR storage.
- [ ] `MleVerifier.verify` already absorbs `circuitDigest` + VK-binds `preprocessedRoot` +
      checks `gatesDigest` ⇒ cross-circuit replay (validity/withdrawal proof as close) is blocked,
      CONDITIONAL on the close VK carrying the real close-circuit digests.
- [ ] Set-once deployer latch; `degreeBits > 0` enforced at init; revert before init.
- [ ] `closePIHash` is no longer a TRUSTED equality target — replace `closePIHash + _matches`,
      do not keep both.

## 2. Implementation phases (falsifiable)

### Phase R (Rust) — produce a real close-circuit MLE proof + VK
- [ ] R1. Add a close `WrapperCircuit` + MLE proving path (reuse `wrapper.rs` + `mle_prover.rs`;
      mirror `generate_withdrawal_fixture.rs`). New bin `generate_close_fixture.rs` (or extend the
      lifecycle generator) that: builds the close proof at the production member count, wraps it,
      `setup_mle_vk`, `prove_with_mle`, `verify_mle_proof`, and exports (a) the MLE proof JSON and
      (b) the close VK params JSON (degreeBits/preprocessedRoot/gatesDigest/kIs/subgroupGenPowers/
      whirParams/protocolId/sessionId) for `initializeCloseVk`.
- [ ] R2. Golden vector: a Rust test emitting `ChannelClosePublicInputs::to_u64_vec()` for a known
      witness, asserted byte-identical to the Solidity expected-limb builder
      (`close_intent_public_inputs_match_solidity_shared_vector`).
- HEAVY COMPUTE: R1 runs full close proving + MLE wrap (degree 2^19+, minutes, multi-GB).
  **Requires explicit user permission to run.**

### Phase S (Solidity) — stateful close verifier
- [ ] S1. `ChannelSettlementVerifier` imports `@mle/MleVerifier.sol`; add storage for the close VK
      + WHIR params; `initializeCloseVk(...)` (deployer set-once, degreeBits>0) mirroring
      `IntmaxRollup.initializeWithdrawalVk`.
- [ ] S2. Add `_expectedCloseLimbs(CloseProofFields) -> uint256[87]` building the limb vector in
      `to_u64_vec()` order. Add `_bindLimbsStrict(pi, expected)` (length==87, exact eq, reject ≥2³²).
- [ ] S3. Rewrite `verifyCloseIntent(fields, MleVerifier.MleProof)` ⇒ bind all 87 limbs, then
      `MleVerifier.verify(closeVk, proof)`; revert if VK unset. Remove the `_matches` close path.
- [ ] S4. Update `IChannelSettlementVerifier` + `ChannelSettlementManager.submitCloseIntent` /
      `_checkCloseProof` to pass an `MleVerifier.MleProof` (calldata) instead of `bytes`.
- [ ] S5. EIP-170 check: measure `ChannelSettlementVerifier` bytecode after adding MLE verify; if
      over 24,576 B, split the MLE-verify into a library/separate verifier (decision point).

### Phase T (tests) — real + adversarial
- [ ] T1. `ChannelSettlementManager.t.sol` / `CloseLifecycleE2E.t.sol`: feed the REAL close MLE
      fixture; positive close succeeds.
- [ ] T2. NEGATIVES (must reject): tampered `final_state_version` limb; forged
      `member_set_commitment` (non-member keys); wrong `channel_id`; a withdrawal/validity MLE proof
      replayed as a close proof (VK/gatesDigest mismatch); proof with a limb ≥ 2³²; unset VK reverts.
- [ ] T3. Rust↔Solidity golden vector test (R2) passes.

## 3. Out of scope (explicit, documented residuals)
- `verifyWithdrawalClaim` / `verifyPostCloseClaim` / `verifyCancelClose` / `verifySpecialClose` /
  `verifyLateOutgoingDebit` stay `_matches` stubs (no on-chain verifier exists for their proof
  systems). Intra-channel mis-allocation among a channel's own members remains the accepted
  residual; cross-channel theft stays blocked by `receivedChannelFunds`.
- Stub `cancelClose`/`lateOutgoingDebit` can still reset a real pendingClose (T-D residual).
- manager→verifier deployment wiring trust (LOW-2) unchanged.

## 4. Outcome / assessment

### Phase A — DONE & independently security-reviewed SOUND (2026-06-18)
Implementer + a SEPARATE adversarial reviewer (CLAUDE.md §2). Verdict: no blocking soundness/binding holes.
- Tautology removed: `verifyCloseIntent` no longer uses `closePIHash`+`_matches`; only acceptance route is
  strict 87-limb bind + `MleVerifier.verify`. `closePIHash` survives only as a pure helper for the 5 stubs.
- All 87 raw Goldilocks limbs bound limb-by-limb, strict eq, no mask, reject ≥2³², `length==87`, in exact
  `to_u64_vec()` order (dual golden vectors pin Rust↔Solidity, incl. endianness + count packing).
- `closeIntentDigest` (limbs 57..64) recomputed byte-identical across circuit / native / Solidity
  (golden vector `0xa2679bf7…`). channelId(0), finalStateVersion(67..68), finalSettledTxChain(69..76),
  memberSetCommitment(77..84), member/delegate count(85/86) all bound.
- `initializeCloseVk`: deployer-only, set-once latch, degreeBits>0, NO disable seam, revert-until-set,
  MleVerifier address pinned atomically with the VK.
- Cross-circuit replay blocked by MleVerifier preprocessedRoot/gatesDigest/circuitDigest binding
  (conditional on deployer initializing closeVk with the real close-circuit values — accepted deploy-integrity).
- EIP-170: ChannelSettlementVerifier runtime = 13,166 B (delegates crypto to deployed MleVerifier; no split).
- Files: `ChannelSettlementVerifier.sol`, `ChannelSettlementManager.sol` (bytes→MleProof I/F),
  `close_pis.rs` (+golden), `close_circuit.rs` (fixture builders feature-gated `close-fixture-bin`),
  new `src/bin/generate_close_fixture.rs`, `Cargo.toml`, `CloseTestLib.sol` (MockMleVerifier), tests.
- Compiles (`cargo check` ±feature; `forge build`); 109 contract tests pass.

### OPEN follow-ups
- **MEDIUM (test gap, non-blocking):** the real Solidity `MleVerifier` verifying a REAL close-circuit proof
  through `verifyCloseIntent` is UNTESTED — `CloseLifecycleE2E` self-skips because the close fixture and the
  lifecycle (withdrawal) fixture come from two generators with mismatched member sets / freeze nonce. The two
  halves are tested independently. FIX: co-generate a matching close+lifecycle fixture pair (same member keys,
  freeze_nonce=1) so the integration runs in CI before mainnet.
- **USER ACTION (heavy proving):** run `cargo run --release --features close-fixture-bin --bin generate_close_fixture`
  to produce `contracts/test/data/close_intent_mle.json` (+ `close_intent.json`).
- **Minor:** rejection signal asymmetry — `_bindCloseLimbsStrict` mismatch reverts with a raw string while a
  crypto-false yields `InvalidCloseProof`; both reject safely (monitoring nuance only).

### Phases B / C — PENDING (per locked decision: all plonky2, on the same @mle rail)
- B: verifyWithdrawalClaim, verifyPostCloseClaim (Regev decryption §E-3 as plonky2 circuits).
- C: verifyCancelClose, verifySpecialClose, verifyLateOutgoingDebit (signature/inclusion as plonky2 circuits).
