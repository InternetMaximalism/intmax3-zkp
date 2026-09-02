# Multi-token channels (≤10 per channel) — implementation plan

Authoritative design: detail2.md §N. Threat model: doc/tasks/multitoken-threat-model.md
(TM-1..TM-15 — cited per item below). Status: PLAN ONLY, no implementation started.
Owner decisions fixed 2026-07-27 (§N preamble). v3 testnet resets — no migration work.

Gate on every phase: a fresh attacker-subagent pass over the phase's actual diff before merge
(CLAUDE.md §Adversarial Thinking); implementation and security review by SEPARATE subagents.

## Phase 0 — Lean model generalization (before any Rust)

NOTE (2026-07-27): implemented as NEW files `ChannelSafetyMT.lean` (doc/architecture-audit) and
`Zkp/Contracts/ChannelSettlementManagerMT.lean` (doc/audit/zkp) rather than in-place edits — the
single-token baselines stay intact as the audit record of the deployed code, and reviewers diff
MT against them side by side.

- [x] Channel model (`ChannelSafetyMT.lean`): `EncBalanceStateMT : Member → Fin 10 → Ct`;
      per-token `ValidEncStateMT` (non-negativity + `total t = provenTotal t` over ALL 10 slots);
      `TransferProvenMT` + preservation + frame theorems (TM-2 analogue).
- [x] Batch model (same file, TM-14): `BatchTxMT.tokenSlot`; `batchMT_preserves_validity` /
      `batchMT_conserves_total` / `batchMT_step_eq_seq`; mixed-token frame `batchMT_frame`;
      R1 generalized to distinct (sender, token) pairs.
- [x] C2C (TM-6): `BulkChannelUpdateMT` carries BASE token_index; `ResolvesMT` per-side registry
      resolution; cross-channel conservation + mis-resolution counterexample.
- [x] `L1DepositImportVerifiedMT` + per-token import conservation — TM-7.
- [x] Manager model (`ChannelSettlementManagerMT.lean`): per-base-token CapInv;
      claim/pull/pullCredit preserve cap; NO-CROSS-TOKEN frame theorems — TM-1, TM-3.
- [x] Registry injectivity: `RegistryInjective` (active prefix) +
      `tokenRegister_preserves_injectivity` (freshness = the in-circuit duplicate check) — TM-1.
- [x] Security-review MAJOR fixes (review 2026-07-27, gate for Phase 0 close):
      M1 `c2cMT_conservation_base` — `baseTotal`-level C2C conservation with load-bearing
      ResolvesMT + injectivity (TM-6); M2 deposit-import leg (c) registry clause +
      `l1_depositMT_baseTotal` (TM-7); M3 `execMT_payout_ceiling` — Σ payouts ≤ received per
      token, machine-checked over ARBITRARY op traces incl. adversarial mints (TM-3); M4 faithful
      §N-6 quote + unmodeled-variable scope note; M5 `InactiveZero` + `step_preserves_inactiveZero`
      + `tokenRegister_fresh_slot_zero` (TM-8 fail-close); m6 mixed-token batch witness (same
      member debits two tokens); m7 out-of-scope disclosure list.
- [x] Re-review by the security-review agent: ALL findings VERIFIED-FIXED, hypotheses verified
      load-bearing in the proof terms; no property lost; kernel-only axioms. Verdict: fit to
      close. Residual cosmetic nits (sampleC2C_conservation_base instantiation, §7 docstring
      cross-ref) folded in post-verdict.

**PHASE 0 COMPLETE (2026-07-27).** Artifacts: doc/architecture-audit/ChannelSafetyMT.lean
(~1900 lines) + lakefile lib entry; doc/audit/zkp/Zkp/Contracts/ChannelSettlementManagerMT.lean
+ Zkp.lean import. Both projects build clean, zero sorry, axioms = propext/Quot.sound only.

Deferred out of the Phase 0 model (disclosed; do NOT assume Lean coverage): settledChain /
hash-chain step lemmas (cross-batch nullifier story), per-(slot,token) pending_adds (TM-13),
claim nullifiers (TM-5), rollup-side `escrowed[t]` ceiling (TM-1 layer b), refresh transitions,
H1 hashing / signatures / close game.

## Phase 1 — Rust core types (src/common)

- [ ] `constants.rs`: `MAX_CHANNEL_TOKENS = 10`; new domain constants (slot-leaf v2, H1-header
      v2, IMPA_V2, IMLD_V2, IMCW_V2, E-2 PI domain, TFD) + §G-2 registration + non-collision
      test — TM-15.
- [ ] `balance_state.rs`: `enc_balances`/`pending_adds` gain the token dimension;
      `token_registry: [u32; 10]` + `token_count: u8` in the struct AND the H1 header preimage
      (26→37 elems, fixed width) — TM-9; leaf v2 (103 elems, all leaves incl. padding) — §N-2;
      canonical zero-ct digest constant; `validate()` fail-closed per (slot, token): zero digest +
      `pending_adds == 0` for `t >= token_count`, all 10 counters ≤ 64, `1 ≤ token_count ≤ 10` —
      TM-8, TM-13. Sparse storage allowed; hash layout always full width.
- [ ] `channel.rs`: `ChannelTx.token_slot` + IMPA-v2 preimage (own limb, no bit-packing) — TM-2,
      TM-15; `ChannelFund.amounts[10]`; `token_funds_digest` (fixed-width keccak) — TM-11;
      `l1_deposit_import_digest` v2 — TM-7; claim nullifier v2 keyed
      `(close_intent, slot_regev_pk_digest, token_slot)` — NEVER `member_pk_g` — TM-5;
      `ChannelTransitionKind::TokenRegister` with in-verifier injectivity + append-only checks —
      TM-1.
- [ ] Unit tests: header/leaf preimage width goldens; digest aliasing negatives (packed vs
      own-limb); registry duplicate/append-at-wrong-index/reorder negatives.

### Phase 1 status (2026-07-27)

- [x] Implementation landed (see report in session): constants + 7 domain constants w/
      43-domain non-collision test; balance_state token dimension (leaf 104 elems — recipient is
      5 limbs, §N-2 corrected from 103; header 37), validate() fail-close, TokenRegister
      apply/verify; channel.rs IMPA-v2/TFD/IMLD-v2/nullifier-v2/ChannelFund.amounts;
      per-token binding triple in InChannelTransferUpdateWitness (token_slot==0 gate,
      fail-closed); 39 SECURITY(multitoken-phase2) markers; compile-green, targeted tests green.
- [x] Security review (separate agent): no CRITICAL; implementer deviations confirmed sound
      (IMCH/IMCI in-place widening ACCEPTED — single message type per domain, keccak CR across
      widths, v3 reset; IMCK post-close nullifier non-reversioning ACCEPTED with Phase 2
      re-check obligation below).
- [x] Review MAJOR fixes: M1 registry/token_count immutability equality in
      verify_balance_state_common (all six transition kinds) + validate()-clean negative tests;
      M2 wasm32 build fixed (three sites, markers); M3 35 proving tests ignore-gated
      (attribute-only; native pk_g-regression coverage confirmed un-gated); MINORs 4-7.
- [x] Targeted re-review: ALL VERIFIED-FIXED; fix round added checks only, nothing weakened;
      wasm32 check re-run green; file set unchanged. Verdict: fit to close.

**PHASE 1 COMPLETE (2026-07-27).** ~2,500 insertions / 34 files, compile-green (native + wasm32
lib), targeted suites green, 36 proving tests ignore-gated pending Phase 2, 40+
SECURITY(multitoken-phase2) markers. Phase 2 attacker pass must revisit: (a) TokenRegister
bypass design at the verify_balance_state_common SECURITY comment; (b) IMCK one-token-per-C2C-
descriptor obligation; (c) re-enabling the gated proving tests + the two ignored-not-repinned
cross-check vectors (IMCI Solidity shared vector, h1 gadget parity).

Carried obligations from the Phase 1 review:
- Phase 2: IMCK re-check — C2C descriptor must stay one-token-per-descriptor structurally, or
  the unversioned post-close nullifier collapses multi-token bundles under one incoming_tx_hash.
- Phase 2: give `WithdrawalClaim::signing_digest` token_slot its own limb when the claim-circuit
  work re-touches the IMCW preimage (currently bound transitively via the nullifier — sufficient
  but indirect).
- Phase 4: TokenRegister needs a ChannelState-level verifier (fund/chain/roots/h2/epoch freeze
  for that kind) when the transition gets dispatched; the M1 equality check must then exempt
  exactly that kind (see SECURITY comment at the M1 site).
- Pre-merge routine: add `cargo check --target wasm32-unknown-unknown --release` (wasm breakage
  is invisible to native builds).

## Phase 2 — Transition verification + circuits (src/circuits/channel, src/regev)

- [x] `state_update_verifier.rs` (`InChannelTransferUpdateWitness::verify` + batch path): the
      TOKEN BINDING TRIPLE as connected constraints (signed token_slot == leaf select == only
      mutated position; other 9 proven unchanged on sender AND recipient; pending_adds only at
      (recipient, token_slot); E-1 handed the selected cts) — TM-2. Batch obligations total over
      all 10 positions per tx; mixed-token batches — TM-14. *(Phase 2b, 2026-07-27)*
- [x] C2C: descriptor carries base token_index; E-2 PI gains it; both-side in-circuit registry
      resolution (`registry[slot] == token_index ∧ slot < token_count`) — TM-6. *(Phase 2b;
      IMIT → IMI2 re-version, IMUZ → IMU2 wired — see §G-2)*
- [x] Deposit import transition: three-way binding (fund[t], leaf position t, registry
      membership) in-circuit — TM-7. *(Phase 2b: general registry resolution replaces the
      registry[0] pin; unregistered token_index fail-closed)*
- [x] `close_circuit.rs` / `close_pis.rs`: PI 95 → 103 (`token_funds_digest`); in-circuit registry
      injectivity re-check — TM-1, TM-11. *(Phase 2a, 2026-07-27)*
- [x] `withdrawal_claim_circuit.rs` / PIs (+ post-close claim): per-(slot, token) claim; one-hot
      ct select bound to PI token_slot; expose resolved base token_index; nullifier v2 — TM-5,
      TM-8. *(Phase 2a; claim PI 48 → 50: + token_slot + token_index)*
- [x] Local-slot ↔ base-token boundary (review finding m8): the claim/close circuits are the
      formal link between the channel model's `registry[token_slot]` and the Manager's base-token
      accounting — state the binding obligation explicitly in the claim-circuit tests (a claim's
      PI base token_index MUST equal the H1-committed `registry[token_slot]`; no prover choice).
      *(Phase 2a: `withdrawal_claim_circuit_rejects_tampered_token_index`)*
- [x] Adversarial tests (per CLAUDE.md test categories): tampered token_slot (sign A, move B);
      bystander-ciphertext mutation; cross-token credit in C2C; claim on unused/beyond-registry
      position; duplicate-registry close; nullifier replay across tokens; nullifier grinding via
      pk_g (regression); token_count boundary (0, 10, 11).
      *(Phase 2a landed the claim/close subset: tampered token_slot PI, cross-position
      ciphertext, inactive-position claim, duplicate-registry close, TFD mismatch, cross-token
      nullifier replay both directions, pk_g-grinding regression re-enabled. Phase 2b landed the
      transition-verifier subset — see the Phase 2b status block.)*

### Phase 2a status (2026-07-27) — circuit migration to the v2 layouts

- [x] `h1_gadget.rs` → v2: 37-elem "IMB2" header recompute (token_count + 10 registry limbs) +
      104-elem "IMS2" leaf (10 ct digests + 10 counters); native↔circuit parity test re-enabled
      and green. Retired v1 "IMBS"/"IMSL" constants deleted (values stay pinned in the two
      non-collision tests, same treatment as IMPA/IMLD v1).
- [x] `close_circuit.rs`/`close_pis.rs`: v2 H1; IMCH/IMCI amount segments widened to the 80-limb
      vector; in-circuit 92-word IMTF TFD recompute → new PI (95 → 103); token-slot unary
      activeness bits (1 <= token_count <= 10 in-circuit) gating the 45-pair TM-1 injectivity
      re-check; `amounts[0]` connected to the `channel_fund_amount` PI (burn denomination).
- [x] `withdrawal_claim_circuit.rs`/`_pis.rs`: full 104-elem leaf witness; one-hot ct select from
      the PI `token_slot` (Σ flags == 1 ⇒ canonical 0..9); `token_slot < token_count` (TM-8);
      `token_index = registry[token_slot]` PI select (m8); IMW2 nullifier recompute with the
      token_slot limb (TM-5). PI 48 → 50. `WithdrawalClaimProver::build_full_witness` gains a
      `token_slot` parameter (CLI passes 0 until Phase 4).
- [x] `WithdrawalClaim::signing_digest` (carried Phase 1 MINOR 7): token_slot own canonical limb
      after `member_pk_g`; IMCW domain retained per §G-2 (same in-place-widening acceptance as
      IMCH/IMCI); own-limb aliasing golden added.
- [x] `post_close_claim_circuit.rs`: v2 H1/leaf (10 digest + 10 counter witnesses); claims stay
      keyed per incoming tx (IMCK unversioned); credited token follows the native path (genesis
      token) — the C2C descriptor token limb is Phase 2b, a token PI (if needed) is Phase 3.
- [x] `cancel_close_circuit.rs`: v2 H1 (token_count + registry witnesses); revived-IMCH + close-
      IMCI amount segments widened to 80 limbs; IMCL burn segment = `amounts[0]` wire.
- [x] All 36 Phase 1 ignore-gated proving tests re-enabled module by module (assertions
      unchanged) + `e2e_flow::channel_full_close_circuit_proof_e2e`; new v2 negative tests per
      the checklist subset above. The `#[ignore]`d IMCI Solidity shared-vector test stays
      ignored (Phase 3 re-pin, TM-11).
- Phase 3 re-pin pointers: `ChannelSettlementVerifier.sol` closePIHash preimage (103 limbs incl.
  tokenFundsDigest at limbs 95..103) + `token_funds_digest` recompute; withdrawal-claim
  limb binding gains tokenSlot/tokenIndex (limbs 48/49); Manager per-token accounting (TM-3).
- [x] Security review (2026-07-27): one-hot select construction SOUND (single-wire discipline
      across all four uses verified constraint-by-constraint); close-circuit token gating SOUND
      (unary prefix bits force token_count ∈ [1,10], 45-pair active-prefix coverage, TFD
      word-identical to native + live cross-check); IMCW in-place widening ACCEPTED (with the
      precision note that the equal-total-length v1↔v2 realignment case rests on the v3 reset
      alone — doc sentence owed, riding with Phase 2b); re-enabled tests diffed — zero assertion
      changes; new adversarial tests verified to reject through the intended constraint.
      2 doc-level MINORs carried to Phase 2b (IMCW reset-note; degree-17 print unasserted).

**PHASE 2a COMPLETE (2026-07-27).** Verdict: fit to close. Phase 2b carry-forwards: lift the
`token_slot != 0` gate together with the TM-14 mixed-batch obligations; IMCK
one-token-per-C2C-descriptor structural re-check; the two 2a MINOR doc fixes.

### Phase 2b status (2026-07-27) — transition-verifier semantics generalization

- [x] Solo in-channel gate LIFTED (`InChannelTransferUpdateWitness::verify`): token_slot != 0
      accepted; explicit layout bound (>= MAX_CHANNEL_TOKENS) added ahead of the token_count
      bound. Full TM-2 adversarial suite landed in the same change (two-token fixture, transfer
      at slot 1): sign-A/apply-B both directions, bystander-ct mutation (sender AND recipient
      rows), pending_adds at wrong (slot, token) + missing increment, cross-position REAL E-1
      proof substitution, token_slot >= token_count (signed-bound + doctored-header variants),
      token_slot ∈ {10, 255}, D3 budget at token 1.
- [x] Batch/slim per token (TM-14): `verify_slim_send_tx` accepts any active token_slot (bounds
      + per-position refresh gate + E-1 `before` at the SIGNED position); `BatchTxApply` gains
      `token_slot`; canonical fold per (slot, token) with R1 generalized to distinct
      (sender, token) PAIRS (Lean `sendersDistinctMT`) and TM-8 fail-closed bounds inside the
      fold; `solo_next_state` gains the token selector. Tests: same member debits two tokens in
      one batch (fold + decryption assertions), doctored token_slot echo, swapped after_ct,
      TM-8 bounds at verifier AND fold, K=1 fold ≡ solo per token (digest equality).
- [x] C2C base token_index end-to-end (TM-6): `InterChannelTx.token_index: u32` (BASE index),
      own canonical limb in the signing digest under the NEW "IMI2" domain
      (`INTER_CHANNEL_TX_DOMAIN_V2`; v1 "IMIT" retired-pinned — new domain chosen over in-place
      widening because the preimage's three variable-length tails make the equal-total-length
      realignment case rest on the v3 reset; single hashing site, NO in-circuit recompute: the
      legacy cancel-close IMIT recompute was already retired by the Finding-D statement
      correction, so cancel_close_circuit needed NO change). Source send / destination fund
      import / destination bundle apply all resolve `registry[t] == token_index && t <
      token_count` against their OWN signed registries, move fund + ciphertext at exactly the
      resolved position, freeze the rest (`ensure_funds_unchanged_except`); unregistered ⇒
      reject fail-closed on either side. E-2 PI binding wired under the reserved IMU2 domain:
      `RegevStatement::ChannelUpdate` + prove/verify gain `token_index` as the 5th extra PV
      (AIR internals untouched); negative test: proof for token X rejected for X+1 and 0.
      IMCK structural re-check discharged: doc note at `derive_shared_native_nullifier` + tests
      `receiver_bundle_apply_rejects_second_token_position_credit`,
      `bundle_apply_rejects_credit_at_wrong_local_position`,
      `c2c_rejects_unregistered_token_index_on_both_sides`.
- [x] Deposit import general resolution (TM-7): `L1DepositImportUpdateWitness` replaces the
      registry[0] pin with general resolution; fund at amounts[t], others frozen; builder
      (`build_l1_deposit_import`) credits the depositor leaf at the SAME resolved position
      (leg b). Tests: token-55 import to local slot 1 (witness + builder + co-signer gate),
      unregistered index rejected, fund bump at wrong token rejected.
      **Review MAJOR 1 fix (2026-07-27):** leg (b) no longer relies on proposer == co-signer:
      the bundle step is factored into the single canonical `l1_deposit_bundle_state`, and
      `verify_l1_deposit_import_transition` now verifies BOTH steps — the fund-import witness
      plus REBUILD-EQUALITY of the proposed bundle state against the canonical step (the
      `verify_token_register_transition` pattern; recipient_delta is the co-signer's own
      derivation; accumulator-root push-faithfulness stays the Stage-3 persisted-tree
      obligation). Negatives: cross-token credit (right slot, wrong position), cross-slot
      credit, double credit — all rejected; happy path at the non-genesis token.
- [x] Refresh per (member, token) (TM-13): `BalanceRefreshUpdateWitness.token_slot` +
      `RefreshPayload.token_slot` + `build_refresh` selector; ct replaced + counter reset at
      exactly (slot, token), all other positions (cts AND counters) frozen; IMRF transition
      digest gains token_slot as its own limb (PI-only preimage — in-place, documented). Tests:
      token-1 refresh leaves token 0 (ct + counter) untouched, reset/swap at unselected
      position rejected, out-of-range selector rejected.
- [x] Per-token PI plumbing: `ChannelStateUpdatePublicInputs.channel_fund_{before,after}` widened
      to the full `[U256; 10]` registry-aligned vectors (ALWAYS full width, 80 fixed limbs per
      side in `digest()` — layout documented at the field/digest).
- [x] 2a review MINORs: IMCW equal-total-length realignment sentence added (channel.rs);
      close-circuit degree print now backed by `assert_eq!(degree_bits, 17)` in the fixture.
- [x] Marker sweep: every `SECURITY(multitoken-phase2)` marker discharged or re-labeled —
      remaining phase markers: `multitoken-phase3` (CloseIntent non-genesis-funds close gate —
      Manager per-token settlement) and `multitoken-phase4` (build-path token parameters:
      build_send / C2C builders / wasm balance reads + refresh selector plumbing).
- Wire-format note (Phase 5): `InterChannelTx` (+ descriptors embedding it) and `RefreshPayload`
  gained serde fields; previously persisted JSON payloads/fixtures do not deserialize — covered
  by the standing Phase 5 regeneration + v3 reset.

Carried obligations from the Phase 2b review (MINORs, no code yet):
- Phase 4 (review MINOR 2): when REAL small-block cosigning replaces the structural sig stub,
  the C2C cosign gate must rebuild the 1-Transfer TxV2 tree from the descriptor and check
  `tx_tree_root` equality — closing the base `Transfer.{token_index, amount}` binding, which is
  currently builder-trusted via the structural signature stub.
- Phase 3 (review MINOR 3): the attacker pass must re-examine the single CROSS-TOKEN
  `unallocated_confirmed_incoming` scalar against the per-token Manager accounting (whether a
  per-token unallocated vector is required for P2 once L1 settlement is per token).
- Verification: `cargo build --release` green; targeted suites green (state_update_verifier 37,
  e2e_flow 16 incl. full close-circuit proof, cancel_close 15, common::channel 29,
  balance_state 19, transfer_stark 19, delegate_send_tests 17 incl. heavy close/withdrawal
  pipelines, constants 2); `cargo check --target wasm32-unknown-unknown --release --lib` green;
  fmt applied; clippy introduces no new warnings on changed lines. No circuit CONFIG or
  security-parameter changes; close circuit still builds at degree bits 17 (now asserted).
- [x] Security review (2026-07-27): IMI2 new-domain decision CONFIRMED (zero live IMIT sites
      repo-wide incl. contracts/api/node; variable-length tails made in-place widening
      reset-reliant); deviation 4 (base Transfer.token_index = registry[0]) judged a semantic
      FIX; E-2 IMU2 binding chain SOUND (PV rebuilt by verifier from signed data); IMCK
      one-token-per-descriptor obligation DISCHARGED with test; gate lift verified — nothing
      weakened; marker audit clean. One MAJOR: deposit-import bundle-apply step had no cosigner
      witness (leg b enforced only by same-process rebuild).
- [x] MAJOR 1 fix: single canonical `l1_deposit_bundle_state` shared by builder and gate;
      `verify_l1_deposit_import_transition` now two-step (witness + rebuild-equality over a
      RECOMPUTED signing digest); cosigner-own recipient_delta; negative tests (cross-token /
      cross-slot / double credit) reject through the digest equality. Re-verified: VERIFIED,
      safe for future distributed cosigners.

**PHASE 2 COMPLETE (2026-07-27)** (2a + 2b). Verdict: fit to close, modulo the disclosed
Phase 3/4/5 deferrals. Phase 3 attacker pass must cover: per-token L1 settlement against
`token_funds_digest`; the cross-token `unallocated_confirmed_incoming` scalar (MINOR 3);
the two `#[ignore]`d-not-repinned Rust↔Solidity shared vectors (IMCI + close PI).

## Phase 3 — Solidity (contracts/src)

- [x] `IntmaxRollup.sol`: set-once `tokenIndex → IERC20` registry — TM-10b; ERC-20 `deposit` with
      nonReentrant + balanceOf-delta == stated amount else revert — TM-4, TM-10a; per-token
      `escrowed[t]` underflow-revert ceiling — TM-1; `withdrawERC20` (authDigest already binds
      tokenIndex); retire the "accounting-only nonzero tokenIndex" regime.
- [x] `ChannelSettlementManager.sol`: per-base-token conversion of ALL SIX accounting variables
      (finalizedChannelFundAmount, totalWithdrawn, receivedChannelFunds, totalCreditedOut,
      withdrawalCredits, + pending-close fund fields); per-token CapInv; payout dispatch by token
      (0 → ETH, else registered ERC-20); per-token pull-credit — TM-3.
- [x] `ChannelSettlementVerifier.sol`: close PI preimage v2 (103 limbs) + `token_funds_digest`
      recompute; Rust↔Solidity byte-for-byte differential test — TM-11.
- [x] Foundry adversarial tests: malicious-token reentrancy (ERC-777 hook), fee-on-transfer
      deposit revert, index remap attempt, cross-token claim (fund[t]=0), per-token cap
      exhaustion, duplicate-index drain attempt across two channels — TM-1/3/4/10.

### Phase 3 status (2026-07-27) — L1 ERC-20 escrow + per-token settlement

- [x] `IntmaxRollup.sol` (§N-7): `registerToken` (deployer-gated, index 0 = ETH reserved,
      address(0)/no-code rejected, SET-ONCE per index — TM-10b); ERC-20 `deposit` branch
      (registered index required, `msg.value == 0`, `nonReentrant`, balanceOf-delta == stated
      amount else `TokenDepositAmountMismatch` — TM-4); `escrowedByToken[t]` underflow-revert
      ceiling (TM-1 layer b); `withdrawERC20` sharing the FULL `withdrawNative` verification core
      (factored `_verifyWithdrawalSet` — real MLE + finalized-root anchor + chain refold; per-leaf
      `tokenIndex != 0` + registered + IMPW auth gate); pull-payment
      `pendingTokenWithdrawals[t][r]` + `withdrawToken(t, amount)` (the ERC-20 mirror of
      `withdraw(amount)`). Both pull APIs debit exactly the caller-supplied amount; unrelated
      recipient-wide credits remain in the Rollup.
      ETH stays on `totalEscrowed` (documented; `escrowedByToken[0]` never used — minimal diff).
      Runtime size 23,855 B (721 B EIP-170 margin; the factoring PAID for the additions).
      Minimal in-tree `SafeERC20.sol` (IERC20 + SafeERC20Lib) — no new external dependency
      (repo vendors no OZ/solady).
- [x] `ChannelSettlementVerifier.sol` (TM-11): `CLOSE_PI_LEN` 95 → 103 with `tokenFundsDigest`
      limbs 95..102 RECOMPUTED on-chain (`tokenFundsDigest(registry, count, amounts)` — byte-exact
      92-word IMTF mirror, Rust↔Solidity shared vector pinned FROM RUST); IMCI recompute widened
      to the 80-word amounts vector; withdrawal-claim PI 48 → 50 (`tokenSlot` limb 48,
      `tokenIndex` limb 49, both strict-bound). `CloseProofFields` gains
      `channelFundAmounts[10]` / `tokenRegistry[10]` / `tokenCount`. Legacy DEAD `closePIHash`
      outer-keccak mirror REMOVED (no caller; stale-mirror hazard class). VK set-once machinery
      untouched (values regenerate in Phase 5 — none baked now).
- [x] `ChannelSettlementManager.sol` (TM-3): ALL SIX accounting variables per-BASE-token
      (`finalizedChannelFundAmount[t]`, `totalWithdrawn[t]`, `receivedChannelFunds[t]`,
      `totalCreditedOut[t]`, `withdrawalCredits[t][addr]`, PendingClose fund vector+registry+count
      — TFD-bound at submit); per-token CapInv `totalCreditedOut[t] + amount <=
      receivedChannelFunds[t]` at the payout site (the `execMT_payout_ceiling` machine's site);
      payout dispatch t==0 → ETH else safeTransfer of `registry.tokenAddressOf(t)` (the SAME
      set-once rollup registry — no second copy); `pullChannelTokenFunds(t)` (measured delta;
      donations not counted); claim token = PROOF-bound limbs (+ Manager re-checks
      `tokenSlot < finalizedTokenCount` and `finalizedTokenRegistry[slot] == tokenIndex` — TM-8);
      post-close claims PINNED to the finalized genesis token `registry[0]` (the post-close PI has
      no token limb — a token PI is a later-phase circuit change).
- [x] Shared-vector re-pins (generated FROM RUST, cross-checked via independent
      cast-keccak reconstruction): IMCI v2 constant `0x9fc3ce…42fb` (Rust
      `close_intent_digest_matches_solidity_shared_vector` UN-IGNORED + Solidity twin green);
      NEW TFD shared vector `0x44987e…7278` (pinned in the Rust golden + Solidity
      `test_tokenFundsDigest_matchesRustSharedVector`). NOTE: the only `#[ignore]`d Rust
      cross-check was the IMCI one; the close-PI layout is pinned by
      `close_public_inputs_roundtrip` (limb indices) + the Solidity golden — no second ignored
      test existed to re-enable.
- [x] Foundry adversarial tests: `MultiTokenEscrow.t.sol` (12) + `MultiTokenSettlement.t.sol`
      (16) — registry set-once/remap, fee-on-transfer fail-closed, false-return token,
      deposit/payout ERC-777 reentrancy (rollup AND manager), per-token escrow ceiling
      (duplicate-index/cross-channel drain bound + no-cross-token draw), TFD tamper at close
      submit (amounts/registry/count), per-token cap exhaustion + frame, zero-fund cross-token
      claim, inactive-slot + registry-mismatch claims, token-limb proof replay, genesis pin,
      donation non-counting, ETH regression. Full suite green (SKIP_GROTH16).
- [x] Carried obligation (Phase 2b review MINOR 3, `unallocated_confirmed_incoming`):
      DETERMINATION — the Manager NEVER consumes it (not a close PI, not in any L1 accounting
      variable), and `CloseIntent::new` fail-closes on a nonzero residue, so NO per-token
      unallocated vector is required for L1 per-token settlement soundness. Whether the Rust
      channel layer wants a per-token vector for mid-life P2 bookkeeping (wallet_core credits the
      scalar on C2C receive regardless of token) is a channel-layer question for Phase 4+ — the
      close gate keeps it non-exploitable on L1 either way. Documented at `finalizeClose`.
- [x] Security review (2026-07-27): fit to close, no CRITICAL/MAJOR. Two MINOR hardening fixes
      applied same-day: MINOR 1 — `SafeERC20Lib._callToken` now matches OZ semantics EXACTLY
      (success = call ok AND (empty return OR decodable 32-byte `true`); a malformed 1-31-byte
      return is FAILURE, was previously accepted) + `ShortReturnERC20` negative
      (`test_deposit_shortReturnToken_reverts`); MINOR 2 — `ChannelSettlementVerifier.
      tokenFundsDigest` self-contained `tokenCount ∈ 1..=10` bound (`TokenCountOutOfRange`
      custom error; inherited by every `_expectedCloseLimbs` close bind) +
      `test_tokenFundsDigest_tokenCountBounds_reverts` (0/11 revert, 1/10 boundary accept).
      Post-fix: full suite 210 passed / 0 failed / 1 documented skip; sizes IntmaxRollup
      23,877 B (699 B margin), Verifier 22,348 B, Manager 18,309 B — all under EIP-170.

**PHASE 3 COMPLETE (2026-07-27).** Verdict: fit to close, modulo the disclosed Phase 4/5
deferrals below.

- Deferred to Phase 5 (documented in-test, NOT faked): the baked close/claim fixtures predate the
  103/50-limb PIs and the new Manager initcode (CREATE2 address moved), so `CloseLifecycleE2E`'s
  close-intent section + manager-address assert now SELF-SKIP with explicit logs pending fixture
  regeneration; scripts parse the legacy scalar descriptor into the genesis-token embedding until
  the regenerated descriptors emit per-token fields. The Rust `CloseIntent::new` non-genesis-funds
  fail-closed gate (`SECURITY(multitoken-phase3)` marker) was deliberately left in place at
  Phase 3 close, and has since been LIFTED in Phase 4 per its stated condition (together with
  the per-token claim builders + a native two-token close test — see the Phase 4 status block).

- [x] Attacker/security review (2026-07-27): TFD binding chain SOUND end-to-end (member-signed
      PI → Verifier recompute over intent vectors → PendingClose → finalize → per-token accrual
      + authoritative payout CapInv); factored `_verifyWithdrawalSet` FAITHFUL (line-by-line, no
      check dropped); per-token exhaustiveness verified by independent storage enumeration (no
      residual global; ETH/ERC-20 fully disjoint); claim provenance doubly bound (proof limbs
      48/49 in pis_hash + finalized-registry re-check); TFD shared vector independently
      re-derived (Rust→Solidity direction confirmed); deviation 3 (CloseIntent non-genesis gate)
      ruled STILL REQUIRED until Phase 4/5 builders exist (funds-stuck risk, not theft). No
      CRITICAL/MAJOR; 2 MINOR hardening items (SafeERC20 short-return handling → OZ semantics;
      Verifier self-contained tokenCount require) applied post-verdict.

**PHASE 3 COMPLETE (2026-07-27).** Verdict: fit to close. Carry-forwards for Phase 4/5 attacker
passes: re-enable CloseLifecycleE2E close section on regenerated multi-token fixtures at the new
CREATE2 manager address; replace the post-close-claim genesis-token pin with a strict-bound token
field when the Rust PI gains the limb; lift the CloseIntent non-genesis-funds gate only WITH the
per-token claim builders + e2e coverage.

## Phase 4 — CLI / WASM / JS plumbing

- [x] `channel_member.rs` + `wallet_core.rs` + WASM entry points: token_slot / token_index
      parameters end-to-end (send, cosign, batch, import, claim); slim wire `SlimSendPayload`
      += token_slot *(the slim-wire field itself landed in Phase 2b; Phase 4 wired the builders)*.
- [x] api/: `deposit.js` + `channel-init.js` un-hardcode tokenIndex '0'; routes gain `token`
      params (send, close claims, partial/full withdrawal, inter-channel); `chain-watcher.js`
      stop discarding `args.tokenIndex`; API-DESIGN.md types updated (also fix stale `slot: u8`).
- [x] node/: `wallet.js` signatures gain token arg; `policy.js` per-token caps; delegate/cosigner
      branch plumbing.

### Phase 4 status (2026-07-27) — CLI / WASM / JS plumbing + TokenRegister dispatch + close-gate lift

- [x] Build paths per token (`SECURITY(multitoken-phase4)` markers ALL discharged — zero left
      repo-wide): `build_send` → `build_send_token(token_slot)` (legacy fn = token-0 wrapper;
      per-(slot,token) pending_adds gate; E-1 handed the SIGNED position's ct); C2C
      `build_inter_channel_send{,_token}(token_index)` + `build_burn_send{,_token}` (source-side
      registry resolution fail-closed; fund debit + ct swap at exactly the resolved slot; base
      Transfer + descriptor carry the base index; burn records token_index into last_burn.json →
      pw-submit Withdrawal/IMPW); `decrypt_balance` → token-0 wrapper over
      `decrypt_balance_token` (TM-8-bounded); `verify_snapshot` self-check decrypts ALL active
      positions; `resolve_local_token_slot` made pub (CLI/WASM twins of the verifier check).
- [x] TokenRegister dispatch (carried Phase 1 obligation): canonical
      `token_register_next_state` builder (channel.rs) shared by proposer
      (`wallet_core::build_token_register`) and gate; NEW `TokenRegisterUpdateWitness::verify`
      (state_update_verifier.rs) = state linkage + `verify_balance_state_shared` (the factored
      registry-agnostic core; `verify_balance_state_common` = shared + the M1 registry equality,
      unchanged for all other kinds) + `BalanceState::verify_token_register_transition` +
      explicit full freeze (h2 zero, chain, accumulator, fund, unallocated, shared nullifier,
      small_block_number, close_freeze_nonce) + whole-state rebuild-equality + N-of-N
      signatures. CLI `register-token <base_token_index>` (check-and-sign per controlled member,
      authoritative `verify_all_signatures` before the head advances); API route
      `POST /channel/:ch/register-token`.
- [x] CloseIntent non-genesis gate LIFTED (carried Phase 3 obligation, WITH the per-token claim
      builders as conditioned): semantics DETERMINATION against §N-6 + the Manager — the burn
      leg denominates ONLY `amounts[0]` (close circuit pins it to the `channel_fund_amount` PI;
      Manager `finalizeClose` reads `channelFundAmounts[0]` as the burn denomination); non-
      genesis funds settle via per-token claims against `finalizedChannelFundAmount[registry[t]]`
      accrual + `pullChannelTokenFunds(t)` — NO burn. `burn_amount == amounts[0]` and
      `unallocated == 0` checks kept; the refusal loop removed with a SECURITY comment citing
      the chain of custody (IMCI 80-limb vector → TFD PI recompute → per-token accrual).
- [x] WASM: session witness is now `(token_slot, amount, witness)` (a witness backs exactly one
      position; sends/burns refuse a token/witness mismatch fail-closed); `wallet_send(+token_
      slot?)`, `wallet_refresh(token_slot?)`, `wallet_send_inter_channel(+token_index?)`,
      `wallet_burn_send(+token_index?)` (all Option-typed → JS-optional, default genesis);
      balance reports keep the token-0 scalar and add `balances[]` + `witnessTokenSlot`;
      genesis-sign self-check decrypts all active positions.
- [x] CLI: `send`/`gen-send` `[token_slot]`; `claim` `[token_slot]` (descriptor +
      tokenSlot/tokenIndex from the proved PIs); `cosign-l1-deposit-import` `[token_index]`
      (deposit's REAL base index, no longer pinned 0); `balance` prints per-token;
      inter-transfer/burn cosign conservation checks generalized to per-position (resolved slot
      moves exactly amount, all other 9 positions frozen — belt-and-braces over the witness).
- [x] api/: deposit routes accept `tokenIndex` (validated decimal u32; ERC-20 path omits
      `--value` per §N-7 and forwards the index to the CLI import); close/full-withdrawal claim
      routes take `tokenSlot`; inter-channel/burn/pw routes cross-check an optional top-level
      token param against the SIGNED descriptor field (400 on mismatch — never an override);
      `GET /tokens` + `POST /register-token`; API-DESIGN.md multi-token section + stale
      `slot: u8` → u16 fixes.
- [x] node/: `chain-watcher.js` gains the exact `TokenRegistered`/`Erc20Withdrawn`/
      `TokenWithdrawalClaimed` fragments (verified against IntmaxRollup.sol); cosigner deposit
      branch validates + forwards the Deposited `tokenIndex` (was discarded); delegate branches
      forward tokenSlot/tokenIndex through send/refresh/inter/burn; classify maps the ERC-20
      credit events to CHAIN_CREDIT (delegate) / CHAIN_OBSERVE (cosigner); token-aware exit
      confirm (recipient match unchanged; tokenIndex recorded); `policy.amountWithinCap` gains
      per-token caps (`amountCapWeiByToken` map, default = legacy `amountCapWei`); `wallet.js`
      wrappers gain trailing token args AND were aligned to the real wasm-bindgen signatures
      (the old wrappers passed extra positional args that shifted parameters — flagged as a
      latent-bug fix in the Phase 4 report).
- [x] New tests (all green): state_update_verifier 43 (TokenRegister happy path + balance/
      pending/fund-touch + wrong-append(4 variants) + version-skip negatives); common::channel
      30 (multi-token close-intent acceptance + burn-mismatch negative + IMCI vector binding;
      token_register_next_state golden); wallet_core delegate_send_tests 22 (TokenRegister
      cosign-gate e2e w/ REAL sigs + doctored-balance + duplicate-index negatives; two-token
      close intent + per-token claims — distinct TM-5 nullifiers, token-1 claim PROVED +
      verified; token-1 C2C debit at the resolved slot + unregistered-index refusal + cosigner
      gate; TM-8 inactive-position send refusal; TM-14 batch helper now drives the REAL
      `build_send_token`); balance_state 19; e2e_flow 16. wasm32 lib check green; fmt/clippy
      clean on changed lines; node/ suite 45/45; `node --check` on every changed JS file.
- OPEN (unchanged, deliberate): the transfer-tree rebuild obligation (Phase 2b review MINOR 2 —
  C2C cosign gate must rebuild the 1-Transfer TxV2 tree once REAL small-block cosigning replaces
  the structural sig stub). The e2e PROVING fixtures + CloseLifecycleE2E re-enable stay Phase 5;
  post-close claims remain genesis-pinned (no token PI limb yet — Phase 3 carry-forward).
- [x] Security review (2026-07-27): M1 factoring FAITHFUL (bypass provably confined to
      TokenRegister — `verify_balance_state_shared` file-private, single call site); cross-kind
      signature replay EXCLUDED (token_count increment is the structural discriminator vs the M1
      equality on all six ordinary kinds; transport PI is kind-tagged); TokenRegister three-layer
      freeze COMPLETE (all 12 ChannelState fields enumerated); close-gate lift semantics CORRECT
      (burn = genesis leg only; no residual genesis-zero assumption found); burn token chain
      bound via withdrawal-chain fold + IMPW (last_burn.json is transport-only); wrapper pattern
      defaults-only with TM-8 inside the _token variants; API cross-check-not-override verified;
      wallet.js pre-existing bug assessed FAIL-NOISY (no silent live-funds exposure). One MAJOR
      (stale Manager event fragments) + one MINOR (todo prose).
- [x] Review MAJOR 1 fix (2026-07-27): three STALE Manager fragments in `chain-watcher.js`
      (topic0 mismatch ⇒ silent never-match) corrected field-for-field against the committed
      `ChannelSettlementManager.sol` — `WithdrawalClaimAccepted` + trailing `uint32 tokenIndex`
      (:283), `WithdrawalClaimed` + `uint32 indexed tokenIndex` (2nd position, :300),
      `ChannelFundsPulled` + LEADING `uint32 indexed tokenIndex` (:626); all other Manager
      fragments re-verified unchanged. Downstream: cosigner CHAIN_OBSERVE log now surfaces the
      decoded `tokenIndex`; the delegate credit-confirm already read `args.tokenIndex`
      generically (comments corrected — the Manager's `WithdrawalClaimed` now decodes it).
      Review MINOR 2 fix: the Phase 3 status prose about the phase3 gate marker updated to
      reflect the Phase 4 lift. `node --check` + node suite 45/45 green after both.
- [x] MAJOR 1 fix verified by the orchestrator directly (fragments diffed field-for-field,
      indexed-ness included, against the contract declarations — mechanical scope).

**PHASE 4 COMPLETE (2026-07-27).** Verdict: fit to close. Phase 5 carry-forwards: fixture/VK
regeneration + CloseLifecycleE2E re-enable at the new CREATE2 manager address; post-close-claim
genesis pin → strict-bound token PI limb; transfer-tree rebuild obligation at real small-block
cosigning (OPEN); two-token full E2E on anvil; final full-suite attacker pass before deploy.

## Phase 5 — Fixtures, VKs, E2E, deploy

### Phase 5a status (2026-07-27) — post-close claim token binding (TM-16)

Premise correction first: the Phase 3 carry-forward assumed the claim circuit opens an
IMIT/IMI2-committed token field — it does NOT (it recomputes the IMTL/IMTC chain, whose
preimages never carried the token). The implementation agent STOPPED per instruction; the gap
analysis became **TM-16** (threat model) and the approved fix is the IMTC ids-limb design below.

- [x] **Anchored token limb (TM-16 fix):** `inter_channel_tx_hash` moved to `common::channel`
      as the canonical single source and gained the BASE `token_index` at ids limb 5
      (`[0,0,0,0,0, token, dest, src]` — own canonical limb, TM-15; IMTC domain retained, shape
      unchanged — §G-2 note). Token-free v1 fold preserved as
      `InterChannelTx::replay_identity()`. `InterChannelTx::compute_tx_hash()` = the recompute
      every gate runs.
- [x] **Obligation 1 (MATERIAL — replay ledgers token-free):** CLI `applied_tx_hashes` /
      `spent_tx_hashes` → `applied_tx_identities` / `spent_tx_identities`, keyed on
      `replay_identity()` at all six sites (cosign-inter-transfer both legs + burn-send); a
      second token-variant of a credited debit is refused as a replay. Pre-TM-16 ledger entries
      drop via serde default — v3-reset-covered, documented at the field.
- [x] **Obligations 2/5 (gate recompute, single-sourced):** `require_token_bearing_tx_hash` in
      state_update_verifier — descriptor `tx_hash` must equal the recompute over the
      descriptor's OWN `token_index` (the SAME field the registry resolution + E-2 statement
      read) — run by the source send witness (obligation 5, symmetry) AND both destination
      witnesses (fund import + bundle apply) before the chain/accumulator absorb; also invariant
      5b in `verify_inter_channel_credit_transition` (+ descriptor-vs-embedded tx_hash equality).
- [x] **Claim circuit + PI (obligation "single wire"):** post-close claim PI 56 → 57 —
      `token_index` appended at limb 56, range-checked canonical u32, and wired as the SAME
      target as ids limb 5 of the in-circuit `incoming_tx_hash` recompute (no independent
      witness). Native mirror: `PostCloseClaimWitness::to_public_inputs` fail-closes on
      `compute_tx_hash() != source_tx.tx_hash` and copies the descriptor's token (no caller
      choice). IMCK nullifier stays unversioned — now transitively token-bound via the tx_hash
      (comment at `derive_shared_native_nullifier`).
- [x] **Solidity (obligation 3):** Verifier `POST_CLOSE_CLAIM_PI_LEN` 56 → 57, token limb
      strict-bound (layout doc at `_expectedPostCloseClaimLimbs`); Manager `PostCloseClaim.tokenIndex`
      (proof-bound), genesis-registry[0] pin REPLACED by per-token accrual
      (`totalWithdrawn[t]` vs `finalizedChannelFundAmount[t]`, credit
      `withdrawalCredits[t][recipient]` — same semantics as withdrawal claims, shared budget per
      token) + finalized-registry membership re-check (defense in depth; zero cap backstops);
      `PostCloseClaimAccepted` + trailing `uint32 tokenIndex` (chain-watcher.js fragment updated
      in the SAME change — the Phase 4 stale-fragment lesson); RunClose.s.sol parses the CLI
      descriptor's new `token_index`.
- [x] **Builders/CLI:** `PostCloseClaimProver` exposes the descriptor-derived token (asserted in
      the a3 prover test, now at a NON-GENESIS token 55); CLI post-close descriptor JSON gains
      the proved `token_index`.
- [x] **Tests (obligation 4):** Rust — circuit happy path at non-genesis token 55 (limb 56
      asserted); `rejects_tampered_token_limb` (PI token != anchored ids limb → unprovable; also
      the "second submission, different token" negative);
      `rejects_cross_token_variant_of_absorbed_tx` (consistent token-7 re-label of the real
      absorbed tx: hash+nullifier recomputed, fails ONLY the accumulator inclusion — isolates
      the anchor); pis-level `TxHashRecomputeMismatch` negative; channel.rs
      `inter_channel_tx_hash_binds_token_and_replay_identity_strips_it` (token binds hash,
      identity strips it, v1-formula pin, own-limb non-alias, HIGH-1 dest binding);
      e2e_flow `c2c_rejects_token_relabeled_descriptor_on_all_gates` (REGISTERED-token relabel —
      resolution would accept, the TM-16 recompute rejects at all three gates). Foundry —
      genesis-pin test REPLACED by `test_postCloseClaim_proofBoundToken` (token-A credit/accrual,
      ETH lane frame) + `tamperedTokenLimb_reverts` (limb-56-only mismatch) +
      `unregisteredToken_reverts` + `perTokenCap_noCrossTokenDraw` (cap isolation + real-token
      payout); PI-length/golden-vector tests updated to 57 limbs.
- [x] Verification: `cargo build --release` green; post_close_claim 12/12 (incl. heavy proving),
      common::channel 31, state_update_verifier + e2e_flow + _pis suites green (see assessment
      log); `SKIP_GROTH16=true forge test` 213 passed / 0 failed / 1 documented self-skip; sizes
      Manager 18,035 B / Verifier 22,418 B / IntmaxRollup 23,877 B (all under EIP-170); wasm32
      lib check green; fmt/clippy clean on changed lines.
- Fixture note: the PI length change invalidates the baked post-close fixtures — EXPECTED,
  regenerated in Phase 5b with everything else. detail2 §N-6 + §G-2 updated (TM-16).

- [x] Regenerate ALL baked fixtures + re-pin VKs (every preimage/PI change invalidates them —
      known gotcha from the delegate-account work; batch with the pending D12–D14 regeneration).
      *(Phase 5b, 2026-07-27 — see the status block below)*
- [x] E2E: 2-token channel lifecycle on anvil — `tests/two_token_cli_e2e.rs` (see the Phase 5b
      status block for the exact coverage and the disclosed CLI-witness-store deviations).
- [ ] Full-suite attacker-subagent pass over the integrated feature before deploy.
- [ ] v3 testnet reset + redeploy (regen-and-redeploy-runbook.md); update live demo.

### Phase 5b status (2026-07-27) — fixture/VK regeneration + E2E integration

- [x] **Full fixture regeneration** (one batch, consistent circuit set — MLE/WHIR proofs are
      ZK-blinded/non-deterministic, so every fixture was validated SEMANTICALLY by its consuming
      test, never by byte diff):
      `generate_e2e_fixture` (mle/vpi/block fixtures → MleE2E + MleFinalizeE2E + IntmaxRollup
      suites), `generate_withdrawal_fixture` plain set (WithdrawNativeE2E), `close_` set at the
      NEW manager CREATE2 address `0x1B5d05406197D5db3c43eBA9064188b968B03e62`
      (CloseLifecycleE2E), `generate_close_fixture` (co-generated TWO-token close intent — see
      below), claim/post-close/cancel fixture pairs (VK sources for DeployCloseCli + RunClose),
      `generate_c2c_fixture` (C2CFullE2E/C2CBlockHash/ReclaimStake), `generate_wasm_fixtures`
      (tests/fixtures/*.bin). All VK pins are read from the fixture JSONs at runtime
      (FixtureLib/DeployCloseCli/CloseLifecycleE2E `_initRealCloseVk`) — regeneration IS the
      re-pin; repo-wide check found NO hardcoded real VK constants (the CloseTestLib dummy VKs
      drive a MockMleVerifier and are intentionally fake). `e2e_groth16.json` is managed
      separately (legacy, no active generator) and untouched; the tracked `sepolia_*` staged
      copies are runtime-overwritten by the CLI and left as-is.
- [x] **CloseLifecycleE2E close section RE-ENABLED and green end-to-end for the first time**
      (it had ALWAYS self-skipped on the member-set mismatch): `generate_close_fixture` now
      derives its signing keys from `ChannelMemberKeys::deterministic(1)` — the same derivation
      `generate_withdrawal_fixture` registers — via the new
      `test_fixture::build_close_full_witness_two_token(channel, sks, registry1, amount1)`
      (channel 1, registry `[ETH, 7]`, amounts `[77, 55]`). The descriptor (fixture bin AND the
      CLI `close`) gains `channel_fund_amounts[10]`/`token_registry[10]`/`token_count`;
      CloseLifecycleE2E + RunClose parse them verbatim (genesis-token embedding retired); the
      claim step parses `.token_slot`/`.token_index`; all stale-fixture self-skips converted to
      HARD assertions; new per-token accrual asserts (`finalizedChannelFundAmount(0)==77`,
      `(7)==55`) after finalizeClose.
- [x] **CREATE2 gotcha discovered + fixed (runbook updated):** the manager address printer gave a
      DIFFERENT address than the lifecycle test's own `_deployAll` with IDENTICAL fixture inputs —
      `type(MleVerifier).creationCode` embeds linked external-library addresses and Foundry links
      PER TEST CONTRACT. The printer (`test_printCloseManagerAddress`) moved INTO
      `CloseLifecycleE2ETest`; `CloseManagerAddr.t.sol` is now a pointer stub. If the lifecycle
      test file is edited after baking, re-run the printer (address can shift with the bytecode).
- [x] **ERC-20 withdrawal lane (new, for the two-token E2E):**
      `ChannelWithdrawalParams.erc20_lane: Option<Erc20LaneParams>` — a second deposit (token t,
      own recipient salt) in the SAME deposit block + a second transfer in the SAME withdrawal tx
      + its OWN single-leaf withdrawal chain/wrapped MLE (chains are single-asset-class on L1),
      verified by the SAME withdrawal VK; `None` keeps byte-parity. CLI `withdraw` gains
      `WD_ERC20_TOKEN/WD_ERC20_AMOUNT/WD_ERC20_TOKEN_ADDR` (approve + ERC-20 `deposit()`
      balanceOf-delta branch on-chain, `RunClose.withdrawErc20Step` → `withdrawERC20`,
      `pullChannelTokenFunds`); CLI `claim` pulls every native/ERC-20 payout through its exact
      proof-scoped `claimWithdrawalCredit(bytes32 withdrawalNullifier)`. The aggregate token-index
      overload is removed. `close_lifecycle_cli_e2e` accessors fixed to the per-token getters
      (they still read the retired scalar getters — latent breakage since Phase 3).
- [x] **Two-token anvil E2E** — `tests/two_token_cli_e2e.rs` (ignored/heavy, CLI-driven; GREEN,
      946s): DeployCloseCli + SimpleERC20 + set-once `registerToken` → init (ETH genesis) → CLI
      `register-token` (mid-life cosigned TokenRegister, token_count 2) → ETH send → REAL
      two-token close proof built and submitted, REFUSED by the Manager's strict 103-limb bind at
      the delegate-count limb (the pre-existing B-2 fence, pinned as an EXPECTED negative — see
      the E2E findings below) → withdraw BOTH lanes with REAL value (real ETH deposit + real
      balanceOf-delta ERC-20 deposit in ONE deposit block, finalize, real withdrawNative +
      the NEW real-proof withdrawERC20 chain — the FIRST real-MLE ERC-20 withdrawal —
      pullChannelFunds + pullChannelTokenFunds: 0.09 ETH + 40 real tokens land in the manager)
      → per-token conservation with no finalized close (both proof-scoped
      `claimWithdrawalCredit(bytes32)` calls refuse, `totalCreditedOut[t] == 0`, both asset
      pools intact, no cross-token movement).
      **E2E FINDINGS (stop-and-report, both PRE-EXISTING fences working fail-closed as designed;
      neither weakened nor bypassed):**
      1. *P1 re-attestation fence:* a close AFTER `cosign-l1-deposit-import` is refused by the
         close circuit's balance binding (`BalanceBindingMismatch`) — the import pushes
         `settled_tx_chain`, and the CLI cannot yet regenerate a base-layer attestation covering
         the imported deposit. So a LIVE close with nonzero amounts[1] (and a nonzero live
         per-token claim payout) awaits that follow-up; the on-chain two-token close accrual is
         validated by CloseLifecycleE2E (real proof, amounts [77, 55]) and per-token claims by
         MultiTokenSettlement.t.sol (:288, incl. nonzero-token submitPostCloseClaim) + the
         native claim-proving suites.
      2. *B-2 delegate-close fence (Option B R3):* `init` always joins a browser delegate
         (close PI delegate_count = 1) while Option B's cosigners-only registration deploys the
         Manager with activeDelegateCount = 0 — limb 94 strict-bind refuses EVERY live CLI close
         since Option B (also affects `close_lifecycle_cli_e2e`'s close section, which predates
         that change). Offline limb-by-limb reproduction confirmed all OTHER 102 limbs (incl.
         the IMCI and TFD recomputes over the two-token vectors) match exactly.
      **DEVIATIONS (disclosed, not silently skipped):** in-channel token-1 SENDS, the TM-14
      mixed-token batch, the C2C ERC-20 leg and the TM-16 post-close claim are NOT driven by this
      anvil E2E — the CLI's deterministic balance-witness store is genesis-token-scoped (a
      token-1 E-1 witness exists only after a refresh of that position; the CLI has no
      refresh-payload builder yet). Those paths are proof-covered by the native suites
      (`wallet_core` mixed_token_batch_* / two_token_close_intent_builds_per_token_claims /
      inter-channel token tests; post_close_claim TM-16 suite; e2e_flow relabel-gate test) and
      the Foundry proof-bound-token tests. Follow-ups: a CLI `gen-refresh` + per-token witness
      store; the P1 re-attestation; the B-2 Manager-side delegate-count reconciliation.
      Orchestration note: with foundry 1.5.1, anvil automine reproducibly leaves one tx of the
      VK-init burst stuck pending (interval mining outright DROPS it); the E2E runs a txpool
      unsticker thread that force-mines when anything sits pending.
- [x] **Phase 5a review MINORs:** (a) regen runbook gains the explicit "do not reuse pre-TM-16
      cli_state.json / delete stale state" warning (Step 0); (b) the CLI replay ledgers
      (`applied_tx_identities`/`spent_tx_identities`) converted from unbounded Vec + linear scan
      to `HashSet` (O(1) membership; JSON stays an array; rationale documented at the fields).
- Verification (see assessment log): full Foundry suite 214/0/0 incl. the re-enabled
  CloseLifecycleE2E close section (previous suites carried 1 documented skip; the run WITHOUT
  SKIP_GROTH16 is identical — the Groth16-gated test no longer exists since the MLE-only
  switch, `grep -r SKIP_GROTH16 contracts/` is empty and the CLAUDE.md note is stale);
  `cargo test --test e2e --release` 1/1 (132.6s) + `--test mle_onchain_e2e --release` 1/1
  (40.9s) — base layer unchanged, no security signal; two-token anvil E2E 1/1 (946s);
  node/ 45/45; wasm32 lib check green; fmt applied; clippy: no new warnings on changed lines
  (one new clone_on_copy in the ERC-20 lane fixed).
- [x] Security review (2026-07-27): skip→hard-assert conversion strictly STRENGTHENS (close
      section now runs the member-set binding + strict 103-limb bind + real MLE verify that were
      previously skipped); co-generation ruled honest-flow-faithful (papers over nothing — the
      old mismatch was genuine two-generator staleness, future divergence hard-fails); BOTH stop
      fences verified pre-existing on main (P1 re-attestation at close_circuit.rs:867-875;
      B-2/R3 delegate limb-94); deviation coverage claims all verified against real un-ignored
      tests; txpool unsticker ruled inert (evm_mine only, never re-broadcasts/retries; all E2E
      asserts terminal-state). One MAJOR: lib test target compile break (missing erc20_lane in
      one test initializer) — fixed, all targeted suites re-run green on the compiling tree.
      MINORs: E2E claim-refusal asserts strengthened to the NoWithdrawalCredit selector
      (0xe10881ae); coverage attribution corrected to MultiTokenSettlement.t.sol; stale
      SKIP_GROTH16 mention fixed in CLAUDE.md (historical docs left as records); token-1
      destination-credit positive added post-verdict (MINOR 3).

**PHASE 5b COMPLETE (2026-07-27).** Remaining Phase 5: integrated full-suite attacker pass over
the whole feature (must include: exercising the strengthened E2E asserts; the B-2/R3 and P1
fence follow-ups as pre-existing tracked items); then the OWNER decision on v3 reset + redeploy
(regen-and-redeploy-runbook.md). Follow-ups surfaced (pre-existing, tracked, NOT multitoken
regressions): P1 re-attestation after deposit import blocks live close-after-import; B-2/R3
delegate-count reconciliation blocks every live CLI close since Option B; CLI per-token witness
store (gen-refresh); transfer-tree rebuild at real small-block cosigning (OPEN).

## Assessment log

(append per-phase outcomes here; unexpected results follow the CLAUDE.md security-first protocol)

- **Phase 5b (2026-07-27)**: fixture/VK regeneration + E2E integration complete (see the Phase 5b
  status block). All baked fixtures regenerated in ONE batch and validated SEMANTICALLY
  (consuming tests green; never byte-compared — MLE/WHIR is ZK-blinded). CloseLifecycleE2E's
  close-intent section ran end-to-end ON-CHAIN for the FIRST TIME (co-generated member sets +
  the two-token close fixture; all stale-fixture self-skips are now hard assertions).
  Security-first protocol was applied to three unexpected results, none of which was a
  soundness bug and none of which was worked around: (1) the per-test-contract MleVerifier
  library-linking divergence (CREATE2 address printer moved into the lifecycle test contract;
  runbook updated); (2) the P1 re-attestation fence — close-after-import correctly refused by
  the close circuit's `BalanceBindingMismatch` (adversarially, this refusal is exactly what
  prevents closing against a stale balance attestation); (3) the B-2 delegate-close fence —
  the Manager's strict limb bind refuses every live delegate-bearing close since Option B's
  cosigners-only registration (offline reproduction matched all other 102 limbs, incl. the IMCI
  and TFD recomputes, confirming the refusal is exactly the delegate-count reconciliation gap
  and nothing else). Fences (2) and (3) were pinned as EXPECTED negatives in the anvil E2E and
  left in force. Suites: Foundry 214/0/0 (twice; SKIP_GROTH16 irrelevant — gate no longer
  exists), base e2e 1/1, mle_onchain_e2e 1/1, two-token anvil E2E 1/1, node 45/45, wasm32 lib
  check green. Awaiting the mandatory full-suite attacker pass before deploy (next Phase 5
  item).

- **Phase 5a (2026-07-27)**: post-close claim token binding complete (see Phase 5a status
  above). The phase began with a STOP-and-report: the tasked premise (claim circuit opens an
  IMI2 token field) was wrong — no anchored preimage carried the token, and an IMI2 in-circuit
  recompute would have been VACUOUS (no anchor to compare against). The gap analysis became
  TM-16; the approved ids-limb design (near-zero constraint cost, protocol-level change to the
  accumulator-leaf fold) was implemented WITH its obligations: token-free replay-ledger
  re-keying (MATERIAL — defeats the cross-token double-credit that the token-bearing hash would
  otherwise enable), absorb-time tx_hash recompute at all three gates (single-sourced token),
  single-wire PI binding, strict Solidity limb bind + per-token accrual. No existing assertion
  was weakened: the one REPLACED Foundry test (`test_postCloseClaim_genesisTokenPin`) asserted
  the temporary pin this phase's specified deliverable removes; its replacement asserts the
  proof-bound per-token semantics plus three new negatives. Setup-only updates: test fixtures
  that carried FAKE `tx_hash` values (e2e_flow harness, pis unit test) now compute the real
  fold — required by the new fail-closed recompute checks, assertions unchanged. Suites:
  post_close_claim 12 (incl. 2 new circuit negatives + non-genesis happy path),
  state_update_verifier 43, e2e_flow 17 (+1 new relabel-gate test), common::channel 31 (+1
  identity/binding test), delegate_send_tests 22, cancel_close 15, _pis roundtrips green;
  `cargo build --release`, wasm32 lib check, fixture-bin feature check green; clippy warning
  count identical pre/post (302 — no new warnings); Foundry 213/0/1 (SKIP_GROTH16);
  node/ 45/45 (`chain-watcher` fragment updated with the event change, per the Phase 4 lesson);
  all contracts under EIP-170. Post-close fixtures invalidated as expected (Phase 5b).
  Awaiting the mandatory separate security-review / attacker pass over the diff before merge.

- **Phase 4 (2026-07-27)**: CLI/WASM/JS plumbing complete (see Phase 4 status above). All
  `SECURITY(multitoken-phase4)` markers discharged (repo-wide grep: zero phase markers remain);
  the TokenRegister ChannelState-level dispatch and the CloseIntent gate lift landed WITH their
  test suites in the same change-unit; no existing test was weakened (the one REPLACED test —
  `close_intent_rejects_nonzero_non_genesis_funds` — asserted the temporary fail-close that this
  phase's specified deliverable removes; its replacement asserts the new per-token semantics
  PLUS the burn-mismatch rejection). The close-gate semantics determination was made against
  §N-6 + the Phase 3 Manager code (burn = amounts[0] only; per-token claims for the rest) — not
  ambiguous, so no stop-and-report was needed. Suites: state_update_verifier 43,
  common::channel 30, balance_state 19, delegate_send_tests 22, e2e_flow 16,
  partial_withdrawal 4, slot_capacity 2 — all green; `cargo build --release` green; wasm32 lib
  check green; all test targets compile; node/ 45/45; `node --check` clean on every changed JS
  file. Flagged during the work: node/common/wallet.js wrappers were calling the wasm-bindgen
  entries with extra positional args (senderSlot/nonce/slot), silently shifting parameters —
  aligned to the real signatures as part of the token-arg change (behavioral fix, disclosed).
  Awaiting the mandatory separate security-review / attacker pass over the diff before merge.

- **Phase 3 (2026-07-27)**: L1 Solidity escrow + per-token settlement complete (see Phase 3
  status above). Full Foundry suite (SKIP_GROTH16): 208 passed / 0 failed / 1 self-skip (the
  documented stale-fixture CloseLifecycleE2E close section, pending Phase 5). The two expected
  behavior-change failures (accounting-only nonzero-index deposit test; rollback-gas test using
  unregistered indices) were updated to the retired-regime semantics — no test was weakened to
  pass (the retirement IS the specified change, §N-7). Shared vectors regenerated from Rust and
  independently cross-checked by reconstructing both preimages byte-by-byte from the documented
  layouts and hashing with cast keccak — both reconstructions matched the Rust outputs exactly
  (no unexpected results). IntmaxRollup stayed under EIP-170 (23,855 B) BECAUSE the ERC-20 path
  shares the factored `_verifyWithdrawalSet` core with `withdrawNative`. Awaiting the mandatory
  separate security-review / attacker pass over the diff before merge (per the phase gate).
- **Phase 2b (2026-07-27)**: transition-verifier semantics generalization complete (see Phase 2b
  status above). Gate lift landed WITH the full TM-2 suite in the same change-unit; no existing
  test needed weakening or adjustment (no unexpected failures — the per-token checks Phase 1
  wrote behind the gate held as designed). IMIT re-versioned to IMI2 (explicit domain-analysis
  in constants.rs; the task's premise that cancel_close_circuit recomputes IMIT in-circuit was
  STALE — the Finding-D correction had already removed that recompute, verified by repo-wide
  grep for the domain word). Awaiting the separate security-review pass before merge.
- **Phase 2a (2026-07-27)**: circuit migration to the v2 layouts complete (see Phase 2a status
  above). All 36 Phase-1-gated proving tests re-enabled and green with assertions unchanged; h1
  gadget parity restored; 8 new adversarial tests (close: TFD-mismatch, duplicate-registry;
  claim: tampered token_slot, inactive position, cross-position ciphertext, tampered
  token_index, cross-token nullifier replay both directions, + native IMCW own-limb golden) all
  reject as designed — no negative test unexpectedly proved. `cargo build --release` green,
  wasm32 lib check green, clippy clean on changed lines. No circuit CONFIG or security-parameter
  changes anywhere (all circuits keep `standard_recursion_zk_config`); the close circuit builds
  at degree bits 17 with the widened preimages. Awaiting the mandatory separate security-review
  pass before merge.
