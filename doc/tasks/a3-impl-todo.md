# A-3 main implementation — progress tracker

Spec: `doc/tasks/a3-close-lifecycle-spec.md` (approved, full scope)
Branch: `fix/audit-soundness-and-tests` (same branch as A-2 etc.)

Approved decisions: (1) on-chain anchor check included (2) implement everything (3) liveness grief is documented only

## P1 — real L1-close anchor ✅
- [x] Threat model (attacker subagent) — Threats 1-9 enumerated. The anchor is fund-safe (Option B); real custody is guaranteed by the existing withdrawal gate (IntmaxRollup.sol:1262)
- [x] PART A: `setup-backing` fetches `latestFinalizedStateRoot()` → stores it in `ChannelBacking.intmax_state_root`, placeholder removed, warns when zero (liveness documented). Compiles OK
- [x] **PART B is NOT adopted (user decision A)**: EIP-170 (IntmaxRollup margin 10B, a getter at ~70B is impossible) + redundant with the existing withdrawal gate (contributes nothing to fund safety). → no Solidity change = no close fixture regeneration needed, forge stays fully green
- [x] No test regressions (no automated test drives `setup-backing` = only relay/demo are live. Live confirmation of the anchor behavior is the P5 E2E)
- Note: live confirmation of the anchor behavior is deferred to the full E2E in P5

## P2 — wallet_core close builders
- [x] Threat model (attacker subagent) — conclusions reflected in the "P2 precise design" below

### P2 precise design (threat model settled; implementation guide)

**New `CloseProver` (wallet_core.rs, non-test):**
```
pub struct CloseProver { single_sig: &'static SingleSigCircuit, list: ListCircuit, close_circuit: ChannelCloseCircuit<F,C,D> }
CloseProver::new(balance_vd: &VerifierCircuitData) -> Self   // list = ListCircuit::new(single_sig.vd); close = ChannelCloseCircuit::new(balance_vd, list.vd)
```
- Reuses `single_sig_circuit()` (L204, existing shared). `list_circuit()` can also be made a shared OnceLock.

**`build_close_full_witness(state, member_keys[N], balance_proof, close_nonce, burn_tx_hash, snapshot_mbn) -> ChannelCloseFullWitness`:**
- close_tx = CloseWithdrawal{ channel_id, final_channel_state_digest=state.digest, final_balance_state_h1=state.balance_state.h1(), intmax_state_root=state.channel_fund.intmax_state_root, burn_tx_hash, burn_amount=state.channel_fund.amount, zkp=vec![] }
- close_intent = CloseIntent::new(close_nonce, &state, &close_tx, snapshot_mbn)?  ← **already has fail-closed binding checks built in** (channel_id/digest/h1/anchor/amount)
- member_auth + list_proof: for each member_keys[i], `single_sig.prove(signing_key, state.digest)` → `list.prove_append(&sig, list_commitment(pairs[0..i]), &prev)`, folded in slot order (same shape as fixture::member_auth_for_digest_n, but with real keys)
- **Rust fail-closed preconditions (threat model):** 2≤member_count≤MAX, member_keys.len()==member_count, state.digest computed, h1 matches, unallocated_confirmed_incoming==0, all pk_g distinct, the balance_proof's channel_id/settled_tx_chain match the close PI

**`prove_close(full_witness) -> close_proof` = close_circuit.prove(&w)** (member_set_commitment is overwritten by prove with the correct value = not tamperable)

**`prove_close_mle(close_proof) -> (mle_json, CloseProofFields)`** = WrapperCircuit + setup_mle_vk + prove_with_mle + export_mle_json (same procedure as generate_close_fixture.rs)

**IN-CIRCUIT soundness (the builder cannot bypass it; confirmed by the threat model):** H1/IMCH recomputation binding, the balance proof's channel_id/settled_tx_chain binding, ListCircuit C'==C (real signatures), member_set_commitment keccak, active_bits, member pk_g distinctness.

**`build_withdrawal_claim(final_balance_state, member_index, regev_sk, recipient) -> claim+proof`:** the amount is bound in-circuit to the decrypted value by decryption_core (over-claim impossible), and the regev pk is Poseidon-bound to the H1 commitment. Preconditions: member_index<active, the decrypted amount matches, the pk digest matches.
**`build_cancel_close(revived_state, close_intent)` / `build_post_close_claim(...)`:** wired to the existing circuits in the same way.

- [x] **CloseProver (new + build_full_witness + prove + close_vd) implemented, verified with a real-proof test, PASS (48.9s)**. build→prove→verify passes, and so does the negative case (key-count mismatch → Err). All public types are used without un-gating; `CloseIntent::new` fail-closed checks the binding.
- [x] **prove_mle (WrapperCircuit + MLE export, same procedure as generate_close_fixture) implemented, compiles OK** (including MLE self-verification. Runtime verification is via the P3 close fixture generation or a dedicated test)
- [x] **build_withdrawal_claim (WithdrawalClaimProver) implemented, real-proof test PASS (14.3s)**. Slot decryption → amount derivation, proving and verification with the E-3 + claim circuits, amount==decrypted value (over-claim impossible), padding slot rejected. wrap+MLE was factored out into the shared `wrap_and_export_mle` helper (also used by CloseProver).
- [x] **build_cancel_close (CancelCloseProver) implemented, real-proof test PASS (12.2s)**. Member signatures + list fold over the revived state's IMCH, the precondition revived_version > close_version is fail-closed, stale-state negative case.
- [x] **build_post_close_claim (PostCloseClaimProver) implemented, real-proof test PASS (13.7s)**. Delta extraction and decryption from source_tx, an inclusion proof from the accumulator, Stage-3 FullWitness construction. **All 4 P2 builders complete.**
- [x] **Security review (separate subagent, attacker's perspective) complete — no soundness defects**. All 5 builders match the verified fixtures field by field, soundness is in-circuit, secret keys are appropriately scoped, nullifiers are derived canonically, and amounts come from decryption. Optional defensive improvements (not required; fail-closed in-circuit):
  - (optional) an early era-fence check in CancelCloseProver
  - (optional) an early `incoming_tx_index < accumulator.len()` check in PostCloseClaimProver
  - (optional) early validation of the Regev pk length/canonicality in WithdrawalClaim/PostClose

### P2 verified (release-only #[ignore] tests)
- `a3_close_prover_builds_and_verifies_real_close_proof` (49s): real genesis state + real balance proof + 3 member signatures → close proof generated and verified.
- `a3_withdrawal_claim_prover_builds_and_verifies` (14s): slot0 claims and verifies the decrypted value 77; padding slot negative.

## P3 — CLI close + cancel-close
- [x] **`cmd_close <manager> [rpc]` implemented (compiles OK)**: load_state + N member keys + balance proof → close proof + MLE generated with the verified CloseProver → emits `close_intent.json`/`close_intent_mle.json` (same schema as generate_close_fixture, but from real state) → requestClose (cast) + submitCloseIntent (RunClose forge step, large calldata). Co-signature aggregation = signing with all member keys under CLI control.
  - Generation uses the verified CloseProver. Live verification (requires deploy + VK init) is the P5 E2E.
- [ ] implement `cancel-close`
- [ ] confirm requestClose→submitCloseIntent on anvil (P5 E2E)

## P4 — settle + withdraw + claim
- [x] **`settle <manager> [rpc]` implemented (compiles OK)**: reads the pending digest and the monotone request generation from the durable checkpoint and, immediately after re-validating them, casts `finalizeCloseGuarded(bytes32,uint64)`. close→Closed transition. The old no-arg selector was removed from the production ABI.
- [x] **`claim <manager> <member_slot> [rpc]` implemented (Rust + Solidity compile OK)**: close reconstruction → withdrawal-claim MLE + descriptor generated with the verified WithdrawalClaimProver (the amount comes from decryption = over-claim impossible) → **a working `submitWithdrawalClaimStep` was newly added** to RunClose → forge submit → claimWithdrawalCredit. env: CLAIM_RECIPIENT + the CLOSE_* variables must match those used for close. Live is P5.
- [x] **`withdraw` completed (whole pipeline embedded, verified live on anvil)** — decisions: Q1=embed the whole pipeline / Q2=builders live in wallet_core / Q3=fully automated including anvil. The plan + threat model are in `doc/tasks/a3-p4-withdraw-plan.md`.
  - **wallet_core::build_channel_withdrawal** (`ChannelWithdrawalParams`/`ChannelWithdrawalArtifacts`) = the whole `generate_withdrawal_fixture` pipeline (3-block reconstruction registration→deposit→withdrawal-tx + balance/single_withdrawal/chain/validity proofs + wrap+MLE×2 + keccak re-fold + ext_commitment match sanity check) moved over. **generate_withdrawal_fixture now delegates to it** (1 source of truth).
  - **Finding**: MLE/WHIR proofs are **non-deterministic** because of ZK blinding → byte parity is impossible. Verification is semantic (structural fields == the committed ones + internal self-verification + on-chain VK verification). Memory [[project_mle_whir_nondeterministic]].
  - **release self-verify test** `a3_channel_withdrawal_builds_and_verifies` (94.8s PASS): build → self-verify all proofs, payout amount==the requested amount (over-claim impossible), ext_commitment==final state root.
  - **cmd_withdraw** (`channel_member withdraw <manager> [rpc]`) = build → register (skipped if already done) → deposit (sender = depositor) → postBlock×3 (`cast send --blob`) → finalize (forge RunClose, SUB_ID=base+2) → withdrawNative (forge RunClose) → pullChannelFunds (cast). Dispatcher replacement + removal of `cmd_close_lifecycle_unimplemented` (all commands are now implemented).
- [x] **Real ETH received on anvil — verified**: deploy with DeployClose → `INTMAX_CHANNEL=1 ROLLUP=… channel_member withdraw <manager>` ran to completion. manager balance 0→3, pendingWithdrawals 3→0 (pulled), totalEscrowed=7 (=10-3), receivedChannelFunds=3, latestFinalizedBlockNumber=3. **close→settle→withdraw→claim can now be driven end to end from the CLI.**

## P5 — relay + full E2E
- [x] **P5-A `/api/close|settle|withdraw|claim` (done)**: added to `wallet/wallet-relay.js` + `wallet-relay-ec2.js`
  (same shape as `/api/inter/send`, a thin wrapper). The manager is taken from the body, the rollup from channel_backing.json, and the RPC is
  local=localhost:8545 / ec2=`process.env.RPC`. close passes CLOSE_SV, claim passes CLAIM_RECIPIENT, and withdraw passes ROLLUP via env. node --check green.
- [x] **P5-B integration core (done; unit + heavy verification)**: user decision = full integration. `build_channel_withdrawal` was
  extended so that it can be bound to **the channel's real member keys + the real deposit salt** (new argument `cli_member_keys: Option<&[MemberKeys]>`,
  and `deposit_salt: Option<Salt>` in params). When `Some`, `ChannelMemberKeys::from_member_keys` +
  `add_channel_registration_keys` **register with the real members**, and the deposit salt is the real value → a single on-chain registration + deposit
  can serve both close and withdraw. `None` is the previous behavior (fixture parity). `deposit_salt` is persisted in `ChannelBacking` (S5, `setup-backing`).
  `cmd_withdraw` gains an **integrated branch** (backing present → real members + real deposit; since the deposit was already made by setup-backing it **does not deposit again**,
  it only posts the blocks / backing absent → the previous standalone behavior).
  - **Verification**: the fast unit test `a3_withdraw_registration_matches_close_member_set` (no proving) = the withdraw registration's
    member-set commitment **matches exactly** the close path's `close_member_set_commitment(pk_gs)` (= proof that 1 registration satisfies both).
    The heavy `a3_channel_withdrawal_builds_and_verifies` (95.6s) = all proofs self-verify with the real members, and the registration emits the CLI members'
    pk_g. Both PASS. Full build green.
- [~] **P5-B live E2E (started; halted on 2 narrow gaps)**: tooling complete — `channel_member export-reg-record` (fast; emits the CLI members'
  reg record) + `contracts/script/DeployCloseCli.s.sol` (registerChannel with the CLI members + manager binding + validity/
  withdrawal/close VK init). On anvil: deploy (CLI members) → setup-backing (deposit 140M, deposit_salt persisted) → drives the **integrated
  withdraw**. **2 remaining issues were found (neither was hacked around; both escalated)**:
  1. **(correction) the close-path freeze nonce was a misdiagnosis = it is sound**: `CloseIntent::new` (channel.rs:763) computes
     `close_freeze_nonce = state.close_freeze_nonce + 1`, and the circuit also enforces `pis = state+1`. genesis(0) → intent(1), which **matches**
     the manager (1) after requestClose. The close-intent skip in `CloseLifecycleE2E` is mainly due to a **member-set mismatch, not the freeze**, and
     **this integration (unifying on the CLI members) resolves it**. **However, there is another, genuine gap**: `cmd_close` calls
     `submitCloseIntent` immediately after the guarded `requestClose(uint64,uint64)`, but the latter requires `GRACE_BEFORE_PROCESS_SECS=600` to have elapsed → on a real chain this gives `GracePeriodNotElapsed`.
     Either split `cmd_close` into request/submit, or use `evm_increaseTime` in the E2E (not a soundness issue = wiring).
  2. **deposit/registration folding mismatch in the integrated withdraw (genuine; root cause)**: on-chain, "the pending chain advanced by `deposit()`/`registerChannel`
     is absorbed by **the first block that is posted**". In standalone (withdraw emits block1, block2 and then deposit → absorbed in block3), this matched
     the proof model (deposit gets its own block), but in the integrated case **setup-backing's deposit is pending from before all the blocks**,
     so **block1 (registration) absorbs the deposit** → this structurally diverges from the proof's "deposit in block2" → the whole chain mismatches
     → `blockHashChainAt[3] ≠ final_block_chain` → finalize false. Proposed fix A (recommended): in the integrated case, change the block structure of `build_channel_withdrawal`
     to "fold both registration and deposit into the first block" = match the on-chain absorption order (a restructuring of `BlockWitnessGenerator`'s
     block generation order. The keystone is preserved).
  → **The integration core is verified** (the member-set-sharing unit test + the heavy self-verification of real-member proofs). The full live path = fix #2 via proposal A + the
     GRACE wiring for close. #2 is not a soundness issue (block-hash consistency), but it requires a careful remodeling.

### Progress on starting P5-B live (proposal B adopted, 2026-06)
User decision = **proposal B** (setup-backing does not deposit on-chain; withdraw deposits in the standard order. Proofs/circuits/generators unchanged).
Done, and bugs fixed:
- **Proposal B implementation**: a `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` mode in `setup-backing` (off-chain balance proof + params persistence only;
  the default is the previous behavior = a real deposit = the demo is unchanged). `cmd_withdraw` now always creates the deposit (the skip was removed). build OK.
- **close GRACE wiring (#1)**: `cmd_close` gained `CLOSE_ADVANCE_TIME`, which does `evm_increaseTime` after requestClose.
- **fix for the close forge step name bug**: `cmd_close` was calling a non-existent `submitCloseIntentStep()` → corrected to `closeIntentStep()`.
  (This had been latent because a live submit of the close intent had never been executed until now.)
- **live tooling**: `channel_member export-reg-record` (emits the CLI members' reg record) + `contracts/script/DeployCloseCli.s.sol`
  (registerChannel with the CLI members + manager binding + validity/withdrawal/close VK init).
- **How far the anvil verification got**: deploy (CLI members) → setup-backing (no-deposit) → init → **close: proof generation + requestClose +
  grace elapsed + closeIntentStep executed**. The close proof's **member_set_commitment / channel_id(7) / close_freeze_nonce(1)
  were confirmed to match on-chain** (the Rust↔Solidity close_member_set_commitment also matches).
- **#3 delegate_count resolved**: the initialized channel has 3 members + 1 delegate. The close proof binds delegate_count=1, so
  registration was unified to **4-active (3 members + 1 delegate)**: the generator gained `to_reg_record_split`/`add_channel_registration_keys_split`
  (member/delegate split) + `from_member_keys` now handles all active slots, `build_channel_withdrawal` derives delegate_count from the active count,
  `channel_member` gained `cli_active_keys()` (3 members + a delegate seed), `export-reg-record` emits 4 active, and `DeployCloseCli` gained
  a 4-active registerChannel + the manager's member/delegate bindings + **withdrawal-claim VK init**.
- [x] **P5-B full CLI E2E succeeded (anvil, real proofs, 2026-06)** 🎉: via `tests`/driver,
  deploy (DeployCloseCli) → setup-backing (no-deposit) → gen-contribution+init → **close** (submitCloseIntent OK = **the first live close verification**)
  → evm_increaseTime → **settle** (channelStatus=Closed) → **withdraw** (integrated: register skipped + deposit + postBlock×3 + finalize OK
  + withdrawNative 140000000 + pullChannelFunds) → **claim** (member slot 0 received real ETH 40000000, totalCreditedOut=40000000).
  The whole run is green. Soundness remains in-circuit + on-chain (proposal B makes the deposit fold consistent; circuits/contracts unchanged).

## P6 — post-close-claim + turning stubs into reverts + cleanup
- [ ] post-close-claim CLI/relay (optional, not started)
- [x] **P6-A turning specialClose / lateOutgoingDebit into reverts (done, attacker review GO)**: both entry points revert immediately
  (`SpecialCloseDisabled`/`LateOutgoingDebitDisabled`, `external pure`, selectors preserved). The 3 affected tests were replaced from
  disabled→revert (all 66 Manager tests PASS). The Manager bytecode changed → new CREATE2 manager
  `0xED5e1c64…1A8FA8`, close_ fixtures regenerated, CloseLifecycleE2E PASS. Details in `doc/tasks/a3-p6a-stub-revert-plan.md`.
  Dead-code removal is deferred (stated in detail2 §H-3).
- [x] **removing the fail-closed stubs + updating the followup (done)**: `cmd_close_lifecycle_unimplemented` was already removed in P4.
  `doc/tasks/a3-close-lifecycle-followup.md` updated to "nearly complete". detail2 §H-3 "IMPLEMENTED", and
  **D10** (the §K-4 on-chain anchor check was not adopted = an approved deviation; C2/C3 disabled) added to detail2-implementation-notes.md.

## Findings log
- (P1 started)
- **P5-B integration blocker (2026-06)**: the registration that withdraw generates for itself and close's real-member registration cannot
  coexist on the same channel. A full E2E requires extending the withdraw pipeline to bind to the real members/deposit (the part deferred from P4). Presented to the user.
