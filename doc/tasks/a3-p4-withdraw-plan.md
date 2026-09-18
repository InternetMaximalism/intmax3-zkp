# A-3 P4 `withdraw` — implementation plan + threat model

Parent documents: `doc/tasks/a3-close-lifecycle-spec.md` / `doc/tasks/a3-impl-todo.md` / `doc/tasks/a3-p4-withdraw-handoff.md`.
Decisions (user-approved): **Q1 = embed the whole pipeline in withdraw**, **Q2 = the builders live in wallet_core**, **Q3 = fully automated, including anvil**.

## 0. Goal (completion criteria)
`channel_member withdraw <manager> [rpc]` generates a real channel's withdrawal proof and drives
**registerChannel → deposit → postBlock×3 (blob) → finalize → withdrawNative → pullChannelFunds** through
live (anvil). Assert that the manager's L1 balance increases.

## 1. Architectural facts established (investigated)
- `withdrawNative` requires `finalizedStateRoots[extCommitment]` (`IntmaxRollup.sol:1262`).
  → the withdrawal proof's ext_commitment must be a **finalized rollup root**.
- finalize presupposes that **3 blocks (registration / deposit / withdrawal-tx) have been postBlock'd**
  (`fullVerify` cross-checks against `blockHashChainAt[finalBlockNumber]`).
- postBlock is an **EIP-4844 blob tx** (`postBlockAndSubmit`, 1 ETH stake). **forge script cannot do blobs** →
  send it with `cast send --blob --path <128KiB>` (the existing procedure in `doc/docs/sepolia-smoke-runbook.md`).
- The authoritative on-chain sequence = `contracts/test/WithdrawNativeE2E.t.sol::_runLifecycleThroughFinalize`:
  1. `registerChannel(channelId,bpSlot,0,sphincs[],pkBs[],regev[],recipients[])`
  2. postBlock(block0=registration)  ← blob
  3. `deposit{value}(recipient,token,amount,aux)` (msg.sender == the proven depositor)
  4. postBlock(block1=deposit)  ← blob
  5. postBlock(block2=withdrawal)  ← blob; this submissionId is the one to finalize
  6. `finalize(subId, finalRoot, vpis, validityMle)`
  7. `withdrawNative(ws, prover, withdrawalMle)`
  8. `pullChannelFunds()` (the manager pulls only that channel's share via rollup.withdraw(expectedAmount))
- The 4 artifacts (emitted by `generate_withdrawal_fixture.rs`; `build_channel_withdrawal` generates the same ones):
  `lifecycle.json` / `lifecycle_validity_mle.json` / `withdrawal_mle.json` / `withdrawal_payout.json`.

## 2. Implementation steps
- [ ] **S1. wallet_core::build_channel_withdrawal** — move the whole `generate_withdrawal_fixture.rs` pipeline
  (Phase1 registration → Phase2 deposit → Phase3 withdrawal-tx → Phase4 block-hash-chain + validity →
  wrap+MLE×2 → sanity re-fold → assembling the 4 JSON artifacts) into `wallet_core.rs`.
  - `ChannelWithdrawalParams { channel_id, deposit_amount, withdrawal_amount, depositor: Option<Address>,
    withdrawal_recipient: Option<Address> }` (None = the previous rng-derived behavior = fixture parity preserved).
  - Return value `ChannelWithdrawalArtifacts { lifecycle_json, validity_mle_json, withdrawal_mle_json, payout_json }`.
  - Move the fixture structs (LifecycleFixture etc.) into wallet_core; the binary just writes the strings.
- [ ] **S2. make generate_withdrawal_fixture.rs delegate** — read the env vars (WD_DEPOSITOR/WD_RECIPIENT/WD_OUT_PREFIX) →
  call `build_channel_withdrawal` → write the 4 files. **The output is byte-identical to before.**
- [x] **S3. parity verification (done; finding updated)** — **MLE/WHIR proofs are non-deterministic** (ZK blinding/masking;
  two runs of the same binary produce differing MLE bytes). Byte parity is therefore impossible = it is not the right verification criterion.
  The correct criterion, confirmed in practice: **the structural/semantic fields (genesis/final state root, vpis, blocks, deposit,
  registration, and the withdrawal_payout recipient/amount/nullifier/ext_commitment) match the committed fixture
  exactly** (✓), plus the builder's internal self-verification (verify_mle_proof×2, single/chain/validity verify, keccak re-fold,
  ext_commitment match) all PASS (✓ the binary ran to completion). → the port is faithful. The committed fixtures were restored via git checkout.
- [ ] **S4. self-verify test** — add `#[cfg_attr(debug_assertions, ignore)] a3_channel_withdrawal_builds_and_verifies` to `wallet_core`:
  build → withdrawal proof self-verify + ext_commitment==validity final root + withdrawal keccak re-fold match.
  Same shape as the P2 builders.
- [ ] **S5. add persistence to setup-backing** — add `deposit_salt`, `depositor`, `deposit_recipient` to `ChannelBacking`
  (the depositor is already taken from the live receipt = `channel_member.rs:360`). Needed so `cmd_withdraw` can reconstruct the same deposit.
- [ ] **S6. cmd_withdraw** — drive the on-chain sequence above with cast/forge:
  - build_channel_withdrawal (the channel's real params + recipient=manager) → write the 4 JSON files → stage them into `sepolia_*`.
  - registerChannel / deposit / postBlock×3 (`cast send --blob --path blob.bin`) / finalize (forge RunClose finalizeStep) /
    withdrawNative (the existing forge RunClose withdrawNativeStep) / `cast send <manager> pullChannelFunds()`.
  - Replace the dispatcher's `"withdraw" => cmd_close_lifecycle_unimplemented` with `cmd_withdraw`.
- [ ] **S7. live verification (anvil)** — fresh deploy + VK init (validity/withdrawal) + register + the whole withdraw run →
  assert the manager's balance increases. `#[ignore]` + release.

## 3. Threat model (attacker subagent perspective)
Soundness is **entirely in-circuit + on-chain**. The CLI is only wiring. Attack-surface review:
1. **over/double-withdraw**: the used-nullifier map + the `totalEscrowed` decrement + the `pendingWithdrawals` pull,
   plus `totalCreditedOut ≤ receivedChannelFunds` (the manager-side global cap). The CLI cannot choose the value (the payout comes from the proof PI). ✅ existing REAL.
2. **fake ext_commitment**: the `finalizedStateRoots[ext]` gate. finalize verifies the validity MLE/WHIR + the PI binding.
   Even if the CLI passes an arbitrary root, finalize fails (fail-closed). ✅
3. **tampered withdrawal set**: withdrawNative cross-checks pis_hash via a keccak re-fold. Tampering with the amount → revert. ✅ (demonstrated in WithdrawNativeE2E).
4. **depositor mismatch**: the deposit hash folds in msg.sender. If the proven depositor and the on-chain msg.sender diverge, the
   block2 hash mismatches → finalize reverts. → off local, `cast send --account $INTMAX_L1_ACCOUNT` guarantees the sender ==
   the proven depositor (using the persisted depositor). Raw keys are only the public Anvil key on chain 31337.
5. **registration mismatch**: if registerChannel's member set does not match the proof's registration block → block1 hash mismatch → finalize reverts.
   → pass lifecycle.json's registration straight into registerChannel.
6. **fixture contention**: withdraw/claim/close all stage into `sepolia_*`. **Write immediately before each step** (order must be respected).
7. **port bugs in build_channel_withdrawal**: the S3 byte-parity check guarantees a match with the reference. Any difference = stop immediately.
8. **secret keys**: off local, select the Foundry encrypted keystore's `INTMAX_L1_ACCOUNT` with
   `--account`, and never put the secret key/password in argv. The public dev key is for anvil 31337 only.
9. **IntmaxRollup/Manager bytecode unchanged**: do not modify them at all (avoiding CREATE2 drift → fixture regeneration).

**Invariant checks (mandatory before completion)**:
- [ ] the withdrawal proof self-verifies PASS, ext_commitment == validity final root, keccak re-fold matches (S4).
- [ ] build_channel_withdrawal is byte-identical to the reference (S3).
- [ ] cmd_withdraw does not change the IntmaxRollup/Manager bytecode.
- [ ] withdrawNative + pullChannelFunds succeed live and the manager's balance increases (S7).

## 4. Findings log
- **S1–S2 done**: `build_channel_withdrawal` moved into wallet_core, `generate_withdrawal_fixture` made to delegate. compile OK.
- **S3 done (finding)**: MLE/WHIR is non-deterministic because of ZK blinding (two runs of the same binary differ in the MLE bytes). Byte parity is impossible = it was the wrong criterion.
  Confirmed under the correct criterion: the structural/semantic fields (state roots, vpis, blocks, deposit, registration, payout) match the committed ones +
  all internal self-verification PASS. Saved to memory [[project_mle_whir_nondeterministic]].
- **S4 done**: `a3_channel_withdrawal_builds_and_verifies` PASS (94.8s). amount == the requested amount, ext_commitment == final root.
- **S5 made unnecessary**: the pipeline is self-contained (cmd_withdraw makes its own deposit, depositor = the sending key) → no setup-backing persistence needed.
- **S6 done**: `cmd_withdraw` implemented, dispatcher replaced, the unimplemented stub removed. compile OK.
- **S7 done (anvil live)**: DeployClose → `INTMAX_CHANNEL=1 ROLLUP=… channel_member withdraw <manager>`.
  Result: manager 0→3 ETH, pendingWithdrawals 3→0, totalEscrowed=7, receivedChannelFunds=3, finalizedBlock=3. **All invariants ✓.**

## 5. Completion summary
P4 `withdraw` is complete. Every CLI command in the close lifecycle (close→settle→withdraw→claim) works end to end live.
Soundness is in-circuit + on-chain (the CLI is only wiring, the payout comes from the proof PI and cannot be tampered with, and
finalize/withdrawNative are fail-closed gates). Remaining: P5 (relay + a full close-lifecycle E2E, integrated with a real channel deposit), P6 (turning the stubs into reverts).
