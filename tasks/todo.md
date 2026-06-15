# Task: Make the payment channel real (eliminate all stubs) — real ETH escrow + real on-chain settlement + value transfer

Status: IN PROGRESS — user instruction "fix all the stubs, send funds via a real payment channel → close, redeploy".
Option A (memory project_channel_close_unification): channel close = real base-intmax L1 native withdrawal,
bound to latestFinalizedStateRoot, native payout + nullifier. Design investigation complete (design ii-b adopted).

## Architecture decision (design ii-b, investigation confirmed)
- **Withdrawals are not inside the ext-commitment** (no withdrawal root in ext_public_state.rs:38-47).
- The existing `WithdrawalCircuit`(withdrawal_circuit.rs:175) folds `Withdrawal{recipient,token_index,amount,nullifier,aux_data}`
  into a keccak `withdrawal_hash` chain, and via PI `ext_public_state_commitment` it is **already bound to latestFinalizedStateRoot**.
- → Verify this with the **shared MleVerifier** (hold a separate withdrawal VK in IntmaxRollup, with verify taking the VK as an argument).
  On L1, re-fold the keccak chain to bind each Withdrawal leaf to the proof root → payout via nullifier + totalEscrowed underflow.
- **No validity VK regeneration needed** (design i = adding a withdrawal root to ext-state is the most expensive, so avoid it).
- EIP-170: do not create a second verifier contract (shared). The withdrawal VK uses the same MleVerifier too.

## Non-negotiable invariants
- **cross-channel solvency (Σ payout ≤ real escrow) = enforced by real ZK**. The payout amount is the amount PI of the verified withdrawal proof (not a prover claim).
  The underflow revert of `totalEscrowed -= amount` is the global guard.
- intra-channel split = two-party signed close intent + challenge window (need not be full ZK, accepted).

## Threat model (attack → mitigation)
- (a) over-withdrawal/cross-channel theft → payout = the amount of the verified proof, totalEscrowed underflow revert, demote finalizedChannelFundAmount to a non-authoritative hint.
- (b) double withdrawal/replay → rollup-level `withdrawalNullifierUsed[nullifier]`(existing settled_transfer.nullifier()). manager-level is kept as-is for intra split. CEI(check→set→pay).
- (c) forged close state → aggregate is capped by the proof, intra uses challenge + `_isNewer` strict ordering, member_set_commitment checked against the registration set (after verifyCloseIntent is made real).
- (d) reentrancy → all ETH-moving functions nonReentrant + CEI, pull-payment preferred.
- (e) escrow drift → deposit payable with `msg.value==amount`(ETH index)/`==0`(other), totalEscrowed single accumulator + underflow revert.
- (f) registerChannel/close front-run → one-time registration(existing) + commitment check at manager construction, payout recipient fixed by proof PI.
- (g) challenge/grace griefing → `_isNewer` strict `>`, fixed challengeDeadline, pull-payment so finalize cannot be blocked.
- (h) replay against a different finalized root → nullifier is unique and root-independent, only retained roots are accepted.
- (i) divergence between ETH received by the manager and finalizedChannelFundAmount → set from the received msg.value, intent.channelFundAmount is only a consistency check.

## P3+P4 execution spec (2026-06-14 investigation confirmed) — making close real

Decision (user): P2 committed (ae06923) → P3+P4 (make close real).

### Current state (investigation confirmed, file:line)
- `ChannelSettlementManager.claimWithdrawalCredit`(827-832): only zeroes out the credit, **no real ETH transfer**. No receive()/fallback() = cannot hold ETH.
- `finalizedChannelFundAmount`(374): a solvency cap, but **copied from the intent claim**(719) = forgeable. `submitWithdrawalClaim`(770) has a cap check, **`submitPostCloseClaim`(786-825) lacks a cap check** (does withdrawalCredits += but does not add to totalWithdrawn).
- The manager references the rollup as `IChannelRegistry`(read-only); there is no withdrawNative call/receive path. The manager is deployed after registerChannel (member set/bp checked in the constructor).
- ChannelSettlementVerifier: every verify* is a `_matches(proof==keccak(PI))` stub.

### Design (consistent with approved plan project_channel_close_unification)
**Core**: close aggregate settlement = **run the channel-as-user withdrawal proof (recipient=manager) via the P2 `withdrawNative`** → `pendingWithdrawals[manager]`. The manager actually receives it and distributes to members as a cap. Since base intmax = per-channel (base account = channel_id), this is an aggregate withdrawal, and member split is at the channel layer (intra, accepted-stub).
- **P3-a make manager hold real ETH**: `receive() payable`(**only msg.sender==rollup**, reject misdirected sends) + `pullChannelFunds()`(call `rollup.withdraw()`, record the balance delta into `receivedChannelFunds`).
- **P3-b demote the cap to the actually-received amount**: change `finalizedChannelFundAmount` from intent claim → **actually-received amount (the balance delta of pullChannelFunds)**. The intent's channelFundAmount is only a consistency check (non-authoritative hint). This is the non-negotiable invariant of cross-channel isolation.
- **P3-c make claimWithdrawalCredit transfer for real**: CEI+nonReentrant, `Σ credits ≤ receivedChannelFunds`, `address(this).balance>=amount`, pull-payment.
- **P3-d add a cap to submitPostCloseClaim**: add to totalWithdrawn + enforce `≤ receivedChannelFunds` (close the currently-missing hole).
- **P4 organize verify* (documentation)**: aggregate solvency is borne by withdrawNative's real MLE proof + the actually-received cap (real enforcement). verifyCloseIntent/WithdrawalClaim/PostCloseClaim/SpecialClose/CancelClose/LateOutgoingDebit are explicitly documented as **intra-channel agreement (two-party signature+challenge) = accepted-stub** (real ZK replacement is out of this scope, intra-channel risk is accepted).

### Threat model (attack→mitigation)
- (a) over-cap distribution/cross-channel theft → claimWithdrawalCredit's `Σ≤receivedChannelFunds` + balance check, cap on both submitWithdrawalClaim/PostCloseClaim. The received amount is withdrawNative's real proof amount (not the intent claim).
- (b) misdirected ETH stuck in manager → restrict receive() to rollup only.
- (c) close proof recipient forgery → withdrawNative's pis_hash binding (the recipient comes from the proof, demonstrated in P2).
- (d) reentrancy → all ETH-moving functions nonReentrant+CEI, pull-payment.
- (e) finalizedChannelFundAmount forgery → demoted to the actually-received amount (the pull balance delta), ignore the intent claim.
- (f) manager address ↔ proof recipient match → the close withdrawal proof's recipient=manager. Fixture/tests fix a deterministic manager address at proof-generation time via CREATE2 etc.

### Verification
- Solidity unit: receive restriction, pullChannelFunds, claimWithdrawalCredit real transfer, cap (both claims), reentrancy.
- Full e2e (optional, heavy): regenerate the recipient=manager close withdrawal fixture (heavy run + CREATE2 manager) → deposit → close aggregate withdrawal → manager receives → finalizeClose → submitWithdrawalClaim → claimWithdrawalCredit → member real ETH.
- Independent adversarial review.

### 2026-06-14 P3+P4 complete ✅ (Solidity unit scope)
- Implementation (ChannelSettlementManager.sol): `receive()`(rollup only) + `pullChannelFunds()`(nonReentrant, balance delta→receivedChannelFunds) + `claimWithdrawalCredit`(nonReentrant+CEI, real ETH transfer, `totalCreditedOut+amount<=receivedChannelFunds` = cross-channel solvency cap) + added the missing cap to `submitPostCloseClaim` + reentrancy guard + demoted `finalizedChannelFundAmount` to a non-authoritative hint. Added `withdraw()` to `IChannelRegistry`.
- P4: stated the trust boundary explicitly in the ChannelSettlementVerifier header (verify* are intra-channel accepted-stubs, cross-channel solvency is guaranteed by withdrawNative's real MLE + receivedChannelFunds cap).
- Tests: added 6 P3 tests to ChannelSettlementManager.t.sol (receive reject/pull/real transfer/over-cap revert/postClose cap/reentrancy blocked). Added withdraw()+creditWithdrawal to MockChannelRegistry.
- **All Forge 87/87 green** (IntmaxRollup 47 + ChannelSettlement 31 + MleE2E 2 + MleFinalizeE2E 1 + WithdrawNativeE2E 6). EIP-170: manager 11.4KB, IntmaxRollup +112B.
- **Independent adversarial review: SOUND** (no critical/high). Cross-channel isolation in 2 layers (rollup totalEscrowed + manager receivedChannelFunds). Remaining LOW: finalizedChannelFundAmount footgun (intra-channel liveness, accepted and documented), fundBpBondCredits is intent-level (bounded by the payout cap, pre-existing).
- **All three original stubs now made real**: ① non-payable deposit → real escrow (P1) ② settlement digest stub → manager real ETH+cap+close → withdrawNative wiring (P3/P4) ③ value-less withdrawal → withdrawNative real payout (P2). The remaining accepted-stub is only the intra-channel split (not needed for cross-channel safety).
- Remaining: P7 Sepolia redeploy + real 2-member lifecycle (after checkpoint).

### 2026-06-14 local close e2e (in progress, incomplete)
User choice: "local close e2e first" (rehearsal before Sepolia).
- **Done**: extended `generate_withdrawal_fixture.rs` for close support (compiles). With `WD_RECIPIENT=0x..20bytes`,
  set the withdrawal recipient to the manager address, and with `WD_OUT_PREFIX=close_` output under aliased names (do not overwrite the P2 fixture).
  Added `parse_address_hex`. **working tree uncommitted**.
- **Remaining recipe (CREATE2 orchestration is the core)**:
  1. With the canonical CREATE2 factory(0x4e59b44847b379578588920cA78FbF26c0B4956C),
     compute the deterministic addresses of
     MleVerifier→IntmaxRollup(VK arg from the existing lifecycle_validity_mle.json, the VK is the same circuit so unchanged for close too)→
     ChannelSettlementVerifier→ChannelSettlementManager(registry=rollup addr, bindings from lifecycle.json
     registration) via a chain of `vm.computeCreate2Address` → fix the manager addr.
     Using the factory is deployer-independent = the compute script and the actual test get the same address.
  2. `WD_RECIPIENT=<manager addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture`
     (heavy run ~2 min) → close_lifecycle.json / close_lifecycle_validity_mle.json / close_withdrawal_mle.json /
     close_withdrawal_payout.json. Assert the VK matches P2 (addr consistency).
  3. CloseLifecycleE2E.t.sol (WithdrawNativeE2E + ChannelSettlementManager patterns combined): deploy for real with the same CREATE2
     → initializeWithdrawalVk → registerChannel(lifecycle.registration) → deposit{value} →
     postBlock×3 → finalize(validity) → withdrawNative([recipient=manager],prover,close withdrawal proof) →
     manager.pullChannelFunds() → requestClose→submitCloseIntent(stub)→finalizeClose→
     submitWithdrawalClaim(stub, member, amount≤received)→claimWithdrawalCredit→member receives real ETH + cap verification.
  4. Independent review → checkpoint → P7 Sepolia.
- Note: P1–P4 (the main stub-elimination body) is complete and committed (ae06923,8dfca7f). The close e2e is a verification rehearsal.

### 2026-06-14 local close e2e complete ✅
- `CloseLifecycleE2E.t.sol` **PASS**: deploy(CREATE2)→registerChannel→deposit{value}→postBlock×3→
  finalize(real validity MLE)→withdrawNative(recipient=manager, real withdrawal MLE)→pullChannelFunds→
  requestClose→submitCloseIntent→finalizeClose→submitWithdrawalClaim→claimWithdrawalCredit→**member receives real ETH**.
  manager(actual)=0x5Ddb = matches the baked-in recipient. All Forge 89/89 green.
- **Important lesson (CREATE2 + external library linking)**: `MleVerifier` uses external libraries (delegatecall), and
  the linked library address is baked into `type(MleVerifier).creationCode`. Foundry links the library
  to **different addresses in script vs test**, so the manager CREATE2 address diverges between script/test.
  → **Always compute the address in the test context** (`CloseManagerAddr.t.sol::test_printCloseManagerAddress`).
  The rollup initcode is fully identical for the P2/close fixtures (the VK is witness-independent), so it can be computed from the P2 fixture.
- Procedure (runbook): (1) `forge test --match-test test_printCloseManagerAddress -vv` → obtain the manager addr.
  (2) `WD_RECIPIENT=<addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture`.
  (3) `forge test --match-path test/CloseLifecycleE2E.t.sol`.
- New: CloseE2EBase.sol (shared CREATE2 deploy), CloseManagerAddr.t.sol, CloseLifecycleE2E.t.sol,
  4 close_*.json fixtures. Added WD_RECIPIENT/WD_OUT_PREFIX support to generate_withdrawal_fixture.
- **Next: P7 Sepolia redeploy + real 2-member lifecycle** (production is a normal deploy = deployer is an EOA, no CREATE2 factory
  problem. The key is .claude/priv, shell-expand only without reading the contents).

---

## P2 execution spec (2026-06-14 investigation confirmed — scope of this session)

Decision (user 2026-06-14): (1) **pipeline first, heavy proving once after review**, (2) **checkpoint at P2** (demonstrate deposit→finalize→withdrawNative on anvil → independent review → go/no-go). Do not touch P3+ and redeploy.

### Scope reality (revealed by investigation)
For an honest `deposit→finalize→withdrawNative`, the withdrawal proof's `ext_public_state_commitment` must
match the on-chain `latestFinalizedStateRoot`, which **only holds once a real validity proof for the same block
sequence (the 3 blocks registration→deposit→withdrawal) is finalized**. Therefore P2's heavy run generates
not only the withdrawal proof but **also the validity proof for the same chain** (effectively subsuming the P6 lifecycle). No shortcut.
Because `_postBlock` folds the real on-chain deposit/registration hash chains into the block hash, the test
actually calls `deposit()`/`registerChannel()` with the same parameters as the fixture.

### Binding formula (make-or-break, verified)
WithdrawalCircuit PI (= wrapped MleProof.publicInputs, **18 limbs**):
`[ pis_hash(8) ‖ ext_commitment(8) ‖ block_number(2) ]`(withdrawal_circuit.rs:206-208).
- `pis_hash = remove_3bits( keccak256( withdrawal_hash(32B) ‖ prover(20B) ‖ ext_commitment(32B) ‖ block_number(8B big-endian) ) )`
  - remove_3bits = `value & ((1<<253)-1)`(bytes32.rs:30 `limb[0] &= (1<<29)-1`).
- `withdrawal_hash` = keccak chain (seed=0): each leaf preimage (152B) =
  `prevHash(32) ‖ recipient(20=address) ‖ tokenIndex(4) ‖ amount(32=uint256 BE) ‖ nullifier(32) ‖ auxData(32)`
  (withdrawal.rs:97 / WITHDRAWAL_LEN=30 / solidity_keccak256 is u32→4B big-endian, same convention as `_computeBlockHash`).
- on-chain: ext_commitment is reconstructed as bytes32 from PI[8..16] → check `== latestFinalizedStateRoot`.
  block_number = PI[16]<<32 | PI[17]. Re-fold withdrawal_hash from the caller-supplied Withdrawal[] →
  recompute pis_hash → check it matches PI[0..8]. **The payout amount is the amount bound by the verified PI (not a prover claim)**.

### Rust (new binary `src/bin/generate_withdrawal_fixture.rs`, mirrors e2e.rs + generate_e2e_fixture.rs)
Minimal chain: ch1 registration block → deposit(amount=10) block → withdrawal send_tx(amount=3→L1 addr) block.
1. balance proof: receive_deposit → send_tx(withdrawal_transfer) (the internal transfer is omitted).
2. single_withdrawal → withdrawal chain(step, prev=None) → withdrawal final(ext_state after blk3, prover).
3. validity proof: fold the 3 blocks via block_hash_chain and validity_circuit.prove (the e2e.rs:454-495 loop).
4. wrap+MLE ×2: validity→`lifecycle_validity_mle.json`, withdrawal→`withdrawal_mle.json` (export_mle_json).
5. emit: `lifecycle_blocks.json` (postBlock SubBlock args for the 3 blocks + deposit()/registerChannel() args +
   each blockHashChainAt expected value + genesis/final root + VPIs), `withdrawal_payout.json` (Withdrawal[]{recipient,
   token_index,amount,nullifier,auxData} + prover + block_number + ext_commitment).
   Do not touch the existing smoke fixture (mle_fixture.json etc.) (separate files).
6. Rust-side sanity: assert that the on-chain-style withdrawal_hash re-fold (seed=0) matches the proof's withdrawal_hash.

### Solidity (IntmaxRollup.sol)
- **Add the second VK to the constructor** (immutable, no post-deploy mutation = minimal attack surface): `withdrawalMleVk` +
  `_whirParamsW` + `_mleKIsW` + `_mleSubgroupGenPowersW` + `whirProtocolIdW` + `whirSplitSessionIdW`.
  The MleVerifier is **shared** (EIP-170: do not create a second verifier contract). Mechanically update Deploy.s.sol + the existing test constructors.
- `_verifyMleWithdrawal(mleProof)` (mirrors `_verifyMle`, uses the withdrawal VK storage).
- `withdrawNative(Withdrawal[] calldata ws, address withdrawalProver, uint64 blockNumber, MleProof calldata proof)`:
  CEI+nonReentrant. ① `_verifyMleWithdrawal` ② ext_commitment(PI[8..16])==latestFinalizedStateRoot
  ③ withdrawal_hash re-fold→recompute pis_hash==PI[0..8] ④ each w: require token_index==ETH_TOKEN_INDEX (v1),
  `withdrawalNullifierUsed[nullifier]` check→set, `totalEscrowed -= amount` (underflow revert = global cap),
  `pendingWithdrawals[recipient] += amount` (pull-payment, reclaimed via the existing withdraw()).
- EIP-170: monitor the deployed size of IntmaxRollup.

### Tests (`contracts/test/WithdrawNativeE2E.t.sol`, mirrors MleFinalizeE2E.t.sol)
deploy(2 VK) → registerChannel/deposit{value:10}/postBlock×3 (fixture args) → finalize(validity proof, root=final)
→ withdrawNative(withdrawal proof) credits exactly 3 ETH to recipient in pendingWithdrawals + totalEscrowed 10→7 +
recipient receives real ETH via withdraw(). Negative cases: double (nullifier) revert, over-cap (amount>totalEscrowed) revert,
ext_commitment≠finalized revert, tampered Withdrawal (pis_hash mismatch) revert, non-ETH token_index revert.

## Phases
- [x] **P1 escrow** (small, no circuit change): IntmaxRollup.deposit() payable, ETH_TOKEN_INDEX, `msg.value==amount`, `totalEscrowed`, reject receive. Tests. **Complete (working tree, 5/5 green, uncommitted)**.
- [ ] **P2 native withdrawal payout (core, heaviest)**:
      - Rust: stand up the WrapperCircuit + MLE VK for `WithdrawalCircuit` (mirror the validity wrapper) + fixture emitter (new generate_*_fixture).
      - Solidity: add `withdrawNative(Withdrawal w, MleProof p)` to IntmaxRollup — mleVerifier.verify with the withdrawal VK, `w.ext_public_state_commitment==latestFinalizedStateRoot`, bind w to the root by re-folding the keccak chain, nullifier check/set, `totalEscrowed -=`, CEI+nonReentrant pull-payment.
      - Hold the withdrawal VK params in IntmaxRollup (separate from the validity VK). Monitor EIP-170.
      - Tests (anvil-driven): deposit→finalize→withdrawal proof→withdrawNative pays out exact ETH, double revert, over-cap revert.
- [ ] **P3 wire channel close to the withdrawal payout**: add receive() to the manager, finalizeClose requires the rollup native withdrawal to arrive and sets `finalizedChannelFundAmount=received amount`, make claimWithdrawalCredit transfer real ETH (CEI+nonReentrant). The close Withdrawal.recipient=manager. Test full close→payout→split.
- [ ] **P0/P4 make verifyCloseIntent real / organize ChannelSettlementVerifier**: route close to the withdrawal MLE path. The remaining verify* (specialClose etc.) stay signature/challenge-based in v1 (accepted-stub, documented). Really enforce member_set_commitment binding.
- [ ] **P5 independent security review** (agent separate from implementation, attacker viewpoint): cap/nullifier/reentrancy/escrow drift/close binding.
- [ ] **P6 multi-block lifecycle fixture** (register→deposit→transfer→withdrawal/close).
- [ ] **P7 anvil full rehearsal → Sepolia redeploy + run the real lifecycle** (opus→codex real ETH transfer).

## Crux of verification
- The real ETH deposited in P2 is paid out exactly by withdrawNative, and double/over-cap revert (anvil).
- codex can withdraw real ETH via close→payout→split (Sepolia).
- The independent review confirms cap=real proof, nullifier, reentrancy, escrow drift.

## Risks
- 🔴 P2 is the heaviest (WithdrawalCircuit's wrapper+MLE+fixture, new VK generation, heavy proving). EIP-170 makes a second verifier impossible = sharing is mandatory; if infeasible, add a withdrawal root to ext-state (the worst-case contingency of validity VK regeneration).
- 🔴 security-critical (moves real ETH). Independent review per phase is mandatory, CEI/nonReentrant thoroughly.
- The intra-channel split is an accepted-stub (two-party signature+challenge).

## Progress log

### 2026-06-14 P2 progress
- **P1 escrow: complete** (working tree, 5/5 green, uncommitted).
- **P2 Solidity: complete (core)**. Added `withdrawNative(Withdrawal[],address,MleProof)` to IntmaxRollup +
  binding helpers (`_foldWithdrawalLeaf`/`_withdrawalPisHash`/`_limbsToBytes32`/`_limbsMatchBytes32`) +
  second VK (`initializeWithdrawalVk`, deployer-only set-once, degreeBits>0 required, shared MleVerifier) +
  `_verifyMleWithVk(proof,bool)` (validity/withdrawal VK unified, EIP-170 reduction) + `withdrawalNullifierUsed`.
  EIP-170: IntmaxRollup runtime 24,498B (+78 margin, production deploy OK). **No regression**: IntmaxRollup.t
  47/47 + MleFinalizeE2E (real validity finalize is still green after the refactor) + MleE2E 2/2.
  - Removed the blockNumber argument (derived from PI[16..18], no redundant check needed since the pis_hash binding forces the value).
- **🔴 BLOCKER found (deposit hash chain semantics mismatch)**:
  In an honest 3-block lifecycle (reg→deposit→withdrawal), the **block hash of block3 (withdrawal, no deposit)
  mismatches between on-chain and Rust** → cannot finalize.
  - Rust (block_witness_generator.rs:617,631): each block carries `projected = self.deposit_hash_chain` (**cumulative**).
    block3 carries H(0‖dep) (block2's cumulative value).
  - on-chain (_postBlock:594-596): `batchDepositHashChain = _pendingDepositHashChain`, **reset to 0 every round**,
    no carry-forward. The block of an empty round carries depositHash=0, and the global
    depositHashChain is overwritten with 0 too. → block3 on-chain=0 ≠ Rust=H(0‖dep).
  - **Evidence of asymmetry**: the reg chain is carry-forwarded (the ternary at _postBlock:604+), only the deposit chain resets.
    → The deposit chain reset is a possible latent bug (it loses history despite being a cumulative ledger).
  - Because the deposit must be a block before the withdrawal (receive_deposit→send_tx order), an empty block
    after the deposit is unavoidable → without a contract change the honest lifecycle cannot finalize.
  - **Recommended fix**: make the deposit chain cumulative (carry-forward) = align with the reg chain pattern. However,
    the impact on deposit()/rollback/`test_blockDepositHash_persistAndRollback`/fraud path needs scrutiny, and it is
    a security-sensitive change touching the block-hash binding = validity binding. Out of scope (P2 assumed "no block model change") → needs user decision.

### 2026-06-14 make the deposit chain cumulative (user-approved: Fix deposit chain)
**Threat model (before code)**:
- Change (minimal): make `_pendingDepositHashChain` a **live cumulative chain** = (1) remove the
  `_pendingDepositHashChain = bytes32(0)` reset in `_postBlock`, (2) change the intermediate sub-block's depositHash from
  `bytes32(0)`→`previousDepositHashChain` (the cumulative at the end of the immediately prior round). deposit() is unchanged (folds into the cumulative).
  The last sub-block carries `batchDepositHashChain = _pendingDepositHashChain` (= the current cumulative).
  `depositHashChain = batchDepositHashChain` is unchanged too. Consistent with the reg chain's carry-forward pattern.
- T1 validity binding: making it cumulative is a **fix to align with Rust's cumulative deposit_hash_chain** (previously
  it diverged across multiple rounds = a latent bug). Strictly more correct.
- T2 rollback soundness: `_rollbackBatch` needs no change. `pendingDepositHashChainBefore`/`previousDepositHashChain`
  already capture the cumulative at postBlock entry → restoring returns to the correct state. For deleted blocks,
  blockDepositHash is deleted (zeroing is correct since the block itself disappears). No per-deposit loop = O(1) maintained.
- T3 re-post: after rollback `_pendingDepositHashChain` retains cumulative-with-deposits → the deposit can be re-posted
  while still pending. processedDepositCount is restored too.
- T4 empty round: previously depositHashChain was overwritten with 0 (history loss) → carry-forward preserves the cumulative.
- T5 impact on existing tests: as long as there is no prior round with a deposit, previousDepositHashChain=0 = the intermediate
  is also 0, identical to before. Existing tests (batchOf3/twoRounds have no deposits, persistAndRollback is 0 due to block deletion,
  blockHashChannelRegDifferential calls `_computeBlockHash` directly without going through _postBlock) are expected to be unchanged. Need to confirm by running all.
- Verification: all Forge tests green + independent adversarial review.
- **Complete**: after all changes IntmaxRollup.t 47/47 + MleFinalizeE2E green, EIP-170 +47B (production deploy OK).

### 2026-06-14 P2 pipeline complete + independent review
- Rust `src/bin/generate_withdrawal_fixture.rs` (compiles, reg extraction confirmed byte-identical to to_reg_record,
  fixed the missing depositor export, includes a Rust-side sanity assert for the withdrawal keccak re-fold + ext_commitment).
- Solidity `contracts/test/WithdrawNativeE2E.t.sol` (compiles, self-skips when the fixture is not generated). Reuses FixtureLib.
- **Independent adversarial review: SOUND** (no theft/double-spend/replay/binding-forge path, byte layout fully matches).
  - F1(HIGH, trust boundary): per-token value conservation is a property of the circuit. v1 only escrows token0(ETH) = aggregate cap
    = effectively relaxed to the token0 cap, the rest relies on standard ZK soundness.
  - **F2(MEDIUM) fixed**: a withdrawal required an exact match to `latestFinalizedStateRoot` → the next finalize would lock out an honest
    withdrawer. Changed to the `finalizedStateRoots` set (permanent, non-rollbackable) = redeemable against any already-finalized
    root (the nullifier prevents double-spend).
  - F3(LOW): rollback drops post-batch pending deposits (the same existing pattern as the reg chain). Documented.
- Next: heavy proving run (generate_withdrawal_fixture) → run WithdrawNativeE2E on anvil/forge → checkpoint.

### 2026-06-14 P2 complete (checkpoint reached) ✅
- Heavy run succeeded (~2 min): 4 fixtures generated, withdrawal keccak re-fold sanity check PASSED.
- **One on-chain bug found and fixed**: the wrapped withdrawal PI is **17 limbs** (block_number is u63=1 field
  element, 1 limb in the registered form; only the pis_hash keccak preimage is 2×u32). Fixed `withdrawNative`'s `pi.length`
  and block_number extraction from 18/[hi,lo]→17/single limb.
- **WithdrawNativeE2E 6/6 PASS**: fullLifecycle (register→deposit{value}→postBlock×3→finalize(real
  validity MLE)→withdrawNative(real withdrawal MLE)→exact ETH payout + withdraw() receipt + totalEscrowed decrement),
  doubleSpend revert, beforeFinalize revert, tamperedAmount revert, vkNotSet revert, init access/set-once.
- **All Forge 81/81 green** (zero regression). EIP-170 +47B.
- **All P2 verification criteria met**: real escrow→real finalize→real withdrawNative pays out exact ETH, double/before-finalize/tampered revert.
- Uncommitted (awaiting user instruction). P3 (close→payout wiring) / P4 (settlement verifier) / P7 (Sepolia redeploy) are after checkpoint.

## Existing deployment (old smoke, empty-block genesis, to be replaced by redeploy)
- IntmaxRollup 0xBa057F093765a0AA4c4001d8deC5171E836A0af0 / MleVerifier 0x4154a4A27Ad06dc57Dab86e3a696e2454a62d871 (Sepolia)
- deployer 0x2C0BF10558adafDd21296CbF71dd6FE88c782C80, balance ~10 ETH (+1 ETH reclaimable)

## 2026-06-14 Third milestone: channel-to-channel transfer real Sepolia completion ✅
New deployment (manager-free / direct-to-EOA exit):
- IntmaxRollup  0x5D8e7BAfbFe2Fb79ca8D4a28C3DeC496528Aa452
- MleVerifier   0xf15a24686Ac6ce10d0c68D7d8005E6ddaE516d41
Order (the only order where the cumulative reg+deposit chain matches; pre-verified in C2CBlockHash.t.sol):
  register(ch1) -> postBlock(b0, empty) -> deposit(10wei real escrow) -> postBlock(b1, empty) ->
  **interleave register(ch2) between postBlocks** -> postBlock(b2, empty) -> postBlock(b3, ch1->ch2 transfer) ->
  postBlock(b4, ch2 withdrawal) -> finalize(sub=4, real validity MLE/WHIR) ->
  withdrawNative(ch2->EOA, real withdrawal MLE/WHIR) -> withdraw() (the recipient EOA receives real ETH)
Verification: blockHashChainAt(5)=0xc2f0da7f… = matches proved final_block_chain / latestFinalizedStateRoot=0x998c9aa3…(block5)
      / totalEscrowed 10->7 / pendingWithdrawals[EOA]=1ETH+3wei / receives real ETH via withdraw().
tx: register1 0x2e54f387… / deposit 0x85ca4b78… / register2 0xc533f4b2… / postBlock b0..b4
    (0xfdd36fd0/0x244bb605/0x6e15be7b/0x4ea9ea17/0x219bb32e) / finalize 0xfa3b13a2… /
    withdrawNative 0x4cf96d76… / withdraw 0x7d674fdd…
Tools: script/DeployC2C.s.sol, script/RunC2C.s.sol, test/C2CFullE2E.t.sol (in-EVM full e2e PASS),
        test/C2CBlockHash.t.sol (PASS), src/bin/generate_c2c_fixture.rs (added WD_PROVER_SEED).

### ★finding: withdrawal proof calldata clings to the 128KiB(131072B) per-tx limit
- single=130180B (below), c2c seed777=131012B→raw tx 131134B is rejected as oversized data by publicnode/drpc/tenderly all
  (128KiB = the universal go-ethereum txpool limit). WHIR/FRI auth-path pruning varies with the FS query index ⇒ ~800B variance across instances.
- Mitigation: vary the withdrawal_prover seed (= re-rolls pis_hash→FS→query index, statement/anchored root unchanged = demo-neutral) via
  WD_PROVER_SEED. With seed=1, 130084B<130950 ⇒ sent successfully. Set generate_c2c_fixture's default to 1.
  Future work: large proofs need blob-carried submission or proof compression.
- gotcha: sending withdraw() via forge script reverts due to a gas under-estimate ⇒ `cast send "withdraw()" --gas-limit 120000`.

### Incomplete / blocked
- [ ] CloseLifecycleE2E.t.sol: the reg-chain bytecode change shifts the manager CREATE2 addr 0x5Ddb…→0x2E37DF9A….
      Need to regenerate the close_* fixture with WD_RECIPIENT=0x2E37DF9AF5A948a1c2a5e2ad69dFdb390F164A55.
      **Currently blocked**: a parallel session's WASM wallet WIP (src/wallet_core.rs/wasm_wallet.rs/lib.rs/constants.rs/Cargo.*) is in an
      uncompiled state ⇒ generate_withdrawal_fixture cannot build. Once the lib compiles, regenerate→PASS is expected. The parallel work is untouchable.
- [x] **Correction (important)**: "if you finalize(0..3) with the same proof you can reclaim" is **wrong**. finalize
      requires `initialExtCommitment == latestFinalizedStateRoot`, and the sub4 finalize advanced latest from
      genesis→0x998c. Since the c2c proof's initial=genesis, finalize(0..3) returns false.
      ⇒ **the 4ETH stake of sub0..3 is unreclaimable with the current proof and stranded** (write-off recommended since it is Sepolia testnet ETH).
      The only reclaim path: generate a block5→block5 no-op validity proof and pass finalize(0..3) entirely with it (heavy, prover support unconfirmed).
      Lesson: each postBlockAndSubmit locks 1 stake and it only returns via finalize. To return all stakes in a multi-submission chain,
      either finalize each submission individually with an incremental proof, or bundle SubBlock[] into 1 call to reduce the number of submissions.
      ⇒ Added `test_c2c_postBlockStakes_recovery_and_strandedLesson` to C2CFullE2E.t.sol (the refund→withdraw normal path +
      the stranding of aggregate-proof re-finalize=false) to lock in the regression.
- [ ] commit/push: selectively stage only the c2c tools + reg-chain fix (lib.rs/wallet_core.rs/constants.rs/Cargo.* = exclude the parallel WIP). Awaiting user decision.

## 2026-06-15 stake stranding bug fix: add reclaimStake (threat model→adversarial review→implementation)
User pointed out "isn't the inability to reclaim stake a bug that would also happen in production?" → YES. Confirmed as a real fund-loss design flaw:
the POST_BLOCK_STAKE bond only returns via `finalize(that submission)`, but the aggregate proof finalizes only 1
submission (monotonically advancing latestFinalizedStateRoot), and skipped submissions cannot be finalized + fraudProof is
also blocked by a guard → the bond is permanently frozen. Since this is the system's standard behavior (aggregate finalize), real ETH is lost every round on mainnet.

Fix = `reclaimStake(submissionId)` (keep the fraud bond design, return the bond to the submitter after block confirmation):
- Conditions: stakeInfo live (not already refunded/slashed) + `endBlockNumber <= latestFinalizedBlockNumber`. Height only.
- Soundness: from INV-A (rollback cannot roll back below latestFinalizedBlockNumber → the blockHashChainAt at the finalized height is immutable) +
  INV-B (posting strictly advances blockNumber, and re-posting at the same height first truncates the prior submission = deletes stakeInfo),
  a live stake with end<=finalized is "the unique canonical finalized batch at that height" ⇒ the bond is settled ⇒ returning it is legitimate.
- Defense: add a `finalBlockNumber >= latestFinalizedBlockNumber` monotonic assert to fullVerify (on-chain reinforcement of INV-A).
Process: tasks/reclaim-stake-threat-model.md (threat model) → independent attacker subagent (flagged the height-only hole = HIGH) →
argued it is unreachable via INV-A/B and adopted height-only → independent security-review subagent ruled **SOUND-TO-MERGE** (INV-A/B verified,
double-pay/ETH conservation/spam all safe, the require→error conversion is behavior-preserving).
EIP-170: reclaimStake added +303B and went over, so converted require strings to custom errors (the nonReentrant
"ReentrancyGuard…" being duplicated many times by via_ir inline was the biggest contributor) → **24,404B / +172 margin** (better than the original +47).
Tests: contracts/test/ReclaimStake.t.sol 7/7 (full reclaim of stranded→real ETH, before-finalize revert, double/after-refund
revert, unknown revert, cannot reclaim after timeout-truncate, cannot reclaim→finalize twice, fresh bond on truncate→repost).
All Forge 96/97 (the only red is CloseLifecycleE2E's stale fixture = regeneration is blocked because the lib is uncompiled due to the parallel WASM WIP).
