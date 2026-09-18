# Signer-independent exact-vector exit: handoff

## Scope of work

- Working branch: `codex/signerless-latest-head-exit-20260903`
- Starting commit: `9f5d820` (`fix: close release blockers and retire direct MSU`)
- Working tree: `/private/tmp/intmax3-signerless-exit.2qrfge`
- `contracts/lib/polygon-plonky2` is a submodule and was not modified in this work.
- The KZG trusted setup is treated as a trust assumption, as requested, and is not treated as a blocker.

## What has been done so far

### 1. Pinning the latest signed state as the single close target

The path that mixes `V` and `B` per token was removed; close now targets a single authenticated whole-state vector. `ChannelSettlementManager` and `CloseFundingMaterializer` read the channel, the settled chain, the TFD, the extended state root, and the anchor from the same proof, and materialize the exact vector atomically. Old closes, a different identity, stale burns, and a different generation all fail closed.

### 2. Exit material that does not require a signer

A signed-head exit kit was added to `src/live_balance_service.rs`, designed so that at the point where the complete N-of-N state `H` becomes durable, the Balance proof corresponding to that state, the whole-vector backing proof, the fixed public inputs, the root, and the anchor are stored and verified. The L1 side does not require an additional channel signature; it drives close/finalize/materialize using the stored kit and a permissionless backing attestation.

### 3. Close backing circuit

`src/circuits/channel/close_asset_backing_circuit.rs` was added. It reconstructs the Balance proof/VK, PrivateState, ExtendedPublicState, asset registry, and canonical zero limbs, and constrains the asset tree and the TFD exactly for all tokens. Its public inputs are a fixed 26 limbs; it is an additive circuit that changes neither the proof size nor the existing close circuit ABI.

### 4. Solidity safety boundaries

- `ChannelSettlementManager.sol`: implements whole-state close, the finalized/pending high-water mark, reorg rollback, exact TFD, and historical authenticated partial withdrawal.
- `CloseFundingMaterializer.sol`: implements permissionless backing attestation, attestation receipts, exact-vector credit, channel/generation/freeze guards, and prevention of double materialization.
- `IntmaxRollup.sol`: implements set-once for the materializer, the post/rollback journal, and the release runtime guard.
- The unsafe paths of the old MSU have been stopped and isolated from production.

### 5. Public prover/publisher/deployment

- The `public_close_prover` bundle schema was updated so that the bundle contains the backing proof, the MLE proof, the 26 PI, the root/anchor, and the protocol metadata.
- `public_close_publisher` records the order attestation → submit → finalize authorization → finalize → materialize in the WAL. Raw signed transactions are fsynced before broadcast.
- Attestation is permissionless, and the winner among other watchtowers can be adopted via exact events/receipts/getters.
- `DeployCloseCli.s.sol` and `channel_member` attach the materializer to an existing Rollup, use a distinct backing VK, pin the bundle hash/PI/root/metadata, and re-verify the nonce/target/calldata.

### 6. Verified tests and sizes

- SignerIndependentExit: 11/11
- ChannelSettlementManager: 79/79
- PartialWithdrawal: 42/42
- DeployGuards: 30/30
- Node focused tests: 14/14
- EIP-170 sizes: IntmaxRollup 24,533 B, Manager 23,988 B, Materializer 15,339 B (all within the limit).
- The Rust backing circuit fixed-width PI test, `cargo check`, and the publisher's existing tests have been run. However, the publisher's final attestation-ordering test and a full re-run must be re-confirmed after handoff.

## What must be done after handoff

1. **Check the working tree and the diff**
   ```sh
   cd /private/tmp/intmax3-signerless-exit.2qrfge
   git status --short
   git diff --check
   ```

2. **Complete the publisher's final consistency work**
   - Align the completed journal's schema with `PUBLICATION_VERSION` (currently 3).
   - Compare the completed publication's `attest_transaction_hash` against the journal's exact attestation observation.
   - At every site that adopts a `submit_observation`, require that the semantic position of `CloseSubmitted` be strictly after the attestation.
   - Test restarts, transaction ordering within the same block, attestation races, reorg/rollback, and contamination by stale events.

3. **Re-confirm the signer-independent operation of channel_member**
   - The kit must be durable at the moment the complete N-of-N state `H` is accepted.
   - There must be no path that requires a cosigner signature after `H`.
   - Internal intermediate transitions must not be mistaken for the external canonical head.
   - Re-audit whether the browser/wasm raw signing path can publish a canonical head without a kit in a public environment.

4. **Complete three rounds of attack/defense review**
   - Round 1: attack whole-vector mixing, stale burn, double materialization, and cross-channel backing.
   - Round 2: attack attestation races, reorgs, cancel/replay, and exact-vector inconsistencies in delegate/partial-withdrawal.
   - Round 3: attack signer absence, WAL crash, ordering within the same block, RPC substitution, and browser/public claims.
   For each round, record the reproduction test, the fix, and a re-run of the same attack.

5. **All tests and benchmarks**
   ```sh
   /Users/andropov/.cargo/bin/cargo check --bin public_close_publisher
   /Users/andropov/.cargo/bin/cargo test --lib close_asset_backing_circuit
   forge build --sizes --skip test --skip script
   forge test --match-contract SignerIndependentExit -vvv
   forge test --match-contract ChannelSettlementManager -vvv
   forge test --match-contract PartialWithdrawal -vvv
   forge test --match-contract DeployGuards -vvv
   ```
   Compare the proof size/time of the existing close proof against the size/time of the backing proof, and record that the existing ABI and the production benchmarks have not been degraded.

6. **Confirm the public-environment boundary**

   The constituent-evaluation problem in the MLE/WHIR PCS is within the scope of a separate submodule audit and is not cryptographically repaired on this branch. Re-confirm that the official deploy, the Rollup/Manager value boundary, the chain ID, the MLE VK, and the bundle hash are fail-closed in production.

7. **Commit/push after review**

   ```sh
   git diff --check
   git add HANDOFF_SIGNER_INDEPENDENT_EXIT.md
   git commit -m "docs: add signer-independent exact-vector exit handoff"
   git push -u origin codex/signerless-latest-head-exit-20260903
   ```

## Known caveats

- Broadcast to a real chain has not been performed. Do it only after confirming the deployment bundle, the nonce, the manager/materializer addresses, the MLE verifier code, the backing VK, and the finalized readback on a real chain.
- The MLE/WHIR PCS Critical is handled in a separate thread. It must not be recorded as resolved.
- Foundry can crash inside the sandbox due to macOS SystemConfiguration; in that case, re-run it in an approved `forge test` execution environment.
- The final release decision is to be made only once the publisher ordering verification, the three rounds of attack review, the full test run, the benchmarks, and the real-deploy readback are all in place.

---

# Record of work done after handoff (2026-09-03, `codex/signerless-latest-head-exit-20260903` from 8f70b73 onward)

The results of carrying out items 1 through 7 of "What must be done after handoff" above. Line numbers are as of the time of this record.

## 1. Working tree

`8f70b73` was taken in by fast-forward and the submodules were initialized. `git diff --check` is clean.
This handoff document was not included in commit `8f70b73`, so it was brought into `doc/tasks/`.

## 2. Publisher final consistency (`src/public_close_publisher.rs`)

Gaps found and fixes made:

- **The completed journal's schema check was hardcoded as `!= 2`** (`PUBLICATION_VERSION` is 3). This is a liveness bug in which the publisher always rejects, on the next startup, a completed journal it wrote itself. Fixed to compare against `PUBLICATION_VERSION`, and validated in `load_or_create_journal` as well.
- **`attest_transaction_hash` was not referenced at all on the re-validation path.** When re-validating the completed journal and when loading the journal, it is now checked against the tx hash of `attest_observation` (which `advance_attestation` re-validates on-chain every time).
- **There was no requirement that the semantic position of `CloseSubmitted` be strictly after the attestation.** `strictly_after` was added to `discover_semantic_confirmation` and the attestation observation is passed as the lower bound at all 9 call sites. `require_after_attestation` is also applied at the local receipt adoption site (`ReceiptState::Finalized`), at completed-journal re-validation, and at journal load. The ordering is the lexicographic order of `(block_number, transaction_index)`; within the same block it is decided by the transaction index.
- **The test harness did not support the attestation stage**, so 16 of 30 were failing (`SignedHeadBackingAttested provenance count 0 != 1`). `FakeBackend::new` now carries an external watchtower's attestation receipt (block 10, index 1), and `attested_backend()` enters the close state machine from the already-adopted state.

Additional tests (all passing, 37 in total):

| Test | Target |
|---|---|
| `permissionless_attestation_winner_is_adopted_and_local_raw_is_superseded` | attestation race: after a local raw submission, another party's attestation finalizes first → it is adopted, and the nonce lane is not released until the local loser's revert is confirmed |
| `close_submitted_in_the_attestation_block_must_follow_the_attestation_index` | ordering within the same block: a submit whose index is lower than the attestation's is rejected, a higher one is adopted |
| `local_submit_receipt_ordered_before_the_attestation_is_rejected` | rejection when RPC substitution makes our own submit appear before the attestation |
| `adopted_attestation_is_revalidated_and_fails_closed_after_reorg` | reorg of the attestation block |
| `foreign_attestation_events_are_filtered_and_duplicate_exact_attestations_fail_closed` | contamination by stale/foreign events, duplicate exact attestations |
| `completed_publication_attestation_provenance_and_schema_are_revalidated` | tampering with the completed journal's attest hash / schema |
| `journal_load_rejects_close_provenance_at_or_before_the_attestation` | the ordering invariant at journal load |

The contract side emits `SignedHeadBackingAttested` only once for the same `proofId` (`CloseFundingMaterializer.sol` `attestSignedHeadBacking`), so a duplicate exact attestation is an RPC-side anomaly and failing closed is correct.

## 3. Re-audit of channel_member / the kit

- The kit is persisted atomically in the same snapshot as the N-of-N head (`persist_snapshot`: create_new 0600 → fsync → rename → dir fsync), and `verify_snapshot_semantics(require_exit_kit=true)` re-verifies the proof on every commit/load. There is no window in which only the head is durable and the kit is missing.
- There is no exit path that requires a cosigner signature after H. `cmd_close` does not derive cosigner keys. The 8 signing purposes that move assets/composition are uniformly rejected by `requires_prepared_exit_kit` before the signing primitive (until the pre-sign prepare+fsync receipt is exposed as an API).
- Internal intermediate transitions do not become the canonical head (the linear-progress check in `live_balance_service.rs`: epoch+1 / state_version+1 / small block, fund, settled chain, accumulator, nullifier root, and import cursor unchanged).
- **A wasm/browser gap was fixed**: `wallet_cosign` had no kit gate. `wallet_core::verify_exit_kit_preserving_successor` was added so that `wasm_wallet::wallet_cosign` permits, before releasing a signature, only successors that are "H2=0 and leave the backing statement entirely unchanged" (the same boundary as the CLI's rejection). Test `cosign_gate_refuses_every_asset_or_composition_moving_successor` (release).
- Unfixed caveats: `receive_deposit_unbound` makes an additional deposit into an already-bound channel fail closed via stale-kit detection (a functional limitation). `settle_close_funding` is deprecated and is a dead path that does not install a kit. The kit-reuse decision does not compare the anchor (intentional; documented only).

## 4. Three rounds of attack/defense review

### Round 1 (Solidity: mixing / stale burn / double materialization / cross-channel)

All existing guards are effective (`BackingPublicInputsMismatch` requires both the TFD and settledTxChain to match, `proofId` binds the entire proof, and the `ChannelAlreadyExited` latch is written before the credit and is not cleared even by a rollback). For attacks that were not covered, 10 tests were added to `contracts/test/SignerIndependentExit.t.sol` (21/21): settledTxChain crossing, anchor tampering, cross-channel, unbound manager, materialize without freeze, unfinalized root, interleaved rollback across multiple channels (including ordering violations), re-materialization after a rollback, and atomic revert when escrow is insufficient.

**Serious bug (fixed): `IntmaxRollup.registerSettlementManager` never installs the materializer.** Because Yul evaluates arguments right to left, `and(staticcall(...), eq(returndatasize(), 32))` read the pre-call `returndatasize()==0` and was therefore always false. On a real deploy, `requestClose` would always revert with `NotBoundManager` and `creditChannelExit` would be closed forever. The existing suite was green only because it used a stub materializer. This was fixed to `let ok := staticcall(...)`, and `MaterializerSetOnceTest` (set-once, credit gate, registration calls bind) was added to `DeployGuards.t.sol`. The EIP-170 size is unchanged (24,533 B). **Because the Rollup bytecode changed, the entire close fixture set was regenerated** (§5).

### Round 2 (attestation race / reorg / cancel-replay / exact-vector for delegate and PW)

The Rust side is reproduced by the tests in §2. Auditing the node delegate side led to fixing 3 issues with real impact:

- `node/delegate/branches/owntx.js` `doBurn`: when the state in the cosigner's response was top-level, `verifyCosignedStructural` would pass but the import was skipped, so `acceptedHead` reached `BURN_FINALIZED` while still at its pre-burn value. Subsequent closes would then be rejected forever with `CloseOlderThanAuthorizedBurn`. The nested `state` was made mandatory and the import unconditional, the head is confirmed to have advanced after the import, and `burnHead {digest, epoch, stateVersion}` is recorded on the PW ticket.
- `node/delegate/branches/exit.js`: if `acceptedHead` advanced due to a chain-originated deposit import while a close was in progress, the publisher would open a journal for a different digest and the original journal would never progress again — a liveness wedge. The head is now pinned into `publicClosePublication.acceptedHeadDigest` and released only by `CloseCancelled` / the CANCELLED conversion in reconcile.
- `exit.js`: close requests / publications on a head older than the local burn high-water mark (`burnHead`) are rejected with `CLOSE_BELOW_AUTHORIZED_BURN` (`Store.listTickets` was added).
- `api/routes/close.js`: the caller-supplied `manager` was passed to the CLI argv without validation, and there was no devnet gate either. It is now restricted to chain 31337 like `full-withdrawal.js`, and the address format is validated.

Tests: `node/test/delegate-burn-head.test.js` (5), `node/test/api-close-route-devnet.test.js` (2), and 2 added to `delegate-close-lifecycle.test.js`.

### Round 3 (signer absence / WAL crash / same block / RPC substitution / browser)

- WAL: all 4 stages follow the order reservation → sign → offline decode verification → journal fsync → broadcast. Recovery only re-sends the stored raw bytes, and stops if the nonce has moved.
- RPC substitution: this requires 5 runtime code hashes, double reads at a pinned block, rejection of same-height replacement, double reads of the receipt, and an exact match between the event and the getter. The calldata/target are generated locally from the sha256 of the bundle and the manifest and do not depend on the RPC.
- Same block: §2 introduced and tested the strict `(block, tx index)` ordering.
- Browser: the wasm gate from §3. `/api/backing` does not hand out kit material, and the claim route is a 50-PI withdrawal claim, which cannot publish a canonical head.

## 5. Tests and sizes

| suite | result |
|---|---|
| `cargo check --bin public_close_publisher` | OK |
| `cargo test --release --lib close_asset_backing_circuit` | 4/4 |
| `cargo test --release --lib public_close_publisher` | 37/37 (16 were failing at handoff) |
| `cargo test --release --lib cosign_gate_refuses_every_asset_or_composition_moving_successor` | 1/1 |
| forge `SignerIndependentExit` | 21/21 (+10) |
| forge `ChannelSettlementManager` | 79/79 |
| forge `PartialWithdrawal` | 4 suites 59/59 |
| forge `DeployGuards` + `MaterializerSetOnceTest` | 33/33 |
| forge overall (after fixture regeneration) | 550 of 551 passing, 1 failing (CloseLifecycleE2E, see below), 0 skipped |
| node overall | 441 tests, 0 failures |
| EIP-170 | IntmaxRollup 24,533 B / Manager 23,988 B / Materializer 15,339 B (unchanged) |

**Breakdown and handling of the 32 tests that were failing in the whole forge suite at handoff**:

- `CloseFundingAuthorization.t.sol` (15): these exercised the retired cooperative close funding API. They were replaced with 3 tombstone tests, keeping the tests for the live pull/claim nullifier (10/10).
- Tests from the old spec that tolerated stale closes (14: `AuthorizedBurnFenwick`, `CloseExitLivenessInvariant`, `CloseLifecycleHardening`, `CloseLifecycleRedTeam`, `RedTeamRound3`): rewritten as fail-closed tests asserting `CloseOlderThanAuthorizedBurn` / `CloseForksAuthorizedBurn`. The invariant handler was fixed to generate admissible closes (256 runs / 128,000 calls).
- `CloseLifecycleE2E` (2): the close fixtures were stale because the Manager/Rollup init code had changed. Resolved by regeneration.

**Fixture regeneration**: following Step 1 of the runbook, the plain set → printer → close family (`close_` withdrawal / close / withdrawal_claim / post_close_claim / cancel_close / c2c / wasm) were generated in one batch. Because the printer (`test_printCloseManagerAddress`) has a `setUp` that unconditionally reads `close_lifecycle*.json`, rather than setting the old close set aside, the plain set must be copied under `close_` names so that both predictions agree (this is not documented in the runbook). Furthermore, the predicted address depends on the library link targets of the test contract, so **it moves merely by editing any Solidity test file at all** (during this work it changed `0x894a…`→`0xb1f6…`→`0x894a…`). Therefore the close family must be baked in only after all Solidity-side edits are final. The Manager address ultimately baked in was `0x894a113DB75C344CCC287A7C1ECC5CfDC2B06d1B`.

`ClaimMleVerify.test_realMleVerifier_rejectsMismatchedFinalDuplicateRow` had pinned the byte offsets of a specific fixture. Because WHIR's final round draws 16 queries from a domain of 2^11, the probability that a regenerated proof contains a duplicate query is only about 6% per fixture. The test now searches dynamically for a duplicate row given the current WHIR shape, and if no fixture has one it skips with a stated reason. This time cancel_close was regenerated repeatedly (30 misses in the first batch) and the `cancel_close_mle.json` from the point at which a proof containing a duplicate query was obtained was adopted, so no skip occurs.

**CloseLifecycleE2E (the one remaining red)**: once the addresses matched, the E2E stops at `submitCloseIntent` with `ChannelFundStateRootNotFinalized(0x00000001…04…)`. The cause is that the fixture design has not kept up with the new design:
1. `close_circuit::test_fixture::build_close_full_witness_two_token` puts the placeholder `[1,2,3,4]` into `channel_fund.intmax_state_root`, whereas the Manager requires `registry.isFinalizedStateRoot` (the only roots finalized in the E2E are the lifecycle genesis root and `final_state_root`).
2. In the new design, `_checkCloseProof` requires `requireSignedHeadBacking`, so the whole-vector backing proof (26 PI, MLE-wrapped) for the same signed state must be passed to `attestSignedHeadBacking` within the E2E. The backing proof's `finalized_extended_state_commitment` must be the commitment of the extended state that the lifecycle chain finalizes (the state in which the channel's asset leaf matches the close vector `[77, 55]`), and no generator for a backing fixture exists (only `channel_member` uses `close_asset_backing_circuit`).
In other words, a new generator that co-generates the close fixture and the lifecycle chain's extended state (emitting the `close_asset_backing_{manifest,mle,public_inputs}.json` that `DeployCloseCli.s.sol` expects), plus the addition of the backing VK initialization and attestation steps to the E2E, are required, and this was not started in this session. The E2E keeps failing with an explicit revert (it has not been turned into a skip).

Benchmarks: the backing circuit is an additional circuit independent of the existing close circuit, and the close proof's size/time and the Manager/Verifier ABI are unchanged (`public_inputs_roundtrip_is_fixed_width` confirms the fixed 26 limbs).

## 6. The public-environment boundary (open items, preconditions for the release decision)

- **The MLE/WHIR PCS constituent-evaluation problem is unresolved** (a separate submodule audit). It is not addressed on this branch.
- `IntmaxRollup.releaseRuntime` pins value movement, including `creditChannelExit`, to chain 31337. By design, signer-independent exit cannot currently be executed on a public chain (because the MLE engine has not been released). The Manager's `releaseRuntime` has only a challenge-period floor, so the two have divergent definitions of "production".
- The existing-Rollup attach branch of `DeployCloseCli.s.sol` (`EXISTING_ROLLUP`) has no fixture/driver/tests and has never been run. The file names it reads (`close_asset_backing_{manifest,mle,public_inputs}.json`) do not match the prover's output names (`public_close_manifest.json` / `backing_mle.json` / `backing_public_inputs.json`), and the rename procedure is undefined. There is also no explicit comparison that the backing VK ≠ the close VK (provenance only).
- The publisher takes the `cast mktx` nonce from the RPC, so a malicious RPC that inflates the nonce can make an already-journaled raw transaction permanently un-broadcastable (a liveness problem; funds do not move). The `finalized` tag depends on a single RPC.
- The Rollup's value boundary is only the global `totalEscrowed` / per-token amounts; there is no per-channel ledger (soundness depends on the proof).
- The JS publisher skips re-proving based only on the existence of `bundles/<digest>/` (no sha256 binding of the contents; local in scope).

## 7. commit/push

The changes in this record are committed as logical units on the same branch. Broadcast to a real chain has not been performed.

---

# Addendum (2026-09-04): releasing the 8 asset-moving purposes, and the remaining close-path work

Of the items in the previous section "What is blocking the testnet", the 2 that are self-contained within this repository have been implemented.

## 1. pre-sign exit kit (`doc/docs/pre-sign-exit-kit.md`)

The blanket rejection in `requires_prepared_exit_kit` was replaced with the gate it was originally meant to be:
requiring that the kit for the successor state H' being signed has been verified, fsynced, and is durable.

- **live balance service** `prepare_exit_kit`: for a proposed (unsigned) successor state, it proves the
  kit without committing and returns an artifact that has passed semantic verification in which signature
  verification is replaced by structural verification (`verify_snapshot_structure`). The 3 proposals are
  TokenRegister / L1DepositImport / InterChannelDebit.
- **producer staging**: because for debit-type operations the subsequent settle chain depends on "posting an
  N-of-N-completed block", the block for the unsigned proposed state is staged as a `prepared` entry in the
  journal (`StagedInterChannelExitKit`, `BlockWitnessGenerator::unsigned_staging`). The block hash, each
  root, and the `bp_sig_chain` statement `(IMSB digest, the registered signer pk sequence)` do not depend
  on the signature bytes, so the head snapshot at staging time is byte-identical to the real N-of-N block,
  and `post_inter_channel` verifies that and then promotes it in place (a mismatch fails closed). During
  staging, other producer changes are frozen just as with close funding's prepared state, and they can be
  released with `abandon`.
- **CLI**: `cli_state.json` schema 5 (`prepared_exit_kit_receipt` as a required key),
  `--propose-exit-kit`, `INTMAX_PREPARED_EXIT_KIT`, verification via `verify_public_backing_proposed`,
  content-addressed archiving, saving before signing, and promotion of the receipt on adoption. The
  recipient-side credits (InterChannelFundImport/BundleApply) are signed under "net increase only, plus the
  current head's receipt verified", and after receipt the kit is installed with `install-exit-kit` (a
  kit-pending state). CloseFunding remains rejected because it is retired on-chain.
- **API**: `api/lib/exit-kit.js` (propose → `livePrepareExitKit` → sign, abandon on failure); the
  register-token / deposit import / burn / inter-channel routes were each made two-phase.
- **wasm**: unchanged (the browser is not a signer for asset-moving purposes. The cosign gate from the previous section is retained).

A side-effect fix: `receive_deposit_unbound` now drops the old kit on the transition to awaiting, resolving
the problem where an additional deposit into an already-bound channel would stop fail-closed.

Tests: `signing_ledger_tests` 10/10 (4 new: exact-successor release and promotion, kit sharing across a
two-stage import, kit-pending for the recipient-side credit, CloseFunding retirement); a real-proof
integration test in `tests/live_balance_service.rs` covering staging → prepare → verification (only the
proposed digest is accepted; N-of-N verification is rejected) → sign → promote → settle; node
`api-exit-kit.test.js` 3 tests, plus updates to existing route tests.

## 2. Remaining close-path work

- **backing fixture co-generator** (`generate_close_fixture`): co-generates the close witness and the
  whole-vector backing proof from the final `ExtendedPublicState`, balance proof, and asset vector of the
  lifecycle chain (deposit 6 / withdraw 3), and emits
  `close_asset_backing_{manifest,mle,public_inputs}.json`.
  `intmax_state_root` is the finalized `final_state_root`, and the anchor is 3.
- **CloseLifecycleE2E**: `initializeBackingVk` and `attestSignedHeadBacking` were added, so that request →
  attest → submit → finalize → payout passes against the real contracts.
- **DeployCloseCli attach branch**: a test for the `EXISTING_ROLLUP` branch was added to
  `DeployGuards.t.sol` (it attaches to a Rollup created by `Deploy.s.sol` and verifies the backing VK
  initialization and the readback).
- **deploy readback**: `channel_member export-close-deployment-manifest <out> <rpc>` was added.
  It generates the publisher's deployment manifest v3 from the ACTIVE settlement binding, and at the
  activation checkpoint it re-reads and cross-checks the runtime code hash and the MLE verifier
  (`allowedChainId`). The example in `doc/docs/public-close-publisher.md` was updated to v3. Running it
  against a real chain such as Sepolia has not been done, because that requires keys and funds.

## 3. Merging the MLE/WHIR PCS repair branch (2026-09-05)

`origin/codex/mle-whir-pcs-repair-20260904` (c533e71; wire-v3 / WHIR profile 105 / 20M gas
envelope, constructor-pinned `PinnedMleVerifierV2`, removal of on-chain VK initialization) was merged into
this branch, and signer-independent exit was ported onto the new model.

- **Solidity**: `CloseFundingMaterializer(rollup, IPinnedMleVerifierV2 backingMleVerifier)`.
  `attestSignedHeadBacking(manager, bytes compactProof)` / `materializeSignedHead(manager, bytes)`
  re-derive the 26 limbs via the pinned adapter's `verifyCompactPublicInputs` (the PI in the calldata is not trusted),
  and the receipt is `keccak(domain, chainid, materializer, rollup, manager, keccak256(proof))`.
  `initializeBackingVk` / `backingVkInitialized` / `MleVk` were deleted. The Manager's `_checkCloseProof`
  takes the funds digest (limbs 95..102) from the PI of `closeMleVerifier.verifyCompactPublicInputs`
  and calls `requireSignedHeadBacking`. The Yul fix in `registerSettlementManager` is retained.
  The attach branch of `DeployCloseCli` deploys the backing adapter from `close_asset_backing_mle_config.json`
  and passes it to the materializer (requiring that the authenticated backing proof and
  `pinnedVerifier.verificationConfigDigest` match). The broadcast core is
  15 txs (backing core+adapter → materializer → 4×(core, adapter) → verifier → registerChannel →
  manager → registerSettlementManager).
- **Rust**: `public_close_prover::wrap_and_export_backing_mle` returns `{mle_json, mle_config_json, compact_proof}`
  using the v2 API (`setup_mle_vk_v2` / `prove_with_mle_v2` / `export_mle_v2_json` + config validation).
  The bundle manifest is schema 3 (adding `backingMleConfigFile/Bytes/Sha256`). The publisher's attest /
  materialize calldata is `(address, bytes)`, and the deployment manifest is schema 4 (in addition to the
  pins for the 4 adapters, the 9 pins `backingMle{Verifier,VerifierCore,…WhirSessionId}`,
  `closeFundingMaterializer`, and the attest / materialize selectors and 2 topics). `channel_member` stages
  the 4 backing bundle files (manifest / mle / mle_config / public_inputs), and `settlement.json` carries
  `backing_mle_core` / `backing_mle_adapter`.
- **Fixture**: `generate_close_fixture` is the single co-generator for the close family (`close_` lifecycle,
  close intent, backing proof). `WD_OUT_PREFIX=close_ generate_withdrawal_fixture` is rejected.
  `--mle-config-only` writes the 4 close-family configs. The aux binding of `pullChannelFunds`
  (`CloseFundingAuxMismatch`) is retired under signer-independent exit, so
  `WD_CLOSE_FUNDING_ROLLUP` is unnecessary. The cohort in `tests/mle_v2_fixture_release.rs` is 53 files
  (16 config / 17 full proof / 20 companion). The backing statement is pinned as the 7th production
  profile (26 PI), and its cross-binding with the close intent / `close_` lifecycle
  (settled_tx_chain, token_funds_digest, finalized root, anchor) is verified by a gate.
- **Runbook**: `doc/tasks/regen-and-redeploy-runbook.md` Step 1 (config cohort; removal of the retired
  target-133 switch) / Step 2 (15 txs, 14 addresses) / Step 3 (the co-generator) were updated.

### `partial_withdrawal_e2e_anvil` (fixed 2026-09-05)

`submitPartialWithdrawalIntent` requires, via `requireSignedHeadBacking`, an attested backing for the
post-burn head (anchored to a finalized root), but the old E2E only advanced the Rust-side
`BlockWitnessGenerator` and left anvil's Rollup at genesis, so the submit produced `BackingProofNotAttested()`
(an existing inconsistency since 8f70b73). The E2E now performs the same steps as the production CLI:

1. The deploy script's `registerChannel` is mirrored on the Rust side with `add_channel_registration_with_record`
   (a new API: a record with a real recipient + a Falcon signer) to build the registration block.
2. deposit / bootstrap / burn blocks (`add_block_with_tx_v2`) → 4-block validity proof → wrap + MLE
   (cross-checked against the deployed `mle_fixture_config.json`; compact 129,484 B).
3. The 4 blocks are posted with `cast mktx --blob` (EIP-4844), the signed txs are verified with
   `proof_da::validate_decoded_blob_transaction` (identical to the production CLI), then
   `attestProofData` (KZG sidecar) → `finalize` (`script/PartialWithdrawalE2ELifecycle.s.sol`).
   The real deposit is sent after the registration block has been posted (the fold order of the pending deposit chain).
4. The `CloseAssetBacking` proof over the burn-send balance proof (anchor = block 4, cross-checked against
   the deployed `close_asset_backing_mle_config.json`) is attested with `attestSignedHeadBacking`.
5. submit (gas 19,028,810 / 20M) → finalize → authorize → fail-closed claim → replay rejection.

The artifacts are written to the gitignored `proof-da-output/pw-e2e/`, and only
`pw_reg.json` / `pw_submit.json` / `pw_close_intent_mle.json` remain in `test/data` (the cohort is unchanged).
anvil's block gas limit is 30M (attest / finalize are not subject to the 20M envelope), and the verification
of the submit tx's fixed 20M gas limit is as before.

## Remaining assumptions

On 2026-09-05, `IntmaxRollup.releaseRuntime` was changed from a hardcoded chain 31337 to a pin on
`deploymentChainId` (an immutable that is fixed in the constructor after requiring that
`allowedChainId()` of both pinned adapters == `block.chainid`). If
`MLE_VERIFIER_CHAIN_ID=<chain id>` is specified at deploy time, value movement becomes valid on any chain,
and moving the code/state to a different chain fails closed
(`test_releaseValueBoundaries_followTheDeploymentChain`).
The old, unpinned `postBlockAndSubmit` remains restricted to 31337, and for public chains only
`postBlockAndSubmitGuarded` is available. The MLE/WHIR PCS repair has been merged, but until the
protocol-specific Fiat-Shamir / grinding analysis and external review are complete, value movement on a
public chain remains operationally NO-GO.
