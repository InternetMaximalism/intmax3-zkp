# MLE/WHIR PCS repair: progress and handoff (2026-09-03)

## Status

**Release status: NO-GO.** This is an intentionally incomplete, local-only cutover checkpoint.
Do not deploy, publish, transfer value, tag, or treat the current artifact directory as a
release candidate. The proof-free target-133 configuration cohort is complete, but only 7 of the
16 required parent full proofs have been regenerated as wire v3. A full proof/config mixture is
safe only because the release gates fail closed; it is not an admissible deployment state.

The current parent branch is `codex/release-blockers-2-5-20260831`; the submodule branch is
`codex/whir-leaf-consistency-20260830`. Commit and push the submodule first, then update and push
the parent gitlink in the same handoff change.

## Completed repair work

### PCS and verifier hardening

- Reworked the MLE/WHIR proof wire to schema/protocol version 3 and `MLEWHIR3`; genuine historical
  wire-v2 bytes are rejected before decode and at the cryptographic boundary.
- Bound the complete public-input relation directly into the outer relation using the canonical
  `(row:u16 little-endian, column:u8)` map derived from copy classes. The map is bound to the
  circuit/config digest and preserves order and duplicates.
- Bound ordered grouped WHIR commitments, both opening points, every root and all three Ext3 limbs;
  removed the former compensating kernel surface and retained the immutable chain pin.
- Added target-133/PoW-22 production profiles. The machine-checked conservative native WHIR
  aggregate is approximately 128.356-bit as a *generic work factor* for admitted dimensions.
- Removed `skipVerification` from production Solidity APIs and bytecode. The old bool selectors are
  regression-tested as unreachable; decode-only measurement remains confined to a test harness.
- Hardened proof-free config creation: unique same-directory staging file, file fsync, no-clobber
  hard-link publication, directory fsync, cleanup, byte-identical concurrent-writer acceptance
  only. Race and injected pre-publication interruption tests pass.

### Fixtures, configs, compatibility, and CI

- Regenerated all 15 proof-free config artifacts as one target-133 cohort. They are schema/protocol
  3, PoW 22, `MLEWHIR3`, and share WHIR protocol ID
  `0x373dc84ebf4d0e3e38e74fb1124a0622830ad4e1bdf5030d4c6cbb44a03d15af984814bd3da7fd67a57ec15fb40084a947ba0e68becd7ab900c90d69d15d3313`.
- Updated the six production ABI/config hash pins, added strict manifests for the 49 parent JSON
  artifacts and the quarantined submodule fixture/testdata set, and made reappearance of retired
  `xlarge_mul.json` fail closed.
- Regenerated the seven packed-v1 conformance fixtures, transcript trace, and frozen historical PCS
  triples explicitly from this revision. They remain quarantined test/conformance inputs, never
  wire-v3 deployment artifacts.
- Regenerated and checked the canonical cross-language wire-v3 and maximum-resource fixtures.
- Added a CI Node artifact-binding job and documented the complete atomic cohort/recovery process in
  `doc/tasks/regen-and-redeploy-runbook.md`.

### Fresh complete parent proofs already generated

These seven proof artifacts and their generator-owned companions are current wire v3 / target-133:

1. `mle_fixture.json` (validity/E2E), plus `vpi_fixture.json` and `block_fixture.json`.
2. `lifecycle_validity_mle.json` and `withdrawal_mle.json`, plus `lifecycle.json` and
   `withdrawal_payout.json`.
3. `close_lifecycle_validity_mle.json` and `close_withdrawal_mle.json`, plus
   `close_lifecycle.json` and `close_withdrawal_payout.json`.
4. `sepolia_lifecycle_validity_mle.json` and `sepolia_withdrawal_mle.json`, plus
   `sepolia_lifecycle.json` and `sepolia_withdrawal_payout.json`.

The ABI change moved the local CREATE2 manager. It was recomputed twice in the exact Forge context
and stabilized at `0xFE7cb59C300218C04aE5360f77cDa771019eabb7`. The current close payout is
correctly bound to lowercase `0xfe7cb59c300218c04ae5360f77cda771019eabb7`, token index `0`, and
amount `77`; the close native deposit is also `77`.

## Verified evidence

- `cargo test -p plonky2_mle --all-targets --locked --offline`: PASS, including the 489-second
  all-fixture conformance test, wire-v3 adversarial/decoder tests, and the 16 soundness-budget
  checks.
- `forge test --offline` in `contracts/lib/polygon-plonky2/mle/contracts`: PASS, **347/347** tests,
  27 suites, 0 failed, 0 skipped.
- `forge build --sizes --offline` for the submodule: PASS. Production runtime sizes after bypass
  removal: `MleVerifierV2` 20,782 bytes and `PinnedMleVerifierV2` 12,285 bytes.
- Exact 15-config target-133 cohort gate: PASS.
- Config race/interruption tests, six resource-pin tests, parent 49-artifact/18-companion manifest
  checks, submodule manifest checks, `rustfmt --check`, YAML parse, and `git diff --check`: PASS.
- Targeted parent Solidity mock/fraud/chain/starvation tests: PASS. The `test_printCloseManagerAddress`
  Forge test passed twice with the same address.
- Node MLE artifact-binding tests: PASS, 8/8.

## Required next steps (do these in order)

1. Keep all deployments/publishers stopped and retain `IntmaxRollup.releaseRuntime` containment.
   Do **not** use the incomplete proof directory.
2. Regenerate the remaining full parent proof families sequentially from the repository root:

   ```bash
   cargo run --release --locked --offline --bin generate_burn_withdrawal_fixture
   cargo run --release --locked --offline --features close-fixture-bin --bin generate_close_fixture
   cargo run --release --locked --offline --features withdrawal-claim-fixture-bin \
     --bin generate_withdrawal_claim_fixture
   cargo run --release --locked --offline --features post-close-claim-fixture-bin \
     --bin generate_post_close_claim_fixture
   cargo run --release --locked --offline --features cancel-close-fixture-bin \
     --bin generate_cancel_close_fixture
   cargo run --release --locked --offline --bin generate_c2c_fixture
   cargo run --release --locked --offline --bin generate_wasm_fixtures
   ```

   These must produce the remaining `burn_*`, `c2c_*`, `close_intent_mle.json`,
   `withdrawal_claim_mle.json`, `post_close_claim_mle.json`, and `cancel_close_mle.json` records
   plus every listed companion. If the Manager-bearing contract bytecode changes, repeat the
   Manager printer and regenerate the `close_` withdrawal family until it is stable.

3. Generate the canonical partial-withdrawal proof on a fresh local Anvil as specified in the
   runbook. It must rewrite `pw_reg.json`, `pw_submit.json`, and `pw_close_intent_mle.json` from a
   real CloseProver proof, not an alias or copied fixture:

   ```bash
   cargo test --release --locked --offline --test partial_withdrawal_e2e \
     partial_withdrawal_e2e_anvil -- --nocapture
   ```

4. Rebuild both ignored WASM packages only after the source and complete fixture cohort are final:

   ```bash
   test ! -e pkg
   test ! -e pkg-node
   bash hosting/build-wallet-node-wasm.sh
   bash hosting/build-wallet-wasm.sh
   ```

5. Run the complete acceptance matrix from Step 4 of
   `doc/tasks/regen-and-redeploy-runbook.md`: parent `mle_onchain_e2e`, full
   `mle_v2_fixture_release`, parent `cargo check --all-targets --locked`, Node tests, full guarded
   parent Forge, explicit `V2FixtureCompletenessTest`, production sizes, and git/submodule
   integrity. Run the fully cold `ManagerCloseGas` path against the fresh partial-withdrawal proof
   with an explicit 30M Anvil gas limit. Record fresh proof sizes/hashes and gas values; do not use
   historical measurements.

6. Resolve any gate failure by regeneration from the documented source; never patch generated JSON
   or hash pins by hand. Commit the submodule first, then a single parent commit pinning it together
   with all 15 configs, all 16 full proofs, all 18 companions, the full submodule fixture manifest,
   source changes, tests, documentation, and CI configuration. Do not push or tag a config-only or
   proof-only intermediate as a release candidate.

## Outstanding release blockers that code generation cannot close

- The current 128.356-bit figure is a conventional generic-work-factor bound, **not** a complete
  literal random-oracle failure probability. With the coarse `H = 2^32` trial convention the
  recorded literal bound is about 96.356 bits. A protocol-specific Fiat--Shamir/grinding reduction,
  enforceable oracle-query policy, and full composition proof are still required.
- The required external independent cryptographic review has not been obtained. Internal review
  found no new deterministic PCS bypass, but it does not meet the acceptance condition.
- The parent system's Goldilocks/Poseidon recursion configuration is independently estimated near
  95-bit security; do not claim whole-system 128-bit security based on target-133 PCS parameters.
- Separate final-audit operational blockers remain, including public close-proof availability, live
  withdrawal producer, channel-scoped Manager backing, browser/public-claim E2E, and atomic MSU.

These blockers are intentional NO-GO conditions, not permissions to weaken release containment.
