# Phase A — real `verifyCloseIntent` via plonky2 MLE/WHIR (close-verifier-a1-plan.md)

Status: IMPLEMENTED (compile-verified; heavy close proving deferred to the user).

## Done (falsifiable)

### Rust
- R1. `src/bin/generate_close_fixture.rs` (feature `close-fixture-bin`): builds a REAL close witness
  via shared `test_fixture::build_close_full_witness_n`, proves the close circuit, wraps
  (`WrapperCircuit`), `setup_mle_vk`+`prove_with_mle`+`verify_mle_proof`, exports
  `contracts/test/data/close_intent_mle.json` (export_mle_json) + a `close_intent.json` descriptor
  (all CloseProofFields + member pk_g list pulled from the proved 87 PI limbs). Compiles. NOT run.
- Test-gating: canonical witness builders moved into `close_circuit::test_fixture`, re-gated
  `#[cfg(any(test, feature="close-fixture-bin"))]`, made `pub`; inline `tests` reuse them (single
  source). Default build/test unaffected (verified).
- R2. Rust golden vector `close_pis::tests::close_public_inputs_match_solidity_shared_vector` — PASS.

### Solidity
- S1. `ChannelSettlementVerifier`: `@mle/MleVerifier` import; `CloseVk` + close WHIR storage;
  `initializeCloseVk` (deployer set-once, degreeBits>0, `CloseVkDegreeBitsZero`). No disable seam
  (reverts `CloseVkNotSet`). Mirrors `IntmaxRollup.initializeWithdrawalVk`.
- S2. `_expectedCloseLimbs` (87 limbs, to_u64_vec order, recomputes closeIntentDigest);
  `_bindCloseLimbsStrict` (len==87, strict eq, reject >= 2**32). Public `expectedCloseLimbs` helper.
- S3. `verifyCloseIntent(fields, MleVerifier.MleProof)` binds 87 limbs then `closeMleVerifier.verify`.
  Old `closePIHash`+`_matches` close path removed (closePIHash kept for the other 5 stubs).
- S4. Interface + `submitCloseIntent`/`_checkCloseProof`/`_runCloseVerify` thread MleProof calldata.
- S5. EIP-170: runtime 13,166 B (margin 11,410). No split.

### Tests
- ChannelSettlementManager.t.sol: mock-MLE close path; positive + negatives (tampered version/chain,
  forged commitment, wrong channelId, len!=87, limb>=2**32, unset VK, deployer-only/set-once/
  degreeBits==0). 42/42 PASS. Solidity golden `test_expectedCloseLimbs_goldenVector` PASS.
- CloseLifecycleE2E.t.sol: real close VK + real MleProof wiring; self-skips until fixture exists.
  Full contract suite: 109 pass, 1 skip.

## USER ACTION (heavy compute)
    cargo run --release --features close-fixture-bin --bin generate_close_fixture
Writes close_intent_mle.json + close_intent.json; then the CloseLifecycleE2E close section can run
(gated on member-set match + close_freeze_nonce==1).

## Flagged residuals
- Cross-circuit replay rejection is structural (separate close VK w/ real close digests); executed
  end-to-end only once the heavy fixture exists.
- CloseLifecycleE2E: lifecycle (withdrawal) fixture and close fixture have different member sets, and
  member_pk_gs feed the validity block-hash chain, so one channel can't satisfy both with one
  registration. Close-submission section is GATED; a co-generated lifecycle+close fixture pair is
  follow-up.
