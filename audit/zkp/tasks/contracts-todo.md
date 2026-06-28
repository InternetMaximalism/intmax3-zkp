# Smart-contract Lean formalization — plan & findings

Goal: model every line of the Intmax3 Solidity contracts in the SAME
Lean framework as the ZKP circuits, to prove **combined-system** safety
(circuits + contracts) or find vulnerabilities. Crypto verifiers
(Groth16/KZG/MLE-WHIR pairing math) are uninterpreted oracles — same as
Poseidon/keccak in the circuit model. Channel settlement contracts are
secondary (the zkp audit excluded channel scope), modeled after the core.

Method per function: protocol role → line-by-line rationale → Lean
state-transition (`require`/checked-math = revert) → soundness theorem.

Legend: [ ] todo · [~] in progress · [x] modeled+proved

## Core EVM modeling
- [x] `Contracts/Evm.lean` — storage/mappings, checked add/sub (revert), Call=Option

## IntmaxRollup.sol (1889 L) — native fund + state pipeline
- [x] `withdrawNative()` (:1307)  → IntmaxRollupWithdraw.lean
      **PROVED:** solvency ceiling, no-double-withdraw (CEI nullifier),
      proof-required anchoring, finalize-only-on-valid; combined-system bridge.
- [x] `deposit()` (:815)          → IntmaxRollupSolvency.lean (deposit_escrow); GLOBAL SOLVENCY proved (solvent_from_genesis: Σ out ≤ Σ in)
- [x] `finalize()` (:1102)        → IntmaxRollupWithdraw.lean (finalize_only_on_valid)
- [x] `_postBlock()` / deposit chain → IntmaxRollupDeposit.lean (deposit_sequential) + Coverage (block chain structural, validity-proof-checked)
- [x] `_submit`/postBlockAndSubmit → Coverage (structural commitment) + IntmaxRollupStake
- [x] `fraudProof()` (:1153)      → IntmaxRollupOptimistic (rollback floor; finalized roots permanent)
- [x] `withdraw()` (:1212)        → IntmaxRollupWithdraw (claimWithdraw_no_double, CEI)
- [x] reclaimStake/_slashStake/_refundStake → IntmaxRollupStake (single-resolution + conservation)
- [x] claimAuthorizedWithdrawal → IntmaxRollupWithdraw (claimAuthorized_safe); authorizePartialWithdrawal → IntmaxRollupDeposit (access control)
- [x] helpers (hash/crypto) → Coverage.lean (structural keccak_det + crypto oracles)
- [x] `registerChannel()` (:891)  → Coverage.lean (structural reg keccak chain)

## Crypto verifiers (uninterpreted oracles)
- [x] `BlobKZGVerifier.sol` (244) → Coverage.lean (KZG pairing = oracle)
- [x] `@mle/MleVerifier.sol` (submodule) → Coverage.lean (MLE/WHIR = oracle)

## Channel settlement (secondary — zkp audit excluded channel)
- [x] `ChannelSettlementManager.sol` (1301) → ChannelSettlementManager.lean (payout cap + no-double-claim) + Coverage (verify*=oracle)
- [x] `ChannelSettlementVerifier.sol` (1154) → Coverage.lean (verify* = crypto-oracle + check-then-set nullifier)

## Findings log
No new contract-level fund-safety vulnerability found. F-WITHDRAW-1 closed
(in-circuit + contract re-pin). Every payout path is solvency-capped + nullifier
single-use (CEI) + proof/auth-gated; channel path cap-bounded by real ETH pulled;
optimistic finalize requires a verified validity proof; rollback cannot touch
finalized state.

## Assessment (running)
- EVM core + withdrawal path done. Combined-system fund safety established
  for the native withdraw flow: L1 ETH out ≤ ETH in, every unit backed by a
  circuit-proven single-use validly-finalized withdrawal. Done: EVM core, withdrawNative, deposit, global solvency, finalize-write.
  GLOBAL FUND SAFETY established: Σ ETH out ≤ Σ ETH in (solvent_from_genesis),
  every payout circuit-proven + single-use + validly-finalized. Next: the
  optimistic pipeline (postBlock/submit/fraudProof/stake) governing WHEN
  finalizedStateRoots are written, then withdraw()/claimAuthorizedWithdrawal.
