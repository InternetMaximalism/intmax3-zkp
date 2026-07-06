# Fixture/VK regeneration + redeploy runbook (#11/#12)

Written 2026-07-06. This is the critical path that makes the mainnet-blocker
fixes (#1 block-producer whitelist, #2b `to_hash_out` canonicity) actually
effective on-chain. Heavy (hours of real proof generation) + needs a target
network — a maintainer-run step. Fixtures are NOT byte-reproducible (MLE/WHIR ZK
blinding); verify by MEANING (tests pass), not by diff.

## Why regen is needed — what each change invalidated

- **#2b (circuit change).** `tx_settlement.rs` and `single_withdrawal_circuit.rs`
  now use `to_hash_out` instead of bare `reduce_to_hash_out`. `tx_settlement` is
  in the balance core (`send_tx_circuit`, `receive_transfer_circuit`);
  `single_withdrawal` is in the withdrawal core (`withdrawal_step`,
  `withdrawal_chain_circuit`). Adding a constraint changes these circuits'
  digests, so **their VKs change**, cascading to essentially ALL proof fixtures
  and their VKs (validity, withdrawal, close, withdrawal-claim, post-close-claim,
  cancel-close, c2c, e2e, wasm). Old fixtures will FAIL to verify under
  regenerated VKs and vice-versa — they must be regenerated together.
- **#1 (contract change).** New `isBlockProducer` mapping + `setBlockProducer` +
  the `postBlockAndSubmit` gate change `IntmaxRollup` bytecode, hence its CREATE2
  address and the derived manager address baked into the CLOSE fixtures. This is
  the pre-existing `CloseLifecycleE2E` address-mismatch (also needs close-fixture
  regen). No VK changes from #1 (VKs are circuit-, not contract-, derived).

## Step 0 — preconditions
- Build native release once: `cargo build --release --locked`.
- Contracts build: `cd contracts && forge build`.
- Decide the target network + set `.env` (see `contracts/.env.example` and
  `api/.env.example`): `FRAUD_TREASURY`, `BLOCK_PRODUCER`, `INTMAX_DEPOSIT_KEY`,
  `INTMAX_API_TOKEN`, `INTMAX_ALLOWED_ORIGINS`.

## Step 1 — regenerate fixtures (release; each is minutes of proving)
Run from repo root. Feature-gated generators un-gate the shared witness builders.
```
# Balance/withdrawal + validity (base pipeline)
cargo run --release --bin generate_e2e_fixture
cargo run --release --bin generate_withdrawal_fixture
# Close family (bake the manager CREATE2 recipient — see below)
WD_RECIPIENT=0x<close-manager-addr> WD_OUT_PREFIX=close_ \
  cargo run --release --bin generate_withdrawal_fixture
cargo run --release --features close-fixture-bin            --bin generate_close_fixture
cargo run --release --features withdrawal-claim-fixture-bin --bin generate_withdrawal_claim_fixture
cargo run --release --features post-close-claim-fixture-bin --bin generate_post_close_claim_fixture
cargo run --release --features cancel-close-fixture-bin     --bin generate_cancel_close_fixture
# Cross-channel + wasm
cargo run --release --bin generate_c2c_fixture
cargo run --release --bin generate_wasm_fixtures
```
Outputs land in `contracts/test/data/`. The CLOSE fixtures bake the manager's
CREATE2 address — compute it in a TEST context (`CloseManagerAddr.t.sol` /
`CloseE2EBase._deployAll`), because the `MleVerifier` library link differs
between forge script and test. See `project_p2_native_withdrawal` / the CREATE2
lessons before regenerating close fixtures.

## Step 2 — verify by meaning (must be green before deploy)
```
# Rust proof-gen E2E (real MLE/WHIR)
cargo test --release --test e2e                       # e2e_deposit_validity_withdrawal
cargo test --release --test mle_onchain_e2e           # validity_proof_mle_onchain_e2e
# Solidity suite against the regenerated fixtures
cd contracts && forge test
```
Expected: the previously-red `CloseLifecycleE2E` now passes (its baked manager
address matches the freshly regenerated close fixture). All in-module circuit
tests (`tx_settlement`, `single_withdrawal_circuit`) already pass on this branch.

## Step 3 — deploy + VK init (target network)
Deploy scripts already wire the new guards: they authorize `BLOCK_PRODUCER`
(#1), require `FRAUD_TREASURY` on non-anvil chains (#6), and set the KZG
satellite. The per-statement VKs are initialized IN the deploy scripts from the
regenerated fixtures:
- `rollup.initializeWithdrawalVk(...)`  (withdrawal VK — CHANGED by #2b)
- `sv.initializeCloseVk(...)`, `initializeWithdrawalClaimVk(...)`,
  `initializePostCloseClaimVk(...)`, `initializeCancelCloseVk(...)`
Use `DeployCloseCli.s.sol` (CLI/prod path) or `Deploy.s.sol` (rollup-only smoke).
Build/deploy with `--locked` (dependency pin, #14). After deploy, authorize the
block producer if the posting key differs from the deployer:
`BLOCK_PRODUCER=0x<poster-addr>` (deploy reads it) — the whitelist is otherwise
empty (fail-closed).

## Step 4 — Option B (1024-slot) redeploy (#12)
Option B circuits/fixtures are already present on this branch (constants
`MAX_COSIGNERS=16`, `MAX_CHANNEL_MEMBERS=1024`). The LIVE network still runs
pre-Option-B params, so a fresh deploy with the regenerated Option-B fixtures/VKs
is required. Also complete the one-key member-model validity-path registration
follow-up (tracked with the Option B work).

## Verification checklist before opening deposits
- [ ] All fixtures regenerated in the same run (consistent circuit set).
- [ ] `cargo test --release --test e2e` + `--test mle_onchain_e2e` green.
- [ ] `forge test` fully green (incl. `CloseLifecycleE2E`).
- [ ] Deploy used `--locked`; `FRAUD_TREASURY` + `BLOCK_PRODUCER` set explicitly.
- [ ] Post-deploy: `isBlockProducer[poster] == true`, `allowMleDisabled == false`,
      all VKs initialized (`degreeBits > 0`).
- [ ] A real close/withdraw lifecycle passes on the target network.
