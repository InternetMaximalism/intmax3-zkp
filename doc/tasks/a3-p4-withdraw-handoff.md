# A-3 P4 completion handoff: CLI `withdraw` (channel funds from rollup → manager)

This file is written to be self-contained — context, design, pitfalls, and verification — so that the next thread can implement `withdraw` from it alone.

## 0. Prerequisites (where we are so far)
Branch `fix/audit-soundness-and-tests`. `doc/tasks/a3-impl-todo.md` and `doc/tasks/a3-close-lifecycle-spec.md` are the base documents.
- **P2 complete and verified**: `CloseProver` / `WithdrawalClaimProver` / `CancelCloseProver` / `PostCloseClaimProver` in `src/wallet_core.rs` (all have real-proof tests PASSing + an independent security review).
- **P3/P4 wired up**: `cmd_close` (P3) / `cmd_settle` / `cmd_claim` (P4) in `src/bin/channel_member.rs`. `submitCloseIntentStep` / `submitWithdrawalClaimStep` (newly added) / `withdrawNativeStep` (existing) in `contracts/script/RunClose.s.sol`.
- **The only thing missing = `withdraw`**. Without it the manager has no funds at `claim` time.

## 1. Goal
`channel_member withdraw <manager_addr> [rpc_url]`:
1. Generate a **withdrawal proof** (recipient = manager) against the channel's real deposit (wrap + MLE).
2. Fill the manager's `pendingWithdrawals` via `IntmaxRollup.withdrawNative(ws, prover, mleProof)`.
3. Pull the funds into the manager with `ChannelSettlementManager.pullChannelFunds()`.

→ then distribute to members with `claim`.

## 2. Why this is a big job (rationale for re-scoping)
The withdrawal proof is not part of the close circuits but of the **rollup's withdrawal subsystem**. `src/bin/generate_withdrawal_fixture.rs` (~700 lines) is the template; what is needed:
- `BalanceProcessor` + `BalanceWitnessGenerator` (`src/circuits/test_utils/balance_witness_generator.rs`)
- `BlockWitnessGenerator` (the rollup's block state = which deposit/block)
- `balance_witness_generator.single_withdrawal_witness(&single_withdrawal_data)` → `single_withdrawal_circuit.prove(...)`
- `WithdrawalProcessor` (`prove_step` → `prove_final(&chain_proof, prover, &ext_public_state)`)
- `ext_public_state` (i.e. `block_witness_generator.current_extended_public_state()` and friends; its `.commitment()` must match withdrawNative's `ext_public_state_commitment` PI)
- Output: the final withdrawal proof → `WrapperCircuit` + MLE (`wallet_core::wrap_and_export_mle` can be reused) → `withdrawal_mle.json` + payout (`Withdrawal` struct)

**The core constraint (SECURITY)**: withdrawNative does `if (!finalizedStateRoots[extCommitment]) revert` (`IntmaxRollup.sol:1262`). That is, the withdrawal proof's `ext_public_state_commitment` must be a **state root the rollup has already finalized**. Therefore the block containing the channel's deposit must be finalized (the same prerequisite as P1's anchor/liveness).

## 3. Design (two options, A recommended)

### Option A (recommended): rebuild the witness-generator context from setup-backing and use it in withdraw
`setup-backing` (`channel_member.rs:cmd_setup_backing`) already performs a real deposit and builds a balance proof by feeding the deposit witness into `BalanceWitnessGenerator`. **Persist** the same deposit parameters (channel_id, deposit_salt, recipient, amount) in something like `ChannelBacking`, and **deterministically rebuild** the same block/witness context in `withdraw` to build single_withdrawal_witness.
- Additional persistence needed: deposit_salt (currently not stored), and the deposit's block context. Add `deposit_salt` etc. to `ChannelBacking`.
- Upside: correctly bound to the real deposit. Downside: the block-witness rebuild logic has to be ported over from generate_withdrawal_fixture.

### Option B: add a new `build_channel_withdrawal` to wallet_core
Factor the steps of `generate_withdrawal_fixture` (single_withdrawal → chain → final → wrap+MLE) out into a builder function in `wallet_core` and call it from `withdraw`. The inputs are (deposit context, recipient=manager, finalized_root). Same style as the P2 builders (fail-closed by default + verified tests).
- Upside: reusable and easy to test. Downside: threading the deposit/block context through is heavy.

**Either way, generate_withdrawal_fixture is the one correct reference implementation.** First run it with `cargo run --release --bin generate_withdrawal_fixture`, understand it step by step, then port.

## 4. Implementation steps (concrete)
1. Read `generate_withdrawal_fixture.rs` and extract the minimal path for generating a withdrawal proof (`fn main` from line 209, single_withdrawal_witness at line 452, prove_step/prove_final at lines 466-487, ext_public_state at line 480, wrap+MLE output).
2. Add a `WithdrawalProver` (or `build_channel_withdrawal`) to wallet_core. Reuse `wrap_and_export_mle` for the MLE. Make the recipient=manager, which corresponds to WD_RECIPIENT, a parameter.
3. Add `cmd_withdraw` to `channel_member.rs`:
   - args: `<manager> [rpc]`. The manager's 20 bytes → `calculate_recipient_from_address`.
   - Obtain the deposit context per option A/B → generate the withdrawal proof + MLE → write `withdrawal_mle.json` + `withdrawal_payout.json` (following the staging pattern of `cmd_claim`, copy them to `contracts/test/data/sepolia_withdrawal_mle.json` / `sepolia_withdrawal_payout.json`).
   - `forge script RunClose --sig withdrawNativeStep()` (existing, ROLLUP/MANAGER env) → then `cast send <manager> pullChannelFunds()`.
   - Replace the dispatcher's `"withdraw" => cmd_close_lifecycle_unimplemented` with `cmd_withdraw`.
4. Payout format: match the `Withdrawal` structure (recipient, amount, …) of `sepolia_withdrawal_payout.json` that `RunClose._payout()` reads. See the payout output of `generate_withdrawal_fixture` (around line 700).

## 5. Verification
- **Unit (release, heavy)**: add the equivalent of `a3_withdrawal_prover_builds_and_verifies` to `wallet_core` and self-verify deposit→withdrawal proof→`single_withdrawal_circuit.data.verify` (same shape as the P2 tests, `#[cfg_attr(debug_assertions, ignore)]`).
- **Live is the P5 E2E** (see the plan below): on anvil, deposit→finalize→withdrawNative→pullChannelFunds→assert `pendingWithdrawals[manager]` and the manager balance.

## 6. Pitfalls
- **ext_commitment must be an already-finalized root**. The E2E must always finalize the block containing the deposit before withdraw.
- **fixture contention**: `withdraw`/`claim`/`close` all stage into `contracts/test/data/sepolia_*`. Watch the ordering and overwrites in the E2E (write them immediately before each step).
- **Do not change IntmaxRollup at all**: a bytecode change = manager CREATE2 address drift = close fixture regeneration (experienced in A-2, stemming from the metadata hash). `withdraw` does not touch IntmaxRollup, so this is not needed.
- Heavy proving (on the order of minutes). Tests are `#[ignore]` + release; for live runs on anvil, get permission each time.

## 7. Completion criteria
`channel_member withdraw` generates a withdrawal proof for a real channel and withdrawNative + pullChannelFunds succeed. → P4 complete (close→settle→withdraw→claim works end to end from the CLI).
