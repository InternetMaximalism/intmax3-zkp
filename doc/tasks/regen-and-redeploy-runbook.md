# Fixture/VK regeneration + redeploy runbook (#11/#12, multitoken Phase 5b)

Written 2026-07-06; extended 2026-07-27 for the multitoken (§N) regeneration.
This is the critical path that makes the mainnet-blocker fixes (#1
block-producer whitelist, #2b `to_hash_out` canonicity) and the §N multi-token
preimage/PI changes actually effective on-chain. Heavy (hours of real proof
generation) + needs a target network — a maintainer-run step. Fixtures are NOT
byte-reproducible (MLE/WHIR ZK blinding); verify by MEANING (tests pass), not
by diff.

## Multitoken (§N) additions — what changed in the flow (2026-07-27)

- **Every close/claim fixture predating §N is invalid** (close PI 95→103 w/
  `token_funds_digest`; claim PI 48→50 w/ tokenSlot/tokenIndex; post-close PI
  56→57 w/ tokenIndex; IMCH/IMCI/IMW2/IMB2/IMS2 preimage widenings; IMI2/TFD new
  domains) and the `IntmaxRollup`/`ChannelSettlementManager` initcode changed →
  NEW CREATE2 manager address baked into the close fixtures.
- **Descriptors are per-token now.** `close_intent.json` (fixture bin AND the
  CLI `close`) carries `channel_fund_amounts[10]` / `token_registry[10]` /
  `token_count` (+ the legacy `channel_fund_amount` scalar); the claim
  descriptor carries `token_slot`/`token_index`; the post-close descriptor
  carries `token_index`. `RunClose.s.sol` / `CloseLifecycleE2E` parse them
  verbatim (the Phase-3 genesis-token embedding is retired).
- **Close fixture co-generation.** `generate_close_fixture` now derives its
  signing keys from `ChannelMemberKeys::deterministic(1)` — the SAME derivation
  `generate_withdrawal_fixture` registers — and proves a TWO-token final state
  (registry `[0, 7]`, amounts `[77, 55]`). `CloseLifecycleE2E`'s close-intent
  section therefore RUNS (member-set commitment matches) and HARD-FAILS on any
  stale/mixed fixture set: always regenerate the unprefixed set, the `close_`
  set and the close/claim fixtures in ONE batch.
- **ERC-20 withdrawal lane.** `build_channel_withdrawal` (and the CLI
  `withdraw`) can add a second, ERC-20 lane: `WD_ERC20_TOKEN` /
  `WD_ERC20_AMOUNT` / `WD_ERC20_TOKEN_ADDR` env → a second deposit in the
  deposit block (on-chain: approve + `deposit()` ERC-20 branch, balanceOf-delta
  checked) and a SECOND single-leaf withdrawal chain paid via `withdrawERC20`
  (`RunClose.withdrawErc20Step`), then `pullChannelTokenFunds(t)`.
- **Two-token anvil E2E:** after regenerating the close-stack fixtures, run
  `cargo test --release --test two_token_cli_e2e -- --ignored --nocapture`.

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
- **STALE CLI STATE (TM-16): do NOT reuse pre-TM-16 `cli_state.json` files.** The
  TM-16 change re-keyed the CLI replay ledgers (`applied_tx_identities` /
  `spent_tx_identities`, token-free replay identities) and the descriptor wire
  format gained token fields; old state files deserialize with EMPTY ledgers
  (serde default), silently losing replay protection for previously-credited
  transfers. Delete every stale per-channel state directory (`cli_state.json`
  and siblings) before driving any post-TM-16 flow — the v3 reset assumes fresh
  state everywhere.
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
# Compute the manager CREATE2 address from the JUST-regenerated plain set:
cd contracts && forge build && \
  forge test --match-test test_printCloseManagerAddress -vv && cd ..
# Close family (bake the manager CREATE2 recipient printed above)
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
CREATE2 address — compute it with
`CloseLifecycleE2ETest.test_printCloseManagerAddress` (in
`CloseLifecycleE2E.t.sol`; moved there in Phase 5b), because the `MleVerifier`
external-library link differs not only between forge script and test but PER
TEST CONTRACT — only a printer inside the lifecycle test contract shares its
linking context (`CloseManagerAddr.t.sol` is now a pointer stub). NOTE the
ORDER: the plain (unprefixed) set must be regenerated BEFORE the printer runs
(its prediction reads `lifecycle*.json`, valid because registration/VK/genesis
are identical between the plain and `close_` sets — both use the deterministic
channel-1 member keys), and `generate_close_fixture` must run in the SAME batch
(co-generated member set, see the §N additions above). If
`CloseLifecycleE2E.t.sol` itself is EDITED after baking, re-run the printer and
confirm the address is unchanged (library linking can shift with the contract).

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

### Step 3b — register the ERC-20 tokens (AFTER the rollup deploy, BEFORE any ERC-20 deposit)

The base `tokenIndex → ERC-20` registry is **set-once per index** (§N-7 / TM-10b) and
`deposit()` reverts for an unregistered nonzero index, so this step must run **after** the rollup
exists and **before** any ERC-20 deposit (incl. the `WD_ERC20_*` withdrawal lane above and the
two-token E2E). It is a standalone script — it does **not** run from `Deploy*.s.sol`.

```bash
# 1) write the per-deployment manifest (template: node/tokens.example.json). `rollup` MUST be the
#    address just deployed and `chainId` the target chain — the script and the node both refuse to
#    proceed when either disagrees.
$EDITOR deploy-staging/ch7/tokens.json

# 2) register (idempotent: a re-run with the same manifest is a no-op; a manifest that disagrees
#    with an already-set index REVERTS — set-once is never an "update")
cd contracts && TOKENS_MANIFEST=../deploy-staging/ch7/tokens.json \
  forge script script/RegisterTokens.s.sol --rpc-url "$RPC_URL" \
  --private-key "$(cat "$PRIV")" --broadcast --slow      # NEVER echo/print the key

# 3) confirm (the script also reads back `tokenAddressOf` itself and reverts on a mismatch)
cast call <rollup> "tokenAddressOf(uint32)(address)" 5 --rpc-url "$RPC_URL"
```

**Ship `tokens.json` alongside `channel_backing.json`** — same propagation as the rest of the
backing artifacts, into each channel's work dir on the relay/api box:

```bash
# deploy-staging/ch{7,8}/{channel_backing.json,channel_attestation.bin,balance_vd.bin,tokens.json}
#   → <box>:~/relay/wallet-live-work/ch{7,8}/
```

The relay / api / node programs then load it and **verify every entry against the on-chain
`tokenAddressOf`** before serving any symbol. Display metadata (symbol/name/decimals) carries ZERO
authority — a mislabelled token is a user-funds attack — so an unverified or unregistered entry is
served with `null` metadata and the wallet falls back to the raw base index. A manifest that
CONTRADICTS the chain (address/chainId/rollup mismatch) is a hard startup failure by design; fix
the file rather than working around it. See `node/DESIGN.md` §2.5 for the full policy table.

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
- [ ] `RegisterTokens.s.sol` run for every ERC-20 the deployment will accept, BEFORE the first
      ERC-20 deposit; `tokenAddressOf(idx)` reads back the expected address for each.
- [ ] `tokens.json` shipped alongside `channel_backing.json` into every channel work dir, and the
      relay/api logged every entry as `verified` (an unverified entry silently degrades the UI to
      raw base indices; a contradicting entry refuses to start).
