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
- **CO-SIGNER KEY MATERIAL (fail-closed; provision FIRST).** `channel_member` refuses to run
  unless exactly one of these is set:
  - `INTMAX_COSIGNER_KEYFILE=/path/to/cosigner.key` — **production**. A 0600, gitignored file with
    >= 32 bytes of hex. Create once per host with `umask 077; openssl rand -hex 32 >
    .claude/cosigner.key`, then **back it up**: keys are derived from it, so losing it makes every
    channel derived from it permanently unclosable. The CLI rejects a group/world-readable file,
    a short file, and an all-zero file. Never `cat`, echo, log, or commit it.
  - `INTMAX_INSECURE_DETERMINISTIC_KEYS=1` — **tests / local anvil only**. Prints a red banner on
    every invocation. Every key it produces is computable by anyone from this public repo.

  Setting **both** is a hard error (a provisioned host cannot be silently downgraded); setting
  neither is a hard error. Do not put the insecure flag in any systemd unit, Dockerfile `ENV`, or
  `.env` — `api/lib/cli.js:47` spreads `process.env` into every CLI child, so it would silently
  apply to every channel the API creates.

  **Every channel created before this fix has publicly derivable co-signer keys and must be
  drained and retired, not merely redeployed** — see `doc/tasks/cosigner-key-provenance.md` §2.
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
  `api/env.example`): `FRAUD_TREASURY`, `BLOCK_PRODUCER`, `INTMAX_L1_ACCOUNT`,
  `ETH_PASSWORD` (an absolute root-only password-file path, not password text),
  `INTMAX_COSIGNER_KEYFILE`, `INTMAX_API_TOKEN`, `INTMAX_ALLOWED_ORIGINS`.
  On every non-31337 chain the Rust CLI and API reject `INTMAX_DEPOSIT_KEY` and require the named
  encrypted Foundry keystore; only `--account <name>` reaches child argv.

## Step 1 — regenerate fixtures (release; each is minutes of proving)
Run from repo root. Feature-gated generators un-gate the shared witness builders.
```
# Balance/withdrawal + validity (base pipeline)
cargo run --release --bin generate_e2e_fixture
cargo run --release --bin generate_withdrawal_fixture
# Compute the manager CREATE2 address from the JUST-regenerated plain set:
cd contracts && forge build && \
  forge test --match-test test_printCloseManagerAddress -vv && cd ..
# Close family (bake the manager CREATE2 recipient printed above). Signer-independent exit
# (2026-09): `generate_close_fixture` is now the CO-GENERATOR of the whole family — it builds the
# `close_` lifecycle itself (deposit 6 / withdraw 3, recipient = WD_RECIPIENT; what
# `WD_OUT_PREFIX=close_ generate_withdrawal_fixture` used to write), closes THAT lifecycle's final
# balance proof (`intmax_state_root` = its finalized `final_state_root`, single-lane vector
# {ETH -> 3}) and proves the whole-vector CloseAssetBacking proof over the same balance proof
# (`close_asset_backing_{mle,public_inputs,manifest}.json`, anchor block 3). `submitCloseIntent`
# requires the finalized root AND an attested backing, so the three are only valid together.
# The printer's cross-check needs `close_lifecycle*.json` present and agreeing with the plain set:
# seed them from the plain set BEFORE the printer (the generator overwrites them).
cp contracts/test/data/lifecycle.json contracts/test/data/close_lifecycle.json
cp contracts/test/data/lifecycle_validity_mle.json contracts/test/data/close_lifecycle_validity_mle.json
# (printer, see above) then:
WD_RECIPIENT=0x<close-manager-addr> \
  cargo run --release --features close-fixture-bin          --bin generate_close_fixture
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
regenerated fixtures. **Which script initializes what — verified, do not
assume:**

| script | VKs initialized | real-network? |
|---|---|---|
| `DeployCloseCli.s.sol` (CLI/prod path — rollup **+** settlement stack) | withdrawal, close, withdrawalClaim, **postCloseClaim**, **cancelClose** — all five, **plus `registerSettlementManager(manager)`** (2026-08-13) | YES (needs `FRAUD_TREASURY` and a staged `cli_reg_record.json`) |
| `Deploy.s.sol` (rollup ONLY — no settlement stack) | validity (constructor) + **withdrawal** | YES (needs `FRAUD_TREASURY`) |
| `DeployTestnetBlockProducer.s.sol` (rollup ONLY, posting restricted to an admin) | validity (constructor) + **withdrawal** | YES (needs `FRAUD_TREASURY`) |
| `DeployC2C.s.sol` (rollup ONLY; header: "NOTHING else") | validity (constructor) + **withdrawal** | YES (needs `FRAUD_TREASURY`), but C2C-fixture-specific |
| `DeployClose.s.sol` | withdrawal only | **NO — and since 2026-08-13 that is ENFORCED**, not documented: `run()` opens with `require(block.chainid == SETTLEMENT_LOCAL_DEVNET_CHAIN_ID, ...)`. It deploys a settlement stack and keys NONE of its four VKs, so a channel it creates can be frozen by `requestClose()` and then never closed (`CloseVkNotSet()`) or un-frozen (`CancelCloseVkNotSet()`), and its `sepolia_*` fixtures are one circuit generation stale, so keying the VKs could not have made it work either. Devnet demo / manager-address dry run only. |
| `DeployWalletSettlement.s.sol`, `DeployPartialWithdrawalE2E.s.sol` | close, cancelClose, **withdrawalClaim, postCloseClaim** (the last two added 2026-08-13 — without them the wallet demo's own `claim` step reverted `WithdrawalClaimVkNotSet()`), + `registerSettlementManager` | anvil-gated (`chainid == 31337`, hard `require`) |

**What the chain-id checks actually gate — verified by reading each script, because two different
checks read alike:**
- `DeployWalletSettlement.s.sol:40` and `DeployPartialWithdrawalE2E.s.sol:44` are TRUE gates: a bare
  `require(block.chainid == 31337, …)` at the top of `run()`. They install an always-true mock MLE
  verifier, so they must never reach a public chain, and they cannot.
- The `require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys")` in
  `Deploy.s.sol`, `DeployTestnetBlockProducer.s.sol`, `DeployClose.s.sol` and `DeployCloseCli.s.sol`
  is **not** an anvil gate — it sits inside `if (fraudTreasury == address(0))`. Set `FRAUD_TREASURY`
  and these scripts run on any chain. `DeployCloseCli.s.sol` is therefore a real-network-capable
  full settlement deployer; it is simply not reachable from the CLI/API surface (see the gap below).

**Withdrawal VK — FIXED 2026-08-13, was the same defect class as the A-M4 history below.**
`Deploy.s.sol` and `DeployTestnetBlockProducer.s.sol` never called `initializeWithdrawalVk`, so
every rollup they produced accepted deposits (`deposit()` is ungated) and reverted
`WithdrawalVkNotSet()` on both `withdrawNative` and `withdrawERC20` forever
(`IntmaxRollup.sol:1619`, shared by both payout entry points). The `Deploy.s.sol` row above used to
read "rollup-only smoke / YES", and `doc/docs/deploy-runbook.md` uses that script for the live
Sepolia deploy — "smoke" was doing load-bearing work no operator would decode. Both scripts now
install the VK from `withdrawal_mle.json` (read BEFORE `startBroadcast`, so a missing fixture aborts
before anything is on chain) and `require(rollup.withdrawalVkInitialized())` afterwards. Covered by
`contracts/test/DeployGuards.t.sol`, which executes the scripts on chain id 11155111.

**Challenge period — FIXED 2026-08-13.** Every script that constructed a
`ChannelSettlementManager` hardcoded `CHALLENGE_PERIOD = 1` second while
`ChannelSettlementManager.CHALLENGE_PERIOD_SECS = 86_400` (documented, spec-referenced) was read by
nothing, and every test used 1 day — so the value that actually shipped was exercised by no test.
`finalizeCloseGuarded(bytes32,uint64)` is permissionless at the deadline and both remedies (`cancelClose`, a newer
`submitCloseIntent`) require minutes of MLE proving, so the deployed window made a stale close
unchallengeable: fund MIS-ALLOCATION among members, not a liveness inconvenience. Now:
- `script/DeployConfig.sol` resolves the value — the protocol constant off-devnet, 1 second on
  chain id 31337 (the anvil E2Es drive a real node and cannot wait a day);
- the manager's **constructor** independently rejects anything below the floor off-devnet
  (`ChallengePeriodTooShort`), so no deploy tooling — script, factory or hand-rolled — can ship a
  short window to a public chain.

⚠️ **Consequence for this runbook: changing `ChannelSettlementManager`'s bytecode moves its CREATE2
address, so the close fixture set must be regenerated** (`close_withdrawal_payout.json` /
`close_withdrawal_mle.json` bake the manager address as the withdrawal recipient, inside the proof).
Until that is done, `CloseLifecycleE2E.t.sol::test_closeLifecycle_endToEnd` fails with
`manager CREATE2 address != close payout fixture recipient (stale fixtures -- regenerate)` — the
intended signal, per Step 2 above. Get the new address from
`forge test --match-test test_printCloseManagerAddress -vv`, then rerun Step 1's
`WD_RECIPIENT=<addr> cargo run --release --features close-fixture-bin --bin generate_close_fixture`
(the close-family co-generator: `close_` lifecycle + close intent + backing proof in one run).

**Settlement-manager registration — FIXED 2026-08-13.** `DeployCloseCli.s.sol` did not call
`rollup.registerSettlementManager(manager)`; its only callers were the two anvil-gated scripts. That
gates `finalizePartialWithdrawal` (`IntmaxRollup.sol` `NotRegisteredSettlementManager`); full-close
withdrawal leaves carry `auxData == 0` and skip it, so full close was unaffected.

**This was NOT moot, and the prior text claiming it was is retracted.** That text said "the CLI's
`cmd_partial_withdraw` is unimplemented and `pw-finalize` deliberately `exit(1)`s before payout" —
`cmd_partial_withdraw` is a command name that does not exist, so the grep behind that claim could
only ever come back empty. The real commands are `pw-submit` (`src/bin/channel_member.rs:5706`) and
`pw-finalize` (`:5893`), both implemented, both driven by `api/routes/partial-withdrawal.js:67,80`,
and `tests/partial_withdrawal_e2e.rs` exercises them. On a real deployment the revert landed at
FINALIZE — after the member had submitted the intent and waited out the entire challenge period.
The call is now step 6 of the script, followed by a read-back `require`, and covered by
`contracts/test/DeployGuards.t.sol` (which executes the script at chain id 11155111 and asserts the
deployed manager can actually call `authorizePartialWithdrawal`, while a stranger still cannot).
*Lesson: a "this path is dead so the gap is moot" argument must name the live entry points it
searched for and show they are absent — a negative grep for the wrong identifier is not evidence.*

**HISTORY — this text was an OVERCLAIM until 2026-08-12.** `DeployCloseCli.s.sol`
called only `initializeCloseVk` and `initializeWithdrawalClaimVk`;
`initializePostCloseClaimVk` was called by NO script anywhere in the repo, and
`initializeCancelCloseVk` only by the two anvil-gated scripts. So every REAL
deployment shipped with both unset, and:
- `ChannelSettlementVerifier.sol:1111` reverted `PostCloseClaimVkNotSet()` →
  the `post-close-claim` CLI command (`channel_member.rs:2152-2184`) could
  never succeed;
- `ChannelSettlementVerifier.sol:1050` reverted `CancelCloseVkNotSet()` →
  `cancel-close` (`channel_member.rs:1988-2025`), the ONLY on-chain remedy
  against a stale close, was unavailable.

Reported as audit622 **A-M4** ("MEDIUM, liveness bricking") on 2026-06-22 and
open until the two calls were added (steps 3b/3c in the script). SECURITY: the
fix supplies the VKs the reverts were correctly demanding; no fail-closed check
was weakened.

This is the SAME CLASS as the gate-8 defect — a fail-closed check that is
soundness-safe (it never accepts a bad proof) while making an HONEST user's
path impossible. A threat model that only asks "can an adversary get a false
statement accepted?" cannot see either one. When editing this runbook, state
what the scripts DO, verified by reading them — not what they ought to do.
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
  --account "$INTMAX_L1_ACCOUNT" --broadcast --slow

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

### Step 3c — testnet $ITX faucet (OPTIONAL; anvil + public testnets only)

Gives new browser users an in-channel balance of a test ERC-20 (`$ITX`) so they can try a transfer
without funding anything. Runs **after** 3b (the faucet token is just another registered base
token) and **after** the channel exists (`init`). Skip the whole step on any deployment that should
not dispense value — the relay endpoint is off unless explicitly enabled.

**Model.** A designated CLI **faucet member** holds an in-channel `$ITX` balance and the relay
sends new users an ordinary in-channel transfer at the ITX token position. No new protocol path.
The supply is ONE real L1 deposit imported once, so the faucet **cannot mint**: it can only run
dry, and every dripped balance stays backed by `channel_fund.amounts[t]` and stays claimable.

**Scale.** In-channel balances are **u64 base units**, so a position tops out at
`u64::MAX / 10**decimals` whole tokens. `$ITX` uses **6 decimals** precisely for this: the ceiling
is ~18.4 trillion ITX (it would be ~18.44 at 18 decimals). The contract constant, the manifest
`decimals`, the faucet env and the E2E constants must move TOGETHER — the relay/node read
`decimals()` back from the token at startup and **refuse to run on a mismatch**.

```bash
export RPC_URL=http://127.0.0.1:8545       # or "$SEPOLIA_RPC_URL"
export CHANNEL=7
export ROLLUP=0x…                          # this channel's IntmaxRollup (channel_backing.json .rollup)
export ITX_TOKEN_INDEX=1                   # base index reserved for $ITX — MUST be nonzero
export ITX_SUPPLY=1000000000000000         # L1 supply: 1,000,000,000 ITX @ 6dp (uint256, unconstrained)
export FAUCET_SUPPLY=1000000000000         # imported into the channel: 1,000,000 ITX  (< 2^64!)
export FAUCET_SLOT=2                       # a CLI CO-SIGNING member slot (0..INTMAX_CLI_COSIGNERS-1);
                                           # avoid slot 0, which is the BP/builder slot
WORK=wallet-live-work/ch$CHANNEL           # on the EC2 box: ~/relay/wallet-live-work/ch$CHANNEL
CLI=$PWD/target/release/channel_member

# 1) deploy $ITX. TESTNET-ONLY contract — it lives under contracts/test/ on purpose and must never
#    be referenced from contracts/src/ or a mainnet script. Fixed supply, no mint entry point.
( cd contracts && forge create test/tokens/IntmaxTestTokenITX.sol:IntmaxTestTokenITX \
    --rpc-url "$RPC_URL" --account "$INTMAX_L1_ACCOUNT" --broadcast \
    --constructor-args "$ITX_SUPPLY" )     # prints `Deployed to: 0x…`
export ITX=0x…

# 2) register it on the rollup's SET-ONCE registry, through the manifest (Step 3b machinery).
#    Add to deploy-staging/ch$CHANNEL/tokens.json (template: node/tokens.example.json):
#      { "tokenIndex": 1, "symbol": "ITX", "name": "Intmax Test Token", "decimals": 6,
#        "address": "<ITX>" }
( cd contracts && TOKENS_MANIFEST=../deploy-staging/ch$CHANNEL/tokens.json \
    forge script script/RegisterTokens.s.sol --rpc-url "$RPC_URL" \
    --account "$INTMAX_L1_ACCOUNT" --broadcast --slow )
cast call "$ROLLUP" "tokenAddressOf(uint32)(address)" "$ITX_TOKEN_INDEX" --rpc-url "$RPC_URL"

# 3) give ITX a LOCAL slot in the channel: an append-only, N-of-N-cosigned TokenRegister.
#    Prints "registered at local slot <t>". The relay resolves <t> itself from the SIGNED
#    snapshot at request time — it is not configured anywhere.
( cd $WORK && INTMAX_CHANNEL=$CHANNEL "$CLI" register-token "$ITX_TOKEN_INDEX" token_register.json )

# 4) escrow the faucet supply on L1. msg.value MUST be 0 for a nonzero tokenIndex; the rollup
#    credits a MEASURED balanceOf delta (fee-on-transfer tokens fail closed here).
DEPOSIT_RECIPIENT=$(jq -r .deposit_recipient $WORK/channel_backing.json)
cast send "$ITX" "approve(address,uint256)" "$ROLLUP" "$FAUCET_SUPPLY" \
  --rpc-url "$RPC_URL" --account "$INTMAX_L1_ACCOUNT"
# Capture the REAL deposit tx hash — the import is verified against this transaction's on-chain
# `Deposited` log (doc/tasks/deposit-import-threat-model.md).
DEPOSIT_TX=$(cast send "$ROLLUP" "deposit(bytes32,uint32,uint256,bytes32)" \
  "$DEPOSIT_RECIPIENT" "$ITX_TOKEN_INDEX" "$FAUCET_SUPPLY" \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  --value 0 --rpc-url "$RPC_URL" --account "$INTMAX_L1_ACCOUNT" --json | jq -r .transactionHash)

# 5) import the deposit to the FAUCET member (cosigned). The amount, depositor and base
#    token_index are READ FROM THE CHAIN — they are no longer arguments, so they cannot be
#    misstated. The token index still resolves against the channel's signed registry (an
#    unregistered index is refused fail-closed, TM-7).
#
#    --allow-unbound-depositor is needed ONLY here: the faucet slot's B-1b bound exit address is
#    the synthetic per-(channel, slot) address, not the operator's deployer account. It does NOT
#    weaken the check that blocks redirecting another MEMBER's deposit — that refusal is
#    unconditional. Never pass this flag on a user deposit, and never wire it into a relay.
#
#    On a public chain the import also waits for 12 confirmations by default; append a smaller
#    depth as the 5th positional argument if you knowingly want less (0 is not permitted).
( cd $WORK && INTMAX_CHANNEL=$CHANNEL "$CLI" cosign-l1-deposit-import \
    "$FAUCET_SLOT" "$DEPOSIT_TX" "$RPC_URL" itx_import.json --allow-unbound-depositor )

# 6) sanity: make the faucet position spendable once, up front. A homomorphically credited
#    position (which is what an import produces) has pending_adds > 0 and no local encryption
#    witness — `refresh` re-encrypts it value-preservingly (RefreshAir, re-verified by every
#    co-signer). The relay ALSO runs this before every drip, so this is only a smoke check.
( cd $WORK && INTMAX_CHANNEL=$CHANNEL "$CLI" refresh "$FAUCET_SLOT" <t> )

# 7) enable the relay endpoint (systemd Environment= on EC2). ALL of these are required —
#    the faucet stays off, and POST /api/faucet 404s, unless the whole set is coherent.
FAUCET_ENABLED=1 \
FAUCET_SLOT=$FAUCET_SLOT \
ITX_TOKEN_INDEX=$ITX_TOKEN_INDEX \
FAUCET_DRIP=100000000 \
FAUCET_CHANNEL_CAP=100000000000 \
FAUCET_COOLDOWN_MS=5000 \
#    Amounts are BASE UNITS (6 decimals): 100000000 = 100 ITX, 100000000000 = 100,000 ITX.
#    Hard ceilings in faucet-policy.js refuse anything above 1,000 ITX per claim / 10,000,000 ITX
#    per channel, so a mistyped digit disables the faucet (404 + a logged reason) instead of
#    handing out orders of magnitude too much. Raising a ceiling needs a code change.
  node hosting/wallet/wallet-relay.js       # (EC2: wallet-relay-ec2.js under systemd)
```

Verify: `curl -s https://<host>/api/faucet` → `{"enabled":true,"tokenIndex":1,"amount":"100000000",…}`
(and `{"enabled":false}` when it is off). A browser join then logs `faucet: received 100 ITX` and
the per-token balance row appears once the manifest entry is chain-verified (address AND
`decimals()` both read back equal — a `decimals` disagreement is a hard startup failure, and a
token with no readable `decimals()` is shown in raw base units rather than a guessed scale).

**Security notes for the operator** (see `hosting/wallet/wallet-relay*.js` and
`node/common/faucet-policy.js` for the enforced rules):
- The endpoint is **public and unauthenticated**. It is off by default; `FAUCET_ENABLED=1` without
  a valid `FAUCET_SLOT`/`ITX_TOKEN_INDEX` logs a warning and stays off. `ITX_TOKEN_INDEX=0` is
  rejected outright — index 0 is native ETH, i.e. the channel's own deposit backing.
- One drip per balance slot, **for ever**, plus a per-channel cap and a cooldown. The record is
  written BEFORE the transfer, so a crash costs a drip instead of paying twice; a failed drip is
  NOT retried automatically. Ledger: `wallet-live-work/ch<N>/faucet_state.json` — a corrupt file
  makes the endpoint fail closed (500), and deleting it **re-opens the faucet to everyone who
  already drank**. Treat it as state, not cache.
- The recipient slot is the only request-controlled value and is checked against the channel's own
  signed `member_count + delegate_count`; the amount and token are server-side config only. There
  is **no ownership proof** on that slot — an anonymous caller may request a drip for any active
  account, which lands with the legitimate owner but consumes the channel allowance (residual risk
  R-1 in `doc/tasks/itx-faucet-threat-model.md`).
- **DEPLOYMENT INVARIANT (D-1): exactly ONE writer process per channel directory.** Every
  single-use ledger in `wallet-live-work/ch<N>/` is a plain JSON file guarded by an IN-PROCESS
  mutex, not a file lock — the faucet drip ledger (`faucet_state.json`), the imported-deposit
  ledger (`CliState.imported_deposits`, see `doc/tasks/deposit-import-threat-model.md`) and the
  pre-existing inter-channel spent/applied ledgers. Two processes sharing one directory can both
  pass a membership check and both commit: a double drip, or the SAME L1 deposit credited twice.
  Note this is not only "two relays" — the api service, the relay and the node co-signer can all
  be pointed at the same work dir. Run one writer per channel; if that ever changes, these ledgers
  need a real file lock BEFORE the faucet or browser deposit import is re-enabled.

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
