# Fix plan — testnet pw-settle: `relay /api/pw-submit: cannot find contracts/ dir`

> **STATUS (2026-07-05, rebased onto main):** the CLI fix (chain-aware `pw-finalize`,
> `CONTRACTS_DIR` error hint, exact ABI-bool parsing) is what this branch carries. The EIP-170
> library extraction (RollupHashLib/WhirParamsLib) that originally accompanied it was **dropped as
> superseded**: main's B-3 landed its own EIP-170 relief (BlobKZGVerifierExt satellite, IntmaxRollup
> 21,443 B / 3,133 B headroom) with all fixtures regenerated and Foundry 175/175 green — see
> `doc/tasks/reg-chain-1024-threat-model.md` (B-3). The deploy-only MAX=256 working-tree patch was
> likewise discarded (Option B supersedes it; kept at `.claude/max256.patch` for reference only).
> EC2 provisioning from this effort **persists and stays valid** (foundry installed; systemd
> `CONTRACTS_DIR`/`INTMAX_DEPOSIT_KEY`/`RPC`/`CHAIN_ID` env), **but** the `contracts/` tree rsynced
> to the box was built from the superseded branch — it MUST be re-shipped from main during the B-3
> redeploy, together with the signer binary, or validity/close binding diverges again.
> Path note: repo layout moved `wallet/` → `hosting/wallet/` and `tasks/` → `doc/tasks/`; file
> references below predate that.

Reported 2026-07-03 on https://v3testnet.intmax.io/ (EC2 demo): Step 2 "Settle on L1" of the
partial withdrawal fails with `pw-settle failed: relay /api/pw-submit: {"error":"error: cannot
find contracts/ dir\n"}` after a successful 0.001 ETH burn (ticket persisted, retry-safe).

## Root cause (confirmed in code)

`/api/pw-submit` (`wallet/wallet-relay-ec2.js:265`) execs `channel_member pw-submit` — and, when
`settlement.json` is missing, `deploy-settlement` first (line 270-272). Both commands resolve a
contracts dir via `CONTRACTS_DIR` env or by walking up from the exe path
(`src/bin/channel_member.rs:2842-2852`, `:3143-3152`), write `contracts/test/data/pw_*.json`,
then run `forge script … --broadcast`.

The EC2 box **by design ships only the signer binary + backing artifacts** ("NO anvil/forge on
this box — it only co-signs", relay header + docs/deploy-runbook.md). No repo checkout, no
`contracts/`, no foundry → the exe-ancestor walk fails → `die("cannot find contracts/ dir")`.
The pw settle path was wired for the local anvil relay only and was never provisioned on EC2.

## Latent follow-on failures (will hit immediately after unblocking)

1. **No `forge`/`cast` on EC2** — both commands shell out to foundry.
2. **`INTMAX_DEPOSIT_KEY` unset** → falls back to `ANVIL_DEV_KEY` (channel_member.rs:326-328)
   → 0 balance on Sepolia → broadcast fails. Needs a funded key in the systemd env.
3. **`pw-finalize` uses anvil-only RPCs unconditionally** (`evm_increaseTime`/`evm_mine`,
   channel_member.rs:3228-3229) → dies on Sepolia. (The close paths already gate this behind
   `CLOSE_ADVANCE_TIME`, dev-only — only pw-finalize is unconditional.)
4. **via_ir compile is heavy** for t4g.medium (4 GB RAM) — mitigate by shipping precompiled
   `out/` + `cache/` (JSON, platform-independent) and/or adding swap for the one-time build.

Security notes (testnet-scale, must be stated): the funded key lands on a public box whose
unauthenticated endpoints trigger broadcasts (gas-drain DoS possible) → use a **dedicated
low-balance relay key** (~0.05 ETH Sepolia), NOT the main deployer; hand it via root-only
`EnvironmentFile`, never print (per CLAUDE.md secrets rules). `registerChannel` /
`registerSettlementManager` have no owner gate, so any funded key works. The settlement path
still uses the known `WalletMockMleVerifier` (always-true) demo stub — unchanged by this fix.

## Chosen approach

**A: make the EC2 box forge-capable** (ship `contracts/` + foundry, set `CONTRACTS_DIR`), plus a
small Rust fix for pw-finalize. Keeps ONE code path shared with the anvil demo; minimal churn on
a security-sensitive path.

Rejected alternative B (pre-deploy settlement locally + replace forge-script with cast calls):
requires pulling the durable EC2 channel state down before every deploy, and hand-encoding the
nested `submitPartialWithdrawalIntent(CloseIntent, MleProof, bytes32, AuthorizedWithdrawal)`
calldata — more new code and more soundness-relevant surface for the same demo outcome.

## Steps

### Phase 0 — confirm on the box (read-only)
- [ ] ssh EC2 (`.claude/deploy-record.md` identifiers): `journalctl -u intmax-relay` shows which
      CLI call died (deploy-settlement vs pw-submit); check `wallet-live-work/ch{7,8}/settlement.json`
      presence; confirm `RPC`/`CHAIN_ID` env of the unit.

### Phase 1 — Rust fix (small; anvil path must not regress)
- [ ] `cmd_pw_finalize`: attempt `evm_increaseTime`/`evm_mine` only on a dev chain (chain_id
      31337 via `cast chain-id`, or tolerate-failure), else wait for real time — manager
      `CHALLENGE_PERIOD = 1s`, so one Sepolia block (~12 s) suffices; poll or sleep+retry.
- [ ] `cast()` helper currently dies on any failure — the fallback must not route through it
      blindly (add a non-fatal variant or pre-check chain id).
- [ ] Improve the two `die("cannot find contracts/ dir")` messages to mention `CONTRACTS_DIR`.

### Phase 2 — provision EC2
- [ ] Install foundry (linux/arm64; svm's aarch64 solc fallback) — `forge`+`cast` reachable from
      the systemd unit's PATH (symlink into /usr/local/bin).
- [ ] `forge build` locally, then rsync `contracts/` (src, script, test/data, lib incl. the
      polygon-plonky2 mle subtree, foundry.toml + remappings, prebuilt `out/` + `cache/`) →
      `~/relay/contracts`. On the box run `forge build` once to validate/warm the cache (add 4 GB
      swap first if it recompiles via_ir).
- [ ] systemd unit env: `CONTRACTS_DIR=/home/ubuntu/relay/contracts`,
      `INTMAX_DEPOSIT_KEY=<dedicated funded relay key>` (root-only EnvironmentFile), verify
      `RPC=<sepolia>`, `CHAIN_ID=11155111`.
- [ ] Fund the relay key (small amount) from the deployer; record the address (public) in
      `.claude/deploy-record.md`.

### Phase 3 — deploy + verify (falsifiable)
- [ ] Local regression first: full pw flow (burn → settle → finalize) against `wallet-relay.js`
      + anvil passes with the new binary.
- [ ] Build linux/arm64 binary via `Dockerfile.signer`, scp per runbook, restart unit.
- [ ] `curl /api/health` OK; then resume the stuck ticket in the browser: Step 2 Settle →
      deploy-settlement broadcasts (~5 Sepolia txs, first time per channel), `pw-submit` returns
      `pw_auth.json` with matching Rust/on-chain authDigest.
- [ ] `pw-finalize` succeeds on Sepolia without `evm_*` (real ~12 s wait); recipient balance
      increases by the burn amount (`cast balance`) — escrow `withdrawNative` path.
- [ ] Anvil E2E unaffected (`cargo test --release` pw tests, if present, still pass).

### Phase 4 — docs
- [ ] Update `docs/deploy-runbook.md`: new shipped pieces (contracts/, foundry), unit env vars,
      relay-key policy, pw-flow verification commands.
- [ ] `.claude/deploy-record.md`: relay key address, settlement manager/verifier addresses.
- [ ] `tasks/lessons.md`: "EC2 ships no repo — any CLI path that shells out to forge must be
      provisioned explicitly or fail with an actionable message."

## Phase 0 findings (2026-07-04, confirmed on the box + on-chain)

- journalctl: the dying call is `deploy-settlement` (no `settlement.json` in ch7) — exactly the
  `cannot find contracts/ dir` die. No forge/cast installed; `INTMAX_DEPOSIT_KEY` not in the unit
  env. Disk 17G free / RAM 3.7G — provisioning feasible.
- ch7 has **6 stranded burn-done partial-withdrawal tickets** (Σ ≈ 0.0215 "ETH" demo balance).
  `last_burn.json` only holds the latest burn, so at most the newest one is settleable by design
  (pre-existing limitation, out of scope). Also the `cosign-burn` 409 guard only checks the FIRST
  active ticket (`settle_pending` ≠ `burn_done`), which is how 6 accumulated — ticket-state
  loophole, out of scope, noted.
- **BLOCKER (new): the Sepolia rollups are too old for the pw feature.** rollup#7/#8 were deployed
  2026-06-16; `claimAuthorizedWithdrawal`/`authorizePartialWithdrawal`/`registerSettlementManager`
  landed 2026-06-26 (7fdfd56, in HEAD). Bytecode probe of rollup#7: `registerChannel` PRESENT,
  `registerSettlementManager`/`partialWithdrawalAuthorized`/`claimAuthorizedWithdrawal` MISSING.
  Not a proxy (EIP-1967 slot zero) → **cannot be patched; pw settle requires redeploying both
  rollups from HEAD + re-running setup-backing (real deposit + balance proof) + resetting channel
  state**. Consequences: testers must re-join; the 6 stranded burns can never settle (old-rollup
  escrow); old deposits stay in the abandoned rollups (testnet).
- So the pw settle path on this testnet was broken twice over: EC2 missing contracts/forge AND
  the on-chain rollups predating the feature. The Jun-29 deploy shipped the new binary/frontend
  but kept the Jun-16 rollups/backing.

DECISION NEEDED from user before the destructive part: redeploy rollup#7/#8 + rebuild backing +
reset channel state (live demo reset), or leave pw broken until the next planned redeploy.

## Open items to verify during execution
- foundry cache portability (absolute-path invalidation) → fallback is on-box via_ir build w/ swap.
- deploy-settlement gas total on Sepolia (registerChannel + manager deploy).
- Close (full-withdrawal) flow on Sepolia has the same anvil-isms behind `CLOSE_ADVANCE_TIME` +
  a 600 s real grace window — out of scope here, but document that it means real waiting.
