# Exit-path facade sweep

**Scope frame:** *"someone deposits money and can withdraw it again without losing it."*
Every judgement below is against that one property. This is **not** a soundness audit — the question
is never "can an adversary forge a proof", it is always "would a real user, on a real deployment,
with an honest history, actually get their funds out?"

**Repo:** `/Users/plasma/repos/intmax3-zkp` · **branch** `feat/falcon-poseidon-sig` · **HEAD** `8407080`
**Date:** 2026-08-12 · **Mode:** read-only. No code changed, nothing committed, no proving run.

**Relationship to prior work.** `doc/audit/why-gate8-was-missed.md` §7 already swept this exact defect
class and produced the L1–L4 / PLAUSIBLE / LATENT lists; commit `eb93e5d` fixed L1 and L2. This is a
**follow-on**. Every finding is marked NEW or TRACKED; TRACKED items get a citation and a HEAD status
rather than a re-report.

---

## Executive summary

**Fourteen findings. Two are irreversible loss, four brick the exit outright, and the live testnet is
currently in one of them.**

The headline result is **F1**: the two rollups holding real Sepolia deposits today were deployed by a
script that never initializes the withdrawal verification key. This is not inferred from reading a
script — it is visible in the checked-in on-chain broadcast records. Those contracts accept deposits
and cannot pay out.

**F2** is the one finding where an honest user does not merely fail to withdraw but *loses money*:
the challenge period is one second on every deploy script, while the protocol constant that documents
it as one day is declared and never read. The challenge/cancel remedy — the entire defence against
someone finalizing a stale state — is non-functional on every deployment this repo can produce.

Underneath those, the user-facing surface has three independent hard breaks: every exit command
resolves `contracts/` from the working directory and every product driver runs them from a directory
that has none (**F4**); the only settlement-stack deployer reachable from the CLI/API is a mock
hard-gated to anvil (**F6**); and the claim command derives the claimant's key from a fixed operator
seed, so the browser delegate whose funds they are can never claim (**F8**).

None of these is a soundness bug. All of them have green test suites — and **there is no CI at all**
(**F10**), so "green" has only ever meant "green on someone's laptop, from the repo root, with
fixtures present".

---

# Findings, ranked by fund-recoverability impact

## F1 — The live Sepolia rollups cannot pay out: `initializeWithdrawalVk` was never called — **NEW**

**Impact:** every deposit into the live testnet is currently unwithdrawable. Recoverable only by the
deployer EOA making a manual call that no script, CLI command, relay route or runbook step performs.

**Failure story.** A user deposits ETH (or the registered ERC-20) via the wallet. `deposit()` escrows
the value and grows `totalEscrowed`. Later, after any amount of honest activity, someone tries to pay
out a withdrawal leaf. `withdrawNative`/`withdrawERC20` call the shared core `_verifyWithdrawalSet`,
whose **first statement** is `if (!withdrawalVkInitialized) revert WithdrawalVkNotSet();`. The flag is
false. It has always been false on these contracts.

**Evidence.**

- `contracts/src/IntmaxRollup.sol:1619` — the gate, inside `_verifyWithdrawalSet`, shared by
  `withdrawNative` (`:1485`) and `withdrawERC20` (`:1548`). The deposit side (`:969`) has no such
  gate. Money in, no money out.
- `contracts/src/IntmaxRollup.sol:703-726` — `initializeWithdrawalVk` is `deployer`-only (`:711`),
  set-once (`:712`).
- `contracts/script/Deploy.s.sol` — the entire broadcast body is `new IntmaxRollup(...)` (`:44`),
  `setKzgVerifier` (`:57`), `setBlockProducer` (`:60`). **No `initializeWithdrawalVk`.**
  `contracts/script/DeployTestnetBlockProducer.s.sol` — same omission (`:69`, `:73` only).
- **The live deployment used exactly this script.** `doc/docs/deploy-runbook.md:126` is the Sepolia
  procedure: `forge script script/Deploy.s.sol --rpc-url "$SEPOLIA_RPC_URL" … # run TWICE (ch7, ch8)`.
- **Confirmed against the on-chain record, not just the script.**
  `contracts/broadcast/Deploy.s.sol/11155111/run-1785574200576.json` and `run-1785574381449.json`
  show, per rollup, exactly three state-changing txs: constructor, `setKzgVerifier(address)`,
  `setBlockProducer(address,bool)`. The deployed addresses `0x0ee4c12f92ff49408719748c3a124e0b9db4bf8a`
  and `0x210f7daddd5fc817746e47daa0c10324483863f6` are precisely the `rollup` fields of
  `deploy-staging/ch7/channel_backing.json` and `deploy-staging/ch8/channel_backing.json` — the
  rollups the live wallet points at.
- Only two scripts ever ran on chain 11155111: `Deploy.s.sol` and `RegisterTokens.s.sol`. Scanning
  every Sepolia broadcast record for `initializeWithdrawalVk`, `registerChannel` or
  `registerSettlementManager` returns nothing. There is no settlement stack on Sepolia at all.
- `RegisterTokens.s.sol/11155111/run-latest.json` registered ERC-20 index 1 on the ch8 rollup, so the
  ERC-20 deposit door is open there too, and `withdrawERC20` hits the same gate.

**Why it stayed invisible.** The runbook's table is *accurate* —
`doc/tasks/regen-and-redeploy-runbook.md:149` says `| Deploy.s.sol | rollup-only smoke | YES |`. But
"rollup-only smoke" and "real-network: YES" sit in one row without anyone reconciling them against
the exit requirement, and the Sepolia procedure two documents over uses that script for production.
The CLI encodes the failure as a hint rather than a fix: `src/bin/channel_member.rs:2719` —
`"forge withdrawNativeStep failed (ensure the withdrawal VK is initialized on this rollup)"`.

**Recoverability.** Not permanent — `initializeWithdrawalVk` is still callable by the deployer EOA on
both contracts. It becomes permanent if that key is lost or rotated.

**Cheapest confirmation:** `cast call <rollup> "withdrawalVkInitialized()(bool)" --rpc-url $SEPOLIA_RPC_URL`.

---

## F2 — The challenge period is 1 second on every deployment; the 1-day constant is declared and never read — **NEW · the only systematic fund-LOSS finding**

**Impact:** irreversible loss of the difference between an honest member's true balance and whatever
stale state someone else finalizes. This is not "can't withdraw" — it is "withdraws the wrong,
smaller amount, permanently".

**Failure story.** Alice and Bob share a channel; Bob's latest signed state credits Alice 10 ETH,
having earlier credited her 1 ETH. Bob calls `requestClose()`, waits the 600-second grace, then
submits the **old** intent (1 ETH). `pendingClose.challengeDeadline = block.timestamp + challengePeriod`
= now + **1 second**. One block later `finalizeClose()` is callable by anyone, and Bob calls it. For
Alice to have replaced it she would have needed to submit a newer close intent inside that one-second
window — which requires a *heavy MLE close proof* she would have had to generate in advance,
plus a transaction landing in the same block. `cancelClose` is equally unusable: it also only works
while `pendingClose.active`, and `finalizeClose` deletes that state. Alice's claims are then capped
at the finalized `finalizedChannelFundAmount`, and the 9 ETH is gone.

**Evidence.**

- `contracts/src/ChannelSettlementManager.sol:527` —
  `uint64 public constant CHALLENGE_PERIOD_SECS = 86_400;` with the doc comment *"Reference challenge
  period (abstract2 §3.5: 1 day). The constructor argument is kept for test configurability but MUST
  be nonzero."* **This constant is read nowhere.** Verified: `grep -rn CHALLENGE_PERIOD_SECS
  contracts/{src,test,script}` returns only its own declaration line.
- The constructor accepts any nonzero value (`:717` `if (challengePeriod_ == 0) revert
  InvalidChallengePeriod();`) and stores it immutably (`:534`, `:722`). **There is no setter and no
  lower bound.**
- **Every deploy script in the repo passes 1 second:** `DeployCloseCli.s.sol:24` (`= 1; // seconds;
  settle after a tiny evm_increaseTime`) used at `:226`; `DeployClose.s.sol:26` used at `:92`;
  `DeployWalletSettlement.s.sol:27` used at `:110`; `DeployPartialWithdrawalE2E.s.sol:31` used at
  `:121`. `DeployCloseCli.s.sol` is the documented CLI/prod path
  (`doc/tasks/regen-and-redeploy-runbook.md:147`); `DeployClose.s.sol` is headed "Sepolia".
- **Every test passes 1 day:** `ChannelSettlementManager.t.sol:129`, `CloseSettlementBase.sol:107`,
  `CloseE2EBase.sol:35`. The value that actually gets deployed is exercised by no test.
- Consumption sites: `:934` (`challengeDeadline` for close), `:1182`
  (`pendingPartialWithdrawalDeadline`) — so the partial-withdrawal challenge window is 1 second too.
  Gates at `:880` (challenge replacement must beat the deadline) and `:1022` (`finalizeClose`
  requires the deadline passed).
- Partial mitigation, and only for the *first* intent of a frozen era: `GRACE_BEFORE_PROCESS_SECS =
  600` (`:523`) is a genuine hard constant, correctly enforced at `:896`. It gives honest members ten
  minutes to notice the freeze — but the window in which they must land a *proven* replacement is
  still one second.

**Assessment.** This is the cleanest instance in the repo of the class this audit is about: the
protocol parameter is declared, documented with a spec reference, and never used; the deployed
reality is four orders of magnitude smaller; and the tests only ever exercise the value that is never
deployed. The comment "kept for test configurability" is exactly inverted — the constant is what is
kept for tests, and the argument is what ships.

**Speculative, labelled as such:** I did not find an attacker who profits *without* being a channel
member. `requestClose` requires `isMemberRecipient` (`:852`) and the close intent must carry a
genuinely N-of-N-signed state, so the actor must be a member holding a stale signed state. That is
the standard payment-channel adversary, and it is precisely who the challenge window exists to
defeat.

---

## F3 — Deposits have no force-inclusion, no timeout and no refund; the censorship remedy is permanently disabled — **NEW as a stated finding**

**Impact:** a censored or absent block producer strands deposits with no on-chain remedy of any kind.

**Failure story.** A user deposits. `IntmaxRollup.sol:981-1007` escrows the value immediately and
appends a `DepositRecord`. Getting that deposit into intmax state requires a block producer to call
`postBlockAndSubmit`, which is permissioned (`:839` `NotAuthorizedBlockProducer`). If the producer
never includes it, the user has no action available: there is no force-inclusion queue, no
inclusion deadline, and no refund. Grep for `refund` / `forceInclude` / `cancelDeposit` across
`contracts/src/` finds only the *stake* refund (`_refundStake`, `:2001`).

**Compounding:** the two fault/censorship escapes are permanently reverted —
`ChannelSettlementManager.sol:963-965` `submitSpecialClose` → `SpecialCloseDisabled()`, and
`:1013-1018` `submitLateOutgoingDebitCorrection` → `LateOutgoingDebitDisabled()`. Both were
tautological `_matches` stubs and disabling them was correct; the in-code note says a sound version
*"does not exist yet"* (`:956-958`). But it means the BP-censorship remedy is a documented absence.

**Documentation facade found alongside:** `CLAUDE.md`'s "Acceptable in tests" list cites
`FixedReturnForcedTxLogic` as an example helper for a ForcedTransaction feature. That component does
not exist anywhere in this repo — `grep -rn "ForcedTx\|forced_tx\|ForcedTransaction" contracts/ src/
api/` returns nothing, and there is no design doc under `doc/`. The project's own instructions
reference a censorship-resistance mechanism the code does not have.

---

## F4 — Five exit commands resolve `contracts/` from CWD; every product driver runs them from a directory that has none — **NEW**

**Impact:** on any deployment driven through the API or either relay — which is how the live wallet
works — `close`, `withdraw`, `claim`, `cancel-close` and `post-close-claim` all abort. In `close` and
`withdraw` the abort happens *after* the heavy proof, so the user pays minutes of proving and then
gets a file-not-found.

**Failure story.** A user clicks "withdraw". `POST /full-withdrawal/request` → `api/lib/cli.js:44-48`
spawns `channel_member close` with `cwd: chDir(ch)` = `<repo>/wallet-live-work/ch7`. The command
generates the close intent and its MLE proof (minutes), then reaches
`src/bin/channel_member.rs:1587` — `let data_dir = std::path::Path::new("contracts/test/data");` —
and `fs::copy` into `<repo>/wallet-live-work/ch7/contracts/test/data/…`, which does not exist. It
dies with `stage close_intent.json: No such file or directory`. The proof is discarded.

**Evidence.**

- Relative resolution, five commands: `src/bin/channel_member.rs:1587`/`:1601` (`close`),
  `:1809`/`:1820` (`claim`), `:1990`/`:2004` (`cancel-close`), `:2153`/`:2167` (`post-close-claim`),
  `:2458`/`:2676`/`:2701`/`:2730` (`withdraw`) — each either `Path::new("contracts/test/data")` or
  `Command::new("forge").current_dir("contracts")`.
- Driver CWDs, all three: `api/lib/cli.js:44-48` (`cwd: chDir(ch)`, where `chDir` is
  `path.join(WORK, 'ch'+ch)` at `:28-30`), `hosting/wallet/wallet-relay.js:50`,
  `hosting/wallet/wallet-relay-ec2.js:46` — the EC2 relay being the one pointed at a real RPC.
- Verified on disk: `wallet-live-work/ch7` exists; `wallet-live-work/ch7/contracts` does not. Same
  for the runbook's manual staging dirs `deploy-staging/ch7`, `deploy-staging/ch8`.
- **The correct pattern already exists in the same file and was simply not applied to the exit
  commands.** `cmd_deploy_settlement` (`:4801-4811`) and `cmd_pw_submit` (`:5552-5562`) resolve via
  `CONTRACTS_DIR` with an ancestor search and a clear error if it fails.
- Ordering: in `cmd_close` the heavy proof runs first; the `fs::copy` is at `:1588`.

**Why tests are green.** The Rust E2Es invoke the CLI with `cwd = repo_root()`
(`tests/close_lifecycle_cli_e2e.rs:225`, `:244`). The exit path has never been exercised from the
working directory the product uses.

---

## F5 — The Sepolia deploy script bakes a stale validity VK, one circuit generation old — **TRACKED as deferred, quantified here**

**Impact:** a rollup deployed by `DeployClose.s.sol` can never finalize a block, so
`finalizedStateRoots` never advances and `withdrawNative` never has a root to anchor against.
Deposits in, nothing out — the same end state as F1, by a different mechanism.

**Failure story.** The deployer runs `DeployClose.s.sol`. It reads
`test/data/sepolia_lifecycle_validity_mle.json` (`:33`) and hands the whole validity VK —
`degreeBits`, `preprocessedRoot`, `gatesDigest`, `kIs`, `subgroupGenPowers`, `whirParams` — to the
constructor (`:56-58`). A freshly-proved validity proof from the current tree carries a different
`preprocessedRoot` and dies at `MleVerifier.sol:187`
`require(proof.preprocessedRoot == vp.preprocessedCommitmentRoot, "VK binding")`.

**Evidence — verified directly from the checked-in fixtures:**

| fixture | `preprocessedCommitmentRoot` |
|---|---|
| `sepolia_lifecycle_validity_mle.json` | `0x4a55dc571f8fff00eac7e94d…` |
| `lifecycle_validity_mle.json` | `0x9540daa7984467edbf366a70…` |
| `close_lifecycle_validity_mle.json` | `0x9540daa7984467edbf366a70…` |
| `c2c_lifecycle_validity_mle.json` | `0x9540daa7984467edbf366a70…` |
| `mle_fixture.json` (regenerated + real-verifier-checked by `MleE2E`) | `0x9540daa7984467edbf366a70…` |

`circuitDigest` diverges identically. The withdrawal wrapper is unaffected —
`sepolia_withdrawal_mle.json`, `withdrawal_mle.json` and `close_withdrawal_mle.json` all agree on
`0xc05f78b2c36bbb66cd82f54f…` — which is exactly what you would expect if Falcon changed the validity
circuit only. So `0x4a55…` is the pre-Falcon validity wrapper.

**Why it is invisible:** `forge test` never reads `sepolia_*` (only `script/` does), and
`tests/close_lifecycle_cli_e2e.rs:86-99` deliberately **backs up and restores** the stale file after
the CLI clobbers it — so even a live E2E run leaves the staleness in the tree.
`tests/mle_gate_support.rs` checks gate *ids* only and never compares `preprocessedCommitmentRoot`
across fixtures that must share a circuit.

**Status:** known and deferred — `doc/tasks/falcon-sig-phase5-notes.md:370` ("STOP 1 … DEFERRED —
deploy-time"). New here: the mismatch is offline-detectable and now quantified, and the E2E restore
is what makes it permanently invisible.

**Cheapest fix:** add to `tests/mle_gate_support.rs` (already a pure file-read test) an assertion
that all fixtures sharing a wrapper circuit agree on `preprocessedCommitmentRoot` + `circuitDigest` +
`degreeBits`. Zero proving cost, turns this class from invisible into a hard failure.

---

## F6 — The only settlement-stack deployer reachable from the CLI/API is a mock, hard-gated to anvil — **partly TRACKED, consequence NEW**

**Impact:** on a real chain there is no way to bring a channel's settlement stack into existence
through the product surface. No manager ⇒ no close ⇒ no claim ⇒ no exit.

**Failure story.** `POST /full-withdrawal/deploy` → `cmd_deploy_settlement` →
`forge script script/DeployWalletSettlement.s.sol` → `require(block.chainid == 31337, "local-devnet
only: this script deploys mock verifiers")`. The route returns 500. There is no alternative route.

**Evidence.**

- `contracts/script/DeployWalletSettlement.s.sol:11-20` defines `WalletMockMleVerifier.verify(...)
  returns (true)`; `:27` sets `CHALLENGE_PERIOD = 1`; `:40` is the chain-id guard.
- `src/bin/channel_member.rs:4821-4835` runs that script unconditionally, with no chain branch.
- Callers: `api/routes/full-withdrawal.js:58`, `api/routes/settlement.js:16`,
  `api/routes/partial-withdrawal.js:63` and `:105`, `hosting/wallet/wallet-relay-ec2.js:934`/`:963`,
  `hosting/wallet/wallet-live.html:2460`.
- The real deployer `DeployCloseCli.s.sol` is referenced only from
  `tests/close_lifecycle_cli_e2e.rs:337` and `tests/two_token_cli_e2e.rs:363` — never from the CLI,
  the API, or a relay.
- Secondary, even on anvil: `DeployWalletSettlement.s.sol` initializes only `closeVk` (`:61`) and
  `cancelCloseVk` (`:75`), so `submitWithdrawalClaim` reverts `WithdrawalClaimVkNotSet()`
  (`ChannelSettlementVerifier.sol:1004`) even in the demo stack.

**TRACKED portion:** the mock verifier and the missing chain guard are
`doc/tasks/pw-auth-threat-model.md` §8.2 (`:419-421`); the guard at `:40` *is* that fix, and the
in-file comment says so. **NEW portion:** nothing tracks the consequence — closing the hole left the
product with zero production settlement-deploy path. The door was load-bearing for the exit and no
replacement was wired.

---

## F7 — `DeployClose.s.sol` deploys a settlement verifier and initializes none of its four VKs — **NEW (same family as the two already fixed)**

**Impact:** a channel deployed by this script can be frozen but never closed and never un-frozen.

**Failure story.** A member calls `requestClose()` (succeeds), waits the grace, then
`submitCloseIntent` → `_checkCloseProof` → `verifier.verifyCloseIntent` → `revert CloseVkNotSet()`.
`cancelClose` is equally unavailable (`CancelCloseVkNotSet()`), so the channel cannot be returned to
Active either. Funds sit in a channel with no legal on-chain move.

**Evidence.** `contracts/script/DeployClose.s.sol:68` constructs the verifier; `:91-95` wires it into
the manager; the script's only initializer call is `rollup.initializeWithdrawalVk` at `:102`. Grep
for `sv.` in that file returns the construction line and nothing else. Runtime reverts:
`ChannelSettlementVerifier.sol:238`, `:1004`, `:1050`, `:1111`. The script header describes itself as
the Sepolia close-lifecycle deployment (`:19`).

Exactly the shape of the two initializers fixed in `eb93e5d`, in a script that fix did not touch.
`doc/tasks/regen-and-redeploy-runbook.md:150` records this script as "withdrawal only", so it is
known-and-shipped — but the consequence (channel permanently unclosable) is stated nowhere.

---

## F8 — `claim` / `post-close-claim` derive the claimant's key from a fixed operator seed, so a browser delegate can never claim — **NEW**

**Impact:** the depositor whose funds these are cannot produce the claim proof. Fail-closed, so
nothing is stolen — but the money is unreachable through the implemented surface.

**Failure story.** A user generates keys in the browser, joins as a delegate, deposits; their slot
leaf commits their browser-generated Regev public key. At exit they call `POST /api/claim
{slot, recipient}` → CLI `claim`. The CLI ignores any user key material and derives its own:
`keys_for(0xC1_0000 + member_slot)` — `0xC1_0000` being `CLI_COSIGNER_SEED_BASE`, the *operator's*
cosigner derivation. The claim needs `user_amount_ct` to decrypt under the *leaf's* Regev key and the
nullifier to key on that leaf's pk digest, so witness construction fails.

**Evidence.**

- `src/bin/channel_member.rs:1757` — `let keys = keys_for(0xC1_0000 + member_slot as u64);` in
  `cmd_claim`; `:2100` — identical in `cmd_post_close_claim`. `:609` —
  `pub(crate) const CLI_COSIGNER_SEED_BASE: u64 = 0xC1_0000;`
- Delegates supply their own key: `cmd_init` takes `contrib.regev_pk` from the browser contribution
  (`:2913`).
- The leaf binds it: `src/common/balance_state.rs:424-461` hashes
  `(regev_pk_digest, token_ct_digests, pending_adds, recipient)`; the claim PIs require the match
  (`src/circuits/channel/withdrawal_claim_pis.rs:110-119`, `:167-177`).
- Reachable from the UI exactly this way: `hosting/wallet/wallet-live.html:180` (`fwClaimSlot`,
  default 0) → `:2529` → `api/routes/close.js:175` → CLI `claim`.
- Falling back to slot 0 does not help: slot 0's leaf recipient is the synthetic
  `test_recipient_for(channel_id, 0)` (`src/bin/channel_member.rs:702`, documented at `:657-663` as
  *"nobody holds its key"*), and `withdrawal_claim_pis.rs:181-186` requires
  `l1_withdrawal_recipient == recipients[member_index]`, so a user-supplied recipient is rejected.

**Structural root:** `src/wasm_wallet.rs` exports 12 functions — `wallet_keygen`,
`wallet_genesis_contribution`, `wallet_sign_state`, `wallet_import_channel`, `wallet_balance`,
`wallet_send`, `wallet_send_inter_channel`, `wallet_burn_send`, `wallet_refresh`, `wallet_cosign`,
`wallet_finalize`, `wallet_keygen_seeded` — **none of them a claim.** The Regev secret that must
decrypt the slot ciphertext never leaves the browser, and nothing in the browser can consume it. Any
claim path must therefore run server-side, which is why the CLI invents a key.

**Related tracked:** `eb93e5d`'s open list already carries *"POST /api/v1/keys/generate mints a user's
key server-side"* and *"withdrawal salts use `seed_from_u64(1)` outside `cfg(test)`"* — the same
theme. The delegate-claim consequence is not among them.

---

## F9 — No unilateral exit exists against an uncooperative operator — **partly TRACKED, consolidated**

If the operator stops cooperating, or simply loses `wallet-live-work/chN`, there is no implemented
route to the money.

- Both censorship escapes are permanently reverted (see F3).
- **`close` requires operator-held artifacts, not just the signed head.** `load_backing()` at
  `src/bin/channel_member.rs:1453` reads `balance_vd.bin`, `channel_attestation.bin`,
  `channel_backing.json`, which exist only in the operator's per-channel work directory. A user
  holding a fully N-of-N-signed snapshot still cannot close.
- No browser entry point for close, claim or withdraw (see F8).
- The only documented closure workflow is *"W10. Full Withdrawal (Cooperative Channel Closure)"*
  (`api/API-DESIGN.md:1207`). No uncooperative workflow is specified anywhere.
- `api/routes/close.js:21-26` states the residual itself: one shared bearer token, no per-member
  authorization, and the coordinator unilaterally chooses `closeNonce` / `burnTxHash` /
  `snapshotMediumBlockNumber`.

**TRACKED sub-item (L3 in the gate-8 doc, `:428-435`), verified still open at HEAD, and sharpened.**
`ChannelSettlementManager.sol:852` gates `requestClose()` on `isMemberRecipient[msg.sender]`, written
only in the constructor (`:751`, `:806`) with no setter. The original wording is slightly stronger
than the mechanism: a delegate needs *one* registered member to call `requestClose()`, after which
everything is permissionless or proof-enforced and delegate-admitting (`:1266-1273`, `:1333-1337`).
But **in practice that set has exactly one member**: `src/bin/channel_member.rs:4782-4788` registers
every recipient as the synthetic `0xAAAA_0000 + channel_id*16 + slot`, an address nobody controls,
and `DeployCloseCli.s.sol:207` overrides **slot 0 only** to `msg.sender` — the comment at `:196-199`
saying *"Without it the EOA could not open the close at all."* So on a real deployment only the
deployer EOA can start an exit. The colluding-cosigner residual is accepted and documented in place
at `ChannelSettlementManager.sol:1575-1576` (DLG-2).

---

## F10 — There is no CI, and the suites that would catch all of the above are vacuous under liveness failure — **NEW**

This is the meta-finding: it is why every item above shipped with a green suite.

**No CI at all.** No `.github/`, no `Makefile`, no `justfile`, no workflow file of any kind (only
`hosting/pnpm-lock.yaml` matches a `*.yaml` search). Nothing runs `forge test` or `cargo test`
automatically. Also note `contracts/test/ZZAdversarialExpProbe.t.sol` is **untracked** (`git status:
??`) — it runs in a local `forge test` but is not committed, and must not be counted as coverage.

**The invariant and fuzz suites cannot fail on a liveness break.**
`ChannelSettlementInvariant.t.sol` try/catch-swallows all four handler actions (`:66`, `:90`, `:111`,
`:117`), so `invariant_I1_solvency` (`:152`), `I2_conservation` (`:157`), `I3_accrualCap` (`:168`),
`I4_ethBacking` (`:175`) and `ghost_consistency` (`:192`) are all satisfied by `0 == 0`. **There is
no liveness floor anywhere in the file** — no `assertGt(totalPaid, 0)`. If `submitWithdrawalClaim`
reverted unconditionally on every call, the entire invariant suite stays green. Same shape at
`ChannelSettlementAdversarial.t.sol:214-231` via `_tryAccrue` (`:270-279`).

**Nearly every real-proof test self-skips when a fixture is absent.** `CloseLifecycleE2E.t.sol:52-67`
+ `:150` — the only real-verifier settlement E2E — `vm.skip(true)`s if any of three fixtures is
missing. Same pattern in `WithdrawNativeE2E.t.sol`, `PartialWithdrawalPayout.t.sol`,
`ReclaimStake.t.sol`, `C2CFullE2E.t.sol`, `C2CBlockHash.t.sol`. On the Rust side
`tests/close_lifecycle_cli_e2e.rs:270` is `#[ignore]` **and** silently `return`s green if anvil/forge/
cast are missing (`:272-276`) or any of five fixtures is absent (`:277-290`) — while its own header
(`:16-18`) calls it *"THE live verification point for the close lifecycle"*. It is the only coverage
of `submitWithdrawalClaim` → `claimWithdrawalCredit` against real proofs.

**Mock-verified tests prove the contract agrees with itself.** Every settlement test that uses
`MockMleVerifier` builds its proof by calling the verifier's own view function and stuffing the
result into `publicInputs`: `CloseSettlementBase.sol:330`, `:420`, `:491`;
`ChannelSettlementManager.t.sol:264`, `:280`, `:301`, `:327`, `:453`;
`ChannelSettlementInvariant.t.sol:85`, `:99`; `MultiTokenSettlement.t.sol:259`;
`PartialWithdrawal.t.sol:339`; `SubmitPartialWithdrawal.s.sol:82`.

**The gap that matters most.** The only place a *real prover-emitted PI vector* is checked against
the Solidity limb layout is the **close** statement, at `CloseLifecycleE2E.t.sol:216` →
`ChannelSettlementVerifier.sol:276 _bindCloseLimbsStrict`. For **withdrawal-claim, post-close-claim
and cancel-close there is no such check anywhere.** `ClaimMleVerify.t.sol` (added in `eb93e5d`) proves
"the real `MleVerifier` accepts the real fixture" (`:79`) and deliberately never touches
`ChannelSettlementVerifier` (`:28-32`); the manager suites prove "the strict bind works on limbs I
generated". **Nobody joins the two halves.** A layout disagreement between the circuit's PI vector
and `expectedWithdrawalClaimLimbs` / `expectedPostCloseClaimLimbs` / `expectedCancelCloseLimbs` would
be invisible to the entire Foundry suite while the member's withdrawal reverts on a real deployment —
one abstraction level up from gate-8, same shape.

**Other coverage holes on exit-path functions:** `withdrawERC20` has no successful real-proof payout
(every success is under `MockMleVerifier` in `MultiTokenEscrow.t.sol`); `withdrawToken` has none at
all; the burn-leaf branch (`auxData != 0`) of both withdrawal entry points is never accepted in any
test (self-documented at `PartialWithdrawalPayout.t.sol:191-197`); `BlobKZGVerifier`'s real pairing
branch (`:233-242`, precompile `0x11`) has zero coverage because the test helper always supplies the
G2 generator (`IntmaxRollup.t.sol:190`) which takes the G1ADD fast path (`:220`).

**`allowMleDisabled = true` in every functioning test deployment**: `C2CBlockHash.t.sol:38`,
`C2CFullE2E.t.sol:53`, `WithdrawNativeE2E.t.sol:95`, `WithdrawNativeE2EBase.sol:67`,
`MleFinalizeE2E.t.sol:82`, `MultiTokenEscrow.t.sol:90`, `ReclaimStake.t.sol:46`, and eight sites in
`IntmaxRollup.t.sol`. The production value `false` appears only inside `vm.expectRevert`
(`:1081`). `IntmaxRollup.t.sol` `setUp` uses `_emptyMleVk()` (`:330`), so
`test_verify_validProof_returnsTrue` (`:1010`), `test_finalize_success` (`:1105`) and the
"MLE/WHIR gas" benchmark (`:1801`) all run with verification **off** — admitted at `:1057-1059`.

**EIP-170 headroom is masked**: `tests/partial_withdrawal_e2e.rs:238`/`:325` launch anvil and forge
with `--code-size-limit 50000`. `IntmaxRollup` runtime is ~23.5 KB against the 24,576 B limit — about
1.1 KB of margin. A change pushing it over deploys fine in that test and fails on Sepolia.

---

## F11 — `finalize()` fails silently, and the six error types that would explain why are declared but never used — **NEW**

**Impact:** not a fund loss by itself. It is the *mechanism* that keeps this whole class invisible,
including the original gate-8 defect — worth fixing precisely because it is what makes F1-class
problems cost weeks instead of one transaction.

**Failure story.** A block producer posts a batch and calls `finalize(...)`. Something is wrong — a
state-root mismatch, a PI-binding mismatch, or an on-chain verifier that cannot handle a gate.
`finalize` wraps the check in `try/catch`, sets `valid = false`, and **returns `false` instead of
reverting**. The transaction succeeds. Gas is consumed. No `Finalized` event. No revert reason to
decode. No way to learn which of eight checks failed. `finalizedStateRoots` never advances, so
`_verifyWithdrawalSet`'s anchor check (`:1638`) can never be satisfied.

**Evidence.**

- `contracts/src/IntmaxRollup.sol:1286-1291` — the try/catch and `if (!valid) return false;`
- `fullVerify` has eight silent exits: `:1742`, `:1743`, `:1744`, `:1745`, `:1746`, `:1757`, `:1760`,
  plus the catch. All `return false`; none reverts; none is distinguishable.
- **The diagnostics exist in the ABI and nothing ever raises them.** Declared and never used anywhere
  in `contracts/`: `CommitmentMismatch` (`:66`), `SubmissionNotFound` (`:67`),
  `ProofVerificationFailed` (`:69`), `InitialStateMismatch` (`:70`), `BlockChainMismatch` (`:71`),
  `MleVerificationFailed` (`:72`). Verified by grepping `src/`, `test/` and `script/` for each name —
  every one appears only at its own declaration. An integrator reading the ABI would reasonably
  expect `finalize` to revert with `InitialStateMismatch`; it never does.
- Same swallow-and-generalize on the withdrawal path: `_verifyMleWithdrawal` (`:1712-1720`) catches
  any revert from the MLE verifier and returns `false`, surfacing as `WithdrawalProofInvalid()` —
  i.e. a verifier that cannot evaluate a gate tells the honest user *"your proof is invalid."* That
  is exactly how gate-8 presented.
- Partial mitigation: the forge scripts `require(ok, ...)` after calling `finalize`
  (`Finalize.s.sol:41`, `RunClose.s.sol:45`, `RunC2C.s.sol:75`).

Dead in the manager for the record: `ChannelNotClosable` (`ChannelSettlementManager.sol:192`) and
`CloseAlreadyFinalized` (`:194`). (`InvalidSpecialCloseProof`, `InvalidLateOutgoingDebitProof`,
`InvalidSpecialCloseWindow`, `InvalidBpForSpecialClose` and the events `SpecialCloseSubmitted` /
`LateOutgoingDebitAccepted` are also unused, but belong to the deliberately disabled paths in F3.)

---

## F12 — Gate *parameters* are scraped from a `Debug` string with a silent `0` fallback, and the new export guard does not cover them — **NEW**

**Impact:** the gate-8 defect one level down, with the identical signature — well-formed fixture,
valid `gatesDigest`, passing Rust `mle_verify`, on-chain revert, no signal until a real submission.

**Evidence.**

- `contracts/lib/polygon-plonky2/mle/src/fixture.rs:449-513` `classify_gate` derives `numOrConsts` /
  `param2` / `param3` by string-splitting `gate.id()`. `num_after(...)` at `:450-462` ends in
  `.and_then(|s| s.parse::<u16>().ok()).unwrap_or(0)` — any format change, or a value > 65535, yields
  **0**. `:486` — `let base = num_after(id, "+ Base:").max(2);` — a failed scrape claims base-2 for a
  `BaseSumGate<B≠2>`.
- The `eb93e5d` guard at `src/utils/mle_prover.rs:211-217` checks exactly five fields
  (`selectorIndex`, `groupStart`, `groupEnd`, `gateRowIndex`, `numConstraints`) against
  `common_data`. `numOrConsts` / `param2` / `param3` are **not** recomputed or compared.
- Those three drive on-chain evaluation: `Plonky2GateEvaluator.sol:159`, `:168`, `:185`, `:194`,
  `:201`, `:206`, `:208`, `:210`, `:216-218`, `:225-226`. A zeroed `numOrConsts` produces a gate that
  writes no constraints (silent `"Phi_gate terminal"` mismatch at `MleVerifier.sol:312`) or an
  outright revert (`Plonky2GateEvaluator.sol:609`).

**Cheapest fix:** extend `ExpectedGateRow` (`src/utils/mle_prover.rs:151-158`) with
`num_or_consts`/`param2`/`param3` recomputed from the concrete gate rather than the `Debug` string,
and compare exactly as the five existing fields are.

**Related, unvalidated on the Rust side:** `CosetInterpolationConstants.sol` carries only subgroups
2^1…2^5 and `Plonky2GateEvaluator.sol:1236-1245` requires `2 ≤ degree ≤ N`. Current fixtures sit at
`subgroup_bits:4, degree:6` — inside the envelope, but a plonky2 config change moves it outside with
no Rust-side signal. (This is the LATENT item at `why-gate8-was-missed.md:465-466`, still latent.)

---

## F13 — `whirParams.numCommitments` is exported wrong and survives only because three consumers hardcode the correction — **NEW**

`contracts/lib/polygon-plonky2/mle/src/fixture.rs:337` — `let num_commitments = 2; // preprocessed +
witness`. Stale since v2 added the aux and inverse-helper commitments: `MleVerifier.sol:519-539`
builds `whirEvals` as 4 points × 4 vectors, and `SpongefishWhirVerify.sol:152`, `:195`, `:395` drive
round-0 Merkle verification off `params.numCommitments`.

Every in-repo consumer patches it by hand right after parsing: `contracts/script/FixtureLib.sol:103`,
`contracts/test/MleE2E.t.sol:199`, `contracts/test/MleFinalizeE2E.t.sol:237` — all
`d.whirParams.numCommitments = 4;`. Nothing in Rust checks or fixes the field it wrote. **Verified:
`withdrawal_mle.json` really does carry `numCommitments: 2`.**

Any new submitter that trusts the exported value — a JS relayer, a new deploy script, a partner
integration — deploys a VK describing a 2-commitment proof and rejects every honest proof. The
exported field is simply wrong data with a stale explanatory comment.

---

## F14 — Smaller silent truncations and defaults on the Rust→chain path — **NEW, conditions stated**

- **`FixtureLib.countGates` truncates at 64 gate rows.** `contracts/script/FixtureLib.sol:194-202`
  probes `.gates[i].gateId` for `i < 64` and stops. `buildMleVk` then computes `gatesDigest` over the
  *same* truncated array (`:68-74`), so the digest check passes and only
  `Plonky2GateEvaluator.evalCombinedFlat` comes up short → `"Phi_gate terminal"`. The Rust guard
  (`src/utils/mle_prover.rs:170-175`) compares against `common_data.gates.len()` and would happily
  emit 80. Current circuits use 13; `gateRowIndex` is `u8` so Rust tolerates 255.
- **`parseSumcheckProof` assumes exactly `degreeBits` rounds.** `FixtureLib.sol:233-248`, called at
  `:138`, `:154`, `:208-209`. Fewer → loud parse revert; **more → silently dropped** and the
  verifier consumes a truncated proof. Not violated today (all four are `degree_bits`-round), but
  nothing asserts it.
- **`publicInputsHash` silently defaults to `[0,0,0,0]`.** `FixtureLib.sol:184-191` — a `try/catch`
  with an empty handler, plus `i < 4 && i < hs.length` zero-padding a short array. Fail-closed, but
  the user's diagnostic becomes `"Phi_gate terminal"` rather than "your fixture is missing a field".
- **Only `withdrawals[0]` is ever submitted.** `RunClose.s.sol:56`, `:80` and `RunC2C.s.sol:86`,
  `:108` read `.withdrawals[0]` from a payout fixture that Rust types as a `Vec`
  (`src/wallet_core.rs:5013-5024`). Consistent today (the wallet emits exactly one), but the moment a
  proof aggregates N withdrawals, N−1 are silently never paid despite being proved.
- **`registerChannel` finalization-DoS (sharpens the tracked PLAUSIBLE item at
  `why-gate8-was-missed.md:454-456`).** `IntmaxRollup.sol:1064-1078` has no `msg.sender` check of any
  kind and is one-shot per `channelId` (`:1078`). Beyond the known registration squat, the call folds
  into `_pendingChannelRegHashChain` (`:1128`) which `_postBlock` folds into the block hash
  (`:912-927`). A stranger's registration landing between witness generation and the `postBlock` tx
  desynchronises the on-chain chain from the proven one, so `finalize` fails — silently, per F11 —
  and `finalizedStateRoots` never advances, blocking **every** withdrawal for as long as the griefer
  keeps paying gas with fresh channel ids.
- **`DeployClose.s.sol:13-18` bakes the predicted nonce-derived CREATE address of the manager into
  the withdrawal proof.** Any extra broadcast tx before the manager deploy shifts the deployer nonce,
  the baked recipient stops matching, and `withdrawNative` credits an address nobody controls — with
  **no revert**. `DeployCloseCli.s.sol` has since added four broadcast calls (`:112`, `:140`, `:166`,
  `:180`) between the rollup and the manager deploy, so any fixture baked against the older ordering
  is now silently wrong. Alongside F2 this is the only finding where funds move to the *wrong place*
  rather than not moving.

---

# Also confirmed still open (TRACKED, not re-reported)

- **`registerSettlementManager` has no real-network caller** — gate-8 doc L4 (`:437-441`). Verified
  unchanged: listing every `rollup.` / `sv.` / `manager.` call in `DeployCloseCli.s.sol` gives
  `setKzgVerifier` (`:57`), `setBlockProducer` (`:60`), `initializeWithdrawalVk` (`:66`), the four
  settlement VKs (`:88`, `:112`, `:140`, `:166`), `registerChannel` (`:180`) — **no
  `registerSettlementManager`**. Its only callers remain the two `chainid == 31337` scripts. Runtime:
  `ChannelSettlementManager.sol:1213` → `IntmaxRollup.sol:787`.
  *Scope correction worth recording:* this breaks the **partial** withdrawal exit only. Full-close
  leaves carry `auxData == 0` (confirmed in `contracts/test/data/{sepolia,close,c2c}_withdrawal_payout.json`),
  so they skip the IMPW gate at `IntmaxRollup.sol:1512`. Given the next item, its practical ranking
  is low.
- **Partial withdrawal terminates before payout by design** —
  `src/bin/channel_member.rs:5748-5771` prints "STOPPING BEFORE PAYOUT" and `exit(1)` because
  `cmd_partial_withdraw` is not implemented (`:5765`, tracked at `doc/tasks/todo.md:90`); the
  contract says the same at `IntmaxRollup.sol:809-811`. Not a facade — a loud, correct fail-closed
  state. **One real gap:** `api/routes/partial-withdrawal.js:80` and `:110` call it and report
  `{ok:true}` on the authDigest, so the API's success response does not mean money moved.
  `POST /partial-withdrawal/cancel` is 501 (`:134-139`). Other 501s:
  `api/routes/blocks.js:8-14` (`/blocks/post`), `api/routes/inter-channel.js:46-53` and `:55-61`.
- **The ExponentiationGate evaluator patch still needs upstreaming** before the `gpu_merkle` /
  v2-MleVerifier bump drops it — on `eb93e5d`'s own open list; unchanged.

---

# Checked and CLEARED

Items with the *shape* of a facade that are genuinely fine. Recorded so the next sweep does not
re-spend the effort.

- **Gate id coverage** — the full id↔name mapping was diffed on both sides. Rust `classify_gate`
  (`fixture.rs:464-512`) and `Plonky2GateEvaluator.sol:48-61` agree on ids 0–13, and **all fourteen
  are genuinely dispatched** (`:154-229`, including `GATE_EXPONENTIATION` at `:198`). Vendored
  plonky2 has exactly 16 gate types; the two not covered are `lookup.rs` / `lookup_table.rs`, which
  map to the 255 sentinel and are now rejected at export (`src/utils/mle_prover.rs:187-196`). **No
  gate is declared-but-undispatched.** The submodule is pinned at `fbf3735b` ("implement
  ExponentiationGate (id 8)"), matching HEAD's pin commit. The gate-8 hole is closed.
- **`export_mle_json` really is the complete chokepoint** — all 11 fixture-producing call sites in
  `src/bin/generate_*.rs` and `src/wallet_core.rs` funnel through it, so the `mle_prover.rs:96` claim
  holds. The `serde_json::Value` matches in the generator bins
  (`generate_withdrawal_claim_fixture.rs:103-109` and siblings) end in `_ => panic!(…)` — fail-loud,
  not silent defaults.
- **`allowMleDisabled`** — the `degreeBits==0` bypass is honored only when the immutable opt-in flag
  is true (`IntmaxRollup.sol:1852`), and the constructor rejects a zero validity VK otherwise
  (`:639`). Every real deploy script passes `false`. The withdrawal path has no such seam at all —
  `initializeWithdrawalVk` enforces `degreeBits > 0` (`:713`) and `_verifyMleWithdrawal` documents
  the absence (`:1709-1711`). (F10 notes the *test* consequence; the contract itself is correct.)
- **`ChannelSettlementManager.receive()`** — restricted to the rollup (`:683-684` `OnlyRollup`), so
  `pullChannelFunds`'s `registry.withdraw()` callback lands.
- **Token registration** — `RegisterTokens.s.sol` is standalone and never called from a Deploy
  script, which looks like a gap but is not one for fund recovery: the *same* set-once mapping gates
  `deposit()` (`IntmaxRollup.sol:993`) and every withdrawal path (`:1553`, `:1583`, manager `:1434`,
  `:1474`). Value can never be escrowed under an index that is later un-withdrawable. Forgetting the
  script is a UX failure, not a trapped-funds failure. The script is idempotent, checks `.chainId`
  against `block.chainid` (`:69`), and reads back every write (`:137-138`).
- **KZG verifier** — `setKzgVerifier` is called by all five deploy scripts, and `kzgVerifier` is read
  only by `fraudProof`'s `_verifyFraud` (`:1798`). The liveness-critical branch — unconditional
  removal of a submission that missed `FINALIZE_DEADLINE_BLOCKS` (`:1348-1352`) — runs *before*
  `_verifyFraud` and needs no KZG verifier, so a stuck submission can always be cleared. (F10 notes
  the real pairing branch is untested; that is a coverage gap, not a liveness gap.)
- **Payout accounting in `claimWithdrawalCredit`** — the per-token ceiling
  `totalCreditedOut[t] + amount <= receivedChannelFunds[t]` (`:1463`) is measured from real pulls
  (`:1417`, `:1438`), CEI-ordered, `nonReentrant`. The shared `totalWithdrawn[t]` budget between
  `submitWithdrawalClaim` and `submitPostCloseClaim` creates a first-come race in principle; per the
  session note `project_close_settlement_test_coverage.md` the manager accounting invariant was
  reviewed and found sound. Not re-litigated.
- **`MAX_MEMBER_COUNT = 16` vs Rust `MAX_CHANNEL_MEMBERS = 1024`** — looks like cross-language
  constant drift; is not. The Solidity constants (`ChannelSettlementManager.sol:167`,
  `IntmaxRollup.sol:499`) mirror Rust `MAX_COSIGNERS = 16` (`src/constants.rs:131`), and the L1
  registration record is a fixed 16-slot preimage on both sides
  (`src/common/channel_registration.rs:100`, `:206` vs `IntmaxRollup.sol:1171`, `:1202`). **Doc bug
  only:** both Solidity comments name the constant `MAX_CHANNEL_MEMBERS`, which in Rust is 1024. The
  values are right; the cross-references point at the wrong constant.
- **Proof-enforced claim membership** — `submitWithdrawalClaim` / `submitPostCloseClaim` were
  deliberately converted from map-enforced to proof-enforced (`:1266-1273`, `:1333-1337`), correctly
  admitting delegates never L1-registered. This is the right pattern; F9 is the observation that
  `requestClose` and the partial-withdrawal recipient check were not converted with them.
- **`_copyWhirParams` / `_loadWhirParamsFrom`** (`IntmaxRollup.sol:665-694`, `:1888-1923`;
  `ChannelSettlementVerifier.sol:310`, `:363`) omit `additionalEvaluationPoints` — harmless, because
  `MleVerifier.sol:219-223` overwrites `evaluationPoint`, `evaluationPoint2` and
  `additionalEvaluationPoints` from on-chain sumcheck output before use.
- **Deploy-time fixture availability** — every JSON the deploy scripts read is checked in under
  `contracts/test/data/`. No prod deploy depends on a dev-only generation step. (F5 is about a
  checked-in file being *stale*, not missing.)
- **`initializePostCloseClaimVk` / `initializeCancelCloseVk`** — the user's `eb93e5d` fix is present
  and ungated at `DeployCloseCli.s.sol:140` and `:166`. Complete *for that script*; F7 is the same
  defect surviving in `DeployClose.s.sol`.
- **`fixture.rs` `evaluation_point`** (with `c1 = c2 = 0`, `:591-599`) is dead data — no consumer
  parses it.

---

# Not covered

- **No proving was run and no `#[ignore]`d E2E was executed**, per the constraints. Every finding is
  static reading plus checked-in artifacts. F1 in particular is proven from the on-chain transaction
  list, not a live `eth_call` — one `cast call` settles it and is the recommended first step.
- **`@mle/MleVerifier.sol` internals** were surveyed for revert surfaces but not audited. Note that
  `vp.kIs.length >= nr` (`MleVerifier.sol:276`) makes a short or empty `kIs` array in a deployed VK a
  total verification brick, and `kIs` comes straight from the fixture JSON via
  `FixtureLib.sol:109-110` — while `initializeCloseVk` and siblings validate only deployer, set-once
  and `degreeBits != 0` (`ChannelSettlementVerifier.sol:185-199`, and `:673`, `:702`, `:731`). That
  is what makes `CloseTestLib.dummyVkArgs()` — with **empty** `kIs`/`subgroupGenPowers`/`protocolId`/
  `sessionId` (`CloseTestLib.sol:61-112`) — installable. A real deployment with a malformed VK would
  be caught by no test. Not investigated further.
- **VK migration.** All five VKs are set-once with no update path, so any circuit change permanently
  invalidates a deployed instance and there is no migration mechanism. This generalises the
  `SumcheckVerifier.sol:39` "Wrong number of rounds" LATENT item; the operational consequence for an
  already-funded rollup was not worked through.
- **`contracts/test/ZZAdversarialExpProbe.t.sol`** is untracked and appears to belong to a concurrent
  session. Not examined.
- **The Lean development** under `doc/audit/zkp/` was not read; a concurrent session is writing
  there.
