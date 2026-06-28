# INTMAX3 Node Programs — Design Specification

**Status:** Draft v1 (design only — no code yet)
**Scope:** Two long-running programs that compose the `api/` REST surface, the `channel_member`
CLI, the WASM wallet, and the L1 contracts into autonomous agents:

1. **Co-signer node** (`node/cosigner/`) — a trusted N-of-N channel member. Watches the chain,
   validates and co-signs peers' state transitions, drives deposits and the close lifecycle, and
   reacts to abnormal/adversarial on-chain events.
2. **Delegate account** (`node/delegate/`) — a send-only participant. Generates its own
   transactions + ZKPs, submits them for co-signing, verifies the co-signed results, refreshes
   when required, and exits (partial/full withdrawal, post-close claim) when it must act alone.

Both are structured as a single **supervisory event loop with explicit branches** for three
regimes: **normal flow**, **own-transaction flow**, and **abnormal flow**.

Spec references: `architecture-audit/design2.md` (design2), `architecture-audit/abstract2-1.md`
(abstract2-1), `api/API-DESIGN.md` (the REST surface this composes).

---

## 0. Goals / Non-goals

### Goals
- A deterministic, restartable control loop per program with a clearly enumerated branch set.
- Reuse the existing, audited machinery: do not re-implement proving, verification, or on-chain
  calls. The node programs **orchestrate** `api/`, `channel_member`, the WASM wallet, and `cast`.
- Fail-closed everywhere: when a check is ambiguous, halt the affected channel and alert; never
  co-sign or send on a check that did not pass.
- First-class abnormal-flow handling: invalid peer txs, stale/malicious closes, equivocation,
  withholding, and fund-safety exits are loop branches, not afterthoughts.

### Non-goals (v1)
- No new circuits or contracts (A15 bulk send and A45 PW-cancel remain out — see API-DESIGN).
- No multi-co-signer consensus among independent operators (current model: one operator holds the
  N member keys; abstract2-1 §3.1). The design leaves seams for future multi-operator split.
- No P2P gossip layer; peers reach the co-signer over the REST API (and the chain).

---

## 1. Background

### 1.1 Actors & trust model (abstract2-1 §3.0–3.1, design2)
- **Co-signing members** — slots `0..member_count`. Hold Goldilocks signing keys (`pk_g`, P4-2),
  BabyBear hash-sig keys (`pk_b`, A11), and Regev encryption keys. The N-of-N over the channel
  state digest (IMCH) is the channel's authority. In the current deployment one operator holds all
  N member keys (the co-signer node).
- **Delegates** — slots `member_count..member_count+delegate_count`. Send-only: they build
  `channelTxZKP` (E-1 STARK) and authorize with a BabyBear A11 hash-sig over the IMPA digest, but
  do **not** co-sign channel state. Honest members verify the hash-sig before signing (DLG-1).
- **L1** — `IntmaxRollup` (escrow + validity/withdrawal proofs) and `ChannelSettlementManager`
  (per-channel close/withdrawal game). Both are the ultimate soundness gate; the node programs can
  never mint a valid proof for a false statement.

### 1.2 What is already built (this design only wires it)
- **REST API** (`api/`): per-channel endpoints — `init`/`join`, `snapshot`, `status`, `backing`,
  `deposit/*`, `cosign`, `cosign-refresh`, `inter-channel/send`, `burn/cosign`,
  `partial-withdrawal/{burn,submit,finalize,settle}`, `settlement/deploy`,
  `close/{request,submit-intent,challenge,cancel,finalize,claim,pull-credit,post-close-claim}`,
  `full-withdrawal/*`, `tickets`.
- **CLI** (`channel_member`): `init`, `cosign`, `cosign-refresh`, `cosign-inter-transfer`,
  `cosign-l1-deposit-import`, `cosign-burn-send`, `deploy-settlement`, `close` (with
  `CLOSE_REQUEST_ONLY` / `CLOSE_SKIP_REQUEST` phase flags), `settle`, `withdraw`, `claim`
  (with `CLAIM_PULL_ONLY`), `cancel-close`, `post-close-claim`, `pw-submit`, `pw-finalize`.
- **WASM wallet** (delegate proving): `wallet_keygen[_seeded]`, `wallet_genesis_contribution`,
  `wallet_import_channel`, `wallet_balance`, `wallet_send`, `wallet_refresh`,
  `wallet_send_inter_channel`, `wallet_burn_send`, `wallet_cosign`, `wallet_finalize`.
- **Contract events** (the chain-watcher's inputs):
  - `IntmaxRollup`: `Deposited`, `BlockPosted`, `ChannelRegistered`, `Submitted`, `Finalized`,
    `FraudConfirmed`, `WithdrawalCredited`, `PartialWithdrawalAuthorized`,
    `SettlementManagerRegistered`, `NativeWithdrawn`.
  - `ChannelSettlementManager`: `CloseRequested`, `CloseSubmitted`, `SpecialCloseSubmitted`,
    `CloseCancelled`, `LateOutgoingDebitAccepted`, `CloseFinalized`, `WithdrawalClaimAccepted`,
    `PostCloseClaimAccepted`, `WithdrawalClaimed`, `PartialWithdrawalSubmitted`,
    `PartialWithdrawalFinalized`, `PartialWithdrawalCancelled`, `ChannelFundsPulled`.
  - Getters for reconciliation: `getPendingClose()`, `isNativeSendAllowed(nonce)`,
    `registeredMemberSetCommitment()`, `IntmaxRollup.latestFinalizedStateRoot()`.

### 1.3 Off-chain soundness gates the co-signer already enforces (CLI)
Before any signature the co-signer re-verifies, fail-closed: `verify_send_transition`,
`verify_refresh_transition`, `verify_inter_channel_send_transition`,
`verify_inter_channel_credit_transition`, `verify_l1_deposit_import_transition`,
`verify_all_signatures`, plus the replay ledgers `applied_tx_hashes` (B-side double-credit) and
`spent_tx_hashes` (A-side double-debit). The node loop wraps these with policy (rate limits,
quotas, alerting) but never weakens them.

---

## 2. Shared infrastructure (`node/common/`)

Both programs build on the same modules.

### 2.1 Runtime & language
- **Node.js** (matches `api/` and the existing relay). The heavy crypto stays in Rust/WASM:
  - Co-signer proving/verification → `channel_member` CLI via `execFile` (argv array; never a
    shell string — no injection).
  - Delegate proving → the WASM wallet built with `wasm-pack --target nodejs`, loaded in-process.
- **Chain access** → `viem` (or `ethers`) read client for logs/getters; writes go through the
  existing CLI/forge paths (which already hold the deposit key safely), never by re-implementing
  signing in JS.

### 2.2 Modules
- `chain-watcher.js` — subscribes to the contract events in §1.2 with a **confirmation depth**
  (`CONFIRMATIONS`, default 2) and a **persisted cursor** (`lastProcessedBlock`). Emits normalized
  `ChainEvent { kind, channelId, args, blockNumber, txHash, log }`. On reconnect it backfills from
  the cursor (`getLogs(fromBlock=cursor)`) so no event is missed across restarts. Reorg handling:
  events are only acted on after `CONFIRMATIONS`; if a reorg drops a confirmed event the watcher
  re-derives state from getters (`getPendingClose`, balances) rather than trusting cached logs.
- `api-client.js` — typed wrapper over the `api/` endpoints (co-signer side) / the delegate uses it
  to reach the co-signer. Adds retries with backoff, idempotency keys, and timeout handling.
- `cli.js` — `execFile('channel_member', argv, { cwd: chDir(ch), env })` with the same env
  conventions as the relay (`INTMAX_CHANNEL`, `CLOSE_*`, `CLAIM_*`, `PW_RECIPIENT`,
  `POST_CLOSE_SOURCE_TX`). Co-signer only.
- `wallet.js` — WASM session wrapper (`wallet_*`). Delegate only. Holds secrets in memory; never
  serializes private key material (matches `wasm_wallet.rs` session model).
- `store.js` — durable JSON state per channel (cursor, tickets, pending intents, seen-nonce sets,
  alert log). Crash-safe (write-tmp-then-rename). The co-signer's authoritative channel state stays
  in `cli_state.json` (owned by the CLI); `store.js` holds only loop/orchestration metadata.
- `policy.js` — configurable thresholds (rate limits, max in-flight, amount caps, grace/challenge
  timers) and the **decision functions** the branches consult.
- `log.js` / `alert.js` — structured logging + an alert sink (stderr + optional webhook) for
  abnormal-flow escalations. Security alerts are never silently swallowed.

### 2.3 Persistence & idempotency
- Every externally-visible action (cosign, on-chain submit) is keyed by a **deterministic action
  id** (e.g. `tx_hash`, `close_intent_digest`, `(channel, state_version)`), recorded before and
  after execution, so a crash-restart never double-acts. This complements the CLI replay ledgers.
- The loop is **resumable**: on boot it (a) loads cursors/tickets, (b) backfills chain events, (c)
  reconciles against contract getters, (d) resumes any in-flight ticket from its last step.

### 2.4 Configuration (`node/config.example.json`)
`{ rpcUrl, chainId, channels:[{id, rollup, manager, verifier, workDir}], confirmations,
role:"cosigner"|"delegate", apiBaseUrl, pollIntervalMs, policy:{...}, keys:{seedSource} }`.
Secrets (deposit key, delegate seed) come from env / gitignored files, never from this file —
consistent with the repo's key-handling rules.

---

## 3. Co-signer node (`node/cosigner/`)

### 3.1 Responsibilities
- Serve `cosign` / `cosign-refresh` / `inter-channel` / `burn` / deposit-import requests, each
  gated by the CLI's fail-closed verification **plus** loop policy.
- Watch the chain and keep each channel's lifecycle state reconciled (Active / ClosePending /
  Closed / PartialWithdrawalPending).
- Drive co-signer-owned on-chain actions: deposit import, settlement deploy, and the close-game
  steps it is responsible for.
- Detect and respond to abnormal/adversarial situations: invalid peer txs, stale or unauthorized
  closes, equivocation attempts, replay, and quota abuse.

### 3.2 Main loop (single-threaded supervisor, per tick)
```
boot: load config → load cursors/tickets → backfill chain events → reconcile getters → resume tickets
loop forever:
  ev = await next( chainEvents ∪ apiRequests ∪ timers )      // unified, ordered queue
  ch = ev.channelId
  with channelLock(ch):                                       // serialize per channel (matches relay)
    switch classify(ev):
      ── NORMAL ────────────────────────────────────────────
      case PEER_TX_REQUEST:        handleCosign(ev)           // 3.3
      case PEER_REFRESH_REQUEST:   handleCosignRefresh(ev)
      case PEER_INTER_REQUEST:     handleInterChannel(ev)
      case PEER_BURN_REQUEST:      handleCosignBurn(ev)
      case CHAIN_DEPOSITED:        handleDepositImport(ev)    // 3.4
      case CHAIN_BLOCK_FINALIZED:  refreshAnchors(ev)
      case SNAPSHOT_POLL:          publishSnapshot(ev)
      ── OWN ACTIONS ───────────────────────────────────────
      case TIMER_SETTLE_DUE:       driveCloseStep(ev)         // 3.5
      case TIMER_PW_FINALIZE_DUE:  drivePwFinalize(ev)
      ── ABNORMAL ──────────────────────────────────────────
      case INVALID_REQUEST:        rejectAndScore(ev)         // 3.6
      case CHAIN_CLOSE_REQUESTED:  onCloseObserved(ev)        // 3.7 (may → challenge/cancel)
      case CHAIN_CLOSE_SUBMITTED:  onCloseIntentObserved(ev)
      case CHAIN_PW_SUBMITTED:     onPartialWithdrawalObserved(ev)
      case ATTACK_SUSPECTED:       enterDefensiveMode(ev)     // 3.8
  persist(cursor, tickets, scores)
```
`classify` is a pure function of the event and the channel's reconciled state. Unknown/ambiguous
events route to `ATTACK_SUSPECTED` (fail-closed), never silently dropped.

### 3.3 NORMAL — checking peers' txs & co-signing
For each `cosign`-family request (intra send, refresh, inter-channel, burn):
1. **Pre-policy** (`policy.js`): per-sender rate limit, max in-flight per channel, amount sanity,
   and "is this channel Active?" (refuse if ClosePending/Closed). Reject → `INVALID_REQUEST`.
2. **Head-extension check**: the payload's `prev_digest` must equal the current committed head
   (the CLI also enforces this); a mismatch means a stale/racing client → ask it to re-import the
   snapshot (one retry), else reject.
3. **Delegate authorization (DLG-1)**: for delegate-sourced sends, the CLI verifies the BabyBear
   A11 hash-sig over the IMPA digest inside `cosign`; the loop additionally checks the sender slot
   is a registered delegate.
4. **Delegate to CLI** (the real gate): `channel_member cosign|cosign-refresh|cosign-inter-transfer
   |cosign-burn-send`. The CLI re-verifies the E-1/E-2 STARK, the transition, the replay ledgers,
   and produces the N-of-N signed next state. **The loop never signs anything itself.**
5. **Post-checks**: confirm the returned state advances `state_version` by exactly 1, conserves the
   channel fund, and that `verify_all_signatures` passed (CLI guarantees; loop asserts on the
   returned snapshot). On any inconsistency → do not publish, raise `ATTACK_SUSPECTED`.
6. **Publish** the new snapshot (so peers re-import) and update tickets. Idempotent on the payload's
   `tx_hash`/digest.

Inter-channel specifics: `cosign-inter-transfer` is the single atomic debit+credit command (the
loop never exposes a standalone credit that would trust a request-body signed state — CRITICAL-1).
The destination channel is resolved locally; both legs persist only if both pass.

### 3.4 NORMAL — deposit import (A20 / W7)
On a confirmed `Deposited(recipient, amount, …)` for a backed channel:
1. Reconcile the deposit against the on-chain `depositHashChain` (the CLI's setup-backing
   reconciliation model) — refuse if the Rust-computed hash disagrees.
2. Check the deposit nullifier is unused (double-fold prevention, detail2 C-10 T2).
3. `channel_member cosign-l1-deposit-import <slot> <amount> <depositor>` → 2-step fund-import +
   bundle-apply, N-of-N verified. Advance the deposit ticket `l1_done → import_done`.
4. Publish the updated snapshot. If import fails, leave the ticket at `l1_done` for retry (the
   channel is still joinable with prior balance).

### 3.5 OWN ACTIONS — close-lifecycle automation the co-signer drives
Driven by timers + tickets (W10/W8), each step idempotent and gated on contract getters:
- `settlement/deploy` (once per channel, idempotent).
- Deposit/partial-withdrawal: `pw-submit` → after grace `pw-finalize` (timer
  `TIMER_PW_FINALIZE_DUE` fires when `block.timestamp ≥ deadline`).
- Cooperative close: `close --CLOSE_REQUEST_ONLY` → wait grace → `close --CLOSE_SKIP_REQUEST`
  (submit intent) → wait challenge window → `settle` (finalizeClose) → per-member `claim`.
- All timers are derived from on-chain values (`getPendingClose().challengeDeadline`,
  `closeRequestedAt + grace`) re-read each tick — never from local clocks alone.

### 3.6 ABNORMAL — invalid requests & scoring
A request that fails any pre-policy or verification step is:
1. Rejected with a precise error (4xx) — never partially applied.
2. Scored against the sender (`policy.scoreInvalid`). Crossing a threshold → temporary refusal
   (back-pressure) for that sender + an alert. This is anti-griefing, not a soundness control
   (soundness is the CLI/contract gate); it is documented as such.
3. Logged with the offending payload digest for forensics.

### 3.7 ABNORMAL — close observed on-chain (defensive close game)
The co-signer continuously reconciles `getPendingClose()` against its own latest co-signed head.
On `CloseRequested` / `CloseSubmitted` / `SpecialCloseSubmitted`:
- **Legitimate cooperative close** (it matches a close this operator initiated): advance the
  ticket; continue the W10 timeline.
- **Stale close** (the pending close froze an *older* `(epoch, state_version)` than the operator's
  latest N-of-N head): the operator holds a strictly-newer signed state ⇒ two lawful responses,
  selected by `policy.staleCloseResponse`:
  - **Challenge (A29)** — `close --CLOSE_SKIP_REQUEST` re-submits the intent for the newer head;
    the manager enforces monotonic `(epoch, version)` via on-chain `_isNewer`, so a non-newer
    challenge fails closed. Use when only this operator needs to win the close.
  - **Cancel (A30)** — `cancel-close` proves the members kept operating at a higher version and
    returns the channel to Active. Use when the cooperative intent is to keep the channel open.
    (The CLI reads the persisted `close_intent_full.json` to bind the exact pending digest.)
- **Unrecognized / unauthorized close** (digest matches no head the operator can reconstruct, or
  member-set mismatch): the on-chain verifier already binds `registeredMemberSetCommitment()`, so a
  forged member set cannot pass; the loop nonetheless raises `ATTACK_SUSPECTED`, alerts, and (if a
  newer head exists) challenges/cancels. If no newer head exists and the close is genuine, it is a
  legitimate exit — the operator proceeds to settle/claim.

### 3.8 ABNORMAL — partial-withdrawal & attack detection
- On `PartialWithdrawalSubmitted` not initiated by this operator while it holds a newer head:
  v1 cannot cancel a PW (A45 era-fence is unsatisfiable — see API-DESIGN); the loop **alerts and
  records** and, if the PW is itself invalid, relies on the manager's gates. (Seam left for A45
  once the PW-cancel era model exists.)
- `FraudConfirmed` (rollup) → enter defensive mode: freeze new co-signing for the affected channel,
  alert, and require operator acknowledgement before resuming.
- Attack heuristics → `ATTACK_SUSPECTED`: repeated head-mismatch storms, replay attempts
  (tx_hash already in `spent/applied` ledgers), signature-count anomalies, member-set-commitment
  drift vs `registeredMemberSetCommitment()`, and unexpected status transitions. Defensive mode =
  stop co-signing that channel, keep watching, alert; only an operator (or a clear getter-based
  all-clear) resumes.

### 3.9 Co-signer state machine (per channel)
```
ACTIVE ──CloseRequested(self)──▶ CLOSE_PENDING ──submit-intent──▶ CLOSE_SUBMITTED
   │                                                                  │
   │◀──cancel-close (A30, newer head)─────────────────────────────────┤
   │                                            challenge (A29) ▲      │
   │                                                                  ▼
   │                                                       CHALLENGE_WINDOW
   │                                                                  │ finalizeClose
   ▼                                                                  ▼
DEFENSIVE (attack)                                                 CLOSED ──claim/pull──▶ SETTLED
```
PartialWithdrawal is an orthogonal sub-state on ACTIVE
(`PW_PENDING → settle_pending → settle_done`). Any state can transition to `DEFENSIVE` on
`ATTACK_SUSPECTED`.

---

## 4. Delegate account (`node/delegate/`)

### 4.1 Responsibilities
- Maintain a synced view of its channel (snapshot import, balance decryption).
- Build and submit its own transactions (intra send, inter-channel send, burn) with real ZKPs,
  then **verify** the co-signed result before treating funds as moved.
- Refresh its ciphertext when required (`canSend == false`).
- Exit autonomously when it must not depend on the co-signer: partial withdrawal, cooperative full
  withdrawal participation (claim), and post-close late claim.
- Detect co-signer misbehavior (withholding, equivocation, serving a non-extending head) and
  escalate to an on-chain exit.

### 4.2 Main loop
```
boot: load config + seed → wallet_keygen[_seeded] → import latest snapshot → reconcile chain
loop forever:
  ev = await next( chainEvents ∪ userIntents ∪ timers )
  with accountLock:
    switch classify(ev):
      ── NORMAL ────────────────────────────────────────────
      case SNAPSHOT_UPDATED:    importAndVerify(ev)          // 4.3
      case CHAIN_DEPOSITED:     awaitImportThenSync(ev)
      case BALANCE_POLL:        decryptAndReport(ev)
      ── OWN TX ────────────────────────────────────────────
      case INTENT_SEND:         doSend(ev)                   // 4.4
      case INTENT_INTER_SEND:   doInterChannelSend(ev)
      case INTENT_BURN:         doBurn(ev)                   // 4.5
      case NEED_REFRESH:        doRefresh(ev)                // 4.4 (pre-send)
      ── ABNORMAL ──────────────────────────────────────────
      case COSIGN_INVALID:      onCosignInvalid(ev)          // 4.6
      case COSIGNER_WITHHOLDING:onWithholding(ev)            // 4.6
      case CHAIN_CLOSE_SEEN:    onCloseSeen(ev)              // 4.7
      case CHAIN_FINALIZED:     onChannelFinalized(ev)       // 4.7 (claim / post-close)
      case EQUIVOCATION:        enterExitMode(ev)            // 4.8
  persist(localState)
```

### 4.3 NORMAL — sync & verify the head
- `GET snapshot` (or react to a `SNAPSHOT_UPDATED` notification) → `wallet_import_channel` →
  verify all N member signatures and structural integrity (the WASM importer fails closed on a bad
  signature). Decrypt own balance (`wallet_balance`) and compute `canSend` (false if pending
  homomorphic adds require a refresh).
- **Monotonicity check**: the imported head must not regress `(epoch, state_version)` vs the last
  one the delegate accepted. A regression ⇒ `EQUIVOCATION` (4.8).

### 4.4 OWN TX — intra send & refresh
```
ensureSendable:
  if !canSend: doRefresh()                                   // mandatory before send
doSend:
  payload = wallet_send(recipient_slot, amount)              // E-1 STARK + A11 hash-sig (local proving)
  resp    = POST cosign(payload)                             // co-signer N-of-N
  verifyCosigned(resp):                                      // 4.6 gate — BEFORE trusting it
    - all N member sigs valid (wallet_cosign/local verify)
    - extends the exact head we sent against (prev_digest match)
    - amount/recipient/nonce equal what we built
    - state_version == prev+1, fund conserved
  wallet_finalize(resp)                                      // commit locally only after verify
doRefresh:
  rp   = wallet_refresh()                                    // RefreshAir proof
  resp = POST cosign-refresh(rp)
  verifyCosigned(resp); wallet_finalize(resp)
```
On a "does not extend the current head" rejection: re-import snapshot and retry once (W3 branch);
a second failure ⇒ `COSIGNER_WITHHOLDING` or a genuine race — escalate per policy.

### 4.5 OWN TX — inter-channel send & burn (partial withdrawal)
- **Inter-channel (W4):** refresh (always required) → `wallet_send_inter_channel(to_channel,
  to_slot, amount, dest_recipient)` → `POST inter-channel/send { debitPayload, transferDescriptor }`
  → verify both `sourceHead` and `destSnapshot` → finalize. Bulk (W5/A15) is out of scope.
- **Burn / partial withdrawal (W8):** refresh if needed → `wallet_burn_send(amount, l1_address)` →
  `POST partial-withdrawal/burn` → verify cosigned burn + ticket → finalize. Settle phase
  (`partial-withdrawal/submit` then `finalize`, or combined `settle`) is co-signer-driven; the
  delegate polls the ticket and the `PartialWithdrawalFinalized` / `NativeWithdrawn` events, then
  confirms its L1 receipt.

### 4.6 ABNORMAL — co-signer result rejection / withholding
- **`COSIGN_INVALID`** (the cosigned result fails any check in `verifyCosigned`): treat as a
  protocol violation. Do **not** finalize. Snapshot the evidence (the bad response + the payload),
  alert, and switch to **exit mode** (4.8) — the delegate must assume the co-signer is faulty and
  recover funds on-chain rather than continue.
- **`COSIGNER_WITHHOLDING`** (no response / repeated non-extending heads / timeout): retry with
  backoff up to `policy.maxCosignRetries`; on exhaustion, escalate to exit mode. Withholding is a
  liveness attack; the exit path (partial/full withdrawal) is the censorship-resistant recourse.

### 4.7 ABNORMAL — close seen / channel finalized (exit-liveness)
- **`CHAIN_CLOSE_SEEN`** (someone submitted a close): the delegate verifies the pending close's
  `(epoch, state_version)` against its own latest accepted head.
  - If the close froze a **stale** state and the delegate holds (or can obtain from the co-signer)
    a newer N-of-N head, it asks the co-signer to challenge/cancel; if the co-signer is the
    suspected adversary, the delegate falls back to its own exit (it cannot challenge with a member
    signature it does not hold, so it proceeds to claim against whatever close finalizes, using its
    own decryption ZKP — exit-liveness, detail2 H-2 §3.5.4).
  - If the close is **legitimate**, the delegate prepares to claim after finalization.
- **`CHAIN_FINALIZED`** (`CloseFinalized`): the delegate claims its slot balance independently of
  any other member — `close/claim { manager, slot, recipient }` builds the `withdrawClaimZKP`
  (Regev decryption proof; amount derived, cannot over-claim) and pulls credit. If a late
  inter-channel transfer landed after finalization, it files a **post-close claim** (A34) via
  `close/post-close-claim` (needs the persisted source `InterChannelTx` + accumulator index). The
  shared-native nullifier is recomputed on-chain (no double claim).

### 4.8 ABNORMAL — equivocation & exit mode
- **`EQUIVOCATION`**: the delegate observed two conflicting heads at the same `(epoch,
  state_version)` signed by the members, or a head regression, or a cosigned result contradicting a
  prior finalized one. This is unambiguous member misbehavior. Action: stop sending, persist the
  conflicting evidence (both signed states — a publishable fraud proof), alert loudly, and enter
  **exit mode**.
- **Exit mode**: the delegate's sole objective becomes recovering funds with no further dependence
  on the co-signer: prefer a partial-withdrawal burn of the full balance if the channel is still
  Active and PW is permitted; otherwise wait for (or rely on) channel finalization and use the
  independent withdrawal claim. Exit mode is sticky until funds are confirmed on L1.

### 4.9 Delegate state machine
```
SYNCED ──intent──▶ PROVING ──cosign──▶ AWAIT_COSIGN ──verify ok──▶ FINALIZED ─▶ SYNCED
   │                                        │ verify fail / withhold
   │                                        ▼
   │                                    EXITING ──burn/claim──▶ EXITED
   ▼
NEEDS_REFRESH ─(refresh+cosign)─▶ SYNCED
Any state ──equivocation/close-against-us──▶ EXITING
```

---

## 5. Cross-cutting concerns

### 5.1 Security model (per CLAUDE.md)
- **The node programs are orchestrators, not crypto.** Every soundness property is enforced by the
  CLI verification, the WASM importer/verifier, and the on-chain manager/verifier. The loops add
  policy and liveness, and must never weaken a check to "make progress."
- **Fail-closed default**: ambiguous classification → abnormal branch; failed verification → no
  publish/finalize; unknown event → `ATTACK_SUSPECTED` / evidence capture.
- **Key handling**: co-signer member keys are derived in the CLI process; the delegate seed lives in
  the WASM session. Neither leaves its process, enters logs, or is sent over the wire. On-chain
  signing uses the deposit key via `cast`/forge exactly as today (env-expanded by the shell, never
  echoed). No secret in config files.
- **Adversarial review obligation**: before implementation, an attacker subagent enumerates
  malformed inputs, transcript/Fiat-Shamir manipulation, evaluation-point reuse, batch-opening
  forgery, missing domain separation, and replay — separate from the implementer (CLAUDE.md §2).

### 5.2 Failure, idempotency, restart
- Each branch is a pure function of (event, reconciled on-chain state, persisted tickets); replaying
  an event is safe. Action ids dedupe externally-visible effects.
- On boot: load cursor → backfill+reconcile → resume tickets from last step → only then accept new
  requests/intents.
- Heavy operations (close/claim/withdraw proving, minutes; GB memory) run under the per-channel
  lock and surface progress via tickets so a restart resumes rather than restarts.

### 5.3 Observability
- Structured JSON logs with `{channel, branch, actionId, result}`; an alert sink for every abnormal
  branch (security alerts are mandatory, never suppressed to reduce noise — CLAUDE.md).
- A read-only status endpoint/CLI per program: current per-channel state-machine node, ticket
  states, last processed block, score table, and any active defensive/exit mode.

### 5.4 Testing plan (falsifiable)
- **Unit**: `classify` truth table (every event×state → expected branch), policy thresholds,
  cursor/backfill, idempotency (replay an action id ⇒ no second effect).
- **Integration (anvil)**: drive the full happy path (join → deposit → send → inter-send → partial
  withdrawal → cooperative close → claim) end to end through both programs.
- **Adversarial**:
  - Co-signer: feed invalid/tampered payloads, replayed tx_hashes, non-extending heads, a stale
    close on-chain (expect challenge/cancel), a forged member set (expect on-chain reject + alert).
  - Delegate: co-signer returns a tampered cosigned state (expect `COSIGN_INVALID` → exit), withholds
    (expect retry→exit), equivocates (expect fraud evidence + exit), closes against a stale state
    (expect independent claim).
- **Restart/chaos**: kill each program mid-ticket and at each branch boundary; assert no
  double-cosign, no double-spend, no missed event, correct resume.
- Each test documents *what security property it proves*, not just the mechanical assertion.

---

## 6. File layout & milestones

### 6.1 Proposed layout
```
node/
  DESIGN.md                 # this document
  config.example.json
  common/  chain-watcher.js  api-client.js  cli.js  wallet.js  store.js  policy.js  log.js  alert.js
  cosigner/  index.js  loop.js  branches/{cosign,deposit,close,abnormal}.js  state-machine.js
  delegate/  index.js  loop.js  branches/{sync,send,inter,burn,exit,claim}.js  state-machine.js
  test/  classify.test.js  integration.anvil.test.js  adversarial.test.js  restart.test.js
```

### 6.2 Milestones
1. **M0 — common infra**: chain-watcher (events + cursor + backfill), api-client, cli/wallet
   wrappers, store, config. Tests: cursor/backfill/idempotency.
2. **M1 — co-signer normal flow**: cosign/refresh/inter/burn branches + deposit import + snapshot
   publish + the per-channel state machine. Integration happy path.
3. **M2 — delegate normal + own-tx**: sync/verify, send/refresh/inter/burn with `verifyCosigned`.
   End-to-end happy path through both programs on anvil.
4. **M3 — abnormal flows**: invalid-request scoring, defensive close game (challenge/cancel),
   delegate exit mode (withholding/equivocation/independent claim/post-close claim). Adversarial +
   restart suites. Attacker-subagent review before merge.
5. **M4 — hardening**: input validation, rate limits, observability/status surface, ops docs.

### 6.2.1 M4 adversarial review — findings & resolutions (implemented)
An independent subagent (not the implementer) audited the orchestration layer. All
CRITICAL/HIGH and the actioned MED findings were fixed; re-audit confirmed:
- **C1/C2/M3** (close game compared our *own* persisted intent; event args never decoded — the
  hand-written event signatures were wrong so topic0 never matched): `common/chain-watcher.js`
  rebuilt on an `ethers.Interface` from the EXACT contract event fragments (decodes args by name);
  `cosigner/branches/close.js` now reads the authoritative on-chain `getPendingClose()` and decides
  "ours" by `close_intent_digest`, so a stale *foreign* close triggers challenge/cancel.
- **H4/H5** (delegate `verifyCosigned` recipient bypass + missing amount/nonce; inter/burn finalize
  skipped crypto re-verify): `delegate/verify.js` makes the tx echo mandatory and checks
  recipient+amount+nonce; `delegate/branches/owntx.js` calls `wallet.cosignVerify` before every
  `finalize`.
- **H2/H1** (actionId `.length` collisions; non-atomic dedup): content-addressed sha256 action ids
  that refuse a missing binding; gate on `claimAction` (atomic), `releaseAction` on failure so a
  failed cosign is retryable while a success stays deduped.
- **H3** (per-batch cursor → silent event loss): per-BLOCK cursor advance; dispatch rethrows
  chain/timer errors so the cursor never passes an unprocessed block.
- **M5/M6** (delegate marked EXITED on a co-signer API 200; one-shot recovery): EXITED now gated on
  an on-chain credit for our recipient (`CHAIN_CREDIT` branch); recovery retryable.
- **M2** (unknown chain event froze the channel): unmapped chain kind → `CHAIN_OBSERVE`.
- **L1** (flag injection): deposit args shape-validated before becoming CLI argv.
A re-audit then flagged residuals, all fixed in a second round:
- **MED-1 (highest value)**: the `getPendingClose()` getter ABI was a wrong 6-field tuple (would
  decode positionally → garbage, silently degrading C1). Replaced with the EXACT 17-field
  `PendingClose` struct, verified by a decode test (`finalEpoch`/`finalStateVersion` land at the
  right positions).
- **N1**: amount/nonce echo is now mandatory (not skippable by sub-field omission), matching the
  recipient check.
- **MED-2**: `getPendingClose`/event-args parsing returns `null` on non-finite values (no
  `compareVersion` throw).
- **MED-3**: a wedged watcher cursor now escalates to an ALERT after repeated consecutive failures
  (not just a warn).
- **MED-4**: `onCreditConfirmed` requires the credit to name OUR recipient (an absent/foreign
  recipient never clears the sticky exit).
Regression: 45 node unit tests pass (incl. `test/adversarial.test.js` guarding every fix).

### 6.3 Open questions (resolve before/early in implementation)
- Transport for delegate→co-signer beyond REST (WebSocket push for `SNAPSHOT_UPDATED`?).
- Where the delegate obtains a *newer N-of-N head* to request a challenge when it suspects the
  co-signer (today only the co-signer can produce member signatures — documents the single-operator
  trust boundary; revisit under multi-operator).
- A45 PW-cancel remains blocked on the era-fence model; the co-signer's PW-defense branch is
  alert-only until then.
