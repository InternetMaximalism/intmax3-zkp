# Live inter-channel send (channel 7 → channel 8) — REAL, no facade

Goal: a delegate in channel A debits `amount`; the recipient slot in channel B is credited the SAME
amount, with the credit cryptographically backed by the verified debit. The crypto already exists and
is proven in tests/inter_channel_{e2e,validity_b2,unified_e2e}.rs — this WIRES it into wallet_core +
wasm + the CLI + the relay + the browser. No silent intra-channel fallback, no fabricated credit.

## Threat model (attacker controls the browser + can replay/forge network payloads)
T1 Credit B without a real debit in A → MUST verify A's small block is N-of-N co-signed (invariant 1)
   before B credits anything (fail-closed; refuse to sign on any failure).
T2 Amount mismatch (debit x, credit y>x) → amount bound across E-2 statement, descriptor, both legs
   (invariant 2); E-2 STARK enforces after+amount==before and both deltas encrypt exactly `amount`.
T3 Wrong recipient (credit a slot the sender didn't pay) → receiver_delta.pk_g must == B member at
   recipient_slot (ReceiverBundleApply :766); decrypt == amount (invariant 3).
T4 Cross-channel confusion → inter_channel_tx.{source,destination}_channel_id pinned to A/B ids (inv 4).
T5 Debit↔credit unbinding → state_commitment_root == a_send.h1() (§C-7), tx_tree_root==h2_tag!=0, and B
   recomputes the SAME tx_leaf it pushes into settled_tx_chain; E-2 re-verified with the descriptor's
   sender_before/after ct (bound in the STARK transcript) (invariant 5).
T6 Replay / double-credit → per-channel applied-tx_hash ledger persisted in channel B's cli_state;
   reject a repeated tx_hash (invariant 6). NEW mechanism (no existing analog).
T7 Inclusion/liveness → receiver checks tx_v2_proof.verify (flowReceive3-1, abstract2 §3.4) (inv 7).
T8 Conservation → A channel_fund -= amount, B channel_fund += amount then unallocated drawn down;
   relay sanity-checks both legs net zero (invariant 8).
T9 Atomicity gap (A debits but B credit fails) → relay gates step2 on step1; if step2 fails after a
   valid step1, SURFACE a reconciliation error (A's debit stands) — never silently drop.
Pinned-record trust: channel B must verify A's signatures against a KNOWN-GOOD channel-A ChannelRecord
   (member set), shipped + pinned, not taken from the attacker-controlled payload. NEW mechanism.

## Plan
1. wallet_core: build_inter_channel_send + verify_inter_channel_send_transition (channel A debit);
   build_inter_channel_credit + verify_inter_channel_credit_transition (channel B credit). New
   serde structs InterChannelDebitPayload / InterChannelTransferDescriptor. Reuse the UNIFIED test
   construction (prove_channel_update E-2, tx_leaf_hash, settled_tx_chain_push, the witness verifiers).
2. A local E2E test that drives BOTH legs through the new wallet_core API (no test-only shortcuts) and
   asserts all 8 invariants — the gate for correctness.
3. CLI: cosign-inter-debit / cosign-inter-credit (+ the tx_hash replay ledger + pinned A-record).
4. wasm: wallet_send_inter_channel; browser: real /api/inter/{debit,credit} flow (ordered).
5. SEPARATE security-review subagent (attacker lens) before deploy.
6. Local relay E2E, then ship to EC2.

## Status
- [x] Machinery mapped + design fixed.
- [x] wallet_core + tests/inter_channel_live.rs (2/2 pass). COMMITTED.
- [x] CLI cosign-inter-debit/credit + replay ledger + pinned A-record + pk_g dedup. COMMITTED.
- [x] wasm wallet_send_inter_channel + relay /api/inter + browser. COMMITTED.
- [x] INDEPENDENT security review → found CRITICAL-1.
- [x] FIX LANDED (atomic combined command). See "RESOLUTION" below.
- [x] re-review (2026-06-20): CRITICAL-1 verified CLOSED in code. [ ] deploy.

## SECURITY REVIEW — CRITICAL-1 (blocks deploy) — found 2026-06-17
The credit trusted a REQUEST-BODY `aSignedState`, authenticated only by N-of-N over channel A's
member set. But A's members (slots 0,1,2) have keys from PUBLIC seeds (`0xC1_0000 + slot`) — anyone
can forge a valid N-of-N `aSignedState` with NO real debit and POST it to /api/inter/credit → credits
B from nothing (value creation). Credit never bound to A's committed head / fund decrease; no A-side
spent ledger. Also: MEDIUM-1 atomicity (debit commits, credit can fail → funds stranded/grief);
HIGH-1 no A-side spend ledger; LOW conservation u32 truncation; LOW pk_g-only dedup (info).

## FIX (in progress)
Single ATOMIC combined command `cosign-inter-transfer` (relay owns both channels = one trust domain):
debit A (extend A's REAL head, fund-=amount, record tx_hash spent on A) + credit B (bind to the
IN-PROCESS proposed A debit, NOT a request blob; check B replay ledger; fund+=amount) — persist BOTH
or NEITHER. Drops the request-body `aSignedState` trust entirely. One relay endpoint /api/inter/send.
Regression test: a forged N-of-N aSignedState with no committed A debit MUST be refused; full
conservation across A AND B; replay/tamper refused; atomicity (A head unchanged if credit fails).

## RESOLUTION — CRITICAL-1 CLOSED (verified 2026-06-20)
The value-creation vector is closed at BOTH the core and the relay layer. The standalone
`/api/inter/credit` endpoint that trusted a request-body `aSignedState` NO LONGER EXISTS.

Core binding (`src/wallet_core.rs`, `verify_inter_channel_credit_transition`):
- invariant 1 (~:1994): A's `a_signed_state` MUST be N-of-N co-signed under the TRUSTED channel-A
  record (session-pinned), not a request blob → a forged N-of-N over public seeds with no real
  debit fails here (fail-closed).
- invariant 5 (~:2007): A's small block `state_commitment_root == a_signed_state.h1()` and
  `tx_tree_root` match → the fund decrease (debit) is pinned into the signed head.
- invariant 2 (~:2057): the E-2 transfer is re-verified over the descriptor amount + ciphertexts →
  a forged amount cannot pass the STARK transcript.

Relay atomicity (`wallet/wallet-relay.js` ~:126-143): a SINGLE atomic `cosign-inter-transfer`
command (relay owns both channels = one trust domain) debits A's REAL head and credits B, persisting
BOTH or NEITHER. There is no standalone credit endpoint.

Regression coverage:
- `tests/inter_channel_cli.rs` `inter_channel_cli_forged_n_of_n_a_state_refused` (~:454): a forged
  N-of-N A-state with no committed debit is refused; A head + B fund/ledgers unchanged on disk.
- `tests/inter_channel_live.rs` (~:481-535): per-invariant tamper → reject, asserting the error
  cites the specific invariant.

Remaining: deploy only. (MEDIUM-1 atomicity and HIGH-1 A-side spend ledger are subsumed by the
atomic command + replay ledger above.)

## Sender-independent completion (2026-09-21)

A transfer must land even when the sender's process dies after the source leg committed. The relay
now owns that: `api/lib/inter-channel-send.js` exports `pendingInterTransfer(ch)` /
`resumePendingInterTransfer(ch)`; `hosting/wallet/wallet-relay.js` runs `sweepPendingInterTransfers`
at startup and every `INTMAX_INTER_RESUME_MS` (default 30 s), and `/api/inter/send` resumes any
pending transfer on the source channel BEFORE a new one. `GET /api/inter/pending?channel=A` shows the
state; `POST /api/exit-kit/install?channel=B` repairs a head without its exit-kit receipt.
Verified on the local stack with `INTMAX_TEST_FAIL_INTER_TRANSFER_AFTER_SOURCE=1` (channel 9 → 10,
source committed, sender gone; relay restarted without the failpoint; the sweep completed it:
9 v3 0.005, 10 v2 0.005, `pending:false`). Mocked coverage: `node/test/inter-channel-crash-recovery.test.js`.

Two destination-side preconditions surfaced by this work:

1. **Empty-genesis channels need an exit-kit receipt before their first credit.** `cosign-inter-transfer`
   refuses with "destination signer exit-kit verification: SIGNER-INDEPENDENT EXIT REQUIRED: no signer
   exit-kit receipt is installed". The relay's `/api/init` empty-genesis branch now runs
   `installHeadExitKit` after `register` (deposit imports already did).
2. **Receive-after-send window (base layer, NOT fixed).** `receive_transfer_circuit` /
   `receive_deposit_circuit` (spec §7.2/§7.3) require, for a channel that has ever posted a send
   (`channel_leaf.prev != 0`), `send_leaf.prev <= prev_block_r` and `new_block_r < send_leaf.cur`:
   a receive is only provable STRICTLY BEFORE the channel's NEXT send block. The witness generator
   (`new_block_r = next_send_block - 1`) assumes that next send is already in a block; when it is
   not, `get_account_state` falls back to send leaf 0 and the prover fails with the opaque
   "Not new_block_r < account_state.send_leaf.cur". Consequence on the live stack: **a channel that
   has debited (inter-channel send at block S) cannot be credited or import a deposit at any block
   >= S until it posts its next send**, and the daemon proves that next send immediately after the
   block, so the window never opens in the current flow (the 8 → 7 transfer on the local stack is
   stuck this way: 7 debited at block 7, 8 debited at block 8, 7's credit needs 8 <= new_block_r < next
   send of 7). `LiveBalanceService::ensure_receive_window_open` now refuses up front with the real
   reason so the relay keeps the transfer pending instead of treating it as corrupt. Fix options:
   (a) intmax2-native deferral — queue the receive (`ReceiveTransferData` inputs) in the live
   snapshot and replay it right after the channel's next send BLOCK is posted but BEFORE that send's
   balance proof (order: post block c → prove queued receives with new_block_r = c-1 → prove send at
   c); close/withdraw must drain the queue the same way; (b) a window-opening no-op send block for
   the destination at credit time (one extra base-layer block per credit, needs a no-op tx shape in
   the validity circuit). (a) costs no blocks and matches the circuit's intent.
