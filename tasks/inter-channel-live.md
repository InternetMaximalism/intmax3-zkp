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
- [x] Machinery mapped + design fixed (see git: subagent report).
- [ ] wallet_core + local E2E test (in progress, worktree).
- [ ] CLI subcommands. [ ] wasm + relay + browser. [ ] security review. [ ] deploy.
