# F-WD-2 remediation — threat model & plan (2026-07-04)

## Vulnerability (confirmed)
Withdrawal/receive nullifier = Poseidon(`SettledTransfer`) where
`SettledTransfer = inner_transfer ‖ from(channel_id) ‖ transfer_index ‖ block_number`
(transfer.rs:110-118). `block_number` = the SETTLEMENT block (send_leaf.cur).
`Transfer` has NO salt (recipient/token_index/amount/aux_data only). Settlement
(update_channel_tree.rs per-user loop) appends one send leaf per updating block
and does NOT gate a tx by nonce — ChannelLeaf has no settled-nonce field
(channel_tree.rs:95-101). `should_update = should_check_account ∧ prev≠block`
only blocks two updates in the SAME block.

=> A block producer / channel co-signer can settle the SAME sender tx (nonce N)
into two blocks B1,B2 → two send leaves (cur=B1,B2) → two DISTINCT nullifiers
for ONE balance deduction. On-chain `withdrawalNullifierUsed` and the recipient
indexed-merkle both key on the nullifier, so neither catches it. Impact:
double native withdrawal (peer-escrow theft, capped by solvent_from_genesis)
AND double receive-credit (inflation, same cap). Requires block-producer
misbehavior (the channel's own signing authority) — NOT proven safe today.

## Sender-side facts that ground the fix (verified)
- spend_circuit.rs:166 verifies sent_tx_tree slot at index=nonce is EMPTY
  before write; :172 writes tx at index=nonce; :183 `is_valid = tx_nonce ==
  prev_state.nonce`; :179 nonce++ → within one balance lineage each nonce is
  used exactly once and is sequential.
- tx_settlement.rs:180 binds settled `tx_v2.nonce == tx.nonce`.
- single_withdrawal binds `tx.nonce` via txLeafHash(transferTreeRoot,nonce) in
  the sent-tx tree at index=nonce AND in the block tx tree → nonce is available
  and bound to the deduction at the nullifier-construction site.
Conclusion: `(from_channel_id, nonce, transfer_index)` is a settlement-
independent, one-time identifier bound to the deduction. `block_number` is the
ONLY settlement-varying field in the preimage.

## Fix (recommended B+A)
- **B (immediate, surgical):** replace `block_number` with `nonce` in the
  `SettledTransfer` preimage (both native transfer.rs and Target). Same scheme
  for receive AND withdrawal (they share SettledTransfer). Double-settle ⇒
  IDENTICAL nullifier ⇒ caught by withdrawalNullifierUsed + recipient indexed
  merkle. No contract logic change (contract stores the 32B nullifier, does not
  recompute) — only differential tests + fixtures regenerate. Legit uniqueness:
  distinct sends have distinct nonce; multiple transfers/tx use transfer_index;
  cross-channel uses `from`.
- **A (defense-in-depth + Lean closure):** add `last_settled_nonce` to
  ChannelLeaf; settlement asserts strictly-increasing settled nonce and updates
  it. Makes double-settle unreachable on-chain (also protects receive + block
  chain). Enables Lean to prove send-settled-once from the settlement circuit.

## Adversarial obligations (attacker subagent must clear ALL before merge)
1. Is `nonce` bound to the EXTRACTED transfer at EVERY SettledTransfer
   construction site (single_withdrawal native+target, receive_transfer
   native+target), with no site where a prover can pick nonce free of the
   tx/deduction? Enumerate each site.
2. Nullifier-collision across LEGITIMATE distinct transfers under the new
   preimage (recipient DoS via forced collision)? Consider channel-action txs
   (tx_class), close txs (channel_message.rs to_channel_close_tx_v2 with its own
   nonce), and cross-lineage/fork replays.
3. Does removing block_number break any OTHER consumer/ordering invariant
   (e.g. block_r bounds F-BLKR-1, receive ordering, event indexing)?
4. Option A: does per-channel single settled-nonce fit the 1-key channel model
   (project_one_key_member: base identity = channel_id only)? Multi-member
   channels: is the tx nonce per-channel or per-member? If per-member, a single
   ChannelLeaf counter is wrong — surface it.
5. Does A interact with F-UPDU-1 (channel_reg writing account root) — fresh
   channel leaves must init last_settled_nonce consistently (channel_reg_step).

## Non-negotiables
- Threat model before code (this file). Attacker subagent red-teams design
  BEFORE implementation; separate reviewer AFTER. No silent security weakening.
- Fixtures WILL be invalidated (nullifier/leaf preimage change) — regenerate,
  never hand-edit to pass. Differential tests (test_withdrawalLeafDifferential
  etc.) must be updated to the new preimage and must PASS as real checks.

## Attacker red-team verdict (2026-07-04) — design gate

- **Option B: GO.** All 4 SettledTransfer sites (single_withdrawal native :373 /
  target :506; receive native :279 / target :469) bind `nonce` to the deduction
  (withdrawal via sent_tx_merkle_proof at index=nonce; receive via
  tx_settlement.tx.connect(spend_pis.tx) + is_valid). A prover CANNOT pick nonce
  free → double-settle now yields byte-identical nullifiers → caught. No legit
  collision (transfer_index / from / one-base-lineage-per-channel disambiguate;
  close/channel-action txs never reach the SettledTransfer path). No flow broken;
  block_number in the nullifier was NOT load-bearing elsewhere (ordering uses a
  separate tx_block_number wire). Contract needs NO change (nullifier opaque 32B).
- **Option A (strictly-increasing): NO-GO as specified — LIVENESS BLOCKER.**
  Settlement is block-producer-driven and non-contiguous; nonces settle out of
  order / with gaps. A bare `nonce > last_settled` wedges the channel. Corrected
  design = per-channel "nonce-not-previously-settled" predicate (settled-nonce
  SET / bitmap, or high-water-mark + explicit membership), init the new
  ChannelLeaf field in channel_reg_step deterministic construction + R5 default
  leaf, gate on should_update, and review JOINTLY with F-UPDU-1 (same loop,
  at-most-one-transition invariant :966-971). nonce is per-CHANNEL in the base
  layer (one base account = channel), so a single per-channel structure is the
  right granularity (per-member fear does NOT bite).

## DECISION (2026-07-04)
Land **B now** (full exploit fix, surgical) + **close F-WD-2 in Lean from B's
nonce-binding** (single-use provable from spend_circuit empty-slot + nonce
binding, WITHOUT the settlement-uniqueness induction). Corrected-A (settled-
nonce set in the settlement circuit) is a larger, F-UPDU-1-entangled protocol
change → specify it as an attacker-vetted defense-in-depth FOLLOW-UP (record in
findings), do NOT rush it in the same pass. Rationale: B alone makes double-
settle harmless; corrected-A's marginal value is settlement hygiene + a
settlement-side Lean fact, not fund-safety. "Correct incomplete > incorrect
complete" (CLAUDE.md).

## Lean closure done (2026-07-04)

The Lean model was updated to the Option B preimage and F-WD-2 is now CLOSED in
the formalization (not merely noted as an on-chain fix). Zero sorry/axiom; full
`lake build` green (43/43).

- `Zkp/Circuits/Withdraw/SingleWithdrawalCircuit.lean`:
  - `settledNullifier`'s 4th argument changed from the block number
    (`send_leaf.cur`) to `tx.nonce`; doc re-cites the Option B preimage.
  - `Constraints.wNul` now reads
    `w.nullifier = settledNullifier transfer channelId transferIndex tx.nonce`;
    `tx.nonce` is an ALREADY-BOUND wire (via `Constraints.sentTx`, sent-tx
    membership at index=nonce), so no new binding was introduced.
  - `withdrawal_sound` re-proved: its final conjunct now establishes the
    nonce-keyed, settlement-INDEPENDENT nullifier. The satisfiability
    witness (`constraints_satisfiable`) updated accordingly.
  - SECURITY OBSERVATIONS + the `-- SECURITY FINDING (F-WD-2)` block: status
    changed to CLOSED-by-Option-B (nonce-binding closure), with the honest note
    that single-use ENFORCEMENT stays on the on-chain map and Option A remains
    an optional defense-in-depth follow-up.

- `Zkp/EndToEnd.lean`:
  - `WithdrawalProvenance` inherits the nonce arg
    (`... settledNullifier sw.transfer sw.channelId sw.transferIndex sw.tx.nonce`).
  - `end_to_end_payout_sound` type-checks unchanged: clause (d) was already
    proved from the on-chain single-use map (`withdrawNative_consumes` /
    `withdrawLeaf_nullifier_once`) + circuit-side `LeafFacts.spendOnce`, both
    keyed on the opaque nullifier. Under Option B the two settlements of one
    deduction now share ONE key, so those existing consumption theorems SUFFICE
    — no new `BridgeAssumptions` field was needed (the nonce-binding is PROVED
    per witness by `withdrawal_sound`'s `wNul`, surfaced via
    `LeafFacts.provenance`, not assumed).
  - RESIDUAL TRUST SURFACE item 7 moved from OPEN to "CLOSED by Option B, NO
    LONGER a residual".

Theorems now carrying the closure: `withdrawal_sound`,
`constraints_satisfiable` (SingleWithdrawalCircuit) and
`singleWitness_provenance`, `end_to_end_payout_sound` (EndToEnd).

## VERIFICATION COMPLETE (2026-07-04) — F-WD-2 CLOSED by Option B
- Rust fix applied (transfer.rs preimage block_number→nonce + 6 sites + C14 test).
  Adversarial code review: GO (nonce bound at all 4 prod sites; native/target
  preimage identical 1-limb; swap complete; ordering intact; tests not weakened).
- Lean: wNul re-keyed to tx.nonce (bound via sentTx); withdrawal_sound re-proved;
  EndToEnd single-use re-argued from nonce-uniqueness; lake build green.
- PROOF-GENERATION (native↔target agreement, the decisive check):
    cargo test --test e2e --release        → e2e_deposit_validity_withdrawal ok 129s
    cargo test --test mle_onchain_e2e --release → validity_proof_mle_onchain_e2e ok 60s
    SKIP_GROTH16=true forge test           → 174/175 pass
  The 1 fail (CloseLifecycleE2E, close-fixture manager/recipient address mismatch)
  is PRE-EXISTING — reproduced against committed baseline fixtures; unrelated
  close path, not the nullifier path.
- Nondeterministic block/mle/vpi fixture regen (ZK blinding) discarded to keep the
  fix diff focused; withdrawal fixtures did not need regen (forge green with them).
- Corrected-Option-A (per-channel settled-nonce SET, NOT strict-increase which the
  red-team found is a liveness bug) deferred as optional defense-in-depth.
