# Stage 3 threat model — anchor the post-close claim to a signed, finalized InterChannelTx

Status: **THREAT MODEL — design-fork decision needed before code.**
Goal: close the post-close "vacuous inclusion" residual — prove the claimed receiver-delta belongs to a REAL
signed inter-channel tx the closed channel actually received, not a fabricated one.

## Residual being closed
`post_close_claim_circuit` (B-D + Stage 2) binds the delta ct + decrypts to `amount`, but `incoming_tx_hash`
(= witnessed `source_tx.tx_hash`) is a FREE witness — nothing proves the tx was signed/posted/received. A
claimant knowing `(close_intent_digest, incoming_tx_hash, receiver_pk_g)` + a self-consistent `(pk,s,ct)`
fabricates a delta that never existed, bounded only by `finalizedChannelFundAmount`. ALSO: Stage 2 left the
post-close **receiver Regev pk a FREE witness** (unlike withdrawal, which binds it via H1) — so post-close
decryption is currently vacuous too.

## Soundness backbone (exists today)
- `tx_hash = keccak(ids, keccak(tx_tree_root, tx_leaf))`, `tx_leaf = keccak(TX_LEAF, src_pk_g,
  sender_ct.digest, receiver_pk_g, receiver_ct.digest)` (`wallet_core.rs:2049`, `balance_state.rs:255`). So
  `tx_hash` cryptographically commits the receiver delta + the signed small-block `tx_tree_root` + both ids.
- Receiver import advances `settled_tx_chain` by `tx_hash` (`state_update_verifier.rs:646`); the closed
  channel's final `settled_tx_chain` = `finalizedSettledTxChain` on-chain (`ChannelSettlementManager.sol:870`),
  bound by the close proof via H1 (H1 includes `settled_tx_chain` at `balance_state.rs:151`, signed in
  `ChannelState::signing_digest`). So the anchor VALUE is on-chain + member-signed.
- Reusable in-circuit gadgets: `builder.keccak256` (already used), `settled_tx_chain_push_circuit`
  (`balance_state.rs:303`, tested twin), `SmallBlockMessageFields::recompute` (`small_block_message.rs:130`).
  Merkle gadgets are Poseidon (NOT reusable for the keccak chain). No in-circuit SPHINCS+ verify exists; "signed"
  = attested by the close proof's signed H1 over settled_tx_chain, NOT an in-circuit signature check.

## OPEN ISSUES / forks (decide before code)
1. **Membership structure fork — settled_tx_chain is a HASH CHAIN, not a set:**
   - **A — full chain replay (no protocol change):** witness the ordered leaf sequence from genesis
     (`Bytes32::default()`) to `finalizedSettledTxChain`, replay via `settled_tx_chain_push_circuit`, assert one
     step's leaf == the recomputed incoming `tx_hash`. No new signed field. Cost: replay length = total settled
     txs of the channel (UNBOUNDED in general; per-claim prover cost grows with history). Sound.
   - **B — keccak accumulator/Merkle over settled txs (Stage-1-class protocol-data change):** add a
     settled-tx accumulator root to the SIGNED H1 (like Stage 1's regev_pk_digests); the claim supplies ONE
     inclusion proof. Cheap/bounded in-circuit, but another signed-H1 change rippling fixtures/mirrors.
2. **Chained-leaf discrepancy (must resolve):** fund-import chains `tx_hash` (`state_update_verifier.rs:646`);
   bundle-apply/send chain `tx_leaf` (`:780`, `:523`). The canonical credit path for the LATE-tx scenario must
   be pinned, or the anchor predicate must accept either `tx_hash` or `tx_leaf` as the chained leaf.
3. **Receiver Regev pk binding (required for post-close decryption to be non-vacuous):** bind the witnessed
   `(a,b)` to the receiver's record. Options mirror the decryption sub-phase: the incoming tx's receiver-delta
   was encrypted to the receiver's registered Regev pk by the SENDER, so the pk must equal the closed channel's
   committed member regev_pk_digest (now in H1 after Stage 1) for the claimant's slot — reuse the Stage-1 H1
   one-hot bind. CONFIRM the receiver of a late tx is always a registered member of the closed channel.
4. **`tx_inclusion_proof` is dead** (constructed, never verified; redundant under the 1-receiver/1-tx-per-block
   invariant, asserted at `state_update_verifier.rs:507,755`). Stage 3 can bind `tx_tree_root` directly via
   `tx_hash` instead of a Merkle path — confirm the invariant holds everywhere.

## Minimal sound anchor (pending fork)
In-circuit: recompute `tx_leaf` + `tx_hash` from the witnessed (Stage-2-bound) delta; connect `tx_hash` to the
`incoming_tx_hash` PI (replace the free `source_tx_hash.connect` at `post_close_claim_circuit.rs:208`); prove
the chained leaf is in the finalized `settled_tx_chain` (fork A replay or fork B accumulator); bind receiver pk
(#3); add a new PI `final_settled_tx_chain` that L1 `submitPostCloseClaim` binds to `finalizedSettledTxChain`
(today ignored, `Sol:941-997`).

## Recommendation
Resolve fork #1 (A replay vs B accumulator) + #2 (leaf identity) + #3 (receiver-pk bind) BEFORE code.

## DECISION (user, 2026-06-18): Fork B — accumulator in the signed H1. Resolved sub-decisions:
- **Gadget**: REUSE the existing `IncrementalMerkleTree<Bytes32>` (`src/utils/trees/incremental_merkle_tree.rs`)
  — native `push`/`get_root`/`prove` + in-circuit `IncrementalMerkleProofTarget::verify` (Poseidon). NO new
  gadget. In-circuit = inclusion only; insertion is native (`push`).
- **NO in-circuit per-transition insertion proof (user correction 2026-06-18).** The accumulator's faithfulness
  is attested by the EXISTING N-of-N co-signing model: every settle transition is co-signed by all members,
  who verify it off-chain (native `state_update_verifier`) BEFORE signing; the accumulator root rides in the
  signed H1 (exactly like `settled_tx_chain`), and the close circuit already verifies the N-of-N member
  signatures over the final H1 — so the finalized accumulator root is signature-attested. Therefore the settle
  TRANSITION circuits do NOT grow at all (the transitions are not standalone ZK circuits — they are co-signed).
  The only ZK additions are: (a) the accumulator root in the circuit H1 recompute (byte-identical), and
  (b) the post-close claim's Merkle INCLUSION proof (~H Poseidon hashes) + receiver-pk bind. Off-chain
  verification = a cheap NATIVE `require_accumulator_push` in `state_update_verifier` that co-signers run
  before signing (NOT a ZK constraint).
- **Leaf = `tx_hash` UNIFORMLY** at every settle advancement (fund-import already pushes tx_hash; send/bundle
  push tx_leaf to the chain but ALSO insert tx_hash into the accumulator). One canonical claim predicate =
  the claim's `incoming_tx_hash`. (Resolves leaf-identity fork #2; the chain & accumulator are independent
  commitments storing different leaves — documented.)
- **Bind via a DEDICATED PI** `final_settled_tx_accumulator_root` (NOT via H1) — isolates the change; avoids
  forcing H1 into the post-close PIs. The root rides in the signed H1 (so it's attested), the close circuit
  exposes it as a close PI, and L1 finalizes it; the post-close claim binds against the finalized value.
- **Include the receiver-pk bind (threat-model #3) in this stage** — reuse the Stage-1 H1 `regev_pk_digests`
  one-hot so the witnessed receiver `(a,b)` is bound to the closed channel's committed member record. Without
  it post-close stays vacuous on the decryption axis. Fork-B anchoring + receiver-pk bind TOGETHER close
  post-close over-claim.
- **Tree height H = 20** (≈1M settles, far beyond any real channel); native `push` asserts `len < 2^H`.
- **Wallet persistence (runtime follow-up)**: the full `IncrementalMerkleTree` must be persisted per channel to
  generate inclusion proofs at claim time (today only the scalar `settled_tx_chain` is persisted). Flagged for
  the wallet/CLI layer; the circuit + fixture generators build the tree directly.
- Implement → SEPARATE independent review (the H1 byte-identity pin + lockstep accumulator maintenance are the
  fragile invariants). NO git commands in the implementer (prior incident).

### Stage 3 — DONE (filled after execution, 2026-06-18)

Implemented Fork B. Rust lib + touched unit/circuit tests PASS (release); contracts `forge build`
green + golden-vector tests pass. Heavy MLE-fixture E2E (CloseLifecycleE2E / MleE2E) + fixture-gen
NOT run — they need regeneration (see below).

**P1 (signed-H1 accumulator + native lockstep):**
- `BalanceState.settled_tx_accumulator_root` folded into `h1()` IMMEDIATELY AFTER `settled_tx_chain`
  (byte-identical native ↔ `h1_gadget::recompute_h1` ↔ `close_circuit` inline ↔
  `withdrawal_claim_circuit`; proven by the randomized `recompute_h1_matches_native…` circuit test).
  NO settle TRANSITION CIRCUIT changed.
- Native co-signer checks in `state_update_verifier.rs`: `require_accumulator_push(prev_tree, tx_hash,
  next_root)` (STRONG, run in the WALLET where the frontier exists) + `require_accumulator_unchanged`
  (root-only, wired into the in-channel-transfer + refresh verify paths). The verifier push sites do
  NOT assert insertion (they lack the frontier) — documented.
- Wallet lockstep (`wallet_core.rs`): genesis seeds the empty-tree root; `build_inter_channel_send`
  pushes `tx_hash`; **build_inter_channel_credit now pushes `tx_hash` at BOTH fund-import AND
  bundle-apply** (CORRECTED — the prior partial implementation advanced only the SENDER channel,
  which would have left the CLOSED/receiver channel's accumulator without the incoming tx → unprovable
  post-close inclusion). `BuiltInterChannelSend/Credit` now return the advanced tree for persistence;
  `ChannelSnapshot.settled_tx_accumulator` threads it. `channel_member.rs` genesis seeds the empty tree.

**P2 (post-close claim circuit):**
- `post_close_claim_circuit.rs`: replaced the free `source_tx_hash.connect` with an IN-CIRCUIT
  recompute of `tx_leaf` (keccak IMTL) + `tx_hash` (`inter_channel_tx_hash` = two IMTC pushes over
  ids+tx_tree_root) from the witnessed delta, connected to `incoming_tx_hash`; then
  `IncrementalMerkleProofTarget::verify(tx_hash, index, root)` against the accumulator-root PI
  (decoded via `Bytes32Target::to_hash_out`, which enforces canonical Poseidon→Bytes32). Receiver-pk
  bind reuses the Stage-1 H1 one-hot: recompute H1 (connected to a NEW `final_balance_state_h1` PI),
  one-hot-select `regev_pk_digests[receiver_member_index]`, connect `poseidon_digest(a,b)` to it,
  active-region check. Stage-2 decryption (amount == plaintext) kept.
- PI LEN: post-close 40 → **56** (appended `final_balance_state_h1` 40..48 + accumulator root 48..56).
  H1 was added because the receiver-pk one-hot bind is impossible without the H1-committed
  `regev_pk_digests` — the prompt's "+8 only" under-counted; surfaced + implemented as the sound design.
  Close PI LEN 87 → **95** (accumulator root inserted 77..85; already done by the prior agent).
- Solidity: `ChannelSettlementVerifier` CLOSE_PI_LEN 95 / POST_CLOSE_CLAIM_PI_LEN 56,
  `_expectedCloseLimbs` + `_expectedPostCloseClaimLimbs` + `verifyPostCloseClaim` extended (strict,
  <2^32, no-mask). `ChannelSettlementManager` threads `finalSettledTxAccumulatorRoot` through
  CloseIntent/PendingClose/CloseProofFields, stores `finalizedSettledTxAccumulatorRoot` in
  `finalizeClose`, and `submitPostCloseClaim` passes `finalizedBalanceStateH1` +
  `finalizedSettledTxAccumulatorRoot`. `computeCloseIntentDigest` UNCHANGED (accumulator root is in
  H1, NOT in the close-intent preimage).

**FIXTURES needing regeneration (user runs — heavy, not run here):**
- `generate_close_fixture` (emit `final_settled_tx_accumulator_root`; struct field added) and the
  close `mle_fixture.json` / `close_intent.json` — `CloseLifecycleE2E.t.sol` parses the new JSON key.
- `generate_post_close_claim_fixture` (witness now carries `final_balance_state` +
  `receiver_member_index`) and any post-close MLE fixture — new 56-limb PIs + the new VK.
- The post-close + close circuit VKs change (new PI count / digests) → re-run VK setup.

**Open security notes (surfaced, not silently resolved):**
- Leaf uniformity for late txs: accumulator stores `tx_hash` UNIFORMLY; the RECEIVER side (fund-import
  + bundle-apply) now inserts it, which is what a post-close claim against the closed channel needs.
- Receiver-always-a-member: enforced both natively (`to_public_inputs` rejects a non-member receiver
  slot) and in-circuit (one-hot over `regev_pk_digests` + active-region). The receiver of a late tx
  MUST be a registered member of the closed channel — confirm this holds at the protocol level for
  every late-tx path.
- Wallet tree PERSISTENCE: the build_* fns now RETURN the advanced tree, but writing it back into the
  per-channel snapshot on disk (so inclusion proofs can be generated at claim time) is still a
  WALLET/CLI follow-up.
- Pre-existing (independent): `generate_close_fixture` imports a `#[cfg(test)]`-only module so it
  cannot compile under its `close-fixture-bin` feature — flagged as a separate task.
