# Threat model — `reclaimStake(submissionId)` (POST_BLOCK_STAKE recovery)

## Problem being fixed

`POST_BLOCK_STAKE` (1 ETH) is the fraud bond attached to each `postBlockAndSubmit` call. It is
refunded ONLY by `finalize()`-ing that exact submission (`_refundStake`, the sole refund path). But:

- `finalize` advances a single global `latestFinalizedStateRoot` monotonically and requires every
  proof to chain from the last finalized state (`initialExtCommitment == latestFinalizedStateRoot`).
- One aggregate validity proof (genesis→blockN) finalizes ONE submission and refunds ONE stake. Every
  other postBlock submission whose blocks are covered by that aggregate proof is "leapfrogged": it can
  never be finalized afterwards (no proof chains backwards) and its bond is permanently frozen.
- It cannot even be fraud-proved/timeout-removed: `fraudProof` reverts when
  `meta.startBlockNumber <= latestFinalizedBlockNumber` (`IntmaxRollup.sol:1006`).

This is the system's NORMAL flow (the project's own fixtures finalize a multi-block chain with one
aggregate proof + one finalize), so on mainnet every posting round beyond the one finalized leaks a
real-ETH bond. Observed on Sepolia: c2c run stranded 4 ETH (sub0–3).

## Fix: `reclaimStake(uint256 submissionId)`

Once a submission's blocks are part of canonical FINALIZED history, its fraud claim can never be
challenged (the `fraudProof` guard already excludes it) and a valid proof for that state provably
exists (finalize verified the chain past it). The bond is therefore no longer at risk and must be
returnable to its submitter.

### Eligibility (ALL required)
1. `stakeInfo[submissionId].submitter != address(0)` and `!stakeInfo[submissionId].spent`
   — the stake exists and was neither refunded (via finalize) nor slashed (via fraud).
2. `_batchMetadata[submissionId].endBlockNumber <= latestFinalizedBlockNumber`
   — the ENTIRE batch (last block) is finalized. Strictly stronger than the fraud-exclusion guard
   (which uses `startBlockNumber`), so a batch straddling the finalized boundary is NOT reclaimable
   until its tail finalizes too.

### Effects (CEI, nonReentrant)
- Set `spent = true`, `delete stakeInfo[submissionId]` (effects first).
- `pendingWithdrawals[submitter] += POST_BLOCK_STAKE` (pull-payment; no push, no external call).
- Permissionless caller; credit ALWAYS goes to the recorded submitter (a helper may sweep on their
  behalf with no benefit to itself).

### RESOLUTION of the adversarial review (height-only check is sufficient)
The first reviewer (agent a5d8cb83) rated as HIGH that a bare `endBlockNumber <= latestFinalizedBlockNumber`
check could release a NON-canonical batch's bond, because `finalize` does not bind `submissionId` to
the verified proof and block numbers might be reused. After tracing the fraud/rollback machinery this
is NOT reachable, from two invariants — so the implementation uses the height-only check (a per-batch
`endBlockHash` binding was prototyped but is redundant, and adding it overflows the EIP-170 runtime-size
budget / triggers a via_ir stack-too-deep):
  - **INV-A (rollback floor):** `fraudProof` refuses any submission with
    `startBlockNumber <= latestFinalizedBlockNumber` (`IntmaxRollup.sol:1006`), and `_truncateSubmissions`
    only rewinds from the fraud target upward. So `blockNumber` is never rewound below
    `latestFinalizedBlockNumber`; therefore `blockHashChainAt[k]` for any finalized height
    `k <= latestFinalizedBlockNumber` is IMMUTABLE and equals the chain `finalize` verified.
  - **INV-B (unique live batch per height):** posting strictly advances `blockNumber`; two batches can
    only share an end height via rewind+repost, which first DELETES the prior submission there (clears
    its `stakeInfo`). So at most one *live* submission ends at any height.
  Together: a live submission (cond 1) with `endBlockNumber <= latestFinalizedBlockNumber` is THE
  canonical finalized batch at that height ⇒ its bond is settled ⇒ release is correct. Both invariants
  are pinned by tests (ReclaimStake.t.sol). A re-review by an INDEPENDENT security agent (separate from
  the implementer) must confirm INV-A/INV-B before merge.

## Adversarial analysis

### A1. Double refund (finalize + reclaim of the same stake)
- Submission finalized via itself → `_refundStake` already set submitter→0 / deleted stakeInfo →
  reclaim reverts (cond 1). ✓
- Stake reclaimed first → stakeInfo deleted → a later `finalize(thatId)` calls `_refundStake` which
  early-returns on submitter==0 (no second credit). ✓  Moreover finalize of an orphaned submission
  fails anyway (its proof's initial ≠ current latest). ✓
- Two reclaim calls → second reverts (stakeInfo deleted). ✓

### A2. Reclaiming a still-at-risk (un-finalized) submission
- Guarded: `endBlockNumber > latestFinalizedBlockNumber` reverts. Before ANY finalize,
  `latestFinalizedBlockNumber == 0 < endBlockNumber (>=1)`, so nothing is reclaimable. ✓
- A submission still inside the fraud window has `endBlockNumber > latestFinalizedBlockNumber` (its
  blocks are not finalized) → not reclaimable. The honest challenger can still slash it. ✓

### A3. Does reclaim make block-spam cheaper?
- A junk/divergent block can only become reclaimable if it ends up in FINALIZED history
  (`endBlockNumber <= latestFinalizedBlockNumber`). For that, a valid validity proof must finalize the
  canonical chain past it — i.e. the block was actually valid/canonical. A spammer who posts blocks
  that diverge from the honest chain can never get them finalized (the honest proof's
  `finalBlockChain` won't match `blockHashChainAt[N]`), so those bonds stay locked exactly as today.
  reclaim returns bonds ONLY for blocks that legitimately became finalized history. So spam is NOT
  made cheaper. (Open question for reviewer: is postBlock permissioned? If anyone can advance the
  chain, that is a PRE-EXISTING liveness concern independent of reclaim.)

### A4. Interaction with `_truncateSubmissions` (fraud) and rollback
- Fraud only targets submissions with `startBlockNumber > latestFinalizedBlockNumber`; reclaim only
  releases `endBlockNumber <= latestFinalizedBlockNumber`. Since start <= end, the two sets are
  disjoint at the boundary (a fully-finalized batch has start<=end<=latest → reclaimable, not
  fraud-able; an un-finalized batch has end>latest → not reclaimable). A straddling batch
  (start<=latest<end) is neither — conservative limbo until its tail finalizes (pre-existing for the
  fraud side too). ✓
- Truncation deletes stakeInfo+metadata of truncated submissions → reclaim reverts (cond 1). ✓

### A5. Griefing via permissionless caller
- Credit always to the recorded submitter; caller gains nothing. nonReentrant + CEI; pendingWithdrawals
  is a storage write, no external call. No reentrancy / no front-run benefit. ✓

### A6. Metadata edge cases
- Unknown/deleted submissionId → submitter==0 → revert. ✓
- endBlockNumber is always >= 1 (startBlockNumber = blockNumber+1). No underflow / no zero-confusion. ✓

## Invariants the tests must pin
- I1 reclaim of a finalized-past orphan credits exactly POST_BLOCK_STAKE to the submitter, once.
- I2 second reclaim reverts; reclaim-after-finalize-refund reverts; finalize-after-reclaim does not
  double-credit.
- I3 reclaim of an un-finalized submission reverts; reclaim before any finalize reverts.
- I4 a fraud-slashed/truncated submission is not reclaimable.
- I5 total ETH paid out (withdrawals + all refunds/reclaims + slashes) never exceeds ETH escrowed +
  stakes posted (no inflation).
