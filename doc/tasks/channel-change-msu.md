# Channel-change MSU — unanimous close, replacement channel, full migration

Status: **TODO / not a release capability**
Owner decision: direct in-place member-set update (the historical `MemberSetUpdate` / `IMMS`
prototype) is permanently retired. Production must not initialize an MSU VK, build an MSU block,
or mutate a Manager/validity member root in place.

## Goal

Change a channel's co-signer set only by completing a protocol-visible migration:

1. every current co-signer unanimously authorizes a migration manifest;
2. the old channel is frozen and finalized through its ordinary close path;
3. a new channel with a new channel id and the desired member/delegate set is registered;
4. every token asset, participant balance, pending credit, nullifier frontier, and protocol
   commitment named by the manifest is moved exactly once to the new channel;
5. the old channel becomes permanently retired and cannot send, receive, reopen, or be used as a
   source for a second migration.

This is called **channel-change MSU**. “MSU” here is a product-level migration name, not revival of
the retired direct mutation opcode.

## Non-goals

- No mutation of `memberPkGs`, `activeMemberCount`, `participantRoot`, `bpPkG`, or the registered
  validity leaf of an existing channel.
- No two independent transactions advertised as atomic.
- No temporary global-escrow credit, operator IOU, or balance reconstruction from local plaintext.
- No reuse of the old channel id for the replacement channel.
- No proof-system or circuit-size change merely to ship a first implementation. Reuse existing
  close, claim/withdrawal, registration, deposit/import, and live-validity statements where their
  public inputs already bind the required facts.

## Canonical migration manifest

Define a versioned, domain-separated `ChannelChangeManifest` containing at least:

- source chain id, rollup address, old channel id, old Manager address, and old registration hash;
- source close era/freeze nonce, final epoch/state version, final H1, final settled-tx chain and
  accumulator root;
- destination channel id, destination registration commitment, participant root/count, BP slot/key,
  token registry/count, and genesis-state commitment;
- full per-token source fund vector and destination import vector;
- per-participant/per-token balance-root commitment (not plaintext balances);
- all pending incoming/outgoing commitments that remain claimable after the source snapshot;
- migration nullifier, expiry/finality policy, protocol version, and hash of the complete manifest.

The old set signs exactly one manifest digest with full N-of-N. Destination participants separately
prove/sign enrollment and recipient/key ownership; old-set unanimity must not manufacture consent
for a new key or payout address.

## Required state machine

`Prepared -> SourceClosePending -> SourceFinalized -> DestinationRegistered -> AssetsImported -> Complete`

- `Prepared`: durable manifest and every old-set signature are fsynced before any L1 mutation.
- `SourceClosePending`: exact request/intent tx identity and canonical block hash are journaled.
- `SourceFinalized`: finalized-head evidence binds the source close digest and fund vector.
- `DestinationRegistered`: registration event and byte-for-byte read-back match the manifest.
- `AssetsImported`: each token/participant migration leaf is consumed once under the common
  migration nullifier; cumulative imported value equals, never exceeds, the finalized source value.
- `Complete`: exact finalized destination state root and old-channel retirement are re-read from the
  canonical chain. A local `complete` flag alone is never evidence.

Every transition must be idempotent after restart. A reorg invalidating any recorded block hash
causes a sticky halt and canonical rescan; it must never advance from a merely mined receipt.

## Value conservation and exact reconciliation

- Prove or derive from authenticated public inputs, for every token `t`:
  `source_final_fund[t] = destination_imported[t] + source_exit_claims[t] + explicitly_burned[t]`.
- Attribute backing by `(chain, rollup, oldChannelId, oldCloseDigest, tokenIndex,
  migrationNullifier)`. A Manager-wide or recipient-wide balance delta is insufficient.
- Require exact event and balance deltas, not `>=` checks. Pre-existing `pendingWithdrawals` or
  token credits must either be zero or be fully identified in the durable journal and excluded.
- Consume the migration nullifier before exposing imported funds as spendable. Duplicate manifest,
  replacement destination, cross-token, cross-chain, cross-rollup, and old/new channel-id replay
  must all fail.
- Late incoming transfers use the existing post-close accumulator/claim policy and must be assigned
  explicitly either to source claims or a follow-up destination import; they cannot disappear in
  the snapshot gap.

## Availability and abort rules

- Before source close finalization, unanimous cancellation may discard the prepared destination.
- After source finalization, migration is not allowed to depend on coordinator secrets. The
  manifest, authenticated balance attestation, proofs/commitments, and destination registration
  material must be independently recoverable by every participant.
- If destination registration conflicts, stop before importing any value and permit creation of a
  different manifest only under a new migration nullifier and fresh unanimous signatures.
- There is no rollback to an Active old channel after any source value has been imported.

## Implementation work

- [ ] Specify the manifest encoding and domain hashes in Rust, Solidity, and a language-neutral
      golden vector; reject non-canonical encodings and unknown versions.
- [ ] Extend durable public channel-state/close attestation storage so any participant can rebuild
      the source close proof and migration inputs without the coordinator.
- [ ] Add a journaled `prepare-channel-change` command that collects old-set N-of-N and destination
      enrollment consent without mutating either channel.
- [ ] Reuse the normal close watcher through finalized source close; no migration-specific shortcut.
- [ ] Register the destination through the normal production registration/live-validity producer.
- [ ] Implement channel-scoped live withdrawal/import artifacts for the finalized source head.
      Prefer existing proof statements; introduce a new circuit only if an explicit soundness gap
      proves they cannot bind the manifest.
- [ ] Import all token funds and participant commitments into the destination exactly once, then
      publish the first spendable destination head.
- [ ] Permanently mark the source channel retired in wallet/API/service state and reject every
      send, deposit import, delegate join, close cancel, and second migration attempt.
- [ ] Provide per-participant recovery tooling that resumes from the public manifest and canonical
      chain without coordinator-held signing or decryption keys.
- [ ] Remove the historical `member-update` command tombstone only in a breaking API release; until
      then it must remain a pure, side-effect-free `deprecated` error.

## Adversarial acceptance tests

- [ ] Missing/duplicate old signer, forged destination consent, signature order substitution.
- [ ] Old/new channel-id collision; cross-chain, cross-rollup, cross-manager and cross-token replay.
- [ ] Destination registration front-run with a different root/BP/recipient.
- [ ] Crash before/after every broadcast and every fsync; restart produces no duplicate transfer.
- [ ] Reorg of source request, intent, finalize, destination registration, any import, and completion.
- [ ] Pre-existing global/Manager credit cannot be swept or counted as channel backing.
- [ ] Partial token import, token registry permutation, overflow, zero/duplicate recipient, and
      mismatch between total imported balances and source fund vector all fail closed.
- [ ] Late incoming transfer at each close boundary is either claimable or imported exactly once.
- [ ] Source cannot resume or migrate again after first imported value becomes canonical.
- [ ] Hostile coordinator disappears immediately after source finalization; every participant can
      complete or claim independently from durable public material.

## Performance and release gates

- Preserve current proof statement sizes unless a reviewed soundness requirement forces a change.
- Record before/after proof bytes, build/prove/verify wall time, peak RSS, calldata, gas, and EIP-170
  runtime size for every touched production contract.
- Default budget: no proof-size or median proof-time regression above measurement noise (use 3 warm
  runs and report median); any >2% regression requires an explicit design review and owner sign-off.
- The migration may use more existing proofs/transactions, but it must not enlarge the normal send,
  close, withdrawal-claim, or validity proofs for channels that never migrate.
- Release only after three attack/defense rounds, an independent final review, clean-clone tests,
  and a public-chain E2E covering restart and reorg recovery.

## Deprecated-code boundary

- Rust historical circuit/fixture code lives under `src/deprecated/member_set_update` and is
  excluded unless the explicit `deprecated-msu` feature is selected.
- Historical Solidity fixtures live under `contracts/test/data/deprecated/member_set_update` and
  are not consumed by the active Foundry suite or deployment scripts.
- Production CLI, producer, and service expose rejection tombstones only; constructive prototype
  code is not compiled in default builds.
- Solidity production verifier has no MSU VK or verification entry point. The Manager production
  ABI also has no `applyMemberSetUpdate(...)` selector. Regression tests pin the historical
  selector `0x66e3ff78` as a literal, independent of later PCS proof-tuple changes, solely to prove
  that legacy calldata reaches an empty unknown-selector revert and cannot mutate the active
  Manager.
- The active validity circuit contains no member-root transition gadget and no dormant MSU
  selection path. It rejects every authenticated `ChannelAction::MemberUpdate` slot and preserves
  the old member root across every release transition. The serialized historical wire marker is a
  zero-only compatibility tombstone at the input boundary, not an alternative constraint system.
- Removing the dormant gadget intentionally rotates the validity circuit digest/VK. Consequently
  every validity MLE fixture, deploy manifest, and Rollup deployment must be regenerated from this
  circuit generation; an old deployed VK is incompatible and must never be treated as a benchmark
  shortcut. Record the old/new proof bytes and three-run warm medians before a public deployment.
