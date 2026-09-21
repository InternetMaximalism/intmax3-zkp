const fs = require('fs');
const { cli, wc, RPC, readJson } = require('./cli');
const producer = require('./block-producer');
const { flushPublishedHead } = require('./producer-head');
const { cliWithPreparedExitKit, acknowledgePreparedExitKit, installHeadExitKit } = require('./exit-kit');

// Fold a journaled L1 deposit into the live balance proof. Which receive is correct depends on who
// owns the deposit recipient: when `channel_backing.json` records a deposit salt, `setup-backing`
// owns it (and every deposit — the backing one and every browser one — is sent to that same
// recipient), so the salt must be named explicitly; the daemon re-derives the recipient from it
// and refuses a salt that does not reproduce the deposit's on-chain recipient. Without a backing
// salt the live service issued the recipient itself and the configured path applies.
function receiveDepositIntoLiveBalance(ch, producerReceipt, deposit) {
  const backing = readJson(wc(ch, 'channel_backing.json'));
  const depositSalt = backing.deposit_salt;
  return depositSalt
    ? producer.liveReceiveBackingDeposit(ch, producerReceipt, deposit, depositSalt)
    : producer.liveReceiveConfiguredDeposit(ch, producerReceipt, deposit);
}

async function flushLastDepositImport(ch) {
  const artifactPath = wc(ch, 'l1_import_cosigned.json');
  if (!fs.existsSync(artifactPath)) return null;
  const artifact = readJson(artifactPath);
  if (!artifact.fundImportState || !artifact.bundleApplyState) return null;
  const depositPath = wc(ch, 'producer_deposit.json');
  const snapshotPath = wc(ch, 'channel_snapshot.json');
  if (!fs.existsSync(depositPath) || !fs.existsSync(snapshotPath)) {
    throw new Error('deposit recovery is missing producer_deposit.json or channel_snapshot.json');
  }
  const deposit = readJson(depositPath);
  const producerReceipt = await producer.postDeposit(deposit);
  const liveReceipt = await receiveDepositIntoLiveBalance(ch, producerReceipt, deposit);
  const snapshot = readJson(snapshotPath);
  const liveStatus = await producer.liveBindSnapshot(ch, snapshot);
  const headSyncReceipt = await producer.syncOffchainHeads([
    artifact.fundImportState,
    artifact.bundleApplyState,
  ]);
  acknowledgePreparedExitKit(ch, artifact.fundImportState);
  return { deposit, producerReceipt, liveReceipt, liveStatus, headSyncReceipt, artifact };
}

// The live balance service is the channel's base-state authority, but `setup-backing` funds the
// genesis BEFORE that service exists: it derives its own deposit salt/recipient, sends the L1
// deposit and proves the balance itself. A freshly initialized live service therefore sits at an
// empty proof while the signed snapshot already carries that deposit's settle chain, and
// `bind_signed_snapshot` compares exactly those two — so without this step the pair is rejected
// for ever ("signed snapshot settle chain differs from the pending live balance proof") and no
// exit kit can ever be proved for the channel.
//
// Adopting the backing deposit first walks the live proof to the same settle chain the snapshot
// was signed at. Idempotent and safe to call on every import: it is a no-op once the settle chains
// agree, the deposit is authenticated against the producer journal's L1 leaf, and the daemon
// rejects any salt that does not reproduce the deposit's on-chain recipient.
// The producer journal, not the live balance snapshot, is the source of truth for whether a
// channel is registered — and the two are separate durable stores. Registration must therefore be
// ensured on EVERY adoption return path (idempotent by the snapshot-derived request id), or a live
// balance that is bound while the journal lacks the registration leaves every later import to die
// in `syncStateIfNeeded` with "channel is not registered in the production block producer".
async function ensureRegistered(ch) {
  const status = await producer.status();
  const registered = (status.channelHeads || [])
    .some((head) => Number(head.channelId) === Number(ch));
  if (!registered) await producer.register(readJson(wc(ch, 'channel_snapshot.json')));
}

async function ensureLiveBackingAdopted(ch) {
  const backing = readJson(wc(ch, 'channel_backing.json'));
  const settled = String(backing.settled_tx_chain || '').toLowerCase();
  const depositSalt = backing.deposit_salt;
  const depositTx = backing.deposit_tx;
  // An unfunded genesis (no backing deposit) needs no adoption: the live balance was created and
  // bound to the signed genesis when the channel was initialized (`/api/init`, mirroring
  // `api/routes/channel-init.js`), and liveInit's empty proof already matches that snapshot.
  if (!settled || !depositSalt || !depositTx) return null;
  // ONE account per channel. `setup-backing` already created and proved the base account and
  // recorded the salt that names it, so the live balance must be put on THAT account; `liveInit`
  // would mint a second one whose settle chain can never match the signed snapshot's. Create only
  // when there is nothing there: `liveInit*` is a CREATE, not an ensure, and re-calling it on an
  // existing balance fails once its configured deposit recipient has been consumed.
  const accountSalt = backing.base_private_state && backing.base_private_state.salt;
  if (!accountSalt) throw new Error('channel_backing.json has no base account salt to adopt');
  if (!producer.liveSnapshotExists(ch)) await producer.liveInitWithAccountSalt(ch, accountSalt);
  let status = await producer.liveStatus(ch);
  // Adoption has THREE distinct states, and conflating them is what bricked earlier runs:
  //   * appliedTransitionCount === 0                     → nothing consumed yet: journal + receive.
  //   * appliedTransitionCount > 0 && awaitingChannelBinding → the backing deposit was consumed but
  //       a crash (e.g. a missing channel_snapshot on the first attempt) landed before the bind.
  //       RESUME: register + bind, but do NOT re-journal — that would double the deposit.
  //   * appliedTransitionCount > 0 && !awaitingChannelBinding → fully adopted and bound: done.
  // The old check returned on `appliedTransitionCount > 0` alone, so a consume-but-not-bound
  // channel short-circuited here for ever, never registered, and every import died downstream in
  // `syncStateIfNeeded` with "channel is not registered in the production block producer".
  const consumed = Number(status.appliedTransitionCount) > 0;
  if (consumed && !status.awaitingChannelBinding) {
    await ensureRegistered(ch);
    // Catch the live balance up to the CURRENT signed record before the deposit advances it. A
    // delegate join since the last bind advanced channel_snapshot.json's record while leaving the
    // asset vector untouched; the live balance is still pinned to the pre-join record. Binding the
    // current (post-join, PRE-deposit) snapshot here lands that single-step delegate-add, so the
    // deposit's own bind below is a clean same-record asset advance rather than an unsupported
    // two-step (join + deposit) change that fails "channel record changed". Idempotent: if no join
    // happened, the snapshot already matches the bound head and the bind is a no-op.
    return producer.liveBindSnapshot(ch, readJson(wc(ch, 'channel_snapshot.json')));
  }
  if (!consumed) {
    // ORDER IS LOAD-BEARING: the producer assigns this deposit `block_number = block_number + 1`,
    // and that number is hashed into `Deposit::nullifier()` — the leaf of `settled_tx_chain`.
    // `setup-backing` proved the genesis against the (index, block) the relay bootstrap handed
    // it, so the backing deposit must be journaled at exactly that position. Registering the
    // channel first consumed a block and pushed the deposit one later, which is exactly the
    // settle-chain mismatch that made the channel unbindable (measured: CLI index 0/block 1,
    // producer index 0/block 2). Journal the deposit first; registration follows.
    await journalBackingDeposit(ch);
  }
  // Register (idempotent by snapshot-derived request id) then bind. Reached both on a fresh
  // consume and when resuming a consumed-but-unbound channel.
  await ensureRegistered(ch);
  // Adoption is only complete once the resulting proof is bound to the signed snapshot; until
  // then the service refuses every further transition (`awaiting_channel_binding`).
  return producer.liveBindSnapshot(ch, readJson(wc(ch, 'channel_snapshot.json')));
}

// Journal a channel's backing deposit into the shared producer and fold it into the channel's
// live balance — the consume half of `ensureLiveBackingAdopted`, WITHOUT registration/bind (those
// need the signed genesis snapshot, which at relay bootstrap does not exist yet). With ONE shared
// producer the backing deposits of ALL channels form a single L1 deposit sequence
// (`deposit_index` must be consecutive), so the relay journals them in bootstrap order — each at
// the (index, block) its genesis was proved against — BEFORE any browser deposit can consume the
// next index. `ensureLiveBackingAdopted` later takes its consumed-but-unbound resume path
// (register + bind). Idempotent: a consumed channel is left alone.
async function journalBackingDeposit(ch) {
  const backing = readJson(wc(ch, 'channel_backing.json'));
  if (!backing.settled_tx_chain || !backing.deposit_salt || !backing.deposit_tx) return null;
  const accountSalt = backing.base_private_state && backing.base_private_state.salt;
  if (!accountSalt) throw new Error('channel_backing.json has no base account salt to adopt');
  if (!producer.liveSnapshotExists(ch)) await producer.liveInitWithAccountSalt(ch, accountSalt);
  const status = await producer.liveStatus(ch);
  if (Number(status.appliedTransitionCount) > 0) return null;
  // A distinct filename: `producer_deposit.json` belongs to the in-flight user import.
  cli(ch, ['inspect-l1-deposit', String(backing.deposit_tx), RPC, 'backing_deposit.json']);
  const deposit = readJson(wc(ch, 'backing_deposit.json'));
  const producerReceipt = await producer.postDeposit(deposit);
  return receiveDepositIntoLiveBalance(ch, producerReceipt, deposit);
}

// One crash-recoverable production ordering for every API deposit import:
//   verified L1 receipt -> durable producer deposit block -> channel N-of-N import -> durable
//   off-chain head sync. The Rust inspector owns ABI parsing and emits the exact producer schema.
async function importL1Deposit(ch, recipientSlot, txHash, {
  allowUnboundDepositor = true, depositReservation = null,
} = {}) {
  // The live balance service must already stand at the snapshot's settle chain before anything
  // below asks it to prove a transition or an exit kit.
  await ensureLiveBackingAdopted(ch);
  // Native command entry rolls pending signing WALs forward before any API artifact read. This
  // also applies to external/legacy imports, which did not pass through pre-spend preflight.
  cli(ch, ['recover-inter-transfers']);
  cli(ch, ['publish-snapshot', 'channel_snapshot.json']);
  // Complete a prior crash window before posting another L1 deposit. The two import states must be
  // replayed together because the final bundle head extends the intermediate fund-import digest.
  await flushLastDepositImport(ch);
  await flushPublishedHead(ch);
  const inspectArgs = ['inspect-l1-deposit', String(txHash), RPC, 'producer_deposit.json'];
  if (depositReservation) inspectArgs.push('--deposit-reservation', depositReservation);
  cli(ch, inspectArgs);
  const deposit = readJson(wc(ch, 'producer_deposit.json'));
  const producerReceipt = await producer.postDeposit(deposit);
  // Phase 1 is durable before the N-of-N channel import. This consumes the exact journaled L1
  // leaf into the resident balance proof, but deliberately withholds public head adoption until
  // the resulting proof is bound to the signed channel snapshot below.
  const liveReceipt = await receiveDepositIntoLiveBalance(ch, producerReceipt, deposit);

  const artifactPath = wc(ch, 'l1_import_cosigned.json');
  let artifact = null;
  if (fs.existsSync(artifactPath)) {
    const existing = readJson(artifactPath);
    if (
      String(existing.txHash || '').toLowerCase() === String(txHash).toLowerCase() &&
      Number(existing.intmaxBlockNumber) === Number(producerReceipt.blockNumber)
    ) {
      artifact = existing;
    }
  }

  if (!artifact) {
    const args = [
      'cosign-l1-deposit-import',
      String(recipientSlot),
      String(txHash),
      RPC,
      'l1_import_cosigned.json',
      `--intmax-block-number=${producerReceipt.blockNumber}`,
    ];
    if (allowUnboundDepositor) args.push('--allow-unbound-depositor');
    if (depositReservation) args.push('--deposit-reservation', depositReservation);
    // Signer-independent exit: the deposit moves the channel's fund vector and settle chain, so
    // the co-signers' exit kit for the exact import state is proved BEFORE they sign it.
    await cliWithPreparedExitKit(ch, args);
    artifact = readJson(artifactPath);
  }

  if (!artifact.fundImportState || !artifact.bundleApplyState) {
    throw new Error('l1_import_cosigned.json lacks the two N-of-N signed import states');
  }
  const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
  const liveStatus = await producer.liveBindSnapshot(ch, snapshot);
  const headSyncReceipt = await producer.syncOffchainHeads([
    artifact.fundImportState,
    artifact.bundleApplyState,
  ]);
  acknowledgePreparedExitKit(ch, artifact.fundImportState);
  // Install the CLI's verified signer exit-kit receipt for the NEW current head. A deposit moves
  // the channel's fund vector and settle chain, so the predecessor's kit no longer backs it; the
  // next value-preserving H2=0 successor (a balance refresh, an intra-channel send) reuses THIS
  // head's receipt and refuses to run without it ("SIGNER-INDEPENDENT EXIT REQUIRED: the durable
  // predecessor has no cryptographically verified signer exit-kit receipt"). The deposit proved and
  // bound the kit on the live balance service above; archive it into cli_state.json now so a
  // subsequent refresh/send can spend the credited balance.
  await installHeadExitKit(ch);
  return { deposit, producerReceipt, liveReceipt, liveStatus, headSyncReceipt, artifact };
}

module.exports = { importL1Deposit, journalBackingDeposit };
