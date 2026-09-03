const { Router } = require('express');
const fs = require('fs');
const { cli, wc, RPC, readJson, rollupOf, chainId } = require('../lib/cli');
const { publicBacking } = require('../../node/common/public-backing');
const {
  LIVE_BALANCE_SNAPSHOT_VERSION,
  PUBLIC_BACKING_SCHEMA_VERSION,
  validateSignedHeadExitKit,
} = require('../../node/delegate/backing-vault');
const producer = require('../lib/block-producer');
const { withLock } = require('../lib/lock');
const { flushPublishedHead } = require('../lib/producer-head');

// ONE shared implementation of the manifest validation + chain verification (node/common), so the
// api, the node programs and the wallet relay cannot drift on what "verified" means. If the module
// is not present in a given deployment the route degrades to null metadata — never to a local
// re-implementation of the rules.
let TokenRegistry = null;
try { ({ TokenRegistry } = require('../../node/common/token-registry')); }
catch (e) { console.warn(`[tokens] token-registry module unavailable (${e.message}) — serving raw base indices`); }

const router = Router({ mergeParams: true });

// ── Token DISPLAY metadata (multi-token detail2 §N-1/§N-7, threat model TM-10b) ───────────────
//
// SECURITY CONTRACT: symbol / name / decimals carry ZERO authority. The authoritative token
// identity is the base `token_index` — proof-bound in the circuits and set-once on-chain in
// `IntmaxRollup.tokenAddressOf(uint32)`. Labelling a worthless token "USDC" is a user-funds
// attack, so metadata is served ONLY for entries whose manifest address was read back EQUAL from
// the on-chain registry; everything else is served as null and the UI falls back to the raw index.
//
// The manifest ships per deployment alongside `channel_backing.json` (`<workdir>/tokens.json`),
// overridable with TOKENS_MANIFEST. Loading + verification is lazy and cached per channel:
//   * no manifest                       → no metadata (a valid state, not an error)
//   * structurally invalid manifest     → NO metadata, ever, + a loud error log (fail closed)
//   * verification not finished yet     → NO metadata (entries are unverified until proven)
//   * verification found a CONTRADICTION → registry poisoned: all entries forced unverified.
// A contradiction cannot abort startup here the way it does in the node (this is a request-time
// path), so it degrades to "never serve metadata" — the same fail-closed direction.
const _tokenRegistries = new Map(); // channelId -> { registry: TokenRegistry|null }

function tokenRegistryFor(ch) {
  if (_tokenRegistries.has(ch)) return _tokenRegistries.get(ch).registry;
  const slot = { registry: null };
  _tokenRegistries.set(ch, slot);
  if (!TokenRegistry) return null;
  const manifestPath = process.env.TOKENS_MANIFEST || wc(ch, 'tokens.json');
  if (!fs.existsSync(manifestPath)) return null;
  let registry;
  try {
    registry = TokenRegistry.fromFile(manifestPath);
  } catch (e) {
    console.error(`[tokens] channel ${ch}: REJECTED ${manifestPath}: ${e.message} — serving raw base indices`);
    return null;
  }
  slot.registry = registry;
  // Verify asynchronously; until it resolves every entry stays unverified (fail-safe default).
  (async () => {
    try {
      await registry.verifyAgainstChain(RPC, rollupOf(ch), { logger: console });
      console.log(`[tokens] channel ${ch}: ${JSON.stringify(registry.summary())}`);
    } catch (e) {
      registry.markAllUnverified('verification failed');
      console.error(`[tokens] channel ${ch}: token manifest contradicts the chain: ${e.message} — metadata withheld`);
    }
  })();
  return registry;
}

// GET /api/v1/channel/:ch/snapshot (A6/A39)
router.get('/snapshot', (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    await flushPublishedHead(ch);
    res.json(readJson(wc(ch, 'channel_snapshot.json')));
  }).catch(() => {
    res.status(404).json({ error: 'no channel yet' });
  });
});

// GET /api/v1/channel/:ch/status (A40)
router.get('/status', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const record = snapshot.record || {};
    const status = record.status || 'active';
    const result = { status };
    if (record.closeRequestedAt) result.closeRequestedAt = record.closeRequestedAt;
    if (record.challengeDeadline) result.challengeDeadline = record.challengeDeadline;
    if (record.finalizedAt) result.finalizedAt = record.finalizedAt;
    res.json(result);
  } catch (e) {
    res.status(404).json({ error: 'no channel yet' });
  }
});

// GET /api/v1/channel/:ch/tokens (multi-token §N)
// Per-token channel view derived from the cosigned snapshot: the active registry
// (local slot -> base tokenIndex) and the per-token channel-fund amounts, enriched with VERIFIED
// display metadata. Balance-bearing responses stay backward compatible elsewhere (scalar = token
// 0); this route is the additive per-token surface. Hidden per-member balances are NOT here — they
// only decrypt client-side (wallet_balance returns a per-token `balances` array).
//
// Which slots exist and what base index each maps to comes from the CHANNEL's own signed registry
// (the snapshot) — never from the metadata manifest. The manifest only ever answers "what may this
// base index be CALLED", and only when chain-verified (see tokenRegistryFor above).
router.get('/tokens', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const snapshot = readJson(wc(ch, 'channel_snapshot.json'));
    const bs = (snapshot.state && snapshot.state.balanceState) || {};
    const fund = (snapshot.state && snapshot.state.channelFund) || {};
    const tokenCount = bs.tokenCount || 1;
    const registry = bs.tokenRegistry || [];
    const amounts = fund.amounts || [];
    const meta = tokenRegistryFor(ch);
    const tokens = [];
    for (let t = 0; t < tokenCount; t++) {
      const tokenIndex = registry[t] !== undefined ? registry[t] : 0;
      const md = meta
        ? meta.metadataFor(tokenIndex)
        : { symbol: null, name: null, decimals: null, address: null, native: tokenIndex === 0, verified: false };
      tokens.push({
        tokenSlot: t,
        tokenIndex,
        symbol: md.symbol,
        name: md.name,
        decimals: md.decimals,
        address: md.address,
        native: md.native,
        verified: md.verified,
        fundAmount: amounts[t] !== undefined ? String(amounts[t]) : '0',
      });
    }
    res.json({ tokenCount, tokens });
  } catch (e) {
    res.status(404).json({ error: 'no channel yet' });
  }
});

// GET /api/v1/channel/:ch/backing (A43)
router.get('/backing', async (req, res) => {
  const ch = Number(req.params.ch);
  withLock(ch, async () => {
    await flushPublishedHead(ch);
    const deployment = publicBacking(readJson(wc(ch, 'channel_backing.json')));
    const artifact = await producer.liveBackingArtifact(ch);
    if (!artifact || !artifact.baseHead
        || artifact.baseHead.snapshotVersion !== LIVE_BALANCE_SNAPSHOT_VERSION) {
      throw new Error(`public backing requires live snapshot version ${LIVE_BALANCE_SNAPSHOT_VERSION}`);
    }
    const signedSettledTxChain = artifact.signedHead
      && artifact.signedHead.balanceState
      && artifact.signedHead.balanceState.settledTxChain;
    // Only the live public close surface requires this kit. Historical inter-channel
    // `sourceBacking` records remain readable and may predate v4, but they are never substituted
    // here for a signer-independent close artifact.
    validateSignedHeadExitKit(artifact.signedHeadExitKit, ch, signedSettledTxChain);
    res.json({
      schemaVersion: PUBLIC_BACKING_SCHEMA_VERSION,
      source: 'liveBalanceService',
      // The transport context is a security binding consumed by public_close_prover. Read the
      // configured RPC, not a caller/operator environment label that can silently name another
      // chain while serving an otherwise valid proof bundle.
      chainId: chainId(),
      rollup: deployment.rollup,
      ...artifact,
    });
  }).catch((e) => {
    // Never fall back to setup-time channel_backing.json: doing so would publish a stale settle
    // chain exactly while the newest balance proof is awaiting its N-of-N channel binding.
    res.status(409).json({ error: String(e.message || e) });
  });
});

// Public base send cursor. The full private witness stays operator-local; wallets need only this
// nonce to bind their TxV2.
//
// SECURITY (base-nonce strand fix): this MUST serve the daemon's LIVE cursor, not
// `channel_backing.json`. That file's `base_private_state` is written once at `setup-backing` and
// never advanced, while the daemon (the live base-state authority) advances its cursor on every
// settled send. Serving the frozen file let a delegate build a second burn at the stale nonce; the
// co-sign guard — reading the same frozen file — agreed and persisted the channel debit, and only
// then did the daemon reject the settle, stranding the burned value forever. Sourcing the nonce from
// `liveBaseHead` makes the delegate build at the authoritative nonce, so a divergent burn is refused
// at co-sign (fail-closed) instead of debited-then-stranded. On any daemon error we 409 rather than
// fall back to the frozen file, because that fallback is exactly the strand.
router.get('/base-head', async (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const live = await producer.liveBaseHead(ch);
    const nonce = live && live.baseNonce;
    if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
      throw new Error('live base nonce is unavailable from the producer');
    }
    res.json({
      schemaVersion: 1,
      nonce,
      settledTxChain: (live && live.settledTxChain) ?? null,
      // Live authority: not the setup-time projection.
      source: 'liveBaseHead',
    });
  } catch (e) {
    res.status(409).json({ error: String(e.message || e) });
  }
});

// GET /api/v1/channel/:ch/registration-record (A3)
router.get('/registration-record', (req, res) => {
  try {
    const ch = Number(req.params.ch);
    cli(ch, ['export-reg-record']);
    const record = readJson(wc(ch, 'cli_reg_record.json'));
    res.json(record);
  } catch (e) {
    res.status(500).json({ error: String(e.stderr || e.message || e) });
  }
});

// GET /api/v1/channel/:ch/deposit/info (A42)
router.get('/deposit/info', async (req, res) => {
  try {
    const ch = Number(req.params.ch);
    const backing = readJson(wc(ch, 'channel_backing.json'));
    if (!backing.rollup) throw new Error('no rollup in channel_backing.json');
    const depositRecipient = await producer.livePrepareDepositRecipient(ch);
    res.json({
      rollup: backing.rollup,
      depositRecipient,
      rpc: RPC,
      // Same authority as /backing: an operator label must not contradict the RPC the deposit
      // will actually be submitted to.
      chainId: chainId(),
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

module.exports = router;
