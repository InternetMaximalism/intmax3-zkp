# Deploy runbook — INTMAX3 channel wallet demo (Sepolia + AWS EC2)

How to (re)deploy and operate the two-channel payment-channel demo. Procedure only — the live
identifiers (EC2 IP, instance id, domain/URL, on-chain addresses, key paths) are in the **gitignored**
`.claude/deploy-record.md` (per "keep server records out of git"). Set the shell vars below from there.

## Architecture (EC2-only, single small box)
- ONE small EC2 (t4g.medium, arm64, eu-north-1) serves BOTH the static frontend AND the `/api`
  co-signing from a single origin over **HTTPS**, with **COEP/COOP** headers so the multi-threaded
  wasm proving works (SharedArrayBuffer needs a secure context + cross-origin isolation).
  → `wallet-relay-ec2.js`, run by systemd unit `intmax-relay` (User=root for :443 + cert read).
- TLS: a **nip.io** domain + **Let's Encrypt** (trusted cert, no warning). No CloudFront (the IAM user
  has S3+EC2 only; S3 alone cannot set COEP/COOP, and the wasm is a shared-memory build → S3 hosting
  is impossible. That's why everything is served from EC2.)
- Two channels (**7 & 8**), each backed by its OWN real Sepolia deposit (its own IntmaxRollup, so each
  deposit is first on its chain → prev hash 0).
- The heavy `setup-backing` (deposit + ~4GB balance proof) runs LOCALLY; only the cached backing
  artifacts ship to EC2, which only co-signs (light: a real init co-sign ≈ 2-8s, ~210MB).
- The `channel_member` signer binary is built locally for **linux/arm64 via Docker** (native on Apple
  silicon) — the EC2 box never compiles Rust.

## Prerequisites (paths; NEVER read the secret contents)
- AWS creds: `.claude/.apikey` (gitignored, `KEY=value` lines). Load: `set -a; . ./.claude/.apikey; set +a`.
  Scope: S3 + EC2 only, region **eu-north-1**. No CloudFront / SSM / other-region EC2.
- EC2 SSH key: `.claude/aws/intmax-signer.pem` (gitignored, chmod 600).
- Sepolia deployer key: `…/intmax3-zkp-enshrined-paymentchannel/.claude/priv` (SIBLING worktree;
  gitignored). Hand to forge/cast via `--private-key "$(cat <that path>)"`; NEVER read/print it.
- Tools: docker + buildx, foundry (forge/cast), node 20, wasm-bindgen, rust nightly (rust-toolchain.toml).

## Build
```bash
# 1) signer binary for EC2 (linux/arm64) — native on Apple silicon, no emulation:
#    (build context stays the repo root `.`; the Dockerfile now lives under hosting/)
docker buildx build --platform linux/arm64 -f hosting/Dockerfile.signer --target bin \
  --output type=local,dest=./signer-bin .            # → signer-bin/channel_member (aarch64 ELF)

# 2) browser wasm — MUST use this script, NOT `wasm-pack` directly (Cargo.toml keeps crate-type rlib;
#    the script appends --crate-type cdylib at invocation). Output → pkg/ (run from repo root)
bash hosting/build-wallet-wasm.sh

# 3) local CLI (for the local relay) — the relay exec's it fresh each call, no relay restart needed:
cargo build --release --bins
```
`.dockerignore` excludes `.claude` (secrets!), target/, .git/, worktrees/ — keep it that way.

## Deploy to EC2
```bash
set -a; . ./.claude/.apikey; set +a            # only needed for aws CLI, not for ssh/scp
PEM=.claude/aws/intmax-signer.pem
H=ubuntu@<EC2_IP>                               # <EC2_IP> from .claude/deploy-record.md
O="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
# ship whatever changed:
scp -i $PEM ${=O} signer-bin/channel_member       ${H}:relay/bin/channel_member   # if Rust changed
scp -i $PEM ${=O} pkg/intmax3_zkp.js pkg/intmax3_zkp_bg.wasm ${H}:relay/public/pkg/ # if wasm changed
scp -i $PEM ${=O} hosting/wallet/wallet-live.html ${H}:relay/public/index.html     # if frontend changed
scp -i $PEM ${=O} hosting/wallet/wallet-worker.js ${H}:relay/public/
scp -i $PEM ${=O} hosting/wallet/wallet-relay-ec2.js ${H}:relay/
scp -i $PEM ${=O} node/common/token-registry.js   ${H}:relay/token-registry.js  # token metadata (§N)
ssh -i $PEM ${=O} $H 'chmod +x ~/relay/bin/channel_member; sudo systemctl restart intmax-relay'
```
Notes:
- **zsh gotcha**: brace host paths as `${H}:relay/...` (bare `$H:relay` triggers the `:r` modifier);
  word-split option strings with `${=O}`.
- **Membership is durable across restarts** (the cosigner is the member registry). A restart does NOT
  wipe registered delegates/slots. To deliberately start fresh: `RESET_CHANNELS=1` in the unit/env.
- index.html / wasm are served `no-store` (frontend) / `max-age 3600` (`/pkg`); a browser hard-reload
  picks up a new frontend. A new binary is picked up on the next `/api` call (exec'd fresh).
- CLI-only change → just ship the binary + restart (no wasm/frontend rebuild).

### Verify after deploy
```bash
D=https://<DOMAIN>                               # nip.io domain from .claude/deploy-record.md
curl -s $D/api/health                            # {"ok":true,"channels":[7,8]}
curl -s "$D/api/snapshot?channel=7" | python3 -c 'import sys,json;s=json.load(sys.stdin);print(s["record"]["delegateCount"])'
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H 'content-type: application/json' -d '{}' "$D/api/inter/send?channel=7"  # 500 = route OK
```

## Local relay (fast iteration, no AWS)
```bash
node hosting/wallet/wallet-relay.js   # https://localhost:8000/wallet-live.html  (channels 7,8)
```
- First launch only: starts anvil (Prague) + `forge script script/Deploy.s.sol` (2 rollups) +
  `channel_member setup-backing` per channel (~90s). Cached backing in `wallet-live-work/ch{7,8}/`
  makes later launches instant.
- Durable membership across restarts (RESET_CHANNELS=1 to wipe). Serves the SAME `wallet-live.html`
  + `pkg/` from the repo dir, so editing them + a browser reload is the dev loop.
- **The local relay is a long-lived node process** — it does NOT hot-reload `wallet-relay.js`; restart
  it after editing the relay or adding an `/api` route (a stale process is the classic "Cannot POST
  /api/inter/send" 404 even though the on-disk file has the route).

## Sepolia (one-time, when rollups/backing must be rebuilt)
```bash
export SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com    # or your own
PRIV=…/intmax3-zkp-enshrined-paymentchannel/.claude/priv
cd contracts && forge script script/Deploy.s.sol --rpc-url "$SEPOLIA_RPC_URL" \
  --private-key "$(cat "$PRIV")" --broadcast --slow                  # prints IntmaxRollup addr; run TWICE (ch7, ch8)
cd .. && mkdir -p deploy-staging/ch7 deploy-staging/ch8
( cd deploy-staging/ch7 && INTMAX_CHANNEL=7 INTMAX_DEPOSIT_KEY="$(cat "$PRIV")" \
    ../../target/release/channel_member setup-backing "$SEPOLIA_RPC_URL" <rollup7> )   # real Sepolia deposit + balance proof
( cd deploy-staging/ch8 && INTMAX_CHANNEL=8 INTMAX_DEPOSIT_KEY="$(cat "$PRIV")" \
    ../../target/release/channel_member setup-backing "$SEPOLIA_RPC_URL" <rollup8> )
# ship deploy-staging/ch{7,8}/{channel_backing.json,channel_attestation.bin,balance_vd.bin,tokens.json} → EC2 ~/relay/wallet-live-work/ch{7,8}/
```
- `INTMAX_CHANNEL` selects the channel; `INTMAX_DEPOSIT_KEY` is the funded deposit key (default = anvil
  dev key for local). EIP-170 is NOT a blocker: IntmaxRollup runtime ≈ 24,446 B (fits the 24,576 cap).

### ERC-20 token registration (multi-token §N-7) — AFTER the rollup deploy, BEFORE any ERC-20 deposit
The base `tokenIndex → ERC-20` registry is **set-once per index** (TM-10b) and `deposit()` reverts
for an unregistered nonzero index, so this runs between the `Deploy.s.sol` above and the first
ERC-20 deposit. Standalone — no existing deploy script runs it.
```bash
$EDITOR deploy-staging/ch7/tokens.json            # template: node/tokens.example.json
                                                  # `rollup` = the address just deployed, `chainId` = 11155111
cd contracts && TOKENS_MANIFEST=../deploy-staging/ch7/tokens.json \
  forge script script/RegisterTokens.s.sol --rpc-url "$SEPOLIA_RPC_URL" \
  --private-key "$(cat "$PRIV")" --broadcast --slow     # NEVER echo/print the key
cast call <rollup7> "tokenAddressOf(uint32)(address)" 5 --rpc-url "$SEPOLIA_RPC_URL"
```
- Idempotent: a re-run with the same manifest is a no-op. A manifest disagreeing with an
  already-set index **reverts** — set-once is never an "update" (a remappable index would turn
  token-A escrow into token-B withdrawals).
- **`tokens.json` ships alongside `channel_backing.json`** (see the scp line above) and the relay
  serves it at `GET /api/tokens?channel=N`.
- SECURITY: symbol/name/decimals carry **zero** authority — the base `token_index` does. The relay
  verifies every manifest entry against on-chain `tokenAddressOf` at startup and serves metadata
  ONLY for verified entries (otherwise `null`, and the wallet shows the raw index). A manifest that
  contradicts the chain makes the relay **refuse to start** — fix the file, never bypass the check.
  Full policy table: `node/DESIGN.md` §2.5.

### Testnet $ITX faucet (OPTIONAL) — AFTER the token registration above, AFTER `init`
New browser accounts join with balance 0. The faucet gives them an in-channel balance of a test
ERC-20 (`$ITX`) so they can immediately try a transfer. A designated CLI **faucet member** holds
the supply and the relay sends an ordinary in-channel transfer at the ITX token position — no new
protocol path. The supply is ONE real L1 deposit imported once, so the faucet **cannot mint**: it
can only run dry, and every dripped balance stays backed by `channel_fund` and stays claimable.

Full step-by-step (deploy → register → channel `register-token` → approve+deposit → import →
enable): **`doc/tasks/regen-and-redeploy-runbook.md` Step 3c**. Summary of what this box needs:

```bash
# systemd Environment= for the relay unit. ALL of these are required; anything missing or
# incoherent leaves the faucet OFF and POST /api/faucet answering 404.
FAUCET_ENABLED=1
FAUCET_SLOT=2                      # a CLI CO-SIGNING member slot (not 0, the BP/builder slot)
ITX_TOKEN_INDEX=1                  # the registered base index of $ITX — MUST be nonzero
FAUCET_DRIP=100000000              # 100 ITX per account (base units; $ITX has 6 decimals)
FAUCET_CHANNEL_CAP=100000000000    # 100,000 ITX total per channel
FAUCET_COOLDOWN_MS=5000
```
- `curl -s https://<host>/api/faucet` → `{"enabled":true,…}` / `{"enabled":false}`. The wallet
  hides the faucet notice + button entirely when it is off (no console noise, no broken UI).
- **In-channel balances are u64 base units** — a position tops out at `u64::MAX / 10**decimals`
  whole tokens. `$ITX` uses **6 decimals** so that ceiling is ~18.4 trillion (it would be ~18.44 at
  18). The relay refuses a drip or cap above the u64 ceiling at startup. The contract's `decimals`
  and the manifest's must agree: both relays and the node now read `decimals()` BACK from the token
  and **refuse to start on a mismatch** (an unreadable `decimals()` degrades to raw base units in
  the UI, never a guessed 18).
- SECURITY: the endpoint is public and hands out real escrowed value. It is off by default; one
  drip per balance slot **for ever** (recorded BEFORE the transfer, in
  `wallet-live-work/ch<N>/faucet_state.json`), plus a per-channel cap and a cooldown; the request
  body supplies ONLY the recipient slot, which is checked against the channel's own signed
  membership — but there is **no ownership proof** on it, so an anonymous caller can consume the
  channel allowance on behalf of other accounts (value still lands with the legitimate owners;
  residual risk R-1). **Deleting `faucet_state.json` re-opens the faucet to every account that
  already drank** — it is state, not cache. A corrupt ledger (including one that parses to `null`)
  fails closed (500) rather than resetting; writes are temp-file + atomic rename.
- **DEPLOYMENT INVARIANT: exactly ONE relay process per channel directory.** The per-channel mutex
  is in-process JS state, not a file lock — two processes sharing one work dir could double-drip.
  No clustering exists today; if that changes, the ledger needs a file lock first.
- $ITX lives at `contracts/test/tokens/IntmaxTestTokenITX.sol` — deliberately under `test/`,
  TESTNET-ONLY, 6 decimals, fixed supply, **no mint entry point at all** (asserted over the
  compiled ABI). Never reference it from `contracts/src/`.

## AWS infra (how it was provisioned — eu-north-1, account in deploy-record)
```bash
set -a; . ./.claude/.apikey; set +a
# AMI: aws ec2 describe-images --owners 099720109477 --filters Name=name,Values='ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*' ...
# keypair → .claude/aws/intmax-signer.pem ; SG opens 22(your IP) + 80/443(world) ; t4g.medium + 20GB gp3
# certbot --standalone -d <DOMAIN> (port 80) ; systemd unit intmax-relay (User=root, TLS_CERT/TLS_KEY env)
```
(SSM is denied; the AMI is found via describe-images. Tokyo/ap-northeast-1 is denied — the key is
eu-north-1-locked, so the Japan↔Stockholm latency is inherent.)

## Operational notes / invariants (do NOT regress)
- **§F-1 backing is anchored at GENESIS only** (`create_channel` uses `sign_state_if_backed`). Ongoing
  co-signs (`cmd_cosign`, `cmd_cosign_refresh`, `join_delegate`, `cosign-inter-transfer`) use plain
  N-of-N `sign_state`, because an inter-channel send legitimately ADVANCES `settled_tx_chain` (detail2
  §C-6) and a per-state exact-backing check would reject everything after the first inter-channel send.
  Reconciliation against the deposit is the close/settlement step. Do not re-add a per-state backing gate.
- **h2_tag must be 0 for §C-2 transitions** (intra send / refresh / join): `build_send`/`build_refresh`
  explicitly set `h2_tag = Bytes32::default()` (never inherit prev's, which an inter-channel send set to
  tx_tree_root). `build_inter_channel_send` sets `h2_tag = tx_tree_root`.
- **Inter-channel transfer is a SINGLE atomic command** `cosign-inter-transfer` (relay owns both
  channels). It debits A by extending A's COMMITTED on-disk head (+ records tx_hash in A's spent
  ledger) and credits B against that IN-PROCESS debit — NEVER a request-body signed state (that was the
  CRITICAL-1 value-creation hole, closed). Both legs persist or neither. There is exactly ONE relay
  endpoint `/api/inter/send`; do not reintroduce a standalone credit endpoint.
- **Witness vs decryption**: decryption needs only the secret key; PROVING a spend needs the
  encryption-randomness *witness* for the CURRENT ciphertext. A receive (homomorphic add) or a reload
  invalidates the witness → "refresh to send". The browser auto-refreshes before any send so the E-1/E-2
  proof matches the stored ciphertext. Losing the witness ≠ losing funds (refresh regenerates it from
  the secret key); only losing the secret key loses funds.

## Security boundaries (mandatory)
- NEVER read/print the Sepolia key (`.claude/priv` sibling) or AWS creds (`.claude/.apikey`). Hand them
  to local processes via `$(cat …)` / `set -a; . …` only. Derived addresses/account-ids are public.
- Any change to the inter-channel / co-sign / backing logic is security-critical: threat-model first,
  and run an INDEPENDENT (separate-from-implementer) adversarial review before deploy (that's how
  CRITICAL-1 was caught pre-deploy). See `doc/tasks/inter-channel-live.md` for the threat model + invariants.

## Live identifiers
→ `.claude/deploy-record.md` (gitignored): EC2 IP / instance id / SG / domain / live URL / Sepolia
rollup + deposit addresses / deployer address / key paths.
