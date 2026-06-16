# Sepolia + AWS deployment — two-channel payment-channel demo (DONE)

> Operational/server records (live URL, EC2 instance/IP/SG, on-chain addresses, key paths) are
> **gitignored** in `.claude/deploy-record.md` — not tracked here.

## Architecture (confirmed)
- **EC2-only hosting** (small instance): one box serves the static frontend AND the /api co-signing
  from a single origin over HTTPS, with COEP/COOP so the multi-threaded wasm proving works
  (SharedArrayBuffer needs a secure context + cross-origin isolation). TLS via a nip.io domain +
  Let's Encrypt. S3+CloudFront was abandoned (IAM has no CloudFront perms; S3 alone cannot set
  COEP/COOP, and the wasm is a shared-memory build).
- **Two channels (7 & 8)**, each its OWN IntmaxRollup on Sepolia → each deposit is first on its
  contract (prev hash 0, keystone simple).
- **cached backing + relay**: the heavy `setup-backing` (Sepolia deposit + ~4GB balance proof) runs
  LOCALLY; only the cached artifacts ship to EC2, which only co-signs (verified light: a real init
  co-sign returned a valid snapshot in 8s using ~210MB on the 4GB box).

## Code changes (tracked)
- `channel_member`: channel id from `INTMAX_CHANNEL` env; setup-backing deposit key from
  `INTMAX_DEPOSIT_KEY` env (default = anvil dev key) so a funded Sepolia key is handed to `cast` by
  the shell, never hardcoded.
- `wallet-relay-ec2.js`: EC2 host (frontend + /api, COEP/COOP, HTTPS via TLS_CERT/TLS_KEY env).
- `Dockerfile.signer` + `.dockerignore`: build the channel_member linux/arm64 binary locally
  (`.dockerignore` excludes `.claude` (secrets) + target/.git/worktrees).

## Status
- [x] Sepolia: 2 rollups deployed + 2 real deposits + cached backing (EIP-170 cleared: 24,446 B).
- [x] EC2: small box, frontend + signer over HTTPS, both channels served, verified server-side.
- [x] Real co-sign proving validated on the small box (8s, ~210MB).
- [ ] In-browser click-through (wasm thread init + a full join) — not auto-testable here (no
      connected browser); all server-side prerequisites are verified correct.
- [ ] Actual inter-channel SEND logic (`build_inter_channel_send` + wasm wrapper) — only the UI field
      exists so far.
