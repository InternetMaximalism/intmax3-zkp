# Sepolia + AWS deployment — two-channel payment-channel demo

## Decisions (confirmed by user)
- Frontend: **S3 + CloudFront** (CloudFront response-headers-policy injects COEP/COOP so the
  multi-threaded wasm proving works — plain S3 cannot set those headers).
- EC2 signer: **cached backing + relay** — the heavy `setup-backing` (~4GB balance proof) runs
  LOCALLY (this Mac) against Sepolia; only the cached artifacts ship to EC2, which co-signs only.
- Two channels: **7 and 8**, each its OWN IntmaxRollup on Sepolia (each deposit is first on its
  contract → prev hash 0, keystone stays simple).

## Prereqs (DONE)
- [x] Sepolia deployer key: `…/intmax3-zkp-enshrined-paymentchannel/.claude/priv` (funded 2.45 ETH,
      gitignored, contents NEVER read — handed to forge/cast via shell `$(cat …)` only).
      Address `0x2C0BF10558adafDd21296CbF71dd6FE88c782C80`.
- [x] Sepolia RPC: `https://ethereum-sepolia-rpc.publicnode.com` (verified).
- [x] AWS: account 992382759484 / user s3-ec2-eu-north-1 / region eu-north-1 (S3+EC2 scoped).
- [x] EIP-170 cleared: IntmaxRollup runtime 24,446 B (130 B margin) — fits Sepolia.

## Phase 1 — Sepolia deploy (2 rollups)
- [ ] Deploy IntmaxRollup #1 (channel 7) to Sepolia; record address.
- [ ] Deploy IntmaxRollup #2 (channel 8) to Sepolia; record address.

## Phase 2 — Local cached backing against Sepolia
- [ ] `setup-backing` ch7 vs rollup#1 over the Sepolia RPC (REAL Sepolia ETH deposit).
- [ ] `setup-backing` ch8 vs rollup#2 over the Sepolia RPC (REAL Sepolia ETH deposit).
- [ ] Verify on-chain depositHashChain == Rust Deposit hash for both (keystone).

## Phase 3 — EC2 relay (signer)
- [ ] Provision EC2 (eu-north-1). Sizing: build needs RAM; run (cosign) lighter.
- [ ] Build channel_member on EC2 (or ship a linux binary). Ship cached backing.
- [ ] Run relay; expose over HTTPS reachable from the browser.

## Phase 4 — S3 + CloudFront frontend
- [ ] Build wasm (release). Upload wallet-live.html + pkg + worker to S3.
- [ ] CloudFront distribution + response-headers-policy (COEP/COOP). Point relay URL at EC2.

## Phase 5 — Wire + verify
- [ ] Frontend → EC2 relay; join channel 7 and 8; confirm a real send end-to-end.

## Notes / risks
- EC2 build RAM vs "small instance" wish: building this Rust stack needs a mid-size box; may build
  on a larger instance (one-time) then downsize, or keep mid-size.
- EC2 HTTPS cert reachable from the browser (CloudFront origin or domain+cert) — TBD in Phase 3.
