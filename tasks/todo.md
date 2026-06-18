# Phase B (Option D) — real verifyWithdrawalClaim / verifyPostCloseClaim

Authoritative spec: tasks/phase-b-claims-threat-model.md (DECISION = Option D).
Template: Phase A (tasks/close-verifier-a1-plan.md), mirrored exactly.

SCOPE: prove the NON-decryption bindings as two NEW plonky2 binding circuits, MLE/WHIR-wrapped on
the @mle rail, replacing the two `_matches` stubs. NO Regev decryption (deferred sub-phase).

## RESIDUAL (DOCUMENT LOUDLY — not silently)
- Over-claim is NOT closed: `amount` is a range-checked u64 PI, NOT bound to the plaintext of the
  slot/delta ciphertext. A member/receiver can still claim more than their ciphertext holds,
  bounded only by on-chain `totalWithdrawn <= finalizedChannelFundAmount` + the authoritative
  `receivedChannelFunds` ETH ceiling. Closing this requires the decryption sub-phase.

## Hazard #8 decision: BIND (safe option)
Evidence: `PostCloseIncomingClaim.shared_native_nullifier` (the CLAIM field) is DISTINCT from the
channel-state `shared_native_nullifier_root` (a settle hash-chain). The claim field is
free-standing — `e2e_flow.rs:878` sets it to an arbitrary placeholder `bytes32_word(801)`; nothing
in `to_public_inputs` validates it against any tree, and the only consumer is the manager's
`usedSharedNativeNullifiers` double-claim key. Today it is attacker-chosen → a malicious claimant
can pick a fresh nullifier to double-claim the SAME tx. Therefore deriving it in-circuit from
`keccak([IMCK=0x494d434b] ++ close_intent_digest(8) ++ incoming_tx_hash(8) ++ receiver_pk_g(8))`
(mirroring the withdrawal nullifier) is the SAFE, correct fix. Manager must RECOMPUTE the same
value. New native helper `PostCloseIncomingClaim::derive_shared_native_nullifier`.

## Plan / falsifiable checklist
- [ ] h1_gadget.rs: extract close H1 keccak recompute; call from BOTH close + withdrawal circuits.
- [ ] channel.rs: add `PostCloseIncomingClaim::derive_shared_native_nullifier` (IMCK).
- [ ] withdrawal_claim_circuit.rs: 48-limb PI; H1 recompute; one-hot slot select; member_index <
      member_count+delegate_count; user_amount_digest == enc[member_index]; derive nullifier; amount u64.
- [ ] post_close_claim_circuit.rs: 40-limb PI; receiver-delta inclusion; tx_hash bind; derive #8 nullifier.
- [ ] Golden-vector Rust tests pinning to_u64_vec() to Solidity _expected*Limbs.
- [ ] Fixture bins + feature gates.
- [ ] Solidity per-statement VKs, _expected*Limbs, strict bind, rewrite verify*, remove their _matches.
- [ ] Manager: verify* take MleProof; recompute shared_native_nullifier.
- [ ] Tests: positives + negatives + golden vectors + double-claim. cargo check, forge build, EIP-170.

## Outcome (DONE)
- Two new plonky2 binding circuits implemented + MLE/WHIR-wrapped on the @mle rail; the two
  tautological _matches stubs removed and replaced with strict-limb-bind + MleVerifier.verify.
- Hazard #8: BOUND (safe option). Evidence: PostCloseIncomingClaim.shared_native_nullifier is the
  CLAIM field, DISTINCT from the channel-state shared_native_nullifier_root tree; it is free-standing
  (e2e_flow.rs:878 placeholder, no derivation/equality anywhere, only the manager double-claim key).
  Derived in-circuit + natively + in the manager from keccak(IMCK ++ close_intent_digest ++
  incoming_tx_hash ++ receiver_pk_g). Manager RECOMPUTES (struct field removed).
- H1 gadget SHARED (h1_gadget.rs) by close + withdrawal circuits; close circuit still proves (n2 ✓).
- EIP-170: ChannelSettlementVerifier runtime = 19,218 B (< 24,576; no split).
- Adversarial review (separate agent): CLEAN, no blocking issues. Added defense-in-depth in-circuit
  `active <= MAX_CHANNEL_MEMBERS` range-check (O1) + comment clarifications (O2).
- RESIDUAL stands: over-claim (amount-vs-decryption) NOT closed — deferred decryption sub-phase.
- Tests: Rust 5 wclaim + 4 pcclaim circuit tests, 3 golden vectors pass; Solidity 55 manager+verifier
  (Phase B-D negatives + double-claim + golden vectors) pass; full forge suite 122 pass / 1 skip.
- USER must run (heavy proving) to generate fixtures:
    cargo run --release --features withdrawal-claim-fixture-bin --bin generate_withdrawal_claim_fixture
    cargo run --release --features post-close-claim-fixture-bin --bin generate_post_close_claim_fixture

---

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
