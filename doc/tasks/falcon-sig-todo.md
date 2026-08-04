# Plan: Falcon-512/Poseidon cosigner signatures

Branch `feat/falcon-poseidon-sig`. Threat model: `falcon-sig-threat-model.md` (TM-C1..C11,
obligations O-1..O-11). Status: DRAFT — awaiting owner approval. Workflow per CLAUDE.md: each
phase = implementer subagent + separate security-review subagent; attacker pass before merge.

## Design decisions to confirm with owner

- **DD-1 Vendor source**: fork `0xMiden/crypto` `falcon512_poseidon2` (MIT/Apache-2.0, pure
  Rust, no_std/wasm-ready, deterministic-capable keygen), swapping ONLY `hash_to_point.rs` to
  the in-tree plonky2 Poseidon. Alternative (stronger constant-time story, more surgery):
  Pornin `rust-fn-dsa`. **Recommended: Miden fork.**
- **DD-2 Member identity**: add `pk_f` as a 4th field of `MemberLeaf` + registration keccak
  preimage (`pk_g‖pk_b‖pk_f‖regev‖recipient`); member-set commitment for close/cancel-close
  switches to pk_f under new domain IMC2. pk_g stays (bp path). Invalidates all
  registration-bearing fixtures (accepted; v3 resets).
- **DD-3 Salt policy**: randomized 40-byte CSPRNG salt (not deterministic signing).
- **DD-4 Signature wire format**: version byte ‖ salt(40) ‖ compressed s2 (Falcon standard
  Golomb-Rice, ~625 B) — total ~666 B. Circuit witnesses uncompressed s2; native verifier
  decompresses.

## Phase 0 — Vendor + native primitive
- [ ] Vendor `falcon512_poseidon2` under `src/falcon_sig/vendor/` with upstream commit pinned;
      pristine-copy upstream tests green BEFORE the H2P swap (O-4)
- [ ] Swap `hash_to_point.rs` to plonky2 Poseidon, domain IMFH, full-element sampling (O-1)
- [ ] `pk_f = Poseidon(IMFK‖encode(h))`; canonical `encode(h)` documented
- [ ] Seed-deterministic keygen from `MemberKeys` seed (O-11) + determinism tests
- [ ] Native sign/verify + wire encode/decode (DD-4, format byte, O-9)
- [ ] Salt-freshness CI test (O-3); norm-distribution sanity; bench (sign/verify/keygen,
      native + wasm32)
- [ ] Security review (separate subagent)

## Phase 1 — In-circuit Falcon verifier gadget (plonky2)
- [ ] H2P in-circuit (64 Poseidon perms, native gates) pinned to native by shared vectors (O-2)
- [ ] NTT mod 12289 gadget with range-checked reductions; s2 canonicity; norm bound at β²/β²+1
      (TM-C5 items 1–3)
- [ ] `h` opening → pk_f connection (TM-C5 item 5)
- [ ] Standalone `FalconSigCircuit` harness proving 1..N=16 verifications; **measure gates +
      proving time** (the number the owner asked for — report before Phase 2)
- [ ] Full O-5 adversarial test suite
- [ ] Security review (separate subagent)

## Phase 2 — Close + cancel-close rewiring
- [ ] Replace `agg_vd` recursive verify with direct N-sig verification; delete
      `AggLevelCircuit`/`SigAggregator` (keep `SingleSigCircuit`/`ListCircuit` — validity)
- [ ] Member-set commitment → pk_f/IMC2; A5 distinctness re-argued; padding argument re-written
      (O-8); Rust↔Solidity shared-vector re-pin
- [ ] Close/cancel-close PI layout unchanged where possible; enumerate VK ripple
- [ ] Cross-scheme rejection tests (O-6)
- [ ] Security review + attacker pass on the circuit changes

## Phase 3 — Identity & registration
- [ ] `MemberLeaf` + registration preimage gain pk_f (DD-2); Solidity registration +
      `registeredMemberSetCommitment` over pk_f; `channelBpPkG` untouched
- [ ] A11 three-way mismatched-pair rejection tests (O-7)
- [ ] Foundry suite green; EIP-170 margin re-checked

## Phase 4 — Wallet/CLI/wasm/node swap
- [ ] `sign_state`/`verify_state_sig`/`verify_all_signatures` → Falcon native (O-9 downgrade
      rejection incl. valid-old-proof-rejected test)
- [ ] wasm exports unchanged in shape; browser signs in ~ms (no plonky2 proving for cosign)
- [ ] CLI `channel_member.rs` key handling; relay; node tests' size premises fixed (O-10)
- [ ] Wallet wire field naming decision executed (TM-C9)

## Phase 5 — Fixtures, e2e, deploy prep
- [ ] Enumerate (do not assume) fixture regen set; regenerate; semantic validation
- [ ] `cargo test --release` full + `--test e2e`; forge full suite; wasm32 lib check
- [ ] detail2.md §G-2 domain table (IMFH/IMFK/IMC2; IMCM retired) + spec section for the scheme
- [ ] Integrated attacker pass (CLAUDE.md) before merge; v3 reset/redeploy is a separate owner
      decision

## Measured facts feeding this plan
- Poseidon perm (pinned plonky2, native M-series): 738 ns. H2P = 64 perms ≈ 47 µs native.
- Current cosign wire: 3 × 277,620 B JSON (76 KB binary each). Falcon: ~666 B each.
- keccak-in-circuit rides the hook→STARK path (measured 0 builder gates); close already pays
  the recursive-verify fixed cost.
