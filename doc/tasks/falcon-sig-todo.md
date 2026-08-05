# Plan: Falcon-512/Poseidon unified signing key (replaces sk_g everywhere)

Branch `feat/falcon-poseidon-sig`. Threat model: `falcon-sig-threat-model.md` (TM-C1..C11,
obligations O-1..O-11). Status: APPROVED (owner, 2026-08-05; DD-1..DD-4 confirmed, DD-1 under MIT). Goal: Falcon replaces the plonky2-proof signature; aggregation stays plonky2 as usual; on-chain MLE verification unchanged. Workflow per CLAUDE.md: each
phase = implementer subagent + separate security-review subagent; attacker pass before merge.

## Design decisions to confirm with owner

- **DD-1 Vendor source**: fork `0xMiden/crypto` `falcon512_poseidon2` (MIT/Apache-2.0, pure
  Rust, no_std/wasm-ready, deterministic-capable keygen), swapping ONLY `hash_to_point.rs` to
  the in-tree plonky2 Poseidon. Alternative (stronger constant-time story, more surgery):
  Pornin `rust-fn-dsa`. **Recommended: Miden fork.**
- **DD-2 Member identity (revised: unified)**: `pk_g` REDEFINED in place as
  `Poseidon(IMFK‖encode(h))`. No new field; `MemberLeaf` stays 3 fields; registration keccak,
  member-set commitment, IMLL chain, Solidity `bytes32 pkG` all layout-stable. One signing key
  per member, signing both IMCH and IMSB with message-domain isolation (as sk_g does today).
  All fixtures regenerate (values change).
- **DD-3 Salt policy**: randomized 40-byte CSPRNG salt (not deterministic signing).
- **DD-4 Signature wire format**: version byte ‖ salt(40) ‖ compressed s2 (Falcon standard
  Golomb-Rice, ~625 B) — total ~666 B. Circuit witnesses uncompressed s2; native verifier
  decompresses.

## Phase 0 — Vendor + native primitive — DONE (commit 395b0d9; review NOT-FIT->FIT after F-1 bounds fix, F-2 verify_with_pk_g, F-3 sign self-verify; bench keygen 455ms/sign 5.4ms/verify 63us; notes in falcon-sig-phase0-notes.md)
- [x] Vendor `falcon512_poseidon2` under `src/falcon_sig/vendor/` with upstream commit pinned;
      pristine-copy upstream tests green BEFORE the H2P swap (O-4)
- [x] Swap `hash_to_point.rs` to plonky2 Poseidon, domain IMFH, full-element sampling (O-1)
- [x] `pk_f = Poseidon(IMFK‖encode(h))`; canonical `encode(h)` documented
- [x] Seed-deterministic keygen from `MemberKeys` seed (O-11) + determinism tests
- [x] Native sign/verify + wire encode/decode (DD-4, format byte, O-9)
- [x] Salt-freshness CI test (O-3); norm-distribution sanity; bench (sign/verify/keygen,
      native + wasm32)
- [x] Security review (separate subagent)

## Phase 1 — In-circuit Falcon verifier gadget (plonky2) — DONE
Review: FIT to commit, no CRITICAL/MAJOR, no forgery path found. Measured (release,
standard_recursion_config, reproduced by the orchestrator): N=1 51,734 gates / 2^16 /
prove 2.2s; N=3 155,198 / 2^18 / 8.9s; N=16 827,720 / 2^20 / 59s. ~51.7k gates per
signature, NTT range checks dominant; 16 sigs fit 2^20 with 27% slack, NO config change.
Findings addressed here: INFO-1 (the naive-quotient non-uniqueness range is ~half the
field, not x<5287 — comment corrected), MINOR-1 (norm no-wrap ledger now pins the
ADVERSARIAL max 1024*q^2 < 2^38, not the honest 1024*6144^2), INFO-2 (centering-bit
monotonicity now has an empirical adversarial probe), INFO-3 (quotient-cheat test extended
to every instantiated width 1/14/15/32). Suite 33/33.
- [x] H2P in-circuit (64 Poseidon perms, native gates) pinned to native by shared vectors (O-2)
- [x] NTT mod 12289 gadget with range-checked reductions; s2 canonicity; norm bound at β²/β²+1
      (TM-C5 items 1–3)
- [x] `h` opening → pk_f connection (TM-C5 item 5)
- [x] Standalone `FalconSigCircuit` harness proving 1..N=16 verifications; **measure gates +
      proving time** (the number the owner asked for — report before Phase 2)
- [x] Full O-5 adversarial test suite
- [x] Security review (separate subagent)

## Phase 2 — Close + cancel-close rewiring
- [ ] **Carried from Phase-1 review (MINOR-2, TM-C5)**: the gadget's accept set is strictly
      LARGER than "native wire-decodable signature" — it accepts any canonical `s2` residue
      meeting the equation + norm bound, while `FalconSignature::from_bytes` additionally
      restricts `s2` to the Golomb-Rice transport band `[-2047, 2047]` (a norm-feasible
      coefficient can reach |centered| <= 5833). NOT a forgery vector (GPV unforgeability is the
      norm bound, and beta is unchanged), but confirm NO consumer relies on
      "circuit-accepted => native-wire-decodable" — in particular any path that re-serializes a
      signature or cross-checks it against `from_bytes`. Decide and record; do not inherit it
      silently.
- [ ] **Carried from Phase-1 (TM-C5 item 4)**: `FalconSigVerifyTarget.message_digest` is a free
      INPUT; consumers MUST connect it to an in-circuit-RECOMPUTED IMCH/IMSB digest. Phase 1
      documents the obligation on the field itself; Phase 2 discharges it.
- [ ] Replace `agg_vd` recursive verify with direct N-sig verification; delete
      `AggLevelCircuit`/`SigAggregator`
- [ ] Padding + A5 arguments re-written at their new sites; member-set commitment domain
      decision recorded (TM-C7); Rust↔Solidity shared-vector re-pin
- [ ] Cross-scheme rejection tests (O-6, O-9)
- [ ] Security review + attacker pass on the circuit changes

## Phase 3 — Validity path (list step swap)
- [ ] `ListCircuit` leaf: recursive SingleSig verify → in-circuit Falcon verify (chain format,
      `list_leaf`/`chain_step_target`, `bp_sig_chain` accumulator all unchanged)
- [ ] `ValidityCircuit` re-pins the new list VK; conditional-verify gate unchanged
- [ ] IMCH↔IMSB cross-context rejection tests under the single key (O-6)
- [ ] Delete `SingleSigCircuit` + the old primitive (`poseidon_sig` reduced to the shared
      chain gadgets); grep proves 0 active refs
- [ ] Security review

## Phase 4 — Wallet/CLI/wasm/node swap
- [ ] `MemberKeys` single Falcon signing key from seed (O-11);
      `sign_state`/`verify_state_sig`/`verify_all_signatures` → Falcon native (O-9 downgrade
      rejection incl. valid-old-proof-rejected test)
- [ ] wasm exports unchanged in shape; browser signs in ~ms (no plonky2 proving for cosign)
- [ ] CLI `channel_member.rs` key handling incl. bp/IMSB signing; relay; node tests' size
      premises fixed (O-10)
- [ ] Solidity: registration values (layout unchanged); Foundry green; EIP-170 margin

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
