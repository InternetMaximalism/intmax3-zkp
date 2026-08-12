# Phase 0 notes — Falcon-512/Poseidon native primitive (vendor + sign/verify)

Status: implemented, all checks green, NOT committed (awaiting separate security review per
plan). Branch `feat/falcon-poseidon-sig`. Implements exactly the Phase 0 checklist of
`falcon-sig-todo.md` under the threat model `falcon-sig-threat-model.md`.

## What was built

New standalone module `src/falcon_sig/` (nothing wired into existing consumers; `poseidon_sig`
and all other existing code untouched):

- `src/falcon_sig/vendor/` — Falcon-512 core vendored from `0xMiden/crypto`
  (`miden-crypto/src/dsa/falcon512_poseidon2`), upstream commit
  **`475092a8476bf4c806424579e5d9225b12941c1a`** (main HEAD 2026-08-05), MIT license text at
  `vendor/LICENSE-MIT`, full provenance + per-file modification list in `vendor/README.md`.
  - Pristine-copy fidelity check (O-4) done BEFORE modification:
    `cargo test -p miden-crypto --release falcon512_poseidon2` on the pristine clone —
    **10/10 passed**, including the reference-implementation KAT
    (`test_signature_gen_reference_impl`) that pins the Gaussian sampler/FFT byte-for-byte
    against `falcon.py` `sign_KAT` vectors.
  - `math/fft.rs`, `math/field.rs`: byte-identical. `samplerz.rs` (3 lines), `math/mod.rs`
    (4), `ffsampling.rs` (11), `polynomial.rs` (27): import-line edits only. The sampler and
    keygen MATH is untouched. `src/falcon_sig/vendor` added to `rustfmt.toml ignore` so it
    stays diffable against upstream (TM-C3 CI-diff obligation).
- `src/falcon_sig/compat.rs` — the single type-adaptation seam: `Felt` = plonky2
  `GoldilocksField` (same prime), `Word` = `Bytes32`, minimal re-implementations of the Miden
  serialization traits, re-export of the audited `zeroize` crate. No cryptographic logic.
- `vendor/hash_to_point.rs` — **the one intentional functional change** (TM-C1/O-1): plonky2
  Poseidon (width 12, rate 8), capacity initialized `[IMFH, 0, 0, 0]`; absorb salt (8 elements
  of 5 LE bytes — injective, canonical), then the digest's 8 canonical u32 limbs
  (`Bytes32::to_u32_vec`, the repo-wide IMCH limb convention); 64-permutation squeeze, ONE full
  element per coefficient reduced mod q, never split/reused (bias ≈ 2^-50/coeff ≈ 2^-41 total,
  A-F3) — layout and bias argument documented in-file for the Phase-1 in-circuit mirror (O-2).
- `src/falcon_sig/mod.rs` — public API:
  - Domains (ASCII-tag u32s, non-collision pinned by test): `IMFH` 0x494d4648 (H2P capacity),
    `IMFK` 0x494d464b (pk digest), `IMFG` 0x494d4647 (keygen seed derivation).
  - `FalconKeys::from_seed([u8;32])` (O-11): ChaCha20Rng seeded with
    `keccak256("IMFG" || seed)` driving the vendored `ntru_gen` — domain-separated from any
    other member-seed use; deterministic (tested with two fresh derivations).
  - `pk_g = falcon_pk_digest(h) = Poseidon(IMFK || encode(h))`, `encode(h)` = 4 coefficients ×
    14-bit lanes per Goldilocks element (128 elements, each < 2^56 — canonical and
    circuit-friendly: linear-combination + 14-bit range checks in Phase 1), hashed via the same
    `PoseidonHashOut::hash_inputs_u64([domain, ...])` → `Bytes32` construction as today's
    `pk_g` (drop-in for Phase 4).
  - `FalconKeys::sign(digest)`: 40-byte salt from OS CSPRNG (`SysRng`/getrandom), sampled once
    OUTSIDE the retry loop; ffSampling randomness from the same OS CSPRNG; `// SECURITY:`
    comments at both RNG sites (TM-C2/O-3). Retry loop covers the negligible case of an s2 that
    overflows the padded encoding (Falcon padded-format rule; upstream would panic).
  - Wire (DD-4/O-9): `0x01 || salt(40) || compressed s2 (625, zero-padded)` = exactly
    **666 bytes**. `from_bytes` checks the version byte FIRST (distinct
    `UnsupportedVersion` error), then exact length, then the canonical s2 decode.
  - `verify(pk_h: &[u16;512], digest, sig)`: rejects any `h` coefficient ≥ q (canonicity
    gate), recomputes c via the new H2P, `s1 = c − s2·h` via exact NTT, accepts iff
    `‖(s1,s2)‖² ≤ 34_034_726`.
- 10 new tests (13 total with the 3 vendored upstream math tests) (all release-gated per repo convention, each documenting what it proves about
  security): domain non-collision (vs the full pinned registry), round-trip + wire identity,
  salt freshness (fails loudly on constant salt), keygen determinism/separation, tamper suite
  (salt/s2/digest/pk), version gate + 76 KB legacy-blob rejection (no panic), norm boundary at
  exactly β² (accept) and β²+1 (reject), H2P determinism + 16-bucket histogram smoke test,
  pk-encoding canonicity (incl. the sharp mod-q-equivalent `h[0]+q` case), bench. Plus the 3
  vendored upstream in-file math tests now running in-tree.

## Tree changes outside `src/falcon_sig/`

- `Cargo.toml`: added `rand_chacha010` (rand_chacha 0.10), `zeroize`, `subtle`, `num-complex`
  — all already present transitively; declared as direct deps of the vendored code.
- `Cargo.lock`: the 4 corresponding direct-dependency edges (no version changes).
- `src/lib.rs`: `pub mod falcon_sig;` + `extern crate alloc;` (vendored code imports via
  `alloc::` paths).
- `rustfmt.toml`: `ignore = ["src/falcon_sig/vendor"]` (keeps vendor diffable; see TM-C3).
- Nothing else. No existing test was modified.

## Verification results (2026-08-05, Apple Silicon, release)

- `cargo test --release -p intmax3-zkp --lib falcon_sig`: **13 passed, 0 failed**.
- `cargo clippy --release --lib --tests`: **zero findings in `src/falcon_sig`** (remaining
  warnings are pre-existing in untouched files).
- `cargo check --target wasm32-unknown-unknown --lib`: green (getrandom wasm backends already
  configured by the repo's existing `wasm_js` setup; `SysRng` rides getrandom 0.4).
- `cargo build --release` (full tree incl. all bins): green.
- `cargo fmt` run; vendor dir exempted (see below).

## Bench numbers (Phase 0 deliverable)

`falcon_sig bench (native, release)` on this machine (M-series):

- **keygen: ~455 ms** (per-seed samples 468 / 469 / 533 ms — NTRU keygen with retries)
- **sign: ~5.4 ms/op** (20 iters)
- **verify: ~0.063 ms/op** (20 iters)

Notes vs the plan's estimates: keygen is ~10x the threat model's 10–50 ms guess and sign ~5x
the ~1 ms guess — this is the upstream pure-Rust implementation (BigInt `ntru_solve`, f64 FFT
ffSampling), not a bug. TM-C10's requirement (keygen at join/restore only, never per
signature) still holds comfortably; flagging the numbers for the Phase-1/owner sizing
discussion. wasm32 bench not run (no wasm test runner in Phase 0 scope; wasm32 build-check
green — cross-platform keygen-determinism testing is an O-11 item listed for later phases).

## Security-relevant findings during implementation

1. **Wire-encoding malleability (found by the tamper test, fixed).** The vendored
   `SignaturePoly` decoder checks coefficient canonicity and the unused bits of the last
   CONSUMED byte, but never inspects the zero-padding bytes after the compressed prefix —
   flipping a padding byte produced a different 666-byte string that decoded to the same
   signature and verified. Since signature BYTES feed keccak digests downstream
   (`SignedSmallBlock::signing_digest`), the wire format must be a bijection.
   Handled per CLAUDE.md §5 (security-first): `FalconSignature::from_bytes` now re-encodes the
   decoded s2 and requires byte equality, so exactly one byte string decodes to any
   (salt, s2). The upstream reference Falcon implementation requires zero padding explicitly;
   upstream miden does not — worth an upstream report.
2. **Upstream norm-bound off-by-one.** Upstream `verify_helper` accepts strictly
   `norm² < β²` while its own signing loop retries only on `norm² > β²` — upstream sign can
   emit a (measure-zero) signature its own verifier rejects. The threat model mandates
   `≤ β²` (matching the Falcon reference). Resolution: the vendored verifier is REMOVED
   entirely (single canonical verifier `falcon_sig::verify` with `≤`), avoiding two
   subtly-different verifiers in tree. Boundary pinned by test at β² / β²+1.
3. **Deterministic-signing machinery removed, not just unused** (TM-C2): upstream HEAD is a
   det-Falcon variant (fixed nonce + Blake3-derandomized sampler). All of it
   (`Nonce::deterministic`, fixed-nonce serde that silently fabricates salt bytes,
   `sign`/`generate_seed`) is deleted from the vendor copy so no reachable fixed-salt path
   exists.

## Deviations from the brief (with justification)

- **D-1 Salt packing**: brief suggested absorbing the 40-byte salt "as 5 u64 field elements".
  5×u64 requires mod-p reduction (non-injective, ~2^-32 collision slack per element). Used
  upstream's packing instead — 8 elements of 5 LE bytes each (< 2^40): injective, canonical,
  and identical to the vendored `Nonce::to_elements`, minimizing vendor diff. Total absorbed
  input = 8 salt + 8 digest limbs = exactly two rate-8 blocks. Documented in
  `vendor/hash_to_point.rs`.
- **D-2 Upstream structure vs brief**: upstream HEAD turned out to be the DETERMINISTIC
  variant (see finding 3) and its verifier uses `<` (finding 2); the brief's randomized-salt
  and ≤-bound requirements were implemented by removing/replacing those specific upstream
  parts, each listed in `vendor/README.md`. Not a STOP: the sampler/keygen/FFT the survey
  cared about are isolated exactly as claimed, and `hash_to_point.rs` is cleanly isolated.
- **D-3 `sign_with_rng` signature change**: one extra mechanical vendor edit beyond imports —
  it takes the caller-supplied `Nonce` (upstream hard-coded the fixed nonce). Required by the
  randomized-salt policy; the ffSampling call path is unchanged.
- **D-4 `keys` / `signature` / `mod` vendor files carry structural removals** (verifier,
  1524-byte serde, Miden pk commitment, det-nonce): all removals (no rewritten crypto), each
  listed with reasons in `vendor/README.md`. The alternative (keeping them dormant behind the
  compat layer) would have left a second verifier and a fixed-salt constructor in tree.
- **D-5 Vendored in-file upstream tests are not release-gated**: the 3 surviving math tests
  (samplerz KAT, LDL decomposition, negacyclic reduction) keep upstream form (no
  `cfg_attr(debug_assertions, ignore)`), i.e. they also run in debug — they are fast pure-math
  tests and adding the attribute would add vendor diff. Every NEW test follows the repo
  convention.
- **D-6 `cargo fmt` scope**: repo-wide `cargo fmt` also reformats the pre-existing
  unformatted `tests/itx_faucet_cli_e2e.rs`; that churn was reverted to keep the existing
  suite untouched. `rustfmt.toml` gained the vendor `ignore` entry.
- **D-7 `falcon_pk_digest` panics on non-canonical input** (assert) instead of returning an
  error: it is only reachable with key-derived (canonical-by-construction) coefficients;
  untrusted encodings enter through `verify`, which rejects gracefully. Chosen to keep the
  Phase-4 drop-in signature identical to today's `pk_g` producer. No `#[should_panic]` test
  (profile sets `panic = "abort"`); the verify-side rejection carries the test coverage.

## Open items handed to later phases

- Merge IMFH/IMFK/IMFG into the `constants.rs` domain registry (Phase 2; a local pinned-list
  non-collision test covers the gap) and register in detail2 §G-2.
- O-2 shared-vector tests native ↔ in-circuit H2P (Phase 1; the native side exports
  `hash_to_point_poseidon` + `Nonce` for exactly this).
- Cross-platform (native vs wasm32) keygen determinism test (O-11).
- Report the padding-malleability laxity upstream (finding 1).
- Keygen/sign wasm bench once a wasm test harness exists.

## Post-review hardening (2026-08-05, applied by the orchestrator after independent review)

Review verdict was NOT-FIT solely on F-1; all three findings are now addressed:

- **F-1 (MAJOR, fixed)**: the vendored s2 decoder (`vendor/signature.rs`, Algorithm-18 loop)
  indexed the 625-byte buffer unguarded; a valid-version, valid-length blob with long unary runs
  ran past the end — under `panic = "abort"` a remote process-kill (~10% of RANDOM 666-byte v1
  blobs). Two bounds checks now fail closed with `DeserializationError::UnexpectedEof`.
  Regression: `malformed_wire_blobs_error_instead_of_panicking` (exact repro + 2000-blob
  deterministic fuzz through the shipped `from_bytes`). Upstream miden has the same bug —
  report upstream alongside the padding-laxity finding.
- **F-2 (MINOR, fixed)**: added `verify_with_pk_g` — the consumer-facing entry point that checks
  `falcon_pk_digest(h) == pk_g` INSIDE the call; Phases 2/4 must use it (`verify` stays public
  for gadget-mirror tests). Test: `verify_with_pk_g_binds_identity`.
- **F-3 (MINOR, fixed)**: `sign` now self-verifies before returning (~64 us vs ~5.4 ms). Closes
  the pre-rounding-float vs post-rounding-integer norm divergence inherited from upstream and
  blunts the TM-C4 fault residual.
- Review §4 gap: `zero_s2_never_verifies` (canonical zero-polynomial encoding decodes, never
  verifies). Review §9c gap: `h2p_and_pk_digest_pinned_vectors` pins H2P prefix/suffix/fold and
  a from_seed pk_g as fixed anchors for the Phase-1 in-circuit mirror (O-2).

Module suite after hardening: 17 passed / 0 failed (release).
