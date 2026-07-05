# Lessons — browser wallet for in-channel send/receive

## Feasibility (Phase 0)
- **regev_plonky3 STARK runs fine in wasm** under `wasm-bindgen-rayon`. Its `init_thread_pool`
  (`std::env`, `available_parallelism`, `rayon::ThreadPoolBuilder::build_global()`) is harmless on
  wasm: env→None, available_parallelism→Err→4, and `build_global()` fails harmlessly because
  wasm-bindgen-rayon already built the global pool first. **No patch to regev_plonky3 was needed.**
  Verified by an actual headless run: E-1 prove+verify, 14 threads, 30 KB proof, 34 ms (Test level).
- **getrandom version split:** `rand010` (rand 0.10) pulls **getrandom 0.4**, whose wasm support is a
  Cargo *feature* (`wasm_js`), NOT the `getrandom_backend="wasm_js"` cfg used by getrandom 0.3. The
  global cfg in `.cargo/config.toml` is harmless to 0.4 (build.rs ignores it; the cfg value isn't a
  valid 0.4 backend so it falls through to the wasm32 target branch). Fix: enable getrandom 0.4's
  `wasm_js` feature for wasm only (target-scoped renamed dep in Cargo.toml).
- **`crate-type = ["cdylib","rlib"]` breaks native bin linking** (undefined-symbol errors in
  src/bin/*) — the documented E0463-class collision. Keep `["rlib"]` and build wasm via
  `cargo rustc --crate-type cdylib` + `wasm-bindgen` (see `hosting/build-wallet-wasm.sh`); wasm-pack can't
  do this because it pre-checks the manifest for cdylib.
- **`wasm_demo.rs` is already broken on this branch** (calls `*_async` methods removed in the
  SIS→Regev migration; missing generated fixtures). Gated behind off-by-default `legacy_wasm_demo`.
- `MAX_NUM_CHANNELS = 1usize << 32` overflows wasm32's 32-bit `usize`; widened to `u64` (unused
  const, value-preserving on native).
- **Crypto perf: build the CLI in `--release`.** Debug SPHINCS+ keygen/sign and (especially) the
  Production STARK proof are orders of magnitude slower; a debug e2e effectively hangs.

## Protocol / design
- **Witness staleness:** to SEND, a member needs the `AmountWitness` for its current balance
  ciphertext (held since it freshly encrypted it). After RECEIVING (homomorphic add), the slot is a
  sum with no reproducible witness → a balance refresh (detail2 §B-3) is required before sending
  again. The MVP does not implement refresh, so the e2e uses a **3-member channel** (browser + 2
  CLI members): the browser sends from its fresh genesis balance, and a *different* CLI member (also
  fresh) sends to the browser — demonstrating both directions without any refresh.
- **`validate_all_member_signatures` is structural only.** The wallet/CLI verify REAL SLH-DSA
  signatures via `sphincsplus_poseidon::verify::crypto_sign_verify` over the exact `signing_digest`,
  matching the in-circuit msg encoding (8 u32 limbs → LE u64 = 64 bytes).
- Reuse the hardened `InChannelTransferUpdateWitness::verify` (rebuilds the E-1 statement from
  authenticated state) rather than re-deriving statements in the wallet.

## RESOLVED: wasm↔native portability (regev_plonky3 3b17b8e)
- Root cause (fixed upstream): `make_config` built the Poseidon2 permutation from a `SmallRng`
  (RNG-seeded → width/platform-dependent). Replaced with the canonical compile-time constant
  permutation (`config::canonical_perm` / `default_babybear_poseidon2_16()`), a single target-
  independent path. Soundness params (queries/PoW) unchanged.
- Consumer change: bumped regev rev `377dfc2` → **`3b17b8e`** (regv-plonky3 `main`). BREAKING: old
  proofs/keys must be regenerated (old SmallRng-constant proofs don't verify under the new config).
- Result: **`node wallet-e2e.js` passes end-to-end** — a browser-generated E-1 proof is verified by
  the native CLI; balance 50 → 43 (send 7) → 48 (receive 5). The architecture (browser proves, CLI
  verifies) works.
- Note: also bumped `getrandom` handling stays as-is; the new regev made `rayon` optional under
  `parallel` and gated `pool.rs`, so with `default-features=false` the Regev STARK proves
  single-threaded on wasm (see "Multithreading" below).

## (historical) BLOCKER: wasm↔native Regev STARK proof portability
- **A Regev E-1 proof generated in the browser (wasm32) does NOT verify on the native CLI**
  (`FRI InvalidOpeningArgument(InvalidPowWitness)`), even though the in-wasm self-verify of the
  same proof passes. Decisive evidence: the *same* `verify_send_transition` Rust code returns `Ok`
  on wasm and `Err(InvalidPowWitness)` on native for the *identical* serialized proof+statement
  (round-tripped via JSON; bytes confirmed identical). So the upstream BabyBear/plonky3 verifier is
  **non-deterministic across targets**.
- Ruled out: SIMD (`+simd128` off changed nothing); the statement rebuild (passes in wasm); proof
  byte corruption (Vec<u8>/Vec<u32> JSON round-trip is lossless); my wallet code (same code both
  sides). Native↔native works (the `wallet_core_e2e` test passes); wasm↔wasm works (Phase-0 probe +
  in-wasm self-verify). Only the **cross-target** path fails.
- Consequence: the "browser proves, native CLI verifies" architecture cannot work until either the
  upstream wasm determinism bug is fixed, OR the verifier runs in the same environment as the prover
  (e.g. a Node-based CLI that uses the same wasm module for verification). Escalated to the user.

## Multithreading (final)
- Built wasm with `--features regev-parallel` (`hosting/build-wallet-wasm.sh`). The Regev STARK then proves
  on the wasm-bindgen-rayon global pool (worker calls `initThreadPool(N)` first; regev's gated
  `pool.rs` `build_global()` is a harmless no-op). Confirmed: multithreaded e2e passes and the
  browser proof still verifies natively (50→43→48). This is the requested in-browser speedup.

## Security hardening (post-review)
- Bound-check every attacker-supplied `u8` slot before indexing `[_; MAX_CHANNEL_MEMBERS]`
  (`check_slot`) — closes the wasm OOB-trap DoS class.
- `wallet_sign_state` restricted to genesis (epoch 1, version 0) since it signs without
  head/linkage checks; all later states go through `wallet_cosign` (which verifies the transition).
- Import validates `members` covers `0..member_count` bijectively.
- CLI `cosign` requires a `SendPayload` (carries the ChannelTx + E-1 proof) so every cosigner
  re-verifies the transition before signing — no signing of an unverified bare state.
