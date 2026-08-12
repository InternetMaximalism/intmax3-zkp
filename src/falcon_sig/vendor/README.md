# Vendored Falcon-512 (`falcon512_poseidon2`) from 0xMiden/crypto

## Provenance

- Upstream repository: <https://github.com/0xMiden/crypto>
- Vendored path: `miden-crypto/src/dsa/falcon512_poseidon2/`
- Pinned upstream commit: `475092a8476bf4c806424579e5d9225b12941c1a`
  (`main` HEAD at vendoring time, 2026-08-05; last upstream commit dated 2026-07-17,
  "Add repository relocation notice (#1097)". Note: upstream development has moved to
  `0xmiden/miden-vm`; this repo remains the source of the vendored revision.)
- License: upstream is dual-licensed **MIT OR Apache-2.0**; we take the **MIT** license
  (owner decision DD-1). The full MIT license text is in `LICENSE-MIT` (verbatim upstream
  `LICENSE-MIT`).

## Pristine-copy fidelity check (threat model TM-C3, obligation O-4)

BEFORE any modification, the upstream module's own test suite was run against the pristine
clone (which includes the KAT test `test_signature_gen_reference_impl` pinning the vendored
Gaussian sampler + FFT + signing pipeline byte-for-byte against the reference Falcon
implementation's `sign_KAT` vectors):

```
cd <scratch>/miden-crypto
cargo test -p miden-crypto --release falcon512_poseidon2
# result: ok. 10 passed; 0 failed  (2026-08-05, rustc 1.94 per upstream rust-toolchain.toml)
```

All 10 upstream tests passed, including:
`test_signature_gen_reference_impl` (reference KAT), `test_falcon_verification`,
`test_serialization_round_trip`, `test_signature_determinism`, `test_ldl_decomposition_random`,
`test_negacyclic_reduction`, `test_approx_exp` (samplerz KAT).

## Modification policy

The Gaussian sampler (`math/ffsampling.rs`, `math/samplerz.rs`), FFT (`math/fft.rs`), field
(`math/field.rs`), polynomial arithmetic (`math/polynomial.rs`) and NTRU keygen
(`math/mod.rs`) are BYTE-IDENTICAL to upstream except for mechanical import-line edits forced
by type adaptation (host crate aliases `rand` 0.10 as `rand010`; Miden `Felt`/serialization/
zeroize utilities live in `falcon_sig::compat`). Every edit is marked in-file with a
`// VENDOR EDIT` comment. `src/falcon_sig/vendor` is excluded from rustfmt (`rustfmt.toml
ignore`) so the files stay diffable against upstream.

The ONE intentional functional change in this vendor tree is `hash_to_point.rs` (Miden
Poseidon2 -> in-tree plonky2 Poseidon, threat model TM-C1 / O-1).

The deterministic-signing machinery is intentionally REMOVED rather than left dormant
(TM-C2 / DD-3: randomized 40-byte salt; a reachable fixed-salt path is the exact footgun the
threat model bans).

## Exact list of modified files

| File | Changed lines vs upstream | Nature of change |
|---|---|---|
| `math/fft.rs` | 0 | byte-identical |
| `math/field.rs` | 0 | byte-identical |
| `math/samplerz.rs` | 3 | import only: `rand` -> `rand010` (+ VENDOR EDIT comment) |
| `math/mod.rs` (ntru_gen / ntru_solve / babai_reduce) | 4 | import only: `rand` -> `rand010` |
| `math/ffsampling.rs` | 11 | imports only: `rand` -> `rand010`, zeroize path -> `compat::zeroize`; test-module imports `rand010`/`rand_chacha010` |
| `math/polynomial.rs` | 27 | imports (`Felt`/paths/zeroize -> compat); `Felt::from_u16` -> `Felt::from_canonical_u16` (3 call sites, same operation on the same Goldilocks prime); test-only `prng_array` from compat |
| `mod.rs` | 176 | imports -> compat; constants' visibility raised to `pub(crate)`; deterministic-nonce machinery removed (`Nonce::deterministic`, `PREVERSIONED_NONCE`, nonce version byte, `Nonce` serde impls — SECURITY: TM-C2); `Nonce::to_elements` uses `from_canonical_u64` (upstream `new_unchecked`; identical for values < 2^40); upstream `tests/` dir not vendored; re-export list trimmed; `#![allow(dead_code)]` (vendored API kept whole where harmless) |
| `hash_to_point.rs` | 148 | **the intentional functional change**: plonky2 Poseidon sponge (width 12, rate 8, capacity domain `IMFH`), salt as upstream's 8x5-byte packing, message digest as 8 canonical u32 limbs, 64-permutation squeeze, one full element per coefficient mod q. Layout + bias argument documented in-file |
| `keys/secret_key.rs` | 141 | imports -> compat/`rand010`; `SilentDebug`/`SilentDisplay` derives -> equivalent manual redacted impls; `new()` (thread-RNG ctor) removed; deterministic `sign()`/`generate_seed`/`sign_with_rng_testing` removed (TM-C2); `sign_with_rng` now takes the caller-supplied `Nonce` and calls the plonky2 H2P. `with_rng` (keygen), `sign_helper` (ffSampling driver), serde, zeroization untouched |
| `keys/public_key.rs` | 45 | imports -> compat; Miden `SequentialCommit`/`to_commitment` removed (host digest is `falcon_sig::falcon_pk_digest`); `verify`/`recover_from` removed (single canonical verifier); `Display` uses `compat::write_hex`. The 14-bit PK codec (`Serializable`/`Deserializable`) untouched |
| `keys/mod.rs` | 52 | import trim; inline `test_falcon_verification` removed (coverage lives in `falcon_sig::tests` against the canonical verifier) |
| `signature.rs` | 105 | imports -> compat; `Signature::verify`/`verify_helper` removed — the single canonical verifier is `falcon_sig::verify`, which uses the threat-model bound `<= beta^2` (upstream used strict `<`); `Signature` serde impls (1524-byte format, depended on removed nonce serde), `Display`, inline test removed. The `SignaturePoly` compressed codec (Algorithms 17/18 of the Falcon spec) untouched |

Not vendored: upstream `tests/` directory (KAT data + SHAKE256 test PRNG; exercised on the
pristine copy instead, see above).

## Post-vendoring verification

The vendored in-file upstream tests (`test_approx_exp` samplerz KAT,
`test_ldl_decomposition_random`, `test_negacyclic_reduction`) run in this crate's test suite
(`cargo test --release -p intmax3-zkp --lib falcon_sig`), plus round-trip/adversarial coverage
of the host instantiation in `falcon_sig::tests`.

## Post-review local modification (F-1)

`signature.rs`: two bounds checks added in the Algorithm-18 s2 decoder (marked `SECURITY (F-1)`).
Upstream indexes the 625-byte input unguarded; malformed input panics there. This is a local
hardening on top of upstream, kept in the modified-files list deliberately.
