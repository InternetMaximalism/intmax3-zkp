//! # regev-plonky3
//!
//! Plonky3-friendly Regev (Ring-LWE) encryption with STARK proofs of correct
//! encryption, built around three design decisions:
//!
//! 1. **Native modulus.** The ciphertext modulus `q` *is* the proof-field
//!    prime (BabyBear, `q = 2^31 - 2^27 + 1`). Every ring operation is a
//!    native field operation; no limb decomposition, no reduction gadgets.
//!    LWE tolerates a large `q` — security comes from the dimension and the
//!    noise — and BabyBear's two-adicity also gives the encryptor a fast
//!    negacyclic NTT for free.
//!
//! 2. **Linear-size multiplication proof.** The products `a·r`, `b·r` in
//!    `Z_q[x]/(x^n+1)` are never computed in-circuit. Instead, a random
//!    point `z` is sampled (Fiat-Shamir) *after* the witness is committed,
//!    every polynomial is evaluated at `z` with an O(n) Horner running-sum
//!    column, and the identities
//!    `c1(z) = a(z)·r(z) + e1(z) − (z^n+1)·k1(z)`,
//!    `c2(z) = b(z)·r(z) + e2(z) + Δ·m(z) − (z^n+1)·k2(z)`
//!    are enforced at that single point (Schwartz-Zippel). The two-phase
//!    commitment uses the same multi-round challenge plumbing that Plonky3's
//!    logUp lookups use ([`gadget::EvalGadget`] implements the evaluation
//!    argument as a `LookupGadget`).
//!
//! 3. **Cheap smallness checks.** Ternary `r` and CBD(η=2) noise are
//!    enforced by degree-3 vanishing constraints (`x(x-1)(x+1)`,
//!    `x(x-1)(x-2)` on the CBD halves) — for ranges this small that is
//!    strictly cheaper than a logUp lookup, which would cost an extension
//!    field running-sum column per check.
//!
//! Batching: each ciphertext is one `p3-batch-stark` instance; the whole
//! batch shares one commitment per phase and a single FRI opening, so fixed
//! costs amortize across transactions.
//!
//! ## Value-level additive homomorphism
//!
//! Messages are scaled by `Δ = floor(q/t)` with plaintext modulus
//! `t = 2^plain_bits` (default 256), and decryption decodes per-coefficient
//! **digits** in `[0, t)`. With values encoded as little-endian bits over
//! the coefficients, ciphertext addition is exact integer addition:
//!
//! ```rust
//! # use regev_plonky3::*;
//! # use rand::{rngs::SmallRng, SeedableRng};
//! # let params = RegevParams { n: 256, eta: 2, plain_bits: 8 };
//! # let mut rng = SmallRng::seed_from_u64(0);
//! # let (pk, sk) = keygen(&mut rng, &params);
//! let (ct_a, _) = encrypt(&mut rng, &params, &pk, &encode_value_message(5, params.n));
//! let (ct_b, _) = encrypt(&mut rng, &params, &pk, &encode_value_message(3, params.n));
//! let sum = add_ciphertexts(&ct_a, &ct_b);
//! assert_eq!(decrypt_value(&params, &sk, &sum), 8);
//! ```
//!
//! Valid for up to `t − 1` stacked additions (digit headroom) within a noise
//! budget of `Δ/2` (thousands of additions). See [`regev`] for details.
//!
//! ## Transfer proofs
//!
//! [`prove_transfers`] proves, per instance, that three ciphertexts
//! (`before`, `delta`, `after`) are well-formed encryptions **and** that
//! `before = after + delta` as n-bit integers, via a ripple-carry column —
//! conservation plus no-underflow for confidential balances. See
//! [`transfer`].
//!
//! ## Optional plaintext range proof
//!
//! [`prove_encryptions_with_range`] additionally proves that the integer
//! encoded by the low `value_bits` message coefficients lies in `[0, bound)`,
//! *without revealing it* — useful for confidential balances. The argument
//! lives entirely in witness columns (degree ≤ 2, ~1 ms/ct), so it works
//! identically under plain and hiding (zk) FRI. See [`air`] and [`RangeSpec`].
//!
//! ## Privacy
//!
//! Only evaluations of *public* polynomials (`a, b, c1, c2`) are published.
//! The witness evaluations `r(z), e1(z), e2(z), m(z), k1(z), k2(z)` stay in
//! the (committed) permutation trace and enter the ring identities as
//! in-circuit constraints — publishing them would leak ~128 bits of
//! information per polynomial and allow dictionary attacks on low-entropy
//! messages. The default config is succinct but not zero-knowledge (plain
//! FRI); use [`config::zk_config`] (hiding FRI commitments + randomized
//! quotient chunks) when the proof itself must leak nothing about the
//! witness.
//!
//! ## Quick start
//!
//! ```rust
//! use regev_plonky3::*;
//! use rand::{rngs::SmallRng, RngExt, SeedableRng};
//!
//! let params = RegevParams { n: 256, eta: 2, plain_bits: 8 }; // use N1024/N2048 in production
//! let mut rng = SmallRng::seed_from_u64(42);
//! let (pk, sk) = keygen(&mut rng, &params);
//!
//! let m: Vec<u8> = (0..params.n).map(|_| rng.random_range(0..=1)).collect();
//! let (ct, witness) = encrypt(&mut rng, &params, &pk, &m);
//! assert_eq!(decrypt(&params, &sk, &ct), m);
//!
//! let config = test_config();
//! let proof = prove_encryptions(&config, &params, &pk, &[ct.clone()], &[witness]);
//! verify_encryptions(&config, &params, &pk, &[ct], &proof).unwrap();
//! ```
//!
//! Bundling a range proof (prove the low 16 bits encode a value `< 50000`):
//!
//! ```rust
//! use regev_plonky3::*;
//! use rand::{rngs::SmallRng, RngExt, SeedableRng};
//!
//! let params = RegevParams { n: 256, eta: 2, plain_bits: 8 };
//! let mut rng = SmallRng::seed_from_u64(1);
//! let (pk, _sk) = keygen(&mut rng, &params);
//!
//! let value: u64 = 31337;
//! let mut m = vec![0u8; params.n];
//! for i in 0..16 { m[i] = ((value >> i) & 1) as u8; }
//! let (ct, witness) = encrypt(&mut rng, &params, &pk, &m);
//!
//! let spec = RangeSpec { value_bits: 16, bound: 50_000 };
//! let config = test_config();
//! let proof =
//!     prove_encryptions_with_range(&config, &params, &pk, &[ct.clone()], &[witness], spec);
//! verify_encryptions_with_range(&config, &params, &pk, &[ct], &proof, spec).unwrap();
//! ```

extern crate alloc;

pub mod air;
pub mod config;
pub mod gadget;
pub mod ntt;
pub mod params;
pub mod pool;
pub mod portability;
pub mod prove;
pub mod regev;
pub mod stark;
pub mod transfer;

pub use air::RangeSpec;
pub use config::{
    default_config, test_config, zk_config, zk_test_config, Challenge, RegevStarkConfig,
    RegevZkStarkConfig, Val, ZkRng,
};
pub use params::RegevParams;
pub use pool::init_thread_pool;
pub use prove::{
    prove_encryptions, prove_encryptions_with_range, verify_encryptions,
    verify_encryptions_with_range, RegevProof, RegevVerifyError,
};
pub use regev::{
    add_ciphertexts, decrypt, decrypt_value, encode_value_message, encrypt, keygen, Ciphertext,
    EncryptionWitness, PublicKey, SecretKey,
};
pub use transfer::{prove_transfers, verify_transfers, Transfer, TransferWitness};
