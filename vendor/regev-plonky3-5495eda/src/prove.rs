//! High-level prove/verify API for batched Regev encryption proofs.
//!
//! One STARK instance per ciphertext, all batched into a single
//! `p3-batch-stark` proof: one main commitment, one permutation commitment,
//! one quotient commitment and one FRI opening for the whole batch, so the
//! per-ciphertext cost is dominated by the (small) trace itself.
//!
//! Generic over the STARK config (any `StarkGenericConfig` whose value field
//! is BabyBear): use [`crate::config::default_config`] for plain FRI or
//! [`crate::config::zk_config`] for zero-knowledge hiding FRI.
//!
//! # Statement
//!
//! For each ciphertext `(c1, c2)` under public key `(a, b)`:
//!
//! > "I know `r` ternary, `e1, e2` with coefficients in `[-2, 2]`, and a
//! > binary `m`, such that `c1 = a·r + e1` and `c2 = b·r + e2 + Δ·m` in
//! > `Z_q[x]/(x^n + 1)`."
//!
//! With a [`RangeSpec`], the statement additionally asserts that the integer
//! encoded by the low message bits lies in `[0, bound)` (see [`crate::air`]).
//!
//! # Verification structure
//!
//! 1. [`crate::stark::verify_batch`] checks all in-circuit constraints
//!    (smallness, Horner evaluation columns, the ring identities at the
//!    random point `z`, and — if enabled — the range argument) and returns `z`.
//! 2. This wrapper recomputes `a(z), b(z), c1(z), c2(z)` from the *claimed*
//!    statement and compares them to the evaluations published in the proof.
//!    This binds the committed trace columns to the actual ciphertext: by
//!    Schwartz-Zippel, agreement at the post-commitment challenge `z`
//!    implies equality as polynomials (soundness error `< 2n / |EF|`,
//!    about `2^-113` for `n = 1024` over the quartic BabyBear extension).

use p3_air::DebugConstraintBuilder;
use p3_air::symbolic::{SymbolicAirBuilder, SymbolicExpressionExt};
use p3_air::Air;
use p3_batch_stark::common::{CommonData, ProverData};
use p3_batch_stark::config::{Challenge, Domain, PcsError, StarkGenericConfig, Val};
use p3_batch_stark::proof::BatchProof;
use p3_batch_stark::prover::StarkInstance;
use p3_commit::PolynomialSpace;
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::VerificationError;

use crate::air::{
    generate_trace, generate_trace_with_range, public_values, RangeSpec, RegevEncAir,
};
use crate::params::RegevParams;
use crate::regev::EncryptionWitness;
use crate::regev::{Ciphertext, PublicKey, F};
use crate::stark;

/// A batched proof of correct encryption for one or more ciphertexts.
pub type RegevProof = BatchProof<crate::config::RegevStarkConfig>;

#[derive(Debug)]
pub enum RegevVerifyError<E: core::fmt::Debug> {
    /// Number of ciphertexts and proof instances disagree, or trace sizes
    /// don't match the ring dimension.
    Shape(&'static str),
    /// The inner STARK failed (constraints, openings, FRI, ...).
    Stark(VerificationError<E>),
    /// A published evaluation does not match the claimed statement:
    /// the proof was made for a different public key or ciphertext.
    StatementMismatch { instance: usize, poly: &'static str },
}

impl<E: core::fmt::Debug> core::fmt::Display for RegevVerifyError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape(s) => write!(f, "malformed proof: {s}"),
            Self::Stark(e) => write!(f, "STARK verification failed: {e:?}"),
            Self::StatementMismatch { instance, poly } => write!(
                f,
                "instance {instance}: published evaluation of `{poly}` does not match statement"
            ),
        }
    }
}

impl<E: core::fmt::Debug> std::error::Error for RegevVerifyError<E> {}

fn air_for<SC>(params: &RegevParams, range: Option<RangeSpec>) -> RegevEncAir<Val<SC>>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
{
    let delta = Val::<SC>::from_u32(params.delta());
    match range {
        Some(r) => RegevEncAir::new_with_range(params.n, delta, r),
        None => RegevEncAir::new(params.n, delta),
    }
}

/// Horner evaluation of a base-field coefficient vector at an extension
/// field point: `P(z) = Σ_i p_i z^i`.
pub(crate) fn eval_at<SC>(coeffs: &[Val<SC>], z: SC::Challenge) -> SC::Challenge
where
    SC: StarkGenericConfig,
{
    coeffs
        .iter()
        .rev()
        .fold(SC::Challenge::ZERO, |acc, &c| {
            acc * z + SC::Challenge::from(c)
        })
}

/// Prove that every `(ciphertext, witness)` pair is a well-formed encryption
/// under `pk`. All ciphertexts are batched into a single proof.
pub fn prove_encryptions<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    ciphertexts: &[Ciphertext],
    witnesses: &[EncryptionWitness],
) -> BatchProof<SC>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevEncAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
{
    prove_inner(config, params, pk, ciphertexts, witnesses, None)
}

/// Prove correct encryption *and* a plaintext range proof for every
/// ciphertext: the integer encoded by the low `range.value_bits` message
/// bits lies in `[0, range.bound)`. The same `range` applies to all
/// ciphertexts in the batch.
pub fn prove_encryptions_with_range<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    ciphertexts: &[Ciphertext],
    witnesses: &[EncryptionWitness],
    range: RangeSpec,
) -> BatchProof<SC>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevEncAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
{
    prove_inner(config, params, pk, ciphertexts, witnesses, Some(range))
}

fn prove_inner<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    ciphertexts: &[Ciphertext],
    witnesses: &[EncryptionWitness],
    range: Option<RangeSpec>,
) -> BatchProof<SC>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevEncAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
{
    crate::pool::init_thread_pool();
    assert!(!ciphertexts.is_empty(), "empty batch");
    assert_eq!(ciphertexts.len(), witnesses.len());
    assert_eq!(pk.a.len(), params.n);

    let air = air_for::<SC>(params, range);
    let airs = vec![air; ciphertexts.len()];

    let traces: Vec<RowMajorMatrix<Val<SC>>> = ciphertexts
        .iter()
        .zip(witnesses)
        .map(|(ct, w)| match range {
            Some(r) => generate_trace_with_range(pk, ct, w, r),
            None => generate_trace(pk, ct, w),
        })
        .collect();

    let instances: Vec<StarkInstance<'_, SC, RegevEncAir<Val<SC>>>> = airs
        .iter()
        .zip(&traces)
        .zip(ciphertexts)
        .map(|((air, trace), ct)| StarkInstance {
            air,
            trace,
            public_values: public_values(pk, ct),
            lookups: air.clone().get_lookups(),
        })
        .collect();

    let prover_data = ProverData::from_instances(config, &instances);
    stark::prove_batch(config, &instances, &prover_data)
}

/// Verify a batched encryption proof against `pk` and the ciphertexts.
pub fn verify_encryptions<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    ciphertexts: &[Ciphertext],
    proof: &BatchProof<SC>,
) -> Result<(), RegevVerifyError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevEncAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>,
{
    verify_inner(config, params, pk, ciphertexts, proof, None)
}

/// Verify a batched encryption proof that also carries a plaintext range
/// proof. The verifier must supply the same `range` the prover used; a proof
/// for any other range fails its constraints.
pub fn verify_encryptions_with_range<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    ciphertexts: &[Ciphertext],
    proof: &BatchProof<SC>,
    range: RangeSpec,
) -> Result<(), RegevVerifyError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevEncAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>,
{
    verify_inner(config, params, pk, ciphertexts, proof, Some(range))
}

fn verify_inner<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    ciphertexts: &[Ciphertext],
    proof: &BatchProof<SC>,
    range: Option<RangeSpec>,
) -> Result<(), RegevVerifyError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevEncAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>,
{
    crate::pool::init_thread_pool();
    if ciphertexts.is_empty() {
        return Err(RegevVerifyError::Shape("empty batch"));
    }
    if pk.a.len() != params.n || pk.b.len() != params.n {
        return Err(RegevVerifyError::Shape("public key length != n"));
    }

    // The Horner argument identifies "the polynomial" with "the trace
    // column", so the trace height must equal the ring dimension.
    let expected_db = params.log_n() + config.is_zk();
    if proof.degree_bits.len() != ciphertexts.len()
        || proof.degree_bits.iter().any(|&db| db != expected_db)
    {
        return Err(RegevVerifyError::Shape("trace height != ring dimension"));
    }

    // Rebuild the lookups (the evaluation arguments). The range proof adds no
    // permutation columns and no preprocessed commitment — it lives entirely
    // in the committed main trace — so there is nothing for the verifier to
    // reconstruct beyond the lookup metadata.
    let mut air = air_for::<SC>(params, range);
    let lookups = air.get_lookups();
    let airs = vec![air; ciphertexts.len()];
    let common = CommonData::new(None, vec![lookups; ciphertexts.len()]);

    let pvs: Vec<Vec<Val<SC>>> = ciphertexts.iter().map(|ct| public_values(pk, ct)).collect();

    // Inner STARK: constraints, Horner columns, ring identities, range proof.
    let challenges = stark::verify_batch(config, &airs, proof, &pvs, &common)
        .map_err(RegevVerifyError::Stark)?;

    // Outer binding: published evaluations must match the actual statement.
    for (i, ct) in ciphertexts.iter().enumerate() {
        let data = &proof.global_lookup_data[i];
        if data.len() != 4 {
            return Err(RegevVerifyError::Shape("expected 4 published evaluations"));
        }
        if ct.c1.len() != params.n || ct.c2.len() != params.n {
            return Err(RegevVerifyError::Shape("ciphertext length != n"));
        }
        let z = challenges[i][0];

        // Order is pinned by the constraint system (the j-th published value
        // is checked in-circuit against the j-th global lookup's running
        // evaluation), so positional matching is sound.
        let expected = [
            ("a", eval_at::<SC>(&pk.a, z)),
            ("b", eval_at::<SC>(&pk.b, z)),
            ("c1", eval_at::<SC>(&ct.c1, z)),
            ("c2", eval_at::<SC>(&ct.c2, z)),
        ];
        for (j, (poly, want)) in expected.into_iter().enumerate() {
            if data[j].expected_cumulated != want {
                return Err(RegevVerifyError::StatementMismatch { instance: i, poly });
            }
        }
    }

    Ok(())
}
