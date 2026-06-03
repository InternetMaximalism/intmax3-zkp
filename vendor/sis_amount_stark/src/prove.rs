use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, StarkConfig, VerificationError,
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
};
use thiserror::Error as ThisError;

use crate::air::AmountAir;
use crate::commitment::{CommitmentError, compute_commitment, compute_quotients};
use crate::config::{
    ConfigError, PROOF_FORMAT_VERSION, PROTOCOL_ID, ProofSystemOptions, RangeParameters,
};
use crate::envelope::ProofEnvelope;
use crate::params::{M, N};
use crate::trace::{TraceError, generate_trace};
use crate::witness::{PublicInputs, Witness};

type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<8>;
type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 4>;
type Challenge = BinomialExtensionField<Val, 2>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type StarkConfigImpl = StarkConfig<Pcs, Challenge, Challenger>;
type PreprocessedProverDataImpl = PreprocessedProverData<StarkConfigImpl>;
type PreprocessedVerifierKeyImpl = PreprocessedVerifierKey<StarkConfigImpl>;
pub type Proof = p3_uni_stark::Proof<StarkConfigImpl>;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("invalid witness: {0}")]
    InvalidWitness(&'static str),
    #[error(transparent)]
    Commitment(#[from] CommitmentError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Trace(#[from] TraceError),
    #[error("missing preprocessed trace")]
    MissingPreprocessedTrace,
    #[error("verification failed: {0:?}")]
    Verification(VerificationError<p3_uni_stark::PcsError<StarkConfigImpl>>),
    #[error("failed to serialize proof or envelope: {0}")]
    Serialize(#[from] postcard::Error),
    #[error("unsupported proof format version {0}")]
    UnsupportedProofFormatVersion(u32),
    #[error("unexpected protocol identifier: {0}")]
    UnexpectedProtocol(String),
    #[error("invalid public input length: expected {expected}, got {actual}")]
    InvalidPublicInputLength { expected: usize, actual: usize },
}

pub struct PreparedSystem {
    options: ProofSystemOptions,
    range: RangeParameters,
    air: AmountAir,
    config: StarkConfigImpl,
    preprocessed_prover_data: PreprocessedProverDataImpl,
    preprocessed_vk: PreprocessedVerifierKeyImpl,
}

impl PreparedSystem {
    pub fn options(&self) -> &ProofSystemOptions {
        &self.options
    }

    pub fn range(&self) -> &RangeParameters {
        &self.range
    }
}

fn build_config(options: &ProofSystemOptions) -> StarkConfigImpl {
    let perm = default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: options.fri.log_blowup,
        log_final_poly_len: options.fri.log_final_poly_len,
        max_log_arity: options.fri.max_log_arity,
        num_queries: options.fri.num_queries,
        commit_proof_of_work_bits: options.fri.commit_proof_of_work_bits,
        query_proof_of_work_bits: options.fri.query_proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    StarkConfigImpl::new(pcs, challenger)
}

fn public_values(public_inputs: &PublicInputs) -> Result<[Val; M], Error> {
    if public_inputs.c.len() != M {
        return Err(Error::InvalidPublicInputLength {
            expected: M,
            actual: public_inputs.c.len(),
        });
    }
    Ok(core::array::from_fn(|i| Val::from_u64(public_inputs.c[i])))
}

fn validate_randomness(r: &[i64; N], beta: i64) -> Result<(), Error> {
    if r.iter().any(|value| !(-beta..=beta).contains(value)) {
        return Err(Error::InvalidWitness(
            "randomness coefficient outside [-beta, beta]",
        ));
    }
    Ok(())
}

fn build_prepared_system(options: &ProofSystemOptions) -> Result<PreparedSystem, Error> {
    let range = options.range_parameters()?;
    let air = AmountAir {
        range: range.clone(),
    };
    let config = build_config(options);
    let degree_bits = range.trace_rows.trailing_zeros() as usize;
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed::<StarkConfigImpl, _>(&config, &air, degree_bits)
            .ok_or(Error::MissingPreprocessedTrace)?;

    Ok(PreparedSystem {
        options: options.clone(),
        range,
        air,
        config,
        preprocessed_prover_data,
        preprocessed_vk,
    })
}

fn prepared_cache() -> &'static Mutex<HashMap<ProofSystemOptions, Arc<PreparedSystem>>> {
    static PREPARED_CACHE: OnceLock<Mutex<HashMap<ProofSystemOptions, Arc<PreparedSystem>>>> =
        OnceLock::new();
    PREPARED_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_or_create_prepared(options: &ProofSystemOptions) -> Result<Arc<PreparedSystem>, Error> {
    if let Some(prepared) = prepared_cache()
        .lock()
        .expect("cache lock poisoned")
        .get(options)
    {
        return Ok(Arc::clone(prepared));
    }

    let prepared = Arc::new(build_prepared_system(options)?);
    let mut cache = prepared_cache().lock().expect("cache lock poisoned");
    let cached = cache
        .entry(options.clone())
        .or_insert_with(|| Arc::clone(&prepared));
    Ok(Arc::clone(cached))
}

pub fn prepare_system(options: &ProofSystemOptions) -> Result<PreparedSystem, Error> {
    build_prepared_system(options)
}

pub fn prove_amount_prepared(
    prepared: &PreparedSystem,
    amount: u64,
    r: [i64; N],
) -> Result<(Proof, PublicInputs), Error> {
    validate_randomness(&r, prepared.range.beta)?;

    let c = compute_commitment(amount, &r);
    let k = compute_quotients(amount, &r, &c)?;
    let witness = Witness { amount, r, k };
    let public_inputs = PublicInputs { c: c.to_vec() };
    let trace = generate_trace::<Val>(&witness, &prepared.range)?;
    let public_values = public_values(&public_inputs)?;

    let proof = prove_with_preprocessed(
        &prepared.config,
        &prepared.air,
        trace,
        &public_values,
        Some(&prepared.preprocessed_prover_data),
    );

    Ok((proof, public_inputs))
}

pub fn verify_amount_prepared(
    prepared: &PreparedSystem,
    proof: &Proof,
    public_inputs: &PublicInputs,
) -> Result<(), Error> {
    let public_values = public_values(public_inputs)?;
    verify_with_preprocessed(
        &prepared.config,
        &prepared.air,
        proof,
        &public_values,
        Some(&prepared.preprocessed_vk),
    )
    .map_err(Error::Verification)
}

pub fn prove_amount(amount: u64, r: [i64; N]) -> Result<(Proof, PublicInputs), Error> {
    prove_amount_with_options(amount, r, &ProofSystemOptions::default())
}

pub fn prove_amount_with_options(
    amount: u64,
    r: [i64; N],
    options: &ProofSystemOptions,
) -> Result<(Proof, PublicInputs), Error> {
    let prepared = get_or_create_prepared(options)?;
    prove_amount_prepared(&prepared, amount, r)
}

pub fn verify_amount(proof: &Proof, public_inputs: &PublicInputs) -> Result<(), Error> {
    verify_amount_with_options(proof, public_inputs, &ProofSystemOptions::default())
}

pub fn verify_amount_with_options(
    proof: &Proof,
    public_inputs: &PublicInputs,
    options: &ProofSystemOptions,
) -> Result<(), Error> {
    let prepared = get_or_create_prepared(options)?;
    verify_amount_prepared(&prepared, proof, public_inputs)
}

pub fn serialize_envelope(
    proof: &Proof,
    public_inputs: &PublicInputs,
    options: &ProofSystemOptions,
) -> Result<Vec<u8>, Error> {
    let proof_bytes = postcard::to_allocvec(proof)?;
    let envelope = ProofEnvelope::new(options.clone(), public_inputs.clone(), proof_bytes);
    Ok(postcard::to_allocvec(&envelope)?)
}

pub fn deserialize_envelope(
    bytes: &[u8],
) -> Result<(Proof, PublicInputs, ProofSystemOptions), Error> {
    let envelope: ProofEnvelope = postcard::from_bytes(bytes)?;
    if envelope.version != PROOF_FORMAT_VERSION {
        return Err(Error::UnsupportedProofFormatVersion(envelope.version));
    }
    if envelope.protocol_id != PROTOCOL_ID {
        return Err(Error::UnexpectedProtocol(envelope.protocol_id));
    }
    let proof: Proof = postcard::from_bytes(&envelope.proof_bytes)?;
    Ok((proof, envelope.public_inputs, envelope.options))
}

pub fn proof_size_bytes(proof: &Proof) -> Result<usize, Error> {
    Ok(postcard::to_allocvec(proof)?.len())
}
