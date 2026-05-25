use std::sync::Arc;

use p3_circuit::{
    ops::{generate_poseidon2_trace, generate_recompose_trace, Poseidon2Config},
    CircuitBuilder, CircuitRunner, NonPrimitiveOpId,
};
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_commit::Pcs;
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::{
    pcs::{
        set_fri_mmcs_private_data, FriProofTargets, InputProofTargets, MerkleCapTargets,
        RecExtensionValMmcs, RecValMmcs, Witness,
    },
    traits::{RecursiveAir, RecursivePcs},
    FriRecursionBackend, FriRecursionConfig, FriVerifierParams, ProveNextLayerParams,
    RecursionInput, VerificationError,
};
use p3_test_utils::koala_bear_params::{
    default_koalabear_poseidon2_16, make_test_config_with_fri, Challenge, Challenger, MyCompress,
    MyConfig, MyHash, MyMmcs, MyPcs, Perm, D, DIGEST_ELEMS, F, RATE, WIDTH,
};
use p3_uni_stark::{StarkGenericConfig, Val};

pub const KOALA_HASH_WIDTH: usize = WIDTH;
pub const KOALA_HASH_RATE: usize = RATE;
pub const KOALA_HASH_DIGEST_ELEMS: usize = DIGEST_ELEMS;
pub const KOALA_CHALLENGE_DEGREE: usize = D;

pub type KoalaBear = F;
pub type KoalaChallenge = Challenge;
pub type KoalaPerm = Perm;
pub type KoalaPcsConfig = MyConfig;
pub type KoalaCommitment = MerkleCapTargets<F, DIGEST_ELEMS>;
pub type KoalaInputProof =
    InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
pub type KoalaOpeningProof = FriProofTargets<
    Val<MyConfig>,
    Challenge,
    RecExtensionValMmcs<
        Val<MyConfig>,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    KoalaInputProof,
    Witness<Val<MyConfig>>,
>;

#[derive(Clone)]
pub struct KoalaRecursionConfig {
    config: Arc<MyConfig>,
    fri_verifier_params: FriVerifierParams,
}

impl KoalaRecursionConfig {
    pub fn new() -> Self {
        let perm = default_koalabear_poseidon2_16();
        let config = make_test_config_with_fri(&perm, 1, 3);
        let fri_verifier_params =
            FriVerifierParams::with_mmcs(1, 0, 0, 16, Poseidon2Config::KOALA_BEAR_D4_W16);

        Self {
            config: Arc::new(config),
            fri_verifier_params,
        }
    }
}

impl Default for KoalaRecursionConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for KoalaRecursionConfig {
    type Target = MyConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl StarkGenericConfig for KoalaRecursionConfig {
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = MyPcs;

    fn pcs(&self) -> &Self::Pcs {
        self.config.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for KoalaRecursionConfig
where
    MyPcs: RecursivePcs<
        KoalaRecursionConfig,
        KoalaInputProof,
        KoalaOpeningProof,
        KoalaCommitment,
        <MyPcs as Pcs<Challenge, Challenger>>::Domain,
    >,
{
    type Commitment = KoalaCommitment;
    type InputProof = KoalaInputProof;
    type OpeningProof = KoalaOpeningProof;
    type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;

    const DIGEST_ELEMS: usize = DIGEST_ELEMS;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Self::Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_koalabear_poseidon2_16();
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Self::Challenge, KoalaBearD4Width16>,
            perm,
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<MyPcs as RecursivePcs<
        KoalaRecursionConfig,
        KoalaInputProof,
        KoalaOpeningProof,
        KoalaCommitment,
        <MyPcs as Pcs<Challenge, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, Self::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_fri_mmcs_private_data::<F, Challenge, _, MyMmcs, MyHash, MyCompress, DIGEST_ELEMS>(
            runner,
            op_ids,
            opening_proof,
            Poseidon2Config::KOALA_BEAR_D4_W16,
        )
    }
}

pub fn koala_recursion_backend(
) -> p3_recursion::FriRecursionBackendForExt<4, KOALA_HASH_WIDTH, KOALA_HASH_RATE, Poseidon2Config>
{
    FriRecursionBackend::<KOALA_HASH_WIDTH, KOALA_HASH_RATE, _>::new(
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .for_extension_degree::<4>()
}

pub fn koala_recursion_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 3).with_fri_params(0, 1),
        constraint_profile: ConstraintProfile::Standard,
    }
}
