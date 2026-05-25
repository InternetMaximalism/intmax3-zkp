use std::rc::Rc;

use anyhow::{anyhow, ensure, Context, Result};
use p3_batch_stark::ProverData;
use p3_circuit::{
    builder::CircuitBuilder,
    ops::{generate_poseidon2_trace, generate_recompose_trace, Poseidon2Config},
    Circuit, ExprId,
};
use p3_circuit_prover::{
    batch_stark_prover::{poseidon2_air_builders, recompose_air_builders},
    common::{get_airs_and_degrees_with_prep, NpoPreprocessor},
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear};
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use p3_uni_stark::StarkGenericConfig;

use super::config::{
    KoalaChallenge, KoalaRecursionConfig, KOALA_CHALLENGE_DEGREE, KOALA_HASH_RATE,
};

pub const KOALA_LIMB_BITS: usize = 16;
pub const KOALA_HASH_OUTPUT_LIMBS: usize = KOALA_HASH_RATE / KOALA_CHALLENGE_DEGREE;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KoalaPoseidon2HashOut {
    pub elements: [u64; KOALA_HASH_RATE],
}

impl KoalaPoseidon2HashOut {
    pub fn to_public_inputs(self) -> [KoalaChallenge; KOALA_HASH_OUTPUT_LIMBS] {
        core::array::from_fn(|i| {
            let start = i * KOALA_CHALLENGE_DEGREE;
            KoalaChallenge::from_basis_coefficients_slice(
                &self.elements[start..start + KOALA_CHALLENGE_DEGREE]
                    .iter()
                    .copied()
                    .map(KoalaBear::from_u64)
                    .collect::<Vec<_>>(),
            )
            .expect("hash output chunk length should match challenge degree")
        })
    }
}

pub struct KoalaHashProof {
    pub expected: KoalaPoseidon2HashOut,
    pub output: RecursionOutput<KoalaRecursionConfig>,
}

pub struct KoalaHashCircuit {
    input_len: usize,
    limb_len: usize,
    circuit: Circuit<KoalaChallenge>,
    config: KoalaRecursionConfig,
    prover_data: Rc<CircuitProverData<KoalaRecursionConfig>>,
    table_packing: TablePacking,
}

impl KoalaHashCircuit {
    pub fn new(input_len: usize) -> Result<Self> {
        let limb_len = input_len * 4;
        ensure!(
            limb_len % KOALA_CHALLENGE_DEGREE == 0,
            "limb length must be aligned to the recursive extension degree"
        );

        let perm = default_koalabear_poseidon2_16();
        let mut builder = CircuitBuilder::<KoalaChallenge>::new();
        builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<KoalaChallenge, KoalaBearD4Width16>,
            perm,
        );
        builder
            .enable_recompose::<KoalaBear>(generate_recompose_trace::<KoalaBear, KoalaChallenge>);

        let input_exprs: Vec<ExprId> = (0..(limb_len / KOALA_CHALLENGE_DEGREE))
            .map(|_| builder.public_input())
            .collect();
        let outputs = builder
            .add_hash_slice(&Poseidon2Config::KOALA_BEAR_D4_W16, &input_exprs, true)
            .context("failed to add KoalaBear Poseidon2 hash op")?;
        ensure!(
            outputs.len() == KOALA_HASH_OUTPUT_LIMBS,
            "unexpected KoalaBear Poseidon2 output arity"
        );

        for output in outputs {
            let expected = builder.public_input();
            builder.connect(output, expected);
        }

        let circuit = builder
            .build()
            .context("failed to build KoalaBear plonky3 circuit")?;
        let config = KoalaRecursionConfig::new();
        let table_packing = TablePacking::new(2, 2);
        let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![
            Box::new(Poseidon2Preprocessor),
            Box::new(RecomposePreprocessor::default()),
        ];
        let mut air_builders = poseidon2_air_builders::<KoalaRecursionConfig, 4>();
        air_builders.extend(recompose_air_builders(1, false));
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<KoalaRecursionConfig, _, 4>(
                &circuit,
                &table_packing,
                &npo_prep,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .context("failed to derive AIRs for KoalaBear hash circuit")?;
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let prover_data = Rc::new(CircuitProverData::new(
            prover_data,
            primitive_columns,
            non_primitive_columns,
        ));

        Ok(Self {
            input_len,
            limb_len,
            circuit,
            config,
            prover_data,
            table_packing,
        })
    }

    pub fn hash_native(&self, inputs: &[u64]) -> Result<KoalaPoseidon2HashOut> {
        ensure!(
            inputs.len() == self.input_len,
            "input length mismatch: expected {}, got {}",
            self.input_len,
            inputs.len()
        );
        Ok(hash_u64s_with_koala_poseidon2(inputs))
    }

    pub fn prove(&self, inputs: &[u64]) -> Result<KoalaHashProof> {
        ensure!(
            inputs.len() == self.input_len,
            "input length mismatch: expected {}, got {}",
            self.input_len,
            inputs.len()
        );

        let expected = self.hash_native(inputs)?;
        let public_inputs = self.public_inputs(inputs, expected)?;

        let mut runner = self.circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .context("failed to set KoalaBear hash public inputs")?;
        let traces = runner
            .run()
            .context("failed to execute KoalaBear hash circuit")?;

        let mut prover = BatchStarkProver::new(self.config.clone())
            .with_table_packing(self.table_packing.clone());
        prover.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
        prover.register_recompose_table::<4>(false);

        let proof = prover
            .prove_all_tables(&traces, &self.prover_data)
            .context("failed to create KoalaBear plonky3 proof")?;

        Ok(KoalaHashProof {
            expected,
            output: RecursionOutput(proof, Rc::clone(&self.prover_data)),
        })
    }

    pub fn verify_base_proof(&self, proof: &BatchStarkProof<KoalaRecursionConfig>) -> Result<()> {
        let mut prover = BatchStarkProver::new(self.config.clone())
            .with_table_packing(self.table_packing.clone());
        prover.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
        prover.register_recompose_table::<4>(false);
        prover
            .verify_all_tables(proof)
            .map_err(|e| anyhow!("failed to verify KoalaBear batch proof: {e}"))?;
        Ok(())
    }

    pub fn prove_and_verify(&self, inputs: &[u64]) -> Result<KoalaPoseidon2HashOut> {
        let proof = self.prove(inputs)?;
        self.verify_base_proof(&proof.output.0)?;
        Ok(proof.expected)
    }

    fn public_inputs(
        &self,
        inputs: &[u64],
        expected: KoalaPoseidon2HashOut,
    ) -> Result<Vec<KoalaChallenge>> {
        let limb_inputs = split_u64s_to_koala_limbs(inputs);
        ensure!(
            limb_inputs.len() == self.limb_len,
            "limb length mismatch: expected {}, got {}",
            self.limb_len,
            limb_inputs.len()
        );

        Ok(pack_limbs_to_ext4(&limb_inputs)
            .into_iter()
            .chain(expected.to_public_inputs())
            .collect())
    }
}

fn u64_to_koala_limbs(value: u64) -> [u64; 4] {
    [
        value & 0xffff,
        (value >> 16) & 0xffff,
        (value >> 32) & 0xffff,
        (value >> 48) & 0xffff,
    ]
}

pub fn split_u64s_to_koala_limbs(inputs: &[u64]) -> Vec<u64> {
    inputs
        .iter()
        .flat_map(|&value| u64_to_koala_limbs(value))
        .collect()
}

pub fn hash_u64s_with_koala_poseidon2(inputs: &[u64]) -> KoalaPoseidon2HashOut {
    let perm = default_koalabear_poseidon2_16();
    let hasher = PaddingFreeSponge::<_, 16, 8, 8>::new(perm);
    let limbs = split_u64s_to_koala_limbs(inputs);
    let out = hasher.hash_iter(limbs.iter().copied().map(KoalaBear::from_u64));
    KoalaPoseidon2HashOut {
        elements: out.map(|x| x.as_canonical_u64()),
    }
}

fn pack_limbs_to_ext4(limbs: &[u64]) -> Vec<KoalaChallenge> {
    limbs
        .chunks(KOALA_CHALLENGE_DEGREE)
        .map(|chunk| {
            let coeffs = chunk
                .iter()
                .copied()
                .map(KoalaBear::from_u64)
                .collect::<Vec<_>>();
            KoalaChallenge::from_basis_coefficients_slice(&coeffs)
                .expect("limb chunk length should match challenge degree")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn koala_hash_circuit_round_trip() {
        let inputs = vec![1, 2, 3, 4, 5, 6];
        let circuit = KoalaHashCircuit::new(inputs.len()).unwrap();
        let native = circuit.hash_native(&inputs).unwrap();
        let proved = circuit.prove_and_verify(&inputs).unwrap();
        assert_eq!(native, proved);
    }
}
