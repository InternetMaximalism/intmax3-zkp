use anyhow::{Context, Result, anyhow, ensure};
use p3_batch_stark::ProverData;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit::ops::{
    KoalaBearD1Width16, Poseidon2Config, generate_poseidon2_trace,
};
use p3_circuit::{Circuit, ExprId};
use p3_circuit_prover::batch_stark_prover::{
    Poseidon2Preprocessor, poseidon2_air_builders_d5, poseidon2_table_provers_d5,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking, config,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use p3_test_utils::LiftPermToQuintic;

pub const KOALA_POSEIDON2_RATE: usize = 8;
pub const KOALA_LIMB_BITS: usize = 16;

pub type KoalaExt5 = QuinticTrinomialExtensionField<KoalaBear>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KoalaPoseidon2HashOut {
    pub elements: [u64; KOALA_POSEIDON2_RATE],
}

impl KoalaPoseidon2HashOut {
    pub fn to_public_inputs(self) -> [KoalaExt5; KOALA_POSEIDON2_RATE] {
        self.elements.map(lift_u64)
    }
}

fn lift_u64(value: u64) -> KoalaExt5 {
    KoalaExt5::new([
        KoalaBear::from_u64(value),
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
    ])
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
    inputs.iter().flat_map(|&value| u64_to_koala_limbs(value)).collect()
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

pub struct KoalaHashCircuit {
    input_len: usize,
    limb_len: usize,
    circuit: Circuit<KoalaExt5>,
    prover_data: CircuitProverData<KoalaBearConfig>,
    table_packing: TablePacking,
}

impl KoalaHashCircuit {
    pub fn new(input_len: usize) -> Result<Self> {
        let limb_len = input_len * 4;
        let inner_perm = default_koalabear_poseidon2_16();
        let lift_perm = LiftPermToQuintic::<KoalaBear, _, 16>::new(inner_perm);

        let mut builder = CircuitBuilder::<KoalaExt5>::new();
        builder.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
            generate_poseidon2_trace::<KoalaExt5, KoalaBearD1Width16>,
            lift_perm,
        );

        let input_exprs: Vec<ExprId> = (0..limb_len)
            .map(|_| builder.public_input())
            .collect();
        let outputs = builder
            .add_hash_slice(&Poseidon2Config::KOALA_BEAR_D1_W16, &input_exprs, true)
            .context("failed to add KoalaBear Poseidon2 hash op")?;
        ensure!(
            outputs.len() == KOALA_POSEIDON2_RATE,
            "unexpected KoalaBear Poseidon2 output arity"
        );

        for output in outputs {
            let expected = builder.public_input();
            builder.connect(output, expected);
        }

        let circuit = builder.build().context("failed to build KoalaBear plonky3 circuit")?;
        let table_packing = TablePacking::default();
        let npo_prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> =
            vec![Box::new(Poseidon2Preprocessor)];
        let air_builders = poseidon2_air_builders_d5::<KoalaBearConfig>();
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 5>(
                &circuit,
                &table_packing,
                &npo_prep,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .context("failed to derive AIRs for KoalaBear hash circuit")?;
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let prover_data = ProverData::from_airs_and_degrees(&config::koala_bear(), &airs, &degrees);
        let prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

        Ok(Self {
            input_len,
            limb_len,
            circuit,
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

    pub fn prove_and_verify(&self, inputs: &[u64]) -> Result<KoalaPoseidon2HashOut> {
        ensure!(
            inputs.len() == self.input_len,
            "input length mismatch: expected {}, got {}",
            self.input_len,
            inputs.len()
        );

        let expected = self.hash_native(inputs)?;
        let limb_inputs = split_u64s_to_koala_limbs(inputs);
        ensure!(
            limb_inputs.len() == self.limb_len,
            "limb length mismatch: expected {}, got {}",
            self.limb_len,
            limb_inputs.len()
        );

        let public_inputs = limb_inputs
            .into_iter()
            .map(lift_u64)
            .chain(expected.to_public_inputs())
            .collect::<Vec<_>>();

        let mut runner = self.circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .context("failed to set KoalaBear hash public inputs")?;
        let traces = runner
            .run()
            .context("failed to execute KoalaBear hash circuit")?;

        let mut prover =
            BatchStarkProver::new(config::koala_bear()).with_table_packing(self.table_packing.clone());
        for table_prover in poseidon2_table_provers_d5(Poseidon2Config::KOALA_BEAR_D1_W16) {
            prover.register_table_prover(table_prover);
        }

        let proof = prover
            .prove_all_tables(&traces, &self.prover_data)
            .context("failed to create KoalaBear plonky3 proof")?;
        prover
            .verify_all_tables(&proof)
            .map_err(|e| anyhow!("failed to verify KoalaBear plonky3 proof: {e}"))?;
        Ok(expected)
    }
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
