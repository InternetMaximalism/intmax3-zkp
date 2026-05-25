use anyhow::Result;

use crate::common::{private_state::PrivateState, salt::Salt};

use super::hash::{KoalaHashCircuit, KoalaPoseidon2HashOut};

pub struct PrivateStateCommitmentCircuit {
    hash_circuit: KoalaHashCircuit,
}

impl PrivateStateCommitmentCircuit {
    pub fn new() -> Result<Self> {
        let sample = PrivateState::new(Salt::default());
        let hash_circuit = KoalaHashCircuit::new(sample.to_u64_vec().len())?;
        Ok(Self { hash_circuit })
    }

    pub fn commitment(&self, private_state: &PrivateState) -> Result<KoalaPoseidon2HashOut> {
        self.hash_circuit.hash_native(&private_state.to_u64_vec())
    }

    pub fn prove_and_verify(
        &self,
        private_state: &PrivateState,
    ) -> Result<KoalaPoseidon2HashOut> {
        self.hash_circuit.prove_and_verify(&private_state.to_u64_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::salt::Salt;

    #[test]
    fn private_state_commitment_round_trip() {
        let circuit = PrivateStateCommitmentCircuit::new().unwrap();
        let private_state = PrivateState::new(Salt::default());
        let native = circuit.commitment(&private_state).unwrap();
        let proved = circuit.prove_and_verify(&private_state).unwrap();
        assert_eq!(native, proved);
    }
}
