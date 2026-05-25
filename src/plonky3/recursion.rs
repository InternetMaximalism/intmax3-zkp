use anyhow::Result;
use p3_recursion::RecursionOutput;

use super::{
    config::KoalaRecursionConfig,
    hash::{KoalaHashCircuit, KoalaHashProof, KoalaPoseidon2HashOut},
    utils::wrapper::wrap_recursion_output,
};

pub struct KoalaRecursiveHashProof {
    pub expected: KoalaPoseidon2HashOut,
    pub base: RecursionOutput<KoalaRecursionConfig>,
    pub compressed: RecursionOutput<KoalaRecursionConfig>,
}

pub fn recurse_hash_proof(base: KoalaHashProof) -> Result<KoalaRecursiveHashProof> {
    let compressed = wrap_recursion_output(&base.output)?;
    Ok(KoalaRecursiveHashProof {
        expected: base.expected,
        base: base.output,
        compressed,
    })
}

pub fn prove_hash_recursively(
    circuit: &KoalaHashCircuit,
    inputs: &[u64],
) -> Result<KoalaRecursiveHashProof> {
    recurse_hash_proof(circuit.prove(inputs)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn koala_hash_circuit_first_recursive_layer_round_trip() {
        let inputs = vec![11, 22, 33, 44];
        let circuit = KoalaHashCircuit::new(inputs.len()).unwrap();
        let recursive = prove_hash_recursively(&circuit, &inputs).unwrap();
        assert_eq!(recursive.expected, circuit.hash_native(&inputs).unwrap());
    }
}
