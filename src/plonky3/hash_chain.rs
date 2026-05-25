use anyhow::{ensure, Result};

use crate::ethereum_types::{
    address::{Address, ADDRESS_LEN},
    u32limb_trait::U32LimbTrait,
};

use super::{
    hash::{KoalaHashCircuit, KoalaHashProof, KoalaPoseidon2HashOut, KOALA_HASH_OUTPUT_LIMBS},
    utils::{
        cyclic::fold_recursion_chain,
        dummy::empty_recursion_chain,
        recursively_verifiable::{aggregate_recursion_outputs, KoalaRecursionProof},
        wrapper::wrap_recursion_output,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KoalaHashChainLink {
    pub prev_hash: KoalaPoseidon2HashOut,
    pub hash: KoalaPoseidon2HashOut,
}

pub struct KoalaHashChainStepProof {
    pub link: KoalaHashChainLink,
    pub base: KoalaHashProof,
    pub wrapped: KoalaRecursionProof,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KoalaHashChainEnd {
    pub last_hash: KoalaPoseidon2HashOut,
    pub aggregator: Address,
    pub digest: KoalaPoseidon2HashOut,
}

pub struct KoalaHashChainEndProof {
    pub public_inputs: KoalaHashChainEnd,
    pub base: KoalaHashProof,
    pub wrapped: KoalaRecursionProof,
    pub aggregated: Option<KoalaRecursionProof>,
}

pub struct KoalaHashChainProof {
    pub links: Vec<KoalaHashChainLink>,
    pub aggregated: Option<KoalaRecursionProof>,
}

impl KoalaHashChainProof {
    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn start_hash(&self) -> KoalaPoseidon2HashOut {
        self.links
            .first()
            .map(|link| link.prev_hash)
            .unwrap_or_default()
    }

    pub fn last_hash(&self) -> KoalaPoseidon2HashOut {
        self.links.last().map(|link| link.hash).unwrap_or_default()
    }

    pub fn root(&self) -> Option<&KoalaRecursionProof> {
        self.aggregated.as_ref()
    }
}

impl KoalaHashChainEndProof {
    pub fn root(&self) -> &KoalaRecursionProof {
        self.aggregated.as_ref().unwrap_or(&self.wrapped)
    }
}

pub struct KoalaHashChainProcessor {
    step_circuit: KoalaHashCircuit,
    end_circuit: KoalaHashCircuit,
    content_len: usize,
}

impl KoalaHashChainProcessor {
    pub fn new(content_len: usize) -> Result<Self> {
        let step_circuit = KoalaHashCircuit::new(KOALA_HASH_OUTPUT_LIMBS * 4 + content_len)?;
        let end_circuit = KoalaHashCircuit::new(KOALA_HASH_OUTPUT_LIMBS * 4 + ADDRESS_LEN)?;
        Ok(Self {
            step_circuit,
            end_circuit,
            content_len,
        })
    }

    pub fn prove_step(
        &self,
        prev_hash: KoalaPoseidon2HashOut,
        content: &[u64],
    ) -> Result<KoalaHashChainStepProof> {
        ensure!(
            content.len() == self.content_len,
            "content length mismatch: expected {}, got {}",
            self.content_len,
            content.len()
        );

        let mut inputs = prev_hash.elements.to_vec();
        inputs.extend_from_slice(content);
        let base = self.step_circuit.prove(&inputs)?;
        let wrapped = wrap_recursion_output(&base.output)?;
        Ok(KoalaHashChainStepProof {
            link: KoalaHashChainLink {
                prev_hash,
                hash: base.expected,
            },
            base,
            wrapped,
        })
    }

    pub fn prove_chain(&self, contents: &[Vec<u64>]) -> Result<KoalaHashChainProof> {
        let mut prev_hash = KoalaPoseidon2HashOut::default();
        let mut links = Vec::with_capacity(contents.len());
        let mut wrapped = Vec::with_capacity(contents.len());

        for content in contents {
            let step = self.prove_step(prev_hash, content)?;
            prev_hash = step.link.hash;
            links.push(step.link);
            wrapped.push(step.wrapped);
        }

        let aggregated = if wrapped.is_empty() {
            empty_recursion_chain()
        } else {
            fold_recursion_chain(wrapped)?
        };

        Ok(KoalaHashChainProof { links, aggregated })
    }

    pub fn prove_end(
        &self,
        chain: KoalaHashChainProof,
        aggregator: Address,
    ) -> Result<KoalaHashChainEndProof> {
        let last_hash = chain.last_hash();
        let mut inputs = last_hash.elements.to_vec();
        inputs.extend(aggregator.to_u64_vec());
        let base = self.end_circuit.prove(&inputs)?;
        let wrapped = wrap_recursion_output(&base.output)?;
        let public_inputs = KoalaHashChainEnd {
            last_hash,
            aggregator,
            digest: base.expected,
        };

        let aggregated = match chain.aggregated {
            Some(chain_root) => Some(aggregate_recursion_outputs(&chain_root, &wrapped, 1, None)?),
            None => None,
        };

        Ok(KoalaHashChainEndProof {
            public_inputs,
            base,
            wrapped,
            aggregated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_round_trip() {
        let processor = KoalaHashChainProcessor::new(3).unwrap();
        let contents = vec![vec![1, 2, 3]];
        let chain = processor.prove_chain(&contents).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.start_hash(), KoalaPoseidon2HashOut::default());
        assert!(chain.aggregated.is_some());
        assert_eq!(chain.links[0].prev_hash, KoalaPoseidon2HashOut::default());
    }

    #[test]
    #[ignore = "expensive recursive aggregation smoke test"]
    fn hash_chain_end_round_trip() {
        let processor = KoalaHashChainProcessor::new(2).unwrap();
        let contents = vec![vec![10, 11]];
        let chain = processor.prove_chain(&contents).unwrap();
        let aggregator =
            Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678])
                .unwrap();
        let end = processor.prove_end(chain, aggregator).unwrap();
        assert_eq!(end.public_inputs.aggregator, aggregator);
        end.root();
    }
}
