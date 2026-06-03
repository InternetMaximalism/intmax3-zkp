use serde::{Deserialize, Serialize};

use crate::config::{PROOF_FORMAT_VERSION, PROTOCOL_ID, ProofSystemOptions};
use crate::witness::PublicInputs;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub version: u32,
    pub protocol_id: String,
    pub options: ProofSystemOptions,
    pub public_inputs: PublicInputs,
    pub proof_bytes: Vec<u8>,
}

impl ProofEnvelope {
    pub fn new(
        options: ProofSystemOptions,
        public_inputs: PublicInputs,
        proof_bytes: Vec<u8>,
    ) -> Self {
        Self {
            version: PROOF_FORMAT_VERSION,
            protocol_id: PROTOCOL_ID.to_string(),
            options,
            public_inputs,
            proof_bytes,
        }
    }
}
