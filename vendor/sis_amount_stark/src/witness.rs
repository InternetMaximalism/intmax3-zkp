use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub amount: u64,
    pub r: [i64; crate::params::N],
    pub k: [i64; crate::params::M],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputs {
    pub c: Vec<u64>,
}
