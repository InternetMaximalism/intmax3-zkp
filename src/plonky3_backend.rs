use serde::{Deserialize, Serialize};

/// Repository-wide choice for the Plonky3 recursion backend.
///
/// This is intentionally a pure-data module so the migration target is explicit before the
/// circuit rewrite lands. The actual Plonky3 crates are not wired into the build yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plonky3Field {
    KoalaBear,
    BabyBear,
    Goldilocks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plonky3Hash {
    Poseidon2,
    Poseidon1,
    KeccakF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plonky3CommitmentScheme {
    Fri,
    Whir,
    Circle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plonky3ChallengeExtension {
    Degree4,
    Degree5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plonky3RecursionBackend {
    pub field: Plonky3Field,
    pub hash: Plonky3Hash,
    pub commitment_scheme: Plonky3CommitmentScheme,
    pub challenge_extension: Plonky3ChallengeExtension,
    pub recursive_batch_stark_layers: bool,
    pub use_poseidon2_in_circuit: bool,
}

impl Plonky3RecursionBackend {
    pub const fn default_for_repo() -> Self {
        Self {
            field: Plonky3Field::KoalaBear,
            hash: Plonky3Hash::Poseidon2,
            commitment_scheme: Plonky3CommitmentScheme::Fri,
            challenge_extension: Plonky3ChallengeExtension::Degree4,
            recursive_batch_stark_layers: true,
            use_poseidon2_in_circuit: true,
        }
    }

    pub const fn recursion_api(self) -> &'static str {
        match self.commitment_scheme {
            Plonky3CommitmentScheme::Fri => "p3_recursion::FriRecursionBackend",
            Plonky3CommitmentScheme::Whir | Plonky3CommitmentScheme::Circle => "unsupported",
        }
    }

    pub const fn poseidon2_config(self) -> &'static str {
        match (self.field, self.challenge_extension) {
            (Plonky3Field::KoalaBear, Plonky3ChallengeExtension::Degree4) => {
                "Poseidon2Config::KoalaBearD4Width16"
            }
            (Plonky3Field::KoalaBear, Plonky3ChallengeExtension::Degree5) => {
                "Poseidon2Config::KoalaBearD4Width16 with quintic witness lifting"
            }
            (Plonky3Field::BabyBear, Plonky3ChallengeExtension::Degree4) => {
                "Poseidon2Config::BabyBearD4Width16"
            }
            (Plonky3Field::Goldilocks, Plonky3ChallengeExtension::Degree4) => {
                "Poseidon2Config::GoldilocksD2Width8"
            }
            _ => "unsupported",
        }
    }

    pub const fn recursion_strategy(self) -> &'static str {
        if self.recursive_batch_stark_layers {
            "Base circuits should target p3_circuit + p3_batch_stark; compress with build_and_prove_next_layer; aggregate with build_and_prove_aggregation_layer."
        } else {
            "unsupported"
        }
    }

    pub const fn rationale(self) -> &'static str {
        match (
            self.field,
            self.hash,
            self.commitment_scheme,
            self.challenge_extension,
            self.recursive_batch_stark_layers,
        ) {
            (
                Plonky3Field::KoalaBear,
                Plonky3Hash::Poseidon2,
                Plonky3CommitmentScheme::Fri,
                Plonky3ChallengeExtension::Degree4,
                true,
            ) => {
                "Prefer the official Plonky3 FRI recursion path with KoalaBear, Poseidon2, and degree-4 recursive challenges. Keep recursive layers on batch-STARK proofs; do not target Whir or quintic recursion for the first end-to-end migration."
            }
            _ => {
                "Non-default backend choice; validate recursion support, ZK support, and proof-size tradeoffs before use."
            }
        }
    }
}

pub const DEFAULT_PLONKY3_RECURSION_BACKEND: Plonky3RecursionBackend =
    Plonky3RecursionBackend::default_for_repo();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_matches_repo_target() {
        let backend = DEFAULT_PLONKY3_RECURSION_BACKEND;
        assert_eq!(backend.field, Plonky3Field::KoalaBear);
        assert_eq!(backend.hash, Plonky3Hash::Poseidon2);
        assert_eq!(backend.commitment_scheme, Plonky3CommitmentScheme::Fri);
        assert_eq!(
            backend.challenge_extension,
            Plonky3ChallengeExtension::Degree4
        );
        assert_eq!(backend.recursion_api(), "p3_recursion::FriRecursionBackend");
        assert_eq!(
            backend.poseidon2_config(),
            "Poseidon2Config::KoalaBearD4Width16"
        );
        assert!(backend.recursive_batch_stark_layers);
        assert!(backend.use_poseidon2_in_circuit);
    }
}
