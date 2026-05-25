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
pub struct Plonky3RecursionBackend {
    pub field: Plonky3Field,
    pub hash: Plonky3Hash,
    pub fri_recursion: bool,
    pub use_poseidon2_in_circuit: bool,
}

impl Plonky3RecursionBackend {
    pub const fn default_for_repo() -> Self {
        Self {
            field: Plonky3Field::KoalaBear,
            hash: Plonky3Hash::Poseidon2,
            fri_recursion: true,
            use_poseidon2_in_circuit: true,
        }
    }

    pub const fn recursion_api(self) -> &'static str {
        if self.fri_recursion {
            "p3_recursion::FriRecursionBackend"
        } else {
            "unsupported"
        }
    }

    pub const fn rationale(self) -> &'static str {
        match (self.field, self.hash, self.fri_recursion) {
            (Plonky3Field::KoalaBear, Plonky3Hash::Poseidon2, true) => {
                "Prefer the public Plonky3 FRI recursion path with KoalaBear and Poseidon2 for small recursive layers."
            }
            _ => "Non-default backend choice; validate recursion support and proof-size tradeoffs before use.",
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
        assert_eq!(backend.recursion_api(), "p3_recursion::FriRecursionBackend");
        assert!(backend.use_poseidon2_in_circuit);
    }
}
