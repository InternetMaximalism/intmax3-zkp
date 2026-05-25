use super::recursively_verifiable::KoalaRecursionProof;

pub fn empty_recursion_chain() -> Option<KoalaRecursionProof> {
    None
}

pub fn is_empty_recursion_chain(proof: &Option<KoalaRecursionProof>) -> bool {
    proof.is_none()
}
