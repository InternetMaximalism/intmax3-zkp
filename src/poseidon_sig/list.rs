//! The **IMLL `(message, public_key)` hash-chain format** — the shared, format-stable commitment
//! the signature-list proof produces and its consumers rebuild.
//!
//! Order-sensitive Poseidon hash chain:
//!   - `leaf_i  = Poseidon([LIST_LEAF_DOMAIN] ‖ m_i ‖ pk_i)`
//!   - `C_0     = 0` (the empty chain)
//!   - `C_i     = Poseidon(C_{i-1} ‖ leaf_i)`   (two-to-one)
//!
//! The final `C_N` (a `Bytes32`) commits to the exact ordered multiset of `(m, pk)` pairs that were
//! each backed by a verified signature. A consumer (the validity circuit) recursively verifies the
//! list proof, rebuilds the same chain from the `(m, pk)` pairs it requires, and asserts equality —
//! so it learns "these messages were signed by these keys" without re-running any signature check.
//!
//! This module owns ONLY the FORMAT: the native reference (`list_leaf` / `list_chain_step` /
//! `list_commitment`) and the in-circuit gadgets (`leaf_target` / `chain_step_target`) that the
//! producer and every consumer share, so the chain is computed by identical constraints on both
//! sides. The PRODUCER — the circuit that verifies a signature and folds one pair per step — lives
//! in [`crate::falcon_sig::list`] (falcon-sig Phase 3: it verifies a Falcon-512/Poseidon signature
//! directly in-circuit; it previously recursively verified a `SingleSigCircuit` proof). The format
//! below is UNCHANGED by that swap and MUST stay unchanged: `update_channel_tree.rs` folds
//! `(IMSB digest, bp_pk_g)` with these very gadgets and the validity circuit asserts equality
//! against the list proof's commitment.

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

/// Domain separator for a list leaf `Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)`. ASCII "IMLL".
pub const LIST_LEAF_DOMAIN: u32 = 0x494d_4c4c;

// ----------------------------------------------------------------------------------------------
// Native reference (must match the in-circuit computation bit-for-bit; used by consumers + tests).
// ----------------------------------------------------------------------------------------------

/// `leaf = Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)` — message first, then public key (the `<message,
/// pubkey>` list semantics).
pub fn list_leaf(message: Bytes32, public_key: Bytes32) -> PoseidonHashOut {
    let mut inputs = Vec::with_capacity(1 + 2 * BYTES32_LEN);
    inputs.push(LIST_LEAF_DOMAIN as u64);
    inputs.extend(message.to_u32_vec().into_iter().map(u64::from));
    inputs.extend(public_key.to_u32_vec().into_iter().map(u64::from));
    PoseidonHashOut::hash_inputs_u64(&inputs)
}

/// `C' = Poseidon(prev ‖ leaf)` (two-to-one), matching `PoseidonHashOutTarget::two_to_one`.
pub fn list_chain_step(prev: PoseidonHashOut, leaf: PoseidonHashOut) -> PoseidonHashOut {
    let mut inputs = Vec::with_capacity(2 * crate::utils::poseidon_hash_out::POSEIDON_HASH_OUT_LEN);
    inputs.extend_from_slice(&prev.elements);
    inputs.extend_from_slice(&leaf.elements);
    PoseidonHashOut::hash_inputs_u64(&inputs)
}

/// The chain commitment over an ordered list of `(message, public_key)` pairs, folded from `C_0 =
/// 0`.
pub fn list_commitment(pairs: &[(Bytes32, Bytes32)]) -> Bytes32 {
    let mut chain = PoseidonHashOut::default();
    for (message, public_key) in pairs {
        chain = list_chain_step(chain, list_leaf(*message, *public_key));
    }
    chain.into()
}

// ----------------------------------------------------------------------------------------------
// Shared in-circuit gadgets — used by BOTH the producer (`falcon_sig::list::ListStepCircuit`,
// relocated in Phase 3 when the step swapped recursive SingleSig verification for direct
// in-circuit Falcon verification) and the consumer
// (`super::consumer`), so the folded commitment is computed by identical constraints on both sides.
// ----------------------------------------------------------------------------------------------

/// In-circuit `leaf = Poseidon([LIST_LEAF_DOMAIN] ‖ m ‖ pk)`. Mirrors [`list_leaf`].
///
/// Generic over the field so the SAME gadget can be used by the producer (`ListStepCircuit`), the
/// consumer, and the validity/close circuits — guaranteeing the folded commitment is computed by
/// identical constraints everywhere (the validity path uses `F = GoldilocksField, D = 2`).
pub(crate) fn leaf_target<GF: RichField + Extendable<GD>, const GD: usize>(
    builder: &mut CircuitBuilder<GF, GD>,
    message: &Bytes32Target,
    public_key: &Bytes32Target,
) -> PoseidonHashOutTarget {
    let dom = builder.constant(GF::from_canonical_u32(LIST_LEAF_DOMAIN));
    let mut inputs = Vec::with_capacity(1 + 2 * BYTES32_LEN);
    inputs.push(dom);
    inputs.extend(message.to_vec());
    inputs.extend(public_key.to_vec());
    PoseidonHashOutTarget::hash_inputs(builder, &inputs)
}

/// In-circuit `C' = Poseidon(prev ‖ leaf)`. Mirrors [`list_chain_step`]. Generic over the field
/// for the same shared-gadget reason as [`leaf_target`].
pub(crate) fn chain_step_target<GF: RichField + Extendable<GD>, const GD: usize>(
    builder: &mut CircuitBuilder<GF, GD>,
    prev: PoseidonHashOutTarget,
    leaf: PoseidonHashOutTarget,
) -> PoseidonHashOutTarget {
    PoseidonHashOutTarget::two_to_one(builder, prev, leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(byte: u8) -> Bytes32 {
        Bytes32::from_u32_slice(&[0x494d_0000 | byte as u32, 9, 8, 7, 6, 5, 4, 3]).unwrap()
    }

    #[test]
    fn native_chain_is_order_sensitive_and_deterministic() {
        let a = (message(1), message(0x10));
        let b = (message(2), message(0x20));
        assert_eq!(list_commitment(&[a, b]), list_commitment(&[a, b]));
        assert_ne!(list_commitment(&[a, b]), list_commitment(&[b, a]));
        assert_ne!(list_commitment(&[a]), list_commitment(&[a, b]));
        // The empty list is the zero chain (the value the validity circuit gates on).
        assert_eq!(list_commitment(&[]), Bytes32::zero());
        // LIST_LEAF_DOMAIN is distinct from the signature domains.
        assert_eq!(LIST_LEAF_DOMAIN, u32::from_be_bytes(*b"IMLL"));
        assert_ne!(LIST_LEAF_DOMAIN, super::super::DOMAIN_PK_G);
        assert_ne!(LIST_LEAF_DOMAIN, super::super::DOMAIN_SIG_G);
        assert_ne!(LIST_LEAF_DOMAIN, crate::falcon_sig::DOMAIN_FALCON_PK);
    }

    /// SECURITY (documents the boundary): the chain binds the ORDERED pairs but does NOT enforce
    /// pubkey distinctness — appending the same (m, pk) twice yields a well-defined, distinct
    /// commitment. Distinctness / all-members-present / pk-in-member-set are CONSUMER obligations
    /// (threat model 2.4.3, A5/A8).
    #[test]
    fn duplicate_entries_are_accepted_at_chain_level() {
        let pair = (message(0xd0), message(0xd1));
        assert_ne!(list_commitment(&[pair]), list_commitment(&[pair, pair]));
    }
}
