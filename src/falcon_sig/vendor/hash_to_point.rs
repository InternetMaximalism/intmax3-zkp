//! VENDOR EDIT — this file is the ONE intentional functional change in the vendor tree
//! (threat model `doc/tasks/falcon-sig-threat-model.md` TM-C1, obligation O-1).
//!
//! Upstream instantiates hash-to-point with the Miden Poseidon2 (RPO-family) permutation. This
//! copy instantiates it with the in-tree plonky2 Poseidon permutation over Goldilocks
//! (width 12, rate 8, capacity 4) so the Phase-1 close-circuit gadget can recompute `c` with
//! native plonky2 gates. The sponge structure (overwrite-mode absorb of salt then message,
//! then a fixed 64-permutation squeeze of 512 coefficients, one FULL field element per
//! coefficient reduced mod q with no rejection sampling) follows the upstream construction and
//! the Falcon specification's sanctioned no-rejection variant.

use alloc::vec::Vec;

use plonky2::{
    field::types::{Field as _, PrimeField64 as _},
    hash::poseidon::{Poseidon as _, SPONGE_RATE, SPONGE_WIDTH},
};

use super::{MODULUS, N, Nonce, Polynomial, math::FalconFelt};
use crate::{
    ethereum_types::u32limb_trait::U32LimbTrait as _,
    falcon_sig::{
        DOMAIN_FALCON_H2P,
        compat::{Felt, Word, ZERO},
    },
};

// HASH-TO-POINT FUNCTION
// ================================================================================================

/// Returns a polynomial in `Z_p[x]/(phi)` representing the hash of the provided message digest
/// and nonce (salt), using the in-tree plonky2 Poseidon permutation.
///
/// Sponge layout (fixed, documented for the Phase-1 in-circuit mirror, O-2):
///
/// - State: 12 Goldilocks elements; rate = `state[0..8]`, capacity = `state[8..12]`.
/// - SECURITY (TM-C1 domain separation): the capacity is initialized to `[IMFH, 0, 0, 0]` where
///   `IMFH = 0x494d4648` (ASCII "IMFH"). Every other Poseidon sponge in this codebase
///   (`hash_no_pad` and friends) runs with an all-zero capacity, so a nonzero capacity constant
///   separates this hash from every existing Poseidon use; IMFH is also distinct from every
///   registered IMxx domain constant (see the `falcon_domains_do_not_collide` test in
///   `falcon_sig`).
/// - Absorb block 1 (overwrite mode): the 40-byte salt as 8 field elements of 5 little-endian bytes
///   each (`Nonce::to_elements`, upstream's packing). Each element is `< 2^40 < p`, so the salt ->
///   elements map is injective and canonical. Then one permutation.
/// - Absorb block 2 (overwrite mode): the 32-byte message digest as its 8 canonical u32 limbs
///   (`Bytes32::to_u32_vec`, the same limb decomposition used for IMCH digests throughout the
///   codebase), each lifted with `from_canonical_u32`. This overwrites the full rate; state
///   continuity is carried by the 4-element (256-bit) capacity, which is the standard
///   overwrite-mode sponge argument (128-bit sponge security).
/// - Squeeze: 64 iterations of (permute, read `state[0..8]`), producing exactly 512 coefficients.
///   Both the absorbed input (16 elements) and the squeeze count are compile-time-fixed, so no
///   length framing is required (fixed-arity convention, as in `poseidon_sig`).
///
/// SECURITY (O-1 / A-F3 bias argument): each coefficient consumes ONE FULL 64-bit field element
/// reduced mod q = 12289. Mapping the `2^64 - 2^32 + 1` field values onto `12289` residues is
/// non-uniform by at most `q / p ~= 2^-50` per coefficient (~`2^-41` statistical distance over
/// all 512 coefficients) — the Falcon specification's sanctioned no-rejection variant, accepted
/// in the threat model (A-F3). Never split one element across coefficients and never reuse
/// sponge output for two coefficients: either would correlate coefficients and void the bias
/// bound.
pub fn hash_to_point_poseidon(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
    let mut state = [ZERO; SPONGE_WIDTH];

    // SECURITY: capacity domain separation — see the sponge layout doc above (TM-C1).
    state[SPONGE_RATE] = Felt::from_canonical_u32(DOMAIN_FALCON_H2P);

    // absorb the nonce (salt) into the rate portion of the state
    let nonce_elements = nonce.to_elements();
    state[..SPONGE_RATE].copy_from_slice(&nonce_elements);
    state = Felt::poseidon(state);

    // absorb the message digest limbs into the rate portion of the state (overwrite mode)
    for (s, limb) in state[..SPONGE_RATE].iter_mut().zip(message.to_u32_vec()) {
        *s = Felt::from_canonical_u32(limb);
    }

    // squeeze the coefficients of the polynomial
    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    for _ in 0..(N / SPONGE_RATE) {
        state = Felt::poseidon(state);
        state[..SPONGE_RATE]
            .iter()
            .for_each(|value| coefficients.push(felt_to_falcon_felt(*value)));
    }

    Polynomial::new(coefficients)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a Goldilocks field element to a field element in the prime field with characteristic
/// the Falcon prime.
///
/// Note that since `FalconFelt::new` accepts `i16`, we first reduce the canonical value of
/// the Goldilocks field element modulo the Falcon prime and then cast the resulting value to an
/// `i16`. Note that this final cast is safe as the Falcon prime is less than `i16::MAX`.
fn felt_to_falcon_felt(value: Felt) -> FalconFelt {
    FalconFelt::new((value.to_canonical_u64() % MODULUS as u64) as i16)
}
