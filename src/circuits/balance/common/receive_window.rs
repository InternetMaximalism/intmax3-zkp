//! Authenticated receive intervals. The latest channel leaf commits the last outgoing block.
//! If that block is already covered by prev_block_r, there are NO outgoing transactions in the
//! tail (prev_block_r, public_state.block_number]. Otherwise a send-tree interval is required.
use crate::common::u63::{BlockNumber, BlockNumberTarget};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

pub fn requires_send_interval(last: BlockNumber, previous: BlockNumber) -> bool {
    if cfg!(feature = "authenticated-tail-receive") {
        last > previous
    } else {
        last != BlockNumber::default()
    }
}

pub fn requires_send_interval_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    last: &BlockNumberTarget,
    previous: &BlockNumberTarget,
) -> BoolTarget {
    if cfg!(feature = "authenticated-tail-receive") {
        has_unprocessed_send(builder, last, previous)
    } else {
        let zero = last.is_zero(builder);
        builder.not(zero)
    }
}

pub fn has_unprocessed_send<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    last: &BlockNumberTarget,
    previous: &BlockNumberTarget,
) -> BoolTarget {
    // Both values are canonical 63-bit counters. Avoid field subtraction/wraparound comparisons.
    let a = builder.split_le(last.value, 63);
    let b = builder.split_le(previous.value, 63);
    let mut greater = builder._false();
    for (a, b) in a.iter().zip(b.iter()) {
        let equal = builder.is_equal(a.target, b.target);
        greater = BoolTarget::new_unsafe(builder.select(equal, greater.target, a.target));
    }
    greater
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    #[test]
    fn authenticated_tail_comparison_including_u63_boundaries() {
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;
        let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let last = BlockNumberTarget::new(&mut b, true);
        let previous = BlockNumberTarget::new(&mut b, true);
        let later = has_unprocessed_send(&mut b, &last, &previous);
        b.register_public_input(later.target);
        let data = b.build::<C>();
        for (a, p) in [
            (0, 0),
            (7, 7),
            (7, 9),
            (9, 7),
            ((1u64 << 63) - 1, 0),
            (0, (1u64 << 63) - 1),
            ((1u64 << 63) - 1, (1u64 << 63) - 1),
        ] {
            let mut w = PartialWitness::new();
            w.set_target(last.value, F::from_canonical_u64(a)).unwrap();
            w.set_target(previous.value, F::from_canonical_u64(p))
                .unwrap();
            let proof = data.prove(w).unwrap();
            assert_eq!(proof.public_inputs[0], if a > p { F::ONE } else { F::ZERO });
            data.verify(proof).unwrap();
        }
    }
}
