use intmax3_zkp::{
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};

type F = GoldilocksField;

#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn backing_hash_bytes_are_canonical_at_field_boundaries() {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let hash = PoseidonHashOutTarget::new(&mut builder);
    let bytes = Bytes32Target::from_hash_out(&mut builder, hash);
    let limbs = bytes.to_vec();
    builder.register_public_inputs(&limbs);
    let data = builder.build::<PoseidonGoldilocksConfig>();
    let p = 0xffff_ffff_0000_0001u64;
    let edges = [
        0,
        1,
        (1u64 << 32) - 2,
        (1u64 << 32) - 1,
        1u64 << 32,
        p - 2,
        p - 1,
    ];
    for offset in 0..edges.len() {
        let values = std::array::from_fn(|i| edges[(offset + i) % edges.len()]);
        let mut witness = PartialWitness::new();
        for (target, value) in hash.elements.iter().zip(values) {
            witness
                .set_target(*target, F::from_canonical_u64(value))
                .unwrap();
        }
        let proof = data.prove(witness).unwrap();
        let expected: Bytes32 = PoseidonHashOut { elements: values }.into();
        assert_eq!(
            proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .collect::<Vec<_>>(),
            expected.to_u64_vec()
        );
        data.verify(proof).unwrap();
    }
    // x and x+p share a field value but must not share an accepted byte encoding.
    for x in [0, 1, (1u64 << 32) - 2] {
        let mut witness = PartialWitness::new();
        for target in hash.elements {
            witness
                .set_target(target, F::from_canonical_u64(x))
                .unwrap();
        }
        let alias = x + p;
        witness
            .set_target(limbs[0], F::from_canonical_u64(alias >> 32))
            .unwrap();
        witness
            .set_target(limbs[1], F::from_canonical_u64(alias & 0xffff_ffff))
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(witness)));
        let accepted = match result {
            Ok(Ok(proof)) => data.verify(proof).is_ok(),
            _ => false,
        };
        assert!(!accepted, "noncanonical alias for {x} accepted");
    }
}
