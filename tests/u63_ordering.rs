//! Regression for modular-wrap acceptance in the previous U63 comparison gates.
//! All four operations check canonical boundaries and reject active out-of-range inputs.
//! Disabled conditional checks must remain vacuous even for unchecked operands.
use intmax3_zkp::common::u63::U63Target;
use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, types::Field},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig as C,
    },
};
#[test]
#[cfg_attr(debug_assertions, ignore = "run with --release")]
fn u63_comparisons_match_integer_order_and_disabled_checks_are_vacuous() {
    let top = (1u64 << 63) - 1;
    let bound = (1u64 << 63) - (1u64 << 32) + 1;
    let mut pairs = vec![
        (0, 0),
        (1, 0),
        (0, 1),
        (top, top),
        (top, 0),
        (0, top),
        (bound, 0),
        (0, bound),
        (bound + 1, 0),
        (0, bound + 1),
        (top - 1, top),
        (top, top - 1),
    ];
    for i in 0..8u64 {
        pairs.push(((i * 7919 + 19) << 39, (i * 104729 + 7) << 35));
    }
    for kind in ["ge", "gt", "conditional_ge", "conditional_gt"] {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let a = U63Target::new(&mut builder, false);
        let b = U63Target::new(&mut builder, false);
        let enabled = builder.add_virtual_bool_target_safe();
        match kind {
            "ge" => a.enforce_ge(&mut builder, &b),
            "gt" => a.enforce_gt(&mut builder, &b),
            "conditional_ge" => a.conditional_ge(&mut builder, &b, enabled),
            "conditional_gt" => a.conditional_gt(&mut builder, &b, enabled),
            _ => unreachable!(),
        }
        builder.register_public_inputs(&[a.value, b.value, enabled.target]);
        let data = builder.build::<C>();
        let mut count = 0;
        let mut rejected = 0;
        let conditional = kind.starts_with("conditional");
        let strict = kind.ends_with("gt");
        let mut cases: Vec<_> = pairs.iter().map(|&(x, y)| (x, y, true)).collect();
        cases.extend([
            (top + 1, 0, true),
            (0, top + 1, true),
            (top + 1, top + 1, true),
            (u64::MAX - (1u64 << 32), 0, true),
            (0, u64::MAX - (1u64 << 32), true),
        ]);
        if conditional {
            cases.extend(pairs.iter().map(|&(x, y)| (x, y, false)));
            cases.extend([
                (u64::MAX - (1u64 << 32), top, false),
                (0, u64::MAX - (1u64 << 32), false),
            ]);
        }
        for (x, y, on) in cases {
            let mut pw = PartialWitness::new();
            pw.set_target(a.value, F::from_canonical_u64(x)).unwrap();
            pw.set_target(b.value, F::from_canonical_u64(y)).unwrap();
            pw.set_bool_target(enabled, on).unwrap();
            let ok = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(pw)))
            {
                Ok(Ok(proof)) => data.verify(proof).is_ok(),
                _ => false,
            };
            let expected =
                conditional && !on || (x <= top && y <= top && if strict { x > y } else { x >= y });
            assert_eq!(ok, expected, "{kind}: x={x}, y={y}, enabled={on}");
            count += 1;
            if !ok {
                rejected += 1;
            }
        }
        println!("{{\"operation\":\"{kind}\",\"cases\":{count},\"correctly_rejected\":{rejected},\"all_match_native\":true}}");
    }
}
