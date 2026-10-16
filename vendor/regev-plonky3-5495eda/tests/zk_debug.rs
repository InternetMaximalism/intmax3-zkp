//! Minimal isolation tests for the ZK (hiding FRI) path.

use p3_air::symbolic::{BaseEntry, SymbolicVariable};
use p3_air::{Air, BaseAir, PermutationAirBuilder};
use p3_batch_stark::common::{CommonData, ProverData};
use p3_batch_stark::prover::StarkInstance;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::lookup_traits::{Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use regev_plonky3::config::{zk_config_seeded, Val};

/// One main column, one evaluation argument, no other constraints.
#[derive(Clone, Debug)]
struct TrivialAir {
    global: bool,
}

impl<F: p3_field::Field> BaseAir<F> for TrivialAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<F: p3_field::Field> LookupAir<F> for TrivialAir {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let kind = if self.global {
            Kind::Global("eval:x".to_string())
        } else {
            Kind::Local
        };
        vec![Lookup {
            kind,
            element_exprs: vec![vec![
                SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 0).into(),
            ]],
            multiplicities_exprs: vec![],
            columns: vec![0],
        }]
    }
}

impl<AB: PermutationAirBuilder> Air<AB> for TrivialAir {
    fn eval(&self, _builder: &mut AB) {}
}

/// Two main columns, two eval arguments, plus a first-row constraint that
/// multiplies the two permutation columns — the shape of the ring-identity
/// ("master") constraints in RegevEncAir.
#[derive(Clone, Debug)]
struct ProductAir;

impl<F: p3_field::Field> BaseAir<F> for ProductAir {
    fn width(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<F: p3_field::Field> LookupAir<F> for ProductAir {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        (0..2)
            .map(|c| Lookup {
                kind: Kind::Global(format!("eval:{c}")),
                element_exprs: vec![vec![
                    SymbolicVariable::new(BaseEntry::Main { offset: 0 }, c).into(),
                ]],
                multiplicities_exprs: vec![],
                columns: vec![c],
            })
            .collect()
    }
}

impl<AB: PermutationAirBuilder> Air<AB> for ProductAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::{ExtensionBuilder, WindowAccess};
        // deg-3 main constraint, like the ternary check.
        let main = builder.main();
        let x: AB::Expr = main.current_slice()[0].into();
        builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x + AB::Expr::ONE));

        // first-row constraint with a product of two perm columns, like the
        // ring identities: s0 * s1 - pv0 * pv1 = 0 (true for our witness
        // since pv_i = s_i[0]).
        let perm = builder.permutation();
        let s0: AB::ExprEF = perm.current(0).unwrap().into();
        let s1: AB::ExprEF = perm.current(1).unwrap().into();
        let pv0: AB::ExprEF = builder.permutation_values()[0].clone().into();
        let pv1: AB::ExprEF = builder.permutation_values()[1].clone().into();
        builder
            .when_first_row()
            .assert_zero_ext(s0 * s1 - pv0 * pv1);
    }
}

/// Degree-3 main constraint only (no permutation product): isolates
/// whether the failure is the quotient-chunk accounting (lq = 2) or the
/// permutation product itself.
#[derive(Clone, Debug)]
struct CubeAir;

impl<F: p3_field::Field> BaseAir<F> for CubeAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<F: p3_field::Field> LookupAir<F> for CubeAir {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        vec![Lookup {
            kind: Kind::Local,
            element_exprs: vec![vec![
                SymbolicVariable::new(BaseEntry::Main { offset: 0 }, 0).into(),
            ]],
            multiplicities_exprs: vec![],
            columns: vec![0],
        }]
    }
}

impl<AB: PermutationAirBuilder> Air<AB> for CubeAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::WindowAccess;
        let main = builder.main();
        let x: AB::Expr = main.current_slice()[0].into();
        builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x + AB::Expr::ONE));
    }
}

#[test]
fn zk_degree3_main_constraint() {
    let config = zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(11));
    let air = CubeAir;
    let mut rng = SmallRng::seed_from_u64(12);
    let vals: Vec<Val> = (0..128)
        .map(|_| {
            let t: i32 = rng.random_range(-1..=1);
            if t < 0 {
                -Val::ONE
            } else {
                Val::from_u32(t as u32)
            }
        })
        .collect();
    let trace = RowMajorMatrix::new(vals, 1);

    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: vec![],
        lookups: air.clone().get_lookups(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = regev_plonky3::stark::prove_batch(&config, &instances, &prover_data);

    let common = CommonData::new(None, vec![air.clone().get_lookups()]);
    regev_plonky3::stark::verify_batch(&config, &[air], &proof, &[vec![]], &common)
        .expect("zk proof with degree-3 main constraint verifies");
}

#[test]
fn zk_product_first_row_constraint() {
    let config = zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(321));
    let air = ProductAir;
    let mut rng = SmallRng::seed_from_u64(6);
    // col 0 ternary-ish (vals in {-1,0,1}) so the deg-3 constraint holds.
    let vals: Vec<Val> = (0..128)
        .flat_map(|_| {
            let t: i32 = rng.random_range(-1..=1);
            let v = if t < 0 { -Val::ONE } else { Val::from_u32(t as u32) };
            [v, rng.random()]
        })
        .collect();
    let trace = RowMajorMatrix::new(vals, 2);

    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: vec![],
        lookups: air.clone().get_lookups(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = regev_plonky3::stark::prove_batch(&config, &instances, &prover_data);

    let common = CommonData::new(None, vec![air.clone().get_lookups()]);
    regev_plonky3::stark::verify_batch(&config, &[air], &proof, &[vec![]], &common)
        .expect("zk proof with product first-row constraint verifies");
}

fn run(global: bool) {
    let config = zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(123));
    let air = TrivialAir { global };
    let mut rng = SmallRng::seed_from_u64(5);
    let trace = RowMajorMatrix::new((0..64).map(|_| rng.random()).collect::<Vec<Val>>(), 1);

    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: vec![],
        lookups: air.clone().get_lookups(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = regev_plonky3::stark::prove_batch(&config, &instances, &prover_data);

    let common = CommonData::new(None, vec![air.clone().get_lookups()]);
    regev_plonky3::stark::verify_batch(&config, &[air], &proof, &[vec![]], &common)
        .expect("trivial zk proof verifies");
}

#[test]
fn zk_local_eval_argument() {
    run(false);
}

#[test]
fn zk_global_eval_argument() {
    run(true);
}

/// Pure upstream check: p3-uni-stark + HidingFriPcs with a degree-3
/// constraint (no lookups, none of our vendored code). If this fails, the
/// quotient-chunk randomization bug is upstream.
mod upstream {
    use super::*;
    use p3_air::AirBuilder;

    #[derive(Clone, Debug)]
    pub struct PlainCubeAir;

    impl<F> BaseAir<F> for PlainCubeAir {
        fn width(&self) -> usize {
            1
        }
        fn main_next_row_columns(&self) -> Vec<usize> {
            vec![]
        }
        fn max_constraint_degree(&self) -> Option<usize> {
            Some(3)
        }
    }

    impl<AB: AirBuilder> Air<AB> for PlainCubeAir {
        fn eval(&self, builder: &mut AB) {
            use p3_air::WindowAccess;
            let main = builder.main();
            let x: AB::Expr = main.current_slice()[0].into();
            builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x + AB::Expr::ONE));
        }
    }

    #[test]
    fn zk_uni_stark_degree3() {
        let config = zk_config_seeded(regev_plonky3::config::ZkRng::seed_from_u64(31));
        let mut rng = SmallRng::seed_from_u64(32);
        let vals: Vec<Val> = (0..128)
            .map(|_| {
                let t: i32 = rng.random_range(-1..=1);
                if t < 0 {
                    -Val::ONE
                } else {
                    Val::from_u32(t as u32)
                }
            })
            .collect();
        let trace = RowMajorMatrix::new(vals, 1);
        let proof = p3_uni_stark::prove(&config, &PlainCubeAir, trace, &[]);
        p3_uni_stark::verify(&config, &PlainCubeAir, &proof, &[])
            .expect("upstream uni-stark zk deg-3 verifies");
    }
}
