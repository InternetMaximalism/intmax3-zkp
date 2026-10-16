//! A polynomial-evaluation ("Schwartz-Zippel") argument packaged as a
//! Plonky3 [`LookupGadget`].
//!
//! Each registered [`Lookup`] is interpreted as one *evaluation argument*:
//! for a per-row expression `p_i` over the main trace, the gadget materialises
//! an auxiliary extension-field column `s` satisfying the Horner recurrence
//!
//! ```text
//! s[N-1] = p[N-1]
//! s[i]   = p[i] + z * s[i+1]
//! ```
//!
//! so that `s[0] = P(z) = Σ_i p_i z^i`, where `z` is a random extension-field
//! challenge sampled *after* the main trace is committed. This turns the check
//! of a degree-`< N` polynomial identity into O(N) degree-≤2 constraints —
//! no NTT in the circuit, no quadratic convolution.
//!
//! Exposure semantics follow the lookup [`Kind`]:
//! - [`Kind::Global`]: `s[0]` is published in the proof as the lookup's
//!   `expected_cumulated` value, bound into the Fiat-Shamir transcript, and
//!   pinned by a first-row constraint. Use this for *public* polynomials
//!   (the ciphertext and public key), whose evaluations the verifier
//!   recomputes and compares.
//! - [`Kind::Local`]: nothing is exposed. The running value is still
//!   available to AIR constraints via the permutation trace (first row),
//!   which is how the secret polynomials (`r`, noise, message, quotients)
//!   enter the ring-identity constraints without leaking their evaluations.
//!
//! All evaluation arguments in a proof share a single challenge `z` (sampled
//! once per proof by [`sample_eval_challenges`]), because the ring identities
//! relate several polynomials *at the same point*.

use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use p3_air::{ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_challenger::FieldChallenger;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Kind, Lookup, LookupData, LookupEvaluator, LookupGadget};
use p3_lookup::LookupError;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{StarkGenericConfig, Val};

/// The evaluation-argument gadget. See module docs.
#[derive(Debug, Clone, Default)]
pub struct EvalGadget;

impl EvalGadget {
    pub const fn new() -> Self {
        Self {}
    }
}

/// Samples the shared evaluation challenge `z` and replicates it into the
/// per-instance challenge layout expected by the gadget
/// (`challenges[num_challenges() * column]` for each lookup).
///
/// This replaces `p3_batch_stark::get_perm_challenges`, which samples fresh
/// challenges per `Kind::Local` lookup; the ring identities need every
/// polynomial evaluated at the *same* point.
pub fn sample_eval_challenges<SC: StarkGenericConfig>(
    challenger: &mut SC::Challenger,
    all_lookups: &[Vec<Lookup<Val<SC>>>],
) -> Vec<Vec<SC::Challenge>> {
    let any = all_lookups.iter().any(|l| !l.is_empty());
    let z: Option<SC::Challenge> = any.then(|| challenger.sample_algebra_element());
    all_lookups
        .iter()
        .map(|lookups| vec![z.unwrap_or_default(); lookups.len()])
        .collect()
}

/// Evaluate a base-field symbolic expression at a given trace row.
///
/// Supports the subset of [`SymbolicExpression`] that evaluation arguments
/// use: main-trace variables (offsets 0/1, wrapping), public values,
/// constants, and arithmetic nodes.
fn eval_symbolic_at_row<F: Field>(
    expr: &SymbolicExpression<F>,
    main: &RowMajorMatrix<F>,
    public_values: &[F],
    row: usize,
) -> F {
    match expr {
        SymbolicExpr::Leaf(leaf) => match leaf {
            BaseLeaf::Constant(c) => *c,
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset } => {
                    let h = main.height();
                    main.get((row + offset) % h, v.index)
                        .expect("main column index out of range")
                }
                BaseEntry::Public => public_values[v.index],
                _ => panic!("unsupported leaf entry in evaluation argument"),
            },
            _ => panic!("row selectors are not supported in evaluation arguments"),
        },
        SymbolicExpr::Add { x, y, .. } => {
            eval_symbolic_at_row(x, main, public_values, row)
                + eval_symbolic_at_row(y, main, public_values, row)
        }
        SymbolicExpr::Sub { x, y, .. } => {
            eval_symbolic_at_row(x, main, public_values, row)
                - eval_symbolic_at_row(y, main, public_values, row)
        }
        SymbolicExpr::Neg { x, .. } => -eval_symbolic_at_row(x, main, public_values, row),
        SymbolicExpr::Mul { x, y, .. } => {
            eval_symbolic_at_row(x, main, public_values, row)
                * eval_symbolic_at_row(y, main, public_values, row)
        }
    }
}

impl EvalGadget {
    /// The single per-row expression of an evaluation argument.
    fn element_expr<F: Field>(context: &Lookup<F>) -> &SymbolicExpression<F> {
        assert_eq!(
            context.element_exprs.len(),
            1,
            "evaluation argument takes exactly one expression"
        );
        assert_eq!(context.element_exprs[0].len(), 1);
        assert!(
            context.multiplicities_exprs.is_empty(),
            "evaluation arguments have no multiplicities"
        );
        &context.element_exprs[0][0]
    }

    /// Shared constraint logic. `expected` is `Some` for exposed (global)
    /// arguments and `None` for hidden (local) ones.
    fn eval_horner<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
        expected: Option<AB::ExprEF>,
    ) where
        AB: PermutationAirBuilder,
    {
        let expr = Self::element_expr(context);
        let column = context.columns[0];

        let p: AB::ExprEF = p3_lookup::lookup_traits::symbolic_to_expr(builder, expr).into();

        let challenges = builder.permutation_randomness();
        let z: AB::ExprEF = challenges[self.num_challenges() * column].into();

        let permutation = builder.permutation();
        let s_local: AB::ExprEF = permutation
            .current(column)
            .expect("permutation trace too narrow")
            .into();
        let s_next: AB::ExprEF = permutation
            .next(column)
            .expect("permutation trace too narrow")
            .into();

        // Horner recurrence: s[i] = p[i] + z * s[i+1] on transition rows...
        builder
            .when_transition()
            .assert_zero_ext(s_local.clone() - p.clone() - z * s_next);
        // ...anchored by s[N-1] = p[N-1] on the last row.
        builder.when_last_row().assert_zero_ext(s_local.clone() - p);

        // Exposed arguments additionally pin s[0] = P(z) to the published value.
        if let Some(expected) = expected {
            builder
                .when_first_row()
                .assert_zero_ext(s_local - expected);
        }
    }
}

impl LookupEvaluator for EvalGadget {
    fn num_aux_cols(&self) -> usize {
        1
    }

    fn num_challenges(&self) -> usize {
        1
    }

    fn eval_local_lookup<AB>(&self, builder: &mut AB, context: &Lookup<AB::F>)
    where
        AB: PermutationAirBuilder,
    {
        self.eval_horner(builder, context, None);
    }

    fn eval_global_update<AB>(
        &self,
        builder: &mut AB,
        context: &Lookup<AB::F>,
        expected_cumulated: AB::ExprEF,
    ) where
        AB: PermutationAirBuilder,
    {
        self.eval_horner(builder, context, Some(expected_cumulated));
    }
}

impl LookupGadget for EvalGadget {
    /// Evaluation arguments are verified *outside* this trait: the wrapper
    /// verifier recomputes the public polynomials' evaluations at `z` and
    /// compares them against the published values, then relies on the
    /// in-circuit ring-identity constraints. Nothing to do here.
    fn verify_global_final_value<EF: Field>(&self, _: &[EF]) -> Result<(), LookupError> {
        Ok(())
    }

    fn constraint_degree<F: Field>(&self, context: &Lookup<F>) -> usize {
        // Transition: selector(1) * (s - p - z*s'), where deg(s) = deg(z*s') = 1.
        1 + Self::element_expr(context).degree_multiple().max(1)
    }

    fn generate_permutation<SC: StarkGenericConfig>(
        &self,
        main: &RowMajorMatrix<Val<SC>>,
        _preprocessed: &Option<RowMajorMatrix<Val<SC>>>,
        public_values: &[Val<SC>],
        lookups: &[Lookup<Val<SC>>],
        lookup_data: &mut [LookupData<SC::Challenge>],
        permutation_challenges: &[SC::Challenge],
    ) -> RowMajorMatrix<SC::Challenge> {
        let height = main.height();
        let width: usize = lookups.len() * self.num_aux_cols();
        debug_assert_eq!(
            permutation_challenges.len(),
            lookups.len() * self.num_challenges()
        );

        let mut perm = RowMajorMatrix::new(SC::Challenge::zero_vec(height * width), width);

        for lookup in lookups {
            let col = lookup.columns[0];
            let expr = Self::element_expr(lookup);
            let z = permutation_challenges[self.num_challenges() * col];

            // Horner from the bottom: s[N-1] = p[N-1], s[i] = p[i] + z*s[i+1].
            let mut acc = SC::Challenge::ZERO;
            for row in (0..height).rev() {
                let p = eval_symbolic_at_row(expr, main, public_values, row);
                acc = acc * z + p;
                perm.values[row * width + col] = acc;
            }

            // Publish s[0] = P(z) for exposed (global) arguments.
            if matches!(lookup.kind, Kind::Global(_)) {
                let data = lookup_data
                    .iter_mut()
                    .find(|d| d.aux_idx == col)
                    .expect("missing LookupData for global evaluation argument");
                data.expected_cumulated = acc;
            }
        }

        perm
    }
}
