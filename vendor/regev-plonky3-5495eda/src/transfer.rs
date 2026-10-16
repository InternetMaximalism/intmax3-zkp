//! Transfer AIR: proves a value-level conservation law across three
//! ciphertexts in one STARK instance.
//!
//! # Statement
//!
//! Given three ciphertexts under the same public key `(a, b)` —
//! `before`, `delta`, `after` — the proof shows that each is a well-formed
//! encryption (same constraints as [`crate::air::RegevEncAir`]) **and** that
//! their plaintext *values* satisfy the conservation law
//!
//! ```text
//! before = after + delta        (as n-bit integers)
//! ```
//!
//! i.e. `delta = before − after` is exactly the amount removed from the
//! balance, with **no underflow possible**: `after` and `delta` are
//! committed bit vectors, hence non-negative, and the bit-addition is exact.
//!
//! # How
//!
//! The three message-bit columns are linked by a ripple-carry adder, one bit
//! per row, using a single carry column `c`:
//!
//! ```text
//! after[i] + delta[i] + c[i] = before[i] + 2·c[i+1]      (transition rows)
//! c[0] = 0                                               (first row)
//! after[n-1] + delta[n-1] + c[n-1] = before[n-1]         (last row: carry out 0)
//! c[i] ∈ {0, 1}
//! ```
//!
//! All degree ≤ 2. The last-row form forces the final carry to be zero, so
//! the equation holds over the integers (no wraparound mod `2^n`).
//!
//! This proves the relation between *independently encrypted* values without
//! any homomorphic evaluation. It composes with the additive homomorphism of
//! the scheme itself (see [`crate::regev::add_ciphertexts`]): e.g. a verifier
//! may homomorphically add proven ciphertexts, while transfers between
//! separately-held balances are proven here.
//!
//! # Layout
//!
//! One instance = one transfer, trace height `n`. Main columns: shared
//! `a, b`, then ten columns per ciphertext (as in `RegevEncAir`, minus the
//! shared `a, b`), then the carry:
//!
//! ```text
//! a b | c1 c2 r e1u e1v e2u e2v m k1 k2 |×3 (before, delta, after) | carry
//! ```
//!
//! Aux (permutation) columns: Horner evaluations of `a, b` (exposed) and,
//! per ciphertext, `c1, c2` (exposed) + `r, e1, e2, m, k1, k2` (hidden) —
//! 26 extension-field columns. The verifier recomputes the 8 exposed
//! evaluations from the claimed statement, exactly as in the single
//! ciphertext proof.

use p3_air::symbolic::{BaseEntry, SymbolicAirBuilder, SymbolicExpressionExt, SymbolicVariable};
use p3_air::DebugConstraintBuilder;
use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_batch_stark::common::{CommonData, ProverData};
use p3_batch_stark::config::{Challenge, Domain, PcsError, StarkGenericConfig, Val};
use p3_batch_stark::proof::BatchProof;
use p3_batch_stark::prover::StarkInstance;
use p3_commit::PolynomialSpace;
use p3_field::{Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::lookup_traits::{Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::params::RegevParams;
use crate::prove::RegevVerifyError;
use crate::regev::{centered_to_field, Ciphertext, EncryptionWitness, PublicKey, F};
use crate::stark;

// Shared main columns.
pub const TCOL_A: usize = 0;
pub const TCOL_B: usize = 1;
/// Number of per-ciphertext main columns.
pub const CT_COLS: usize = 10;
// Per-ciphertext offsets, relative to `ct_base(j)`.
pub const OFF_C1: usize = 0;
pub const OFF_C2: usize = 1;
pub const OFF_R: usize = 2;
pub const OFF_E1U: usize = 3;
pub const OFF_E1V: usize = 4;
pub const OFF_E2U: usize = 5;
pub const OFF_E2V: usize = 6;
pub const OFF_M: usize = 7;
pub const OFF_K1: usize = 8;
pub const OFF_K2: usize = 9;
/// Carry column of the ripple-carry adder.
pub const TCOL_CARRY: usize = 2 + 3 * CT_COLS;
pub const TNUM_COLS: usize = TCOL_CARRY + 1;

/// Ciphertext roles, in column order.
pub const ROLE_BEFORE: usize = 0;
pub const ROLE_DELTA: usize = 1;
pub const ROLE_AFTER: usize = 2;

/// First main column of ciphertext `j`.
pub const fn ct_base(j: usize) -> usize {
    2 + j * CT_COLS
}

// Aux (permutation) columns: a, b exposed, then 8 per ciphertext
// (c1, c2 exposed; r, e1, e2, m, k1, k2 hidden).
pub const TAUX_A: usize = 0;
pub const TAUX_B: usize = 1;
pub const CT_AUX: usize = 8;
pub const AOFF_C1: usize = 0;
pub const AOFF_C2: usize = 1;
pub const AOFF_R: usize = 2;
pub const AOFF_E1: usize = 3;
pub const AOFF_E2: usize = 4;
pub const AOFF_M: usize = 5;
pub const AOFF_K1: usize = 6;
pub const AOFF_K2: usize = 7;
pub const TNUM_AUX: usize = 2 + 3 * CT_AUX;

pub const fn aux_base(j: usize) -> usize {
    2 + j * CT_AUX
}

/// A transfer statement: three ciphertexts under the same public key whose
/// plaintext values satisfy `before = after + delta`.
#[derive(Clone, Debug)]
pub struct Transfer {
    pub before: Ciphertext,
    pub delta: Ciphertext,
    pub after: Ciphertext,
}

/// The prover's secret inputs for one transfer.
#[derive(Clone, Debug)]
pub struct TransferWitness {
    pub before: EncryptionWitness,
    pub delta: EncryptionWitness,
    pub after: EncryptionWitness,
}

/// AIR for one transfer (three well-formed encryptions + ripple-carry
/// conservation `before = after + delta`).
#[derive(Clone, Debug)]
pub struct RegevTransferAir<F> {
    pub n: usize,
    pub delta_scale: F,
}

impl<F: Field> RegevTransferAir<F> {
    pub fn new(n: usize, delta_scale: F) -> Self {
        assert!(n.is_power_of_two());
        Self { n, delta_scale }
    }

    fn main_var(col: usize) -> SymbolicVariable<F> {
        SymbolicVariable::new(BaseEntry::Main { offset: 0 }, col)
    }
}

impl<F: Field> BaseAir<F> for RegevTransferAir<F> {
    fn width(&self) -> usize {
        TNUM_COLS
    }

    /// `[a || b || c1,c2(before) || c1,c2(delta) || c1,c2(after)]`.
    fn num_public_values(&self) -> usize {
        8 * self.n
    }

    /// Only the carry column steps to the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![TCOL_CARRY]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<F: Field> LookupAir<F> for RegevTransferAir<F> {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let col = |c: usize| -> Vec<Vec<_>> { vec![vec![Self::main_var(c).into()]] };
        let diff = |u: usize, v: usize| vec![vec![Self::main_var(u) - Self::main_var(v)]];

        let mut specs: Vec<(Kind, Vec<Vec<_>>)> = vec![
            (Kind::Global("eval:a".to_string()), col(TCOL_A)),
            (Kind::Global("eval:b".to_string()), col(TCOL_B)),
        ];
        for (j, role) in ["before", "delta", "after"].iter().enumerate() {
            let base = ct_base(j);
            specs.extend([
                (
                    Kind::Global(format!("eval:c1:{role}")),
                    col(base + OFF_C1),
                ),
                (
                    Kind::Global(format!("eval:c2:{role}")),
                    col(base + OFF_C2),
                ),
                (Kind::Local, col(base + OFF_R)),
                (Kind::Local, diff(base + OFF_E1U, base + OFF_E1V)),
                (Kind::Local, diff(base + OFF_E2U, base + OFF_E2V)),
                (Kind::Local, col(base + OFF_M)),
                (Kind::Local, col(base + OFF_K1)),
                (Kind::Local, col(base + OFF_K2)),
            ]);
        }

        specs
            .into_iter()
            .enumerate()
            .map(|(aux, (kind, element_exprs))| Lookup {
                kind,
                element_exprs,
                multiplicities_exprs: vec![],
                columns: vec![aux],
            })
            .collect()
    }
}

impl<AB> Air<AB> for RegevTransferAir<AB::F>
where
    AB: PermutationAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        // --- Per-ciphertext smallness (same as RegevEncAir) ---------------
        for j in 0..3 {
            let base = ct_base(j);

            let r: AB::Expr = local[base + OFF_R].into();
            builder.assert_zero(r.clone() * (r.clone() - AB::Expr::ONE) * (r + AB::Expr::ONE));

            for off in [OFF_E1U, OFF_E1V, OFF_E2U, OFF_E2V] {
                let x: AB::Expr = local[base + off].into();
                builder
                    .assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x - AB::Expr::TWO));
            }

            let m: AB::Expr = local[base + OFF_M].into();
            builder.assert_bool(m);
        }

        // --- Ripple-carry conservation: before = after + delta -----------
        let m_before: AB::Expr = local[ct_base(ROLE_BEFORE) + OFF_M].into();
        let m_delta: AB::Expr = local[ct_base(ROLE_DELTA) + OFF_M].into();
        let m_after: AB::Expr = local[ct_base(ROLE_AFTER) + OFF_M].into();
        let carry: AB::Expr = local[TCOL_CARRY].into();
        let carry_next: AB::Expr = next[TCOL_CARRY].into();

        builder.assert_bool(carry.clone());
        builder.when_first_row().assert_zero(carry.clone());

        let lhs = m_after + m_delta + carry - m_before;
        // after[i] + delta[i] + c[i] − before[i] = 2·c[i+1]
        builder
            .when_transition()
            .assert_zero(lhs.clone() - carry_next * AB::Expr::TWO);
        // Final carry must be zero: the equation holds over the integers.
        builder.when_last_row().assert_zero(lhs);

        // --- Ring identities at the random point z (×3) -------------------
        let perm = builder.permutation();
        let s = |aux: usize| -> AB::ExprEF {
            perm.current(aux)
                .expect("permutation trace too narrow")
                .into()
        };

        let z: AB::ExprEF = builder.permutation_randomness()[0].into();
        let mut zn = z;
        for _ in 0..self.n.trailing_zeros() {
            zn = zn.clone() * zn;
        }
        let zn1 = zn + AB::ExprEF::ONE;

        for j in 0..3 {
            let ab = aux_base(j);
            let eq1 = s(TAUX_A) * s(ab + AOFF_R) + s(ab + AOFF_E1)
                - s(ab + AOFF_C1)
                - zn1.clone() * s(ab + AOFF_K1);
            builder.when_first_row().assert_zero_ext(eq1);

            let eq2 = s(TAUX_B) * s(ab + AOFF_R)
                + s(ab + AOFF_E2)
                + s(ab + AOFF_M) * AB::Expr::from(self.delta_scale)
                - s(ab + AOFF_C2)
                - zn1.clone() * s(ab + AOFF_K2);
            builder.when_first_row().assert_zero_ext(eq2);
        }
    }
}

/// Build the trace for one transfer.
///
/// Panics if the witnesses do not satisfy `before = after + delta` as n-bit
/// integers (a consistent witness is the prover's responsibility).
pub fn generate_transfer_trace(
    pk: &PublicKey,
    witness: &TransferWitness,
    statement: &Transfer,
) -> RowMajorMatrix<F> {
    let n = pk.a.len();
    let cts = [&statement.before, &statement.delta, &statement.after];
    let wits = [&witness.before, &witness.delta, &witness.after];

    let mut values = F::zero_vec(n * TNUM_COLS);
    for i in 0..n {
        let row = &mut values[i * TNUM_COLS..(i + 1) * TNUM_COLS];
        row[TCOL_A] = pk.a[i];
        row[TCOL_B] = pk.b[i];
        for (j, (ct, w)) in cts.iter().zip(&wits).enumerate() {
            let base = ct_base(j);
            row[base + OFF_C1] = ct.c1[i];
            row[base + OFF_C2] = ct.c2[i];
            row[base + OFF_R] = centered_to_field(w.r[i] as i64);
            row[base + OFF_E1U] = F::from_u8(w.e1u[i]);
            row[base + OFF_E1V] = F::from_u8(w.e1v[i]);
            row[base + OFF_E2U] = F::from_u8(w.e2u[i]);
            row[base + OFF_E2V] = F::from_u8(w.e2v[i]);
            row[base + OFF_M] = F::from_u8(w.m[i]);
            row[base + OFF_K1] = w.k1[i];
            row[base + OFF_K2] = w.k2[i];
        }
    }

    // Ripple-carry chain for before = after + delta.
    let mut carry = 0u8;
    for i in 0..n {
        values[i * TNUM_COLS + TCOL_CARRY] = F::from_u8(carry);
        let sum = witness.after.m[i] + witness.delta.m[i] + carry;
        let out = sum as i16 - witness.before.m[i] as i16;
        assert!(
            out == 0 || out == 2,
            "transfer witness inconsistent at bit {i}: before != after + delta"
        );
        carry = (out / 2) as u8;
    }
    assert_eq!(
        carry, 0,
        "transfer witness inconsistent: after + delta overflows n bits"
    );

    RowMajorMatrix::new(values, TNUM_COLS)
}

/// Public values for one transfer instance:
/// `[a || b || c1,c2(before) || c1,c2(delta) || c1,c2(after)]`.
pub fn transfer_public_values(pk: &PublicKey, t: &Transfer) -> Vec<F> {
    let mut pv = Vec::with_capacity(8 * pk.a.len());
    pv.extend_from_slice(&pk.a);
    pv.extend_from_slice(&pk.b);
    for ct in [&t.before, &t.delta, &t.after] {
        pv.extend_from_slice(&ct.c1);
        pv.extend_from_slice(&ct.c2);
    }
    pv
}

fn air_for<SC>(params: &RegevParams) -> RegevTransferAir<Val<SC>>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
{
    RegevTransferAir::new(params.n, Val::<SC>::from_u32(params.delta()))
}

/// Prove a batch of transfers: for each, all three ciphertexts are
/// well-formed encryptions under `pk` and `before = after + delta` at the
/// value level.
pub fn prove_transfers<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    transfers: &[Transfer],
    witnesses: &[TransferWitness],
) -> BatchProof<SC>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevTransferAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
{
    crate::pool::init_thread_pool();
    assert!(!transfers.is_empty(), "empty batch");
    assert_eq!(transfers.len(), witnesses.len());
    assert_eq!(pk.a.len(), params.n);

    let air = air_for::<SC>(params);
    let airs = vec![air; transfers.len()];

    let traces: Vec<RowMajorMatrix<Val<SC>>> = transfers
        .iter()
        .zip(witnesses)
        .map(|(t, w)| generate_transfer_trace(pk, w, t))
        .collect();

    let instances: Vec<StarkInstance<'_, SC, RegevTransferAir<Val<SC>>>> = airs
        .iter()
        .zip(&traces)
        .zip(transfers)
        .map(|((air, trace), t)| StarkInstance {
            air,
            trace,
            public_values: transfer_public_values(pk, t),
            lookups: air.clone().get_lookups(),
        })
        .collect();

    let prover_data = ProverData::from_instances(config, &instances);
    stark::prove_batch(config, &instances, &prover_data)
}

/// Verify a batch of transfer proofs against `pk` and the claimed
/// ciphertext triples.
pub fn verify_transfers<SC>(
    config: &SC,
    params: &RegevParams,
    pk: &PublicKey,
    transfers: &[Transfer],
    proof: &BatchProof<SC>,
) -> Result<(), RegevVerifyError<PcsError<SC>>>
where
    SC: StarkGenericConfig,
    Domain<SC>: PolynomialSpace<Val = F>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SC::Challenge>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
    RegevTransferAir<Val<SC>>: Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
        + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>,
{
    crate::pool::init_thread_pool();
    if transfers.is_empty() {
        return Err(RegevVerifyError::Shape("empty batch"));
    }
    if pk.a.len() != params.n || pk.b.len() != params.n {
        return Err(RegevVerifyError::Shape("public key length != n"));
    }
    let expected_db = params.log_n() + config.is_zk();
    if proof.degree_bits.len() != transfers.len()
        || proof.degree_bits.iter().any(|&db| db != expected_db)
    {
        return Err(RegevVerifyError::Shape("trace height != ring dimension"));
    }

    let mut air = air_for::<SC>(params);
    let lookups = air.get_lookups();
    let airs = vec![air; transfers.len()];
    let common = CommonData::new(None, vec![lookups; transfers.len()]);

    let pvs: Vec<Vec<Val<SC>>> = transfers
        .iter()
        .map(|t| transfer_public_values(pk, t))
        .collect();

    let challenges = stark::verify_batch(config, &airs, proof, &pvs, &common)
        .map_err(RegevVerifyError::Stark)?;

    // Outer binding: 8 published evaluations per instance, positionally
    // (a, b, then c1/c2 of before, delta, after).
    for (i, t) in transfers.iter().enumerate() {
        let data = &proof.global_lookup_data[i];
        if data.len() != 8 {
            return Err(RegevVerifyError::Shape("expected 8 published evaluations"));
        }
        for ct in [&t.before, &t.delta, &t.after] {
            if ct.c1.len() != params.n || ct.c2.len() != params.n {
                return Err(RegevVerifyError::Shape("ciphertext length != n"));
            }
        }
        let z = challenges[i][0];

        let expected = [
            ("a", crate::prove::eval_at::<SC>(&pk.a, z)),
            ("b", crate::prove::eval_at::<SC>(&pk.b, z)),
            ("c1(before)", crate::prove::eval_at::<SC>(&t.before.c1, z)),
            ("c2(before)", crate::prove::eval_at::<SC>(&t.before.c2, z)),
            ("c1(delta)", crate::prove::eval_at::<SC>(&t.delta.c1, z)),
            ("c2(delta)", crate::prove::eval_at::<SC>(&t.delta.c2, z)),
            ("c1(after)", crate::prove::eval_at::<SC>(&t.after.c1, z)),
            ("c2(after)", crate::prove::eval_at::<SC>(&t.after.c2, z)),
        ];
        for (j, (poly, want)) in expected.into_iter().enumerate() {
            if data[j].expected_cumulated != want {
                return Err(RegevVerifyError::StatementMismatch { instance: i, poly });
            }
        }
    }

    Ok(())
}
