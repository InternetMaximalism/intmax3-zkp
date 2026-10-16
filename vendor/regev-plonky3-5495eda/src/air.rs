//! The AIR proving that a Regev ciphertext is well formed:
//!
//! ```text
//! c1 = a·r + e1                 in Z_q[x]/(x^n + 1)
//! c2 = b·r + e2 + Δ·m           in Z_q[x]/(x^n + 1)
//! r  ternary, e1, e2 ∈ CBD(2), m binary
//! ```
//!
//! One trace = one ciphertext, with one row per polynomial coefficient
//! (height = ring dimension `n`). Multiple ciphertexts batch as multiple
//! instances of `p3-batch-stark`, sharing commitments and FRI.
//!
//! # Layout
//!
//! Main (base field) columns:
//!
//! | col | meaning                                  | constraint            |
//! |-----|------------------------------------------|-----------------------|
//! | a, b, c1, c2 | the public statement            | eval exposed at `z`   |
//! | r            | encryption randomness           | `r(r-1)(r+1) = 0`     |
//! | e1u, e1v     | CBD halves of `e1 = e1u - e1v`  | `x(x-1)(x-2) = 0`     |
//! | e2u, e2v     | CBD halves of `e2`              | `x(x-1)(x-2) = 0`     |
//! | m            | message bits                    | `m(m-1) = 0`          |
//! | k1, k2       | quotients by `x^n + 1`          | free                  |
//!
//! Smallness is enforced by these degree-≤3 vanishing constraints — for
//! ranges this tiny they are strictly cheaper than logUp lookups (zero
//! auxiliary columns and no batch inversions; a lookup would cost one
//! extension-field running-sum column *per* range check).
//!
//! Permutation (extension field) columns: one Horner running-evaluation
//! column per polynomial (see [`crate::gadget`]), at the challenge `z`
//! sampled after the main trace is committed.
//!
//! The multiplication is verified at the single random point `z`
//! (Schwartz-Zippel), via two first-row constraints over the running
//! evaluations:
//!
//! ```text
//! A·R + E1          − C1 − (z^n + 1)·K1 = 0
//! B·R + E2 + Δ·M    − C2 − (z^n + 1)·K2 = 0
//! ```
//!
//! Only `A, B, C1, C2` (evaluations of *public* polynomials) are published;
//! the witness evaluations stay inside the permutation trace, so the proof
//! leaks nothing about `r`, the noise, or the message beyond the STARK
//! itself.
//!
//! # Optional plaintext range proof
//!
//! When a [`RangeSpec`] is attached, the AIR additionally proves that the
//! integer encoded by the low `value_bits` message coefficients,
//!
//! ```text
//! value = Σ_{i < K} m[i] · 2^i      (little-endian, K = value_bits)
//! ```
//!
//! lies in `[0, bound)`, *without revealing `value`*. This is the standard
//! complement technique: the prover supplies complement bits `d[i]` with
//! `Σ d[i] 2^i = bound − 1 − value`, and the AIR enforces
//!
//! ```text
//! Σ_{i < K} (m[i] + d[i]) · 2^i = bound − 1.
//! ```
//!
//! Since `value, d_value ∈ [0, 2^K)` (both are sums of `K` boolean bits) and
//! they sum to `bound − 1`, we get `value ≤ bound − 1 < bound`.
//!
//! Everything is materialised in **witness** columns (no preprocessed
//! commitment — that would be salted by the hiding PCS and so unreconstructable
//! by the verifier in zk mode):
//!
//! - `flag[i]`: an active indicator, `1` for the first `K` rows then `0`,
//!   pinned by `flag[0]=1`, a non-increasing constraint, and a count
//!   accumulator `cnt` with `cnt[0]=K`;
//! - `w[i]`: the weight `2^i` while active and `0` afterwards, via
//!   `w[0]=1`, `w[i+1] = 2·w[i]·flag[i+1]`;
//! - `d[i]`: complement bits, forced to `0` where inactive (`d·(1−flag)=0`);
//! - `acc[i] = Σ_{j ≥ i} (m[j]+d[j])·w[j]`, a suffix sum with `acc[0]=bound−1`.
//!
//! All range constraints are degree ≤ 2. The bound and `value_bits` are
//! public parameters baked into the AIR — the verifier supplies the ones it
//! wants to check, so a proof for any other `(bound, value_bits)` simply
//! fails its constraints.

use p3_air::symbolic::{BaseEntry, SymbolicVariable};
use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Kind, Lookup};
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::regev::{centered_to_field, Ciphertext, EncryptionWitness, PublicKey};

// Main trace column indices (always present).
pub const COL_A: usize = 0;
pub const COL_B: usize = 1;
pub const COL_C1: usize = 2;
pub const COL_C2: usize = 3;
pub const COL_R: usize = 4;
pub const COL_E1U: usize = 5;
pub const COL_E1V: usize = 6;
pub const COL_E2U: usize = 7;
pub const COL_E2V: usize = 8;
pub const COL_M: usize = 9;
pub const COL_K1: usize = 10;
pub const COL_K2: usize = 11;
pub const NUM_COLS: usize = 12;

// Extra main columns present only with a range proof.
pub const COL_D: usize = 12; // complement bits
pub const COL_FLAG: usize = 13; // active indicator (1 for first K rows)
pub const COL_W: usize = 14; // weight 2^i while active, else 0
pub const COL_ACC: usize = 15; // suffix sum of (m+d)*w  (acc[0] = bound-1)
pub const COL_CNT: usize = 16; // suffix sum of flag      (cnt[0] = value_bits)
pub const NUM_COLS_RANGE: usize = 17;

// Auxiliary (permutation) column indices: one evaluation argument each.
// The first four are exposed; the verifier recomputes them from the
// statement. The rest stay hidden.
pub const AUX_A: usize = 0;
pub const AUX_B: usize = 1;
pub const AUX_C1: usize = 2;
pub const AUX_C2: usize = 3;
pub const AUX_R: usize = 4;
pub const AUX_E1: usize = 5;
pub const AUX_E2: usize = 6;
pub const AUX_M: usize = 7;
pub const AUX_K1: usize = 8;
pub const AUX_K2: usize = 9;
pub const NUM_AUX: usize = 10;

/// Interaction names for the exposed evaluation arguments, in aux-column
/// order. The verifier matches published values positionally; the names are
/// labels for debugging.
pub const EXPOSED_EVALS: [&str; 4] = ["eval:a", "eval:b", "eval:c1", "eval:c2"];

/// Specification of a plaintext range proof attached to the encryption proof.
///
/// Proves that `value = Σ_{i < value_bits} m[i] · 2^i ∈ [0, bound)`.
///
/// # Constraints on the parameters
///
/// To rule out modular wraparound in the field equation
/// `value + (bound−1−value) = bound − 1`, we require `2^(value_bits + 1) ≤ q`,
/// i.e. **`value_bits ≤ 29`** for the BabyBear prime. `bound` must satisfy
/// `1 ≤ bound ≤ 2^value_bits`. For larger value ranges, decompose into limbs
/// and run one range proof per limb (future work).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeSpec {
    /// Number of low message coefficients interpreted as the value, `K`.
    pub value_bits: usize,
    /// Exclusive upper bound `B`; the proof shows `value ∈ [0, B)`.
    pub bound: u64,
}

impl RangeSpec {
    /// Maximum supported `value_bits` for BabyBear (keeps `2^(K+1) < q`).
    pub const MAX_VALUE_BITS: usize = 29;

    pub fn validate(&self) {
        assert!(
            self.value_bits >= 1 && self.value_bits <= Self::MAX_VALUE_BITS,
            "value_bits must be in 1..={}",
            Self::MAX_VALUE_BITS
        );
        assert!(self.bound >= 1, "bound must be positive");
        assert!(
            self.bound <= (1u64 << self.value_bits),
            "bound must be <= 2^value_bits"
        );
    }
}

/// AIR for one Regev encryption, optionally with a plaintext range proof.
///
/// `n` is the ring dimension (= trace height) and `delta` the message scaling
/// `Δ`. When `range` is `Some`, the AIR widens to [`NUM_COLS_RANGE`] columns
/// and adds the transparent powers-of-two preprocessed column.
#[derive(Clone, Debug)]
pub struct RegevEncAir<F> {
    pub n: usize,
    pub delta: F,
    pub range: Option<RangeSpec>,
}

impl<F: Field> RegevEncAir<F> {
    /// AIR for a plain encryption proof (no range proof).
    pub fn new(n: usize, delta: F) -> Self {
        assert!(n.is_power_of_two());
        Self {
            n,
            delta,
            range: None,
        }
    }

    /// AIR for an encryption proof bundled with a plaintext range proof.
    pub fn new_with_range(n: usize, delta: F, range: RangeSpec) -> Self {
        assert!(n.is_power_of_two());
        range.validate();
        assert!(range.value_bits <= n, "value_bits must not exceed n");
        Self {
            n,
            delta,
            range: Some(range),
        }
    }

    fn main_var(col: usize) -> SymbolicVariable<F> {
        SymbolicVariable::new(BaseEntry::Main { offset: 0 }, col)
    }

    /// `bound − 1` as a field element (only meaningful when `range` is set).
    fn bound_minus_one(&self) -> F {
        F::from_u64(self.range.expect("range not set").bound - 1)
    }
}

impl<F: Field> BaseAir<F> for RegevEncAir<F> {
    fn width(&self) -> usize {
        if self.range.is_some() {
            NUM_COLS_RANGE
        } else {
            NUM_COLS
        }
    }

    /// `[a || b || c1 || c2]`, binding the statement into the transcript
    /// before the evaluation challenge `z` is sampled.
    fn num_public_values(&self) -> usize {
        4 * self.n
    }

    /// The range proof's `flag`, `w`, `acc`, `cnt` columns use next-row
    /// access; the plain encryption proof reads only the current main row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.range.is_some() {
            vec![COL_FLAG, COL_W, COL_ACC, COL_CNT]
        } else {
            vec![]
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<F: Field> LookupAir<F> for RegevEncAir<F> {
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let col = |c: usize| -> Vec<Vec<_>> { vec![vec![Self::main_var(c).into()]] };
        let e1 = vec![vec![Self::main_var(COL_E1U) - Self::main_var(COL_E1V)]];
        let e2 = vec![vec![Self::main_var(COL_E2U) - Self::main_var(COL_E2V)]];

        let exposed = |name: &str| Kind::Global(name.to_string());

        // Aux column order must match the AUX_* constants. The range proof
        // adds no permutation columns — it is entirely a base-field argument.
        let specs: Vec<(Kind, Vec<Vec<_>>)> = vec![
            (exposed(EXPOSED_EVALS[0]), col(COL_A)),
            (exposed(EXPOSED_EVALS[1]), col(COL_B)),
            (exposed(EXPOSED_EVALS[2]), col(COL_C1)),
            (exposed(EXPOSED_EVALS[3]), col(COL_C2)),
            (Kind::Local, col(COL_R)),
            (Kind::Local, e1),
            (Kind::Local, e2),
            (Kind::Local, col(COL_M)),
            (Kind::Local, col(COL_K1)),
            (Kind::Local, col(COL_K2)),
        ];

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

impl<AB> Air<AB> for RegevEncAir<AB::F>
where
    AB: PermutationAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        // --- Smallness, all degree <= 3, no lookups needed ---------------

        // r ∈ {-1, 0, 1}
        let r: AB::Expr = local[COL_R].into();
        builder.assert_zero(r.clone() * (r.clone() - AB::Expr::ONE) * (r + AB::Expr::ONE));

        // CBD halves ∈ {0, 1, 2}
        for col in [COL_E1U, COL_E1V, COL_E2U, COL_E2V] {
            let x: AB::Expr = local[col].into();
            builder.assert_zero(x.clone() * (x.clone() - AB::Expr::ONE) * (x - AB::Expr::TWO));
        }

        // m ∈ {0, 1}
        let m: AB::Expr = local[COL_M].into();
        builder.assert_bool(m.clone());

        // --- Optional plaintext range proof ------------------------------
        if let Some(range) = self.range {
            let d: AB::Expr = local[COL_D].into();
            let flag: AB::Expr = local[COL_FLAG].into();
            let flag_next: AB::Expr = next[COL_FLAG].into();
            let w: AB::Expr = local[COL_W].into();
            let w_next: AB::Expr = next[COL_W].into();
            let acc: AB::Expr = local[COL_ACC].into();
            let acc_next: AB::Expr = next[COL_ACC].into();
            let cnt: AB::Expr = local[COL_CNT].into();
            let cnt_next: AB::Expr = next[COL_CNT].into();

            // d, flag ∈ {0, 1}.
            builder.assert_bool(d.clone());
            builder.assert_bool(flag.clone());

            // flag is non-increasing: once 0 it stays 0 (flag' ≤ flag).
            builder
                .when_transition()
                .assert_zero(flag_next.clone() * (AB::Expr::ONE - flag.clone()));
            // flag starts at 1, and exactly `value_bits` of them are 1
            // (cnt suffix-sum pinned below), so flag = [1^K 0^{n-K}].
            builder.when_first_row().assert_one(flag.clone());

            // Complement bits live only in the active region.
            builder.assert_zero(d.clone() * (AB::Expr::ONE - flag.clone()));

            // Weight: w[0] = 1, w[i+1] = 2·w[i]·flag[i+1]  (→ 2^i while active,
            // 0 once inactive). Powers stay < q since value_bits ≤ 29.
            builder.when_first_row().assert_one(w.clone());
            builder
                .when_transition()
                .assert_zero(w_next - w.clone() * AB::Expr::TWO * flag_next.clone());

            // Count accumulator: cnt[i] = Σ_{j≥i} flag[j], so cnt[0] = #active.
            builder
                .when_transition()
                .assert_zero(cnt.clone() - flag.clone() - cnt_next);
            builder.when_last_row().assert_zero(cnt.clone() - flag);
            builder
                .when_first_row()
                .assert_zero(cnt - AB::Expr::from(AB::F::from_usize(range.value_bits)));

            // Bound accumulator: acc[i] = Σ_{j≥i} (m[j]+d[j])·w[j], so
            // acc[0] = value + d_value, pinned to bound − 1.
            let contribution = (m + d) * w;
            builder
                .when_transition()
                .assert_zero(acc.clone() - contribution.clone() - acc_next);
            builder
                .when_last_row()
                .assert_zero(acc.clone() - contribution);
            builder
                .when_first_row()
                .assert_zero(acc - AB::Expr::from(self.bound_minus_one()));
        }

        // --- Ring identities at the random point z -----------------------
        //
        // The Horner constraints themselves are emitted by the EvalGadget;
        // here we consume the running evaluations on the first row, where
        // perm[AUX_P][0] = P(z).

        let perm = builder.permutation();
        let s = |aux: usize| -> AB::ExprEF {
            perm.current(aux)
                .expect("permutation trace too narrow")
                .into()
        };

        let z: AB::ExprEF = builder.permutation_randomness()[0].into();

        // z^n + 1 by repeated squaring (n is a power of two).
        let mut zn = z;
        for _ in 0..self.n.trailing_zeros() {
            zn = zn.clone() * zn;
        }
        let zn1 = zn + AB::ExprEF::ONE;

        // A·R + E1 − C1 − (z^n+1)·K1 = 0
        let eq1 = s(AUX_A) * s(AUX_R) + s(AUX_E1) - s(AUX_C1) - zn1.clone() * s(AUX_K1);
        builder.when_first_row().assert_zero_ext(eq1);

        // B·R + E2 + Δ·M − C2 − (z^n+1)·K2 = 0
        let eq2 = s(AUX_B) * s(AUX_R) + s(AUX_E2) + s(AUX_M) * AB::Expr::from(self.delta)
            - s(AUX_C2)
            - zn1 * s(AUX_K2);
        builder.when_first_row().assert_zero_ext(eq2);
    }
}

/// Build the main trace for one ciphertext (no range proof).
pub fn generate_trace(
    pk: &PublicKey,
    ct: &Ciphertext,
    witness: &EncryptionWitness,
) -> RowMajorMatrix<crate::regev::F> {
    fill_trace(pk, ct, witness, None)
}

/// Build the main trace for one ciphertext with a plaintext range proof.
///
/// Panics if the encrypted value (low `range.value_bits` bits of the message)
/// is not in `[0, range.bound)` — an in-range value is the prover's
/// responsibility.
pub fn generate_trace_with_range(
    pk: &PublicKey,
    ct: &Ciphertext,
    witness: &EncryptionWitness,
    range: RangeSpec,
) -> RowMajorMatrix<crate::regev::F> {
    fill_trace(pk, ct, witness, Some(range))
}

/// Reads the integer value encoded by the low `value_bits` message bits.
pub fn message_value(m: &[u8], value_bits: usize) -> u64 {
    (0..value_bits).fold(0u64, |acc, i| acc | ((m[i] as u64 & 1) << i))
}

fn fill_trace(
    pk: &PublicKey,
    ct: &Ciphertext,
    witness: &EncryptionWitness,
    range: Option<RangeSpec>,
) -> RowMajorMatrix<crate::regev::F> {
    use crate::regev::F;
    let n = pk.a.len();
    assert_eq!(witness.r.len(), n);

    let width = if range.is_some() {
        NUM_COLS_RANGE
    } else {
        NUM_COLS
    };
    let mut values = F::zero_vec(n * width);
    for i in 0..n {
        let row = &mut values[i * width..(i + 1) * width];
        row[COL_A] = pk.a[i];
        row[COL_B] = pk.b[i];
        row[COL_C1] = ct.c1[i];
        row[COL_C2] = ct.c2[i];
        row[COL_R] = centered_to_field(witness.r[i] as i64);
        row[COL_E1U] = F::from_u8(witness.e1u[i]);
        row[COL_E1V] = F::from_u8(witness.e1v[i]);
        row[COL_E2U] = F::from_u8(witness.e2u[i]);
        row[COL_E2V] = F::from_u8(witness.e2v[i]);
        row[COL_M] = F::from_u8(witness.m[i]);
        row[COL_K1] = witness.k1[i];
        row[COL_K2] = witness.k2[i];
    }

    if let Some(range) = range {
        range.validate();
        let k = range.value_bits;
        let value = message_value(&witness.m, k);
        assert!(
            value < range.bound,
            "encrypted value {value} is not in [0, {})",
            range.bound
        );
        let d_value = range.bound - 1 - value;

        // Per-row flag / weight / complement bit and the weighted contribution.
        let two = F::TWO;
        let mut contribution = vec![F::ZERO; n];
        let mut pow = F::ONE;
        for i in 0..n {
            let row = &mut values[i * width..(i + 1) * width];
            if i < k {
                let d_bit = ((d_value >> i) & 1) as u8;
                row[COL_FLAG] = F::ONE;
                row[COL_W] = pow;
                row[COL_D] = F::from_u8(d_bit);
                let m_plus_d = F::from_u8(witness.m[i] & 1) + F::from_u8(d_bit);
                contribution[i] = m_plus_d * pow;
                pow *= two;
            }
            // i >= k: flag, w, d already zero from zero_vec.
        }

        // Suffix sums for the count and bound accumulators.
        let mut cnt_suffix = F::ZERO;
        let mut acc_suffix = F::ZERO;
        for i in (0..n).rev() {
            cnt_suffix += if i < k { F::ONE } else { F::ZERO };
            acc_suffix += contribution[i];
            values[i * width + COL_CNT] = cnt_suffix;
            values[i * width + COL_ACC] = acc_suffix;
        }
        debug_assert_eq!(values[COL_ACC], F::from_u64(range.bound - 1));
        debug_assert_eq!(values[COL_CNT], F::from_usize(k));
    }

    RowMajorMatrix::new(values, width)
}

/// The public values for one instance: `[a || b || c1 || c2]`.
pub fn public_values(pk: &PublicKey, ct: &Ciphertext) -> Vec<crate::regev::F> {
    let mut pv = Vec::with_capacity(4 * pk.a.len());
    pv.extend_from_slice(&pk.a);
    pv.extend_from_slice(&pk.b);
    pv.extend_from_slice(&ct.c1);
    pv.extend_from_slice(&ct.c2);
    pv
}
