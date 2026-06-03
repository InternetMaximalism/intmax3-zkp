use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::RangeParameters;
use crate::params::{BITS_PER_LIMB, CHUNK_BITS, LIMBS, M, N, Q, b_coeff, g_coeff};

const CHUNK_RADIX: u64 = 1 << CHUNK_BITS;
const AMOUNT_CHUNKS_PER_LIMB: usize = BITS_PER_LIMB / CHUNK_BITS;

pub const COL_LIMB_START: usize = 0;
pub const COL_CHUNK_BIT_START: usize = COL_LIMB_START + LIMBS;
pub const COL_CHUNK_WEIGHT: usize = COL_CHUNK_BIT_START + CHUNK_BITS;
pub const COL_RUNNING_SUM: usize = COL_CHUNK_WEIGHT + 1;
pub const COL_SHIFTED_INV: usize = COL_RUNNING_SUM + 1;
pub const COL_R_START: usize = COL_SHIFTED_INV + 1;
pub const COL_K_START: usize = COL_R_START + N;
pub const WIDTH: usize = COL_K_START + M;

const PREP_IS_AMOUNT_ACTIVE: usize = 0;
const PREP_IS_PADDING: usize = 1;
const PREP_IS_AMOUNT_LIMB_END: usize = 2;
const PREP_AMOUNT_LIMB_SEL_START: usize = 3;
const PREP_IS_SHIFTED_R_ACTIVE: usize = PREP_AMOUNT_LIMB_SEL_START + LIMBS;
const PREP_IS_SHIFTED_R_END: usize = PREP_IS_SHIFTED_R_ACTIVE + 1;
const PREP_SHIFTED_R_SEL_START: usize = PREP_IS_SHIFTED_R_END + 1;
const PREP_IS_SLACK_R_ACTIVE: usize = PREP_SHIFTED_R_SEL_START + N;
const PREP_IS_SLACK_R_END: usize = PREP_IS_SLACK_R_ACTIVE + 1;
const PREP_SLACK_R_SEL_START: usize = PREP_IS_SLACK_R_END + 1;
const PREP_IS_COMMIT_ACTIVE: usize = PREP_SLACK_R_SEL_START + N;
const PREP_COMMIT_SEL_START: usize = PREP_IS_COMMIT_ACTIVE + 1;
const PREP_COMMIT_G_START: usize = PREP_COMMIT_SEL_START + M;
const PREP_COMMIT_B_START: usize = PREP_COMMIT_G_START + LIMBS;
const PREP_ALLOWED_BIT_START: usize = PREP_COMMIT_B_START + N;
const PREP_WIDTH: usize = PREP_ALLOWED_BIT_START + CHUNK_BITS;

#[derive(Clone)]
pub struct AmountAir {
    pub range: RangeParameters,
}

#[inline]
fn limb<T: Copy>(row: &[T], i: usize) -> T {
    row[COL_LIMB_START + i]
}

#[inline]
fn chunk_bit<T: Copy>(row: &[T], i: usize) -> T {
    row[COL_CHUNK_BIT_START + i]
}

#[inline]
fn chunk_weight<T: Copy>(row: &[T]) -> T {
    row[COL_CHUNK_WEIGHT]
}

#[inline]
fn running_sum<T: Copy>(row: &[T]) -> T {
    row[COL_RUNNING_SUM]
}

#[inline]
fn shifted_inv<T: Copy>(row: &[T]) -> T {
    row[COL_SHIFTED_INV]
}

#[inline]
fn randomness<T: Copy>(row: &[T], i: usize) -> T {
    row[COL_R_START + i]
}

#[inline]
fn quotient<T: Copy>(row: &[T], j: usize) -> T {
    row[COL_K_START + j]
}

#[inline]
fn prep_amount_active<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_AMOUNT_ACTIVE]
}

#[inline]
fn prep_padding<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_PADDING]
}

#[inline]
fn prep_amount_limb_end<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_AMOUNT_LIMB_END]
}

#[inline]
fn prep_amount_limb_sel<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_AMOUNT_LIMB_SEL_START + i]
}

#[inline]
fn prep_shifted_r_active<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_SHIFTED_R_ACTIVE]
}

#[inline]
fn prep_shifted_r_end<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_SHIFTED_R_END]
}

#[inline]
fn prep_shifted_r_sel<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_SHIFTED_R_SEL_START + i]
}

#[inline]
fn prep_slack_r_active<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_SLACK_R_ACTIVE]
}

#[inline]
fn prep_slack_r_end<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_SLACK_R_END]
}

#[inline]
fn prep_slack_r_sel<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_SLACK_R_SEL_START + i]
}

#[inline]
fn prep_commit_active<T: Copy>(row: &[T]) -> T {
    row[PREP_IS_COMMIT_ACTIVE]
}

#[inline]
fn prep_commit_sel<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_COMMIT_SEL_START + i]
}

#[inline]
fn prep_commit_g<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_COMMIT_G_START + i]
}

#[inline]
fn prep_commit_b<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_COMMIT_B_START + i]
}

#[inline]
fn prep_allowed_bit<T: Copy>(row: &[T], i: usize) -> T {
    row[PREP_ALLOWED_BIT_START + i]
}

pub fn generate_preprocessed_trace<F>(range: &RangeParameters) -> RowMajorMatrix<F>
where
    F: Field + PrimeCharacteristicRing,
{
    let mut prep = RowMajorMatrix::new(F::zero_vec(range.trace_rows * PREP_WIDTH), PREP_WIDTH);
    let commit_start = range.amount_range_rows + range.shifted_r_rows + range.slack_r_rows;

    for row in 0..range.trace_rows {
        let row_slice = prep.row_mut(row);
        if row < range.amount_range_rows {
            row_slice[PREP_IS_AMOUNT_ACTIVE] = F::ONE;
            row_slice[PREP_IS_AMOUNT_LIMB_END] =
                F::from_bool(row % AMOUNT_CHUNKS_PER_LIMB == AMOUNT_CHUNKS_PER_LIMB - 1);
            row_slice[PREP_AMOUNT_LIMB_SEL_START + (row / AMOUNT_CHUNKS_PER_LIMB)] = F::ONE;
            for bit_idx in 0..CHUNK_BITS {
                row_slice[PREP_ALLOWED_BIT_START + bit_idx] = F::ONE;
            }
        } else if row < range.amount_range_rows + range.shifted_r_rows {
            let shifted_row = row - range.amount_range_rows;
            row_slice[PREP_IS_SHIFTED_R_ACTIVE] = F::ONE;
            row_slice[PREP_IS_SHIFTED_R_END] =
                F::from_bool(shifted_row % range.r_chunks == range.r_chunks - 1);
            row_slice[PREP_SHIFTED_R_SEL_START + (shifted_row / range.r_chunks)] = F::ONE;
            let allowed_bits = if shifted_row % range.r_chunks == range.r_chunks - 1
                && range.final_chunk_bits < CHUNK_BITS
            {
                range.final_chunk_bits
            } else {
                CHUNK_BITS
            };
            for bit_idx in 0..CHUNK_BITS {
                row_slice[PREP_ALLOWED_BIT_START + bit_idx] = F::from_bool(bit_idx < allowed_bits);
            }
        } else if row < commit_start {
            let slack_row = row - range.amount_range_rows - range.shifted_r_rows;
            row_slice[PREP_IS_SLACK_R_ACTIVE] = F::ONE;
            row_slice[PREP_IS_SLACK_R_END] =
                F::from_bool(slack_row % range.r_chunks == range.r_chunks - 1);
            row_slice[PREP_SLACK_R_SEL_START + (slack_row / range.r_chunks)] = F::ONE;
            let allowed_bits = if slack_row % range.r_chunks == range.r_chunks - 1
                && range.final_chunk_bits < CHUNK_BITS
            {
                range.final_chunk_bits
            } else {
                CHUNK_BITS
            };
            for bit_idx in 0..CHUNK_BITS {
                row_slice[PREP_ALLOWED_BIT_START + bit_idx] = F::from_bool(bit_idx < allowed_bits);
            }
        } else if row < range.active_rows {
            let commit_row = row - commit_start;
            row_slice[PREP_IS_COMMIT_ACTIVE] = F::ONE;
            row_slice[PREP_COMMIT_SEL_START + commit_row] = F::ONE;
            for limb_idx in 0..LIMBS {
                row_slice[PREP_COMMIT_G_START + limb_idx] =
                    F::from_u64(g_coeff(commit_row, limb_idx));
            }
            for i in 0..N {
                row_slice[PREP_COMMIT_B_START + i] = F::from_u64(b_coeff(commit_row, i));
            }
        } else {
            row_slice[PREP_IS_PADDING] = F::ONE;
        }
    }

    prep
}

impl<F> BaseAir<F> for AmountAir
where
    F: Field + PrimeCharacteristicRing,
{
    fn width(&self) -> usize {
        WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(generate_preprocessed_trace(&self.range))
    }

    fn num_public_values(&self) -> usize {
        M
    }
}

fn chunk_expr<AB: AirBuilder>(row: &[AB::Var]) -> AB::Expr {
    let mut value = AB::Expr::ZERO;
    for i in 0..CHUNK_BITS {
        value = value + chunk_bit(row, i) * AB::F::from_u64(1_u64 << i);
    }
    value
}

impl<AB> Air<AB> for AmountAir
where
    AB: AirBuilder,
    AB::F: Field + PrimeCharacteristicRing,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let prep = builder.preprocessed().current_slice();
        let prep_amount_active_value = prep_amount_active(prep);
        let prep_padding_value = prep_padding(prep);
        let prep_amount_limb_end_value = prep_amount_limb_end(prep);
        let prep_amount_limb_sel_values: [AB::Var; LIMBS] =
            core::array::from_fn(|i| prep_amount_limb_sel(prep, i));
        let prep_shifted_r_active_value = prep_shifted_r_active(prep);
        let prep_shifted_r_end_value = prep_shifted_r_end(prep);
        let prep_shifted_r_sel_values: [AB::Var; N] =
            core::array::from_fn(|i| prep_shifted_r_sel(prep, i));
        let prep_slack_r_active_value = prep_slack_r_active(prep);
        let prep_slack_r_end_value = prep_slack_r_end(prep);
        let prep_slack_r_sel_values: [AB::Var; N] =
            core::array::from_fn(|i| prep_slack_r_sel(prep, i));
        let prep_commit_active_value = prep_commit_active(prep);
        let prep_commit_sel_values: [AB::Var; M] =
            core::array::from_fn(|i| prep_commit_sel(prep, i));
        let prep_commit_g_values: [AB::Var; LIMBS] =
            core::array::from_fn(|i| prep_commit_g(prep, i));
        let prep_commit_b_values: [AB::Var; N] = core::array::from_fn(|i| prep_commit_b(prep, i));
        let prep_allowed_bit_values: [AB::Var; CHUNK_BITS] =
            core::array::from_fn(|i| prep_allowed_bit(prep, i));
        let public_c: [AB::PublicVar; M] = core::array::from_fn(|j| builder.public_values()[j]);

        builder.when_first_row().assert_one(chunk_weight(local));
        builder.when_first_row().assert_zero(running_sum(local));

        let mut when_transition = builder.when_transition();
        for i in 0..LIMBS {
            when_transition.assert_eq(limb(local, i), limb(next, i));
        }
        for i in 0..N {
            when_transition.assert_eq(randomness(local, i), randomness(next, i));
        }
        for j in 0..M {
            when_transition.assert_eq(quotient(local, j), quotient(next, j));
        }

        let active_selector =
            prep_amount_active_value + prep_shifted_r_active_value + prep_slack_r_active_value;
        let mut when_digit_active = builder.when(active_selector);
        for bit_idx in 0..CHUNK_BITS {
            when_digit_active.assert_bool(chunk_bit(local, bit_idx));
            when_digit_active.assert_zero(
                chunk_bit(local, bit_idx)
                    - prep_allowed_bit_values[bit_idx] * chunk_bit(local, bit_idx),
            );
        }

        let digit = chunk_expr::<AB>(local);

        let mut when_amount_mid =
            builder.when(prep_amount_active_value - prep_amount_limb_end_value);
        when_amount_mid.assert_eq(
            chunk_weight(next),
            chunk_weight(local) * AB::F::from_u64(CHUNK_RADIX),
        );
        when_amount_mid.assert_eq(
            running_sum(next),
            running_sum(local) + chunk_weight(local) * digit.clone(),
        );
        when_amount_mid.assert_zero(shifted_inv(local));
        when_amount_mid.assert_zero(shifted_inv(next));

        let mut when_amount_end = builder.when(prep_amount_limb_end_value);
        when_amount_end.assert_one(chunk_weight(next));
        when_amount_end.assert_zero(running_sum(next));
        let completed_limb = running_sum(local) + chunk_weight(local) * digit.clone();
        for i in 0..LIMBS {
            let mut when_selected = when_amount_end.when(prep_amount_limb_sel_values[i]);
            when_selected.assert_eq(limb(local, i), completed_limb.clone());
        }
        when_amount_end.assert_zero(shifted_inv(local));

        let mut when_shifted_mid =
            builder.when(prep_shifted_r_active_value - prep_shifted_r_end_value);
        when_shifted_mid.assert_eq(
            chunk_weight(next),
            chunk_weight(local) * AB::F::from_u64(CHUNK_RADIX),
        );
        when_shifted_mid.assert_eq(
            running_sum(next),
            running_sum(local) + chunk_weight(local) * digit.clone(),
        );
        when_shifted_mid.assert_zero(shifted_inv(local));

        let mut when_shifted_end = builder.when(prep_shifted_r_end_value);
        when_shifted_end.assert_one(chunk_weight(next));
        when_shifted_end.assert_zero(running_sum(next));
        let completed_shifted = running_sum(local) + chunk_weight(local) * digit.clone();
        for i in 0..N {
            let mut when_selected = when_shifted_end.when(prep_shifted_r_sel_values[i]);
            when_selected.assert_eq(
                randomness(local, i) + AB::F::from_i64(self.range.shift_offset),
                completed_shifted.clone(),
            );
        }
        if self.range.single_shift_optimized {
            when_shifted_end.assert_one(completed_shifted.clone() * shifted_inv(local));
        } else {
            let mut when_slack_mid =
                builder.when(prep_slack_r_active_value - prep_slack_r_end_value);
            when_slack_mid.assert_eq(
                chunk_weight(next),
                chunk_weight(local) * AB::F::from_u64(CHUNK_RADIX),
            );
            when_slack_mid.assert_eq(
                running_sum(next),
                running_sum(local) + chunk_weight(local) * digit.clone(),
            );
            when_slack_mid.assert_zero(shifted_inv(local));
            when_slack_mid.assert_zero(shifted_inv(next));

            let mut when_slack_end = builder.when(prep_slack_r_end_value);
            when_slack_end.assert_one(chunk_weight(next));
            when_slack_end.assert_zero(running_sum(next));
            let completed_slack = running_sum(local) + chunk_weight(local) * digit.clone();
            for i in 0..N {
                let mut when_selected = when_slack_end.when(prep_slack_r_sel_values[i]);
                when_selected.assert_eq(
                    completed_slack.clone()
                        + randomness(local, i)
                        + AB::F::from_i64(self.range.shift_offset),
                    AB::F::from_u128(self.range.shifted_max),
                );
            }
            when_slack_end.assert_zero(shifted_inv(local));
        }

        let mut when_commit = builder.when(prep_commit_active_value);
        for bit_idx in 0..CHUNK_BITS {
            when_commit.assert_zero(chunk_bit(local, bit_idx));
        }
        when_commit.assert_one(chunk_weight(local));
        when_commit.assert_zero(running_sum(local));
        when_commit.assert_zero(shifted_inv(local));

        let mut selected_public_c = AB::Expr::ZERO;
        let mut selected_quotient = AB::Expr::ZERO;
        for j in 0..M {
            selected_public_c = selected_public_c + prep_commit_sel_values[j] * public_c[j].into();
            selected_quotient = selected_quotient + prep_commit_sel_values[j] * quotient(local, j);
        }

        let mut commitment_expr = AB::Expr::ZERO;
        for limb_idx in 0..LIMBS {
            commitment_expr =
                commitment_expr + limb(local, limb_idx) * prep_commit_g_values[limb_idx];
        }
        for i in 0..N {
            commitment_expr = commitment_expr + randomness(local, i) * prep_commit_b_values[i];
        }
        commitment_expr = commitment_expr - selected_public_c;
        commitment_expr = commitment_expr - selected_quotient * AB::F::from_u64(Q);
        when_commit.assert_zero(commitment_expr);

        let mut when_padding = builder.when(prep_padding_value);
        for bit_idx in 0..CHUNK_BITS {
            when_padding.assert_zero(chunk_bit(local, bit_idx));
        }
        when_padding.assert_one(chunk_weight(local));
        when_padding.assert_zero(running_sum(local));
        when_padding.assert_zero(shifted_inv(local));
    }
}
