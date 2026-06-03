use core::ops::Neg;

use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use thiserror::Error;

use crate::air::{
    COL_CHUNK_BIT_START, COL_CHUNK_WEIGHT, COL_K_START, COL_LIMB_START, COL_R_START,
    COL_RUNNING_SUM, COL_SHIFTED_INV, WIDTH,
};
use crate::commitment::amount_to_limbs;
use crate::config::RangeParameters;
use crate::params::{BITS_PER_LIMB, CHUNK_BITS, M, N};
use crate::witness::Witness;

const AMOUNT_CHUNKS_PER_LIMB: usize = BITS_PER_LIMB / CHUNK_BITS;

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("randomness coefficient outside [-beta, beta]")]
    RandomnessOutOfRange,
}

pub fn i64_to_field<F>(x: i64) -> F
where
    F: Field + PrimeCharacteristicRing + Neg<Output = F>,
{
    if x >= 0 {
        F::from_u64(x as u64)
    } else {
        -F::from_u64((-x) as u64)
    }
}

fn fill_chunk_row<F>(row: &mut [F], value: u128, chunk_idx: usize)
where
    F: Field + PrimeCharacteristicRing,
{
    let shift = chunk_idx * CHUNK_BITS;
    let chunk = ((value >> shift) & ((1_u128 << CHUNK_BITS) - 1)) as u64;
    for bit_idx in 0..CHUNK_BITS {
        row[COL_CHUNK_BIT_START + bit_idx] = F::from_u64((chunk >> bit_idx) & 1);
    }
    row[COL_CHUNK_WEIGHT] = F::from_u128(1_u128 << shift);
    row[COL_RUNNING_SUM] = if shift == 0 {
        F::ZERO
    } else {
        F::from_u128(value & ((1_u128 << shift) - 1))
    };
}

pub fn generate_trace<F>(
    witness: &Witness,
    range: &RangeParameters,
) -> Result<RowMajorMatrix<F>, TraceError>
where
    F: Field + PrimeCharacteristicRing + Neg<Output = F>,
{
    let limbs = amount_to_limbs(witness.amount);
    let shifted_end = range.amount_range_rows + range.shifted_r_rows;
    let slack_end = shifted_end + range.slack_r_rows;
    let mut trace = RowMajorMatrix::new(F::zero_vec(range.trace_rows * WIDTH), WIDTH);

    for row in 0..range.trace_rows {
        let row_slice = trace.row_mut(row);

        for (i, limb) in limbs.iter().enumerate() {
            row_slice[COL_LIMB_START + i] = F::from_u64(u64::from(*limb));
        }
        for i in 0..N {
            row_slice[COL_R_START + i] = i64_to_field(witness.r[i]);
        }
        for j in 0..M {
            row_slice[COL_K_START + j] = i64_to_field(witness.k[j]);
        }

        if row < range.amount_range_rows {
            let limb_idx = row / AMOUNT_CHUNKS_PER_LIMB;
            let chunk_idx = row % AMOUNT_CHUNKS_PER_LIMB;
            fill_chunk_row(row_slice, u128::from(limbs[limb_idx]), chunk_idx);
        } else if row < shifted_end {
            let shifted_row = row - range.amount_range_rows;
            let r_idx = shifted_row / range.r_chunks;
            let chunk_idx = shifted_row % range.r_chunks;
            let shifted = u128::try_from(witness.r[r_idx] + range.shift_offset)
                .map_err(|_| TraceError::RandomnessOutOfRange)?;
            fill_chunk_row(row_slice, shifted, chunk_idx);
            if range.single_shift_optimized && chunk_idx == range.r_chunks - 1 {
                row_slice[COL_SHIFTED_INV] = F::from_u128(shifted).inverse();
            }
        } else if row < slack_end {
            let slack_row = row - shifted_end;
            let r_idx = slack_row / range.r_chunks;
            let chunk_idx = slack_row % range.r_chunks;
            let shifted = u128::try_from(witness.r[r_idx] + range.shift_offset)
                .map_err(|_| TraceError::RandomnessOutOfRange)?;
            let slack = range.shifted_max - shifted;
            fill_chunk_row(row_slice, slack, chunk_idx);
        } else if row < range.active_rows {
            row_slice[COL_CHUNK_WEIGHT] = F::ONE;
        } else {
            row_slice[COL_CHUNK_WEIGHT] = F::ONE;
            row_slice[COL_RUNNING_SUM] = F::ZERO;
        }
    }

    Ok(trace)
}
