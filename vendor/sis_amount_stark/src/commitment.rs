use rayon::prelude::*;
use thiserror::Error;

use crate::params::{LIMBS, M, N, Q, b_coeff, g_coeff};

#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("quotient does not fit into i64")]
    QuotientOverflow,
}

#[inline]
fn mod_q_i128(x: i128) -> u64 {
    let q = i128::from(Q);
    x.rem_euclid(q) as u64
}

pub fn amount_to_limbs(amount: u64) -> [u16; LIMBS] {
    [
        (amount & 0xffff) as u16,
        ((amount >> 16) & 0xffff) as u16,
        ((amount >> 32) & 0xffff) as u16,
        ((amount >> 48) & 0xffff) as u16,
    ]
}

pub fn compute_commitment(amount: u64, r: &[i64; N]) -> [u64; M] {
    let amount_limbs = amount_to_limbs(amount);
    let mut c = [0_u64; M];
    c.par_iter_mut().enumerate().for_each(|(j, c_j)| {
        let mut acc = 0_i128;
        for (limb_idx, limb) in amount_limbs.iter().enumerate() {
            acc += i128::from(g_coeff(j, limb_idx)) * i128::from(*limb);
        }
        for (i, r_i) in r.iter().enumerate() {
            acc += i128::from(b_coeff(j, i)) * i128::from(*r_i);
        }
        *c_j = mod_q_i128(acc);
    });
    c
}

pub fn compute_quotients(
    amount: u64,
    r: &[i64; N],
    c: &[u64; M],
) -> Result<[i64; M], CommitmentError> {
    let amount_limbs = amount_to_limbs(amount);
    let mut k = [0_i64; M];
    k.par_iter_mut()
        .enumerate()
        .try_for_each(|(j, k_j)| -> Result<(), CommitmentError> {
            let mut acc = 0_i128;
            for (limb_idx, limb) in amount_limbs.iter().enumerate() {
                acc += i128::from(g_coeff(j, limb_idx)) * i128::from(*limb);
            }
            for (i, r_i) in r.iter().enumerate() {
                acc += i128::from(b_coeff(j, i)) * i128::from(*r_i);
            }
            acc -= i128::from(c[j]);
            debug_assert_eq!(acc.rem_euclid(i128::from(Q)), 0);
            *k_j = (acc / i128::from(Q))
                .try_into()
                .map_err(|_| CommitmentError::QuotientOverflow)?;
            Ok(())
        })?;
    Ok(k)
}
