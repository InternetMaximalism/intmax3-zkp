use core::hash::Hash;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_ID: &str = "sis_amount_stark/toy/v1";
pub const PROOF_FORMAT_VERSION: u32 = 1;
#[cfg(feature = "fast-benchmark")]
pub const DEFAULT_BETA: i64 = (1 << 10) - 1;
#[cfg(not(feature = "fast-benchmark"))]
pub const DEFAULT_BETA: i64 = (1 << 17) - 1;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FriConfigOptions {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub commit_proof_of_work_bits: usize,
    pub query_proof_of_work_bits: usize,
}

impl Default for FriConfigOptions {
    fn default() -> Self {
        Self {
            log_blowup: 2,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: if cfg!(feature = "fast-benchmark") {
                16
            } else {
                32
            },
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: if cfg!(feature = "fast-benchmark") {
                0
            } else {
                8
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofSystemOptions {
    pub beta: i64,
    pub fri: FriConfigOptions,
}

impl Default for ProofSystemOptions {
    fn default() -> Self {
        Self {
            beta: DEFAULT_BETA,
            fri: FriConfigOptions::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeParameters {
    pub beta: i64,
    pub r_bits: usize,
    pub r_chunks: usize,
    pub final_chunk_bits: usize,
    pub shift_offset: i64,
    pub shifted_max: u128,
    pub single_shift_optimized: bool,
    pub amount_range_rows: usize,
    pub shifted_r_rows: usize,
    pub slack_r_rows: usize,
    pub commitment_rows: usize,
    pub active_rows: usize,
    pub trace_rows: usize,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("beta must be positive")]
    NonPositiveBeta,
    #[error("beta is too large for the current trace encoding")]
    BetaTooLarge,
}

impl ProofSystemOptions {
    pub fn range_parameters(&self) -> Result<RangeParameters, ConfigError> {
        if self.beta <= 0 {
            return Err(ConfigError::NonPositiveBeta);
        }

        let beta_u128 = u128::try_from(self.beta).map_err(|_| ConfigError::NonPositiveBeta)?;
        let single_shift_optimized = beta_u128
            .checked_add(1)
            .is_some_and(|x| x.is_power_of_two());
        let shift_offset = if single_shift_optimized {
            i64::try_from(beta_u128 + 1).map_err(|_| ConfigError::BetaTooLarge)?
        } else {
            self.beta
        };
        let shifted_max = if single_shift_optimized {
            beta_u128
                .checked_mul(2)
                .and_then(|x| x.checked_add(1))
                .ok_or(ConfigError::BetaTooLarge)?
        } else {
            beta_u128.checked_mul(2).ok_or(ConfigError::BetaTooLarge)?
        };
        let r_bits = (u128::BITS - shifted_max.leading_zeros()) as usize;
        if r_bits == 0 || r_bits > 63 {
            return Err(ConfigError::BetaTooLarge);
        }

        let amount_range_rows =
            crate::params::LIMBS * (crate::params::BITS_PER_LIMB / crate::params::CHUNK_BITS);
        let r_chunks = r_bits.div_ceil(crate::params::CHUNK_BITS);
        let final_chunk_bits = r_bits - (r_chunks - 1) * crate::params::CHUNK_BITS;
        let shifted_r_rows = crate::params::N * r_chunks;
        let slack_r_rows = if single_shift_optimized {
            0
        } else {
            crate::params::N * r_chunks
        };
        let commitment_rows = crate::params::M;
        let active_rows = amount_range_rows + shifted_r_rows + slack_r_rows + commitment_rows;
        let trace_rows = active_rows.next_power_of_two();

        Ok(RangeParameters {
            beta: self.beta,
            r_bits,
            r_chunks,
            final_chunk_bits,
            shift_offset,
            shifted_max,
            single_shift_optimized,
            amount_range_rows,
            shifted_r_rows,
            slack_r_rows,
            commitment_rows,
            active_rows,
            trace_rows,
        })
    }
}
