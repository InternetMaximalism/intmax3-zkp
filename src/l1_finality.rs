//! Durable L1 authority carried by fund-moving journals and prover snapshots.
//!
//! A transaction receipt is only a statement made by one RPC response.  It becomes durable
//! authority only after its block is covered by an independently read canonical `finalized`
//! checkpoint.  Local development may explicitly substitute `latest`, but that escape is encoded
//! in the checkpoint and is valid only for Anvil's chain id (`31337`).

#![cfg(not(target_arch = "wasm32"))]

use serde::{Deserialize, Serialize};

use crate::ethereum_types::bytes32::Bytes32;

pub const ANVIL_CHAIN_ID: u64 = 31_337;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum L1FinalitySource {
    RpcFinalized,
    DevnetLatest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L1FinalizedCheckpoint {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: Bytes32,
    pub parent_hash: Bytes32,
    pub source: L1FinalitySource,
}

impl L1FinalizedCheckpoint {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0 {
            return Err("finalized checkpoint chain id must be nonzero".into());
        }
        if self.block_hash == Bytes32::default() {
            return Err("finalized checkpoint block hash must be nonzero".into());
        }
        if self.block_number != 0 && self.parent_hash == Bytes32::default() {
            return Err("non-genesis finalized checkpoint parent hash must be nonzero".into());
        }
        if self.source == L1FinalitySource::DevnetLatest && self.chain_id != ANVIL_CHAIN_ID {
            return Err(format!(
                "unfinalized development checkpoint is restricted to chain {ANVIL_CHAIN_ID}"
            ));
        }
        Ok(())
    }

    pub fn covers_receipt(&self, block_number: u64, block_hash: Bytes32) -> Result<(), String> {
        self.validate()?;
        if block_hash == Bytes32::default() {
            return Err("receipt block hash must be nonzero".into());
        }
        if block_number > self.block_number {
            return Err(format!(
                "receipt block {block_number} is above durable head {}",
                self.block_number
            ));
        }
        if block_number == self.block_number && block_hash != self.block_hash {
            return Err("receipt and durable head hashes differ at the same height".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;

    fn word(tag: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[tag; 8]).expect("bytes32")
    }

    #[test]
    fn public_latest_can_never_masquerade_as_finalized() {
        let checkpoint = L1FinalizedCheckpoint {
            chain_id: 1,
            block_number: 100,
            block_hash: word(100),
            parent_hash: word(99),
            source: L1FinalitySource::DevnetLatest,
        };
        assert!(checkpoint.validate().is_err());
    }

    #[test]
    fn same_height_receipt_replacement_is_rejected() {
        let checkpoint = L1FinalizedCheckpoint {
            chain_id: 1,
            block_number: 100,
            block_hash: word(100),
            parent_hash: word(99),
            source: L1FinalitySource::RpcFinalized,
        };
        assert!(checkpoint.covers_receipt(100, word(101)).is_err());
        checkpoint
            .covers_receipt(100, word(100))
            .expect("same canonical block");
    }
}
