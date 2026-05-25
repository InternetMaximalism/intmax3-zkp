use anyhow::{ensure, Result};
use p3_recursion::{AggregationPrepCache, RecursionOutput};

use super::{
    config::KoalaRecursionConfig,
    hash::{KoalaHashCircuit, KoalaPoseidon2HashOut},
    utils::{
        recursively_verifiable::{aggregate_recursion_outputs, KoalaRecursionProof},
        wrapper::wrap_recursion_output,
    },
};

pub const SEND_TX_HASH_WORDS: usize = 4;

pub type SendTxHash = [u64; SEND_TX_HASH_WORDS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePublicState {
    pub block_number: u64,
    pub timestamp: u64,
    pub account_tree_root: SendTxHash,
    pub deposit_tree_root: SendTxHash,
    pub prev_public_state_root: SendTxHash,
}

impl NativePublicState {
    pub fn to_u64_vec(self) -> Vec<u64> {
        [
            vec![self.block_number, self.timestamp],
            self.account_tree_root.to_vec(),
            self.deposit_tree_root.to_vec(),
            self.prev_public_state_root.to_vec(),
        ]
        .concat()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBalancePublicInputs {
    pub user_id: u64,
    pub public_state: NativePublicState,
    pub block_r: u64,
    pub private_commitment: SendTxHash,
}

impl NativeBalancePublicInputs {
    pub fn to_u64_vec(self) -> Vec<u64> {
        [
            vec![self.user_id],
            self.public_state.to_u64_vec(),
            vec![self.block_r],
            self.private_commitment.to_vec(),
        ]
        .concat()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeUpdatePublicState {
    pub old: NativePublicState,
    pub new: NativePublicState,
}

impl NativeUpdatePublicState {
    pub fn validate(&self) -> Result<()> {
        if self.old == self.new {
            return Ok(());
        }

        ensure!(
            self.new.block_number >= self.old.block_number,
            "new block_number must be >= old block_number"
        );
        ensure!(
            self.new.timestamp >= self.old.timestamp,
            "new timestamp must be >= old timestamp"
        );
        ensure!(
            self.new.prev_public_state_root != [0; SEND_TX_HASH_WORDS],
            "new prev_public_state_root must be non-zero when public state changes"
        );
        Ok(())
    }

    pub fn to_u64_vec(self) -> Vec<u64> {
        [self.old.to_u64_vec(), self.new.to_u64_vec()].concat()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTx {
    pub transfer_tree_root: SendTxHash,
    pub nonce: u64,
}

impl NativeTx {
    pub fn to_u64_vec(self) -> Vec<u64> {
        [self.transfer_tree_root.to_vec(), vec![self.nonce]].concat()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSpendPublicInputs {
    pub prev_private_commitment: SendTxHash,
    pub new_private_commitment: SendTxHash,
    pub tx: NativeTx,
    pub is_valid: bool,
}

impl NativeSpendPublicInputs {
    pub fn to_u64_vec(self) -> Vec<u64> {
        [
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.tx.to_u64_vec(),
            vec![self.is_valid as u64],
        ]
        .concat()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTxSettlement {
    pub user_id: u64,
    pub tx: NativeTx,
    pub public_state: NativePublicState,
    pub account_tree_root: SendTxHash,
    pub send_block_number_before_tx: u64,
    pub tx_block_number: u64,
    pub spend_pis: NativeSpendPublicInputs,
}

impl NativeTxSettlement {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.account_tree_root == self.public_state.account_tree_root,
            "account_tree_root must equal public_state.account_tree_root"
        );
        ensure!(
            self.tx == self.spend_pis.tx,
            "settlement tx must equal spend tx"
        );
        ensure!(
            self.tx_block_number > self.send_block_number_before_tx,
            "tx_block_number must be > send_block_number_before_tx"
        );
        Ok(())
    }

    pub fn to_u64_vec(self) -> Vec<u64> {
        [
            vec![self.user_id],
            self.tx.to_u64_vec(),
            self.public_state.to_u64_vec(),
            self.account_tree_root.to_vec(),
            vec![self.send_block_number_before_tx, self.tx_block_number],
            self.spend_pis.to_u64_vec(),
        ]
        .concat()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendTxStatement {
    pub prev_balance_pis: NativeBalancePublicInputs,
    pub update_old_public_state: NativePublicState,
    pub update_new_public_state: NativePublicState,
    pub settlement_user_id: u64,
    pub settlement_public_state: NativePublicState,
    pub spend_pis: NativeSpendPublicInputs,
    pub send_block_number_before_tx: u64,
    pub tx_block_number: u64,
    pub expected_new_balance_pis: NativeBalancePublicInputs,
}

impl SendTxStatement {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.prev_balance_pis.public_state == self.update_old_public_state,
            "prev_balance_pis.public_state must equal update_old_public_state"
        );
        ensure!(
            self.update_new_public_state == self.settlement_public_state,
            "update_new_public_state must equal settlement_public_state"
        );
        ensure!(
            self.prev_balance_pis.user_id == self.settlement_user_id,
            "prev user_id must equal settlement user_id"
        );
        ensure!(
            self.prev_balance_pis.private_commitment == self.spend_pis.prev_private_commitment,
            "prev private commitment must equal spend prev_private_commitment"
        );
        ensure!(
            self.prev_balance_pis.block_r >= self.send_block_number_before_tx,
            "prev block_r must be >= send_block_number_before_tx"
        );
        ensure!(
            self.tx_block_number >= self.prev_balance_pis.block_r,
            "tx_block_number must be >= prev block_r"
        );
        ensure!(
            self.tx_block_number > self.send_block_number_before_tx,
            "tx_block_number must be > send_block_number_before_tx"
        );
        ensure!(
            self.expected_new_balance_pis.user_id == self.prev_balance_pis.user_id,
            "new balance user_id must stay unchanged"
        );
        ensure!(
            self.expected_new_balance_pis.public_state == self.update_new_public_state,
            "new balance public_state must equal update_new_public_state"
        );
        if self.update_old_public_state != self.update_new_public_state {
            ensure!(
                self.update_new_public_state.block_number
                    >= self.update_old_public_state.block_number,
                "new public state block_number must be >= old block_number"
            );
            ensure!(
                self.update_new_public_state.timestamp >= self.update_old_public_state.timestamp,
                "new public state timestamp must be >= old timestamp"
            );
            ensure!(
                self.update_new_public_state.prev_public_state_root != [0; SEND_TX_HASH_WORDS],
                "new public state prev_public_state_root must be non-zero when public state changes"
            );
        }

        let expected_block_r = if self.spend_pis.is_valid {
            self.tx_block_number
        } else {
            self.prev_balance_pis.block_r
        };
        ensure!(
            self.expected_new_balance_pis.block_r == expected_block_r,
            "new balance block_r selection mismatch"
        );

        let expected_private_commitment = if self.spend_pis.is_valid {
            self.spend_pis.new_private_commitment
        } else {
            self.prev_balance_pis.private_commitment
        };
        ensure!(
            self.expected_new_balance_pis.private_commitment == expected_private_commitment,
            "new balance private commitment selection mismatch"
        );

        Ok(())
    }

    pub fn to_u64_vec(self) -> Vec<u64> {
        [
            self.prev_balance_pis.to_u64_vec(),
            self.update_old_public_state.to_u64_vec(),
            self.update_new_public_state.to_u64_vec(),
            vec![self.settlement_user_id],
            self.settlement_public_state.to_u64_vec(),
            self.spend_pis.to_u64_vec(),
            vec![self.send_block_number_before_tx, self.tx_block_number],
            self.expected_new_balance_pis.to_u64_vec(),
        ]
        .concat()
    }

    pub fn prev_balance_statement(&self) -> NativeBalancePublicInputs {
        self.prev_balance_pis
    }

    pub fn update_public_state_statement(&self) -> NativeUpdatePublicState {
        NativeUpdatePublicState {
            old: self.update_old_public_state,
            new: self.update_new_public_state,
        }
    }

    pub fn tx_settlement_statement(&self) -> NativeTxSettlement {
        NativeTxSettlement {
            user_id: self.settlement_user_id,
            tx: self.spend_pis.tx,
            public_state: self.settlement_public_state,
            account_tree_root: self.settlement_public_state.account_tree_root,
            send_block_number_before_tx: self.send_block_number_before_tx,
            tx_block_number: self.tx_block_number,
            spend_pis: self.spend_pis,
        }
    }
}

pub struct SendTxStatementProof {
    pub statement: SendTxStatement,
    pub expected: KoalaPoseidon2HashOut,
    pub output: RecursionOutput<KoalaRecursionConfig>,
}

pub struct SendTxStatementRecursiveProof {
    pub statement: SendTxStatement,
    pub expected: KoalaPoseidon2HashOut,
    pub base: RecursionOutput<KoalaRecursionConfig>,
    pub compressed: RecursionOutput<KoalaRecursionConfig>,
}

pub struct NativeBalanceBaseProof {
    pub statement: NativeBalancePublicInputs,
    pub expected: KoalaPoseidon2HashOut,
    pub output: RecursionOutput<KoalaRecursionConfig>,
}

pub struct NativeUpdatePublicStateBaseProof {
    pub statement: NativeUpdatePublicState,
    pub expected: KoalaPoseidon2HashOut,
    pub output: RecursionOutput<KoalaRecursionConfig>,
}

pub struct NativeTxSettlementBaseProof {
    pub statement: NativeTxSettlement,
    pub expected: KoalaPoseidon2HashOut,
    pub output: RecursionOutput<KoalaRecursionConfig>,
}

pub struct NativeSendTxProofBundle {
    pub send_tx: SendTxStatementProof,
    pub aggregated: KoalaRecursionProof,
}

pub struct NativeSendTxDecomposedProofBundle {
    pub prev_balance: NativeBalanceBaseProof,
    pub update_public_state: NativeUpdatePublicStateBaseProof,
    pub tx_settlement: NativeTxSettlementBaseProof,
    pub send_tx: SendTxStatementProof,
    pub aggregated: KoalaRecursionProof,
}

pub struct NativeBalanceCircuit {
    hash_circuit: KoalaHashCircuit,
}

impl NativeBalanceCircuit {
    pub fn new() -> Result<Self> {
        Ok(Self {
            hash_circuit: KoalaHashCircuit::new(balance_word_len())?,
        })
    }

    pub fn prove(&self, statement: NativeBalancePublicInputs) -> Result<NativeBalanceBaseProof> {
        let proof = self.hash_circuit.prove(&statement.to_u64_vec())?;
        Ok(NativeBalanceBaseProof {
            statement,
            expected: proof.expected,
            output: proof.output,
        })
    }
}

pub struct NativeUpdatePublicStateCircuit {
    hash_circuit: KoalaHashCircuit,
}

impl NativeUpdatePublicStateCircuit {
    pub fn new() -> Result<Self> {
        Ok(Self {
            hash_circuit: KoalaHashCircuit::new(update_public_state_word_len())?,
        })
    }

    pub fn prove(
        &self,
        statement: NativeUpdatePublicState,
    ) -> Result<NativeUpdatePublicStateBaseProof> {
        statement.validate()?;
        let proof = self.hash_circuit.prove(&statement.to_u64_vec())?;
        Ok(NativeUpdatePublicStateBaseProof {
            statement,
            expected: proof.expected,
            output: proof.output,
        })
    }
}

pub struct NativeTxSettlementCircuit {
    hash_circuit: KoalaHashCircuit,
}

impl NativeTxSettlementCircuit {
    pub fn new() -> Result<Self> {
        Ok(Self {
            hash_circuit: KoalaHashCircuit::new(tx_settlement_word_len())?,
        })
    }

    pub fn prove(&self, statement: NativeTxSettlement) -> Result<NativeTxSettlementBaseProof> {
        statement.validate()?;
        let proof = self.hash_circuit.prove(&statement.to_u64_vec())?;
        Ok(NativeTxSettlementBaseProof {
            statement,
            expected: proof.expected,
            output: proof.output,
        })
    }
}

pub struct SendTxStatementCircuit {
    hash_circuit: KoalaHashCircuit,
    prev_balance_circuit: NativeBalanceCircuit,
    update_public_state_circuit: NativeUpdatePublicStateCircuit,
    tx_settlement_circuit: NativeTxSettlementCircuit,
}

impl SendTxStatementCircuit {
    pub fn new() -> Result<Self> {
        Ok(Self {
            hash_circuit: KoalaHashCircuit::new(statement_word_len())?,
            prev_balance_circuit: NativeBalanceCircuit::new()?,
            update_public_state_circuit: NativeUpdatePublicStateCircuit::new()?,
            tx_settlement_circuit: NativeTxSettlementCircuit::new()?,
        })
    }

    pub fn commitment(&self, statement: &SendTxStatement) -> Result<KoalaPoseidon2HashOut> {
        statement.validate()?;
        self.hash_circuit.hash_native(&statement.to_u64_vec())
    }

    pub fn prove(&self, statement: SendTxStatement) -> Result<SendTxStatementProof> {
        statement.validate()?;
        let base = self.hash_circuit.prove(&statement.to_u64_vec())?;
        Ok(SendTxStatementProof {
            statement,
            expected: base.expected,
            output: base.output,
        })
    }

    pub fn prove_recursively(
        &self,
        statement: SendTxStatement,
    ) -> Result<SendTxStatementRecursiveProof> {
        let proof = self.prove(statement)?;
        let compressed = wrap_recursion_output(&proof.output)?;
        Ok(SendTxStatementRecursiveProof {
            statement: proof.statement,
            expected: proof.expected,
            base: proof.output,
            compressed,
        })
    }

    pub fn prove_full(&self, statement: SendTxStatement) -> Result<NativeSendTxProofBundle> {
        let send_tx = self.prove(statement)?;
        let aggregated = wrap_recursion_output(&send_tx.output)?;
        Ok(NativeSendTxProofBundle {
            send_tx,
            aggregated,
        })
    }

    pub fn prove_decomposed_full(
        &self,
        statement: SendTxStatement,
    ) -> Result<NativeSendTxDecomposedProofBundle> {
        statement.validate()?;

        let prev_balance = self
            .prev_balance_circuit
            .prove(statement.prev_balance_statement())?;
        let update_public_state = self
            .update_public_state_circuit
            .prove(statement.update_public_state_statement())?;
        let tx_settlement = self
            .tx_settlement_circuit
            .prove(statement.tx_settlement_statement())?;
        let send_tx = self.prove(statement)?;

        let mut prep_cache: Option<AggregationPrepCache<KoalaRecursionConfig>> = None;
        let prev_and_update = aggregate_recursion_outputs(
            &prev_balance.output,
            &update_public_state.output,
            1,
            Some(&mut prep_cache),
        )?;
        let settlement_and_send = aggregate_recursion_outputs(
            &tx_settlement.output,
            &send_tx.output,
            1,
            Some(&mut prep_cache),
        )?;
        let aggregated = aggregate_recursion_outputs(
            &prev_and_update,
            &settlement_and_send,
            2,
            Some(&mut prep_cache),
        )?;

        Ok(NativeSendTxDecomposedProofBundle {
            prev_balance,
            update_public_state,
            tx_settlement,
            send_tx,
            aggregated,
        })
    }
}

fn balance_word_len() -> usize {
    1 + 14 + 1 + 4
}

fn update_public_state_word_len() -> usize {
    14 + 14
}

fn tx_settlement_word_len() -> usize {
    1 + 5 + 14 + 4 + 2 + 14
}

fn statement_word_len() -> usize {
    1 + 14 + 1 + 4 + 14 + 14 + 1 + 14 + 4 + 4 + 5 + 1 + 2 + 1 + 14 + 1 + 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn sample_hash(seed: u64) -> SendTxHash {
        [seed, seed + 1, seed + 2, seed + 3]
    }

    fn sample_public_state(seed: u64, block_number: u64) -> NativePublicState {
        NativePublicState {
            block_number,
            timestamp: seed * 10,
            account_tree_root: sample_hash(seed),
            deposit_tree_root: sample_hash(seed + 10),
            prev_public_state_root: sample_hash(seed + 20),
        }
    }

    fn sample_send_tx_statement() -> SendTxStatement {
        let old_state = sample_public_state(10, 5);
        let new_state = sample_public_state(30, 7);
        let prev_private_commitment = sample_hash(100);
        let new_private_commitment = sample_hash(200);

        SendTxStatement {
            prev_balance_pis: NativeBalancePublicInputs {
                user_id: 1,
                public_state: old_state,
                block_r: 6,
                private_commitment: prev_private_commitment,
            },
            update_old_public_state: old_state,
            update_new_public_state: new_state,
            settlement_user_id: 1,
            settlement_public_state: new_state,
            spend_pis: NativeSpendPublicInputs {
                prev_private_commitment,
                new_private_commitment,
                tx: NativeTx {
                    transfer_tree_root: sample_hash(300),
                    nonce: 9,
                },
                is_valid: true,
            },
            send_block_number_before_tx: 4,
            tx_block_number: 7,
            expected_new_balance_pis: NativeBalancePublicInputs {
                user_id: 1,
                public_state: new_state,
                block_r: 7,
                private_commitment: new_private_commitment,
            },
        }
    }

    #[test]
    fn send_tx_statement_round_trip() {
        let statement = sample_send_tx_statement();
        let circuit = SendTxStatementCircuit::new().unwrap();
        let proof = circuit.prove(statement).unwrap();
        let expected = circuit.commitment(&proof.statement).unwrap();
        assert_eq!(proof.expected, expected);
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn send_tx_full_recursive_bundle_round_trip() {
        let statement = sample_send_tx_statement();
        let circuit = SendTxStatementCircuit::new().unwrap();
        let proof = circuit.prove_full(statement).unwrap();
        assert_eq!(proof.send_tx.statement, statement);
        let _ = &proof.aggregated;
    }

    #[test]
    fn send_tx_statement_invalid_rejected() {
        let mut statement = sample_send_tx_statement();
        statement.expected_new_balance_pis.block_r = 6;
        let circuit = SendTxStatementCircuit::new().unwrap();
        assert!(circuit.prove(statement).is_err());
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn send_tx_statement_release_bench() {
        let statement = sample_send_tx_statement();
        let circuit = SendTxStatementCircuit::new().unwrap();

        let prove_timer = Instant::now();
        let base = circuit.prove(statement).unwrap();
        println!(
            "plonky3 native send tx statement proof time: {:?}",
            prove_timer.elapsed()
        );

        let wrap_timer = Instant::now();
        let _recursive = wrap_recursion_output(&base.output).unwrap();
        println!(
            "plonky3 native send tx statement recursive wrap time: {:?}",
            wrap_timer.elapsed()
        );

        let full_timer = Instant::now();
        let _bundle = circuit.prove_full(statement).unwrap();
        println!(
            "plonky3 native compact send tx recursive bundle time: {:?}",
            full_timer.elapsed()
        );

        let decomposed_timer = Instant::now();
        let _decomposed = circuit.prove_decomposed_full(statement).unwrap();
        println!(
            "plonky3 native decomposed send tx recursive bundle time: {:?}",
            decomposed_timer.elapsed()
        );
    }
}
