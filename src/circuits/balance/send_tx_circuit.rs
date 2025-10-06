use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{
            BalancePisBeforeAfter, BalancePisBeforeAfterTarget, BalancePublicInputs,
            BalancePublicInputsTarget,
        },
        common::{
            tx_settlement::{TxSettlement, TxSettlementTarget},
            update_public_state::{UpdatePublicState, UpdatePublicStateTarget},
        },
    },
    common::{
        block_number::{BlockNumber, BlockNumberTarget},
        public_state::PublicStateTarget,
        user_id::UserIdTarget,
    },
    constants::BLOCK_NUMBER_BITS,
    utils::poseidon_hash_out::PoseidonHashOutTarget,
};

#[derive(thiserror::Error, Debug)]
pub enum SpendTxError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Spend public inputs error: {0}")]
    SpendPisError(String),

    #[error("Block number error: {0}")]
    BlockNumberError(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

pub struct SpendTxWitness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub prev_balance_pis: BalancePublicInputs,

    /* update_public_state.old ==
     * prev_balance_pis.public_state */
    pub update_public_state: UpdatePublicState,

    /* update_public_state.new ==
     * tx_settlement.public_state */
    pub tx_settlement: TxSettlement<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SpendTxWitness<F, C, D>
{
    pub fn to_public_inputs(&self) -> Result<BalancePisBeforeAfter, SpendTxError> {
        if self.prev_balance_pis.public_state != self.update_public_state.old {
            return Err(SpendTxError::ConnectionError(format!(
                "prev_balance_pis.public_state: {:?}, update_public_state.old: {:?}",
                self.prev_balance_pis.public_state, self.update_public_state.old
            )));
        }
        if self.update_public_state.new != self.tx_settlement.public_state {
            return Err(SpendTxError::ConnectionError(format!(
                "update_public_state.new: {:?}, tx_settlement.public_state: {:?}",
                self.update_public_state.new, self.tx_settlement.public_state
            )));
        }
        if self.tx_settlement.user_id != self.prev_balance_pis.user_id {
            return Err(SpendTxError::ConnectionError(format!(
                "tx_settlement.user_id: {}, prev_balance_pis.user_id: {}",
                self.tx_settlement.user_id.0, self.prev_balance_pis.user_id.0
            )));
        }
        let spend_pis = self
            .tx_settlement
            .spend_pis()
            .map_err(|e| SpendTxError::SpendPisError(format!("failed to get spend pis: {}", e)))?;
        if spend_pis.prev_private_commitment != self.prev_balance_pis.private_commitment {
            return Err(SpendTxError::ConnectionError(format!(
                "spend_pis.prev_private_commitment: {}, prev_balance_pis.private_commitment: {}",
                spend_pis.prev_private_commitment, self.prev_balance_pis.private_commitment
            )));
        }
        if self.prev_balance_pis.block_r != BlockNumber(0)
            && self.prev_balance_pis.block_r < self.tx_settlement.send_block_number_before_tx()
        {
            return Err(SpendTxError::BlockNumberError(format!(
                "prev_balance_pis.block_r: {} should be >= tx_settlement.send_block_number_before_tx(): {}",
                self.prev_balance_pis.block_r.0,
                self.tx_settlement.send_block_number_before_tx().0
            )));
        }
        let (new_block_r, new_private_commitment) = if spend_pis.is_valid {
            (
                self.tx_settlement.tx_block_number(),
                spend_pis.new_private_commitment,
            )
        } else {
            (
                self.prev_balance_pis.block_r,
                self.prev_balance_pis.private_commitment,
            )
        };
        let new_balance_pis = BalancePublicInputs {
            user_id: self.prev_balance_pis.user_id,
            public_state: self.update_public_state.new.clone(),
            block_r: new_block_r,
            private_commitment: new_private_commitment,
        };
        Ok(BalancePisBeforeAfter {
            before: self.prev_balance_pis.clone(),
            after: new_balance_pis,
        })
    }
}

fn new_balance_public_inputs_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BalancePublicInputsTarget {
    BalancePublicInputsTarget {
        user_id: UserIdTarget::new(builder, true),
        public_state: PublicStateTarget::new(builder, true),
        block_r: BlockNumberTarget::new(builder, true),
        private_commitment: PoseidonHashOutTarget::new(builder),
    }
}

#[derive(Clone, Debug)]
pub struct SendTxTarget<const D: usize> {
    pub balance_pis_before_after: BalancePisBeforeAfterTarget,
    pub update_public_state: UpdatePublicStateTarget,
    pub tx_settlement: TxSettlementTarget<D>,
}

impl<const D: usize> SendTxTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        spend_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let before = new_balance_public_inputs_target(builder);
        let after = new_balance_public_inputs_target(builder);
        let balance_pis_before_after = BalancePisBeforeAfterTarget { before, after };

        let update_public_state = UpdatePublicStateTarget::new::<F, C, D>(builder);
        let tx_settlement = TxSettlementTarget::new(builder, spend_vd, true);

        // Link user IDs across components.
        builder.connect(
            balance_pis_before_after.before.user_id.value,
            tx_settlement.user_id.value,
        );
        builder.connect(
            balance_pis_before_after.after.user_id.value,
            balance_pis_before_after.before.user_id.value,
        );

        // The previous public state must match the updater's old state.
        builder.connect(
            balance_pis_before_after
                .before
                .public_state
                .block_number
                .value,
            update_public_state.old.block_number.value,
        );
        balance_pis_before_after
            .before
            .public_state
            .account_tree_root
            .connect(builder, update_public_state.old.account_tree_root.clone());
        balance_pis_before_after
            .before
            .public_state
            .deposit_tree_root
            .connect(builder, update_public_state.old.deposit_tree_root.clone());
        balance_pis_before_after
            .before
            .public_state
            .prev_public_state_root
            .connect(
                builder,
                update_public_state.old.prev_public_state_root.clone(),
            );

        // The new public state must align everywhere.
        builder.connect(
            balance_pis_before_after
                .after
                .public_state
                .block_number
                .value,
            update_public_state.new.block_number.value,
        );
        balance_pis_before_after
            .after
            .public_state
            .account_tree_root
            .connect(builder, update_public_state.new.account_tree_root.clone());
        balance_pis_before_after
            .after
            .public_state
            .deposit_tree_root
            .connect(builder, update_public_state.new.deposit_tree_root.clone());
        balance_pis_before_after
            .after
            .public_state
            .prev_public_state_root
            .connect(
                builder,
                update_public_state.new.prev_public_state_root.clone(),
            );

        builder.connect(
            tx_settlement.public_state.block_number.value,
            update_public_state.new.block_number.value,
        );
        tx_settlement
            .public_state
            .account_tree_root
            .connect(builder, update_public_state.new.account_tree_root.clone());
        tx_settlement
            .public_state
            .deposit_tree_root
            .connect(builder, update_public_state.new.deposit_tree_root.clone());
        tx_settlement.public_state.prev_public_state_root.connect(
            builder,
            update_public_state.new.prev_public_state_root.clone(),
        );

        // Previous private commitment must coincide with the spend proof.
        let spend_pis = tx_settlement.spend_pis();
        balance_pis_before_after
            .before
            .private_commitment
            .connect(builder, spend_pis.prev_private_commitment.clone());

        // Ensure block_r >= send_block_number_before_tx when block_r is not zero.
        let send_block_number_before_tx = tx_settlement.send_block_number_before_tx();
        let zero = builder.zero();
        let block_r_is_zero = builder.is_equal(balance_pis_before_after.before.block_r.value, zero);
        let block_r_non_zero = builder.not(block_r_is_zero);

        let block_r_diff = builder.add_virtual_target();
        builder.range_check(block_r_diff, BLOCK_NUMBER_BITS);
        let recomposed_block_r = builder.add(send_block_number_before_tx.value, block_r_diff);
        builder.conditional_assert_eq(
            block_r_non_zero.target,
            recomposed_block_r,
            balance_pis_before_after.before.block_r.value,
        );
        builder.conditional_assert_eq(block_r_is_zero.target, block_r_diff, zero);

        // Select the next block reference depending on the spend validity.
        let tx_block_number = tx_settlement.tx_block_number();
        let new_block_r_value = builder.select(
            spend_pis.is_valid,
            tx_block_number.value,
            balance_pis_before_after.before.block_r.value,
        );
        builder.connect(
            new_block_r_value,
            balance_pis_before_after.after.block_r.value,
        );

        // Select the next private commitment.
        let new_private_commitment = PoseidonHashOutTarget::select(
            builder,
            spend_pis.is_valid,
            spend_pis.new_private_commitment.clone(),
            balance_pis_before_after.before.private_commitment.clone(),
        );
        balance_pis_before_after
            .after
            .private_commitment
            .connect(builder, new_private_commitment);

        Self {
            balance_pis_before_after,
            update_public_state,
            tx_settlement,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &SpendTxWitness<F, C, D>,
        balance_pis: &BalancePisBeforeAfter,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        self.balance_pis_before_after
            .set_witness(witness, balance_pis);
        self.update_public_state
            .set_witness(witness, &value.update_public_state);
        self.tx_settlement
            .set_witness::<F, C, _>(witness, &value.tx_settlement);
    }
}

#[derive(Debug)]
pub struct SendTxCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SendTxTarget<D>,
    pub public_inputs: BalancePisBeforeAfterTarget,
}

impl<F, C, const D: usize> SendTxCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(spend_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = SendTxTarget::new(&mut builder, spend_vd);
        let public_inputs = target.balance_pis_before_after.clone();

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build();

        Self {
            data,
            target,
            public_inputs,
        }
    }

    pub fn prove(
        &self,
        witness: &SpendTxWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SpendTxError> {
        let balance_pis = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();

        self.target
            .set_witness::<F, C, _>(&mut pw, witness, &balance_pis);
        self.public_inputs.set_witness(&mut pw, &balance_pis);

        self.data
            .prove(pw)
            .map_err(|e| SpendTxError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::balance::spend_circuit::{SpendCircuit, SpendWitness},
        common::{
            block_number::BlockNumber,
            private_state::FullPrivateState,
            transfer::Transfer,
            trees::{
                account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
                asset_tree::AssetTree,
                tx_tree::TxTree,
            },
            tx::Tx,
            user_id::UserId,
        },
        constants::{
            ACCOUNT_TREE_HEIGHT, ASSET_TREE_HEIGHT, MAX_NUM_TRANSFERS_PER_TX, SEND_TREE_HEIGHT,
            TX_TREE_HEIGHT,
        },
        ethereum_types::{bytes32::Bytes32, u256::U256},
        utils::poseidon_hash_out::PoseidonHashOut,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_send_tx_circuit_smoke() {
        // Build a spend witness to reuse its proof inside the send circuit.
        let mut full_state = FullPrivateState::new();

        let mut asset_tree_initial = AssetTree::new(ASSET_TREE_HEIGHT);
        let mut transfers = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);

        for i in 0..MAX_NUM_TRANSFERS_PER_TX {
            let amount = U256::from((i + 1) as u32);
            let base_balance = amount + U256::from(10u32);
            let transfer = Transfer {
                recipient: Bytes32::default(),
                token_index: i as u32,
                amount,
                aux_data: Bytes32::default(),
            };
            asset_tree_initial.update(i as u64, base_balance);
            transfers.push(transfer);
        }

        let mut asset_tree_current = asset_tree_initial.clone();
        let mut before_balances = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);
        let mut asset_merkle_proofs = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);

        for transfer in &transfers {
            let index = transfer.token_index as u64;
            let balance = asset_tree_current.get_leaf(index);
            let proof = asset_tree_current.prove(index);

            before_balances.push(balance);
            asset_merkle_proofs.push(proof);

            let new_balance = balance - transfer.amount;
            asset_tree_current.update(index, new_balance);
        }

        full_state.asset_tree = asset_tree_initial;
        let prev_private_state = full_state.to_private_state();

        let spend_witness = SpendWitness {
            tx_nonce: prev_private_state.nonce,
            prev_private_state: prev_private_state.clone(),
            transfers,
            before_balances,
            asset_merkle_proofs,
        };

        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let spend_vd = spend_circuit.data.verifier_data();
        let spend_proof = spend_circuit
            .prove(&spend_witness)
            .expect("spend proof should succeed");

        let spend_pis = spend_witness
            .to_public_inputs()
            .expect("public inputs from spend witness");

        let tx = spend_pis.tx;
        let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        tx_tree.push(Tx::default());
        let local_id = 1u32;
        tx_tree.push(tx);
        let tx_merkle_proof = tx_tree.prove(local_id as u64);
        let tx_tree_root: PoseidonHashOut = tx_tree.get_root();
        let tx_tree_root_bytes: Bytes32 = tx_tree_root.clone().into();

        let send_leaf = SendLeaf {
            prev: BlockNumber::new(2).unwrap(),
            cur: BlockNumber::new(3).unwrap(),
            tx_tree_root: tx_tree_root_bytes,
        };
        let mut send_tree = SendTree::new(SEND_TREE_HEIGHT);
        send_tree.push(send_leaf.clone());
        let send_leaf_index = 0u32;
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        let account_leaf = AccountLeaf {
            index: send_tree.len() as u64,
            prev: BlockNumber::new(1).unwrap(),
            send_tree_root: send_tree.get_root(),
        };
        let user_id = UserId::new(0, local_id).unwrap();
        account_tree.update(user_id.0, account_leaf.clone());
        let account_merkle_proof = account_tree.prove(user_id.0);
        let account_tree_root = account_tree.get_root();

        let public_state = crate::common::public_state::PublicState {
            block_number: BlockNumber::new(6).unwrap(),
            account_tree_root,
            deposit_tree_root: PoseidonHashOut::default(),
            prev_public_state_root: PoseidonHashOut::default(),
        };

        let account_state = crate::circuits::balance::common::account_state::AccountState::new(
            user_id,
            public_state.account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            account_leaf,
            account_merkle_proof,
        )
        .expect("account state should be valid");

        let update_public_state =
            UpdatePublicState::new(public_state.clone(), public_state.clone(), None)
                .expect("update public state");

        let tx_settlement = TxSettlement::new(
            &spend_vd,
            user_id,
            tx,
            public_state.clone(),
            account_state,
            tx_merkle_proof,
            spend_proof,
        )
        .expect("tx settlement");

        let prev_balance_pis = BalancePublicInputs {
            user_id,
            public_state: public_state.clone(),
            block_r: BlockNumber::new(5).unwrap(),
            private_commitment: spend_pis.prev_private_commitment,
        };

        let witness = SpendTxWitness {
            prev_balance_pis,
            update_public_state,
            tx_settlement,
        };

        let send_tx_circuit = SendTxCircuit::<F, C, D>::new(&spend_vd);
        let proof = send_tx_circuit
            .prove(&witness)
            .expect("send tx proof should succeed");

        send_tx_circuit
            .data
            .verify(proof.clone())
            .expect("send tx verification should succeed");

        let parsed =
            BalancePisBeforeAfter::from_pis_u64(&proof.public_inputs.to_u64_vec()).unwrap();

        assert_eq!(parsed.before.user_id.0, user_id.0);
        assert_eq!(parsed.after.user_id.0, user_id.0);
        assert_eq!(parsed.after.block_r, BlockNumber::new(3).unwrap());
        assert_eq!(
            parsed.after.private_commitment,
            spend_pis.new_private_commitment,
        );
    }
}
