use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{
            BalanceFullPublicInputs, BalanceFullPublicInputsTarget, BalancePublicInputs,
            BalancePublicInputsError, BalancePublicInputsTarget,
        },
        common::{
            account_state::{AccountState, AccountStateError, AccountStateTarget},
            deposit_witness::{DepositWitness, DepositWitnessError, DepositWitnessTarget},
            update_private_state::{UpdatePrivateState, UpdatePrivateStateTarget},
            update_public_state::{UpdatePublicState, UpdatePublicStateTarget},
        },
    },
    common::u63::{BlockNumber, BlockNumberTarget},
    ethereum_types::u32limb_trait::U32LimbTargetTrait as _,
    utils::conversion::ToU64,
};

#[derive(Debug, thiserror::Error)]
pub enum ReceiveDepositError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Balance public inputs error: {0}")]
    BalancePublicInputsError(#[from] BalancePublicInputsError),

    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid balance verifier data: {0}")]
    InvalidBalanceVd(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Block number error: {0}")]
    BlockNumberError(String),

    #[error("Invalid deposit witness: {0}")]
    InvalidDepositWitness(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

#[derive(Clone, Debug)]
pub struct ReceiveDepositWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous receiver balance proof
    pub prev_balance_proof: ProofWithPublicInputs<F, C, D>,

    // receiver's public state update
    pub update_public_state: UpdatePublicState,

    // receiver's new block_r
    pub new_block_r: BlockNumber,

    // account state that proves no outgoing tx (prev_balance_proof.block_r, new_block_r]
    pub account_state: AccountState,

    // deposit witness
    pub deposit_witness: DepositWitness,

    // private state update
    pub update_private_state: UpdatePrivateState,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveDepositWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_cd: &CommonCircuitData<F, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, ReceiveDepositError> {
        let prev_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.prev_balance_proof.public_inputs.to_u64_vec(),
            &balance_cd.config,
        )?;
        let balance_vd = prev_full_pis.vd.clone();

        let prev_balance_pis = prev_full_pis.pis;
        let receiver_user_id = prev_balance_pis.user_id;

        self.update_public_state.verify().map_err(|e| {
            ReceiveDepositError::ConnectionError(format!(
                "update_public_state verification failed: {e}"
            ))
        })?;

        if self.update_public_state.old != prev_balance_pis.public_state {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_public_state.old {:?} != prev_balance_pis.public_state {:?}",
                self.update_public_state.old, prev_balance_pis.public_state
            )));
        }
        let public_state = self.update_public_state.new.clone();

        self.account_state
            .verify()
            .map_err(|e: AccountStateError| {
                ReceiveDepositError::ConnectionError(format!(
                    "account_state verification failed: {e}"
                ))
            })?;

        if self.account_state.user_id != receiver_user_id {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "account_state.user_id {:?} != receiver_user_id {:?}",
                self.account_state.user_id, receiver_user_id,
            )));
        }
        if self.account_state.account_tree_root != public_state.account_tree_root {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "account_state.account_tree_root {:?} != public_state.account_tree_root {:?}",
                self.account_state.account_tree_root, public_state.account_tree_root,
            )));
        }

        if self.deposit_witness.user_id != receiver_user_id {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "deposit_witness.user_id {:?} != receiver_user_id {:?}",
                self.deposit_witness.user_id, receiver_user_id,
            )));
        }

        self.deposit_witness
            .verify()
            .map_err(|e: DepositWitnessError| match e {
                DepositWitnessError::InvalidRecipient(msg) => {
                    ReceiveDepositError::InvalidRecipient(msg)
                }
                other => ReceiveDepositError::InvalidDepositWitness(other.to_string()),
            })?;

        if self.deposit_witness.deposit_tree_root != public_state.deposit_tree_root {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "deposit_witness.deposit_tree_root {:?} != public_state.deposit_tree_root {:?}",
                self.deposit_witness.deposit_tree_root, public_state.deposit_tree_root,
            )));
        }

        let prev_block_r = prev_balance_pis.block_r;

        if self.new_block_r < prev_block_r || self.new_block_r > public_state.block_number {
            return Err(ReceiveDepositError::BlockNumberError(format!(
                "Not prev_block_r <= new_block_r <= public_state.block_number: {:?} <= {:?} <= {:?}",
                prev_block_r, self.new_block_r, public_state.block_number,
            )));
        }

        if self.account_state.account_leaf.prev != BlockNumber::default() {
            if self.account_state.send_leaf.prev > prev_block_r {
                return Err(ReceiveDepositError::BlockNumberError(format!(
                    "Not account_state.send_leaf.prev <= prev_balance_pis.block_r: {:?} <= {:?}",
                    self.account_state.send_leaf.prev, prev_block_r,
                )));
            }

            if self.new_block_r >= self.account_state.send_leaf.cur {
                return Err(ReceiveDepositError::BlockNumberError(format!(
                    "Not new_block_r < account_state.send_leaf.cur: {:?} < {:?}",
                    self.new_block_r, self.account_state.send_leaf.cur,
                )));
            }
        }

        if self.deposit_witness.deposit.block_number > self.new_block_r {
            return Err(ReceiveDepositError::BlockNumberError(format!(
                "deposit block number {:?} must be <= new_block_r {:?}",
                self.deposit_witness.deposit.block_number, self.new_block_r,
            )));
        }

        let deposit = &self.deposit_witness.deposit;
        if self.update_private_state.token_index != deposit.token_index {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.token_index {:?} != deposit.token_index {:?}",
                self.update_private_state.token_index, deposit.token_index,
            )));
        }
        if self.update_private_state.amount != deposit.amount {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.amount {:?} != deposit.amount {:?}",
                self.update_private_state.amount, deposit.amount,
            )));
        }
        let deposit_nullifier = deposit.nullifier();
        if self.update_private_state.nullifier != deposit_nullifier {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.nullifier {:?} != deposit.nullifier {:?}",
                self.update_private_state.nullifier, deposit_nullifier,
            )));
        }

        let prev_private_commitment = self.update_private_state.prev_private_state.commitment();
        if prev_private_commitment != prev_balance_pis.private_commitment {
            return Err(ReceiveDepositError::ConnectionError(format!(
                "update_private_state.prev_private_state.commitment() {:?} != prev_balance_pis.private_commitment {:?}",
                prev_private_commitment, prev_balance_pis.private_commitment,
            )));
        }

        let new_private_commitment = self.update_private_state.new_private_state.commitment();

        let new_balance_pis = BalanceFullPublicInputs {
            pis: BalancePublicInputs {
                user_id: receiver_user_id,
                public_state,
                block_r: self.new_block_r,
                private_commitment: new_private_commitment,
            },
            vd: balance_vd,
        };

        Ok(new_balance_pis)
    }
}

#[derive(Clone, Debug)]
pub struct ReceiveDepositTarget<const D: usize> {
    pub prev_balance_proof: ProofWithPublicInputsTarget<D>,
    pub update_public_state: UpdatePublicStateTarget,
    pub new_block_r: BlockNumberTarget,
    pub account_state: AccountStateTarget,
    pub deposit_witness: DepositWitnessTarget,
    pub update_private_state: UpdatePrivateStateTarget,
    pub new_full_pis: BalanceFullPublicInputsTarget,
}

impl<const D: usize> ReceiveDepositTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        balance_cd: &CommonCircuitData<F, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_balance_proof = builder.add_virtual_proof_with_pis(balance_cd);
        let prev_balance_full_pis = BalanceFullPublicInputsTarget::from_pis(
            &prev_balance_proof.public_inputs,
            &balance_cd.config,
        );

        builder.verify_proof::<C>(&prev_balance_proof, &prev_balance_full_pis.vd, balance_cd);

        let prev_balance_pis = prev_balance_full_pis.pis.clone();

        let update_public_state = UpdatePublicStateTarget::new::<F, C, D>(builder);
        let new_block_r = BlockNumberTarget::new(builder, true);
        let account_state = AccountStateTarget::new::<F, C, D>(builder, true);
        let deposit_witness = DepositWitnessTarget::new::<F, C, D>(builder, true);
        let update_private_state = UpdatePrivateStateTarget::new::<F, C, D>(builder, true);

        update_public_state
            .old
            .connect(builder, &prev_balance_pis.public_state);
        let public_state = &update_public_state.new;

        account_state
            .user_id
            .connect(builder, &prev_balance_pis.user_id);
        account_state
            .account_tree_root
            .connect(builder, public_state.account_tree_root.clone());

        deposit_witness
            .user_id
            .connect(builder, &prev_balance_pis.user_id);
        deposit_witness
            .deposit_tree_root
            .connect(builder, public_state.deposit_tree_root.clone());

        let prev_block_r = prev_balance_pis.block_r.clone();
        new_block_r.enforce_ge(builder, &prev_block_r);
        public_state.block_number.enforce_ge(builder, &new_block_r);

        let prev_is_zero = account_state.account_leaf.prev.is_zero(builder);
        let has_outgoing = builder.not(prev_is_zero);
        prev_block_r.conditional_ge(builder, &account_state.send_leaf.prev, has_outgoing);
        account_state
            .send_leaf
            .cur
            .conditional_gt(builder, &new_block_r, has_outgoing);

        let deposit_block_number = deposit_witness.deposit.block_number.clone();
        new_block_r.enforce_ge(builder, &deposit_block_number);

        builder.connect(
            update_private_state.token_index,
            deposit_witness.deposit.token_index,
        );
        update_private_state
            .amount
            .connect(builder, deposit_witness.deposit.amount.clone());
        let deposit_nullifier_target = deposit_witness.deposit.nullifier(builder);
        update_private_state
            .nullifier
            .connect(builder, deposit_nullifier_target);

        let prev_private_commitment = update_private_state.prev_private_state.commitment(builder);
        prev_private_commitment.connect(builder, prev_balance_pis.private_commitment.clone());
        let new_private_commitment = update_private_state.new_private_state.commitment(builder);

        let new_pis = BalancePublicInputsTarget {
            user_id: prev_balance_pis.user_id.clone(),
            public_state: public_state.clone(),
            block_r: new_block_r.clone(),
            private_commitment: new_private_commitment,
        };
        let new_full_pis = BalanceFullPublicInputsTarget {
            pis: new_pis,
            vd: prev_balance_full_pis.vd.clone(),
        };

        Self {
            prev_balance_proof,
            update_public_state,
            new_block_r,
            account_state,
            deposit_witness,
            update_private_state,
            new_full_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &ReceiveDepositWitness<F, C, D>,
        new_full_pis: &BalanceFullPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        witness.set_proof_with_pis_target(&self.prev_balance_proof, &value.prev_balance_proof);
        self.update_public_state
            .set_witness(witness, &value.update_public_state);
        self.new_block_r.set_witness(witness, value.new_block_r);
        self.account_state
            .set_witness(witness, &value.account_state);
        self.deposit_witness
            .set_witness(witness, &value.deposit_witness);
        self.update_private_state
            .set_witness(witness, &value.update_private_state);
        self.new_full_pis.set_witness(witness, new_full_pis);
    }
}

#[derive(Debug)]
pub struct ReceiveDepositCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub balance_cd: CommonCircuitData<F, D>,
    pub target: ReceiveDepositTarget<D>,
    pub public_inputs: BalanceFullPublicInputsTarget,
}

impl<F, C, const D: usize> ReceiveDepositCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_cd: &CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = ReceiveDepositTarget::new::<F, C>(&mut builder, &balance_cd);
        let public_inputs = target.new_full_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&balance_cd.config));
        let data = builder.build();

        Self {
            data,
            balance_cd: balance_cd.clone(),
            target,
            public_inputs,
        }
    }

    pub fn prove(
        &self,
        witness: &ReceiveDepositWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ReceiveDepositError> {
        let new_full_pis = witness.to_public_inputs(&self.balance_cd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness::<F, C, _>(&mut pw, witness, &new_full_pis);
        self.public_inputs.set_witness(&mut pw, &new_full_pis);
        self.data
            .prove(pw)
            .map_err(|e| ReceiveDepositError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::balance::{
            balance_pis::{
                BALANCE_PUBLIC_INPUTS_LEN, BalanceFullPublicInputs, BalancePublicInputs,
            },
            common::{
                account_state::AccountState, deposit_witness::DepositWitness,
                recipient::calculate_recipient_from_user_id,
                update_private_state::UpdatePrivateState, update_public_state::UpdatePublicState,
            },
        },
        common::{
            deposit::Deposit,
            private_state::FullPrivateState,
            public_state::PublicState,
            salt::Salt,
            trees::{
                account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
                asset_tree::AssetTree,
                deposit_tree::DepositTree,
                nullifier_tree::NullifierTree,
            },
            u63::BlockNumber,
            user_id::UserId,
        },
        constants::{ACCOUNT_TREE_HEIGHT, ASSET_TREE_HEIGHT, SEND_TREE_HEIGHT},
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
        utils::{
            conversion::ToField as _, cyclic::TestCyclicCircuit, poseidon_hash_out::PoseidonHashOut,
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_receive_deposit_circuit() {
        let receiver_user_id = UserId::new(0, 7).unwrap();
        let mut rng = rand::thread_rng();
        let deposit_salt = Salt::rand(&mut rng);

        let prev_block_r = BlockNumber::new(4).unwrap();
        let new_block_r = BlockNumber::new(6).unwrap();

        let deposit_amount = U256::from(5u32);
        let token_index = 0u32;
        let deposit_recipient = calculate_recipient_from_user_id(receiver_user_id, deposit_salt);

        let deposit = Deposit {
            depositor: Address::default(),
            recipient: deposit_recipient,
            token_index,
            amount: deposit_amount,
            block_number: new_block_r,
            aux_data: Bytes32::default(),
        };

        let mut deposit_tree = DepositTree::init();
        deposit_tree.push(deposit.clone());
        let deposit_index = 0u64;
        let deposit_merkle_proof = deposit_tree.prove(deposit_index);
        let deposit_tree_root = deposit_tree.get_root();

        let deposit_witness = DepositWitness::new(
            receiver_user_id,
            deposit_tree_root,
            deposit_salt,
            deposit.clone(),
            deposit_index,
            deposit_merkle_proof,
        )
        .expect("deposit witness should be valid");

        let mut send_tree = SendTree::new(SEND_TREE_HEIGHT);
        let send_leaf = SendLeaf::default();
        send_tree.push(send_leaf.clone());
        let send_leaf_index = 0u32;
        let send_merkle_proof = send_tree.prove(send_leaf_index as u64);

        let account_leaf = AccountLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::new(0).unwrap(),
            send_tree_root: send_tree.get_root(),
        };

        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        account_tree.update(receiver_user_id.as_u64(), account_leaf.clone());
        let account_merkle_proof = account_tree.prove(receiver_user_id.as_u64());
        let account_tree_root = account_tree.get_root();

        let account_state = AccountState::new(
            receiver_user_id,
            account_tree_root,
            send_leaf,
            send_leaf_index,
            send_merkle_proof,
            account_leaf,
            account_merkle_proof,
        )
        .expect("account state should be valid");

        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        let prev_balance = U256::from(10u32);
        asset_tree.update(token_index as u64, prev_balance);
        let asset_merkle_proof = asset_tree.prove(token_index as u64);

        let mut full_private_state = FullPrivateState::new(Salt::rand(&mut rng));
        full_private_state.asset_tree = asset_tree.clone();
        let prev_private_state = full_private_state.to_private_state();

        let mut nullifier_tree = NullifierTree::init();
        let deposit_nullifier = deposit.nullifier();
        let nullifier_proof = nullifier_tree
            .prove_and_insert(deposit_nullifier)
            .expect("nullifier proof");

        let update_private_state = UpdatePrivateState::new(
            token_index,
            deposit_amount,
            deposit_nullifier,
            &prev_private_state,
            &nullifier_proof,
            prev_balance,
            &asset_merkle_proof,
        )
        .expect("update private state");

        let public_state = PublicState {
            block_number: BlockNumber::new(8).unwrap(),
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root: PoseidonHashOut::default(),
        };

        let update_public_state =
            UpdatePublicState::new(public_state.clone(), public_state.clone(), None)
                .expect("update public state");

        let prev_balance_pis = BalancePublicInputs {
            user_id: receiver_user_id,
            public_state: update_public_state.old.clone(),
            block_r: prev_block_r,
            private_commitment: prev_private_state.commitment(),
        };

        let balance_common_data =
            TestCyclicCircuit::<F, C, D>::generate_cd(BALANCE_PUBLIC_INPUTS_LEN);
        let balance_circuit = TestCyclicCircuit::<F, C, D>::new(
            CircuitConfig::standard_recursion_config(),
            BALANCE_PUBLIC_INPUTS_LEN,
            &balance_common_data,
        );
        let balance_vd = balance_circuit.data.verifier_data();
        let balance_cd = balance_vd.common.clone();

        let prev_full_pis = BalanceFullPublicInputs {
            pis: prev_balance_pis.clone(),
            vd: balance_vd.verifier_only.clone(),
        };
        let prev_fields = prev_full_pis
            .to_u64_vec(&balance_vd.common.config)
            .to_field_vec::<F>();
        let prev_balance_proof = balance_circuit
            .prove(Some(prev_fields.as_slice()), None)
            .expect("balance proof");

        let witness = ReceiveDepositWitness {
            prev_balance_proof: prev_balance_proof.clone(),
            update_public_state,
            new_block_r,
            account_state,
            deposit_witness,
            update_private_state,
        };

        let circuit = ReceiveDepositCircuit::<F, C, D>::new(&balance_cd);
        let proof = circuit
            .prove(&witness)
            .expect("receive deposit proof should succeed");

        circuit
            .data
            .verify(proof.clone())
            .expect("receive deposit proof verification");

        let expected = witness
            .to_public_inputs(&balance_cd)
            .expect("expected public inputs");
        let expected_fields = expected.to_u64_vec(&balance_cd.config).to_field_vec::<F>();

        assert_eq!(proof.public_inputs, expected_fields);
        assert_eq!(expected.pis.block_r, new_block_r);
    }
}
