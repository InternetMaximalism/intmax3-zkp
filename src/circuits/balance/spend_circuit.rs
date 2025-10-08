use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        transfer::{Transfer, TransferTarget},
        trees::asset_tree::{AssetMerkleProof, AssetMerkleProofTarget},
        tx::{TX_LEN, Tx, TxTarget},
    },
    constants::{ASSET_TREE_HEIGHT, MAX_NUM_TRANSFERS_PER_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::{
        u32limb_trait::U32LimbTargetTrait as _,
        u256::{U256, U256Target},
    },
    utils::{
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

pub const SPEND_PUBLIC_INPUTS_LEN: usize = POSEIDON_HASH_OUT_LEN * 2 + TX_LEN + 1;

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error("The number of inputs should be {MAX_NUM_TRANSFERS_PER_TX}")]
    InvalidNumInputs,

    #[error("Invalid Merkle proof {0}")]
    InvalidMerkleProof(String),

    #[error("Insufficient balance {0}")]
    InsufficientBalance(String),

    #[error("Invalid data {0}")]
    InvalidData(String),

    #[error("Failed to prove {0}")]
    FailedToProve(String),

    #[error("Invalid public inputs {0}")]
    InvalidPublicInputs(String),
}

#[derive(Clone, Debug)]
pub struct SpendPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub tx: Tx,
    pub is_valid: bool,
}

impl SpendPublicInputs {
    pub fn from_pis_u64(pis: &[u64]) -> Result<Self, SpendError> {
        if pis.len() < SPEND_PUBLIC_INPUTS_LEN {
            return Err(SpendError::InvalidPublicInputs(format!(
                "Expected {} public inputs, got {}",
                SPEND_PUBLIC_INPUTS_LEN,
                pis.len()
            )));
        }
        let mut cursor = 0;

        let prev_private_commitment_slice = &pis[cursor..cursor + POSEIDON_HASH_OUT_LEN];
        let prev_private_commitment =
            PoseidonHashOut::from_u64_slice(prev_private_commitment_slice)
                .map_err(|e| SpendError::InvalidPublicInputs(e.to_string()))?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let new_private_commitment_slice = &pis[cursor..cursor + POSEIDON_HASH_OUT_LEN];
        let new_private_commitment = PoseidonHashOut::from_u64_slice(new_private_commitment_slice)
            .map_err(|e| SpendError::InvalidPublicInputs(e.to_string()))?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let tx_slice = &pis[cursor..cursor + TX_LEN];
        let tx = Tx::from_u64_slice(tx_slice)
            .map_err(|e| SpendError::InvalidPublicInputs(e.to_string()))?;
        cursor += TX_LEN;
        let is_valid = pis[cursor] != 0;

        Ok(Self {
            prev_private_commitment,
            new_private_commitment,
            tx,
            is_valid,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SpendWitness {
    pub tx_nonce: u32,
    pub prev_private_state: PrivateState,
    pub transfers: Vec<Transfer>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub before_balances: Vec<U256>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub asset_merkle_proofs: Vec<AssetMerkleProof>, /* the length must be equal to
                                   * MAX_NUM_TRANSFERS_PER_TX */
}

impl SpendWitness {
    pub fn to_public_inputs(&self) -> Result<SpendPublicInputs, SpendError> {
        if self.transfers.len() != MAX_NUM_TRANSFERS_PER_TX
            || self.before_balances.len() != MAX_NUM_TRANSFERS_PER_TX
            || self.asset_merkle_proofs.len() != MAX_NUM_TRANSFERS_PER_TX
        {
            return Err(SpendError::InvalidNumInputs);
        }
        let mut asset_tree_root = self.prev_private_state.asset_tree_root;
        for i in 0..MAX_NUM_TRANSFERS_PER_TX {
            let prev_balance = self.before_balances[i];
            let transfer = &self.transfers[i];
            self.asset_merkle_proofs[i]
                .verify(&prev_balance, transfer.token_index as u64, asset_tree_root)
                .map_err(|e| {
                    SpendError::InvalidMerkleProof(format!(
                        "Invalid {}th asset merkle proof: {}",
                        i, e
                    ))
                })?;
            if prev_balance < transfer.amount {
                return Err(SpendError::InsufficientBalance(format!(
                    "{}th transfer: balance {}, transfer.amount {}",
                    i, prev_balance, transfer.amount
                )));
            }
            let new_balance = prev_balance - transfer.amount;
            asset_tree_root =
                self.asset_merkle_proofs[i].get_root(&new_balance, transfer.token_index as u64);
        }
        let new_private_state = PrivateState {
            asset_tree_root,
            nullifier_tree_root: self.prev_private_state.nullifier_tree_root,
            prev_private_commitment: self.prev_private_state.commitment(),
            nonce: self.prev_private_state.nonce + 1,
            salt: self.prev_private_state.salt,
        };

        // construct tx
        let transfer_tree_root = get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, &self.transfers)
            .map_err(|e| {
                SpendError::InvalidData(format!("Failed to get transfer tree root: {}", e))
            })?;
        let tx = Tx {
            transfer_tree_root,
            nonce: self.tx_nonce,
        };
        let is_valid = self.tx_nonce == self.prev_private_state.nonce;
        let prev_private_commitment = self.prev_private_state.commitment();
        let new_private_commitment = new_private_state.commitment();

        Ok(SpendPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            tx,
            is_valid,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SpendPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub tx: TxTarget,
    pub is_valid: BoolTarget,
}

impl SpendPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let mut v = vec![];
        v.extend(self.prev_private_commitment.to_vec());
        v.extend(self.new_private_commitment.to_vec());
        v.extend(self.tx.to_vec());
        v.push(self.is_valid.target);
        assert_eq!(v.len(), SPEND_PUBLIC_INPUTS_LEN);
        v
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        assert!(pis.len() >= SPEND_PUBLIC_INPUTS_LEN);
        let mut cursor = 0;
        let prev_private_commitment =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;
        let new_private_commitment =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;
        let tx = TxTarget::from_slice(&pis[cursor..cursor + TX_LEN]);
        cursor += TX_LEN;
        let is_valid = BoolTarget::new_unsafe(pis[cursor]);
        Self {
            prev_private_commitment,
            new_private_commitment,
            tx,
            is_valid,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &SpendPublicInputs,
    ) {
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
        self.tx.set_witness(witness, value.tx);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

#[derive(Clone, Debug)]
pub struct SpendTarget {
    pub tx_nonce: Target,
    pub prev_private_state: PrivateStateTarget,
    pub transfers: Vec<TransferTarget>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub before_balances: Vec<U256Target>, // the length must be equal to MAX_NUM_TRANSFERS_PER_TX
    pub asset_merkle_proofs: Vec<AssetMerkleProofTarget>, /* the length must be equal to
                                         * MAX_NUM_TRANSFERS_PER_TX */
}

impl SpendTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let tx_nonce = builder.add_virtual_target();
        builder.range_check(tx_nonce, 32);

        let prev_private_state = PrivateStateTarget::new(builder);

        let transfers = (0..MAX_NUM_TRANSFERS_PER_TX)
            .map(|_| TransferTarget::new(builder, true))
            .collect();

        let before_balances = (0..MAX_NUM_TRANSFERS_PER_TX)
            .map(|_| U256Target::new(builder, true))
            .collect();

        let asset_merkle_proofs = (0..MAX_NUM_TRANSFERS_PER_TX)
            .map(|_| AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT))
            .collect();

        Self {
            tx_nonce,
            prev_private_state,
            transfers,
            before_balances,
            asset_merkle_proofs,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &SpendWitness) {
        assert_eq!(
            value.transfers.len(),
            MAX_NUM_TRANSFERS_PER_TX,
            "transfers length mismatch"
        );
        assert_eq!(
            value.before_balances.len(),
            MAX_NUM_TRANSFERS_PER_TX,
            "before_balances length mismatch"
        );
        assert_eq!(
            value.asset_merkle_proofs.len(),
            MAX_NUM_TRANSFERS_PER_TX,
            "asset_merkle_proofs length mismatch"
        );

        witness.set_target(self.tx_nonce, F::from_canonical_u32(value.tx_nonce));
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);

        for (target, transfer) in self.transfers.iter().zip(value.transfers.iter()) {
            target.set_witness(witness, transfer);
        }

        for (target, balance) in self
            .before_balances
            .iter()
            .zip(value.before_balances.iter())
        {
            target.set_witness(witness, *balance);
        }

        for (target, proof) in self
            .asset_merkle_proofs
            .iter()
            .zip(value.asset_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }
    }
}

#[derive(Debug)]
pub struct SpendCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SpendTarget,
    pub public_inputs: SpendPublicInputsTarget,
}

impl<F, C, const D: usize> SpendCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let target = SpendTarget::new(&mut builder);

        let mut asset_tree_root = target.prev_private_state.asset_tree_root;
        for i in 0..MAX_NUM_TRANSFERS_PER_TX {
            let transfer = &target.transfers[i];
            let before_balance = &target.before_balances[i];
            let proof = &target.asset_merkle_proofs[i];

            proof.verify::<F, C, D>(
                &mut builder,
                before_balance,
                transfer.token_index,
                asset_tree_root,
            );
            let new_balance = before_balance.sub(&mut builder, &transfer.amount);
            asset_tree_root =
                proof.get_root::<F, C, D>(&mut builder, &new_balance, transfer.token_index);
        }
        let prev_private_commitment = target.prev_private_state.commitment(&mut builder);
        let new_nonce = builder.add_const(target.prev_private_state.nonce, F::ONE);
        let new_private_state = PrivateStateTarget {
            asset_tree_root,
            nullifier_tree_root: target.prev_private_state.nullifier_tree_root,
            prev_private_commitment,
            nonce: new_nonce,
            salt: target.prev_private_state.salt,
        };
        let new_private_commitment = new_private_state.commitment(&mut builder);

        let transfer_tree_root = get_merkle_root_from_leaves_circuit::<F, C, D, TransferTarget>(
            &mut builder,
            TRANSFER_TREE_HEIGHT,
            &target.transfers,
        );
        let tx = TxTarget {
            transfer_tree_root,
            nonce: target.tx_nonce,
        };

        let is_valid = builder.is_equal(target.tx_nonce, target.prev_private_state.nonce);

        let public_inputs = SpendPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            tx,
            is_valid,
        };

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build();

        Self {
            data,
            target,
            public_inputs,
        }
    }

    pub fn prove(&self, w: &SpendWitness) -> Result<ProofWithPublicInputs<F, C, D>, SpendError> {
        let mut pw = PartialWitness::<F>::new();

        let public_inputs = w.to_public_inputs()?;

        self.target.set_witness(&mut pw, w);
        self.public_inputs.set_witness(&mut pw, &public_inputs);

        self.data
            .prove(pw)
            .map_err(|e| SpendError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            private_state::FullPrivateState, salt::Salt, transfer::Transfer,
            trees::asset_tree::AssetTree,
        },
        constants::ASSET_TREE_HEIGHT,
        ethereum_types::{bytes32::Bytes32, u256::U256},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_spend_circuit() {
        let mut rng = rand::thread_rng();
        let mut full_state = FullPrivateState::new(Salt::rand(&mut rng));

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

        let witness = SpendWitness {
            tx_nonce: prev_private_state.nonce,
            prev_private_state,
            transfers,
            before_balances,
            asset_merkle_proofs,
        };

        let circuit = SpendCircuit::<F, C, D>::new();
        let proof = circuit
            .prove(&witness)
            .expect("spend circuit proof should succeed");

        circuit
            .data
            .verify(proof)
            .expect("verification should succeed");
    }
}
