use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    common::block_number::{BlockNumber, BlockNumberTarget},
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        u256::{U256, U256Target},
    },
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

/// A deposit of tokens to the contract
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deposit {
    pub depositor: Address,        // The address of the depositor
    pub recipient: Bytes32,        // The recipient of the deposit,
    pub token_index: u32,          // The index of the token
    pub amount: U256,              // The amount of the token, which is the amount of the deposit
    pub block_number: BlockNumber, // The block number of the deposit
    pub aux_data: Bytes32,         // Auxiliary data for the deposit, e.g. timestamp, mining info
}

#[derive(Debug, Clone)]
pub struct DepositTarget {
    pub depositor: AddressTarget,
    pub recipient: Bytes32Target,
    pub token_index: Target,
    pub amount: U256Target,
    pub block_number: BlockNumberTarget,
    pub aux_data: Bytes32Target,
}

impl Deposit {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.depositor.to_u64_vec(),
            self.recipient.to_u64_vec(),
            vec![self.token_index as u64],
            self.amount.to_u64_vec(),
            vec![self.block_number.0],
            self.aux_data.to_u64_vec(),
        ]
        .concat()
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            depositor: Address::rand(rng),
            recipient: Bytes32::rand(rng),
            token_index: rng.next_u32(),
            amount: U256::rand(rng),
            block_number: BlockNumber::rand(rng),
            aux_data: Bytes32::rand(rng),
        }
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }

    pub fn nullifier(&self) -> Bytes32 {
        self.poseidon_hash().into()
    }

    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Bytes32 {
        let inputs: Vec<u32> = [
            prev_hash.to_u32_vec(),
            self.depositor.to_u32_vec(),
            self.recipient.to_u32_vec(),
            vec![self.token_index],
            self.amount.to_u32_vec(),
            self.aux_data.to_u32_vec(),
        ]
        .concat();
        Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hashing result invalid")
    }
}

impl DepositTarget {
    pub fn to_u64_vec(&self) -> Vec<Target> {
        [
            self.depositor.to_vec(),
            self.recipient.to_vec(),
            vec![self.token_index],
            self.amount.to_vec(),
            vec![self.block_number.value],
            self.aux_data.to_vec(),
        ]
        .concat()
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let depositor = AddressTarget::new(builder, is_checked);
        let recipient = Bytes32Target::new(builder, is_checked);
        let token_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(token_index, 32);
        }
        let amount = U256Target::new(builder, is_checked);
        let block_number = BlockNumberTarget::new(builder, is_checked);
        let aux_data = Bytes32Target::new(builder, is_checked);
        Self {
            depositor,
            recipient,
            token_index,
            amount,
            block_number,
            aux_data,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Deposit,
    ) -> Self {
        let depositor = AddressTarget::constant(builder, value.depositor);
        let recipient = Bytes32Target::constant(builder, value.recipient);
        let token_index = builder.constant(F::from_canonical_u32(value.token_index));
        let amount = U256Target::constant(builder, value.amount);
        let block_number = BlockNumberTarget::constant(builder, value.block_number);
        let aux_data = Bytes32Target::constant(builder, value.aux_data);
        Self {
            depositor,
            recipient,
            token_index,
            amount,
            block_number,
            aux_data,
        }
    }

    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_u64_vec())
    }

    pub fn nullifier<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target {
        let poseidon_hash = self.poseidon_hash(builder);
        Bytes32Target::from_hash_out(builder, poseidon_hash)
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Deposit) {
        self.depositor.set_witness(witness, value.depositor);
        self.recipient.set_witness(witness, value.recipient);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
        self.block_number.set_witness(witness, value.block_number);
        self.aux_data.set_witness(witness, value.aux_data);
    }

    pub fn hash_with_prev_hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_hash: Bytes32Target,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut inputs = prev_hash.to_vec();
        inputs.extend(self.depositor.to_vec());
        inputs.extend(self.recipient.to_vec());
        inputs.push(self.token_index);
        inputs.extend(self.amount.to_vec());
        inputs.extend(self.aux_data.to_vec());
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }
}

impl Leafable for Deposit {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        self.poseidon_hash()
    }
}

impl LeafableTarget for DepositTarget {
    type Leaf = Deposit;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, &Deposit::default())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_u64_vec())
    }
}
