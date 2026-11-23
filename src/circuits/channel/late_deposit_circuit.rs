//! Post-close continuation of the ordinary ReceiveDeposit relation.
//!
//! An L1 deposit that was never imported into a signed channel state before the channel closed is
//! stranded in the rollup. The Balance-state holder proves one ReceiveDeposit step over that
//! deposit against the finalized close state; the Materializer then refunds `depositor`. L1
//! serializes the full Balance PI commitment exactly as the late-incoming lane does, so both lanes
//! advance the same `lateBalanceStateCommitment` cursor.
use crate::{
    circuits::{
        balance::{
            balance_pis::{BalanceFullPublicInputs, BalanceFullPublicInputsTarget},
            receive_deposit_circuit::{ReceiveDepositTarget, ReceiveDepositWitness},
        },
        validity::block_hash_chain::ext_public_state::{
            ExtendedPublicState, ExtendedPublicStateTarget,
        },
    },
    ethereum_types::{
        address::Address,
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
        u256::U256,
    },
    utils::conversion::ToU64,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

/// [0] channel_id | [1..9] prev Balance commitment | [9..17] next Balance commitment |
/// [17..25] ExtendedPublicState commitment | [25] anchor block number | [26..34] deposit nullifier |
/// [34..39] depositor (5 u32 limbs) | [39] token_index | [40..48] amount (8 u32 limbs, U256 limb
/// order, limb 0 most significant) | [48] version = 1.
pub const LATE_DEPOSIT_PUBLIC_INPUTS_LEN: usize = 49;
pub const LATE_DEPOSIT_PI_CHANNEL_ID: usize = 0;
pub const LATE_DEPOSIT_PI_PREVIOUS_COMMITMENT: usize = 1;
pub const LATE_DEPOSIT_PI_NEXT_COMMITMENT: usize = 9;
pub const LATE_DEPOSIT_PI_EXTENDED_COMMITMENT: usize = 17;
pub const LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER: usize = 25;
pub const LATE_DEPOSIT_PI_NULLIFIER: usize = 26;
pub const LATE_DEPOSIT_PI_DEPOSITOR: usize = 34;
pub const LATE_DEPOSIT_PI_TOKEN_INDEX: usize = 39;
pub const LATE_DEPOSIT_PI_AMOUNT: usize = 40;
pub const LATE_DEPOSIT_PI_VERSION: usize = 48;
pub const LATE_DEPOSIT_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LateDepositPublicInputs {
    pub channel_id: u32,
    pub previous_balance_commitment: Bytes32,
    pub next_balance_commitment: Bytes32,
    pub finalized_extended_state_commitment: Bytes32,
    pub anchor_block_number: u64,
    pub deposit_nullifier: Bytes32,
    pub depositor: Address,
    pub token_index: u32,
    /// Full 256-bit deposit amount. The circuit does not constrain the upper limbs; the contract
    /// refuses a nonzero limb above the 64-bit payout range.
    pub amount: U256,
}

impl LateDepositPublicInputs {
    pub fn from_u64_slice(v: &[u64]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            v.len() == LATE_DEPOSIT_PUBLIC_INPUTS_LEN,
            "late deposit PI length"
        );
        anyhow::ensure!(
            v[LATE_DEPOSIT_PI_VERSION] == LATE_DEPOSIT_VERSION
                && v[LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER] < (1 << 63),
            "late deposit version/anchor"
        );
        for (i, &x) in v.iter().enumerate() {
            anyhow::ensure!(
                i == LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER || x <= u32::MAX as u64,
                "noncanonical late deposit PI"
            );
        }
        let word = |i| Bytes32::from_u64_slice(&v[i..i + 8]).map_err(|e| anyhow::anyhow!("{e}"));
        Ok(Self {
            channel_id: v[LATE_DEPOSIT_PI_CHANNEL_ID] as u32,
            previous_balance_commitment: word(LATE_DEPOSIT_PI_PREVIOUS_COMMITMENT)?,
            next_balance_commitment: word(LATE_DEPOSIT_PI_NEXT_COMMITMENT)?,
            finalized_extended_state_commitment: word(LATE_DEPOSIT_PI_EXTENDED_COMMITMENT)?,
            anchor_block_number: v[LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER],
            deposit_nullifier: word(LATE_DEPOSIT_PI_NULLIFIER)?,
            depositor: Address::from_u64_slice(
                &v[LATE_DEPOSIT_PI_DEPOSITOR..LATE_DEPOSIT_PI_DEPOSITOR + 5],
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?,
            token_index: v[LATE_DEPOSIT_PI_TOKEN_INDEX] as u32,
            amount: U256::from_u64_slice(&v[LATE_DEPOSIT_PI_AMOUNT..LATE_DEPOSIT_PI_AMOUNT + 8])
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        })
    }
}

pub struct LateDepositCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    receive: ReceiveDepositTarget<D>,
    extended: ExtendedPublicStateTarget,
    balance_vd: VerifierCircuitData<F, C, D>,
}

impl<F, C, const D: usize> LateDepositCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// The Balance verifier key is constructor-pinned: the prev proof's embedded VK must equal it.
    pub fn new(balance_vd: &VerifierCircuitData<F, C, D>) -> Self {
        // A post-close receive is proved at a block after the channel's last send; only the
        // authenticated-tail rule lets that receive skip a send interval that will never exist.
        assert!(
            cfg!(feature = "authenticated-tail-receive"),
            "late deposits require authenticated-tail-receive verifier keys"
        );
        let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let receive = ReceiveDepositTarget::new::<F, C>(&mut b, &balance_vd.common);
        let previous = BalanceFullPublicInputsTarget::from_pis(
            &receive.prev_balance_proof.public_inputs,
            &balance_vd.common.config,
        );
        let pinned = b.constant_verifier_data(&balance_vd.verifier_only);
        b.connect_verifier_data(&previous.vd, &pinned);
        let extended = ExtendedPublicStateTarget::new(&mut b, true);
        receive
            .new_full_pis
            .pis
            .public_state
            .connect(&mut b, &extended.inner);
        let root = extended.commitment(&mut b);
        let prev_hash = previous.commitment(&mut b, &balance_vd.common.config);
        let prev = Bytes32Target::from_hash_out(&mut b, prev_hash);
        let next_hash = receive
            .new_full_pis
            .commitment(&mut b, &balance_vd.common.config);
        let next = Bytes32Target::from_hash_out(&mut b, next_hash);
        let deposit = &receive.deposit_witness.deposit;
        let version = b.one();
        let pi = [
            vec![previous.pis.channel_id.value],
            prev.to_vec(),
            next.to_vec(),
            root.to_vec(),
            vec![extended.inner.block_number.value],
            receive.update_private_state.nullifier.to_vec(),
            deposit.depositor.to_vec(),
            vec![deposit.token_index],
            deposit.amount.to_vec(),
            vec![version],
        ]
        .concat();
        assert_eq!(pi.len(), LATE_DEPOSIT_PUBLIC_INPUTS_LEN);
        b.register_public_inputs(&pi);
        Self {
            data: b.build::<C>(),
            receive,
            extended,
            balance_vd: balance_vd.clone(),
        }
    }

    pub fn prove(
        &self,
        receive: &ReceiveDepositWitness<F, C, D>,
        extended: &ExtendedPublicState,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.balance_vd.verify(receive.prev_balance_proof.clone())?;
        let next = receive.to_public_inputs(&self.balance_vd.common)?;
        anyhow::ensure!(next.vd == self.balance_vd.verifier_only, "wrong Balance VK");
        anyhow::ensure!(
            next.pis.public_state == extended.inner,
            "wrong finalized anchor"
        );
        let mut w = PartialWitness::new();
        self.receive.set_witness(&mut w, receive, &next);
        self.extended.set_witness(&mut w, extended);
        Ok(self.data.prove(w)?)
    }

    /// The caller persists the ordinary Balance proof with this commitment to build the next
    /// late receipt. Identical to the late-incoming cursor computation.
    pub fn balance_commitment(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<Bytes32> {
        self.balance_vd.verify(proof.clone())?;
        let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &proof.public_inputs.to_u64_vec(),
            &self.balance_vd.common.config,
        )?;
        anyhow::ensure!(full.vd == self.balance_vd.verifier_only, "wrong Balance VK");
        Ok(Bytes32::from(
            full.commitment(&self.balance_vd.common.config),
        ))
    }

    pub fn balance_vd(&self) -> &VerifierCircuitData<F, C, D> {
        &self.balance_vd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_deposit_statement_parses_layout_and_rejects_noncanonical_limbs_and_unknown_version() {
        let mut v = vec![0u64; LATE_DEPOSIT_PUBLIC_INPUTS_LEN];
        v[LATE_DEPOSIT_PI_CHANNEL_ID] = 7;
        v[LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER] = (1u64 << 63) - 1;
        for i in 0..5 {
            v[LATE_DEPOSIT_PI_DEPOSITOR + i] = 0x1111_0000 + i as u64;
        }
        v[LATE_DEPOSIT_PI_TOKEN_INDEX] = 55;
        v[LATE_DEPOSIT_PI_AMOUNT + 6] = 1;
        v[LATE_DEPOSIT_PI_AMOUNT + 7] = 9;
        v[LATE_DEPOSIT_PI_VERSION] = 1;
        let parsed = LateDepositPublicInputs::from_u64_slice(&v).unwrap();
        assert_eq!(parsed.channel_id, 7);
        assert_eq!(parsed.anchor_block_number, (1u64 << 63) - 1);
        assert_eq!(parsed.token_index, 55);
        assert_eq!(parsed.amount, U256::from((1u64 << 32) + 9));
        assert_eq!(
            parsed.depositor,
            Address::from_u32_slice(&[0x1111_0000, 0x1111_0001, 0x1111_0002, 0x1111_0003, 0x1111_0004])
                .unwrap()
        );
        // The upper amount limbs are carried verbatim; the contract, not the parser, bounds them.
        let mut wide = v.clone();
        wide[LATE_DEPOSIT_PI_AMOUNT] = u32::MAX as u64;
        assert!(LateDepositPublicInputs::from_u64_slice(&wide).is_ok());
        for index in 0..v.len() {
            let old = v[index];
            v[index] = if index == LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER {
                1u64 << 63
            } else {
                1u64 << 32
            };
            assert!(
                LateDepositPublicInputs::from_u64_slice(&v).is_err(),
                "limb {index} accepted out of range"
            );
            v[index] = old;
        }
        assert!(LateDepositPublicInputs::from_u64_slice(&v[..LATE_DEPOSIT_PUBLIC_INPUTS_LEN - 1]).is_err());
        v[LATE_DEPOSIT_PI_VERSION] = 2;
        assert!(LateDepositPublicInputs::from_u64_slice(&v).is_err());
    }
}

#[cfg(all(test, feature = "authenticated-tail-receive"))]
mod composition_tests {
    use super::*;
    use crate::{
        circuits::balance::{
            balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalancePublicInputs},
            common::{
                account_state::AccountState, deposit_witness::DepositWitness,
                recipient::calculate_recipient_from_user_id,
                update_private_state::UpdatePrivateState, update_public_state::UpdatePublicState,
            },
        },
        common::{
            channel_id::ChannelId,
            deposit::Deposit,
            private_state::FullPrivateState,
            public_state::PublicState,
            salt::Salt,
            trees::{
                asset_tree::AssetTree,
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                deposit_tree::DepositTree,
                nullifier_tree::NullifierTree,
            },
            u63::{BlockNumber, U63},
        },
        constants::{ASSET_TREE_HEIGHT, CHANNEL_TREE_HEIGHT, SEND_TREE_HEIGHT},
        utils::{
            conversion::ToField as _, cyclic::TestCyclicCircuit, poseidon_hash_out::PoseidonHashOut,
        },
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        plonk::config::PoseidonGoldilocksConfig,
    };
    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    /// A deposit received after the channel's last send (the stranded post-close case): the
    /// channel leaf's last send is already covered by the Balance cursor, so no send interval is
    /// needed and the receive anchors at a later block.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn late_deposit_over_real_receive_deposit_witness_round_trips_statement() {
        let receiver_user_id = ChannelId::new(7).unwrap();
        let mut rng = rand::thread_rng();
        let deposit_salt = Salt::rand(&mut rng);
        let prev_block_r = BlockNumber::new(4).unwrap();
        let new_block_r = BlockNumber::new(9).unwrap();
        let deposit_amount = U256::from(((1u64 << 32) + 5) as u64);
        let token_index = 3u32;
        let depositor = Address::from_u32_slice(&[0xdead_beef, 1, 2, 3, 0xcafe_0000]).unwrap();
        let deposit = Deposit {
            deposit_index: U63::new(12).unwrap(),
            block_number: BlockNumber::new(6).unwrap(),
            depositor,
            recipient: calculate_recipient_from_user_id(receiver_user_id, deposit_salt),
            token_index,
            amount: deposit_amount,
            aux_data: Bytes32::default(),
        };
        let mut deposit_tree = DepositTree::init();
        for _ in 0..12 {
            deposit_tree.push(Deposit::default());
        }
        deposit_tree.push(deposit.clone());
        let deposit_merkle_proof = deposit_tree.prove(12);
        let deposit_tree_root = deposit_tree.get_root();
        let deposit_witness = DepositWitness::new(
            receiver_user_id,
            deposit_tree_root,
            deposit_salt,
            deposit.clone(),
            deposit_merkle_proof,
        )
        .unwrap();

        // Last send at block 4 == prev_block_r: authenticated tail, no interval required.
        let mut send_tree = SendTree::new(SEND_TREE_HEIGHT);
        let send_leaf = SendLeaf { cur: prev_block_r, ..SendLeaf::default() };
        send_tree.push(send_leaf.clone());
        let send_merkle_proof = send_tree.prove(0);
        let channel_leaf = ChannelLeaf {
            index: send_tree.len() as u32,
            prev: prev_block_r,
            send_tree_root: send_tree.get_root(),
            member_pubkeys_root: ChannelLeaf::default().member_pubkeys_root,
        };
        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(receiver_user_id.as_u64(), channel_leaf.clone());
        let user_merkle_proof = channel_tree.prove(receiver_user_id.as_u64());
        let account_tree_root = channel_tree.get_root();
        let account_state = AccountState::new(
            receiver_user_id,
            account_tree_root,
            send_leaf,
            0,
            send_merkle_proof,
            channel_leaf,
            user_merkle_proof,
        )
        .unwrap();

        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        asset_tree.update(token_index as u64, U256::from(10u32));
        let asset_merkle_proof = asset_tree.prove(token_index as u64);
        let mut full_private_state = FullPrivateState::new(Salt::rand(&mut rng));
        full_private_state.asset_tree = asset_tree.clone();
        let prev_private_state = full_private_state.to_private_state();
        let mut nullifier_tree = NullifierTree::init();
        let deposit_nullifier = deposit.nullifier();
        let nullifier_proof = nullifier_tree.prove_and_insert(deposit_nullifier).unwrap();
        let update_private_state = UpdatePrivateState::new(
            token_index,
            deposit_amount,
            deposit_nullifier,
            &prev_private_state,
            &nullifier_proof,
            U256::from(10u32),
            &asset_merkle_proof,
        )
        .unwrap();

        let public_state = PublicState {
            block_number: BlockNumber::new(9).unwrap(),
            timestamp: 77,
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root: PoseidonHashOut::default(),
        };
        let update_public_state =
            UpdatePublicState::new(public_state.clone(), public_state.clone(), None).unwrap();
        let prev_balance_pis = BalancePublicInputs {
            channel_id: receiver_user_id,
            public_state: update_public_state.old.clone(),
            block_r: prev_block_r,
            private_commitment: prev_private_state.commitment(),
            settled_tx_chain: Bytes32::from_u32_slice(&[7; 8]).unwrap(),
        };
        let balance_common_data =
            TestCyclicCircuit::<F, C, D>::generate_cd(BALANCE_PUBLIC_INPUTS_LEN);
        let balance_circuit = TestCyclicCircuit::<F, C, D>::new(
            CircuitConfig::standard_recursion_config(),
            BALANCE_PUBLIC_INPUTS_LEN,
            &balance_common_data,
        );
        let balance_vd = balance_circuit.data.verifier_data();
        let prev_full_pis = BalanceFullPublicInputs {
            pis: prev_balance_pis,
            vd: balance_vd.verifier_only.clone(),
        };
        let prev_fields = prev_full_pis
            .to_u64_vec(&balance_vd.common.config)
            .to_field_vec::<F>();
        let prev_balance_proof = balance_circuit.prove(Some(prev_fields.as_slice()), None).unwrap();
        let witness = ReceiveDepositWitness {
            prev_balance_proof,
            update_public_state,
            new_block_r,
            account_state,
            deposit_witness,
            update_private_state,
        };
        let next = witness.to_public_inputs(&balance_vd.common).unwrap();

        let late = LateDepositCircuit::<F, C, D>::new(&balance_vd);
        let ext = ExtendedPublicState { inner: public_state.clone(), ..Default::default() };
        let proof = late.prove(&witness, &ext).unwrap();
        late.data.verify(proof.clone()).unwrap();
        let statement =
            LateDepositPublicInputs::from_u64_slice(&proof.public_inputs.to_u64_vec()).unwrap();
        assert_eq!(statement.channel_id, 7);
        assert_eq!(statement.depositor, depositor);
        assert_eq!(statement.token_index, token_index);
        assert_eq!(statement.amount, deposit_amount);
        assert_eq!(statement.deposit_nullifier, deposit_nullifier);
        assert_eq!(statement.deposit_nullifier, witness.update_private_state.nullifier);
        assert_eq!(statement.anchor_block_number, 9);
        assert_eq!(statement.finalized_extended_state_commitment, ext.commitment());
        assert_eq!(
            statement.previous_balance_commitment,
            late.balance_commitment(&witness.prev_balance_proof).unwrap()
        );
        assert_eq!(
            statement.next_balance_commitment,
            Bytes32::from(next.commitment(&balance_vd.common.config))
        );
        assert_ne!(statement.previous_balance_commitment, statement.next_balance_commitment);
        // Amount limb order: limb 6 is the high u32, limb 7 the low u32 of a u64 amount.
        let raw = proof.public_inputs.to_u64_vec();
        assert!(raw[LATE_DEPOSIT_PI_AMOUNT..LATE_DEPOSIT_PI_AMOUNT + 6].iter().all(|x| *x == 0));
        assert_eq!(raw[LATE_DEPOSIT_PI_AMOUNT + 6], 1);
        assert_eq!(raw[LATE_DEPOSIT_PI_AMOUNT + 7], 5);

        // Every statement field is authenticated by the outer proof.
        for offset in [
            LATE_DEPOSIT_PI_CHANNEL_ID,
            LATE_DEPOSIT_PI_PREVIOUS_COMMITMENT,
            LATE_DEPOSIT_PI_NEXT_COMMITMENT,
            LATE_DEPOSIT_PI_EXTENDED_COMMITMENT,
            LATE_DEPOSIT_PI_ANCHOR_BLOCK_NUMBER,
            LATE_DEPOSIT_PI_NULLIFIER,
            LATE_DEPOSIT_PI_DEPOSITOR,
            LATE_DEPOSIT_PI_TOKEN_INDEX,
            LATE_DEPOSIT_PI_AMOUNT,
            LATE_DEPOSIT_PI_AMOUNT + 7,
            LATE_DEPOSIT_PI_VERSION,
        ] {
            let mut forged = proof.clone();
            forged.public_inputs[offset] += F::ONE;
            assert!(late.data.verify(forged).is_err(), "modified public input {offset}");
        }
        let mut wrong_ext = ext.clone();
        wrong_ext.inner.timestamp += 1;
        assert!(late.prove(&witness, &wrong_ext).is_err());
        let mut invalid_parent = witness.clone();
        invalid_parent.prev_balance_proof.public_inputs[0] += F::ONE;
        assert!(late.prove(&invalid_parent, &ext).is_err());
    }
}
