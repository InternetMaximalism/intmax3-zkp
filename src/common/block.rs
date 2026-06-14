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
use serde::{Deserialize, Serialize};

use crate::{
    common::{trees::tx_v2_tree::compute_tx_v2_root, tx::TxV2},
    constants::CHANNEL_ID_BITS,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        u64::{U64, U64Target},
    },
};

#[derive(thiserror::Error, Debug, Clone)]
pub enum BlockError {
    #[error("Invalid number of key IDs: {0}")]
    InvalidNumUsers(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Block {
    // the number of users in this block
    pub num_users: u32,

    /// Channel identifier for this fast/small block.
    ///
    /// The serialized field is still named `channel_id` in a few call sites
    /// and contracts during migration, but protocol semantics are channel based:
    /// this is the 5-byte `ChannelId` value constrained to the current u32 ABI.
    pub channel_id: u32,
    pub timestamp: u64,
    /// Active member slots of the channel participating in this block.
    ///
    /// One SPHINCS+ key per member: the field (kept named `key_ids` to minimize churn during the
    /// migration; F7/F8 finalize Block/Solidity) now carries the per-slot ACTIVE-MEMBER index. A
    /// non-zero entry marks an active member slot; zero is padding/dummy. The signing identity of
    /// a slot is the member's SPHINCS+ pubkey hash, proven slot-included under the channel's
    /// `member_pubkeys_root` (see `update_channel_tree`), not a derived `channel_id || key_id`.
    pub key_ids: Vec<u32>,
    pub tx_tree_root: Bytes32,
    pub deposit_hash_chain: Bytes32,
    /// On-chain channel-registration hash chain AFTER this block's registrations.
    ///
    /// SECURITY (G6): this is folded into the block hash exactly like `deposit_hash_chain`, so the
    /// postBlock-built block hash chain (the on-chain authenticity anchor, snapshotted in
    /// `blockHashChainAt`) commits the registration chain. The validity proof must match that
    /// block hash, preventing in-proof fabrication of registrations with no on-chain
    /// `registerChannel` call. For a registration block this is the post-registration chain; for
    /// an ordinary block it is unchanged from the previous block.
    pub channel_reg_hash_chain: Bytes32,
}

#[derive(Debug, Clone)]
pub struct BlockTarget {
    // user length is the constant of the circuit
    pub num_users: u32,

    pub channel_id: Target,
    pub timestamp: U64Target,
    pub key_ids: Vec<Target>,
    pub tx_tree_root: Bytes32Target,
    pub deposit_hash_chain: Bytes32Target,
    pub channel_reg_hash_chain: Bytes32Target,
}

impl Block {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tx_v2s(
        num_users: u32,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        txs: &[TxV2],
        deposit_hash_chain: Bytes32,
        channel_reg_hash_chain: Bytes32,
    ) -> Result<Self, BlockError> {
        Self::new_with_channel(
            num_users,
            channel_id,
            key_ids,
            timestamp,
            compute_tx_v2_root(txs).into(),
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_channel(
        num_users: u32,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        deposit_hash_chain: Bytes32,
        channel_reg_hash_chain: Bytes32,
    ) -> Result<Self, BlockError> {
        Self::new(
            num_users,
            channel_id,
            key_ids,
            timestamp,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_users: u32,
        channel_id: u32,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        deposit_hash_chain: Bytes32,
        channel_reg_hash_chain: Bytes32,
    ) -> Result<Self, BlockError> {
        if key_ids.len() as u32 > num_users {
            return Err(BlockError::InvalidNumUsers(format!(
                "key_ids length is {}, but num_users is {}",
                key_ids.len(),
                num_users
            )));
        }
        // pad user_ids with zeros
        let mut key_ids = key_ids.to_vec();
        key_ids.resize(num_users as usize, 0);

        Ok(Self {
            num_users,
            channel_id,
            timestamp,
            key_ids,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        })
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    pub fn key_ids(&self) -> &[u32] {
        &self.key_ids
    }

    pub fn hash_with_prev_hash(&self, prev_hash: Bytes32) -> Result<Bytes32, BlockError> {
        // key_ids should already be padded with zeros
        if self.key_ids.len() as u32 != self.num_users {
            return Err(BlockError::InvalidNumUsers(format!(
                "key_ids length is {}, but num_users is {}",
                self.key_ids.len(),
                self.num_users
            )));
        }
        let inputs = [
            prev_hash.to_u32_vec(),
            vec![self.channel_id()],
            U64::from(self.timestamp).to_u32_vec(),
            self.key_ids().to_vec(),
            self.tx_tree_root.to_u32_vec(),
            self.deposit_hash_chain.to_u32_vec(),
            self.channel_reg_hash_chain.to_u32_vec(),
        ]
        .concat();
        Ok(Bytes32::from_u32_slice(&solidity_keccak256(&inputs)).expect("hashing result invalid"))
    }
}

impl BlockTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        num_users: u32,
        is_checked: bool,
    ) -> Self {
        let channel_id = builder.add_virtual_target();
        if is_checked {
            builder.range_check(channel_id, CHANNEL_ID_BITS);
        }

        let timestamp = U64Target::new(builder, is_checked);

        let key_ids = (0..num_users)
            .map(|_| {
                let target = builder.add_virtual_target();
                if is_checked {
                    // Active-member slot index (small); the legacy key-id bit-width bound is
                    // retired, CHANNEL_ID_BITS is a safe wider u32 range bound.
                    builder.range_check(target, CHANNEL_ID_BITS);
                }
                target
            })
            .collect();

        let tx_tree_root = Bytes32Target::new(builder, is_checked);
        let deposit_hash_chain = Bytes32Target::new(builder, is_checked);
        let channel_reg_hash_chain = Bytes32Target::new(builder, is_checked);

        Self {
            num_users,
            channel_id,
            timestamp,
            key_ids,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Block,
    ) -> Self {
        if value.key_ids.len() as u32 != value.num_users {
            panic!("user_ids length does not match num_users");
        }
        let channel_id = builder.constant(F::from_canonical_u32(value.channel_id));
        let timestamp = U64Target::constant(builder, U64::from(value.timestamp));
        let key_ids = value
            .key_ids
            .iter()
            .cloned()
            .map(|id| builder.constant(F::from_canonical_u32(id)))
            .collect();
        let tx_tree_root = Bytes32Target::constant(builder, value.tx_tree_root);
        let deposit_hash_chain = Bytes32Target::constant(builder, value.deposit_hash_chain);
        let channel_reg_hash_chain = Bytes32Target::constant(builder, value.channel_reg_hash_chain);
        Self {
            num_users: value.num_users,
            channel_id,
            timestamp,
            key_ids,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        }
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
        inputs.push(self.channel_id);
        inputs.extend(self.timestamp.to_vec());
        inputs.extend(self.key_ids.iter().copied());
        inputs.extend(self.tx_tree_root.to_vec());
        inputs.extend(self.deposit_hash_chain.to_vec());
        inputs.extend(self.channel_reg_hash_chain.to_vec());
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }

    pub fn channel_id(&self) -> Target {
        self.channel_id
    }

    pub fn key_ids(&self) -> &[Target] {
        &self.key_ids
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Block) {
        assert_eq!(self.num_users, value.num_users, "num_users mismatch");
        witness.set_target(self.channel_id, F::from_canonical_u32(value.channel_id));
        self.timestamp
            .set_witness(witness, U64::from(value.timestamp));
        for (target, key_id) in self.key_ids.iter().zip(value.key_ids.iter()) {
            witness.set_target(*target, F::from_canonical_u32(*key_id));
        }
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.deposit_hash_chain
            .set_witness(witness, value.deposit_hash_chain);
        self.channel_reg_hash_chain
            .set_witness(witness, value.channel_reg_hash_chain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait};
    use rand::{SeedableRng, rngs::StdRng};

    /// G6 byte-exact differential vector (Rust side). A single-keyId block with a NONZERO
    /// `channel_reg_hash_chain` proves the reg chain is folded into the block-hash preimage
    /// `prev || channel_id || timestamp || key_ids || tx_tree_root || deposit_hash_chain ||
    /// channel_reg_hash_chain`. The Foundry test `test_blockHashChannelRegDifferential` calls
    /// `_computeBlockHash` over the IDENTICAL fields and MUST produce the SAME constant.
    ///
    /// SECURITY: if this constant changes, the Rust <-> Solidity block-hash encodings have
    /// diverged — DO NOT update blindly; investigate the layout.
    const PINNED_BLOCK_HASH_WITH_REG: &str =
        "0x3099e735b9d4cc17baec8e5797b12e65a09186ee6abd8e0094470d81aa1d2ad7";

    #[test]
    fn test_block_hash_channel_reg_differential() {
        // Fixed, easy-to-mirror values (whole-word u32 limbs).
        let prev_hash = Bytes32::from_u32_slice(&[0x0a0a_0a0a; 8]).unwrap();
        let tx_tree_root = Bytes32::from_u32_slice(&[0x0b0b_0b0b; 8]).unwrap();
        let deposit_hash_chain = Bytes32::from_u32_slice(&[0x0c0c_0c0c; 8]).unwrap();
        let channel_reg_hash_chain = Bytes32::from_u32_slice(&[0x0d0d_0d0d; 8]).unwrap();
        // num_users = 1, channel_id = 7, single key_id = 9, timestamp = 0x1122334455667788.
        let block = Block::new(
            1,
            7,
            &[9],
            0x1122_3344_5566_7788,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
        .unwrap();
        let h = format!("{}", block.hash_with_prev_hash(prev_hash).unwrap());
        println!("BLOCK_HASH_WITH_REG = {h}");
        assert_eq!(
            h, PINNED_BLOCK_HASH_WITH_REG,
            "block-hash preimage (incl. channel_reg_hash_chain) drifted"
        );
    }

    #[test]
    fn test_block_new_and_hash() {
        let mut rng = StdRng::seed_from_u64(42);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);
        let channel_reg_hash_chain = Bytes32::rand(&mut rng);
        let prev_hash = Bytes32::rand(&mut rng);

        let block = Block::new(
            2,
            1,
            &[10, 20],
            1000,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
        .unwrap();

        let h1 = block.hash_with_prev_hash(prev_hash).unwrap();
        let h2 = block.hash_with_prev_hash(prev_hash).unwrap();
        assert_eq!(h1, h2, "block hash should be deterministic");
    }

    #[test]
    fn test_block_hash_is_stable_without_extra_queue_state() {
        let mut rng = StdRng::seed_from_u64(99);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);
        let channel_reg_hash_chain = Bytes32::rand(&mut rng);
        let prev_hash = Bytes32::default();

        let block_a = Block::new(
            1,
            1,
            &[1],
            100,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
        .unwrap();

        let block_b = Block::new(
            1,
            1,
            &[1],
            100,
            tx_tree_root,
            deposit_hash_chain,
            channel_reg_hash_chain,
        )
        .unwrap();

        let h1 = block_a.hash_with_prev_hash(prev_hash).unwrap();
        let h2 = block_b.hash_with_prev_hash(prev_hash).unwrap();
        assert_eq!(h1, h2, "block hash should depend only on the block payload");
    }

    #[test]
    fn test_block_padding() {
        let block = Block::new(
            4,
            1,
            &[10, 20],
            100,
            Bytes32::default(),
            Bytes32::default(),
            Bytes32::default(),
        )
        .unwrap();
        assert_eq!(block.key_ids.len(), 4);
        assert_eq!(block.key_ids[2], 0);
        assert_eq!(block.key_ids[3], 0);
    }

    #[test]
    fn test_block_new_with_tx_v2s_uses_poseidon_root() {
        use crate::common::{
            channel_id::ChannelId,
            trees::tx_v2_tree::{compute_channel_action_root, compute_tx_v2_root},
            tx::{ChannelAction, ChannelActionKind, TxClass, TxV2},
        };

        let tx = TxV2 {
            tx_class: TxClass::ChannelAction,
            transfer_tree_root: Default::default(),
            nonce: 11,
            channel_action_root: compute_channel_action_root(&[ChannelAction {
                kind: ChannelActionKind::InterChannelSend,
                source_channel_id: ChannelId::new(1).unwrap(),
                destination_channel_id: ChannelId::new(2).unwrap(),
                tx_hash: Bytes32::default(),
                seal: Bytes32::default(),
                payload_hash: Default::default(),
            }]),
        };

        let block = Block::new_with_tx_v2s(
            1,
            3,
            &[9],
            100,
            &[tx],
            Bytes32::default(),
            Bytes32::default(),
        )
        .unwrap();

        assert_eq!(block.tx_tree_root, compute_tx_v2_root(&[tx]).into());
    }
}
