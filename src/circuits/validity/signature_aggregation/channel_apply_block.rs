use plonky2::{
    field::extension::Extendable,
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
    circuits::validity::{
        block_hash_chain::sphincs_sig::{SmallBlockMessageFields, SmallBlockMessageFieldsTarget},
        signature_aggregation::channel_apply_block_pis::{
            ChannelApplyBlockPublicInputs, ChannelApplyBlockPublicInputsError,
            ChannelApplyBlockPublicInputsTarget,
        },
    },
    common::{
        channel_id::{ChannelId, ChannelIdTarget},
        trees::channel_tree::{
            ChannelLeaf, ChannelLeafTarget, ChannelMerkleProof, ChannelMerkleProofTarget, SendLeaf,
            SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
        u63::{BlockNumber, BlockNumberTarget},
    },
    constants::{CHANNEL_TREE_HEIGHT, KEY_ID_BITS, SEND_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        leafable::Leafable as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

/// Maximum number of users processed per flat block proof.
pub const USER_APPLY_BLOCK_SIZE: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum ChannelApplyBlockError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
    #[error("Public inputs error: {0}")]
    PublicInputsError(#[from] ChannelApplyBlockPublicInputsError),
}

/// Per-user witness data for user tree update.
pub struct ChannelApplyUserWitness {
    pub is_active: bool,
    pub user_key_id: u32,
    pub prev_user_leaf: ChannelLeaf,
    pub user_merkle_proof: ChannelMerkleProof,
    pub send_merkle_proof: SendMerkleProof,
}

/// Witness for the entire block.
pub struct ChannelApplyBlockWitness {
    pub initial_account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub channel_id: u32,
    pub tx_tree_root: Bytes32,
    /// Per-block IMSB `SmallBlockRootMessage` preimage fields (detail2 §F-2). The signing
    /// digest is recomputed in-circuit from these with the `channel_id`/`tx_tree_root`
    /// components connected to this circuit's block targets and exposed as the
    /// `signed_digest` PI consumed by the sig-agg pipelines.
    pub msg_fields: SmallBlockMessageFields,
    /// Exactly USER_APPLY_BLOCK_SIZE entries. Inactive entries are padded with dummies.
    pub users: Vec<ChannelApplyUserWitness>,
}

impl ChannelApplyBlockWitness {
    pub fn to_public_inputs(
        &self,
    ) -> Result<ChannelApplyBlockPublicInputs, ChannelApplyBlockError> {
        if self.users.len() != USER_APPLY_BLOCK_SIZE {
            return Err(ChannelApplyBlockError::InvalidInput(format!(
                "Expected {} users, got {}",
                USER_APPLY_BLOCK_SIZE,
                self.users.len()
            )));
        }

        // SECURITY (detail2 §C-2): this block exists only to apply member-signed small-block
        // settlements; tx_tree_root == 0 (H2 = 0) is reserved for in-channel updates and is
        // rejected unconditionally. Mirrors the in-circuit constraint.
        if self.tx_tree_root == Bytes32::default() {
            return Err(ChannelApplyBlockError::InvalidInput(
                "tx_tree_root must be nonzero (H2=0 is reserved for in-channel updates)"
                    .to_string(),
            ));
        }
        // IMSB signing digest (detail2 §F-2), recomputed natively with the SAME limb order as
        // the in-circuit keccak preimage.
        let signed_digest = self
            .msg_fields
            .signing_digest(self.channel_id, self.tx_tree_root);

        let mut current_root = self.initial_account_tree_root;
        let mut current_hash = PoseidonHashOut::default();
        let mut user_count: u32 = 0;
        let mut first_user_id: u64 = 0;
        let mut last_user_id: u64 = 0;

        for user in &self.users {
            if !user.is_active {
                continue;
            }

            // Two-layer identity: the channel-tree index is the channel id alone; the per-user
            // identity inside this block is the member key_id (threaded separately below for the
            // user chain hash / ordering ids).
            let channel_id = ChannelId::new(self.channel_id as u64)
                .map_err(|e| ChannelApplyBlockError::InvalidInput(e.to_string()))?;
            let member_key_id = user.user_key_id as u64;

            // Verify old leaf membership
            let old_root = user
                .user_merkle_proof
                .get_root(&user.prev_user_leaf, channel_id.as_u64());
            if old_root != current_root {
                return Err(ChannelApplyBlockError::InvalidInput(format!(
                    "Account merkle proof mismatch for user {}",
                    channel_id.as_u64()
                )));
            }

            // Verify empty send leaf at index
            let empty_send_root = user
                .send_merkle_proof
                .get_root(&SendLeaf::empty_leaf(), user.prev_user_leaf.index as u64);
            if empty_send_root != user.prev_user_leaf.send_tree_root {
                return Err(ChannelApplyBlockError::InvalidInput(format!(
                    "Send merkle proof mismatch for user {}",
                    channel_id.as_u64()
                )));
            }

            // Create new send leaf
            let new_send_leaf = SendLeaf {
                prev: user.prev_user_leaf.prev,
                cur: self.block_number,
                tx_tree_root: self.tx_tree_root,
            };

            // Compute new send tree root
            let new_send_tree_root = user
                .send_merkle_proof
                .get_root(&new_send_leaf, user.prev_user_leaf.index as u64);

            // Create new account leaf (member_key_ids_root preserved across state transitions)
            let new_user_leaf = ChannelLeaf {
                index: user.prev_user_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
                member_key_ids_root: user.prev_user_leaf.member_key_ids_root,
            };

            // Update current root
            current_root = user
                .user_merkle_proof
                .get_root(&new_user_leaf, channel_id.as_u64());

            // Chain hash: H(prev_hash || member_key_id)
            current_hash = PoseidonHashOut::hash_inputs_u64(
                &[current_hash.to_u64_vec(), vec![member_key_id]].concat(),
            );

            // Track first/last member key_id and count
            user_count += 1;
            if user_count == 1 {
                first_user_id = member_key_id;
            }
            last_user_id = member_key_id;
        }

        Ok(ChannelApplyBlockPublicInputs {
            initial_account_tree_root: self.initial_account_tree_root,
            final_account_tree_root: current_root,
            block_number: self.block_number,
            channel_id: self.channel_id,
            tx_tree_root: self.tx_tree_root,
            signed_digest,
            channels_hash: current_hash,
            user_count,
            first_user_id,
            last_user_id,
        })
    }
}

struct ChannelApplyBlockUserTarget {
    is_active: BoolTarget,
    user_key_id: Target,
    prev_user_leaf: ChannelLeafTarget,
    user_merkle_proof: ChannelMerkleProofTarget,
    send_merkle_proof: SendMerkleProofTarget,
}

pub struct ChannelApplyBlockTarget {
    initial_account_tree_root: PoseidonHashOutTarget,
    block_number: BlockNumberTarget,
    channel_id: Target,
    tx_tree_root: Bytes32Target,
    msg_fields: SmallBlockMessageFieldsTarget,
    users: Vec<ChannelApplyBlockUserTarget>,
    pub new_pis: ChannelApplyBlockPublicInputsTarget,
}

impl ChannelApplyBlockTarget {
    pub fn new<F, C, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let initial_account_tree_root = PoseidonHashOutTarget::new(builder);
        let block_number = BlockNumberTarget::new(builder, true);
        let channel_id = builder.add_virtual_target();
        // The channel id is a u32 limb of the IMSB keccak preimage below; range-check it here
        // (the keccak gadget requires 32-bit-constrained input limbs).
        let channel_id_checked = ChannelIdTarget::from_parts(builder, channel_id, true).value;
        let tx_tree_root = Bytes32Target::new::<F, D>(builder, true);

        // ── IMSB signing digest (detail2 §F-2), recomputed ONCE per block ──
        //
        // SECURITY: the `channel_id` and `tx_tree_root` preimage components are this
        // circuit's own block targets, so the `signed_digest` PI consumed as the SPHINCS+
        // message by the sig-agg pipelines is structurally bound to the tx root this block
        // applies — a prover cannot have signatures verified over a different root.
        let msg_fields = SmallBlockMessageFieldsTarget::new(builder);
        let signed_digest = msg_fields.compute_signing_digest::<F, C, D>(
            builder,
            channel_id_checked,
            &tx_tree_root,
        );

        // SECURITY (detail2 §C-2): tx_tree_root != 0 — H2 = 0 is reserved for in-channel
        // updates and this block exists only to apply member-signed settlements.
        let tx_tree_root_is_zero = tx_tree_root.is_zero::<F, D, Bytes32>(builder);
        let _false = builder._false();
        builder.connect(tx_tree_root_is_zero.target, _false.target);

        let zero = builder.zero();
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());
        let empty_send_leaf = SendLeafTarget::constant(builder, SendLeaf::empty_leaf());

        let mut current_root = initial_account_tree_root.clone();
        let mut current_hash = zero_hash.clone();
        let mut current_count = zero;
        let mut current_first_user_id = zero;
        let mut current_last_user_id = zero;
        let mut users = Vec::new();

        for _ in 0..USER_APPLY_BLOCK_SIZE {
            let is_active = builder.add_virtual_bool_target_safe();
            let user_key_id = builder.add_virtual_target();
            // SECURITY: key_id is used as the per-user identity in the chain hash and the
            // first/last ordering ids; keep it range-checked (the old combined-id constructor
            // used to range-check it).
            builder.range_check(user_key_id, KEY_ID_BITS);
            let prev_user_leaf = ChannelLeafTarget::new::<F, D>(builder, true);
            let user_merkle_proof =
                ChannelMerkleProofTarget::new::<F, D>(builder, CHANNEL_TREE_HEIGHT);
            let send_merkle_proof = SendMerkleProofTarget::new::<F, D>(builder, SEND_TREE_HEIGHT);

            // Compute the channel-tree index (channel id alone; the member key_id is the per-user
            // identity threaded separately below)
            let leaf_index = ChannelIdTarget::from_parts(builder, channel_id, true).value;

            // Verify old leaf membership against current_root
            let old_root =
                user_merkle_proof.get_root::<F, C, D>(builder, &prev_user_leaf, leaf_index);
            current_root.conditional_assert_eq(builder, old_root, is_active);

            // Verify empty send leaf at index in prev send tree
            send_merkle_proof.conditional_verify::<F, C, D>(
                builder,
                is_active,
                &empty_send_leaf,
                prev_user_leaf.index,
                prev_user_leaf.send_tree_root.clone(),
            );

            // Create new send leaf
            let new_send_leaf = SendLeafTarget {
                prev: prev_user_leaf.prev.clone(),
                cur: block_number.clone(),
                tx_tree_root: tx_tree_root.clone(),
            };
            let new_send_root = send_merkle_proof.get_root::<F, C, D>(
                builder,
                &new_send_leaf,
                prev_user_leaf.index,
            );

            // Create new account leaf (member_key_ids_root preserved across state transitions)
            let one = builder.one();
            let next_index = builder.add(prev_user_leaf.index, one);
            let new_user_leaf = ChannelLeafTarget {
                index: next_index,
                prev: block_number.clone(),
                send_tree_root: new_send_root,
                member_key_ids_root: prev_user_leaf.member_key_ids_root.clone(),
            };
            let updated_root =
                user_merkle_proof.get_root::<F, C, D>(builder, &new_user_leaf, leaf_index);

            // Conditionally update root
            current_root =
                PoseidonHashOutTarget::select(builder, is_active, updated_root, current_root);

            // Chain user hash: H(prev_hash || member_key_id)
            let hash_inputs: Vec<_> = current_hash
                .to_vec()
                .into_iter()
                .chain(std::iter::once(user_key_id))
                .collect();
            let new_hash = PoseidonHashOutTarget::hash_inputs(builder, &hash_inputs);
            current_hash =
                PoseidonHashOutTarget::select(builder, is_active, new_hash, current_hash);

            // Update count
            let new_count = builder.add(current_count, one);
            current_count = builder.select(is_active, new_count, current_count);

            // Update first_user_id (only on first active user, when count was still 0)
            let is_first = builder.is_equal(current_first_user_id, zero);
            let is_first_active = builder.and(is_active, is_first);
            current_first_user_id =
                builder.select(is_first_active, user_key_id, current_first_user_id);

            // Update last_user_id (always update on active)
            current_last_user_id = builder.select(is_active, user_key_id, current_last_user_id);

            users.push(ChannelApplyBlockUserTarget {
                is_active,
                user_key_id,
                prev_user_leaf,
                user_merkle_proof,
                send_merkle_proof,
            });
        }

        let new_pis = ChannelApplyBlockPublicInputsTarget {
            initial_account_tree_root: initial_account_tree_root.clone(),
            final_account_tree_root: current_root,
            block_number: block_number.clone(),
            channel_id,
            tx_tree_root: tx_tree_root.clone(),
            signed_digest,
            channels_hash: current_hash,
            user_count: current_count,
            first_user_id: current_first_user_id,
            last_user_id: current_last_user_id,
        };

        Self {
            initial_account_tree_root,
            block_number,
            channel_id,
            tx_tree_root,
            msg_fields,
            users,
            new_pis,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        witness: &ChannelApplyBlockWitness,
        new_pis: &ChannelApplyBlockPublicInputs,
    ) {
        self.initial_account_tree_root
            .set_witness(pw, witness.initial_account_tree_root);
        self.block_number.set_witness(pw, witness.block_number);
        pw.set_target(
            self.channel_id,
            F::from_canonical_u64(witness.channel_id as u64),
        );
        self.tx_tree_root.set_witness(pw, witness.tx_tree_root);
        self.msg_fields.set_witness(pw, &witness.msg_fields);

        for (i, user_target) in self.users.iter().enumerate() {
            let user_witness = &witness.users[i];
            pw.set_bool_target(user_target.is_active, user_witness.is_active);
            pw.set_target(
                user_target.user_key_id,
                F::from_canonical_u64(user_witness.user_key_id as u64),
            );
            user_target
                .prev_user_leaf
                .set_witness(pw, &user_witness.prev_user_leaf);
            user_target
                .user_merkle_proof
                .set_witness(pw, &user_witness.user_merkle_proof);
            user_target
                .send_merkle_proof
                .set_witness(pw, &user_witness.send_merkle_proof);
        }

        self.new_pis.set_witness::<F, D, _>(pw, new_pis);
    }
}

pub struct ChannelApplyBlockCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ChannelApplyBlockTarget,
}

impl<F, C, const D: usize> ChannelApplyBlockCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = ChannelApplyBlockTarget::new::<F, C, D>(&mut builder);
        builder.register_public_inputs(&target.new_pis.to_vec());
        let data = builder.build::<C>();
        Self { data, target }
    }

    pub fn prove(
        &self,
        witness: &ChannelApplyBlockWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelApplyBlockError> {
        let new_pis = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, witness, &new_pis);
        self.data
            .prove(pw)
            .map_err(|e| ChannelApplyBlockError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ChannelApplyBlockError> {
        self.data.verify(proof.clone()).map_err(|e| {
            ChannelApplyBlockError::FailedToProve(format!("Verification failed: {}", e))
        })
    }
}
