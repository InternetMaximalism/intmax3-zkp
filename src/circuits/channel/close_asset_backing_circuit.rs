//! Exact base-asset backing proof for a member-signed channel close.
//!
//! `ChannelCloseCircuit` authenticates the channel's N-of-N-signed fund vector. A Balance proof,
//! however, exposes only a hiding commitment to `PrivateState`; it does not reveal that the
//! committed asset tree contains exactly that vector. This circuit closes that boundary without
//! changing Spend or Validity:
//!
//! * recursively verify a Balance proof against constructor-pinned verifier data;
//! * open its `private_commitment` with a witnessed `PrivateState`;
//! * bind the Balance `public_state` to a witnessed `ExtendedPublicState.inner`;
//! * reconstruct the complete asset tree from the canonical empty root and the one signed state's
//!   active token registry/full ten-fund vector; and
//! * expose only the composition points needed by the close/system-exit statement: `(channel_id,
//!   settled_tx_chain, token_funds_digest, finalized_extended_state_commitment,
//!   anchor_block_number)`.

use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use plonky2_keccak::builder::BuilderKeccak256 as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::{
        balance::balance_pis::{
            BALANCE_PUBLIC_INPUTS_LEN, BalanceFullPublicInputs, BalanceFullPublicInputsTarget,
        },
        validity::block_hash_chain::ext_public_state::{
            ExtendedPublicState, ExtendedPublicStateTarget,
        },
    },
    common::{
        channel::{ChannelState, token_funds_digest},
        channel_id::{ChannelId, ChannelIdTarget},
        private_state::{FullPrivateState, PrivateState, PrivateStateTarget},
        trees::asset_tree::{AssetMerkleProof, AssetMerkleProofTarget, AssetTree},
        u63::{BlockNumber, BlockNumberTarget},
    },
    constants::{ASSET_TREE_HEIGHT, MAX_CHANNEL_TOKENS, TOKEN_FUNDS_DIGEST_DOMAIN},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u256::{U256, U256Target},
    },
    utils::{
        conversion::ToU64 as _, cyclic::vd_vec_len, poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::add_proof_target_and_verify_cyclic,
    },
};

/// `channel_id(1) | settled_tx_chain(8) | token_funds_digest(8) |
/// finalized_extended_state_commitment(8) | anchor_block_number(1)`.
pub const CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN: usize = 2 + 3 * BYTES32_LEN;

#[derive(Debug, Error)]
pub enum CloseAssetBackingCircuitError {
    #[error("invalid channel asset vector: {0}")]
    InvalidAssetVector(String),
    #[error("private asset-tree root does not equal the channel's exact fund vector")]
    AssetTreeRootMismatch,
    #[error("balance proof verification failed: {0}")]
    BalanceProofVerification(String),
    #[error("balance proof private commitment does not open to the witnessed PrivateState")]
    BalancePrivateCommitmentMismatch,
    #[error("balance proof public state does not equal ExtendedPublicState.inner")]
    BalancePublicStateMismatch,
    #[error("balance proof channel id does not equal the signed ChannelState channel id")]
    BalanceChannelMismatch,
    #[error("balance proof settled chain does not equal the signed ChannelState settled chain")]
    BalanceSettledChainMismatch,
    #[error("invalid public inputs: {0}")]
    InvalidPublicInputs(String),
    #[error("failed to prove close asset backing: {0}")]
    FailedToProve(String),
}

/// Public composition boundary for the close/system-exit circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseAssetBackingPublicInputs {
    pub channel_id: ChannelId,
    pub settled_tx_chain: Bytes32,
    /// Byte-for-byte compatible with [`crate::common::channel::token_funds_digest`].
    pub token_funds_digest: Bytes32,
    pub finalized_extended_state_commitment: Bytes32,
    /// Same wire as `ExtendedPublicState.inner.block_number`; the L1 materializer uses this
    /// channel anchor to reject a close artifact older than the last channel-affecting post.
    pub anchor_block_number: BlockNumber,
}

impl CloseAssetBackingPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.channel_id.to_u64_vec(),
            self.settled_tx_chain.to_u64_vec(),
            self.token_funds_digest.to_u64_vec(),
            self.finalized_extended_state_commitment.to_u64_vec(),
            self.anchor_block_number.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, CloseAssetBackingCircuitError> {
        if values.len() != CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN {
            return Err(CloseAssetBackingCircuitError::InvalidPublicInputs(format!(
                "expected {CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN} limbs, got {}",
                values.len()
            )));
        }
        let channel_id = ChannelId::from_u64_slice(&values[..1])
            .map_err(|err| CloseAssetBackingCircuitError::InvalidPublicInputs(err.to_string()))?;

        let parse_bytes32 = |start: usize| {
            Bytes32::from_u64_slice(&values[start..start + BYTES32_LEN])
                .map_err(|err| CloseAssetBackingCircuitError::InvalidPublicInputs(err.to_string()))
        };
        let anchor_block_number = BlockNumber::new(values[1 + 3 * BYTES32_LEN])
            .map_err(|err| CloseAssetBackingCircuitError::InvalidPublicInputs(err.to_string()))?;
        Ok(Self {
            channel_id,
            settled_tx_chain: parse_bytes32(1)?,
            token_funds_digest: parse_bytes32(1 + BYTES32_LEN)?,
            finalized_extended_state_commitment: parse_bytes32(1 + 2 * BYTES32_LEN)?,
            anchor_block_number,
        })
    }

    pub fn from_pis<F: PrimeField64>(values: &[F]) -> Result<Self, CloseAssetBackingCircuitError> {
        Self::from_u64_slice(
            &values
                .iter()
                .map(PrimeField64::to_canonical_u64)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct CloseAssetBackingPublicInputsTarget {
    pub channel_id: ChannelIdTarget,
    pub settled_tx_chain: Bytes32Target,
    pub token_funds_digest: Bytes32Target,
    pub finalized_extended_state_commitment: Bytes32Target,
    pub anchor_block_number: BlockNumberTarget,
}

impl CloseAssetBackingPublicInputsTarget {
    /// Parse the fixed public-input layout for recursive composition by the close/system-exit
    /// circuit. Exact length is deliberate: appended, silently-unbound fields are rejected.
    pub fn from_pis(values: &[Target]) -> Self {
        assert_eq!(values.len(), CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN);
        Self {
            channel_id: ChannelIdTarget { value: values[0] },
            settled_tx_chain: Bytes32Target::from_slice(&values[1..1 + BYTES32_LEN]),
            token_funds_digest: Bytes32Target::from_slice(
                &values[1 + BYTES32_LEN..1 + 2 * BYTES32_LEN],
            ),
            finalized_extended_state_commitment: Bytes32Target::from_slice(
                &values[1 + 2 * BYTES32_LEN..1 + 3 * BYTES32_LEN],
            ),
            anchor_block_number: BlockNumberTarget {
                value: values[1 + 3 * BYTES32_LEN],
            },
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.channel_id.to_vec(),
            self.settled_tx_chain.to_vec(),
            self.token_funds_digest.to_vec(),
            self.finalized_extended_state_commitment.to_vec(),
            vec![self.anchor_block_number.value],
        ]
        .concat()
    }
}

/// Private witness retained only while constructing the signer-independent exit artifact.
#[derive(Clone, Debug)]
pub struct CloseAssetBackingWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    pub final_balance_proof: ProofWithPublicInputs<F, C, D>,
    pub extended_public_state: ExtendedPublicState,
    pub private_state: PrivateState,
    pub token_count: u8,
    pub token_registry: [u32; MAX_CHANNEL_TOKENS],
    pub fund_amounts: [U256; MAX_CHANNEL_TOKENS],
    pub asset_construction_proofs: [AssetMerkleProof; MAX_CHANNEL_TOKENS],
}

impl<F, C, const D: usize> CloseAssetBackingWitness<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Production constructor. It verifies the exact cyclic Balance proof/VK and every native
    /// mirror before the backing artifact crosses a trust boundary.
    pub fn from_full_private_state_and_channel_state(
        full_private_state: &FullPrivateState,
        channel_state: &ChannelState,
        final_balance_proof: ProofWithPublicInputs<F, C, D>,
        extended_public_state: ExtendedPublicState,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<Self, CloseAssetBackingCircuitError> {
        Self::from_private_state_and_channel_state(
            full_private_state.to_private_state(),
            channel_state,
            final_balance_proof,
            extended_public_state,
            balance_vd,
        )
    }

    /// Shared constructor seam. The public production entry above supplies a `FullPrivateState`;
    /// this narrower form also keeps unit tests independent of unrelated private tree machinery.
    fn from_private_state_and_channel_state(
        private_state: PrivateState,
        channel_state: &ChannelState,
        final_balance_proof: ProofWithPublicInputs<F, C, D>,
        extended_public_state: ExtendedPublicState,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<Self, CloseAssetBackingCircuitError> {
        check_cyclic_proof_verifier_data(
            &final_balance_proof,
            &balance_vd.verifier_only,
            &balance_vd.common,
        )
        .map_err(|err| {
            CloseAssetBackingCircuitError::BalanceProofVerification(format!(
                "cyclic verifier-data mismatch: {err:?}"
            ))
        })?;

        balance_vd
            .verify(final_balance_proof.clone())
            .map_err(|err| {
                CloseAssetBackingCircuitError::BalanceProofVerification(format!(
                    "proof verification failed: {err:?}"
                ))
            })?;
        let balance_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &final_balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )
        .map_err(|err| {
            CloseAssetBackingCircuitError::BalanceProofVerification(format!(
                "public-input decode failed: {err}"
            ))
        })?;
        let balance_pis = balance_full_pis.pis;

        if balance_pis.private_commitment != private_state.commitment() {
            return Err(CloseAssetBackingCircuitError::BalancePrivateCommitmentMismatch);
        }
        if balance_pis.public_state != extended_public_state.inner {
            return Err(CloseAssetBackingCircuitError::BalancePublicStateMismatch);
        }
        if channel_state.channel_id != channel_state.balance_state.channel_id
            || channel_state.channel_id != channel_state.channel_fund.channel_id
        {
            return Err(CloseAssetBackingCircuitError::InvalidAssetVector(
                "channel_id differs between ChannelState, BalanceState and ChannelFund".to_string(),
            ));
        }
        if balance_pis.channel_id != channel_state.channel_id {
            return Err(CloseAssetBackingCircuitError::BalanceChannelMismatch);
        }
        if balance_pis.settled_tx_chain != channel_state.balance_state.settled_tx_chain {
            return Err(CloseAssetBackingCircuitError::BalanceSettledChainMismatch);
        }

        let token_count = usize::from(channel_state.balance_state.token_count);
        if !(1..=MAX_CHANNEL_TOKENS).contains(&token_count) {
            return Err(CloseAssetBackingCircuitError::InvalidAssetVector(format!(
                "token_count {token_count} is outside 1..={MAX_CHANNEL_TOKENS}"
            )));
        }
        let token_registry = channel_state.balance_state.token_registry;
        let fund_amounts = channel_state.channel_fund.amounts;
        for i in 0..token_count {
            for j in (i + 1)..token_count {
                if token_registry[i] == token_registry[j] {
                    return Err(CloseAssetBackingCircuitError::InvalidAssetVector(format!(
                        "active token_registry positions {i} and {j} both contain {}",
                        token_registry[i]
                    )));
                }
            }
        }
        for t in token_count..MAX_CHANNEL_TOKENS {
            if token_registry[t] != 0 || fund_amounts[t] != U256::default() {
                return Err(CloseAssetBackingCircuitError::InvalidAssetVector(format!(
                    "inactive token position {t} is not canonical zero"
                )));
            }
        }

        let mut canonical_tree = AssetTree::init();
        let mut proofs = Vec::with_capacity(MAX_CHANNEL_TOKENS);
        for t in 0..MAX_CHANNEL_TOKENS {
            let active = t < token_count;
            let token_index = if active {
                u64::from(token_registry[t])
            } else {
                0
            };
            proofs.push(canonical_tree.prove(token_index));
            if active {
                debug_assert_eq!(canonical_tree.get_leaf(token_index), U256::default());
                canonical_tree.update(token_index, fund_amounts[t]);
            }
        }
        if canonical_tree.get_root() != private_state.asset_tree_root {
            return Err(CloseAssetBackingCircuitError::AssetTreeRootMismatch);
        }

        Ok(Self {
            final_balance_proof,
            extended_public_state,
            private_state,
            token_count: channel_state.balance_state.token_count,
            token_registry,
            fund_amounts,
            asset_construction_proofs: proofs.try_into().expect("fixed token width"),
        })
    }

    pub fn public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<CloseAssetBackingPublicInputs, CloseAssetBackingCircuitError> {
        let balance_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.final_balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )
        .map_err(|err| {
            CloseAssetBackingCircuitError::BalanceProofVerification(format!(
                "public-input decode failed: {err}"
            ))
        })?;
        Ok(CloseAssetBackingPublicInputs {
            channel_id: balance_full_pis.pis.channel_id,
            settled_tx_chain: balance_full_pis.pis.settled_tx_chain,
            token_funds_digest: token_funds_digest(
                &self.token_registry,
                self.token_count,
                &self.fund_amounts,
            ),
            finalized_extended_state_commitment: self.extended_public_state.commitment(),
            anchor_block_number: self.extended_public_state.inner.block_number,
        })
    }
}

#[derive(Debug)]
pub struct CloseAssetBackingCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub public_inputs: CloseAssetBackingPublicInputsTarget,
    final_balance_proof: ProofWithPublicInputsTarget<D>,
    extended_public_state: ExtendedPublicStateTarget,
    private_state: PrivateStateTarget,
    token_count: Target,
    token_registry: [Target; MAX_CHANNEL_TOKENS],
    fund_amounts: [U256Target; MAX_CHANNEL_TOKENS],
    token_active_bits: [BoolTarget; MAX_CHANNEL_TOKENS],
    asset_construction_proofs: [AssetMerkleProofTarget; MAX_CHANNEL_TOKENS],
    /// TEST-ONLY handles on the constructor's internal wires; see
    /// [`CloseAssetBackingFaithfulnessProbe`].
    #[cfg(test)]
    pub(crate) probe: CloseAssetBackingFaithfulnessProbe,
}

/// TEST-ONLY: the internal wires of [`CloseAssetBackingCircuit::new`] that
/// `doc/audit/zkp/Zkp/Implementation/CloseAssetBacking.lean` names in its `constructorProgram`
/// but that the struct does not otherwise keep. Compiled out of every non-test build.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct CloseAssetBackingFaithfulnessProbe {
    /// `private_state.commitment(builder)`, :417 (`computePrivatePoseidon`).
    pub opened_private_commitment: PoseidonHashOutTarget,
    /// `builder.zero()` / `builder.one()`, :435-436 (`constantZero` / `constantOne`).
    pub zero: Target,
    pub one: Target,
    /// the activity `add` chain, :443-446 (`addActivityToSum`).
    pub active_sum: Target,
    /// the accumulator BEFORE the first `add`, i.e. the `activitySumWire 0` of the Lean
    /// `constantZero` case (`a.activitySumWire 0 = a.zeroWire`).
    pub active_sum_seed: Target,
    /// the nine `mul(active[t+1], one - active[t])` wires the no-rise loop connects to
    /// zero (`connectNoRiseZero`).
    pub rise_products: Vec<Target>,
    /// the ten `mul(not active[t], registry[t])` wires (`connectInactiveRegistryZero`).
    pub dirty_registry: Vec<Target>,
    /// the eighty `mul(not active[t], amount[t][limb])` wires, row-major
    /// (`connectInactiveAmountZero`).
    pub dirty_amounts: Vec<Target>,
    /// the forty-five `and(is_equal(reg[i], reg[j]), active[j])` wires, in the ordered-pair
    /// order of the Lean program (`connectDuplicateZero`).
    pub duplicate_active: Vec<Target>,
    /// `U256Target::constant(builder, U256::default())`, :471 (`constantZeroLeaf`).
    pub empty_leaf: U256Target,
    /// the canonical empty asset-tree root constant, :472-473 (`constantEmptyRoot`).
    pub empty_asset_root: PoseidonHashOutTarget,
    /// the final `select`ed root fed to the `connect`, :488 (`connectFinalAssetRoot`).
    pub reconstructed_root: PoseidonHashOutTarget,
    /// the `keccak256` preimage of the token-funds digest, :492-501.
    pub digest_preimage: Vec<Target>,
}

impl<F, C, const D: usize> CloseAssetBackingCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// `balance_vd` is embedded as constants, including the cyclic proof's self-VD binding.
    pub fn new(balance_vd: &VerifierCircuitData<F, C, D>) -> Self {
        assert_eq!(
            balance_vd.common.num_public_inputs,
            BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&balance_vd.common.config),
            "balance verifier public-input shape is not the canonical cyclic Balance shape"
        );
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

        let final_balance_proof = add_proof_target_and_verify_cyclic(balance_vd, &mut builder);
        let balance_full_pis = BalanceFullPublicInputsTarget::from_pis(
            &final_balance_proof.public_inputs,
            &balance_vd.common.config,
        );
        let balance_pis = balance_full_pis.pis;

        let private_state = PrivateStateTarget::new(&mut builder);
        let opened_private_commitment = private_state.commitment(&mut builder);
        #[cfg(test)]
        let opened_private_commitment_probe = opened_private_commitment;
        opened_private_commitment.connect(&mut builder, balance_pis.private_commitment);

        let extended_public_state = ExtendedPublicStateTarget::new(&mut builder, true);
        balance_pis
            .public_state
            .connect(&mut builder, &extended_public_state.inner);

        let token_count = builder.add_virtual_target();
        builder.range_check(token_count, 32);
        let token_registry = std::array::from_fn(|_| {
            let target = builder.add_virtual_target();
            builder.range_check(target, 32);
            target
        });
        let fund_amounts = std::array::from_fn(|_| U256Target::new(&mut builder, true));
        let token_active_bits = std::array::from_fn(|_| builder.add_virtual_bool_target_safe());
        let asset_construction_proofs =
            std::array::from_fn(|_| AssetMerkleProofTarget::new(&mut builder, ASSET_TREE_HEIGHT));

        let zero = builder.zero();
        let one = builder.one();
        #[cfg(test)]
        let mut rise_products: Vec<Target> = Vec::new();
        for t in 0..MAX_CHANNEL_TOKENS - 1 {
            let one_minus_prev = builder.sub(one, token_active_bits[t].target);
            let active_after_padding = builder.mul(token_active_bits[t + 1].target, one_minus_prev);
            #[cfg(test)]
            rise_products.push(active_after_padding);
            builder.connect(active_after_padding, zero);
        }
        let mut active_sum = zero;
        #[cfg(test)]
        let active_sum_seed = active_sum;
        for active in &token_active_bits {
            active_sum = builder.add(active_sum, active.target);
        }
        builder.connect(active_sum, token_count);
        builder.assert_one(token_active_bits[0].target);

        #[cfg(test)]
        let mut dirty_registry_probe: Vec<Target> = Vec::new();
        #[cfg(test)]
        let mut dirty_amounts_probe: Vec<Target> = Vec::new();
        for t in 0..MAX_CHANNEL_TOKENS {
            let inactive = builder.not(token_active_bits[t]);
            let dirty_registry = builder.mul(inactive.target, token_registry[t]);
            #[cfg(test)]
            dirty_registry_probe.push(dirty_registry);
            builder.connect(dirty_registry, zero);
            for limb in fund_amounts[t].to_vec() {
                let dirty_amount = builder.mul(inactive.target, limb);
                #[cfg(test)]
                dirty_amounts_probe.push(dirty_amount);
                builder.connect(dirty_amount, zero);
            }
        }
        #[cfg(test)]
        let mut duplicate_active_probe: Vec<Target> = Vec::new();
        for i in 0..MAX_CHANNEL_TOKENS {
            for j in (i + 1)..MAX_CHANNEL_TOKENS {
                let equal = builder.is_equal(token_registry[i], token_registry[j]);
                let duplicate_active = builder.and(equal, token_active_bits[j]);
                #[cfg(test)]
                duplicate_active_probe.push(duplicate_active.target);
                builder.connect(duplicate_active.target, zero);
            }
        }

        // Every active path opens a zero leaf in the accumulated root, then inserts the exact
        // fund. Starting at the canonical empty root and forbidding duplicate active indices also
        // proves there is no unlisted asset leaf.
        let empty_leaf = U256Target::constant(&mut builder, U256::default());
        let mut reconstructed_root =
            PoseidonHashOutTarget::constant(&mut builder, AssetTree::init().get_root());
        #[cfg(test)]
        let empty_asset_root = reconstructed_root;
        for t in 0..MAX_CHANNEL_TOKENS {
            asset_construction_proofs[t].conditional_verify::<F, C, D>(
                &mut builder,
                token_active_bits[t],
                &empty_leaf,
                token_registry[t],
                reconstructed_root,
            );
            let inserted_root = asset_construction_proofs[t].get_root::<F, C, D>(
                &mut builder,
                &fund_amounts[t],
                token_registry[t],
            );
            reconstructed_root = PoseidonHashOutTarget::select(
                &mut builder,
                token_active_bits[t],
                inserted_root,
                reconstructed_root,
            );
        }
        reconstructed_root.connect(&mut builder, private_state.asset_tree_root);

        let token_funds_domain = builder.constant(F::from_canonical_u32(TOKEN_FUNDS_DIGEST_DOMAIN));
        let fund_amount_limbs = fund_amounts
            .iter()
            .flat_map(U256Target::to_vec)
            .collect::<Vec<_>>();
        let digest_preimage = [
            vec![token_funds_domain],
            token_registry.to_vec(),
            vec![token_count],
            fund_amount_limbs,
        ]
        .concat();
        let token_funds_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&digest_preimage));
        let finalized_extended_state_commitment = extended_public_state.commitment(&mut builder);
        let public_inputs = CloseAssetBackingPublicInputsTarget {
            channel_id: balance_pis.channel_id,
            settled_tx_chain: balance_pis.settled_tx_chain,
            token_funds_digest,
            finalized_extended_state_commitment,
            anchor_block_number: extended_public_state.inner.block_number.clone(),
        };
        #[cfg(test)]
        let probe = CloseAssetBackingFaithfulnessProbe {
            opened_private_commitment: opened_private_commitment_probe,
            zero,
            one,
            active_sum,
            active_sum_seed,
            rise_products,
            dirty_registry: dirty_registry_probe,
            dirty_amounts: dirty_amounts_probe,
            duplicate_active: duplicate_active_probe,
            empty_leaf,
            empty_asset_root,
            reconstructed_root,
            digest_preimage: digest_preimage.clone(),
        };

        builder.register_public_inputs(&public_inputs.to_vec());

        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            final_balance_proof,
            extended_public_state,
            private_state,
            token_count,
            token_registry,
            fund_amounts,
            token_active_bits,
            asset_construction_proofs,
            #[cfg(test)]
            probe,
        }
    }

    fn fill_witness(&self, value: &CloseAssetBackingWitness<F, C, D>) -> PartialWitness<F> {
        let mut witness = PartialWitness::new();
        witness
            .set_proof_with_pis_target(&self.final_balance_proof, &value.final_balance_proof)
            .unwrap();
        self.extended_public_state
            .set_witness(&mut witness, &value.extended_public_state);
        self.private_state
            .set_witness(&mut witness, &value.private_state);
        witness
            .set_target(self.token_count, F::from_canonical_u8(value.token_count))
            .unwrap();
        for t in 0..MAX_CHANNEL_TOKENS {
            witness
                .set_target(
                    self.token_registry[t],
                    F::from_canonical_u32(value.token_registry[t]),
                )
                .unwrap();
            self.fund_amounts[t].set_witness(&mut witness, value.fund_amounts[t]);
            witness
                .set_bool_target(
                    self.token_active_bits[t],
                    t < usize::from(value.token_count),
                )
                .unwrap();
            self.asset_construction_proofs[t]
                .set_witness(&mut witness, &value.asset_construction_proofs[t]);
        }
        witness
    }

    pub fn prove(
        &self,
        witness: &CloseAssetBackingWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, CloseAssetBackingCircuitError> {
        self.data
            .prove(self.fill_witness(witness))
            .map_err(|err| CloseAssetBackingCircuitError::FailedToProve(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    use super::*;
    use crate::{
        circuits::balance::balance_pis::{BalanceFullPublicInputs, BalancePublicInputs},
        common::{
            balance_state::BalanceState,
            channel::{ChannelFund, ChannelId},
            public_state::PublicState,
            salt::Salt,
            u63::BlockNumber,
        },
        ethereum_types::{address::Address, bytes32::Bytes32},
        utils::{conversion::ToField as _, cyclic::TestCyclicCircuit},
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    struct Fixture {
        balance_vd: VerifierCircuitData<F, C, D>,
        backing_circuit: CloseAssetBackingCircuit<F, C, D>,
        witness: CloseAssetBackingWitness<F, C, D>,
        private_state: PrivateState,
        state: ChannelState,
    }

    fn fixture() -> Fixture {
        let id = ChannelId::new(91).unwrap();
        let mut registry = [0u32; MAX_CHANNEL_TOKENS];
        registry[0] = 0;
        registry[1] = 17;
        registry[2] = u32::MAX;
        let mut amounts = [U256::default(); MAX_CHANNEL_TOKENS];
        amounts[0] = U256::from(11u32);
        amounts[1] = U256::from(22u32);
        amounts[2] = U256::from(33u32);

        let mut asset_tree = AssetTree::init();
        for t in 0..3 {
            asset_tree.update(u64::from(registry[t]), amounts[t]);
        }
        let private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: Default::default(),
            sent_tx_tree_root: Default::default(),
            prev_private_commitment: Default::default(),
            nonce: 7,
            salt: Salt::default(),
        };
        let public_state = PublicState {
            block_number: BlockNumber::new(12).unwrap(),
            timestamp: 34,
            account_tree_root: Default::default(),
            deposit_tree_root: Default::default(),
            prev_public_state_root: Default::default(),
        };
        let extended_public_state = ExtendedPublicState::new(
            public_state.clone(),
            Bytes32::default(),
            Bytes32::default(),
            Default::default(),
            Bytes32::default(),
            Bytes32::default(),
        );
        let settled_tx_chain = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let balance_pis = BalancePublicInputs {
            channel_id: id,
            public_state,
            block_r: BlockNumber::new(12).unwrap(),
            private_commitment: private_state.commitment(),
            settled_tx_chain,
        };
        let balance_common_data =
            TestCyclicCircuit::<F, C, D>::generate_cd(BALANCE_PUBLIC_INPUTS_LEN);
        let balance_circuit = TestCyclicCircuit::<F, C, D>::new(
            CircuitConfig::standard_recursion_config(),
            BALANCE_PUBLIC_INPUTS_LEN,
            &balance_common_data,
        );
        let balance_vd = balance_circuit.data.verifier_data();
        let balance_full_pis = BalanceFullPublicInputs {
            pis: balance_pis,
            vd: balance_vd.verifier_only.clone(),
        };
        let balance_fields = balance_full_pis
            .to_u64_vec(&balance_vd.common.config)
            .to_field_vec::<F>();
        let final_balance_proof = balance_circuit
            .prove(Some(&balance_fields), None)
            .expect("mock canonical balance proof");

        // Only identity/registry/settled-chain/fund fields are consumed by this narrowly scoped
        // constructor. Avoid allocating the unrelated 1024x10 encrypted member matrix here.
        let balance_state = BalanceState {
            channel_id: id,
            member_count: 2,
            delegate_count: 0,
            enc_balances: Vec::new(),
            regev_pk_digests: [Bytes32::default(); crate::constants::MAX_CHANNEL_MEMBERS],
            recipients: [Address::default(); crate::constants::MAX_CHANNEL_MEMBERS],
            settled_tx_chain,
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 1,
            pending_adds: Vec::new(),
            token_registry: registry,
            token_count: 3,
        };
        let state = ChannelState {
            channel_id: id,
            epoch: 0,
            small_block_number: 0,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: id,
                amounts,
                intmax_state_root: Bytes32::default(),
            },
            balance_state,
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::default(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: Vec::new(),
        };
        let witness = CloseAssetBackingWitness::from_private_state_and_channel_state(
            private_state.clone(),
            &state,
            final_balance_proof,
            extended_public_state,
            &balance_vd,
        )
        .unwrap();
        let backing_circuit = CloseAssetBackingCircuit::new(&balance_vd);
        Fixture {
            balance_vd,
            backing_circuit,
            witness,
            private_state,
            state,
        }
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn recursive_balance_exact_asset_backing_proves_and_exposes_composition_pis() {
        let build_started = Instant::now();
        let fixture = fixture();
        let build = build_started.elapsed();
        let expected = fixture.witness.public_inputs(&fixture.balance_vd).unwrap();
        assert_eq!(expected.channel_id, fixture.state.channel_id);
        assert_eq!(
            expected.settled_tx_chain,
            fixture.state.balance_state.settled_tx_chain
        );
        assert_eq!(
            expected.token_funds_digest,
            token_funds_digest(
                &fixture.state.balance_state.token_registry,
                fixture.state.balance_state.token_count,
                &fixture.state.channel_fund.amounts,
            )
        );
        assert_eq!(
            expected.finalized_extended_state_commitment,
            fixture.witness.extended_public_state.commitment()
        );
        assert_eq!(
            expected.anchor_block_number,
            fixture.witness.extended_public_state.inner.block_number
        );

        let prove_started = Instant::now();
        let proof = fixture.backing_circuit.prove(&fixture.witness).unwrap();
        let prove = prove_started.elapsed();
        let proof_bytes = proof.to_bytes().len();
        assert_eq!(
            CloseAssetBackingPublicInputs::from_pis(&proof.public_inputs).unwrap(),
            expected
        );
        let verify_started = Instant::now();
        fixture.backing_circuit.data.verify(proof).unwrap();
        let verify = verify_started.elapsed();
        println!(
            "close-asset-backing: degree=2^{} pis={} build={build:?} prove={prove:?} \
             verify={verify:?} proof={proof_bytes} B",
            fixture.backing_circuit.data.common.degree_bits(),
            fixture.backing_circuit.data.common.num_public_inputs,
        );
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn native_constructor_rejects_unbacked_vector_and_balance_anchor_mismatch() {
        let fixture = fixture();
        let mut wrong_state = fixture.state.clone();
        wrong_state.channel_fund.amounts[1] = U256::from(23u32);
        assert!(matches!(
            CloseAssetBackingWitness::from_private_state_and_channel_state(
                fixture.private_state.clone(),
                &wrong_state,
                fixture.witness.final_balance_proof.clone(),
                fixture.witness.extended_public_state.clone(),
                &fixture.balance_vd,
            ),
            Err(CloseAssetBackingCircuitError::AssetTreeRootMismatch)
        ));

        let mut duplicate_registry = fixture.state.clone();
        duplicate_registry.balance_state.token_registry[2] =
            duplicate_registry.balance_state.token_registry[1];
        assert!(matches!(
            CloseAssetBackingWitness::from_private_state_and_channel_state(
                fixture.private_state.clone(),
                &duplicate_registry,
                fixture.witness.final_balance_proof.clone(),
                fixture.witness.extended_public_state.clone(),
                &fixture.balance_vd,
            ),
            Err(CloseAssetBackingCircuitError::InvalidAssetVector(_))
        ));

        let mut dirty_inactive_registry = fixture.state.clone();
        dirty_inactive_registry.balance_state.token_registry[8] = 9;
        assert!(matches!(
            CloseAssetBackingWitness::from_private_state_and_channel_state(
                fixture.private_state.clone(),
                &dirty_inactive_registry,
                fixture.witness.final_balance_proof.clone(),
                fixture.witness.extended_public_state.clone(),
                &fixture.balance_vd,
            ),
            Err(CloseAssetBackingCircuitError::InvalidAssetVector(_))
        ));

        let mut dirty_inactive_amount = fixture.state.clone();
        dirty_inactive_amount.channel_fund.amounts[8] = U256::from(1u32);
        assert!(matches!(
            CloseAssetBackingWitness::from_private_state_and_channel_state(
                fixture.private_state.clone(),
                &dirty_inactive_amount,
                fixture.witness.final_balance_proof.clone(),
                fixture.witness.extended_public_state.clone(),
                &fixture.balance_vd,
            ),
            Err(CloseAssetBackingCircuitError::InvalidAssetVector(_))
        ));

        let mut wrong_extended = fixture.witness.extended_public_state.clone();
        wrong_extended.inner.timestamp += 1;
        assert!(matches!(
            CloseAssetBackingWitness::from_private_state_and_channel_state(
                fixture.private_state,
                &fixture.state,
                fixture.witness.final_balance_proof,
                wrong_extended,
                &fixture.balance_vd,
            ),
            Err(CloseAssetBackingCircuitError::BalancePublicStateMismatch)
        ));
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn circuit_rejects_asset_balance_and_extended_state_tampering() {
        let fixture = fixture();

        let mut wrong_amount = fixture.witness.clone();
        wrong_amount.fund_amounts[1] = U256::from(23u32);
        assert!(fixture.backing_circuit.prove(&wrong_amount).is_err());

        let mut dirty_inactive = fixture.witness.clone();
        dirty_inactive.token_registry[8] = 9;
        assert!(fixture.backing_circuit.prove(&dirty_inactive).is_err());

        let mut dirty_inactive_amount = fixture.witness.clone();
        dirty_inactive_amount.fund_amounts[8] = U256::from(1u32);
        assert!(
            fixture
                .backing_circuit
                .prove(&dirty_inactive_amount)
                .is_err()
        );

        let mut duplicate_active = fixture.witness.clone();
        duplicate_active.token_registry[2] = duplicate_active.token_registry[1];
        assert!(fixture.backing_circuit.prove(&duplicate_active).is_err());

        let mut wrong_private_opening = fixture.witness.clone();
        wrong_private_opening.private_state.nonce += 1;
        assert!(
            fixture
                .backing_circuit
                .prove(&wrong_private_opening)
                .is_err()
        );

        let mut wrong_extended = fixture.witness;
        wrong_extended.extended_public_state.inner.timestamp += 1;
        assert!(fixture.backing_circuit.prove(&wrong_extended).is_err());
    }

    #[test]
    fn public_inputs_roundtrip_is_fixed_width() {
        assert_eq!(CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN, 26);
        let inputs = CloseAssetBackingPublicInputs {
            channel_id: ChannelId::new(7).unwrap(),
            settled_tx_chain: Bytes32::from_u32_slice(&[1; 8]).unwrap(),
            token_funds_digest: Bytes32::from_u32_slice(&[2; 8]).unwrap(),
            finalized_extended_state_commitment: Bytes32::from_u32_slice(&[3; 8]).unwrap(),
            anchor_block_number: BlockNumber::new(4).unwrap(),
        };
        assert_eq!(
            inputs.to_u64_vec().len(),
            CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
        );
        assert_eq!(
            CloseAssetBackingPublicInputs::from_u64_slice(&inputs.to_u64_vec()).unwrap(),
            inputs
        );

        let mut noncanonical_anchor = inputs.to_u64_vec();
        noncanonical_anchor[CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN - 1] = 1 << 63;
        assert!(matches!(
            CloseAssetBackingPublicInputs::from_u64_slice(&noncanonical_anchor),
            Err(CloseAssetBackingCircuitError::InvalidPublicInputs(_))
        ));
    }


    // LAYER M: MECHANICAL FAITHFULNESS EVIDENCE
    // ---------------------------------------------------------------------------------------
    //
    // Model: `doc/audit/zkp/Zkp/Implementation/CloseAssetBacking.lean` — `BuildOp` /
    // `constructorProgram`, and since Layer B1 landed the per-op `BuildOp.holds` plus the
    // headline `program_satisfied_implies_constraints`. There is exactly ONE row per `BuildOp`
    // constructor (46 of them, covering all 468 program entries), and each row diffs the
    // constructor's actual `holds` case against the circuit plonky2 built:
    //
    //   ok         — the `holds` case is (or contains) a copy constraint, a constant pin, a
    //                range width or a public-input registration, and `RepView` confirms the
    //                built circuit agrees with it;
    //   not-static — the `holds` case is arithmetic or gadget semantics (an `ArithmeticGate`
    //                output relation, a hash, a Merkle opening, a recursive verification), which
    //                the copy-constraint partition cannot see;
    //   trivial    — the `holds` case is literally `True` and the Lean docstring makes no
    //                structural claim either;
    //   MISMATCH   — `holds` disagrees with the built circuit (fails the test).
    //
    // A constructor whose `holds` is `True` but whose docstring DOES make a checkable claim
    // (`allocatePrivateUnchecked`'s "NO range check", `allocatePath`'s 32 siblings,
    // `decodeBalanceTargetPis`'s "pure re-slicing", `startStandardRecursionZk`'s config) carries
    // that docstring claim as the executed check, and says so in its detail — so a docstring
    // that stops describing the circuit still surfaces here.

    use crate::faithfulness::{EvidenceTable, NOT_STATIC, RepView, TRIVIAL};

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn faithfulness_close_asset_backing_circuit_static_table() {
        let fx = fixture();
        let c = &fx.backing_circuit;
        let view = RepView::new(&c.data);
        let p = &c.probe;
        let pi = &c.public_inputs;
        let mut table = EvidenceTable::new("CloseAssetBacking");

        // --- recursive verification and its decoded statement ---------------------------------
        table.check(
            "assertBalancePiShape", "close_asset_backing_circuit.rs:442-446", "public-inputs",
            c.final_balance_proof.public_inputs.len()
                == BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&fx.balance_vd.common.config)
                && BALANCE_PUBLIC_INPUTS_LEN == 29,
            "holds: balanceProofWire.publicInputCount = recursive.expectedBalancePiCount — the \
             consumed proof is the canonical cyclic shape (29 + vd tail)",
        );
        table.check(
            "startStandardRecursionZk", "close_asset_backing_circuit.rs:447-448", "config",
            c.data.common.config == CircuitConfig::standard_recursion_zk_config(),
            "holds = True (config selection emits no gate); checked the docstring claim: the \
             built circuit carries standard_recursion_zk_config",
        );
        table.note(
            "allocateProofAndVerifyPinnedCyclic", "close_asset_backing_circuit.rs:450", "gadget",
            NOT_STATIC,
            "holds: recursive.circuitAccepts balanceProofWire — add_proof_target_and_verify_cyclic \
             bakes balance_vd in as constants and binds the self-VD; a FRI verifier, not a copy \
             constraint",
        );
        let balance_full = BalanceFullPublicInputsTarget::from_pis(
            &c.final_balance_proof.public_inputs,
            &fx.balance_vd.common.config,
        );
        let balance_pis = balance_full.pis;
        table.check(
            "decodeBalanceTargetPis", "close_asset_backing_circuit.rs:451-455", "aliasing",
            balance_pis.to_vec().len() == BALANCE_PUBLIC_INPUTS_LEN
                && balance_pis.to_vec()
                    == c.final_balance_proof.public_inputs[..BALANCE_PUBLIC_INPUTS_LEN].to_vec(),
            "holds = True (pure re-slicing, no gate); checked the docstring claim that carries the \
             aliasing: all 29 decoded statement wires ARE, target for target, the first 29 public \
             inputs of the verified proof",
        );

        // --- private state and its Poseidon opening -------------------------------------------
        table.check(
            "allocatePrivateUnchecked", "close_asset_backing_circuit.rs:457", "range",
            c.private_state.to_vec().len() == 21
                && view.none_range_checked(&c.private_state.to_vec()),
            "holds = True; checked the docstring claim: PrivateStateTarget::new range-checks none \
             of its 21 wires (four Poseidon roots, nonce, salt)",
        );
        table.note(
            "computePrivatePoseidon", "close_asset_backing_circuit.rs:458", "gadget", NOT_STATIC,
            "holds: hash.privateCommitment privateStateWire.words = openedPrivateCommitmentWire — \
             PoseidonHashOutTarget::hash_inputs over the 21-word to_vec(); the permutation is a \
             PoseidonGate relation, not a copy constraint",
        );
        table.check(
            "connectPrivateCommitment", "close_asset_backing_circuit.rs:461", "connect",
            view.same_slices(
                &p.opened_private_commitment.elements,
                &balance_pis.private_commitment.elements,
            ),
            "holds: openedPrivateCommitmentWire = balanceProofWire.statement.privateCommitment — \
             all four limbs share a copy-constraint class",
        );

        // --- extended public state -------------------------------------------------------------
        let ext = &c.extended_public_state;
        table.check(
            "allocateExtendedChecked", "close_asset_backing_circuit.rs:463", "range",
            view.range_bits(ext.inner.block_number.value).contains(&63)
                && view.all_range_checked(&ext.inner.timestamp.to_vec(), 32)
                && ext.inner.timestamp.to_vec().len() == 2
                && view.all_range_checked(&ext.block_hash_chain.to_vec(), 32)
                && view.all_range_checked(&ext.deposit_hash_chain.to_vec(), 32)
                && view.range_bits(ext.deposit_count.value).contains(&63)
                && view.all_range_checked(&ext.channel_reg_hash_chain.to_vec(), 32)
                && view.all_range_checked(&ext.bp_sig_chain.to_vec(), 32)
                && view.none_range_checked(&ext.inner.account_tree_root.elements)
                && view.none_range_checked(&ext.inner.deposit_tree_root.elements)
                && view.none_range_checked(&ext.inner.prev_public_state_root.elements),
            "holds: extendedStateWire.Checked — all eight conjuncts: blockNumber < 2^63, both \
             timestamp limbs < 2^32, four Bytes32 chains u32-checked, depositCount < 2^63; and \
             the three inner Poseidon roots stay range-unconstrained as the docstring says",
        );
        table.check(
            "connectInnerPublicState", "close_asset_backing_circuit.rs:464-466", "connect",
            balance_pis.public_state.to_vec().len() == 15
                && view.same_slices(&balance_pis.public_state.to_vec(), &ext.inner.to_vec()),
            "holds: balanceProofWire.statement.publicState = extendedStateWire.inner — all 15 \
             inner wires (block number, 2 timestamp limbs, 3 Poseidon roots) are connected",
        );

        // --- token vector allocation -----------------------------------------------------------
        table.note(
            "allocateCount", "close_asset_backing_circuit.rs:468", "no-gate", TRIVIAL,
            "holds = True — add_virtual_target() emits no constraint",
        );
        table.check(
            "rangeCount32", "close_asset_backing_circuit.rs:469", "range",
            view.range_bits(c.token_count).contains(&32),
            "holds: tokenCountWire < 2^32 — range_check(token_count, 32)",
        );
        table.note(
            "allocateRegistry [0..10)", "close_asset_backing_circuit.rs:470-471", "no-gate",
            TRIVIAL, "holds = True — the raw registry allocation emits no constraint",
        );
        table.check(
            "rangeRegistry32 [0..10)", "close_asset_backing_circuit.rs:472", "range",
            c.token_registry.len() == MAX_CHANNEL_TOKENS
                && view.all_range_checked(&c.token_registry, 32),
            "holds: registryWire row < 2^32 — range_check(registry[t], 32) for every one of the \
             ten slots",
        );
        let fund_limbs: Vec<Target> = c.fund_amounts.iter().flat_map(|a| a.to_vec()).collect();
        table.check(
            "allocateCheckedU256 [0..10)", "close_asset_backing_circuit.rs:475", "range",
            fund_limbs.len() == MAX_CHANNEL_TOKENS * 8 && view.all_range_checked(&fund_limbs, 32),
            "holds: (amountWire row).Checked — U256Target::new(_, true) u32-checks all eight \
             limbs of every token slot",
        );
        table.note(
            "allocateSafeBoolean [0..10)", "close_asset_backing_circuit.rs:476", "arith",
            NOT_STATIC,
            "holds: activityWire row = 0 ∨ activityWire row = 1 — add_virtual_bool_target_safe is \
             mul_sub(b,b,b) asserted zero through an ArithmeticGate output, not a copy constraint",
        );
        table.check(
            "allocatePath [0..10)", "close_asset_backing_circuit.rs:477-478", "width",
            c.asset_construction_proofs.len() == MAX_CHANNEL_TOKENS
                && MAX_CHANNEL_TOKENS == 10
                && ASSET_TREE_HEIGHT == 32
                && c.asset_construction_proofs
                    .iter()
                    .all(|proof| proof.0.siblings.len() == ASSET_TREE_HEIGHT),
            "holds = True; checked the constructor's own parameters: ten paths, each with exactly \
             assetTreeHeight = 32 sibling hashes, and the allocation itself emits no gate",
        );

        // --- constants ---------------------------------------------------------------------------
        table.check(
            "constantZero", "close_asset_backing_circuit.rs:480", "constant",
            view.is_zero(p.zero) && view.same(p.active_sum_seed, p.zero),
            "holds: zeroWire = 0 ∧ activitySumWire 0 = zeroWire — builder.zero() is pinned by a \
             gate constant AND is the seed of the activity accumulator",
        );
        table.check(
            "constantOne", "close_asset_backing_circuit.rs:481", "constant",
            view.is_one(p.one),
            "holds: oneWire = 1 — builder.one() is wired to its ConstantGate value",
        );

        // --- no-rise (padding-suffix) loop -------------------------------------------------------
        table.note(
            "subtractActivityFromOne [0..9)", "close_asset_backing_circuit.rs:485", "arith",
            NOT_STATIC,
            "holds: oneMinusActivityWire row = oneWire - activityWire row — builder.sub output is \
             an ArithmeticGate relation",
        );
        table.note(
            "multiplyNextActivity [0..9)", "close_asset_backing_circuit.rs:486", "arith",
            NOT_STATIC,
            "holds: riseProductWire row = activityWire (row+1) * oneMinusActivityWire row — \
             builder.mul output is an ArithmeticGate relation",
        );
        table.check(
            "connectNoRiseZero [0..9)", "close_asset_backing_circuit.rs:489", "connect",
            p.rise_products.len() == MAX_CHANNEL_TOKENS - 1 && view.all_zero(&p.rise_products),
            "holds: riseProductWire row = zeroWire — each of the nine rise products is connected \
             to the zero constant",
        );

        // --- activity count ----------------------------------------------------------------------
        table.note(
            "addActivityToSum [0..10)", "close_asset_backing_circuit.rs:491-496", "arith",
            NOT_STATIC,
            "holds: activitySumWire (row+1) = activitySumWire row + activityWire row — the ten \
             builder.add outputs are ArithmeticGate relations",
        );
        table.check(
            "connectSumToCount", "close_asset_backing_circuit.rs:497", "connect",
            view.same(p.active_sum, c.token_count),
            "holds: activitySumWire 10 = tokenCountWire — the final accumulator wire is connected \
             to the token_count wire",
        );
        table.check(
            "assertFirstActive", "close_asset_backing_circuit.rs:498", "constant",
            view.is_one(c.token_active_bits[0].target),
            "holds: activityWire 0 = 1 — assert_one(token_active_bits[0])",
        );

        // --- padding zeroing ---------------------------------------------------------------------
        table.note(
            "notActivity [0..10)", "close_asset_backing_circuit.rs:505", "arith", NOT_STATIC,
            "holds: inactiveWire row = 1 - activityWire row — builder.not is a sub, an \
             ArithmeticGate relation",
        );
        table.note(
            "multiplyInactiveRegistry [0..10)", "close_asset_backing_circuit.rs:506", "arith",
            NOT_STATIC,
            "holds: dirtyRegistryWire row = inactiveWire row * registryWire row — builder.mul \
             output is an ArithmeticGate relation",
        );
        table.check(
            "connectInactiveRegistryZero [0..10)", "close_asset_backing_circuit.rs:509", "connect",
            p.dirty_registry.len() == MAX_CHANNEL_TOKENS && view.all_zero(&p.dirty_registry),
            "holds: dirtyRegistryWire row = zeroWire — each of the ten inactive*registry products \
             is connected to the zero constant",
        );
        table.note(
            "multiplyInactiveAmount [0..10)x[0..8)", "close_asset_backing_circuit.rs:510-511",
            "arith", NOT_STATIC,
            "holds: dirtyAmountWire row limb = inactiveWire row * (amountWire row).words[limb] — \
             the eighty builder.mul outputs are ArithmeticGate relations",
        );
        table.check(
            "connectInactiveAmountZero [0..10)x[0..8)", "close_asset_backing_circuit.rs:514",
            "connect",
            p.dirty_amounts.len() == MAX_CHANNEL_TOKENS * 8 && view.all_zero(&p.dirty_amounts),
            "holds: dirtyAmountWire row limb = zeroWire — all eighty inactive*limb products are \
             connected to the zero constant",
        );

        // --- duplicate-registry exclusion ---------------------------------------------------------
        table.note(
            "equalRegistry [45 pairs]", "close_asset_backing_circuit.rs:521", "arith", NOT_STATIC,
            "holds: registryEqualWire i j = (if registryWire i = registryWire j then 1 else 0) — \
             builder.is_equal is an inverse-witness gadget, not a copy constraint",
        );
        table.note(
            "andEqualWithLaterActive [45 pairs]", "close_asset_backing_circuit.rs:522", "arith",
            NOT_STATIC,
            "holds: duplicateActiveWire i j = registryEqualWire i j * activityWire j — builder.and \
             is a mul, an ArithmeticGate relation",
        );
        table.check(
            "connectDuplicateZero [45 pairs]", "close_asset_backing_circuit.rs:525", "connect",
            p.duplicate_active.len()
                == MAX_CHANNEL_TOKENS * (MAX_CHANNEL_TOKENS - 1) / 2
                && view.all_zero(&p.duplicate_active),
            "holds: duplicateActiveWire i j = zeroWire — all 45 ordered-pair duplicate flags are \
             connected to the zero constant",
        );

        // --- asset-tree reconstruction -------------------------------------------------------------
        table.check(
            "constantZeroLeaf", "close_asset_backing_circuit.rs:532", "constant",
            view.all_zero(&p.empty_leaf.to_vec()) && p.empty_leaf.to_vec().len() == 8,
            "holds: zeroLeafWire = Words8.zero — U256Target::constant(builder, U256::default()) is \
             eight wires pinned to the zero constant",
        );
        let empty_root = AssetTree::init().get_root();
        table.check(
            "constantEmptyRoot", "close_asset_backing_circuit.rs:533-534", "constant",
            (0..4).all(|i| view.is_const(p.empty_asset_root.elements[i], empty_root.elements[i])),
            "holds: rootWire 0 = merkle.emptyRoot — the reconstruction starts at four wires pinned \
             to the canonical empty AssetTree root (which also discharges CanonicalEmptyRoot)",
        );
        table.note(
            "conditionalVerifyZeroPath [0..10)", "close_asset_backing_circuit.rs:538-544",
            "gadget", NOT_STATIC,
            "holds: activityWire row = 1 → merkle.pathRoot (pathWire row) zeroLeaf (registryWire \
             row) = rootWire row — a 32-level Poseidon Merkle opening under a select, not a copy \
             constraint",
        );
        table.note(
            "computeInsertedRoot [0..10)", "close_asset_backing_circuit.rs:545-549", "gadget",
            NOT_STATIC,
            "holds: insertedRootWire row = merkle.pathRoot (pathWire row) (amountWire row) \
             (registryWire row) — a 32-level Poseidon Merkle recomputation",
        );
        table.note(
            "selectUpdatedRoot [0..10)", "close_asset_backing_circuit.rs:550-555", "arith",
            NOT_STATIC,
            "holds: rootWire (row+1) = if activityWire row = 1 then insertedRootWire row else \
             rootWire row — PoseidonHashOutTarget::select is four ArithmeticGate selects",
        );
        table.check(
            "connectFinalAssetRoot", "close_asset_backing_circuit.rs:557", "connect",
            view.same_slices(
                &p.reconstructed_root.elements,
                &c.private_state.asset_tree_root.elements,
            ),
            "holds: rootWire 10 = privateStateWire.assetTreeRoot — the final selected root is \
             connected to the opened private state's asset tree root",
        );

        // --- token-funds digest preimage ---------------------------------------------------------
        table.check(
            "constantTokenFundsDomain", "close_asset_backing_circuit.rs:559", "constant",
            u64::from(TOKEN_FUNDS_DIGEST_DOMAIN) == 0x494d_5446
                && view.is_const(p.digest_preimage[0], u64::from(TOKEN_FUNDS_DIGEST_DOMAIN)),
            "holds: tokenFundsDomainWire = 0x494d5446 — the first preimage wire is pinned to the \
             'IMTF' domain constant the Lean model names",
        );
        table.check(
            "flattenAmountLimbs", "close_asset_backing_circuit.rs:560-563", "aliasing",
            fund_limbs.len() == MAX_CHANNEL_TOKENS * 8
                && (0..MAX_CHANNEL_TOKENS)
                    .all(|t| c.fund_amounts[t].to_vec() == fund_limbs[8 * t..8 * t + 8].to_vec()),
            "holds: amountLimbsWire = amountWords (assignedRows a) — the 80 hashed limbs are the \
             ten checked U256 slots flattened in row-major order, on the SAME wires",
        );
        table.check(
            "concatenateDigestPreimage", "close_asset_backing_circuit.rs:564-570", "preimage",
            p.digest_preimage.len() == 1 + MAX_CHANNEL_TOKENS + 1 + MAX_CHANNEL_TOKENS * 8
                && p.digest_preimage[1..1 + MAX_CHANNEL_TOKENS] == c.token_registry[..]
                && p.digest_preimage[1 + MAX_CHANNEL_TOKENS] == c.token_count
                && p.digest_preimage[2 + MAX_CHANNEL_TOKENS..] == fund_limbs[..]
                && view.same_slices(
                    &p.digest_preimage[1..1 + MAX_CHANNEL_TOKENS],
                    &c.token_registry,
                ),
            "holds: digestPreimageWire = [tokenFundsDomainWire] ++ registryWords ++ \
             [tokenCountWire] ++ amountLimbsWire — the 92-word IMTF preimage, wire for wire, on \
             the same targets the rest of the circuit constrains",
        );
        table.note(
            "computeKeccakTokenFunds", "close_asset_backing_circuit.rs:571-572", "gadget",
            NOT_STATIC,
            "holds: tokenFundsDigestWire = hash.tokenFundsHash digestPreimageWire — the keccak \
             relation is the HashFunctions dependency",
        );
        table.note(
            "computeExtendedPoseidonBytes", "close_asset_backing_circuit.rs:573", "gadget",
            NOT_STATIC,
            "holds: extendedCommitmentWire = hash.extendedCommitment extendedStateWire.words — \
             extended_public_state.commitment is a Poseidon/keccak gadget call",
        );

        // --- public inputs -------------------------------------------------------------------------
        let expected_pi_order: Vec<Target> = [
            vec![balance_pis.channel_id.value],
            balance_pis.settled_tx_chain.to_vec(),
            pi.token_funds_digest.to_vec(),
            pi.finalized_extended_state_commitment.to_vec(),
            vec![ext.inner.block_number.value],
        ]
        .concat();
        table.check(
            "assembleComputedPublicInputs", "close_asset_backing_circuit.rs:574-580", "aliasing",
            pi.channel_id.value == balance_pis.channel_id.value
                && pi.settled_tx_chain.to_vec() == balance_pis.settled_tx_chain.to_vec()
                && pi.anchor_block_number.value == ext.inner.block_number.value
                && pi.token_funds_digest.to_vec().len() == BYTES32_LEN
                && pi.finalized_extended_state_commitment.to_vec().len() == BYTES32_LEN
                && pi.to_vec() == expected_pi_order,
            "holds: publicWire = {channelId := balance.channelId, settledTxChain := \
             balance.settledTxChain, tokenFundsDigest, extendedStateCommitment, anchorBlockNumber \
             := extendedState.inner.blockNumber} — every field is the SAME wire as its source \
             (the two digests are the literal gadget outputs); no re-witnessing",
        );
        table.check(
            "registerPublicInputs 26", "close_asset_backing_circuit.rs:598", "public-inputs",
            expected_pi_order.len() == CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
                && CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN == 26
                && view.public_inputs_are(&expected_pi_order)
                && c.data.common.num_public_inputs == 26,
            "holds: publicWire.words.length = 26 — checked strictly stronger: the 26 registered \
             wires are exactly the 5 fields of CloseAssetBackingPublicInputsTarget, in to_vec order",
        );
        table.note(
            "buildCircuit", "close_asset_backing_circuit.rs:600", "no-gate", TRIVIAL,
            "holds = True — builder.build emits no constraint",
        );

        table.finish();
    }
}
