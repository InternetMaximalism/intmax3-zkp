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
        for t in 0..MAX_CHANNEL_TOKENS - 1 {
            let one_minus_prev = builder.sub(one, token_active_bits[t].target);
            let active_after_padding = builder.mul(token_active_bits[t + 1].target, one_minus_prev);
            builder.connect(active_after_padding, zero);
        }
        let mut active_sum = zero;
        for active in &token_active_bits {
            active_sum = builder.add(active_sum, active.target);
        }
        builder.connect(active_sum, token_count);
        builder.assert_one(token_active_bits[0].target);

        for t in 0..MAX_CHANNEL_TOKENS {
            let inactive = builder.not(token_active_bits[t]);
            let dirty_registry = builder.mul(inactive.target, token_registry[t]);
            builder.connect(dirty_registry, zero);
            for limb in fund_amounts[t].to_vec() {
                let dirty_amount = builder.mul(inactive.target, limb);
                builder.connect(dirty_amount, zero);
            }
        }
        for i in 0..MAX_CHANNEL_TOKENS {
            for j in (i + 1)..MAX_CHANNEL_TOKENS {
                let equal = builder.is_equal(token_registry[i], token_registry[j]);
                let duplicate_active = builder.and(equal, token_active_bits[j]);
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
    // `constructorProgram` (:714-790). NOTE: unlike the other five programs this module does
    // NOT yet define a per-op `holds` (Layer B1 is still running); its denotation is the
    // whole-constructor `CircuitConstraints` (:601-612) reached through `FieldGateLowering`.
    // The table below therefore checks each `BuildOp` against the structural content its
    // docstring/name asserts, plus every `CircuitConstraints` field that is a copy constraint.

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

        table.check(
            "assertBalancePiShape", "close_asset_backing_circuit.rs:400-405", "public-inputs",
            c.final_balance_proof.public_inputs.len()
                == BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&fx.balance_vd.common.config),
            "the consumed balance statement is the canonical cyclic shape (29 + vd tail)",
        );
        table.check(
            "startStandardRecursionZk", "close_asset_backing_circuit.rs:406-407", "config",
            c.data.common.config == CircuitConfig::standard_recursion_zk_config(),
            "the built circuit carries standard_recursion_zk_config",
        );
        table.note(
            "allocateProofAndVerifyPinnedCyclic", "close_asset_backing_circuit.rs:409", "gadget",
            NOT_STATIC,
            "add_proof_target_and_verify_cyclic bakes balance_vd in and binds the self-VD",
        );
        let balance_full = BalanceFullPublicInputsTarget::from_pis(
            &c.final_balance_proof.public_inputs,
            &fx.balance_vd.common.config,
        );
        let balance_pis = balance_full.pis;
        table.check(
            "decodeBalanceTargetPis", "close_asset_backing_circuit.rs:410-415", "aliasing",
            balance_pis.channel_id.value
                == c.final_balance_proof.public_inputs[0]
                && balance_pis.settled_tx_chain.to_vec()
                    == c.final_balance_proof.public_inputs
                        [BALANCE_PUBLIC_INPUTS_LEN - BYTES32_LEN..BALANCE_PUBLIC_INPUTS_LEN]
                        .to_vec(),
            "the decoded statement fields ARE slices of the verified proof's PI vector",
        );
        table.check(
            "allocatePrivateUnchecked", "close_asset_backing_circuit.rs:416", "range",
            view.none_range_checked(&c.private_state.asset_tree_root.elements)
                && view.range_bits(c.private_state.nonce).is_empty(),
            "PrivateStateTarget::new range-checks neither the roots nor the nonce/salt",
        );
        table.note(
            "computePrivatePoseidon", "close_asset_backing_circuit.rs:417", "gadget", NOT_STATIC,
            "private_state.commitment is a Poseidon gadget call",
        );
        table.check(
            "connectPrivateCommitment", "close_asset_backing_circuit.rs:418", "connect",
            view.same_slices(
                &p.opened_private_commitment.elements,
                &balance_pis.private_commitment.elements,
            ),
            "opened_private_commitment.connect(balance_pis.private_commitment)",
        );
        table.check(
            "allocateExtendedChecked", "close_asset_backing_circuit.rs:420", "range",
            view.all_range_checked(&c.extended_public_state.block_hash_chain.to_vec(), 32)
                && view.all_range_checked(&c.extended_public_state.deposit_hash_chain.to_vec(), 32)
                && view
                    .all_range_checked(&c.extended_public_state.channel_reg_hash_chain.to_vec(), 32)
                && view.all_range_checked(&c.extended_public_state.bp_sig_chain.to_vec(), 32),
            "ExtendedPublicStateTarget::new(_, true) range-checks every extension chain limb",
        );
        table.check(
            "connectInnerPublicState", "close_asset_backing_circuit.rs:421-424", "connect",
            view.same(
                balance_pis.public_state.block_number.value,
                c.extended_public_state.inner.block_number.value,
            ) && view.same_slices(
                &balance_pis.public_state.account_tree_root.elements,
                &c.extended_public_state.inner.account_tree_root.elements,
            ),
            "balance_pis.public_state.connect(extended_public_state.inner)",
        );
        table.check(
            "allocateCount / rangeCount32", "close_asset_backing_circuit.rs:426-427", "range",
            view.range_bits(c.token_count).contains(&32),
            "range_check(token_count, 32)",
        );
        table.check(
            "allocateRegistry / rangeRegistry32 [0..10)",
            "close_asset_backing_circuit.rs:428-432", "range",
            c.token_registry.len() == MAX_CHANNEL_TOKENS
                && view.all_range_checked(&c.token_registry, 32),
            "range_check(registry[t], 32) for every slot",
        );
        let fund_limbs: Vec<Target> = c.fund_amounts.iter().flat_map(|a| a.to_vec()).collect();
        table.check(
            "allocateCheckedU256 [0..10)", "close_asset_backing_circuit.rs:433", "range",
            fund_limbs.len() == MAX_CHANNEL_TOKENS * 8 && view.all_range_checked(&fund_limbs, 32),
            "U256Target::new(_, true): 8 range-checked limbs per token slot",
        );
        table.note(
            "allocateSafeBoolean [0..10)", "close_asset_backing_circuit.rs:434", "arith",
            NOT_STATIC,
            "add_virtual_bool_target_safe is mul_sub(b,b,b) connected to zero on an internal wire",
        );
        table.check(
            "allocatePath [0..10)", "close_asset_backing_circuit.rs:435-436", "width",
            c.asset_construction_proofs.len() == MAX_CHANNEL_TOKENS,
            "one height-ASSET_TREE_HEIGHT asset proof per token slot",
        );
        table.check(
            "constantZero / constantOne", "close_asset_backing_circuit.rs:438-439", "constant",
            view.is_zero(p.zero) && view.is_one(p.one),
            "builder.zero() / builder.one() are wired to their ConstantGate values",
        );
        for (op, src) in [
            ("subtractActivityFromOne [0..9)", "close_asset_backing_circuit.rs:441"),
            ("multiplyNextActivity [0..9)", "close_asset_backing_circuit.rs:442"),
            ("connectNoRiseZero [0..9)", "close_asset_backing_circuit.rs:443"),
            ("addActivityToSum [0..10)", "close_asset_backing_circuit.rs:445-448"),
            ("notActivity [0..10)", "close_asset_backing_circuit.rs:453"),
            ("multiplyInactiveRegistry [0..10)", "close_asset_backing_circuit.rs:454"),
            ("connectInactiveRegistryZero [0..10)", "close_asset_backing_circuit.rs:455"),
            ("multiplyInactiveAmount [0..10)x[0..8)", "close_asset_backing_circuit.rs:456-458"),
            ("connectInactiveAmountZero [0..10)x[0..8)", "close_asset_backing_circuit.rs:456-459"),
            ("equalRegistry [45 pairs]", "close_asset_backing_circuit.rs:462"),
            ("andEqualWithLaterActive [45 pairs]", "close_asset_backing_circuit.rs:463"),
            ("connectDuplicateZero [45 pairs]", "close_asset_backing_circuit.rs:464"),
        ] {
            table.note(op, src, "arith", NOT_STATIC,
                "sub/mul/not/is_equal/and outputs are arithmetic wires connected to zero");
        }
        table.check(
            "connectSumToCount", "close_asset_backing_circuit.rs:449", "connect",
            view.same(p.active_sum, c.token_count),
            "the 10-bit activity add chain is connected to the token_count wire",
        );
        table.check(
            "assertFirstActive", "close_asset_backing_circuit.rs:450", "constant",
            view.is_one(c.token_active_bits[0].target),
            "assert_one(token_active_bits[0])",
        );
        table.check(
            "constantZeroLeaf", "close_asset_backing_circuit.rs:471", "constant",
            view.all_zero(&p.empty_leaf.to_vec()),
            "U256Target::constant(builder, U256::default()) is 8 zero-constant wires",
        );
        let empty_root = AssetTree::init().get_root();
        table.check(
            "constantEmptyRoot", "close_asset_backing_circuit.rs:472-473", "constant",
            (0..4).all(|i| view.is_const(p.empty_asset_root.elements[i], empty_root.elements[i])),
            "the reconstruction starts at the canonical empty AssetTree root, as 4 constants",
        );
        for (op, src) in [
            ("conditionalVerifyZeroPath [0..10)", "close_asset_backing_circuit.rs:475-481"),
            ("computeInsertedRoot [0..10)", "close_asset_backing_circuit.rs:482-486"),
            ("selectUpdatedRoot [0..10)", "close_asset_backing_circuit.rs:487-492"),
        ] {
            table.note(op, src, "gadget", NOT_STATIC,
                "the asset-Merkle gadget and the root select are not copy constraints");
        }
        table.check(
            "connectFinalAssetRoot", "close_asset_backing_circuit.rs:494", "connect",
            view.same_slices(
                &p.reconstructed_root.elements,
                &c.private_state.asset_tree_root.elements,
            ),
            "reconstructed_root.connect(private_state.asset_tree_root)",
        );
        table.check(
            "constantTokenFundsDomain / flattenAmountLimbs / concatenateDigestPreimage",
            "close_asset_backing_circuit.rs:496-506", "preimage",
            p.digest_preimage.len() == 1 + MAX_CHANNEL_TOKENS + 1 + MAX_CHANNEL_TOKENS * 8
                && view.is_const(p.digest_preimage[0], u64::from(TOKEN_FUNDS_DIGEST_DOMAIN))
                && view.same_slices(
                    &p.digest_preimage[1..1 + MAX_CHANNEL_TOKENS],
                    &c.token_registry,
                )
                && view.same(p.digest_preimage[1 + MAX_CHANNEL_TOKENS], c.token_count)
                && view.same_slices(
                    &p.digest_preimage[2 + MAX_CHANNEL_TOKENS..],
                    &fund_limbs,
                ),
            "the 92-word IMTF preimage is [domain, registry(10), token_count, amounts(80)] \
             on the SAME wires the rest of the circuit constrains",
        );
        table.note(
            "computeKeccakTokenFunds", "close_asset_backing_circuit.rs:507-508", "gadget",
            NOT_STATIC, "the keccak relation is the HashFunctions dependency",
        );
        table.note(
            "computeExtendedPoseidonBytes", "close_asset_backing_circuit.rs:509", "gadget",
            NOT_STATIC, "extended_public_state.commitment is a Poseidon gadget call",
        );
        // assembleComputedPublicInputs / registerPublicInputs 26 — :510-517.
        let expected_pi_order: Vec<Target> = [
            vec![balance_pis.channel_id.value],
            balance_pis.settled_tx_chain.to_vec(),
            pi.token_funds_digest.to_vec(),
            pi.finalized_extended_state_commitment.to_vec(),
            vec![c.extended_public_state.inner.block_number.value],
        ]
        .concat();
        table.check(
            "assembleComputedPublicInputs", "close_asset_backing_circuit.rs:510-516", "aliasing",
            pi.channel_id.value == balance_pis.channel_id.value
                && pi.settled_tx_chain.to_vec() == balance_pis.settled_tx_chain.to_vec()
                && pi.anchor_block_number.value
                    == c.extended_public_state.inner.block_number.value,
            "channel_id / settled_tx_chain / anchor are the SAME wires as the verified \
             balance statement and the extended state (no re-witnessing)",
        );
        table.check(
            "registerPublicInputs 26", "close_asset_backing_circuit.rs:517", "public-inputs",
            expected_pi_order.len() == CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN
                && CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN == 26
                && view.public_inputs_are(&expected_pi_order)
                && c.data.common.num_public_inputs == 26,
            "the 26 registered wires are exactly the 5 fields of CloseAssetBackingPublicInputsTarget",
        );
        table.note(
            "buildCircuit", "close_asset_backing_circuit.rs:519", "no-gate", TRIVIAL,
            "builder.build emits no constraint",
        );

        table.finish();
    }
}
