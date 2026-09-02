//! Pre-authorized, live-state close funding without a new proof system.
//!
//! A close-funding proposal is the channel analogue of a Lightning commitment transaction: every
//! cosigner signs one terminal child of the current channel head whose `h2_tag` is the exact base
//! `TxV2` root paying the channel's complete fund vector to its immutable settlement manager.  The
//! channel balances and fund vector do not change in that child.  Only the channel counters,
//! `settled_tx_chain`, `prev_digest`, and `h2_tag` advance.  Consequently the ordinary validity,
//! balance, withdrawal, and close circuits can be reused byte-for-byte; this module adds no gate,
//! public input, verifier key, or proof byte.
//!
//! Publishing this transaction is terminal.  The base collateral has moved to the Manager's
//! rollup withdrawal credit, so the producer/live service must reject every later channel update
//! and drive the signed child through the ordinary close path.

use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::common::recipient::calculate_recipient_from_address,
    common::{
        balance_state::settled_tx_chain_push,
        channel::{ChannelState, token_funds_digest},
        channel_id::ChannelId,
        transfer::Transfer,
        trees::tx_v2_tree::{TxV2MerkleProof, TxV2Tree},
        tx::{TxClass, TxV2},
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    utils::poseidon_hash_out::PoseidonHashOut,
};

/// "IMCF" — close-funding authorization/aux-data domain.
pub const CLOSE_FUNDING_DOMAIN: u32 = 0x494d4346;
/// "IMFP" — durable proposal identity domain.
pub const CLOSE_FUNDING_PLAN_DOMAIN: u32 = 0x494d4650;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CloseFundingError {
    #[error("invalid close-funding proposal: {0}")]
    Invalid(String),
    #[error("close-funding counter overflow: {0}")]
    CounterOverflow(&'static str),
}

/// The exact transaction material a keyless producer and resident live-balance service consume.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseFundingPlan {
    pub chain_id: u64,
    pub rollup: Address,
    pub manager: Address,
    pub source_channel_id: ChannelId,
    /// The Manager era expected after `requestClose`: signed-state era + 1.
    pub close_freeze_nonce: u64,
    pub base_nonce: u32,
    pub token_funds_digest: Bytes32,
    /// Shared by every transfer in this one Tx. The rollup's existing IPW2 digest additionally
    /// binds each transfer's token index and amount before the Manager authorizes its payout.
    pub funding_aux_data: Bytes32,
    /// Active, non-zero fund entries in channel registry order. Every recipient is the Manager.
    pub transfers: Vec<Transfer>,
    pub tx_v2: TxV2,
    pub tx_tree_root: Bytes32,
    pub tx_v2_merkle_proof: TxV2MerkleProof,
    pub plan_digest: Bytes32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseFundingProposal {
    pub plan: CloseFundingPlan,
    /// Unsigned terminal child. Existing detached N-of-N signing installs `member_signatures`.
    pub proposed_state: ChannelState,
}

/// Byte-identical to Solidity:
///
/// `keccak256(abi.encodePacked(bytes4("IMCF"), uint256(chainId), rollup, manager,
///                              bytes4(channelId), uint64(closeFreezeNonce), tokenFundsDigest))`.
///
/// The preimage deliberately excludes the final child digest: that digest contains `h2_tag`,
/// whose transfer leaves contain this aux value, so including it would create a hash cycle.
pub fn close_funding_aux_data(
    chain_id: u64,
    rollup: Address,
    manager: Address,
    channel_id: ChannelId,
    close_freeze_nonce: u64,
    funds_digest: Bytes32,
) -> Bytes32 {
    let words: Vec<u32> = [CLOSE_FUNDING_DOMAIN]
        .into_iter()
        // Solidity packs uint256 as 32 bytes. Chain ids accepted by the daemon are u64, so the
        // leading six limbs are canonical zero padding.
        .chain(U256::from(chain_id).to_u32_vec())
        .chain(rollup.to_u32_vec())
        .chain(manager.to_u32_vec())
        .chain(channel_id.to_u32_vec())
        .chain([(close_freeze_nonce >> 32) as u32, close_freeze_nonce as u32])
        .chain(funds_digest.to_u32_vec())
        .collect();
    Bytes32::from_u32_slice(&solidity_keccak256(&words))
        .expect("keccak output is exactly one bytes32")
}

pub fn build_close_funding_proposal(
    head: &ChannelState,
    chain_id: u64,
    rollup: Address,
    manager: Address,
    base_nonce: u32,
) -> Result<CloseFundingProposal, CloseFundingError> {
    head.balance_state
        .validate()
        .map_err(|e| CloseFundingError::Invalid(format!("channel balance head: {e}")))?;
    if head.channel_id != head.balance_state.channel_id
        || head.channel_id != head.channel_fund.channel_id
    {
        return Err(CloseFundingError::Invalid(
            "channel, balance-state, and fund ids must agree".into(),
        ));
    }
    if head.digest != head.signing_digest() {
        return Err(CloseFundingError::Invalid(
            "channel head digest does not match its signed preimage".into(),
        ));
    }
    if rollup == Address::default() || manager == Address::default() {
        return Err(CloseFundingError::Invalid(
            "rollup and manager must both be nonzero".into(),
        ));
    }
    if head.h2_tag != Bytes32::default() {
        return Err(CloseFundingError::Invalid(
            "prepare close funding only from a settled zero-H2 channel head".into(),
        ));
    }
    if head.unallocated_confirmed_incoming != U256::zero() {
        return Err(CloseFundingError::Invalid(
            "unallocated confirmed incoming value must be assigned before close funding".into(),
        ));
    }

    let token_count = head.balance_state.token_count as usize;
    if token_count == 0 || token_count > head.balance_state.token_registry.len() {
        return Err(CloseFundingError::Invalid(format!(
            "token_count {} is outside the supported registry",
            head.balance_state.token_count
        )));
    }
    if head.channel_fund.amounts[token_count..]
        .iter()
        .any(|amount| *amount != U256::zero())
    {
        return Err(CloseFundingError::Invalid(
            "inactive fund-vector positions must be zero".into(),
        ));
    }
    let close_freeze_nonce = head
        .close_freeze_nonce
        .checked_add(1)
        .ok_or(CloseFundingError::CounterOverflow("close_freeze_nonce"))?;
    let funds_digest = token_funds_digest(
        &head.balance_state.token_registry,
        head.balance_state.token_count,
        &head.channel_fund.amounts,
    );
    let funding_aux_data = close_funding_aux_data(
        chain_id,
        rollup,
        manager,
        head.channel_id,
        close_freeze_nonce,
        funds_digest,
    );
    let recipient = calculate_recipient_from_address(manager);
    let mut transfers = Vec::with_capacity(token_count);
    for slot in 0..token_count {
        let amount = head.channel_fund.amounts[slot];
        if amount == U256::zero() {
            continue;
        }
        transfers.push(Transfer {
            recipient,
            token_index: head.balance_state.token_registry[slot],
            amount,
            aux_data: funding_aux_data,
        });
    }
    if transfers.is_empty() {
        return Err(CloseFundingError::Invalid(
            "the finalized fund vector contains no nonzero asset".into(),
        ));
    }

    let mut transfer_tree = crate::common::trees::transfer_tree::TransferTree::init();
    for transfer in &transfers {
        transfer_tree.push(transfer.clone());
    }
    let tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: transfer_tree.get_root(),
        nonce: base_nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut tx_tree = TxV2Tree::init();
    tx_tree.update(head.channel_id.as_u64(), tx_v2);
    let tx_tree_root = Bytes32::from(tx_tree.get_root());
    let tx_v2_merkle_proof = tx_tree.prove(head.channel_id.as_u64());

    let plan_digest = close_funding_plan_digest(
        chain_id,
        rollup,
        manager,
        head.channel_id,
        close_freeze_nonce,
        base_nonce,
        funds_digest,
        tx_tree_root,
    );
    let plan = CloseFundingPlan {
        chain_id,
        rollup,
        manager,
        source_channel_id: head.channel_id,
        close_freeze_nonce,
        base_nonce,
        token_funds_digest: funds_digest,
        funding_aux_data,
        transfers,
        tx_v2,
        tx_tree_root,
        tx_v2_merkle_proof,
        plan_digest,
    };

    let mut proposed_state = head.clone();
    proposed_state.epoch = proposed_state
        .epoch
        .checked_add(1)
        .ok_or(CloseFundingError::CounterOverflow("epoch"))?;
    proposed_state.small_block_number = proposed_state
        .small_block_number
        .checked_add(1)
        .ok_or(CloseFundingError::CounterOverflow("small_block_number"))?;
    proposed_state.balance_state.state_version = proposed_state
        .balance_state
        .state_version
        .checked_add(1)
        .ok_or(CloseFundingError::CounterOverflow("state_version"))?;
    proposed_state.balance_state.settled_tx_chain =
        settled_tx_chain_push(head.balance_state.settled_tx_chain, funding_aux_data);
    proposed_state.prev_digest = head.digest;
    proposed_state.h2_tag = tx_tree_root;
    proposed_state.member_signatures.clear();
    proposed_state = proposed_state.with_computed_digest();

    Ok(CloseFundingProposal {
        plan,
        proposed_state,
    })
}

/// Rebuild-equality co-signer/producer gate. No caller-supplied field is trusted independently.
pub fn verify_close_funding_proposal(
    previous: &ChannelState,
    signed_state: &ChannelState,
    plan: &CloseFundingPlan,
) -> Result<(), CloseFundingError> {
    let expected = build_close_funding_proposal(
        previous,
        plan.chain_id,
        plan.rollup,
        plan.manager,
        plan.base_nonce,
    )?;
    if !same_plan_fields(&expected.plan, plan) {
        return Err(CloseFundingError::Invalid(
            "plan is not the canonical full fund vector/Manager transaction".into(),
        ));
    }
    let root = PoseidonHashOut::try_from(plan.tx_tree_root).map_err(|e| {
        CloseFundingError::Invalid(format!(
            "tx tree root is not a canonical Poseidon hash: {e:?}"
        ))
    })?;
    plan.tx_v2_merkle_proof
        .verify(&plan.tx_v2, plan.source_channel_id.as_u64(), root)
        .map_err(|e| {
            CloseFundingError::Invalid(format!("TxV2 inclusion proof is invalid: {e:?}"))
        })?;
    if signed_state.digest != expected.proposed_state.digest
        || signed_state.signing_digest() != expected.proposed_state.digest
    {
        return Err(CloseFundingError::Invalid(
            "signed child is not the canonical terminal close-funding transition".into(),
        ));
    }
    Ok(())
}

/// Compare every semantic plan field. A sparse Merkle proof intentionally has no `PartialEq`;
/// its validity is checked separately against the canonical leaf/index/root above.
fn same_plan_fields(left: &CloseFundingPlan, right: &CloseFundingPlan) -> bool {
    left.chain_id == right.chain_id
        && left.rollup == right.rollup
        && left.manager == right.manager
        && left.source_channel_id == right.source_channel_id
        && left.close_freeze_nonce == right.close_freeze_nonce
        && left.base_nonce == right.base_nonce
        && left.token_funds_digest == right.token_funds_digest
        && left.funding_aux_data == right.funding_aux_data
        && left.transfers == right.transfers
        && left.tx_v2 == right.tx_v2
        && left.tx_tree_root == right.tx_tree_root
        && left.plan_digest == right.plan_digest
}

#[allow(clippy::too_many_arguments)]
fn close_funding_plan_digest(
    chain_id: u64,
    rollup: Address,
    manager: Address,
    channel_id: ChannelId,
    close_freeze_nonce: u64,
    base_nonce: u32,
    funds_digest: Bytes32,
    tx_tree_root: Bytes32,
) -> Bytes32 {
    let words: Vec<u32> = [CLOSE_FUNDING_PLAN_DOMAIN]
        .into_iter()
        .chain(U256::from(chain_id).to_u32_vec())
        .chain(rollup.to_u32_vec())
        .chain(manager.to_u32_vec())
        .chain(channel_id.to_u32_vec())
        .chain([(close_freeze_nonce >> 32) as u32, close_freeze_nonce as u32])
        .chain([base_nonce])
        .chain(funds_digest.to_u32_vec())
        .chain(tx_tree_root.to_u32_vec())
        .collect();
    Bytes32::from_u32_slice(&solidity_keccak256(&words))
        .expect("keccak output is exactly one bytes32")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{balance_state::BalanceState, channel::ChannelFund},
        regev::RegevCiphertext,
    };

    fn address(word: u32) -> Address {
        Address::from_u32_slice(&[word; 5]).unwrap()
    }

    #[test]
    fn imcf_rust_solidity_fixed_golden_vector() {
        // Shared with contracts/test/CloseFundingAuthorization.t.sol.  The packed preimage is
        // exactly 120 bytes: IMCF || uint256(chain) || rollup || manager || uint32(channel) ||
        // uint64(freeze nonce) || IMTF.  A width/order drift on either side changes this digest.
        let funds_digest =
            Bytes32::from_hex("0x44987e3ca1c57257dfd4e9f5d6cc165f341cc4a9e5e0de7b6c06595105d27278")
                .unwrap();
        let got = close_funding_aux_data(
            1,
            address(0x1111_1111),
            address(0x2222_2222),
            ChannelId::new(7).unwrap(),
            4,
            funds_digest,
        );
        assert_eq!(
            got,
            Bytes32::from_hex(
                "0x44bf64ff1965bdc482a566498e4f33854d01d3ba814e8f8a2e6b19a2823f5fc0",
            )
            .unwrap()
        );
    }

    fn head() -> ChannelState {
        let channel_id = ChannelId::new(7).unwrap();
        let mut state = ChannelState {
            channel_id,
            epoch: 9,
            small_block_number: 11,
            close_freeze_nonce: 3,
            channel_fund: ChannelFund {
                channel_id,
                amounts: {
                    let mut amounts = [U256::zero(); 10];
                    amounts[0] = U256::from(40u32);
                    amounts[1] = U256::from(9u32);
                    amounts
                },
                intmax_state_root: Bytes32::from_u32_slice(&[3; 8]).unwrap(),
            },
            balance_state: BalanceState {
                channel_id,
                member_count: 2,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances(&[
                    std::array::from_fn(|_| RegevCiphertext::padding()),
                    std::array::from_fn(|_| RegevCiphertext::padding()),
                ]),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                    Bytes32::from_u32_slice(&[1; 8]).unwrap(),
                    Bytes32::from_u32_slice(&[2; 8]).unwrap(),
                ]),
                recipients: BalanceState::pad_recipients(&[address(1), address(2)]),
                settled_tx_chain: Bytes32::from_u32_slice(&[8; 8]).unwrap(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 14,
                pending_adds: BalanceState::pad_pending_adds(&[[0; 10], [0; 10]]),
                token_count: 2,
                token_registry: {
                    let mut registry = [0u32; 10];
                    registry[1] = 55;
                    registry
                },
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: Vec::new(),
        };
        // This focused unit tests the close-funding projection. Full channel validity and N-of-N
        // membership are exercised at the producer boundary, where realistic snapshots exist.
        state.digest = state.signing_digest();
        state
    }

    #[test]
    fn plan_pays_exact_active_fund_vector_and_changes_no_economics() {
        let previous = head();
        let proposal =
            build_close_funding_proposal(&previous, 1, address(0x11), address(0x22), 5).unwrap();
        assert_eq!(proposal.plan.transfers.len(), 2);
        assert_eq!(proposal.plan.transfers[0].token_index, 0);
        assert_eq!(proposal.plan.transfers[1].token_index, 55);
        assert_eq!(proposal.plan.transfers[0].amount, U256::from(40u32));
        assert_eq!(proposal.plan.transfers[1].amount, U256::from(9u32));
        assert_eq!(proposal.proposed_state.channel_fund, previous.channel_fund);
        assert_eq!(
            proposal.proposed_state.balance_state.enc_balances,
            previous.balance_state.enc_balances
        );
        assert_eq!(proposal.proposed_state.prev_digest, previous.digest);
        assert_eq!(proposal.proposed_state.h2_tag, proposal.plan.tx_tree_root);
        assert_ne!(
            proposal.proposed_state.balance_state.settled_tx_chain,
            previous.balance_state.settled_tx_chain
        );
    }

    #[test]
    fn rebuild_gate_rejects_amount_or_recipient_substitution() {
        let previous = head();
        let proposal =
            build_close_funding_proposal(&previous, 1, address(0x11), address(0x22), 5).unwrap();
        verify_close_funding_proposal(&previous, &proposal.proposed_state, &proposal.plan).unwrap();

        let mut changed = proposal.plan.clone();
        changed.transfers[0].amount += U256::from(1u32);
        assert!(
            verify_close_funding_proposal(&previous, &proposal.proposed_state, &changed).is_err()
        );
        let mut changed = proposal.plan.clone();
        changed.manager = address(0x23);
        assert!(
            verify_close_funding_proposal(&previous, &proposal.proposed_state, &changed).is_err()
        );
    }
}
