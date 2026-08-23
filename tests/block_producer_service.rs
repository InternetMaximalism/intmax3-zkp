use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use intmax3_zkp::{
    block_producer::{ProductionBlockProducerError, ProductionDepositRequest},
    block_producer_service::{BlockProducerService, BlockProducerServiceError},
    common::{
        balance_state::{settled_tx_chain_push, tx_leaf_hash},
        channel::{
            ChannelProofEnvelope, ChannelState, InterChannelTx, MemberSignature,
            MerkleInclusionProof, ProofBackend, ReceiverBalanceDelta, SignedSmallBlock,
            SmallBlockRootMessage, TransitionProofRole,
        },
        channel_id::ChannelId,
        deposit::Deposit,
        u63::{BlockNumber, U63},
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    regev::RegevCiphertext,
    wallet_core::{
        ChannelSnapshot, InterChannelDebitPayload, InterChannelTransferDescriptor, MemberInfo,
        MemberKeys, assemble_genesis_state, build_record, default_settled_tx_accumulator,
        inter_channel_base_transfer, inter_channel_tx_v2, sign_state,
    },
};
use rand010::SeedableRng as _;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("intmax-bp-{label}-{}-{unique}", std::process::id()));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("producer.journal.json")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn public_member(slot: usize, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot: slot as u16,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

fn signed_snapshot(channel: u32) -> (Vec<MemberKeys>, ChannelSnapshot) {
    let mut rng = rand010::rngs::StdRng::seed_from_u64(0x4250_0000 + channel as u64);
    let keys: Vec<MemberKeys> = (0..2).map(|_| MemberKeys::generate(&mut rng)).collect();
    let members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| public_member(slot, keys))
        .collect();
    let record = build_record(channel, &members, 0, 0).expect("channel record");
    let ciphertexts = vec![RegevCiphertext::padding(); keys.len()];
    let regev_digests: Vec<Bytes32> = keys
        .iter()
        .map(|keys| Bytes32::from(keys.regev_pk.poseidon_digest()))
        .collect();
    let recipients: Vec<Address> = (0..keys.len())
        .map(|slot| {
            Address::from_u32_slice(&[0x5253_0000 + slot as u32; 5]).expect("nonzero recipient")
        })
        .collect();
    let mut state = assemble_genesis_state(&record, &ciphertexts, &regev_digests, &recipients, 100)
        .expect("genesis state");
    state.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| sign_state(keys, slot as u8, &state).expect("sign genesis"))
        .collect();
    (
        keys,
        ChannelSnapshot {
            record,
            state,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        },
    )
}

fn next_descriptor(
    keys: &[MemberKeys],
    snapshot: &ChannelSnapshot,
    previous: &ChannelState,
    base_nonce: u32,
    amount: u64,
) -> (
    ChannelState,
    InterChannelDebitPayload,
    InterChannelTransferDescriptor,
) {
    let source = snapshot.record.channel_id;
    let destination = ChannelId::new(source.as_u64() + 100).expect("destination channel");
    let receiver_pk_g = keys[1].pk_g();
    let sender_delta = RegevCiphertext::padding();
    let receiver_delta = RegevCiphertext::padding();
    let tx_leaf = tx_leaf_hash(
        keys[0].pk_g(),
        sender_delta.digest(),
        receiver_pk_g,
        receiver_delta.digest(),
    );
    // F-AUX-1: the BASE-layer recipient is the DESTINATION CHANNEL's base account, NOT the
    // receiving member's channel-layer pk_g — "the BASE intmax native user IS the channel"
    // (constants.rs). `canonical_inter_channel_base_transfer` recomputes exactly this from the
    // descriptor's own `destination_channel_id` / `destination_base_transfer_salt`, so a pk_g
    // here made `intmax_transfer_commitment` disagree with the canonical binding.
    let base_recipient =
        intmax3_zkp::circuits::balance::common::recipient::calculate_recipient_from_user_id(
            destination,
            intmax3_zkp::common::salt::Salt::default(),
        );
    let transfer = inter_channel_base_transfer(base_recipient, 0, amount, tx_leaf);
    let (tx_v2, tx_v2_tree) = inter_channel_tx_v2(source, &transfer, base_nonce);
    let tx_tree_root = Bytes32::from(tx_v2_tree.get_root());
    let tx_v2_merkle_proof = tx_v2_tree.prove(source.as_u64());

    let mut signed_state = previous.clone();
    signed_state.epoch = previous.epoch + 1;
    signed_state.small_block_number = previous.small_block_number + 1;
    signed_state.balance_state.state_version = previous.balance_state.state_version + 1;
    signed_state.balance_state.settled_tx_chain =
        settled_tx_chain_push(previous.balance_state.settled_tx_chain, tx_leaf);
    signed_state.h2_tag = tx_tree_root;
    signed_state.prev_digest = previous.digest;
    signed_state.digest = Bytes32::default();
    signed_state.member_signatures.clear();
    signed_state = signed_state.with_computed_digest();
    signed_state.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| {
            sign_state(keys, slot as u8, &signed_state).expect("sign next channel head")
        })
        .collect();

    let structural_signatures: Vec<MemberSignature> = (0..snapshot.record.member_count)
        .map(|slot| MemberSignature {
            member_slot: slot,
            pk_g: snapshot.record.member_pk_gs[slot as usize],
            signature: vec![1, slot],
        })
        .collect();
    let mut inter_channel_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof::default(),
        signed_small_block: SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: source,
                bp_member_slot: snapshot.record.bp_member_slot,
                bp_pk_g: snapshot.record.member_pk_gs[snapshot.record.bp_member_slot as usize],
                small_block_number: signed_state.small_block_number,
                prev_small_block_root: previous.h2_tag,
                tx_tree_root,
                state_commitment_root: signed_state.balance_state.h1(),
                medium_epoch_hint: 0,
                close_freeze_nonce: signed_state.close_freeze_nonce,
            },
            signatures: structural_signatures,
            aggregated_signature_proof: Vec::new(),
            medium_block_number: 0,
            confirmation_proof: Vec::new(),
        },
        sender_delta_ct: sender_delta.clone(),
        source_channel_id: source,
        destination_channel_id: destination,
        token_index: 0,
        base_nonce,
        destination_base_transfer_salt: intmax3_zkp::common::salt::Salt::default(),
        source_pk_g: keys[0].pk_g(),
        seal: Bytes32::default(),
        tx_hash: Bytes32::default(),
        intmax_transfer_commitment: Bytes32::from(transfer.poseidon_hash()),
        recipient_memo: Vec::new(),
        receiver_deltas: vec![ReceiverBalanceDelta {
            receiver_pk_g,
            amount: receiver_delta.clone(),
        }],
        channel_update_zkp: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof: Vec::new(),
        },
        transport_proof: Vec::new(),
        sender_hash_sig: Vec::new(),
        sender_pk_b: Bytes32::default(),
    };
    inter_channel_tx.tx_hash = inter_channel_tx
        .compute_tx_hash()
        .expect("canonical transaction hash");

    let descriptor = InterChannelTransferDescriptor {
        source_channel_id: source,
        destination_channel_id: destination,
        recipient_slot: 1,
        amount,
        tx_hash: inter_channel_tx.tx_hash,
        tx_tree_root,
        source_pk_g: inter_channel_tx.source_pk_g,
        receiver_pk_g,
        destination_base_transfer_salt: inter_channel_tx.destination_base_transfer_salt,
        source_pk: keys[0].regev_pk.clone(),
        receiver_pk: keys[1].regev_pk.clone(),
        sender_before_ct: RegevCiphertext::padding(),
        sender_after_ct: RegevCiphertext::padding(),
        sender_delta_ct: sender_delta,
        receiver_delta,
        inter_channel_tx,
        tx_v2,
        tx_v2_merkle_proof,
    };
    let debit_payload = InterChannelDebitPayload {
        sender_index: 0,
        proposed_next_state: signed_state.clone(),
        inter_channel_tx: descriptor.inter_channel_tx.clone(),
        amount,
        members: snapshot.members.clone(),
        record: snapshot.record.clone(),
        destination_recipient_pk: keys[1].regev_pk.clone(),
        aggregate_manifest: None,
    };
    (signed_state, debit_payload, descriptor)
}

fn next_offchain_state(
    keys: &[MemberKeys],
    previous: &ChannelState,
    small_block_delta: u64,
) -> ChannelState {
    let mut state = previous.clone();
    state.epoch = previous.epoch + 1;
    state.small_block_number = previous.small_block_number + small_block_delta;
    state.balance_state.state_version = previous.balance_state.state_version + 1;
    state.h2_tag = Bytes32::default();
    state.prev_digest = previous.digest;
    state.digest = Bytes32::default();
    state.member_signatures.clear();
    state = state.with_computed_digest();
    state.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| sign_state(keys, slot as u8, &state).expect("sign off-chain head"))
        .collect();
    state
}

#[test]
fn journal_restart_recovers_head_and_accepts_the_next_block() {
    let directory = TestDirectory::new("restart");
    let journal = directory.journal();
    let (keys, snapshot) = signed_snapshot(17);
    let (first_state, first_debit, first_descriptor) =
        next_descriptor(&keys, &snapshot, &snapshot.state, 0, 3);

    let first_receipt;
    let before_restart;
    {
        let mut service = BlockProducerService::open(&journal, &[2]).expect("new service");
        let registration = service
            .register("register-17".to_string(), snapshot.clone())
            .expect("durable registration");
        assert_eq!(registration.generation, 1);
        let (skipped_state, skipped_debit, skipped_descriptor) =
            next_descriptor(&keys, &snapshot, &snapshot.state, 1, 2);
        assert!(matches!(
            service.post_inter_channel(
                "post-17-skipped".to_string(),
                skipped_state,
                skipped_debit,
                skipped_descriptor,
            ),
            Err(BlockProducerServiceError::Producer(
                ProductionBlockProducerError::WalletAuthorization(message)
            )) if message.contains("expected 0")
        ));
        assert_eq!(
            service
                .status()
                .expect("rejection did not commit")
                .generation,
            1
        );
        first_receipt = service
            .post_inter_channel(
                "post-17-0".to_string(),
                first_state.clone(),
                first_debit.clone(),
                first_descriptor.clone(),
            )
            .expect("first durable post");
        assert_eq!(first_receipt.generation, 2);
        let retry = service
            .post_inter_channel(
                "post-17-0".to_string(),
                first_state.clone(),
                first_debit.clone(),
                first_descriptor.clone(),
            )
            .expect("same request is idempotent");
        assert_eq!(retry, first_receipt);
        assert!(matches!(
            service.post_inter_channel(
                "different-id".to_string(),
                first_state.clone(),
                first_debit.clone(),
                first_descriptor.clone(),
            ),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        before_restart = service.status().expect("status");
        assert!(!before_restart.holds_local_signing_keys);
        assert_eq!(before_restart.block_number, 2);
    }

    let mut service = BlockProducerService::open(&journal, &[2]).expect("semantic replay");
    assert_eq!(service.status().expect("recovered status"), before_restart);
    let (second_state, second_debit, second_descriptor) =
        next_descriptor(&keys, &snapshot, &first_state, 1, 4);
    let second = service
        .post_inter_channel(
            "post-17-1".to_string(),
            second_state,
            second_debit,
            second_descriptor,
        )
        .expect("next block after restart");
    assert_eq!(second.generation, 3);
    assert_eq!(second.block_number, 3);
    let final_status = service.status().expect("final status");
    assert_eq!(final_status.generation, 3);
    assert_ne!(final_status.bp_sig_chain, Bytes32::default());
    assert!(!final_status.holds_local_signing_keys);
    drop(service);

    let recovered = BlockProducerService::open(&journal, &[2]).expect("second replay");
    assert_eq!(
        recovered.status().expect("second recovered status"),
        final_status
    );
    let journal_text = fs::read_to_string(&journal).expect("journal is JSON");
    assert!(!journal_text.contains("local_test_signers"));
    assert!(!journal_text.contains("fixture_channel_keys"));
    assert!(!journal_text.contains("falcon_key"));
}

#[test]
fn l1_reconciled_deposit_is_durable_and_replay_fenced() {
    let directory = TestDirectory::new("deposit");
    let journal = directory.journal();
    let depositor = Address::from_u32_slice(&[0x4445_504f; 5]).expect("nonzero deposit address");
    let recipient = Bytes32::from_u32_slice(&[0x5245_4350; 8]).expect("deposit recipient");
    let canonical = Deposit {
        deposit_index: U63::new(0).expect("index"),
        depositor,
        recipient,
        token_index: 7,
        amount: U256::from(123u64),
        block_number: BlockNumber::new(1).expect("block"),
        aux_data: Bytes32::from_u32_slice(&[9; 8]).expect("aux"),
    };
    let request = ProductionDepositRequest {
        deposit_index: 0,
        depositor,
        recipient,
        token_index: canonical.token_index,
        amount: canonical.amount,
        aux_data: canonical.aux_data,
        expected_deposit_hash_chain: canonical.hash_with_prev_hash(Bytes32::default()),
    };

    let receipt;
    let durable_status;
    {
        let mut service = BlockProducerService::open(&journal, &[2]).expect("service");
        receipt = service
            .post_deposit("l1:0xabc:0".to_string(), request.clone())
            .expect("reconciled deposit");
        assert_eq!(receipt.generation, 1);
        assert_eq!(receipt.block_number, 1);
        assert_eq!(
            service
                .post_deposit("l1:0xabc:0".to_string(), request.clone())
                .expect("idempotent receipt"),
            receipt
        );
        assert!(matches!(
            service.post_deposit("replay-under-new-id".to_string(), request.clone()),
            Err(BlockProducerServiceError::Producer(
                ProductionBlockProducerError::WalletAuthorization(message)
            )) if message.contains("stale or skipped")
        ));
        durable_status = service.status().expect("status");
    }

    let service = BlockProducerService::open(&journal, &[2]).expect("semantic deposit replay");
    assert_eq!(service.status().expect("recovered status"), durable_status);
    assert_eq!(service.producer().expect("producer").block_number(), 1);
}

#[test]
fn offchain_heads_are_durable_contiguous_and_bridge_the_next_real_block() {
    let directory = TestDirectory::new("offchain-heads");
    let journal = directory.journal();
    let (keys, snapshot) = signed_snapshot(23);
    let first = next_offchain_state(&keys, &snapshot.state, 0);
    let second = next_offchain_state(&keys, &first, 1);

    let durable_status;
    {
        let mut service = BlockProducerService::open(&journal, &[2]).expect("service");
        service
            .register("register-23".to_string(), snapshot.clone())
            .expect("registration");

        let mut nonzero_h2 = first.clone();
        nonzero_h2.h2_tag = Bytes32::from_u32_slice(&[7; 8]).expect("nonzero H2");
        nonzero_h2.digest = Bytes32::default();
        nonzero_h2.member_signatures.clear();
        nonzero_h2 = nonzero_h2.with_computed_digest();
        nonzero_h2.member_signatures = keys
            .iter()
            .enumerate()
            .map(|(slot, keys)| {
                sign_state(keys, slot as u8, &nonzero_h2).expect("sign invalid H2 state")
            })
            .collect();
        assert!(matches!(
            service.sync_offchain_heads("bad-h2".to_string(), vec![nonzero_h2]),
            Err(BlockProducerServiceError::Producer(
                ProductionBlockProducerError::WalletAuthorization(message)
            )) if message.contains("non-zero h2_tag")
        ));
        assert_eq!(service.status().expect("unchanged status").generation, 1);

        let first_receipt = service
            .sync_offchain_heads("sync-23-1".to_string(), vec![first.clone()])
            .expect("first off-chain head");
        assert_eq!(first_receipt.generation, 2);
        assert_eq!(first_receipt.block_number, 1);
        let second_receipt = service
            .sync_offchain_heads("sync-23-2".to_string(), vec![second.clone()])
            .expect("second off-chain head in the same wall-clock interval");
        assert_eq!(second_receipt.generation, 3);
        assert_eq!(second_receipt.block_number, 1);
        assert_eq!(
            service
                .sync_offchain_heads("sync-23-2".to_string(), vec![second.clone()])
                .expect("idempotent sync"),
            second_receipt
        );
        assert!(matches!(
            service.sync_offchain_heads("duplicate-head".to_string(), vec![second.clone()]),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        durable_status = service.status().expect("durable sync status");
        assert_eq!(durable_status.channel_heads[0].state_digest, second.digest);
    }

    let mut recovered =
        BlockProducerService::open(&journal, &[2]).expect("replay two journal-only actions");
    assert_eq!(
        recovered.status().expect("recovered status"),
        durable_status
    );
    let (posted, debit, descriptor) = next_descriptor(&keys, &snapshot, &second, 0, 5);
    let receipt = recovered
        .post_inter_channel("post-after-sync".to_string(), posted, debit, descriptor)
        .expect("next real block extends the synchronized head");
    assert_eq!(receipt.generation, 4);
    assert_eq!(receipt.block_number, 2);
}

#[test]
fn corrupt_and_truncated_journals_fail_closed() {
    for (label, mutate) in [("truncated", 0u8), ("corrupt", 1u8)] {
        let directory = TestDirectory::new(label);
        let journal = directory.journal();
        let service = BlockProducerService::open(&journal, &[2]).expect("create journal");
        drop(service);
        let mut bytes = fs::read(&journal).expect("read journal");
        if mutate == 0 {
            bytes.truncate(bytes.len() / 2);
        } else {
            let position = bytes
                .iter()
                .position(|byte| *byte == b'I')
                .expect("journal magic byte");
            bytes[position] ^= 1;
        }
        fs::write(&journal, bytes).expect("damage isolated journal");
        assert!(matches!(
            BlockProducerService::open(&journal, &[2]),
            Err(BlockProducerServiceError::Journal(_))
        ));
    }
}

#[test]
fn a_second_daemon_cannot_share_the_journal() {
    let directory = TestDirectory::new("lock");
    let journal = directory.journal();
    let first = BlockProducerService::open(&journal, &[2]).expect("first owner");
    assert!(matches!(
        BlockProducerService::open(&journal, &[2]),
        Err(BlockProducerServiceError::Locked(_))
    ));
    drop(first);
    BlockProducerService::open(&journal, &[2]).expect("lock released on drop");
}
