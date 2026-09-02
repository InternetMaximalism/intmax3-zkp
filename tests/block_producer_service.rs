use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "deprecated-msu")]
use intmax3_zkp::common::tx::TxV2;
#[cfg(feature = "deprecated-msu")]
#[allow(deprecated)]
use intmax3_zkp::wallet_core::{
    canonical_member_set_update_action_index, canonical_member_set_update_block,
    cosign_member_set_update, member_set_update_block_root, propose_rotate_key,
    registered_cosigner_leaves, registered_cosigner_root_hash, verify_member_set_update,
};
use intmax3_zkp::{
    block_producer::{
        ProductionBlockProducer, ProductionBlockProducerError, ProductionDepositRequest,
    },
    block_producer_service::{
        BlockProducerCommand, BlockProducerService, BlockProducerServiceError,
    },
    circuits::witness::block_witness_generator::BlockTxV2Witness,
    close_funding::build_close_funding_proposal,
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

fn signed_close_funding(
    keys: &[MemberKeys],
    previous: &ChannelState,
) -> (ChannelState, intmax3_zkp::close_funding::CloseFundingPlan) {
    let rollup = Address::from_u32_slice(&[0x524f_4c4c; 5]).expect("rollup");
    let manager = Address::from_u32_slice(&[0x4d41_4e47; 5]).expect("manager");
    let proposal = build_close_funding_proposal(previous, 1, rollup, manager, 0)
        .expect("canonical close funding");
    let mut state = proposal.proposed_state;
    state.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| sign_state(keys, slot as u8, &state).expect("sign close funding"))
        .collect();
    (state, proposal.plan)
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
fn close_funding_prepare_is_durable_frozen_and_exactly_committed() {
    let directory = TestDirectory::new("close-funding-two-phase");
    let journal = directory.journal();
    let (keys, snapshot) = signed_snapshot(29);
    let (signed_state, plan) = signed_close_funding(&keys, &snapshot.state);
    let (inter_state, inter_debit, inter_descriptor) =
        next_descriptor(&keys, &snapshot, &snapshot.state, 0, 3);
    let later = next_offchain_state(&keys, &snapshot.state, 0);
    let (_, other_snapshot) = signed_snapshot(30);
    let frozen_deposit = ProductionDepositRequest {
        deposit_index: 0,
        depositor: Address::from_u32_slice(&[0x4445_504f; 5]).expect("depositor"),
        recipient: Bytes32::from_u32_slice(&[0x5245_4350; 8]).expect("recipient"),
        token_index: 0,
        amount: U256::from(1u64),
        aux_data: Bytes32::default(),
        expected_deposit_hash_chain: Bytes32::default(),
    };

    let authoritative_before;
    let prepared_receipt;
    let prepared_anchor;
    {
        let mut service = BlockProducerService::open(&journal, &[2]).expect("service");
        let register_receipt = service
            .register("register-29".to_string(), snapshot.clone())
            .expect("register");
        authoritative_before = service.status().expect("authoritative before prepare");
        let authoritative_anchor = service.current_anchor().expect("authoritative anchor");
        assert_eq!(
            service
                .committed_receipt_at_anchor(&authoritative_anchor)
                .expect("ordinary canonical receipt lookup"),
            Some(register_receipt)
        );
        assert!(matches!(
            service.commit_prepared_close_funding_at_anchor(&authoritative_anchor),
            Err(BlockProducerServiceError::Conflict(reason))
                if reason.contains("not a terminal close-funding")
        ));

        assert!(matches!(
            service.post_close_funding(
                "legacy-immediate".to_string(),
                signed_state.clone(),
                plan.clone(),
            ),
            Err(BlockProducerServiceError::InvalidRequest(reason))
                if reason.contains("prepare_close_funding")
        ));
        assert!(matches!(
            service.execute(BlockProducerCommand::PostCloseFunding {
                request_id: "legacy-command".to_string(),
                signed_state: signed_state.clone(),
                plan: plan.clone(),
            }),
            Err(BlockProducerServiceError::InvalidRequest(reason))
                if reason.contains("prepare_close_funding")
        ));

        prepared_receipt = service
            .prepare_close_funding(
                "close-funding-29".to_string(),
                signed_state.clone(),
                plan.clone(),
            )
            .expect("durable prepare");
        prepared_anchor = service
            .prepared_anchor()
            .expect("prepared anchor read")
            .expect("prepared anchor");
        assert_eq!(
            prepared_receipt.generation,
            authoritative_before.generation + 1
        );
        assert_eq!(
            prepared_receipt.block_number,
            authoritative_before.block_number + 1
        );
        assert_eq!(prepared_anchor.generation, prepared_receipt.generation);
        assert_eq!(prepared_anchor.entry_hash, prepared_receipt.entry_hash);
        assert_eq!(
            prepared_anchor.extended_state_commitment,
            prepared_receipt.extended_state_commitment
        );
        assert_eq!(service.status().unwrap(), authoritative_before);
        assert_eq!(service.current_anchor().unwrap(), authoritative_anchor);
        assert_eq!(service.producer().unwrap().block_number(), 1);
        assert_eq!(
            service
                .prepared_producer()
                .unwrap()
                .expect("borrowed candidate")
                .block_number(),
            2
        );
        assert_eq!(
            service
                .prepared_producer_clone()
                .unwrap()
                .expect("candidate")
                .block_number(),
            2
        );
        assert_eq!(
            service.prepared_receipt().unwrap(),
            Some(prepared_receipt.clone())
        );
        assert_eq!(
            service
                .prepared_receipt_for_close_funding("close-funding-29", &signed_state, &plan)
                .unwrap(),
            Some(prepared_receipt.clone())
        );
        assert_eq!(
            service
                .prepare_close_funding(
                    "close-funding-29".to_string(),
                    signed_state.clone(),
                    plan.clone(),
                )
                .expect("exact prepare is idempotent"),
            prepared_receipt
        );

        let mut changed = plan.clone();
        changed.transfers[0].amount += U256::from(1u64);
        assert!(matches!(
            service.prepare_close_funding(
                "close-funding-29".to_string(),
                signed_state.clone(),
                changed,
            ),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        assert!(matches!(
            service.prepare_close_funding(
                "sibling-close".to_string(),
                signed_state.clone(),
                plan.clone(),
            ),
            Err(BlockProducerServiceError::Conflict(_))
        ));

        // A prepared terminal mutation freezes every other producer mutation, including one that
        // reuses the prepared request id under a different action kind.
        assert!(matches!(
            service.register(
                "register-while-prepared".to_string(),
                other_snapshot.clone()
            ),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        assert!(matches!(
            service.post_deposit("close-funding-29".to_string(), frozen_deposit),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        assert!(matches!(
            service.sync_offchain_heads("sync-while-prepared".to_string(), vec![later.clone()]),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        assert!(matches!(
            service.post_inter_channel(
                "inter-while-prepared".to_string(),
                inter_state,
                inter_debit,
                inter_descriptor,
            ),
            Err(BlockProducerServiceError::Conflict(_))
        ));
        assert_eq!(service.status().unwrap(), authoritative_before);

        let disk: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).expect("prepared journal JSON");
        assert_eq!(
            disk["generation"],
            serde_json::json!(authoritative_before.generation)
        );
        assert_eq!(disk["entries"].as_array().unwrap().len(), 1);
        assert!(!disk["prepared"].is_null());
    }

    // Simulated crash/restart: startup semantically replays both the authoritative prefix and the
    // separate candidate, without advancing the authoritative producer.
    let mut service = BlockProducerService::open(&journal, &[2]).expect("restart with prepare");
    assert_eq!(service.status().unwrap(), authoritative_before);
    assert_eq!(
        service.prepared_receipt().unwrap(),
        Some(prepared_receipt.clone())
    );
    assert_eq!(
        service.prepared_anchor().unwrap(),
        Some(prepared_anchor.clone())
    );
    assert_eq!(service.producer().unwrap().block_number(), 1);
    assert_eq!(
        service
            .prepared_producer_clone()
            .unwrap()
            .expect("replayed candidate")
            .block_number(),
        2
    );

    let mut wrong_plan = plan.clone();
    wrong_plan.transfers[0].amount += U256::from(1u64);
    assert!(matches!(
        service.commit_prepared_close_funding(
            "close-funding-29".to_string(),
            &signed_state,
            &wrong_plan,
            &prepared_anchor,
        ),
        Err(BlockProducerServiceError::Conflict(_))
    ));
    let mut wrong_anchor = prepared_anchor.clone();
    wrong_anchor.entry_hash = Bytes32::default();
    assert!(matches!(
        service.commit_prepared_close_funding_at_anchor(&wrong_anchor),
        Err(BlockProducerServiceError::Conflict(_))
    ));

    let committed = service
        .commit_prepared_close_funding_at_anchor(&prepared_anchor)
        .expect("exact prepared commit");
    assert_eq!(committed, prepared_receipt);
    assert_eq!(service.status().unwrap().generation, committed.generation);
    assert_eq!(service.status().unwrap().block_number, 2);
    assert_eq!(service.producer().unwrap().block_number(), 2);
    assert_eq!(service.prepared_receipt().unwrap(), None);
    assert_eq!(service.prepared_anchor().unwrap(), None);
    assert!(service.prepared_producer_clone().unwrap().is_none());
    assert_eq!(
        service
            .committed_receipt_for_close_funding_at_anchor(
                "close-funding-29",
                &signed_state,
                &plan,
                &prepared_anchor,
            )
            .unwrap(),
        Some(committed.clone())
    );
    assert_eq!(
        service
            .commit_prepared_close_funding_at_anchor(&prepared_anchor)
            .expect("commit replay is idempotent"),
        committed
    );
    assert_eq!(
        service
            .committed_receipt_at_anchor(&prepared_anchor)
            .expect("anchor-only committed replay"),
        Some(committed.clone())
    );
    assert_eq!(
        service
            .prepare_close_funding(
                "close-funding-29".to_string(),
                signed_state.clone(),
                plan.clone(),
            )
            .expect("prepare replay discovers committed receipt"),
        committed
    );

    assert!(matches!(
        service.sync_offchain_heads("after-terminal".to_string(), vec![later]),
        Err(BlockProducerServiceError::Producer(
            ProductionBlockProducerError::WalletAuthorization(message)
        )) if message.contains("terminal")
    ));

    // The terminal channel stays frozen, but unrelated channels are allowed to advance the
    // global producer after commit. The exact historical witness remains reconstructible for
    // terminal withdrawal proofs and cannot be substituted with a sibling/future anchor.
    service
        .register("register-other-after-terminal".to_string(), other_snapshot)
        .expect("an unrelated channel may advance after terminal commit");
    assert_eq!(
        service.status().unwrap().generation,
        committed.generation + 1
    );
    assert_eq!(
        service.status().unwrap().block_number,
        committed.block_number + 1
    );
    let historical = service
        .producer_at_anchor(&prepared_anchor)
        .expect("replay exact terminal anchor");
    assert_eq!(historical.block_number(), committed.block_number);
    assert_eq!(
        historical
            .witness_handle()
            .expect("historical public witness")
            .borrow()
            .current_extended_public_state()
            .commitment(),
        committed.extended_state_commitment
    );
    let mut sibling_anchor = prepared_anchor.clone();
    sibling_anchor.entry_hash = Bytes32::default();
    assert!(matches!(
        service.producer_at_anchor(&sibling_anchor),
        Err(BlockProducerServiceError::Conflict(_))
    ));
    drop(service);

    let recovered = BlockProducerService::open(&journal, &[2]).expect("terminal replay");
    assert_eq!(
        recovered
            .committed_receipt_for_close_funding_at_anchor(
                "close-funding-29",
                &signed_state,
                &plan,
                &prepared_anchor,
            )
            .expect("replayed exact committed receipt"),
        Some(committed)
    );
}

fn prepared_journal(label: &str) -> (TestDirectory, PathBuf) {
    let directory = TestDirectory::new(label);
    let journal = directory.journal();
    let (keys, snapshot) = signed_snapshot(31);
    let (signed_state, plan) = signed_close_funding(&keys, &snapshot.state);
    let mut service = BlockProducerService::open(&journal, &[2]).expect("service");
    service
        .register("register-31".to_string(), snapshot)
        .expect("registration");
    service
        .prepare_close_funding("prepare-31".to_string(), signed_state, plan)
        .expect("prepare");
    drop(service);
    (directory, journal)
}

#[test]
fn prepared_journal_metadata_and_semantic_result_tampering_fail_closed() {
    let (_directory, journal) = prepared_journal("prepared-tampering");
    let canonical: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal).expect("read prepared journal"))
            .expect("parse prepared journal");
    for (label, expected, mutate) in [
        ("prepared-generation", "generation", 0u8),
        ("prepared-prev", "previous-hash", 1u8),
        ("prepared-fingerprint", "fingerprint", 2u8),
        ("prepared-timestamp", "timestamp", 3u8),
        ("prepared-result", "hash", 4u8),
        ("prepared-entry-hash", "hash", 5u8),
    ] {
        let mut disk = canonical.clone();
        match mutate {
            0 => disk["prepared"]["generation"] = disk["generation"].clone(),
            1 => {
                disk["prepared"]["prevEntryHash"] =
                    serde_json::to_value(Bytes32::default()).unwrap()
            }
            2 => {
                disk["prepared"]["requestFingerprint"] =
                    serde_json::to_value(Bytes32::default()).unwrap()
            }
            3 => disk["prepared"]["action"]["timestamp"] = serde_json::json!(0),
            4 => {
                let block = disk["prepared"]["result"]["blockNumber"]
                    .as_u64()
                    .expect("candidate block number");
                disk["prepared"]["result"]["blockNumber"] = serde_json::json!(block + 1);
            }
            5 => disk["prepared"]["entryHash"] = serde_json::to_value(Bytes32::default()).unwrap(),
            _ => unreachable!(),
        }
        fs::write(&journal, serde_json::to_vec(&disk).unwrap()).expect("write tampered journal");
        match BlockProducerService::open(&journal, &[2]) {
            Err(BlockProducerServiceError::Journal(reason)) => {
                assert!(reason.contains(expected), "{label}: {reason}");
            }
            Err(other) => panic!("{label}: unexpected error {other}"),
            Ok(_) => panic!("{label}: tampered prepared entry was accepted"),
        }
    }
}

#[test]
fn journal_v1_without_prepared_field_remains_compatible() {
    let directory = TestDirectory::new("journal-v1-no-prepared");
    let journal = directory.journal();
    let (_, snapshot) = signed_snapshot(32);
    let expected;
    {
        let mut service = BlockProducerService::open(&journal, &[2]).expect("service");
        service
            .register("register-32".to_string(), snapshot)
            .expect("registration");
        expected = service.status().expect("status");
    }
    let mut disk: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal).unwrap()).expect("journal JSON");
    assert!(disk.get("prepared").is_some());
    disk.as_object_mut()
        .expect("journal object")
        .remove("prepared");
    fs::write(&journal, serde_json::to_vec(&disk).unwrap()).expect("legacy v1 journal");
    let recovered = BlockProducerService::open(&journal, &[2]).expect("legacy v1 replay");
    assert_eq!(recovered.status().unwrap(), expected);
    assert_eq!(recovered.prepared_receipt().unwrap(), None);
}

#[test]
fn uncertain_commit_persistence_poisons_the_live_service() {
    let directory = TestDirectory::new("prepared-commit-poison");
    let journal = directory.journal();
    let (keys, snapshot) = signed_snapshot(33);
    let (signed_state, plan) = signed_close_funding(&keys, &snapshot.state);
    let mut service = BlockProducerService::open(&journal, &[2]).expect("service");
    service
        .register("register-33".to_string(), snapshot)
        .expect("registration");
    service
        .prepare_close_funding("prepare-33".to_string(), signed_state.clone(), plan.clone())
        .expect("prepare");
    let anchor = service.prepared_anchor().unwrap().expect("prepared anchor");

    // Removing the parent makes the commit's create/rename/fsync sequence fail. The service must
    // not guess whether its durable name advanced; every subsequent read/mutation is poisoned.
    fs::remove_dir_all(&directory.0).expect("remove journal parent");
    assert!(matches!(
        service.commit_prepared_close_funding_at_anchor(&anchor),
        Err(BlockProducerServiceError::Journal(_))
    ));
    assert!(matches!(
        service.status(),
        Err(BlockProducerServiceError::Poisoned)
    ));
    assert!(matches!(
        service.prepared_producer_clone(),
        Err(BlockProducerServiceError::Poisoned)
    ));
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

/// Release gate: even a structurally valid, fully N-of-N-authorized update must not advance the
/// validity-side registry while the settlement manager's member set is immutable. The direct
/// producer API, typed service API, command dispatcher and legacy journal replay all fail closed.
#[test]
fn retired_member_set_update_has_only_fail_closed_tombstones() {
    let directory = TestDirectory::new("retired-member-set-update");
    let journal = directory.journal();
    let (_keys, snapshot) = signed_snapshot(21);
    let mut service = BlockProducerService::open(&journal, &[2]).expect("new service");
    service
        .register("register-21".to_string(), snapshot.clone())
        .expect("register");
    let before = service.status().expect("status before retired request");

    let refused = service.post_member_set_update(
        "retired-msu".to_string(),
        snapshot.state.clone(),
        snapshot.members.clone(),
        snapshot.record.clone(),
        snapshot.members.clone(),
    );
    assert!(matches!(
        refused,
        Err(BlockProducerServiceError::InvalidRequest(ref reason))
            if reason.contains("retired")
    ));
    assert_eq!(service.status().unwrap(), before);

    let command_refused = service.execute(BlockProducerCommand::PostMemberSetUpdate {
        request_id: "retired-msu-command".to_string(),
        signed_state: snapshot.state.clone(),
        old_members: snapshot.members.clone(),
        new_record: snapshot.record.clone(),
        new_members: snapshot.members.clone(),
    });
    assert!(matches!(
        command_refused,
        Err(BlockProducerServiceError::InvalidRequest(ref reason))
            if reason.contains("retired")
    ));
    assert_eq!(service.status().unwrap(), before);

    let mut producer = ProductionBlockProducer::new(&[2]);
    producer
        .register_snapshot(&snapshot, 1)
        .expect("register producer");
    let block_before = producer.block_number();
    assert!(matches!(
        producer.produce_member_set_update_block(
            &snapshot.state,
            &snapshot.members,
            &snapshot.record,
            &snapshot.members,
            2,
        ),
        Err(ProductionBlockProducerError::MemberSetUpdateRetired)
    ));

    // The low-level witness marker remains reserved so a legacy/raw caller cannot bypass the
    // named tombstone. Rejection happens before signatures, proving, or head mutation.
    let raw_reserved = BlockTxV2Witness {
        tx_v2_indices: Vec::new(),
        tx_v2s: Vec::new(),
        tx_v2_merkle_proofs: Vec::new(),
        new_member_leaves: Some(Vec::new()),
        channel_action_indices: None,
        channel_actions: None,
        channel_action_merkle_proofs: None,
    };
    assert!(matches!(
        producer.produce_cosigned_block(&snapshot.state, &[], 2, Bytes32::default(), raw_reserved,),
        Err(ProductionBlockProducerError::MemberSetUpdateRetired)
    ));
    assert_eq!(producer.block_number(), block_before);
}

#[cfg(feature = "deprecated-msu")]
#[test]
fn member_set_update_is_disabled_across_all_production_paths() {
    let directory = TestDirectory::new("member-set-update");
    let journal = directory.journal();
    let (keys, snapshot) = signed_snapshot(21);
    let mut service = BlockProducerService::open(&journal, &[2]).expect("new service");
    service
        .register("register-21".to_string(), snapshot.clone())
        .expect("register");

    // Wallet layer: slot 1 rotates to a fresh key — IMKR self-consent + the OLD set's full
    // N-of-N over IMMS, exactly the ChannelSafetyQ-verified gate.
    let mut rng = rand010::rngs::StdRng::seed_from_u64(0xEE21);
    let new_keys = MemberKeys::generate(&mut rng);
    let mut update =
        propose_rotate_key(&keys[1], &new_keys, &snapshot.record, &snapshot.members, 1)
            .expect("propose");
    update.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, k)| cosign_member_set_update(k, slot as u8, &update))
        .collect();
    let (new_record, new_members) =
        verify_member_set_update(&snapshot.record, &snapshot.members, &update)
            .expect("wallet gate accepts the rotation");

    // The OLD set signs a state whose h2_tag commits the canonical update-block root.
    let root = member_set_update_block_root(
        &snapshot.record,
        &snapshot.members,
        &new_record,
        &new_members,
    )
    .expect("canonical block root");
    let mut state = snapshot.state.clone();
    state.epoch += 1;
    state.small_block_number += 1;
    state.balance_state.state_version += 1;
    state.h2_tag = root;
    state.prev_digest = snapshot.state.digest;
    state.member_signatures.clear();
    state = state.with_computed_digest();
    state.member_signatures = keys
        .iter()
        .enumerate()
        .map(|(slot, k)| sign_state(k, slot as u8, &state).expect("old set signs the update"))
        .collect();

    let before_service = service.status().expect("status before refused update");
    let refused = service.post_member_set_update(
        "msu-21-0".to_string(),
        state.clone(),
        snapshot.members.clone(),
        new_record.clone(),
        new_members.clone(),
    );
    assert!(matches!(
        refused,
        Err(BlockProducerServiceError::InvalidRequest(ref reason))
            if reason.contains("disabled in this release")
    ));
    assert_eq!(
        service.status().expect("status after refused update"),
        before_service,
        "typed service rejection must not mutate the journal or producer head"
    );

    let command_refused = service.execute(BlockProducerCommand::PostMemberSetUpdate {
        request_id: "msu-21-command".to_string(),
        signed_state: state.clone(),
        old_members: snapshot.members.clone(),
        new_record: new_record.clone(),
        new_members: new_members.clone(),
    });
    assert!(matches!(
        command_refused,
        Err(BlockProducerServiceError::InvalidRequest(ref reason))
            if reason.contains("disabled in this release")
    ));
    assert_eq!(service.status().unwrap(), before_service);

    let mut producer = ProductionBlockProducer::new(&[2]);
    producer
        .register_snapshot(&snapshot, 1)
        .expect("direct producer registration");
    let direct_before = (
        producer.block_number(),
        producer.last_timestamp(),
        producer.current_extended_public_state().commitment(),
        producer.channel_heads(),
    );
    let direct_refused = producer.produce_member_set_update_block(
        &state,
        &snapshot.members,
        &new_record,
        &new_members,
        2,
    );
    assert!(matches!(
        direct_refused,
        Err(ProductionBlockProducerError::MemberSetUpdateRetired)
    ));
    assert_eq!(
        (
            producer.block_number(),
            producer.last_timestamp(),
            producer.current_extended_public_state().commitment(),
            producer.channel_heads(),
        ),
        direct_before,
        "direct producer rejection must leave every public head unchanged"
    );

    // Attack the generic lower-level facade directly. Before the release gate was duplicated at
    // this boundary, a caller could skip `produce_member_set_update_block`, embed the canonical
    // MSU action/new leaves in a caller-built BlockTxV2Witness, and advance the validity member
    // root despite every named MSU entry point returning Disabled.
    let prev_root = registered_cosigner_root_hash(&snapshot.record, &snapshot.members)
        .expect("old registered root");
    let next_root =
        registered_cosigner_root_hash(&new_record, &new_members).expect("new registered root");
    let (action, action_tree, tx_v2, tx_v2_tree, smuggled_root) =
        canonical_member_set_update_block(snapshot.record.channel_id, prev_root, next_root);
    assert_eq!(
        smuggled_root, root,
        "attack witness must be the signed MSU block"
    );
    let tx_v2_proof = tx_v2_tree.prove(snapshot.record.channel_id.as_u64());
    let action_index = canonical_member_set_update_action_index();
    let action_proof = action_tree.prove(action_index);
    let new_leaves =
        registered_cosigner_leaves(&new_record, &new_members).expect("new registered leaves");
    let smuggled_witness = BlockTxV2Witness {
        tx_v2_indices: vec![snapshot.record.channel_id.as_u64(), 0],
        tx_v2s: vec![tx_v2, TxV2::default()],
        tx_v2_merkle_proofs: vec![tx_v2_proof; 2],
        new_member_leaves: Some(new_leaves),
        channel_action_indices: Some(vec![action_index; 2]),
        channel_actions: Some(vec![action; 2]),
        channel_action_merkle_proofs: Some(vec![action_proof; 2]),
    };
    let mut action_only = smuggled_witness.clone();
    action_only.new_member_leaves = None;
    let mut leaves_only = smuggled_witness.clone();
    leaves_only.channel_actions = None;
    for attack_witness in [smuggled_witness, action_only, leaves_only] {
        let smuggled_refused =
            producer.produce_cosigned_block(&state, &[1], 2, smuggled_root, attack_witness);
        assert!(matches!(
            smuggled_refused,
            Err(ProductionBlockProducerError::MemberSetUpdateRetired)
        ));
    }
    assert_eq!(
        (
            producer.block_number(),
            producer.last_timestamp(),
            producer.current_extended_public_state().commitment(),
            producer.channel_heads(),
        ),
        direct_before,
        "generic facade rejection must leave every public head unchanged"
    );

    // Simulate an authenticated journal written by an older release. Startup must identify the
    // disabled action before replaying it; it must never silently advance the validity registry.
    drop(service);
    let mut disk: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal).expect("read journal")).expect("parse journal");
    let first_entry = disk["entries"][0].clone();
    let legacy_entry = serde_json::json!({
        "generation": 2,
        "requestId": "legacy-msu-21",
        "requestFingerprint": Bytes32::default(),
        "prevEntryHash": Bytes32::default(),
        "action": {
            "kind": "postMemberSetUpdate",
            "signed_state": state,
            "old_members": snapshot.members,
            "new_record": new_record,
            "new_members": new_members,
            "timestamp": 2
        },
        "result": first_entry["result"].clone(),
        "entryHash": Bytes32::default()
    });
    disk["generation"] = serde_json::json!(2);
    disk["entries"]
        .as_array_mut()
        .expect("journal entries")
        .push(legacy_entry);
    fs::write(&journal, serde_json::to_vec_pretty(&disk).unwrap()).expect("write legacy journal");

    match BlockProducerService::open(&journal, &[2]) {
        Err(BlockProducerServiceError::Journal(reason)) => {
            assert!(
                reason.contains("disabled legacy member-set update"),
                "{reason}"
            );
        }
        Err(other) => panic!("unexpected legacy replay error: {other}"),
        Ok(_) => panic!("legacy member-set update journal must fail closed at startup"),
    }
}
