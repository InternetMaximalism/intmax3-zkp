use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use intmax3_zkp::{
    block_producer_service::BlockProducerService,
    common::{
        balance_state::{settled_tx_chain_push, tx_leaf_hash},
        channel::{
            ChannelProofEnvelope, ChannelState, InterChannelTx, MemberSignature,
            MerkleInclusionProof, ProofBackend, ReceiverBalanceDelta, SignedSmallBlock,
            SmallBlockRootMessage, TransitionProofRole,
        },
        channel_id::ChannelId,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    regev::RegevCiphertext,
    validity_prover_service::{
        L1ValidityAcknowledgement, ValidityProverService, ValidityProverServiceError,
    },
    wallet_core::{
        assemble_genesis_state, build_record, default_settled_tx_accumulator,
        inter_channel_base_transfer, inter_channel_tx_v2, sign_state, ChannelSnapshot,
        InterChannelDebitPayload, InterChannelTransferDescriptor, MemberInfo, MemberKeys,
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
        let path = std::env::temp_dir().join(format!(
            "intmax-validity-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn producer_journal(&self) -> PathBuf {
        self.0.join("producer.json")
    }

    fn prover_snapshot(&self) -> PathBuf {
        self.0.join("validity.snapshot")
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
    let mut rng = rand010::rngs::StdRng::seed_from_u64(0x5650_0000 + channel as u64);
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
            Address::from_u32_slice(&[0x5650_0000 + slot as u32; 5]).expect("nonzero recipient")
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
    let transfer = inter_channel_base_transfer(base_recipient, 0, 1, tx_leaf);
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
        .map(|(slot, keys)| sign_state(keys, slot as u8, &signed_state).expect("sign next state"))
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
        amount: 1,
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
    let debit = InterChannelDebitPayload {
        sender_index: 0,
        proposed_next_state: signed_state.clone(),
        inter_channel_tx: descriptor.inter_channel_tx.clone(),
        amount: 1,
        members: snapshot.members.clone(),
        record: snapshot.record.clone(),
        destination_recipient_pk: keys[1].regev_pk.clone(),
    };
    (signed_state, debit, descriptor)
}

fn acknowledgement(tag: u32, commitment: Bytes32) -> L1ValidityAcknowledgement {
    L1ValidityAcknowledgement {
        chain_id: 31_337,
        transaction_hash: Bytes32::from_u32_slice(&[tag; 8]).expect("tx hash"),
        block_number: tag as u64,
        final_extended_state_commitment: commitment,
    }
}

#[cfg_attr(debug_assertions, ignore = "run with --release")]
#[test]
fn resident_prover_recovers_candidate_and_proves_two_independent_spans() {
    let directory = TestDirectory::new("two-span");
    let journal = directory.producer_journal();
    let snapshot_path = directory.prover_snapshot();
    let prover_address =
        Address::from_u32_slice(&[0x5650_5256; 5]).expect("nonzero prover address");
    let (keys, channel_snapshot) = signed_snapshot(41);
    let mut producer = BlockProducerService::open(&journal, &[2]).expect("producer");
    producer
        .register("register-41".into(), channel_snapshot.clone())
        .expect("registration block");
    let (first_state, first_debit, first_descriptor) =
        next_descriptor(&keys, &channel_snapshot, &channel_snapshot.state, 0);
    producer
        .post_inter_channel(
            "post-41-0".into(),
            first_state.clone(),
            first_debit,
            first_descriptor,
        )
        .expect("first signing block");

    let mut validity =
        ValidityProverService::initialize(&snapshot_path, &[2], prover_address, &producer)
            .expect("initialize resident circuits once");
    assert_eq!(
        validity
            .status()
            .expect("status")
            .circuit_construction_count,
        1
    );
    let first = validity
        .prove_candidate("validity-span-1".into(), &producer)
        .expect("first candidate");
    assert_eq!(first.initial_block_number, 0);
    assert_eq!(first.final_block_number, 2);
    assert_eq!(first.signature_event_count, 1);
    assert_eq!(first.metrics.appended_signature_event_count, 1);
    assert!(first.metrics.aggregate_list_proof_bytes > 0);
    assert!(first.metrics.validity_proof_bytes > 0);
    assert_eq!(
        validity
            .prove_candidate("validity-span-1".into(), &producer)
            .expect("candidate request id is idempotent"),
        first
    );
    assert_eq!(validity.status().expect("status").finalized_block_number, 0);

    // The on-chain finalize payload: wrapped validity MLE + vpis in the schema `finalize()`
    // parses. The final state root is the candidate's committed final ext-commitment — the value
    // a later withdrawNative binds against.
    let fin = validity
        .finalize_artifact()
        .expect("finalize artifact")
        .expect("a candidate exists");
    assert_eq!(fin.final_state_root, first.final_extended_state_commitment);
    let vpis: serde_json::Value =
        serde_json::from_str(&fin.vpis_json).expect("vpis json parses");
    assert_eq!(vpis["final_block_number"].as_u64().unwrap(), 2);
    assert_eq!(
        vpis["final_ext_commitment"].as_str().unwrap(),
        first.final_extended_state_commitment.to_string()
    );
    assert_eq!(
        vpis["prover"].as_str().unwrap(),
        prover_address.to_string()
    );
    assert!(
        fin.validity_mle_json.len() > 100_000,
        "a real validity MLE/WHIR proof was exported"
    );
    // ON-CHAIN FINALIZE COMPATIBILITY: the wrapped validity VK must equal the one the rollup is
    // deployed with (mle_fixture.json). `MleFinalizeE2ETest` already proves that fixture finalizes
    // on a real MleVerifier; matching its VK params here is what lets a LIVE-produced validity MLE
    // take the same path. circuitDigest and preprocessedCommitmentRoot are structural — they depend
    // on the wrapper circuit, not on the proven span — so they must match despite different spans.
    {
        let live: serde_json::Value =
            serde_json::from_str(&fin.validity_mle_json).expect("live validity mle json");
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("contracts/test/data/mle_fixture.json");
        if let Ok(fixture_str) = std::fs::read_to_string(&fixture_path) {
            let fixture: serde_json::Value =
                serde_json::from_str(&fixture_str).expect("mle_fixture.json");
            assert_eq!(
                live["circuitDigest"], fixture["circuitDigest"],
                "live validity VK circuitDigest diverged from the deployed rollup's (mle_fixture)"
            );
            assert_eq!(
                live["preprocessedCommitmentRoot"], fixture["preprocessedCommitmentRoot"],
                "live validity VK preprocessedCommitmentRoot diverged from mle_fixture"
            );
            assert_eq!(live["degreeBits"], fixture["degreeBits"]);
            assert_eq!(live["numRoutedWires"], fixture["numRoutedWires"]);
            eprintln!("[finalize] live validity VK matches the deployed rollup VK (mle_fixture)");
        } else {
            eprintln!("[finalize] mle_fixture.json absent — skipping the on-chain VK-match guard");
        }
    }

    drop(validity);
    let mut validity = ValidityProverService::open(&snapshot_path, &[2], prover_address, &producer)
        .expect("restart verifies pending candidate and all proofs");
    assert_eq!(
        validity
            .status()
            .expect("status")
            .circuit_construction_count,
        1
    );
    assert_eq!(
        validity
            .prove_candidate("validity-span-1".into(), &producer)
            .expect("restart preserves candidate idempotence"),
        first
    );
    let first_final = validity
        .acknowledge_candidate_unchecked_for_test(
            "ack-span-1".into(),
            first.candidate_id,
            acknowledgement(1, first.final_extended_state_commitment),
            &producer,
        )
        .expect("L1 ack advances finalized cursor");
    assert_eq!(first_final.finalized_block_number, 2);

    let (second_state, second_debit, second_descriptor) =
        next_descriptor(&keys, &channel_snapshot, &first_state, 1);
    producer
        .post_inter_channel(
            "post-41-1".into(),
            second_state,
            second_debit,
            second_descriptor,
        )
        .expect("second signing block");
    let second = validity
        .prove_candidate("validity-span-2".into(), &producer)
        .expect("independent second span from finalized state");
    assert_eq!(second.initial_block_number, 2);
    assert_eq!(second.final_block_number, 3);
    assert_eq!(second.signature_event_count, 2);
    assert_eq!(second.metrics.appended_signature_event_count, 1);
    assert!(second.metrics.aggregate_list_proof_bytes > 0);
    assert_eq!(
        validity
            .status()
            .expect("status")
            .circuit_construction_count,
        1
    );
    let second_ack = acknowledgement(2, second.final_extended_state_commitment);
    validity
        .acknowledge_candidate_unchecked_for_test(
            "ack-span-2".into(),
            second.candidate_id,
            second_ack.clone(),
            &producer,
        )
        .expect("second L1 ack");
    assert_eq!(validity.status().expect("status").finalized_block_number, 3);
    assert_eq!(validity.status().expect("status").acknowledgement_count, 2);
    assert_eq!(
        validity
            .acknowledge_candidate_unchecked_for_test(
                "ack-span-2".into(),
                second.candidate_id,
                second_ack,
                &producer,
            )
            .expect("ack request id is idempotent")
            .finalized_block_number,
        3
    );

    let other_directory = TestDirectory::new("wrong-anchor");
    let other_producer = BlockProducerService::open(other_directory.producer_journal(), &[2])
        .expect("other journal");
    assert!(matches!(
        validity.reconcile(&other_producer),
        Err(ValidityProverServiceError::ProducerReconciliation(_))
    ));

    let metrics = &second.metrics;
    println!(
        "VALIDITY_PROVER_BENCH build_ms={} span_ms={} block_ms={} list_ms={} validity_ms={} block_bytes={} list_bytes={} validity_bytes={} block_pi={} list_pi={} validity_pi={} peak_rss_bytes={}",
        validity
            .status()
            .expect("metrics status")
            .circuit_build_elapsed_ms,
        metrics.total_elapsed_ms,
        metrics.block_chain_elapsed_ms,
        metrics.aggregate_list_elapsed_ms,
        metrics.validity_elapsed_ms,
        metrics.block_chain_proof_bytes,
        metrics.aggregate_list_proof_bytes,
        metrics.validity_proof_bytes,
        metrics.block_chain_public_inputs,
        metrics.aggregate_list_public_inputs,
        metrics.validity_public_inputs,
        metrics.peak_rss_bytes,
    );

    drop(validity);
    let corrupt_path = directory.0.join("corrupt.snapshot");
    fs::copy(&snapshot_path, &corrupt_path).expect("copy valid snapshot");
    fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600)).expect("private copy");
    let mut bytes = fs::read(&corrupt_path).expect("read copied snapshot");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&corrupt_path, bytes).expect("corrupt snapshot payload");
    assert!(matches!(
        ValidityProverService::open(&corrupt_path, &[2], prover_address, &producer),
        Err(ValidityProverServiceError::Snapshot(message)) if message.contains("checksum")
    ));
}
