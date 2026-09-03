#![cfg(not(debug_assertions))]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use intmax3_zkp::{
    block_producer::{ProductionBlockProducerError, ProductionDepositRequest},
    block_producer_service::{BlockProducerService, BlockProducerServiceError},
    circuits::balance::common::recipient::{
        calculate_recipient_from_user_id, extract_address_from_recipient,
    },
    common::{
        balance_state::settled_tx_chain_push,
        channel::{ChannelState, token_funds_digest},
        channel_id::ChannelId,
        deposit::Deposit,
        salt::Salt,
        u63::{BlockNumber, U63},
    },
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    live_balance_service::{LiveBalanceService, LiveBalanceServiceError},
    regev::{RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltInterChannelSend, ChannelSnapshot, MemberInfo, MemberKeys, add_signature,
        assemble_genesis_state_backed, attach_small_block_signatures,
        build_burn_send_token_at_base_nonce, build_inter_channel_credit,
        build_inter_channel_send_token_at_base_nonce, build_record, build_token_register,
        canonical_inter_channel_base_transfer, default_settled_tx_accumulator, sign_state,
        verify_snapshot,
    },
};
use rand010::{SeedableRng as _, rngs::StdRng};

const CHANNEL: u32 = 41;
const DEPOSIT_AMOUNT: u64 = 100;
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "intmax-live-balance-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("isolated directory");
        Self(path)
    }

    fn producer(&self) -> PathBuf {
        self.0.join("producer.journal.json")
    }

    fn balance(&self) -> PathBuf {
        self.0.join("wallet.balance")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn member_info(slot: usize, keys: &MemberKeys) -> MemberInfo {
    MemberInfo {
        slot: slot as u16,
        pk_g: keys.pk_g(),
        pk_b: keys.pk_b(),
        regev_pk: keys.regev_pk.clone(),
    }
}

fn sign_all(mut state: ChannelState, keys: &[MemberKeys]) -> ChannelState {
    state.member_signatures.clear();
    for (slot, keys) in keys.iter().enumerate() {
        let signature = sign_state(keys, slot as u8, &state).expect("sign state");
        add_signature(&mut state, signature);
    }
    state
}

fn fresh_root(tag: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, tag]).expect("root")
}

fn build_burn(
    keys: &[MemberKeys],
    snapshot: &ChannelSnapshot,
    base_nonce: u32,
    amount: u64,
    before_amount: u64,
    before_witness: &intmax3_zkp::regev::AmountWitness,
    tag: u32,
    rng: &mut StdRng,
) -> BuiltInterChannelSend {
    build_burn_send_token_at_base_nonce(
        &keys[0],
        snapshot,
        0,
        Address::from_u32_slice(&[0, 0, 0, 0, 0xBEEF + tag]).expect("withdraw address"),
        0,
        base_nonce,
        amount,
        before_amount,
        before_witness,
        fresh_root(tag),
        LEVEL,
        rng,
    )
    .expect("build canonical burn")
}

fn token_registration_child(
    snapshot: &ChannelSnapshot,
    keys: &[MemberKeys],
    token_index: u32,
) -> ChannelState {
    let proposed = build_token_register(&keys[0], snapshot, 0, token_index)
        .expect("build canonical token-register child");
    sign_all(proposed, keys)
}

fn snapshot_with_state(template: &ChannelSnapshot, state: ChannelState) -> ChannelSnapshot {
    ChannelSnapshot {
        record: template.record.clone(),
        state,
        members: template.members.clone(),
        settled_tx_accumulator: template.settled_tx_accumulator.clone(),
    }
}

fn assert_bind_rejected_without_mutation(
    live: &mut LiveBalanceService,
    producer: &BlockProducerService,
    balance_path: &Path,
    snapshot: &ChannelSnapshot,
) {
    // Keep this precondition explicit: the negative vectors below are fully formed, N-of-N
    // signed snapshots.  The live-backing continuity boundary, rather than signature parsing or
    // malformed input, must be what refuses them.
    verify_snapshot(snapshot, None).expect("negative vector remains a valid N-of-N snapshot");

    let bytes_before = fs::read(balance_path).expect("read live snapshot before refusal");
    let status_before = live.status().expect("status before refusal");
    let attestation_before = live.attestation().expect("attestation before refusal");
    let backing_before = serde_json::to_vec(
        &live
            .channel_backing_artifact()
            .expect("backing before refusal"),
    )
    .expect("serialize backing before refusal");

    assert!(matches!(
        live.bind_signed_snapshot(producer, snapshot),
        Err(LiveBalanceServiceError::InvalidRequest(_)) | Err(LiveBalanceServiceError::Snapshot(_))
    ));

    assert_eq!(
        fs::read(balance_path).expect("read live snapshot after refusal"),
        bytes_before,
        "a refused rebind must not rewrite even one durable snapshot byte"
    );
    assert_eq!(
        live.status().expect("status after refusal"),
        status_before,
        "a refused rebind must not mutate any in-memory public/base cursor"
    );
    assert_eq!(
        live.attestation()
            .expect("attestation after refusal")
            .balance_proof,
        attestation_before.balance_proof,
        "a refused rebind must not replace or reprove the balance proof"
    );
    assert_eq!(
        serde_json::to_vec(
            &live
                .channel_backing_artifact()
                .expect("backing after refusal"),
        )
        .expect("serialize backing after refusal"),
        backing_before,
        "the public backing artifact must remain byte-identical after refusal"
    );
}

#[test]
fn zero_funded_binding_and_h2_zero_head_rebinding_are_exact_and_fail_closed() {
    std::thread::Builder::new()
        .name("live-backing-rebind".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(run_zero_funded_binding_and_h2_zero_head_rebinding)
        .expect("spawn large-stack backing test")
        .join()
        .expect("live backing test thread");
}

fn run_zero_funded_binding_and_h2_zero_head_rebinding() {
    let directory = TestDirectory::new();
    let producer_path = directory.producer();
    let balance_path = directory.balance();
    let channel_id = ChannelId::new(CHANNEL as u64).expect("channel id");
    // A hard crash in v3 used a deterministic `(pid,generation)` temporary name. PID reuse must
    // not permanently block the v4 recovery write; new commits add an unpredictable nonce.
    let legacy_producer_orphan = producer_path.parent().expect("producer parent").join(format!(
        ".{}.tmp.{}.0",
        producer_path.file_name().expect("producer filename").to_string_lossy(),
        std::process::id(),
    ));
    let legacy_balance_orphan = balance_path.parent().expect("balance parent").join(format!(
        ".{}.tmp.{}.0",
        balance_path.file_name().expect("balance filename").to_string_lossy(),
        std::process::id(),
    ));
    fs::write(&legacy_producer_orphan, b"orphaned-v3-journal-temp")
        .expect("seed legacy producer orphan");
    fs::write(&legacy_balance_orphan, b"orphaned-v3-balance-temp")
        .expect("seed legacy balance orphan");
    let producer = BlockProducerService::open(&producer_path, &[2]).expect("producer");
    let mut live = LiveBalanceService::initialize(&balance_path, channel_id, Salt::default())
        .expect("initialize zero-funded live balance");

    let mut rng = StdRng::seed_from_u64(0xBACC_1A11);
    let keys: Vec<MemberKeys> = (0..2).map(|_| MemberKeys::generate(&mut rng)).collect();
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| member_info(slot, keys))
        .collect();
    let record = build_record(CHANNEL, &members, 0, 0).expect("record");
    let (first_zero, _) =
        encrypt_amount(&mut rng, &keys[0].regev_pk, 0).expect("encrypt first zero");
    let (second_zero, _) =
        encrypt_amount(&mut rng, &keys[1].regev_pk, 0).expect("encrypt second zero");
    let regev_digests: Vec<Bytes32> = keys
        .iter()
        .map(|keys| Bytes32::from(keys.regev_pk.poseidon_digest()))
        .collect();
    let exits = [
        Address::from_u32_slice(&[0, 0, 0, 0, 0xA1]).expect("first exit"),
        Address::from_u32_slice(&[0, 0, 0, 0, 0xA2]).expect("second exit"),
    ];
    let genesis = assemble_genesis_state_backed(
        &record,
        &[first_zero, second_zero],
        &regev_digests,
        &exits,
        0,
        Bytes32::default(),
        Bytes32::default(),
    )
    .expect("zero-funded genesis");
    let genesis_snapshot = ChannelSnapshot {
        record: record.clone(),
        state: sign_all(genesis, &keys),
        members: members.clone(),
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };
    verify_snapshot(&genesis_snapshot, None).expect("valid zero-funded genesis snapshot");

    assert!(
        live.channel_backing_artifact().is_err(),
        "a fresh unbound balance must not expose public backing"
    );
    let unbound = live.status().expect("unbound status");
    let proof_before_binding = live.attestation().expect("initial proof").balance_proof;
    live.bind_signed_snapshot(&producer, &genesis_snapshot)
        .expect("bind a genuinely zero-funded N-of-N genesis");
    let bound = live.status().expect("bound status");
    assert_eq!(bound.balance_generation, unbound.balance_generation);
    assert_eq!(bound.base_nonce, unbound.base_nonce);
    assert_eq!(bound.private_commitment, unbound.private_commitment);
    assert_eq!(bound.settled_tx_chain, unbound.settled_tx_chain);
    assert_eq!(bound.proof_size, unbound.proof_size);
    assert_eq!(bound.applied_transition_count, 0);
    assert_eq!(
        bound.signed_head_digest,
        Some(genesis_snapshot.state.digest)
    );
    assert_eq!(
        live.attestation().expect("bound proof").balance_proof,
        proof_before_binding,
        "initial binding must reuse the exact resident proof bytes"
    );
    let genesis_backing = live
        .channel_backing_artifact()
        .expect("bound genesis backing");
    let genesis_exit_kit = genesis_backing
        .signed_head_exit_kit
        .clone()
        .expect("every accepted N-of-N H has an exit kit");
    assert_eq!(genesis_exit_kit.schema_version, 1);
    assert_eq!(genesis_exit_kit.backing_public_inputs.channel_id, channel_id);
    assert_eq!(
        genesis_exit_kit.backing_public_inputs.settled_tx_chain,
        genesis_snapshot.state.balance_state.settled_tx_chain
    );
    assert_eq!(
        genesis_exit_kit.backing_public_inputs.token_funds_digest,
        token_funds_digest(
            &genesis_snapshot.state.balance_state.token_registry,
            genesis_snapshot.state.balance_state.token_count,
            &genesis_snapshot.state.channel_fund.amounts,
        ),
        "the kit binds the complete H vector, not a per-token minimum"
    );
    assert!(!genesis_exit_kit.backing_proof.is_empty());

    // An exact ordinary child may update only the public N-of-N head.  It must neither invoke a
    // prover nor move the private/base cursor, proof bytes, settled history, or accumulator root.
    let child = token_registration_child(&genesis_snapshot, &keys, 7);
    let child_snapshot = snapshot_with_state(&genesis_snapshot, child.clone());
    verify_snapshot(&child_snapshot, None).expect("valid exact H2=0 child");
    let status_before_child = live.status().expect("status before child");
    let backing_before_child = live.channel_backing_artifact().expect("genesis backing");
    let proof_before_child = live
        .attestation()
        .expect("proof before child")
        .balance_proof;
    live.bind_signed_snapshot(&producer, &child_snapshot)
        .expect("advance exact H2=0 child");
    let status_after_child = live.status().expect("status after child");
    let backing_after_child = live.channel_backing_artifact().expect("child backing");
    let child_exit_kit = backing_after_child
        .signed_head_exit_kit
        .clone()
        .expect("ordinary accepted child has an exit kit");
    assert_eq!(status_after_child.signed_head_digest, Some(child.digest));
    assert_eq!(backing_after_child.signed_head, child);
    assert_eq!(
        status_after_child.balance_generation,
        status_before_child.balance_generation
    );
    assert_eq!(
        status_after_child.base_nonce,
        status_before_child.base_nonce
    );
    assert_eq!(
        status_after_child.private_commitment,
        status_before_child.private_commitment
    );
    assert_eq!(
        status_after_child.settled_tx_chain,
        status_before_child.settled_tx_chain
    );
    assert_eq!(
        status_after_child.proof_size,
        status_before_child.proof_size
    );
    assert_eq!(
        status_after_child.applied_transition_count,
        status_before_child.applied_transition_count
    );
    assert_eq!(
        live.attestation().expect("proof after child").balance_proof,
        proof_before_child,
        "ordinary head archival must not alter proof bytes"
    );
    assert_eq!(
        backing_after_child.balance_verifier_data,
        backing_before_child.balance_verifier_data
    );
    assert_eq!(
        backing_after_child
            .signed_head
            .channel_fund
            .intmax_state_root,
        backing_before_child
            .signed_head
            .channel_fund
            .intmax_state_root
    );
    assert_eq!(
        backing_after_child
            .signed_head
            .balance_state
            .settled_tx_accumulator_root,
        backing_before_child
            .signed_head
            .balance_state
            .settled_tx_accumulator_root
    );
    assert_eq!(
        child_exit_kit.backing_public_inputs.token_funds_digest,
        token_funds_digest(
            &child.balance_state.token_registry,
            child.balance_state.token_count,
            &child.channel_fund.amounts,
        )
    );
    assert_ne!(
        child_exit_kit.backing_public_inputs.token_funds_digest,
        genesis_exit_kit.backing_public_inputs.token_funds_digest,
        "changing the authenticated registry regenerates the whole-vector kit"
    );

    // Exact replay is a no-write idempotent success.
    let accepted_bytes = fs::read(&balance_path).expect("accepted snapshot bytes");
    live.bind_signed_snapshot(&producer, &child_snapshot)
        .expect("exact accepted-head replay");
    assert_eq!(
        fs::read(&balance_path).expect("snapshot after exact replay"),
        accepted_bytes
    );

    // A different child of the old genesis is a sibling, even if its counters are locally
    // plausible. It cannot replace the already archived child.
    let sibling = token_registration_child(&genesis_snapshot, &keys, 8);
    assert_ne!(sibling.digest, child_snapshot.state.digest);
    assert_bind_rejected_without_mutation(
        &mut live,
        &producer,
        &balance_path,
        &snapshot_with_state(&genesis_snapshot, sibling),
    );

    // A descendant must advance epoch and state-version by exactly one, never skip a link.
    let grandchild = token_registration_child(&child_snapshot, &keys, 8);
    let grandchild_snapshot = snapshot_with_state(&child_snapshot, grandchild);
    let skipped = token_registration_child(&grandchild_snapshot, &keys, 9);
    assert_bind_rejected_without_mutation(
        &mut live,
        &producer,
        &balance_path,
        &snapshot_with_state(&child_snapshot, skipped),
    );

    // The resident balance proof is the authority for the settled chain.
    let canonical_next = token_registration_child(&child_snapshot, &keys, 8);
    let mut wrong_chain = canonical_next.clone();
    wrong_chain.balance_state.settled_tx_chain = fresh_root(0xC1A1);
    wrong_chain = sign_all(wrong_chain.with_computed_digest(), &keys);
    assert_bind_rejected_without_mutation(
        &mut live,
        &producer,
        &balance_path,
        &snapshot_with_state(&child_snapshot, wrong_chain),
    );

    // The hidden private asset tree, not a newly supplied signed header, is authoritative for
    // every close-fund amount.
    let mut unbacked_fund = canonical_next.clone();
    unbacked_fund.channel_fund.amounts[0] = U256::from(1u64);
    unbacked_fund = sign_all(unbacked_fund.with_computed_digest(), &keys);
    assert_bind_rejected_without_mutation(
        &mut live,
        &producer,
        &balance_path,
        &snapshot_with_state(&child_snapshot, unbacked_fund),
    );

    // H2!=0 is a base-moving transition and belongs exclusively to settle_* paths.
    let mut nonzero_h2 = canonical_next.clone();
    nonzero_h2.h2_tag = fresh_root(0xA202);
    nonzero_h2 = sign_all(nonzero_h2.with_computed_digest(), &keys);
    assert_bind_rejected_without_mutation(
        &mut live,
        &producer,
        &balance_path,
        &snapshot_with_state(&child_snapshot, nonzero_h2),
    );

    // These base-settlement headers are immutable across an ordinary H2=0 send/refresh. A signed
    // child must not smuggle a fabricated L1 root, nullifier era, incoming escrow, or settled-tx
    // accumulator into the public-close backing artifact.
    for (label, forged_state) in [
        ("intmax root", {
            let mut state = canonical_next.clone();
            state.channel_fund.intmax_state_root = fresh_root(0xA301);
            sign_all(state.with_computed_digest(), &keys)
        }),
        ("shared nullifier root", {
            let mut state = canonical_next.clone();
            state.shared_native_nullifier_root = fresh_root(0xA302);
            sign_all(state.with_computed_digest(), &keys)
        }),
        ("unallocated incoming", {
            let mut state = canonical_next.clone();
            state.unallocated_confirmed_incoming = U256::from(1u64);
            sign_all(state.with_computed_digest(), &keys)
        }),
        ("settled accumulator root", {
            let mut state = canonical_next.clone();
            state.balance_state.settled_tx_accumulator_root = fresh_root(0xA303);
            sign_all(state.with_computed_digest(), &keys)
        }),
    ] {
        let forged = snapshot_with_state(&child_snapshot, forged_state);
        assert_bind_rejected_without_mutation(&mut live, &producer, &balance_path, &forged);
        eprintln!("ordinary rebind rejected forged {label}");
    }

    // Persistence/restart must expose only the accepted child, never one of the refused heads.
    drop(live);
    let reopened = LiveBalanceService::open(&balance_path, &producer)
        .expect("reopen after accepted and refused rebinds");
    let reopened_status = reopened.status().expect("reopened status");
    assert_eq!(reopened_status, status_after_child);
    assert_eq!(
        reopened
            .channel_backing_artifact()
            .expect("reopened backing")
            .signed_head,
        child_snapshot.state
    );
    let reopened_kit = reopened
        .channel_backing_artifact()
        .expect("reopened backing with exit kit")
        .signed_head_exit_kit
        .expect("persisted exit kit");
    assert_eq!(reopened_kit.backing_proof, child_exit_kit.backing_proof);
    assert_eq!(
        reopened_kit.backing_public_inputs,
        child_exit_kit.backing_public_inputs,
        "restart must retain the exact proof-bound composition fields"
    );
}

#[test]
fn real_deposit_send_restart_next_nonce_and_corruption_fences() {
    std::thread::Builder::new()
        .name("live-balance-e2e".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(run_live_balance_e2e)
        .expect("spawn large-stack prover thread")
        .join()
        .expect("live balance E2E thread");
}

fn run_live_balance_e2e() {
    let directory = TestDirectory::new();
    let producer_path = directory.producer();
    let balance_path = directory.balance();
    let channel_id = ChannelId::new(CHANNEL as u64).expect("channel id");
    let account_salt = Salt::default();
    let deposit_salt = Salt(
        intmax3_zkp::utils::poseidon_hash_out::PoseidonHashOut::from_u64_slice(&[11, 12, 13, 14])
            .expect("salt"),
    );

    let mut producer = BlockProducerService::open(&producer_path, &[2]).expect("producer");
    let mut live = LiveBalanceService::initialize(&balance_path, channel_id, account_salt)
        .expect("initialize live balance");
    assert_eq!(live.base_nonce().expect("nonce"), 0);
    assert!(matches!(
        LiveBalanceService::open(&balance_path, &producer),
        Err(LiveBalanceServiceError::Locked(_))
    ));

    // A real producer deposit leaf, reconciled against the exact L1 hash-chain value.
    let depositor = Address::from_u32_slice(&[0, 0, 0, 0, 0xD3]).expect("depositor");
    let recipient = calculate_recipient_from_user_id(channel_id, deposit_salt);
    let deposit = Deposit {
        deposit_index: U63::new(0).expect("index"),
        depositor,
        recipient,
        token_index: 0,
        amount: U256::from(DEPOSIT_AMOUNT),
        block_number: BlockNumber::new(1).expect("block"),
        aux_data: Bytes32::default(),
    };
    let deposit_request = ProductionDepositRequest {
        deposit_index: 0,
        depositor,
        recipient,
        token_index: 0,
        amount: U256::from(DEPOSIT_AMOUNT),
        aux_data: Bytes32::default(),
        expected_deposit_hash_chain: deposit.hash_with_prev_hash(Bytes32::default()),
    };
    let deposit_receipt = producer
        .post_deposit("l1:deposit:0".into(), deposit_request.clone())
        .expect("durable L1 deposit block");

    // Build the N-of-N deposit-backed genesis that the newly advanced balance proof must match.
    let mut rng = StdRng::seed_from_u64(0x1A11_CE55);
    let keys: Vec<MemberKeys> = (0..2).map(|_| MemberKeys::generate(&mut rng)).collect();
    let members: Vec<MemberInfo> = keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| member_info(slot, keys))
        .collect();
    let record = build_record(CHANNEL, &members, 0, 0).expect("record");
    let (sender_ciphertext, sender_witness) =
        encrypt_amount(&mut rng, &keys[0].regev_pk, DEPOSIT_AMOUNT).expect("encrypt sender");
    let (other_ciphertext, _) =
        encrypt_amount(&mut rng, &keys[1].regev_pk, 0).expect("encrypt other");
    let regev_digests: Vec<Bytes32> = keys
        .iter()
        .map(|keys| Bytes32::from(keys.regev_pk.poseidon_digest()))
        .collect();
    let exits = [
        Address::from_u32_slice(&[0, 0, 0, 0, 1]).expect("exit 1"),
        Address::from_u32_slice(&[0, 0, 0, 0, 2]).expect("exit 2"),
    ];
    let deposit_chain = settled_tx_chain_push(Bytes32::default(), deposit.nullifier());
    let genesis = assemble_genesis_state_backed(
        &record,
        &[sender_ciphertext, other_ciphertext],
        &regev_digests,
        &exits,
        DEPOSIT_AMOUNT,
        deposit_chain,
        deposit_receipt.extended_state_commitment,
    )
    .expect("backed genesis");
    let backed_snapshot = ChannelSnapshot {
        record: record.clone(),
        state: sign_all(genesis, &keys),
        members: members.clone(),
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };
    verify_snapshot(&backed_snapshot, None).expect("valid backed snapshot");

    let received = live
        .receive_deposit_unbound(&producer, &deposit_receipt, &deposit_request, deposit_salt)
        .expect("real unbound receive-deposit proof");
    assert_eq!(received.settled_tx_chain, deposit_chain);
    assert_eq!(
        received.base_nonce, 0,
        "receive does not consume send nonce"
    );
    assert_eq!(
        live.receive_deposit_unbound(&producer, &deposit_receipt, &deposit_request, deposit_salt,)
            .expect("unbound receive retry is idempotent"),
        received
    );
    assert!(
        live.status()
            .expect("unbound status")
            .awaiting_channel_binding
    );
    assert!(live.channel_backing_artifact().is_err());

    // Crash exactly between phase 1 (proof durable) and phase 2 (signed genesis bind), then bind
    // without reproving or replaying the L1 deposit.
    drop(live);
    let mut live = LiveBalanceService::open(&balance_path, &producer)
        .expect("restart with an unbound deposit proof");
    assert!(
        live.status()
            .expect("recovered unbound status")
            .awaiting_channel_binding
    );
    live.bind_signed_snapshot(&producer, &backed_snapshot)
        .expect("bind N-of-N genesis after restart");
    assert!(
        !live
            .status()
            .expect("bound status")
            .awaiting_channel_binding
    );
    assert_eq!(
        live.receive_deposit(
            &producer,
            &deposit_receipt,
            &deposit_request,
            deposit_salt,
            &backed_snapshot,
        )
        .expect("bound one-shot retry stays idempotent"),
        received
    );

    producer
        .register("register:41".into(), backed_snapshot.clone())
        .expect("register deposit-backed head");

    let mut first = build_burn(
        &keys,
        &backed_snapshot,
        0,
        10,
        DEPOSIT_AMOUNT,
        &sender_witness,
        1,
        &mut rng,
    );
    first.debit_payload.proposed_next_state =
        sign_all(first.debit_payload.proposed_next_state.clone(), &keys);
    let first_state = first.debit_payload.proposed_next_state.clone();
    let first_receipt = producer
        .post_inter_channel(
            "burn:0".into(),
            first_state.clone(),
            first.debit_payload.clone(),
            first.transfer_descriptor.clone(),
        )
        .expect("durable first burn block");
    let first_settle = live
        .settle_inter_channel(
            &producer,
            &first_receipt,
            &first_state,
            &first.debit_payload,
            &first.transfer_descriptor,
        )
        .expect("settle first base send");
    assert_eq!(first_settle.base_nonce, 1);
    assert_eq!(
        first_settle.settled_tx_chain,
        first_state.balance_state.settled_tx_chain
    );

    drop(live);
    let mut live = LiveBalanceService::open(&balance_path, &producer)
        .expect("semantic restart from proof/private trees/journal checkpoint");
    assert_eq!(live.base_nonce().expect("recovered nonce"), 1);

    let first_snapshot = ChannelSnapshot {
        record: record.clone(),
        state: first_state.clone(),
        members: members.clone(),
        settled_tx_accumulator: first.settled_tx_accumulator.clone(),
    };
    let mut skipped = build_burn(
        &keys,
        &first_snapshot,
        2,
        1,
        DEPOSIT_AMOUNT - 10,
        &first.new_balance_witness,
        2,
        &mut rng,
    );
    skipped.debit_payload.proposed_next_state =
        sign_all(skipped.debit_payload.proposed_next_state.clone(), &keys);
    assert!(matches!(
        producer.post_inter_channel(
            "burn:skip".into(),
            skipped.debit_payload.proposed_next_state.clone(),
            skipped.debit_payload,
            skipped.transfer_descriptor,
        ),
        Err(BlockProducerServiceError::Producer(
            ProductionBlockProducerError::WalletAuthorization(message)
        )) if message.contains("expected 1")
    ));

    let mut second = build_burn(
        &keys,
        &first_snapshot,
        1,
        7,
        DEPOSIT_AMOUNT - 10,
        &first.new_balance_witness,
        3,
        &mut rng,
    );
    second.debit_payload.proposed_next_state =
        sign_all(second.debit_payload.proposed_next_state.clone(), &keys);
    let second_state = second.debit_payload.proposed_next_state.clone();
    let second_receipt = producer
        .post_inter_channel(
            "burn:1".into(),
            second_state.clone(),
            second.debit_payload.clone(),
            second.transfer_descriptor.clone(),
        )
        .expect("durable second burn block");
    let second_settle = live
        .settle_inter_channel(
            &producer,
            &second_receipt,
            &second_state,
            &second.debit_payload,
            &second.transfer_descriptor,
        )
        .expect("settle next nonce after restart");
    assert_eq!(second_settle.base_nonce, 2);
    assert_eq!(
        second_settle.settled_tx_chain,
        second_state.balance_state.settled_tx_chain
    );

    // ── P3-2/P3-3 (partial-withdrawal-payout-design): the payout proof comes from the LIVE base
    // history. TWO CONSECUTIVE burns from the same channel both prove — the second builds on the
    // first's post-state, which a from-scratch generator cannot reproduce — and the Withdrawal is
    // read from the proof's public inputs, matching the canonical burn leaf field for field.
    let payout_prover = Address::from_u32_slice(&[0x50415955u32; 5]).expect("prover address");
    let first_burn_proof = live
        .prove_burn_withdrawal(
            &producer,
            "burn:0",
            &first.transfer_descriptor,
            payout_prover,
        )
        .expect("prove first burn withdrawal from live history");
    let expected_first = canonical_inter_channel_base_transfer(
        &first.transfer_descriptor.inter_channel_tx,
        first.transfer_descriptor.amount,
    )
    .expect("canonical first burn transfer");
    assert_eq!(
        first_burn_proof.withdrawal.recipient,
        extract_address_from_recipient(expected_first.recipient)
            .expect("burn recipient is the canonical ADDRESS_TAG form"),
        "the paid L1 address is the one inside the co-signed burn leaf"
    );
    assert_eq!(first_burn_proof.withdrawal.amount, expected_first.amount);
    assert_eq!(
        first_burn_proof.withdrawal.aux_data, expected_first.aux_data,
        "the burn leaf must carry the burn descriptor, not zero (the repo's first aux!=0 leaf)"
    );
    assert_ne!(first_burn_proof.withdrawal.aux_data, Bytes32::default());

    // The full payout artifact set (wrap + MLE + payout descriptor) for the first burn. The MLE
    // proof is verified inside the builder; here we pin the wire schema the forge step parses and
    // that every leaf field is the PI-decoded value.
    let first_artifacts = live
        .burn_payout_artifacts(
            &producer,
            "burn:0",
            &first.transfer_descriptor,
            payout_prover,
        )
        .expect("burn payout artifacts");
    let payout: serde_json::Value =
        serde_json::from_str(&first_artifacts.payout_json).expect("payout json parses");
    assert_eq!(
        payout["withdrawals"][0]["aux_data"].as_str().unwrap(),
        expected_first.aux_data.to_string(),
        "the payout descriptor carries the burn aux_data"
    );
    assert_eq!(
        payout["withdrawals"][0]["amount"].as_str().unwrap(),
        first_burn_proof.withdrawal.amount.to_string(),
    );
    assert_eq!(
        payout["withdrawal_prover"].as_str().unwrap(),
        payout_prover.to_string(),
    );
    assert!(
        first_artifacts.withdrawal_mle_json.len() > 100_000,
        "a real MLE/WHIR proof was exported"
    );
    assert_eq!(
        first_artifacts.withdrawal.nullifier,
        first_burn_proof.withdrawal.nullifier
    );

    let second_burn_proof = live
        .prove_burn_withdrawal(
            &producer,
            "burn:1",
            &second.transfer_descriptor,
            payout_prover,
        )
        .expect("prove SECOND consecutive burn withdrawal (P3-2)");
    assert_ne!(
        second_burn_proof.withdrawal.nullifier, first_burn_proof.withdrawal.nullifier,
        "consecutive burns must yield distinct nullifiers"
    );

    // Binding negative: the journaled transition and the supplied descriptor must be the SAME
    // burn — replaying burn:0's descriptor under burn:1's journal entry dies on the settled-leaf
    // binding before any proving.
    let err = live
        .prove_burn_withdrawal(
            &producer,
            "burn:1",
            &first.transfer_descriptor,
            payout_prover,
        )
        .expect_err("a mismatched descriptor/journal pair must be rejected");
    assert!(
        format!("{err}").contains("settled leaf"),
        "the refusal must name the broken binding, got: {err}"
    );

    // Give channel B an independently proved, L1-reconciled base account and bind its signed
    // deposit-backed genesis. This is intentionally a second producer deposit: the destination
    // ReceiveTransfer below must extend a real non-genesis balance proof rather than a fixture.
    const DESTINATION_CHANNEL: u32 = 42;
    const DESTINATION_DEPOSIT_AMOUNT: u64 = 50;
    let destination_channel_id =
        ChannelId::new(DESTINATION_CHANNEL as u64).expect("destination channel id");
    let destination_balance_path = directory.0.join("destination.balance");
    let destination_account_salt = Salt(
        intmax3_zkp::utils::poseidon_hash_out::PoseidonHashOut::from_u64_slice(&[21, 22, 23, 24])
            .expect("destination account salt"),
    );
    let destination_deposit_salt = Salt(
        intmax3_zkp::utils::poseidon_hash_out::PoseidonHashOut::from_u64_slice(&[31, 32, 33, 34])
            .expect("destination deposit salt"),
    );
    let mut destination_live = LiveBalanceService::initialize(
        &destination_balance_path,
        destination_channel_id,
        destination_account_salt,
    )
    .expect("initialize destination live balance");
    let destination_depositor =
        Address::from_u32_slice(&[0, 0, 0, 0, 0xD4]).expect("destination depositor");
    let destination_deposit_recipient =
        calculate_recipient_from_user_id(destination_channel_id, destination_deposit_salt);
    let destination_deposit_block = producer
        .status()
        .expect("producer status before destination deposit")
        .block_number
        + 1;
    let destination_deposit = Deposit {
        deposit_index: U63::new(1).expect("destination deposit index"),
        depositor: destination_depositor,
        recipient: destination_deposit_recipient,
        token_index: 0,
        amount: U256::from(DESTINATION_DEPOSIT_AMOUNT),
        block_number: BlockNumber::new(destination_deposit_block).expect("destination block"),
        aux_data: Bytes32::default(),
    };
    let destination_deposit_request = ProductionDepositRequest {
        deposit_index: 1,
        depositor: destination_depositor,
        recipient: destination_deposit_recipient,
        token_index: 0,
        amount: U256::from(DESTINATION_DEPOSIT_AMOUNT),
        aux_data: Bytes32::default(),
        expected_deposit_hash_chain: destination_deposit
            .hash_with_prev_hash(deposit.hash_with_prev_hash(Bytes32::default())),
    };
    let destination_deposit_receipt = producer
        .post_deposit("l1:deposit:1".into(), destination_deposit_request.clone())
        .expect("durable destination L1 deposit block");

    let destination_keys: Vec<MemberKeys> =
        (0..2).map(|_| MemberKeys::generate(&mut rng)).collect();
    let destination_members: Vec<MemberInfo> = destination_keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| member_info(slot, keys))
        .collect();
    let destination_record =
        build_record(DESTINATION_CHANNEL, &destination_members, 0, 0).expect("destination record");
    let (destination_funded_ciphertext, _) = encrypt_amount(
        &mut rng,
        &destination_keys[0].regev_pk,
        DESTINATION_DEPOSIT_AMOUNT,
    )
    .expect("encrypt destination funded member");
    let (destination_recipient_ciphertext, _) =
        encrypt_amount(&mut rng, &destination_keys[1].regev_pk, 0)
            .expect("encrypt destination recipient");
    let destination_regev_digests: Vec<Bytes32> = destination_keys
        .iter()
        .map(|keys| Bytes32::from(keys.regev_pk.poseidon_digest()))
        .collect();
    let destination_exits = [
        Address::from_u32_slice(&[0, 0, 0, 0, 3]).expect("destination exit 1"),
        Address::from_u32_slice(&[0, 0, 0, 0, 4]).expect("destination exit 2"),
    ];
    let destination_deposit_chain =
        settled_tx_chain_push(Bytes32::default(), destination_deposit.nullifier());
    let destination_genesis = assemble_genesis_state_backed(
        &destination_record,
        &[
            destination_funded_ciphertext,
            destination_recipient_ciphertext,
        ],
        &destination_regev_digests,
        &destination_exits,
        DESTINATION_DEPOSIT_AMOUNT,
        destination_deposit_chain,
        destination_deposit_receipt.extended_state_commitment,
    )
    .expect("destination backed genesis");
    let destination_backed_snapshot = ChannelSnapshot {
        record: destination_record.clone(),
        state: sign_all(destination_genesis, &destination_keys),
        members: destination_members.clone(),
        settled_tx_accumulator: default_settled_tx_accumulator(),
    };
    destination_live
        .receive_deposit_unbound(
            &producer,
            &destination_deposit_receipt,
            &destination_deposit_request,
            destination_deposit_salt,
        )
        .expect("destination receive-deposit proof");
    destination_live
        .bind_signed_snapshot(&producer, &destination_backed_snapshot)
        .expect("bind destination signed genesis");
    producer
        .register("register:42".into(), destination_backed_snapshot.clone())
        .expect("register destination head");

    // The normal transfer keeps the encrypted channel receiver key and the base-layer UID
    // recipient separate. IMI4 signs the explicit destination salt; ReceiveTransfer opens the
    // resulting UID and proves the exact same canonical transfer committed by H2.
    const INTER_AMOUNT: u64 = 5;
    let destination_base_transfer_salt = Salt(
        intmax3_zkp::utils::poseidon_hash_out::PoseidonHashOut::from_u64_slice(&[41, 42, 43, 44])
            .expect("destination transfer salt"),
    );
    let second_snapshot = ChannelSnapshot {
        record: record.clone(),
        state: second_state.clone(),
        members: members.clone(),
        settled_tx_accumulator: second.settled_tx_accumulator.clone(),
    };
    let mut inter = build_inter_channel_send_token_at_base_nonce(
        &keys[0],
        &second_snapshot,
        0,
        destination_channel_id,
        1,
        destination_keys[1].regev_pk.clone(),
        destination_keys[1].pk_g(),
        destination_base_transfer_salt,
        0,
        2,
        INTER_AMOUNT,
        DEPOSIT_AMOUNT - 10 - 7,
        &second.new_balance_witness,
        fresh_root(20),
        LEVEL,
        &mut rng,
    )
    .expect("build canonical normal inter-channel send");
    inter.debit_payload.proposed_next_state =
        sign_all(inter.debit_payload.proposed_next_state.clone(), &keys);
    attach_small_block_signatures(
        &record,
        &inter.debit_payload.proposed_next_state,
        &mut inter.transfer_descriptor.inter_channel_tx,
    )
    .expect("attach source N-of-N to small block");
    inter.debit_payload.inter_channel_tx = inter.transfer_descriptor.inter_channel_tx.clone();
    let inter_state = inter.debit_payload.proposed_next_state.clone();
    let inter_receipt = producer
        .post_inter_channel(
            "inter:41:42:0".into(),
            inter_state.clone(),
            inter.debit_payload.clone(),
            inter.transfer_descriptor.clone(),
        )
        .expect("durable normal inter-channel block");
    let source_inter_settle = live
        .settle_inter_channel(
            &producer,
            &inter_receipt,
            &inter_state,
            &inter.debit_payload,
            &inter.transfer_descriptor,
        )
        .expect("settle source normal base send");
    assert_eq!(source_inter_settle.base_nonce, 3);
    let source_artifact = live
        .inter_channel_send_artifact("inter:41:42:0")
        .expect("durable source balance/spend artifact");

    let mut credit = build_inter_channel_credit(
        &destination_keys[0],
        &destination_backed_snapshot,
        &inter.transfer_descriptor,
        LEVEL,
        &mut rng,
    )
    .expect("build destination credit states");
    credit.fund_import_state = sign_all(credit.fund_import_state, &destination_keys);
    credit.bundle_apply_state = sign_all(credit.bundle_apply_state, &destination_keys);
    let destination_credit_snapshot = ChannelSnapshot {
        record: destination_record.clone(),
        state: credit.bundle_apply_state.clone(),
        members: destination_members.clone(),
        settled_tx_accumulator: credit.settled_tx_accumulator,
    };
    let destination_receive = destination_live
        .receive_inter_channel(
            &producer,
            &inter_receipt,
            &inter.debit_payload,
            &inter.transfer_descriptor,
            &source_artifact,
            &credit.fund_import_state,
            &destination_credit_snapshot,
            LEVEL,
        )
        .expect("prove and settle destination ReceiveTransfer");
    assert_eq!(destination_receive.base_nonce, 0);
    assert_eq!(
        destination_receive.settled_tx_chain,
        credit.bundle_apply_state.balance_state.settled_tx_chain
    );
    assert_eq!(
        destination_receive.settled_tx_chain,
        settled_tx_chain_push(
            destination_deposit_chain,
            inter
                .transfer_descriptor
                .inter_channel_tx
                .tx_leaf_hash()
                .expect("tx leaf"),
        ),
        "destination base and channel heads fold the incoming transfer exactly once"
    );
    assert_eq!(
        source_inter_settle.settled_tx_chain, inter_state.balance_state.settled_tx_chain,
        "source base and signed channel heads fold the outgoing transfer exactly once"
    );

    drop(destination_live);
    let mut destination_live = LiveBalanceService::open(&destination_balance_path, &producer)
        .expect("semantic destination restart after ReceiveTransfer");
    assert_eq!(destination_live.base_nonce().expect("destination nonce"), 0);
    assert_eq!(
        destination_live
            .base_head_artifact()
            .expect("destination base head")
            .settled_tx_chain,
        destination_receive.settled_tx_chain
    );
    let mut wrong_destination_salt = inter.transfer_descriptor.clone();
    wrong_destination_salt.destination_base_transfer_salt = Salt::default();
    assert!(matches!(
        destination_live.receive_inter_channel(
            &producer,
            &inter_receipt,
            &inter.debit_payload,
            &wrong_destination_salt,
            &source_artifact,
            &credit.fund_import_state,
            &destination_credit_snapshot,
            LEVEL,
        ),
        Err(LiveBalanceServiceError::InvalidRequest(_))
            | Err(LiveBalanceServiceError::ProducerReconciliation(_))
    ));
    assert!(
        intmax3_zkp::wallet_core::verify_inter_channel_descriptor_matches_debit(
            &inter.debit_payload,
            &wrong_destination_salt,
        )
        .is_err()
    );
    drop(destination_live);

    // A body mutation under an already settled request id is rejected rather than treated as a
    // retry, even though the supplied producer receipt itself is genuine.
    let mut wrong_nonce = second.transfer_descriptor.clone();
    wrong_nonce.inter_channel_tx.base_nonce += 1;
    assert!(matches!(
        live.settle_inter_channel(
            &producer,
            &second_receipt,
            &second_state,
            &second.debit_payload,
            &wrong_nonce,
        ),
        Err(LiveBalanceServiceError::InvalidRequest(_))
            | Err(LiveBalanceServiceError::ProducerReconciliation(_))
    ));

    // The release close path is a terminal, ordinary TxV2 send: every remaining asset is paid
    // to the immutable Manager under one shared IMCF authorization, then the exact N-of-N child
    // is settled into the resident balance IVC. No close-specific circuit or VK is introduced.
    let rollup = Address::from_u32_slice(&[0x524f_4c4c; 5]).expect("rollup address");
    let manager = Address::from_u32_slice(&[0x4d41_4e47; 5]).expect("manager address");
    let proposal = live
        .prepare_close_funding(1, rollup, manager)
        .expect("prepare exact terminal funding plan");
    assert_eq!(proposal.plan.base_nonce, 3);
    assert_eq!(proposal.plan.transfers.len(), 1);
    assert_eq!(proposal.plan.transfers[0].token_index, 0);
    assert_eq!(proposal.plan.transfers[0].amount, U256::from(78u64));
    let close_state = sign_all(proposal.proposed_state, &keys);
    let close_receipt = producer
        .post_close_funding(
            "close-funding:41".into(),
            close_state.clone(),
            proposal.plan.clone(),
        )
        .expect("producer admits terminal funding block");
    let close_settle = live
        .settle_close_funding(&producer, &close_receipt, &close_state, &proposal.plan)
        .expect("settle terminal funding into live balance proof");
    assert_eq!(close_settle.base_nonce, 4);
    let close_status = live.status().expect("terminal live status");
    assert!(close_status.terminal_close_funding);
    assert_eq!(
        close_status.close_funding_plan_digest,
        Some(proposal.plan.plan_digest)
    );
    assert!(matches!(
        live.prepare_close_funding(1, rollup, manager),
        Err(LiveBalanceServiceError::InvalidRequest(message)) if message.contains("terminal")
    ));

    // Extract the paid leaf from the proved Spend/TxV2 history, aggregate it through the existing
    // withdrawal circuits, wrap it and self-verify the MLE artifact. This is the public/operator
    // handoff later submitted to the Rollup after Manager close finalization.
    let close_artifacts = live
        .close_funding_payout_artifacts(&producer, "close-funding:41", payout_prover)
        .expect("terminal close-funding payout artifacts");
    assert_eq!(close_artifacts.plan_digest, proposal.plan.plan_digest);
    assert_eq!(
        close_artifacts.funding_aux_data,
        proposal.plan.funding_aux_data
    );
    assert_eq!(close_artifacts.lanes.len(), 1);
    assert_eq!(close_artifacts.lanes[0].withdrawals.len(), 1);
    assert_eq!(
        close_artifacts.lanes[0].withdrawals[0].amount,
        U256::from(78u64)
    );
    assert_eq!(
        close_artifacts.lanes[0].withdrawals[0].aux_data,
        proposal.plan.funding_aux_data
    );
    assert!(close_artifacts.lanes[0].withdrawal_mle_json.len() > 100_000);
    // A one-leaf terminal lane uses exactly the same frozen proof statements as the pre-existing
    // one-leaf burn payout above.  These byte-for-byte size equalities make an accidental circuit
    // or recursion-layout expansion a release-test failure instead of a documentation claim.
    assert_eq!(
        close_artifacts.lanes[0]
            .metrics
            .single_withdrawal_proof_bytes,
        first_artifacts.metrics.single_withdrawal_proof_bytes
    );
    assert_eq!(
        close_artifacts.lanes[0]
            .metrics
            .withdrawal_chain_proof_bytes,
        first_artifacts.metrics.withdrawal_chain_proof_bytes
    );
    assert_eq!(
        close_artifacts.lanes[0]
            .metrics
            .withdrawal_final_proof_bytes,
        first_artifacts.metrics.withdrawal_final_proof_bytes
    );
    eprintln!(
        "terminal close lane metrics: single={}ms/{}B chain={}ms/{}B final={}ms/{}B wrap+mle={}ms json={}B",
        close_artifacts.lanes[0].metrics.single_withdrawal_millis,
        close_artifacts.lanes[0]
            .metrics
            .single_withdrawal_proof_bytes,
        close_artifacts.lanes[0].metrics.withdrawal_chain_millis,
        close_artifacts.lanes[0]
            .metrics
            .withdrawal_chain_proof_bytes,
        close_artifacts.lanes[0].metrics.withdrawal_final_millis,
        close_artifacts.lanes[0]
            .metrics
            .withdrawal_final_proof_bytes,
        close_artifacts.lanes[0].metrics.wrap_mle_millis,
        close_artifacts.lanes[0].metrics.mle_json_bytes,
    );

    drop(live);
    let live = LiveBalanceService::open(&balance_path, &producer)
        .expect("terminal marker and zero asset vector survive restart");
    assert!(
        live.status()
            .expect("restarted status")
            .terminal_close_funding
    );

    drop(live);
    let mut damaged = fs::read(&balance_path).expect("read snapshot");
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    fs::write(&balance_path, damaged).expect("damage snapshot");
    assert!(matches!(
        LiveBalanceService::open(&balance_path, &producer),
        Err(LiveBalanceServiceError::Snapshot(message)) if message.contains("checksum")
    ));
}
