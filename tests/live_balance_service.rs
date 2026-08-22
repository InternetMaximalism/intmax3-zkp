#![cfg(not(debug_assertions))]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use intmax3_zkp::wallet_core::canonical_inter_channel_base_transfer;
use intmax3_zkp::circuits::balance::common::recipient::extract_address_from_recipient;
use intmax3_zkp::{
    block_producer::{ProductionBlockProducerError, ProductionDepositRequest},
    block_producer_service::{BlockProducerService, BlockProducerServiceError},
    circuits::balance::common::recipient::calculate_recipient_from_user_id,
    common::{
        balance_state::settled_tx_chain_push,
        channel::ChannelState,
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
        build_inter_channel_send_token_at_base_nonce, build_record,
        default_settled_tx_accumulator, sign_state, verify_snapshot,
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
        .receive_deposit_unbound(
            &producer,
            &deposit_receipt,
            &deposit_request,
            deposit_salt,
        )
        .expect("real unbound receive-deposit proof");
    assert_eq!(received.settled_tx_chain, deposit_chain);
    assert_eq!(
        received.base_nonce, 0,
        "receive does not consume send nonce"
    );
    assert_eq!(
        live.receive_deposit_unbound(
            &producer,
            &deposit_receipt,
            &deposit_request,
            deposit_salt,
        )
        .expect("unbound receive retry is idempotent"),
        received
    );
    assert!(live.status().expect("unbound status").awaiting_channel_binding);
    assert!(live.channel_backing_artifact().is_err());

    // Crash exactly between phase 1 (proof durable) and phase 2 (signed genesis bind), then bind
    // without reproving or replaying the L1 deposit.
    drop(live);
    let mut live = LiveBalanceService::open(&balance_path, &producer)
        .expect("restart with an unbound deposit proof");
    assert!(live.status().expect("recovered unbound status").awaiting_channel_binding);
    live.bind_signed_snapshot(&backed_snapshot)
        .expect("bind N-of-N genesis after restart");
    assert!(!live.status().expect("bound status").awaiting_channel_binding);
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

    let second_burn_proof = live
        .prove_burn_withdrawal(
            &producer,
            "burn:1",
            &second.transfer_descriptor,
            payout_prover,
        )
        .expect("prove SECOND consecutive burn withdrawal (P3-2)");
    assert_ne!(
        second_burn_proof.withdrawal.nullifier,
        first_burn_proof.withdrawal.nullifier,
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
        expected_deposit_hash_chain: destination_deposit.hash_with_prev_hash(
            deposit.hash_with_prev_hash(Bytes32::default()),
        ),
    };
    let destination_deposit_receipt = producer
        .post_deposit(
            "l1:deposit:1".into(),
            destination_deposit_request.clone(),
        )
        .expect("durable destination L1 deposit block");

    let destination_keys: Vec<MemberKeys> =
        (0..2).map(|_| MemberKeys::generate(&mut rng)).collect();
    let destination_members: Vec<MemberInfo> = destination_keys
        .iter()
        .enumerate()
        .map(|(slot, keys)| member_info(slot, keys))
        .collect();
    let destination_record = build_record(DESTINATION_CHANNEL, &destination_members, 0, 0)
        .expect("destination record");
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
    let destination_deposit_chain = settled_tx_chain_push(
        Bytes32::default(),
        destination_deposit.nullifier(),
    );
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
        .bind_signed_snapshot(&destination_backed_snapshot)
        .expect("bind destination signed genesis");
    producer
        .register(
            "register:42".into(),
            destination_backed_snapshot.clone(),
        )
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
        credit
            .bundle_apply_state
            .balance_state
            .settled_tx_chain
    );
    assert_eq!(
        destination_receive.settled_tx_chain,
        settled_tx_chain_push(
            destination_deposit_chain,
            inter.transfer_descriptor.inter_channel_tx.tx_leaf_hash().expect("tx leaf"),
        ),
        "destination base and channel heads fold the incoming transfer exactly once"
    );
    assert_eq!(
        source_inter_settle.settled_tx_chain,
        inter_state.balance_state.settled_tx_chain,
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
    assert!(intmax3_zkp::wallet_core::verify_inter_channel_descriptor_matches_debit(
        &inter.debit_payload,
        &wrong_destination_salt,
    )
    .is_err());
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
