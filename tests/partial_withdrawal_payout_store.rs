use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use intmax3_zkp::{
    block_producer_service::{BlockProducerAnchor, BlockProducerReceipt},
    circuits::balance::common::recipient::calculate_recipient_from_address,
    common::{channel::burn_descriptor, channel_id::ChannelId, withdrawal::Withdrawal},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    l1_finality::{L1FinalitySource, L1FinalizedCheckpoint},
    partial_withdrawal_payout::{
        BroadcastIntent, FinalizeConfirmation, L1CallKind, L1TransactionReceipt,
        PartialWithdrawalOnchainState, PartialWithdrawalPayoutError, PartialWithdrawalPayoutStore,
        PartialWithdrawalProofArtifacts, PartialWithdrawalProofMetrics,
        PartialWithdrawalResumeAction, PayoutConfirmation, PreparePartialWithdrawalPayout,
        PullConfirmation, partial_withdrawal_resume_action,
    },
    wallet_core::partial_withdrawal_auth_digest,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TempSnapshot(PathBuf);

impl TempSnapshot {
    fn new(label: &str) -> Self {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "intmax-pw-payout-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir.join("payout.snapshot"))
    }
}

impl Drop for TempSnapshot {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

fn b32(last: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, last]).unwrap()
}

fn addr(last: u32) -> Address {
    Address::from_u32_slice(&[0, 0, 0, 0, last]).unwrap()
}

fn request(token_index: u32, amount: u64, nullifier: u32) -> PreparePartialWithdrawalPayout {
    let channel_id = ChannelId::new(7).unwrap();
    let recipient = addr(0x71);
    let withdrawal = Withdrawal {
        recipient,
        token_index,
        amount: U256::from(amount),
        nullifier: b32(nullifier),
        aux_data: burn_descriptor(
            channel_id,
            nullifier,
            b32(0x1000 + nullifier),
            calculate_recipient_from_address(recipient),
            token_index,
            U256::from(amount),
        ),
    };
    let anchor = BlockProducerAnchor {
        generation: 8,
        entry_hash: b32(8),
        block_number: 5,
        timestamp: 50,
        extended_state_commitment: b32(0xee),
        bp_sig_chain: b32(0xbb),
    };
    let payout_json = serde_json::json!({
        "withdrawals": [{
            "recipient": withdrawal.recipient,
            "token_index": withdrawal.token_index,
            "amount": withdrawal.amount,
            "nullifier": withdrawal.nullifier,
            "aux_data": withdrawal.aux_data,
        }],
        "withdrawal_prover": addr(0x99),
        "block_number": anchor.block_number,
        "ext_commitment": anchor.extended_state_commitment,
    })
    .to_string();
    PreparePartialWithdrawalPayout {
        chain_id: 31337,
        rollup: addr(0x42),
        manager: addr(0x43),
        channel_id,
        signed_head_digest: b32(nullifier + 100),
        burn_base_nonce: nullifier,
        producer_receipt: BlockProducerReceipt {
            request_id: format!("burn-{nullifier}"),
            generation: 7,
            entry_hash: b32(7),
            block_number: 5,
            timestamp: 49,
            extended_state_commitment: b32(0xdd),
            bp_sig_chain: b32(0xba),
        },
        auth_digest: partial_withdrawal_auth_digest(&withdrawal),
        artifacts: PartialWithdrawalProofArtifacts {
            withdrawal,
            withdrawal_prover: addr(0x99),
            payout_json,
            withdrawal_mle_json: "{}".into(),
            producer_anchor: anchor,
            metrics: PartialWithdrawalProofMetrics {
                single_withdrawal_millis: 1,
                withdrawal_chain_millis: 2,
                withdrawal_final_millis: 3,
                wrap_mle_millis: 4,
                single_withdrawal_proof_bytes: 10,
                withdrawal_chain_proof_bytes: 11,
                withdrawal_final_proof_bytes: 12,
                mle_json_bytes: 2,
                peak_rss_bytes: Some(100),
            },
        },
    }
}

fn intent() -> BroadcastIntent {
    BroadcastIntent {
        caller: addr(0x71),
        start_block: 20,
        caller_nonce: 3,
        calldata_hash: b32(0xca11),
        credit_before: U256::default(),
    }
}

fn receipt(kind: L1CallKind, token: u32) -> L1TransactionReceipt {
    L1TransactionReceipt {
        tx_hash: b32(0x100 + token),
        block_hash: b32(0x200 + token),
        block_number: 21,
        chain_id: 31337,
        from: addr(0x71),
        to: addr(0x42),
        success: true,
        call_kind: kind,
        calldata_hash: b32(0xca11),
        transaction_nonce: 3,
        finalized_checkpoint: L1FinalizedCheckpoint {
            chain_id: 31337,
            block_number: 22,
            block_hash: b32(0x300 + token),
            parent_hash: b32(0x2ff + token),
            source: L1FinalitySource::DevnetLatest,
        },
        manager_finalized_auth_digest: None,
    }
}

fn finalize_receipt(auth_digest: Bytes32, token: u32) -> L1TransactionReceipt {
    let mut receipt = receipt(L1CallKind::FinalizePartialWithdrawal, token);
    receipt.tx_hash = b32(0xf000 + token);
    receipt.to = addr(0x43);
    receipt.manager_finalized_auth_digest = Some(auth_digest);
    receipt
}

fn finalize_candidate(
    store: &mut PartialWithdrawalPayoutStore,
    candidate_id: Bytes32,
) {
    let auth_digest = store.active().unwrap().unwrap().auth_digest;
    store
        .mark_finalize_broadcast(candidate_id, intent())
        .unwrap();
    store
        .confirm_finalize(
            candidate_id,
            FinalizeConfirmation {
                receipt: finalize_receipt(auth_digest, 0),
                manager_pending_observed: false,
                authorization_observed: true,
                nullifier_used_observed: false,
            },
        )
        .unwrap();
}

fn complete(store: &mut PartialWithdrawalPayoutStore, request: PreparePartialWithdrawalPayout) {
    let amount = request.artifacts.withdrawal.amount;
    let token = request.artifacts.withdrawal.token_index;
    let candidate = store.prepare(request).unwrap();
    finalize_candidate(store, candidate.candidate_id);
    store
        .mark_payout_broadcast(candidate.candidate_id, intent())
        .unwrap();
    store
        .confirm_payout(
            candidate.candidate_id,
            PayoutConfirmation {
                receipt: receipt(
                    if token == 0 {
                        L1CallKind::WithdrawNative
                    } else {
                        L1CallKind::WithdrawErc20
                    },
                    token,
                ),
                authorization_observed: false,
                finalized_anchor_observed: true,
                nullifier_used_observed: true,
                credit_before: U256::default(),
                credit_after: amount,
            },
        )
        .unwrap();
    store
        .mark_pull_broadcast(
            candidate.candidate_id,
            BroadcastIntent {
                credit_before: amount,
                ..intent()
            },
        )
        .unwrap();
    let done = store
        .confirm_pull(
            candidate.candidate_id,
            PullConfirmation {
                receipt: receipt(
                    if token == 0 {
                        L1CallKind::PullNative
                    } else {
                        L1CallKind::PullErc20
                    },
                    token,
                ),
                credit_before: amount,
                credit_after: U256::default(),
            },
        )
        .unwrap();
    assert!(done.is_complete());
}

#[test]
fn native_candidate_is_idempotent_locked_and_restart_safe() {
    let path = TempSnapshot::new("restart");
    let request = request(0, 6, 1);
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let first = store.prepare(request.clone()).unwrap();
    let again = store.prepare(request).unwrap();
    assert_eq!(first.candidate_id, again.candidate_id);
    assert!(matches!(
        PartialWithdrawalPayoutStore::open(&path.0),
        Err(PartialWithdrawalPayoutError::Locked(_))
    ));
    drop(store);
    let reopened = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    assert_eq!(
        reopened.active().unwrap().unwrap().candidate_id,
        first.candidate_id
    );
}

#[test]
fn native_and_erc20_require_success_receipts_and_recipient_pull() {
    for token in [0, 9] {
        let path = TempSnapshot::new(if token == 0 { "native" } else { "erc20" });
        let request = request(token, 6, token + 1);
        let amount = request.artifacts.withdrawal.amount;
        let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
        let candidate = store.prepare(request).unwrap();
        finalize_candidate(&mut store, candidate.candidate_id);
        store
            .mark_payout_broadcast(candidate.candidate_id, intent())
            .unwrap();

        let wrong = PayoutConfirmation {
            receipt: receipt(L1CallKind::WithdrawNative, token),
            authorization_observed: false,
            finalized_anchor_observed: true,
            nullifier_used_observed: true,
            credit_before: U256::default(),
            credit_after: amount,
        };
        if token != 0 {
            assert!(store.confirm_payout(candidate.candidate_id, wrong).is_err());
        }
        let kind = if token == 0 {
            L1CallKind::WithdrawNative
        } else {
            L1CallKind::WithdrawErc20
        };
        store
            .confirm_payout(
                candidate.candidate_id,
                PayoutConfirmation {
                    receipt: receipt(kind, token),
                    authorization_observed: false,
                    finalized_anchor_observed: true,
                    nullifier_used_observed: true,
                    credit_before: U256::default(),
                    credit_after: amount,
                },
            )
            .unwrap();
        assert!(!store.active().unwrap().unwrap().is_complete());
        store
            .mark_pull_broadcast(
                candidate.candidate_id,
                BroadcastIntent {
                    credit_before: amount,
                    ..intent()
                },
            )
            .unwrap();
        let pull_kind = if token == 0 {
            L1CallKind::PullNative
        } else {
            L1CallKind::PullErc20
        };
        let mut pull_receipt = receipt(pull_kind, token);
        pull_receipt.from = addr(0x70);
        assert!(
            store
                .confirm_pull(
                    candidate.candidate_id,
                    PullConfirmation {
                        receipt: pull_receipt,
                        credit_before: amount,
                        credit_after: U256::default(),
                    }
                )
                .is_err()
        );
        complete_after_payout(&mut store, candidate.candidate_id, token, amount);
    }
}

#[test]
fn manager_finalize_requires_exact_finalized_canonical_receipt_before_payout() {
    let path = TempSnapshot::new("manager-finalize-finality");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let candidate = store.prepare(request(0, 6, 19)).unwrap();

    assert!(
        store
            .mark_payout_broadcast(candidate.candidate_id, intent())
            .is_err()
    );
    store
        .mark_finalize_broadcast(candidate.candidate_id, intent())
        .unwrap();

    let confirmation = |receipt| FinalizeConfirmation {
        receipt,
        manager_pending_observed: false,
        authorization_observed: true,
        nullifier_used_observed: false,
    };
    let mut unfinalized = finalize_receipt(candidate.auth_digest, 0);
    unfinalized.finalized_checkpoint.block_number = unfinalized.block_number - 1;
    assert!(
        store
            .confirm_finalize(candidate.candidate_id, confirmation(unfinalized))
            .is_err()
    );

    let mut wrong_manager = finalize_receipt(candidate.auth_digest, 0);
    wrong_manager.to = addr(0x44);
    assert!(
        store
            .confirm_finalize(candidate.candidate_id, confirmation(wrong_manager))
            .is_err()
    );

    let wrong_auth = finalize_receipt(b32(0xbad), 0);
    assert!(
        store
            .confirm_finalize(candidate.candidate_id, confirmation(wrong_auth))
            .is_err(),
        "a zero-argument manager call must be bound to this candidate by its finalized event"
    );

    let mut replaced = finalize_receipt(candidate.auth_digest, 0);
    replaced.finalized_checkpoint.block_number = replaced.block_number;
    replaced.finalized_checkpoint.block_hash = b32(0xdead);
    assert!(
        store
            .confirm_finalize(candidate.candidate_id, confirmation(replaced))
            .is_err()
    );

    store
        .confirm_finalize(
            candidate.candidate_id,
            confirmation(finalize_receipt(candidate.auth_digest, 0)),
        )
        .unwrap();
    store
        .mark_payout_broadcast(candidate.candidate_id, intent())
        .unwrap();
}

#[test]
fn orphaned_or_unfinalized_payout_receipt_cannot_be_adopted() {
    let path = TempSnapshot::new("receipt-finality");
    let request = request(0, 6, 1);
    let amount = request.artifacts.withdrawal.amount;
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let candidate = store.prepare(request).unwrap();
    finalize_candidate(&mut store, candidate.candidate_id);
    store
        .mark_payout_broadcast(candidate.candidate_id, intent())
        .unwrap();

    let mut unfinalized = receipt(L1CallKind::WithdrawNative, 0);
    unfinalized.finalized_checkpoint.block_number = unfinalized.block_number - 1;
    let confirmation = |receipt| PayoutConfirmation {
        receipt,
        authorization_observed: false,
        finalized_anchor_observed: true,
        nullifier_used_observed: true,
        credit_before: U256::default(),
        credit_after: amount,
    };
    assert!(
        store
            .confirm_payout(candidate.candidate_id, confirmation(unfinalized))
            .is_err()
    );

    let mut replaced = receipt(L1CallKind::WithdrawNative, 0);
    replaced.finalized_checkpoint.block_number = replaced.block_number;
    replaced.finalized_checkpoint.block_hash = b32(0xdead);
    assert!(
        store
            .confirm_payout(candidate.candidate_id, confirmation(replaced))
            .is_err()
    );
}

fn complete_after_payout(
    store: &mut PartialWithdrawalPayoutStore,
    candidate_id: Bytes32,
    token: u32,
    amount: U256,
) {
    let kind = if token == 0 {
        L1CallKind::PullNative
    } else {
        L1CallKind::PullErc20
    };
    let done = store
        .confirm_pull(
            candidate_id,
            PullConfirmation {
                receipt: receipt(kind, token),
                credit_before: amount,
                credit_after: U256::default(),
            },
        )
        .unwrap();
    assert!(done.is_complete());
}

#[test]
fn two_consecutive_partial_withdrawals_and_replay_are_fail_closed() {
    let path = TempSnapshot::new("twice");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    complete(&mut store, request(0, 6, 1)); // more than half of a ten-unit balance
    complete(&mut store, request(0, 4, 2)); // the final remainder

    let mut replay = request(0, 6, 1);
    replay.signed_head_digest = b32(999);
    replay.producer_receipt.request_id = "different-head-same-nullifier".into();
    assert!(matches!(
        store.prepare(replay),
        Err(PartialWithdrawalPayoutError::Conflict(message))
            if message.contains("nullifier")
    ));
}

#[test]
fn mutated_auth_payout_leaf_and_corrupt_snapshot_are_rejected() {
    let path = TempSnapshot::new("negative");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let mut bad_auth = request(0, 3, 1);
    bad_auth.auth_digest = b32(123);
    assert!(store.prepare(bad_auth).is_err());

    let mut bad_leaf = request(0, 3, 1);
    let mut json: serde_json::Value =
        serde_json::from_str(&bad_leaf.artifacts.payout_json).unwrap();
    json["withdrawals"][0]["amount"] = serde_json::Value::String("4".into());
    bad_leaf.artifacts.payout_json = json.to_string();
    assert!(store.prepare(bad_leaf).is_err());

    store.prepare(request(0, 3, 1)).unwrap();
    drop(store);
    let mut bytes = fs::read(&path.0).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path.0, bytes).unwrap();
    assert!(matches!(
        PartialWithdrawalPayoutStore::open(&path.0),
        Err(PartialWithdrawalPayoutError::Snapshot(message)) if message.contains("checksum")
    ));
}

fn onchain(
    candidate_auth: Bytes32,
    manager_pending: bool,
    authorization: bool,
    nullifier_used: bool,
) -> PartialWithdrawalOnchainState {
    PartialWithdrawalOnchainState {
        manager_pending,
        pending_auth_digest: if manager_pending {
            candidate_auth
        } else {
            Bytes32::default()
        },
        authorization,
        nullifier_used,
    }
}

#[test]
fn resume_state_machine_distinguishes_pending_authorized_and_consumed() {
    let path = TempSnapshot::new("resume-state");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let candidate = store.prepare(request(0, 6, 11)).unwrap();

    assert_eq!(
        partial_withdrawal_resume_action(
            &candidate,
            onchain(candidate.auth_digest, true, false, false),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::FinalizePending
    );
    // An authorization without our pre-broadcast journal is not adopted as local recovery
    // evidence; it could come from an orphaned or unrelated manager transaction.
    assert!(
        partial_withdrawal_resume_action(
            &candidate,
            onchain(candidate.auth_digest, false, true, false),
        )
        .is_err()
    );
    assert!(
        partial_withdrawal_resume_action(
            &candidate,
            PartialWithdrawalOnchainState {
                manager_pending: true,
                pending_auth_digest: b32(0xbad),
                authorization: false,
                nullifier_used: false,
            },
        )
        .is_err()
    );
    assert!(
        partial_withdrawal_resume_action(
            &candidate,
            onchain(candidate.auth_digest, false, false, true),
        )
        .is_err()
    );
    assert!(
        partial_withdrawal_resume_action(
            &candidate,
            onchain(candidate.auth_digest, false, true, true),
        )
        .is_err()
    );

    store
        .mark_finalize_broadcast(candidate.candidate_id, intent())
        .unwrap();
    let journaled = store.active().unwrap().unwrap();
    assert_eq!(
        partial_withdrawal_resume_action(
            &journaled,
            onchain(journaled.auth_digest, false, true, false),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::FinalizePending
    );
    store
        .confirm_finalize(
            candidate.candidate_id,
            FinalizeConfirmation {
                receipt: finalize_receipt(candidate.auth_digest, 0),
                manager_pending_observed: false,
                authorization_observed: true,
                nullifier_used_observed: false,
            },
        )
        .unwrap();
    let finalized = store.active().unwrap().unwrap();
    assert_eq!(
        partial_withdrawal_resume_action(
            &finalized,
            onchain(finalized.auth_digest, false, true, false),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::BroadcastPayout
    );
    assert_eq!(
        partial_withdrawal_resume_action(
            &finalized,
            PartialWithdrawalOnchainState {
                manager_pending: true,
                pending_auth_digest: b32(0xbeef),
                authorization: true,
                nullifier_used: false,
            },
        )
        .unwrap(),
        PartialWithdrawalResumeAction::BroadcastPayout,
        "a later manager request must not invalidate this candidate's finalized authorization"
    );
}

#[test]
fn crash_boundaries_reopen_broadcast_hash_and_consumed_confirmation() {
    let path = TempSnapshot::new("crash-boundaries");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let candidate = store.prepare(request(0, 6, 12)).unwrap();
    store
        .mark_finalize_broadcast(candidate.candidate_id, intent())
        .unwrap();
    drop(store); // crash after manager-finalization intent, before send/hash persistence

    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let resumed = store.active().unwrap().unwrap();
    assert_eq!(
        partial_withdrawal_resume_action(
            &resumed,
            onchain(resumed.auth_digest, true, false, false),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::FinalizePending
    );
    let finalize_hash = finalize_receipt(resumed.auth_digest, 0).tx_hash;
    store
        .record_finalize_tx_hash(resumed.candidate_id, finalize_hash)
        .unwrap();
    drop(store); // crash after manager send returned, before finalized receipt adoption

    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let resumed = store.active().unwrap().unwrap();
    assert_eq!(resumed.finalize_tx_hashes, [finalize_hash]);
    store
        .confirm_finalize(
            resumed.candidate_id,
            FinalizeConfirmation {
                receipt: finalize_receipt(resumed.auth_digest, 0),
                manager_pending_observed: false,
                authorization_observed: true,
                nullifier_used_observed: false,
            },
        )
        .unwrap();
    drop(store); // crash after finalized manager receipt, before proof-payout intent

    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let resumed = store.active().unwrap().unwrap();
    store
        .mark_payout_broadcast(resumed.candidate_id, intent())
        .unwrap();
    drop(store); // crash after the durable intent, before send/hash persistence

    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let resumed = store.active().unwrap().unwrap();
    assert_eq!(
        partial_withdrawal_resume_action(
            &resumed,
            onchain(resumed.auth_digest, false, true, false),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::ReconcilePayout
    );
    // The process may also die after the payout is mined but before cast returns a hash. The
    // one-shot authorization is then gone and the manager is non-pending; the durable intent is
    // still sufficient to enter sender/nonce canonical-receipt reconciliation.
    assert_eq!(
        partial_withdrawal_resume_action(
            &resumed,
            onchain(resumed.auth_digest, false, false, true),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::ReconcilePayout
    );
    let tx_hash = receipt(L1CallKind::WithdrawNative, 0).tx_hash;
    store
        .record_payout_tx_hash(resumed.candidate_id, tx_hash)
        .unwrap();
    drop(store); // crash after send returned, before the receipt was confirmed

    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let resumed = store.active().unwrap().unwrap();
    assert_eq!(resumed.payout_tx_hashes, [tx_hash]);
    store
        .confirm_payout(
            resumed.candidate_id,
            PayoutConfirmation {
                receipt: receipt(L1CallKind::WithdrawNative, 0),
                authorization_observed: false,
                finalized_anchor_observed: true,
                nullifier_used_observed: true,
                credit_before: U256::default(),
                credit_after: U256::from(6u64),
            },
        )
        .unwrap();
    drop(store); // crash after proof payout confirmation, before recipient pull

    let store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let resumed = store.active().unwrap().unwrap();
    assert_eq!(
        partial_withdrawal_resume_action(
            &resumed,
            onchain(resumed.auth_digest, false, false, true),
        )
        .unwrap(),
        PartialWithdrawalResumeAction::ContinueAfterPayout
    );
}

#[test]
fn payout_confirmation_requires_the_authorization_to_be_consumed() {
    let path = TempSnapshot::new("auth-consumed");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let candidate = store.prepare(request(0, 6, 13)).unwrap();
    finalize_candidate(&mut store, candidate.candidate_id);
    store
        .mark_payout_broadcast(candidate.candidate_id, intent())
        .unwrap();
    let rejected = store.confirm_payout(
        candidate.candidate_id,
        PayoutConfirmation {
            receipt: receipt(L1CallKind::WithdrawNative, 0),
            authorization_observed: true,
            finalized_anchor_observed: true,
            nullifier_used_observed: true,
            credit_before: U256::default(),
            credit_after: U256::from(6u64),
        },
    );
    assert!(matches!(
        rejected,
        Err(PartialWithdrawalPayoutError::InvalidRequest(message))
            if message.contains("consume authorization")
    ));
}

#[test]
fn external_recipient_handoff_completes_workflow_without_a_fake_pull_receipt() {
    let path = TempSnapshot::new("external-recipient");
    let mut store = PartialWithdrawalPayoutStore::open(&path.0).unwrap();
    let candidate = store.prepare(request(0, 6, 14)).unwrap();
    assert!(
        store
            .mark_recipient_pull_delegated(candidate.candidate_id)
            .is_err()
    );
    finalize_candidate(&mut store, candidate.candidate_id);
    store
        .mark_payout_broadcast(candidate.candidate_id, intent())
        .unwrap();
    store
        .confirm_payout(
            candidate.candidate_id,
            PayoutConfirmation {
                receipt: receipt(L1CallKind::WithdrawNative, 0),
                authorization_observed: false,
                finalized_anchor_observed: true,
                nullifier_used_observed: true,
                credit_before: U256::default(),
                credit_after: U256::from(6u64),
            },
        )
        .unwrap();
    let handed_off = store
        .mark_recipient_pull_delegated(candidate.candidate_id)
        .unwrap();
    assert!(handed_off.is_complete());
    assert!(handed_off.pull_confirmation.is_none());

    // Completion writes the nullifier ledger and releases the single active slot for the next PW.
    let next = store.prepare(request(0, 4, 15)).unwrap();
    assert_ne!(next.candidate_id, candidate.candidate_id);
}
