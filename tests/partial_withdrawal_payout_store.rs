use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use intmax3_zkp::{
    block_producer_service::{BlockProducerAnchor, BlockProducerReceipt},
    common::{channel_id::ChannelId, withdrawal::Withdrawal},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    partial_withdrawal_payout::{
        BroadcastIntent, L1CallKind, L1TransactionReceipt, PartialWithdrawalPayoutError,
        PartialWithdrawalPayoutStore, PartialWithdrawalProofArtifacts,
        PartialWithdrawalProofMetrics, PayoutConfirmation, PreparePartialWithdrawalPayout,
        PullConfirmation,
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
    let withdrawal = Withdrawal {
        recipient: addr(0x71),
        token_index,
        amount: U256::from(amount),
        nullifier: b32(nullifier),
        aux_data: b32(0x494d_4244),
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
        channel_id: ChannelId::new(7).unwrap(),
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
    }
}

fn complete(store: &mut PartialWithdrawalPayoutStore, request: PreparePartialWithdrawalPayout) {
    let amount = request.artifacts.withdrawal.amount;
    let token = request.artifacts.withdrawal.token_index;
    let candidate = store.prepare(request).unwrap();
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
                authorization_observed: true,
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
        store
            .mark_payout_broadcast(candidate.candidate_id, intent())
            .unwrap();

        let wrong = PayoutConfirmation {
            receipt: receipt(L1CallKind::WithdrawNative, token),
            authorization_observed: true,
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
                    authorization_observed: true,
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
