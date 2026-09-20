//! Wire-contract guard for `BlockProducerCommand`: the JSONL surface the daemon reads from
//! `api/lib/block-producer.js`.
//!
//! Two independent bugs lived here, both invisible until a daemon actually ran:
//!   1. `rename_all_fields` was missing, so every field-bearing command (all carry `requestId`)
//!      failed to deserialize and the untagged `ServiceCommand` wrapper flattened the reason to a
//!      generic "did not match any variant" — the entire producer surface was unreachable from
//!      the client and no deposit could ever be journaled.
//!   2. The heavy payloads (`ChannelState`/`ChannelSnapshot`) were deserialized directly inside
//!      the internally-tagged enum, whose buffered `Content` tree rejects the `u8` token keys of
//!      the sparse `encBalances`/`pendingAdds` rows ("invalid type: string \"0\", expected u8").
//!      They now travel as `serde_json::Value` and are materialized in `execute` with `from_value`.
//!
//! These tests reconstruct the EXACT camelCase JSON the client sends, including a non-empty sparse
//! balance row, and assert both that the command parses and that its payload materializes back to
//! the typed value with the sparse keys intact.

use std::collections::BTreeMap;

use intmax3_zkp::{
    block_producer_service::BlockProducerCommand,
    common::{
        balance_state::BalanceState,
        channel::{ChannelFund, ChannelState, MemberSignature},
        channel_id::ChannelId,
    },
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait as _},
    regev::{encrypt::RegevCiphertext, REGEV_N, REGEV_Q},
};

fn nonzero_ciphertext() -> RegevCiphertext {
    RegevCiphertext {
        c1: (0..REGEV_N as u32).map(|i| (i * 2 + 1) % REGEV_Q).collect(),
        c2: (0..REGEV_N as u32).map(|i| (i * 3 + 2) % REGEV_Q).collect(),
    }
}

/// A `ChannelState` whose sparse `encBalances`/`pendingAdds` rows are NON-EMPTY, so serializing it
/// emits the `"0"` string token keys that break a `Content`-buffered deserialize. A genesis state
/// has all-padding rows and would not exercise the bug — which is exactly why the pre-existing
/// deposit-only restart test missed it.
fn state_with_sparse_row(channel: u64) -> ChannelState {
    let id = ChannelId::new(channel).unwrap();
    ChannelState {
        channel_id: id,
        epoch: 0,
        small_block_number: 0,
        close_freeze_nonce: 0,
        channel_fund: ChannelFund {
            channel_id: id,
            amounts: std::array::from_fn(|_| U256::default()),
            intmax_state_root: Bytes32::default(),
        },
        balance_state: BalanceState {
            channel_id: id,
            member_count: 1,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&[nonzero_ciphertext()]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
            recipients: BalanceState::pad_recipients(&[]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 3,
            pending_adds: BalanceState::pad_pending_adds_token0(&[7]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        },
        h2_tag: Bytes32::default(),
        shared_native_nullifier_root: Bytes32::default(),
        unallocated_confirmed_incoming: U256::default(),
        prev_digest: Bytes32::default(),
        digest: Bytes32::default(),
        member_signatures: Vec::<MemberSignature>::new(),
    }
}

fn assert_has_sparse_key(state: &ChannelState) {
    let json = serde_json::to_string(&state.balance_state).unwrap();
    assert!(
        json.contains("\"0\""),
        "fixture must emit a sparse u8 token key, or the test proves nothing"
    );
}

#[test]
fn sync_offchain_heads_parses_and_materializes_with_a_sparse_row() {
    let state = state_with_sparse_row(7);
    assert_has_sparse_key(&state);

    let wire = serde_json::json!({
        "command": "syncOffchainHeads",
        "requestId": "sync-1",
        "signedStates": [state],
    });
    let cmd: BlockProducerCommand =
        serde_json::from_str(&wire.to_string()).expect("syncOffchainHeads must parse from the client wire");
    match cmd {
        BlockProducerCommand::SyncOffchainHeads { request_id, signed_states } => {
            assert_eq!(request_id, "sync-1");
            // The payload rides as Value; the daemon materializes it with from_value. Do the same
            // here and confirm the sparse u8 keys survive.
            let states: Vec<ChannelState> =
                serde_json::from_value(signed_states).expect("from_value must coerce the u8 keys");
            assert_eq!(states.len(), 1);
            assert_eq!(states[0], state);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn register_parses_and_materializes_a_snapshot_field() {
    // `Register` carries a `ChannelSnapshot`; here the state alone is enough to prove the Value
    // boundary coerces the keys (the snapshot wrapper adds no map keys of its own).
    let state = state_with_sparse_row(8);
    let wire = serde_json::json!({
        "command": "register",
        "requestId": "reg-1",
        "snapshot": { "state": state, "record": null, "members": [], "settledTxAccumulator": null },
    });
    let cmd: BlockProducerCommand =
        serde_json::from_str(&wire.to_string()).expect("register must parse from the client wire");
    match cmd {
        BlockProducerCommand::Register { request_id, snapshot } => {
            assert_eq!(request_id, "reg-1");
            // The snapshot rides as Value; its `state.balanceState` still carries the sparse keys.
            let bs = &snapshot["state"]["balanceState"];
            let rebuilt: Vec<BTreeMap<u8, u32>> =
                serde_json::from_value(bs["pendingAdds"].clone()).expect("u8 keys coerce");
            assert_eq!(rebuilt[0][&0], 7);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn snake_case_fields_are_rejected() {
    // Regression for the missing `rename_all_fields`: the client speaks camelCase, so a snake_case
    // field must NOT accidentally parse (that would mean the rename is off again and the real
    // client wire would silently mismatch).
    let wire = r#"{"command":"syncOffchainHeads","request_id":"x","signed_states":[]}"#;
    assert!(
        serde_json::from_str::<BlockProducerCommand>(wire).is_err(),
        "snake_case fields must not parse; the wire is camelCase"
    );
}
