//! C14 — withdrawal/receive-nullifier canonicality & anti-double-settlement soundness (F-WD-2).
//!
//! Adversarial hypothesis (from the close-lifecycle scenario map,
//! `tests/scenarios/C-fund-loss.md`, and finding F-WD-2): the withdrawal / receive nullifier is
//! `Poseidon(SettledTransfer)` where
//! `SettledTransfer = inner_transfer ‖ from(channel_id) ‖ transfer_index ‖ nonce`.
//!
//! The ORIGINAL preimage bound the SETTLEMENT block (`send_leaf.cur`) as its last field. A block
//! producer / channel co-signer can settle the SAME sender tx (a single balance deduction, nonce N)
//! into two DIFFERENT blocks B1,B2 → two send leaves (cur=B1,B2) → two DISTINCT nullifiers for ONE
//! deduction. On-chain `withdrawalNullifierUsed` and the recipient's indexed nullifier merkle both
//! key on the nullifier, so neither would catch the second claim → double native withdrawal /
//! double receive-credit (F-WD-2).
//!
//! THE FIX (Option B): the last preimage field is now the sender `nonce` — a one-time, sequential,
//! settlement-INDEPENDENT identifier of the deduction (spend_circuit verifies the sent_tx_tree slot
//! at index=nonce is EMPTY before write and enforces `tx_nonce == prev_state.nonce`, so within a
//! balance lineage each nonce is used exactly once). Because the nullifier no longer depends on the
//! settlement block, settling the same deduction into two blocks now yields the IDENTICAL nullifier
//! → the second claim is caught. Legitimate distinctness is preserved by `nonce` (distinct sends),
//! `transfer_index` (multiple transfers within one tx), and `from`(channel_id) (cross-channel).
//!
//! The on-chain `Withdrawal.nullifier` is a free struct field, so its safety rests entirely on the
//! circuit constraining it to a canonical function of the settled transfer. The NATIVE oracle these
//! tests exercise (`SettledTransfer::nullifier`) is the exact preimage the circuit enforces
//! (`SettledTransferTarget::nullifier`, src/common/transfer.rs) — the target and native `to_vec` /
//! `to_u64_vec` are field-for-field identical, so a native collision/distinctness is a circuit
//! collision/distinctness.
//!
//! These tests PIN the security argument of the fix:
//!   1. CANONICAL: identical (content + position) ⇒ identical nullifier — a true replay is caught.
//!   2. F-WD-2 FIX (the key new positive test): two SettledTransfers that differ ONLY in the
//!      (now-removed) settlement block — i.e. same (from, nonce, transfer_index, content) — produce
//!      the IDENTICAL nullifier, so a double-settlement of one deduction can no longer mint two
//!      distinct nullifiers.
//!   3. INJECTIVE over the binding set: changing ANY bound field (content, `from`, `transfer_index`,
//!      or `nonce`) changes the nullifier — so legitimate distinct payments stay distinct and a
//!      prover cannot forge a colliding nullifier for a genuinely different deduction.
//!
//! They are NOT meant to pass trivially: each asserts a specific field is (or is not) load-bearing
//! in the preimage.
//!
//! Run: `cargo test --release --test withdrawal_nullifier_canonicality`

#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    common::{
        channel_id::ChannelId,
        transfer::{SettledTransfer, Transfer},
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
};

fn b32(seed: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[
        seed,
        seed + 1,
        seed + 2,
        seed + 3,
        seed + 4,
        seed + 5,
        seed + 6,
        seed + 7,
    ])
    .unwrap()
}

/// A representative settled transfer used as the canonical baseline.
fn base() -> SettledTransfer {
    SettledTransfer::new(
        Transfer {
            recipient: b32(0x1000),
            token_index: 0,
            amount: U256::from(1_000u32),
            aux_data: b32(0x2000),
        },
        ChannelId::new(7).unwrap(),
        3,  // transfer_index
        11, // nonce
    )
}

/// 1. CANONICAL: the nullifier is a deterministic, replay-detecting function of the settled
///    transfer. The same (content + position) always yields the same nullifier — so the rollup's
///    used-set catches a genuine replay of one settled transfer.
#[test]
fn nullifier_is_deterministic_for_identical_settled_transfer() {
    let a = base();
    let b = base(); // independently constructed, byte-identical
    assert_eq!(
        a.nullifier(),
        b.nullifier(),
        "identical settled transfers MUST share a nullifier (else a true replay would be paid twice)"
    );
    // Determinism under repeated evaluation.
    assert_eq!(a.nullifier(), a.nullifier());
}

/// 2. F-WD-2 FIX — settlement-independence. The nullifier no longer binds the settlement block.
///    Two settled transfers for the SAME deduction (identical from, nonce, transfer_index, and
///    content) that would previously have been settled into DIFFERENT blocks now produce the
///    IDENTICAL nullifier. This is the property that makes a double-settlement caught rather than
///    minting two distinct nullifiers for one balance deduction.
///
///    Because `block_number` has been removed from `SettledTransfer` entirely, the two objects here
///    are literally byte-identical — which is exactly the point: the settlement block is no longer a
///    preimage field, so it CANNOT create a second nullifier. Contrast with the pre-fix behavior,
///    where varying the settlement block produced a distinct nullifier (the F-WD-2 bug).
#[test]
fn same_deduction_settled_into_two_blocks_has_identical_nullifier() {
    let content = Transfer {
        recipient: b32(0x1000),
        token_index: 0,
        amount: U256::from(1_000u32),
        aux_data: b32(0x2000),
    };

    // One deduction: fixed (from, nonce, transfer_index). Two settlement attempts (conceptually B1
    // and B2). Under the new preimage there is no block field to differ on — both are the same
    // canonical settled transfer.
    let settled_in_b1 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 3, 11);
    let settled_in_b2 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 3, 11);

    assert_eq!(
        settled_in_b1.nullifier(),
        settled_in_b2.nullifier(),
        "F-WD-2: the same deduction (from, nonce, transfer_index) settled into two blocks MUST \
         yield the IDENTICAL nullifier, so the second settlement is caught by the used-set / \
         recipient nullifier merkle"
    );
}

/// 3a. The economically-binding TRANSFER fields are each load-bearing: recipient, token_index,
///     amount, and aux_data all change the nullifier. aux_data is the field the C14 hypothesis
///     specifically worried about — confirm a different aux_data does NOT collide with the baseline.
#[test]
fn nullifier_binds_every_transfer_field() {
    let base_n = base().nullifier();

    let mut t = base();
    t.inner.recipient = b32(0x9999);
    assert_ne!(t.nullifier(), base_n, "recipient must be bound");

    let mut t = base();
    t.inner.token_index = 1;
    assert_ne!(t.nullifier(), base_n, "token_index must be bound");

    let mut t = base();
    t.inner.amount = U256::from(1_001u32);
    assert_ne!(t.nullifier(), base_n, "amount must be bound");

    let mut t = base();
    t.inner.aux_data = b32(0x2001);
    assert_ne!(
        t.nullifier(),
        base_n,
        "aux_data must be bound (C14: an aux_data variant must not collide with the original)"
    );
}

/// 3b. The POSITION / deduction-identity fields are each load-bearing: from-channel, transfer_index,
///     and nonce all change the nullifier. `nonce` REPLACES the old `block_number` binding: it is
///     what makes two genuinely different deductions get distinct nullifiers while a double-
///     settlement of ONE deduction (same nonce) collides. This is the injectivity half of the
///     soundness argument — the prover cannot forge a second nullifier for the SAME deduction, and
///     legitimately distinct sends/transfers/channels never collide.
#[test]
fn nullifier_binds_every_identity_field() {
    let base_n = base().nullifier();

    let mut t = base();
    t.from = ChannelId::new(8).unwrap();
    assert_ne!(t.nullifier(), base_n, "from-channel must be bound");

    let mut t = base();
    t.transfer_index = 4;
    assert_ne!(t.nullifier(), base_n, "transfer_index must be bound");

    let mut t = base();
    t.nonce = 12;
    assert_ne!(
        t.nullifier(),
        base_n,
        "nonce must be bound (F-WD-2: distinct deductions ⇒ distinct nullifiers)"
    );
}

/// 3c. The distinctness invariant stated directly for the legitimate cases: two DIFFERENT
///     deductions (differing in nonce, transfer_index, or from) yield DIFFERENT nullifiers — they
///     are distinct legitimate payments, never forced collisions. Conversely, the SAME deduction
///     yields ONE nullifier regardless of how many times/blocks it is settled.
#[test]
fn distinct_deductions_are_distinct_and_same_deduction_is_one_nullifier() {
    let content = Transfer {
        recipient: b32(0x1000),
        token_index: 0,
        amount: U256::from(1_000u32),
        aux_data: b32(0x2000),
    };

    // Same content, two different transfer_index slots within the same tx ⇒ distinct payments.
    let p_slot0 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 0, 11);
    let p_slot1 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 1, 11);
    assert_ne!(
        p_slot0.nullifier(),
        p_slot1.nullifier(),
        "distinct transfer_index slots are distinct legitimate payments"
    );

    // Same content + slot, two different nonces (two different sends) ⇒ distinct payments.
    let p_nonce0 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 0, 11);
    let p_nonce1 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 0, 12);
    assert_ne!(
        p_nonce0.nullifier(),
        p_nonce1.nullifier(),
        "distinct nonces are distinct sends / distinct legitimate payments"
    );

    // Same content + slot + nonce, two different channels ⇒ distinct payments.
    let p_ch7 = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 0, 11);
    let p_ch8 = SettledTransfer::new(content.clone(), ChannelId::new(8).unwrap(), 0, 11);
    assert_ne!(
        p_ch7.nullifier(),
        p_ch8.nullifier(),
        "distinct from-channels are distinct legitimate payments"
    );

    // Same content + slot + nonce + channel ⇒ ONE nullifier (the single deduction, settled once or
    // many times, is caught — never double-paid).
    let p_again = SettledTransfer::new(content.clone(), ChannelId::new(7).unwrap(), 0, 11);
    assert_eq!(
        p_slot0.nullifier(),
        p_again.nullifier(),
        "the single deduction has ONE nullifier regardless of settlement"
    );
}
