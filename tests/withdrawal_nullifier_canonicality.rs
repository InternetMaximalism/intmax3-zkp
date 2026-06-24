//! C14 — withdrawal-nullifier canonicality / anti-double-claim soundness.
//!
//! Adversarial hypothesis (from the close-lifecycle scenario map,
//! `tests/scenarios/C-fund-loss.md`): if the SAME economic settled transfer could be serialized
//! into two withdrawal leaves with DIFFERENT nullifiers, the rollup's `withdrawalNullifierUsed` set
//! would not catch the second claim → the payout could be drained twice.
//!
//! The on-chain `Withdrawal.nullifier` is a free struct field, so its safety rests entirely on the
//! circuit constraining it to a CANONICAL function of the underlying settled transfer. The single-
//! withdrawal circuit computes `nullifier = settled_transfer.nullifier(builder)`
//! (src/circuits/withdraw/single_withdrawal_circuit.rs:512) — i.e. a Poseidon hash over the settled
//! transfer's full economic identity AND its position (channel, transfer_index, block_number). The
//! NATIVE oracle these tests exercise (`SettledTransfer::nullifier`) is the exact preimage the
//! circuit enforces.
//!
//! These tests PIN the two halves of the soundness argument:
//!   1. CANONICAL: identical (content + position) ⇒ identical nullifier — so a true replay is
//!      caught.
//!   2. INJECTIVE over the binding set: changing ANY binding field (incl. aux_data) changes the
//!      nullifier — so the prover cannot mint a second nullifier for the same SIGNED transfer leaf
//!      without it also being a genuinely different settled transfer at a different position.
//!
//! A regression that dropped a field from the nullifier preimage (e.g. omitted `transfer_index` or
//! `block_number`) would make distinct legitimate payments collide, OR — worse — let an attacker
//! craft a colliding/forked nullifier. Either way these assertions would fail. They are NOT meant
//! to pass trivially: each asserts a specific field is load-bearing in the preimage.
//!
//! Run: `cargo test --release --test withdrawal_nullifier_canonicality`

#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    common::{
        channel_id::ChannelId,
        transfer::{SettledTransfer, Transfer},
        u63::BlockNumber,
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
        3, // transfer_index
        BlockNumber::new(42).unwrap(),
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

/// 2a. The economically-binding TRANSFER fields are each load-bearing: recipient, token_index,
///     amount, and aux_data all change the nullifier. aux_data is the field the C14 hypothesis
///     specifically worried about — confirm a different aux_data does NOT collide with the
/// baseline.
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

/// 2b. The POSITION fields are each load-bearing: from-channel, transfer_index, block_number all
///     change the nullifier. This is what makes two legitimate payments with identical economic
///     content (but distinct positions) get distinct nullifiers — and conversely makes it
/// impossible     to forge a second nullifier for the SAME position.
#[test]
fn nullifier_binds_every_position_field() {
    let base_n = base().nullifier();

    let mut t = base();
    t.from = ChannelId::new(8).unwrap();
    assert_ne!(t.nullifier(), base_n, "from-channel must be bound");

    let mut t = base();
    t.transfer_index = 4;
    assert_ne!(t.nullifier(), base_n, "transfer_index must be bound");

    let mut t = base();
    t.block_number = BlockNumber::new(43).unwrap();
    assert_ne!(t.nullifier(), base_n, "block_number must be bound");
}

/// 2c. The C14 attack, stated directly: two settled transfers with IDENTICAL economic content but
///     DIFFERENT positions (the only way to get two valid proofs) yield DIFFERENT nullifiers — i.e.
///     they are two distinct legitimate payments, not a double-spend of one. There is no
///     serialization of a SINGLE settled transfer that produces two distinct nullifiers.
#[test]
fn identical_content_distinct_positions_are_distinct_payments() {
    let content = Transfer {
        recipient: b32(0x1000),
        token_index: 0,
        amount: U256::from(1_000u32),
        aux_data: b32(0x2000),
    };

    // Same content, two different (transfer_index) slots within the same block/channel.
    let p0 = SettledTransfer::new(
        content.clone(),
        ChannelId::new(7).unwrap(),
        0,
        BlockNumber::new(42).unwrap(),
    );
    let p1 = SettledTransfer::new(
        content.clone(),
        ChannelId::new(7).unwrap(),
        1,
        BlockNumber::new(42).unwrap(),
    );
    assert_ne!(
        p0.nullifier(),
        p1.nullifier(),
        "distinct slots are distinct legitimate payments"
    );

    // Same content + same slot + same block ⇒ SAME nullifier (a replay is caught, not double-paid).
    let p0_again = SettledTransfer::new(
        content.clone(),
        ChannelId::new(7).unwrap(),
        0,
        BlockNumber::new(42).unwrap(),
    );
    assert_eq!(
        p0.nullifier(),
        p0_again.nullifier(),
        "the single settled transfer has ONE nullifier"
    );
}
