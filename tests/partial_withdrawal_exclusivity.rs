//! Partial withdrawal — phase 0 SOUNDNESS GATE: receive-vs-withdraw exclusivity.
//!
//! Spec: architecture-audit/abstract2-1.md §2.6/§3.6; plan: partial-withdrawal-impl-plan.md phase
//! 0.
//!
//! INVARIANT UNDER TEST (must hold before any partial-withdrawal fund logic is built):
//!   a single settled transfer can be consumed AT MOST ONE WAY — either RECEIVED by a destination
//!   channel (`receive_transfer_circuit`) OR WITHDRAWN to L1 (`single_withdrawal` ->
//! `withdrawNative`)   — NEVER both. If both were possible (same `SettledTransfer::nullifier`,
//! different on-chain   used-sets), the value would reach a channel AND L1 = double-spend.
//!
//! The exclusivity is RECIPIENT-TAG-DRIVEN and enforced IN-CIRCUIT:
//!   - receive_transfer_circuit.rs:426-435 CONNECTS `transfer.recipient ==
//!     calculate_recipient_from_user_id_circuit(receiver, salt)` — first byte = USER_ID_TAG (1).
//!   - single_withdrawal_circuit.rs (via extract_address_from_recipient_circuit,
//!     recipient.rs:78-87) CONNECTS `recipient.bytes[0] == ADDRESS_TAG (2)`.
//! A Bytes32 recipient has exactly one first byte, so it satisfies at most one path.
//!
//! These tests pin the NATIVE recipient functions the circuits call verbatim. A regression that
//! made the withdrawal gate accept a USER_ID_TAG recipient, or the receive gate accept an
//! ADDRESS_TAG recipient, would break exclusivity and is caught here. This is a soundness check,
//! not a unit test: it asserts the two consumption paths are provably disjoint over the recipient
//! domain.
//!
//! Run: `cargo test --release --test partial_withdrawal_exclusivity`

#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    circuits::balance::common::recipient::{
        calculate_recipient_from_address, calculate_recipient_from_user_id,
        extract_address_from_recipient,
    },
    common::{channel_id::ChannelId, salt::Salt},
    ethereum_types::{address::Address, u32limb_trait::U32LimbTrait as _},
};
use rand::{SeedableRng, rngs::StdRng};

// Mirror of the private tags in recipient.rs (USER_ID_TAG / ADDRESS_TAG). If these change, the
// circuits change too and this test must be revisited.
const USER_ID_TAG: u8 = 1;
const ADDRESS_TAG: u8 = 2;

fn an_address() -> Address {
    Address::from_hex("0x1234567890abcdef1234567890abcdef12345678").unwrap()
}

/// A channel-receive recipient (the form `receive_transfer_circuit` constrains to) carries the
/// USER_ID_TAG, so it is NEVER accepted by the withdrawal gate (`extract_address_from_recipient`).
#[test]
fn channel_receive_recipient_is_not_withdrawable() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let salt = Salt::rand(&mut rng);
    let recv = calculate_recipient_from_user_id(ChannelId::new(7).unwrap(), salt);

    assert_eq!(
        recv.to_bytes_be()[0],
        USER_ID_TAG,
        "receive recipient must carry USER_ID_TAG"
    );
    assert!(
        extract_address_from_recipient(recv).is_err(),
        "a channel-receive (USER_ID_TAG) recipient MUST NOT be extractable as a withdrawal"
    );
}

/// A withdrawal recipient carries the ADDRESS_TAG and decodes back to the L1 address. It can never
/// equal the channel-receive form (different first byte), so it is NEVER receivable by a channel.
#[test]
fn withdrawal_recipient_is_not_a_channel_receive_form() {
    let addr = an_address();
    let wd = calculate_recipient_from_address(addr);

    assert_eq!(
        wd.to_bytes_be()[0],
        ADDRESS_TAG,
        "withdrawal recipient must carry ADDRESS_TAG"
    );
    // Withdrawable + decodes to the right L1 address.
    assert_eq!(
        extract_address_from_recipient(wd).expect("ADDRESS_TAG recipient is withdrawable"),
        addr,
        "withdrawal recipient decodes back to the L1 address"
    );
    // Disjoint from EVERY channel-receive form: a USER_ID_TAG (1) recipient can never equal an
    // ADDRESS_TAG (2) recipient, so receive_transfer's `recipient ==
    // calculate_recipient_from_user_id` constraint can never be satisfied by a withdrawal
    // recipient.
    assert_ne!(
        wd.to_bytes_be()[0],
        USER_ID_TAG,
        "withdrawal form is not the receive form"
    );
}

/// The exclusivity theorem at the recipient-domain level: the two consumption paths' accepted
/// recipient sets are DISJOINT — no Bytes32 recipient is both a valid receive form and a valid
/// withdrawal form. Sampled over many (channel, salt) and addresses.
#[test]
fn receive_and_withdraw_recipient_domains_are_disjoint() {
    let mut rng = StdRng::seed_from_u64(1);
    for i in 0..64u64 {
        let salt = Salt::rand(&mut rng);
        let recv = calculate_recipient_from_user_id(ChannelId::new(i + 1).unwrap(), salt);
        // every receive form is tag 1 and not withdrawable
        assert_eq!(recv.to_bytes_be()[0], USER_ID_TAG);
        assert!(extract_address_from_recipient(recv).is_err());

        // build a withdrawal form from the low bytes of the salt as a pseudo-address
        let mut limbs = [0u32; 5];
        for (k, l) in limbs.iter_mut().enumerate() {
            *l = (i as u32).wrapping_mul(2654435761).wrapping_add(k as u32);
        }
        let addr = Address::from_u32_slice(&limbs).unwrap();
        let wd = calculate_recipient_from_address(addr);
        assert_eq!(wd.to_bytes_be()[0], ADDRESS_TAG);
        // the two forms never coincide
        assert_ne!(
            recv, wd,
            "receive form and withdrawal form must never be equal"
        );
    }
}
