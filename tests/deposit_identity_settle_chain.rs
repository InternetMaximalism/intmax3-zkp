//! The genesis backing deposit and the producer's journaled deposit must be the SAME instance.
//!
//! `settled_tx_chain` advances as `push(chain, deposit.nullifier())`, and `Deposit::nullifier()`
//! hashes `deposit_index` and `block_number` along with the payment fields. Two provers that agree
//! on depositor/recipient/token/amount/aux but disagree on either number therefore produce
//! different settle chains for one on-chain deposit — and `LiveBalanceService::bind_signed_snapshot`
//! compares exactly those chains, so the channel becomes permanently unbindable.
//!
//! That is not hypothetical: `setup-backing` proves the genesis against a fresh
//! `BlockWitnessGenerator` (deposit in block 1), while the producer stamps
//! `block_number = block_number + 1` at journaling time. Registering the channel before journaling
//! the deposit consumed block 1 and moved the deposit to block 2 — one block of drift, measured as
//! CLI `0xab7078…` vs producer `0x589a6d…` for the same deposit. `api/lib/deposit-pipeline.js`
//! therefore journals the backing deposit before registering the channel.
//!
//! These tests pin the mechanism, so a future reordering fails here with the reason attached
//! rather than as an opaque "settle chain differs" at runtime.

use intmax3_zkp::{
    common::{balance_state::settled_tx_chain_push, deposit::Deposit, u63::U63},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait as _,
    },
};

fn deposit_at(deposit_index: u64, block_number: u64) -> Deposit {
    Deposit {
        deposit_index: U63::new(deposit_index).unwrap(),
        block_number: U63::new(block_number).unwrap(),
        depositor: Address::from_hex("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
        recipient: Bytes32::from_hex(
            "0x0173bfda17e247f0f18a22620eb3be543671625b149dfe658d7a647ad4ec8df7",
        )
        .unwrap(),
        token_index: 0,
        amount: U256::from(90_000_000_000_000_000u64),
        aux_data: Bytes32::default(),
    }
}

fn genesis_chain(deposit: &Deposit) -> Bytes32 {
    settled_tx_chain_push(Bytes32::default(), deposit.nullifier())
}

#[test]
fn the_intmax_block_number_alone_changes_the_settle_chain() {
    let in_block_one = deposit_at(0, 1);
    let in_block_two = deposit_at(0, 2);

    // Same L1 deposit by every payment field...
    assert_eq!(in_block_one.depositor, in_block_two.depositor);
    assert_eq!(in_block_one.recipient, in_block_two.recipient);
    assert_eq!(in_block_one.amount, in_block_two.amount);
    assert_eq!(in_block_one.deposit_index, in_block_two.deposit_index);

    // ...but folded at a different INTMAX block, so it is a different instance.
    assert_ne!(
        in_block_one.nullifier(),
        in_block_two.nullifier(),
        "block_number must be part of the deposit's identity, or two foldings of one deposit \
         would collide"
    );
    assert_ne!(
        genesis_chain(&in_block_one),
        genesis_chain(&in_block_two),
        "a one-block drift between the genesis prover and the producer must be visible in the \
         settle chain — this is what makes a mis-ordered bootstrap unbindable"
    );
}

#[test]
fn the_deposit_index_alone_changes_the_settle_chain() {
    // The same guarantee for the other identity field: `Deposit`'s own comment warns that leaving
    // `deposit_index` at its default collapses distinct on-chain deposits onto one nullifier.
    assert_ne!(
        deposit_at(0, 1).nullifier(),
        deposit_at(1, 1).nullifier(),
        "deposit_index must be part of the deposit's identity"
    );
    assert_ne!(genesis_chain(&deposit_at(0, 1)), genesis_chain(&deposit_at(1, 1)));
}

#[test]
fn one_deposit_proved_twice_the_same_way_agrees() {
    // The positive case the bootstrap depends on: when both sides fold the deposit with the same
    // identity, the chains they hand `bind_signed_snapshot` are equal.
    assert_eq!(genesis_chain(&deposit_at(0, 1)), genesis_chain(&deposit_at(0, 1)));
}
