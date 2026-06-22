//! C15 — in-proof double-deposit / deposit-nullifier canonicality soundness.
//!
//! Adversarial hypothesis (`tests/scenarios/C-fund-loss.md` C15): if the SAME on-chain deposit could
//! be folded into a balance proof with two DIFFERENT nullifiers, the nullifier-tree double-insertion
//! guard would not catch the second fold → the channel could realize more than was deposited.
//!
//! The receive-deposit circuit derives the nullifier as `deposit.nullifier()` and Merkle-proves the
//! FULL `deposit` at position `deposit_index` against `public_state.deposit_tree_root`
//! (src/circuits/balance/receive_deposit_circuit.rs:153-167, 214-220). The deposit-tree LEAF hash is
//! `<Deposit as Leafable>::hash == deposit.poseidon_hash()` (src/common/deposit.rs:213-222), and the
//! nullifier is `deposit.poseidon_hash().into()`. Both cover `to_u64_vec()`, which INCLUDES
//! `deposit_index` AND `block_number` (src/common/deposit.rs:58-68).
//!
//! Consequence — these tests PIN it:
//!   (A) nullifier == the deposit-tree leaf hash. So the on-chain tree position commits the EXACT
//!       nullifier preimage: a deposit proven at `deposit_index` has exactly ONE nullifier.
//!   (B) the nullifier (= leaf) binds `block_number` and `deposit_index`. So the prover cannot fold
//!       the same deposit at a different block to mint a second nullifier — that would require a
//!       different leaf that is NOT in the on-chain tree (Merkle proof fails).
//!
//! NOTE the divergent `Deposit::hash_with_prev_hash` (src/common/deposit.rs:90-102) deliberately
//! EXCLUDES block_number/deposit_index — but that is the cumulative deposit HASH CHAIN, NOT the tree
//! leaf the receive-deposit circuit proves against. A regression that switched the deposit-tree leaf
//! to that chain hash (dropping block/index) while the nullifier kept them would re-open C15 — assert
//! (A) below would then fail (leaf hash != nullifier). This is the soundness coupling under test.
//!
//! Re-folding the SAME deposit (identical nullifier) is separately blocked by the nullifier-tree
//! insertion guard — see `tests/nullifier_duplicate_insertion_poc.rs` (BAL-CRIT-001 regression).
//!
//! Run: `cargo test --release --test deposit_nullifier_canonicality`

#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    common::{deposit::Deposit, u63::{BlockNumber, U63}},
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait as _},
    utils::leafable::Leafable,
};

fn b32(seed: u32) -> Bytes32 {
    Bytes32::from_u32_slice(&[seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed + 6, seed + 7])
        .unwrap()
}

fn base() -> Deposit {
    Deposit {
        deposit_index: U63::new(5).unwrap(),
        block_number: BlockNumber::new(42).unwrap(),
        depositor: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
        recipient: b32(0x1000),
        token_index: 0,
        amount: U256::from(1_000u32),
        aux_data: b32(0x2000),
    }
}

/// (A) SOUNDNESS COUPLING: the deposit's nullifier IS its deposit-tree leaf hash. This is what makes
///     the Merkle inclusion at `deposit_index` bind the nullifier preimage — there is exactly one
///     nullifier per on-chain tree leaf. A regression that decoupled them (e.g. a leaf hash that
///     dropped block_number/deposit_index) would re-open the C15 double-fold gap.
#[test]
fn nullifier_equals_deposit_tree_leaf_hash() {
    let d = base();
    let leaf_hash: Bytes32 = <Deposit as Leafable>::hash(&d).into();
    assert_eq!(
        d.nullifier(), leaf_hash,
        "deposit nullifier MUST equal the deposit-tree leaf hash (the on-chain inclusion that binds it)"
    );
}

/// Determinism: the same deposit always yields the same nullifier (so a true re-fold is detectable).
#[test]
fn nullifier_is_deterministic() {
    assert_eq!(base().nullifier(), base().nullifier());
}

/// (B) The nullifier binds POSITION: deposit_index and block_number both change it. So the same
///     economic deposit folded at a different block/index is a DIFFERENT leaf — which cannot be in
///     the on-chain deposit tree, so its inclusion proof fails. No second nullifier for one deposit.
#[test]
fn nullifier_binds_deposit_index_and_block_number() {
    let base_n = base().nullifier();

    let mut d = base();
    d.deposit_index = U63::new(6).unwrap();
    assert_ne!(d.nullifier(), base_n, "deposit_index must be bound (C15: no re-index re-fold)");

    let mut d = base();
    d.block_number = BlockNumber::new(43).unwrap();
    assert_ne!(d.nullifier(), base_n, "block_number must be bound (C15: no re-block re-fold)");
}

/// The nullifier binds every economic field, so two economically-distinct deposits never collide.
#[test]
fn nullifier_binds_every_economic_field() {
    let base_n = base().nullifier();

    let mut d = base();
    d.depositor = Address::from_u32_slice(&[9, 9, 9, 9, 9]).unwrap();
    assert_ne!(d.nullifier(), base_n, "depositor must be bound");

    let mut d = base();
    d.recipient = b32(0x9999);
    assert_ne!(d.nullifier(), base_n, "recipient must be bound");

    let mut d = base();
    d.token_index = 1;
    assert_ne!(d.nullifier(), base_n, "token_index must be bound");

    let mut d = base();
    d.amount = U256::from(1_001u32);
    assert_ne!(d.nullifier(), base_n, "amount must be bound");

    let mut d = base();
    d.aux_data = b32(0x2001);
    assert_ne!(d.nullifier(), base_n, "aux_data must be bound");
}
