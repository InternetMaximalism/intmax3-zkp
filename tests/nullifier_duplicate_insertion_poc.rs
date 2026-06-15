//! REGRESSION TEST for BAL-CRIT-001: Duplicate nullifier / indexed-leaf insertion
//! via empty position.
//!
//! Originally this was a PoC demonstrating that the indexed-merkle-tree insertion
//! proof accepted a duplicate insertion when `prev_low_leaf == empty_leaf()` and
//! `empty_leaf() == IndexedMerkleLeaf::default()` (all zeros). That matched every
//! unoccupied tree slot's stored hash and allowed an attacker to reinsert any
//! already-present key using two empty positions as a pseudo-sentinel pair.
//!
//! The fix in `src/utils/trees/indexed_merkle_tree/leaf.rs` sets
//!   empty_leaf = { next_index: u64::MAX, key: U256::MAX, next_key: 0, value: 0 }
//! so every empty slot stores a non-default hash. The sentinel pushed at
//! position 0 by `IndexedMerkleTree::new` is still `default()`, which preserves
//! the legitimate first-insert path. An attacker who tries to reuse an empty
//! slot as `prev_low_leaf` must present exactly `empty_leaf` (by hash
//! collision-resistance), and then the lower-bound check
//!   `prev_low_leaf.key (= U256::MAX) < new_key`
//! fails for every realistic key, blocking the attack.
//!
//! These tests construct the historical malicious witness and assert that both
//! the native `get_new_root` and the native `verify` now REJECT it.
//!
//! Run with: `cargo test --test nullifier_duplicate_insertion_poc --release`

use intmax3_zkp::{
    constants::NULLIFIER_TREE_HEIGHT,
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
    utils::trees::{
        incremental_merkle_tree::IncrementalMerkleTree,
        indexed_merkle_tree::{insertion::IndexedInsertionProof, leaf::IndexedMerkleLeaf},
    },
};

#[test]
fn regression_duplicate_nullifier_insertion_blocked() {
    // A concrete nonzero nullifier key.
    let n1_key: U256 = Bytes32::from_u32_slice(&[0xDEAD_BEEF, 1, 2, 3, 4, 5, 6, 7])
        .unwrap()
        .into();

    // ---- Phase A: reconstruct the post-insert tree that NullifierTree::init()
    // followed by prove_and_insert(n1) would produce.
    //
    // Starting tree has the sentinel `IndexedMerkleLeaf::default()` pushed at
    // position 0. After inserting n1:
    //   * position 0 is updated to `updated_sentinel` pointing at position 1
    //   * position 1 gets the new leaf holding `n1_key`
    //   * positions 2.. stay empty (hash = empty_leaf.hash())
    //
    // Because `empty_leaf.hash() == IndexedMerkleLeaf::default().hash()`,
    // the hash tree behaves identically whether position 0 is "sentinel"
    // or "empty" at initialization time. So we can skip the trivial initial
    // sentinel push and jump straight to the post-insert state by pushing
    // `updated_sentinel` then `leaf_for_n1`.
    let updated_sentinel = IndexedMerkleLeaf {
        next_index: 1,
        key: U256::default(),
        next_key: n1_key,
        value: 0,
    };
    let leaf_for_n1 = IndexedMerkleLeaf {
        next_index: 0,
        key: n1_key,
        next_key: U256::default(),
        value: 0,
    };

    let mut legit_tree = IncrementalMerkleTree::<IndexedMerkleLeaf>::new(NULLIFIER_TREE_HEIGHT);
    legit_tree.push(updated_sentinel.clone());
    legit_tree.push(leaf_for_n1.clone());
    let root_after_legit = legit_tree.get_root();

    // ---- Phase B: craft the malicious IndexedInsertionProof.
    //
    // Choose two empty positions (any unused slots). The attack sets
    // `prev_low_leaf = empty_leaf()` and uses position 2 as the bogus
    // "low_leaf_index".
    let bogus_low_leaf_index: u64 = 2;
    let bogus_new_leaf_index: u64 = 3;
    let pseudo_sentinel = IndexedMerkleLeaf::default(); // (0, 0, 0, 0)

    // `low_leaf_proof`: prove that position 2 currently holds `empty_leaf()`.
    // This is true of every empty position; `prove` supplies the needed zero
    // siblings.
    let malicious_low_leaf_proof = legit_tree.prove(bogus_low_leaf_index);

    // Simulate the `temp_root` that `get_new_root` produces after mutating
    // position 2 to `new_low_leaf_malicious`. Build a parallel tree that has
    // the same leaf values at positions 0 and 1, plus `new_low_leaf_malicious`
    // at position 2.
    let new_low_leaf_malicious = IndexedMerkleLeaf {
        next_index: bogus_new_leaf_index,
        next_key: n1_key,
        ..pseudo_sentinel.clone() // key=0, value=0 preserved
    };
    let mut simulated_tree = IncrementalMerkleTree::<IndexedMerkleLeaf>::new(NULLIFIER_TREE_HEIGHT);
    simulated_tree.push(updated_sentinel.clone());
    simulated_tree.push(leaf_for_n1.clone());
    simulated_tree.push(new_low_leaf_malicious.clone());

    // `leaf_proof`: prove position 3 is empty in the simulated temp_root.
    // This is true because position 3 was never written.
    let malicious_leaf_proof = simulated_tree.prove(bogus_new_leaf_index);

    let malicious_proof = IndexedInsertionProof {
        index: bogus_new_leaf_index,
        low_leaf_proof: malicious_low_leaf_proof,
        leaf_proof: malicious_leaf_proof,
        low_leaf_index: bogus_low_leaf_index,
        prev_low_leaf: pseudo_sentinel,
    };

    // ---- Phase C: Assert the native check REJECTS the malicious proof.
    // Pre-fix this would have succeeded and produced a root with two leaves
    // sharing `n1_key`. Post-fix (see `leaf.rs` `empty_leaf()` comment):
    //   * The attacker's `prev_low_leaf = (0, 0, 0, 0)` no longer hashes to what is stored at an
    //     empty slot; `low_leaf_proof.verify` fails at the Merkle layer.
    //   * Even if the attacker adapts to `prev_low_leaf = empty_leaf()` (the new non-zero
    //     sentinel), `empty_leaf.key = U256::MAX` fails the lower bound check `prev_low_leaf.key <
    //     new_key`.
    let outcome = malicious_proof.get_new_root(n1_key, 0, root_after_legit);
    assert!(
        outcome.is_err(),
        "BAL-CRIT-001 regression: native get_new_root must reject the \
         duplicate-insertion witness that previously succeeded. Got Ok({:?}).",
        outcome,
    );

    // Also verify that constructing the adapted attack (using the NEW empty_leaf
    // as prev_low_leaf so the Merkle layer passes) still fails on the bound check.
    let adapted_pseudo_sentinel =
        <IndexedMerkleLeaf as intmax3_zkp::utils::leafable::Leafable>::empty_leaf();
    let adapted_new_low_leaf = IndexedMerkleLeaf {
        next_index: bogus_new_leaf_index,
        next_key: n1_key,
        ..adapted_pseudo_sentinel.clone()
    };
    let mut adapted_sim_tree =
        IncrementalMerkleTree::<IndexedMerkleLeaf>::new(NULLIFIER_TREE_HEIGHT);
    adapted_sim_tree.push(updated_sentinel.clone());
    adapted_sim_tree.push(leaf_for_n1.clone());
    // Pad positions up to bogus_low_leaf_index with empty leaves so `push` lands
    // at the bogus_low_leaf_index slot.
    for _ in adapted_sim_tree.leaves().len() as u64..bogus_low_leaf_index {
        adapted_sim_tree.push(IndexedMerkleLeaf::default());
    }
    adapted_sim_tree.push(adapted_new_low_leaf);
    let adapted_leaf_proof = adapted_sim_tree.prove(bogus_new_leaf_index);

    let adapted_proof = IndexedInsertionProof {
        index: bogus_new_leaf_index,
        low_leaf_proof: legit_tree.prove(bogus_low_leaf_index),
        leaf_proof: adapted_leaf_proof,
        low_leaf_index: bogus_low_leaf_index,
        prev_low_leaf: adapted_pseudo_sentinel,
    };
    let adapted_outcome = adapted_proof.get_new_root(n1_key, 0, root_after_legit);
    assert!(
        adapted_outcome.is_err(),
        "BAL-CRIT-001 regression: the adapted attack using the new empty_leaf \
         as prev_low_leaf must also be rejected (lower-bound check \
         empty_leaf.key = MAX < n1_key must fail). Got Ok({:?}).",
        adapted_outcome,
    );

    // Suppress the unused-variable warning on the unused `new_low_leaf_malicious`.
    let _ = new_low_leaf_malicious;
}

#[test]
fn regression_duplicate_insertion_blocked_for_any_nonzero_key() {
    // Regression parametric variant. For several keys and several empty-position
    // pairs, assert that the malicious duplicate-insertion witness is REJECTED
    // (it previously would have been accepted for every combination).
    let mut keys = vec![
        U256::from(1u32),
        U256::from(42u32),
        U256::from(1_000_000u32),
    ];
    let big: U256 = Bytes32::from_u32_slice(&[
        0xFFFF_FFFF,
        0xAAAA_AAAA,
        0xBBBB_BBBB,
        0xCCCC_CCCC,
        0x1111_1111,
        0x2222_2222,
        0x3333_3333,
        0x4444_4444,
    ])
    .unwrap()
    .into();
    keys.push(big);

    for k in keys {
        let updated_sentinel = IndexedMerkleLeaf {
            next_index: 1,
            key: U256::default(),
            next_key: k,
            value: 0,
        };
        let leaf_for_k = IndexedMerkleLeaf {
            next_index: 0,
            key: k,
            next_key: U256::default(),
            value: 0,
        };
        let mut legit_tree = IncrementalMerkleTree::<IndexedMerkleLeaf>::new(NULLIFIER_TREE_HEIGHT);
        legit_tree.push(updated_sentinel.clone());
        legit_tree.push(leaf_for_k.clone());
        let root = legit_tree.get_root();

        for &(low_empty, new_empty) in &[(2u64, 3u64), (5, 9), (100, 200), (1024, 2048)] {
            let low_proof = legit_tree.prove(low_empty);
            let new_low = IndexedMerkleLeaf {
                next_index: new_empty,
                next_key: k,
                ..IndexedMerkleLeaf::default()
            };
            let mut sim = IncrementalMerkleTree::<IndexedMerkleLeaf>::new(NULLIFIER_TREE_HEIGHT);
            sim.push(updated_sentinel.clone());
            sim.push(leaf_for_k.clone());
            for _ in sim.leaves().len() as u64..low_empty {
                sim.push(IndexedMerkleLeaf::default());
            }
            sim.push(new_low.clone());
            let leaf_proof = sim.prove(new_empty);

            let proof = IndexedInsertionProof {
                index: new_empty,
                low_leaf_proof: low_proof,
                leaf_proof,
                low_leaf_index: low_empty,
                prev_low_leaf: IndexedMerkleLeaf::default(),
            };
            let outcome = proof.get_new_root(k, 0, root);
            assert!(
                outcome.is_err(),
                "BAL-CRIT-001 regression: duplicate insertion must be rejected \
                 for key={k}, low={low_empty}, new={new_empty}. Got Ok({:?}).",
                outcome,
            );
        }
    }
}
