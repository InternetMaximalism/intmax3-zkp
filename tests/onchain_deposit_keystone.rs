//! KEYSTONE: the Rust deposit witness exactly mirrors a REAL on-chain ETH deposit.
//!
//! This pins the values produced by an actual `IntmaxRollup.deposit{value}` call on a local anvil
//! (real ETH escrowed: `totalEscrowed` 0 -> 140) and asserts the Rust `Deposit::hash_with_prev_hash`
//! reproduces the on-chain `Deposited.newDepositHashChain` bit-for-bit. If this holds, a Rust
//! balance proof built from these fields is backed by a deposit that REALLY happened on-chain — not
//! a `BlockWitnessGenerator` fabrication. (The self-driving anvil version lives in the channel
//! deposit-backing flow; this fast test locks the contract<->Rust hash equivalence.)
//!
//! Captured from anvil (Foundry 1.5.1, IntmaxRollup @ 0xCf7E…0Fc9, tx 0x735a…56ad):
//!   deposit(recipient=0x1111…1111, tokenIndex=0, amount=140, aux=0) value=140 wei
//!   Deposited.newDepositHashChain = 0x10e6fb6cab835cddf7de29b5e04d77060ae245ef825d86ab6c07d4ab4518c1cf

use intmax3_zkp::{
    common::deposit::Deposit,
    ethereum_types::{
        address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait,
    },
};

#[test]
fn rust_deposit_hash_matches_onchain_eth_deposit() {
    let d = Deposit {
        // Not part of the hash (matches the contract: deposit_index/block_number excluded).
        deposit_index: Default::default(),
        block_number: Default::default(),
        depositor: Address::from_hex("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
        recipient: Bytes32::from_hex(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        token_index: 0,
        amount: U256::from(140u32),
        aux_data: Bytes32::default(),
    };
    // Rust folds the deposit into the chain exactly as the contract's `_computeDepositHash`
    // (genesis prev = 0). This MUST equal the on-chain `Deposited.newDepositHashChain`.
    let chain = d.hash_with_prev_hash(Bytes32::default());
    assert_eq!(
        chain.to_hex(),
        "0x10e6fb6cab835cddf7de29b5e04d77060ae245ef825d86ab6c07d4ab4518c1cf",
        "Rust deposit_hash_chain must reproduce the REAL on-chain depositHashChain"
    );
}
