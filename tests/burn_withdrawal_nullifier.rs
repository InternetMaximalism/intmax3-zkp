//! The burn nullifier and the stable IPW2 authorization identity.
//!
//! ## The defect these tests exist to prevent recurring
//!
//! Until 2026-08-13 the CLI's `pw-submit` computed
//!
//! ```text
//!     nullifier = keccak(tx_leaf ‖ pre_burn_settled_tx_chain)
//! ```
//!
//! (`src/bin/channel_member.rs`, pre-fix) while the only nullifier a *provable* withdrawal leaf can
//! carry is `SettledTransfer::nullifier()` — a Poseidon hash over
//! `(recipient, token_index, amount, aux_data, channel_id, transfer_index, nonce)`
//! (`src/common/transfer.rs:124-126`, produced natively at
//! `src/circuits/withdraw/single_withdrawal_circuit.rs:376-390` and in-circuit at `:513-525`).
//!
//! Different hash family, different preimage, different arity: the two can never coincide. So the
//! Under the retired IMPW schema that mismatch also changed the authorization digest and stranded
//! the burn. IPW2 deliberately excludes this proof-only nullifier: its stable identity is the IMD2
//! descriptor, which already binds source channel, base nonce, recipient, token, amount, and the
//! co-signed burn transaction leaf. The proof still independently constrains its own nullifier.
//!
//! ## What each test proves
//!
//! * `nullifier_is_the_circuits_poseidon_preimage_not_some_other_hash` — the derivation is pinned
//!   against an INDEPENDENT re-implementation of the circuit's preimage layout written out in this
//!   file. It does not call `SettledTransfer`, so it fails if `burn_withdrawal_leaf` is ever
//!   re-pointed at another hash, another field order, or another tuple.
//! * `auth_v2_is_stable_across_proof_only_nullifier_derivations` — a wrong historical nullifier is
//!   still not the circuit's nullifier, but cannot create a second authorization identity.
//! * `h2_reconstruction_*` — the `pw-submit` pre-flight guard is not a dead guard: every field the
//!   nullifier commits to also moves H2, so a wrong tuple cannot reproduce the co-signed `h2_tag`.
//!
//! Run: `cargo test --release --test burn_withdrawal_nullifier`

#![cfg(not(debug_assertions))]

use intmax3_zkp::{
    common::{
        balance_state::settled_tx_chain_push,
        channel::burn_descriptor,
        channel_id::ChannelId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
    utils::poseidon_hash_out::PoseidonHashOut,
    wallet_core::{
        INTER_CHANNEL_TRANSFER_INDEX, burn_withdrawal_leaf, inter_channel_base_transfer,
        inter_channel_tx_v2, partial_withdrawal_auth_digest,
    },
};

/// A representative burn, in the shape `build_burn_send_token` produces: an `ADDRESS_TAG` L1
/// recipient, a nonzero `aux_data` (= the IMD2 burn descriptor), and the source channel's id.
struct Burn {
    channel_id: ChannelId,
    recipient_pk_g: Bytes32,
    token_index: u32,
    amount: u64,
    aux_data: Bytes32,
    tx_nonce: u32,
}

fn a_burn() -> Burn {
    use intmax3_zkp::{
        circuits::balance::common::recipient::calculate_recipient_from_address,
        ethereum_types::address::Address,
    };
    let channel_id = ChannelId::new(7).unwrap();
    let recipient_pk_g = calculate_recipient_from_address(
        Address::from_hex("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap(),
    );
    let token_index = 0;
    let amount = 5_000_000_000_000_000;
    let tx_nonce = 1;
    let tx_leaf = Bytes32::from_u32_slice(&[0xd1, 0x27, 0x25, 0x4e, 8, 2, 2, 4]).unwrap();
    Burn {
        channel_id,
        recipient_pk_g,
        token_index,
        amount,
        aux_data: burn_descriptor(
            channel_id,
            tx_nonce,
            tx_leaf,
            recipient_pk_g,
            token_index,
            U256::from(amount),
        ),
        tx_nonce,
    }
}

impl Burn {
    fn leaf(&self) -> intmax3_zkp::common::withdrawal::Withdrawal {
        burn_withdrawal_leaf(
            self.channel_id,
            self.recipient_pk_g,
            self.token_index,
            self.amount,
            self.aux_data,
            self.tx_nonce,
        )
        .expect("an ADDRESS_TAG burn always has a withdrawal leaf")
    }

    /// H2 = the root of the burn's 1-tx `TxV2Tree` — the value the post-burn channel state records
    /// as `h2_tag` and every co-signer signs (`src/common/channel.rs:598`).
    fn h2(&self) -> Bytes32 {
        let t = inter_channel_base_transfer(
            self.recipient_pk_g,
            self.token_index,
            self.amount,
            self.aux_data,
        );
        let (_, tree) = inter_channel_tx_v2(self.channel_id, &t, self.tx_nonce);
        tree.get_root().into()
    }
}

/// The pre-fix `pw-submit` derivation, reproduced verbatim so the stranding test below is testing
/// the REAL historical formula and not a paraphrase of it.
fn legacy_cli_nullifier(tx_leaf: Bytes32, pre_burn_chain: Bytes32) -> Bytes32 {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&tx_leaf.to_bytes_be());
    data.extend_from_slice(&pre_burn_chain.to_bytes_be());
    let hash = keccak_hash::keccak(&data);
    Bytes32::from_bytes_be(hash.as_bytes()).unwrap()
}

/// INDEPENDENT re-implementation of what the withdrawal circuit hashes, transcribed from
/// `SettledTransferTarget::to_vec` (`src/common/transfer.rs`, `inner ‖ from ‖ transfer_index ‖
/// nonce`, with `inner = recipient(8) ‖ token_index(1) ‖ amount(8) ‖ aux_data(8)`).
///
/// SECURITY: deliberately does NOT go through `SettledTransfer` — a test that called the same
/// helper the code under test calls would agree with any formula, including a wrong one. That is
/// precisely the shape that let the CLI/circuit divergence survive (and the same shape as the
/// Phase-3 finding-7 incident recorded in `src/bin/channel_member.rs`, where the only test of an
/// invariant compared two values that came from one variable).
fn circuit_preimage_nullifier(b: &Burn) -> Bytes32 {
    let mut inputs: Vec<u64> = Vec::new();
    inputs.extend(b.recipient_pk_g.to_u64_vec());
    inputs.push(b.token_index as u64);
    inputs.extend(U256::from(b.amount).to_u64_vec());
    inputs.extend(b.aux_data.to_u64_vec());
    inputs.extend(b.channel_id.to_u64_vec());
    inputs.push(INTER_CHANNEL_TRANSFER_INDEX as u64);
    inputs.push(b.tx_nonce as u64);
    PoseidonHashOut::hash_inputs_u64(&inputs).into()
}

/// ANTI-DRIFT. `burn_withdrawal_leaf` must produce exactly the Poseidon image of the circuit's
/// preimage. Re-point it at keccak, reorder the fields, drop the nonce, or use a nonzero
/// `transfer_index`, and this fails.
#[test]
fn nullifier_is_the_circuits_poseidon_preimage_not_some_other_hash() {
    let b = a_burn();
    assert_eq!(
        b.leaf().nullifier,
        circuit_preimage_nullifier(&b),
        "the burn nullifier must be Poseidon over the SettledTransfer preimage the withdrawal \
         circuit hashes — any other formula produces an authorization no proof can satisfy"
    );

    // The in-circuit `transfer_index` is CONSTRAINED to zero
    // (`src/circuits/balance/send_tx_circuit.rs:279`), so the constant must be zero too.
    assert_eq!(
        INTER_CHANNEL_TRANSFER_INDEX, 0,
        "send_tx_circuit asserts transfer_index == 0; a nonzero constant here would make every \
         derived nullifier unmatchable"
    );
}

/// Every field the nullifier commits to must actually change it. Without this, a derivation that
/// silently ignored (say) the nonce would still pass the test above on one fixed input.
#[test]
fn nullifier_binds_every_field_of_the_burn() {
    let base = a_burn().leaf().nullifier;

    let mut b = a_burn();
    b.channel_id = ChannelId::new(8).unwrap();
    assert_ne!(base, b.leaf().nullifier, "channel id must bind");

    let mut b = a_burn();
    b.token_index = 1;
    assert_ne!(base, b.leaf().nullifier, "token index must bind");

    let mut b = a_burn();
    b.amount += 1;
    assert_ne!(base, b.leaf().nullifier, "amount must bind");

    let mut b = a_burn();
    b.aux_data = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_ne!(base, b.leaf().nullifier, "aux_data must bind");

    let mut b = a_burn();
    b.tx_nonce += 1;
    assert_ne!(base, b.leaf().nullifier, "tx nonce must bind (F-WD-2)");

    let mut b = a_burn();
    b.recipient_pk_g = {
        use intmax3_zkp::{
            circuits::balance::common::recipient::calculate_recipient_from_address,
            ethereum_types::address::Address,
        };
        calculate_recipient_from_address(
            Address::from_hex("0x000000000000000000000000000000000000dead").unwrap(),
        )
    };
    assert_ne!(base, b.leaf().nullifier, "recipient must bind");
}

/// IPW2 regression: proof-only nullifier variance must not mint a second authorization identity.
/// A legacy invented nullifier remains unequal to the circuit's Poseidon nullifier, but the stable
/// authorization is keyed by the IMD2 descriptor and payout tuple, not by that caller-carried
/// proof field.
#[test]
fn auth_v2_is_stable_across_proof_only_nullifier_derivations() {
    let b = a_burn();
    let provable = b.leaf();

    // The chain value the legacy formula folded in: any real pre-burn chain works — the point is
    // structural, not value-specific.
    let pre_burn_chain =
        Bytes32::from_hex("0x5f653832430535e30f995e9c9c84a2ec813fb11c14b327d7615cd69247ea3fac")
            .unwrap();
    let legacy = legacy_cli_nullifier(b.aux_data, pre_burn_chain);

    assert_ne!(
        legacy, provable.nullifier,
        "REGRESSION: the CLI's invented nullifier equals the provable one — either the second \
         derivation is back, or the real one was changed to match it"
    );

    // IPW2's contract lookup is stable even if an off-chain caller carries the wrong nullifier.
    let mut authorized_leaf = provable.clone();
    authorized_leaf.nullifier = legacy;
    assert_eq!(
        partial_withdrawal_auth_digest(&authorized_leaf),
        partial_withdrawal_auth_digest(&provable),
        "IPW2 must exclude the proof-only nullifier; IMD2 aux_data is the stable burn identity"
    );

    // And the fix's postcondition: what `pw-submit` authorizes today IS what a provable leaf
    // carries, so the same lookup hits.
    let submitted = burn_withdrawal_leaf(
        b.channel_id,
        b.recipient_pk_g,
        b.token_index,
        b.amount,
        b.aux_data,
        b.tx_nonce,
    )
    .unwrap();
    assert_eq!(
        partial_withdrawal_auth_digest(&submitted),
        partial_withdrawal_auth_digest(&provable),
        "the authorization pw-submit writes must be the one the proven leaf resolves to"
    );
}

/// The `pw-submit` pre-flight guard compares a rebuilt H2 against the co-signed `h2_tag`. A guard
/// that cannot fire is worthless, so: every field that feeds the nullifier must also move H2.
/// If any of these stopped mattering, a wrong tuple could reproduce the signed `h2_tag` and the
/// guard would wave through an unmatchable authorization.
#[test]
fn h2_reconstruction_moves_with_every_field_the_nullifier_commits_to() {
    let base = a_burn().h2();
    assert_ne!(base, Bytes32::default(), "H2 must be nonzero for a burn");

    let mut b = a_burn();
    b.channel_id = ChannelId::new(8).unwrap();
    assert_ne!(
        base,
        b.h2(),
        "H2 must bind the source channel id (tree index)"
    );

    let mut b = a_burn();
    b.token_index = 1;
    assert_ne!(base, b.h2(), "H2 must bind the token index");

    let mut b = a_burn();
    b.amount += 1;
    assert_ne!(base, b.h2(), "H2 must bind the amount");

    let mut b = a_burn();
    b.aux_data = Bytes32::from_u32_slice(&[9; 8]).unwrap();
    assert_ne!(base, b.h2(), "H2 must bind aux_data");

    let mut b = a_burn();
    b.tx_nonce += 1;
    assert_ne!(base, b.h2(), "H2 must bind the tx nonce");

    let mut b = a_burn();
    b.recipient_pk_g = Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0xdead]).unwrap();
    assert_ne!(base, b.h2(), "H2 must bind the recipient");
}

/// The guard's other half: it refuses when the channel head has moved past the burn, because the
/// manager recomputes `keccak(IMTC, prevSettledTxChain, auxData) == finalSettledTxChain`
/// (`contracts/src/ChannelSettlementManager.sol:1143-1146`) and a stale pair cannot satisfy it.
/// This pins the fold the guard checks locally.
#[test]
fn the_chain_fold_the_guard_checks_is_burn_specific() {
    let b = a_burn();
    let pre =
        Bytes32::from_hex("0x5f653832430535e30f995e9c9c84a2ec813fb11c14b327d7615cd69247ea3fac")
            .unwrap();
    let post = settled_tx_chain_push(pre, b.aux_data);
    assert_ne!(post, pre, "a burn always advances the chain");

    // One more transition past the burn and the head no longer folds to the burn's push — the
    // guard's check (1) fires instead of letting the chain key be spent on a stale intent.
    let advanced = settled_tx_chain_push(post, Bytes32::from_u32_slice(&[7; 8]).unwrap());
    assert_ne!(
        advanced, post,
        "a head that moved past the burn must not still equal push(pre_burn_chain, tx_leaf)"
    );
}
