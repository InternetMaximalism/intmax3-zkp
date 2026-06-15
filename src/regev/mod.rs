//! Regev (Ring-LWE) encryption layer for hidden channel balances.
//!
//! Implements detail2.md §B on top of the `regev_plonky3` crate (BabyBear modulus,
//! `q = 2^31 - 2^27 + 1`): channel members publish a [`RegevPk`], balances and transfer amounts
//! live in state only as [`RegevCiphertext`] keccak digests, and amounts are encoded **1 bit per
//! coefficient** (approved deviation D1 from detail2 §B-1) so homomorphic addition is exact
//! integer addition with per-coefficient digit headroom `t = 256`.
//!
//! Boundary contract: every ciphertext / public key that crosses a trust boundary
//! (deserialization, digest computation, homomorphic addition, decryption) is validated for
//! canonical mod-q representation and exact length `REGEV_N` first. The plonky3 field types never
//! leak out of this module except through the sender-private [`AmountWitness`].

pub mod encrypt;
pub mod hash_sig;
pub mod keys;
pub mod params;
pub mod transfer_stark;

pub use encrypt::{
    AmountWitness, REGEV_CT_DOMAIN, RegevCiphertext, RegevError, add_ciphertexts, decrypt_amount,
    encode_amount, encrypt_amount,
};
pub use keys::{
    REGEV_PK_DOMAIN, REGEV_PK_POSEIDON_DOMAIN, REGEV_PK_ROOT_DOMAIN, RegevPk, RegevSk,
    channel_keygen, regev_pk_root,
};
pub use params::{
    MAX_HOMO_ADDS_BEFORE_REFRESH, REGEV_ETA, REGEV_N, REGEV_PLAIN_BITS, REGEV_Q,
    channel_regev_params,
};
pub use transfer_stark::{
    BALANCE_REFRESH_ZKP_DOMAIN, CHANNEL_TX_ZKP_DOMAIN, CHANNEL_UPDATE_ZKP_DOMAIN,
    RealRegevProofVerifier, RegevProofPurpose, RegevSecurityLevel, RegevStatement,
    WITHDRAW_CLAIM_ZKP_DOMAIN, prove_balance_refresh, prove_channel_tx, prove_channel_update,
    prove_hash_sig, prove_withdraw_claim, verify_balance_refresh, verify_channel_tx,
    verify_channel_update, verify_hash_sig, verify_withdraw_claim,
};

use plonky2_keccak::utils::solidity_keccak256;

use crate::ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _};

/// Keccak over a u32-word stream, same convention as `src/common/channel.rs` digests
/// (`solidity_keccak256` packs each word big-endian, matching `abi.encodePacked` on-chain).
pub(crate) fn hash_words(words: &[u32]) -> Bytes32 {
    Bytes32::from_u32_slice(&solidity_keccak256(words)).expect("keccak output must be bytes32")
}
