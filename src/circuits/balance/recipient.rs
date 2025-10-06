use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::{
        salt::{Salt, SaltTarget},
        user_id::{UserId, UserIdTarget},
    },
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTrait,
    },
    utils::poseidon_hash_out::PoseidonHashOut,
};

const USER_ID_DOMAIN: u64 = 0x55494400; // "UID\0"
const USER_ID_TAG: u8 = 1;

pub fn calculate_recipient(user_id: UserId, salt: Salt) -> Bytes32 {
    let inputs = vec![vec![USER_ID_DOMAIN, user_id.0], salt.to_u64_vec()].concat();
    let hash: Bytes32 = PoseidonHashOut::hash_inputs_u64(&inputs).into();

    // replace the first byte with the tag
    let mut hash_bits = hash.to_bytes_be();
    hash_bits[0] = USER_ID_TAG;
    Bytes32::from_bytes_be(&hash_bits).expect("hash should be 32 bytes")
}

pub fn calculate_recipient_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    user_id: &UserIdTarget,
    salt: &SaltTarget,
) -> Bytes32Target {
    todo!()
}
