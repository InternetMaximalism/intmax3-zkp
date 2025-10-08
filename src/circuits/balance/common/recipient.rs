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
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

const USER_ID_DOMAIN: u64 = 0x55494400; // "UID\0"
const USER_ID_TAG: u8 = 1;
const ADDRESS_TAG: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum RecipientError {
    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),
}

pub fn calculate_recipient_from_user_id(user_id: UserId, salt: Salt) -> Bytes32 {
    let inputs = vec![vec![USER_ID_DOMAIN, user_id.as_u64()], salt.to_u64_vec()].concat();
    let hash: Bytes32 = PoseidonHashOut::hash_inputs_u64(&inputs).into();

    // replace the first byte with the tag
    let mut hash_bits = hash.to_bytes_be();
    hash_bits[0] = USER_ID_TAG;
    Bytes32::from_bytes_be(&hash_bits).expect("hash should be 32 bytes")
}

pub fn calculate_recipient_from_user_id_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    user_id: &UserIdTarget,
    salt: &SaltTarget,
) -> Bytes32Target {
    let mut inputs = vec![
        builder.constant(F::from_canonical_u64(USER_ID_DOMAIN)),
        user_id.value,
    ];
    inputs.extend(salt.to_vec());

    let hash = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
    let hash_bytes32 = Bytes32Target::from_hash_out(builder, hash);
    let mut bytes = hash_bytes32.to_bytes_be(builder);
    bytes[0] = builder.constant(F::from_canonical_u32(USER_ID_TAG as u32));
    Bytes32Target::from_bytes_be(builder, &bytes)
}

pub fn calculate_recipient_from_address(address: Address) -> Bytes32 {
    let mut limbs = vec![0u32; 8];
    limbs[3..8].copy_from_slice(&address.to_u32_vec());
    let padded_address = Bytes32::from_u32_slice(&limbs).expect("address should fit in Bytes32");
    let mut bytes = padded_address.to_bytes_be();
    bytes[0] = ADDRESS_TAG;
    Bytes32::from_bytes_be(&bytes).expect("address should be 32 bytes")
}

pub fn extract_address_from_recipient(recipient: Bytes32) -> Result<Address, RecipientError> {
    let bytes = recipient.to_bytes_be();
    if bytes[0] != ADDRESS_TAG {
        return Err(RecipientError::InvalidRecipient(format!(
            "Invalid recipient tag: expected {}, got {}",
            ADDRESS_TAG, bytes[0]
        )));
    }
    let address_bytes = &bytes[12..32];
    Ok(Address::from_bytes_be(address_bytes).expect("address should be 20 bytes"))
}

pub fn extract_address_from_recipient_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    recipient: &Bytes32Target,
) -> AddressTarget {
    let mut bytes = recipient.to_bytes_be(builder);
    let expected_tag = builder.constant(F::from_canonical_u32(ADDRESS_TAG as u32));
    builder.connect(bytes[0], expected_tag);
    let address_bytes = bytes.split_off(12);
    AddressTarget::from_bytes_be(builder, &address_bytes)
}

#[cfg(test)]
mod tests {
    use crate::ethereum_types::u32limb_trait::U32LimbTargetTrait as _;

    use super::*;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    #[test]
    fn test_calculate_recipient_from_user_id_circuit() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let user_id = UserId::new(1, 42).unwrap();
        let mut rng = rand::thread_rng();
        let salt = Salt::rand(&mut rng);
        let expected = calculate_recipient_from_user_id(user_id, salt);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let user_id_target = UserIdTarget::constant(&mut builder, user_id);
        let salt_target = SaltTarget::constant(&mut builder, salt);

        let recipient_target =
            calculate_recipient_from_user_id_circuit(&mut builder, &user_id_target, &salt_target);
        let expected_target = Bytes32Target::constant(&mut builder, expected);
        recipient_target.connect(&mut builder, expected_target);

        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
    }

    #[test]
    fn test_extract_address_from_recipient_circuit() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let address = Address::from_hex("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        let recipient_expected =
            Bytes32::from_hex("0x0200000000000000000000001234567890abcdef1234567890abcdef12345678")
                .unwrap();
        let recipient = calculate_recipient_from_address(address);
        assert_eq!(recipient, recipient_expected);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let recipient_target = Bytes32Target::constant(&mut builder, recipient);
        let extracted_target =
            extract_address_from_recipient_circuit(&mut builder, &recipient_target);
        let expected_target = AddressTarget::constant(&mut builder, address);
        extracted_target.connect(&mut builder, expected_target);

        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
    }
}
