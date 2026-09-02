use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::{
        channel_id::{ChannelId, ChannelIdTarget},
        salt::{Salt, SaltTarget},
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

pub fn calculate_recipient_from_user_id(channel_id: ChannelId, salt: Salt) -> Bytes32 {
    let inputs = [vec![USER_ID_DOMAIN, channel_id.as_u64()], salt.to_u64_vec()].concat();
    let hash: Bytes32 = PoseidonHashOut::hash_inputs_u64(&inputs).into();

    // replace the first byte with the tag
    let mut hash_bits = hash.to_bytes_be();
    hash_bits[0] = USER_ID_TAG;
    Bytes32::from_bytes_be(&hash_bits).expect("hash should be 32 bytes")
}

pub fn calculate_recipient_from_user_id_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    channel_id: &ChannelIdTarget,
    salt: &SaltTarget,
) -> Bytes32Target {
    let mut inputs = vec![
        builder.constant(F::from_canonical_u64(USER_ID_DOMAIN)),
        channel_id.value,
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

/// Circuit equivalent of [`calculate_recipient_from_address`]. Keeping construction and
/// extraction inverse to this one canonical form prevents tagged values with non-zero 11-byte
/// padding from being accepted in a proof even though the L1 contract reconstructs zero padding.
pub fn calculate_recipient_from_address_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    address: &AddressTarget,
) -> Bytes32Target {
    let zero = builder.zero();
    let mut bytes = vec![zero; 32];
    bytes[0] = builder.constant(F::from_canonical_u32(ADDRESS_TAG as u32));
    bytes[12..].copy_from_slice(&address.to_bytes_be(builder));
    Bytes32Target::from_bytes_be(builder, &bytes)
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
    let address = Address::from_bytes_be(address_bytes).expect("address should be 20 bytes");
    if recipient != calculate_recipient_from_address(address) {
        return Err(RecipientError::InvalidRecipient(
            "non-canonical ADDRESS_TAG recipient: bytes 1..11 must be zero".into(),
        ));
    }
    Ok(address)
}

pub fn extract_address_from_recipient_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    recipient: &Bytes32Target,
) -> AddressTarget {
    let bytes = recipient.to_bytes_be(builder);
    let address = AddressTarget::from_bytes_be(builder, &bytes[12..]);
    let canonical = calculate_recipient_from_address_circuit(builder, &address);
    recipient.connect(builder, canonical);
    address
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

        let channel_id = ChannelId::new(1).unwrap();
        let mut rng = rand::thread_rng();
        let salt = Salt::rand(&mut rng);
        let expected = calculate_recipient_from_user_id(channel_id, salt);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let user_id_target = ChannelIdTarget::constant(&mut builder, channel_id);
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

    #[test]
    fn rejects_nonzero_address_padding_native_and_circuit() {
        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let address = Address::from_hex("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        let mut malformed_bytes = calculate_recipient_from_address(address).to_bytes_be();
        malformed_bytes[7] ^= 1;
        let malformed = Bytes32::from_bytes_be(&malformed_bytes).unwrap();
        assert!(extract_address_from_recipient(malformed).is_err());

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let recipient_target = Bytes32Target::new(&mut builder, true);
        let extracted_target =
            extract_address_from_recipient_circuit(&mut builder, &recipient_target);
        let expected_target = AddressTarget::constant(&mut builder, address);
        extracted_target.connect(&mut builder, expected_target);
        let circuit = builder.build::<C>();
        let mut pw = PartialWitness::new();
        recipient_target.set_witness(&mut pw, malformed);
        assert!(
            circuit.prove(pw).is_err(),
            "non-zero ADDRESS_TAG padding must make the recipient circuit unsatisfiable"
        );
    }
}
