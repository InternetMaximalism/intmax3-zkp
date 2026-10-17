use intmax3_zkp::{
    circuits::channel::close_asset_backing_circuit::CloseAssetBackingPublicInputs,
    common::{channel_id::ChannelId, u63::BlockNumber},
};

#[test]
fn backing_codec_rejects_wrong_width_and_noncanonical_words() {
    // Distinct limbs catch misplaced or omitted continuation commitments. Layout (35 limbs since
    // 8acbe309): channel_id | settled_tx_chain(8) | token_funds_digest(8) |
    // finalized_extended_state_commitment(8) | anchor_block_number | processed_send_block_number |
    // balance_state_commitment(8).
    let mut words: Vec<u64> = (1..=35).collect();
    words[25] = (1u64 << 63) - 1;
    words[26] = (1u64 << 63) - 2;
    let parsed = CloseAssetBackingPublicInputs::from_u64_slice(&words).unwrap();
    assert_eq!(parsed.channel_id, ChannelId::new(1).unwrap());
    assert_eq!(
        parsed.anchor_block_number,
        BlockNumber::new(words[25]).unwrap()
    );
    assert_eq!(
        parsed.processed_send_block_number,
        BlockNumber::new(words[26]).unwrap()
    );
    assert_eq!(parsed.to_u64_vec(), words);

    for length in [0, 26, 34, 36] {
        let mut wrong = words.clone();
        wrong.resize(length, 0);
        assert!(CloseAssetBackingPublicInputs::from_u64_slice(&wrong).is_err());
    }
    for index in 0..35 {
        let mut overflow = words.clone();
        overflow[index] = if index == 25 || index == 26 { 1u64 << 63 } else { 1u64 << 32 };
        assert!(
            CloseAssetBackingPublicInputs::from_u64_slice(&overflow).is_err(),
            "noncanonical public input at index {index} was accepted"
        );
    }
    let mut zero_channel = words;
    zero_channel[0] = 0;
    assert!(CloseAssetBackingPublicInputs::from_u64_slice(&zero_channel).is_err());
}
