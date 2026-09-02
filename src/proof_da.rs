//! Production proof-data-availability helpers.
//!
//! Foundry's `cast mktx --blob --path` is the component that computes EIP-4844 KZG
//! commitments and proofs.  Before a signed transaction is persisted or published, this module
//! independently checks the complete blob byte stream against Alloy's `SimpleCoder`, recomputes
//! every versioned hash from its 48-byte commitment, and extracts the compact sidecar consumed by
//! `BlobKZGVerifierExt`.  A CLI-format regression therefore fails before any L1 mutation.

#![cfg(not(target_arch = "wasm32"))]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;
pub const PAYLOAD_BYTES_PER_FIELD_ELEMENT: usize = 31;
pub const ONE_BLOB_CAPACITY: usize = (FIELD_ELEMENTS_PER_BLOB - 1) * 31;
pub const TWO_BLOB_CAPACITY: usize = (2 * FIELD_ELEMENTS_PER_BLOB - 1) * 31;

/// The subset of `cast decode-transaction --json` that is security-relevant to proof DA.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedBlobTransaction {
    pub signer: String,
    #[serde(rename = "type")]
    pub tx_type: String,
    pub chain_id: String,
    pub to: String,
    pub value: String,
    pub input: String,
    pub blob_versioned_hashes: Vec<String>,
    pub blobs: Vec<String>,
    pub commitments: Vec<String>,
    pub proofs: Vec<String>,
    pub hash: String,
}

/// Fully checked evidence saved beside the signed blob transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedBlobSidecars {
    pub transaction_hash: String,
    pub blob_versioned_hashes: Vec<String>,
    /// `0x || commitment[0] || proof[0] [|| commitment[1] || proof[1]]`.
    pub compact_sidecars: String,
}

fn decode_hex_exact(value: &str, expected: usize, what: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| format!("decode {what}: {error}"))?;
    if bytes.len() != expected {
        return Err(format!(
            "{what} has {} bytes; expected exactly {expected}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn parse_quantity(value: &str, what: &str) -> Result<u64, String> {
    let raw = value.trim();
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|error| format!("parse {what}: {error}"))
    } else {
        raw.parse::<u64>()
            .map_err(|error| format!("parse {what}: {error}"))
    }
}

fn same_hex(a: &str, b: &str) -> bool {
    a.trim_start_matches("0x")
        .eq_ignore_ascii_case(b.trim_start_matches("0x"))
}

/// Exact Alloy `SimpleCoder` output, including its big-endian u64 length header.
pub fn encode_simple_coder_blobs(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if payload.is_empty() {
        return Err("proof payload is empty".into());
    }
    if payload.len() > TWO_BLOB_CAPACITY {
        return Err(format!(
            "proof payload has {} bytes; maximum is {TWO_BLOB_CAPACITY}",
            payload.len()
        ));
    }
    let blob_count = if payload.len() <= ONE_BLOB_CAPACITY {
        1
    } else {
        2
    };
    let mut stream = vec![0u8; blob_count * BYTES_PER_BLOB];
    let length = u64::try_from(payload.len())
        .map_err(|_| "proof payload length does not fit SimpleCoder u64 header")?;
    // FE 0 = 0x00 || uint64_be(total_length) || 23 zero bytes.
    stream[1..9].copy_from_slice(&length.to_be_bytes());
    for (chunk_index, chunk) in payload.chunks(PAYLOAD_BYTES_PER_FIELD_ELEMENT).enumerate() {
        let offset = (chunk_index + 1) * BYTES_PER_FIELD_ELEMENT;
        stream[offset + 1..offset + 1 + chunk.len()].copy_from_slice(chunk);
    }
    Ok(stream
        .chunks_exact(BYTES_PER_BLOB)
        .map(ToOwned::to_owned)
        .collect())
}

/// Validate the decoded signed transaction and return the exact Solidity sidecar bytes.
pub fn validate_decoded_blob_transaction(
    decoded: &DecodedBlobTransaction,
    payload: &[u8],
    expected_chain_id: u64,
    expected_signer: &str,
    expected_to: &str,
    expected_value: u64,
    expected_input: &str,
) -> Result<ValidatedBlobSidecars, String> {
    if decoded.tx_type != "0x3" {
        return Err(format!(
            "signed transaction type is {}; expected EIP-4844 type 0x3",
            decoded.tx_type
        ));
    }
    if parse_quantity(&decoded.chain_id, "blob transaction chainId")? != expected_chain_id {
        return Err("signed blob transaction targets a different chain id".into());
    }
    if !same_hex(&decoded.signer, expected_signer) {
        return Err(format!(
            "signed blob transaction signer {} != expected {expected_signer}",
            decoded.signer
        ));
    }
    if !same_hex(&decoded.to, expected_to) {
        return Err(format!(
            "signed blob transaction target {} != expected {expected_to}",
            decoded.to
        ));
    }
    if parse_quantity(&decoded.value, "blob transaction value")? != expected_value {
        return Err("signed blob transaction value is not the required posting stake".into());
    }
    if !same_hex(&decoded.input, expected_input) {
        return Err("signed blob transaction calldata differs from the intended post".into());
    }
    decode_hex_exact(&decoded.hash, 32, "signed transaction hash")?;

    let expected_blobs = encode_simple_coder_blobs(payload)?;
    let count = expected_blobs.len();
    if decoded.blobs.len() != count
        || decoded.commitments.len() != count
        || decoded.proofs.len() != count
        || decoded.blob_versioned_hashes.len() != count
    {
        return Err(format!(
            "decoded sidecar count mismatch: blobs={}, commitments={}, proofs={}, hashes={}, expected={count}",
            decoded.blobs.len(),
            decoded.commitments.len(),
            decoded.proofs.len(),
            decoded.blob_versioned_hashes.len()
        ));
    }

    let mut compact = Vec::with_capacity(count * 96);
    let mut normalized_hashes = Vec::with_capacity(count);
    for i in 0..count {
        let actual_blob =
            decode_hex_exact(&decoded.blobs[i], BYTES_PER_BLOB, &format!("blob[{i}]"))?;
        if actual_blob != expected_blobs[i] {
            return Err(format!(
                "blob[{i}] is not the exact lossless Alloy SimpleCoder encoding"
            ));
        }
        let commitment =
            decode_hex_exact(&decoded.commitments[i], 48, &format!("commitment[{i}]"))?;
        let proof = decode_hex_exact(&decoded.proofs[i], 48, &format!("proof[{i}]"))?;
        let supplied_hash = decode_hex_exact(
            &decoded.blob_versioned_hashes[i],
            32,
            &format!("blobVersionedHash[{i}]"),
        )?;
        let mut expected_hash = Sha256::digest(&commitment).to_vec();
        expected_hash[0] = 1;
        if supplied_hash != expected_hash {
            return Err(format!(
                "blobVersionedHash[{i}] does not equal 0x01 || sha256(commitment)[1..]"
            ));
        }
        compact.extend_from_slice(&commitment);
        compact.extend_from_slice(&proof);
        normalized_hashes.push(format!("0x{}", hex::encode(expected_hash)));
    }

    Ok(ValidatedBlobSidecars {
        transaction_hash: format!(
            "0x{}",
            decoded.hash.trim_start_matches("0x").to_ascii_lowercase()
        ),
        blob_versioned_hashes: normalized_hashes,
        compact_sidecars: format!("0x{}", hex::encode(compact)),
    })
}

/// Extract and validate the one `Submitted` event from a successful canonical receipt.
/// Returns its uint256 id as a normalized hex quantity accepted by `vm.envUint`/`cast`.
pub fn submitted_id_from_receipt(
    receipt: &serde_json::Value,
    rollup: &str,
    submitter: &str,
    proof_hash: &str,
    proof_length: u32,
    state_root: &str,
) -> Result<String, String> {
    let successful = receipt["status"]
        .as_str()
        .map(|value| value == "0x1" || value == "1")
        .unwrap_or_else(|| receipt["status"].as_u64() == Some(1));
    if !successful {
        return Err("blob-post receipt is not successful".into());
    }
    let topic0 = format!(
        "0x{}",
        hex::encode(
            keccak_hash::keccak(b"Submitted(uint256,address,bytes32,bytes32,uint32,bytes32)").0
        )
    );
    let logs = receipt["logs"]
        .as_array()
        .ok_or_else(|| "blob-post receipt has no logs array".to_string())?;
    let matching: Vec<&serde_json::Value> = logs
        .iter()
        .filter(|log| {
            log["address"]
                .as_str()
                .is_some_and(|address| same_hex(address, rollup))
                && log["topics"]
                    .as_array()
                    .and_then(|topics| topics.first())
                    .and_then(|topic| topic.as_str())
                    .is_some_and(|topic| same_hex(topic, &topic0))
        })
        .collect();
    if matching.len() != 1 {
        return Err(format!(
            "blob-post receipt contains {} matching Submitted events; expected exactly one",
            matching.len()
        ));
    }
    let log = matching[0];
    let topics = log["topics"]
        .as_array()
        .ok_or_else(|| "Submitted log topics are not an array".to_string())?;
    if topics.len() != 3 {
        return Err(format!(
            "Submitted log has {} topics; expected exactly 3",
            topics.len()
        ));
    }
    let id_word = decode_hex_exact(
        topics[1]
            .as_str()
            .ok_or_else(|| "Submitted id topic is not a string".to_string())?,
        32,
        "Submitted id topic",
    )?;
    let submitter_word = decode_hex_exact(
        topics[2]
            .as_str()
            .ok_or_else(|| "Submitted submitter topic is not a string".to_string())?,
        32,
        "Submitted submitter topic",
    )?;
    let expected_submitter = decode_hex_exact(submitter, 20, "expected submitter")?;
    if submitter_word[..12] != [0u8; 12] || submitter_word[12..] != expected_submitter {
        return Err("Submitted event submitter differs from the signed transaction signer".into());
    }

    let data = decode_hex_exact(
        log["data"]
            .as_str()
            .ok_or_else(|| "Submitted log data is not a string".to_string())?,
        128,
        "Submitted log data",
    )?;
    if data[..32] == [0u8; 32] {
        return Err("Submitted event carries a zero submission commitment".into());
    }
    if data[32..64] != decode_hex_exact(proof_hash, 32, "expected proof hash")? {
        return Err("Submitted event proof hash differs from the proof-DA payload".into());
    }
    if data[64..92] != [0u8; 28]
        || u32::from_be_bytes(data[92..96].try_into().expect("four-byte slice")) != proof_length
    {
        return Err("Submitted event proof length differs from the proof-DA payload".into());
    }
    if data[96..128] != decode_hex_exact(state_root, 32, "expected state root")? {
        return Err("Submitted event state root differs from the intended final state".into());
    }

    Ok(format!("0x{}", hex::encode(id_word)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn decoded_for(payload: &[u8]) -> DecodedBlobTransaction {
        let blobs = encode_simple_coder_blobs(payload).unwrap();
        let commitments: Vec<Vec<u8>> =
            (0..blobs.len()).map(|i| vec![0x31 + i as u8; 48]).collect();
        let hashes = commitments
            .iter()
            .map(|commitment| {
                let mut hash = Sha256::digest(commitment).to_vec();
                hash[0] = 1;
                hex_of(&hash)
            })
            .collect();
        DecodedBlobTransaction {
            signer: "0x1111111111111111111111111111111111111111".into(),
            tx_type: "0x3".into(),
            chain_id: "0x1".into(),
            to: "0x2222222222222222222222222222222222222222".into(),
            value: "0xde0b6b3a7640000".into(),
            input: "0xabcdef".into(),
            blob_versioned_hashes: hashes,
            blobs: blobs.iter().map(|blob| hex_of(blob)).collect(),
            commitments: commitments.iter().map(|value| hex_of(value)).collect(),
            proofs: (0..blobs.len())
                .map(|i| hex_of(&vec![0x71 + i as u8; 48]))
                .collect(),
            hash: hex_of(&[0x99; 32]),
        }
    }

    #[test]
    fn simple_coder_is_lossless_across_the_two_blob_boundary() {
        let payload: Vec<u8> = (0..ONE_BLOB_CAPACITY + 37)
            .map(|i| (i as u8).wrapping_mul(197))
            .collect();
        let blobs = encode_simple_coder_blobs(&payload).unwrap();
        assert_eq!(blobs.len(), 2);
        assert_eq!(&blobs[0][1..9], &(payload.len() as u64).to_be_bytes());
        assert_eq!(blobs[1][0], 0);

        let validated = validate_decoded_blob_transaction(
            &decoded_for(&payload),
            &payload,
            1,
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            1_000_000_000_000_000_000,
            "0xabcdef",
        )
        .unwrap();
        assert_eq!(validated.blob_versioned_hashes.len(), 2);
        assert_eq!(validated.compact_sidecars.len(), 2 + 2 * 96 * 2);
    }

    #[test]
    fn any_blob_byte_or_commitment_hash_mismatch_is_rejected() {
        let payload = b"proof bytes with a high bit: \xff";
        let mut decoded = decoded_for(payload);
        let mut blob = decode_hex_exact(&decoded.blobs[0], BYTES_PER_BLOB, "blob").unwrap();
        blob[33] ^= 1;
        decoded.blobs[0] = hex_of(&blob);
        assert!(
            validate_decoded_blob_transaction(
                &decoded,
                payload,
                1,
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222",
                1_000_000_000_000_000_000,
                "0xabcdef",
            )
            .unwrap_err()
            .contains("exact lossless")
        );

        let mut decoded = decoded_for(payload);
        decoded.blob_versioned_hashes[0] = hex_of(&[0x01; 32]);
        assert!(
            validate_decoded_blob_transaction(
                &decoded,
                payload,
                1,
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222",
                1_000_000_000_000_000_000,
                "0xabcdef",
            )
            .unwrap_err()
            .contains("sha256")
        );
    }

    #[test]
    fn submitted_event_is_bound_to_submitter_and_exact_payload_metadata() {
        let topic0 = format!(
            "0x{}",
            hex::encode(
                keccak_hash::keccak(b"Submitted(uint256,address,bytes32,bytes32,uint32,bytes32)").0
            )
        );
        let mut data = vec![0u8; 128];
        data[..32].fill(0x44);
        data[32..64].fill(0x55);
        data[92..96].copy_from_slice(&130_592u32.to_be_bytes());
        data[96..].fill(0x66);
        let receipt = serde_json::json!({
            "status": "0x1",
            "logs": [{
                "address": "0x2222222222222222222222222222222222222222",
                "topics": [
                    topic0,
                    format!("0x{}", "00".repeat(31) + "07"),
                    format!("0x{}{}", "00".repeat(12), "11".repeat(20)),
                ],
                "data": hex_of(&data),
            }],
        });
        assert_eq!(
            submitted_id_from_receipt(
                &receipt,
                "0x2222222222222222222222222222222222222222",
                "0x1111111111111111111111111111111111111111",
                &format!("0x{}", "55".repeat(32)),
                130_592,
                &format!("0x{}", "66".repeat(32)),
            )
            .unwrap(),
            format!("0x{}", "00".repeat(31) + "07")
        );
    }
}
