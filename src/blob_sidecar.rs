//! Convert a blob transaction's network form from the EIP-4844 sidecar (v0) to the EIP-7594 cell
//! proof sidecar (v1).
//!
//! `cast mktx --blob` (Foundry 1.5.1) builds `0x03 || rlp([tx, blobs, commitments, proofs])`, one
//! KZG proof per blob. After Osaka a node only takes `0x03 || rlp([tx, 1, blobs, commitments,
//! cell_proofs])`, with 128 cell proofs per blob: Sepolia answered the v0 form with -32000
//! "unexpected eip-4844 sidecar after osaka" (2026-11-08). The signed transaction `tx` is the same
//! in both forms, so the transaction hash, keccak-256(0x03 || tx), does not change.
//!
//! A Sepolia node decodes this module's v1 form (a zero-balance probe was answered "insufficient
//! funds", where a v1 form with wrapper version 2 or a truncated one was answered "failed to
//! decode signed transaction", 2026-11-25). Anvil 1.5.1 cannot decode the v1 form at all.

use c_kzg::{Blob, Bytes48, CELLS_PER_EXT_BLOB, KzgSettings};

const BYTES_PER_BLOB: usize = c_kzg::BYTES_PER_BLOB;

/// The network form of a blob transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarVersion {
    /// EIP-4844: one KZG proof per blob.
    V0,
    /// EIP-7594: 128 cell KZG proofs per blob.
    V1,
}

/// The parts of a blob transaction's network form, as raw RLP items.
struct NetworkForm<'a> {
    /// The RLP list of the signed transaction (without the 0x03 type byte).
    transaction: &'a [u8],
    version: SidecarVersion,
    blobs: Vec<&'a [u8]>,
    commitments: Vec<&'a [u8]>,
}

/// The Ethereum KZG trusted setup, loaded once per process (about 2 s).
pub fn settings() -> &'static KzgSettings {
    c_kzg::ethereum_kzg_settings(0)
}

/// The sidecar version of the type-3 network transaction `raw` (`0x03 || rlp(...)`).
pub fn sidecar_version(raw: &[u8]) -> Result<SidecarVersion, String> {
    Ok(parse(raw)?.version)
}

/// `raw` (a type-3 network transaction in either form) in the v1 form, with cell proofs computed
/// from its blobs. Every blob must match its commitment, and every cell proof is verified before
/// the bytes are returned. A v1 input is returned unchanged.
pub fn to_v1(raw: &[u8], settings: &KzgSettings) -> Result<Vec<u8>, String> {
    let form = parse(raw)?;
    if form.version == SidecarVersion::V1 {
        return Ok(raw.to_vec());
    }
    let mut cell_proofs = Vec::with_capacity(form.blobs.len() * CELLS_PER_EXT_BLOB);
    let mut all_commitments = Vec::with_capacity(cell_proofs.capacity());
    let mut all_indices = Vec::with_capacity(cell_proofs.capacity());
    let mut all_cells = Vec::with_capacity(cell_proofs.capacity());
    for (index, (blob, commitment)) in form.blobs.iter().zip(&form.commitments).enumerate() {
        let blob = Blob::from_bytes(blob).map_err(|e| format!("blob {index}: {e:?}"))?;
        let computed = settings
            .blob_to_kzg_commitment(&blob)
            .map_err(|e| format!("commit to blob {index}: {e:?}"))?;
        if computed.to_bytes().as_slice() != *commitment {
            return Err(format!("blob {index} does not match its commitment"));
        }
        let (cells, proofs) = settings
            .compute_cells_and_kzg_proofs(&blob)
            .map_err(|e| format!("cell proofs of blob {index}: {e:?}"))?;
        let commitment =
            Bytes48::from_bytes(commitment).map_err(|e| format!("commitment {index}: {e:?}"))?;
        for (cell_index, (cell, proof)) in cells.iter().zip(proofs.iter()).enumerate() {
            cell_proofs.push(proof.to_bytes());
            all_commitments.push(commitment);
            all_indices.push(cell_index as u64);
            all_cells.push(cell.clone());
        }
    }
    let verified = settings
        .verify_cell_kzg_proof_batch(&all_commitments, &all_indices, &all_cells, &cell_proofs)
        .map_err(|e| format!("verify cell proofs: {e:?}"))?;
    if !verified {
        return Err("computed cell proofs do not verify".into());
    }
    let mut items = vec![
        form.transaction.to_vec(),
        rlp_bytes(&[1]),
        rlp_list(&form.blobs.iter().map(|b| rlp_bytes(b)).collect::<Vec<_>>()),
        rlp_list(
            &form
                .commitments
                .iter()
                .map(|c| rlp_bytes(c))
                .collect::<Vec<_>>(),
        ),
    ];
    items.push(rlp_list(
        &cell_proofs
            .iter()
            .map(|p| rlp_bytes(p.as_slice()))
            .collect::<Vec<_>>(),
    ));
    let mut out = vec![3];
    out.extend(rlp_list(&items));
    Ok(out)
}

/// The transaction hash of a type-3 network transaction in either form.
pub fn transaction_hash(raw: &[u8]) -> Result<[u8; 32], String> {
    let form = parse(raw)?;
    let mut typed = vec![3];
    typed.extend_from_slice(form.transaction);
    Ok(keccak_hash::keccak(&typed).0)
}

fn parse(raw: &[u8]) -> Result<NetworkForm<'_>, String> {
    let body = raw
        .strip_prefix(&[3])
        .ok_or_else(|| "not a type-3 (blob) transaction".to_string())?;
    let (outer, rest) = rlp_item(body)?;
    if !rest.is_empty() || !outer.is_list {
        return Err("a blob network transaction is one RLP list".into());
    }
    let items = rlp_items(outer.payload)?;
    let (version, rest) = match items.as_slice() {
        [tx, blobs, commitments, proofs] if tx.is_list => {
            (SidecarVersion::V0, [*tx, *blobs, *commitments, *proofs])
        }
        [tx, version, blobs, commitments, proofs]
            if tx.is_list && !version.is_list && version.payload == [1] =>
        {
            (SidecarVersion::V1, [*tx, *blobs, *commitments, *proofs])
        }
        _ => {
            return Err(format!(
                "a blob network transaction has 4 (v0) or 5 (v1) fields, not {}",
                items.len()
            ));
        }
    };
    let [tx, blobs, commitments, proofs] = rest;
    let blobs = strings(blobs, BYTES_PER_BLOB, "blobs")?;
    let commitments = strings(commitments, 48, "commitments")?;
    let proofs = strings(proofs, 48, "proofs")?;
    let proofs_per_blob = match version {
        SidecarVersion::V0 => 1,
        SidecarVersion::V1 => CELLS_PER_EXT_BLOB,
    };
    if blobs.is_empty()
        || commitments.len() != blobs.len()
        || proofs.len() != blobs.len() * proofs_per_blob
    {
        return Err(format!(
            "{} blobs, {} commitments and {} proofs do not form a {version:?} sidecar",
            blobs.len(),
            commitments.len(),
            proofs.len()
        ));
    }
    Ok(NetworkForm {
        transaction: tx.encoded,
        version,
        blobs,
        commitments,
    })
}

#[derive(Clone, Copy)]
struct Item<'a> {
    is_list: bool,
    payload: &'a [u8],
    /// The whole item, header included.
    encoded: &'a [u8],
}

/// The first RLP item of `bytes` and the bytes after it.
fn rlp_item(bytes: &[u8]) -> Result<(Item<'_>, &[u8]), String> {
    let first = *bytes.first().ok_or("empty RLP item")?;
    let (is_list, header, length) = match first {
        0x00..=0x7f => (false, 0, 1),
        0x80..=0xb7 => (false, 1, usize::from(first - 0x80)),
        0xb8..=0xbf => {
            let size = usize::from(first - 0xb7);
            (false, 1 + size, be_length(bytes, size)?)
        }
        0xc0..=0xf7 => (true, 1, usize::from(first - 0xc0)),
        0xf8..=0xff => {
            let size = usize::from(first - 0xf7);
            (true, 1 + size, be_length(bytes, size)?)
        }
    };
    let end = header
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or("RLP item overruns its input")?;
    Ok((
        Item {
            is_list,
            payload: &bytes[header..end],
            encoded: &bytes[..end],
        },
        &bytes[end..],
    ))
}

/// The payloads of the RLP list `list`, each a byte string of exactly `size` bytes.
fn strings<'a>(list: Item<'a>, size: usize, what: &str) -> Result<Vec<&'a [u8]>, String> {
    if !list.is_list {
        return Err(format!("{what} is not a list"));
    }
    rlp_items(list.payload)?
        .into_iter()
        .map(|item| {
            if item.is_list || item.payload.len() != size {
                Err(format!("{what} holds an item that is not {size} bytes"))
            } else {
                Ok(item.payload)
            }
        })
        .collect()
}

fn be_length(bytes: &[u8], size: usize) -> Result<usize, String> {
    let digits = bytes
        .get(1..1 + size)
        .ok_or("RLP length overruns its input")?;
    if size > 8 || digits.first() == Some(&0) {
        return Err("non-canonical RLP length".into());
    }
    Ok(digits
        .iter()
        .fold(0usize, |n, b| (n << 8) | usize::from(*b)))
}

fn rlp_items(mut payload: &[u8]) -> Result<Vec<Item<'_>>, String> {
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = rlp_item(payload)?;
        items.push(item);
        payload = rest;
    }
    Ok(items)
}

fn length_prefix(length: usize, short_base: u8, long_base: u8) -> Vec<u8> {
    if length <= 55 {
        vec![short_base + length as u8]
    } else {
        let bytes = length.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut out = vec![long_base + (bytes.len() - start) as u8];
        out.extend_from_slice(&bytes[start..]);
        out
    }
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    let mut out = length_prefix(bytes.len(), 0x80, 0xb7);
    out.extend_from_slice(bytes);
    out
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = length_prefix(items.iter().map(Vec::len).sum(), 0xc0, 0xf7);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v0 network form of a fake signed transaction carrying `blobs`, built as `cast mktx
    /// --blob` lays it out: [tx, blobs, commitments, blob proofs].
    fn v0_form(blobs: &[Vec<u8>]) -> (Vec<u8>, Vec<u8>) {
        let settings = settings();
        let transaction = rlp_list(&[rlp_bytes(&[0x2a]), rlp_bytes(b"a signed blob transaction")]);
        let mut commitments = Vec::new();
        let mut proofs = Vec::new();
        for blob in blobs {
            let blob = Blob::from_bytes(blob).unwrap();
            let commitment = settings.blob_to_kzg_commitment(&blob).unwrap().to_bytes();
            let proof = settings
                .compute_blob_kzg_proof(&blob, &commitment)
                .unwrap()
                .to_bytes();
            commitments.push(rlp_bytes(commitment.as_slice()));
            proofs.push(rlp_bytes(proof.as_slice()));
        }
        let mut raw = vec![3];
        raw.extend(rlp_list(&[
            transaction.clone(),
            rlp_list(&blobs.iter().map(|b| rlp_bytes(b)).collect::<Vec<_>>()),
            rlp_list(&commitments),
            rlp_list(&proofs),
        ]));
        (raw, transaction)
    }

    /// A blob of field elements below the BLS12-381 modulus (each 32-byte element starts 0x00).
    fn blob(seed: u8) -> Vec<u8> {
        (0..BYTES_PER_BLOB)
            .map(|i| {
                if i % 32 == 0 {
                    0
                } else {
                    (i as u8).wrapping_mul(31).wrapping_add(seed)
                }
            })
            .collect()
    }

    #[test]
    fn v1_form_keeps_the_transaction_and_carries_verified_cell_proofs() {
        let (v0, transaction) = v0_form(&[blob(1), blob(2)]);
        assert_eq!(sidecar_version(&v0).unwrap(), SidecarVersion::V0);
        let v1 = to_v1(&v0, settings()).unwrap();
        assert_eq!(sidecar_version(&v1).unwrap(), SidecarVersion::V1);
        let mut typed = vec![3];
        typed.extend_from_slice(&transaction);
        assert_eq!(
            transaction_hash(&v0).unwrap(),
            keccak_hash::keccak(&typed).0
        );
        assert_eq!(
            transaction_hash(&v1).unwrap(),
            transaction_hash(&v0).unwrap()
        );
        // [tx, 1, blobs, commitments, 2 x 128 cell proofs], each proof re-verified against its
        // blob's cells.
        let (outer, _) = rlp_item(&v1[1..]).unwrap();
        let items = rlp_items(outer.payload).unwrap();
        assert_eq!(items.len(), 5);
        assert_eq!(items[0].encoded, transaction.as_slice());
        assert_eq!(items[1].payload, [1]);
        let blobs = strings(items[2], BYTES_PER_BLOB, "blobs").unwrap();
        let commitments = strings(items[3], 48, "commitments").unwrap();
        let proofs = strings(items[4], 48, "proofs").unwrap();
        assert_eq!(proofs.len(), 2 * CELLS_PER_EXT_BLOB);
        for (index, blob) in blobs.iter().enumerate() {
            let (cells, _) = settings()
                .compute_cells_and_kzg_proofs(&Blob::from_bytes(blob).unwrap())
                .unwrap();
            let commitment = Bytes48::from_bytes(commitments[index]).unwrap();
            let proofs: Vec<Bytes48> = proofs[index * CELLS_PER_EXT_BLOB..][..CELLS_PER_EXT_BLOB]
                .iter()
                .map(|p| Bytes48::from_bytes(p).unwrap())
                .collect();
            let indices: Vec<u64> = (0..CELLS_PER_EXT_BLOB as u64).collect();
            assert!(
                settings()
                    .verify_cell_kzg_proof_batch(
                        &vec![commitment; CELLS_PER_EXT_BLOB],
                        &indices,
                        cells.as_slice(),
                        &proofs,
                    )
                    .unwrap()
            );
        }
        assert_eq!(
            to_v1(&v1, settings()).unwrap(),
            v1,
            "a v1 form is returned unchanged"
        );
    }

    #[test]
    fn a_blob_that_does_not_match_its_commitment_is_refused() {
        let (v0, _) = v0_form(&[blob(1)]);
        let mut tampered = v0.clone();
        // The last byte of the blob list sits just before the commitments.
        let position = tampered.len() - 2 * 49 - 3;
        tampered[position] ^= 1;
        let error = to_v1(&tampered, settings()).unwrap_err();
        assert!(error.contains("does not match its commitment"), "{error}");
    }

    #[test]
    fn non_blob_and_malformed_forms_are_refused() {
        assert!(sidecar_version(&[2, 0xc0]).is_err());
        let (v0, _) = v0_form(&[blob(3)]);
        assert!(sidecar_version(&v0[..v0.len() - 1]).is_err());
        let mut extra = v0.clone();
        extra.push(0);
        assert!(sidecar_version(&extra).is_err());
    }
}
