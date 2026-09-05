//! Integrity codec for the local two-channel journal. Version 2 hashes the stored JSON value
//! before typed decoding, so private HashSet ledger order cannot invalidate a crash recovery.
//! Version 1 is read-only compatible: verify its exact compact stored journal bytes, never a
//! reserialized HashSet. This checksum detects corruption; N-of-N/context validation remains
//! the responsibility of `validate_inter_transfer_commit` after decoding.

use super::*;

fn checksum(bytes: &[u8]) -> Result<Bytes32, String> {
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0)
        .map_err(|error| format!("inter-transfer journal checksum: {error:?}"))
}

fn value_checksum(value: &serde_json::Value) -> Result<Bytes32, String> {
    checksum(&serde_json::to_vec(value).map_err(|error| error.to_string())?)
}

pub(super) fn encode<T: Serialize>(journal: &T) -> Result<InterTransferCommitEnvelope, String> {
    let journal = serde_json::to_value(journal).map_err(|error| error.to_string())?;
    if journal.get("version").and_then(serde_json::Value::as_u64)
        != Some(u64::from(INTER_TRANSFER_COMMIT_VERSION))
    {
        return Err("inter-transfer writer requires the current journal version".into());
    }
    Ok(InterTransferCommitEnvelope {
        checksum: value_checksum(&journal)?,
        journal,
    })
}

fn checked_value(bytes: &[u8]) -> Result<serde_json::Value, String> {
    if bytes.len() as u64 > MAX_INTER_TRANSFER_JOURNAL_BYTES {
        return Err("inter-transfer journal exceeds its size limit".into());
    }
    // Parse/validate the entire envelope before the legacy slice scanner touches it. Serde also
    // rejects duplicate envelope fields and trailing bytes. The scanner is not a JSON parser.
    let envelope: InterTransferCommitEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse inter-transfer journal envelope: {error}"))?;
    let version = envelope
        .journal
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "inter-transfer journal version is missing or invalid".to_string())?;
    let expected = match version {
        1 => checksum(legacy_stored_journal(bytes)?)?,
        version if version == u64::from(INTER_TRANSFER_COMMIT_VERSION) => {
            value_checksum(&envelope.journal)?
        }
        _ => {
            return Err(format!(
                "unsupported inter-transfer journal version {version}"
            ));
        }
    };
    if expected != envelope.checksum {
        return Err(
            "checksum mismatch; refusing partial/corrupt inter-transfer state (legacy v1 requires its original compact journal bytes)"
                .into(),
        );
    }
    Ok(envelope.journal)
}

pub(super) fn decode(bytes: &[u8]) -> Result<InterTransferCommitJournal, String> {
    serde_json::from_value(checked_value(bytes)?)
        .map_err(|error| format!("parse verified inter-transfer journal: {error}"))
}

fn skip_space(bytes: &[u8], mut offset: usize) -> usize {
    while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
        offset += 1;
    }
    offset
}

fn string_end(bytes: &[u8], start: usize) -> Result<usize, String> {
    if bytes.get(start) != Some(&b'"') {
        return Err("expected a JSON string in legacy journal envelope".into());
    }
    let mut offset = start + 1;
    while let Some(&byte) = bytes.get(offset) {
        match byte {
            b'\\' => offset += 2,
            b'"' => return Ok(offset + 1),
            _ => offset += 1,
        }
    }
    Err("unterminated JSON string in legacy journal envelope".into())
}

/// Locate the top-level `journal` value in an ALREADY validated envelope. Preserve every byte
/// inside that value (including object/HashSet array order and escapes), matching the v1 writer's
/// `serde_json::to_vec(journal)` exactly. Do not accept a recomputed or missing legacy checksum.
fn legacy_stored_journal(bytes: &[u8]) -> Result<&[u8], String> {
    let mut offset = skip_space(bytes, 0);
    if bytes.get(offset) != Some(&b'{') {
        return Err("legacy journal envelope is not an object".into());
    }
    offset += 1;
    loop {
        offset = skip_space(bytes, offset);
        if bytes.get(offset) == Some(&b'}') {
            return Err("legacy envelope has no journal field".into());
        }
        let key_start = offset;
        offset = string_end(bytes, offset)?;
        let key: String =
            serde_json::from_slice(&bytes[key_start..offset]).map_err(|error| error.to_string())?;
        offset = skip_space(bytes, offset);
        if bytes.get(offset) != Some(&b':') {
            return Err("legacy envelope field has no colon".into());
        }
        offset = skip_space(bytes, offset + 1);
        let start = offset;
        let mut depth = 0usize;
        while let Some(&byte) = bytes.get(offset) {
            match byte {
                b'"' => offset = string_end(bytes, offset)?,
                b'{' | b'[' => {
                    depth += 1;
                    offset += 1;
                }
                b'}' | b']' if depth > 0 => {
                    depth -= 1;
                    offset += 1;
                }
                b',' | b'}' if depth == 0 => break,
                _ => offset += 1,
            }
        }
        if key == "journal" {
            let mut end = offset;
            while end > start && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            return Ok(&bytes[start..end]);
        }
        if bytes.get(offset) != Some(&b',') {
            return Err("legacy envelope has no journal field".into());
        }
        offset += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct LegacyEnvelope<'a, T> {
        checksum: Bytes32,
        journal: &'a T,
    }

    #[derive(Serialize, Deserialize)]
    struct LedgerFixture {
        version: u32,
        imported_deposits: HashSet<String>,
        applied: HashSet<u64>,
        note: String,
    }

    fn fixture(version: u32) -> LedgerFixture {
        LedgerFixture {
            version,
            imported_deposits: (0..24).map(|i| format!("31337:rollup:{i}")).collect(),
            applied: (0..16).collect(),
            note: "ordinary nested JSON: {\"journal\": [1,2]}, 日本語 \\".into(),
        }
    }

    #[test]
    fn current_journal_roundtrip_preserves_all_security_ledger_entries() {
        let original = fixture(INTER_TRANSFER_COMMIT_VERSION);
        let envelope = encode(&original).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        for _ in 0..12 {
            let restored: LedgerFixture =
                serde_json::from_value(checked_value(&bytes).unwrap()).unwrap();
            assert_eq!(restored.imported_deposits, original.imported_deposits);
            assert_eq!(restored.applied, original.applied);
            let next = encode(&restored).unwrap();
            let restored_again: LedgerFixture =
                serde_json::from_value(checked_value(&serde_json::to_vec(&next).unwrap()).unwrap())
                    .unwrap();
            assert_eq!(restored_again.imported_deposits, original.imported_deposits);
        }
    }

    #[test]
    fn legacy_compact_journal_verifies_stored_bytes_not_rebuilt_hashsets() {
        let original = fixture(1);
        let stored_journal = serde_json::to_vec(&original).unwrap();
        let envelope = LegacyEnvelope {
            checksum: checksum(&stored_journal).unwrap(),
            journal: &original,
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(legacy_stored_journal(&bytes).unwrap(), stored_journal);
        for _ in 0..12 {
            let restored: LedgerFixture =
                serde_json::from_value(checked_value(&bytes).unwrap()).unwrap();
            assert_eq!(restored.imported_deposits, original.imported_deposits);
            assert_eq!(restored.applied, original.applied);
        }
    }

    #[test]
    fn legacy_envelope_field_order_does_not_change_journal_bytes() {
        let journal = serde_json::to_vec(&fixture(1)).unwrap();
        let hash = serde_json::to_string(&checksum(&journal).unwrap()).unwrap();
        let bytes = format!(
            "{{\n \"journal\":{},\"checksum\":{hash}\n}}",
            std::str::from_utf8(&journal).unwrap()
        );
        assert_eq!(legacy_stored_journal(bytes.as_bytes()).unwrap(), journal);
        assert!(checked_value(bytes.as_bytes()).is_ok());
    }

    #[test]
    fn integrity_and_version_checks_are_never_skipped() {
        let mut envelope = encode(&fixture(INTER_TRANSFER_COMMIT_VERSION)).unwrap();
        envelope.checksum = Bytes32::default();
        assert!(checked_value(&serde_json::to_vec(&envelope).unwrap()).is_err());
        envelope.journal["version"] = serde_json::json!(999);
        envelope.checksum = value_checksum(&envelope.journal).unwrap();
        assert!(checked_value(&serde_json::to_vec(&envelope).unwrap()).is_err());
        assert!(checked_value(b"{\"checksum\":").is_err());
    }

    #[test]
    fn journal_envelope_survives_private_atomic_file_persistence() {
        let directory = std::env::temp_dir().join(format!(
            "intmax-inter-codec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("journal.json");
        let original = fixture(INTER_TRANSFER_COMMIT_VERSION);
        write_private_json_at(&path, &encode(&original).unwrap());
        let bytes =
            read_bounded_regular_file(&path, MAX_INTER_TRANSFER_JOURNAL_BYTES, "test journal")
                .unwrap();
        let restored: LedgerFixture =
            serde_json::from_value(checked_value(&bytes).unwrap()).unwrap();
        assert_eq!(restored.imported_deposits, original.imported_deposits);
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
