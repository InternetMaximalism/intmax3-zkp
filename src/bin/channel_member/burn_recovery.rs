//! Publish an already validated burn head and its withdrawal metadata through one local WAL.
//! Recovery runs under the channel process lock and never creates a signature or a proof.

use super::*;

const WAL: &str = ".pending-burn-publication.json";
const MAX_BYTES: usize = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    before: Bytes32,
    after: CliState,
    metadata: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    sha256: String,
    payload: serde_json::Value,
}

fn encode<T: Serialize>(value: &T) -> Result<Envelope, String> {
    let payload = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("burn recovery journal exceeds size limit".into());
    }
    Ok(Envelope {
        sha256: hex::encode(Sha256::digest(bytes)),
        payload,
    })
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > MAX_BYTES {
        return Err("burn recovery journal exceeds size limit".into());
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let stored = serde_json::to_vec(&envelope.payload).map_err(|error| error.to_string())?;
    if hex::encode(Sha256::digest(stored)) != envelope.sha256 {
        return Err("burn recovery checksum mismatch; retain journal for recovery".into());
    }
    serde_json::from_value(envelope.payload).map_err(|error| error.to_string())
}

fn validate_output(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('.')
        || path.contains('/')
        || path.contains('\\')
        || !path.ends_with(".json")
        || matches!(
            path,
            STATE_FILE
                | "channel_snapshot.json"
                | "channel_backing.json"
                | "settlement.json"
                | "last_burn.json"
                | "burn_payload.json"
                | "burn_descriptor.json"
        )
    {
        return Err("burn result must use a non-hidden JSON basename, not an authoritative or metadata file".into());
    }
    Ok(())
}

fn exists(directory: &Path) -> bool {
    match fs::symlink_metadata(directory.join(WAL)) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => die(format!("inspect burn recovery journal: {error}")),
    }
}

pub(super) fn require_no_pending_at(directory: &Path) {
    if exists(directory) {
        die(format!(
            "pending burn publication in {}; run publish-snapshot there with its INTMAX_CHANNEL and retry",
            directory.display()
        ));
    }
}

fn validate(journal: &Journal, current: &CliState) -> Result<(), String> {
    let after = &journal.after;
    let head = &after.snapshot.state;
    if journal.version != 1
        || head.prev_digest != journal.before
        || (current.snapshot.state.digest != journal.before
            && current.snapshot.state.digest != head.digest)
        || head.channel_id.as_u64() != u64::from(channel_id_env())
        || current.snapshot.record.signing_digest() != after.snapshot.record.signing_digest()
        || journal.metadata["channel_id"].as_u64() != Some(head.channel_id.as_u64())
    {
        return Err("burn publication does not belong to this channel's before/after head".into());
    }
    validate_signing_security_state(after)?;
    verify_snapshot(&after.snapshot, None).map_err(|error| error.to_string())?;
    if current.accepted_send_receipts != after.accepted_send_receipts
        || current.imported_deposits != after.imported_deposits
        || current.applied_tx_identities != after.applied_tx_identities
        || !current
            .spent_tx_identities
            .is_subset(&after.spent_tx_identities)
        || current.deposit_capacity_reservations != after.deposit_capacity_reservations
        || serde_json::to_value(&current.controlled).map_err(|e| e.to_string())?
            != serde_json::to_value(&after.controlled).map_err(|e| e.to_string())?
        || serde_json::to_value(&current.settlement_binding).map_err(|e| e.to_string())?
            != serde_json::to_value(&after.settlement_binding).map_err(|e| e.to_string())?
    {
        return Err(
            "burn recovery would change identity, reservation, or roll back replay history".into(),
        );
    }
    for (key, decision) in &current.state_signing_ledger {
        let retained = after
            .state_signing_ledger
            .get(key)
            .ok_or("burn recovery omits a signing decision")?;
        if serde_json::to_value(decision).map_err(|e| e.to_string())?
            != serde_json::to_value(retained).map_err(|e| e.to_string())?
        {
            return Err("burn recovery changes a signing decision".into());
        }
    }
    Ok(())
}

fn finish(journal: &Journal, output: Option<&str>) {
    save_state(&journal.after);
    write_json("channel_snapshot.json", &journal.after.snapshot);
    write_json("last_burn.json", &journal.metadata);
    write_json("burn_cosigned.json", &journal.after.snapshot.state);
    if let Some(output) = output.filter(|path| *path != "burn_cosigned.json") {
        write_json(output, &journal.after.snapshot.state);
    }
    fs::remove_file(WAL).unwrap_or_else(|error| die(format!("retire burn journal: {error}")));
    FileSync::sync_directory(Path::new("."));
}

pub(super) fn commit(after: &CliState, metadata: serde_json::Value, output: &str) {
    validate_output(output).unwrap_or_else(|error| die(error));
    require_no_pending_at(Path::new("."));
    let journal = Journal {
        version: 1,
        before: after.snapshot.state.prev_digest,
        after: after.clone(),
        metadata,
    };
    validate(&journal, &load_state()).unwrap_or_else(|error| die(error));
    let envelope = encode(&journal).unwrap_or_else(|error| die(error));
    if serde_json::to_vec(&envelope)
        .unwrap_or_else(|error| die(error))
        .len()
        > MAX_BYTES
    {
        die("burn publication envelope exceeds recovery size limit; head has not been committed");
    }
    write_private_json_at(Path::new(WAL), &envelope);
    finish(&journal, Some(output));
}

pub(super) fn recover() {
    if !exists(Path::new(".")) {
        return;
    }
    let bytes =
        read_bounded_regular_file(Path::new(WAL), MAX_BYTES as u64, "burn publication journal")
            .unwrap_or_else(|error| die(error));
    let journal: Journal = decode(&bytes).unwrap_or_else(|error| die(error));
    validate(&journal, &load_state()).unwrap_or_else(|error| die(error));
    finish(&journal, None);
    eprintln!("[state] recovered burn head and withdrawal metadata without new signatures");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_ledger_roundtrip_is_order_independent() {
        let ledger: HashSet<String> = (0..24).map(|index| format!("decision-{index}")).collect();
        let envelope = encode(&ledger).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let restored: HashSet<String> = decode(&bytes).unwrap();
        assert_eq!(restored, ledger);
    }

    #[test]
    fn publication_output_preserves_authoritative_files() {
        assert!(validate_output("burn_cosigned.json").is_ok());
        assert!(validate_output("result.json").is_ok());
        for path in [
            STATE_FILE,
            "last_burn.json",
            "../result.json",
            "channel_snapshot.json",
            WAL,
        ] {
            assert!(validate_output(path).is_err());
        }
    }
}
