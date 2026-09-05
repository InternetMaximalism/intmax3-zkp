//! Local, single-entry write-ahead log for an already verified, N-of-N signed deposit import.
//!
//! Callers hold `CliStateProcessLock` and run `recover` before any other state operation. This
//! module never imports a deposit, signs a state, or trusts a journal as fresh chain evidence.
//! It only finishes publishing an import whose transition and chain receipt were verified by
//! the caller. Private state, including conservative credit bounds, is committed atomically.

use super::*;

const WAL_PATH: &str = ".pending-deposit-import.json";
const RECEIPT_DIRECTORY: &str = ".deposit-import-receipts";
const CANONICAL_OUTPUT: &str = "l1_import_cosigned.json";
const SCHEMA_VERSION: u32 = 1;
const MAX_RECOVERY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    checksum: String,
    // Hash the JSON value, not a reserialized CliState: its HashSet ledger iteration order is
    // intentionally unspecified and changes on deserialize. Value preserves the stored arrays.
    payload: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    channel_id: ChannelId,
    record_digest: Bytes32,
    tx_hash: String,
    deposit_identity: String,
    before_digest: Bytes32,
    after_digest: Bytes32,
    result: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    receipt: Receipt,
    after: CliState,
}

fn normalized_tx_hash(tx_hash: &str) -> Result<String, String> {
    canonical_hex(tx_hash, 32, "deposit transaction hash")
}

fn receipt_path(tx_hash: &str) -> Result<PathBuf, String> {
    let tx_hash = normalized_tx_hash(tx_hash)?;
    Ok(Path::new(RECEIPT_DIRECTORY).join(format!("{}.json", &tx_hash[2..])))
}

fn validate_output_path(output_path: &str) -> Result<(), String> {
    // Recovery never stores or follows this caller-selected path. Restrict the immediate
    // publication too, so an output argument cannot replace authoritative state or a journal.
    if output_path.is_empty()
        || output_path.starts_with('.')
        || output_path.contains('/')
        || output_path.contains('\\')
        || !output_path.ends_with(".json")
        || matches!(
            output_path,
            STATE_FILE | "channel_snapshot.json" | "channel_backing.json" | "settlement.json"
        )
    {
        return Err(
            "deposit output must be a non-hidden .json basename, not an authoritative state file"
                .into(),
        );
    }
    Ok(())
}

fn payload_checksum(payload: &serde_json::Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn decode_envelope<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() as u64 > MAX_RECOVERY_BYTES {
        return Err("deposit recovery envelope exceeds its size limit".into());
    }
    let envelope: Envelope = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid deposit recovery envelope: {error}"))?;
    if envelope.checksum != payload_checksum(&envelope.payload)? {
        return Err("deposit recovery checksum mismatch; refusing corrupt state".into());
    }
    serde_json::from_value(envelope.payload)
        .map_err(|error| format!("invalid deposit recovery payload: {error}"))
}

fn write_envelope<T: Serialize>(path: &Path, value: &T) {
    let payload = serde_json::to_value(value)
        .unwrap_or_else(|error| die(format!("serialize deposit recovery payload: {error}")));
    let checksum = payload_checksum(&payload).unwrap_or_else(|error| die(error));
    let bytes = serde_json::to_vec(&Envelope { checksum, payload })
        .unwrap_or_else(|error| die(format!("serialize deposit recovery envelope: {error}")));
    if bytes.len() as u64 > MAX_RECOVERY_BYTES {
        die("deposit recovery envelope exceeds its size limit; state has not been committed");
    }
    write_private_bytes_at(path, &bytes);
}

fn read_envelope<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    secure_private_path(path);
    let bytes = read_bounded_regular_file(path, MAX_RECOVERY_BYTES, "deposit recovery file")
        .unwrap_or_else(|error| die(error));
    decode_envelope(&bytes).unwrap_or_else(|error| die(format!("{}: {error}", path.display())))
}

fn path_exists(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => die(format!("inspect {}: {error}", path.display())),
    }
}

/// Cross-channel callers hold this directory's process lock, but must not advance its head
/// until its own startup has finished an older deposit publication. The API does that recovery
/// automatically; direct native callers get a precise, non-spending retry instruction.
pub(super) fn require_no_pending_at(directory: &Path) {
    if path_exists(&directory.join(WAL_PATH)) {
        die(format!(
            "pending deposit import in {}; run publish-snapshot there with its INTMAX_CHANNEL, then retry before signing",
            directory.display()
        ));
    }
}

fn ensure_receipt_directory(create: bool) -> bool {
    let path = Path::new(RECEIPT_DIRECTORY);
    if !path_exists(path) {
        if !create {
            return false;
        }
        fs::create_dir(path)
            .unwrap_or_else(|error| die(format!("create deposit receipts: {error}")));
        FileSync::sync_directory(Path::new("."));
    }
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| die(format!("inspect deposit receipt directory: {error}")));
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        die("deposit receipt directory is not a real non-symlink directory");
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| die(format!("chmod 0700 deposit receipt directory: {error}")));
    true
}

fn result_states(result: &serde_json::Value) -> Result<(ChannelState, ChannelState), String> {
    let parse = |field: &str| {
        serde_json::from_value(
            result
                .get(field)
                .cloned()
                .ok_or_else(|| format!("deposit result is missing {field}"))?,
        )
        .map_err(|error| format!("invalid deposit result {field}: {error}"))
    };
    Ok((parse("fundImportState")?, parse("bundleApplyState")?))
}

fn validate_receipt(receipt: &Receipt, current: &CliState) -> Result<(), String> {
    if receipt.schema_version != SCHEMA_VERSION {
        return Err("unsupported deposit recovery schema version".into());
    }
    if receipt.channel_id.as_u64() != u64::from(channel_id_env())
        || receipt.channel_id != current.snapshot.record.channel_id
        || receipt.record_digest != current.snapshot.record.signing_digest()
    {
        return Err("deposit recovery channel/record context does not match this directory".into());
    }
    if normalized_tx_hash(&receipt.tx_hash)? != receipt.tx_hash
        || normalized_tx_hash(json_required_string(&receipt.result, "txHash")?)? != receipt.tx_hash
    {
        return Err("deposit recovery transaction identity mismatch".into());
    }
    let deposit_index = json_required_u64(&receipt.result, "depositIndex")?;
    let identity_parts: Vec<_> = receipt.deposit_identity.split(':').collect();
    if identity_parts.len() != 3
        || identity_parts[0]
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .is_none()
        || &canonical_hex(identity_parts[1], 20, "deposit rollup")?[2..] != identity_parts[1]
        || identity_parts[2] != deposit_index.to_string()
    {
        return Err("deposit recovery consumed-deposit identity is malformed".into());
    }
    if let Some(binding) = &current.settlement_binding {
        if &canonical_hex(&binding.rollup, 20, "bound deposit rollup")?[2..] != identity_parts[1]
            || binding
                .deployment
                .as_ref()
                .is_some_and(|deployment| deployment.chain_id.to_string() != identity_parts[0])
        {
            return Err(
                "deposit recovery receipt disagrees with the pinned settlement network".into(),
            );
        }
    }
    json_required_u64(&receipt.result, "intmaxBlockNumber")?;
    let (fund, bundle) = result_states(&receipt.result)?;
    validate_digest_chain(
        receipt.before_digest,
        fund.prev_digest,
        fund.digest,
        bundle.prev_digest,
        bundle.digest,
        receipt.after_digest,
    )?;
    current
        .snapshot
        .record
        .validate()
        .map_err(|error| format!("invalid deposit recovery record: {error:?}"))?;
    for (label, state) in [("fund import", &fund), ("bundle apply", &bundle)] {
        if state.channel_id != receipt.channel_id
            || state.channel_fund.channel_id != receipt.channel_id
            || state.balance_state.channel_id != receipt.channel_id
            || state.balance_state.member_count != current.snapshot.record.member_count
            || state.balance_state.delegate_count != current.snapshot.record.delegate_count
            || state.member_signatures.len() != current.snapshot.record.member_count as usize
        {
            return Err(format!(
                "deposit recovery {label} channel/member context mismatch"
            ));
        }
        state
            .balance_state
            .validate()
            .map_err(|error| format!("invalid deposit recovery {label} balances: {error:?}"))?;
        verify_all_signatures(&current.snapshot.record, &current.snapshot.members, state)
            .map_err(|error| format!("deposit recovery {label} N-of-N check: {error}"))?;
    }
    Ok(())
}

fn validate_digest_chain(
    before: Bytes32,
    fund_parent: Bytes32,
    fund: Bytes32,
    bundle_parent: Bytes32,
    bundle: Bytes32,
    after: Bytes32,
) -> Result<(), String> {
    if before == Bytes32::default()
        || fund == Bytes32::default()
        || bundle == Bytes32::default()
        || before == fund
        || before == bundle
        || fund == bundle
        || fund_parent != before
        || bundle_parent != fund
        || bundle != after
    {
        return Err("deposit recovery breaks the two-step signed digest chain".into());
    }
    Ok(())
}

fn validate_recovery_head(current: Bytes32, before: Bytes32, after: Bytes32) -> Result<(), String> {
    if current != before && current != after {
        return Err(
            "pending deposit import cannot overwrite a head other than its before/after state; preserve the journal and investigate"
                .into(),
        );
    }
    Ok(())
}

fn validate_journal(journal: &Journal, current: &CliState) -> Result<(), String> {
    let receipt = &journal.receipt;
    validate_recovery_head(
        current.snapshot.state.digest,
        receipt.before_digest,
        receipt.after_digest,
    )?;
    validate_receipt(receipt, current)?;
    if journal.after.state_schema_version != STATE_SCHEMA_VERSION {
        return Err("pending deposit state has an incompatible private-state schema".into());
    }
    validate_signing_security_state(&journal.after)?;
    verify_snapshot(&journal.after.snapshot, None)
        .map_err(|error| format!("pending deposit snapshot verification: {error}"))?;
    let (_, bundle) = result_states(&receipt.result)?;
    if journal.after.snapshot.record.signing_digest() != receipt.record_digest
        || journal.after.snapshot.state != bundle
        || !journal
            .after
            .imported_deposits
            .contains(&receipt.deposit_identity)
    {
        return Err("pending deposit state/result/consumed ledger mismatch".into());
    }
    // A matching head alone is not permission to erase a durable signing/replay decision made
    // before the journal. All monotone security histories survive the roll-forward unchanged.
    if !current
        .imported_deposits
        .is_subset(&journal.after.imported_deposits)
        || !current
            .applied_tx_identities
            .is_subset(&journal.after.applied_tx_identities)
        || !current
            .spent_tx_identities
            .is_subset(&journal.after.spent_tx_identities)
        || serde_json::to_value(&current.controlled).map_err(|e| e.to_string())?
            != serde_json::to_value(&journal.after.controlled).map_err(|e| e.to_string())?
        || serde_json::to_value(&current.settlement_binding).map_err(|e| e.to_string())?
            != serde_json::to_value(&journal.after.settlement_binding).map_err(|e| e.to_string())?
    {
        return Err(
            "pending deposit would replace private identity or roll back a security ledger".into(),
        );
    }
    for (key, value) in &current.state_signing_ledger {
        let Some(after_value) = journal.after.state_signing_ledger.get(key) else {
            return Err("pending deposit omits a durable signing decision".into());
        };
        if serde_json::to_value(value).map_err(|e| e.to_string())?
            != serde_json::to_value(after_value).map_err(|e| e.to_string())?
        {
            return Err("pending deposit changes a durable signing decision".into());
        }
    }
    for (key, reservation) in &current.deposit_capacity_reservations {
        let Some(after_reservation) = journal.after.deposit_capacity_reservations.get(key) else {
            return Err("pending deposit would remove a durable capacity reservation".into());
        };
        let mut completed_reservation = reservation.clone();
        let matches_import = reservation
            .tx_hash
            .is_some_and(|hash| hash.to_hex() == receipt.tx_hash);
        if matches_import {
            completed_reservation.completed = true;
            if !after_reservation.completed {
                return Err(
                    "pending deposit has not completed its own capacity reservation".into(),
                );
            }
        }
        if after_reservation != reservation && after_reservation != &completed_reservation {
            return Err(
                "pending deposit changes a different reservation or reverses its completion".into(),
            );
        }
    }
    Ok(())
}

fn finish(journal: &Journal, output_path: Option<&str>) {
    // WAL already durable. Retain it on any failure, including receipt/output publication.
    save_state(&journal.after);
    write_json("channel_snapshot.json", &journal.after.snapshot);
    write_json(CANONICAL_OUTPUT, &journal.receipt.result);
    if let Some(output_path) = output_path.filter(|path| *path != CANONICAL_OUTPUT) {
        write_json(output_path, &journal.receipt.result);
    }
    ensure_receipt_directory(true);
    let path = receipt_path(&journal.receipt.tx_hash).unwrap_or_else(|error| die(error));
    if path_exists(&path) {
        let existing: Receipt = read_envelope(&path);
        if serde_json::to_value(&existing).unwrap_or_else(|error| die(error))
            != serde_json::to_value(&journal.receipt).unwrap_or_else(|error| die(error))
        {
            die("deposit transaction already has a different durable completion receipt");
        }
    } else {
        write_envelope(&path, &journal.receipt);
    }
    fs::remove_file(WAL_PATH).unwrap_or_else(|error| {
        die(format!(
            "retire completed deposit recovery journal: {error}"
        ))
    });
    FileSync::sync_directory(Path::new("."));
}

/// Commit an already authenticated import. The result and full private successor enter a
/// durable WAL before either authoritative state or public artifacts are replaced.
pub(super) fn commit(
    before_digest: Bytes32,
    after: &CliState,
    result: &serde_json::Value,
    tx_hash: &str,
    output_path: &str,
) {
    validate_output_path(output_path).unwrap_or_else(|error| die(error));
    if path_exists(Path::new(WAL_PATH)) {
        die("a deposit import is already pending; recover it before preparing another import");
    }
    let current = load_state();
    if current.snapshot.state.digest != before_digest {
        die("deposit commit predecessor is not the durable channel head");
    }
    let added: Vec<_> = after
        .imported_deposits
        .difference(&current.imported_deposits)
        .collect();
    if added.len() != 1 {
        die("deposit commit must add exactly one consumed-deposit identity");
    }
    let journal = Journal {
        receipt: Receipt {
            schema_version: SCHEMA_VERSION,
            channel_id: after.snapshot.record.channel_id,
            record_digest: after.snapshot.record.signing_digest(),
            tx_hash: normalized_tx_hash(tx_hash).unwrap_or_else(|error| die(error)),
            deposit_identity: added[0].clone(),
            before_digest,
            after_digest: after.snapshot.state.digest,
            result: result.clone(),
        },
        after: after.clone(),
    };
    validate_journal(&journal, &current).unwrap_or_else(|error| die(error));
    write_envelope(Path::new(WAL_PATH), &journal);
    finish(&journal, Some(output_path));
}

/// Run under the process lock before dispatching a command. No WAL means no state read, so new
/// channel initialization still works. A stale or corrupt WAL is preserved and fails closed.
pub(super) fn recover() {
    if !path_exists(Path::new(WAL_PATH)) {
        return;
    }
    let journal: Journal = read_envelope(Path::new(WAL_PATH));
    let current = load_state();
    validate_journal(&journal, &current).unwrap_or_else(|error| die(error));
    finish(&journal, None);
    eprintln!(
        "[state] recovered deposit import {}; no new signature or credit was produced",
        journal.receipt.tx_hash
    );
}

/// Lookup only; the caller must first recheck the transaction's chain receipt, amount, token and
/// recipient policy. Later channel heads are permitted, but channel/record and consumed ledger
/// identity must still match. Replaying this result never re-applies the import.
pub(super) fn completed(tx_hash: &str) -> Option<serde_json::Value> {
    let path = receipt_path(tx_hash).unwrap_or_else(|error| die(error));
    if !ensure_receipt_directory(false) || !path_exists(&path) {
        return None;
    }
    let receipt: Receipt = read_envelope(&path);
    if receipt.tx_hash != normalized_tx_hash(tx_hash).unwrap_or_else(|error| die(error)) {
        die("deposit receipt filename and transaction identity disagree");
    }
    let current = load_state();
    validate_receipt(&receipt, &current).unwrap_or_else(|error| die(error));
    if !current
        .imported_deposits
        .contains(&receipt.deposit_identity)
    {
        die("deposit completion receipt is not present in the durable consumed-deposit ledger");
    }
    Some(receipt.result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Bytes32 {
        Bytes32::from_bytes_be(&[byte; 32]).unwrap()
    }

    #[test]
    fn deposit_recovery_hash_paths_are_canonical_and_confined() {
        let mixed = format!("0X{}", "Ab".repeat(32));
        assert_eq!(
            normalized_tx_hash(&mixed).unwrap(),
            format!("0x{}", "ab".repeat(32))
        );
        assert_eq!(
            receipt_path(&mixed).unwrap(),
            Path::new(RECEIPT_DIRECTORY).join(format!("{}.json", "ab".repeat(32)))
        );
        for bad in ["../receipt", "0x00", "", "/tmp/receipt.json"] {
            assert!(receipt_path(bad).is_err());
        }
    }

    #[test]
    fn deposit_recovery_output_cannot_replace_authority_or_escape() {
        assert!(validate_output_path(CANONICAL_OUTPUT).is_ok());
        assert!(validate_output_path("my-import.json").is_ok());
        for bad in [
            "../out.json",
            "/tmp/out.json",
            "a/b.json",
            "a\\b.json",
            STATE_FILE,
            "channel_snapshot.json",
            "channel_backing.json",
            "settlement.json",
            WAL_PATH,
            "out",
            "",
        ] {
            assert!(validate_output_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn deposit_recovery_envelope_roundtrips_stored_ledger_order() {
        let payload = serde_json::json!({"ledger": ["b", "a"], "value": 3});
        let envelope = Envelope {
            checksum: payload_checksum(&payload).unwrap(),
            payload: payload.clone(),
        };
        let decoded: serde_json::Value =
            decode_envelope(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn deposit_recovery_rejects_corrupt_or_truncated_envelopes() {
        let payload = serde_json::json!({"ledger": ["b", "a"]});
        let mut envelope = Envelope {
            checksum: payload_checksum(&payload).unwrap(),
            payload,
        };
        envelope.payload["ledger"][0] = serde_json::json!("changed");
        assert!(
            decode_envelope::<serde_json::Value>(&serde_json::to_vec(&envelope).unwrap()).is_err()
        );
        assert!(decode_envelope::<serde_json::Value>(b"{\"checksum\":").is_err());
    }

    #[test]
    fn deposit_recovery_accepts_only_before_or_after_head() {
        let before = digest(1);
        let after = digest(3);
        assert!(validate_recovery_head(before, before, after).is_ok());
        assert!(validate_recovery_head(after, before, after).is_ok());
        assert!(validate_recovery_head(digest(4), before, after).is_err());
        assert!(validate_recovery_head(digest(2), before, after).is_err());
    }

    #[test]
    fn deposit_recovery_requires_exact_two_step_digest_links() {
        let before = digest(1);
        let fund = digest(2);
        let after = digest(3);
        assert!(validate_digest_chain(before, before, fund, fund, after, after).is_ok());
        assert!(validate_digest_chain(before, after, fund, fund, after, after).is_err());
        assert!(validate_digest_chain(before, before, fund, before, after, after).is_err());
        assert!(validate_digest_chain(before, before, fund, fund, after, fund).is_err());
        assert!(validate_digest_chain(before, before, fund, fund, before, before).is_err());
    }
}
