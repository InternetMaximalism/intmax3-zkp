//! Acceptance receipts are committed in the SAME private state replacement as the debit.
//! A response or public snapshot can be lost without losing the request -> accepted head index.
use super::*;

pub(super) fn canonical_id(slim: &SlimSendPayload) -> String {
    let value = serde_json::to_value(slim).unwrap_or_else(|e| die(e));
    hex::encode(Sha256::digest(
        serde_json::to_vec(&value).unwrap_or_else(|e| die(e)),
    ))
}

pub(super) fn record(state: &mut CliState, next: &ChannelState, ids: &[String]) {
    record_at(Path::new("."), state, next, ids);
}

pub(super) fn record_at(root: &Path, state: &mut CliState, next: &ChannelState, ids: &[String]) {
    verify_all_signatures(&state.snapshot.record, &state.snapshot.members, next)
        .unwrap_or_else(|e| die(format!("send receipt requires N-of-N signatures: {e}")));
    let dir = root.join("accepted_send_states");
    fs::create_dir_all(&dir).unwrap_or_else(|e| die(e));
    // Archive before publishing the index: an orphan archive is harmless; an indexed missing
    // result would strand an accepted payment. write_json fsyncs the file and its directory.
    write_json(
        &dir.join(format!("{}.json", next.digest.to_hex()))
            .to_string_lossy(),
        next,
    );
    for id in ids {
        if let Some(previous) = state.accepted_send_receipts.get(id) {
            if *previous != next.digest {
                die("send request already accepted at another head");
            }
        }
        state.accepted_send_receipts.insert(id.clone(), next.digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_ids_and_signed_head_survive_private_state_commit_before_publication() {
        let mut state = super::super::signing_ledger_tests::fixture();
        let root = std::env::temp_dir().join(format!(
            "send-receipts-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&root).unwrap();
        let mut signed = state.snapshot.state.clone();
        for member in &state.controlled {
            let keys = keys_for(member.keygen_seed);
            let sig = sign_state(&keys, member.slot as u8, &signed).unwrap();
            add_signature(&mut signed, sig);
        }
        let ids = vec!["ab".repeat(32), "cd".repeat(32)];
        record_at(&root, &mut state, &signed, &ids);
        state.snapshot.state = signed.clone();
        write_private_json_at(&root.join(STATE_FILE), &state);
        // Simulate losing the entire response/publication phase; only reopen private commit.
        assert!(!root.join("channel_snapshot.json").exists());
        let recovered: CliState =
            serde_json::from_slice(&fs::read(root.join(STATE_FILE)).unwrap()).unwrap();
        for id in ids {
            assert_eq!(recovered.accepted_send_receipts[&id], signed.digest);
        }
        let archived: ChannelState = serde_json::from_slice(
            &fs::read(
                root.join("accepted_send_states")
                    .join(format!("{}.json", signed.digest.to_hex())),
            )
            .unwrap(),
        )
        .unwrap();
        verify_all_signatures(
            &recovered.snapshot.record,
            &recovered.snapshot.members,
            &archived,
        )
        .unwrap();
        assert_eq!(archived.digest, recovered.snapshot.state.digest);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires a public real send payload and its independently computed browser hash"]
    fn browser_receipt_identity_matches_native_payload() {
        let path = std::env::var("INTMAX_TEST_SEND_PAYLOAD").expect("public payload fixture path");
        let expected = std::env::var("INTMAX_TEST_SEND_ID").expect("browser canonical hash");
        let payload: SendPayload = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(canonical_id(&payload.to_slim()), expected);
    }
}
