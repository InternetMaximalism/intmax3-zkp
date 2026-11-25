//! Broadcast an already-signed raw transaction without putting it on a command line.
//!
//! A validity post carries its proof in blobs: two blobs make a raw transaction of about 526,000
//! hex characters. Linux refuses to start a process when any single argument is longer than
//! 131,071 bytes (`MAX_ARG_STRLEN`), so `cast publish <raw>` failed with E2BIG ("Argument list too
//! long", os error 7) on every post from the Linux host, and no block reached L1. macOS has no
//! per-argument limit, which is why local rehearsals did not show it.
//!
//! `cast rpc --raw` reads its JSON params from stdin when none are given on the command line, so
//! the transaction is written to the child's stdin instead.

use std::{
    io::Write,
    process::{Command, Stdio},
};

/// Send `eth_sendRawTransaction` for `raw_transaction` with the transaction on stdin, and return
/// the transaction hash the RPC answered.
///
/// The caller compares that hash with the one it signed, and on an error checks whether the RPC
/// already knows the signed hash (a node may accept the transaction and then fail to answer).
pub fn send_raw_transaction(rpc: &str, raw_transaction: &str) -> Result<String, String> {
    let params = serde_json::to_vec(&[raw_transaction])
        .map_err(|error| format!("encode eth_sendRawTransaction params: {error}"))?;
    let mut child = Command::new("cast")
        .args(["rpc", "--raw", "eth_sendRawTransaction", "--rpc-url", rpc])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start cast rpc eth_sendRawTransaction: {error}"))?;
    // cast reads all of stdin before it sends anything and prints only a hash, so writing the
    // whole transaction before collecting the output cannot deadlock. If cast exits early, the
    // write fails with a broken pipe; its stderr then says why, so report that first.
    let written = child
        .stdin
        .take()
        .ok_or_else(|| "cast rpc has no stdin".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&params)
                .map_err(|error| format!("write the raw transaction to cast rpc: {error}"))
        });
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for cast rpc eth_sendRawTransaction: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "eth_sendRawTransaction failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    written?;
    let answer: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "eth_sendRawTransaction answered {:?}, not JSON: {error}",
            String::from_utf8_lossy(&output.stdout).trim()
        )
    })?;
    answer
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("eth_sendRawTransaction answered {answer}, not a transaction hash"))
}
