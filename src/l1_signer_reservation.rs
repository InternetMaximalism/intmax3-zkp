//! Signer-scoped durable intent reservation for production L1 publishers.
//!
//! A process-only `flock` prevents two live publishers from signing concurrently, but the kernel
//! releases it after a crash. If publisher A has already fsynced raw transaction nonce `N` into
//! its private journal, publisher B could then sign a different transaction at `N` before A
//! broadcasts. The result is either a replacement or a permanently unrecoverable exact-replay
//! journal.
//!
//! Every conforming Rust publisher therefore creates this signer-global record while holding the
//! existing `(chain, signer)` flock **before offline signing begins**. There is no two-file window
//! containing durable raw bytes but no global reservation: a crash before the action journal is
//! written leaves an opaque-looking but recoverable intent reservation, and the same journal +
//! phase + intent may resume it. Other actions fail closed. The owner removes the record only
//! after its exact transaction is canonical-finalized and that fact is durable in its journal.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 16 * 1024;
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignerReservation {
    schema_version: u32,
    chain_id: u64,
    signer: String,
    owner_kind: String,
    journal_path: String,
    phase: String,
    intent_hash: String,
}

impl SignerReservation {
    pub(crate) fn new(
        chain_id: u64,
        signer: &str,
        owner_kind: &str,
        journal_path: &Path,
        phase: &str,
        intent_hash: &str,
    ) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("signer reservation chain id must be nonzero".into());
        }
        let signer = canonical_hex(signer, 20, "signer reservation address")?;
        let intent_hash = canonical_hex(intent_hash, 32, "signer reservation intent hash")?;
        validate_label(owner_kind, "owner kind")?;
        validate_label(phase, "phase")?;
        let journal_path = canonical_file_identity(journal_path)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            chain_id,
            signer,
            owner_kind: owner_kind.to_owned(),
            journal_path,
            phase: phase.to_owned(),
            intent_hash,
        })
    }

    pub(crate) fn phase(&self) -> &str {
        &self.phase
    }
}

fn validate_label(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        return Err(format!(
            "signer reservation {what} must be 1..=128 conservative ASCII characters"
        ));
    }
    Ok(())
}

fn canonical_hex(value: &str, bytes: usize, what: &str) -> Result<String, String> {
    let body = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .ok_or_else(|| format!("{what} must start with 0x"))?;
    if body.len() != bytes * 2 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{what} must contain exactly {bytes} bytes"));
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

fn canonical_file_identity(path: &Path) -> Result<String, String> {
    let filename = path
        .file_name()
        .ok_or_else(|| format!("journal {} has no filename", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("canonicalize journal parent {}: {error}", parent.display()))?;
    parent
        .join(filename)
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "canonical journal path is not UTF-8".into())
}

#[cfg(unix)]
fn canonical_private_root(root: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("create signer reservation root {}: {error}", root.display()))?;
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        format!(
            "inspect signer reservation root {}: {error}",
            root.display()
        )
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "signer reservation root {} must be a non-symlink directory",
            root.display()
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!(
            "signer reservation root {} is not owned by the current operator",
            root.display()
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "repair signer reservation root {} permissions: {error}",
                root.display()
            )
        })?;
    }
    fs::canonicalize(root).map_err(|error| format!("canonicalize signer reservation root: {error}"))
}

#[cfg(not(unix))]
fn canonical_private_root(_root: &Path) -> Result<PathBuf, String> {
    Err("durable signer reservations require Unix ownership/fsync semantics".into())
}

fn reservation_path(root: &Path, reservation: &SignerReservation) -> Result<PathBuf, String> {
    let root = canonical_private_root(root)?;
    Ok(root.join(format!(
        ".intmax-l1-signer-{}-{}.reservation.json",
        reservation.chain_id,
        reservation.signer.trim_start_matches("0x")
    )))
}

#[cfg(unix)]
fn read_existing(path: &Path) -> Result<Option<SignerReservation>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect signer reservation {}: {error}",
                path.display()
            ));
        }
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_RECORD_BYTES
    {
        return Err(format!(
            "signer reservation {} is not a private, operator-owned regular file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read signer reservation {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(format!(
            "signer reservation {} is oversized",
            path.display()
        ));
    }
    let value: SignerReservation = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse signer reservation {}: {error}", path.display()))?;
    if value.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "signer reservation {} has unsupported schema {}",
            path.display(),
            value.schema_version
        ));
    }
    Ok(Some(value))
}

#[cfg(not(unix))]
fn read_existing(_path: &Path) -> Result<Option<SignerReservation>, String> {
    Err("durable signer reservations require Unix ownership/fsync semantics".into())
}

#[cfg(unix)]
fn create_atomic(path: &Path, reservation: &SignerReservation) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "reservation path needs a UTF-8 filename".to_owned())?;
    let temporary = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let bytes = serde_json::to_vec_pretty(reservation)
        .map_err(|error| format!("serialize signer reservation: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("create signer reservation staging file: {error}"))?;
    let staged = (|| -> std::io::Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // `hard_link` is a no-overwrite atomic publication. Even a nonconforming process cannot
        // win a race by replacing a reservation that appeared after our initial read.
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        fs::File::open(parent)?.sync_all()
    })();
    if let Err(error) = staged {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "durably publish signer reservation {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_atomic(_path: &Path, _reservation: &SignerReservation) -> Result<(), String> {
    Err("durable signer reservations require Unix ownership/fsync semantics".into())
}

/// Claim the signer lane for exactly one journal phase. Call while holding the canonical signer
/// flock and before invoking any offline signing command.
pub(crate) fn claim(root: &Path, expected: &SignerReservation) -> Result<(), String> {
    let path = reservation_path(root, expected)?;
    if let Some(actual) = read_existing(&path)? {
        if actual == *expected {
            return Ok(());
        }
        return Err(format!(
            "signer lane is durably reserved by {} phase {} at {}; resume that journal before signing another nonce",
            actual.owner_kind, actual.phase, actual.journal_path
        ));
    }
    create_atomic(&path, expected)
}

/// Release an exact reservation only after its transaction is canonical-finalized and that fact
/// has been fsynced into the owning journal.
#[cfg(unix)]
pub(crate) fn release(root: &Path, expected: &SignerReservation) -> Result<(), String> {
    let path = reservation_path(root, expected)?;
    let actual = read_existing(&path)?.ok_or_else(|| {
        format!(
            "signer reservation for phase {} disappeared before durable release",
            expected.phase()
        )
    })?;
    if actual != *expected {
        return Err(format!(
            "refusing to release signer reservation owned by {} phase {} at {}",
            actual.owner_kind, actual.phase, actual.journal_path
        ));
    }
    fs::remove_file(&path)
        .map_err(|error| format!("remove signer reservation {}: {error}", path.display()))?;
    fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync signer reservation release: {error}"))
}

#[cfg(not(unix))]
pub(crate) fn release(_root: &Path, _expected: &SignerReservation) -> Result<(), String> {
    Err("durable signer reservations require Unix ownership/fsync semantics".into())
}

/// Remove a reservation only when it is byte-for-byte the expected owner.
///
/// This is the recovery half of the `journal confirmation fsync -> reservation release`
/// boundary. A crash between those operations leaves the exact reservation behind even though
/// the owning journal already proves canonical finality. Earlier confirmed phases may call this
/// while replaying their evidence: an absent record, or a record for a later/foreign phase, is
/// deliberately left untouched.
#[cfg(unix)]
pub(crate) fn release_if_exact(root: &Path, expected: &SignerReservation) -> Result<bool, String> {
    let path = reservation_path(root, expected)?;
    let Some(actual) = read_existing(&path)? else {
        return Ok(false);
    };
    if actual != *expected {
        return Ok(false);
    }
    fs::remove_file(&path)
        .map_err(|error| format!("remove signer reservation {}: {error}", path.display()))?;
    fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync signer reservation release: {error}"))?;
    Ok(true)
}

#[cfg(not(unix))]
pub(crate) fn release_if_exact(
    _root: &Path,
    _expected: &SignerReservation,
) -> Result<bool, String> {
    Err("durable signer reservations require Unix ownership/fsync semantics".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "intmax-signer-reservation-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn reservation(root: &Path, phase: &str, hash_byte: u8) -> SignerReservation {
        let journal = root.join("publisher.journal.json");
        SignerReservation::new(
            1,
            &format!("0x{}", "11".repeat(20)),
            "public-validity",
            &journal,
            phase,
            &format!("0x{}", format!("{hash_byte:02x}").repeat(32)),
        )
        .unwrap()
    }

    #[test]
    fn exact_owner_recovers_but_foreign_phase_cannot_replace_after_crash() {
        let root = TempDir::new();
        let post = reservation(&root.0, "post", 0x22);
        claim(&root.0, &post).unwrap();
        claim(&root.0, &post).unwrap();

        let attest = reservation(&root.0, "attest", 0x33);
        let error = claim(&root.0, &attest).unwrap_err();
        assert!(error.contains("durably reserved"));

        release(&root.0, &post).unwrap();
        claim(&root.0, &attest).unwrap();
        release(&root.0, &attest).unwrap();
    }

    #[test]
    fn wrong_owner_cannot_release_the_signer_lane() {
        let root = TempDir::new();
        let post = reservation(&root.0, "post", 0x44);
        let sibling = reservation(&root.0, "post", 0x45);
        claim(&root.0, &post).unwrap();
        assert!(
            release(&root.0, &sibling)
                .unwrap_err()
                .contains("refusing to release")
        );
        release(&root.0, &post).unwrap();
    }

    #[test]
    fn crash_after_confirmation_only_releases_the_exact_lingering_owner() {
        let root = TempDir::new();
        let post = reservation(&root.0, "post", 0x54);
        let attest = reservation(&root.0, "attest", 0x55);

        claim(&root.0, &post).unwrap();
        assert!(!release_if_exact(&root.0, &attest).unwrap());
        assert!(claim(&root.0, &attest).unwrap_err().contains("phase post"));
        assert!(release_if_exact(&root.0, &post).unwrap());
        assert!(!release_if_exact(&root.0, &post).unwrap());

        claim(&root.0, &attest).unwrap();
        release(&root.0, &attest).unwrap();
    }
}
