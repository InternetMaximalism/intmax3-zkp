//! Refuse to build against a polygon-plonky2 checkout that is not the commit this repository pins.
//!
//! Cargo.toml's `[patch]` block compiles plonky2 / plonky2_mle from the WORKING TREE of
//! `contracts/lib/polygon-plonky2`. `git pull` and `git checkout` move that submodule's gitlink but
//! not its files, so an updated clone silently builds the new code against the old prover (and a
//! patch that exists only in the local checkout is the defect doc/audit/why-gate8-was-missed.md
//! describes). This check compares the checkout with the pinned commit and stops with the one
//! command that fixes it.
//!
//! The pinned commit is read from `contracts/plonky2-pin.json`, the same manifest Forge checks
//! (contracts/script/Plonky2Pin.sol); `.github/ci/plonky2-pin.sh check` keeps it equal to the
//! gitlink, and this script also compares it with the gitlink staged in the index.
//!
//! RE-RUN TRIGGERS ARE DELIBERATE. A build-script re-run recompiles this whole crate (7m25s on a
//! CI runner), so the script watches only files whose change already means a rebuild or a moved
//! pin: the manifest, the submodule's HEAD, and the sources Cargo compiles from the submodule. It
//! must NOT watch the parent's `.git/index`: `git add`, `git checkout -- <file>` and even
//! `git status` rewrite that file, and each rewrite cost a full recompile (measured 2026-11-27).
//!
//! Without git metadata (the deploy host receives `git archive` trees and verifies submodule
//! content against submodules.sha256 instead) the check is skipped with a warning. While developing
//! a submodule change, set INTMAX3_SKIP_PLONKY2_PIN_CHECK=1.

use std::{path::Path, process::Command};

const SUB: &str = "contracts/lib/polygon-plonky2";
const MANIFEST: &str = "contracts/plonky2-pin.json";
const SKIP: &str = "INTMAX3_SKIP_PLONKY2_PIN_CHECK";
const FIX: &str = "run `git submodule update --init --recursive` (git pull / git checkout do not move submodules)";
/// The `[patch]` path dependencies in Cargo.toml, relative to SUB.
const PATCHED_PACKAGES: &[&str] = &["plonky2", "field", "util", "maybe_rayon", "mle", "starky"];

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    // --no-optional-locks: `git status` must not refresh (rewrite) an index as a side effect.
    let out = Command::new("git")
        .current_dir(dir)
        .arg("--no-optional-locks")
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn watch(path: &Path) {
    // Cargo re-runs the script on EVERY build when a watched path does not exist, so only existing
    // paths are emitted.
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn manifest_commit(root: &Path) -> String {
    let text = std::fs::read_to_string(root.join(MANIFEST)).unwrap_or_else(|e| {
        panic!("\n\n{MANIFEST} is unreadable ({e}): it records the pinned {SUB} commit.\n\n")
    });
    let key = "\"commit\": \"";
    text.find(key)
        .map(|i| &text[i + key.len()..])
        .and_then(|rest| rest.get(..40))
        .filter(|c| c.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("\n\n{MANIFEST} has no 40-hex \"commit\" field.\n\n"))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={SKIP}");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sub = root.join(SUB);

    if std::env::var_os(SKIP).is_some_and(|v| v == "1") {
        println!("cargo:warning={SKIP}=1: NOT checking that {SUB} is the pinned commit");
        return;
    }
    if git(root, &["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true") {
        println!("cargo:warning=no git metadata: cannot check that {SUB} is the pinned commit");
        return;
    }

    // What moves the pin: the manifest (every submodule bump regenerates it, enforced in CI).
    // What moves the checkout: the submodule's HEAD and the sources Cargo compiles from it — a
    // change there already rebuilds the patched crates and therefore this one.
    watch(&root.join(MANIFEST));
    watch(&sub.join("Cargo.toml"));
    for pkg in PATCHED_PACKAGES {
        let dir = sub.join(pkg);
        watch(&dir.join("Cargo.toml"));
        watch(&dir.join("build.rs"));
        watch(&dir.join("src"));
    }

    // A submodule that is not initialised is a plain directory, and git run inside it answers for
    // the PARENT repository: require the submodule to be its own work tree first.
    let sub_top =
        git(&sub, &["rev-parse", "--show-toplevel"]).map(|t| Path::new(&t).canonicalize().ok());
    if sub_top.flatten() != sub.canonicalize().ok() {
        panic!("\n\n{SUB} is not checked out: {FIX}.\n\n");
    }
    if let Some(p) = git(
        &sub,
        &["rev-parse", "--path-format=absolute", "--git-path", "HEAD"],
    ) {
        watch(Path::new(&p));
    }

    let pin = manifest_commit(root);
    let gitlink = git(root, &["ls-files", "-s", "--", SUB]).and_then(|line| {
        let mut f = line.split_whitespace();
        (f.next() == Some("160000"))
            .then(|| f.next().map(str::to_string))
            .flatten()
    });
    match gitlink {
        None => panic!("{SUB} is not a submodule gitlink in the index"),
        Some(g) if g != pin => panic!(
            "\n\nThe staged {SUB} gitlink is {g}, but {MANIFEST} pins {pin}.\n\
             After a submodule bump run `.github/ci/plonky2-pin.sh write` and update \
             contracts/foundry.lock (README, Setup).\n\n"
        ),
        Some(_) => {}
    }

    let head = git(&sub, &["rev-parse", "HEAD"])
        .filter(|h| h.len() == 40)
        .unwrap_or_else(|| panic!("\n\n{SUB} is not checked out: {FIX}.\n\n"));
    if head != pin {
        panic!(
            "\n\n{SUB} is checked out at {head}, but this repository pins {pin}.\n\
             The prover would be built from the wrong plonky2: {FIX}.\n\
             (Developing a submodule change? Set {SKIP}=1.)\n\n"
        );
    }

    let dirty = git(&sub, &["status", "--porcelain", "--untracked-files=no"]).unwrap_or_default();
    if !dirty.is_empty() {
        panic!(
            "\n\n{SUB} has uncommitted changes to tracked files; a clean clone would build \
             different code:\n{dirty}\n\
             Commit them in the submodule (and stage the new gitlink), discard them, or set {SKIP}=1 \
             while developing.\n\n"
        );
    }
}
