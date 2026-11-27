//! Refuse to build against a polygon-plonky2 checkout that is not the commit this repository pins.
//!
//! Cargo.toml's `[patch]` block compiles plonky2 / plonky2_mle from the WORKING TREE of
//! `contracts/lib/polygon-plonky2`. `git pull` and `git checkout` move that submodule's gitlink but
//! not its files, so an updated clone silently builds the new code against the old prover (and a
//! patch that exists only in the local checkout is the defect doc/audit/why-gate8-was-missed.md
//! describes). This check compares the checkout with the gitlink staged in the index and stops with
//! the one command that fixes it.
//!
//! Without git metadata (the deploy host receives `git archive` trees and verifies submodule
//! content against submodules.sha256 instead) the check is skipped with a warning. While developing
//! a submodule change, set INTMAX3_SKIP_PLONKY2_PIN_CHECK=1.

use std::{path::Path, process::Command};

const SUB: &str = "contracts/lib/polygon-plonky2";
const SKIP: &str = "INTMAX3_SKIP_PLONKY2_PIN_CHECK";
const FIX: &str = "run `git submodule update --init --recursive` (git pull / git checkout do not move submodules)";

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
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

    // Re-run when either side can move: the parent's index/HEAD (a pull or checkout changes the
    // gitlink) and the submodule's own HEAD/index (an update or a local edit).
    for (dir, what) in [
        (root, "index"),
        (root, "HEAD"),
        (sub.as_path(), "index"),
        (sub.as_path(), "HEAD"),
    ] {
        if let Some(p) = git(
            dir,
            &["rev-parse", "--path-format=absolute", "--git-path", what],
        ) {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    let pin = git(root, &["ls-files", "-s", "--", SUB])
        .and_then(|line| {
            let mut f = line.split_whitespace();
            (f.next() == Some("160000"))
                .then(|| f.next().map(str::to_string))
                .flatten()
        })
        .unwrap_or_else(|| panic!("{SUB} is not a submodule gitlink in the index"));

    // A submodule that is not initialised is a plain directory, and git run inside it answers for
    // the PARENT repository: require the submodule to be its own work tree first.
    let sub_top =
        git(&sub, &["rev-parse", "--show-toplevel"]).map(|t| Path::new(&t).canonicalize().ok());
    if sub_top.flatten() != sub.canonicalize().ok() {
        panic!("\n\n{SUB} is not checked out: {FIX}.\n\n");
    }
    let head = git(&sub, &["rev-parse", "HEAD"])
        .filter(|h| h.len() == 40)
        .unwrap_or_else(|| panic!("\n\n{SUB} is not checked out: {FIX}.\n\n"));

    if head != pin {
        panic!(
            "\n\n{SUB} is checked out at {head}, but this repository pins {pin}.\n\
             The prover would be built from the wrong plonky2: {FIX}.\n\
             (Developing a submodule change? Stage the new gitlink, or set {SKIP}=1.)\n\n"
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
