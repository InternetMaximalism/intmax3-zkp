//! SECURITY: guards the whole "the on-chain evaluator cannot evaluate this circuit" defect class.
//!
//! `Plonky2GateEvaluator.sol` reverts (fail-closed) on any gate id it does not implement. That
//! revert is soundness-perfect and liveness-fatal: it cannot accept a false statement, but it makes
//! every honest proof carrying such a gate unverifiable on-chain. The Rust side gives no signal —
//! `plonky2_mle::fixture::classify_gate` maps an unrecognised gate to the `255` sentinel, which
//! still produces a well-formed fixture, a valid `gatesDigest` and a PASSING `mle_verify`. The only
//! signal was an on-chain revert on a real submission. That is how `ExponentiationGate` (id 8)
//! shipped on 2026-07-31 (`89cd044`) and survived until 2026-08-09 (`4574348`).
//! See `doc/audit/why-gate8-was-missed.md` §7 (finding L2) and §8 (R3).
//!
//! What this test proves, mechanically:
//!
//! 1. The supported-id set is DERIVED from the Solidity that will run on-chain — the `GATE_* =
//!    <id>` constants that `Plonky2GateEvaluator.evalGateConstraints` actually branches on — not
//!    from a hand-maintained list. A gate ported in Solidity but not recorded in Rust (or the
//!    reverse) is a failure, so `SOLIDITY_SUPPORTED_GATE_IDS` cannot drift into meaninglessness.
//! 2. Every checked-in fixture in `contracts/test/data/` names only gate ids in that set — in
//!    particular never the `255` sentinel.
//! 3. The fail-closed `revert` is still present in the dispatcher. It is a genuine soundness guard
//!    (`doc/tasks/b2-implementation-notes.md:718-719`): removing it would let an unimplemented
//!    constraint go UNCHECKED on-chain, turning this liveness bug into a soundness bug. This test
//!    fails if it is deleted.
//!
//! Deliberately cheap: pure file reads + JSON parsing, no proving, no `#[ignore]`, no
//! `debug_assertions` gate — it must run on every `cargo test`, in debug and release alike.

use std::{collections::BTreeSet, fs, path::PathBuf};

use intmax3_zkp::utils::mle_prover::{
    ExpectedGateRow, SOLIDITY_SUPPORTED_GATE_IDS, UNSUPPORTED_GATE_ID, check_fixture_json_gates,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn evaluator_sol_path() -> PathBuf {
    repo_root().join("contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol")
}

/// Parse `uint8 internal constant GATE_<NAME> = <id>;` declarations.
fn parse_gate_constants(src: &str) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("uint8 internal constant GATE_") else {
            continue;
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_end_matches(';').trim();
        let Ok(id) = value.parse::<u8>() else {
            continue;
        };
        out.push((format!("GATE_{}", name.trim()), id));
    }
    out
}

/// Names appearing in a `gi.gateId == GATE_<NAME>` dispatcher comparison. A constant that is
/// declared but never branched on is NOT supported — the `else` arm would revert on it.
fn parse_dispatched_names(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let needle = "gi.gateId == ";
    let mut rest = src;
    while let Some(pos) = rest.find(needle) {
        rest = &rest[pos + needle.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// The supported set, derived from the deployed Solidity.
fn derive_supported_ids(src: &str) -> BTreeSet<u8> {
    let constants = parse_gate_constants(src);
    let dispatched = parse_dispatched_names(src);

    // SECURITY: shape guards. If the Solidity is refactored so that either pattern stops matching
    // (e.g. a `switch`-style dispatch, or an enum instead of `uint8` constants), the derivation
    // would silently produce an empty/partial set and this whole test would stop meaning anything.
    // Fail loudly instead, with instructions.
    assert!(
        constants.len() >= 10,
        "derivation broke: found only {} `uint8 internal constant GATE_* = <id>;` declarations in \
         {}. The dispatcher's shape changed — update `parse_gate_constants` here AND re-derive \
         `SOLIDITY_SUPPORTED_GATE_IDS` in src/utils/mle_prover.rs.",
        constants.len(),
        evaluator_sol_path().display()
    );
    assert!(
        dispatched.len() >= 10,
        "derivation broke: found only {} `gi.gateId == GATE_*` dispatcher comparisons in {}. The \
         dispatcher's shape changed — update `parse_dispatched_names` here AND re-derive \
         `SOLIDITY_SUPPORTED_GATE_IDS` in src/utils/mle_prover.rs.",
        dispatched.len(),
        evaluator_sol_path().display()
    );

    let mut ids = BTreeSet::new();
    for (name, id) in &constants {
        if dispatched.contains(name) {
            ids.insert(*id);
        }
    }
    for name in &dispatched {
        assert!(
            constants.iter().any(|(n, _)| n == name),
            "dispatcher branches on `{name}`, which has no `uint8 internal constant {name} = <id>;` \
             declaration — the derivation cannot resolve it to a gate id."
        );
    }
    ids
}

#[test]
fn solidity_supported_gate_ids_match_the_deployed_evaluator() {
    let path = evaluator_sol_path();
    let src = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} — is the submodule checked out? {e}",
            path.display()
        )
    });

    let derived = derive_supported_ids(&src);
    let declared: BTreeSet<u8> = SOLIDITY_SUPPORTED_GATE_IDS.iter().copied().collect();

    assert_eq!(
        derived,
        declared,
        "SOLIDITY_SUPPORTED_GATE_IDS in src/utils/mle_prover.rs disagrees with the dispatcher in \
         {}.\n  derived from Solidity: {:?}\n  declared in Rust:      {:?}\nIf a gate was ported \
         on-chain, add its id to the Rust constant. If a gate was REMOVED from the evaluator, \
         remove it from the Rust constant and regenerate every affected fixture — otherwise the \
         guard in `export_mle_json` will keep waving through fixtures that now revert on-chain.",
        path.display(),
        derived,
        declared
    );

    assert!(
        !declared.contains(&UNSUPPORTED_GATE_ID),
        "the `255` unsupported sentinel must never be a supported id"
    );
}

#[test]
fn unsupported_gate_revert_is_still_present() {
    // SECURITY: the fail-closed arm at `Plonky2GateEvaluator.sol:235` is what stops an
    // unimplemented gate's constraints from being silently SKIPPED (i.e. a soundness break). It is
    // deliberately not relaxed; this test fails if it is removed or reworded away.
    let path = evaluator_sol_path();
    let src = fs::read_to_string(&path).expect("cannot read Plonky2GateEvaluator.sol");
    assert!(
        src.contains(r#"revert("unsupported gate with non-zero filter")"#),
        "the fail-closed unsupported-gate revert is missing from {}. It must NOT be relaxed: \
         without it an unimplemented gate's constraints go UNCHECKED on-chain.",
        path.display()
    );
}

#[test]
fn checked_in_fixtures_only_use_on_chain_supported_gates() {
    let data_dir = repo_root().join("contracts/test/data");
    let supported: BTreeSet<u8> = SOLIDITY_SUPPORTED_GATE_IDS.iter().copied().collect();

    let mut checked_files = 0usize;
    let mut checked_rows = 0usize;
    let mut seen_ids: BTreeSet<u8> = BTreeSet::new();

    let mut entries: Vec<PathBuf> = fs::read_dir(&data_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", data_dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();

    for path in entries {
        let raw = fs::read_to_string(&path).unwrap();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue; // not a JSON object we care about
        };
        // Every MLE proof fixture carries a top-level `gates` array; other fixtures (VK params,
        // lifecycle descriptors, token lists) do not, and are skipped.
        let Some(gates) = value.get("gates").and_then(|g| g.as_array()) else {
            continue;
        };
        checked_files += 1;

        for (row, entry) in gates.iter().enumerate() {
            checked_rows += 1;
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("<unnamed>");
            let id_u64 = entry
                .get("gateId")
                .and_then(|g| g.as_u64())
                .unwrap_or_else(|| panic!("{}: gate row {row} has no `gateId`", path.display()));
            let id = u8::try_from(id_u64).unwrap_or_else(|_| {
                panic!(
                    "{}: gate row {row} gateId {id_u64} exceeds u8",
                    path.display()
                )
            });
            seen_ids.insert(id);

            assert_ne!(
                id,
                UNSUPPORTED_GATE_ID,
                "{}: gate row {row} `{name}` carries the {UNSUPPORTED_GATE_ID} \"unsupported\" \
                 sentinel. plonky2_mle's classifier does not recognise this gate, so \
                 Plonky2GateEvaluator.sol will revert on every on-chain verification of this \
                 fixture while every Rust check passes.",
                path.display()
            );
            assert!(
                supported.contains(&id),
                "{}: gate row {row} `{name}` uses gate id {id}, which the deployed \
                 Plonky2GateEvaluator.sol does not implement (supported: {:?}). Every on-chain \
                 verification of this fixture would revert with \"unsupported gate with non-zero \
                 filter\".",
                path.display(),
                supported
            );

            // Same failure shape as an unsupported gate: `mle/src/fixture.rs` narrows these with
            // `as u8` / `as u16`, so a wrap yields a well-formed fixture pointing at the wrong
            // selector column or row. JSON already constrains them to the serialized width; this
            // catches a fixture hand-edited or produced by a differently-shaped generator.
            for field in ["selectorIndex", "groupStart", "groupEnd", "gateRowIndex"] {
                let v = entry
                    .get(field)
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| {
                        panic!("{}: gate row {row} has no `{field}`", path.display())
                    });
                assert!(
                    v <= u8::MAX as u64,
                    "{}: gate row {row} `{field}` = {v} does not fit the fixture's u8",
                    path.display()
                );
            }
            let group_start = entry.get("groupStart").and_then(|v| v.as_u64()).unwrap();
            let group_end = entry.get("groupEnd").and_then(|v| v.as_u64()).unwrap();
            assert!(
                group_start < group_end,
                "{}: gate row {row} has an empty selector group [{group_start}, {group_end})",
                path.display()
            );
            assert_eq!(
                entry.get("gateRowIndex").and_then(|v| v.as_u64()),
                Some(row as u64),
                "{}: gate row {row} declares gateRowIndex {:?} — a truncated or reordered row \
                 index makes the fixture describe a different circuit",
                path.display(),
                entry.get("gateRowIndex")
            );
        }
    }

    // Anti-vacuity: if the glob, the directory layout or the fixture format changes, this test must
    // fail rather than silently pass over zero files.
    assert!(
        checked_files >= 12,
        "expected at least 12 MLE proof fixtures under {} but found {checked_files} — the fixture \
         layout changed and this guard is no longer covering them",
        data_dir.display()
    );
    assert!(checked_rows > 0, "no gate rows were checked");
    eprintln!(
        "[mle_gate_support] {checked_files} fixtures / {checked_rows} gate rows; gate ids present: \
         {seen_ids:?}; supported on-chain: {supported:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  Adversarial coverage OF THE GUARD ITSELF.
//
//  SECURITY: a guard that never fires is indistinguishable from no guard. The tests above only
//  exercise the happy path — every checked-in fixture is currently clean. These drive the exported
//  core of `export_mle_json`'s check with hand-tampered fixtures and require it to REJECT. No
//  proving: a real fixture is loaded and one field is mutated.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Load a real fixture plus the expectation vector implied by its own (untampered) gate rows.
/// The expectation stands in for what `common_data` supplies in production.
fn real_fixture_with_expectations() -> (serde_json::Value, Vec<ExpectedGateRow>) {
    let path = repo_root().join("contracts/test/data/withdrawal_claim_mle.json");
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("fixture unreadable")).unwrap();
    let expected = value["gates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| ExpectedGateRow {
            selector_index: g["selectorIndex"].as_u64().unwrap() as usize,
            group_start: g["groupStart"].as_u64().unwrap() as usize,
            group_end: g["groupEnd"].as_u64().unwrap() as usize,
            gate_row_index: g["gateRowIndex"].as_u64().unwrap() as usize,
            num_constraints: g["numConstraints"].as_u64().unwrap() as usize,
        })
        .collect();
    (value, expected)
}

#[test]
fn guard_accepts_an_untampered_fixture() {
    let (value, expected) = real_fixture_with_expectations();
    check_fixture_json_gates(&value.to_string(), &expected)
        .expect("the guard must accept a real, untampered fixture");
}

#[test]
fn guard_rejects_the_unsupported_gate_sentinel() {
    let (mut value, expected) = real_fixture_with_expectations();
    value["gates"][0]["gateId"] = serde_json::json!(UNSUPPORTED_GATE_ID);
    let err = check_fixture_json_gates(&value.to_string(), &expected)
        .expect_err("gate id 255 MUST be rejected — it is the on-chain revert in disguise");
    assert!(
        err.to_string().contains("255"),
        "error must name the sentinel: {err}"
    );
}

#[test]
fn guard_rejects_an_unimplemented_gate_id() {
    // One past the current dispatcher: the exact shape of the gate-8 incident, where a real gate
    // classified fine in Rust and had no Solidity branch.
    let next_id = SOLIDITY_SUPPORTED_GATE_IDS.iter().max().unwrap() + 1;
    let (mut value, expected) = real_fixture_with_expectations();
    value["gates"][0]["gateId"] = serde_json::json!(next_id);
    check_fixture_json_gates(&value.to_string(), &expected).expect_err(
        "a gate id the deployed Plonky2GateEvaluator.sol has no branch for MUST be rejected",
    );
}

#[test]
fn guard_rejects_truncated_narrow_fields() {
    // The `as u8` wrap: the circuit says row 260, the fixture says 4. Both are well-formed; only a
    // comparison against the pre-truncation value can tell them apart.
    for field in ["selectorIndex", "groupStart", "groupEnd", "gateRowIndex"] {
        let (value, mut expected) = real_fixture_with_expectations();
        let original = value["gates"][0][field].as_u64().unwrap() as usize;
        match field {
            "selectorIndex" => expected[0].selector_index = original + 256,
            "groupStart" => expected[0].group_start = original + 256,
            "groupEnd" => expected[0].group_end = original + 256,
            "gateRowIndex" => expected[0].gate_row_index = original + 256,
            _ => unreachable!(),
        }
        let err = check_fixture_json_gates(&value.to_string(), &expected).unwrap_err();
        assert!(
            err.to_string().contains(field),
            "rejection for a truncated `{field}` must name the field: {err}"
        );
    }
}

#[test]
fn guard_rejects_a_fixture_describing_a_different_circuit() {
    // Same width, wrong value: the fixture points at a selector column the circuit does not use.
    let (value, mut expected) = real_fixture_with_expectations();
    expected[0].selector_index = expected[0].selector_index.wrapping_add(1) % 200;
    check_fixture_json_gates(&value.to_string(), &expected)
        .expect_err("a fixture that disagrees with the circuit's selector layout MUST be rejected");
}

#[test]
fn guard_rejects_a_gate_row_count_mismatch() {
    let (value, expected) = real_fixture_with_expectations();
    check_fixture_json_gates(&value.to_string(), &expected[..expected.len() - 1])
        .expect_err("a gate-row count mismatch MUST be rejected");
}
