//! SECURITY: guards the whole "the on-chain evaluator cannot evaluate this circuit" defect class.
//!
//! `Plonky2GateEvaluator.sol` reverts (fail-closed) on any gate id it does not implement. That
//! revert is soundness-perfect and liveness-fatal: it cannot accept a false statement, but it makes
//! every honest proof carrying such a gate unverifiable on-chain. The Rust side used to give no
//! signal — `plonky2_mle::fixture::classify_gate` mapped an unrecognised gate to the `255`
//! sentinel, which still produces a well-formed fixture, a valid `gatesDigest` and a PASSING
//! `mle_verify`. The only signal was an on-chain revert on a real submission. That is how
//! `ExponentiationGate` (id 8) shipped on 2026-07-31 (`89cd044`) and survived until 2026-08-09
//! (`4574348`). See `doc/audit/why-gate8-was-missed.md` §7 (finding L2) and §8 (R3).
//!
//! Since 2026-08-30 (audit M-10) `classify_gate` returns an `Err` naming the gate instead of the
//! sentinel, and derives gate PARAMETERS structurally rather than scraping them out of a `Debug`
//! string. The sentinel checks below are kept as defence in depth: a hand-edited fixture, or a
//! `plonky2_mle` reverted by a plain `git submodule update`, can still produce one.
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
            gate_id: g["gateId"].as_u64().unwrap() as u8,
            selector_index: g["selectorIndex"].as_u64().unwrap() as usize,
            group_start: g["groupStart"].as_u64().unwrap() as usize,
            group_end: g["groupEnd"].as_u64().unwrap() as usize,
            gate_row_index: g["gateRowIndex"].as_u64().unwrap() as usize,
            num_constraints: g["numConstraints"].as_u64().unwrap() as usize,
            num_or_consts: g["numOrConsts"].as_u64().unwrap() as u16,
            param2: g["param2"].as_u64().unwrap() as u16,
            param3: g["param3"].as_u64().unwrap() as u16,
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

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  Audit finding M-10: gate PARAMETERS.
//
//  `gateId` picks the branch in `Plonky2GateEvaluator`; `numOrConsts` / `param2` / `param3` decide
//  how many constraints that branch checks and where its wires are (`num_ops`, `num_power_bits`,
//  the `BaseSumGate` base, `num_copies`, the interpolation `degree`, …). Until 2026-08-30 they were
//  scraped out of `format!("{:?}")` with `.unwrap_or(0)` and a `.max(2)` "default base", and they
//  were NOT covered by the export guard. A wrong value there is strictly worse than an unsupported
//  gate id: it produces a well-formed fixture, a valid `gatesDigest`, a passing Rust `mle_verify`
//  AND, often, a non-reverting on-chain verification that simply checks the wrong constraints.
//
//  The exporter now derives them STRUCTURALLY (downcast through `AnyGate::as_any`, read the gate's
//  own typed fields) and hard-errors on anything it cannot resolve. These tests pin all three
//  halves: the hard errors fire, the widened guard compares the parameters, and every checked-in
//  fixture round-trips against an INDEPENDENT derivation from the recorded `gate.id()` string.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

use std::sync::Arc;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    gates::{
        base_sum::BaseSumGate, exponentiation::ExponentiationGate, gate::GateRef,
        lookup_table::LookupTableGate, random_access::RandomAccessGate,
    },
    plonk::circuit_data::CircuitConfig,
};
use plonky2_mle::fixture::{
    GateParams, SUPPORTED_BASE_SUM_BASES, classify_gate, parse_gate_params_from_id,
};

type F = GoldilocksField;
const D: usize = 2;

/// R3 — the item `why-gate8-was-missed.md` §8 calls the highest value-to-effort in the document:
/// a gate the classifier does not know must be a HARD ERROR at export, not a `255` row.
///
/// `LookupTableGate` is a real plonky2 gate with no `Plonky2GateEvaluator.sol` branch — i.e. it
/// stands in for exactly what `ExponentiationGate` was on 2026-07-31.
#[test]
fn an_unclassified_gate_is_a_hard_error_not_the_255_sentinel() {
    let config = CircuitConfig::standard_recursion_config();
    let lut = Arc::new(vec![(0u16, 1u16), (1u16, 2u16)]);
    let gate = GateRef::<F, D>::new(LookupTableGate::new_from_table(&config, lut, 0));

    let msg = classify_gate::<F, D>(&gate)
        .expect_err("an unclassified gate MUST NOT be silently classified")
        .to_string();
    assert!(
        msg.contains("LookupTableGate"),
        "the error must name the offending gate: {msg}"
    );
    assert!(
        msg.contains("255"),
        "the error must explain what the old sentinel cost: {msg}"
    );
}

/// The `.max(2)` "default base" path. `BaseSumGate<B>`'s base is a const generic, so a base the
/// classifier cannot resolve must be an error naming the base list — never a silent 2, which would
/// make `_evalBaseSum` check a base-2 decomposition of a base-B value.
#[test]
fn an_unresolvable_base_sum_base_is_a_hard_error_not_a_default_of_2() {
    // 9 is deliberately outside SUPPORTED_BASE_SUM_BASES.
    assert!(!SUPPORTED_BASE_SUM_BASES.contains(&9));
    let gate = GateRef::<F, D>::new(BaseSumGate::<9>::new(5));
    let msg = classify_gate::<F, D>(&gate)
        .expect_err("an unresolvable BaseSumGate base MUST NOT default to 2")
        .to_string();
    assert!(
        msg.contains("BaseSumGate") && msg.contains("SUPPORTED_BASE_SUM_BASES"),
        "the error must name the gate and the fix: {msg}"
    );
}

/// The structural classifier reads the gate's own typed fields, so it is correct regardless of how
/// plonky2 renders `Debug`. Two independent derivations (typed data vs. `gate.id()`) must agree.
#[test]
fn parameters_are_derived_from_the_gates_typed_data() {
    let config = CircuitConfig::standard_recursion_config();
    let gates: Vec<(GateRef<F, D>, Option<GateParams>)> = vec![
        (
            GateRef::new(BaseSumGate::<6>::new(24)),
            Some(GateParams {
                gate_id: 9,
                num_or_consts: 24,
                param2: 6,
                param3: 0,
            }),
        ),
        (
            GateRef::new(ExponentiationGate::<F, D>::new(66)),
            Some(GateParams {
                gate_id: 8,
                num_or_consts: 66,
                param2: 0,
                param3: 0,
            }),
        ),
        // Config-derived, so pinned only against the independent derivation.
        (
            GateRef::new(RandomAccessGate::<F, D>::new_from_config(&config, 4)),
            None,
        ),
    ];
    for (gate, want) in gates {
        let id = gate.0.id();
        let structural = classify_gate::<F, D>(&gate).unwrap_or_else(|e| panic!("{e}"));
        if let Some(want) = want {
            assert_eq!(structural, want, "structural classification of `{id}`");
        }
        let from_id = parse_gate_params_from_id(&id).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            structural, from_id,
            "the two independent derivations disagree for `{id}`"
        );
    }
    // `BaseSumGate<6>` is the case the old `.max(2)` got WRONG whenever the id separator drifted;
    // structurally, the base comes from the type, so it cannot.
    assert_eq!(
        classify_gate::<F, D>(&GateRef::<F, D>::new(BaseSumGate::<6>::new(24)))
            .unwrap()
            .param2,
        6
    );
}

/// The strict `gate.id()` parser must REFUSE every input the pre-2026-08-30 scraper answered with a
/// guess. Each string below produced a well-formed, silently WRONG fixture row before this fix
/// (values verified against a verbatim copy of the old `classify_gate`):
///
/// | id string                                      | pre-fix result   | why it is wrong       |
/// |------------------------------------------------|------------------|-----------------------|
/// | `ArithmeticGate { ops: 20 }`                   | `(3, 0, 0, 0)`   | 0 of 20 ops evaluated |
/// | `BaseSumGate { num_limbs: 24 } + B: 6`         | `(9, 24, 2, 0)`  | claims base 2 for B=6 |
/// | `RandomAccessGate { bits: 4, copies: 4, … }`   | `(12, 4, 0, 2)`  | 0 copies evaluated    |
/// | `CosetInterpolationGate { subgroup_bits: 4, … }`| `(13, 4, 0, 0)` | degree 0              |
/// | `ExponentiationGateV2 { num_power_bits: 66 }`  | `(8, 66, 0, 0)`  | a DIFFERENT gate      |
/// | `LookupGate { … }`                             | `(255, 0, 0, 0)` | the gate-8 sentinel   |
#[test]
fn the_strict_parser_refuses_every_pre_fix_guess() {
    let must_fail = [
        ("ArithmeticGate { ops: 20 }", "num_ops"),
        ("BaseSumGate { num_limbs: 24 } + B: 6", "Base"),
        (
            "RandomAccessGate { bits: 4, copies: 4, num_extra_constants: 2 }",
            "num_copies",
        ),
        (
            "CosetInterpolationGate { subgroup_bits: 4, barycentric_weights: [1] }",
            "degree",
        ),
        ("ExponentiationGateV2 { num_power_bits: 66 }", "classifies"),
        ("LookupGate { num_slots: 12 }", "classifies"),
        ("ConstantGate { }", "num_consts"),
    ];
    for (id, needle) in must_fail {
        let msg = parse_gate_params_from_id(id)
            .expect_err("must not be classified by guesswork")
            .to_string();
        assert!(
            msg.contains(needle),
            "the rejection of `{id}` must mention `{needle}`: {msg}"
        );
    }

    // Anti-vacuity: the parser is strict, not broken — today's real id strings still parse.
    assert_eq!(
        parse_gate_params_from_id("BaseSumGate { num_limbs: 63 } + Base: 2").unwrap(),
        GateParams {
            gate_id: 9,
            num_or_consts: 63,
            param2: 2,
            param3: 0
        }
    );
    assert_eq!(
        parse_gate_params_from_id(
            "RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: \
             PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"
        )
        .unwrap(),
        GateParams {
            gate_id: 12,
            num_or_consts: 4,
            param2: 4,
            param3: 2
        },
        "`bits:` must resolve to the RandomAccessGate field, not a `subgroup_bits:` near-miss"
    );
}

/// R3's "cheap Rust test that reads every `contracts/test/data/*_mle.json`", extended to the
/// parameters: every gate id is on-chain supported AND every parameter round-trips against an
/// independent re-derivation from the `gate.id()` string the fixture itself recorded.
#[test]
fn every_checked_in_fixture_parameter_round_trips() {
    let data_dir = repo_root().join("contracts/test/data");
    let supported: BTreeSet<u8> = SOLIDITY_SUPPORTED_GATE_IDS.iter().copied().collect();

    let mut entries: Vec<PathBuf> = fs::read_dir(&data_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", data_dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with("_mle.json"))
        .collect();
    entries.sort();

    let mut checked_files = 0usize;
    let mut checked_rows = 0usize;

    for path in entries {
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let Some(gates) = value.get("gates").and_then(|g| g.as_array()) else {
            continue;
        };
        checked_files += 1;

        for (row, entry) in gates.iter().enumerate() {
            checked_rows += 1;
            let name = entry["name"]
                .as_str()
                .unwrap_or_else(|| panic!("{}: gate row {row} has no `name`", path.display()));
            let serialized = GateParams {
                gate_id: entry["gateId"].as_u64().unwrap() as u8,
                num_or_consts: entry["numOrConsts"].as_u64().unwrap() as u16,
                param2: entry["param2"].as_u64().unwrap() as u16,
                param3: entry["param3"].as_u64().unwrap() as u16,
            };

            assert!(
                supported.contains(&serialized.gate_id),
                "{}: gate row {row} `{name}` uses unsupported gate id {}",
                path.display(),
                serialized.gate_id
            );

            let rederived = parse_gate_params_from_id(name).unwrap_or_else(|e| {
                panic!(
                    "{}: gate row {row} cannot be re-derived from its own recorded name — {e}",
                    path.display()
                )
            });
            assert_eq!(
                rederived,
                serialized,
                "{}: gate row {row} `{name}` — the exported parameters disagree with the gate the \
                 fixture says it is. numOrConsts/param2/param3 drive Plonky2GateEvaluator's \
                 constraint count and wire layout, so this fixture would have the on-chain \
                 verifier check constraints that are not the circuit's.",
                path.display()
            );
        }
    }

    assert!(
        checked_files >= 12,
        "expected at least 12 `*_mle.json` fixtures under {} but found {checked_files}",
        data_dir.display()
    );
    assert!(checked_rows > 0, "no gate rows were checked");
    eprintln!(
        "[mle_gate_support] parameter round-trip: {checked_files} fixtures / {checked_rows} rows"
    );
}

/// Mutation check for the WIDENED export guard: each of the three parameters, tampered one at a
/// time, must be rejected. Before 2026-08-30 every one of these passed — the guard read only
/// `selectorIndex`, `groupStart`, `groupEnd`, `gateRowIndex` and `numConstraints`.
#[test]
fn guard_rejects_a_tampered_gate_parameter() {
    for field in ["numOrConsts", "param2", "param3"] {
        let (mut value, expected) = real_fixture_with_expectations();
        // Pick a row where the field is meaningful, so the mutation is not a no-op.
        let row = value["gates"]
            .as_array()
            .unwrap()
            .iter()
            .position(|g| g[field].as_u64().unwrap_or(0) != 0)
            .unwrap_or(0);
        let original = value["gates"][row][field].as_u64().unwrap();
        value["gates"][row][field] = serde_json::json!(original + 1);

        let msg = check_fixture_json_gates(&value.to_string(), &expected)
            .expect_err(&format!(
                "a tampered `{field}` on gate row {row} MUST be rejected — it changes what the \
                 on-chain evaluator checks while leaving the fixture well-formed"
            ))
            .to_string();
        assert!(
            msg.contains(field),
            "the rejection must name `{field}`: {msg}"
        );
    }
}

/// A `gateId` swapped for another SUPPORTED id: no sentinel, no unsupported id, nothing else in
/// the pipeline notices — only an equality check against the circuit's own gate catches it.
#[test]
fn guard_rejects_a_gate_id_swapped_for_another_supported_one() {
    let (mut value, expected) = real_fixture_with_expectations();
    let original = value["gates"][0]["gateId"].as_u64().unwrap() as u8;
    let other = *SOLIDITY_SUPPORTED_GATE_IDS
        .iter()
        .find(|id| **id != original)
        .unwrap();
    value["gates"][0]["gateId"] = serde_json::json!(other);
    let msg = check_fixture_json_gates(&value.to_string(), &expected)
        .expect_err("a swapped-but-supported gateId MUST be rejected")
        .to_string();
    assert!(
        msg.contains("gateId"),
        "the rejection must name the field: {msg}"
    );
}
