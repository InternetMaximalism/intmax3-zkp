//! MLE-based Plonky2 prover — uses plonky2_mle for multilinear PCS.
//!
//! Replaces the previous WHIR pipeline with the plonky2_mle crate which
//! provides sumcheck + multilinear polynomial commitment based proving.

use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{ErrorKind, Read as _, Write as _},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Result, bail, ensure};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::CircuitData,
        config::{GenericConfig, Hasher},
    },
    util::timing::TimingTree,
};
use plonky2_mle::{
    compact_v2::{decode_compact_v2, encode_compact_v2},
    fixture_v2::{
        MleProofV2Fixture, MleVerifierV2ConfigFixture, MleVerifierV2Fixture,
        SOLIDITY_MLE_PROOF_ENCODING_V2, SOLIDITY_MLE_VERIFICATION_CONFIG_ENCODING_V2,
        solidity_abi_encode_mle_proof_v2, solidity_abi_encode_verification_config_v2,
        try_export_mle_v2_config_fixture, try_export_mle_v2_fixture,
    },
    proof_v2::{MleProofV2, MleVerificationKeyV2},
    protocol_schema_v2::{COMPACT_MAGIC_V2, MAX_COMPACT_PROOF_BYTES_V2},
    prover_v2::{mle_prove_v2, mle_setup_v2},
    verifier_v2::mle_verify_v2,
};

/// Result of MLE V2 implementation proving under the current wire-v3 protocol, including timing.
pub struct MleProveResultV2<F: plonky2::field::types::Field> {
    pub proof: MleProofV2<F>,
    pub prove_time: Duration,
}

/// Compute the MLE V2 implementation's current wire-v3 verification key for a circuit.
/// This must be done once during setup and is deterministic.
pub fn setup_mle_vk_v2<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
) -> MleVerificationKeyV2<F>
where
    C::Hasher: Hasher<F>,
{
    mle_setup_v2::<F, C, D>(&circuit_data.prover_only, &circuit_data.common)
}

/// Generate a current wire-v3 proof through the MLE V2 implementation API.
pub fn prove_with_mle_v2<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    inputs: PartialWitness<F>,
) -> Result<MleProveResultV2<F>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    let start = Instant::now();
    let mut timing = TimingTree::new("mle_prove_v2", log::Level::Debug);

    let proof = mle_prove_v2::<F, C, D>(
        &circuit_data.prover_only,
        &circuit_data.common,
        inputs,
        &mut timing,
    )?;

    let prove_time = start.elapsed();
    Ok(MleProveResultV2 { proof, prove_time })
}

/// Verify a current wire-v3 MLE V2 proof against the circuit data and verification key.
pub fn verify_mle_proof_v2<F: RichField + Extendable<D>, const D: usize>(
    circuit_data: &CircuitData<F, impl GenericConfig<D, F = F>, D>,
    vk: &MleVerificationKeyV2<F>,
    proof: &MleProofV2<F>,
) -> Result<()> {
    mle_verify_v2::<F, D>(&circuit_data.common, vk, proof)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  On-chain evaluability guard (systemic, NOT specific to any one gate)
//
//  SECURITY: this is the fail-fast counterpart of the fail-CLOSED revert at
//  `Plonky2GateEvaluator.sol:235` ("unsupported gate with non-zero filter"). That revert is
//  soundness-perfect (it never silently skips a constraint) and liveness-fatal (every honest proof
//  reverts). Without a guard here, a circuit change that pulls in a gate the Solidity evaluator
//  lacks produces a WELL-FORMED fixture, a valid `gatesDigest`, a PASSING Rust
//  `mle_verify`, and an on-chain revert — with no signal until a real submission on a real chain.
//  That is exactly how `ExponentiationGate` (gate id 8) shipped on 2026-07-31 (`89cd044`) and
//  survived until 2026-08-09 (`4574348`). See `doc/audit/why-gate8-was-missed.md` §7 (L2) and §8
//  (R3). This check converts that class from "found by incident on a real chain" to "found by the
//  fixture generator that is about to write the file".
//
//  WHY THIS STILL LIVES HERE, NOW THAT THE SUBMODULE ALSO FAILS CLOSED
//  As of 2026-08-30 (audit M-10) `mle/src/fixture.rs` no longer emits the `255` sentinel or a
//  guessed parameter: `classify_gate` derives every gate parameter structurally and returns an
//  `Err` naming the gate for anything it cannot resolve. This guard is NOT redundant with it:
//    (a) the submodule fix is not carried by the Cargo/Foundry pin — a plain `git submodule
//        update` silently reverts it, which is the very failure mode being guarded against;
//    (b) `SOLIDITY_SUPPORTED_GATE_IDS` is a property of THIS repo's deployed evaluator (locally
//        patched to add id 8), not of upstream's, so only this side can decide that a gate
//        upstream classifies happily has no on-chain branch — that is literally the gate-8 case;
//    (c) it compares the fixture's BYTES against values recomputed from `common_data`, so it also
//        catches a fixture that was hand-edited, reordered, or produced by a different generator.
//  This block remains the audit guard for checked-in historical v1 fixtures and the explicitly
//  feature-gated deprecated MSU generator. Production v2 export uses `check_v2_gate_rows` below
//  against the Ext3 evaluator instead.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Gate ids that the deployed `Plonky2GateEvaluator.sol` dispatcher can actually evaluate.
///
/// SECURITY: this list is NOT free-standing documentation — `tests/mle_gate_support.rs` DERIVES the
/// set from `contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol` (the
/// `GATE_* = <id>` constants that the `gi.gateId == GATE_*` dispatcher actually branches on) and
/// fails if it disagrees with this constant. Editing this list without editing the Solidity — or
/// vice versa — is a test failure, so it cannot silently go stale.
pub const SOLIDITY_SUPPORTED_GATE_IDS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Sentinel that `plonky2_mle::fixture::classify_gate` USED to write for any gate it did not
/// recognise (it now returns an `Err` naming the gate instead — audit M-10). It is a well-formed
/// `u8` that hashes into a valid `gatesDigest`, so in a fixture produced before that fix — or by a
/// reverted submodule — it is invisible to every check except this one and the on-chain revert.
pub const UNSUPPORTED_GATE_ID: u8 = 255;

/// SECURITY: reject a fixture the deployed on-chain evaluator provably cannot verify.
///
/// Two independent failure shapes are checked, both of which yield a well-formed-but-unusable
/// fixture:
///
/// 1. **Unsupported gate.** The Solidity dispatcher reverts on any id outside
///    [`SOLIDITY_SUPPORTED_GATE_IDS`] whose filter is non-zero. Historically an unrecognised gate
///    also reached here as the [`UNSUPPORTED_GATE_ID`] (255) sentinel; the exporter now refuses to
///    write one at all, so the sentinel check is retained only for fixtures produced by a hand-edit
///    or by an older / reverted `plonky2_mle`.
/// 2. **Silent `as u8` truncation.** `fixture.rs:531-534` narrows `selector_index`, `group_start`,
///    `group_end` and `gate_row_index` with `as u8` and `num_constraints` with `as u16`. A wrap
///    produces a fixture that names the WRONG selector column / row — the proof would then be
///    checked against constraints that are not the circuit's. This recomputes each field from
///    `common_data` (the pre-truncation source of truth), bounds-checks it, and compares it against
///    what was actually serialized, so both an out-of-range value and any future divergence between
///    the two are caught.
/// 3. **A wrong gate PARAMETER** (audit finding M-10). `gateId` alone does not determine what the
///    on-chain evaluator checks: `numOrConsts` / `param2` / `param3` carry `num_ops`,
///    `num_power_bits`, the `BaseSumGate` base, `num_copies`, the interpolation `degree` … and they
///    drive `Plonky2GateEvaluator`'s per-gate constraint count and wire layout. Until 2026-08-30
///    they were scraped from a `Debug` string with a `.unwrap_or(0)` fallback and were NOT covered
///    here — a wrong value still produced a well-formed fixture, a valid `gatesDigest` and a
///    passing Rust `mle_verify`. They are now re-derived STRUCTURALLY from the circuit's own gate
///    objects via `plonky2_mle::fixture::classify_gate` and compared field-for-field, exactly like
///    the five layout fields.
pub fn check_on_chain_evaluable<F: RichField + Extendable<D>, const D: usize>(
    common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    json: &str,
) -> Result<()> {
    let si = &common_data.selectors_info;
    let expected: Vec<ExpectedGateRow> = (0..common_data.gates.len())
        .map(|row| {
            let sel_idx = si.selector_indices[row];
            let group = &si.groups[sel_idx];
            // SECURITY: an independent re-derivation, NOT a re-read of the fixture. If a gate
            // cannot be classified this fails here rather than emitting a `255` row.
            let params = plonky2_mle::fixture::classify_gate::<F, D>(&common_data.gates[row])
                .map_err(|e| {
                    anyhow::anyhow!(
                        "gate row {row}: the circuit uses a gate whose on-chain parameters cannot \
                         be established — {e}"
                    )
                })?;
            Ok(ExpectedGateRow {
                gate_id: params.gate_id,
                selector_index: sel_idx,
                group_start: group.start,
                group_end: group.end,
                gate_row_index: row,
                num_constraints: common_data.gates[row].0.num_constraints(),
                num_or_consts: params.num_or_consts,
                param2: params.param2,
                param3: params.param3,
            })
        })
        .collect::<Result<_>>()?;
    check_fixture_json_gates(json, &expected)
}

/// Circuit-derived, PRE-truncation expectation for one serialized gate row. These are the values
/// `mle/src/fixture.rs` narrows with `as u8` / `as u16`.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedGateRow {
    /// Structurally derived gate id — compared for equality, not merely membership in
    /// [`SOLIDITY_SUPPORTED_GATE_IDS`].
    pub gate_id: u8,
    pub selector_index: usize,
    pub group_start: usize,
    pub group_end: usize,
    pub gate_row_index: usize,
    pub num_constraints: usize,
    /// `numOrConsts` / `param2` / `param3`: the gate's on-chain evaluation parameters. Audit
    /// finding M-10 — these were outside this guard while driving on-chain evaluation.
    pub num_or_consts: u16,
    pub param2: u16,
    pub param3: u16,
}

/// Pure core of [`check_on_chain_evaluable`], split out so the guard itself can be tested against
/// hand-tampered fixtures without generating a proof (`tests/mle_gate_support.rs`).
pub fn check_fixture_json_gates(json: &str, expected: &[ExpectedGateRow]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| anyhow::anyhow!("fixture is not valid JSON: {e}"))?;
    let gates = value
        .get("gates")
        .and_then(|g| g.as_array())
        .ok_or_else(|| anyhow::anyhow!("fixture has no `gates` array — fixture format changed"))?;

    ensure!(
        gates.len() == expected.len(),
        "fixture serialized {} gate rows but the circuit has {} — fixture format changed",
        gates.len(),
        expected.len()
    );

    for (row, entry) in gates.iter().enumerate() {
        let name = entry
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let gate_id = entry
            .get("gateId")
            .and_then(|g| g.as_u64())
            .ok_or_else(|| anyhow::anyhow!("gate row {row} ({name}) has no `gateId`"))?;

        if gate_id == u64::from(UNSUPPORTED_GATE_ID) {
            bail!(
                "gate row {row}: `{name}` is NOT recognised by plonky2_mle's gate classifier \
                 (emitted the {UNSUPPORTED_GATE_ID} sentinel). Plonky2GateEvaluator.sol would \
                 revert with \"unsupported gate with non-zero filter\" on-chain while every Rust \
                 check passes. Port the gate to Plonky2GateEvaluator.sol (and classify it in \
                 mle/src/fixture.rs) or change the circuit so it is not emitted — do NOT relax the \
                 on-chain revert."
            );
        }
        let gate_id_u8 = u8::try_from(gate_id)
            .map_err(|_| anyhow::anyhow!("gate row {row} ({name}): gateId {gate_id} exceeds u8"))?;
        if !SOLIDITY_SUPPORTED_GATE_IDS.contains(&gate_id_u8) {
            bail!(
                "gate row {row}: `{name}` classified as gate id {gate_id_u8}, which the deployed \
                 Plonky2GateEvaluator.sol does not implement (supported: \
                 {SOLIDITY_SUPPORTED_GATE_IDS:?}). Every on-chain verification of this proof would \
                 revert."
            );
        }

        // Pre-truncation values, recomputed from the circuit itself.
        let e = &expected[row];

        ensure!(
            gate_id_u8 == e.gate_id,
            "gate row {row} (`{name}`): fixture serialized gateId = {gate_id_u8} but the circuit's \
             own gate classifies as {} — the fixture does not describe this circuit. Both ids are \
             on-chain-supported, so nothing downstream would notice: the evaluator would simply \
             check the WRONG gate's constraints.",
            e.gate_id
        );

        // The Solidity CosetInterpolation evaluator has a deliberately finite constants table:
        // subgroup_bits must be one of 1..=5, and its wire walk assumes 2 <= degree <= 2^bits.
        // Structural classification proves that these values came from the Rust gate, but that is
        // not enough to prove the deployed evaluator has constants for them. Without this envelope
        // check a perfectly well-formed fixture (and gatesDigest) can pass every Rust check and
        // then deterministically revert on-chain when the constants table is touched.
        if gate_id_u8 == 13 {
            let subgroup_bits = e.num_or_consts;
            let degree = e.param2;
            ensure!(
                (1..=5).contains(&subgroup_bits),
                "gate row {row} (`{name}`): CosetInterpolation subgroup_bits = {subgroup_bits} is \
                 outside the deployed Solidity constants-table envelope 1..=5"
            );
            ensure!(
                degree >= 2,
                "gate row {row} (`{name}`): CosetInterpolation degree = {degree} is below the \
                 deployed evaluator minimum 2"
            );
            let subgroup_size = 1u32 << u32::from(subgroup_bits);
            ensure!(
                u32::from(degree) <= subgroup_size,
                "gate row {row} (`{name}`): CosetInterpolation degree = {degree} exceeds the \
                 subgroup size 2^{subgroup_bits} = {subgroup_size} supported by the deployed \
                 evaluator"
            );
        }

        // SECURITY (M-10): the on-chain evaluation parameters. `gateId` selects the branch;
        // these select how many constraints that branch checks and where its wires are. A wrong
        // value here is invisible to `gatesDigest`, to `mle_verify`, and — unlike an unsupported
        // gate id — often invisible on-chain too: it just evaluates the wrong thing.
        for (field, wide) in [
            ("numOrConsts", e.num_or_consts),
            ("param2", e.param2),
            ("param3", e.param3),
        ] {
            let serialized = entry
                .get(field)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("gate row {row} ({name}) has no `{field}`"))?;
            ensure!(
                serialized == u64::from(wide),
                "gate row {row} (`{name}`): fixture serialized {field} = {serialized} but the \
                 gate itself says {wide}. This parameter drives Plonky2GateEvaluator's constraint \
                 count / wire layout for this gate, so the on-chain verifier would evaluate \
                 constraints that are not the circuit's — with a valid `gatesDigest` and a \
                 passing Rust `mle_verify`."
            );
        }

        for (field, wide, max) in [
            ("selectorIndex", e.selector_index, u8::MAX as usize),
            ("groupStart", e.group_start, u8::MAX as usize),
            ("groupEnd", e.group_end, u8::MAX as usize),
            ("gateRowIndex", e.gate_row_index, u8::MAX as usize),
            ("numConstraints", e.num_constraints, u16::MAX as usize),
        ] {
            ensure!(
                wide <= max,
                "gate row {row} (`{name}`): {field} = {wide} does not fit the fixture's narrow \
                 integer (max {max}). `mle/src/fixture.rs` would silently wrap it, producing a \
                 well-formed fixture that names the WRONG selector column or row."
            );
            let serialized = entry
                .get(field)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("gate row {row} ({name}) has no `{field}`"))?;
            ensure!(
                serialized == wide as u64,
                "gate row {row} (`{name}`): fixture serialized {field} = {serialized} but the \
                 circuit says {wide} — the fixture does not describe this circuit."
            );
        }
    }

    Ok(())
}

/// Fail closed when a v2 artifact names a gate the deployed Ext3 evaluator does not implement.
///
/// The submodule exporter already derives these rows from `CommonCircuitData` and checks their
/// exact widths. This repository-level check independently pins that derived gate-id set to the
/// evaluator deployed by this repository, including the finite CosetInterpolation envelope.
fn check_v2_gate_rows(fixture: &MleVerifierV2ConfigFixture) -> Result<()> {
    for (row, gate) in fixture.verification_config.gates.iter().enumerate() {
        ensure!(
            SOLIDITY_SUPPORTED_GATE_IDS.contains(&gate.gate_id),
            "v2 gate row {row} has gate id {}, which Plonky2GateEvaluatorExt3.sol does not implement",
            gate.gate_id
        );
        if gate.gate_id == 13 {
            let subgroup_bits = gate.num_or_consts;
            let degree = gate.param2;
            ensure!(
                (1..=5).contains(&subgroup_bits),
                "v2 gate row {row}: CosetInterpolation subgroup_bits = {subgroup_bits} is outside 1..=5"
            );
            ensure!(
                degree >= 2,
                "v2 gate row {row}: CosetInterpolation degree = {degree} is below 2"
            );
            ensure!(
                u32::from(degree) <= (1u32 << u32::from(subgroup_bits)),
                "v2 gate row {row}: CosetInterpolation degree = {degree} exceeds its subgroup"
            );
        }
    }
    Ok(())
}

/// Export the proof-free, circuit-derived wire-v3 deployment configuration as canonical JSON.
pub fn export_mle_v2_config_json<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    circuit_data: &CircuitData<F, C, D>,
) -> Result<String>
where
    C::Hasher: Hasher<F>,
{
    let fixture = try_export_mle_v2_config_fixture(circuit_data)
        .map_err(|e| anyhow::anyhow!("MLE v2 config export refused the circuit: {e}"))?;
    check_v2_gate_rows(&fixture)?;
    fixture
        .to_canonical_json()
        .map_err(|e| anyhow::anyhow!("MLE v2 config canonical JSON failed: {e}"))
}

/// Stable generator mode for emitting deployment configuration without constructing a witness or
/// producing a proof. Every production fixture binary that has an MLE output accepts this flag.
pub const MLE_V2_CONFIG_ONLY_FLAG: &str = "--mle-config-only";

/// Explicit one-release switch for replacing a circuit-identical retired wire-v2
/// deployment artifact with its wire-v3 successor. Ordinary generation
/// remains create-once/compare-only.
pub const MLE_V3_CONFIG_CUTOVER_ENV: &str = "MLE_ALLOW_WIRE_V3_CONFIG_CUTOVER";

/// Whether the current process was invoked in proof-free MLE-v2 configuration mode.
pub fn mle_v2_config_only_requested() -> bool {
    std::env::args_os().any(|arg| arg == MLE_V2_CONFIG_ONLY_FLAG)
}

/// Create a canonical config artifact, or fail if an existing artifact differs.
///
/// A deployment config is an address/VK commitment, not a disposable generated file. Silently
/// overwriting it after a verifier has been deployed would sever the deployment from subsequent
/// proofs, so generators use this helper as a create-once/compare-later boundary.
pub fn persist_or_validate_mle_v2_config_json(
    path: impl AsRef<Path>,
    generated_json: &str,
) -> Result<()> {
    let allow_v3_cutover =
        std::env::var_os(MLE_V3_CONFIG_CUTOVER_ENV).is_some_and(|value| value == OsStr::new("1"));
    persist_or_validate_mle_v2_config_json_inner(path.as_ref(), generated_json, allow_v3_cutover)
}

fn persist_or_validate_mle_v2_config_json_inner(
    path: &Path,
    generated_json: &str,
    allow_v3_cutover: bool,
) -> Result<()> {
    let generated =
        MleVerifierV2ConfigFixture::from_canonical_json(generated_json).map_err(|e| {
            anyhow::anyhow!("generated MLE v2 config is not strict canonical JSON: {e}")
        })?;
    match fs::read_to_string(path) {
        Ok(existing_json) => {
            match MleVerifierV2ConfigFixture::from_canonical_json(&existing_json) {
                Ok(existing) => ensure!(
                    existing == generated && existing_json == generated_json,
                    "existing MLE v2 config artifact {} differs from the circuit-derived canonical config",
                    path.display()
                ),
                Err(_parse_error) if allow_v3_cutover => {
                    validate_protocol_v2_config_cutover(path, &existing_json, generated_json)
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "refuse MLE wire-v3 config cutover for {}: {error}",
                                path.display()
                            )
                        })?;
                    atomic_replace_config(path, generated_json)?;
                }
                Err(parse_error) => {
                    bail!(
                        "existing MLE v2 config artifact {} is not the strict current config: {parse_error}; set {MLE_V3_CONFIG_CUTOVER_ENV}=1 only for the reviewed retired wire-v2 to wire-v3 cohort cutover; a WHIR profile change is a fresh cohort (remove the retired config artifacts first)",
                        path.display()
                    );
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            create_new_or_validate_config(path, generated_json)?;
        }
        Err(error) => {
            return Err(anyhow::anyhow!(
                "read MLE v2 config artifact {}: {error}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Publish a previously absent config without ever exposing a partially written target or
/// overwriting a racing writer.
///
/// The complete bytes are first written and synced to a unique same-directory staging file. A
/// hard link then publishes that already-complete inode at `path` with no-clobber semantics. If
/// another generator wins the race, accept its artifact only when its complete bytes are exactly
/// the canonical bytes this invocation was going to publish. Both link creation and staging-file
/// cleanup are directory-synced before success is returned.
fn create_new_or_validate_config(path: &Path, contents: &str) -> Result<()> {
    create_new_or_validate_config_with_before_publish(path, contents, |_| Ok(()))
}

fn create_new_or_validate_config_with_before_publish<F>(
    path: &Path,
    contents: &str,
    before_publish: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MLE config path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("MLE config path is not UTF-8: {}", path.display()))?;

    let mut temporary = None::<(PathBuf, std::fs::File)>;
    for nonce in 0..64u32 {
        let candidate = parent.join(format!(
            ".{file_name}.create-{}-{nonce}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => bail!(
                "create MLE config staging file for {} without overwrite: {error}",
                path.display()
            ),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        anyhow::anyhow!(
            "could not allocate a unique MLE config staging file for {}",
            path.display()
        )
    })?;

    let stage_result = (|| -> Result<()> {
        file.write_all(contents.as_bytes()).map_err(|error| {
            anyhow::anyhow!(
                "write MLE config staging file {}: {error}",
                temporary_path.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            anyhow::anyhow!(
                "fsync MLE config staging file {}: {error}",
                temporary_path.display()
            )
        })?;
        Ok(())
    })();
    drop(file);

    let publish_result = stage_result.and_then(|()| {
        before_publish(&temporary_path)?;
        match fs::hard_link(&temporary_path, path) {
            Ok(()) => sync_config_directory(parent),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                validate_existing_config_bytes(path, contents, parent)
            }
            Err(error) => bail!(
                "publish complete MLE config staging file {} at {} without overwrite: {error}",
                temporary_path.display(),
                path.display()
            ),
        }
    });

    let cleanup_result = fs::remove_file(&temporary_path)
        .map_err(|error| {
            anyhow::anyhow!(
                "remove MLE config staging file {}: {error}",
                temporary_path.display()
            )
        })
        .and_then(|()| sync_config_directory(parent));

    match (publish_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(anyhow::anyhow!(
            "{error}; additionally failed to clean MLE config staging file: {cleanup_error}"
        )),
    }
}

fn validate_existing_config_bytes(path: &Path, contents: &str, parent: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        anyhow::anyhow!(
            "inspect concurrently created MLE v2 config artifact {}: {error}",
            path.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_file(),
        "concurrently created MLE v2 config artifact {} is not a regular file",
        path.display()
    );

    let mut file = OpenOptions::new().read(true).open(path).map_err(|error| {
        anyhow::anyhow!(
            "open concurrently created MLE v2 config artifact {}: {error}",
            path.display()
        )
    })?;
    let mut existing = Vec::new();
    file.read_to_end(&mut existing).map_err(|error| {
        anyhow::anyhow!(
            "read concurrently created MLE v2 config artifact {}: {error}",
            path.display()
        )
    })?;
    ensure!(
        existing == contents.as_bytes(),
        "MLE v2 config artifact {} was created concurrently with different bytes; refusing overwrite",
        path.display()
    );
    file.sync_all().map_err(|error| {
        anyhow::anyhow!(
            "fsync concurrently created MLE v2 config artifact {}: {error}",
            path.display()
        )
    })?;
    sync_config_directory(parent)
}

/// Admit only the one known retired-wire-v2 -> wire-v3 migration and only when
/// both documents describe the same underlying circuit. Protocol/session,
/// layout, PI-map and encoded-config pins are deliberately allowed to change.
fn validate_protocol_v2_config_cutover(
    path: &Path,
    existing_json: &str,
    generated_json: &str,
) -> Result<()> {
    let file_name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    ensure!(
        file_name.ends_with("_mle_config.json") || file_name == "mle_fixture_config.json",
        "cutover target is not a canonical MLE config artifact"
    );

    let existing: serde_json::Value = serde_json::from_str(existing_json)
        .map_err(|error| anyhow::anyhow!("legacy config is not JSON: {error}"))?;
    let generated: serde_json::Value = serde_json::from_str(generated_json)
        .map_err(|error| anyhow::anyhow!("generated config is not JSON: {error}"))?;
    ensure!(
        existing
            .pointer("/schema")
            .and_then(serde_json::Value::as_str)
            == Some("plonky2-mle-v2-solidity-config")
            && existing
                .pointer("/schemaVersion")
                .and_then(serde_json::Value::as_u64)
                == Some(2)
            && existing
                .pointer("/protocolVersion")
                .and_then(serde_json::Value::as_u64)
                == Some(2)
            && existing
                .pointer("/compactProofEncoding")
                .and_then(serde_json::Value::as_str)
                == Some("MLEWHIR2")
            && existing
                .pointer("/whirPowBits")
                .and_then(serde_json::Value::as_u64)
                == Some(20),
        "existing artifact is not the retired canonical wire-v2/PoW-20 identity"
    );
    ensure!(
        generated
            .pointer("/schema")
            .and_then(serde_json::Value::as_str)
            == Some("plonky2-mle-v3-solidity-config")
            && generated
                .pointer("/schemaVersion")
                .and_then(serde_json::Value::as_u64)
                == Some(3)
            && generated
                .pointer("/protocolVersion")
                .and_then(serde_json::Value::as_u64)
                == Some(3)
            && generated
                .pointer("/compactProofEncoding")
                .and_then(serde_json::Value::as_str)
                == Some("MLEWHIR3")
            && generated
                .pointer("/whirPowBits")
                .and_then(serde_json::Value::as_u64)
                == Some(22),
        "generated artifact is not the reviewed wire-v3/PoW-22 identity"
    );

    for pointer in [
        "/verificationConfig/circuit",
        "/verificationKey/circuitDigest",
        "/verificationKey/preprocessedCommitmentRoot",
        "/verificationKey/numSelectors",
        "/verificationKey/numGateConstraints",
        "/verificationKey/quotientDegreeFactor",
        "/verificationKey/gates",
        "/verificationKey/numConstants",
        "/verificationKey/numRoutedWires",
        "/verificationKey/numWires",
        "/verificationKey/kIs",
        "/verificationKey/subgroupGenPowers",
    ] {
        ensure!(
            existing.pointer(pointer).is_some()
                && existing.pointer(pointer) == generated.pointer(pointer),
            "underlying circuit identity differs at {pointer}"
        );
    }
    Ok(())
}

fn atomic_replace_config(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MLE config path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("MLE config path is not UTF-8: {}", path.display()))?;

    let mut temporary = None::<(PathBuf, std::fs::File)>;
    for nonce in 0..32u32 {
        let candidate = parent.join(format!(
            ".{file_name}.wire-v3-{}-{nonce}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => bail!("create MLE config cutover staging file: {error}"),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        anyhow::anyhow!("could not allocate a unique MLE config cutover staging file")
    })?;
    let result = (|| -> Result<()> {
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)?;
        sync_config_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result.map_err(|error| {
        anyhow::anyhow!("atomically replace MLE config {}: {error}", path.display())
    })
}

fn sync_config_directory(parent: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            anyhow::anyhow!("fsync MLE config directory {}: {error}", parent.display())
        })?;
    Ok(())
}

/// Assert that a persisted full fixture carries exactly the separately generated deployment
/// configuration artifact.
///
/// Both inputs must be strict canonical JSON. This is intentionally a byte-artifact boundary
/// check rather than a circuit helper: generators call it on the exact strings they write, so a
/// stale or accidentally cross-circuit `*_mle_config.json` cannot accompany an otherwise valid
/// proof. The compact proof record is checked here as well so the full artifact has one exact DA /
/// calldata payload.
pub fn validate_mle_v2_full_against_config_json(
    full_fixture_json: &str,
    config_fixture_json: &str,
) -> Result<Vec<u8>> {
    let full = MleVerifierV2Fixture::from_canonical_json(full_fixture_json)
        .map_err(|e| anyhow::anyhow!("MLE v2 full fixture is not strict canonical JSON: {e}"))?;
    let config = MleVerifierV2ConfigFixture::from_canonical_json(config_fixture_json)
        .map_err(|e| anyhow::anyhow!("MLE v2 config fixture is not strict canonical JSON: {e}"))?;
    ensure!(
        full.config_fixture() == config,
        "MLE v2 full fixture configuration differs from the deployment config artifact"
    );

    // The compact stream is the one and only calldata / Proof-DA artifact. Authenticate its
    // recorded length + Keccak digest, then decode and re-encode it with the pinned shape. Merely
    // hashing the JSON (or trusting a separately serialized proof object) would let downstream
    // submission metadata commit to bytes different from those verified on-chain.
    let compact = compact_mle_v2_bytes_from_fixture(&full)?;
    let shape = full.compact_shape.decode();
    let decoded = decode_compact_v2::<GoldilocksField>(&compact, &shape)
        .map_err(|e| anyhow::anyhow!("MLE v2 compactProof grammar validation failed: {e}"))?;
    let reencoded = encode_compact_v2(&decoded, &shape)
        .map_err(|e| anyhow::anyhow!("MLE v2 compactProof re-encoding failed: {e}"))?;
    ensure!(
        reencoded == compact,
        "MLE v2 compactProof is not the unique canonical encoding"
    );
    ensure!(
        MleProofV2Fixture::encode(&decoded) == full.proof,
        "MLE v2 structured proof disagrees with canonical compactProof bytes"
    );

    // The full fixture carries an ABI view for diagnostic/backward tooling. It is not an
    // alternative proof payload: require it to be the exact encoding of the same structured proof.
    let recorded_proof_abi = full
        .solidity_abi_proof
        .decode_and_validate(SOLIDITY_MLE_PROOF_ENCODING_V2)
        .map_err(|e| anyhow::anyhow!("MLE v2 Solidity proof ABI integrity failure: {e}"))?;
    let canonical_proof_abi = solidity_abi_encode_mle_proof_v2(&full.proof)
        .map_err(|e| anyhow::anyhow!("MLE v2 Solidity proof ABI re-encoding failed: {e}"))?;
    ensure!(
        recorded_proof_abi == canonical_proof_abi,
        "MLE v2 recorded Solidity proof ABI is not canonical"
    );

    // Do the same for the deployment configuration so a full proof cannot be paired with a
    // config file whose recorded bytes/hash describe a different constructor argument.
    let recorded_config_abi = config
        .solidity_abi_verification_config
        .decode_and_validate(SOLIDITY_MLE_VERIFICATION_CONFIG_ENCODING_V2)
        .map_err(|e| anyhow::anyhow!("MLE v2 Solidity config ABI integrity failure: {e}"))?;
    let canonical_config_abi =
        solidity_abi_encode_verification_config_v2(&config.verification_config)
            .map_err(|e| anyhow::anyhow!("MLE v2 Solidity config ABI re-encoding failed: {e}"))?;
    ensure!(
        recorded_config_abi == canonical_config_abi,
        "MLE v2 recorded Solidity verification-config ABI is not canonical"
    );
    ensure!(
        config.pinned_verifier.verification_config_digest
            == config.solidity_abi_verification_config.keccak256,
        "MLE v2 pinned verification-config digest disagrees with canonical ABI bytes"
    );

    Ok(compact)
}

/// Return the exact submission/Proof-DA commitment for a canonical full v2 fixture.
///
/// This intentionally consumes both the full proof and its separately persisted proof-free
/// deployment config. The returned pair is always `keccak256(compactProof.bytes)` and the exact
/// compact byte length; JSON bytes and the legacy FNV placeholder are never valid commitments.
pub fn mle_v2_compact_submission_metadata(
    full_fixture_json: &str,
    config_fixture_json: &str,
) -> Result<(String, u32)> {
    let compact = validate_mle_v2_full_against_config_json(full_fixture_json, config_fixture_json)?;
    let length = u32::try_from(compact.len())
        .map_err(|_| anyhow::anyhow!("MLE v2 compactProof length does not fit u32"))?;
    let hash = format!("0x{}", hex::encode(keccak_hash::keccak(&compact).0));
    Ok((hash, length))
}

/// Strictly parse a canonical full v2 fixture and return its one authoritative compact proof.
///
/// This authenticates the fixture against the supplied circuit, including the deterministic
/// preprocessed commitment root, then re-runs native verification and checks the compact record's
/// encoding label, byte length and Keccak digest. Calldata, DA, attestation and fraud-classifier
/// callers must all use these returned bytes rather than independently re-encoding the JSON proof.
pub fn validated_compact_mle_v2_bytes<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    json: &str,
    circuit_data: &CircuitData<F, C, D>,
) -> Result<Vec<u8>>
where
    C::Hasher: Hasher<F>,
{
    let fixture = MleVerifierV2Fixture::from_canonical_json(json)
        .map_err(|e| anyhow::anyhow!("MLE v2 fixture is not strict canonical JSON: {e}"))?;
    let expected_config = try_export_mle_v2_config_fixture(circuit_data)
        .map_err(|e| anyhow::anyhow!("MLE v2 circuit config derivation failed: {e}"))?;
    ensure!(
        fixture.config_fixture() == expected_config,
        "MLE v2 fixture configuration/VK differs from the supplied circuit"
    );
    check_v2_gate_rows(&expected_config)?;
    fixture
        .validate_against_common(&circuit_data.common)
        .map_err(|e| anyhow::anyhow!("MLE v2 fixture/native verification failed: {e}"))?;

    compact_mle_v2_bytes_from_fixture(&fixture)
}

fn compact_mle_v2_bytes_from_fixture(fixture: &MleVerifierV2Fixture) -> Result<Vec<u8>> {
    let encoding = std::str::from_utf8(&COMPACT_MAGIC_V2)
        .map_err(|e| anyhow::anyhow!("generated compact-v2 magic is not UTF-8: {e}"))?;
    let compact = fixture
        .compact_proof
        .decode_and_validate(encoding)
        .map_err(|e| anyhow::anyhow!("MLE v2 compactProof integrity failure: {e}"))?;
    ensure!(
        !compact.is_empty() && compact.len() <= MAX_COMPACT_PROOF_BYTES_V2,
        "MLE v2 compactProof length {} is outside 1..={MAX_COMPACT_PROOF_BYTES_V2}",
        compact.len()
    );
    Ok(compact)
}

/// Export a verified current wire-v3 proof through the V2 API as strict canonical full-fixture
/// JSON.
///
/// The supplied VK is compared with a fresh proof-free derivation from the complete circuit. The
/// result is round-tripped through the strict canonical parser and the same compact-record check as
/// [`validated_compact_mle_v2_bytes`], so no producer can publish JSON whose `.compactProof` is not
/// the exact verified calldata/DA payload.
pub fn export_mle_v2_json<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &MleProofV2<F>,
    vk: &MleVerificationKeyV2<F>,
    circuit_data: &CircuitData<F, C, D>,
) -> Result<String>
where
    C::Hasher: Hasher<F>,
{
    let fixture = try_export_mle_v2_fixture(proof, vk, &circuit_data.common)
        .map_err(|e| anyhow::anyhow!("MLE v2 full fixture export refused the proof: {e}"))?;
    let expected_config = try_export_mle_v2_config_fixture(circuit_data)
        .map_err(|e| anyhow::anyhow!("MLE v2 circuit config derivation failed: {e}"))?;
    ensure!(
        fixture.config_fixture() == expected_config,
        "MLE v2 proof VK differs from the circuit-derived deployment VK"
    );
    check_v2_gate_rows(&expected_config)?;
    let json = fixture
        .to_canonical_json()
        .map_err(|e| anyhow::anyhow!("MLE v2 canonical JSON export failed: {e}"))?;
    let reparsed = MleVerifierV2Fixture::from_canonical_json(&json)
        .map_err(|e| anyhow::anyhow!("MLE v2 canonical JSON did not round-trip: {e}"))?;
    ensure!(
        reparsed == fixture,
        "MLE v2 canonical JSON round-trip changed the full fixture"
    );
    let _ = compact_mle_v2_bytes_from_fixture(&reparsed)?;
    Ok(json)
}

/// Historical v1 proof generation is available only to the explicitly feature-gated retired
/// member-set-update fixture binary. Production modules cannot import these symbols accidentally.
#[cfg(feature = "deprecated-msu")]
pub mod deprecated_v1 {
    use super::{Duration, Instant, Result, check_on_chain_evaluable};
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::{CircuitData, CommonCircuitData},
            config::{GenericConfig, Hasher},
        },
        util::timing::TimingTree,
    };
    use plonky2_mle::{
        proof::{MleProof, MleVerificationKey},
        prover::{mle_prove, mle_setup},
        verifier::mle_verify,
    };

    pub struct DeprecatedMleV1ProveResult<F: plonky2::field::types::Field> {
        pub proof: MleProof<F>,
        pub prove_time: Duration,
    }

    pub fn setup_mle_vk<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        circuit_data: &CircuitData<F, C, D>,
    ) -> MleVerificationKey<F>
    where
        C::Hasher: Hasher<F>,
    {
        mle_setup::<F, C, D>(&circuit_data.prover_only, &circuit_data.common)
    }

    pub fn prove_with_mle<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        circuit_data: &CircuitData<F, C, D>,
        inputs: PartialWitness<F>,
    ) -> Result<DeprecatedMleV1ProveResult<F>>
    where
        C::Hasher: Hasher<F>,
        C::InnerHasher: Hasher<F>,
    {
        let start = Instant::now();
        let mut timing = TimingTree::new("deprecated_mle_prove_v1", log::Level::Debug);
        let proof = mle_prove::<F, C, D>(
            &circuit_data.prover_only,
            &circuit_data.common,
            inputs,
            &mut timing,
        )?;
        Ok(DeprecatedMleV1ProveResult {
            proof,
            prove_time: start.elapsed(),
        })
    }

    pub fn verify_mle_proof<F: RichField + Extendable<D>, const D: usize>(
        circuit_data: &CircuitData<F, impl GenericConfig<D, F = F>, D>,
        vk: &MleVerificationKey<F>,
        proof: &MleProof<F>,
    ) -> Result<()> {
        mle_verify::<F, D>(&circuit_data.common, vk, proof)
    }

    pub fn export_mle_json<F: RichField + Extendable<D>, const D: usize>(
        proof: &MleProof<F>,
        common_data: &CommonCircuitData<F, D>,
    ) -> Result<String> {
        let json =
            plonky2_mle::fixture::try_proof_to_json(proof, common_data, common_data.degree_bits())
                .map_err(|e| anyhow::anyhow!("deprecated MLE v1 fixture export failed: {e}"))?;
        check_on_chain_evaluable(common_data, &json)?;
        Ok(json)
    }
}

#[cfg(test)]
mod v2_export_tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::WitnessWrite,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use plonky2_mle::fixture_v2::EncodedProofV2Fixture;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn test_config_circuit() -> (CircuitData<F, C, D>, plonky2::iop::target::Target) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let value = builder.add_virtual_target();
        let square = builder.square(value);
        builder.register_public_input(square);
        (builder.build::<C>(), value)
    }

    fn retired_v2_config_from_current(current_json: &str) -> serde_json::Value {
        let mut retired: serde_json::Value = serde_json::from_str(current_json).unwrap();
        retired["schema"] = serde_json::json!("plonky2-mle-v2-solidity-config");
        retired["schemaVersion"] = serde_json::json!(2);
        retired["protocolVersion"] = serde_json::json!(2);
        retired["compactProofEncoding"] = serde_json::json!("MLEWHIR2");
        retired["whirPowBits"] = serde_json::json!(20);
        retired["verificationKey"]["protocolVersion"] = serde_json::json!(2);
        retired["verificationKey"]
            .as_object_mut()
            .unwrap()
            .remove("publicInputWireMap");
        retired["verificationConfig"]
            .as_object_mut()
            .unwrap()
            .remove("publicInputWireMap");
        retired
    }

    #[test]
    fn config_create_race_never_overwrites_and_accepts_only_identical_bytes() {
        let unique = format!(
            "intmax-mle-config-create-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("mle_fixture_config.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

        let contenders = ["first canonical config\n", "second canonical config\n"];
        let handles: Vec<_> = contenders
            .into_iter()
            .map(|contents| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    create_new_or_validate_config(&path, contents)
                })
            })
            .collect();
        barrier.wait();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one differing concurrent creator must win"
        );

        let winner = fs::read_to_string(&path).unwrap();
        assert!(contenders.contains(&winner.as_str()));
        create_new_or_validate_config(&path, &winner)
            .expect("an identical AlreadyExists race is idempotent");

        let loser = contenders
            .into_iter()
            .find(|contents| *contents != winner)
            .unwrap();
        let mismatch = create_new_or_validate_config(&path, loser)
            .expect_err("a differing AlreadyExists race must fail closed");
        assert!(mismatch.to_string().contains("different bytes"));
        assert_eq!(fs::read_to_string(&path).unwrap(), winner);
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            1,
            "every contender must remove its private staging file"
        );

        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn config_create_interruption_before_publish_never_exposes_target_and_cleans_staging() {
        let unique = format!(
            "intmax-mle-config-create-interruption-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("mle_fixture_config.json");
        let contents = "complete canonical config\n";

        let interrupted =
            create_new_or_validate_config_with_before_publish(&path, contents, |temporary_path| {
                assert!(
                    !path.exists(),
                    "the final target must not exist while staging bytes are being prepared"
                );
                assert_eq!(fs::read_to_string(temporary_path).unwrap(), contents);
                Err(anyhow::anyhow!(
                    "injected interruption before no-clobber publish"
                ))
            })
            .expect_err("the injected pre-publication interruption must propagate");
        assert!(interrupted.to_string().contains("injected interruption"));
        assert!(
            !path.exists(),
            "an interruption before publish must never expose a partial target"
        );
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            0,
            "the error path must remove and directory-sync its staging entry"
        );

        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn canonical_v2_export_has_one_strict_compact_proof() {
        let (circuit, value) = test_config_circuit();
        let mut witness = PartialWitness::new();
        witness.set_target(value, F::from_canonical_u64(9)).unwrap();

        let vk = setup_mle_vk_v2::<F, C, D>(&circuit);
        let proved = prove_with_mle_v2::<F, C, D>(&circuit, witness).unwrap();
        verify_mle_proof_v2(&circuit, &vk, &proved.proof).unwrap();
        let json = export_mle_v2_json(&proved.proof, &vk, &circuit).unwrap();
        assert!(json.ends_with('\n'));

        let fixture = MleVerifierV2Fixture::from_canonical_json(&json).unwrap();
        assert_eq!(fixture.protocol_version, 3);
        let config_json = export_mle_v2_config_json(&circuit).unwrap();
        let validated_compact =
            validate_mle_v2_full_against_config_json(&json, &config_json).unwrap();
        assert_eq!(
            fixture.config_fixture(),
            MleVerifierV2ConfigFixture::from_canonical_json(&config_json).unwrap()
        );
        let compact = validated_compact_mle_v2_bytes(&json, &circuit).unwrap();
        assert_eq!(validated_compact, compact);
        assert!(compact.starts_with(&COMPACT_MAGIC_V2));
        assert_eq!(compact.len(), fixture.compact_proof.byte_length);
        let (submission_hash, submission_length) =
            mle_v2_compact_submission_metadata(&json, &config_json).unwrap();
        assert_eq!(submission_length as usize, compact.len());
        assert_eq!(
            submission_hash,
            format!("0x{}", hex::encode(keccak_hash::keccak(&compact).0))
        );

        // The full schema string is authenticated independently of the
        // projected config view. A relabelled artifact must fail at both the
        // parser and the parent full/config release boundary.
        let mut wrong_schema = fixture.clone();
        wrong_schema.schema = "plonky2-mle-v2-solidity".to_string();
        let wrong_schema_json = wrong_schema.to_canonical_json().unwrap();
        assert!(MleVerifierV2Fixture::from_canonical_json(&wrong_schema_json).is_err());
        assert!(
            validate_mle_v2_full_against_config_json(&wrong_schema_json, &config_json).is_err()
        );

        // Updating a redundant structured view while leaving the authoritative compact stream
        // untouched must fail. Otherwise downstream metadata could bind valid compact bytes while
        // human/tooling consumers read a different proof from the same JSON artifact.
        let mut inconsistent_view = fixture.clone();
        inconsistent_view.proof.public_inputs[0] = "0x0000000000000000".to_string();
        let inconsistent_json = inconsistent_view.to_canonical_json().unwrap();
        assert!(
            validate_mle_v2_full_against_config_json(&inconsistent_json, &config_json).is_err()
        );

        let mut tampered = fixture;
        let last = tampered.compact_proof.bytes.pop().unwrap();
        tampered
            .compact_proof
            .bytes
            .push(if last == '0' { '1' } else { '0' });
        let tampered_json = tampered.to_canonical_json().unwrap();
        assert!(validated_compact_mle_v2_bytes(&tampered_json, &circuit).is_err());
    }

    #[test]
    fn wire_v3_config_cutover_is_explicit_circuit_identical_and_atomic() {
        let (circuit, _) = test_config_circuit();
        let current_json = export_mle_v2_config_json(&circuit).unwrap();
        let retired = retired_v2_config_from_current(&current_json);
        let retired_json = format!("{}\n", serde_json::to_string_pretty(&retired).unwrap());

        let unique = format!(
            "intmax-mle-v3-cutover-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        fs::create_dir(&directory).unwrap();

        let fresh_path = directory.join("fresh_mle_config.json");
        persist_or_validate_mle_v2_config_json_inner(&fresh_path, &current_json, false).unwrap();
        assert_eq!(fs::read_to_string(&fresh_path).unwrap(), current_json);
        persist_or_validate_mle_v2_config_json_inner(&fresh_path, &current_json, false).unwrap();

        let path = directory.join("mle_fixture_config.json");
        fs::write(&path, &retired_json).unwrap();

        let without_explicit_cutover =
            persist_or_validate_mle_v2_config_json_inner(&path, &current_json, false)
                .expect_err("retired config must not be overwritten implicitly");
        assert!(
            without_explicit_cutover
                .to_string()
                .contains(MLE_V3_CONFIG_CUTOVER_ENV)
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), retired_json);

        persist_or_validate_mle_v2_config_json_inner(&path, &current_json, true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), current_json);
        assert!(
            fs::read_dir(&directory).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")),
            "successful cutover must leave no staging file"
        );

        let mut changed_current: serde_json::Value = serde_json::from_str(&current_json).unwrap();
        changed_current["verificationKey"]["circuitDigest"][0] =
            serde_json::json!("0x0000000000000000");
        let changed_current_json = format!(
            "{}\n",
            serde_json::to_string_pretty(&changed_current).unwrap()
        );
        assert!(
            persist_or_validate_mle_v2_config_json_inner(&path, &changed_current_json, true)
                .is_err(),
            "the cutover switch must not overwrite a different current-v3 config"
        );

        fs::remove_file(&fresh_path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn wire_v3_config_cutover_rejects_identity_and_target_drift() {
        let (circuit, _) = test_config_circuit();
        let current_json = export_mle_v2_config_json(&circuit).unwrap();
        let current: serde_json::Value = serde_json::from_str(&current_json).unwrap();
        let retired = retired_v2_config_from_current(&current_json);
        let encode = |value: &serde_json::Value| serde_json::to_string(value).unwrap();
        let valid_retired = encode(&retired);

        validate_protocol_v2_config_cutover(
            Path::new("mle_fixture_config.json"),
            &valid_retired,
            &current_json,
        )
        .unwrap();
        assert!(
            validate_protocol_v2_config_cutover(
                Path::new("not-a-config.json"),
                &valid_retired,
                &current_json,
            )
            .is_err()
        );

        for key in [
            "schema",
            "schemaVersion",
            "protocolVersion",
            "compactProofEncoding",
            "whirPowBits",
        ] {
            let mut changed = retired.clone();
            changed[key] = serde_json::Value::Null;
            assert!(
                validate_protocol_v2_config_cutover(
                    Path::new("mle_fixture_config.json"),
                    &encode(&changed),
                    &current_json,
                )
                .is_err(),
                "retired identity drift at {key} must fail"
            );
        }

        for key in [
            "schema",
            "schemaVersion",
            "protocolVersion",
            "compactProofEncoding",
            "whirPowBits",
        ] {
            let mut changed = current.clone();
            changed[key] = serde_json::Value::Null;
            assert!(
                validate_protocol_v2_config_cutover(
                    Path::new("mle_fixture_config.json"),
                    &valid_retired,
                    &encode(&changed),
                )
                .is_err(),
                "current identity drift at {key} must fail"
            );
        }

        for pointer in [
            "/verificationConfig/circuit",
            "/verificationKey/circuitDigest",
            "/verificationKey/preprocessedCommitmentRoot",
            "/verificationKey/numSelectors",
            "/verificationKey/numGateConstraints",
            "/verificationKey/quotientDegreeFactor",
            "/verificationKey/gates",
            "/verificationKey/numConstants",
            "/verificationKey/numRoutedWires",
            "/verificationKey/numWires",
            "/verificationKey/kIs",
            "/verificationKey/subgroupGenPowers",
        ] {
            let mut changed = retired.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
            assert!(
                validate_protocol_v2_config_cutover(
                    Path::new("mle_fixture_config.json"),
                    &encode(&changed),
                    &current_json,
                )
                .is_err(),
                "underlying circuit drift at {pointer} must fail"
            );
        }
    }
}
