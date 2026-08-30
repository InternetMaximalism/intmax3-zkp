//! MLE-based Plonky2 prover — uses plonky2_mle for multilinear PCS.
//!
//! Replaces the previous WHIR pipeline with the plonky2_mle crate which
//! provides sumcheck + multilinear polynomial commitment based proving.

use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::CircuitData,
        config::{GenericConfig, Hasher},
    },
    util::timing::TimingTree,
};
use plonky2_mle::{
    proof::{MleProof, MleVerificationKey},
    prover::{mle_prove, mle_setup},
    verifier::mle_verify,
};

/// Result of MLE proving, including timing information.
pub struct MleProveResult<F: plonky2::field::types::Field> {
    pub proof: MleProof<F>,
    pub prove_time: Duration,
}

/// Compute the MLE verification key for a circuit.
/// This must be done once during setup (deterministic).
pub fn setup_mle_vk<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
) -> MleVerificationKey<F>
where
    C::Hasher: Hasher<F>,
{
    mle_setup::<F, C, D>(&circuit_data.prover_only, &circuit_data.common)
}

/// Generate an MLE proof for a Plonky2 circuit.
pub fn prove_with_mle<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    inputs: PartialWitness<F>,
) -> Result<MleProveResult<F>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    let start = Instant::now();
    let mut timing = TimingTree::new("mle_prove", log::Level::Debug);

    let proof = mle_prove::<F, C, D>(
        &circuit_data.prover_only,
        &circuit_data.common,
        inputs,
        &mut timing,
    )?;

    let prove_time = start.elapsed();
    Ok(MleProveResult { proof, prove_time })
}

/// Verify an MLE proof against the circuit's common data and verification key.
pub fn verify_mle_proof<F: RichField + Extendable<D>, const D: usize>(
    circuit_data: &CircuitData<F, impl GenericConfig<D, F = F>, D>,
    vk: &MleVerificationKey<F>,
    proof: &MleProof<F>,
) -> Result<()> {
    mle_verify::<F, D>(&circuit_data.common, vk, proof)
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
//  Every fixture this repo writes goes through `export_mle_json` below, so this is the complete
//  chokepoint.
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
        // check a perfectly well-formed fixture (and gatesDigest) can pass every Rust check and then
        // deterministically revert on-chain when the constants table is touched.
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

/// Export MLE proof data as JSON for on-chain verification via MleVerifier.sol.
///
/// SECURITY: fails closed via [`check_on_chain_evaluable`] rather than returning a fixture that
/// only the Rust verifier can accept. See the block comment above.
pub fn export_mle_json<F: RichField + Extendable<D>, const D: usize>(
    proof: &MleProof<F>,
    common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
) -> Result<String> {
    // SECURITY: `try_proof_to_json` fails rather than emitting a guessed gate parameter or the
    // `255` sentinel (audit M-10). `check_on_chain_evaluable` then re-derives the same values
    // independently and compares them against what was actually serialized.
    let json =
        plonky2_mle::fixture::try_proof_to_json(proof, common_data, common_data.degree_bits())
            .map_err(|e| anyhow::anyhow!("MLE fixture export refused to write a fixture: {e}"))?;
    check_on_chain_evaluable(common_data, &json)?;
    Ok(json)
}
