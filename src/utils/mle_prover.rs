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
//  WHY THIS LIVES HERE AND NOT IN THE SUBMODULE
//  `contracts/lib/polygon-plonky2/mle/src/fixture.rs:510-512` is where the `255` sentinel is
//  emitted, but a guard placed there would be (a) NOT carried by the Cargo/Foundry pin — a plain
//  `git submodule update` silently reverts it, which is the very failure mode being guarded
//  against, and (b) wrong in the general case, because the supported set is a property of THIS
//  repo's deployed evaluator (locally patched to add id 8) rather than of upstream's. Upstream's
//  `proof_to_json` / `proof_to_fixture` are also infallible-signature public API, so turning them
//  into fallible calls is a breaking upstream change. Every fixture this repo writes goes through
//  `export_mle_json` below, so this is the complete chokepoint.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Gate ids that the deployed `Plonky2GateEvaluator.sol` dispatcher can actually evaluate.
///
/// SECURITY: this list is NOT free-standing documentation — `tests/mle_gate_support.rs` DERIVES the
/// set from `contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol` (the
/// `GATE_* = <id>` constants that the `gi.gateId == GATE_*` dispatcher actually branches on) and
/// fails if it disagrees with this constant. Editing this list without editing the Solidity — or
/// vice versa — is a test failure, so it cannot silently go stale.
pub const SOLIDITY_SUPPORTED_GATE_IDS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Sentinel written by `plonky2_mle::fixture::classify_gate` for any gate it does not recognise.
/// It is a well-formed `u8` that hashes into a valid `gatesDigest`, so it is invisible to every
/// check except this one and the on-chain revert.
pub const UNSUPPORTED_GATE_ID: u8 = 255;

/// SECURITY: reject a fixture the deployed on-chain evaluator provably cannot verify.
///
/// Two independent failure shapes are checked, both of which yield a well-formed-but-unusable
/// fixture:
///
/// 1. **Unsupported gate.** `classify_gate` maps an unrecognised gate to [`UNSUPPORTED_GATE_ID`]
///    (255); the Solidity dispatcher reverts on any id outside [`SOLIDITY_SUPPORTED_GATE_IDS`]
///    whose filter is non-zero.
/// 2. **Silent `as u8` truncation.** `fixture.rs:531-534` narrows `selector_index`, `group_start`,
///    `group_end` and `gate_row_index` with `as u8` and `num_constraints` with `as u16`. A wrap
///    produces a fixture that names the WRONG selector column / row — the proof would then be
///    checked against constraints that are not the circuit's. This recomputes each field from
///    `common_data` (the pre-truncation source of truth), bounds-checks it, and compares it against
///    what was actually serialized, so both an out-of-range value and any future divergence between
///    the two are caught.
pub fn check_on_chain_evaluable<F: RichField + Extendable<D>, const D: usize>(
    common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    json: &str,
) -> Result<()> {
    let si = &common_data.selectors_info;
    let expected: Vec<ExpectedGateRow> = (0..common_data.gates.len())
        .map(|row| {
            let sel_idx = si.selector_indices[row];
            let group = &si.groups[sel_idx];
            ExpectedGateRow {
                selector_index: sel_idx,
                group_start: group.start,
                group_end: group.end,
                gate_row_index: row,
                num_constraints: common_data.gates[row].0.num_constraints(),
            }
        })
        .collect();
    check_fixture_json_gates(json, &expected)
}

/// Circuit-derived, PRE-truncation expectation for one serialized gate row. These are the values
/// `mle/src/fixture.rs` narrows with `as u8` / `as u16`.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedGateRow {
    pub selector_index: usize,
    pub group_start: usize,
    pub group_end: usize,
    pub gate_row_index: usize,
    pub num_constraints: usize,
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
    let json = plonky2_mle::fixture::proof_to_json(proof, common_data, common_data.degree_bits());
    check_on_chain_evaluable(common_data, &json)?;
    Ok(json)
}
