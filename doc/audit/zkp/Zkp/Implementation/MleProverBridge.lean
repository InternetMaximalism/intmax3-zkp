import Std

/-!
# MLE prover bridge: plonky2 proof -> pinned MLE/WHIR artifact, and the retired member-set-update prototype

Handwritten semantic model of

* `src/utils/mle_prover.rs` (1399 lines) — the wrapper that turns a plonky2 proof into the
  pinned MLE/WHIR artifacts the deployed Solidity verifier consumes: the on-chain-evaluability
  gate guards, the create-once/compare-later deployment-config boundary, the reviewed
  wire-v2 -> wire-v3 cutover, the compact-proof serialization checks, and the submission
  (calldata / Proof-DA) commitment.
* `src/deprecated/member_set_update/circuit.rs` (597), `.../generate_fixture.rs` (203),
  `.../mod.rs` (8) and `src/deprecated/mod.rs` (6) — the RETIRED direct in-place
  member-set-update prototype, modelled as data.

This is NOT a refinement proof of the Rust code, of `plonky2`, of the `plonky2_mle` submodule,
or of the Solidity verifier. It is a local semantic model plus kernel-checked theorems about
that model. Nothing here proves that a proof is sound, that a fixture is safe, or that any
retired path is unreachable beyond what the Cargo manifest text itself states.

## Feature gating of the retired member-set-update tree (asked explicitly)
`Cargo.toml:177` declares `default = []`; `deprecated-msu` is a non-default feature
(`Cargo.toml:223`). `src/lib.rs:15-19` compiles `pub mod deprecated` only under
`#[cfg(feature = "deprecated-msu")]`, and the only binary that constructs the circuit,
`generate_member_set_update_fixture`, carries `required-features = ["deprecated-msu"]`
(`Cargo.toml:255-257`). `src/utils/mle_prover.rs:953` gates the whole `deprecated_v1`
proving/export surface the same way. So in a DEFAULT build the module is not compiled and the
path is not reachable. `manifestReachability` below models exactly those manifest facts and
nothing more: it is not a claim that no operator ever enables the feature, and not a claim that
the prototype is safe.

## Named boundaries (undischarged premises; none of these are proved here)
* PROVING / VERIFICATION: `mle_prove_v2`, `mle_verify_v2`, plonky2 `prove`/`verify`,
  `validate_against_common`. Modelled as opaque outcomes.
* WHIR/FRI + sumcheck SOUNDNESS and the PCS security level. Never modelled.
* KZG attestation / Proof-DA availability. Out of scope; only the byte commitment is modelled.
* KECCAK and POSEIDON: opaque callbacks. No injectivity is assumed anywhere.
* `plonky2_mle` submodule semantics: `classify_gate`, `try_export_mle_v2_fixture`,
  `try_export_mle_v2_config_fixture`, `from_canonical_json`/`to_canonical_json`,
  `decode_compact_v2`/`encode_compact_v2`, `decode_and_validate`, the ABI encoders, and the
  constants `COMPACT_MAGIC_V2`, `MAX_COMPACT_PROOF_BYTES_V2`,
  `SOLIDITY_MLE_PROOF_ENCODING_V2`, `SOLIDITY_MLE_VERIFICATION_CONFIG_ENCODING_V2`. All are
  parameters of the model (`MleEnv`), never definitions.
* SOLIDITY side: `Plonky2GateEvaluator(Ext3).sol` dispatch and the deployed verifier are
  modelled only through this repository's pinned gate-id set. The registered current module
  `Zkp.Contracts.CurrentVerification` models the pinned verifier from the Solidity side; it is
  deliberately NOT imported here (it is not a `Zkp.Implementation` module), so the Rust-side /
  Solidity-side agreement is a named boundary rather than a theorem.
* FILESYSTEM atomicity: `hard_link` no-clobber semantics, `rename`, `fsync`. Modelled as the
  documented decision procedure, not as OS behaviour.
* WALLET GATE: `verify_member_set_update`, `validate_member_set_delta`, the Falcon batch
  aggregate and its verifier key are opaque outcomes / callbacks.
-/

namespace Zkp.Implementation.MleProverBridge

/-! ## 0. Shared vocabulary -/

/-- A byte string. Byte values are not range-modelled; only equality and length are used. -/
abbrev Bytes := List Nat

/-- The compact-proof shape descriptor (`full.compact_shape.decode()`), opaque. -/
abbrev Shape := Nat

/-- First error wins, in list order. Used to model a straight-line block of `ensure!`s. -/
def firstError {E : Type} : List (Except E Unit) → Except E Unit
  | [] => .ok ()
  | c :: cs => match c with
    | .error e => .error e
    | .ok _ => firstError cs

theorem first_error_ok_implies_mem {E : Type} :
    ∀ (cs : List (Except E Unit)), firstError cs = .ok () → ∀ c ∈ cs, c = .ok () := by
  intro cs
  induction cs with
  | nil => intro _ c hc; cases hc
  | cons a as ih =>
    intro h c hc
    cases ha : a with
    | error e => rw [firstError, ha] at h; cases h
    | ok u =>
      cases hc with
      | head => cases u; exact ha
      | tail _ hmem =>
        rw [firstError, ha] at h
        exact ih h c hmem

theorem first_error_head_error_wins {E : Type} (e : E) (c : Except E Unit)
    (cs : List (Except E Unit)) (h : c = .error e) : firstError (c :: cs) = .error e := by
  rw [firstError, h]

theorem first_error_nil_ok {E : Type} : firstError ([] : List (Except E Unit)) = .ok () := rfl

/-- `List.find?` returning `none` means the predicate failed everywhere (own copy, no Std drift). -/
theorem find_none_forall {α : Type} (p : α → Bool) :
    ∀ l : List α, l.find? p = none → ∀ a ∈ l, p a = false := by
  intro l
  induction l with
  | nil => intro _ a ha; cases ha
  | cons x xs ih =>
    intro h a ha
    rw [List.find?] at h
    cases hx : p x with
    | true => rw [hx] at h; cases h
    | false =>
      rw [hx] at h
      simp only at h
      cases ha with
      | head => exact hx
      | tail _ hmem => exact ih h a hmem

/-! ## 1. `mle_prover.rs` — the on-chain-evaluability pins (lines 118-131, 272-298) -/

/-- `SOLIDITY_SUPPORTED_GATE_IDS` (`mle_prover.rs:125`): the gate ids the deployed
`Plonky2GateEvaluator.sol` dispatcher branches on. `tests/mle_gate_support.rs` derives the set
from the Solidity source; that derivation is a boundary, the literal is pinned here. -/
def soliditySupportedGateIds : List Nat := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

theorem solidity_supported_gate_ids_pinned :
    soliditySupportedGateIds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] := rfl

/-- `ExponentiationGate` (id 8) — the gate whose omission shipped on 2026-07-31 and was repaired
on 2026-08-09 — is in the pinned deployed set. -/
theorem exponentiation_gate_id_is_supported : soliditySupportedGateIds.contains 8 = true := by
  decide

/-- `UNSUPPORTED_GATE_ID` (`mle_prover.rs:131`): the historical classifier sentinel. -/
def unsupportedGateId : Nat := 255

theorem unsupported_gate_id_pinned : unsupportedGateId = 255 := rfl

theorem sentinel_gate_id_is_not_supported :
    soliditySupportedGateIds.contains unsupportedGateId = false := by decide

/-- `CosetInterpolationGate`, the only id with a finite Solidity constants table. -/
def cosetInterpolationGateId : Nat := 13
def cosetMinSubgroupBits : Nat := 1
def cosetMaxSubgroupBits : Nat := 5
def cosetMinDegree : Nat := 2

theorem coset_envelope_pinned :
    cosetInterpolationGateId = 13 ∧ cosetMinSubgroupBits = 1 ∧ cosetMaxSubgroupBits = 5 ∧
      cosetMinDegree = 2 := by decide

/-- The narrow integer widths `mle/src/fixture.rs` serializes into. -/
def u8Max : Nat := 255
def u16Max : Nat := 65535
def u32Max : Nat := 4294967295

theorem narrow_widths_pinned : u8Max = 255 ∧ u16Max = 65535 ∧ u32Max = 4294967295 := by decide

/-! ## 2. `check_fixture_json_gates` (lines 159-349): the v1 fixture gate guard -/

/-- One circuit-derived, PRE-truncation gate row (`ExpectedGateRow`, `mle_prover.rs:196-210`). -/
structure ExpectedGateRow where
  gateId : Nat
  selectorIndex : Nat
  groupStart : Nat
  groupEnd : Nat
  gateRowIndex : Nat
  numConstraints : Nat
  numOrConsts : Nat
  param2 : Nat
  param3 : Nat
  deriving DecidableEq, Repr

/-- One row as it appears in the serialized fixture JSON. Every numeric field is optional
because the Rust reads it with `get(field).and_then(as_u64)` and errors when absent. -/
structure SerializedGateRow where
  name : Option String
  gateId : Option Nat
  numOrConsts : Option Nat
  param2 : Option Nat
  param3 : Option Nat
  selectorIndex : Option Nat
  groupStart : Option Nat
  groupEnd : Option Nat
  gateRowIndex : Option Nat
  numConstraints : Option Nat
  deriving DecidableEq, Repr

inductive GateGuardError where
  | notJson
  | noGatesArray
  | rowCountMismatch (serialized expected : Nat)
  | missingField (row : Nat) (field : String)
  | sentinelGate (row : Nat)
  | gateIdExceedsU8 (row gateId : Nat)
  | unsupportedGate (row gateId : Nat)
  | gateIdMismatch (row serialized expected : Nat)
  | cosetSubgroupBitsOutsideEnvelope (row bits : Nat)
  | cosetDegreeBelowMinimum (row degree : Nat)
  | cosetDegreeExceedsSubgroup (row degree bits : Nat)
  | parameterMismatch (row : Nat) (field : String) (serialized expected : Nat)
  | narrowIntegerOverflow (row : Nat) (field : String) (value maxValue : Nat)
  | layoutMismatch (row : Nat) (field : String) (serialized expected : Nat)
  deriving DecidableEq, Repr

/-- Lines 272-298 / 363-378: the deployed `CosetInterpolation` constants-table envelope.
Shared by the v1 and v2 guards. Values are the CIRCUIT-derived ones. -/
def checkCosetEnvelope (row gateId bits degree : Nat) : Except GateGuardError Unit :=
  if gateId ≠ cosetInterpolationGateId then .ok ()
  else if bits < cosetMinSubgroupBits ∨ bits > cosetMaxSubgroupBits then
    .error (.cosetSubgroupBitsOutsideEnvelope row bits)
  else if degree < cosetMinDegree then .error (.cosetDegreeBelowMinimum row degree)
  else if degree > 2 ^ bits then .error (.cosetDegreeExceedsSubgroup row degree bits)
  else .ok ()

theorem coset_envelope_skipped_for_other_gates (row gateId bits degree : Nat)
    (h : gateId ≠ cosetInterpolationGateId) :
    checkCosetEnvelope row gateId bits degree = .ok () := by
  simp [checkCosetEnvelope, h]

theorem coset_envelope_ok_bounds (row bits degree : Nat)
    (h : checkCosetEnvelope row cosetInterpolationGateId bits degree = .ok ()) :
    cosetMinSubgroupBits ≤ bits ∧ bits ≤ cosetMaxSubgroupBits ∧ cosetMinDegree ≤ degree ∧
      degree ≤ 2 ^ bits := by
  simp only [checkCosetEnvelope, ne_eq, not_true_eq_false, if_false] at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · rename_i h1 h2 h3
        simp only [not_or, Nat.not_lt] at h1 h2 h3
        exact ⟨h1.1, by omega, h2, by omega⟩

/-- Lines 304-321 (M-10): the on-chain evaluation parameters `numOrConsts` / `param2` /
`param3`, compared field-for-field against a structural re-derivation. -/
def checkParameterField (row : Nat) (field : String) (serialized : Option Nat) (expected : Nat) :
    Except GateGuardError Unit :=
  match serialized with
  | none => .error (.missingField row field)
  | some v => if v = expected then .ok () else .error (.parameterMismatch row field v expected)

/-- Lines 323-345: a layout field. The PRE-truncation bound on the CIRCUIT value is checked
FIRST, before the serialized value is even read, so an out-of-range circuit value is reported as
a silent-`as u8`-wrap hazard rather than as a mismatch. -/
def checkLayoutField (row : Nat) (field : String) (serialized : Option Nat)
    (expected maxValue : Nat) : Except GateGuardError Unit :=
  if expected > maxValue then .error (.narrowIntegerOverflow row field expected maxValue)
  else match serialized with
    | none => .error (.missingField row field)
    | some v => if v = expected then .ok () else .error (.layoutMismatch row field v expected)

theorem layout_bound_precedes_field_read (row : Nat) (field : String) (serialized : Option Nat)
    (expected maxValue : Nat) (h : expected > maxValue) :
    checkLayoutField row field serialized expected maxValue =
      .error (.narrowIntegerOverflow row field expected maxValue) := by
  simp [checkLayoutField, h]

theorem layout_field_ok_fits_and_matches (row : Nat) (field : String) (serialized : Option Nat)
    (expected maxValue : Nat) (h : checkLayoutField row field serialized expected maxValue = .ok ()) :
    expected ≤ maxValue ∧ serialized = some expected := by
  simp only [checkLayoutField] at h
  split at h
  · cases h
  · rename_i hbound
    split at h
    · cases h
    · split at h
      · rename_i _ hveq
        subst hveq
        exact ⟨Nat.le_of_not_lt hbound, rfl⟩
      · cases h

theorem parameter_field_ok_matches (row : Nat) (field : String) (serialized : Option Nat)
    (expected : Nat) (h : checkParameterField row field serialized expected = .ok ()) :
    serialized = some expected := by
  simp only [checkParameterField] at h
  split at h
  · cases h
  · split at h
    · rename_i _ hveq; subst hveq; rfl
    · cases h

/-- The tail of one row check, in exact source order: coset envelope, then the three evaluation
parameters, then the five layout fields. -/
def gateRowChecks (row : Nat) (s : SerializedGateRow) (e : ExpectedGateRow) :
    List (Except GateGuardError Unit) :=
  [ checkCosetEnvelope row e.gateId e.numOrConsts e.param2,
    checkParameterField row "numOrConsts" s.numOrConsts e.numOrConsts,
    checkParameterField row "param2" s.param2 e.param2,
    checkParameterField row "param3" s.param3 e.param3,
    checkLayoutField row "selectorIndex" s.selectorIndex e.selectorIndex u8Max,
    checkLayoutField row "groupStart" s.groupStart e.groupStart u8Max,
    checkLayoutField row "groupEnd" s.groupEnd e.groupEnd u8Max,
    checkLayoutField row "gateRowIndex" s.gateRowIndex e.gateRowIndex u8Max,
    checkLayoutField row "numConstraints" s.numConstraints e.numConstraints u16Max ]

/-- Lines 229-345: one serialized gate row versus its circuit-derived expectation. -/
def checkGateRow (row : Nat) (s : SerializedGateRow) (e : ExpectedGateRow) :
    Except GateGuardError Unit :=
  match s.gateId with
  | none => .error (.missingField row "gateId")
  | some gid =>
    if gid = unsupportedGateId then .error (.sentinelGate row)
    else if gid > u8Max then .error (.gateIdExceedsU8 row gid)
    else if !(soliditySupportedGateIds.contains gid) then .error (.unsupportedGate row gid)
    else if gid ≠ e.gateId then .error (.gateIdMismatch row gid e.gateId)
    else firstError (gateRowChecks row s e)

/-- Precedence: the `255` sentinel is reported as the sentinel, not as "unsupported id". -/
theorem gate_row_sentinel_precedes_membership (row : Nat) (s : SerializedGateRow)
    (e : ExpectedGateRow) (h : s.gateId = some unsupportedGateId) :
    checkGateRow row s e = .error (.sentinelGate row) := by
  simp [checkGateRow, h]

/-- Precedence: a well-formed but WRONG gate id (both ids on-chain supported) is still rejected. -/
theorem gate_row_rejects_supported_but_wrong_id (row : Nat) (s : SerializedGateRow)
    (e : ExpectedGateRow) (gid : Nat) (hg : s.gateId = some gid) (hs : gid ≠ unsupportedGateId)
    (hu : gid ≤ u8Max) (hm : soliditySupportedGateIds.contains gid = true)
    (hne : gid ≠ e.gateId) :
    checkGateRow row s e = .error (.gateIdMismatch row gid e.gateId) := by
  have hb : ¬ gid > u8Max := Nat.not_lt.mpr hu
  have hc : ¬ ((!soliditySupportedGateIds.contains gid) = true) := by rw [hm]; simp
  simp only [checkGateRow, hg, if_neg hs, if_neg hb, if_neg hc, if_pos hne]

theorem gate_row_ok_implies_id_supported_and_equal (row : Nat) (s : SerializedGateRow)
    (e : ExpectedGateRow) (h : checkGateRow row s e = .ok ()) :
    s.gateId = some e.gateId ∧ soliditySupportedGateIds.contains e.gateId = true ∧
      e.gateId ≠ unsupportedGateId := by
  simp only [checkGateRow] at h
  split at h
  · cases h
  · rename_i gid hgid
    split at h
    · cases h
    · split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · cases h
          · rename_i hsent _ hmem hEq
            simp only [Bool.not_eq_true', Bool.not_eq_false] at hmem
            have : gid = e.gateId := by
              simpa using hEq
            refine ⟨by rw [hgid, this], ?_, ?_⟩
            · rw [← this]; exact hmem
            · rw [← this]; exact hsent

theorem gate_row_ok_implies_parameters_match (row : Nat) (s : SerializedGateRow)
    (e : ExpectedGateRow) (h : checkGateRow row s e = .ok ()) :
    s.numOrConsts = some e.numOrConsts ∧ s.param2 = some e.param2 ∧ s.param3 = some e.param3 := by
  simp only [checkGateRow] at h
  split at h
  · cases h
  · repeat' (split at h; · cases h)
    have hall := first_error_ok_implies_mem _ h
    exact ⟨parameter_field_ok_matches row "numOrConsts" s.numOrConsts e.numOrConsts
        (hall _ (by simp [gateRowChecks])),
      parameter_field_ok_matches row "param2" s.param2 e.param2
        (hall _ (by simp [gateRowChecks])),
      parameter_field_ok_matches row "param3" s.param3 e.param3
        (hall _ (by simp [gateRowChecks]))⟩

theorem gate_row_ok_implies_layout_fits_and_matches (row : Nat) (s : SerializedGateRow)
    (e : ExpectedGateRow) (h : checkGateRow row s e = .ok ()) :
    (e.selectorIndex ≤ u8Max ∧ s.selectorIndex = some e.selectorIndex) ∧
    (e.groupStart ≤ u8Max ∧ s.groupStart = some e.groupStart) ∧
    (e.groupEnd ≤ u8Max ∧ s.groupEnd = some e.groupEnd) ∧
    (e.gateRowIndex ≤ u8Max ∧ s.gateRowIndex = some e.gateRowIndex) ∧
    (e.numConstraints ≤ u16Max ∧ s.numConstraints = some e.numConstraints) := by
  simp only [checkGateRow] at h
  split at h
  · cases h
  · repeat' (split at h; · cases h)
    have hall := first_error_ok_implies_mem _ h
    exact ⟨layout_field_ok_fits_and_matches row "selectorIndex" s.selectorIndex e.selectorIndex
        u8Max (hall _ (by simp [gateRowChecks])),
      layout_field_ok_fits_and_matches row "groupStart" s.groupStart e.groupStart u8Max
        (hall _ (by simp [gateRowChecks])),
      layout_field_ok_fits_and_matches row "groupEnd" s.groupEnd e.groupEnd u8Max
        (hall _ (by simp [gateRowChecks])),
      layout_field_ok_fits_and_matches row "gateRowIndex" s.gateRowIndex e.gateRowIndex u8Max
        (hall _ (by simp [gateRowChecks])),
      layout_field_ok_fits_and_matches row "numConstraints" s.numConstraints e.numConstraints
        u16Max (hall _ (by simp [gateRowChecks]))⟩

theorem gate_row_ok_implies_coset_envelope (row : Nat) (s : SerializedGateRow)
    (e : ExpectedGateRow) (h : checkGateRow row s e = .ok ())
    (hc : e.gateId = cosetInterpolationGateId) :
    cosetMinSubgroupBits ≤ e.numOrConsts ∧ e.numOrConsts ≤ cosetMaxSubgroupBits ∧
      cosetMinDegree ≤ e.param2 ∧ e.param2 ≤ 2 ^ e.numOrConsts := by
  simp only [checkGateRow] at h
  split at h
  · cases h
  · repeat' (split at h; · cases h)
    have hall := first_error_ok_implies_mem _ h
    have := hall (checkCosetEnvelope row e.gateId e.numOrConsts e.param2) (by simp [gateRowChecks])
    rw [hc] at this
    exact coset_envelope_ok_bounds row _ _ this

/-- Row iteration (lines 229-346). The length equality is checked first, so the ragged case is
unreachable from `checkFixtureJsonGates`; it is modelled as acceptance exactly as a `zip` would. -/
def checkGateRows : Nat → List SerializedGateRow → List ExpectedGateRow →
    Except GateGuardError Unit
  | _, [], [] => .ok ()
  | row, s :: ss, e :: es =>
    match checkGateRow row s e with
    | .error err => .error err
    | .ok _ => checkGateRows (row + 1) ss es
  | _, _, _ => .ok ()

theorem gate_rows_ok_head (row : Nat) (s : SerializedGateRow) (ss : List SerializedGateRow)
    (e : ExpectedGateRow) (es : List ExpectedGateRow)
    (h : checkGateRows row (s :: ss) (e :: es) = .ok ()) : checkGateRow row s e = .ok () := by
  simp only [checkGateRows] at h
  split at h
  · cases h
  · rename_i u hu; cases u; exact hu

theorem gate_rows_first_error_wins (row : Nat) (s : SerializedGateRow)
    (ss : List SerializedGateRow) (e : ExpectedGateRow) (es : List ExpectedGateRow)
    (err : GateGuardError) (h : checkGateRow row s e = .error err) :
    checkGateRows row (s :: ss) (e :: es) = .error err := by
  simp [checkGateRows, h]

/-- `check_fixture_json_gates` (lines 214-349). `gates : Option (List _)` models the
`get("gates").and_then(as_array)` lookup that fails when the fixture format changed. -/
def checkFixtureJsonGates (gates : Option (List SerializedGateRow))
    (expected : List ExpectedGateRow) : Except GateGuardError Unit :=
  match gates with
  | none => .error .noGatesArray
  | some rows =>
    if rows.length ≠ expected.length then
      .error (.rowCountMismatch rows.length expected.length)
    else checkGateRows 0 rows expected

theorem fixture_gates_row_count_checked_first (rows : List SerializedGateRow)
    (expected : List ExpectedGateRow) (h : rows.length ≠ expected.length) :
    checkFixtureJsonGates (some rows) expected =
      .error (.rowCountMismatch rows.length expected.length) := by
  simp [checkFixtureJsonGates, h]

theorem fixture_gates_missing_array_rejected (expected : List ExpectedGateRow) :
    checkFixtureJsonGates none expected = .error .noGatesArray := rfl

/-- A concrete accepting trace: one `ArithmeticGate`-shaped row that matches its circuit
derivation exactly. -/
def sampleExpectedRow : ExpectedGateRow :=
  { gateId := 0, selectorIndex := 1, groupStart := 0, groupEnd := 3, gateRowIndex := 2,
    numConstraints := 20, numOrConsts := 20, param2 := 0, param3 := 0 }

def sampleSerializedRow : SerializedGateRow :=
  { name := some "ArithmeticGate", gateId := some 0, numOrConsts := some 20, param2 := some 0,
    param3 := some 0, selectorIndex := some 1, groupStart := some 0, groupEnd := some 3,
    gateRowIndex := some 2, numConstraints := some 20 }

theorem fixture_gates_accepts_matching_row :
    checkFixtureJsonGates (some [sampleSerializedRow]) [sampleExpectedRow] = .ok () := rfl

theorem fixture_gates_rejects_sentinel_row :
    checkFixtureJsonGates (some [{ sampleSerializedRow with gateId := some 255 }])
      [sampleExpectedRow] = .error (.sentinelGate 0) := rfl

/-! ## 3. `check_v2_gate_rows` (lines 356-381): the production v2 guard -/

/-- A v2 config gate row as exported by the submodule. -/
structure V2GateRow where
  gateId : Nat
  numOrConsts : Nat
  param2 : Nat
  param3 : Nat
  deriving DecidableEq, Repr

def checkV2GateRow (row : Nat) (g : V2GateRow) : Except GateGuardError Unit :=
  if !(soliditySupportedGateIds.contains g.gateId) then .error (.unsupportedGate row g.gateId)
  else checkCosetEnvelope row g.gateId g.numOrConsts g.param2

def checkV2GateRows : Nat → List V2GateRow → Except GateGuardError Unit
  | _, [] => .ok ()
  | row, g :: gs =>
    match checkV2GateRow row g with
    | .error e => .error e
    | .ok _ => checkV2GateRows (row + 1) gs

theorem v2_gate_row_ok_implies_supported (row : Nat) (g : V2GateRow)
    (h : checkV2GateRow row g = .ok ()) : soliditySupportedGateIds.contains g.gateId = true := by
  simp only [checkV2GateRow] at h
  split at h
  · cases h
  · rename_i hmem; simpa using hmem

theorem v2_gate_rows_ok_head (row : Nat) (g : V2GateRow) (gs : List V2GateRow)
    (h : checkV2GateRows row (g :: gs) = .ok ()) : checkV2GateRow row g = .ok () := by
  simp only [checkV2GateRows] at h
  split at h
  · cases h
  · rename_i u hu; cases u; exact hu

/-- HONEST SCOPE. Unlike the v1 guard, the v2 guard checks only gate-id membership plus the
CosetInterpolation envelope: for any non-coset gate id it accepts every parameter triple. The
field-for-field re-derivation of `numOrConsts`/`param2`/`param3` lives in the submodule
exporter (a boundary), not in this repository-level check. -/
theorem v2_gate_check_does_not_pin_non_coset_parameters (row a b c : Nat) :
    checkV2GateRow row { gateId := 0, numOrConsts := a, param2 := b, param3 := c } = .ok () := by
  simp [checkV2GateRow, checkCosetEnvelope, cosetInterpolationGateId]
  decide

theorem v2_gate_check_enforces_coset_envelope (row : Nat) (b c : Nat) :
    checkV2GateRow row { gateId := 13, numOrConsts := 6, param2 := b, param3 := c } =
      .error (.cosetSubgroupBitsOutsideEnvelope row 6) := by
  simp [checkV2GateRow, checkCosetEnvelope, cosetInterpolationGateId, cosetMinSubgroupBits,
    cosetMaxSubgroupBits]
  decide

/-! ## 4. Deployment-configuration artifacts (lines 383-769)

Every submodule codec is a PARAMETER here: `parseConfig` models
`MleVerifierV2ConfigFixture::from_canonical_json`, `toJson` models `to_canonical_json`, and
`parseJson` models `serde_json::from_str`. None of their internals are modelled. -/

/-- A `bytes` + recorded `byteLength` + recorded `keccak256` record, as carried by
`compactProof`, `solidityAbiProof` and `solidityAbiVerificationConfig`. -/
structure EncodedRecord where
  label : String
  byteLength : Nat
  keccak : Bytes
  bytes : Bytes
  deriving DecidableEq

/-- The documented contract of the submodule's `decode_and_validate`: the recorded encoding
label, the recorded byte length and the recorded Keccak digest must all authenticate the bytes.
The submodule implementation itself is a boundary. -/
def decodeAndValidate (keccakOf : Bytes → Bytes) (r : EncodedRecord) (expectedLabel : String) :
    Except String Bytes :=
  if r.label ≠ expectedLabel then .error "encoding label mismatch"
  else if r.byteLength ≠ r.bytes.length then .error "recorded byte length mismatch"
  else if r.keccak ≠ keccakOf r.bytes then .error "recorded keccak digest mismatch"
  else .ok r.bytes

theorem decode_and_validate_ok_binds_label_length_and_digest (keccakOf : Bytes → Bytes)
    (r : EncodedRecord) (label : String) (bytes : Bytes)
    (h : decodeAndValidate keccakOf r label = .ok bytes) :
    r.label = label ∧ r.byteLength = bytes.length ∧ r.keccak = keccakOf bytes ∧
      r.bytes = bytes := by
  simp only [decodeAndValidate] at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · rename_i hl hlen hk
        injection h with hb
        subst hb
        exact ⟨Decidable.of_not_not hl, Decidable.of_not_not hlen, Decidable.of_not_not hk, rfl⟩

/-- The proof-free, circuit-derived deployment configuration. -/
structure ConfigBody where
  circuitDigest : Bytes
  gates : List V2GateRow
  publicInputWireMap : List Nat
  deriving DecidableEq

structure ConfigFixture where
  body : ConfigBody
  solidityAbiVerificationConfig : EncodedRecord
  pinnedVerificationConfigDigest : Bytes
  deriving DecidableEq

structure ProofView where
  publicInputs : List Nat
  payload : Bytes
  deriving DecidableEq

structure FullFixture where
  config : ConfigFixture
  proof : ProofView
  compactProof : EncodedRecord
  compactShape : Shape
  solidityAbiProof : EncodedRecord
  deriving DecidableEq

inductive ConfigExportError where
  | derivationRefused (message : String)
  | gateGuard (error : GateGuardError)
  | canonicalJsonFailed (message : String)
  deriving DecidableEq

/-- `export_mle_v2_config_json` (lines 384-400). The gate guard runs BEFORE the canonical JSON
is produced, so a circuit carrying a gate the deployed Ext3 evaluator lacks never yields an
artifact at all. -/
def exportMleV2ConfigJson (derived : Except String ConfigFixture)
    (toJson : ConfigFixture → Except String String) : Except ConfigExportError String :=
  match derived with
  | .error m => .error (.derivationRefused m)
  | .ok fixture =>
    match checkV2GateRows 0 fixture.body.gates with
    | .error e => .error (.gateGuard e)
    | .ok _ =>
      match toJson fixture with
      | .error m => .error (.canonicalJsonFailed m)
      | .ok json => .ok json

theorem export_config_gate_guard_precedes_serialisation (fixture : ConfigFixture)
    (toJson : ConfigFixture → Except String String) (e : GateGuardError)
    (h : checkV2GateRows 0 fixture.body.gates = .error e) :
    exportMleV2ConfigJson (.ok fixture) toJson = .error (.gateGuard e) := by
  simp [exportMleV2ConfigJson, h]

theorem export_config_derivation_refusal_propagates (m : String)
    (toJson : ConfigFixture → Except String String) :
    exportMleV2ConfigJson (.error m) toJson = .error (.derivationRefused m) := rfl

theorem export_config_ok_implies_gates_accepted (fixture : ConfigFixture)
    (toJson : ConfigFixture → Except String String) (json : String)
    (h : exportMleV2ConfigJson (.ok fixture) toJson = .ok json) :
    checkV2GateRows 0 fixture.body.gates = .ok () ∧ toJson fixture = .ok json := by
  simp only [exportMleV2ConfigJson] at h
  split at h
  · cases h
  · rename_i hu
    split at h
    · cases h
    · rename_i hj
      injection h with h'
      exact ⟨hu, by rw [hj, h']⟩

/-! ### 4.1 Generator mode switches (lines 402-428) -/

def mleV2ConfigOnlyFlag : String := "--mle-config-only"
def mleV3ConfigCutoverEnv : String := "MLE_ALLOW_WIRE_V3_CONFIG_CUTOVER"

theorem generator_switches_pinned :
    mleV2ConfigOnlyFlag = "--mle-config-only" ∧
      mleV3ConfigCutoverEnv = "MLE_ALLOW_WIRE_V3_CONFIG_CUTOVER" := ⟨rfl, rfl⟩

def mleV2ConfigOnlyRequested (args : List String) : Bool :=
  args.any (fun a => a == mleV2ConfigOnlyFlag)

/-- `std::env::var_os(..).is_some_and(|v| v == OsStr::new("1"))` — only the exact value `1`
enables the one-release cutover. -/
def allowV3Cutover : Option String → Bool
  | none => false
  | some v => v == "1"

theorem cutover_env_requires_the_exact_value_one :
    allowV3Cutover none = false ∧ allowV3Cutover (some "0") = false ∧
      allowV3Cutover (some "true") = false ∧ allowV3Cutover (some "1") = true := by
  refine ⟨rfl, ?_, ?_, ?_⟩ <;> simp [allowV3Cutover]

/-! ### 4.2 The reviewed wire-v2 -> wire-v3 cutover (lines 626-712) -/

inductive JsonVal where
  | str (s : String)
  | num (n : Nat)
  | other (tag : String)
  deriving DecidableEq

/-- A parsed document, viewed only through JSON-pointer lookups. -/
abbrev JsonDoc := String → Option JsonVal

def asStr : Option JsonVal → Option String
  | some (.str s) => some s
  | _ => none

def asNat : Option JsonVal → Option Nat
  | some (.num n) => some n
  | _ => none

/-- Retired wire-v2 / PoW-20 identity (lines 644-666). -/
def retiredConfigSchema : String := "plonky2-mle-v2-solidity-config"
def retiredSchemaVersion : Nat := 2
def retiredProtocolVersion : Nat := 2
def retiredCompactProofEncoding : String := "MLEWHIR2"
def retiredWhirPowBits : Nat := 20

/-- Reviewed wire-v3 / PoW-22 identity (lines 667-689). -/
def currentConfigSchema : String := "plonky2-mle-v3-solidity-config"
def currentSchemaVersion : Nat := 3
def currentProtocolVersion : Nat := 3
def currentCompactProofEncoding : String := "MLEWHIR3"
def currentWhirPowBits : Nat := 22

theorem retired_identity_pinned :
    retiredConfigSchema = "plonky2-mle-v2-solidity-config" ∧ retiredSchemaVersion = 2 ∧
      retiredProtocolVersion = 2 ∧ retiredCompactProofEncoding = "MLEWHIR2" ∧
      retiredWhirPowBits = 20 := ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem current_identity_pinned :
    currentConfigSchema = "plonky2-mle-v3-solidity-config" ∧ currentSchemaVersion = 3 ∧
      currentProtocolVersion = 3 ∧ currentCompactProofEncoding = "MLEWHIR3" ∧
      currentWhirPowBits = 22 := ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- The WHIR proof-of-work bits move from 20 to 22 across the cutover; both are pinned
literals, so a WHIR profile change is a different (fresh-cohort) operation. -/
theorem cutover_changes_whir_pow_bits : retiredWhirPowBits ≠ currentWhirPowBits := by decide

def retiredIdentityOk (d : JsonDoc) : Bool :=
  asStr (d "/schema") == some retiredConfigSchema &&
  asNat (d "/schemaVersion") == some retiredSchemaVersion &&
  asNat (d "/protocolVersion") == some retiredProtocolVersion &&
  asStr (d "/compactProofEncoding") == some retiredCompactProofEncoding &&
  asNat (d "/whirPowBits") == some retiredWhirPowBits

def currentIdentityOk (d : JsonDoc) : Bool :=
  asStr (d "/schema") == some currentConfigSchema &&
  asNat (d "/schemaVersion") == some currentSchemaVersion &&
  asNat (d "/protocolVersion") == some currentProtocolVersion &&
  asStr (d "/compactProofEncoding") == some currentCompactProofEncoding &&
  asNat (d "/whirPowBits") == some currentWhirPowBits

/-- The twelve pointers whose equality means "the same underlying circuit" (lines 691-704). -/
def circuitIdentityPointers : List String :=
  [ "/verificationConfig/circuit",
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
    "/verificationKey/subgroupGenPowers" ]

theorem circuit_identity_pointer_count : circuitIdentityPointers.length = 12 := rfl

/-- `existing.pointer(p).is_some() && existing.pointer(p) == generated.pointer(p)`. -/
def circuitIdentityAgreesAt (e g : JsonDoc) (p : String) : Bool :=
  (e p).isSome && (e p == g p)

theorem circuit_identity_agrees_iff (e g : JsonDoc) (p : String) :
    circuitIdentityAgreesAt e g p = true ↔ ((e p).isSome = true ∧ e p = g p) := by
  simp [circuitIdentityAgreesAt]

def circuitIdentityDriftAt (e g : JsonDoc) : Option String :=
  circuitIdentityPointers.find? (fun p => !circuitIdentityAgreesAt e g p)

theorem find_forall_none {α : Type} (p : α → Bool) :
    ∀ l : List α, (∀ a ∈ l, p a = false) → l.find? p = none := by
  intro l
  induction l with
  | nil => intro _; rfl
  | cons x xs ih =>
    intro h
    rw [List.find?, h x (by simp)]
    simp only
    exact ih (fun a ha => h a (by simp [ha]))

inductive CutoverError where
  | notCanonicalConfigArtifact
  | legacyNotJson
  | generatedNotJson
  | retiredIdentityDrift
  | currentIdentityDrift
  | circuitIdentityDrift (pointer : String)
  deriving DecidableEq

def isCanonicalConfigFileName (n : String) : Bool :=
  n.endsWith "_mle_config.json" || n == "mle_fixture_config.json"

/-- Lines 644-710: retired identity, then reviewed identity, then the twelve circuit pointers. -/
def cutoverIdentityCheck (e g : JsonDoc) : Except CutoverError Unit :=
  if !retiredIdentityOk e then .error .retiredIdentityDrift
  else if !currentIdentityOk g then .error .currentIdentityDrift
  else
    match circuitIdentityDriftAt e g with
    | some p => .error (.circuitIdentityDrift p)
    | none => .ok ()

/-- `validate_protocol_v2_config_cutover` (lines 629-712). Order: file-name envelope, then both
parses, then the identity/circuit checks. -/
def validateProtocolV2ConfigCutover (fileName : String) (existing generated : Option JsonDoc) :
    Except CutoverError Unit :=
  if !isCanonicalConfigFileName fileName then .error .notCanonicalConfigArtifact
  else
    match existing, generated with
    | none, _ => .error .legacyNotJson
    | _, none => .error .generatedNotJson
    | some e, some g => cutoverIdentityCheck e g

theorem cutover_file_name_checked_first (fileName : String) (existing generated : Option JsonDoc)
    (h : isCanonicalConfigFileName fileName = false) :
    validateProtocolV2ConfigCutover fileName existing generated =
      .error .notCanonicalConfigArtifact := by
  simp [validateProtocolV2ConfigCutover, h]

theorem cutover_named_artifact_reduces_to_identity_check (fileName : String) (e g : JsonDoc)
    (h : isCanonicalConfigFileName fileName = true) :
    validateProtocolV2ConfigCutover fileName (some e) (some g) = cutoverIdentityCheck e g := by
  simp [validateProtocolV2ConfigCutover, h]

theorem cutover_identity_ok_implies_pins (e g : JsonDoc)
    (h : cutoverIdentityCheck e g = .ok ()) :
    retiredIdentityOk e = true ∧ currentIdentityOk g = true ∧
      ∀ p ∈ circuitIdentityPointers, circuitIdentityAgreesAt e g p = true := by
  simp only [cutoverIdentityCheck] at h
  split at h
  · cases h
  · rename_i hr
    split at h
    · cases h
    · rename_i hc
      split at h
      · cases h
      · rename_i hdrift
        refine ⟨by simpa using hr, by simpa using hc, ?_⟩
        intro p hp
        have hfalse := find_none_forall _ circuitIdentityPointers hdrift p hp
        simpa using hfalse

/-- Whatever the cutover accepts, it accepts BECAUSE those twelve pointers agree: any document
pair that agrees there and carries the two pinned identities is admitted, no matter how it
differs elsewhere. `publicInputWireMap`, the layout pins, the protocol/session values and the
encoded-config bytes are deliberately outside the pinned set — a cutover may change them. -/
theorem cutover_accepts_when_only_unpinned_fields_differ (e g : JsonDoc)
    (hr : retiredIdentityOk e = true) (hc : currentIdentityOk g = true)
    (hp : ∀ p ∈ circuitIdentityPointers, circuitIdentityAgreesAt e g p = true) :
    cutoverIdentityCheck e g = .ok () := by
  have hdrift : circuitIdentityDriftAt e g = none := by
    refine find_forall_none _ circuitIdentityPointers (fun p hp' => ?_)
    simp [hp p hp']
  simp [cutoverIdentityCheck, hr, hc, hdrift]

theorem public_input_wire_map_is_not_a_pinned_circuit_identity :
    "/verificationKey/publicInputWireMap" ∉ circuitIdentityPointers ∧
      "/verificationConfig/publicInputWireMap" ∉ circuitIdentityPointers := by decide

/-! ### 4.3 create-once / compare-later persistence (lines 416-476) -/

inductive ConfigReadResult where
  | contents (json : String)
  | notFound
  | ioError (message : String)
  deriving DecidableEq

inductive PersistAction where
  | keptExistingIdentical
  | createdNew
  | atomicallyReplaced (json : String)
  deriving DecidableEq

inductive PersistError where
  | generatedNotCanonical (message : String)
  | existingDiffers (path : String)
  | existingNotStrictCurrent (path : String) (message : String)
  | cutoverRefused (path : String) (error : CutoverError)
  | readFailed (path : String) (message : String)
  deriving DecidableEq

/-- `persist_or_validate_mle_v2_config_json_inner` (lines 430-476). -/
def persistOrValidateMleV2ConfigJsonInner (parseConfig : String → Except String ConfigFixture)
    (parseJson : String → Option JsonDoc) (path fileName : String) (read : ConfigReadResult)
    (generatedJson : String) (allowCutover : Bool) : Except PersistError PersistAction :=
  match parseConfig generatedJson with
  | .error m => .error (.generatedNotCanonical m)
  | .ok generated =>
    match read with
    | .contents existingJson =>
      match parseConfig existingJson with
      | .ok existing =>
        if existing = generated ∧ existingJson = generatedJson then .ok .keptExistingIdentical
        else .error (.existingDiffers path)
      | .error parseError =>
        if allowCutover then
          match validateProtocolV2ConfigCutover fileName (parseJson existingJson)
              (parseJson generatedJson) with
          | .error e => .error (.cutoverRefused path e)
          | .ok _ => .ok (.atomicallyReplaced generatedJson)
        else .error (.existingNotStrictCurrent path parseError)
    | .notFound => .ok .createdNew
    | .ioError m => .error (.readFailed path m)

/-- The generated document is parsed first: nothing on disk is read when the generator's own
canonical JSON is not strict. -/
theorem persist_parses_generated_before_touching_disk
    (parseConfig : String → Except String ConfigFixture) (parseJson : String → Option JsonDoc)
    (path fileName : String) (read : ConfigReadResult) (generatedJson : String)
    (allowCutover : Bool) (m : String) (h : parseConfig generatedJson = .error m) :
    persistOrValidateMleV2ConfigJsonInner parseConfig parseJson path fileName read generatedJson
      allowCutover = .error (.generatedNotCanonical m) := by
  simp [persistOrValidateMleV2ConfigJsonInner, h]

/-- A replacement happens only for a parseable-generated / unparseable-existing pair, only with
the explicit one-release switch on, and only after the reviewed cutover validation accepted. -/
theorem persist_replacement_requires_validated_cutover
    (parseConfig : String → Except String ConfigFixture) (parseJson : String → Option JsonDoc)
    (path fileName existingJson generatedJson j : String) (allowCutover : Bool)
    (h : persistOrValidateMleV2ConfigJsonInner parseConfig parseJson path fileName
      (.contents existingJson) generatedJson allowCutover = .ok (.atomicallyReplaced j)) :
    allowCutover = true ∧ j = generatedJson ∧
      validateProtocolV2ConfigCutover fileName (parseJson existingJson)
        (parseJson generatedJson) = .ok () := by
  simp only [persistOrValidateMleV2ConfigJsonInner] at h
  split at h
  · cases h
  · split at h
    · split at h
      · cases h
      · cases h
    · split at h
      · rename_i hallow
        split at h
        · cases h
        · rename_i hu
          refine ⟨hallow, ?_, hu⟩
          simp only [Except.ok.injEq, PersistAction.atomicallyReplaced.injEq] at h
          exact h.symm
      · cases h

/-- Ordinary generation is create-once / compare-only: without the explicit switch an existing
artifact is never replaced. -/
theorem persist_contents_never_replaced_without_the_explicit_switch
    (parseConfig : String → Except String ConfigFixture) (parseJson : String → Option JsonDoc)
    (path fileName existingJson generatedJson j : String) :
    persistOrValidateMleV2ConfigJsonInner parseConfig parseJson path fileName
      (.contents existingJson) generatedJson false ≠ .ok (.atomicallyReplaced j) := by
  intro h
  exact Bool.noConfusion
    (persist_replacement_requires_validated_cutover parseConfig parseJson path fileName
      existingJson generatedJson j false h).1

/-- Accepting an artifact already on disk requires BYTE equality, not merely a document that
parses to the same configuration. -/
theorem persist_keeps_existing_only_on_exact_bytes
    (parseConfig : String → Except String ConfigFixture) (parseJson : String → Option JsonDoc)
    (path fileName existingJson generatedJson : String) (allowCutover : Bool)
    (h : persistOrValidateMleV2ConfigJsonInner parseConfig parseJson path fileName
      (.contents existingJson) generatedJson allowCutover = .ok .keptExistingIdentical) :
    existingJson = generatedJson ∧ parseConfig existingJson = parseConfig generatedJson := by
  simp only [persistOrValidateMleV2ConfigJsonInner] at h
  split at h
  · cases h
  · rename_i generated hgen
    split at h
    · rename_i existing hex
      split at h
      · rename_i heq
        exact ⟨heq.2, by rw [hex, hgen, heq.1]⟩
      · cases h
    · split at h
      · split at h
        · cases h
        · cases h
      · cases h

/-- An absent artifact is created; the read error path is never silently treated as absence. -/
theorem persist_missing_artifact_is_created
    (parseConfig : String → Except String ConfigFixture) (parseJson : String → Option JsonDoc)
    (path fileName generatedJson : String) (allowCutover : Bool) (generated : ConfigFixture)
    (h : parseConfig generatedJson = .ok generated) :
    persistOrValidateMleV2ConfigJsonInner parseConfig parseJson path fileName .notFound
      generatedJson allowCutover = .ok .createdNew := by
  simp [persistOrValidateMleV2ConfigJsonInner, h]

theorem persist_read_error_is_not_absence
    (parseConfig : String → Except String ConfigFixture) (parseJson : String → Option JsonDoc)
    (path fileName generatedJson m : String) (allowCutover : Bool) (generated : ConfigFixture)
    (h : parseConfig generatedJson = .ok generated) :
    persistOrValidateMleV2ConfigJsonInner parseConfig parseJson path fileName (.ioError m)
      generatedJson allowCutover = .error (.readFailed path m) := by
  simp [persistOrValidateMleV2ConfigJsonInner, h]

/-! ### 4.4 The no-clobber publish and its staging discipline (lines 486-624, 714-769) -/

def configStagingAttempts : Nat := 64
def cutoverStagingAttempts : Nat := 32

theorem staging_attempt_counts_pinned :
    configStagingAttempts = 64 ∧ cutoverStagingAttempts = 32 := by decide

inductive PublishError where
  | concurrentTargetNotRegularFile
  | concurrentDifferentBytes
  | stagingUnavailable
  | stagingWriteFailed
  | interruptedBeforePublish
  | cleanupFailed
  | publishAndCleanupFailed
  deriving DecidableEq

/-- `create_new_or_validate_config`'s publish step (lines 552-565, 586-624). `target` is the
state of the path at the moment `hard_link` runs: `none` when it does not exist (the link
succeeds), otherwise its regular-file flag and its complete bytes. -/
def publishNoClobber (contents : String) (target : Option (Bool × String)) :
    Except PublishError Unit :=
  match target with
  | none => .ok ()
  | some (isRegularFile, existing) =>
    if !isRegularFile then .error .concurrentTargetNotRegularFile
    else if existing ≠ contents then .error .concurrentDifferentBytes
    else .ok ()

theorem publish_never_overwrites_differing_bytes (contents existing : String)
    (h : existing ≠ contents) :
    publishNoClobber contents (some (true, existing)) = .error .concurrentDifferentBytes := by
  simp [publishNoClobber, h]

theorem publish_accepts_only_identical_concurrent_bytes (contents : String)
    (isRegularFile : Bool) (existing : String)
    (h : publishNoClobber contents (some (isRegularFile, existing)) = .ok ()) :
    isRegularFile = true ∧ existing = contents := by
  simp only [publishNoClobber] at h
  split at h
  · cases h
  · rename_i hreg
    split at h
    · cases h
    · rename_i hbytes
      exact ⟨by simpa using hreg, Decidable.of_not_not hbytes⟩

/-- Lines 576-583: the publish result and the staging-cleanup result are combined, so a
successful publish followed by a failed cleanup is still reported as an error. -/
def combinePublishAndCleanup (publish cleanup : Except PublishError Unit) :
    Except PublishError Unit :=
  match publish, cleanup with
  | .ok _, .ok _ => .ok ()
  | .error e, .ok _ => .error e
  | .ok _, .error c => .error c
  | .error _, .error _ => .error .publishAndCleanupFailed

theorem create_config_ok_iff_publish_and_cleanup_ok (publish cleanup : Except PublishError Unit) :
    combinePublishAndCleanup publish cleanup = .ok () ↔ publish = .ok () ∧ cleanup = .ok () := by
  constructor
  · intro h
    cases publish with
    | error e => cases cleanup <;> cases h
    | ok u =>
      cases u
      cases cleanup with
      | error c => cases h
      | ok v => cases v; exact ⟨rfl, rfl⟩
  · intro h
    rw [h.1, h.2]
    rfl

/-- Staging-file allocation: the first free nonce below the attempt budget, or failure. -/
def allocateStagingNonce (attempts : Nat) (taken : Nat → Bool) : Option Nat :=
  (List.range attempts).find? (fun n => !(taken n))

theorem staging_allocation_fails_when_every_nonce_is_taken (attempts : Nat) :
    allocateStagingNonce attempts (fun _ => true) = none := by
  refine find_forall_none _ (List.range attempts) (fun a _ => ?_)
  simp

/-! ## 5. The compact proof: the one calldata / Proof-DA payload (lines 771-949)

`MleEnv` collects every `plonky2_mle` operation this file calls. They are parameters, never
definitions: the model proves how `mle_prover.rs` COMBINES them, not what they compute. -/

structure MleEnv where
  /-- `keccak_hash::keccak`. Opaque; no injectivity is used anywhere. -/
  keccak : Bytes → Bytes
  /-- `MAX_COMPACT_PROOF_BYTES_V2`. -/
  maxCompactProofBytes : Nat
  /-- `COMPACT_MAGIC_V2`, read as UTF-8 (line 896). -/
  compactMagic : String
  /-- `SOLIDITY_MLE_PROOF_ENCODING_V2`. -/
  solidityProofEncoding : String
  /-- `SOLIDITY_MLE_VERIFICATION_CONFIG_ENCODING_V2`. -/
  solidityConfigEncoding : String
  parseFull : String → Except String FullFixture
  parseConfig : String → Except String ConfigFixture
  decodeCompact : Bytes → Shape → Except String ProofView
  encodeCompact : ProofView → Shape → Except String Bytes
  /-- `MleProofV2Fixture::encode`: the structured JSON view of a decoded proof. -/
  encodeProofFixture : ProofView → ProofView
  abiEncodeProof : ProofView → Except String Bytes
  abiEncodeConfig : ConfigBody → Except String Bytes

inductive MleError where
  | fullNotCanonical (message : String)
  | configNotCanonical (message : String)
  | configFixtureDiffers
  | compactIntegrity (message : String)
  | compactLengthOutsideEnvelope (length : Nat)
  | compactGrammar (message : String)
  | compactReencodingFailed (message : String)
  | compactNotUniqueCanonicalEncoding
  | structuredProofDisagrees
  | proofAbiIntegrity (message : String)
  | proofAbiReencodingFailed (message : String)
  | proofAbiNotCanonical
  | configAbiIntegrity (message : String)
  | configAbiReencodingFailed (message : String)
  | configAbiNotCanonical
  | pinnedConfigDigestDisagrees
  | compactLengthDoesNotFitU32
  | circuitConfigDiffers
  | gateGuard (error : GateGuardError)
  | nativeVerificationFailed (message : String)
  | fullExportRefused (message : String)
  | configDerivationFailed (message : String)
  | canonicalJsonFailed (message : String)
  | canonicalJsonRoundTripChanged
  deriving DecidableEq

/-- `compact_mle_v2_bytes_from_fixture` (lines 895-908): authenticate the record, then bound the
length by `1..=MAX_COMPACT_PROOF_BYTES_V2`. -/
def compactMleV2BytesFromFixture (env : MleEnv) (full : FullFixture) : Except MleError Bytes :=
  match decodeAndValidate env.keccak full.compactProof env.compactMagic with
  | .error m => .error (.compactIntegrity m)
  | .ok compact =>
    if compact.length = 0 ∨ compact.length > env.maxCompactProofBytes then
      .error (.compactLengthOutsideEnvelope compact.length)
    else .ok compact

theorem compact_bytes_ok_binds_magic_length_and_digest (env : MleEnv) (full : FullFixture)
    (compact : Bytes) (h : compactMleV2BytesFromFixture env full = .ok compact) :
    full.compactProof.label = env.compactMagic ∧
      full.compactProof.byteLength = compact.length ∧
      full.compactProof.keccak = env.keccak compact ∧
      0 < compact.length ∧ compact.length ≤ env.maxCompactProofBytes := by
  simp only [compactMleV2BytesFromFixture] at h
  split at h
  · cases h
  · rename_i bytes hrec
    split at h
    · cases h
    · rename_i henv
      injection h with hb
      subst hb
      obtain ⟨hl, hlen, hk, _⟩ := decode_and_validate_ok_binds_label_length_and_digest
        env.keccak full.compactProof env.compactMagic bytes hrec
      simp only [not_or, Nat.not_lt] at henv
      exact ⟨hl, hlen, hk, Nat.pos_of_ne_zero henv.1, by omega⟩

/-- `validate_mle_v2_full_against_config_json` (lines 779-844). The check order is exactly the
source's: canonical parses, then full-vs-config configuration equality, then the compact record,
then the compact grammar/canonicity, then the structured view, then the two Solidity ABI views,
then the pinned verification-config digest. -/
def validateMleV2FullAgainstConfigJson (env : MleEnv) (fullJson configJson : String) :
    Except MleError Bytes :=
  match env.parseFull fullJson with
  | .error m => .error (.fullNotCanonical m)
  | .ok full =>
    match env.parseConfig configJson with
    | .error m => .error (.configNotCanonical m)
    | .ok config =>
      if full.config ≠ config then .error .configFixtureDiffers
      else
        match compactMleV2BytesFromFixture env full with
        | .error e => .error e
        | .ok compact =>
          match env.decodeCompact compact full.compactShape with
          | .error m => .error (.compactGrammar m)
          | .ok decoded =>
            match env.encodeCompact decoded full.compactShape with
            | .error m => .error (.compactReencodingFailed m)
            | .ok reencoded =>
              if reencoded ≠ compact then .error .compactNotUniqueCanonicalEncoding
              else if env.encodeProofFixture decoded ≠ full.proof then
                .error .structuredProofDisagrees
              else
                match decodeAndValidate env.keccak full.solidityAbiProof
                    env.solidityProofEncoding with
                | .error m => .error (.proofAbiIntegrity m)
                | .ok recordedProofAbi =>
                  match env.abiEncodeProof full.proof with
                  | .error m => .error (.proofAbiReencodingFailed m)
                  | .ok canonicalProofAbi =>
                    if recordedProofAbi ≠ canonicalProofAbi then .error .proofAbiNotCanonical
                    else
                      match decodeAndValidate env.keccak config.solidityAbiVerificationConfig
                          env.solidityConfigEncoding with
                      | .error m => .error (.configAbiIntegrity m)
                      | .ok recordedConfigAbi =>
                        match env.abiEncodeConfig config.body with
                        | .error m => .error (.configAbiReencodingFailed m)
                        | .ok canonicalConfigAbi =>
                          if recordedConfigAbi ≠ canonicalConfigAbi then
                            .error .configAbiNotCanonical
                          else if config.pinnedVerificationConfigDigest ≠
                              config.solidityAbiVerificationConfig.keccak then
                            .error .pinnedConfigDigestDisagrees
                          else .ok compact

/-- One extraction of everything the acceptance establishes; the corollaries below are named
views of it. -/
theorem validate_full_ok_extracts (env : MleEnv) (fullJson configJson : String) (compact : Bytes)
    (h : validateMleV2FullAgainstConfigJson env fullJson configJson = .ok compact) :
    ∃ full config decoded,
      env.parseFull fullJson = .ok full ∧
      env.parseConfig configJson = .ok config ∧
      full.config = config ∧
      compactMleV2BytesFromFixture env full = .ok compact ∧
      env.decodeCompact compact full.compactShape = .ok decoded ∧
      env.encodeCompact decoded full.compactShape = .ok compact ∧
      env.encodeProofFixture decoded = full.proof ∧
      decodeAndValidate env.keccak full.solidityAbiProof env.solidityProofEncoding =
        env.abiEncodeProof full.proof ∧
      decodeAndValidate env.keccak config.solidityAbiVerificationConfig
        env.solidityConfigEncoding = env.abiEncodeConfig config.body ∧
      config.pinnedVerificationConfigDigest = config.solidityAbiVerificationConfig.keccak := by
  simp only [validateMleV2FullAgainstConfigJson] at h
  split at h
  · cases h
  · rename_i full hfull
    split at h
    · cases h
    · rename_i config hconfig
      split at h
      · cases h
      · rename_i hcfg
        split at h
        · cases h
        · rename_i compact' hcompact
          split at h
          · cases h
          · rename_i decoded hdecoded
            split at h
            · cases h
            · rename_i reencoded hreencoded
              split at h
              · cases h
              · rename_i hcanon
                split at h
                · cases h
                · rename_i hstruct
                  split at h
                  · cases h
                  · rename_i recordedProofAbi hrecProof
                    split at h
                    · cases h
                    · rename_i canonicalProofAbi hcanProof
                      split at h
                      · cases h
                      · rename_i hproofAbi
                        split at h
                        · cases h
                        · rename_i recordedConfigAbi hrecConfig
                          split at h
                          · cases h
                          · rename_i canonicalConfigAbi hcanConfig
                            split at h
                            · cases h
                            · rename_i hconfigAbi
                              split at h
                              · cases h
                              · rename_i hdigest
                                injection h with hc
                                subst hc
                                refine ⟨full, config, decoded, hfull, hconfig,
                                  Decidable.of_not_not hcfg, hcompact, hdecoded, ?_, ?_, ?_, ?_,
                                  Decidable.of_not_not hdigest⟩
                                · rw [hreencoded, Decidable.of_not_not hcanon]
                                · exact Decidable.of_not_not hstruct
                                · rw [hrecProof, hcanProof, Decidable.of_not_not hproofAbi]
                                · rw [hrecConfig, hcanConfig, Decidable.of_not_not hconfigAbi]

/-- The accepted bytes are the UNIQUE canonical encoding of a proof that actually decodes: the
compact stream is re-decoded and re-encoded with the pinned shape and must come back identical. -/
theorem validate_full_ok_compact_is_the_unique_canonical_encoding (env : MleEnv)
    (fullJson configJson : String) (compact : Bytes)
    (h : validateMleV2FullAgainstConfigJson env fullJson configJson = .ok compact) :
    ∃ full decoded, env.parseFull fullJson = .ok full ∧
      env.decodeCompact compact full.compactShape = .ok decoded ∧
      env.encodeCompact decoded full.compactShape = .ok compact := by
  obtain ⟨full, _, decoded, hfull, _, _, _, hdec, henc, _, _, _, _⟩ :=
    validate_full_ok_extracts env fullJson configJson compact h
  exact ⟨full, decoded, hfull, hdec, henc⟩

/-- PUBLIC-INPUT PLUMBING. The JSON's structured `proof` view — the one a human or a tool reads,
including its `publicInputs` — is required to be the re-encoding of the proof carried by the
authoritative compact bytes. Editing the readable view without the stream is rejected. -/
theorem validate_full_ok_public_inputs_come_from_the_compact_bytes (env : MleEnv)
    (fullJson configJson : String) (compact : Bytes)
    (h : validateMleV2FullAgainstConfigJson env fullJson configJson = .ok compact) :
    ∃ full decoded, env.parseFull fullJson = .ok full ∧
      env.decodeCompact compact full.compactShape = .ok decoded ∧
      (env.encodeProofFixture decoded).publicInputs = full.proof.publicInputs := by
  obtain ⟨full, _, decoded, hfull, _, _, _, hdec, _, hstruct, _, _, _⟩ :=
    validate_full_ok_extracts env fullJson configJson compact h
  exact ⟨full, decoded, hfull, hdec, by rw [hstruct]⟩

/-- The pinned constructor-argument digest equals the Keccak of the canonical ABI bytes of the
very configuration the artifact carries. -/
theorem validate_full_ok_pins_verification_config_digest (env : MleEnv)
    (fullJson configJson : String) (compact : Bytes)
    (h : validateMleV2FullAgainstConfigJson env fullJson configJson = .ok compact) :
    ∃ config, env.parseConfig configJson = .ok config ∧
      config.pinnedVerificationConfigDigest = config.solidityAbiVerificationConfig.keccak ∧
      decodeAndValidate env.keccak config.solidityAbiVerificationConfig
        env.solidityConfigEncoding = env.abiEncodeConfig config.body := by
  obtain ⟨_, config, _, _, hconfig, _, _, _, _, _, _, hcfgAbi, hdigest⟩ :=
    validate_full_ok_extracts env fullJson configJson compact h
  exact ⟨config, hconfig, hdigest, hcfgAbi⟩

/-- The full artifact's embedded configuration must be the separately persisted deployment
config; this is checked BEFORE any compact byte is looked at. -/
theorem validate_full_rejects_config_mismatch (env : MleEnv) (fullJson configJson : String)
    (full : FullFixture) (config : ConfigFixture) (hf : env.parseFull fullJson = .ok full)
    (hc : env.parseConfig configJson = .ok config) (hne : full.config ≠ config) :
    validateMleV2FullAgainstConfigJson env fullJson configJson = .error .configFixtureDiffers := by
  simp [validateMleV2FullAgainstConfigJson, hf, hc, hne]

/-- `mle_v2_compact_submission_metadata` (lines 851-860): the submission commitment is
`keccak256(compactProof.bytes)` over the VALIDATED bytes plus their exact length. JSON bytes are
never hashed. -/
def mleV2CompactSubmissionMetadata (env : MleEnv) (fullJson configJson : String) :
    Except MleError (Bytes × Nat) :=
  match validateMleV2FullAgainstConfigJson env fullJson configJson with
  | .error e => .error e
  | .ok compact =>
    if compact.length > u32Max then .error .compactLengthDoesNotFitU32
    else .ok (env.keccak compact, compact.length)

theorem submission_metadata_is_keccak_of_validated_compact_bytes (env : MleEnv)
    (fullJson configJson : String) (digest : Bytes) (length : Nat)
    (h : mleV2CompactSubmissionMetadata env fullJson configJson = .ok (digest, length)) :
    ∃ compact, validateMleV2FullAgainstConfigJson env fullJson configJson = .ok compact ∧
      digest = env.keccak compact ∧ length = compact.length ∧ length ≤ u32Max := by
  simp only [mleV2CompactSubmissionMetadata] at h
  split at h
  · cases h
  · rename_i compact hvalid
    split at h
    · cases h
    · rename_i hfit
      injection h with hpair
      have hd : digest = env.keccak compact := (congrArg Prod.fst hpair).symm
      have hl : length = compact.length := (congrArg Prod.snd hpair).symm
      exact ⟨compact, hvalid, hd, hl, by rw [hl]; exact Nat.not_lt.mp hfit⟩

/-- `validated_compact_mle_v2_bytes` (lines 868-893): the fixture is authenticated against the
SUPPLIED circuit (config/VK equality), then the repository gate guard runs, then native
verification, and only then are the compact bytes produced. -/
def validatedCompactMleV2Bytes (env : MleEnv) (json : String)
    (derivedConfig : Except String ConfigFixture) (validateAgainstCommon : Except String Unit) :
    Except MleError Bytes :=
  match env.parseFull json with
  | .error m => .error (.fullNotCanonical m)
  | .ok fixture =>
    match derivedConfig with
    | .error m => .error (.configDerivationFailed m)
    | .ok expected =>
      if fixture.config ≠ expected then .error .circuitConfigDiffers
      else
        match checkV2GateRows 0 expected.body.gates with
        | .error e => .error (.gateGuard e)
        | .ok _ =>
          match validateAgainstCommon with
          | .error m => .error (.nativeVerificationFailed m)
          | .ok _ => compactMleV2BytesFromFixture env fixture

theorem validated_compact_ok_implies_circuit_binding_and_guards (env : MleEnv) (json : String)
    (fixture : FullFixture) (expected : ConfigFixture) (validateAgainstCommon : Except String Unit)
    (compact : Bytes) (hfix : env.parseFull json = .ok fixture)
    (h : validatedCompactMleV2Bytes env json (.ok expected) validateAgainstCommon = .ok compact) :
    fixture.config = expected ∧ checkV2GateRows 0 expected.body.gates = .ok () ∧
      validateAgainstCommon = .ok () ∧
      compactMleV2BytesFromFixture env fixture = .ok compact := by
  simp only [validatedCompactMleV2Bytes, hfix] at h
  split at h
  · cases h
  · rename_i hcfg
    split at h
    · cases h
    · rename_i hgate
      split at h
      · cases h
      · rename_i u
        cases u
        exact ⟨Decidable.of_not_not hcfg, hgate, rfl, h⟩

/-- `export_mle_v2_json` (lines 917-949): export, compare the proof's VK against a fresh
proof-free derivation from the complete circuit, run the gate guard, serialize, re-parse, and
require the round-trip to be the identity, then re-check the compact record. -/
def exportMleV2Json (env : MleEnv) (exported : Except String FullFixture)
    (derivedConfig : Except String ConfigFixture)
    (toJson : FullFixture → Except String String) : Except MleError String :=
  match exported with
  | .error m => .error (.fullExportRefused m)
  | .ok fixture =>
    match derivedConfig with
    | .error m => .error (.configDerivationFailed m)
    | .ok expected =>
      if fixture.config ≠ expected then .error .circuitConfigDiffers
      else
        match checkV2GateRows 0 expected.body.gates with
        | .error e => .error (.gateGuard e)
        | .ok _ =>
          match toJson fixture with
          | .error m => .error (.canonicalJsonFailed m)
          | .ok json =>
            match env.parseFull json with
            | .error m => .error (.fullNotCanonical m)
            | .ok reparsed =>
              if reparsed ≠ fixture then .error .canonicalJsonRoundTripChanged
              else
                match compactMleV2BytesFromFixture env reparsed with
                | .error e => .error e
                | .ok _ => .ok json

theorem export_full_ok_round_trips_and_carries_a_valid_compact_record (env : MleEnv)
    (fixture : FullFixture) (expected : ConfigFixture)
    (toJson : FullFixture → Except String String) (json : String)
    (h : exportMleV2Json env (.ok fixture) (.ok expected) toJson = .ok json) :
    fixture.config = expected ∧ checkV2GateRows 0 expected.body.gates = .ok () ∧
      toJson fixture = .ok json ∧ env.parseFull json = .ok fixture ∧
      ∃ compact, compactMleV2BytesFromFixture env fixture = .ok compact := by
  simp only [exportMleV2Json] at h
  split at h
  · cases h
  · rename_i hcfg
    split at h
    · cases h
    · rename_i hgate
      split at h
      · cases h
      · rename_i j hj
        split at h
        · cases h
        · rename_i reparsed hrep
          split at h
          · cases h
          · rename_i hround
            split at h
            · cases h
            · rename_i compact hcompact
              injection h with hjson
              subst hjson
              have hre : reparsed = fixture := Decidable.of_not_not hround
              subst hre
              exact ⟨Decidable.of_not_not hcfg, hgate, hj, hrep, compact, hcompact⟩

/-- The gate guard runs before the artifact is serialized, so `export_mle_v2_json` never returns
JSON for a circuit whose gates the deployed evaluator lacks. -/
theorem export_full_gate_guard_precedes_serialisation (env : MleEnv) (fixture : FullFixture)
    (expected : ConfigFixture) (toJson : FullFixture → Except String String)
    (e : GateGuardError) (hcfg : fixture.config = expected)
    (h : checkV2GateRows 0 expected.body.gates = .error e) :
    exportMleV2Json env (.ok fixture) (.ok expected) toJson = .error (.gateGuard e) := by
  simp [exportMleV2Json, hcfg, h]

/-! ### 5.1 A concrete accepting trace

The opaque callbacks are instantiated with trivial stand-ins ONLY to witness that the acceptance
path is reachable; nothing about the real codecs is claimed. -/

def sampleProofView : ProofView := { publicInputs := [7, 9], payload := [1, 2, 3] }

def sampleCompact : Bytes := [1, 2, 3]

def sampleGateRow : V2GateRow :=
  { gateId := 0, numOrConsts := 20, param2 := 0, param3 := 0 }

def sampleConfigBody : ConfigBody :=
  { circuitDigest := [4], gates := [sampleGateRow], publicInputWireMap := [0, 1] }

def sampleConfigAbiRecord : EncodedRecord :=
  { label := "CFGV2", byteLength := 1, keccak := [8], bytes := [8] }

def sampleProofAbiRecord : EncodedRecord :=
  { label := "PRFV2", byteLength := 1, keccak := [9], bytes := [9] }

def sampleCompactRecord : EncodedRecord :=
  { label := "MLEWHIR3", byteLength := 3, keccak := sampleCompact, bytes := sampleCompact }

def sampleConfigFixture : ConfigFixture :=
  { body := sampleConfigBody, solidityAbiVerificationConfig := sampleConfigAbiRecord,
    pinnedVerificationConfigDigest := [8] }

def sampleFullFixture : FullFixture :=
  { config := sampleConfigFixture, proof := sampleProofView, compactProof := sampleCompactRecord,
    compactShape := 0, solidityAbiProof := sampleProofAbiRecord }

def sampleTamperedFullFixture : FullFixture :=
  { sampleFullFixture with proof := { publicInputs := [0, 9], payload := [1, 2, 3] } }

def sampleEnv : MleEnv :=
  { keccak := fun b => b
    maxCompactProofBytes := 1024
    compactMagic := "MLEWHIR3"
    solidityProofEncoding := "PRFV2"
    solidityConfigEncoding := "CFGV2"
    parseFull := fun _ => .ok sampleFullFixture
    parseConfig := fun _ => .ok sampleConfigFixture
    decodeCompact := fun _ _ => .ok sampleProofView
    encodeCompact := fun _ _ => .ok sampleCompact
    encodeProofFixture := fun p => p
    abiEncodeProof := fun _ => .ok [9]
    abiEncodeConfig := fun _ => .ok [8] }

def sampleTamperedEnv : MleEnv := { sampleEnv with parseFull := fun _ => .ok sampleTamperedFullFixture }

theorem sample_full_artifact_is_accepted :
    validateMleV2FullAgainstConfigJson sampleEnv "full" "config" = .ok sampleCompact := by
  simp [validateMleV2FullAgainstConfigJson, compactMleV2BytesFromFixture, decodeAndValidate,
    sampleEnv, sampleFullFixture, sampleConfigFixture, sampleCompactRecord, sampleProofAbiRecord,
    sampleConfigAbiRecord, sampleCompact, sampleProofView, sampleConfigBody]

theorem sample_submission_metadata_is_the_compact_commitment :
    mleV2CompactSubmissionMetadata sampleEnv "full" "config" = .ok (sampleCompact, 3) := by
  simp only [mleV2CompactSubmissionMetadata, sample_full_artifact_is_accepted]
  simp [sampleEnv, sampleCompact, u32Max]

theorem sample_tampered_structured_proof_is_rejected :
    validateMleV2FullAgainstConfigJson sampleTamperedEnv "full" "config" =
      .error .structuredProofDisagrees := by
  simp [validateMleV2FullAgainstConfigJson, compactMleV2BytesFromFixture, decodeAndValidate,
    sampleTamperedEnv, sampleEnv, sampleTamperedFullFixture, sampleFullFixture,
    sampleConfigFixture, sampleCompactRecord, sampleCompact, sampleProofView]

/-! ## 6. The RETIRED member-set-update prototype (`src/deprecated/**`)

`src/deprecated/mod.rs` and `src/deprecated/member_set_update/mod.rs` are two documentation-only
module declarations: nothing is compiled unless the matching `deprecated-*` Cargo feature is
selected. Section 9 models that manifest gate. Everything in sections 6-8 is a model of a
RETIRED path, kept for audit archaeology; nothing below asserts that the prototype is safe,
complete, or fit to deploy. The prototype's own documented limitation (it authenticates the old
signer set's requested mutation but never proves an atomic transition of every settlement and
validity-layer authority) is NOT modelled and is not repaired by any theorem here. -/

/-- `constants.rs:135`. The sig-cluster capacity. -/
def maxSigCluster : Nat := 8
/-- `Bytes32` limb count. -/
def bytes32Len : Nat := 8

theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl
theorem bytes32_len_pinned : bytes32Len = 8 := rfl

/-- `circuit.rs:91`: `1 + 2 + 8 + 8 + 1 + 1 + 5`. -/
def memberSetUpdatePublicInputsLen : Nat := 1 + 2 + 8 + 8 + 1 + 1 + 5

theorem member_set_update_public_inputs_len_pinned : memberSetUpdatePublicInputsLen = 26 := rfl

/-- The eight cluster slot indices, written out so slot quantification never depends on a
`List.range` membership lemma. -/
def slotIndices : List Nat := [0, 1, 2, 3, 4, 5, 6, 7]

theorem slot_indices_cover_the_cluster : slotIndices.length = maxSigCluster := rfl

theorem mem_slot_indices_lt (i : Nat) (h : i ∈ slotIndices) : i < maxSigCluster := by
  simp only [slotIndices, List.mem_cons, List.not_mem_nil, or_false] at h
  simp only [maxSigCluster]
  omega

theorem lt_mem_slot_indices (i : Nat) (h : i < maxSigCluster) : i ∈ slotIndices := by
  simp only [maxSigCluster] at h
  simp only [slotIndices, List.mem_cons, List.not_mem_nil, or_false]
  omega

/-- `circuit.rs:88` — the in-circuit IMCM constant. -/
def imcmDomain : Nat := 0x494d434d
/-- `common/channel.rs:64` — `CLOSE_MEMBER_SET_DOMAIN`, the native/Manager-side constant the
in-circuit keccak must agree with byte for byte. -/
def closeMemberSetDomain : Nat := 0x494d434d
/-- `constants.rs:262` — `MEMBER_SET_UPDATE_DOMAIN` ("IMMS"). -/
def immsDomain : Nat := 0x494d4d53

/-- The in-circuit commitment domain is the same literal as the native close-path domain, which
is what makes the exposed commitments comparable with the Manager's stored value. -/
theorem imcm_domain_agrees_with_close_member_set_domain : imcmDomain = closeMemberSetDomain := rfl

theorem member_set_update_domains_are_distinct : imcmDomain ≠ immsDomain := by decide

/-- `falcon_sig/agg.rs:161-167`, the aggregate-proof public-input layout the circuit reads. -/
def falconAggMsgOffset : Nat := 0
def falconAggCountOffset : Nat := bytes32Len
def falconAggPkListOffset : Nat := bytes32Len + 1
def falconAggPublicInputsLen : Nat := bytes32Len + 1 + maxSigCluster * bytes32Len

theorem falcon_agg_layout_pinned :
    falconAggMsgOffset = 0 ∧ falconAggCountOffset = 8 ∧ falconAggPkListOffset = 9 ∧
      falconAggPublicInputsLen = 73 := by decide

/-- Slot `i`'s pk_g occupies `[pkSlotStart i, pkSlotStart i + 8)` (`circuit.rs:313`). -/
def pkSlotStart (i : Nat) : Nat := falconAggPkListOffset + i * bytes32Len

theorem pk_slots_are_disjoint_and_inside_the_aggregate_layout (i : Nat) (h : i < maxSigCluster) :
    pkSlotStart i + bytes32Len ≤ falconAggPublicInputsLen ∧
      pkSlotStart i + bytes32Len = pkSlotStart (i + 1) := by
  simp only [pkSlotStart, falconAggPkListOffset, falconAggPublicInputsLen, bytes32Len,
    maxSigCluster] at *
  omega

/-! ### 6.1 The 26-limb public-input record (`circuit.rs:93-123`) -/

structure Words8 where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  w4 : Nat
  w5 : Nat
  w6 : Nat
  w7 : Nat
  deriving DecidableEq, Repr

def Words8.toList (w : Words8) : List Nat := [w.w0, w.w1, w.w2, w.w3, w.w4, w.w5, w.w6, w.w7]
def Words8.zero : Words8 := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩

theorem words8_to_list_length (w : Words8) : w.toList.length = bytes32Len := rfl

structure Address5 where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr

def Address5.toList (a : Address5) : List Nat := [a.a0, a.a1, a.a2, a.a3, a.a4]
def Address5.zero : Address5 := ⟨0, 0, 0, 0, 0⟩

theorem address5_to_list_length (a : Address5) : a.toList.length = 5 := rfl

structure MsuPublicInputs where
  /-- `ChannelId` is a single non-zero u32 limb (`common/channel_id.rs`). -/
  channelId : Nat
  /-- The NEW set version; the Manager checks strict monotonicity on-chain (not modelled). -/
  setVersion : Nat
  oldCommitment : Words8
  newCommitment : Words8
  oldCount : Nat
  newCount : Nat
  /-- The joiner's exit address for an add; the zero address for a rotation. -/
  recipient : Address5
  deriving DecidableEq, Repr

/-- `set_version >> 32` on a `u64`. -/
def setVersionHi (v : Nat) : Nat := v / 4294967296
/-- `set_version & 0xffff_ffff` on a `u64`. -/
def setVersionLo (v : Nat) : Nat := v % 4294967296

theorem set_version_limbs_recompose (v : Nat) :
    setVersionHi v * 4294967296 + setVersionLo v = v := by
  simp only [setVersionHi, setVersionLo]
  omega

theorem set_version_limbs_fit_u32 (v : Nat) (h : v < 18446744073709551616) :
    setVersionHi v < 4294967296 ∧ setVersionLo v < 4294967296 := by
  simp only [setVersionHi, setVersionLo]
  omega

/-- `MemberSetUpdatePublicInputs::to_u64_vec` (`circuit.rs:110-122`):
`[channelId(1) | setVersion hi,lo (2) | oldCommitment(8) | newCommitment(8) | oldCount(1) |
newCount(1) | recipient(5)]`. -/
def MsuPublicInputs.toU64Vec (p : MsuPublicInputs) : List Nat :=
  [p.channelId, setVersionHi p.setVersion, setVersionLo p.setVersion] ++
    p.oldCommitment.toList ++ p.newCommitment.toList ++ [p.oldCount, p.newCount] ++
    p.recipient.toList

theorem msu_public_inputs_length (p : MsuPublicInputs) :
    p.toU64Vec.length = memberSetUpdatePublicInputsLen := rfl

/-- The exact limb positions the Solidity bind re-reads. -/
theorem msu_public_inputs_layout (p : MsuPublicInputs) :
    p.toU64Vec[0]? = some p.channelId ∧
    p.toU64Vec[1]? = some (setVersionHi p.setVersion) ∧
    p.toU64Vec[2]? = some (setVersionLo p.setVersion) ∧
    p.toU64Vec[3]? = some p.oldCommitment.w0 ∧
    p.toU64Vec[10]? = some p.oldCommitment.w7 ∧
    p.toU64Vec[11]? = some p.newCommitment.w0 ∧
    p.toU64Vec[18]? = some p.newCommitment.w7 ∧
    p.toU64Vec[19]? = some p.oldCount ∧
    p.toU64Vec[20]? = some p.newCount ∧
    p.toU64Vec[21]? = some p.recipient.a0 ∧
    p.toU64Vec[25]? = some p.recipient.a4 ∧
    p.toU64Vec[26]? = none := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp [MsuPublicInputs.toU64Vec, Words8.toList, Address5.toList]

theorem words8_ext (a b : Words8) (h0 : a.w0 = b.w0) (h1 : a.w1 = b.w1) (h2 : a.w2 = b.w2)
    (h3 : a.w3 = b.w3) (h4 : a.w4 = b.w4) (h5 : a.w5 = b.w5) (h6 : a.w6 = b.w6)
    (h7 : a.w7 = b.w7) : a = b := by
  cases a; cases b; simp_all

theorem address5_ext (a b : Address5) (h0 : a.a0 = b.a0) (h1 : a.a1 = b.a1) (h2 : a.a2 = b.a2)
    (h3 : a.a3 = b.a3) (h4 : a.a4 = b.a4) : a = b := by
  cases a; cases b; simp_all

/-- The commitment limbs occupy disjoint eight-limb windows: an old-set commitment can never be
read as the new-set commitment. -/
theorem msu_commitment_windows_are_disjoint (p q : MsuPublicInputs)
    (h : p.toU64Vec = q.toU64Vec) : p.oldCommitment = q.oldCommitment ∧
      p.newCommitment = q.newCommitment ∧ p.oldCount = q.oldCount ∧ p.newCount = q.newCount ∧
      p.recipient = q.recipient ∧ p.channelId = q.channelId := by
  simp only [MsuPublicInputs.toU64Vec, Words8.toList, Address5.toList, List.append_assoc,
    List.cons_append, List.nil_append, List.cons.injEq] at h
  obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18,
    h19, h20, h21, h22, h23, h24, h25, _⟩ := h
  exact ⟨words8_ext _ _ h3 h4 h5 h6 h7 h8 h9 h10,
    words8_ext _ _ h11 h12 h13 h14 h15 h16 h17 h18, h19, h20,
    address5_ext _ _ h21 h22 h23 h24 h25, h0⟩

/-! ### 6.2 The native mirror `expected_public_inputs` (`circuit.rs:194-224`) -/

/-- `MemberLeaf` viewed through the three digests the circuit compares. -/
structure MemberLeaf where
  pkG : Words8
  pkB : Words8
  regevPkDigest : Words8
  deriving DecidableEq, Repr

def emptyLeaf : MemberLeaf := ⟨Words8.zero, Words8.zero, Words8.zero⟩

def leafAt (ls : List MemberLeaf) (i : Nat) : MemberLeaf := (ls[i]?).getD emptyLeaf

/-- `old_leaves.iter().take_while(|l| **l != empty).count()`. -/
def leadingCount (ls : List MemberLeaf) : Nat :=
  (ls.takeWhile (fun l => decide (l ≠ emptyLeaf))).length

def changedIndices (old new : List MemberLeaf) : List Nat :=
  (slotIndices).filter (fun i => decide (leafAt old i ≠ leafAt new i))

structure MsuWitness where
  channelId : Nat
  setVersion : Nat
  oldLeaves : List MemberLeaf
  newLeaves : List MemberLeaf
  recipient : Address5
  deriving DecidableEq

inductive MsuWitnessError where
  | deltaRejected (message : String)
  | notExactlyOneChangedSlot
  | rotationCarriesNonZeroRecipient
  deriving DecidableEq

/-- The native strict mirror. `validateDelta` is `validate_member_set_delta` (a boundary in
another module) and `commit` is `close_member_set_commitment` (an opaque keccak callback). The
check ORDER is the source's: delta validation, then exactly-one-changed-slot, then the
rotation/recipient rule. -/
def expectedPublicInputs (validateDelta : List MemberLeaf → List MemberLeaf → Except String Unit)
    (commit : List Words8 → Nat → Words8) (w : MsuWitness) :
    Except MsuWitnessError MsuPublicInputs :=
  match validateDelta w.oldLeaves w.newLeaves with
  | .error m => .error (.deltaRejected m)
  | .ok _ =>
    match changedIndices w.oldLeaves w.newLeaves with
    | [j] =>
      let isAdd := leafAt w.oldLeaves j == emptyLeaf
      let oldCount := leadingCount w.oldLeaves
      let newCount := oldCount + (if isAdd then 1 else 0)
      if !isAdd && w.recipient ≠ Address5.zero then .error .rotationCarriesNonZeroRecipient
      else
        .ok { channelId := w.channelId
              setVersion := w.setVersion
              oldCommitment :=
                commit ((slotIndices).map (fun i => (leafAt w.oldLeaves i).pkG))
                  oldCount
              newCommitment :=
                commit ((slotIndices).map (fun i => (leafAt w.newLeaves i).pkG))
                  newCount
              oldCount := oldCount
              newCount := newCount
              recipient := w.recipient }
    | _ => .error .notExactlyOneChangedSlot

theorem native_mirror_runs_delta_validation_first
    (validateDelta : List MemberLeaf → List MemberLeaf → Except String Unit)
    (commit : List Words8 → Nat → Words8) (w : MsuWitness) (m : String)
    (h : validateDelta w.oldLeaves w.newLeaves = .error m) :
    expectedPublicInputs validateDelta commit w = .error (.deltaRejected m) := by
  simp [expectedPublicInputs, h]

theorem native_mirror_requires_exactly_one_changed_slot
    (validateDelta : List MemberLeaf → List MemberLeaf → Except String Unit)
    (commit : List Words8 → Nat → Words8) (w : MsuWitness) (p : MsuPublicInputs)
    (h : expectedPublicInputs validateDelta commit w = .ok p) :
    validateDelta w.oldLeaves w.newLeaves = .ok () ∧
      (changedIndices w.oldLeaves w.newLeaves).length = 1 := by
  simp only [expectedPublicInputs] at h
  split at h
  · cases h
  · rename_i u hu
    cases u
    split at h
    · rename_i j hchanged
      split at h
      · cases h
      · exact ⟨hu, by rw [hchanged]; rfl⟩
    · cases h

/-- The exposed counts differ by exactly the add bit: a native run never grows the set by more
than one, and never shrinks it. -/
theorem native_mirror_new_count_is_old_plus_add
    (validateDelta : List MemberLeaf → List MemberLeaf → Except String Unit)
    (commit : List Words8 → Nat → Words8) (w : MsuWitness) (p : MsuPublicInputs)
    (h : expectedPublicInputs validateDelta commit w = .ok p) :
    p.oldCount = leadingCount w.oldLeaves ∧
      (p.newCount = p.oldCount ∨ p.newCount = p.oldCount + 1) := by
  simp only [expectedPublicInputs] at h
  split at h
  · cases h
  · split at h
    · rename_i j _
      split at h
      · cases h
      · injection h with hp
        subst hp
        by_cases hadd : (leafAt w.oldLeaves j == emptyLeaf) = true
        · simp [hadd]
        · simp at hadd
          simp [hadd]
    · cases h

/-- A rotation (no add) must expose the zero recipient; the recipient limbs are meaningful only
for an add. -/
theorem native_mirror_rotation_carries_zero_recipient
    (validateDelta : List MemberLeaf → List MemberLeaf → Except String Unit)
    (commit : List Words8 → Nat → Words8) (w : MsuWitness) (p : MsuPublicInputs)
    (h : expectedPublicInputs validateDelta commit w = .ok p) (hrot : p.newCount = p.oldCount) :
    p.recipient = Address5.zero := by
  simp only [expectedPublicInputs] at h
  split at h
  · cases h
  · split at h
    · rename_i j _
      split at h
      · cases h
      · rename_i hguard
        injection h with hp
        subst hp
        by_cases hadd : (leafAt w.oldLeaves j == emptyLeaf) = true
        · have hbad : leadingCount w.oldLeaves + 1 = leadingCount w.oldLeaves := by
            simpa [hadd] using hrot
          omega
        · simp only [Bool.not_eq_true] at hadd
          simp [hadd] at hguard
          exact hguard
    · cases h

/-! ### 6.3 Thermometer encoding of the active-slot bits (`circuit.rs:276-292`) -/

/-- `active[i+1] * (1 - active[i]) = 0` for every adjacent pair. -/
def Thermometer : List Bool → Prop
  | [] => True
  | a :: rest => (rest.head? = some true → a = true) ∧ Thermometer rest

def countTrue : List Bool → Nat
  | [] => 0
  | true :: r => countTrue r + 1
  | false :: r => countTrue r

theorem count_true_le_length : ∀ bs : List Bool, countTrue bs ≤ bs.length := by
  intro bs
  induction bs with
  | nil => exact Nat.le_refl 0
  | cons a r ih =>
    cases a with
    | true => simp only [countTrue, List.length_cons]; omega
    | false => simp only [countTrue, List.length_cons]; omega

theorem thermometer_head_false_forces_all_false :
    ∀ bs : List Bool, Thermometer bs → bs.head? ≠ some true → countTrue bs = 0 := by
  intro bs
  induction bs with
  | nil => intro _ _; rfl
  | cons a r ih =>
    intro h hhead
    obtain ⟨h1, h2⟩ := h
    cases a with
    | true => exact absurd rfl hhead
    | false =>
      have hr : r.head? ≠ some true := by
        intro hcontra
        exact absurd (h1 hcontra) (by simp)
      simp only [countTrue]
      exact ih h2 hr

/-- The thermometer gates plus `Σ active = old_count` force the active set to be exactly the
first `old_count` slots: `old_count` really is a left-packed prefix count, not an arbitrary
population count. -/
theorem thermometer_active_prefix :
    ∀ bs : List Bool, Thermometer bs → ∀ i, i < bs.length →
      (bs[i]?).getD false = decide (i < countTrue bs) := by
  intro bs
  induction bs with
  | nil => intro _ i hi; exact absurd hi (by simp)
  | cons a r ih =>
    intro h i hi
    obtain ⟨h1, h2⟩ := h
    cases i with
    | zero =>
      cases a with
      | true => simp [countTrue]
      | false =>
        have hzero : countTrue r = 0 :=
          thermometer_head_false_forces_all_false r h2 (by
            intro hc
            exact absurd (h1 hc) (by simp))
        simp [countTrue, hzero]
    | succ k =>
      have hk : k < r.length := by simp only [List.length_cons] at hi; omega
      have hrec := ih h2 k hk
      cases a with
      | true =>
        simp only [countTrue, List.getElem?_cons_succ]
        rw [hrec]
        simp only [decide_eq_decide]
        omega
      | false =>
        have hzero : countTrue r = 0 :=
          thermometer_head_false_forces_all_false r h2 (by
            intro hc
            exact absurd (h1 hc) (by simp))
        simp only [countTrue, List.getElem?_cons_succ]
        rw [hrec]
        simp only [hzero, decide_eq_decide]
        omega

/-! ### 7. The in-circuit gates (`circuit.rs:255-529`)

These are the constraints an ARBITRARY satisfying witness must meet — deliberately separate from
the native mirror of section 6.2. `MemberSetUpdateCircuit::prove_with_public_inputs` exists
precisely so a prover can drive the circuit with public inputs the native mirror never produced
(`circuit.rs:541-546`), so no theorem below may lean on `expectedPublicInputs`. -/

structure MsuCircuitWitness where
  active : List Bool
  oldLeaves : List MemberLeaf
  newLeaves : List MemberLeaf
  aggCount : Nat
  aggPkList : List Words8
  aggMessage : Words8
  prevRoot : Words8
  newRoot : Words8
  opDigest : Words8
  publicInputs : MsuPublicInputs

def activeAt (w : MsuCircuitWitness) (i : Nat) : Bool := (w.active[i]?).getD false

def changedAt (w : MsuCircuitWitness) (i : Nat) : Prop :=
  leafAt w.oldLeaves i ≠ leafAt w.newLeaves i

instance (w : MsuCircuitWitness) (i : Nat) : Decidable (changedAt w i) := by
  unfold changedAt
  infer_instance

def changedSlotsOf (w : MsuCircuitWitness) : List Nat :=
  (slotIndices).filter (fun i => decide (changedAt w i))

/-- The circuit forms `Σ changed_i · i`; with a single changed bit that IS the changed index. -/
def changedSlotIndexSum (w : MsuCircuitWitness) : Nat :=
  (changedSlotsOf w).foldl (fun acc i => acc + i) 0

theorem changed_slot_index_sum_selects_the_changed_slot (w : MsuCircuitWitness) (j : Nat)
    (h : changedSlotsOf w = [j]) : changedSlotIndexSum w = j := by
  simp [changedSlotIndexSum, h]

def isAddAt (w : MsuCircuitWitness) (i : Nat) : Bool := decide (changedAt w i) && !activeAt w i

def isAdd (w : MsuCircuitWitness) : Bool := (slotIndices).any (isAddAt w)

/-- The keccak preimage of the IMCM member-set commitment (`circuit.rs:439-451`). -/
def imcmPreimage (leaves : List MemberLeaf) (count : Nat) : List Nat :=
  imcmDomain :: count ::
    List.join ((slotIndices).map (fun i => (leafAt leaves i).pkG.toList))

/-- The keccak preimage of the IMMS digest (`circuit.rs:503-516`). -/
def immsPreimage (w : MsuCircuitWitness) : List Nat :=
  [immsDomain, w.publicInputs.channelId, setVersionHi w.publicInputs.setVersion,
    setVersionLo w.publicInputs.setVersion] ++ w.prevRoot.toList ++ w.newRoot.toList ++
    w.opDigest.toList

/-- The op-digest preimages, both shapes (`circuit.rs:479-494`). -/
def rotateOpPreimage (w : MsuCircuitWitness) (j : Nat) : List Nat :=
  [2, j] ++ (leafAt w.newLeaves j).pkG.toList ++ (leafAt w.newLeaves j).pkB.toList

def addOpPreimage (w : MsuCircuitWitness) (j : Nat) : List Nat :=
  [1] ++ (leafAt w.newLeaves j).pkG.toList ++ (leafAt w.newLeaves j).pkB.toList ++
    (leafAt w.newLeaves j).regevPkDigest.toList ++ w.publicInputs.recipient.toList

/-- Every gate the retired circuit builds, as a Prop over an arbitrary witness. `keccak` and the
Poseidon member-tree fold are opaque; no injectivity is used. -/
structure MsuCircuitGates (keccak : List Nat → Words8) (w : MsuCircuitWitness) : Prop where
  activeLength : w.active.length = maxSigCluster
  oldLeavesLength : w.oldLeaves.length = maxSigCluster
  newLeavesLength : w.newLeaves.length = maxSigCluster
  aggPkListLength : w.aggPkList.length = maxSigCluster
  /-- `builder.connect(prod, zero)` over adjacent bits. -/
  thermometer : Thermometer w.active
  /-- `builder.connect(count_sum, public_inputs.old_count)`. -/
  activeSumIsOldCount : countTrue w.active = w.publicInputs.oldCount
  /-- `builder.assert_one(active_bits[1].target)`. -/
  clusterHasAtLeastTwoSlots : w.active[1]? = some true
  /-- `connect(agg_proof.public_inputs[FALCON_AGG_COUNT_OFFSET], old_count)`. -/
  aggCountIsOldCount : w.aggCount = w.publicInputs.oldCount
  /-- `old_pk.connect(&mut builder, agg_pk)` for every slot. -/
  oldKeysAreTheVerifiedSignerList : ∀ i, i < maxSigCluster →
    (leafAt w.oldLeaves i).pkG = (w.aggPkList[i]?).getD Words8.zero
  oldPaddingIsEmpty : ∀ i, i < maxSigCluster → activeAt w i = false →
    (leafAt w.oldLeaves i).pkB = Words8.zero ∧
      (leafAt w.oldLeaves i).regevPkDigest = Words8.zero
  /-- `builder.connect(sum_changed, one)`. -/
  exactlyOneChangedSlot : (changedSlotsOf w).length = 1
  /-- `conditional_assert_eq(add_here, i, old_count)`. -/
  addIsAtTheLeftPackedBoundary : ∀ i, i < maxSigCluster → changedAt w i → activeAt w i = false →
    i = w.publicInputs.oldCount
  /-- Q-6: a rotation preserves the Regev digest, so balances stay decryptable. -/
  rotationPreservesRegevDigest : ∀ i, i < maxSigCluster → changedAt w i → activeAt w i = true →
    (leafAt w.oldLeaves i).regevPkDigest = (leafAt w.newLeaves i).regevPkDigest
  /-- `builder.assert_zero(removed.target)`. -/
  neverARemoval : ∀ i, i < maxSigCluster → changedAt w i →
    (leafAt w.newLeaves i).pkG ≠ Words8.zero
  /-- M-1: the changed slot's new signing key differs from every other slot's. -/
  noDuplicateSigningIdentity : ∀ i k, i < k → k < maxSigCluster →
    (changedAt w i ∨ changedAt w k) → (leafAt w.newLeaves i).pkG ≠ (leafAt w.newLeaves k).pkG
  newCountIsOldPlusAdd :
    w.publicInputs.newCount = w.publicInputs.oldCount + (if isAdd w = true then 1 else 0)
  newPaddingIsEmpty : ∀ i, i < maxSigCluster → activeAt w i = false →
    ¬(isAdd w = true ∧ i = w.publicInputs.oldCount) → leafAt w.newLeaves i = emptyLeaf
  oldCommitmentIsKeccak :
    w.publicInputs.oldCommitment = keccak (imcmPreimage w.oldLeaves w.publicInputs.oldCount)
  newCommitmentIsKeccak :
    w.publicInputs.newCommitment = keccak (imcmPreimage w.newLeaves w.publicInputs.newCount)
  rotationExposesZeroRecipient : isAdd w = false → w.publicInputs.recipient = Address5.zero
  opDigestIsRecomputed : ∀ j, changedSlotsOf w = [j] →
    w.opDigest = (if isAdd w = true then keccak (addOpPreimage w j)
      else keccak (rotateOpPreimage w j))
  /-- `imms_digest.connect(&mut builder, agg_message)`: the OLD set's unanimous signatures are
  over exactly this transition. -/
  immsDigestIsTheSignedMessage : keccak (immsPreimage w) = w.aggMessage

theorem msu_active_bits_are_the_first_old_count_slots (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) (i : Nat) (hi : i < maxSigCluster) :
    activeAt w i = decide (i < w.publicInputs.oldCount) := by
  have hlen : i < w.active.length := by rw [g.activeLength]; exact hi
  have := thermometer_active_prefix w.active g.thermometer i hlen
  rw [activeAt, this, g.activeSumIsOldCount]

theorem msu_registered_cluster_has_at_least_two_signers (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) : 2 ≤ w.publicInputs.oldCount := by
  have h1 : activeAt w 1 = true := by
    rw [activeAt, g.clusterHasAtLeastTwoSlots]
    rfl
  have h2 := msu_active_bits_are_the_first_old_count_slots keccak w g 1 (by decide)
  rw [h1] at h2
  have : 1 < w.publicInputs.oldCount := of_decide_eq_true h2.symm
  omega

theorem msu_old_count_within_capacity (keccak : List Nat → Words8) (w : MsuCircuitWitness)
    (g : MsuCircuitGates keccak w) : w.publicInputs.oldCount ≤ maxSigCluster := by
  have := count_true_le_length w.active
  rw [g.activeSumIsOldCount, g.activeLength] at this
  exact this

theorem msu_full_cluster_cannot_add (keccak : List Nat → Words8) (w : MsuCircuitWitness)
    (g : MsuCircuitGates keccak w) (hfull : w.publicInputs.oldCount = maxSigCluster) :
    isAdd w = false := by
  cases hadd : isAdd w with
  | false => rfl
  | true =>
    exfalso
    simp only [isAdd, List.any_eq_true] at hadd
    obtain ⟨i, hmem, hi'⟩ := hadd
    have hi : i < maxSigCluster := mem_slot_indices_lt i hmem
    simp only [isAddAt, Bool.and_eq_true, Bool.not_eq_true'] at hi'
    have hact := msu_active_bits_are_the_first_old_count_slots keccak w g i hi
    rw [hi'.2, hfull] at hact
    simp [hi] at hact

theorem msu_add_lands_at_the_left_packed_boundary (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) (hadd : isAdd w = true) :
    w.publicInputs.oldCount < maxSigCluster ∧
      w.publicInputs.newCount = w.publicInputs.oldCount + 1 := by
  have hadd' := hadd
  simp only [isAdd, List.any_eq_true] at hadd'
  obtain ⟨i, hmem, hi'⟩ := hadd'
  have hi : i < maxSigCluster := mem_slot_indices_lt i hmem
  simp only [isAddAt, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at hi'
  have hbound := g.addIsAtTheLeftPackedBoundary i hi hi'.1 hi'.2
  refine ⟨by omega, ?_⟩
  rw [g.newCountIsOldPlusAdd, hadd]
  simp

theorem msu_new_count_within_capacity (keccak : List Nat → Words8) (w : MsuCircuitWitness)
    (g : MsuCircuitGates keccak w) : w.publicInputs.newCount ≤ maxSigCluster := by
  cases hadd : isAdd w with
  | false =>
    rw [g.newCountIsOldPlusAdd, hadd]
    simpa using msu_old_count_within_capacity keccak w g
  | true =>
    obtain ⟨hlt, hnew⟩ := msu_add_lands_at_the_left_packed_boundary keccak w g hadd
    omega

/-- M-1 in force: the changed slot's NEW signing key is distinct from every other slot's, so a
rotate-to-duplicate (an effective removal that passes the "never a removal" gate) is rejected. -/
theorem msu_changed_slot_key_differs_from_every_other_slot (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) (j k : Nat) (hj : j < maxSigCluster)
    (hk : k < maxSigCluster) (hjk : j ≠ k) (hchanged : changedAt w j) :
    (leafAt w.newLeaves j).pkG ≠ (leafAt w.newLeaves k).pkG := by
  rcases Nat.lt_or_ge j k with hlt | hge
  · exact g.noDuplicateSigningIdentity j k hlt hk (Or.inl hchanged)
  · have hkj : k < j := by omega
    exact fun hcontra =>
      g.noDuplicateSigningIdentity k j hkj hj (Or.inr hchanged) hcontra.symm

/-- The changed slot's new key is also non-zero, so the delta is never a removal. -/
theorem msu_changed_slot_key_is_non_zero (keccak : List Nat → Words8) (w : MsuCircuitWitness)
    (g : MsuCircuitGates keccak w) (j : Nat) (hj : j < maxSigCluster) (hchanged : changedAt w j) :
    (leafAt w.newLeaves j).pkG ≠ Words8.zero := g.neverARemoval j hj hchanged

/-- The signature world and the Poseidon world name the same key set, and the aggregate's signer
count is the exposed `old_count`. -/
theorem msu_signer_list_binds_the_old_key_set (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) :
    w.aggCount = w.publicInputs.oldCount ∧
      ∀ i, i < maxSigCluster →
        (leafAt w.oldLeaves i).pkG = (w.aggPkList[i]?).getD Words8.zero :=
  ⟨g.aggCountIsOldCount, g.oldKeysAreTheVerifiedSignerList⟩

theorem msu_rotation_exposes_the_zero_recipient (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) (hrot : isAdd w = false) :
    w.publicInputs.recipient = Address5.zero ∧
      w.publicInputs.newCount = w.publicInputs.oldCount := by
  refine ⟨g.rotationExposesZeroRecipient hrot, ?_⟩
  rw [g.newCountIsOldPlusAdd, hrot]
  simp

/-- The commitments the L1 apply compares are keccaks over the exposed counts and the witnessed
key sets, and the message the previous set signed is the IMMS digest over this exact transition.
Keccak is opaque: nothing here claims the digests determine the sets. -/
theorem msu_exposed_commitments_and_signed_message (keccak : List Nat → Words8)
    (w : MsuCircuitWitness) (g : MsuCircuitGates keccak w) :
    w.publicInputs.oldCommitment = keccak (imcmPreimage w.oldLeaves w.publicInputs.oldCount) ∧
      w.publicInputs.newCommitment = keccak (imcmPreimage w.newLeaves w.publicInputs.newCount) ∧
      keccak (immsPreimage w) = w.aggMessage :=
  ⟨g.oldCommitmentIsKeccak, g.newCommitmentIsKeccak, g.immsDigestIsTheSignedMessage⟩

/-! ## 8. The retired v1 export (`mle_prover.rs:953-1030`) and the fixture generator
(`src/deprecated/member_set_update/generate_fixture.rs`)

`mle_prover::deprecated_v1` is compiled only under `deprecated-msu`; it is the only remaining
caller of the v1 `check_on_chain_evaluable` guard of section 2. -/

inductive DeprecatedExportError where
  | fixtureExportFailed (message : String)
  | gateGuard (error : GateGuardError)
  deriving DecidableEq

/-- `deprecated_v1::export_mle_json` (lines 1020-1029): serialize, then run the v1 guard, and
return the JSON only if the guard accepted. -/
def deprecatedExportMleJson (fixtureJson : Except String String)
    (serializedGates : Option (List SerializedGateRow)) (expected : List ExpectedGateRow) :
    Except DeprecatedExportError String :=
  match fixtureJson with
  | .error m => .error (.fixtureExportFailed m)
  | .ok json =>
    match checkFixtureJsonGates serializedGates expected with
    | .error e => .error (.gateGuard e)
    | .ok _ => .ok json

theorem deprecated_export_returns_only_guard_accepted_json (fixtureJson : Except String String)
    (serializedGates : Option (List SerializedGateRow)) (expected : List ExpectedGateRow)
    (json : String) (h : deprecatedExportMleJson fixtureJson serializedGates expected = .ok json) :
    fixtureJson = .ok json ∧ checkFixtureJsonGates serializedGates expected = .ok () := by
  simp only [deprecatedExportMleJson] at h
  split at h
  · cases h
  · rename_i j hj
    split at h
    · cases h
    · rename_i hguard
      injection h with hjson
      subst hjson
      exact ⟨hj, hguard⟩

theorem deprecated_export_gate_guard_blocks_the_json (fixtureJson : Except String String)
    (serializedGates : Option (List SerializedGateRow)) (expected : List ExpectedGateRow)
    (e : GateGuardError) (h : checkFixtureJsonGates serializedGates expected = .error e) :
    ∀ json, deprecatedExportMleJson fixtureJson serializedGates expected ≠ .ok json := by
  intro json hcontra
  exact absurd (deprecated_export_returns_only_guard_accepted_json fixtureJson serializedGates
    expected json hcontra).2 (by rw [h]; simp)

/-! ### 8.1 The generator pipeline -/

/-- The descriptor written next to the MLE artifact (`generate_fixture.rs:51-65`). -/
structure MsuDescriptor where
  channelId : Nat
  setVersion : Nat
  oldCommitment : Words8
  newCommitment : Words8
  oldCount : Nat
  newCount : Nat
  recipient : Address5
  oldMemberPkGs : List Words8
  newMemberPkGs : List Words8
  rotatedSlot : Nat
  deriving DecidableEq, Repr

/-- `rotated_slot: 1` is a hard-coded descriptor convenience, not a proved value
(`generate_fixture.rs:194`). -/
def descriptorRotatedSlotLiteral : Nat := 1

theorem descriptor_rotated_slot_literal_pinned : descriptorRotatedSlotLiteral = 1 := rfl

inductive MsuFixtureError where
  | walletGateRejected
  | aggregateProvingFailed
  | nativeMirrorRejected (error : MsuWitnessError)
  | circuitProvingFailed
  | circuitVerificationFailed
  | provedLimbsDisagreeWithNativeMirror
  | wrappingFailed
  | mleProvingFailed
  | mleVerificationFailed
  | exportGuardRejected (error : GateGuardError)
  | mleJsonHasNoPublicInputs
  | mlePublicInputsLengthMismatch (length : Nat)
  | mlePublicInputsDisagreeWithProvedLimbs
  deriving DecidableEq

/-- The outcomes of every opaque step of one generator run. Proving, aggregation, the wallet gate
and the MLE prover/verifier are boundaries; the model fixes their outcomes and reasons about the
CHECKS the generator performs around them. -/
structure MsuFixtureRun where
  walletGateAccepted : Bool
  aggregateProved : Bool
  expected : Except MsuWitnessError MsuPublicInputs
  circuitProved : Bool
  circuitVerified : Bool
  provedLimbs : List Nat
  wrapped : Bool
  mleProved : Bool
  mleVerified : Bool
  exportGuard : Except GateGuardError Unit
  mleJsonPublicInputs : Option (List Nat)
  oldMemberPkGs : List Words8
  newMemberPkGs : List Words8

/-- `generate_fixture.rs::main`, in source order: the real wallet gate, the previous set's
aggregate, the native mirror, circuit proving, native verification, the proved-limbs assertion,
wrap + MLE prove/verify, the v1 export guard, and finally the MLE-JSON public-input assertions. -/
def runMemberSetUpdateFixture (r : MsuFixtureRun) : Except MsuFixtureError MsuDescriptor :=
  if !r.walletGateAccepted then .error .walletGateRejected
  else if !r.aggregateProved then .error .aggregateProvingFailed
  else
    match r.expected with
    | .error e => .error (.nativeMirrorRejected e)
    | .ok expected =>
      if !r.circuitProved then .error .circuitProvingFailed
      else if !r.circuitVerified then .error .circuitVerificationFailed
      else if r.provedLimbs ≠ expected.toU64Vec then
        .error .provedLimbsDisagreeWithNativeMirror
      else if !r.wrapped then .error .wrappingFailed
      else if !r.mleProved then .error .mleProvingFailed
      else if !r.mleVerified then .error .mleVerificationFailed
      else
        match r.exportGuard with
        | .error e => .error (.exportGuardRejected e)
        | .ok _ =>
          match r.mleJsonPublicInputs with
          | none => .error .mleJsonHasNoPublicInputs
          | some pis =>
            if pis.length ≠ memberSetUpdatePublicInputsLen then
              .error (.mlePublicInputsLengthMismatch pis.length)
            else if pis ≠ r.provedLimbs then .error .mlePublicInputsDisagreeWithProvedLimbs
            else
              .ok { channelId := expected.channelId
                    setVersion := expected.setVersion
                    oldCommitment := expected.oldCommitment
                    newCommitment := expected.newCommitment
                    oldCount := expected.oldCount
                    newCount := expected.newCount
                    recipient := expected.recipient
                    oldMemberPkGs := r.oldMemberPkGs
                    newMemberPkGs := r.newMemberPkGs
                    rotatedSlot := descriptorRotatedSlotLiteral }

theorem msu_fixture_runs_the_wallet_gate_first (r : MsuFixtureRun)
    (h : r.walletGateAccepted = false) :
    runMemberSetUpdateFixture r = .error .walletGateRejected := by
  simp [runMemberSetUpdateFixture, h]

/-- PUBLIC-INPUT THREADING. A written fixture has: the proved limbs equal to the native mirror's
26-limb encoding, and the exported MLE JSON's `publicInputs` equal to those same limbs. The
length assertion precedes the element-wise comparison, so a shorter or longer array can never be
silently zipped down to a passing prefix. -/
theorem msu_fixture_threads_the_public_inputs (r : MsuFixtureRun) (d : MsuDescriptor)
    (h : runMemberSetUpdateFixture r = .ok d) :
    ∃ expected, r.expected = .ok expected ∧
      r.provedLimbs = expected.toU64Vec ∧
      r.mleJsonPublicInputs = some r.provedLimbs ∧
      r.provedLimbs.length = memberSetUpdatePublicInputsLen ∧
      r.exportGuard = .ok () ∧
      d.oldCommitment = expected.oldCommitment ∧ d.newCommitment = expected.newCommitment ∧
      d.oldCount = expected.oldCount ∧ d.newCount = expected.newCount ∧
      d.recipient = expected.recipient ∧ d.rotatedSlot = descriptorRotatedSlotLiteral := by
  simp only [runMemberSetUpdateFixture] at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · rename_i expected hexp
        split at h
        · cases h
        · split at h
          · cases h
          · split at h
            · cases h
            · rename_i hlimbs
              split at h
              · cases h
              · split at h
                · cases h
                · split at h
                  · cases h
                  · split at h
                    · cases h
                    · rename_i hguard
                      split at h
                      · cases h
                      · rename_i pis hpis
                        split at h
                        · cases h
                        · rename_i hlen
                          split at h
                          · cases h
                          · rename_i heq
                            injection h with hd
                            subst hd
                            have hlimbs' : r.provedLimbs = expected.toU64Vec :=
                              Decidable.of_not_not hlimbs
                            have heq' : pis = r.provedLimbs := Decidable.of_not_not heq
                            refine ⟨expected, hexp, hlimbs', by rw [hpis, heq'], ?_, hguard,
                              rfl, rfl, rfl, rfl, rfl, rfl⟩
                            rw [← heq']
                            exact Decidable.of_not_not hlen

theorem msu_fixture_length_assert_precedes_element_comparison (r : MsuFixtureRun)
    (expected : MsuPublicInputs) (pis : List Nat) (hexp : r.expected = .ok expected)
    (hwallet : r.walletGateAccepted = true) (hagg : r.aggregateProved = true)
    (hproved : r.circuitProved = true) (hverified : r.circuitVerified = true)
    (hlimbs : r.provedLimbs = expected.toU64Vec) (hwrap : r.wrapped = true)
    (hmleproved : r.mleProved = true) (hmleverified : r.mleVerified = true)
    (hguard : r.exportGuard = .ok ()) (hpis : r.mleJsonPublicInputs = some pis)
    (hlen : pis.length ≠ memberSetUpdatePublicInputsLen) :
    runMemberSetUpdateFixture r = .error (.mlePublicInputsLengthMismatch pis.length) := by
  simp [runMemberSetUpdateFixture, hexp, hwallet, hagg, hproved, hverified, hlimbs, hwrap,
    hmleproved, hmleverified, hguard, hpis, hlen]

/-! ### 8.2 A concrete run, and what the descriptor does NOT bind -/

def sampleWords (a : Nat) : Words8 := ⟨a, 0, 0, 0, 0, 0, 0, 0⟩

def sampleMsuPublicInputs : MsuPublicInputs :=
  { channelId := 77, setVersion := 1, oldCommitment := sampleWords 11,
    newCommitment := sampleWords 22, oldCount := 3, newCount := 3, recipient := Address5.zero }

def sampleMsuLimbs : List Nat := sampleMsuPublicInputs.toU64Vec

def sampleMsuRun : MsuFixtureRun :=
  { walletGateAccepted := true, aggregateProved := true, expected := .ok sampleMsuPublicInputs,
    circuitProved := true, circuitVerified := true, provedLimbs := sampleMsuLimbs,
    wrapped := true, mleProved := true, mleVerified := true, exportGuard := .ok (),
    mleJsonPublicInputs := some sampleMsuLimbs, oldMemberPkGs := [sampleWords 1, sampleWords 2],
    newMemberPkGs := [sampleWords 1, sampleWords 3] }

def sampleMsuRunOtherKeys : MsuFixtureRun :=
  { sampleMsuRun with
    oldMemberPkGs := [sampleWords 5, sampleWords 6]
    newMemberPkGs := [sampleWords 5, sampleWords 7] }

def sampleMsuDescriptor : MsuDescriptor :=
  { channelId := 77, setVersion := 1, oldCommitment := sampleWords 11,
    newCommitment := sampleWords 22, oldCount := 3, newCount := 3, recipient := Address5.zero,
    oldMemberPkGs := [sampleWords 1, sampleWords 2],
    newMemberPkGs := [sampleWords 1, sampleWords 3], rotatedSlot := 1 }

def sampleMsuDescriptorOtherKeys : MsuDescriptor :=
  { sampleMsuDescriptor with
    oldMemberPkGs := [sampleWords 5, sampleWords 6]
    newMemberPkGs := [sampleWords 5, sampleWords 7] }

theorem msu_fixture_accepts_a_consistent_run :
    runMemberSetUpdateFixture sampleMsuRun = .ok sampleMsuDescriptor := rfl

/-- HONEST SCOPE. The descriptor's `oldMemberPkGs` / `newMemberPkGs` (the arrays the Solidity
test registers and applies) come from the WALLET objects, not from the proved public inputs:
the circuit exposes only the IMCM commitments. Two runs with identical proved limbs and
identical MLE public inputs can therefore write different key arrays. Binding them is the
Manager's `require(old_commitment == stored)` check plus the keccak preimage, neither of which
is proved here. -/
theorem msu_descriptor_key_arrays_are_not_bound_by_the_public_inputs :
    runMemberSetUpdateFixture sampleMsuRun = .ok sampleMsuDescriptor ∧
      runMemberSetUpdateFixture sampleMsuRunOtherKeys = .ok sampleMsuDescriptorOtherKeys ∧
      sampleMsuRun.provedLimbs = sampleMsuRunOtherKeys.provedLimbs ∧
      sampleMsuRun.mleJsonPublicInputs = sampleMsuRunOtherKeys.mleJsonPublicInputs ∧
      sampleMsuDescriptor.oldMemberPkGs ≠ sampleMsuDescriptorOtherKeys.oldMemberPkGs := by
  refine ⟨rfl, rfl, rfl, rfl, ?_⟩
  decide

theorem msu_fixture_rejects_a_public_input_mismatch :
    runMemberSetUpdateFixture
        { sampleMsuRun with mleJsonPublicInputs := some (0 :: sampleMsuLimbs.drop 1) } =
      .error .mlePublicInputsDisagreeWithProvedLimbs := rfl

/-! ## 9. Reachability of the retired path in a build

Models exactly the Cargo/`cfg` facts: `default = []` (Cargo.toml:177), the `deprecated-msu`
feature (Cargo.toml:223), `#[cfg(feature = "deprecated-msu")] pub mod deprecated` (lib.rs:15-19),
`required-features = ["deprecated-msu"]` for the fixture binary (Cargo.toml:255-257), and
`#[cfg(feature = "deprecated-msu")] pub mod deprecated_v1` (mle_prover.rs:953). It is NOT a
claim about what any operator or release pipeline actually enables. -/

def deprecatedMsuFeature : String := "deprecated-msu"

/-- `[features] default = []`. -/
def cargoDefaultFeatures : List String := []

def featureEnabled (features : List String) (f : String) : Bool :=
  features.any (fun x => x == f)

/-- `lib.rs:15-19`. -/
def deprecatedModuleCompiled (features : List String) : Bool :=
  featureEnabled features deprecatedMsuFeature

/-- `Cargo.toml:255-257`. -/
def msuFixtureBinaryBuildable (features : List String) : Bool :=
  featureEnabled features deprecatedMsuFeature

/-- `mle_prover.rs:953`. -/
def deprecatedV1ProverCompiled (features : List String) : Bool :=
  featureEnabled features deprecatedMsuFeature

/-- In a default build none of the three retired surfaces exist. -/
theorem deprecated_msu_is_absent_from_a_default_build :
    deprecatedModuleCompiled cargoDefaultFeatures = false ∧
      msuFixtureBinaryBuildable cargoDefaultFeatures = false ∧
      deprecatedV1ProverCompiled cargoDefaultFeatures = false := by decide

/-- The retired circuit, its fixture binary and the v1 prover/export are gated by one and the
same feature: enabling any of them enables all three, and none can appear on its own. -/
theorem deprecated_msu_surfaces_share_one_gate (features : List String) :
    deprecatedModuleCompiled features = msuFixtureBinaryBuildable features ∧
      msuFixtureBinaryBuildable features = deprecatedV1ProverCompiled features := ⟨rfl, rfl⟩

theorem deprecated_msu_requires_the_explicit_feature (features : List String)
    (h : deprecatedModuleCompiled features = true) : deprecatedMsuFeature ∈ features := by
  simp only [deprecatedModuleCompiled, featureEnabled, List.any_eq_true, beq_iff_eq] at h
  obtain ⟨f, hf, he⟩ := h
  rw [← he]
  exact hf

end Zkp.Implementation.MleProverBridge
