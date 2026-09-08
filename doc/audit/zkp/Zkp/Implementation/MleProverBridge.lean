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
  simp [mleV2CompactSubmissionMetadata, sample_full_artifact_is_accepted, sampleEnv,
    sampleCompact, u32Max]

theorem sample_tampered_structured_proof_is_rejected :
    validateMleV2FullAgainstConfigJson sampleTamperedEnv "full" "config" =
      .error .structuredProofDisagrees := by
  simp [validateMleV2FullAgainstConfigJson, compactMleV2BytesFromFixture, decodeAndValidate,
    sampleTamperedEnv, sampleEnv, sampleTamperedFullFixture, sampleFullFixture,
    sampleConfigFixture, sampleCompactRecord, sampleCompact, sampleProofView]

end Zkp.Implementation.MleProverBridge
