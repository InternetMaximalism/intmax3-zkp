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
    checkFixtureJsonGates (some [sampleSerializedRow]) [sampleExpectedRow] = .ok () := by
  decide

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

end Zkp.Implementation.MleProverBridge
