import Zkp.Implementation.BalancePublicInputs

/-!
# Block-layer value types

Handwritten implementation model of four `src/common` value types, all lines read:
`public_state.rs` (703), `block.rs` (450), `channel_registration.rs` (421) and
`channel_message.rs` (361). This is a semantic model of those files, NOT a refinement
proof of the Rust, of the plonky2 circuits they build, or of the Solidity twins whose
byte-equality the source pins with differential test constants.

The 15-word `PublicState` layout is REUSED from `BalancePublicInputs` (same five fields,
same word order) rather than duplicated. Native and target (in-circuit) encoders are
transcribed SEPARATELY here and only then proved equal, so a transcription slip shows up
as a failed proof rather than as a shared definition.

Everything cryptographic is an opaque callback: `solidity_keccak256`, the Poseidon hash,
the tree `init()/get_root()` environment, `compute_channel_action_root` and the
`Bytes32 -> PoseidonHashOut` canonicality predicate. No collision resistance, no
signature validity, no membership and no on-chain authenticity is asserted anywhere;
where the source's security argument needs injectivity of a hash, the corresponding
theorem takes injectivity ON THE CONCRETE COMPARED PAIR as an explicit premise.

`Nat` is a representative word domain. Range membership of a word (u32, u64, 63-bit
block number) is an explicit premise, never an enforced invariant of the model.
-/
namespace Zkp.Implementation.BlockTypes

/-! ## Shared word domain and pinned widths -/

abbrev Root := BalancePublicInputs.Root
/-- The Rust `Bytes32` / `U256`: eight u32 limbs, most significant first. -/
abbrev Bytes32 := BalancePublicInputs.Bytes8
abbrev TargetState := BalancePublicInputs.PublicState

abbrev wordBase : Nat := BalancePublicInputs.wordBase
abbrev blockLimit : Nat := BalancePublicInputs.blockLimit
abbrev scalarLimit : Nat := BalancePublicInputs.scalarLimit

def rootZero : Root := BalancePublicInputs.Root.zero
def bytes32Zero : Bytes32 := BalancePublicInputs.Bytes8.zero

def poseidonHashOutLen : Nat := 4
def u64Len : Nat := 2
def bytes32Len : Nat := 8
def addressLen : Nat := 5
def publicStateU64Len : Nat := 1 + u64Len + 3 * poseidonHashOutLen

theorem word_base_pinned : wordBase = 2 ^ 32 := rfl
theorem block_limit_pinned : blockLimit = 2 ^ 63 := rfl
theorem scalar_limit_pinned : scalarLimit = 2 ^ 64 := rfl
theorem poseidon_hash_out_len_pinned : poseidonHashOutLen = 4 := rfl
theorem u64_len_pinned : u64Len = 2 := rfl
theorem bytes32_len_pinned : bytes32Len = 8 := rfl
theorem address_len_pinned : addressLen = 5 := rfl
theorem public_state_u64_len_pinned : publicStateU64Len = 15 := rfl

/-- `U64::from(v)` splits into `[hi, lo]`; this is the high limb. -/
def splitHi (v : Nat) : Nat := v / wordBase
/-- Low limb of `U64::from(v)`. -/
def splitLo (v : Nat) : Nat := v % wordBase
/-- `u64::from(U64)` recombines `(hi << 32) | lo`. -/
def joinWords (hi lo : Nat) : Nat := hi * wordBase + lo

/-- `U64::to_u64_vec()` / `U64::to_u32_vec()`: the SAME two words, high limb first. -/
def u64Words (v : Nat) : List Nat := [splitHi v, splitLo v]

theorem join_split (v : Nat) : joinWords (splitHi v) (splitLo v) = v := by
  simp only [joinWords, splitHi, splitLo, Nat.mul_comm]
  exact Nat.div_add_mod v wordBase

theorem split_lo_lt (v : Nat) : splitLo v < wordBase := by
  simpa [splitLo] using Nat.mod_lt v (show 0 < wordBase by decide)

theorem split_hi_lt (v : Nat) (h : v < scalarLimit) : splitHi v < wordBase := by
  have : v / wordBase < 2 ^ 32 := by
    apply Nat.div_lt_of_lt_mul
    simpa [wordBase, BalancePublicInputs.wordBase] using
      (show v < 2 ^ 32 * 2 ^ 32 by simpa [scalarLimit, BalancePublicInputs.scalarLimit] using h)
  simpa [splitHi] using this

theorem split_pair_eq_iff (x y : Nat) (_hx : x < scalarLimit) (_hy : y < scalarLimit) :
    (splitHi x = splitHi y ∧ splitLo x = splitLo y) ↔ x = y := by
  constructor
  · rintro ⟨hh, hl⟩
    have := join_split x
    rw [hh, hl, join_split y] at this
    exact this.symm
  · rintro rfl
    exact ⟨rfl, rfl⟩

theorem bytes32_words_length (x : Bytes32) : x.words.length = bytes32Len := by
  simp [BalancePublicInputs.Bytes8.words, bytes32Len]

theorem root_words_length (r : Root) : r.words.length = poseidonHashOutLen := by
  simp [BalancePublicInputs.Root.words, poseidonHashOutLen]

theorem root_words_injective {x y : Root} (h : x.words = y.words) : x = y := by
  cases x; cases y; simpa [BalancePublicInputs.Root.words] using h

theorem bytes32_words_injective {x y : Bytes32} (h : x.words = y.words) : x = y := by
  cases x; cases y; simpa [BalancePublicInputs.Bytes8.words] using h

/-! ## public_state.rs — the 15-word `PublicState` -/

/-- The native `PublicState`: `timestamp` is one `u64` value, split only by the encoder. -/
structure NativePublicState where
  blockNumber : Nat
  timestamp : Nat
  accountRoot : Root
  depositRoot : Root
  previousRoot : Root
  deriving DecidableEq, Repr

/-- The in-circuit `PublicStateTarget` holds the timestamp already split into two wires;
    that is exactly the shared `BalancePublicInputs.PublicState` word view. -/
def NativePublicState.view (s : NativePublicState) : TargetState :=
  ⟨s.blockNumber, splitHi s.timestamp, splitLo s.timestamp,
    s.accountRoot, s.depositRoot, s.previousRoot⟩

/-- `PublicState::to_u64_vec`: `[block_number] ++ U64(timestamp) ++ three 4-word roots`. -/
def NativePublicState.toU64Vec (s : NativePublicState) : List Nat :=
  [s.blockNumber] ++ u64Words s.timestamp ++ s.accountRoot.words ++
    s.depositRoot.words ++ s.previousRoot.words

/-- SEPARATE transcription of `PublicStateTarget::to_vec` (wire order, no shared helper). -/
def targetToVec (t : TargetState) : List Nat :=
  [t.blockNumber, t.timestampHi, t.timestampLo,
    t.accountRoot.a, t.accountRoot.b, t.accountRoot.c, t.accountRoot.d,
    t.depositRoot.a, t.depositRoot.b, t.depositRoot.c, t.depositRoot.d,
    t.previousRoot.a, t.previousRoot.b, t.previousRoot.c, t.previousRoot.d]

inductive PublicStateFault where
  /-- `PublicStateError::InvalidLength { expected, actual }`. -/
  | invalidLength (expected actual : Nat)
  /-- `BlockNumberError::ValueOverflow` surfaced as `PublicStateError::BlockNumber`. -/
  | blockNumberOverflow (value : Nat)
  /-- `EthereumTypeError::OutOfU32Range` surfaced as `PublicStateError::Timestamp`. -/
  | timestampOutOfU32Range
  /-- `PublicStateTarget::from_slice` uses `assert_eq!`, i.e. it panics. -/
  | targetLengthPanic (expected actual : Nat)
  deriving DecidableEq, Repr

def readRoot (xs : List Nat) (offset : Nat) : Root := BalancePublicInputs.Root.read xs offset

/-- `PublicState::from_u64_slice`, in the source's check order. Note that the three
    Poseidon roots get NO canonical-field check: `PoseidonHashOut::from_u64_slice` only
    checks the slice length, which is exact by construction here. -/
def publicStateFromU64Slice (xs : List Nat) : Except PublicStateFault NativePublicState :=
  if xs.length ≠ publicStateU64Len then
    .error (.invalidLength publicStateU64Len xs.length)
  else if xs.getD 0 0 ≥ blockLimit then
    .error (.blockNumberOverflow (xs.getD 0 0))
  else if xs.getD 1 0 ≥ wordBase ∨ xs.getD 2 0 ≥ wordBase then
    .error .timestampOutOfU32Range
  else
    .ok ⟨xs.getD 0 0, joinWords (xs.getD 1 0) (xs.getD 2 0),
      readRoot xs 3, readRoot xs 7, readRoot xs 11⟩

/-- `PublicStateTarget::from_slice`: exact-width assertion, then pure wire slicing. -/
def targetFromSlice (xs : List Nat) : Except PublicStateFault TargetState :=
  if xs.length = publicStateU64Len then
    .ok ⟨xs.getD 0 0, xs.getD 1 0, xs.getD 2 0, readRoot xs 3, readRoot xs 7, readRoot xs 11⟩
  else .error (.targetLengthPanic publicStateU64Len xs.length)

/-- The native domain the Rust types can actually hold. -/
def PublicStateDomain (s : NativePublicState) : Prop :=
  s.blockNumber < blockLimit ∧ s.timestamp < scalarLimit

theorem public_state_encoding_width (s : NativePublicState) :
    s.toU64Vec.length = publicStateU64Len := by
  simp [NativePublicState.toU64Vec, u64Words, BalancePublicInputs.Root.words, publicStateU64Len,
    u64Len, poseidonHashOutLen]

theorem public_state_native_and_target_encoders_agree (s : NativePublicState) :
    targetToVec s.view = s.toU64Vec := by
  simp [targetToVec, NativePublicState.toU64Vec, NativePublicState.view, u64Words,
    BalancePublicInputs.Root.words]

theorem public_state_field_offsets (s : NativePublicState) :
    s.toU64Vec.getD 0 0 = s.blockNumber ∧
    s.toU64Vec.getD 1 0 = splitHi s.timestamp ∧
    s.toU64Vec.getD 2 0 = splitLo s.timestamp ∧
    readRoot s.toU64Vec 3 = s.accountRoot ∧
    readRoot s.toU64Vec 7 = s.depositRoot ∧
    readRoot s.toU64Vec 11 = s.previousRoot := by
  cases s with
  | mk bn ts a d p =>
    cases a; cases d; cases p
    refine ⟨rfl, rfl, rfl, ?_, ?_, ?_⟩ <;>
      simp [NativePublicState.toU64Vec, u64Words, readRoot, BalancePublicInputs.Root.read,
        BalancePublicInputs.Root.words]

theorem public_state_native_roundtrip (s : NativePublicState) (dom : PublicStateDomain s) :
    publicStateFromU64Slice s.toU64Vec = .ok s := by
  obtain ⟨hbn, hts⟩ := dom
  cases s with
  | mk bn ts a d p =>
    cases a; cases d; cases p
    have hhi : splitHi ts < wordBase := split_hi_lt ts hts
    have hlo : splitLo ts < wordBase := split_lo_lt ts
    simp [publicStateFromU64Slice, NativePublicState.toU64Vec, u64Words, readRoot,
      BalancePublicInputs.Root.read, BalancePublicInputs.Root.words, publicStateU64Len,
      u64Len, poseidonHashOutLen, Nat.not_le.mpr hbn, Nat.not_le.mpr hhi, Nat.not_le.mpr hlo,
      join_split, Nat.lt_irrefl]

theorem public_state_encoding_injective {s t : NativePublicState}
    (doms : PublicStateDomain s) (domt : PublicStateDomain t) (h : s.toU64Vec = t.toU64Vec) :
    s = t := by
  have hs := public_state_native_roundtrip s doms
  have ht := public_state_native_roundtrip t domt
  rw [h, ht] at hs
  exact (Except.ok.inj hs).symm

theorem public_state_length_guard (xs : List Nat) (wrong : xs.length ≠ publicStateU64Len) :
    publicStateFromU64Slice xs = .error (.invalidLength publicStateU64Len xs.length) := by
  simp [publicStateFromU64Slice, wrong]

theorem public_state_rejects_overflowing_block_number (xs : List Nat)
    (len : xs.length = publicStateU64Len) (big : xs.getD 0 0 ≥ blockLimit) :
    publicStateFromU64Slice xs = .error (.blockNumberOverflow (xs.getD 0 0)) := by
  unfold publicStateFromU64Slice
  rw [if_neg (by simp [len]), if_pos big]

theorem public_state_rejects_wide_timestamp_word (xs : List Nat)
    (len : xs.length = publicStateU64Len) (small : xs.getD 0 0 < blockLimit)
    (wide : xs.getD 1 0 ≥ wordBase ∨ xs.getD 2 0 ≥ wordBase) :
    publicStateFromU64Slice xs = .error .timestampOutOfU32Range := by
  unfold publicStateFromU64Slice
  rw [if_neg (by simp [len]), if_neg (Nat.not_le.mpr small), if_pos wide]

/-- Positive example: a normal decode of a concrete 15-word state. -/
theorem public_state_decode_example :
    publicStateFromU64Slice [7, 1, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] =
      .ok ⟨7, joinWords 1 5, ⟨1, 2, 3, 4⟩, ⟨5, 6, 7, 8⟩, ⟨9, 10, 11, 12⟩⟩ := by
  rfl

/-- The Poseidon roots are copied verbatim: words far outside the Goldilocks field are
    accepted by the native parser. -/
theorem public_state_accepts_non_field_root_words :
    publicStateFromU64Slice
        [0, 0, 0, 2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63,
          2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63] =
      .ok ⟨0, 0, ⟨2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63⟩, ⟨2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63⟩,
        ⟨2 ^ 63, 2 ^ 63, 2 ^ 63, 2 ^ 63⟩⟩ := by
  rfl

theorem public_state_target_roundtrip (t : TargetState) :
    targetFromSlice (targetToVec t) = .ok t := by
  cases t with
  | mk bn hi lo a d p =>
    cases a; cases d; cases p
    simp [targetFromSlice, targetToVec, readRoot, BalancePublicInputs.Root.read,
      publicStateU64Len, u64Len, poseidonHashOutLen]

theorem public_state_target_asserts_exact_width (xs : List Nat)
    (wrong : xs.length ≠ publicStateU64Len) :
    targetFromSlice xs = .error (.targetLengthPanic publicStateU64Len xs.length) := by
  simp [targetFromSlice, wrong]

/-! ### `PublicStateTarget::is_equal` — five fields, timestamp compared limb-wise -/

/-- `U32LimbTargetTrait::is_equal` folds limb equalities into `builder._true()`. -/
def u64IsEqual (aHi aLo bHi bLo : Nat) : Bool := (true && (aHi == bHi)) && (aLo == bLo)

/-- `PoseidonHashOutTarget::is_equal` folds the four field limbs the same way. -/
def rootIsEqual (x y : Root) : Bool :=
  (((true && (x.a == y.a)) && (x.b == y.b)) && (x.c == y.c)) && (x.d == y.d)

/-- `U63Target::is_equal` is a single wire comparison. -/
def blockNumberIsEqual (a b : Nat) : Bool := a == b

/-- `PublicStateTarget::is_equal`, including the left-nested AND tree of the source. -/
def publicStateIsEqual (a b : TargetState) : Bool :=
  let blockEq := blockNumberIsEqual a.blockNumber b.blockNumber
  let timestampEq := u64IsEqual a.timestampHi a.timestampLo b.timestampHi b.timestampLo
  let accountEq := rootIsEqual a.accountRoot b.accountRoot
  let depositEq := rootIsEqual a.depositRoot b.depositRoot
  let prevEq := rootIsEqual a.previousRoot b.previousRoot
  (((blockEq && timestampEq) && accountEq) && depositEq) && prevEq

theorem root_is_equal_iff (x y : Root) : rootIsEqual x y = true ↔ x = y := by
  cases x; cases y
  simp [rootIsEqual, and_assoc]

theorem is_equal_compares_exactly_five_fields (a b : TargetState) :
    publicStateIsEqual a b = true ↔
      (a.blockNumber = b.blockNumber ∧
        (a.timestampHi = b.timestampHi ∧ a.timestampLo = b.timestampLo) ∧
        a.accountRoot = b.accountRoot ∧ a.depositRoot = b.depositRoot ∧
        a.previousRoot = b.previousRoot) := by
  simp [publicStateIsEqual, blockNumberIsEqual, u64IsEqual, root_is_equal_iff, and_assoc]

theorem is_equal_iff_states_equal (a b : TargetState) :
    publicStateIsEqual a b = true ↔ a = b := by
  rw [is_equal_compares_exactly_five_fields]
  cases a; cases b
  simp [and_assoc]

/-- The u64 timestamp is compared as two independent limbs; for in-range timestamps that
    is exactly equality of the underlying u64 values. -/
theorem is_equal_timestamp_split_matches_u64_equality (x y : Nat)
    (hx : x < scalarLimit) (hy : y < scalarLimit) :
    u64IsEqual (splitHi x) (splitLo x) (splitHi y) (splitLo y) = true ↔ x = y := by
  rw [show (u64IsEqual (splitHi x) (splitLo x) (splitHi y) (splitLo y) = true) ↔
      (splitHi x = splitHi y ∧ splitLo x = splitLo y) by simp [u64IsEqual]]
  exact split_pair_eq_iff x y hx hy

/-- A difference confined to the HIGH timestamp limb is caught. -/
theorem is_equal_detects_high_timestamp_limb (r : Root) :
    publicStateIsEqual ⟨0, 1, 0, r, r, r⟩ ⟨0, 0, 0, r, r, r⟩ = false := by
  cases r
  simp [publicStateIsEqual, blockNumberIsEqual, u64IsEqual, rootIsEqual]

/-- A difference confined to the previous-public-state root is caught. -/
theorem is_equal_detects_previous_root (a b : TargetState) (h : a.previousRoot ≠ b.previousRoot) :
    publicStateIsEqual a b = false := by
  have notEq : ¬ (publicStateIsEqual a b = true) := by
    rw [is_equal_compares_exactly_five_fields]
    intro contra
    exact h contra.2.2.2.2
  simpa using notEq

/-! ### `connect` and `conditional_assert_eq` -/

/-- `PublicStateTarget::connect` wires the same five fields. -/
def Connect (a b : TargetState) : Prop :=
  a.blockNumber = b.blockNumber ∧ a.timestampHi = b.timestampHi ∧
    a.timestampLo = b.timestampLo ∧ a.accountRoot = b.accountRoot ∧
    a.depositRoot = b.depositRoot ∧ a.previousRoot = b.previousRoot

/-- `conditional_assert_eq` imposes NOTHING when the condition wire is false. -/
def ConditionalAssertEq (cond : Bool) (a b : TargetState) : Prop := cond = true → Connect a b

theorem connect_forces_equality (a b : TargetState) : Connect a b ↔ a = b := by
  cases a; cases b
  simp [Connect]

theorem conditional_assert_eq_is_vacuous_when_false (a b : TargetState) :
    ConditionalAssertEq false a b := by
  intro h
  exact absurd h (by simp)

theorem conditional_assert_eq_true_forces_equality (a b : TargetState)
    (h : ConditionalAssertEq true a b) : a = b :=
  (connect_forces_equality a b).mp (h rfl)

/-! ### Defaults, the genesis state, and the empty-leaf divergence -/

/-- The three `init().get_root()` values; opaque tree environment. -/
structure TreeRoots where
  accountInit : Root
  depositInit : Root
  publicStateInit : Root
  deriving DecidableEq, Repr

/-- `PublicState::default()` — zero height, zero timestamp, the three INIT tree roots. -/
def defaultPublicState (e : TreeRoots) : NativePublicState :=
  ⟨0, 0, e.accountInit, e.depositInit, e.publicStateInit⟩

/-- `<PublicState as Leafable>::empty_leaf()` — zero height, zero timestamp, ZERO roots. -/
def emptyLeafPublicState : NativePublicState := ⟨0, 0, rootZero, rootZero, rootZero⟩

/-- `<PublicStateTarget as LeafableTarget>::empty_leaf()` = `constant(PublicState::default())`. -/
def targetEmptyLeaf (e : TreeRoots) : TargetState := (defaultPublicState e).view

theorem default_public_state_has_zero_height_and_timestamp (e : TreeRoots) :
    (defaultPublicState e).blockNumber = 0 ∧ (defaultPublicState e).timestamp = 0 :=
  ⟨rfl, rfl⟩

theorem default_public_state_is_in_domain (e : TreeRoots) :
    PublicStateDomain (defaultPublicState e) := by
  constructor <;> decide

/-- SECURITY-RELEVANT DIVERGENCE: the native `Leafable::empty_leaf` uses the DEFAULT
    (all-zero) Poseidon roots, while the target `LeafableTarget::empty_leaf` is the
    constant `PublicState::default()`, which carries the three tree INIT roots. Whenever
    an init root is non-zero the two empty leaves are different values. -/
theorem empty_leaf_native_and_target_differ (e : TreeRoots) (h : e.accountInit ≠ rootZero) :
    targetEmptyLeaf e ≠ emptyLeafPublicState.view := by
  intro hEq
  apply h
  have := congrArg BalancePublicInputs.PublicState.accountRoot hEq
  simpa [targetEmptyLeaf, defaultPublicState, emptyLeafPublicState,
    NativePublicState.view] using this

theorem target_empty_leaf_is_the_default_state (e : TreeRoots) :
    targetEmptyLeaf e = (defaultPublicState e).view := rfl

end Zkp.Implementation.BlockTypes
