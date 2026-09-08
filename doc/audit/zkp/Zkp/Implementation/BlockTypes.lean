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
  refine ⟨?_, ?_⟩
  · show (0 : Nat) < blockLimit
    decide
  · show (0 : Nat) < scalarLimit
    decide

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

/-! ### `get_num_users` and the `FullPublicState` send-leaf loop -/

/-- `get_num_users`: the FIRST supported count that is at least the requested length. -/
def getNumUsers (length : Nat) (supported : List Nat) : Option Nat :=
  supported.find? (fun n => decide (length ≤ n))

theorem get_num_users_fits (length : Nat) (supported : List Nat) (n : Nat)
    (found : getNumUsers length supported = some n) : length ≤ n ∧ n ∈ supported := by
  constructor
  · have := List.find?_some found
    simpa using this
  · exact List.mem_of_find?_eq_some found

theorem get_num_users_none_when_all_too_small (length : Nat) (supported : List Nat)
    (all : ∀ n ∈ supported, n < length) : getNumUsers length supported = none := by
  rw [getNumUsers, List.find?_eq_none]
  intro n mem
  have := all n mem
  simp
  omega

theorem get_num_users_example : getNumUsers 1 [1, 2] = some 1 := rfl
theorem get_num_users_overflow_example : getNumUsers 3 [1, 2] = none := rfl

/-- One `SendLeaf` of a channel's send tree. -/
structure SendLeaf where
  cur : Nat
  prev : Nat
  txTreeRoot : Bytes32
  deriving DecidableEq, Repr

/-- `send_leaves.last().map(|l| l.cur).unwrap_or(BlockNumber::default())`. -/
def lastCur (leaves : List SendLeaf) : Nat :=
  match leaves.reverse with
  | [] => 0
  | l :: _ => l.cur

theorem last_cur_append (l : List SendLeaf) (x : SendLeaf) : lastCur (l ++ [x]) = x.cur := by
  simp [lastCur]

/-- One iteration of `add_block_with_channel`'s `for &key_id in key_ids` loop: zero key
    ids are padding and skipped, and a channel that already has a leaf for this block is
    skipped. The `assert_eq!` channel-leaf sanity check is a panic, not modeled as a value. -/
def pushSendLeaf (blockNo : Nat) (txRoot : Bytes32) (leaves : List SendLeaf) (keyId : Nat) :
    List SendLeaf :=
  if keyId = 0 then leaves
  else if lastCur leaves = blockNo then leaves
  else leaves ++ [⟨blockNo, lastCur leaves, txRoot⟩]

def applySendLeaves (blockNo : Nat) (txRoot : Bytes32) (leaves : List SendLeaf)
    (keyIds : List Nat) : List SendLeaf :=
  keyIds.foldl (pushSendLeaf blockNo txRoot) leaves

theorem send_leaf_skips_zero_key_id (blockNo : Nat) (txRoot : Bytes32) (leaves : List SendLeaf) :
    pushSendLeaf blockNo txRoot leaves 0 = leaves := by
  simp [pushSendLeaf]

theorem send_leaf_noop_when_saturated (blockNo : Nat) (txRoot : Bytes32) (leaves : List SendLeaf)
    (keyId : Nat) (h : lastCur leaves = blockNo) :
    pushSendLeaf blockNo txRoot leaves keyId = leaves := by
  simp [pushSendLeaf, h]

theorem send_leaves_fold_noop_when_saturated (blockNo : Nat) (txRoot : Bytes32)
    (leaves : List SendLeaf) (h : lastCur leaves = blockNo) (ids : List Nat) :
    applySendLeaves blockNo txRoot leaves ids = leaves := by
  induction ids with
  | nil => rfl
  | cons k rest ih =>
      unfold applySendLeaves at *
      rw [List.foldl_cons, send_leaf_noop_when_saturated blockNo txRoot leaves k h]
      exact ih

/-- SECURITY-RELEVANT: however many active member slots a block lists, the channel gains
    AT MOST ONE send leaf per block — the first non-skipped key id saturates the list. -/
theorem send_leaf_appended_at_most_once_per_block (blockNo : Nat) (txRoot : Bytes32) :
    ∀ (ids : List Nat) (leaves : List SendLeaf),
      (applySendLeaves blockNo txRoot leaves ids).length ≤ leaves.length + 1 := by
  intro ids
  induction ids with
  | nil => intro leaves; simpa [applySendLeaves] using Nat.le_succ leaves.length
  | cons k rest ih =>
      intro leaves
      rw [applySendLeaves, List.foldl_cons]
      by_cases hk : k = 0
      · rw [show pushSendLeaf blockNo txRoot leaves k = leaves by simp [pushSendLeaf, hk]]
        simpa [applySendLeaves] using ih leaves
      · by_cases hs : lastCur leaves = blockNo
        · rw [send_leaf_noop_when_saturated blockNo txRoot leaves k hs]
          simpa [applySendLeaves] using ih leaves
        · have hpush : pushSendLeaf blockNo txRoot leaves k =
              leaves ++ [⟨blockNo, lastCur leaves, txRoot⟩] := by
            unfold pushSendLeaf; rw [if_neg hk, if_neg hs]
          rw [hpush]
          have hsat : lastCur (leaves ++ [(⟨blockNo, lastCur leaves, txRoot⟩ : SendLeaf)]) =
              blockNo := by rw [last_cur_append]
          have hfold := send_leaves_fold_noop_when_saturated blockNo txRoot
            (leaves ++ [(⟨blockNo, lastCur leaves, txRoot⟩ : SendLeaf)]) hsat rest
          rw [applySendLeaves] at hfold
          rw [hfold]
          simp

theorem send_leaves_unchanged_when_all_key_ids_zero (blockNo : Nat) (txRoot : Bytes32) :
    ∀ (ids : List Nat) (leaves : List SendLeaf), (∀ k ∈ ids, k = 0) →
      applySendLeaves blockNo txRoot leaves ids = leaves := by
  intro ids
  induction ids with
  | nil => intro leaves _; rfl
  | cons k rest ih =>
      intro leaves hzero
      have hk : k = 0 := hzero k (by simp)
      rw [applySendLeaves, List.foldl_cons,
        show pushSendLeaf blockNo txRoot leaves k = leaves by simp [pushSendLeaf, hk]]
      exact ih leaves (fun x mem => hzero x (by simp [mem]))

/-- Positive example: padding ids are dropped and a repeated active slot adds one leaf. -/
theorem send_leaves_example :
    applySendLeaves 1 bytes32Zero [] [0, 5, 5] = [⟨1, 0, bytes32Zero⟩] := by
  decide

/-! ## block.rs — the small block, its hash preimage and the block-hash chain -/

structure Block where
  numUsers : Nat
  channelId : Nat
  timestamp : Nat
  keyIds : List Nat
  txTreeRoot : Bytes32
  depositHashChain : Bytes32
  channelRegHashChain : Bytes32
  deriving DecidableEq, Repr

inductive BlockFault where
  /-- `BlockError::InvalidNumUsers`. -/
  | invalidNumUsers (keyIdCount numUsers : Nat)
  /-- `BlockTarget::constant` / `set_witness` disagree with `num_users`: a panic. -/
  | numUsersPanic (keyIdCount numUsers : Nat)
  deriving DecidableEq, Repr

/-- `key_ids.resize(num_users as usize, 0)` after the length guard. -/
def padKeyIds (numUsers : Nat) (ids : List Nat) : List Nat :=
  ids ++ List.replicate (numUsers - ids.length) 0

/-- `Block::new` (also reached through `new_with_channel` / `new_with_tx_v2s`). -/
def blockNew (numUsers channelId : Nat) (keyIds : List Nat) (timestamp : Nat)
    (txTreeRoot depositHashChain channelRegHashChain : Bytes32) : Except BlockFault Block :=
  if keyIds.length > numUsers then .error (.invalidNumUsers keyIds.length numUsers)
  else .ok ⟨numUsers, channelId, timestamp, padKeyIds numUsers keyIds, txTreeRoot,
    depositHashChain, channelRegHashChain⟩

/-- `Block::default()` — the genesis block pushed by `FullPublicState::new`. -/
def defaultBlock : Block := ⟨0, 0, 0, [], bytes32Zero, bytes32Zero, bytes32Zero⟩

/-- The keccak preimage of `Block::hash_with_prev_hash`:
    `prev(8) || channel_id(1) || timestamp(2) || key_ids(num_users) || tx_tree_root(8) ||
     deposit_hash_chain(8) || channel_reg_hash_chain(8)`. -/
def Block.hashPreimage (b : Block) (prev : Bytes32) : List Nat :=
  prev.words ++ ([b.channelId] ++ (u64Words b.timestamp ++ (b.keyIds ++
    (b.txTreeRoot.words ++ (b.depositHashChain.words ++ b.channelRegHashChain.words)))))

/-- SEPARATE transcription of `BlockTarget::hash_with_prev_hash`'s `inputs` vector, built
    by `push`/`extend` in the source's order (left-nested). -/
def blockTargetHashInputs (b : Block) (prev : Bytes32) : List Nat :=
  ((((((prev.words ++ [b.channelId]) ++ u64Words b.timestamp) ++ b.keyIds) ++
    b.txTreeRoot.words) ++ b.depositHashChain.words) ++ b.channelRegHashChain.words)

/-- `Block::hash_with_prev_hash`; `keccak` is the opaque `solidity_keccak256` callback. -/
def Block.hashWithPrevHash (keccak : List Nat → Bytes32) (b : Block) (prev : Bytes32) :
    Except BlockFault Bytes32 :=
  if b.keyIds.length ≠ b.numUsers then .error (.invalidNumUsers b.keyIds.length b.numUsers)
  else .ok (keccak (b.hashPreimage prev))

/-- `BlockTarget::constant` panics when the value's key ids do not fill `num_users`. -/
def blockTargetConstant (b : Block) : Except BlockFault Block :=
  if b.keyIds.length ≠ b.numUsers then .error (.numUsersPanic b.keyIds.length b.numUsers)
  else .ok b

theorem block_new_pads_to_num_users (numUsers channelId : Nat) (keyIds : List Nat)
    (timestamp : Nat) (t d r : Bytes32) (fits : keyIds.length ≤ numUsers) (b : Block)
    (built : blockNew numUsers channelId keyIds timestamp t d r = .ok b) :
    b.keyIds.length = numUsers ∧ b.numUsers = numUsers := by
  have hb : b = ⟨numUsers, channelId, timestamp, padKeyIds numUsers keyIds, t, d, r⟩ := by
    unfold blockNew at built
    rw [if_neg (by omega)] at built
    exact (Except.ok.inj built).symm
  subst hb
  refine ⟨?_, rfl⟩
  simp [padKeyIds]
  omega

theorem block_new_keeps_given_key_ids (numUsers : Nat) (ids : List Nat) :
    (padKeyIds numUsers ids).take ids.length = ids := by
  simp [padKeyIds]

theorem block_new_padding_is_zero (numUsers : Nat) (ids : List Nat) :
    (padKeyIds numUsers ids).drop ids.length = List.replicate (numUsers - ids.length) 0 := by
  simp [padKeyIds]

theorem block_new_rejects_overlong_key_ids (numUsers channelId : Nat) (keyIds : List Nat)
    (timestamp : Nat) (t d r : Bytes32) (tooMany : keyIds.length > numUsers) :
    blockNew numUsers channelId keyIds timestamp t d r =
      .error (.invalidNumUsers keyIds.length numUsers) := by
  simp [blockNew, tooMany]

/-- Positive example mirroring the source's own padding test. -/
theorem block_new_padding_example :
    blockNew 4 1 [10, 20] 100 bytes32Zero bytes32Zero bytes32Zero =
      .ok ⟨4, 1, 100, [10, 20, 0, 0], bytes32Zero, bytes32Zero, bytes32Zero⟩ := by
  rfl

theorem block_native_and_target_preimages_agree (b : Block) (prev : Bytes32) :
    blockTargetHashInputs b prev = b.hashPreimage prev := by
  simp [blockTargetHashInputs, Block.hashPreimage, List.append_assoc]

theorem block_preimage_width (b : Block) (prev : Bytes32) :
    (b.hashPreimage prev).length = 35 + b.keyIds.length := by
  simp [Block.hashPreimage, u64Words, BalancePublicInputs.Bytes8.words]
  omega

theorem block_preimage_prefix (b : Block) (prev : Bytes32) :
    b.hashPreimage prev =
      (prev.words ++ [b.channelId] ++ u64Words b.timestamp ++ b.keyIds ++
        b.txTreeRoot.words ++ b.depositHashChain.words) ++ b.channelRegHashChain.words := by
  simp [Block.hashPreimage, List.append_assoc]

theorem block_preimage_prefix_length (b : Block) (prev : Bytes32) :
    (prev.words ++ [b.channelId] ++ u64Words b.timestamp ++ b.keyIds ++
      b.txTreeRoot.words ++ b.depositHashChain.words).length = 27 + b.keyIds.length := by
  simp [u64Words, BalancePublicInputs.Bytes8.words]
  omega

theorem block_hash_requires_padded_key_ids (keccak : List Nat → Bytes32) (b : Block)
    (prev : Bytes32) (unpadded : b.keyIds.length ≠ b.numUsers) :
    Block.hashWithPrevHash keccak b prev = .error (.invalidNumUsers b.keyIds.length b.numUsers) := by
  simp [Block.hashWithPrevHash, unpadded]

theorem block_hash_of_padded_block (keccak : List Nat → Bytes32) (b : Block) (prev : Bytes32)
    (padded : b.keyIds.length = b.numUsers) :
    Block.hashWithPrevHash keccak b prev = .ok (keccak (b.hashPreimage prev)) := by
  simp [Block.hashWithPrevHash, padded]

/-- The genesis block hashes: `Block::default()` already satisfies `key_ids.len() = 0`. -/
theorem genesis_block_hashes (keccak : List Nat → Bytes32) (prev : Bytes32) :
    Block.hashWithPrevHash keccak defaultBlock prev =
      .ok (keccak (defaultBlock.hashPreimage prev)) := by
  simp [Block.hashWithPrevHash, defaultBlock]

theorem append_inj_bytes32 {x y : Bytes32} {s t : List Nat} (h : x.words ++ s = y.words ++ t) :
    x = y ∧ s = t := by
  obtain ⟨h1, h2⟩ := List.append_inj h (by rw [bytes32_words_length, bytes32_words_length])
  exact ⟨bytes32_words_injective h1, h2⟩

/-- The block-hash preimage determines every field of the block and the folded previous
    hash: the encoding is injective on padded blocks of a fixed width. -/
theorem block_preimage_injective {b b' : Block} {prev prev' : Bytes32}
    (sameWidth : b.keyIds.length = b'.keyIds.length)
    (ts : b.timestamp < scalarLimit) (ts' : b'.timestamp < scalarLimit)
    (sameUsers : b.numUsers = b'.numUsers)
    (h : b.hashPreimage prev = b'.hashPreimage prev') : prev = prev' ∧ b = b' := by
  unfold Block.hashPreimage at h
  obtain ⟨hprev, h⟩ := append_inj_bytes32 h
  simp only [List.cons_append, List.nil_append, List.cons.injEq, u64Words] at h
  obtain ⟨hcid, hhi, hlo, h⟩ := h
  obtain ⟨hkeys, h⟩ := List.append_inj h sameWidth
  obtain ⟨htx, h⟩ := append_inj_bytes32 h
  obtain ⟨hdep, hregWords⟩ := append_inj_bytes32 h
  have hreg : b.channelRegHashChain = b'.channelRegHashChain := bytes32_words_injective hregWords
  have htime : b.timestamp = b'.timestamp := (split_pair_eq_iff _ _ ts ts').mp ⟨hhi, hlo⟩
  refine ⟨hprev, ?_⟩
  show (⟨b.numUsers, b.channelId, b.timestamp, b.keyIds, b.txTreeRoot, b.depositHashChain,
      b.channelRegHashChain⟩ : Block) =
    ⟨b'.numUsers, b'.channelId, b'.timestamp, b'.keyIds, b'.txTreeRoot, b'.depositHashChain,
      b'.channelRegHashChain⟩
  rw [sameUsers, hcid, htime, hkeys, htx, hdep, hreg]

/-- G6: the on-chain channel-registration chain is folded into the block hash. With hash
    injectivity assumed ON THIS CONCRETE PAIR (an explicit, undischarged premise — the
    model asserts no collision resistance), two blocks that differ only in the
    registration chain get different block hashes. -/
theorem reg_chain_binds_block_hash (keccak : List Nat → Bytes32) {b b' : Block} {prev : Bytes32}
    (sameWidth : b.keyIds.length = b'.keyIds.length)
    (ts : b.timestamp < scalarLimit) (ts' : b'.timestamp < scalarLimit)
    (sameUsers : b.numUsers = b'.numUsers)
    (differ : b.channelRegHashChain ≠ b'.channelRegHashChain)
    (inj : keccak (b.hashPreimage prev) = keccak (b'.hashPreimage prev) →
      b.hashPreimage prev = b'.hashPreimage prev) :
    keccak (b.hashPreimage prev) ≠ keccak (b'.hashPreimage prev) := by
  intro hEq
  apply differ
  have := (block_preimage_injective sameWidth ts ts' sameUsers (inj hEq)).2
  rw [this]

/-! ### `FullPublicState`: genesis and one `add_block_with_channel` step -/

structure FullState where
  blockNumber : Nat
  /-- `blocks.last().timestamp`, i.e. what `to_public_state` reports. -/
  lastTimestamp : Nat
  accountRoot : Root
  depositRoot : Root
  publicStateRoot : Root
  blockHashChain : Bytes32
  depositHashChain : Bytes32
  channelRegHashChain : Bytes32
  sendLeaves : List SendLeaf
  deriving DecidableEq, Repr

/-- `FullPublicState::new`: height 0, the three init roots, zero chains and one genesis
    `Block::default()` whose timestamp is 0. -/
def genesisFullState (e : TreeRoots) : FullState :=
  ⟨0, 0, e.accountInit, e.depositInit, e.publicStateInit, bytes32Zero, bytes32Zero,
    bytes32Zero, []⟩

/-- `FullPublicState::to_public_state`. -/
def FullState.toPublicState (st : FullState) : NativePublicState :=
  ⟨st.blockNumber, st.lastTimestamp, st.accountRoot, st.depositRoot, st.publicStateRoot⟩

inductive FullFault where
  | tooManyKeyIds (count : Nat)
  /-- `BlockError`; note the source `expect`s (panics) on the hashing step. -/
  | block (fault : BlockFault)
  deriving DecidableEq, Repr

/-- `FullPublicState::add_block_with_channel`. `keccak` and `pushPublicState` are opaque
    callbacks (`solidity_keccak256`, `PublicStateTree::push`). -/
def addBlockWithChannel (keccak : List Nat → Bytes32)
    (pushPublicState : Root → NativePublicState → Root) (supported : List Nat)
    (st : FullState) (channelId : Nat) (keyIds : List Nat) (timestamp : Nat)
    (txTreeRoot : Bytes32) : Except FullFault FullState :=
  match getNumUsers keyIds.length supported with
  | none => .error (.tooManyKeyIds keyIds.length)
  | some numUsers =>
    match blockNew numUsers channelId keyIds timestamp txTreeRoot st.depositHashChain
        st.channelRegHashChain with
    | .error e => .error (.block e)
    | .ok block =>
      match Block.hashWithPrevHash keccak block st.blockHashChain with
      | .error e => .error (.block e)
      | .ok chain =>
        .ok { st with
          blockNumber := st.blockNumber + 1,
          lastTimestamp := timestamp,
          publicStateRoot := pushPublicState st.publicStateRoot st.toPublicState,
          blockHashChain := chain,
          sendLeaves := applySendLeaves (st.blockNumber + 1) txTreeRoot st.sendLeaves keyIds }

theorem genesis_full_state_is_zero_height (e : TreeRoots) :
    (genesisFullState e).blockNumber = 0 ∧ (genesisFullState e).lastTimestamp = 0 ∧
      (genesisFullState e).blockHashChain = bytes32Zero :=
  ⟨rfl, rfl, rfl⟩

theorem genesis_public_state_is_the_default (e : TreeRoots) :
    (genesisFullState e).toPublicState = defaultPublicState e := rfl

theorem add_block_rejects_too_many_key_ids (keccak : List Nat → Bytes32)
    (push : Root → NativePublicState → Root) (supported : List Nat) (st : FullState)
    (channelId : Nat) (keyIds : List Nat) (timestamp : Nat) (txTreeRoot : Bytes32)
    (none : getNumUsers keyIds.length supported = none) :
    addBlockWithChannel keccak push supported st channelId keyIds timestamp txTreeRoot =
      .error (.tooManyKeyIds keyIds.length) := by
  simp [addBlockWithChannel, none]

/-- The whole accepted step, in one place: height +1, timestamp of the new block, the
    previous public state pushed into the history tree BEFORE the update, the block hash
    chain folded over the new block's preimage, and at most one new send leaf. -/
theorem add_block_step (keccak : List Nat → Bytes32)
    (push : Root → NativePublicState → Root) (supported : List Nat) (st : FullState)
    (channelId : Nat) (keyIds : List Nat) (timestamp : Nat) (txTreeRoot : Bytes32)
    (numUsers : Nat) (found : getNumUsers keyIds.length supported = some numUsers)
    (fits : keyIds.length ≤ numUsers) :
    addBlockWithChannel keccak push supported st channelId keyIds timestamp txTreeRoot =
      .ok { st with
        blockNumber := st.blockNumber + 1,
        lastTimestamp := timestamp,
        publicStateRoot := push st.publicStateRoot st.toPublicState,
        blockHashChain := keccak
          ((⟨numUsers, channelId, timestamp, padKeyIds numUsers keyIds, txTreeRoot,
              st.depositHashChain, st.channelRegHashChain⟩ : Block).hashPreimage
            st.blockHashChain),
        sendLeaves := applySendLeaves (st.blockNumber + 1) txTreeRoot st.sendLeaves keyIds } := by
  have hpad : (padKeyIds numUsers keyIds).length = numUsers := by
    simp [padKeyIds]; omega
  simp [addBlockWithChannel, found, blockNew, Nat.not_lt.mpr fits, Block.hashWithPrevHash, hpad]

theorem add_block_increments_height (keccak : List Nat → Bytes32)
    (push : Root → NativePublicState → Root) (supported : List Nat) (st : FullState)
    (channelId : Nat) (keyIds : List Nat) (timestamp : Nat) (txTreeRoot : Bytes32)
    (numUsers : Nat) (found : getNumUsers keyIds.length supported = some numUsers)
    (fits : keyIds.length ≤ numUsers) (next : FullState)
    (stepped : addBlockWithChannel keccak push supported st channelId keyIds timestamp
      txTreeRoot = .ok next) :
    next.blockNumber = st.blockNumber + 1 ∧ next.lastTimestamp = timestamp ∧
      next.depositHashChain = st.depositHashChain ∧
      next.channelRegHashChain = st.channelRegHashChain := by
  rw [add_block_step keccak push supported st channelId keyIds timestamp txTreeRoot numUsers
    found fits] at stepped
  rw [← Except.ok.inj stepped]
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- The snapshot pushed into the public-state history is the state BEFORE the update: old
    height, old timestamp, old roots. -/
theorem add_block_snapshots_the_previous_state (st : FullState) :
    st.toPublicState = ⟨st.blockNumber, st.lastTimestamp, st.accountRoot, st.depositRoot,
      st.publicStateRoot⟩ := rfl

/-! ## channel_registration.rs — the fixed 8-slot registration record -/

def maxSigCluster : Nat := 8
def memberSlotU32Len : Nat := 3 * bytes32Len + addressLen
def channelRegPreimageU32Len : Nat := 8 + 1 + 1 + 1 + 1 + maxSigCluster * memberSlotU32Len

theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl
theorem member_slot_u32_len_pinned : memberSlotU32Len = 29 := rfl
theorem channel_reg_preimage_u32_len_pinned : channelRegPreimageU32Len = 244 := rfl

/-- The L1 `Address`: five u32 limbs. -/
structure Address where
  l0 : Nat
  l1 : Nat
  l2 : Nat
  l3 : Nat
  l4 : Nat
  deriving DecidableEq, Repr

def Address.words (a : Address) : List Nat := [a.l0, a.l1, a.l2, a.l3, a.l4]
def addressZero : Address := ⟨0, 0, 0, 0, 0⟩

theorem address_words_length (a : Address) : a.words.length = addressLen := by
  simp [Address.words, addressLen]

theorem address_words_injective {x y : Address} (h : x.words = y.words) : x = y := by
  cases x; cases y; simpa [Address.words] using h

structure MemberRegEntry where
  pkG : Bytes32
  pkB : Bytes32
  regevPkDigest : Bytes32
  recipient : Address
  deriving DecidableEq, Repr

def memberZero : MemberRegEntry := ⟨bytes32Zero, bytes32Zero, bytes32Zero, addressZero⟩

/-- One member slot's contribution: `pk_g(8) || pk_b(8) || regev_pk_digest(8) ||
    recipient(5)`. -/
def MemberRegEntry.words (m : MemberRegEntry) : List Nat :=
  m.pkG.words ++ (m.pkB.words ++ (m.regevPkDigest.words ++ m.recipient.words))

/-- SEPARATE transcription of `MemberRegEntryTarget::to_u32_stream`. -/
def memberTargetStream (m : MemberRegEntry) : List Nat :=
  ((m.pkG.words ++ m.pkB.words) ++ m.regevPkDigest.words) ++ m.recipient.words

structure ChannelRegRecord where
  channelId : Nat
  bpMemberSlot : Nat
  memberCount : Nat
  delegateCount : Nat
  members : List MemberRegEntry
  deriving DecidableEq, Repr

inductive ChannelRegFault where
  | memberCountOutOfRange (count : Nat)
  | delegateCountNonZero (count : Nat)
  | zeroActivePkG (index : Nat)
  | nonCanonicalPkG (index : Nat)
  | nonCanonicalPkB (index : Nat)
  | nonCanonicalRegevPkDigest (index : Nat)
  | duplicatePkG (i j : Nat)
  | nonZeroPaddingSlot (index : Nat)
  | bpMemberSlotOutOfRange (slot count : Nat)
  deriving DecidableEq, Repr

/-- `PoseidonHashOut::try_from(Bytes32)` as an OPAQUE predicate: the model says nothing
    about which encodings it accepts. -/
abbrev CanonicalCheck := Bytes32 → Bool

/-- One active slot of `ChannelRegRecord::validate`, in the source's check order:
    zero pk_g, then the three canonicality checks, then the forward duplicate scan. -/
def checkActiveSlot (canonical : CanonicalCheck) (members : List MemberRegEntry) (mc i : Nat) :
    Except ChannelRegFault Unit :=
  let m := members.getD i memberZero
  if m.pkG = bytes32Zero then .error (.zeroActivePkG i)
  else if canonical m.pkG = false then .error (.nonCanonicalPkG i)
  else if canonical m.pkB = false then .error (.nonCanonicalPkB i)
  else if canonical m.regevPkDigest = false then .error (.nonCanonicalRegevPkDigest i)
  else
    match ((List.range mc).filter (fun j => decide (i < j))).find?
        (fun j => decide ((members.getD j memberZero).pkG = m.pkG)) with
    | some j => .error (.duplicatePkG i j)
    | none => .ok ()

def checkActiveSlots (canonical : CanonicalCheck) (members : List MemberRegEntry) (mc : Nat) :
    Except ChannelRegFault Unit :=
  (List.range mc).forM (checkActiveSlot canonical members mc)

/-- Padding slots `member_count..MAX_SIG_CLUSTER` must be exactly default. -/
def checkPaddingSlots (members : List MemberRegEntry) (mc : Nat) : Except ChannelRegFault Unit :=
  (List.range (maxSigCluster - mc)).forM fun k =>
    if members.getD (mc + k) memberZero ≠ memberZero then .error (.nonZeroPaddingSlot (mc + k))
    else .ok ()

/-- `ChannelRegRecord::validate`, preserving the source's error precedence. -/
def validateChannelReg (canonical : CanonicalCheck) (r : ChannelRegRecord) :
    Except ChannelRegFault Unit :=
  if r.memberCount < 2 ∨ r.memberCount > maxSigCluster then
    .error (.memberCountOutOfRange r.memberCount)
  else if r.delegateCount ≠ 0 then .error (.delegateCountNonZero r.delegateCount)
  else
    match checkActiveSlots canonical r.members r.memberCount with
    | .error e => .error e
    | .ok () =>
      match checkPaddingSlots r.members r.memberCount with
      | .error e => .error e
      | .ok () =>
        if r.bpMemberSlot ≥ r.memberCount then
          .error (.bpMemberSlotOutOfRange r.bpMemberSlot r.memberCount)
        else .ok ()

theorem channel_reg_rejects_small_member_count (canonical : CanonicalCheck)
    (r : ChannelRegRecord) (small : r.memberCount < 2) :
    validateChannelReg canonical r = .error (.memberCountOutOfRange r.memberCount) := by
  simp [validateChannelReg, small]

theorem channel_reg_rejects_oversized_member_count (canonical : CanonicalCheck)
    (r : ChannelRegRecord) (big : r.memberCount > maxSigCluster) :
    validateChannelReg canonical r = .error (.memberCountOutOfRange r.memberCount) := by
  simp [validateChannelReg, big]

/-- Cosigner-only L1 registration: any non-zero delegate count is rejected, and the
    member-count range check is reported FIRST when both are wrong. -/
theorem channel_reg_rejects_nonzero_delegate_count (canonical : CanonicalCheck)
    (r : ChannelRegRecord) (inRange : 2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster)
    (delegated : r.delegateCount ≠ 0) :
    validateChannelReg canonical r = .error (.delegateCountNonZero r.delegateCount) := by
  obtain ⟨lo, hi⟩ := inRange
  simp [validateChannelReg, Nat.not_lt.mpr lo, Nat.not_lt.mpr hi, delegated]

theorem channel_reg_member_count_checked_before_delegate_count (canonical : CanonicalCheck)
    (r : ChannelRegRecord) (small : r.memberCount < 2) (_delegated : r.delegateCount ≠ 0) :
    validateChannelReg canonical r = .error (.memberCountOutOfRange r.memberCount) := by
  simp [validateChannelReg, small]

theorem channel_reg_rejects_bp_slot_out_of_range (canonical : CanonicalCheck)
    (r : ChannelRegRecord) (inRange : 2 ≤ r.memberCount ∧ r.memberCount ≤ maxSigCluster)
    (noDelegates : r.delegateCount = 0)
    (active : checkActiveSlots canonical r.members r.memberCount = .ok ())
    (padding : checkPaddingSlots r.members r.memberCount = .ok ())
    (slot : r.bpMemberSlot ≥ r.memberCount) :
    validateChannelReg canonical r =
      .error (.bpMemberSlotOutOfRange r.bpMemberSlot r.memberCount) := by
  obtain ⟨lo, hi⟩ := inRange
  simp [validateChannelReg, Nat.not_lt.mpr lo, Nat.not_lt.mpr hi, noDelegates, active, padding,
    slot]

/-- HONESTY / SECURITY: the three "non-canonical encoding" rejections are only as strong
    as the `PoseidonHashOut::try_from` callback. With a TOTAL callback they never fire —
    which is what the deployed `TryFrom<Bytes32>` is, because splitting a u64 into two
    u32 limbs and recombining them round-trips every `Bytes32` exactly. -/
theorem canonicality_rejections_come_only_from_the_callback (members : List MemberRegEntry)
    (mc i : Nat) :
    checkActiveSlot (fun _ => true) members mc i ≠ .error (.nonCanonicalPkG i) ∧
      checkActiveSlot (fun _ => true) members mc i ≠ .error (.nonCanonicalPkB i) ∧
      checkActiveSlot (fun _ => true) members mc i ≠ .error (.nonCanonicalRegevPkDigest i) := by
  refine ⟨?_, ?_, ?_⟩ <;>
    · unfold checkActiveSlot
      simp only [Bool.false_eq_true, if_false, reduceIte]
      split
      · simp
      · split <;> simp

/-! ### The R3 word-aligned registration preimage -/

def memberStream (members : List MemberRegEntry) : List Nat :=
  (members.map MemberRegEntry.words).join

/-- `ChannelRegRecord::hash_with_prev_hash`:
    `prev(8) || channel_id(1) || bp_member_slot(1) || member_count(1) || delegate_count(1)
     || 8 * (pk_g(8) || pk_b(8) || regev(8) || recipient(5))`. -/
def ChannelRegRecord.hashPreimage (r : ChannelRegRecord) (prev : Bytes32) : List Nat :=
  prev.words ++ ([r.channelId] ++ ([r.bpMemberSlot] ++ ([r.memberCount] ++
    ([r.delegateCount] ++ memberStream r.members))))

/-- SEPARATE transcription of `channel_reg_hash_with_prev_hash_circuit`. -/
def channelRegCircuitInputs (r : ChannelRegRecord) (prev : Bytes32) : List Nat :=
  ((((prev.words ++ [r.channelId]) ++ [r.bpMemberSlot]) ++ [r.memberCount]) ++
    [r.delegateCount]) ++ (r.members.map memberTargetStream).join

theorem member_words_length (m : MemberRegEntry) : m.words.length = memberSlotU32Len := by
  simp [MemberRegEntry.words, BalancePublicInputs.Bytes8.words, Address.words, memberSlotU32Len,
    bytes32Len, addressLen]

theorem member_words_injective {m n : MemberRegEntry} (h : m.words = n.words) : m = n := by
  unfold MemberRegEntry.words at h
  obtain ⟨hg, h⟩ := append_inj_bytes32 h
  obtain ⟨hb, h⟩ := append_inj_bytes32 h
  obtain ⟨hr, haddr⟩ := append_inj_bytes32 h
  have hrec : m.recipient = n.recipient := address_words_injective haddr
  show (⟨m.pkG, m.pkB, m.regevPkDigest, m.recipient⟩ : MemberRegEntry) =
    ⟨n.pkG, n.pkB, n.regevPkDigest, n.recipient⟩
  rw [hg, hb, hr, hrec]

theorem member_target_stream_agrees (m : MemberRegEntry) : memberTargetStream m = m.words := by
  simp [memberTargetStream, MemberRegEntry.words, List.append_assoc]

theorem member_stream_length (ms : List MemberRegEntry) :
    (memberStream ms).length = memberSlotU32Len * ms.length := by
  induction ms with
  | nil => simp [memberStream]
  | cons m rest ih =>
      simp only [memberStream, List.map_cons, List.join_cons, List.length_append,
        List.length_cons] at *
      rw [member_words_length, ih, Nat.mul_succ]
      omega

theorem member_stream_injective : ∀ {ms ns : List MemberRegEntry}, ms.length = ns.length →
    memberStream ms = memberStream ns → ms = ns := by
  intro ms
  induction ms with
  | nil => intro ns len _; cases ns with
    | nil => rfl
    | cons _ _ => simp at len
  | cons m rest ih =>
      intro ns len h
      cases ns with
      | nil => simp at len
      | cons n rest' =>
          simp only [memberStream, List.map_cons, List.join_cons] at h
          obtain ⟨hw, hrest⟩ := List.append_inj h
            (by rw [member_words_length, member_words_length])
          have hm : m = n := member_words_injective hw
          have := ih (by simpa using len) hrest
          rw [hm, this]

theorem channel_reg_native_and_circuit_inputs_agree (r : ChannelRegRecord) (prev : Bytes32) :
    channelRegCircuitInputs r prev = r.hashPreimage prev := by
  have hmap : (r.members.map memberTargetStream) = (r.members.map MemberRegEntry.words) := by
    apply List.map_congr_left
    intro m _
    exact member_target_stream_agrees m
  simp [channelRegCircuitInputs, ChannelRegRecord.hashPreimage, memberStream, hmap,
    List.append_assoc]

theorem channel_reg_preimage_width (r : ChannelRegRecord) (prev : Bytes32)
    (slots : r.members.length = maxSigCluster) :
    (r.hashPreimage prev).length = channelRegPreimageU32Len := by
  simp [ChannelRegRecord.hashPreimage, BalancePublicInputs.Bytes8.words, member_stream_length,
    slots, channelRegPreimageU32Len, maxSigCluster, memberSlotU32Len, bytes32Len, addressLen]

/-- `delegate_count` sits IMMEDIATELY after `member_count`, both after the folded prev
    hash, the channel id and the bp member slot. -/
theorem channel_reg_preimage_header_offsets (r : ChannelRegRecord) (prev : Bytes32) :
    (r.hashPreimage prev).getD 8 0 = r.channelId ∧
      (r.hashPreimage prev).getD 9 0 = r.bpMemberSlot ∧
      (r.hashPreimage prev).getD 10 0 = r.memberCount ∧
      (r.hashPreimage prev).getD 11 0 = r.delegateCount := by
  cases prev
  refine ⟨rfl, rfl, rfl, rfl⟩

/-- The preimage is injective on fixed-width records: it commits the channel id, both
    counts, and EVERY member slot including the zero padding slots. -/
theorem channel_reg_preimage_injective {r r' : ChannelRegRecord} {prev prev' : Bytes32}
    (slots : r.members.length = maxSigCluster) (slots' : r'.members.length = maxSigCluster)
    (h : r.hashPreimage prev = r'.hashPreimage prev') : prev = prev' ∧ r = r' := by
  unfold ChannelRegRecord.hashPreimage at h
  obtain ⟨hprev, h⟩ := append_inj_bytes32 h
  simp only [List.cons_append, List.nil_append, List.cons.injEq] at h
  obtain ⟨hcid, hbp, hmc, hdc, hmembers⟩ := h
  have hms : r.members = r'.members :=
    member_stream_injective (by rw [slots, slots']) hmembers
  refine ⟨hprev, ?_⟩
  show (⟨r.channelId, r.bpMemberSlot, r.memberCount, r.delegateCount, r.members⟩ :
      ChannelRegRecord) =
    ⟨r'.channelId, r'.bpMemberSlot, r'.memberCount, r'.delegateCount, r'.members⟩
  rw [hcid, hbp, hmc, hdc, hms]

/-- R2/G6: the keccak registration chain commits the whole member set. Injectivity of the
    hash ON THIS CONCRETE PAIR is an explicit, undischarged premise. -/
theorem channel_reg_chain_binds_member_set (keccak : List Nat → Bytes32)
    {r r' : ChannelRegRecord} {prev : Bytes32}
    (slots : r.members.length = maxSigCluster) (slots' : r'.members.length = maxSigCluster)
    (differ : r.members ≠ r'.members)
    (inj : keccak (r.hashPreimage prev) = keccak (r'.hashPreimage prev) →
      r.hashPreimage prev = r'.hashPreimage prev) :
    keccak (r.hashPreimage prev) ≠ keccak (r'.hashPreimage prev) := by
  intro hEq
  apply differ
  have := (channel_reg_preimage_injective slots slots' (inj hEq)).2
  rw [this]

/-- Positive example: a two-member record with six default padding slots validates. -/
def exampleMember (tag : Nat) : MemberRegEntry :=
  ⟨⟨tag, tag, tag, tag, tag, tag, tag, tag⟩, ⟨tag, 0, 0, 0, 0, 0, 0, 0⟩,
    ⟨0, tag, 0, 0, 0, 0, 0, 0⟩, ⟨tag, 0, 0, 0, 0⟩⟩

def exampleRecord : ChannelRegRecord :=
  ⟨7, 1, 2, 0, [exampleMember 1, exampleMember 2, memberZero, memberZero, memberZero,
    memberZero, memberZero, memberZero]⟩

theorem channel_reg_example_validates :
    validateChannelReg (fun _ => true) exampleRecord = .ok () := by
  rfl

theorem channel_reg_example_has_full_slot_width : exampleRecord.members.length = maxSigCluster :=
  rfl

/-! ## channel_message.rs — the off-chain channel message and its digests -/

/-- `CHANNEL_MESSAGE_MAGIC`, the "IMPC" domain separator. -/
def channelMessageMagic : Nat := 0x494D5043
def allocationU32Len : Nat := bytes32Len + 1 + bytes32Len
def signingPreimageU32Len : Nat := 1 + 1 + 2 + bytes32Len + bytes32Len
def closePayloadU32Len : Nat := 1 + 2 + bytes32Len + bytes32Len

theorem channel_message_magic_pinned : channelMessageMagic = 0x494D5043 := rfl
theorem allocation_u32_len_pinned : allocationU32Len = 17 := rfl
theorem signing_preimage_u32_len_pinned : signingPreimageU32Len = 20 := rfl
theorem close_payload_u32_len_pinned : closePayloadU32Len = 19 := rfl

/-- The magic word is the four big-endian ASCII bytes of "IMPC". -/
theorem channel_message_magic_is_impc_ascii :
    [channelMessageMagic / 2 ^ 24 % 256, channelMessageMagic / 2 ^ 16 % 256,
      channelMessageMagic / 2 ^ 8 % 256, channelMessageMagic % 256] = [73, 77, 80, 67] := by
  decide

structure Allocation where
  recipient : Bytes32
  tokenIndex : Nat
  amount : Bytes32
  deriving DecidableEq, Repr

/-- `Allocation::to_u32_vec`: `recipient(8) || token_index(1) || amount(8)`. -/
def Allocation.words (a : Allocation) : List Nat :=
  a.recipient.words ++ ([a.tokenIndex] ++ a.amount.words)

def allocationsStream (allocs : List Allocation) : List Nat :=
  (allocs.map Allocation.words).join

structure ChannelMessage where
  channelId : Nat
  sequence : Nat
  allocations : List Allocation
  txTreeRoot : Bytes32
  deriving DecidableEq, Repr

/-- SECURITY-RELEVANT LAYOUT NOTE: the channel message splits its u64 sequence LOW WORD
    FIRST (`vec![sequence as u32, (sequence >> 32) as u32]`), the OPPOSITE order of the
    `U64` encoder used by `Block` and `PublicState`. -/
def sequenceWords (s : Nat) : List Nat := [splitLo s, splitHi s]

/-- `ChannelMessage::allocations_hash`: an EMPTY allocation stream short-circuits to the
    zero `Bytes32` instead of hashing. -/
def ChannelMessage.allocationsHash (keccak : List Nat → Bytes32) (m : ChannelMessage) :
    Bytes32 :=
  if allocationsStream m.allocations = [] then bytes32Zero
  else keccak (allocationsStream m.allocations)

/-- `keccak256(magic || channel_id || sequence || allocations_hash || tx_tree_root)`. -/
def ChannelMessage.signingPreimage (keccak : List Nat → Bytes32) (m : ChannelMessage) :
    List Nat :=
  [channelMessageMagic] ++ ([m.channelId] ++ (sequenceWords m.sequence ++
    ((m.allocationsHash keccak).words ++ m.txTreeRoot.words)))

def ChannelMessage.signingHash (keccak : List Nat → Bytes32) (m : ChannelMessage) : Bytes32 :=
  keccak (m.signingPreimage keccak)

/-- `close_action_payload_hash`: the SAME stream WITHOUT the magic word, hashed with
    Poseidon instead of keccak. -/
def ChannelMessage.closePayloadPreimage (keccak : List Nat → Bytes32) (m : ChannelMessage) :
    List Nat :=
  [m.channelId] ++ (sequenceWords m.sequence ++
    ((m.allocationsHash keccak).words ++ m.txTreeRoot.words))

def ChannelMessage.closePayloadHash (keccak : List Nat → Bytes32) (poseidon : List Nat → Root)
    (m : ChannelMessage) : Root :=
  poseidon (m.closePayloadPreimage keccak)

inductive ChannelActionKind where
  | interChannelSend
  | channelClose
  | memberSetUpdate
  deriving DecidableEq, Repr

inductive TxClass where
  | userTransfer
  | channelAction
  deriving DecidableEq, Repr

structure ChannelAction where
  kind : ChannelActionKind
  sourceChannelId : Nat
  destinationChannelId : Nat
  txHash : Bytes32
  sealDigest : Bytes32
  payloadHash : Root
  deriving DecidableEq, Repr

structure TxV2 where
  txClass : TxClass
  transferTreeRoot : Root
  nonce : Nat
  channelActionRoot : Root
  deriving DecidableEq, Repr

/-- `ChannelId::dummy()`. -/
def dummyChannelId : Nat := 0

def ChannelMessage.toChannelCloseAction (keccak : List Nat → Bytes32)
    (poseidon : List Nat → Root) (m : ChannelMessage) (sealDigest : Bytes32) : ChannelAction :=
  ⟨.channelClose, m.channelId, dummyChannelId, m.signingHash keccak, sealDigest,
    m.closePayloadHash keccak poseidon⟩

/-- `compute_channel_action_root` is an opaque callback. -/
def ChannelMessage.toChannelCloseTxV2 (keccak : List Nat → Bytes32) (poseidon : List Nat → Root)
    (actionRoot : List ChannelAction → Root) (m : ChannelMessage) (sealDigest : Bytes32)
    (nonce : Nat) : TxV2 :=
  ⟨.channelAction, rootZero, nonce, actionRoot [m.toChannelCloseAction keccak poseidon sealDigest]⟩

theorem allocation_words_width (a : Allocation) : a.words.length = allocationU32Len := by
  simp [Allocation.words, BalancePublicInputs.Bytes8.words, allocationU32Len, bytes32Len]

theorem allocations_stream_width (allocs : List Allocation) :
    (allocationsStream allocs).length = allocationU32Len * allocs.length := by
  induction allocs with
  | nil => simp [allocationsStream]
  | cons a rest ih =>
      simp only [allocationsStream, List.map_cons, List.join_cons, List.length_append,
        List.length_cons] at *
      rw [allocation_words_width, ih, Nat.mul_succ]
      omega

theorem signing_preimage_width (keccak : List Nat → Bytes32) (m : ChannelMessage) :
    (m.signingPreimage keccak).length = signingPreimageU32Len := by
  simp [ChannelMessage.signingPreimage, sequenceWords, BalancePublicInputs.Bytes8.words,
    signingPreimageU32Len, bytes32Len]

theorem close_payload_width (keccak : List Nat → Bytes32) (m : ChannelMessage) :
    (m.closePayloadPreimage keccak).length = closePayloadU32Len := by
  simp [ChannelMessage.closePayloadPreimage, sequenceWords, BalancePublicInputs.Bytes8.words,
    closePayloadU32Len, bytes32Len]

/-- The Poseidon close-action payload is EXACTLY the keccak signing preimage minus its
    magic word: the domain separator protects only the keccak digest. -/
theorem close_payload_is_signing_preimage_without_magic (keccak : List Nat → Bytes32)
    (m : ChannelMessage) :
    m.closePayloadPreimage keccak = (m.signingPreimage keccak).drop 1 := by
  simp [ChannelMessage.closePayloadPreimage, ChannelMessage.signingPreimage]

theorem empty_allocations_hash_is_the_zero_default (keccak : List Nat → Bytes32)
    (m : ChannelMessage) (empty : m.allocations = []) :
    m.allocationsHash keccak = bytes32Zero := by
  simp [ChannelMessage.allocationsHash, allocationsStream, empty]

/-- The message's sequence words are the REVERSE of the `U64` limb order used elsewhere;
    the two encodings genuinely differ. -/
theorem sequence_word_order_is_low_word_first (s : Nat) :
    sequenceWords s = (u64Words s).reverse := by
  simp [sequenceWords, u64Words]

theorem sequence_word_order_differs_from_u64_encoder : sequenceWords 1 ≠ u64Words 1 := by
  decide

/-- The signing preimage determines the channel id, the sequence (for in-range values),
    the ALLOCATIONS HASH and the tx tree root. -/
theorem signing_preimage_injective (keccak : List Nat → Bytes32) {m m' : ChannelMessage}
    (seq : m.sequence < scalarLimit) (seq' : m'.sequence < scalarLimit)
    (h : m.signingPreimage keccak = m'.signingPreimage keccak) :
    m.channelId = m'.channelId ∧ m.sequence = m'.sequence ∧
      m.allocationsHash keccak = m'.allocationsHash keccak ∧ m.txTreeRoot = m'.txTreeRoot := by
  unfold ChannelMessage.signingPreimage at h
  simp only [List.cons_append, List.nil_append, List.cons.injEq, sequenceWords] at h
  obtain ⟨_, hcid, hlo, hhi, hrest⟩ := h
  obtain ⟨hhash, hroot⟩ := append_inj_bytes32 hrest
  refine ⟨hcid, ?_, hhash, bytes32_words_injective hroot⟩
  exact (split_pair_eq_iff _ _ seq seq').mp ⟨hhi, hlo⟩

/-- HONESTY: allocations enter the signing hash ONLY through `allocations_hash`. Two
    messages with different allocation lists that share an allocations hash share the
    signed digest; the model asserts no collision resistance for `keccak`. -/
theorem signing_preimage_sees_allocations_only_through_their_hash (keccak : List Nat → Bytes32)
    (m m' : ChannelMessage) (sameId : m.channelId = m'.channelId)
    (sameSeq : m.sequence = m'.sequence) (sameRoot : m.txTreeRoot = m'.txTreeRoot)
    (sameHash : m.allocationsHash keccak = m'.allocationsHash keccak) :
    m.signingPreimage keccak = m'.signingPreimage keccak := by
  simp [ChannelMessage.signingPreimage, sameId, sameSeq, sameRoot, sameHash]

theorem close_action_shape (keccak : List Nat → Bytes32) (poseidon : List Nat → Root)
    (m : ChannelMessage) (sealDigest : Bytes32) :
    (m.toChannelCloseAction keccak poseidon sealDigest).kind = .channelClose ∧
      (m.toChannelCloseAction keccak poseidon sealDigest).sourceChannelId = m.channelId ∧
      (m.toChannelCloseAction keccak poseidon sealDigest).destinationChannelId = dummyChannelId ∧
      (m.toChannelCloseAction keccak poseidon sealDigest).txHash = m.signingHash keccak ∧
      (m.toChannelCloseAction keccak poseidon sealDigest).sealDigest = sealDigest :=
  ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem close_tx_shape (keccak : List Nat → Bytes32) (poseidon : List Nat → Root)
    (actionRoot : List ChannelAction → Root) (m : ChannelMessage) (sealDigest : Bytes32)
    (nonce : Nat) :
    (m.toChannelCloseTxV2 keccak poseidon actionRoot sealDigest nonce).txClass = .channelAction ∧
      (m.toChannelCloseTxV2 keccak poseidon actionRoot sealDigest nonce).transferTreeRoot = rootZero ∧
      (m.toChannelCloseTxV2 keccak poseidon actionRoot sealDigest nonce).nonce = nonce :=
  ⟨rfl, rfl, rfl⟩

/-- Positive example: the concrete signing preimage of a one-allocation message under a
    constant hash callback. -/
theorem signing_preimage_example :
    ChannelMessage.signingPreimage (fun _ => bytes32Zero)
        ⟨5, 3, [⟨bytes32Zero, 1, bytes32Zero⟩], bytes32Zero⟩ =
      [channelMessageMagic, 5, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] := by
  rfl

end Zkp.Implementation.BlockTypes
