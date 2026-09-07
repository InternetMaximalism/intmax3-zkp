import Std

/-!
# Block-hash-chain signing messages: IMCH channel-state mirror and IMSB small-block mirror

Handwritten SEMANTIC MODEL of
* src/circuits/validity/block_hash_chain/channel_state_message.rs (707 lines read), and
* src/circuits/validity/block_hash_chain/small_block_message.rs (234 lines read).

This is NOT a refinement proof of the Rust / plonky2 code. Every theorem is about the local
model below; the model was transcribed by hand from the two files, limb for limb.

What the two files are: fixed-width u32-limb SERIALIZERS for two signing preimages, each in a
native form (`Vec<u32>` → keccak) and an in-circuit form (`Vec<Target>` → keccak gadget), plus
the `set_witness` bridge between them. Neither file verifies a signature, checks an
authorization, connects a wire to the enclosing circuit, or inspects a balance. The IMSB
small-block message is explicitly NOT a live authorization path any more (small_block_message.rs
lines 11–19); it is carried off-circuit only.

Modeled precisely:
* the 139-limb IMCH preimage: segment order, every offset, total width, the `IMCH` domain;
* the 41-limb IMSB preimage: segment order, every offset, total width, the `IMSB` domain;
* the mirror's ONE `channel_id` argument feeding TWO limbs ([1] and [8]) versus the canonical
  `ChannelState::signing_digest()` (common/channel.rs 624–646) which reads `channel_id` and
  `channel_fund.channel_id` independently: the two preimages agree iff
  `channel_fund.channel_id == channel_id` (`mirror_matches_canonical_iff_fund_channel_id_equal`);
* `from_channel_state` as a projection that drops both connected components;
* injectivity of both encoders (fixed width, u64 split is a bijection onto its limb pair);
* u32-boundedness of every native limb under the native representation premise;
* the target twins: same limb layout, every witnessed limb range-checked to 32 bits at
  allocation, connected wires at exactly the pinned offsets, `set_witness` writing the
  native limbs onto the witnessed wires (so a consistent assignment reproduces the native
  preimage limb for limb);
* which components each message carries (IMSB: bp slot at [2], bp `pk_g` at [3..11]; IMCH:
  no member-signature set, no stored digest — the preimage is a function of exactly the fields,
  the channel id and `h2_tag`).

Named boundaries (explicit premises or opaque callbacks, never theorems):
* `keccak-hash`: `hash_words` / `builder.keccak256` are `HashEnvironment.hashWords` /
  `KeccakGadget`; no collision resistance, no gadget soundness, no equality between the
  native keccak and the gadget is stated;
* `enclosing-circuit-connects`: the enclosing circuit (update_channel_tree, not these files)
  must connect `channel_id` and `h2_tag` to block-level wires; `FreshCallerWires` and the
  bounded-caller-wire premises stand in for that;
* `plonky2-range-check-lowering`: `range_check(t, 32)` is `TargetRangeGates`, an assumed
  predicate on the witnessed wires; the keccak gadget does not range-check its own inputs;
* `native-and-target-representation`: Nat stands for u32/u64/field elements; `Wire := Nat`
  is a wire identifier, `assign : Wire → Nat` an arbitrary witness;
* `balance-state-h1`: `balance_state.h1()` is an opaque field of `BalanceStateView`;
* `no-authorization`: signature validity, N-of-N aggregation, member registration, block
  acceptance and fund custody are out of scope of both files and of this module.
-/
namespace Zkp.Implementation.BlockMessages

/-! ## Pinned constants -/

def limbBase : Nat := 2^32
def scalarLimit : Nat := 2^64
/-- `CHANNEL_STATE_DOMAIN` = "IMCH" (common/channel.rs line 29). -/
def channelStateDomain : Nat := 0x494d4348
/-- `SMALL_BLOCK_DOMAIN` = "IMSB" (common/channel.rs line 36). -/
def smallBlockDomain : Nat := 0x494d5342
/-- `MAX_CHANNEL_TOKENS` (constants.rs line 189). -/
def maxChannelTokens : Nat := 10
/-- `CHANNEL_STATE_PREIMAGE_U32_LEN` (line 68). -/
def channelStatePreimageLen : Nat := 139
/-- `CHANNEL_ID_LIMB` (line 71). -/
def channelIdLimb : Nat := 1
/-- `FUND_CHANNEL_ID_LIMB` (line 73). -/
def fundChannelIdLimb : Nat := 8
/-- `H2_TAG_LIMBS = 129..137` (line 75). -/
def h2TagStart : Nat := 129
def h2TagEnd : Nat := 137
/-- Small-block preimage width (small_block_message.rs line 71). -/
def smallBlockPreimageLen : Nat := 41
/-- Witnessed limbs of the IMCH twin: 139 minus domain, two channel-id limbs and 8 `h2_tag`. -/
def channelStateWitnessedLen : Nat := 127
/-- Witnessed limbs of the IMSB twin: 41 minus domain, channel id and 8 `tx_tree_root`. -/
def smallBlockWitnessedLen : Nat := 31

theorem channel_state_domain_pinned : channelStateDomain = 0x494d4348 := rfl
theorem small_block_domain_pinned : smallBlockDomain = 0x494d5342 := rfl
theorem domains_are_distinct : channelStateDomain ≠ smallBlockDomain := by decide
theorem max_channel_tokens_pinned : maxChannelTokens = 10 := rfl
theorem channel_state_preimage_len_pinned : channelStatePreimageLen = 139 := rfl
theorem channel_id_limb_pinned : channelIdLimb = 1 := rfl
theorem fund_channel_id_limb_pinned : fundChannelIdLimb = 8 := rfl
theorem h2_tag_limbs_pinned : h2TagStart = 129 ∧ h2TagEnd = 137 := ⟨rfl, rfl⟩
theorem small_block_preimage_len_pinned : smallBlockPreimageLen = 41 := rfl
theorem limb_base_pinned : limbBase = 4294967296 := rfl

/-! ## Limb containers: `Bytes32` / `U256` (8 u32 limbs), `split_u64` (2 limbs), amounts (10 × 8) -/

/-- Eight u32 limbs, exactly `Bytes32::to_u32_vec` / `U256::to_u32_vec` (`limbs.to_vec()`),
    and `Bytes32Target::to_vec` / `U256Target::to_vec` when `α = Wire`. -/
structure Words8 (α : Type) where
  a : α
  b : α
  c : α
  d : α
  e : α
  f : α
  g : α
  h : α
  deriving DecidableEq, Repr

def Words8.words (w : Words8 α) : List α := [w.a, w.b, w.c, w.d, w.e, w.f, w.g, w.h]
def Words8.map (g : α → β) (w : Words8 α) : Words8 β :=
  ⟨g w.a, g w.b, g w.c, g w.d, g w.e, g w.f, g w.g, g w.h⟩
def Words8.read (xs : List α) (dflt : α) (offset : Nat) : Words8 α :=
  ⟨xs.getD offset dflt, xs.getD (offset+1) dflt, xs.getD (offset+2) dflt, xs.getD (offset+3) dflt,
    xs.getD (offset+4) dflt, xs.getD (offset+5) dflt, xs.getD (offset+6) dflt, xs.getD (offset+7) dflt⟩
def Words8.zero : Words8 Nat := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩
/-- All eight limbs fit u32 (the native `[u32; 8]` representation). -/
def Words8.Bounded (w : Words8 Nat) : Prop := ∀ x ∈ w.words, x < limbBase
/-- `set_witness` pairs: (target wire, native limb), limb order. -/
def Words8.pairs (w : Words8 α) (v : Words8 β) : List (α × β) :=
  [(w.a, v.a), (w.b, v.b), (w.c, v.c), (w.d, v.d), (w.e, v.e), (w.f, v.f), (w.g, v.g), (w.h, v.h)]

/-- The `[hi, lo]` pair produced by `split_u64` (common/channel.rs 1664–1666) or the
    `[Target; 2]` allocated by the `u64_limbs` / `u32_limb` closures. -/
structure Words2 (α : Type) where
  hi : α
  lo : α
  deriving DecidableEq, Repr

def Words2.words (w : Words2 α) : List α := [w.hi, w.lo]
def Words2.map (g : α → β) (w : Words2 α) : Words2 β := ⟨g w.hi, g w.lo⟩
def Words2.read (xs : List α) (dflt : α) (offset : Nat) : Words2 α :=
  ⟨xs.getD offset dflt, xs.getD (offset+1) dflt⟩
def Words2.pairs (w : Words2 α) (v : Words2 β) : List (α × β) := [(w.hi, v.hi), (w.lo, v.lo)]

/-- `split_u64(value) = vec![(value >> 32) as u32, value as u32]`. On the native u64 domain
    the high limb is `value / 2^32` and the low limb `value % 2^32`. -/
def splitU64 (v : Nat) : Words2 Nat := ⟨v / limbBase, v % limbBase⟩
def joinU64 (w : Words2 Nat) : Nat := w.hi * limbBase + w.lo

/-- `channel_fund.amounts: [U256; MAX_CHANNEL_TOKENS]` — always the full ten slots (TM-11). -/
structure Amounts (α : Type) where
  t0 : Words8 α
  t1 : Words8 α
  t2 : Words8 α
  t3 : Words8 α
  t4 : Words8 α
  t5 : Words8 α
  t6 : Words8 α
  t7 : Words8 α
  t8 : Words8 α
  t9 : Words8 α
  deriving DecidableEq, Repr

def Amounts.words (x : Amounts α) : List α :=
  x.t0.words ++ x.t1.words ++ x.t2.words ++ x.t3.words ++ x.t4.words ++
  x.t5.words ++ x.t6.words ++ x.t7.words ++ x.t8.words ++ x.t9.words
def Amounts.map (g : α → β) (x : Amounts α) : Amounts β :=
  ⟨x.t0.map g, x.t1.map g, x.t2.map g, x.t3.map g, x.t4.map g,
   x.t5.map g, x.t6.map g, x.t7.map g, x.t8.map g, x.t9.map g⟩
def Amounts.read (xs : List α) (dflt : α) (offset : Nat) : Amounts α :=
  ⟨Words8.read xs dflt offset, Words8.read xs dflt (offset+8), Words8.read xs dflt (offset+16),
   Words8.read xs dflt (offset+24), Words8.read xs dflt (offset+32), Words8.read xs dflt (offset+40),
   Words8.read xs dflt (offset+48), Words8.read xs dflt (offset+56), Words8.read xs dflt (offset+64),
   Words8.read xs dflt (offset+72)⟩
def Amounts.zero : Amounts Nat :=
  ⟨Words8.zero, Words8.zero, Words8.zero, Words8.zero, Words8.zero,
   Words8.zero, Words8.zero, Words8.zero, Words8.zero, Words8.zero⟩
def Amounts.Bounded (x : Amounts Nat) : Prop := ∀ v ∈ x.words, v < limbBase
def Amounts.pairs (x : Amounts α) (v : Amounts β) : List (α × β) :=
  x.t0.pairs v.t0 ++ x.t1.pairs v.t1 ++ x.t2.pairs v.t2 ++ x.t3.pairs v.t3 ++ x.t4.pairs v.t4 ++
  x.t5.pairs v.t5 ++ x.t6.pairs v.t6 ++ x.t7.pairs v.t7 ++ x.t8.pairs v.t8 ++ x.t9.pairs v.t9

theorem words8_has_eight_limbs (w : Words8 α) : w.words.length = 8 := rfl
theorem words2_has_two_limbs (w : Words2 α) : w.words.length = 2 := rfl
theorem amounts_have_eighty_limbs (x : Amounts α) : x.words.length = 80 := by
  simp [Amounts.words, Words8.words]
theorem amounts_width_is_tokens_times_u256 : 80 = maxChannelTokens * 8 := rfl

theorem split_u64_joins_back (v : Nat) : joinU64 (splitU64 v) = v := by
  simp only [joinU64, splitU64]
  have := Nat.div_add_mod v limbBase
  rw [Nat.mul_comm] at this
  exact this

theorem split_u64_injective {a b : Nat} (h : splitU64 a = splitU64 b) : a = b := by
  have := congrArg joinU64 h
  simpa [split_u64_joins_back] using this

theorem split_u64_limbs_are_u32 {v : Nat} (h : v < scalarLimit) :
    ∀ x ∈ (splitU64 v).words, x < limbBase := by
  intro x hx
  simp only [splitU64, Words2.words, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hx
  rcases hx with rfl | rfl
  · have : v < limbBase * limbBase := h
    exact (Nat.div_lt_iff_lt_mul (by decide)).mpr this
  · exact Nat.mod_lt _ (by decide)

/-- Helper: a per-element predicate over a concatenation follows from both halves. -/
theorem forall_mem_append_of {P : α → Prop} {xs ys : List α}
    (hx : ∀ x ∈ xs, P x) (hy : ∀ x ∈ ys, P x) : ∀ x ∈ xs ++ ys, P x := by
  intro x h
  rcases List.mem_append.mp h with h | h
  · exact hx x h
  · exact hy x h

theorem forall_mem_append_left {P : α → Prop} {xs ys : List α}
    (h : ∀ x ∈ xs ++ ys, P x) : ∀ x ∈ xs, P x :=
  fun x hx => h x (List.mem_append.mpr (Or.inl hx))

theorem forall_mem_append_right {P : α → Prop} {xs ys : List α}
    (h : ∀ x ∈ xs ++ ys, P x) : ∀ x ∈ ys, P x :=
  fun x hx => h x (List.mem_append.mpr (Or.inr hx))

theorem amounts_bounded_iff (x : Amounts Nat) :
    x.Bounded ↔ x.t0.Bounded ∧ x.t1.Bounded ∧ x.t2.Bounded ∧ x.t3.Bounded ∧ x.t4.Bounded ∧
      x.t5.Bounded ∧ x.t6.Bounded ∧ x.t7.Bounded ∧ x.t8.Bounded ∧ x.t9.Bounded := by
  constructor
  · intro h
    simp only [Amounts.Bounded, Amounts.words, Words8.Bounded] at h ⊢
    repeat' constructor
    all_goals intro v hv; apply h v
    all_goals simp [hv]
  · rintro ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
    simp only [Amounts.Bounded, Amounts.words]
    repeat' apply forall_mem_append_of
    all_goals assumption

/-! ## IMCH channel-state message: native fields (lines 84–98) and the limb-level shape
    shared by the native preimage (lines 118–141) and the target twin (lines 181–197). -/

/-- `ChannelStateMessageFields` (lines 84–98): the WITNESSED components. No `channel_id`, no
    `h2_tag`, no member signatures, no stored digest. -/
structure ChannelStateFields where
  epoch : Nat
  smallBlockNumber : Nat
  closeFreezeNonce : Nat
  fundAmounts : Amounts Nat
  fundIntmaxStateRoot : Words8 Nat
  balanceStateH1 : Words8 Nat
  sharedNativeNullifierRoot : Words8 Nat
  unallocatedConfirmedIncoming : Words8 Nat
  prevDigest : Words8 Nat
  stateVersion : Nat
  deriving DecidableEq, Repr

/-- The limb-level shape: `ChannelStateMessageFieldsTarget` (lines 181–197) when `α = Wire`,
    and the values `set_witness` writes when `α = Nat`. -/
structure ChannelStateLimbs (α : Type) where
  epoch : Words2 α
  smallBlockNumber : Words2 α
  closeFreezeNonce : Words2 α
  fundAmounts : Amounts α
  fundIntmaxStateRoot : Words8 α
  balanceStateH1 : Words8 α
  sharedNativeNullifierRoot : Words8 α
  unallocatedConfirmedIncoming : Words8 α
  prevDigest : Words8 α
  stateVersion : Words2 α
  deriving DecidableEq, Repr

def ChannelStateLimbs.map (g : α → β) (l : ChannelStateLimbs α) : ChannelStateLimbs β :=
  ⟨l.epoch.map g, l.smallBlockNumber.map g, l.closeFreezeNonce.map g, l.fundAmounts.map g,
   l.fundIntmaxStateRoot.map g, l.balanceStateH1.map g, l.sharedNativeNullifierRoot.map g,
   l.unallocatedConfirmedIncoming.map g, l.prevDigest.map g, l.stateVersion.map g⟩

/-- The 127 witnessed limbs in PREIMAGE order (the complement of the connected offsets). -/
def ChannelStateLimbs.witnessed (l : ChannelStateLimbs α) : List α :=
  l.epoch.words ++ l.smallBlockNumber.words ++ l.closeFreezeNonce.words ++ l.fundAmounts.words ++
  l.fundIntmaxStateRoot.words ++ l.balanceStateH1.words ++ l.sharedNativeNullifierRoot.words ++
  l.unallocatedConfirmedIncoming.words ++ l.prevDigest.words ++ l.stateVersion.words

/-- Native limbs of the fields: `split_u64` on each u64, raw limbs on each 8-word value.
    This is exactly what `set_witness` (lines 281–308) writes. -/
def toLimbs (f : ChannelStateFields) : ChannelStateLimbs Nat :=
  ⟨splitU64 f.epoch, splitU64 f.smallBlockNumber, splitU64 f.closeFreezeNonce, f.fundAmounts,
   f.fundIntmaxStateRoot, f.balanceStateH1, f.sharedNativeNullifierRoot,
   f.unallocatedConfirmedIncoming, f.prevDigest, splitU64 f.stateVersion⟩

/-- The shared 139-limb layout (native lines 119–138, target lines 240–259), segment by segment:
    `[0] domain, [1] channel_id, [2..4) epoch, [4..6) small_block_number, [6..8) close_freeze_nonce,
    [8] channel_id AGAIN (the fund's channel id), [9..89) amounts, [89..97) fund root,
    [97..105) balance_state.h1, [105..113) nullifier root, [113..121) unallocated,
    [121..129) prev_digest, [129..137) h2_tag, [137..139) state_version`. -/
def channelStatePreimageG (domain channelId : α) (l : ChannelStateLimbs α) (h2Tag : Words8 α) :
    List α :=
  [domain] ++ [channelId] ++ l.epoch.words ++ l.smallBlockNumber.words ++
  l.closeFreezeNonce.words ++ [channelId] ++ l.fundAmounts.words ++ l.fundIntmaxStateRoot.words ++
  l.balanceStateH1.words ++ l.sharedNativeNullifierRoot.words ++ l.unallocatedConfirmedIncoming.words ++
  l.prevDigest.words ++ h2Tag.words ++ l.stateVersion.words

/-- `ChannelStateMessageFields::preimage` (lines 118–141). -/
def nativePreimage (f : ChannelStateFields) (channelId : Nat) (h2Tag : Words8 Nat) : List Nat :=
  channelStatePreimageG channelStateDomain channelId (toLimbs f) h2Tag

/-- `hash_words` = keccak256 over the u32 words, as an opaque callback (boundary `keccak-hash`). -/
structure HashEnvironment where
  hashWords : List Nat → Words8 Nat

/-- `ChannelStateMessageFields::signing_digest` (lines 147–149). -/
def nativeSigningDigest (e : HashEnvironment) (f : ChannelStateFields) (channelId : Nat)
    (h2Tag : Words8 Nat) : Words8 Nat :=
  e.hashWords (nativePreimage f channelId h2Tag)

/-! ### Segment widths and offsets -/

/-- Segment widths in order (docstring lines 103–109). -/
def channelStateSegmentWidths : List Nat := [1, 1, 2, 2, 2, 1, 80, 8, 8, 8, 8, 8, 8, 2]
/-- Segment start offsets in order. -/
def channelStateSegmentOffsets : List Nat := [0, 1, 2, 4, 6, 8, 9, 89, 97, 105, 113, 121, 129, 137]
def prefixSums (ws : List Nat) : List Nat :=
  (ws.foldl (fun (acc : List Nat × Nat) w => (acc.1 ++ [acc.2], acc.2 + w)) ([], 0)).1

theorem channel_state_segment_offsets_are_prefix_sums :
    prefixSums channelStateSegmentWidths = channelStateSegmentOffsets := by decide
theorem channel_state_segment_widths_sum_to_139 :
    channelStateSegmentWidths.foldl (· + ·) 0 = channelStatePreimageLen := by decide

theorem channel_state_preimage_width (domain channelId : α) (l : ChannelStateLimbs α)
    (h2Tag : Words8 α) : (channelStatePreimageG domain channelId l h2Tag).length = 139 := by
  simp [channelStatePreimageG, Words8.words, Words2.words, Amounts.words]

theorem native_preimage_width (f : ChannelStateFields) (channelId : Nat) (h2Tag : Words8 Nat) :
    (nativePreimage f channelId h2Tag).length = channelStatePreimageLen :=
  channel_state_preimage_width _ _ _ _

theorem channel_state_witnessed_width (l : ChannelStateLimbs α) :
    l.witnessed.length = channelStateWitnessedLen := by
  simp [ChannelStateLimbs.witnessed, Words8.words, Words2.words, Amounts.words, channelStateWitnessedLen]

/-- Every segment sits at its pinned offset: read back by `drop`/`take`. -/
theorem channel_state_segment_offsets (domain channelId : α) (l : ChannelStateLimbs α)
    (h2Tag : Words8 α) :
    let p := channelStatePreimageG domain channelId l h2Tag
    p.getD 0 domain = domain ∧
    p.getD channelIdLimb domain = channelId ∧
    (p.drop 2).take 2 = l.epoch.words ∧
    (p.drop 4).take 2 = l.smallBlockNumber.words ∧
    (p.drop 6).take 2 = l.closeFreezeNonce.words ∧
    p.getD fundChannelIdLimb domain = channelId ∧
    (p.drop 9).take 80 = l.fundAmounts.words ∧
    (p.drop 89).take 8 = l.fundIntmaxStateRoot.words ∧
    (p.drop 97).take 8 = l.balanceStateH1.words ∧
    (p.drop 105).take 8 = l.sharedNativeNullifierRoot.words ∧
    (p.drop 113).take 8 = l.unallocatedConfirmedIncoming.words ∧
    (p.drop 121).take 8 = l.prevDigest.words ∧
    (p.drop h2TagStart).take (h2TagEnd - h2TagStart) = h2Tag.words ∧
    p.drop 137 = l.stateVersion.words := by
  cases l with
  | mk ep sb cf am fr h1 nr ui pd sv =>
    cases ep; cases sb; cases cf; cases sv; cases h2Tag
    cases am with
    | mk t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 =>
      cases t0; cases t1; cases t2; cases t3; cases t4; cases t5; cases t6; cases t7; cases t8; cases t9
      cases fr; cases h1; cases nr; cases ui; cases pd
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- The single `channel_id` argument lands on BOTH limb 1 and limb 8 (lines 121 and 125). -/
theorem channel_id_feeds_two_limbs (domain channelId : α) (l : ChannelStateLimbs α)
    (h2Tag : Words8 α) :
    (channelStatePreimageG domain channelId l h2Tag).getD channelIdLimb domain = channelId ∧
    (channelStatePreimageG domain channelId l h2Tag).getD fundChannelIdLimb domain = channelId :=
  ⟨(channel_state_segment_offsets domain channelId l h2Tag).2.1,
   (channel_state_segment_offsets domain channelId l h2Tag).2.2.2.2.2.1⟩

/-- `state_version` is the v2 tail AFTER `h2_tag` (lines 136, 257, 503–504). -/
theorem state_version_is_the_tail (domain channelId : α) (l : ChannelStateLimbs α)
    (h2Tag : Words8 α) :
    (channelStatePreimageG domain channelId l h2Tag).drop 137 = l.stateVersion.words :=
  (channel_state_segment_offsets domain channelId l h2Tag).2.2.2.2.2.2.2.2.2.2.2.2.2

/-! ### Mirror versus canonical: the `channel_fund.channel_id == channel_id` invariant -/

/-- Local transcription of the canonical `ChannelState::signing_digest()` preimage
    (common/channel.rs 624–646, NOT one of the mapped files): limb 1 is `channel_id`, limb 8 is
    `channel_fund.channel_id`, two INDEPENDENT sources. -/
def canonicalPreimage (channelId fundChannelId : Nat) (l : ChannelStateLimbs Nat)
    (h2Tag : Words8 Nat) : List Nat :=
  [channelStateDomain] ++ [channelId] ++ l.epoch.words ++ l.smallBlockNumber.words ++
  l.closeFreezeNonce.words ++ [fundChannelId] ++ l.fundAmounts.words ++ l.fundIntmaxStateRoot.words ++
  l.balanceStateH1.words ++ l.sharedNativeNullifierRoot.words ++ l.unallocatedConfirmedIncoming.words ++
  l.prevDigest.words ++ h2Tag.words ++ l.stateVersion.words

/-- The mirror (lines 118–141) reproduces the canonical limb stream EXACTLY WHEN the fund's
    channel id equals the channel id — the production invariant the docstring at lines 111–117
    relies on. A state whose fund carries a foreign channel id is mis-mirrored (the streams
    differ at limb 8); whether the enclosing circuit refuses it is that circuit's connect, not
    this file. -/
theorem mirror_matches_canonical_iff_fund_channel_id_equal (channelId fundChannelId : Nat)
    (l : ChannelStateLimbs Nat) (h2Tag : Words8 Nat) :
    canonicalPreimage channelId fundChannelId l h2Tag =
      channelStatePreimageG channelStateDomain channelId l h2Tag ↔ fundChannelId = channelId := by
  constructor
  · intro h
    have := congrArg (fun xs => xs.getD 8 0) h
    simpa [canonicalPreimage, channelStatePreimageG, Words2.words] using this
  · rintro rfl
    rfl

theorem mirror_digest_matches_canonical_of_invariant (e : HashEnvironment) (f : ChannelStateFields)
    (channelId : Nat) (h2Tag : Words8 Nat) :
    e.hashWords (canonicalPreimage channelId channelId (toLimbs f) h2Tag) =
      nativeSigningDigest e f channelId h2Tag := rfl

/-- Without the invariant the two limb streams are different inputs; equality of their
    digests would be a keccak collision on a concrete pair (boundary, not a theorem). -/
theorem foreign_fund_channel_id_changes_preimage (channelId fundChannelId : Nat)
    (l : ChannelStateLimbs Nat) (h2Tag : Words8 Nat) (foreign : fundChannelId ≠ channelId) :
    canonicalPreimage channelId fundChannelId l h2Tag ≠
      channelStatePreimageG channelStateDomain channelId l h2Tag := by
  intro h
  exact foreign ((mirror_matches_canonical_iff_fund_channel_id_equal _ _ _ _).mp h)

/-! ### `from_channel_state` (lines 155–168): projection that drops the connected components -/

/-- `balance_state.h1()` and `balance_state.state_version` (boundary `balance-state-h1`). -/
structure BalanceStateView where
  h1 : Words8 Nat
  stateVersion : Nat
  deriving DecidableEq, Repr

/-- The `ChannelState` components read by `from_channel_state` plus the two it drops
    (`channel_id`, `h2_tag`) and `channel_fund.channel_id`. `digest` / `member_signatures` are
    never read. -/
structure ChannelState where
  channelId : Nat
  epoch : Nat
  smallBlockNumber : Nat
  closeFreezeNonce : Nat
  fundChannelId : Nat
  fundAmounts : Amounts Nat
  fundIntmaxStateRoot : Words8 Nat
  balanceState : BalanceStateView
  h2Tag : Words8 Nat
  sharedNativeNullifierRoot : Words8 Nat
  unallocatedConfirmedIncoming : Words8 Nat
  prevDigest : Words8 Nat
  deriving DecidableEq, Repr

def fromChannelState (s : ChannelState) : ChannelStateFields :=
  ⟨s.epoch, s.smallBlockNumber, s.closeFreezeNonce, s.fundAmounts, s.fundIntmaxStateRoot,
   s.balanceState.h1, s.sharedNativeNullifierRoot, s.unallocatedConfirmedIncoming, s.prevDigest,
   s.balanceState.stateVersion⟩

theorem from_channel_state_reads_h1_and_version (s : ChannelState) :
    (fromChannelState s).balanceStateH1 = s.balanceState.h1 ∧
    (fromChannelState s).stateVersion = s.balanceState.stateVersion := ⟨rfl, rfl⟩

/-- The projection ignores `channel_id`, `channel_fund.channel_id` and `h2_tag`: two states
    differing only there project to the same fields (so those three are NOT witnessed). -/
theorem from_channel_state_drops_connected_components (s : ChannelState)
    (channelId fundChannelId : Nat) (h2Tag : Words8 Nat) :
    fromChannelState { s with channelId := channelId, fundChannelId := fundChannelId, h2Tag := h2Tag } =
      fromChannelState s := rfl

/-- Projecting and re-mirroring a state with the fund invariant gives the canonical stream. -/
theorem projected_state_mirrors_canonical (s : ChannelState) (inv : s.fundChannelId = s.channelId) :
    nativePreimage (fromChannelState s) s.channelId s.h2Tag =
      canonicalPreimage s.channelId s.fundChannelId (toLimbs (fromChannelState s)) s.h2Tag := by
  rw [inv]
  rfl

/-! ### Injectivity: fixed width + bijective u64 split -/

structure ChannelStateReading (α : Type) where
  domain : α
  channelId : α
  limbs : ChannelStateLimbs α
  h2Tag : Words8 α
  fundChannelId : α
  deriving DecidableEq, Repr

def readChannelStatePreimage (xs : List α) (dflt : α) : ChannelStateReading α :=
  ⟨xs.getD 0 dflt, xs.getD 1 dflt,
   ⟨Words2.read xs dflt 2, Words2.read xs dflt 4, Words2.read xs dflt 6, Amounts.read xs dflt 9,
    Words8.read xs dflt 89, Words8.read xs dflt 97, Words8.read xs dflt 105, Words8.read xs dflt 113,
    Words8.read xs dflt 121, Words2.read xs dflt 137⟩,
   Words8.read xs dflt 129, xs.getD 8 dflt⟩

theorem read_channel_state_preimage (domain channelId : α) (l : ChannelStateLimbs α)
    (h2Tag : Words8 α) (dflt : α) :
    readChannelStatePreimage (channelStatePreimageG domain channelId l h2Tag) dflt =
      ⟨domain, channelId, l, h2Tag, channelId⟩ := by
  cases l with
  | mk ep sb cf am fr h1 nr ui pd sv =>
    cases ep; cases sb; cases cf; cases sv; cases h2Tag
    cases am with
    | mk t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 =>
      cases t0; cases t1; cases t2; cases t3; cases t4; cases t5; cases t6; cases t7; cases t8; cases t9
      cases fr; cases h1; cases nr; cases ui; cases pd
      rfl

theorem channel_state_layout_injective {domain domain' channelId channelId' : α}
    {l l' : ChannelStateLimbs α} {h2Tag h2Tag' : Words8 α}
    (same : channelStatePreimageG domain channelId l h2Tag =
      channelStatePreimageG domain' channelId' l' h2Tag') :
    domain = domain' ∧ channelId = channelId' ∧ l = l' ∧ h2Tag = h2Tag' := by
  have h := congrArg (fun xs => readChannelStatePreimage xs domain) same
  simp only [read_channel_state_preimage, ChannelStateReading.mk.injEq] at h
  exact ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1⟩

theorem to_limbs_injective {f f' : ChannelStateFields} (same : toLimbs f = toLimbs f') : f = f' := by
  cases f; cases f'
  simp only [toLimbs, ChannelStateLimbs.mk.injEq] at same
  obtain ⟨e, s, c, a, r, h, n, u, p, v⟩ := same
  simp [split_u64_injective e, split_u64_injective s, split_u64_injective c, split_u64_injective v,
    a, r, h, n, u, p]

/-- `ChannelStateMessageFields::preimage` is injective in (fields, channel_id, h2_tag): the
    docstring's "fixed-width and injective" (line 67). -/
theorem native_preimage_injective {f f' : ChannelStateFields} {channelId channelId' : Nat}
    {h2Tag h2Tag' : Words8 Nat}
    (same : nativePreimage f channelId h2Tag = nativePreimage f' channelId' h2Tag') :
    f = f' ∧ channelId = channelId' ∧ h2Tag = h2Tag' := by
  obtain ⟨_, c, l, h⟩ := channel_state_layout_injective same
  exact ⟨to_limbs_injective l, c, h⟩

/-- Digest binding on ONE concrete compared pair, with keccak collision-freedom on that pair as
    an explicit premise (boundary `keccak-hash`). -/
theorem concrete_digest_binding (e : HashEnvironment) {f f' : ChannelStateFields}
    {channelId channelId' : Nat} {h2Tag h2Tag' : Words8 Nat}
    (noCollision : e.hashWords (nativePreimage f channelId h2Tag) =
      e.hashWords (nativePreimage f' channelId' h2Tag') →
      nativePreimage f channelId h2Tag = nativePreimage f' channelId' h2Tag')
    (same : nativeSigningDigest e f channelId h2Tag = nativeSigningDigest e f' channelId' h2Tag') :
    f = f' ∧ channelId = channelId' ∧ h2Tag = h2Tag' :=
  native_preimage_injective (noCollision same)

/-- The message carries no member-signature set and no stored digest: the digest is a function
    of exactly (fields, channel_id, h2_tag). Stated as the definitional identity. -/
theorem channel_state_digest_depends_only_on_fields_channel_and_h2 (e : HashEnvironment)
    (f : ChannelStateFields) (channelId : Nat) (h2Tag : Words8 Nat) :
    nativeSigningDigest e f channelId h2Tag =
      e.hashWords (channelStatePreimageG channelStateDomain channelId (toLimbs f) h2Tag) := rfl

/-! ### u32-boundedness of the native limbs -/

/-- The native `ChannelStateMessageFields` value domain: u64 scalars, `[u32; 8]` words. -/
def ChannelStateFields.NativeRepresentable (f : ChannelStateFields) : Prop :=
  f.epoch < scalarLimit ∧ f.smallBlockNumber < scalarLimit ∧ f.closeFreezeNonce < scalarLimit ∧
  f.stateVersion < scalarLimit ∧ f.fundAmounts.Bounded ∧ f.fundIntmaxStateRoot.Bounded ∧
  f.balanceStateH1.Bounded ∧ f.sharedNativeNullifierRoot.Bounded ∧
  f.unallocatedConfirmedIncoming.Bounded ∧ f.prevDigest.Bounded

theorem channel_state_domain_is_u32 : channelStateDomain < limbBase := by decide

theorem singleton_bounded {x : Nat} (h : x < limbBase) : ∀ y ∈ [x], y < limbBase := by
  intro y hy
  simp only [List.mem_singleton] at hy
  exact hy ▸ h

/-- Every one of the 139 native limbs is a u32 whenever the fields are natively representable
    and the caller's `channel_id` / `h2_tag` are. -/
theorem native_preimage_limbs_are_u32 (f : ChannelStateFields) (channelId : Nat) (h2Tag : Words8 Nat)
    (rep : f.NativeRepresentable) (cid : channelId < limbBase) (tag : h2Tag.Bounded) :
    ∀ x ∈ nativePreimage f channelId h2Tag, x < limbBase := by
  obtain ⟨e, s, c, v, am, fr, h1, nr, ui, pd⟩ := rep
  unfold nativePreimage channelStatePreimageG toLimbs
  simp only
  repeat' apply forall_mem_append_of
  · exact singleton_bounded channel_state_domain_is_u32
  · exact singleton_bounded cid
  · exact split_u64_limbs_are_u32 e
  · exact split_u64_limbs_are_u32 s
  · exact split_u64_limbs_are_u32 c
  · exact singleton_bounded cid
  · exact am
  · exact fr
  · exact h1
  · exact nr
  · exact ui
  · exact pd
  · exact tag
  · exact split_u64_limbs_are_u32 v

/-! ## IMCH target twin (lines 181–308) -/

/-- A wire identifier (`Target`). -/
abbrev Wire := Nat
abbrev ChannelStateTarget := ChannelStateLimbs Wire

/-- `ChannelStateMessageFieldsTarget::preimage` (lines 234–262): the SAME layout with the
    caller's `domain`, `channel_id` and `h2_tag` wires at the connected offsets. -/
def targetPreimage (t : ChannelStateTarget) (domain channelId : Wire) (h2Tag : Words8 Wire) :
    List Wire :=
  channelStatePreimageG domain channelId t h2Tag

theorem target_preimage_width (t : ChannelStateTarget) (domain channelId : Wire)
    (h2Tag : Words8 Wire) : (targetPreimage t domain channelId h2Tag).length = channelStatePreimageLen :=
  channel_state_preimage_width _ _ _ _

/-- The connected offsets hold the CALLER'S wires (test `preimage_target_wires_are_the_connected_ones`,
    positive half): `[0] = domain`, `[1] = [8] = channel_id`, `[129..137) = h2_tag`. -/
theorem target_connected_wires_at_pinned_offsets (t : ChannelStateTarget) (domain channelId : Wire)
    (h2Tag : Words8 Wire) :
    (targetPreimage t domain channelId h2Tag).getD 0 domain = domain ∧
    (targetPreimage t domain channelId h2Tag).getD channelIdLimb domain = channelId ∧
    (targetPreimage t domain channelId h2Tag).getD fundChannelIdLimb domain = channelId ∧
    ((targetPreimage t domain channelId h2Tag).drop h2TagStart).take (h2TagEnd - h2TagStart) =
      h2Tag.words := by
  have h := channel_state_segment_offsets domain channelId t h2Tag
  exact ⟨h.1, h.2.1, h.2.2.2.2.2.1, h.2.2.2.2.2.2.2.2.2.2.2.2.1⟩

/-- The target preimage is the interleaving of the caller's wires with the struct's own
    witnessed wires, in preimage order. -/
theorem target_preimage_partition (t : ChannelStateTarget) (domain channelId : Wire)
    (h2Tag : Words8 Wire) :
    targetPreimage t domain channelId h2Tag =
      [domain, channelId] ++ t.witnessed.take 6 ++ [channelId] ++
        (t.witnessed.drop 6).take 120 ++ h2Tag.words ++ t.witnessed.drop 126 := by
  cases t with
  | mk ep sb cf am fr h1 nr ui pd sv =>
    cases ep; cases sb; cases cf; cases sv
    cases am with
    | mk t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 =>
      cases t0; cases t1; cases t2; cases t3; cases t4; cases t5; cases t6; cases t7; cases t8; cases t9
      cases fr; cases h1; cases nr; cases ui; cases pd
      rfl

/-- Every wire in the target preimage is either a caller wire or a witnessed wire of the struct
    (no third source: the struct has no `channel_id` / `h2_tag` field by construction, lines 174–179). -/
theorem target_preimage_wires_are_caller_or_witnessed (t : ChannelStateTarget)
    (domain channelId : Wire) (h2Tag : Words8 Wire) :
    ∀ w ∈ targetPreimage t domain channelId h2Tag,
      w ∈ [domain, channelId] ++ h2Tag.words ∨ w ∈ t.witnessed := by
  rw [target_preimage_partition]
  intro w hw
  simp only [List.append_assoc, List.mem_append, List.mem_cons, List.mem_singleton,
    List.not_mem_nil, or_false] at hw ⊢
  rcases hw with (rfl | rfl) | hw | rfl | hw | hw | hw
  · exact Or.inl (Or.inl rfl)
  · exact Or.inl (Or.inr (Or.inl rfl))
  · exact Or.inr (List.mem_of_mem_take hw)
  · exact Or.inl (Or.inr (Or.inl rfl))
  · exact Or.inr (List.mem_of_mem_drop (List.mem_of_mem_take hw))
  · exact Or.inl (Or.inr (Or.inr hw))
  · exact Or.inr (List.mem_of_mem_drop hw)

/-- Builder-freshness premise (boundary `enclosing-circuit-connects`): the caller's wires are
    not among the struct's freshly allocated wires. With it, the negative half of
    `preimage_target_wires_are_the_connected_ones` follows: a witnessed wire never sits at a
    connected offset and a caller wire never sits at a witnessed offset. -/
structure FreshCallerWires (t : ChannelStateTarget) (domain channelId : Wire) (h2Tag : Words8 Wire) :
    Prop where
  domainFresh : domain ∉ t.witnessed
  channelFresh : channelId ∉ t.witnessed
  h2Fresh : ∀ w ∈ h2Tag.words, w ∉ t.witnessed

theorem witnessed_wires_never_at_connected_offsets (t : ChannelStateTarget)
    (domain channelId : Wire) (h2Tag : Words8 Wire)
    (fresh : FreshCallerWires t domain channelId h2Tag) :
    (targetPreimage t domain channelId h2Tag).getD channelIdLimb domain ∉ t.witnessed ∧
    (targetPreimage t domain channelId h2Tag).getD fundChannelIdLimb domain ∉ t.witnessed ∧
    ∀ w ∈ ((targetPreimage t domain channelId h2Tag).drop h2TagStart).take (h2TagEnd - h2TagStart),
      w ∉ t.witnessed := by
  obtain ⟨_, c, l, h⟩ := target_connected_wires_at_pinned_offsets t domain channelId h2Tag
  rw [c, l, h]
  exact ⟨fresh.channelFresh, fresh.channelFresh, fresh.h2Fresh⟩

/-! ### Allocation (lines 200–226): every witnessed limb range-checked to 32 bits -/

inductive Alloc where
  /-- `u64_limbs`: two virtual targets, each `range_check(_, 32)`. -/
  | u64Limbs (name : String)
  /-- `U256Target::new(builder, true)`: 8 targets, each `range_check(_, 32)`. -/
  | u256 (name : String)
  /-- `Bytes32Target::new(builder, true)`: 8 targets, each `range_check(_, 32)`. -/
  | bytes32 (name : String)
  deriving DecidableEq, Repr

def Alloc.limbs : Alloc → Nat
  | .u64Limbs _ => 2
  | .u256 _ => 8
  | .bytes32 _ => 8

/-- The `range_check: bool` argument passed for each allocation; `new` passes `true` everywhere. -/
def Alloc.rangeChecked : Alloc → Bool
  | _ => true

/-- Allocation ORDER of `ChannelStateMessageFieldsTarget::new` (lines 210–224): the four u64
    scalars first (state_version among them), then the ten amounts, then the five 8-limb values. -/
def channelStateAllocationPlan : List Alloc :=
  [.u64Limbs "epoch", .u64Limbs "small_block_number", .u64Limbs "close_freeze_nonce",
   .u64Limbs "state_version"] ++
  List.replicate maxChannelTokens (.u256 "fund_amounts") ++
  [.bytes32 "fund_intmax_state_root", .bytes32 "balance_state_h1",
   .bytes32 "shared_native_nullifier_root", .u256 "unallocated_confirmed_incoming",
   .bytes32 "prev_digest"]

theorem channel_state_allocation_width :
    (channelStateAllocationPlan.map Alloc.limbs).foldl (· + ·) 0 = channelStateWitnessedLen := by
  decide

theorem channel_state_allocation_all_range_checked :
    ∀ a ∈ channelStateAllocationPlan, a.rangeChecked = true := by
  intro a _
  rfl

theorem channel_state_allocation_has_no_channel_id_or_h2_tag :
    ∀ a ∈ channelStateAllocationPlan,
      a ≠ .u64Limbs "channel_id" ∧ a ≠ .bytes32 "h2_tag" ∧ a ≠ .u256 "h2_tag" := by
  decide

/-- The gates `new` emits (boundary `plonky2-range-check-lowering`): every witnessed wire's
    value is below 2^32 under the witness `val`. Caller wires are NOT covered by these gates. -/
def TargetRangeGates (val : Wire → Nat) (t : ChannelStateTarget) : Prop :=
  ∀ w ∈ t.witnessed, val w < limbBase

/-- The keccak gadget precondition (all inputs u32) holds for the whole 139-limb preimage iff
    the caller's own wires are also bounded — an obligation of the enclosing circuit, not of
    `new` (line 172: the gadget "does NOT range-check its own inputs"). -/
theorem keccak_inputs_bounded_given_caller_wires (val : Wire → Nat) (t : ChannelStateTarget)
    (domain channelId : Wire) (h2Tag : Words8 Wire) (gates : TargetRangeGates val t)
    (dom : val domain < limbBase) (cid : val channelId < limbBase)
    (tag : ∀ w ∈ h2Tag.words, val w < limbBase) :
    ∀ w ∈ targetPreimage t domain channelId h2Tag, val w < limbBase := by
  intro w hw
  rcases target_preimage_wires_are_caller_or_witnessed t domain channelId h2Tag w hw with h | h
  · simp only [List.mem_append, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at h
    rcases h with (rfl | rfl) | h
    · exact dom
    · exact cid
    · exact tag w h
  · exact gates w h

/-! ### In-circuit digest (lines 265–279): constant domain wire, keccak gadget boundary -/

/-- `builder.keccak256::<C>` as an opaque relation on VALUES (boundary `keccak-hash`). -/
def KeccakGadget := List Nat → Words8 Nat

/-- The local wiring of `signing_digest` (lines 276–278): a constant wire carrying `IMCH`,
    the preimage over it, and the gadget output. Gadget soundness is not asserted. -/
structure DigestGates (gadget : KeccakGadget) (val : Wire → Nat) (t : ChannelStateTarget)
    (channelId : Wire) (h2Tag : Words8 Wire) (out : Words8 Wire) : Prop where
  domainWire : Wire
  domainConstant : val domainWire = channelStateDomain
  output : out.map val = gadget ((targetPreimage t domainWire channelId h2Tag).map val)

/-! ### `set_witness` (lines 281–308) -/

/-- Functoriality of the layout: the SAME limb positions under any relabeling. -/
theorem channel_state_preimage_map (g : α → β) (domain channelId : α) (l : ChannelStateLimbs α)
    (h2Tag : Words8 α) :
    (channelStatePreimageG domain channelId l h2Tag).map g =
      channelStatePreimageG (g domain) (g channelId) (l.map g) (h2Tag.map g) := by
  simp [channelStatePreimageG, ChannelStateLimbs.map, Words8.map, Words8.words, Words2.map,
    Words2.words, Amounts.map, Amounts.words]

/-- What `set_witness` establishes: under the witness `assign`, every witnessed wire carries
    the corresponding native limb. -/
def SetWitness (assign : Wire → Nat) (t : ChannelStateTarget) (f : ChannelStateFields) : Prop :=
  t.map assign = toLimbs f

/-- The explicit write list of `set_witness`, in SOURCE order (lines 286–307): the four u64
    scalars (state_version fourth), then the ten amounts, then the five 8-limb values. -/
def channelStateWitnessWrites (t : ChannelStateTarget) (f : ChannelStateFields) :
    List (Wire × Nat) :=
  t.epoch.pairs (splitU64 f.epoch) ++ t.smallBlockNumber.pairs (splitU64 f.smallBlockNumber) ++
  t.closeFreezeNonce.pairs (splitU64 f.closeFreezeNonce) ++ t.stateVersion.pairs (splitU64 f.stateVersion) ++
  t.fundAmounts.pairs f.fundAmounts ++ t.fundIntmaxStateRoot.pairs f.fundIntmaxStateRoot ++
  t.balanceStateH1.pairs f.balanceStateH1 ++ t.sharedNativeNullifierRoot.pairs f.sharedNativeNullifierRoot ++
  t.unallocatedConfirmedIncoming.pairs f.unallocatedConfirmedIncoming ++ t.prevDigest.pairs f.prevDigest

/-- A witness is consistent with a write list when it stores every written value. -/
def Consistent (assign : Wire → Nat) (writes : List (Wire × Nat)) : Prop :=
  ∀ p ∈ writes, assign p.1 = p.2

theorem channel_state_witness_write_count (t : ChannelStateTarget) (f : ChannelStateFields) :
    (channelStateWitnessWrites t f).length = channelStateWitnessedLen := by
  simp [channelStateWitnessWrites, Words2.pairs, Words8.pairs, Amounts.pairs, channelStateWitnessedLen]

theorem words8_consistent_map {assign : Wire → Nat} {w : Words8 Wire} {v : Words8 Nat}
    (h : Consistent assign (w.pairs v)) : w.map assign = v := by
  cases w; cases v
  simp only [Consistent, Words8.pairs, List.forall_mem_cons, List.forall_mem_nil, and_true] at h
  simp [Words8.map, h]

theorem words2_consistent_map {assign : Wire → Nat} {w : Words2 Wire} {v : Words2 Nat}
    (h : Consistent assign (w.pairs v)) : w.map assign = v := by
  cases w; cases v
  simp only [Consistent, Words2.pairs, List.forall_mem_cons, List.forall_mem_nil, and_true] at h
  simp [Words2.map, h]

theorem amounts_consistent_map {assign : Wire → Nat} {w : Amounts Wire} {v : Amounts Nat}
    (h : Consistent assign (w.pairs v)) : w.map assign = v := by
  unfold Consistent Amounts.pairs at h
  have h9 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h8 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h7 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h6 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h5 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h4 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h3 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h2 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have h1 := forall_mem_append_right h
  have h0 := forall_mem_append_left h
  cases w; cases v
  simp only [Amounts.map, Amounts.mk.injEq]
  exact ⟨words8_consistent_map h0, words8_consistent_map h1, words8_consistent_map h2,
    words8_consistent_map h3, words8_consistent_map h4, words8_consistent_map h5,
    words8_consistent_map h6, words8_consistent_map h7, words8_consistent_map h8,
    words8_consistent_map h9⟩

/-- A witness holding every `set_witness` write is exactly a `SetWitness`. -/
theorem channel_state_writes_give_set_witness {assign : Wire → Nat} {t : ChannelStateTarget}
    {f : ChannelStateFields} (h : Consistent assign (channelStateWitnessWrites t f)) :
    SetWitness assign t f := by
  unfold Consistent channelStateWitnessWrites at h
  have hpd := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hui := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hnr := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hh1 := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hfr := forall_mem_append_right h
  have h := forall_mem_append_left h
  have ham := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hsv := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hcf := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hsb := forall_mem_append_right h
  have hep := forall_mem_append_left h
  cases t; cases f
  simp only [SetWitness, ChannelStateLimbs.map, toLimbs, ChannelStateLimbs.mk.injEq]
  exact ⟨words2_consistent_map hep, words2_consistent_map hsb, words2_consistent_map hcf,
    amounts_consistent_map ham, words8_consistent_map hfr, words8_consistent_map hh1,
    words8_consistent_map hnr, words8_consistent_map hui, words8_consistent_map hpd,
    words2_consistent_map hsv⟩

/-- Native/target agreement: a witness that holds the `set_witness` values, the constant
    domain, the caller's `channel_id` and `h2_tag` evaluates the target preimage to the native
    preimage limb for limb ("the SAME 139 limbs in the SAME order", lines 228–229). -/
theorem set_witness_reproduces_native_preimage (assign : Wire → Nat) (t : ChannelStateTarget)
    (f : ChannelStateFields) (domain channelId : Wire) (h2Wires : Words8 Wire)
    (channelIdValue : Nat) (h2Tag : Words8 Nat)
    (sw : SetWitness assign t f) (dom : assign domain = channelStateDomain)
    (cid : assign channelId = channelIdValue) (tag : h2Wires.map assign = h2Tag) :
    (targetPreimage t domain channelId h2Wires).map assign = nativePreimage f channelIdValue h2Tag := by
  unfold targetPreimage nativePreimage
  rw [channel_state_preimage_map, dom, cid, sw, tag]

/-- The in-circuit digest gates evaluate to the native digest under the same agreement, when
    the gadget is instantiated with the native keccak (agreement of the two keccaks is itself
    the boundary; this only shows the WIRING carries the same limbs to it). -/
theorem digest_gates_compute_native_digest (e : HashEnvironment) (assign : Wire → Nat)
    (t : ChannelStateTarget) (f : ChannelStateFields) (channelId : Wire) (h2Wires : Words8 Wire)
    (out : Words8 Wire) (channelIdValue : Nat) (h2Tag : Words8 Nat)
    (gates : DigestGates e.hashWords assign t channelId h2Wires out)
    (sw : SetWitness assign t f) (cid : assign channelId = channelIdValue)
    (tag : h2Wires.map assign = h2Tag) :
    out.map assign = nativeSigningDigest e f channelIdValue h2Tag := by
  rw [gates.output, set_witness_reproduces_native_preimage assign t f gates.domainWire channelId
    h2Wires channelIdValue h2Tag sw gates.domainConstant cid tag]
  rfl

/-! ## IMSB small-block message (small_block_message.rs) -/

/-- `SmallBlockMessageFields` (lines 51–64): witnessed components, EXCLUDING `channel_id` and
    `tx_tree_root`. -/
structure SmallBlockFields where
  bpMemberSlot : Nat
  bpPkG : Words8 Nat
  smallBlockNumber : Nat
  prevSmallBlockRoot : Words8 Nat
  stateCommitmentRoot : Words8 Nat
  mediumEpochHint : Nat
  closeFreezeNonce : Nat
  deriving DecidableEq, Repr

/-- `SmallBlockMessageFieldsTarget` (lines 92–103) when `α = Wire`; the `set_witness` values
    when `α = Nat`. -/
structure SmallBlockLimbs (α : Type) where
  bpMemberSlot : α
  bpPkG : Words8 α
  smallBlockNumber : Words2 α
  prevSmallBlockRoot : Words8 α
  stateCommitmentRoot : Words8 α
  mediumEpochHint : Words2 α
  closeFreezeNonce : Words2 α
  deriving DecidableEq, Repr

def SmallBlockLimbs.map (g : α → β) (l : SmallBlockLimbs α) : SmallBlockLimbs β :=
  ⟨g l.bpMemberSlot, l.bpPkG.map g, l.smallBlockNumber.map g, l.prevSmallBlockRoot.map g,
   l.stateCommitmentRoot.map g, l.mediumEpochHint.map g, l.closeFreezeNonce.map g⟩

/-- The 31 witnessed limbs in preimage order. -/
def SmallBlockLimbs.witnessed (l : SmallBlockLimbs α) : List α :=
  [l.bpMemberSlot] ++ l.bpPkG.words ++ l.smallBlockNumber.words ++ l.prevSmallBlockRoot.words ++
  l.stateCommitmentRoot.words ++ l.mediumEpochHint.words ++ l.closeFreezeNonce.words

def smallToLimbs (f : SmallBlockFields) : SmallBlockLimbs Nat :=
  ⟨f.bpMemberSlot, f.bpPkG, splitU64 f.smallBlockNumber, f.prevSmallBlockRoot,
   f.stateCommitmentRoot, splitU64 f.mediumEpochHint, splitU64 f.closeFreezeNonce⟩

/-- The shared 41-limb layout (native lines 73–85, target lines 150–160):
    `[0] domain, [1] channel_id, [2] bp_member_slot, [3..11) bp_pk_g, [11..13) small_block_number,
    [13..21) prev_small_block_root, [21..29) tx_tree_root, [29..37) state_commitment_root,
    [37..39) medium_epoch_hint, [39..41) close_freeze_nonce`. -/
def smallBlockPreimageG (domain channelId : α) (l : SmallBlockLimbs α) (txTreeRoot : Words8 α) :
    List α :=
  [domain, channelId, l.bpMemberSlot] ++ l.bpPkG.words ++ l.smallBlockNumber.words ++
  l.prevSmallBlockRoot.words ++ txTreeRoot.words ++ l.stateCommitmentRoot.words ++
  l.mediumEpochHint.words ++ l.closeFreezeNonce.words

/-- The limb stream hashed by `SmallBlockMessageFields::signing_digest` (lines 72–86). -/
def nativeSmallPreimage (f : SmallBlockFields) (channelId : Nat) (txTreeRoot : Words8 Nat) :
    List Nat :=
  smallBlockPreimageG smallBlockDomain channelId (smallToLimbs f) txTreeRoot

def nativeSmallDigest (e : HashEnvironment) (f : SmallBlockFields) (channelId : Nat)
    (txTreeRoot : Words8 Nat) : Words8 Nat :=
  e.hashWords (nativeSmallPreimage f channelId txTreeRoot)

def smallBlockSegmentWidths : List Nat := [1, 1, 1, 8, 2, 8, 8, 8, 2, 2]
def smallBlockSegmentOffsets : List Nat := [0, 1, 2, 3, 11, 13, 21, 29, 37, 39]

theorem small_block_segment_offsets_are_prefix_sums :
    prefixSums smallBlockSegmentWidths = smallBlockSegmentOffsets := by decide
theorem small_block_segment_widths_sum_to_41 :
    smallBlockSegmentWidths.foldl (· + ·) 0 = smallBlockPreimageLen := by decide

theorem small_block_preimage_width (domain channelId : α) (l : SmallBlockLimbs α)
    (txTreeRoot : Words8 α) : (smallBlockPreimageG domain channelId l txTreeRoot).length = 41 := by
  simp [smallBlockPreimageG, Words8.words, Words2.words]

theorem native_small_preimage_width (f : SmallBlockFields) (channelId : Nat) (txTreeRoot : Words8 Nat) :
    (nativeSmallPreimage f channelId txTreeRoot).length = smallBlockPreimageLen :=
  small_block_preimage_width _ _ _ _

theorem small_block_witnessed_width (l : SmallBlockLimbs α) :
    l.witnessed.length = smallBlockWitnessedLen := by
  simp [SmallBlockLimbs.witnessed, Words8.words, Words2.words, smallBlockWitnessedLen]

theorem small_block_segment_offsets (domain channelId : α) (l : SmallBlockLimbs α)
    (txTreeRoot : Words8 α) :
    let p := smallBlockPreimageG domain channelId l txTreeRoot
    p.getD 0 domain = domain ∧
    p.getD 1 domain = channelId ∧
    p.getD 2 domain = l.bpMemberSlot ∧
    (p.drop 3).take 8 = l.bpPkG.words ∧
    (p.drop 11).take 2 = l.smallBlockNumber.words ∧
    (p.drop 13).take 8 = l.prevSmallBlockRoot.words ∧
    (p.drop 21).take 8 = txTreeRoot.words ∧
    (p.drop 29).take 8 = l.stateCommitmentRoot.words ∧
    (p.drop 37).take 2 = l.mediumEpochHint.words ∧
    p.drop 39 = l.closeFreezeNonce.words := by
  cases l with
  | mk slot pk sb pr sc me cf =>
    cases pk; cases sb; cases pr; cases sc; cases me; cases cf; cases txTreeRoot
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- The block producer's slot and Goldilocks pubkey hash are carried at [2] and [3..11). -/
theorem small_block_carries_bp_slot_and_key (domain channelId : α) (l : SmallBlockLimbs α)
    (txTreeRoot : Words8 α) :
    (smallBlockPreimageG domain channelId l txTreeRoot).getD 2 domain = l.bpMemberSlot ∧
    ((smallBlockPreimageG domain channelId l txTreeRoot).drop 3).take 8 = l.bpPkG.words :=
  ⟨(small_block_segment_offsets domain channelId l txTreeRoot).2.2.1,
   (small_block_segment_offsets domain channelId l txTreeRoot).2.2.2.1⟩

/-- `channel_id` appears exactly once in the IMSB message (at [1]); `tx_tree_root` at [21..29). -/
theorem small_block_connected_offsets (domain channelId : α) (l : SmallBlockLimbs α)
    (txTreeRoot : Words8 α) :
    (smallBlockPreimageG domain channelId l txTreeRoot).getD 1 domain = channelId ∧
    ((smallBlockPreimageG domain channelId l txTreeRoot).drop 21).take 8 = txTreeRoot.words :=
  ⟨(small_block_segment_offsets domain channelId l txTreeRoot).2.1,
   (small_block_segment_offsets domain channelId l txTreeRoot).2.2.2.2.2.2.1⟩

structure SmallBlockReading (α : Type) where
  domain : α
  channelId : α
  limbs : SmallBlockLimbs α
  txTreeRoot : Words8 α
  deriving DecidableEq, Repr

def readSmallBlockPreimage (xs : List α) (dflt : α) : SmallBlockReading α :=
  ⟨xs.getD 0 dflt, xs.getD 1 dflt,
   ⟨xs.getD 2 dflt, Words8.read xs dflt 3, Words2.read xs dflt 11, Words8.read xs dflt 13,
    Words8.read xs dflt 29, Words2.read xs dflt 37, Words2.read xs dflt 39⟩,
   Words8.read xs dflt 21⟩

theorem read_small_block_preimage (domain channelId : α) (l : SmallBlockLimbs α)
    (txTreeRoot : Words8 α) (dflt : α) :
    readSmallBlockPreimage (smallBlockPreimageG domain channelId l txTreeRoot) dflt =
      ⟨domain, channelId, l, txTreeRoot⟩ := by
  cases l with
  | mk slot pk sb pr sc me cf =>
    cases pk; cases sb; cases pr; cases sc; cases me; cases cf; cases txTreeRoot
    rfl

theorem small_block_layout_injective {domain domain' channelId channelId' : α}
    {l l' : SmallBlockLimbs α} {tx tx' : Words8 α}
    (same : smallBlockPreimageG domain channelId l tx = smallBlockPreimageG domain' channelId' l' tx') :
    domain = domain' ∧ channelId = channelId' ∧ l = l' ∧ tx = tx' := by
  have h := congrArg (fun xs => readSmallBlockPreimage xs domain) same
  simp only [read_small_block_preimage, SmallBlockReading.mk.injEq] at h
  exact h

theorem small_to_limbs_injective {f f' : SmallBlockFields} (same : smallToLimbs f = smallToLimbs f') :
    f = f' := by
  cases f; cases f'
  simp only [smallToLimbs, SmallBlockLimbs.mk.injEq] at same
  obtain ⟨s, k, n, p, c, m, z⟩ := same
  simp [s, k, p, c, split_u64_injective n, split_u64_injective m, split_u64_injective z]

theorem native_small_preimage_injective {f f' : SmallBlockFields} {channelId channelId' : Nat}
    {tx tx' : Words8 Nat}
    (same : nativeSmallPreimage f channelId tx = nativeSmallPreimage f' channelId' tx') :
    f = f' ∧ channelId = channelId' ∧ tx = tx' := by
  obtain ⟨_, c, l, h⟩ := small_block_layout_injective same
  exact ⟨small_to_limbs_injective l, c, h⟩

theorem concrete_small_digest_binding (e : HashEnvironment) {f f' : SmallBlockFields}
    {channelId channelId' : Nat} {tx tx' : Words8 Nat}
    (noCollision : e.hashWords (nativeSmallPreimage f channelId tx) =
      e.hashWords (nativeSmallPreimage f' channelId' tx') →
      nativeSmallPreimage f channelId tx = nativeSmallPreimage f' channelId' tx')
    (same : nativeSmallDigest e f channelId tx = nativeSmallDigest e f' channelId' tx') :
    f = f' ∧ channelId = channelId' ∧ tx = tx' :=
  native_small_preimage_injective (noCollision same)

def SmallBlockFields.NativeRepresentable (f : SmallBlockFields) : Prop :=
  f.bpMemberSlot < limbBase ∧ f.bpPkG.Bounded ∧ f.smallBlockNumber < scalarLimit ∧
  f.prevSmallBlockRoot.Bounded ∧ f.stateCommitmentRoot.Bounded ∧
  f.mediumEpochHint < scalarLimit ∧ f.closeFreezeNonce < scalarLimit

theorem small_block_domain_is_u32 : smallBlockDomain < limbBase := by decide

theorem native_small_preimage_limbs_are_u32 (f : SmallBlockFields) (channelId : Nat)
    (txTreeRoot : Words8 Nat) (rep : f.NativeRepresentable) (cid : channelId < limbBase)
    (root : txTreeRoot.Bounded) :
    ∀ x ∈ nativeSmallPreimage f channelId txTreeRoot, x < limbBase := by
  obtain ⟨slot, pk, sb, pr, sc, me, cf⟩ := rep
  unfold nativeSmallPreimage smallBlockPreimageG smallToLimbs
  simp only
  repeat' apply forall_mem_append_of
  · intro x hx
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hx
    rcases hx with rfl | rfl | rfl
    · exact small_block_domain_is_u32
    · exact cid
    · exact slot
  · exact pk
  · exact split_u64_limbs_are_u32 sb
  · exact pr
  · exact root
  · exact sc
  · exact split_u64_limbs_are_u32 me
  · exact split_u64_limbs_are_u32 cf

/-! ### IMSB target twin (lines 92–188) -/

abbrev SmallBlockTarget := SmallBlockLimbs Wire

/-- `compute_signing_digest`'s input vector (lines 150–160). -/
def smallTargetPreimage (t : SmallBlockTarget) (domain channelId : Wire) (txTreeRoot : Words8 Wire) :
    List Wire :=
  smallBlockPreimageG domain channelId t txTreeRoot

theorem small_target_connected_wires_at_pinned_offsets (t : SmallBlockTarget)
    (domain channelId : Wire) (txTreeRoot : Words8 Wire) :
    (smallTargetPreimage t domain channelId txTreeRoot).getD 0 domain = domain ∧
    (smallTargetPreimage t domain channelId txTreeRoot).getD 1 domain = channelId ∧
    ((smallTargetPreimage t domain channelId txTreeRoot).drop 21).take 8 = txTreeRoot.words := by
  have h := small_block_segment_offsets domain channelId t txTreeRoot
  exact ⟨h.1, h.2.1, h.2.2.2.2.2.2.1⟩

theorem small_target_preimage_partition (t : SmallBlockTarget) (domain channelId : Wire)
    (txTreeRoot : Words8 Wire) :
    smallTargetPreimage t domain channelId txTreeRoot =
      [domain, channelId] ++ t.witnessed.take 19 ++ txTreeRoot.words ++ t.witnessed.drop 19 := by
  cases t with
  | mk slot pk sb pr sc me cf =>
    cases pk; cases sb; cases pr; cases sc; cases me; cases cf
    rfl

theorem small_target_preimage_wires_are_caller_or_witnessed (t : SmallBlockTarget)
    (domain channelId : Wire) (txTreeRoot : Words8 Wire) :
    ∀ w ∈ smallTargetPreimage t domain channelId txTreeRoot,
      w ∈ [domain, channelId] ++ txTreeRoot.words ∨ w ∈ t.witnessed := by
  rw [small_target_preimage_partition]
  intro w hw
  simp only [List.append_assoc, List.mem_append, List.mem_cons, List.mem_singleton,
    List.not_mem_nil, or_false] at hw ⊢
  rcases hw with (rfl | rfl) | hw | hw | hw
  · exact Or.inl (Or.inl rfl)
  · exact Or.inl (Or.inr (Or.inl rfl))
  · exact Or.inr (List.mem_of_mem_take hw)
  · exact Or.inl (Or.inr (Or.inr hw))
  · exact Or.inr (List.mem_of_mem_drop hw)

/-- Allocation ORDER of `SmallBlockMessageFieldsTarget::new` (lines 114–120): slot, pk_g,
    small_block_number, medium_epoch_hint, close_freeze_nonce, prev root, state commitment root
    — NOT preimage order. Every allocation range-checks 32 bits. -/
inductive SmallAlloc where
  | u32Limb (name : String)
  | bytes32 (name : String)
  deriving DecidableEq, Repr

def SmallAlloc.limbs : SmallAlloc → Nat
  | .u32Limb _ => 1
  | .bytes32 _ => 8

def SmallAlloc.rangeChecked : SmallAlloc → Bool
  | _ => true

def smallBlockAllocationPlan : List SmallAlloc :=
  [.u32Limb "bp_member_slot", .bytes32 "bp_pk_g",
   .u32Limb "small_block_number.hi", .u32Limb "small_block_number.lo",
   .u32Limb "medium_epoch_hint.hi", .u32Limb "medium_epoch_hint.lo",
   .u32Limb "close_freeze_nonce.hi", .u32Limb "close_freeze_nonce.lo",
   .bytes32 "prev_small_block_root", .bytes32 "state_commitment_root"]

theorem small_block_allocation_width :
    (smallBlockAllocationPlan.map SmallAlloc.limbs).foldl (· + ·) 0 = smallBlockWitnessedLen := by
  decide

theorem small_block_allocation_all_range_checked :
    ∀ a ∈ smallBlockAllocationPlan, a.rangeChecked = true := by
  intro a _
  rfl

theorem small_block_allocation_has_no_channel_id_or_tx_root :
    ∀ a ∈ smallBlockAllocationPlan, a ≠ .u32Limb "channel_id" ∧ a ≠ .bytes32 "tx_tree_root" := by
  decide

def SmallTargetRangeGates (val : Wire → Nat) (t : SmallBlockTarget) : Prop :=
  ∀ w ∈ t.witnessed, val w < limbBase

/-- Lines 134–136: `channel_id` / `tx_tree_root` are the caller's "already range-checked"
    wires — that is an assumption here, exactly as in the source comment. -/
theorem small_keccak_inputs_bounded_given_caller_wires (val : Wire → Nat) (t : SmallBlockTarget)
    (domain channelId : Wire) (txTreeRoot : Words8 Wire) (gates : SmallTargetRangeGates val t)
    (dom : val domain < limbBase) (cid : val channelId < limbBase)
    (root : ∀ w ∈ txTreeRoot.words, val w < limbBase) :
    ∀ w ∈ smallTargetPreimage t domain channelId txTreeRoot, val w < limbBase := by
  intro w hw
  rcases small_target_preimage_wires_are_caller_or_witnessed t domain channelId txTreeRoot w hw with h | h
  · simp only [List.mem_append, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at h
    rcases h with (rfl | rfl) | h
    · exact dom
    · exact cid
    · exact root w h
  · exact gates w h

structure SmallDigestGates (gadget : KeccakGadget) (val : Wire → Nat) (t : SmallBlockTarget)
    (channelId : Wire) (txTreeRoot : Words8 Wire) (out : Words8 Wire) : Prop where
  domainWire : Wire
  domainConstant : val domainWire = smallBlockDomain
  output : out.map val = gadget ((smallTargetPreimage t domainWire channelId txTreeRoot).map val)

theorem small_block_preimage_map (g : α → β) (domain channelId : α) (l : SmallBlockLimbs α)
    (txTreeRoot : Words8 α) :
    (smallBlockPreimageG domain channelId l txTreeRoot).map g =
      smallBlockPreimageG (g domain) (g channelId) (l.map g) (txTreeRoot.map g) := by
  simp [smallBlockPreimageG, SmallBlockLimbs.map, Words8.map, Words8.words, Words2.map, Words2.words]

def SmallSetWitness (assign : Wire → Nat) (t : SmallBlockTarget) (f : SmallBlockFields) : Prop :=
  t.map assign = smallToLimbs f

/-- `set_witness` writes in SOURCE order (lines 169–186): slot, pk_g, the three u64 pairs,
    then the two roots. -/
def smallBlockWitnessWrites (t : SmallBlockTarget) (f : SmallBlockFields) : List (Wire × Nat) :=
  [(t.bpMemberSlot, f.bpMemberSlot)] ++ t.bpPkG.pairs f.bpPkG ++
  t.smallBlockNumber.pairs (splitU64 f.smallBlockNumber) ++
  t.mediumEpochHint.pairs (splitU64 f.mediumEpochHint) ++
  t.closeFreezeNonce.pairs (splitU64 f.closeFreezeNonce) ++
  t.prevSmallBlockRoot.pairs f.prevSmallBlockRoot ++ t.stateCommitmentRoot.pairs f.stateCommitmentRoot

theorem small_block_witness_write_count (t : SmallBlockTarget) (f : SmallBlockFields) :
    (smallBlockWitnessWrites t f).length = smallBlockWitnessedLen := by
  simp [smallBlockWitnessWrites, Words2.pairs, Words8.pairs, smallBlockWitnessedLen]

theorem small_block_writes_give_set_witness {assign : Wire → Nat} {t : SmallBlockTarget}
    {f : SmallBlockFields} (h : Consistent assign (smallBlockWitnessWrites t f)) :
    SmallSetWitness assign t f := by
  unfold Consistent smallBlockWitnessWrites at h
  have hsc := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hpr := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hcf := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hme := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hsb := forall_mem_append_right h
  have h := forall_mem_append_left h
  have hpk := forall_mem_append_right h
  have hslot := forall_mem_append_left h
  have hslot' : assign t.bpMemberSlot = f.bpMemberSlot := hslot _ (List.mem_singleton.mpr rfl)
  cases t; cases f
  simp only [SmallSetWitness, SmallBlockLimbs.map, smallToLimbs, SmallBlockLimbs.mk.injEq]
  exact ⟨hslot', words8_consistent_map hpk, words2_consistent_map hsb, words8_consistent_map hpr,
    words8_consistent_map hsc, words2_consistent_map hme, words2_consistent_map hcf⟩

theorem small_set_witness_reproduces_native_preimage (assign : Wire → Nat) (t : SmallBlockTarget)
    (f : SmallBlockFields) (domain channelId : Wire) (rootWires : Words8 Wire)
    (channelIdValue : Nat) (txTreeRoot : Words8 Nat)
    (sw : SmallSetWitness assign t f) (dom : assign domain = smallBlockDomain)
    (cid : assign channelId = channelIdValue) (root : rootWires.map assign = txTreeRoot) :
    (smallTargetPreimage t domain channelId rootWires).map assign =
      nativeSmallPreimage f channelIdValue txTreeRoot := by
  unfold smallTargetPreimage nativeSmallPreimage
  rw [small_block_preimage_map, dom, cid, sw, root]

theorem small_digest_gates_compute_native_digest (e : HashEnvironment) (assign : Wire → Nat)
    (t : SmallBlockTarget) (f : SmallBlockFields) (channelId : Wire) (rootWires : Words8 Wire)
    (out : Words8 Wire) (channelIdValue : Nat) (txTreeRoot : Words8 Nat)
    (gates : SmallDigestGates e.hashWords assign t channelId rootWires out)
    (sw : SmallSetWitness assign t f) (cid : assign channelId = channelIdValue)
    (root : rootWires.map assign = txTreeRoot) :
    out.map assign = nativeSmallDigest e f channelIdValue txTreeRoot := by
  rw [gates.output, small_set_witness_reproduces_native_preimage assign t f gates.domainWire channelId
    rootWires channelIdValue txTreeRoot sw gates.domainConstant cid root]
  rfl

/-! ## Cross-message facts -/

/-- The two limb streams can never coincide: different widths (139 vs 41) and different domain
    limbs. Digest-level separation is keccak's job (boundary). -/
theorem channel_state_and_small_block_streams_never_coincide (f : ChannelStateFields)
    (g : SmallBlockFields) (c c' : Nat) (h2 tx : Words8 Nat) :
    nativePreimage f c h2 ≠ nativeSmallPreimage g c' tx := by
  intro h
  have := congrArg List.length h
  rw [native_preimage_width, native_small_preimage_width] at this
  exact absurd this (by decide)

theorem channel_state_stream_starts_with_domain (f : ChannelStateFields) (c : Nat) (h2 : Words8 Nat) :
    (nativePreimage f c h2).getD 0 0 = channelStateDomain := rfl

theorem small_block_stream_starts_with_domain (f : SmallBlockFields) (c : Nat) (tx : Words8 Nat) :
    (nativeSmallPreimage f c tx).getD 0 0 = smallBlockDomain := rfl

/-! ## Concrete positive examples (the `channel_state_preimage_limb_offsets_are_pinned` and
    `small_block_message_fields_digest_matches_canonical_message` fixtures, lines 489–504 and
    201–232). -/

def pinnedFields : ChannelStateFields :=
  ⟨0, 0, 0, Amounts.zero, Words8.zero, Words8.zero, Words8.zero, Words8.zero, Words8.zero,
   0xdeadbeef00000001⟩
def pinnedH2Tag : Words8 Nat := ⟨9, 10, 11, 12, 13, 14, 15, 0xffffffff⟩
def pinnedChannelId : Nat := 0x12345678

theorem pinned_fixture_offsets :
    (nativePreimage pinnedFields pinnedChannelId pinnedH2Tag).length = 139 ∧
    (nativePreimage pinnedFields pinnedChannelId pinnedH2Tag).getD 0 0 = 0x494d4348 ∧
    (nativePreimage pinnedFields pinnedChannelId pinnedH2Tag).getD 1 0 = 0x12345678 ∧
    (nativePreimage pinnedFields pinnedChannelId pinnedH2Tag).getD 8 0 = 0x12345678 ∧
    ((nativePreimage pinnedFields pinnedChannelId pinnedH2Tag).drop 129).take 8 =
      [9, 10, 11, 12, 13, 14, 15, 0xffffffff] ∧
    (nativePreimage pinnedFields pinnedChannelId pinnedH2Tag).drop 137 = [0xdeadbeef, 0x00000001] := by
  decide

theorem pinned_fixture_is_native_representable : pinnedFields.NativeRepresentable := by
  simp only [ChannelStateFields.NativeRepresentable, pinnedFields, scalarLimit, Amounts.Bounded,
    Words8.Bounded, Amounts.zero, Amounts.words, Words8.zero, Words8.words, limbBase]
  decide

theorem pinned_fixture_limbs_are_u32 :
    ∀ x ∈ nativePreimage pinnedFields pinnedChannelId pinnedH2Tag, x < limbBase :=
  native_preimage_limbs_are_u32 _ _ _ pinned_fixture_is_native_representable (by decide)
    (by simp only [Words8.Bounded, pinnedH2Tag, Words8.words, limbBase]; decide)

def pinnedSmallFields : SmallBlockFields :=
  ⟨2, ⟨101, 102, 103, 104, 105, 106, 107, 108⟩, 0x123456789, ⟨1, 2, 3, 4, 5, 6, 7, 8⟩,
   ⟨21, 22, 23, 24, 25, 26, 27, 28⟩, 42, 0xdeadbeef00000001⟩

theorem pinned_small_fixture_stream :
    nativeSmallPreimage pinnedSmallFields 5 pinnedH2Tag =
      [0x494d5342, 5, 2, 101, 102, 103, 104, 105, 106, 107, 108, 1, 0x23456789,
       1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xffffffff,
       21, 22, 23, 24, 25, 26, 27, 28, 0, 42, 0xdeadbeef, 1] := by
  decide

end Zkp.Implementation.BlockMessages
