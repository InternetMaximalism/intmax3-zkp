import Zkp.Implementation.CloseFunding
import Zkp.Implementation.CloseAssetBacking

/-!
# Materializer / backing-circuit public-input bridge

Composes the two existing handwritten models: `CloseFunding`
(contracts/src/CloseFundingMaterializer.sol) and `CloseAssetBacking`
(the Rust `CloseAssetBackingCircuit` public-input codec). Nothing here is a
refinement certificate for Solidity, Rust, plonky2 or the EVM.

What is proved: a successful modeled `materializeSignedHead` call is followed
back to the exact compact-verifier return, the exact Solidity-side
`BackingStatement` it validated, and the exact circuit-side public-input record
those same 26 words decode to, with the two independent big-endian limb readings
(`CloseFunding.limbsToBytes32` and `CloseAssetBacking.Words8.value`) proved
equal on range-checked limbs.

What is NOT proved and stays an explicit dependency: `verifyCompact` soundness
(no proof-system semantics), that the words came from a satisfying assignment of
the backing circuit, that the Manager getter view (`Environment.manager`) agrees
with the Manager contract's storage, keccak collision resistance, and that a
finalized extended-state commitment entitles the channel to the credited amounts
(the L2 ledger residue). The theorems below derive only what this call's own
executable checks force.

Range-check note: `validateBackingPublicInputs` range-checks words 0..24 below
2^32 and word 25 below 2^63, which is every conjunct of
`CloseAssetBacking.PublicInputs.Canonical` EXCEPT `0 < channelId`. The
Materializer never requires the bound channel id to be nonzero, so the receipt
below carries the shape-only `parseTargets` decoding (plus the three `Checked`
facts and the anchor bound) rather than `parsePublicInputs`;
`validated_words_parse_natively` supplies the native decode under the extra
`0 < channelId` premise.
-/

namespace Zkp.Implementation.BackingBridge

/-! ## Local `Except` peeling helpers (same pattern as ChannelStateUpdate) -/

theorem bind_ok_iff {a b : Type} (r : CloseFunding.Result a) (f : a → CloseFunding.Result b)
    (value : b) : (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem require_ok_iff (condition : Bool) (error : CloseFunding.Error) :
    CloseFunding.require condition error = .ok () ↔ condition = true := by
  cases condition <;> simp [CloseFunding.require]

theorem pure_ok_iff {a : Type} (x y : a) : (pure x : CloseFunding.Result a) = .ok y ↔ x = y := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; rw [h]; rfl

/-! ## Pinned width constants shared by the two models -/

theorem backing_word_bound_pinned : CloseFunding.u32Limit = CloseAssetBacking.wordBase := rfl

theorem backing_block_bound_pinned : CloseFunding.u63Limit = CloseAssetBacking.blockLimit := rfl

theorem backing_public_input_length_pinned : CloseAssetBacking.publicInputsLength = 26 := rfl

/-! ## The two big-endian limb readings agree on range-checked limbs

`limbsToBytes32` shifts an accumulator left by 32 bits and ORs the next limb in,
masking to 256 bits; `Words8.value` folds `acc * 2^32 + limb`. On limbs below
2^32 the OR is an addition and the eight-limb result never reaches 2^256, so the
two readings coincide. -/

theorem shift_or_is_mul_add {v limb : Nat} (h : limb < 2 ^ 32) :
    (Nat.shiftLeft v 32 ||| limb) = v * 2 ^ 32 + limb := by
  show v <<< 32 ||| limb = v * 2 ^ 32 + limb
  rw [Nat.shiftLeft_eq, Nat.mul_comm v (2 ^ 32), ← Nat.mul_add_lt_is_or h v, Nat.mul_comm]

theorem limb_step_bound {v limb k : Nat} (hl : limb < 2 ^ 32) (hv : v < 2 ^ k) :
    v * 2 ^ 32 + limb < 2 ^ (k + 32) := by
  have _widen : (v + 1) * 2 ^ 32 ≤ 2 ^ k * 2 ^ 32 := Nat.mul_le_mul hv (Nat.le_refl _)
  have _expand : (v + 1) * 2 ^ 32 = v * 2 ^ 32 + 2 ^ 32 := Nat.succ_mul v (2 ^ 32)
  have collapse : 2 ^ k * 2 ^ 32 = 2 ^ (k + 32) := (Nat.pow_add 2 k 32).symm
  omega

theorem limbs_loop_step {pi : List Nat} {off n i v limb : Nat}
    (h : CloseFunding.limbAt pi (off + i) = .ok limb) :
    CloseFunding.limbsToBytes32Loop pi off (n + 1) i v =
      CloseFunding.limbsToBytes32Loop pi off n (i + 1)
        ((Nat.shiftLeft v 32 ||| limb) % CloseFunding.u256Limit) := by
  simp only [CloseFunding.limbsToBytes32Loop, h, CloseFunding.result_bind_ok]

theorem limbs_loop_step_value {pi : List Nat} {off n i v limb : Nat}
    (h : CloseFunding.limbAt pi (off + i) = .ok limb) (hl : limb < 2 ^ 32)
    (hv : v * 2 ^ 32 + limb < CloseFunding.u256Limit) :
    CloseFunding.limbsToBytes32Loop pi off (n + 1) i v =
      CloseFunding.limbsToBytes32Loop pi off n (i + 1) (v * 2 ^ 32 + limb) := by
  rw [limbs_loop_step h, shift_or_is_mul_add hl, Nat.mod_eq_of_lt hv]

theorem limbs_to_bytes32_is_words8_value {pi : List Nat} {off : Nat}
    {w : CloseAssetBacking.Words8} (checked : w.Checked)
    (r0 : CloseFunding.limbAt pi (off + 0) = .ok w.w0)
    (r1 : CloseFunding.limbAt pi (off + 1) = .ok w.w1)
    (r2 : CloseFunding.limbAt pi (off + 2) = .ok w.w2)
    (r3 : CloseFunding.limbAt pi (off + 3) = .ok w.w3)
    (r4 : CloseFunding.limbAt pi (off + 4) = .ok w.w4)
    (r5 : CloseFunding.limbAt pi (off + 5) = .ok w.w5)
    (r6 : CloseFunding.limbAt pi (off + 6) = .ok w.w6)
    (r7 : CloseFunding.limbAt pi (off + 7) = .ok w.w7) :
    CloseFunding.limbsToBytes32 pi off = .ok w.value := by
  have b0 : w.w0 < 2 ^ 32 := checked w.w0 (by simp [CloseAssetBacking.Words8.words])
  have b1 : w.w1 < 2 ^ 32 := checked w.w1 (by simp [CloseAssetBacking.Words8.words])
  have b2 : w.w2 < 2 ^ 32 := checked w.w2 (by simp [CloseAssetBacking.Words8.words])
  have b3 : w.w3 < 2 ^ 32 := checked w.w3 (by simp [CloseAssetBacking.Words8.words])
  have b4 : w.w4 < 2 ^ 32 := checked w.w4 (by simp [CloseAssetBacking.Words8.words])
  have b5 : w.w5 < 2 ^ 32 := checked w.w5 (by simp [CloseAssetBacking.Words8.words])
  have b6 : w.w6 < 2 ^ 32 := checked w.w6 (by simp [CloseAssetBacking.Words8.words])
  have b7 : w.w7 < 2 ^ 32 := checked w.w7 (by simp [CloseAssetBacking.Words8.words])
  have zero : (0 : Nat) < 2 ^ 0 := by decide
  have t1 : 0 * 2 ^ 32 + w.w0 < 2 ^ 32 := limb_step_bound b0 zero
  have t2 : (0 * 2 ^ 32 + w.w0) * 2 ^ 32 + w.w1 < 2 ^ 64 := limb_step_bound b1 t1
  have t3 : ((0 * 2 ^ 32 + w.w0) * 2 ^ 32 + w.w1) * 2 ^ 32 + w.w2 < 2 ^ 96 :=
    limb_step_bound b2 t2
  have t4 : (((0 * 2 ^ 32 + w.w0) * 2 ^ 32 + w.w1) * 2 ^ 32 + w.w2) * 2 ^ 32 + w.w3 < 2 ^ 128 :=
    limb_step_bound b3 t3
  have t5 : ((((0 * 2 ^ 32 + w.w0) * 2 ^ 32 + w.w1) * 2 ^ 32 + w.w2) * 2 ^ 32 + w.w3) * 2 ^ 32
      + w.w4 < 2 ^ 160 := limb_step_bound b4 t4
  have t6 : (((((0 * 2 ^ 32 + w.w0) * 2 ^ 32 + w.w1) * 2 ^ 32 + w.w2) * 2 ^ 32 + w.w3) * 2 ^ 32
      + w.w4) * 2 ^ 32 + w.w5 < 2 ^ 192 := limb_step_bound b5 t5
  have t7 : ((((((0 * 2 ^ 32 + w.w0) * 2 ^ 32 + w.w1) * 2 ^ 32 + w.w2) * 2 ^ 32 + w.w3) * 2 ^ 32
      + w.w4) * 2 ^ 32 + w.w5) * 2 ^ 32 + w.w6 < 2 ^ 224 := limb_step_bound b6 t6
  have fit : ∀ {value k : Nat}, value < 2 ^ k → k ≤ 256 → value < CloseFunding.u256Limit := by
    intro value k hvalue hk
    exact Nat.lt_of_lt_of_le hvalue (Nat.pow_le_pow_right (by decide) hk)
  rw [CloseFunding.limbsToBytes32,
    limbs_loop_step_value r0 b0 (fit t1 (by decide)),
    limbs_loop_step_value r1 b1 (fit t2 (by decide)),
    limbs_loop_step_value r2 b2 (fit t3 (by decide)),
    limbs_loop_step_value r3 b3 (fit t4 (by decide)),
    limbs_loop_step_value r4 b4 (fit t5 (by decide)),
    limbs_loop_step_value r5 b5 (fit t6 (by decide)),
    limbs_loop_step_value r6 b6 (fit t7 (by decide)),
    limbs_loop_step_value r7 b7 (fit (limb_step_bound b7 t7) (by decide))]
  simp only [CloseFunding.limbsToBytes32Loop, CloseFunding.result_pure, Except.ok.injEq]
  simp [CloseAssetBacking.Words8.value, CloseAssetBacking.Words8.words, CloseAssetBacking.wordBase]

/-! ## What the Solidity-side range gate actually establishes -/

theorem check_u32_limbs_bound {pi : List Nat} : ∀ {n i j x : Nat},
    CloseFunding.checkU32Limbs pi n i = .ok () → j < n →
    CloseFunding.limbAt pi (i + j) = .ok x → x < 2 ^ 32 := by
  intro n
  induction n with
  | zero => intro i j x _ hj _; exact absurd hj (Nat.not_lt_zero j)
  | succ m ih =>
    intro i j x h hj read
    simp only [CloseFunding.checkU32Limbs, CloseFunding.require] at h
    cases hl : CloseFunding.limbAt pi i with
    | error err => simp [hl] at h
    | ok limb =>
      simp only [hl, CloseFunding.result_bind_ok] at h
      split at h <;> simp only [CloseFunding.result_bind_ok, CloseFunding.result_bind_error] at h
      rename_i below
      cases j with
      | zero =>
        rw [Nat.add_zero, hl] at read
        have same : limb = x := Except.ok.inj read
        subst same
        exact of_decide_eq_true below
      | succ k =>
        refine ih h (Nat.lt_of_succ_lt_succ hj) ?_
        rw [show i + 1 + k = i + (k + 1) by omega]
        exact read

theorem validated_limb_below_bound {pi : List Nat} {j x : Nat}
    (h : CloseFunding.checkU32Limbs pi 25 0 = .ok ())
    (hj : j < 25) (read : CloseFunding.limbAt pi j = .ok x) : x < 2 ^ 32 := by
  refine check_u32_limbs_bound h hj ?_
  simpa using read

theorem checked_words_of_reads {pi : List Nat} {w : CloseAssetBacking.Words8} {j : Nat}
    (h : CloseFunding.checkU32Limbs pi 25 0 = .ok ()) (hj : j + 7 < 25)
    (r0 : CloseFunding.limbAt pi (j + 0) = .ok w.w0)
    (r1 : CloseFunding.limbAt pi (j + 1) = .ok w.w1)
    (r2 : CloseFunding.limbAt pi (j + 2) = .ok w.w2)
    (r3 : CloseFunding.limbAt pi (j + 3) = .ok w.w3)
    (r4 : CloseFunding.limbAt pi (j + 4) = .ok w.w4)
    (r5 : CloseFunding.limbAt pi (j + 5) = .ok w.w5)
    (r6 : CloseFunding.limbAt pi (j + 6) = .ok w.w6)
    (r7 : CloseFunding.limbAt pi (j + 7) = .ok w.w7) :
    w.Checked := by
  intro x hx
  simp only [CloseAssetBacking.Words8.words, List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases hx with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · exact validated_limb_below_bound h (by omega) r0
  · exact validated_limb_below_bound h (by omega) r1
  · exact validated_limb_below_bound h (by omega) r2
  · exact validated_limb_below_bound h (by omega) r3
  · exact validated_limb_below_bound h (by omega) r4
  · exact validated_limb_below_bound h (by omega) r5
  · exact validated_limb_below_bound h (by omega) r6
  · exact validated_limb_below_bound h (by omega) r7

/-! ## Reading the circuit-side record back out of the 26 words -/

theorem length_26_parses {pi : List Nat} (h : pi.length = 26) :
    ∃ p : CloseAssetBacking.PublicInputs, CloseAssetBacking.parseTargets pi = some p := by
  rcases pi with _ | ⟨a0, pi⟩; · simp at h
  rcases pi with _ | ⟨a1, pi⟩; · simp at h
  rcases pi with _ | ⟨a2, pi⟩; · simp at h
  rcases pi with _ | ⟨a3, pi⟩; · simp at h
  rcases pi with _ | ⟨a4, pi⟩; · simp at h
  rcases pi with _ | ⟨a5, pi⟩; · simp at h
  rcases pi with _ | ⟨a6, pi⟩; · simp at h
  rcases pi with _ | ⟨a7, pi⟩; · simp at h
  rcases pi with _ | ⟨a8, pi⟩; · simp at h
  rcases pi with _ | ⟨a9, pi⟩; · simp at h
  rcases pi with _ | ⟨a10, pi⟩; · simp at h
  rcases pi with _ | ⟨a11, pi⟩; · simp at h
  rcases pi with _ | ⟨a12, pi⟩; · simp at h
  rcases pi with _ | ⟨a13, pi⟩; · simp at h
  rcases pi with _ | ⟨a14, pi⟩; · simp at h
  rcases pi with _ | ⟨a15, pi⟩; · simp at h
  rcases pi with _ | ⟨a16, pi⟩; · simp at h
  rcases pi with _ | ⟨a17, pi⟩; · simp at h
  rcases pi with _ | ⟨a18, pi⟩; · simp at h
  rcases pi with _ | ⟨a19, pi⟩; · simp at h
  rcases pi with _ | ⟨a20, pi⟩; · simp at h
  rcases pi with _ | ⟨a21, pi⟩; · simp at h
  rcases pi with _ | ⟨a22, pi⟩; · simp at h
  rcases pi with _ | ⟨a23, pi⟩; · simp at h
  rcases pi with _ | ⟨a24, pi⟩; · simp at h
  rcases pi with _ | ⟨a25, pi⟩; · simp at h
  rcases pi with _ | ⟨a26, pi⟩
  · exact ⟨_, rfl⟩
  · simp at h

theorem public_input_words_read (p : CloseAssetBacking.PublicInputs) :
    CloseFunding.limbAt p.words 0 = .ok p.channelId ∧
    CloseFunding.limbAt p.words (1 + 0) = .ok p.settledTxChain.w0 ∧
    CloseFunding.limbAt p.words (1 + 1) = .ok p.settledTxChain.w1 ∧
    CloseFunding.limbAt p.words (1 + 2) = .ok p.settledTxChain.w2 ∧
    CloseFunding.limbAt p.words (1 + 3) = .ok p.settledTxChain.w3 ∧
    CloseFunding.limbAt p.words (1 + 4) = .ok p.settledTxChain.w4 ∧
    CloseFunding.limbAt p.words (1 + 5) = .ok p.settledTxChain.w5 ∧
    CloseFunding.limbAt p.words (1 + 6) = .ok p.settledTxChain.w6 ∧
    CloseFunding.limbAt p.words (1 + 7) = .ok p.settledTxChain.w7 ∧
    CloseFunding.limbAt p.words (9 + 0) = .ok p.tokenFundsDigest.w0 ∧
    CloseFunding.limbAt p.words (9 + 1) = .ok p.tokenFundsDigest.w1 ∧
    CloseFunding.limbAt p.words (9 + 2) = .ok p.tokenFundsDigest.w2 ∧
    CloseFunding.limbAt p.words (9 + 3) = .ok p.tokenFundsDigest.w3 ∧
    CloseFunding.limbAt p.words (9 + 4) = .ok p.tokenFundsDigest.w4 ∧
    CloseFunding.limbAt p.words (9 + 5) = .ok p.tokenFundsDigest.w5 ∧
    CloseFunding.limbAt p.words (9 + 6) = .ok p.tokenFundsDigest.w6 ∧
    CloseFunding.limbAt p.words (9 + 7) = .ok p.tokenFundsDigest.w7 ∧
    CloseFunding.limbAt p.words (17 + 0) = .ok p.extendedStateCommitment.w0 ∧
    CloseFunding.limbAt p.words (17 + 1) = .ok p.extendedStateCommitment.w1 ∧
    CloseFunding.limbAt p.words (17 + 2) = .ok p.extendedStateCommitment.w2 ∧
    CloseFunding.limbAt p.words (17 + 3) = .ok p.extendedStateCommitment.w3 ∧
    CloseFunding.limbAt p.words (17 + 4) = .ok p.extendedStateCommitment.w4 ∧
    CloseFunding.limbAt p.words (17 + 5) = .ok p.extendedStateCommitment.w5 ∧
    CloseFunding.limbAt p.words (17 + 6) = .ok p.extendedStateCommitment.w6 ∧
    CloseFunding.limbAt p.words (17 + 7) = .ok p.extendedStateCommitment.w7 ∧
    CloseFunding.limbAt p.words 25 = .ok p.anchorBlockNumber := by
  obtain ⟨c, s, t, x, a⟩ := p
  obtain ⟨s0, s1, s2, s3, s4, s5, s6, s7⟩ := s
  obtain ⟨t0, t1, t2, t3, t4, t5, t6, t7⟩ := t
  obtain ⟨x0, x1, x2, x3, x4, x5, x6, x7⟩ := x
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_⟩ <;>
    simp [CloseFunding.limbAt, CloseAssetBacking.PublicInputs.words,
      CloseAssetBacking.Words8.words]

/-! ## Following a successful call back to its inputs -/

theorem verify_backing_ok {e : CloseFunding.Environment} {proof : CloseFunding.Bytes}
    {pi : List Nat} (h : e.verifyCompact proof = .ok pi) :
    CloseFunding.verifyBackingProof e proof = .ok pi := by
  simp [CloseFunding.verifyBackingProof, h, Except.mapError]

theorem verify_backing_ok_inverse {e : CloseFunding.Environment} {proof : CloseFunding.Bytes}
    {pi : List Nat} (h : CloseFunding.verifyBackingProof e proof = .ok pi) :
    e.verifyCompact proof = .ok pi := by
  cases hv : e.verifyCompact proof with
  | error err => rw [CloseFunding.verifyBackingProof, hv] at h; simp [Except.mapError] at h
  | ok words =>
    rw [CloseFunding.verifyBackingProof, hv] at h
    simp only [Except.mapError] at h
    exact h

theorem validated_backing_facts {e : CloseFunding.Environment} {s : CloseFunding.State}
    {manager : CloseFunding.Address} {pi : List Nat} {st : CloseFunding.BackingStatement}
    (h : CloseFunding.validateBackingPublicInputs e s manager pi = .ok st) :
    pi.length = 26 ∧ CloseFunding.checkU32Limbs pi 25 0 = .ok () ∧
      CloseFunding.limbAt pi 25 = .ok st.anchor ∧ st.anchor < CloseFunding.u63Limit ∧
      (∃ channel, (e.manager manager).channelId = .ok channel ∧
        s.managerOfChannel channel = manager ∧ CloseFunding.limbAt pi 0 = .ok channel) ∧
      CloseFunding.limbsToBytes32 pi 1 = .ok st.settledChain ∧
      CloseFunding.limbsToBytes32 pi 9 = .ok st.tokenFundsDigest ∧
      CloseFunding.limbsToBytes32 pi 17 = .ok st.backingRoot ∧
      e.isFinalizedRoot st.backingRoot = .ok true ∧
      (∃ last, e.latestFinalized = .ok last ∧ st.anchor ≤ last) := by
  simp only [CloseFunding.validateBackingPublicInputs, bind_ok_iff, exists_unit,
    require_ok_iff, pure_ok_iff] at h
  obtain ⟨hlen, hcheck, anchor, hanchor, hbelow, channel, hchannel, hbound, piChannel,
    hpi, hmatch, settled, hsettled, funds, hfunds, root, hroot, finalized, hfinalized,
    hfinal, last, hlast, hle, hstatement⟩ := h
  subst hstatement
  have channelEq : piChannel = channel := by simpa using hmatch
  subst channelEq
  refine ⟨by simpa using hlen, hcheck, hanchor, by simpa using hbelow,
    ⟨piChannel, hchannel, by simpa using hbound, hpi⟩, hsettled, hfunds, hroot, ?_,
    ⟨last, hlast, by simpa using hle⟩⟩
  rw [hfinalized, hfinal]

theorem prepared_signed_head_provenance {e : CloseFunding.Environment} {s : CloseFunding.State}
    {manager : CloseFunding.Address} {proof : CloseFunding.Bytes}
    {p : CloseFunding.MaterializationPlan}
    (h : CloseFunding.prepareSignedHead e s manager proof = .ok p) :
    ∃ pi st, e.verifyCompact proof = .ok pi ∧
      CloseFunding.validateBackingPublicInputs e s manager pi = .ok st ∧
      s.attestedProof (CloseFunding.backingProofId e manager proof) = true ∧
      (e.manager manager).settledChain = .ok st.settledChain ∧
      (e.manager manager).tokenFundsDigest = .ok st.tokenFundsDigest ∧
      CloseFunding.prepareMaterialization e s manager st.anchor = .ok p := by
  simp only [CloseFunding.prepareSignedHead, bind_ok_iff, exists_unit, require_ok_iff] at h
  obtain ⟨pi, hverify, st, hvalid, hreceipt, settled, hsettled, hsettledEq, funds, hfunds,
    hfundsEq, hplan⟩ := h
  have settledSame : st.settledChain = settled := by simpa using hsettledEq
  have fundsSame : st.tokenFundsDigest = funds := by simpa using hfundsEq
  refine ⟨pi, st, verify_backing_ok_inverse hverify, hvalid, hreceipt, ?_, ?_, hplan⟩
  · rw [hsettled, settledSame]
  · rw [hfunds, fundsSame]

/-! ## The circuit record carried by validated public inputs -/

theorem validated_words_decode {e : CloseFunding.Environment} {s : CloseFunding.State}
    {manager : CloseFunding.Address} {pi : List Nat} {st : CloseFunding.BackingStatement}
    {channel : CloseFunding.Channel}
    (h : CloseFunding.validateBackingPublicInputs e s manager pi = .ok st)
    (hchannel : (e.manager manager).channelId = .ok channel) :
    ∃ p : CloseAssetBacking.PublicInputs, CloseAssetBacking.parseTargets pi = some p ∧
      p.words = pi ∧ p.channelId = channel ∧ p.anchorBlockNumber = st.anchor ∧
      p.anchorBlockNumber < CloseAssetBacking.blockLimit ∧
      p.settledTxChain.Checked ∧ p.tokenFundsDigest.Checked ∧
      p.extendedStateCommitment.Checked ∧
      p.settledTxChain.value = st.settledChain ∧
      p.tokenFundsDigest.value = st.tokenFundsDigest ∧
      p.extendedStateCommitment.value = st.backingRoot := by
  obtain ⟨hlen, hcheck, hanchor, hbelow, ⟨channel', hchannel', _, hzero⟩,
    hsettled, hfunds, hroot, _, _⟩ := validated_backing_facts h
  have sameChannel : channel' = channel := Except.ok.inj (hchannel'.symm.trans hchannel)
  rw [sameChannel] at hzero
  obtain ⟨p, hparse⟩ := length_26_parses hlen
  have hwords : p.words = pi := CloseAssetBacking.target_decode_success_reconstructs_exact_input hparse
  obtain ⟨q0, s0, s1, s2, s3, s4, s5, s6, s7, f0, f1, f2, f3, f4, f5, f6, f7,
    x0, x1, x2, x3, x4, x5, x6, x7, q25⟩ := public_input_words_read p
  rw [hwords] at q0 s0 s1 s2 s3 s4 s5 s6 s7 f0 f1 f2 f3 f4 f5 f6 f7
  rw [hwords] at x0 x1 x2 x3 x4 x5 x6 x7 q25
  have checkedSettled : p.settledTxChain.Checked :=
    checked_words_of_reads hcheck (by omega) s0 s1 s2 s3 s4 s5 s6 s7
  have checkedFunds : p.tokenFundsDigest.Checked :=
    checked_words_of_reads hcheck (by omega) f0 f1 f2 f3 f4 f5 f6 f7
  have checkedRoot : p.extendedStateCommitment.Checked :=
    checked_words_of_reads hcheck (by omega) x0 x1 x2 x3 x4 x5 x6 x7
  have channelValue : p.channelId = channel := by
    have := q0.symm.trans hzero
    exact Except.ok.inj this
  have anchorValue : p.anchorBlockNumber = st.anchor := by
    have := q25.symm.trans hanchor
    exact Except.ok.inj this
  have settledValue : p.settledTxChain.value = st.settledChain := by
    have := (limbs_to_bytes32_is_words8_value checkedSettled s0 s1 s2 s3 s4 s5 s6 s7).symm.trans
      hsettled
    exact Except.ok.inj this
  have fundsValue : p.tokenFundsDigest.value = st.tokenFundsDigest := by
    have := (limbs_to_bytes32_is_words8_value checkedFunds f0 f1 f2 f3 f4 f5 f6 f7).symm.trans
      hfunds
    exact Except.ok.inj this
  have rootValue : p.extendedStateCommitment.value = st.backingRoot := by
    have := (limbs_to_bytes32_is_words8_value checkedRoot x0 x1 x2 x3 x4 x5 x6 x7).symm.trans hroot
    exact Except.ok.inj this
  have anchorBound : p.anchorBlockNumber < CloseAssetBacking.blockLimit := by
    rw [anchorValue]; exact hbelow
  exact ⟨p, hparse, hwords, channelValue, anchorValue, anchorBound,
    checkedSettled, checkedFunds, checkedRoot, settledValue, fundsValue, rootValue⟩

/-- The Materializer never requires a nonzero bound channel id, so the native
    decode needs `0 < channelId` as an extra premise; everything else in
    `PublicInputs.Canonical` is forced by `validateBackingPublicInputs`. -/
theorem validated_words_parse_natively {e : CloseFunding.Environment} {s : CloseFunding.State}
    {manager : CloseFunding.Address} {pi : List Nat} {st : CloseFunding.BackingStatement}
    {channel : CloseFunding.Channel}
    (h : CloseFunding.validateBackingPublicInputs e s manager pi = .ok st)
    (hchannel : (e.manager manager).channelId = .ok channel) (positive : 0 < channel) :
    ∃ p : CloseAssetBacking.PublicInputs, CloseAssetBacking.parsePublicInputs pi = .ok p ∧
      p.Canonical ∧ p.channelId = channel ∧ p.anchorBlockNumber = st.anchor ∧
      p.settledTxChain.value = st.settledChain ∧
      p.tokenFundsDigest.value = st.tokenFundsDigest ∧
      p.extendedStateCommitment.value = st.backingRoot := by
  obtain ⟨p, _, hwords, hchannelValue, hanchor, hblock, cs, cf, cr, vs, vf, vr⟩ :=
    validated_words_decode h hchannel
  obtain ⟨_, hcheck, _, _, _, _, _, _, _, _⟩ := validated_backing_facts h
  obtain ⟨q0, _⟩ := public_input_words_read p
  rw [hwords] at q0
  have channelBound : p.channelId < CloseAssetBacking.wordBase :=
    validated_limb_below_bound hcheck (by omega) q0
  have canonical : p.Canonical :=
    ⟨⟨by rw [hchannelValue]; exact positive, channelBound⟩, hblock, cs, cf, cr⟩
  refine ⟨p, ?_, canonical, hchannelValue, hanchor, vs, vf, vr⟩
  rw [← hwords]
  exact CloseAssetBacking.native_encode_decode p canonical

/-! ## The materialization receipt -/

/-- Everything a successful modeled `materializeSignedHead` call forces: the
exact verifier return, the exact validated Solidity statement with its finality
and anchor guards, the attestation receipt, the two Manager getters that were
compared, the circuit-side decoding of the very same 26 words with the two limb
readings proved equal, and the plan/credit conservation facts of
`CloseFunding.materialization_call_complete_vector`. Soundness of
`verifyCompact` and the provenance of the Manager getter values are NOT
asserted. -/
theorem signed_head_materialization_receipt {fe : CloseFunding.Environment}
    {w after : CloseFunding.World} {manager : CloseFunding.Address}
    {proof : CloseFunding.Bytes} {events : List CloseFunding.Event}
    (call : CloseFunding.materializeSignedHead fe w manager proof = .ok (after, events)) :
    ∃ (pi : List Nat) (st : CloseFunding.BackingStatement)
      (p : CloseAssetBacking.PublicInputs) (channel : CloseFunding.Channel)
      (plan : CloseFunding.MaterializationPlan),
      fe.verifyCompact proof = .ok pi ∧
      CloseFunding.validateBackingPublicInputs fe w.storage manager pi = .ok st ∧
      fe.isFinalizedRoot st.backingRoot = .ok true ∧
      (∃ last, fe.latestFinalized = .ok last ∧ st.anchor ≤ last) ∧
      w.storage.attestedProof (CloseFunding.backingProofId fe manager proof) = true ∧
      (fe.manager manager).channelId = .ok channel ∧
      w.storage.managerOfChannel channel = manager ∧
      (fe.manager manager).settledChain = .ok st.settledChain ∧
      (fe.manager manager).tokenFundsDigest = .ok st.tokenFundsDigest ∧
      CloseAssetBacking.parseTargets pi = some p ∧
      p.words = pi ∧
      p.channelId = channel ∧
      p.settledTxChain.value = st.settledChain ∧
      p.tokenFundsDigest.value = st.tokenFundsDigest ∧
      p.extendedStateCommitment.value = st.backingRoot ∧
      p.anchorBlockNumber = st.anchor ∧
      p.anchorBlockNumber < CloseAssetBacking.blockLimit ∧
      p.settledTxChain.Checked ∧ p.tokenFundsDigest.Checked ∧
      p.extendedStateCommitment.Checked ∧
      plan.manager = manager ∧ plan.credits.length = plan.tokenCount ∧
      CloseFunding.TokensUnique plan.credits ∧
      (∀ c ∈ plan.credits, (fe.manager manager).amountAt c.token = .ok c.amount) ∧
      after.storage.materializedChannelExit plan.channel = plan.digest ∧ plan.digest ≠ 0 ∧
      (∀ token, after.ledger.escrow token + CloseFunding.transferred plan.credits token
          = w.ledger.escrow token ∧
        after.ledger.pending token manager
          = w.ledger.pending token manager + CloseFunding.transferred plan.credits token) := by
  obtain ⟨prepared, hprepared, _, _⟩ := CloseFunding.materialization_call_exact_accounting call
  obtain ⟨pi, st, hverify, hvalid, hreceipt, hsettled, hfunds, _⟩ :=
    prepared_signed_head_provenance hprepared
  obtain ⟨_, _, _, _, ⟨channel, hchannel, hbound, _⟩, _, _, _, hfinalized, hlatest⟩ :=
    validated_backing_facts hvalid
  obtain ⟨p, hparse, hwords, hchannelValue, hanchorValue, hblock, cs, cf, cr, vs, vf, vr⟩ :=
    validated_words_decode hvalid hchannel
  obtain ⟨plan, hmanager, hlength, hunique, hamounts, hlatch, hdigest, haccounting⟩ :=
    CloseFunding.materialization_call_complete_vector call
  exact ⟨pi, st, p, channel, plan, hverify, hvalid, hfinalized, hlatest, hreceipt, hchannel,
    hbound, hsettled, hfunds, hparse, hwords, hchannelValue, vs, vf, vr, hanchorValue, hblock,
    cs, cf, cr, hmanager, hlength, hunique, hamounts, hlatch, hdigest, haccounting⟩

/-! ## Non-vacuity: a concrete accepted materialization

A coherent getter environment and storage in which every guard of
`materializeSignedHead` passes. No proof system is involved: `verifyCompact` is
the modeled external oracle and simply returns the 26 words. -/

def sampleChannel : CloseFunding.Channel := 7
def sampleManager : CloseFunding.Address := 11
def sampleToken : CloseFunding.Token := 5
def sampleProof : CloseFunding.Bytes := []

def samplePublicInputs : List Nat :=
  [7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 5]

def sampleParsed : CloseAssetBacking.PublicInputs :=
  ⟨7, ⟨0, 0, 0, 0, 0, 0, 0, 1⟩, ⟨0, 0, 0, 0, 0, 0, 0, 2⟩, ⟨0, 0, 0, 0, 0, 0, 0, 3⟩, 5⟩

def sampleManagerView : CloseFunding.ManagerView where
  channelId := .ok sampleChannel
  registry := .ok 2
  materializer := .ok 2
  generation := .ok 4
  status := .ok .closed
  closeDigest := .ok 8
  stateRoot := .ok 3
  settledChain := .ok 1
  tokenFundsDigest := .ok 2
  tokenCount := .ok 1
  tokenAt := fun _ => .ok sampleToken
  amountAt := fun _ => .ok 3

def sampleEnvironment : CloseFunding.Environment where
  chainId := 1
  self := 2
  rollup := 4
  backingVerifier := 6
  codeLength := fun _ => 1
  verifier := fun _ => ⟨.ok 1, .ok 6⟩
  manager := fun _ => sampleManagerView
  channelMemberSet := fun _ => .ok 1
  blockNumber := .ok 9
  latestFinalized := .ok 9
  isFinalizedRoot := fun _ => .ok true
  verifyCompact := fun _ => .ok samplePublicInputs
  hashStatement := fun _ => 0
  hashProofKey := fun _ => 0
  hashBytes := fun _ => 0
  rollupDeploymentChain := 1
  installedMaterializer := 2

def sampleState : CloseFunding.State where
  managerOfChannel := fun _ => sampleManager
  frozenGeneration := fun _ => 4
  lastPostedBlock := fun _ => 0
  materializedChannelExit := fun _ => 0
  anchorPlusOne := fun _ => 6
  attestedProof := fun _ => true
  postedChannel := fun _ => 0
  previousChannelBlock := fun _ => 0

def sampleWorld : CloseFunding.World where
  storage := sampleState
  ledger := ⟨fun _ => 10, fun _ _ => 0⟩

theorem sample_public_inputs_are_exact_words : sampleParsed.words = samplePublicInputs := rfl

theorem sample_words_parse : CloseAssetBacking.parseTargets samplePublicInputs = some sampleParsed :=
  rfl

theorem sample_words_parse_natively :
    CloseAssetBacking.parsePublicInputs samplePublicInputs = .ok sampleParsed := rfl

theorem sample_limb_readings_agree :
    CloseFunding.limbsToBytes32 samplePublicInputs 1 = .ok sampleParsed.settledTxChain.value ∧
    CloseFunding.limbsToBytes32 samplePublicInputs 9 = .ok sampleParsed.tokenFundsDigest.value ∧
    CloseFunding.limbsToBytes32 samplePublicInputs 17
      = .ok sampleParsed.extendedStateCommitment.value := ⟨rfl, rfl, rfl⟩

theorem sample_validation_succeeds :
    CloseFunding.validateBackingPublicInputs sampleEnvironment sampleState sampleManager
      samplePublicInputs = .ok ⟨1, 2, 3, 5⟩ := rfl

theorem sample_materialization_succeeds :
    ∃ after events, CloseFunding.materializeSignedHead sampleEnvironment sampleWorld
      sampleManager sampleProof = .ok (after, events) := ⟨_, _, rfl⟩

/-- The receipt theorem is not vacuous: it applies to the sample trace. -/
theorem sample_materialization_has_receipt :
    ∃ (pi : List Nat) (st : CloseFunding.BackingStatement)
      (p : CloseAssetBacking.PublicInputs) (channel : CloseFunding.Channel)
      (plan : CloseFunding.MaterializationPlan) (after : CloseFunding.World)
      (events : List CloseFunding.Event),
      CloseFunding.materializeSignedHead sampleEnvironment sampleWorld sampleManager sampleProof
        = .ok (after, events) ∧
      sampleEnvironment.verifyCompact sampleProof = .ok pi ∧
      CloseFunding.validateBackingPublicInputs sampleEnvironment sampleWorld.storage sampleManager
        pi = .ok st ∧
      CloseAssetBacking.parseTargets pi = some p ∧
      p.channelId = channel ∧ p.settledTxChain.value = st.settledChain ∧
      p.tokenFundsDigest.value = st.tokenFundsDigest ∧
      p.extendedStateCommitment.value = st.backingRoot ∧
      p.anchorBlockNumber = st.anchor ∧
      (∀ c ∈ plan.credits, (sampleEnvironment.manager sampleManager).amountAt c.token
        = .ok c.amount) ∧
      plan.digest ≠ 0 := by
  obtain ⟨after, events, call⟩ := sample_materialization_succeeds
  obtain ⟨pi, st, p, channel, plan, hverify, hvalid, _, _, _, _, _, _, _, hparse, _,
    hchannel, vs, vf, vr, hanchor, _, _, _, _, _, _, _, hamounts, _, hdigest, _⟩ :=
    signed_head_materialization_receipt call
  exact ⟨pi, st, p, channel, plan, after, events, call, hverify, hvalid, hparse, hchannel,
    vs, vf, vr, hanchor, hamounts, hdigest⟩

end Zkp.Implementation.BackingBridge
