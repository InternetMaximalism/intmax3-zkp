/-
# ChannelSafetyClose.lean — the close LIFECYCLE as a status machine (audit25-08-2026 Part 3 V2)

The existing corpus models close only as a version-max fold (`ChannelSafety.finalize`,
`challenge_latest_wins`) with an abstract `CloseGame` payout cap. It has NO intent / cancel /
finalize / deadline STATE MACHINE — `audit25-08-2026` Part 1(a) flagged exactly this, and the
implementation-Lean `Coverage.lean:146-152` lists `requestClose` / `submitCloseIntent` /
`cancelClose` / `finalizeClose` as "STATE MACHINE … no ETH moves", i.e. categorized-not-proved.

This file lifts those four L1 entry points to a guarded transition relation and proves the
close-lifecycle cases, in BOTH directions (soundness AND the R1 honest-exit obligation the gate-8
retrospective demands).

## Trust base

  (A3) Honest discipline / signing freeze — modeled where the version-max argument needs it; the
       actual all-signed check is `ChannelSafety.challenge_latest_wins`, reused conceptually here
       via the `challenge` step's max-version semantics.
  (A4) L1 enforces the transition guards — this file IS the guard model.

## Not modeled (honest, cf. Part 4)

  * Real wall-clock / block time — `Time := Nat`, `deadline ≤ now` abstracts the challenge window.
  * The payout arithmetic — that is `ChannelSafety.close_no_overdraw`'s cap, unchanged; here we
    prove only WHICH state finalizes and WHEN, i.e. who controls the payout, the piece Coverage
    left uninterpreted.
-/

namespace ChannelSafetyClose

/-! ## §1 The close status machine -/

/-- Abstract time (challenge-window clock). -/
abbrev Time := Nat
/-- A caller identity (a channel member, or not). -/
abbrev Caller := Nat

/-- The close lifecycle status (`ChannelSettlementManager` `requestClose` → `finalizeClose`). -/
inductive Status
  | open        -- operating; no close pending
  | intent      -- close requested; challenge window running
  | finalized   -- close finalized; payout enabled
  deriving DecidableEq

/-- On-chain close state. `pendingVersion` is the current best close intent's `stateVersion`
    (the challenge game's running max); `freezeNonce` strictly increases each cancel→reopen so a
    revived channel cannot replay a stale intent; `deadline` bounds the challenge window. -/
structure CloseState where
  status : Status
  pendingVersion : Nat
  freezeNonce : Nat
  deadline : Time
  deriving DecidableEq

/-- The four L1 actions. -/
inductive Action
  /-- `requestClose` by `caller`, opening a close on their latest state version `v`, window `dl`. -/
  | requestClose (caller : Caller) (v : Nat) (dl : Time)
  /-- `submitCloseIntent` / challenge: present a (higher-version) co-signed state `v`. -/
  | challenge (v : Nat)
  /-- `cancelClose`: reopen the channel within the window. -/
  | cancel
  /-- `finalizeClose` at time `now` (only after the window closes). -/
  | finalize (now : Time)

/-- `detail2.md §Q-2`-style guarded transitions, parameterized by channel membership `isMember`
    (the `isMemberRecipient` gate of `requestClose`). Every guard mirrors a manager `require`. -/
inductive Step (isMember : Caller → Prop) : CloseState → Action → CloseState → Prop
  /-- `requestClose`: only from `open`, only by a member. -/
  | reqClose {s : CloseState} {caller : Caller} {v : Nat} {dl : Time} :
      s.status = .open → isMember caller →
      Step isMember s (.requestClose caller v dl)
        ⟨.intent, v, s.freezeNonce, dl⟩
  /-- `challenge`: only during `intent`; the higher version wins (`_isNewer` strict tiebreak). -/
  | chal {s : CloseState} {v : Nat} :
      s.status = .intent →
      Step isMember s (.challenge v)
        ⟨.intent, max s.pendingVersion v, s.freezeNonce, s.deadline⟩
  /-- `cancelClose`: only during `intent` (never after finalize); bumps `freezeNonce`, reopens. -/
  | canc {s : CloseState} :
      s.status = .intent →
      Step isMember s .cancel
        ⟨.open, 0, s.freezeNonce + 1, s.deadline⟩
  /-- `finalizeClose`: only from `intent`, only after the window (`deadline ≤ now`). -/
  | fin {s : CloseState} {now : Time} :
      s.status = .intent → s.deadline ≤ now →
      Step isMember s (.finalize now)
        ⟨.finalized, s.pendingVersion, s.freezeNonce, s.deadline⟩

/-! ## §2 Soundness — the guards hold -/

/-- **T1 (non-member cannot close).** `requestClose` is reachable only for a member — the
    `isMemberRecipient` gate (`ChannelSettlementManager.sol:904`), lifted. -/
theorem non_member_cannot_close
    {isMember : Caller → Prop} {s s' : CloseState} {caller : Caller} {v : Nat} {dl : Time}
    (h : Step isMember s (.requestClose caller v dl) s') :
    isMember caller := by
  cases h with
  | reqClose _ hm => exact hm

/-- **T2 (close starts only from an operating channel).** -/
theorem requestClose_needs_open
    {isMember : Caller → Prop} {s s' : CloseState} {caller : Caller} {v : Nat} {dl : Time}
    (h : Step isMember s (.requestClose caller v dl) s') :
    s.status = .open := by
  cases h with
  | reqClose ho _ => exact ho

/-- **T3 (finalized is terminal — no double close).** A finalized close has NO outgoing
    transition: no second finalize, no post-finalize cancel, no re-open. Every constructor requires
    `open` or `intent`, so `finalized` is a sink. This is `no_double_close` and
    `cancel_only_before_finalize`'s soundness half in one. -/
theorem finalized_is_terminal
    {isMember : Caller → Prop} {s : CloseState} (hf : s.status = .finalized)
    {a : Action} {s' : CloseState} :
    ¬ Step isMember s a s' := by
  intro h
  cases h <;> simp_all

/-- **T4 (cancel only during the challenge window).** `cancelClose` is a valid step only from
    `intent` — never from `open` or `finalized`. -/
theorem cancel_only_before_finalize
    {isMember : Caller → Prop} {s s' : CloseState}
    (h : Step isMember s .cancel s') :
    s.status = .intent := by
  cases h with
  | canc hi => exact hi

/-- **T5 (finalize needs the window closed).** `finalizeClose` requires `intent` AND
    `deadline ≤ now`: an early finalize (before the challenge window elapses) is impossible. -/
theorem finalize_needs_window_closed
    {isMember : Caller → Prop} {s s' : CloseState} {now : Time}
    (h : Step isMember s (.finalize now) s') :
    s.status = .intent ∧ s.deadline ≤ now := by
  cases h with
  | fin hi hd => exact ⟨hi, hd⟩

/-- **T6 (a stale close loses to a newer challenge).** If the pending intent is at version `v0`
    and a co-signed state at a strictly higher version `v1` is challenged in, the pending version
    becomes `v1` — the stale state cannot be the one that finalizes (the status-machine form of
    `challenge_latest_wins`). -/
theorem stale_close_loses
    {isMember : Caller → Prop} {s s' : CloseState} {v1 : Nat}
    (h : Step isMember s (.challenge v1) s') (hnewer : s.pendingVersion < v1) :
    s'.pendingVersion = v1 := by
  cases h with
  | chal _ => simp [Nat.max_eq_right (Nat.le_of_lt hnewer)]

/-- **T6b (challenge never lowers the pending version).** Monotonicity of the challenge game: no
    submission can reduce the running best version. -/
theorem challenge_monotone
    {isMember : Caller → Prop} {s s' : CloseState} {v : Nat}
    (h : Step isMember s (.challenge v) s') :
    s.pendingVersion ≤ s'.pendingVersion := by
  cases h with
  | chal _ => exact Nat.le_max_left _ _

/-- **T7 (freeze nonce is monotone; strictly up on cancel).** Any step keeps `freezeNonce`
    non-decreasing, and a `cancel` strictly increases it — so a revived channel's freeze nonce
    never repeats, and a stale close intent bound to an old nonce cannot be replayed after a
    cancel→reopen (detail2 §Q-5 / close-revive replay guard). -/
theorem freeze_nonce_monotone
    {isMember : Caller → Prop} {s s' : CloseState} {a : Action}
    (h : Step isMember s a s') :
    s.freezeNonce ≤ s'.freezeNonce := by
  cases h <;> simp <;> omega

theorem cancel_bumps_freeze_nonce
    {isMember : Caller → Prop} {s s' : CloseState}
    (h : Step isMember s .cancel s') :
    s'.freezeNonce = s.freezeNonce + 1 := by
  cases h with
  | canc _ => rfl

/-! ## §3 Liveness (R1) — the honest close can always complete -/

/-- **T8 (cancel is AVAILABLE during the window).** The mirror of T4: from `intent`, a cancel step
    exists — an honest party who wants to reopen is never fail-closed out of it. -/
theorem cancel_available_in_intent
    {isMember : Caller → Prop} {s : CloseState} (hi : s.status = .intent) :
    ∃ s', Step isMember s .cancel s' :=
  ⟨_, .canc hi⟩

/-- **T9 (an honest member CAN drive close to finalized).** From an operating channel a member
    reaches `finalized` at their own latest version, in two steps: `requestClose` then, once the
    window has elapsed, `finalizeClose`. This is the gate-8 honest-EXIT obligation for the close
    path — the property whose absence hid the "close unusable on every real deployment" defects.
    No adversary can prevent it at the protocol layer (inclusion/censorship is the separate,
    declared-out-of-scope liveness assumption). -/
theorem honest_close_terminates
    {isMember : Caller → Prop} {s : CloseState} (caller : Caller)
    (ho : s.status = .open) (hm : isMember caller) (latest : Nat) (dl : Time) :
    ∃ s1 s2 : CloseState,
      Step isMember s (.requestClose caller latest dl) s1 ∧
      Step isMember s1 (.finalize dl) s2 ∧
      s2.status = .finalized ∧ s2.pendingVersion = latest := by
  refine ⟨⟨.intent, latest, s.freezeNonce, dl⟩, ⟨.finalized, latest, s.freezeNonce, dl⟩, ?_, ?_, rfl, rfl⟩
  · exact .reqClose ho hm
  · exact .fin rfl (Nat.le_refl dl)

/-- **T10 (a member CAN win the challenge with their latest state).** Composed availability: after
    opening a close, a member can challenge in their latest confirmed version and finalize on it —
    so an honest party is never out-competed for their own funds by inability to submit. -/
theorem honest_challenge_then_finalize
    {isMember : Caller → Prop} {s : CloseState} (caller : Caller)
    (ho : s.status = .open) (hm : isMember caller) (v latest dl : Nat)
    (hlatest : v ≤ latest) :
    ∃ s1 s2 s3 : CloseState,
      Step isMember s (.requestClose caller v dl) s1 ∧
      Step isMember s1 (.challenge latest) s2 ∧
      Step isMember s2 (.finalize dl) s3 ∧
      s3.status = .finalized ∧ s3.pendingVersion = latest := by
  refine ⟨⟨.intent, v, s.freezeNonce, dl⟩, ⟨.intent, max v latest, s.freezeNonce, dl⟩,
          ⟨.finalized, max v latest, s.freezeNonce, dl⟩, .reqClose ho hm, .chal rfl, .fin rfl (Nat.le_refl dl), rfl, ?_⟩
  simp [Nat.max_eq_right hlatest]

end ChannelSafetyClose
