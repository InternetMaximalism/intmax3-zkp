import Std

/-!
# Wallet-side durable replay ledger for member channel-state signatures

Source: hosting/wallet/signature-release-ledger.mjs, lines 1–171 (browser JavaScript).

This is a handwritten SEMANTIC MODEL of that file plus kernel-checked theorems
about the model. It is not a refinement proof of the JavaScript, of the browser
IndexedDB implementation, or of the WASM signer that produces the signatures.

What the model covers
- the record shapes (`Decision` = the stored/candidate decision, `LedgerKey` =
  the `[signerPkG, channelId, prevDigest]` key triple),
- `hex32`, `field`, `channelId`, `signatureFor` as executable checks with the
  source's error precedence (`Error` enumerates every message of the file),
- `signatureDecision` exactly: no existing record ⇒ the candidate; otherwise the
  five consistency conditions (schema version, key, signer, channel, predecessor,
  slot), then successor mismatch, then the stored-signature slot check, then the
  EXISTING record is returned (replay of the exact stored bytes),
- `remember` as an abstract durable store with read-decide-add semantics inside
  one strict-durability transaction: nothing is written or released on abort,
  an existing record is never overwritten, and only `strict` durability is accepted,
- `release` for `signState`/`cosign`: identity/result/parse checks, genesis
  requires the zero predecessor, exactly one own signature, slot agreement with
  the request, key construction, the double `signatureDecision` (inside the
  store and again on the returned record), and the textual splice of the stored
  signature into the original wire, modeled abstractly with its uniqueness
  precondition (`Host.occurrences … = 1`),
- `assertUnsignedProposal` for the four unsigned delegate actions with the
  regex on the WASM wire as an opaque predicate.

Named boundaries (explicit premises / opaque callbacks, NOT proved here)
- `Host.stringify` / `Host.parse`: `JSON.stringify` / `JSON.parse` are opaque;
  the wire-alias comparison in `field` uses `stringify` like the source,
  `parse` failure is the only modeled `SyntaxError`.
- `Host.occurrences` / `Host.replaceFirst`: the `indexOf`/`slice` splice is
  abstract; only "exactly one occurrence" is checked, as in the source.
- `Host.wireCarriesMemberSignatures`: the `memberSignatures` regex of
  `assertUnsignedProposal` is an opaque predicate.
- `Backend`: IndexedDB availability, open/upgrade outcome, granted durability
  and commit outcome are premises supplied per call; the model assumes the
  browser honours `durability: 'strict'` when it reports it, that a committed
  transaction is durable, and that `readwrite` transactions on the store are
  serialized (one `remember` = one atomic step).
- Stored records are assumed to have the `Decision` shape; the source reads
  arbitrary IndexedDB rows and only checks the listed fields.
- The JS key string `JSON.stringify([signerPkG, channelId, prevDigest])` is
  modeled by the triple `LedgerKey`; injectivity of that encoding is assumed.
- `Json.number`/`Json.nonInteger` abstract JS numbers (integers vs. any
  non-integer/NaN/Infinity); `Number.isSafeInteger` is subsumed by the range check.

What is NOT covered
- Other devices, other browser profiles, other origins or a different
  `DB_NAME`: each store is a separate `Store`; the ledger cannot see signatures
  released elsewhere.
- Cleared or evicted storage: a `Store` that lost a row behaves as if the
  predecessor was never signed; no theorem survives a store reset.
- The WASM signer, the state-transition / exit-kit checks it performs, and
  Falcon signature validity or randomization: `Json` signature bytes are opaque.
- Delegate usage: unsigned `send`/`refresh`/… proposals never touch the store;
  their wire is only screened by the opaque regex.
- IndexedDB durability itself is a premise (`CommitOutcome.complete` means
  durable), as is the uniqueness of the spliced signature text in the wire.
- Nothing here says a released signature is valid, that the signed state is
  correct, or that the ledger prevents equivocation across stores.
-/

namespace Zkp.Implementation.SignatureReleaseLedger

/-! ## Pinned constants (source lines 4–6, 33, 25, 41, 121, 134) -/

def dbName : String := "intmax-member-signature-ledger-v1"
def storeName : String := "decisions"
def zeroDigest : String := "0x0000000000000000000000000000000000000000000000000000000000000000"
def schemaVersion : Nat := 1
def maxMemberSlot : Nat := 7
def maxChannelId : Nat := 0xffffffff
def signActions : List String := ["signState", "cosign"]
def unsignedProposalActions : List String := ["send", "refresh", "sendInterChannel", "burnSend"]

theorem constants_pinned :
    dbName = "intmax-member-signature-ledger-v1" ∧ storeName = "decisions" ∧
    zeroDigest.length = 66 ∧ schemaVersion = 1 ∧ maxMemberSlot = 7 ∧
    maxChannelId = 4294967295 ∧ signActions.length = 2 ∧ unsignedProposalActions.length = 4 := by
  refine ⟨rfl, rfl, ?_, rfl, rfl, rfl, rfl, rfl⟩
  decide

/-! ## Errors: one constructor per `throw new Error(...)` message of the file -/

inductive Error where
  /-- `signature release requires a valid ${label}` -/
  | invalidHex32 (label : String)
  /-- `signature release refuses conflicting wire aliases` -/
  | conflictingAliases
  /-- `signature release requires an exact channelId` -/
  | inexactChannelId
  /-- `signature release identity/slot is inconsistent` -/
  | identitySlotInconsistent
  /-- `durable member-signature decision is inconsistent` -/
  | decisionInconsistent
  /-- `a different successor of this predecessor was already signed; recover that exact state` -/
  | differentSuccessor
  /-- `durable member-signature slot is inconsistent` -/
  | durableSlotInconsistent
  /-- `durable member signing requires IndexedDB; no signature was released` -/
  | noIndexedDb
  /-- `member signature database could not be opened` -/
  | databaseOpenFailed
  /-- `member signature database upgrade is blocked` -/
  | databaseUpgradeBlocked
  /-- `this browser does not provide strict durable member signing` -/
  | notStrictlyDurable
  /-- `member signature storage failed; no signature was released` -/
  | storageFailed
  /-- `member signature storage aborted; no signature was released` -/
  | storageAborted
  /-- `wallet proposal unexpectedly contains channel-state signatures; ...` -/
  | unsignedProposalCarriesSignatures
  /-- `signed WASM result must retain its exact serialized wire` -/
  | resultNotString
  /-- `JSON.parse` `SyntaxError` (untyped in the source) -/
  | parseFailure
  /-- `genesis signature requires the zero predecessor` -/
  | genesisRequiresZeroPredecessor
  /-- `co-sign result has no member-signature vector` -/
  | noSignatureVector
  /-- `co-sign result must contain exactly one own signature` -/
  | notExactlyOneOwnSignature
  /-- `genesis signature slot differs from the request` -/
  | genesisSlotMismatch
  /-- `signed WASM signature wire is not canonical and unambiguous` -/
  | wireNotCanonical
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except Error α

/-! ## JS values

`Json` is the parsed-JSON fragment of JavaScript values the file touches.
`Option Json` stands for a possibly-`undefined` JS value. Numbers are split into
integers (`number`) and everything `Number.isInteger` rejects (`nonInteger`). -/

inductive Json where
  | null
  | bool (b : Bool)
  | number (n : Int)
  | nonInteger
  | str (s : String)
  | arr (items : List Json)
  | obj (fields : List (String × Json))

/-- Property lookup on an object literal (JS objects have unique keys). -/
def lookupField : List (String × Json) → String → Option Json
  | [], _ => none
  | (k, v) :: rest, name => if k = name then some v else lookupField rest name

/-- `value[name]`: `undefined` for `undefined`/`null`/primitives/arrays. -/
def prop (value : Option Json) (name : String) : Option Json :=
  match value with
  | some (.obj fields) => lookupField fields name
  | _ => none

/-- Host (browser) functions the file calls but whose semantics stay opaque. -/
structure Host where
  /-- `JSON.stringify` -/
  stringify : Json → String
  /-- `JSON.parse`; `none` is a `SyntaxError` -/
  parse : String → Option Json
  /-- number of non-overlapping occurrences found by the `indexOf` scan of
  `result.indexOf(original)` / `result.indexOf(original, start + length)` -/
  occurrences : String → String → Nat
  /-- `result.slice(0, start) + replacement + result.slice(start + original.length)` -/
  replaceFirst : String → String → String → String
  /-- `/"(?:memberSignatures|member_signatures)"\s*:(?!\s*\[\s*\])/.test(result)` -/
  wireCarriesMemberSignatures : String → Bool

/-! ## Validators (source lines 8–37) -/

def isHexDigit (c : Char) : Bool :=
  c.isDigit || ('a' ≤ c && c ≤ 'f') || ('A' ≤ c && c ≤ 'F')

/-- `/^0x[0-9a-fA-F]{64}$/` -/
def isHex32Text (s : String) : Bool :=
  match s.toList with
  | '0' :: 'x' :: rest => rest.length == 64 && rest.all isHexDigit
  | _ => false

/-- `value.toLowerCase()` on an ASCII hex string. -/
def lowercase (s : String) : String := ⟨s.toList.map Char.toLower⟩

/-- `hex32(value, label)`: a string matching the regex, returned lowercased. -/
def hex32 (value : Option Json) (label : String) : Result String :=
  match value with
  | some (.str s) => if isHex32Text s then .ok (lowercase s) else .error (.invalidHex32 label)
  | _ => .error (.invalidHex32 label)

/-- `field(value, camel, snake)`: camel-case wins; both present with different
`JSON.stringify` text is refused; non-objects read as `undefined`. -/
def field (stringify : Json → String) (value : Option Json) (camel snake : String) :
    Result (Option Json) :=
  match value with
  | some (.obj fields) =>
    match lookupField fields camel, lookupField fields snake with
    | some a, some b =>
      if stringify a = stringify b then .ok (some a) else .error .conflictingAliases
    | some a, none => .ok (some a)
    | none, b => .ok b
  | _ => .ok none

/-- `channelId(value)`: a safe integer in `0 ..= 0xffffffff`. -/
def channelIdOf (value : Option Json) : Result Nat :=
  match value with
  | some (.number n) =>
    if 0 ≤ n ∧ n ≤ (maxChannelId : Int) then .ok n.toNat else .error .inexactChannelId
  | _ => .error .inexactChannelId

/-- `signatureFor(signature, signerPkG)`: slot integer in `0 ..= 7`, identity
equal to `signerPkG` (after `hex32`, whose own error escapes), and a non-null
`signature` member. Returns the slot. -/
def signatureFor (stringify : Json → String) (signature : Option Json) (signerPkG : String) :
    Result Nat := do
  let slot ← field stringify signature "memberSlot" "member_slot"
  match slot with
  | some (.number n) =>
    if n < 0 ∨ (maxMemberSlot : Int) < n then throw .identitySlotInconsistent
    let identity ← field stringify signature "pkG" "pk_g"
    let pk ← hex32 identity "signature identity"
    if pk ≠ signerPkG then throw .identitySlotInconsistent
    match prop signature "signature" with
    | none => throw .identitySlotInconsistent
    | some .null => throw .identitySlotInconsistent
    | some _ => pure n.toNat
  | _ => throw .identitySlotInconsistent

/-! ## Records -/

/-- `JSON.stringify([identity, channelId, prevDigest])`, modeled as the triple. -/
structure LedgerKey where
  signerPkG : String
  channelId : Nat
  prevDigest : String
  deriving DecidableEq, Repr

/-- A candidate or stored decision row (`keyPath: 'key'`). -/
structure Decision where
  schemaVersion : Nat
  signerPkG : String
  channelId : Nat
  prevDigest : String
  successorDigest : String
  memberSlot : Nat
  /-- the exact released signature object (slot, pkG, bytes) -/
  signature : Json
  key : LedgerKey

/-- Candidate construction of source lines 151–154. -/
def mkCandidate (identity : String) (channelId : Nat) (prevDigest successorDigest : String)
    (memberSlot : Nat) (signature : Json) : Decision :=
  { schemaVersion := schemaVersion, signerPkG := identity, channelId := channelId,
    prevDigest := prevDigest, successorDigest := successorDigest, memberSlot := memberSlot,
    signature := signature, key := ⟨identity, channelId, prevDigest⟩ }

/-! ## `signatureDecision` (source lines 39–55) -/

def signatureDecision (stringify : Json → String) (candidate : Decision)
    (existing : Option Decision) : Result Decision :=
  match existing with
  | none => .ok candidate
  | some existing =>
    if existing.schemaVersion ≠ schemaVersion ∨ existing.key ≠ candidate.key
        ∨ existing.signerPkG ≠ candidate.signerPkG ∨ existing.channelId ≠ candidate.channelId
        ∨ existing.prevDigest ≠ candidate.prevDigest ∨ existing.memberSlot ≠ candidate.memberSlot then
      .error .decisionInconsistent
    else if existing.successorDigest ≠ candidate.successorDigest then
      .error .differentSuccessor
    else
      match signatureFor stringify (some existing.signature) candidate.signerPkG with
      | .error e => .error e
      | .ok slot =>
        if slot ≠ candidate.memberSlot then .error .durableSlotInconsistent
        -- Falcon signatures may be randomized: replay the stored bytes, never fresh ones.
        else .ok existing

/-! ## Durable store and `remember` (source lines 57–118) -/

/-- The `decisions` object store of one origin/profile, keyed by `key`. -/
def Store := LedgerKey → Option Decision

def emptyStore : Store := fun _ => none

def insert (store : Store) (key : LedgerKey) (decision : Decision) : Store :=
  fun k => if k = key then some decision else store k

inductive OpenOutcome where
  | opened | failed | blocked

inductive Durability where
  | strict | relaxed | default

inductive CommitOutcome where
  | complete | failed | aborted

/-- Per-call browser premises for `open()` and the readwrite transaction. -/
structure Backend where
  /-- `indexedDB` exists with an `open` function on this origin -/
  indexedDbAvailable : Bool
  openOutcome : OpenOutcome
  /-- durability the browser actually granted for `{ durability: 'strict' }` -/
  durability : Durability
  /-- outcome of the transaction after the read/decision/add ran without our abort -/
  commitOutcome : CommitOutcome

def Durability.isStrict : Durability → Bool
  | .strict => true
  | _ => false

/-- `remember(candidate)`: read the row at `candidate.key`, decide, add only when
absent, all inside one strict-durability transaction. Any failure aborts the
transaction: the store is unchanged and nothing is resolved. -/
def remember (backend : Backend) (stringify : Json → String) (store : Store)
    (candidate : Decision) : Result (Decision × Store) := do
  if !backend.indexedDbAvailable then throw .noIndexedDb
  match backend.openOutcome with
  | .failed => throw .databaseOpenFailed
  | .blocked => throw .databaseUpgradeBlocked
  | .opened => pure ()
  if !backend.durability.isStrict then throw .notStrictlyDurable
  let existing := store candidate.key
  let saved ← signatureDecision stringify candidate existing
  match backend.commitOutcome with
  | .failed => throw .storageFailed
  | .aborted => throw .storageAborted
  | .complete =>
    pure (saved, match existing with
      | none => insert store candidate.key saved
      | some _ => store)

/-! ## `assertUnsignedProposal` and `release` (source lines 120–171) -/

/-- The shape of the `input` argument for `signState` (`stateJson`, `slot`). -/
structure SignInput where
  stateJson : Option Json
  slot : Option Json

structure Request where
  action : String
  input : SignInput
  /-- the WASM result (a serialized wire string for signed actions) -/
  result : Option Json
  /-- the session signer identity -/
  signerPkG : Option Json

/-- `assertUnsignedProposal(action, result)`: only the four unsigned delegate
actions are screened; the wire must be a string without a non-empty member
signature vector (opaque regex). -/
def assertUnsignedProposal (host : Host) (action : String) (result : Option Json) : Result Unit :=
  if action ∈ unsignedProposalActions then
    match result with
    | some (.str wire) =>
      if host.wireCarriesMemberSignatures wire then .error .unsignedProposalCarriesSignatures
      else .ok ()
    | _ => .error .unsignedProposalCarriesSignatures
  else .ok ()

/-- `signatures.filter(signature => hex32(field(signature,'pkG','pk_g'), …) === identity)`;
the first invalid element's error escapes, in vector order. -/
def ownSignatures (stringify : Json → String) (identity : String) : List Json → Result (List Json)
  | [] => .ok []
  | signature :: rest => do
    let pkField ← field stringify (some signature) "pkG" "pk_g"
    let pk ← hex32 pkField "signature identity"
    let others ← ownSignatures stringify identity rest
    pure (if pk = identity then signature :: others else others)

/-- `memberSlot !== input.slot` negated: `input.slot` is that exact number. -/
def isNumber (value : Option Json) (n : Nat) : Bool :=
  match value with
  | some (.number m) => m == n
  | _ => false

/-- What `release` has established before calling `backend.remember`. -/
structure Prepared where
  candidate : Decision
  /-- `own[0]`, the signature object as serialized by the WASM signer -/
  own : Json
  /-- the exact serialized wire (`result`) -/
  resultText : String

/-- Source lines 138–154 in order. -/
def buildCandidate (host : Host) (req : Request) : Result Prepared := do
  let identity ← hex32 req.signerPkG "session signer identity"
  let resultText ← match req.result with
    | some (.str s) => pure s
    | _ => throw .resultNotString
  let output ← match host.parse resultText with
    | some j => pure j
    | none => throw .parseFailure
  let state ← if req.action = "signState" then
      match req.input.stateJson with
      | some (.str s) =>
        match host.parse s with
        | some j => pure (some j)
        | none => throw .parseFailure
      | other => pure other
    else pure (some output)
  let prevField ← field host.stringify state "prevDigest" "prev_digest"
  let prevDigest ← hex32 prevField "predecessor digest"
  if req.action = "signState" ∧ prevDigest ≠ zeroDigest then throw .genesisRequiresZeroPredecessor
  let signatures ← if req.action = "signState" then pure (some (.arr [output]))
    else field host.stringify (some output) "memberSignatures" "member_signatures"
  let vector ← match signatures with
    | some (.arr items) => pure items
    | _ => throw .noSignatureVector
  let own ← ownSignatures host.stringify identity vector
  let first ← match own with
    | [only] => pure only
    | _ => throw .notExactlyOneOwnSignature
  let memberSlot ← signatureFor host.stringify (some first) identity
  if req.action = "signState" ∧ !isNumber req.input.slot memberSlot then throw .genesisSlotMismatch
  let channelField ← field host.stringify state "channelId" "channel_id"
  let channel ← channelIdOf channelField
  let successorDigest ← hex32 (prop state "digest") "successor digest"
  pure { candidate := mkCandidate identity channel prevDigest successorDigest memberSlot first,
         own := first, resultText := resultText }

/-- Source lines 158–168: `signState` returns the stored signature's JSON;
`cosign` splices it over the unique occurrence of the fresh signature text. -/
def render (host : Host) (req : Request) (prepared : Prepared) (saved : Decision) : Result Json :=
  if req.action = "signState" then .ok (.str (host.stringify saved.signature))
  else
    let original := host.stringify prepared.own
    if host.occurrences prepared.resultText original ≠ 1 then .error .wireNotCanonical
    else .ok (.str (host.replaceFirst prepared.resultText original (host.stringify saved.signature)))

/-- `release` for `signState`/`cosign` (source lines 138–168), also exposing the
decision record whose signature bytes are returned. The `!persisted` guard of
line 156 cannot fire here: `remember` resolves with a decision record or fails. -/
def releaseSigned (backend : Backend) (host : Host) (store : Store) (req : Request) :
    Result (Decision × Json × Store) := do
  let prepared ← buildCandidate host req
  let remembered ← remember backend host.stringify store prepared.candidate
  let saved ← signatureDecision host.stringify prepared.candidate (some remembered.1)
  let out ← render host req prepared saved
  pure (saved, out, remembered.2)

/-- `createSignatureReleaseGate(backend).release(...)` (source lines 131–171). -/
def release (backend : Backend) (host : Host) (store : Store) (req : Request) :
    Result (Option Json × Store) :=
  if req.action ∈ signActions then
    match releaseSigned backend host store req with
    | .ok r => .ok (some r.2.1, r.2.2)
    | .error e => .error e
  else
    match assertUnsignedProposal host req.action req.result with
    | .ok () => .ok (req.result, store)
    | .error e => .error e

/-- Stores reachable from a store by any sequence of `release` calls (any
backend, host and request per step). -/
inductive Reachable : Store → Store → Prop
  | refl (s : Store) : Reachable s s
  | step {s s' s'' : Store} (backend : Backend) (host : Host) (req : Request) (out : Option Json) :
      release backend host s req = .ok (out, s') → Reachable s' s'' → Reachable s s''

/-! ## Except helpers -/

theorem bind_ok_iff {α β : Type} (r : Result α) (f : α → Result β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem pure_ok_iff {α : Type} (a b : α) : (pure a : Result α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl

theorem throw_ok_iff_false {α : Type} (e : Error) (value : α) :
    ((throw e : Result α) = .ok value) ↔ False := by
  constructor
  · intro h; cases h
  · intro h; exact h.elim

theorem error_ok_iff_false {α : Type} (e : Error) (value : α) :
    ((Except.error e : Result α) = .ok value) ↔ False := by
  constructor
  · intro h; cases h
  · intro h; exact h.elim

/-! ## Validator facts -/

theorem hex32_ok_is_hex (value : Option Json) (label out : String) :
    hex32 value label = .ok out → ∃ s, value = some (.str s) ∧ isHex32Text s = true ∧ out = lowercase s := by
  intro h
  unfold hex32 at h
  split at h
  · rename_i s
    split at h
    · exact ⟨s, rfl, by assumption, (Except.ok.inj h).symm⟩
    · cases h
  · cases h

theorem channel_id_ok_bounded (value : Option Json) (n : Nat) :
    channelIdOf value = .ok n → n ≤ maxChannelId := by
  intro h
  unfold channelIdOf at h
  split at h
  · rename_i m
    split at h
    · rename_i hm
      have := Except.ok.inj h
      subst this
      omega
    · cases h
  · cases h

theorem signature_for_ok_slot_bounded (stringify : Json → String) (signature : Option Json)
    (signerPkG : String) (slot : Nat) :
    signatureFor stringify signature signerPkG = .ok slot → slot ≤ maxMemberSlot := by
  intro h
  simp only [signatureFor, bind_ok_iff] at h
  obtain ⟨slotField, _, h⟩ := h
  split at h
  · rename_i n
    split at h
    · simp only [throw_ok_iff_false, bind_ok_iff, false_and, exists_false] at h
    · rename_i hn
      simp only [bind_ok_iff] at h
      obtain ⟨_, _, _, _, h⟩ := h
      split at h
      · simp only [throw_ok_iff_false, bind_ok_iff, false_and, exists_false] at h
      · split at h
        · cases h
        · cases h
        · have := Except.ok.inj h
          subst this
          omega
  · cases h

/-! ## `signatureDecision` facts -/

theorem signature_decision_no_existing (stringify : Json → String) (candidate : Decision) :
    signatureDecision stringify candidate none = .ok candidate := rfl

/-- With an existing row, success returns THAT row, and the row agrees with the
candidate on schema version, key, signer, channel, predecessor, successor and slot. -/
theorem signature_decision_existing (stringify : Json → String) (candidate existing saved : Decision) :
    signatureDecision stringify candidate (some existing) = .ok saved →
    saved = existing ∧ existing.schemaVersion = schemaVersion ∧ existing.key = candidate.key ∧
    existing.signerPkG = candidate.signerPkG ∧ existing.channelId = candidate.channelId ∧
    existing.prevDigest = candidate.prevDigest ∧ existing.memberSlot = candidate.memberSlot ∧
    existing.successorDigest = candidate.successorDigest := by
  intro h
  unfold signatureDecision at h
  split at h
  · cases h
  · rename_i hconsistent
    split at h
    · cases h
    · rename_i hsucc
      split at h
      · cases h
      · split at h
        · cases h
        · have hs := Except.ok.inj h
          subst hs
          simp only [not_or, Decidable.not_not] at hconsistent hsucc
          exact ⟨rfl, hconsistent.1, hconsistent.2.1, hconsistent.2.2.1, hconsistent.2.2.2.1,
            hconsistent.2.2.2.2.1, hconsistent.2.2.2.2.2, hsucc⟩

/-- A different successor of an already-signed predecessor is always refused. -/
theorem different_successor_rejected (stringify : Json → String) (candidate existing saved : Decision) :
    existing.successorDigest ≠ candidate.successorDigest →
    signatureDecision stringify candidate (some existing) ≠ .ok saved := by
  intro hne h
  exact hne (signature_decision_existing stringify candidate existing saved h).2.2.2.2.2.2.2

theorem signature_decision_key (stringify : Json → String) (candidate : Decision)
    (existing : Option Decision) (saved : Decision) :
    signatureDecision stringify candidate existing = .ok saved →
    saved.key = candidate.key ∧ saved.prevDigest = candidate.prevDigest := by
  intro h
  cases existing with
  | none => rw [signature_decision_no_existing] at h; cases h; exact ⟨rfl, rfl⟩
  | some existing =>
    obtain ⟨hs, _, hk, _, _, hp, _, _⟩ := signature_decision_existing stringify candidate existing saved h
    subst hs
    exact ⟨hk, hp⟩

/-! ## `remember` facts -/

theorem remember_ok (backend : Backend) (stringify : Json → String) (store : Store)
    (candidate saved : Decision) (store' : Store) :
    remember backend stringify store candidate = .ok (saved, store') →
    store' candidate.key = some saved ∧ saved.key = candidate.key ∧
    (∀ k d, store k = some d → store' k = some d) ∧
    (∀ d, store candidate.key = some d → saved = d) := by
  intro h
  simp only [remember, bind_ok_iff] at h
  split at h
  · simp only [throw_ok_iff_false, false_and, exists_false] at h
  · simp only [pure_ok_iff, exists_eq_left] at h
    split at h
    · simp only [throw_ok_iff_false, false_and, exists_false] at h
    · simp only [throw_ok_iff_false, false_and, exists_false] at h
    · simp only [pure_ok_iff, exists_eq_left] at h
      split at h
      · simp only [throw_ok_iff_false, false_and, exists_false] at h
      · simp only [pure_ok_iff, exists_eq_left] at h
        obtain ⟨decided, hdecided, h⟩ := h
        split at h
        · cases h
        · cases h
        · have hpair := Except.ok.inj h
          have hsaved : decided = saved := congrArg Prod.fst hpair
          have hstore : (match store candidate.key with
              | none => insert store candidate.key decided
              | some _ => store) = store' := congrArg Prod.snd hpair
          subst hsaved
          have hkey := signature_decision_key stringify candidate _ decided hdecided
          cases hex : store candidate.key with
          | none =>
            rw [hex] at hstore hdecided
            rw [signature_decision_no_existing] at hdecided
            have hc := Except.ok.inj hdecided
            subst hc
            subst hstore
            refine ⟨?_, rfl, ?_, ?_⟩
            · simp [insert]
            · intro k d hk
              simp only [insert]
              split
              · rename_i hkk; subst hkk; rw [hex] at hk; cases hk
              · exact hk
            · intro d hd; rw [hex] at hd; cases hd
          | some existing =>
            rw [hex] at hstore hdecided
            subst hstore
            obtain ⟨hs, _⟩ := signature_decision_existing stringify candidate existing decided hdecided
            subst hs
            refine ⟨hex, hkey.1, fun _ _ hk => hk, ?_⟩
            intro d hd
            rw [hex] at hd
            exact (Option.some.inj hd).symm

/-- Nothing is written unless strict durability was granted. -/
theorem remember_requires_strict_durability (backend : Backend) (stringify : Json → String)
    (store : Store) (candidate saved : Decision) (store' : Store) :
    remember backend stringify store candidate = .ok (saved, store') →
    backend.durability = .strict ∧ backend.commitOutcome = .complete ∧
    backend.indexedDbAvailable = true ∧ backend.openOutcome = .opened := by
  intro h
  simp only [remember, bind_ok_iff] at h
  split at h
  · simp only [throw_ok_iff_false, false_and, exists_false] at h
  · rename_i havail
    simp only [pure_ok_iff, exists_eq_left] at h
    split at h
    · simp only [throw_ok_iff_false, false_and, exists_false] at h
    · simp only [throw_ok_iff_false, false_and, exists_false] at h
    · rename_i hopen
      simp only [pure_ok_iff, exists_eq_left] at h
      split at h
      · simp only [throw_ok_iff_false, false_and, exists_false] at h
      · rename_i hstrict
        simp only [pure_ok_iff, exists_eq_left] at h
        obtain ⟨_, _, h⟩ := h
        split at h
        · cases h
        · cases h
        · rename_i hcommit
          refine ⟨?_, hcommit, ?_, hopen⟩
          · cases hd : backend.durability <;> simp [hd, Durability.isStrict] at hstrict ⊢
          · cases ha : backend.indexedDbAvailable <;> simp [ha] at havail ⊢

/-! ## `release` facts -/

theorem release_signed_ok (backend : Backend) (host : Host) (store : Store) (req : Request)
    (saved : Decision) (out : Json) (store' : Store) :
    releaseSigned backend host store req = .ok (saved, out, store') →
    ∃ prepared persisted, buildCandidate host req = .ok prepared ∧
      remember backend host.stringify store prepared.candidate = .ok (persisted, store') ∧
      saved = persisted ∧ render host req prepared saved = .ok out := by
  intro h
  simp only [releaseSigned, bind_ok_iff, pure_ok_iff] at h
  obtain ⟨prepared, hprep, ⟨persisted, store''⟩, hrem, decided, hdec, out', hout, hpair⟩ := h
  have h1 : decided = saved := congrArg Prod.fst hpair
  have h2 : out' = out := congrArg (fun p => p.2.1) hpair
  have h3 : store'' = store' := congrArg (fun p => p.2.2) hpair
  subst h1 h2 h3
  obtain ⟨hs, _⟩ := signature_decision_existing host.stringify prepared.candidate persisted decided hdec
  subst hs
  exact ⟨prepared, decided, hprep, hrem, rfl, hout⟩

/-- Theorem (1a): one `release` call never changes or removes a stored decision. -/
theorem release_preserves_stored (backend : Backend) (host : Host) (store : Store) (req : Request)
    (out : Option Json) (store' : Store) (k : LedgerKey) (d : Decision) :
    release backend host store req = .ok (out, store') → store k = some d → store' k = some d := by
  intro h hk
  unfold release at h
  split at h
  · split at h
    · rename_i r hr
      obtain ⟨saved, out', s'⟩ := r
      have hs : s' = store' := congrArg Prod.snd (Except.ok.inj h)
      subst hs
      obtain ⟨_, _, _, hrem, _, _⟩ := release_signed_ok backend host store req saved out' store' hr
      exact (remember_ok _ _ _ _ _ _ hrem).2.2.1 k d hk
    · cases h
  · split at h
    · have hs : store = store' := congrArg Prod.snd (Except.ok.inj h)
      subst hs
      exact hk
    · cases h

/-- Theorem (1): along any sequence of `release` calls on one store, a decision
stored under a key never changes. -/
theorem stored_decision_never_changes (s s' : Store) (k : LedgerKey) (d : Decision) :
    Reachable s s' → s k = some d → s' k = some d := by
  intro hreach
  induction hreach with
  | refl _ => exact id
  | step backend host req out hstep _ ih =>
    intro hk
    exact ih (release_preserves_stored backend host _ req out _ k d hstep hk)

/-- The output of `render` carries exactly the stored decision's signature bytes. -/
def RenderedFrom (host : Host) (saved : Decision) (out : Json) : Prop :=
  out = .str (host.stringify saved.signature) ∨
  ∃ wire original, out = .str (host.replaceFirst wire original (host.stringify saved.signature))

theorem render_ok (host : Host) (req : Request) (prepared : Prepared) (saved : Decision) (out : Json) :
    render host req prepared saved = .ok out → RenderedFrom host saved out := by
  intro h
  unfold render at h
  split at h
  · exact Or.inl (Except.ok.inj h).symm
  · split at h
    · cases h
    · exact Or.inr ⟨_, _, (Except.ok.inj h).symm⟩

/-- Theorem (4): a signed release returns only a signature that is durably
stored (at its own key, in the post-call store) — and it is that record's bytes
that are rendered. -/
theorem release_returns_only_stored (backend : Backend) (host : Host) (store : Store) (req : Request)
    (saved : Decision) (out : Json) (store' : Store) :
    releaseSigned backend host store req = .ok (saved, out, store') →
    store' saved.key = some saved ∧ RenderedFrom host saved out := by
  intro h
  obtain ⟨prepared, persisted, _, hrem, hs, hout⟩ := release_signed_ok backend host store req saved out store' h
  subst hs
  obtain ⟨hstored, hkey, _, _⟩ := remember_ok _ _ _ _ _ _ hrem
  rw [hkey]
  exact ⟨hstored, render_ok host req prepared saved out hout⟩

/-- Theorem (4'): a signed release with a strict-durability failure or any
storage abort releases nothing (no `.ok` value exists). -/
theorem no_release_without_strict_durability (backend : Backend) (host : Host) (store : Store)
    (req : Request) (saved : Decision) (out : Json) (store' : Store) :
    backend.durability ≠ .strict ∨ backend.commitOutcome ≠ .complete →
    releaseSigned backend host store req ≠ .ok (saved, out, store') := by
  intro hbad h
  obtain ⟨_, _, _, hrem, _, _⟩ := release_signed_ok backend host store req saved out store' h
  obtain ⟨hd, hc, _, _⟩ := remember_requires_strict_durability _ _ _ _ _ _ hrem
  cases hbad with
  | inl hne => exact hne hd
  | inr hne => exact hne hc

/-- Theorem (2): two signed releases with the same key on one store lineage
return the same decision — in particular the same successor digest and the same
signature bytes — regardless of the second request's fresh signature. -/
theorem same_key_same_decision (b₁ b₂ : Backend) (h₁ h₂ : Host) (s s₁ s₂ s₃ : Store)
    (req₁ req₂ : Request) (d₁ d₂ : Decision) (out₁ out₂ : Json) :
    releaseSigned b₁ h₁ s req₁ = .ok (d₁, out₁, s₁) →
    Reachable s₁ s₂ →
    releaseSigned b₂ h₂ s₂ req₂ = .ok (d₂, out₂, s₃) →
    d₂.key = d₁.key → d₂ = d₁ := by
  intro hr₁ hreach hr₂ hkey
  have hstored₁ := (release_returns_only_stored b₁ h₁ s req₁ d₁ out₁ s₁ hr₁).1
  have hstored₂ := stored_decision_never_changes s₁ s₂ d₁.key d₁ hreach hstored₁
  obtain ⟨prepared, persisted, _, hrem, hs, _⟩ := release_signed_ok b₂ h₂ s₂ req₂ d₂ out₂ s₃ hr₂
  subst hs
  obtain ⟨_, hk, _, hreplay⟩ := remember_ok _ _ _ _ _ _ hrem
  rw [← hk, hkey] at hreplay
  exact hreplay d₁ hstored₂

theorem same_key_same_successor_and_bytes (b₁ b₂ : Backend) (h₁ h₂ : Host) (s s₁ s₂ s₃ : Store)
    (req₁ req₂ : Request) (d₁ d₂ : Decision) (out₁ out₂ : Json) :
    releaseSigned b₁ h₁ s req₁ = .ok (d₁, out₁, s₁) →
    Reachable s₁ s₂ →
    releaseSigned b₂ h₂ s₂ req₂ = .ok (d₂, out₂, s₃) →
    d₂.key = d₁.key → d₂.successorDigest = d₁.successorDigest ∧ d₂.signature = d₁.signature := by
  intro hr₁ hreach hr₂ hkey
  have := same_key_same_decision b₁ b₂ h₁ h₂ s s₁ s₂ s₃ req₁ req₂ d₁ d₂ out₁ out₂ hr₁ hreach hr₂ hkey
  subst this
  exact ⟨rfl, rfl⟩

/-- `buildCandidate` for `signState` only succeeds with the zero predecessor,
and the candidate carries it. -/
theorem build_candidate_genesis (host : Host) (req : Request) (prepared : Prepared) :
    req.action = "signState" → buildCandidate host req = .ok prepared →
    prepared.candidate.prevDigest = zeroDigest := by
  intro haction h
  simp only [buildCandidate, bind_ok_iff, pure_ok_iff, haction, if_true, true_and] at h
  obtain ⟨identity, _, resultText, hres, output, hout, state, hstate, prevField, _, prevDigest, _, h⟩ := h
  split at h
  · simp only [throw_ok_iff_false, false_and, exists_false] at h
  · rename_i hzero
    simp only [pure_ok_iff, exists_eq_left, bind_ok_iff] at h
    obtain ⟨vector, _, own, _, first, _, memberSlot, _, h⟩ := h
    split at h
    · simp only [throw_ok_iff_false, false_and, exists_false] at h
    · simp only [pure_ok_iff, exists_eq_left, bind_ok_iff] at h
      obtain ⟨_, _, _, _, _, _, hp⟩ := h
      subst hp
      simp only [Decidable.not_not] at hzero
      exact hzero

/-- Theorem (3): a genesis (`signState`) release only ever returns a decision
whose predecessor digest is zero. -/
theorem genesis_release_requires_zero_predecessor (backend : Backend) (host : Host) (store : Store)
    (req : Request) (saved : Decision) (out : Json) (store' : Store) :
    req.action = "signState" →
    releaseSigned backend host store req = .ok (saved, out, store') →
    saved.prevDigest = zeroDigest := by
  intro haction h
  obtain ⟨prepared, persisted, hprep, hrem, hs, _⟩ := release_signed_ok backend host store req saved out store' h
  subst hs
  have hgen := build_candidate_genesis host req prepared haction hprep
  have hrem' := hrem
  simp only [remember, bind_ok_iff] at hrem'
  split at hrem'
  · simp only [throw_ok_iff_false, false_and, exists_false] at hrem'
  · simp only [pure_ok_iff, exists_eq_left] at hrem'
    split at hrem'
    · simp only [throw_ok_iff_false, false_and, exists_false] at hrem'
    · simp only [throw_ok_iff_false, false_and, exists_false] at hrem'
    · simp only [pure_ok_iff, exists_eq_left] at hrem'
      split at hrem'
      · simp only [throw_ok_iff_false, false_and, exists_false] at hrem'
      · simp only [pure_ok_iff, exists_eq_left] at hrem'
        obtain ⟨decided, hdecided, hrem'⟩ := hrem'
        split at hrem'
        · cases hrem'
        · cases hrem'
        · have hd : decided = saved := congrArg Prod.fst (Except.ok.inj hrem')
          subst hd
          rw [(signature_decision_key _ _ _ _ hdecided).2, hgen]

/-! ## Positive trace (theorem 5): first sign, then a retry with fresh randomized bytes -/

def examplePk : String := "0xabababababababababababababababababababababababababababababababab"
def exampleDigest : String := "0x1111111111111111111111111111111111111111111111111111111111111111"

/-- The WASM `MemberSignature` wire: `{ memberSlot, pkG, signature }`. -/
def exampleSignature (byte : Int) : Json :=
  .obj [("memberSlot", .number 3), ("pkG", .str examplePk), ("signature", .arr [.number byte])]

def exampleState : Json :=
  .obj [("channelId", .number 7), ("prevDigest", .str zeroDigest), ("digest", .str exampleDigest)]

/-- A toy host: `parse` maps the two result texts to the two signatures,
`stringify` distinguishes them by their byte. -/
def exampleHost : Host :=
  { stringify := fun j => match j with
      | .obj [_, _, ("signature", .arr [.number 1])] => "SIG-A"
      | .obj [_, _, ("signature", .arr [.number 2])] => "SIG-B"
      | _ => "?",
    parse := fun s => if s = "A" then some (exampleSignature 1)
      else if s = "B" then some (exampleSignature 2) else none,
    occurrences := fun _ _ => 1,
    replaceFirst := fun _ _ r => r,
    wireCarriesMemberSignatures := fun _ => false }

def exampleBackend : Backend :=
  { indexedDbAvailable := true, openOutcome := .opened, durability := .strict, commitOutcome := .complete }

def exampleRequest (resultText : String) : Request :=
  { action := "signState", input := { stateJson := some exampleState, slot := some (.number 3) },
    result := some (.str resultText), signerPkG := some (.str examplePk) }

def exampleKey : LedgerKey := ⟨examplePk, 7, zeroDigest⟩

def exampleDecision : Decision := mkCandidate examplePk 7 zeroDigest exampleDigest 3 (exampleSignature 1)

/-- First signing from an empty store stores the decision and returns bytes A;
the retry (same state, fresh randomized bytes B) is accepted, leaves the store
unchanged, and replays bytes A — even though B would render as `SIG-B`. -/
theorem first_sign_then_retry_replays :
    releaseSigned exampleBackend exampleHost emptyStore (exampleRequest "A")
      = .ok (exampleDecision, .str "SIG-A", insert emptyStore exampleKey exampleDecision) ∧
    releaseSigned exampleBackend exampleHost (insert emptyStore exampleKey exampleDecision) (exampleRequest "B")
      = .ok (exampleDecision, .str "SIG-A", insert emptyStore exampleKey exampleDecision) ∧
    exampleHost.stringify (exampleSignature 2) = "SIG-B" :=
  ⟨rfl, rfl, rfl⟩

/-- Negative companion: after signing successor `exampleDigest`, a retry that
signs a DIFFERENT successor of the same predecessor is refused. -/
def exampleOtherState : Json :=
  .obj [("channelId", .number 7), ("prevDigest", .str zeroDigest),
        ("digest", .str "0x2222222222222222222222222222222222222222222222222222222222222222")]

theorem different_successor_retry_refused :
    releaseSigned exampleBackend exampleHost (insert emptyStore exampleKey exampleDecision)
      { exampleRequest "B" with input := { stateJson := some exampleOtherState, slot := some (.number 3) } }
      = .error .differentSuccessor :=
  rfl

/-- Negative companion: a genesis request whose predecessor is not zero is refused. -/
theorem genesis_nonzero_predecessor_refused :
    releaseSigned exampleBackend exampleHost emptyStore
      { exampleRequest "A" with input := { stateJson := some (.obj [("channelId", .number 7),
          ("prevDigest", .str exampleDigest), ("digest", .str exampleDigest)]), slot := some (.number 3) } }
      = .error .genesisRequiresZeroPredecessor :=
  rfl

/-- Negative companion: without strict durability nothing is released. -/
theorem relaxed_durability_refused :
    releaseSigned { exampleBackend with durability := .relaxed } exampleHost emptyStore (exampleRequest "A")
      = .error .notStrictlyDurable :=
  rfl

end Zkp.Implementation.SignatureReleaseLedger
