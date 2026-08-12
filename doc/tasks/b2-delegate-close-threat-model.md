# Threat model + design: the B-2 delegate-close fence (close PI limb 94)

Branch: `feat/falcon-poseidon-sig` (HEAD e3a4500). Status: **DESIGN ONLY — no code written, nothing
committed.** Requires owner sign-off on §10 before any implementation.

Related: `doc/tasks/reg-chain-1024-threat-model.md` (Option B decision + the earlier, *claim-side*
"B-2"), `doc/tasks/h1-poseidon-root-threat-model.md` (H1 form, Obligation 3),
`doc/tasks/delegate-account-threat-model.md` (DLG-1/2, DA1..DA6),
`doc/tasks/multitoken-todo.md:644` (the measured fence), `doc/tasks/phase-b-claims-threat-model.md`.

---

## 0. The observed fact (measured, not re-derived)

`channel_member init` joins a browser delegate off-chain, so the live channel state carries
`delegate_count = 1` and the close proof exposes `1` at close-PI limb 94
(`src/circuits/channel/close_pis.rs:94`, `:426-427`). Option B (046a51c) made L1 registration
cosigners-only, so `cmd_export_reg_record` hardcodes `delegate_count = 0`
(`src/bin/channel_member.rs:2119`) and `DeployCloseCli.s.sol:121,149` constructs the Manager with
`activeDelegateCount = 0`. `_runCloseVerify` builds the expected close vector from the Manager's own
immutable (`contracts/src/ChannelSettlementManager.sol:1568`), and `_bindCloseLimbsStrict`
(`contracts/src/ChannelSettlementVerifier.sol:200-215`) demands strict equality on all 103 limbs, so
every live delegate-bearing close is refused at limb 94 with `"close limb mismatch"`. All other 102
limbs match (independently reproduced; pinned as an EXPECTED negative at
`tests/two_token_cli_e2e.rs:452-472`).

Two facts that materially change the framing and were **not** in the problem statement:

1. **The same fence gates the mid-channel partial-withdrawal lane.**
   `submitPartialWithdrawalIntent` calls the identical `_checkCloseProof`
   (`ChannelSettlementManager.sol:1067`), so a post-deploy delegate join also bricks
   `submitPartialWithdrawalIntent`, not just `submitCloseIntent`. (The base-layer `withdraw` lane
   the CLI exercises is a different, chain-based path and is unaffected — that is why "withdraw
   still works".)
2. **The fence is not uniformly in force.** There are two deploy paths with opposite ordering:
   - `DeployCloseCli.s.sol` — deploy **before** `init` ⇒ `activeDelegateCount = 0` always ⇒ fence
     always bites (this is the CLI/E2E path).
   - `DeployWalletSettlement.s.sol` — `cmd_deploy_settlement` runs **after** `init` and writes the
     **live** count (`src/bin/channel_member.rs:3909`, `:3933`; script `:84`, `:110`) ⇒ counts match
     at deploy ⇒ **closes on this path work today**, and keep working until the next delegate joins.

   So the fence blocks exactly "channels whose delegate count moved after manager deployment". It is
   not a coherent security control (§3.5); it is an ordering artifact.

Neither issue is caused by the Falcon migration.

---

## 1. What limb 94 is, end to end

| Layer | Where | Form |
|---|---|---|
| State | `src/common/balance_state.rs:226-241` | `BalanceState.delegate_count: u16`; delegates occupy the contiguous slot region `member_count .. member_count+delegate_count` of the 1024-slot space |
| Commitment | `src/common/balance_state.rs:501-529` (native), `src/circuits/channel/h1_gadget.rs:89-109` (circuit) | element 3 of the fixed 37-element H1 Poseidon header, immediately after `member_count` |
| Signature | `src/common/channel.rs:594` → `wallet_core.rs:822-828` | H1 is a segment of `ChannelState::signing_digest()` (IMCH); every cosigner's Falcon signature covers IMCH ⇒ **`delegate_count` is N-of-N cosigner-authenticated** |
| Close circuit | `src/circuits/channel/close_circuit.rs:161`, `:609-620` | allocated as a 32-bit-range-checked target; its **only** constraint is feeding `recompute_h1`, whose output is `connect`ed to the `final_balance_state_h1` PI. Nothing else. |
| Close PI | `src/circuits/channel/close_pis.rs:48`, `:114-138`, `:183-188` | limb 94 of 103 |
| L1 | `ChannelSettlementVerifier.sol:389`, `:419`; `ChannelSettlementManager.sol:1568` | strict-equality-bound to `(activeMemberCount << 8) | activeDelegateCount` |

**Key structural consequence:** limb 94 is a *decommitment* of a field of the cosigner-signed H1.
Given limbs 17..24 (the H1 itself, which the circuit forces to be the value the N-of-N signatures
cover), limb 94 cannot deviate from the signed value without a Poseidon collision. A prover cannot
choose it freely; only the cosigners can, and only by signing a different state.

---

## 2. What reads `delegate_count` downstream

| Consumer | Location | Uses it for | Effect if larger than truth | Effect if smaller |
|---|---|---|---|---|
| Close circuit | `close_circuit.rs:609-620` | H1 recompute only | none (H1 changes ⇒ signatures must cover it) | none (same) |
| Cancel-close circuit | `cancel_close_circuit.rs:365-376` | private witness → `recompute_h1`; **not a PI** | none | none |
| Withdrawal-claim circuit | `withdrawal_claim_circuit.rs:344-371` | `active = member_count + delegate_count`; enforces `active <= 1024` (11-bit) and `member_index < active` | widens the set of claimable slot indices | narrows it — a real delegate's slot falls outside ⇒ **its claim becomes unprovable** |
| Post-close-claim circuit | `post_close_claim_circuit.rs:428-443` | identical `active` bound on `receiver_member_index` | same | same |
| Registration-chain step | `channel_reg_step.rs:376-393` | genuinely bounds the 16-slot thermometer mask; enforces `member_count + delegate_count <= MAX_COSIGNERS` **in-circuit** | n/a — registration emits 0 under Option B | n/a |
| Native validators | `balance_state.rs:621-630`, `channel.rs:292-301` | `member_count + delegate_count <= MAX_CHANNEL_MEMBERS (1024)` | rejected above 1024 | — |
| Manager (L1) | `ChannelSettlementManager.sol:1568` | the limb-94 equality only | close/partial-withdrawal refused | close/partial-withdrawal refused |

`activeDelegateCount` is read in exactly four places on L1 (`:776` binding-array length, `:787`
presence-marker offset, `:1568` the close bind — `:709` is the constructor cap). **It never reaches a
claim, a payout, or `finalizeClose`.** Nothing on the claim/payout path can distinguish a member slot
from a delegate slot at all: neither `WithdrawalClaim` nor `PostCloseClaim` carries a member-slot
index, and `memberSetCommitment` covers members only
(`ChannelSettlementVerifier.sol:1069-1087`).

**`delegate_count` never determines a payout amount, a slot owner, or a recipient.** Those are
authenticated per-slot and independently: the claim's `recipient` PI is hashed *into* the slot leaf
before the Merkle inclusion check (`withdrawal_claim_circuit.rs:460-477`,
`post_close_claim_circuit.rs:461-467`), the amount is bound by in-circuit Regev decryption against
the leaf-bound pk digest (`withdrawal_claim_circuit.rs:399-412`, `:479-492`), and the nullifier is
keyed on the leaf-bound `pk_digest` + `token_slot` (`:510-520`, fbcf448). Its sole payout-adjacent
effect is the eligibility bound `member_index < member_count + delegate_count`.

---

## 3. What does the limb-94 bind actually protect?

The comment at `ChannelSettlementManager.sol:1526-1531` claims it prevents "member/delegate-boundary
forgery". Worked out concretely:

### 3.1 The signer-set side of the boundary is protected by *other* binds

The close circuit's N-of-N signature loop is gated by `active_bits[i] = i < member_count`
(`close_circuit.rs:498-528`) — `delegate_count` plays no part. `member_count` is bound twice on L1,
independently of limb 94:

- limb 93 strict-equals `activeMemberCount`, and
- `memberSetCommitment` (limbs 85..92) equals `keccak([IMCM, activeMemberCount, memberPkGs[0..15]])`
  — which **includes `activeMemberCount`** (`ChannelSettlementVerifier.sol:1069-1087`) — and that
  commitment is cross-checked against the rollup registry in the constructor
  (`ChannelSettlementManager.sol:752-760`, Finding E).

DA3 ("a member must not be skippable by mislabeling it a delegate") is therefore closed by limbs
85..93, whose authority root is the on-chain registration. **Raising `delegate_count` cannot shrink
the signer set.** Limb 94 adds nothing here.

### 3.2 Larger than truth

An inflated `delegate_count` widens the claim circuits' active region. To convert that into value the
attacker needs a *usable* leaf at an index in the widened region, and that leaf must be inside the
cosigner-signed slot-tree root. Padding leaves are inert:

- their `regev_pk_digest` is zero ⇒ producing the decryption proof requires a Poseidon preimage of
  zero;
- their `recipient` is the zero address ⇒ the credit lands at `withdrawalCredits[t][address(0)]`,
  and `claimWithdrawalCredit` keys on `msg.sender` (`ChannelSettlementManager.sol:1440`), so it is
  unspendable.

A *populated* extra slot requires the cosigners to have signed it — i.e. the same N-of-N signature
that limb 94 is nominally protecting against. Loss is additionally capped per token by
`totalWithdrawn <= finalizedChannelFundAmount` (`:1286-1290`, `:1370-1374`) and hard-capped by
`totalCreditedOut <= receivedChannelFunds` (`:1442-1446`).

### 3.3 Smaller than truth

A deflated `delegate_count` pushes a genuine delegate's slot outside `active`, so its withdrawal
claim becomes unprovable — a targeted freeze-out. Again this requires an N-of-N signature over that
state, and colluding cosigners could equally sign the delegate's balance to zero, which DLG-2
**explicitly accepts** ("the delegate does NOT co-sign state… against fully-colluding members this is
an ACCEPTED risk").

### 3.4 The authority root of the *expected* value is weaker than the thing it checks

The Manager's `activeDelegateCount` is a **deployer-supplied constructor argument cross-checked
against nothing** — the code says so itself (`ChannelSettlementManager.sol:771-774`: *"TRUST:
delegate bindings are deployer-asserted (not re-checked against the registry IMCM, which is
member-only)"*). Contrast with `memberSetCommitment` and `bpPkG`, which are re-derived from
`IChannelRegistry` and revert on mismatch. Under Option B, L1 deliberately has **no** independent
record of the delegate population.

So limb 94 compares a value carrying N-of-N cryptographic authority against a value carrying one
deployer's unverified assertion. A check cannot be more trustworthy than its reference.

### 3.5 It is not even uniformly applied

Per §0, channels deployed via `deploy-settlement` already close with `delegate_count = 1`. The fence
only bites when the count *moves* after deploy. Any claim that it protects a security property must
explain why that property is optional for the wallet path — it cannot.

### 3.6 Verdict

> **Limb 94's strict equality provides no soundness that is not already provided by (i) the N-of-N
> cosigner signature over H1, (ii) limbs 85..93 + the registry cross-check, (iii) the leaf-bound
> recipient / pk_digest / amount bindings in the claim circuits, and (iv) the two aggregate payout
> caps. Its only observable effect is false negatives: it makes the close and partial-withdrawal
> lanes unreachable for exactly the channels the product creates.**

The one property it *does* carry, incidentally, is directional: because `join_delegate` only ever
increments (`src/bin/channel_member.rs:2477`) and there is no leave path, an equality bind also
enforces "no delegate registered on L1 may be excluded from the active region". §6 keeps that as a
one-sided bind rather than discarding it.

---

## 4. Candidate fixes

### (a) Register the true delegate count on L1

**(a1) Deploy after the delegate set is final** (what `deploy-settlement` already does; would mean
reordering the `DeployCloseCli` flow and making `export-reg-record` emit the live count).
*Cost:* freezes the delegate set at deployment. Any later browser join permanently bricks close and
partial withdrawal for that channel — the fence would still fire, just later and less predictably.
Also caps participants at 16 (`ChannelSettlementManager.sol:159`, `:709`) and delegates at 255 (the
`uint8`/`uint16` packing at `:670`, `:712`, `:1568`), against a Rust design space of 1024 slots
(`src/constants.rs:96`) and a `u16` state field. **Rejected as a general fix**; it is, however, the
correct explanation of why one deploy path currently works, and a legitimate *stopgap* if the owner
wants zero contract change (see §10.4).

**(a2) Make `activeDelegateCount` mutable with an authenticated update.** Requires an on-chain
authorization for each join. Options and why each fails:
- verify N Falcon-512 signatures on L1 — Falcon verification plus the Poseidon `pk_g` derivation in
  EVM, per join; not viable on gas or code size;
- a dedicated "delegate-join" ZK proof + a new VK and verify path — a new circuit, a new VK latch, a
  new L1 transaction *per join*, i.e. re-introducing exactly the per-delegate L1 cost Option B was
  adopted to remove (`reg-chain-1024-threat-model.md` §Option A: "118KB calldata + genesis-fixed
  set");
- a permissioned setter (any registered cosigner) — a single cosigner could set a wrong value and
  brick close for everyone: a **new denial-of-service on the safety net**, in exchange for a check
  that still could not exceed the authority of the cosigner signature.
**Rejected.**

### (b) Drop the limb-94 bind (leave limb 94 free)

Security-wise this is sound per §3, and it does **not** require Obligation 3 (§7 — that already
landed). But it breaks the structural invariant the verifier documents and relies on
(`ChannelSettlementVerifier.sol:181`: *"NONE are left free"*): once one limb may be skipped, the
strict loop stops being auditable by inspection, and the next reviewer cannot tell an intentional
hole from a regression. It also throws away the cheap structural sanity bound and the monotone
floor. **Rejected in favour of (d), which is the same security posture with the invariant intact.**

### (c) Bind limb 94 to something else already authenticated on L1

There is no candidate. Under Option B the only L1-authenticated per-channel facts are the ≤16
cosigner `pk_g`s, the bp identity, the IMCM, and — after `finalizeClose` — the finalized H1 and fund
vector. None constrains the delegate population. The delegate bindings that *do* exist are
deployer-asserted (§3.4), i.e. the same non-authority as `activeDelegateCount` itself. **No viable
form.**

### (d) RECOMMENDED — replace equality with an explicit, one-sided **range** bind

Keep all 103 limbs inside the strict loop, and check limb 94 against a *predicate* instead of a
constant, before the loop:

```
floor   : delegateCount >= activeDelegateCount        // monotone: joins only, no leave path
ceiling : activeMemberCount + delegateCount <= MAX_CHANNEL_PARTICIPANTS   // mirror of the
                                                      // in-circuit claim bound (1024)
```

Shape (design, not code):

1. `verifyCloseIntent` asserts `pi.length == CLOSE_PI_LEN` **first**, then reads `dc = pi[94]` and
   range-checks `dc < 2**32` (both currently happen only inside `_bindCloseLimbsStrict`, i.e. too
   late for a pre-loop read).
2. It checks `dc >= fields.minDelegateCount` and `uint256(memberCount) + dc <= MAX_PARTICIPANTS`,
   reverting with a dedicated error (e.g. `CloseDelegateCountOutOfRange`) that is distinguishable
   from `"close limb mismatch"`.
3. `_expectedCloseLimbs` takes the **already-validated** `dc` as an explicit argument and writes it
   at index 94. Limb 93 stays strict-equal to `activeMemberCount` — unchanged, non-negotiable.
4. The strict 103-limb loop runs unchanged over the full vector.
5. `CloseProofFields.memberAndDelegateCount` (`uint16`) is replaced by `uint8 memberCount` +
   `uint32 delegateCount` (or equivalent) so counts above 255 are representable at all; the Manager
   passes `minDelegateCount = activeDelegateCount`.

Why this shape rather than "pass `pi[94]` straight into `expected`": laundering a proof-derived value
into a vector named `expected` is precisely the pattern a future reviewer misreads as a binding. Here
the value is checked by an explicit named predicate first, and the loop's role stays "every limb is
accounted for".

The `SECURITY:` comment at `ChannelSettlementManager.sol:1526-1531` must be rewritten to say what is
true: *the member side of the boundary is L1-rooted (limb 93 + IMCM + registry cross-check); the
delegate side is cosigner-rooted (the signed H1 at limbs 17..24), by the Option B decision; L1
enforces only monotonicity and the structural capacity bound.*

---

## 5. Recommendation

**Option (d).** Security argument in full:

- Limb 94 remains *proof-bound* — the close circuit forces it to equal the `delegate_count` inside
  the H1 that the N-of-N Falcon signatures cover (`close_circuit.rs:609-620`), and the signer set
  producing those signatures is pinned to the registered cosigners by limbs 85..93 + the constructor
  registry cross-check. A prover with no cosigner keys cannot move it by one.
- The only party who can move it is the full cosigner set, which under DLG-2/N-of-N can already
  fabricate any delegate's final balance; the equality bind never protected against that, and its
  reference value has strictly weaker authority than the signature it second-guesses (§3.4).
- What L1 *can* meaningfully assert about the delegate population, it still asserts: the monotone
  floor (no registered delegate may be excluded from the active region) and the structural ceiling
  (mirroring the in-circuit `active <= MAX_CHANNEL_MEMBERS` that the claim circuits enforce).
- No public-input layout change, no circuit change, no VK change, no fixture regeneration (§8) — so
  the change adds no new proof-system surface at all.

**Preconditions that are NOT satisfied by this change alone:** see §9 A-1 and §10.3. The fence today
incidentally suppresses the close→claim lane for post-deploy-join channels; that lane is where the
pre-existing R3 gap (no in-circuit `Σ slot balances <= channel fund`) plus the unbacked delegate join
(`src/bin/channel_member.rs:2489-2505`) become jointly exploitable. That combination is **already
reachable** on the `deploy-settlement` path, so (d) does not create it — but (d) does make it
reachable everywhere, and the owner should decide the ordering explicitly.

---

## 6. Interaction with h1-poseidon "Obligation 3"

`doc/tasks/h1-poseidon-root-threat-model.md:264-270` states the Manager still gates delegate claims
on `registeredRecipientOf` and that "B-2 MUST switch delegate gating to the proof-bound
`claim.recipient` PI".

**That obligation is already discharged and the doc text is stale.** Commit 6d2b9d8 (the *claim-side*
B-2 of `reg-chain-1024-threat-model.md`) removed both gates. On HEAD:

- there is no `RecipientMismatch` error anywhere in `contracts/src/` (it survives only as a Rust
  witness-builder error at `src/circuits/channel/withdrawal_claim_pis.rs:59` and
  `post_close_claim_pis.rs:86`);
- `registeredRecipientOf` and `registeredMemberIndexPlusOne` have **zero runtime reads** — they are
  written in the constructor (`:725`, `:785`, `:726`, `:787`) and read only by the constructor's own
  duplicate check (`:722`, `:782`);
- `submitWithdrawalClaim` (`:1237-1300`) and `submitPostCloseClaim` (`:1304-1385`) gate solely on
  status, digest match, token registry, nullifier replay, the strict claim-limb bind + MLE verify,
  and the accrual cap;
- the recipient is a strict-bound claim PI (withdrawal limbs 25..29 of 50; post-close limbs 25..29
  of 57) and is hashed into the slot leaf in-circuit, so it provably equals the cosigner-signed exit
  address;
- `contracts/test/ChannelSettlementManager.t.sol:1219` (`test_delegate_registered_and_withdraws_after_close`)
  already asserts a delegate collecting 40.

**Therefore the recipient switch is NOT a prerequisite for this change** — it is a completed
predecessor. Two consequential leftovers should ride along with (d):

1. Correct the stale "DEFERRED to B-2" paragraph in `h1-poseidon-root-threat-model.md`.
2. Note the remaining *liveness* asymmetry: a delegate that is not in the constructor's
   `delegateBindings` has no `isMemberRecipient` entry, so it cannot call `requestClose()`
   (`:831`) and cannot be the payee of `submitPartialWithdrawalIntent` (`:1130`). Under Option B a
   post-deploy joiner is never registered, so **every post-deploy delegate depends on a cosigner to
   initiate the close it then claims against**. That is consistent with DLG-3 ("censorship/liveness:
   OUT OF SCOPE"), but it should be restated as a conscious consequence rather than rediscovered.

---

## 7. Does the close PI layout or any VK change?

**No, and it must not.** The 103-limb layout is load-bearing across
`src/circuits/channel/close_pis.rs:48` (`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`), the in-circuit
`to_vec`/`from_slice` (`close_circuit.rs:185-187`, `:238-241`), the pinning tests
(`close_pis.rs:403`, `:426-427`, `close_circuit.rs:1756`), the fixture generator
(`src/bin/generate_close_fixture.rs`), and `CLOSE_PI_LEN = 103`
(`ChannelSettlementVerifier.sol:53`). Option (d) touches none of them: it changes only *how L1
decides whether limb 94 is acceptable*. The close/cancel/claim circuits, their VKs, and every baked
fixture are untouched. `_closeIntentDigest` does **not** include the counts
(`ChannelSettlementVerifier.sol:461-490`), so the IMCI recompute is unaffected.

---

## 8. Blast radius

**Solidity (`contracts/src/`)**
- `ChannelSettlementVerifier.sol` — `verifyCloseIntent` (`:188-195`): length + canonicality check
  hoisted, the new range predicate, new error; `_expectedCloseLimbs` (`:391-429`) gains the
  validated `dc` parameter; layout doc at `:181` and `:389` updated. `_bindCloseLimbsStrict` itself
  **unchanged**.
- `ChannelSettlementManager.sol` — the `CloseProofFields` struct (`:12-44`, field at `:37-38`)
  widens; `_runCloseVerify` (`:1537-1570`) passes `minDelegateCount = activeDelegateCount`; the
  `SECURITY:` comment at `:1526-1531` rewritten. Optionally the constructor capacity check at
  `:709-711` / `MAX_MEMBER_COUNT` at `:159` is split into a cosigner cap (16) and a participant cap
  (1024) — **name this as separate scope** (§10.4).
- ABI note: `IChannelSettlementVerifier.verifyCloseIntent`'s struct changes ⇒ Manager and Verifier
  must be **deployed as a pair**; no existing deployment can be half-upgraded.
- Both `submitCloseIntent` (`:851`) and `submitPartialWithdrawalIntent` (`:1067`) are fixed by the
  single `_checkCloseProof` change — no separate work, but both need tests.

**Solidity (tests / scripts)** — all construct `CloseProofFields` directly and must be updated for
the field change: `contracts/test/CloseSettlementBase.sol:290`, `:300`;
`contracts/test/ChannelSettlementManager.t.sol:419`, `:703-704` (asserts `v[94] == 1`), `:1538`,
`:1696`; `contracts/test/CloseE2EBase.sol:102-103`; `contracts/script/SubmitPartialWithdrawal.s.sol:76`.
Deploy scripts (`DeployCloseCli.s.sol:121-152`, `DeployWalletSettlement.s.sol:84-113`,
`DeployPartialWithdrawalE2E.s.sol:103-121`) need no semantic change but should get a comment that
`delegateCount` is now a **floor**, not an exact count.

**Rust** — no circuit, no PI, no witness change. Only test/E2E expectations:
`tests/two_token_cli_e2e.rs:452-472` flips from a pinned expected-negative to a positive close;
`tests/close_lifecycle_cli_e2e.rs` close section likewise. `cmd_export_reg_record`
(`src/bin/channel_member.rs:2108-2154`) can stay at `delegate_count = 0` — that becomes correct
rather than merely tolerated. The fence comment at `src/bin/channel_member.rs:1712-1716` is retired.

**Fixtures / VKs** — none. This is the main reason to prefer (d) over anything touching the circuit.

**New tests required (falsifiable):**
1. positive: `delegateCount` strictly greater than the registered count ⇒ close accepted (the live
   case);
2. negative: `delegateCount < activeDelegateCount` ⇒ `CloseDelegateCountOutOfRange` (floor);
3. negative: `activeMemberCount + delegateCount > MAX_PARTICIPANTS` ⇒ same error (ceiling);
4. negative: limb 93 tampered ⇒ still `"close limb mismatch"` (proves the member bind was not
   collaterally loosened);
5. negative: `pi.length != 103` and a non-canonical `pi[94] >= 2**32` ⇒ revert **before** any
   arithmetic on `pi[94]` (ordering regression guard);
6. the same matrix through `submitPartialWithdrawalIntent`, not only `submitCloseIntent`;
7. an E2E in which a delegate joins **after** manager deployment and the channel then closes and the
   delegate claims — the exact scenario the fence blocks today.

---

## 9. Adversarial pass

Taking the attacker's side against option (d). Reported regardless of confidence, per CLAUDE.md §2.

- **A-1 (MAJOR, pre-existing, must be an owner decision).** `join_delegate`
  (`src/bin/channel_member.rs:2430-2512`) inserts a slot whose Regev ciphertext is supplied by the
  joiner (`:2489-2492`), sets its recipient, bumps `delegate_count`, and has the cosigners re-sign
  with plain `sign_state` — explicitly **not** `sign_state_if_backed` (`:2501-2505`). The
  contribution is encrypted, so the cosigners cannot see the amount they attest to, and no layer
  binds `Σ slot balances <= channel fund` (R3, `reg-chain-1024-threat-model.md:231-238`, CONFIRMED
  and owner-flagged). Combined: a joining party can self-declare an inflated balance and, once the
  channel closes, claim against the real pot ahead of honest participants. Bounds: per-token
  `finalizedChannelFundAmount` and the hard `receivedChannelFunds` ETH ceiling — so this is
  *misallocation of the real pot*, never minting beyond it.
  **Relevance to (d):** the fence currently suppresses this lane for post-deploy-join channels. It
  does **not** suppress it on the `deploy-settlement` path, where it is reachable today. (d)
  therefore does not create the exposure, but it removes the accidental partial suppression.
  ⇒ Owner decision §10.3. My view: this is a real widening of *who* can trigger R3 — from "all N
  cosigners collude" to "any browser stranger whose join the auto-cosigning relay signs" — and it
  deserves its own control (a contribution-backing check at join, or an in-circuit conservation
  bind), tracked independently of B-2.
- **A-2.** Delegate-count deflation freezing out a delegate registered on L1 — closed by the monotone
  floor. Post-deploy joiners have no L1 registration, so they are *not* covered by the floor;
  freezing them out remains possible for colluding cosigners. Inherent to Option B + DLG-2; not
  closable on L1 without re-introducing per-join registration.
- **A-3.** Delegate-count inflation to open extra claimable slot indices — inert against padding
  leaves (zero `regev_pk_digest` ⇒ no decryption proof; zero recipient ⇒ credit lands at
  `address(0)`, unspendable since `claimWithdrawalCredit` keys on `msg.sender`). Populating a real
  extra slot needs cosigner signatures, i.e. A-1's lane, not a new one.
- **A-4 (implementation hazard).** Reading `pi[94]` before `require(pi.length == CLOSE_PI_LEN)` is an
  out-of-bounds read on a short calldata array. The current code checks the length *inside*
  `_bindCloseLimbsStrict`, which now runs *after* the new predicate. The length and `< 2**32`
  canonicality checks MUST be hoisted. Test 5 in §8 locks this.
- **A-5 (implementation hazard).** Arithmetic on an unchecked `pi[94]` (up to `2**256-1` if the
  canonicality check is skipped) in `activeMemberCount + dc` would wrap only in unchecked blocks;
  Solidity 0.8 reverts, but the failure mode should be the explicit error, not a panic. Range-check
  first.
- **A-6 (invariant to never relax).** Limb 93 must stay strict-equality. If a future "simplification"
  gave `memberCount` the same pass-through treatment, a state with a smaller `member_count` would
  close under fewer than N signatures. (`memberSetCommitment` would still catch it today, because
  IMCM hashes `activeMemberCount` — but that is a second line, not the first.) The new code must say
  so at the site.
- **A-7 (NARROWED — review finding 5).** The original claim ("no cross-path interaction") was too
  strong and is **withdrawn**. What still holds: `verifyCancelClose`
  (`ChannelSettlementVerifier.sol:939-959`) binds 27 limbs with no counts, and
  `revived_delegate_count` (`src/circuits/channel/cancel_close_circuit.rs:280`) is not a cancel-close
  PI. What does NOT hold: it is a **free 32-bit witness**, range-checked and then constrained only
  through `recompute_h1` — i.e. only against the revived H1 the cosigners signed. Once a FLOOR exists
  on the close path, that creates a one-way interaction: a revive that installs a **smaller**
  delegate count than the Manager's `activeDelegateCount` makes **every subsequent close** of that
  channel fail the floor **permanently** — stuck funds, not a one-off rejection, because there is no
  path that raises the count back on L1 and no path that lowers `activeDelegateCount`.
  Preconditions: it needs the N-of-N cosigner signature over the revived state (the same collusion
  that DLG-2 already accepts), so it is not a new unilateral capability — but it converts a
  *cosigner-can-sign-a-bad-balance* problem into a *cosigner-can-brick-the-close-path* problem, which
  is a different severity class. **Filed with A-12** (delegate_count monotonicity): the native
  assertion recommended there should cover the revive path, not just `join_delegate`, and the same
  emergent-monotonicity caveat applies.
- **A-8.** Cross-channel / cross-circuit replay unchanged: limb 0 (`channelId`) stays strict, and
  `MleVerifier.verify` still binds the close VK's `gatesDigest`.
- **A-9 (griefing).** The range bind cannot be used to grief: the ceiling only rejects states the
  claim circuits could not serve anyway, and the floor only rejects states that exclude an
  L1-registered delegate.
- **A-10 (representation, currently a hard blocker for the 1024 goal).** `delegateCount_` is `uint8`
  (`ChannelSettlementManager.sol:670`, `:712`) packed into a `uint16`
  (`:1568`), while Rust carries `u16` over a 1024-slot space; and the constructor caps
  members+delegates at 16 (`:159`, `:709`). A channel with 14+ delegates cannot even deploy a
  Manager. (d) fixes the close-path representation; the constructor cap is separate scope (§10.4).
- **A-11 (VK-window, pre-existing, unchanged by (d)).** Nothing binds a Manager's construction to
  its Verifier's VKs already being latched; a Manager can exist against an un-initialized or (if the
  Verifier deployer key were compromised before latching) attacker-chosen VK
  (`ChannelSettlementVerifier.sol:117`, `:137`, `:155`, `:570`, `:599`, `:628`). Since B-2 (claims)
  the entire claim-side authorization rests on the strict limb bind + VK, so this deploy-window race
  is now the single highest-leverage off-protocol lever in the subsystem. Out of scope here; worth
  its own item.
- **A-12 (consistency gap found in passing).** `ChannelRecord.delegate_count` and
  `BalanceState.delegate_count` are copied together only at genesis (`wallet_core.rs:785-786`) and
  never cross-checked afterwards; `verify_snapshot` derives `active` from the record while the claim
  PI builders derive it from the balance state. Also, no transition verifier checks `delegate_count`
  monotonicity — it holds only *emergently*, via `recipients` immutability plus the
  nonzero-active/zero-padding recipient rule in `BalanceState::validate()`
  (`balance_state.rs:683-696`). The §6 floor leans on that emergent property. If either rule is ever
  relaxed, the floor's justification evaporates. Recommend an explicit native assertion; note it as
  a follow-up, not a blocker.
  **Scope extension (review finding 5):** the recommended assertion must also cover the CANCEL-CLOSE
  REVIVE path, where `revived_delegate_count` is a free witness constrained only through
  `recompute_h1` (see A-7 above). A revive that lowers the count permanently bricks every subsequent
  close against the Manager's floor. The assertion wanted is `new.delegate_count >=
  prev.delegate_count` on every native state transition INCLUDING revive — not only in
  `join_delegate`.
  **Scope note (review finding 6):** the floor is a CARDINALITY bound. L1 binds no delegate to a
  balance-slot INDEX, so the floor cannot deliver "no registered delegate may be EXCLUDED" — only
  "the active region was not shrunk below the registered count". The wording has been corrected at
  all four sites (`ChannelSettlementVerifier.sol` error doc + floor comment,
  `ChannelSettlementManager.sol` `activeDelegateCount` doc + `_checkCloseProof` + `_runCloseVerify`,
  `DeployCloseCli.s.sol`). No logic changed and no regression: the pre-B-2 strict equality had the
  same property.

No attack was found that option (d) enables and that the current equality bind actually prevents.
The residual exposures (A-1, A-2, A-12) are pre-existing, previously documented, and rooted in the
Option B / DLG-2 trust model rather than in this change.

---

## 10. Owner decisions (do not decide these silently)

1. **Trust-model statement.** Accept, in writing, that the member/delegate boundary's authority on
   L1 is the cosigner-signed H1 and not an L1 record — i.e. L1 enforces monotonicity and capacity
   only. This is the direct consequence of the 2026-07-03 Option B decision; B-2 merely makes the
   close path consistent with it. *Owner's call because it changes what the deployed contract
   claims to enforce.*
2. **Keep or drop the monotone floor.** Keeping `delegateCount >= activeDelegateCount` presumes
   delegates never leave (true today, emergent per A-12). If a delegate-exit path is ever added, the
   floor must be revisited or every close of a shrunken channel bricks — the same class of bug as
   the one being fixed. Alternative: no floor, ceiling only (simpler, one less latent brick).
3. **Ordering vs. A-1.** Ship (d) before, or only after, a control for the unbacked-contribution /
   R3 lane. Trade-off: shipping first restores close+partial-withdrawal for every channel (the
   product is currently unusable at close) but generalizes an exposure that today exists on one of
   two deploy paths; shipping second keeps the product blocked for longer. **This is a security-vs-
   availability trade-off and is explicitly the owner's.**
4. **Scope of the capacity widening (A-10).** Splitting the on-chain cosigner cap (16) from the
   participant cap (1024) and widening the count fields is required for the 1000-delegate goal but
   is not required to unblock today's 1-delegate channels. In or out of this change?

---

## 11. What this design does NOT fix

- R3 (no in-circuit `Σ slot balances <= channel fund`) — unchanged, still owner-flagged.
- DLG-2 (colluding cosigners can forge a delegate's final balance) — unchanged, accepted.
- DLG-3 (delegates cannot initiate `requestClose`, and post-deploy delegates are not
  `isMemberRecipient`) — unchanged; §6.2 restates it.
- The `join_delegate` path's absence of transition verification (h1 threat model Obligation 2) —
  unchanged.
- The Verifier VK deploy-window race (A-11) — unchanged.
