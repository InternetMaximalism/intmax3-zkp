# Category G — randomized / property-based generators

The "generate many random fund-loss / liveness / ordering combinations" request. Each generator
RANDOMIZES a dimension space and asserts GLOBAL INVARIANTS over every sample (so a single rule catches
a whole class of bugs). Split by feasible layer:

- **Solidity / Foundry fuzz + invariant testing** (fast, mock-MLE): G36, G40, G41, G42, plus the F-combos.
  Use Foundry's `function testFuzz_*(...)` and `invariant_*` with a handler contract that randomly calls
  the manager's mutators. The mock `MleVerifier` lets you fuzz state-machine/cap/limb logic without proving.
- **Rust + anvil** (heavy, real proofs): G37, G38, G39 — only run a SMALL random sample per CI budget;
  `#[ignore]` + a seed printed for reproduction. Generate the random instance, then drive the live flow.

GLOBAL INVARIANTS (assert in every generator unless stated):
- **I1 solvency**: `totalCreditedOut ≤ receivedChannelFunds ≤ (Σ this channel's real deposits)`, and
  rollup `Σ withdrawNative payouts ≤ totalEscrowed` (no underflow ever succeeds a payout).
- **I2 single-pay**: every nullifier (rollup `withdrawalNullifierUsed`, manager
  `usedWithdrawalNullifiers` / `usedSharedNativeNullifiers`) pays at most once.
- **I3 own-slot**: a member/delegate can only realize its OWN slot amount; padding slots realize nothing.
- **I4 fail-closed**: any forged/mis-ordered/replayed input REVERTS; it never moves funds.
- **I5 status machine**: only the legal transitions occur; `Closed` is absorbing.

---

### G36 — random close-lifecycle action sequences (Foundry invariant)
- **Layer**: Solidity mock + Foundry invariant test.
- **Generator**: a handler randomly calls `{requestClose, submitCloseIntent(random epoch/version),
  cancelClose, finalizeClose, fundBpBondCredits, submitWithdrawalClaim, submitPostCloseClaim,
  pullChannelFunds, claimWithdrawalCredit}` with random callers (member / non-member / stranger) and
  random `vm.warp` jumps around grace/challenge.
- **Assert**: I1, I2, I3, I5 hold after every call; illegal calls revert (I4). No sequence yields
  `totalCreditedOut > receivedChannelFunds` or a status skip.

### G37 — random multi-channel interleavings (heavy)
- **Layer**: Rust+anvil, small N.
- **Generator**: N channels with random deposit amounts on ONE rollup; randomly interleave
  deposit/postBlock/finalize/withdraw/claim across channels (respecting per-channel deposit→post order).
- **Assert**: I1 globally (`Σ receivedChannelFunds ≤ totalEscrowed`), I2 across channels (no nullifier
  reuse), one channel's stuck state never lets another over-withdraw, isolation (D24) holds.

### G38 — random challenge races (epoch/version × arrival time)
- **Layer**: Solidity mock (timestamps) primarily; Rust for real-proof spot checks.
- **Generator**: M candidate states with random `(epoch, version)` submitted at random times relative to
  `challengeDeadline`.
- **Assert**: the finalized state is the MAX `(epoch, version)` among those submitted BEFORE the deadline;
  post-deadline arrivals are ignored; never a lower state than an in-window higher one. Pin the accepted
  fairness boundary (C13).

### G39 — random deposit/block posting orders (heavy, fail-closed)
- **Layer**: Rust+anvil, small N.
- **Generator**: for a fixed proof, randomly permute the on-chain order of `deposit()` and the 3
  `postBlock` rounds (and the registration).
- **Assert**: `finalize` succeeds IFF the on-chain order reproduces the proof's chain; otherwise it
  reverts (I4). NEVER a successful finalize that misbinds funds.

### G40 — random member/delegate configurations
- **Layer**: Solidity mock for the commitment/cap math; Rust+anvil for a few real close→withdraw→claim.
- **Generator**: random `member_count ∈ [2,16]`, `delegate_count ∈ [0, 16-member_count]`, random
  `bp_slot < member_count`, random per-slot balances (incl. 0, dust, near-u32::MAX, sum==fund vs <fund).
- **Assert**: member-set commitment (member-only) + `memberAndDelegateCount` limb match registration;
  each active participant realizes its own balance; padding realizes nothing; I1/I3.

### G41 — amount boundary fuzz
- **Layer**: Solidity mock + Rust.
- **Generator**: deposit/withdraw/claim amounts ∈ {0, 1, fund-1, fund, fund+1, u32 max, values that would
  overflow a sum}.
- **Assert**: over-cap reverts (`WithdrawalCapExceeded`), rollup underflow reverts, 0 is a no-op or
  explicit reject; no silent truncation/overflow.

### G42 — systematic single-limb proof tampering (real-proof negative sweep)
- **Layer**: Solidity (mock for breadth) + a few real-proof cases (depends on A's fixtures).
- **Generator**: for each statement (close 95 / cancel 27 / withdrawal-claim 48 / post-close 56), flip
  ONE public-input limb at a time to: out-of-range (≥2³²), another channel's value, another member's,
  a different H1/accumulator-root/digest.
- **Assert**: every single-limb perturbation reverts with the appropriate `* limb range` / `* limb
  mismatch` / crypto-invalid error (I4). Confirms the strict bind has no gap at any field.

### G43 — random freeze-era cycling then close
- **Layer**: Solidity mock.
- **Generator**: random number of `requestClose`/`cancelClose` cycles, random interleaved member callers,
  then a final close+finalize.
- **Assert**: `currentCloseFreezeNonce` strictly increases per requestClose; a close proved at any stale
  nonce reverts (`InvalidFreezeNonce`); I5; the final close binds the current nonce. (F34 generalized.)

---

### Practical notes for implementing G
- Foundry invariant tests: add a `handler` contract (bounded random actor) + `invariant_*` functions;
  configure `runs`/`depth` in `foundry.toml` modestly (these channels are stateful).
- Rust heavy generators: seed an RNG from a CONSTANT (print it) for reproducibility — do NOT use wall
  clock (the prover pipeline forbids non-deterministic seeds anyway). Keep N small (1–3) given ~minutes
  per real lifecycle; the value is catching a class, not exhaustive coverage.
- Any generator that produces a successful payout violating I1/I2/I3 is a REAL FINDING → stop, capture
  the seed, escalate. Do not relax the invariant.
