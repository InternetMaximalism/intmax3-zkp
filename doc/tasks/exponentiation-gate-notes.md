# ExponentiationGate support in the on-chain Plonky2 gate evaluator

Status: implemented + validated (see §4). **Not committed** — the change touches a
pinned submodule, see §6.

## 1. Why

`@mle/Plonky2GateEvaluator.sol` reverted with `"unsupported gate with non-zero
filter"` for gate id 8 (`ExponentiationGate`). The withdrawal-claim circuit
legitimately contains one (`num_power_bits: 66`) because plonky2's recursive FRI
verifier calls `exp_power_of_2` / `exp_from_bits_const_base`
(`contracts/lib/polygon-plonky2/plonky2/src/fri/recursive_verifier.rs:416,474,547,621`).

Consequence before this change: `submitWithdrawalClaim` could never be verified on
L1. The close-intent circuit happens not to emit the gate, which is why close
verified and claims did not. This was a **gap in the evaluator, not a bug in the
circuits** — the claim circuit was not touched.

Fixtures carrying the gate:
`contracts/test/data/withdrawal_claim_mle.json`,
`contracts/test/data/post_close_claim_mle.json` —
both `{"gateId": 8, "numOrConsts": 66, "numConstraints": 67, ...}`.

## 2. Files changed

| File | Change |
| --- | --- |
| `contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol` | new `_evalExponentiation`, dispatcher branch for `GATE_EXPONENTIATION`, header doc moved gate 8 from UNSUPPORTED to SUPPORTED |
| `contracts/test/ExponentiationGate.t.sol` | new — 13 tests |
| `contracts/test/ExponentiationGateVectors.sol` | new — generated reference vectors (values produced by plonky2's own `eval_unfiltered`) |
| `contracts/test/data/close_withdrawal_payout.json`, `close_withdrawal_mle.json` | regenerated — see §5 (address drift, not a logic change) |

No change to `fixture.rs`: `classify_gate` already mapped
`ExponentiationGate { num_power_bits: N }` → `(8, N, 0, 0)`
(`contracts/lib/polygon-plonky2/mle/src/fixture.rs:480-482`), so
`GateInfo.numOrConsts` already carries `num_power_bits`. Nothing on the Rust side
needed touching.

## 3. The constraint set mirrored

Rust source of truth:
`contracts/lib/polygon-plonky2/plonky2/src/gates/exponentiation.rs`.
All three evaluators there compute the identical set and were cross-read:

* `eval_unfiltered` — `:94-127` (the one mirrored)
* `eval_unfiltered_base_packed` — `:210-243`
* `eval_unfiltered_circuit` — `:141-180`

### Wire layout (`:60-78`), with `n = num_power_bits`

```
wire_base()                = 0            (:60-62)
wire_power_bit(i)          = 1 + i        (:65-68)   i < n, LITTLE-endian
wire_output()              = 1 + n        (:70-72)
wire_intermediate_value(i) = 2 + n + i    (:74-77)   i < n
```

`num_wires() = 2·n + 2` (`:190-192`), `num_constants() = 0` (`:194-196`),
`num_constraints() = n + 1` (`:202-204`), `degree() = 4` (`:198-200`).

Because `num_constants() == 0`, the dispatcher's `wires` slice is the gate's full
`local_wires` with no offset (same situation as `CosetInterpolationGate`).

### Constraints, in the order `eval_unfiltered` pushes them

```
for i in 0..n:                                                    (:108-122)
    prev_i   = (i == 0) ? 1 : intermediate_values[i-1]^2           (:109-113)
    cur_bit  = power_bits[n - i - 1]   // LE wires, BE accumulation (:116)
    computed = prev_i * (cur_bit * base + (1 - cur_bit))            (:118-120)
    C[i]     = computed - intermediate_values[i]                    (:121)
C[n] = output - intermediate_values[n-1]                            (:124)
```

Each `C[i]` is accumulated as `acc[i] += filter · C[i]`, matching
`evaluate_gate_constraints`' `constraints[i] += c` and the pattern every other
gate in the file uses.

### Points that are easy to get wrong, and were checked explicitly

1. **The LE→BE index flip** (`:116`). Wires hold the exponent bits
   little-endian; the ladder consumes them most-significant first. So
   constraint `i` reads wire `1 + (n - i - 1) = n - i`, not wire `1 + i`.
   Test `test_unsatisfyingIndices` plus the varied-bit `n = 66` vector would
   both fail if this were mirrored straight.
2. **`prev` is the squared WIRE value, not the squared computed value**
   (`:112` reads `intermediate_values[i-1]`, not the previous `computed`).
   Using `computed` would still make honest witnesses pass while silently
   dropping the link between rounds — a soundness break. Vectors V2/V6
   (corrupted `intermediate_values[k]`) pin this: they must break constraint
   `k` **and** constraint `k+1`.
3. **There is NO booleanity constraint on `power_bits`.** The gate does not
   constrain `bit ∈ {0,1}`; plonky2 feeds it already-boolean `BoolTarget`s
   (`exp_from_bits`) or hard-wired constants (`exp_power_of_2`). Adding the
   check on-chain would REJECT honest proofs, because the prover's quotient
   polynomial does not contain it — a completeness break at the L1 boundary.
   Mirroring Rust exactly is the only safe option; vector V4 (non-boolean
   bits, satisfying) locks this behaviour in so a later "hardening" PR cannot
   add the constraint without a red test.
4. **`n = 0` is not representable**: `eval_unfiltered` indexes
   `intermediate_values[n - 1]` unconditionally (`:124`), so Rust would panic.
   Solidity rejects it up front rather than underflowing.

### Security properties preserved

* The `revert("unsupported gate with non-zero filter")` fail-closed branch is
  **unchanged**. Only gate id 8 moved out of it; `255` (fixture.rs's
  "unsupported" classifier) and lookup gates still revert.
  Regression-tested by `test_dispatcher_stillRevertsOnUnsupportedGate`.
* C2 non-canonical-wire defence: every prover-supplied wire is `mod(_, p)`
  self-reduced before any `sub(p, ·)`, matching `_evalConstant`'s
  `phase3_c2_threat_model.md §6.2` note. Tested by
  `test_nonCanonicalWiresReduceToSameResult`.
* Fail-closed bounds: Yul `mload`s bypass Solidity bounds checks, so
  `wires.length >= 2n + 2` and `acc.length >= n + 1` are validated before the
  assembly block. A forged `GateInfo.numOrConsts` therefore reverts instead of
  reading adjacent memory (which could otherwise let a malformed descriptor
  fabricate a satisfied constraint set). Tested by `test_revert_wiresTooShort`
  / `test_revert_accTooShort`.

## 4. Validation evidence

### 4.1 Reference vectors come from Rust, not from re-derivation

`contracts/test/ExponentiationGateVectors.sol` is generated. The `expected`
arrays are the output of plonky2's own `Gate::eval_unfiltered` — the generator
links the pinned submodule, lifts each base-field wire into
`QuadraticExtension<Goldilocks>`, calls `eval_unfiltered`, asserts the `c1`
component is zero (it must be: every wire is a lifted base-field value) and
prints `c0`. The generator is a throw-away crate kept OUT of the repo (in the
session scratchpad, `expgate/`); it is a ~130-line `main.rs` whose only
dependency is `path = contracts/lib/polygon-plonky2/plonky2`. To rebuild it:
create a bin crate with that path dependency, pin `serde_with = 3.17.0` /
`darling = 0.21.3` for the `nightly-2025-03-23` MSRV, and call
`ExponentiationGate::<GoldilocksField, 2>::new(n).eval_unfiltered(vars)`.

The wire vectors themselves are built from the constraint recurrence, so they
are also valid for non-boolean bits (V4), which the honest
`ExponentiationGenerator` cannot produce.

### 4.2 Test matrix — `contracts/test/ExponentiationGate.t.sol`, 13/13 pass

| Vector | Shape | Expected |
| --- | --- | --- |
| V1 | `n=5`, base 2, power 13 (output pinned to `2^13 = 8192`) | all 6 constraints zero |
| V2 | V1 with `intermediate_values[2] += 1` | exactly slots 2 and 3 non-zero |
| V3 | V1 with `output += 1` | exactly slot 5 (the final one) non-zero |
| V4 | `n=4`, NON-boolean bits `{3,0,1,7}`, random base | all 5 constraints zero |
| V5 | `n=66` (the real fixture parameter), random base, random bits | all 67 constraints zero |
| V6 | V5 with `intermediate_values[40] += 7` | exactly slots 40 and 41 non-zero |
| V7 | `n=1` boundary | all 2 constraints zero |

Every test compares **bit-exactly** against the Rust values, not merely
zero/non-zero.

Test list:

```
[PASS] test_bitExactMatch_filterOne                    all 7 vectors, slot by slot
[PASS] test_satisfyingIsZero_unsatisfyingIsNonZero     non-zero counts 0/2/1/0/0/2/0
[PASS] test_unsatisfyingIndices                        pins WHICH slots break
[PASS] test_filterZero_contributesNothing              filter = 0 ⇒ acc untouched
[PASS] test_filterScalesLinearly                       acc[k] == f · expected[k]
[PASS] test_accumulatesRatherThanOverwrites            `+=`, not `=`
[PASS] test_nonCanonicalWiresReduceToSameResult        w + P ≡ w
[PASS] test_revert_zeroPowerBits
[PASS] test_revert_wiresTooShort
[PASS] test_revert_accTooShort
[PASS] test_dispatcher_satisfyingFlattensToZero        gate id 8 no longer reverts
[PASS] test_dispatcher_unsatisfyingFlattensNonZero
[PASS] test_dispatcher_stillRevertsOnUnsupportedGate   fail-closed branch intact
```

The last three go through the real `evalCombinedFlat` dispatcher (one selector
group, singleton ⇒ `filter = 1`), i.e. they exercise the exact code path that
used to revert.

### 4.3 Full Foundry suite

`cd contracts && forge test` — see §7 for the recorded result.

### 4.4 End-to-end proof

`cargo test --release --test close_lifecycle_cli_e2e -- --ignored --nocapture`
— see §7.

## 5. Fixture regeneration (expected side effect, NOT a logic change)

`contracts/test/CloseLifecycleE2E.t.sol` deploys the whole close stack through the
canonical CREATE2 factory. `MleVerifier`'s initcode embeds the linked
`Plonky2GateEvaluator` library address, which Foundry derives from the library
bytecode. **Any** edit to the evaluator therefore shifts the predicted
`ChannelSettlementManager` address, and the close withdrawal payout fixture bakes
that address as the L1 recipient. The test's own guard fires:

```
manager CREATE2 address != close payout fixture recipient (stale fixtures -- regenerate)
```

This is the documented regeneration flow (`CloseLifecycleE2E.t.sol:138-145`):

```
cd contracts && forge test --match-test test_printCloseManagerAddress -vv   # → CLOSE_MANAGER_ADDRESS
WD_RECIPIENT=<addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture
```

Confirmed pre-existing-vs-caused: with `Plonky2GateEvaluator.sol` reverted and the
two new test files removed, `CloseLifecycleE2E` passes; with the evaluator change
applied it fails on the address guard only. No other test is affected.

## 6. Submodule / upstream implications — READ BEFORE COMMITTING

`contracts/lib/polygon-plonky2` is a **pinned dependency**, referenced by Cargo
`[patch]` (`Cargo.toml:249-256`) and by the Foundry remapping
`@mle/=lib/polygon-plonky2/mle/contracts/src/`. The edited file lives inside it:

```
contracts/lib/polygon-plonky2/mle/contracts/src/Plonky2GateEvaluator.sol
```

Submodule HEAD at the time of the change: `2a1f5028`
("mle: externalize evalCombinedFlat + verifyWhirProof to fit EIP-170").
The working tree of the submodule is otherwise clean, so `git -C
contracts/lib/polygon-plonky2 status` shows exactly one modified file.

Implications:

1. **The change is not carried by the pin.** Anyone who checks out this repo and
   runs `git submodule update` gets the un-patched evaluator back and
   withdrawal claims stop verifying. The change must land upstream (a
   `polygon-plonky2` PR against the `mle` crate) and the submodule pin bumped,
   or it will silently disappear.
2. **It is generic, not intmax-specific** — a faithful port of an upstream
   plonky2 gate — so it is a natural upstream contribution. Recommended PR
   scope: `_evalExponentiation` + dispatcher branch + a copy of the vector test
   under `mle/contracts/test/` (the submodule has its own Foundry project;
   `CosetInterpolationTest.t.sol` is the precedent, and
   `mle/tests/dump_coset_test_vectors.rs` is the precedent for checking the
   vector generator in as a Rust dumper rather than a scratch crate).
3. **Interacts with the pending `gpu_merkle` / v2 `MleVerifier` migration**
   (CLAUDE.md "Known follow-up"). That migration bumps the submodule to
   `940ce731`+, which will drop this patch unless it is upstreamed first.
   Sequence the upstream PR before the v2 bump.
4. **Any future evaluator edit re-triggers §5.** Worth noting in the upstream PR
   description so downstream consumers expect the address drift.

## 7. Results

```
forge test --match-path test/ExponentiationGate.t.sol
    13 passed, 0 failed

cd contracts && forge test
    Ran 18 test suites: 271 tests passed, 0 failed, 0 skipped (271 total)
    = 258 pre-existing + 13 new

cargo test --release --test close_lifecycle_cli_e2e -- --ignored --nocapture
    run 1 (pre fixture-regen):  test result: ok. 1 passed; 0 failed — 1176.22s
    run 2 (post fixture-regen): test result: ok. 1 passed; 0 failed — 1149.46s
    final line: "[close-lifecycle-e2e] OK: deposited+withdrew 90000000000000000 wei
    into manager …; member claimed 40000000000000000 wei (channel 7, rollup …)."
```

The E2E was previously failing at `submitWithdrawalClaim` with
`"unsupported gate with non-zero filter"`. It now completes, and — per the
assertion at `tests/close_lifecycle_cli_e2e.rs:422` — the check is that the
claim PAYOUT actually landed, not merely that the proof verified. Nothing new
surfaced; no diagnosis of a follow-on failure was needed.

It was run twice on purpose: once against the fixtures as they stood, and again
after the §5 regeneration, so the final tree state is the one that was verified.

## 8. STOP points / open questions

None hit during implementation — `eval_unfiltered` is unambiguous and the three
Rust evaluators agree with each other. Two things were deliberately NOT done:

* **No booleanity constraint on `power_bits`** — see §3 point 3. If a reviewer
  believes the recursion circuit relies on the gate to enforce it, that is a
  question about plonky2's `exp_from_bits` call sites, not about this port;
  adding it here would break completeness.
* **No relaxation of the unsupported-gate revert.** Lookup gates and
  classifier `255` still revert.


## Post-review corrections (independent review, 2026-08-09) — verdict FIT

**F-1 (fixed here): the fixture table above under-reported the regeneration.** FOUR files changed,
not two — `close_lifecycle.json`, `close_lifecycle_validity_mle.json`, `close_withdrawal_mle.json`,
`close_withdrawal_payout.json`. The reviewer verified the causal chain (evaluator bytecode →
linked-library address → MleVerifier initcode → predicted CREATE2 Manager address → baked payout
recipient) and confirmed the diff is consistent with exactly that and nothing more. Crucially the
two gate-8 carriers (`withdrawal_claim_mle.json`, `post_close_claim_mle.json`) are UNTOUCHED — the
evaluator was made to match pre-existing proof data, not the reverse, which is the right direction.

**F-4 (fixed here):** the `else`-branch comment still listed ExponentiationGate as unsupported.
That branch is the fail-closed signal, so it must be accurate.

### What the review established (independently, not on trust)

- All 7 reference vectors **re-derived from the Rust source text**, breaking any circularity risk
  from the vectors having been Solidity-derived. Bit-exact match.
- **Full mutation matrix: 7 mutations, every one caught by a named test.** Mutation A (`prev`
  squaring `computed` instead of the wire value — the classic silent soundness break) is detected
  by ONLY the two negative vectors V2/V6. The negative vectors are load-bearing; a satisfying-only
  vector set would have shipped the hole.
- **The booleanity question is answered.** plonky2 has no booleanity constraint on the power bits
  because the bits originate in `BaseSumGate<2>` (`gadgets/split_join.rs:38`: *"new_unsafe is safe
  here because BaseSumGate<2> forces it to be in {0,1}"*) and reach the exponentiation wires
  through a `connect` — i.e. the permutation argument. BOTH halves are verified on-chain
  (`_evalBaseSum` implements the degree-B+1 product; `MleVerifier` verifies the copy argument with
  a VK-bound `k_is`/`id_col`). So mirroring plonky2's omission is correct, and vector V4
  (deliberately non-boolean bits, satisfying) is a REGRESSION LOCK that stops a future
  "hardening" PR from silently bricking every honest withdrawal claim.
- **The descriptor cannot be forged**: `numOrConsts = 66` is covered by `computeGatesDigest` and
  compared against the storage VK, so the length `require`s are defence-in-depth, not the control.

### Correction TO the review

The review rated the submodule-pin risk partly on "the 271-test suite would stay green on a
reverted submodule". **That is wrong, and I verified it by actually reverting the file**: Foundry
fails to COMPILE, because `contracts/test/ExponentiationGate.t.sol` calls `_evalExponentiation`
directly. A revert is caught loudly at build time, not silently at runtime. (File restored, md5
`e65c119f…`, 13/13 green again.)

The upstream-PR recommendation nevertheless stands, for a different reason than stated: the danger
is not a silent green suite, it is that a future `gpu_merkle` / v2-`MleVerifier` bump to
`940ce731`+ drops the patch, and the build break then invites "fix the build" rather than
"restore the gate". Land the upstream PR BEFORE that bump.

### Still open (named, not silent)

- Vector-generator provenance is UNVERIFIED — the scratch crate was discarded. Mitigated by the
  reviewer's independent re-derivation, but the generator should be checked in as a Rust dumper
  (precedent: `mle/tests/dump_coset_test_vectors.rs`) so the vectors are regenerable.
- `_evalBaseSum`'s own line-by-line correctness was not re-audited (pre-existing, out of scope) —
  flagged because the booleanity argument leans on it.
- EIP-170: `Plonky2GateEvaluator` runtime is now 22,484 B (2,092 B margin). Further gate ports
  (LookupGate especially) will not fit comfortably.
