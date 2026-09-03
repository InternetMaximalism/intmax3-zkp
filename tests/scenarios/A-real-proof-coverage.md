# Category A — real MLE/WHIR V2 proof coverage

This file tracks the remaining *cross-statement lifecycle* coverage gap. It is no longer accurate
to describe the claim lanes as “mock-only”: constructor-pinned V2 verifier acceptance now runs in
Solidity over real compact proofs for close intent, withdrawal claim, post-close claim, and cancel
close (`contracts/test/ClaimMleVerify.t.sol`). The full validity/withdrawal/close value paths also
run with real V2 proofs, and `contracts/test/V2FixtureCompleteness.t.sol` plus
`tests/mle_v2_fixture_release.rs` are non-skipping release gates for every tracked live fixture.

What remains is narrower but still release-relevant: the standalone claim fixtures are not yet
co-generated from the exact final H1/member set/accumulator of the checked-in close lifecycle.
Consequently, manager accounting and payout tests use strict mock-verifier proof payloads while the
real-verifier tests establish cryptographic acceptance separately. Do not combine those two facts
into a claim that one test already proves the entire close-to-claim value path.

All live artifacts use the V2 implementation with strict `plonky2-mle-v3-solidity`
schema/protocol version 3, WHIR PoW 22, and canonical `MLEWHIR3` compact bytes. Proof-free
deployment artifacts use the distinct `plonky2-mle-v3-solidity-config` schema. The release gates reject missing/stale V1 or wire-v2 fixtures instead
of allowing individual E2Es' compatibility skips to turn the suite green.

---

### A1 — withdrawal claim: real verifier coverage present; co-generated payout E2E remains

- **Status**: partially closed.
- **Present**: `generate_withdrawal_claim_fixture`; native self-verification; strict full/config
  artifact pairing; real pinned-V2 Solidity acceptance and compact-proof mutation rejection;
  manager limb binding, solvency cap, nullifier, and real-ETH credit payout coverage.
- **Remaining**: co-generate a withdrawal-claim proof from the *same* finalized H1/member set as
  `close_lifecycle.json`, then run `finalizeClose → pullChannelFunds → submitWithdrawalClaim(real
  proof) → claimWithdrawalCredit` in one non-mock value-path test.
- **Assert**: the member receives exactly its proved slot amount; `totalCreditedOut` increments;
  nullifier is single-use; `totalCreditedOut <= receivedChannelFunds`.

### A2 — post-close claim: real verifier coverage present; co-generated payout E2E remains

- **Status**: partially closed.
- **Present**: `generate_post_close_claim_fixture`; native self-verification; strict full/config
  artifact pairing; real pinned-V2 Solidity acceptance; manager accumulator/root limb binding and
  solvency-cap tests.
- **Remaining**: co-generate a real post-close-claim proof from the same finalized H1 and
  settled-transaction accumulator as the close lifecycle, then pay the proved incoming transfer in
  one real-verifier value-path test.

### A3 — stale or wrong-H1 withdrawal claim through the real manager path

- **Status**: open integration test, with both component boundaries covered.
- **Present**: manager strict-limb mismatch tests reject wrong H1; real V2 tests reject mutated
  compact proofs.
- **Remaining**: submit an otherwise valid real claim proof bound to a different H1 through a
  manager finalized on the checked-in lifecycle.
- **Assert**: strict claim-limb mismatch and no credit/nullifier mutation.

### A4 — member attempts to claim another member's slot through the real manager path

- **Status**: open integration test, with circuit/native and manager binding coverage present.
- **Remaining**: use co-generated lifecycle fixtures to submit member `i`'s valid proof as member
  `j` / recipient `j` through the real pinned verifier.
- **Assert**: member-key/recipient binding rejects it and no credit is created.

### A5 — wrong accumulator root post-close claim through the real manager path

- **Status**: open integration test, with strict manager binding and real proof acceptance covered
  separately.
- **Remaining**: submit a valid real post-close proof whose accumulator root differs from the
  finalized lifecycle root.
- **Assert**: strict claim-limb mismatch and no payout/accounting mutation.

### A6 — `fundBpBondCredits` unauthenticated mutator

- **Status**: closed by capability removal.
- `fundBpBondCredits(uint256)` no longer exists. The regression
  `ChannelSettlementAdversarial.t.sol::test_A6_bpBondCredits_mutator_removed_and_pot_still_inert`
  asserts that its selector fails and the bond pot cannot be inflated. Existing manager tests pin
  the constructor-funded bond balance.

These remaining co-generation items do not relax the broader audit NO-GO conditions (including
independent cryptographic review and the documented soundness-budget qualification).
