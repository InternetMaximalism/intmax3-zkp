# Lean codec / prover fixture parity

**This document records fixture-level agreement evidence. It is NOT a refinement
proof.** Nothing here shows that the handwritten Lean models in
`doc/audit/zkp/Zkp/Implementation` refine the Rust prover, the plonky2 circuit
compiler, or the Solidity consumers. What it shows is narrower and checkable:
on the public-input vectors the real prover actually emitted into
`contracts/test/data`, the Lean decoders parse those words into exactly the field
values the prover recorded in its companion JSON records, and — where the
Solidity contract recomputes a digest from those same fields — into the values a
from-scratch keccak recomputation of the Solidity preimage produces.

A single agreeing fixture is one point of a relation, not the relation. These
checks would not catch a model that is wrong on inputs no fixture exercises
(different lengths, out-of-range limbs, wrapping scalars, zero channel ids, other
member/token counts). They are regression evidence that the *layout and field
identification* in the models match the deployed encodings.

## Running it

```
python3 .github/ci/lean-fixture-parity.py            # human report, exit 1 on any mismatch
python3 .github/ci/lean-fixture-parity.py --json out.json
python3 .github/ci/lean-fixture-parity.py --case withdrawal_chain --dump-probes /tmp/probes
python3 .github/ci/test-lean-fixture-parity.py       # offline unit tests, no lake needed
```

`lake` must be reachable; the checker prepends `$LEAN_PARITY_ELAN_BIN` (default
`~/.elan/bin`) to `PATH`, matching this project's elan-outside-PATH setup. Every
module used is already built, so the probes run under `lake env lean` and never
trigger a `lake build`.

Observed runtime on the checked-in fixture set: **~2.2 s wall for 18 cases**
(18 `lake env lean` probe invocations); the unit suite runs in ~0.2 s.

## Method

For each fixture the checker

1. reads the u64 public-input words the prover emitted — `proof.publicInputs` of
   a `*_mle.json`, or a raw word-list fixture;
2. generates a **throw-away** Lean probe in a temp directory that `import`s the
   audited module, binds those words as `probeWords : List Nat`, `#eval`s the
   module's own decoder, and prints flat `FIELD <name> <value>` lines through a
   **probe-local** printer. No module under `Zkp/` is edited, and no probe
   contains a `theorem`, `axiom` or `sorry` — the unit tests assert this;
3. runs `lake env lean <probe>` in `doc/audit/zkp`;
4. compares every printed field, character for character, against the value
   derived from the companion fixture. Digests are compared as *limbs in the
   model's own order* (eight big-endian u32 limbs, `U32LimbTrait::to_u32_vec`
   order, verified against the fixtures rather than assumed); U256 amounts as the
   model's eight limbs; addresses as five limbs; scalars as the joined u64 the
   model's `joinValue` produces; counts as plain naturals;
5. where the model has an encoder, re-encodes the decoded value and compares the
   resulting word list against the prover's original words (`reencoded`).

A decoder that rejects a fixture, a field the probe fails to print, or any
mismatch is a **FAILURE** and exits non-zero. Fields that genuinely cannot be
compared are printed as `not-comparable` with the reason and are never dropped.

**A mismatch is a finding about the model, not something to normalise away.**
The comparison is deliberately one-directional: expectations are computed from
the fixtures and the Solidity source, never from the Lean output.

## Coverage: fixtures, decoders and the exact fields compared

Current status: **18 cases, 177 comparable fields PASS, 0 FAIL, 22
not-comparable.**

### `close_intent` — 103 words
* words: `close_intent_mle.json` → `proof.publicInputs`
* decoder: `Zkp.Implementation.ClosePublicInputs.fromU64Slice`
* companion: `close_intent.json`
* compared (22): `input.length`, `channelId`, `closeNonce`, `finalEpoch`,
  `finalSmallBlock`, `freezeNonce`, `stateDigest`, `h1`, `genesisFund`,
  `fundRoot`, `burnHash`, `withdrawalDigest`, `closeId`, `snapshot`,
  `stateVersion`, `settledChain`, `accumulatorRoot`, `memberSet`, `memberCount`,
  `delegateCount`, `tokenFundsDigest`, `reencoded` (`toU64Vec` = original words).
* `genesisFund` is the companion's `channel_fund_amount` U256 rendered as the
  model's eight limbs; `memberSet` is `member_set_commitment` — note that the
  *decoder* reads word 85..92 while `projectWitness` deliberately leaves
  `memberSet := Words8.zero`, so only the decoder side is fixture-checkable here.
* not comparable: `member_pk_gs`, `channel_fund_amounts[1..9]`, `token_registry`,
  `token_count` — not separately registered; they enter only through the opaque
  `token_funds_digest` / `member_set_commitment` pre-images.

### `pw_close_intent` — 103 words
* words: `pw_close_intent_mle.json`; decoder as above; **no companion record is
  checked in**, so all 20 decoded fields are reported `not-comparable`. Only
  `input.length` and the `reencoded` roundtrip are asserted.

### `cancel_close` — 29 words
* decoder: `CancelClosePublicInputs.fromU64Slice`; companion `cancel_close.json`
* compared (8): `input.length`, `channelId`, `closeId` (= `close_intent_digest`),
  `memberSet` (= `member_set_commitment`), `closeVersion`
  (= `close_final_state_version`, the joined scalar), `revivedVersion`
  (= `revived_state_version`), `revivedDigest`
  (= `revived_channel_state_digest`), `reencoded`.
* not comparable: `member_pk_gs` (only its commitment is registered).

### `withdrawal_claim` — 50 words
* decoder: `WithdrawalClaimPublicInputs.fromU64Slice`; companion
  `withdrawal_claim.json`
* compared (12): `input.length`, `closeId`, `channelId`, `h1`, `memberPk`,
  `recipient` (5 address limbs), `ciphertextDigest` (= `user_amount_digest`),
  `nullifier` (= `withdrawal_nullifier`), `amount` (joined u64), `tokenSlot`,
  `tokenIndex`, `reencoded`.

### `post_close_claim` — 57 words
* decoder: `PostCloseClaimPublicInputs.fromU64Slice`; companion
  `post_close_claim.json`
* compared (10): `input.length`, `closeIntentDigest`, `receiverChannelId`,
  `incomingTxHash`, `receiverPkG`, `recipient`, `sharedNativeNullifier`,
  `amount`, `tokenIndex`, `reencoded`.
* not comparable (2): `finalBalanceStateH1`, `finalAccumulatorRoot` — the
  companion record does not carry them.

### `close_asset_backing` — raw 26 words
* words: `close_asset_backing_public_inputs.json` (a raw word list), first
  cross-checked to be identical to `close_asset_backing_mle.json`
  `proof.publicInputs` and to `manifest.backingPublicInputCount`
* decoder: `CloseAssetBacking.parsePublicInputs`
* companion: `close_asset_backing_manifest.json` + `close_intent.json`
* compared (7): `input.length`, `channelId` (manifest), `settledTxChain`
  (= close_intent `final_settled_tx_chain`), `tokenFundsDigest` (= close_intent
  `token_funds_digest`), `extendedStateCommitment`
  (= manifest `backingFinalizedExtendedStateCommitment`), `anchorBlockNumber`
  (= manifest `backingAnchorBlockNumber`), `reencoded`.

### `withdrawal_chain[…]` — 17 words × 5 fixtures
`close_`, `c2c_`, `burn_`, plain, `sepolia_` (`*_withdrawal_mle.json`).

* decoder: `Zkp.Implementation.WithdrawalChain.fromU64Slice`, plus the two
  Solidity-mirroring helpers `RollupValue.limbsToBytes32` and
  `RollupValue.limbsMatchBytes32` evaluated in the same probe
* companion: `*_withdrawal_payout.json` + a from-scratch Python keccak
  recomputation of the `IntmaxRollup` preimages
* compared (8 each): `input.length`; `pisHash` vs the recomputation of
  `_withdrawalPisHash` — fold every `withdrawals[]` entry through the 152-byte
  `_foldWithdrawalLeaf` preimage (`prev‖recipient(20)‖tokenIndex(4)‖amount(32)‖
  nullifier(32)‖auxData(32)`) from seed 0, then keccak the 92-byte
  `withdrawalHash‖prover(20)‖extCommitment(32)‖blockNumber(8 BE)` and apply the
  `remove_3bits` mask `& (2^253 - 1)`; `extCommitment` vs
  `payout.ext_commitment`; `blockNumber` vs `payout.block_number`;
  `RollupValue.limbsToBytes32 pi 8` vs the ext-commitment integer;
  `RollupValue.limbsMatchBytes32 pi 0 <recomputed pisHash>` = `true`;
  `pi[16]` vs the block number; `reencoded` (`PublicInputs.toU64Vec`).

This is the strongest case in the set: the Lean decoder, the Lean model of the
Solidity limb helpers, the prover's registered words and an independent keccak
recomputation of the contract's preimage all have to agree on all five fixtures.

### `validity[…]` — 41-word preimage × 7 fixtures
`close_`, `c2c_`, `burn_`, plain, `sepolia_` (`*_lifecycle.json` `vpis` vs
`*_lifecycle_validity_mle.json`'s 8 registered words), `e2e_fixture` (vs its
`pi_hash`), and `vpi_fixture` (no companion proof).

* model: `ValidityChain.ValidityPIs.u32Words` / `.preimage` / `.toRollup`, with
  the probe building a `ValidityPIs` literal from the fixture's seven recorded
  fields
* compared (11 each, 10 for `vpi_fixture`): `input.length`; `u32Words` — the
  41-word `to_u32_vec` order; `preimage` — all 164 bytes, byte for byte, against
  the independently packed preimage; the seven `toRollup.*` recompositions
  (`initialBlock`, `initialChain`, `initialRoot`, `finalBlock`, `finalChain`,
  `finalRoot`, `prover`) against the fixture's hex values; and
  `RollupValue.limbsMatchBytes32 pi 0 <keccak(preimage)>` = `true`, i.e. the
  prover's 8 registered public-input limbs are exactly keccak256 of the byte
  string the Lean model says the circuit absorbs.
* `vpi_fixture.json` has no proof fixture registering it, so its
  `limbsMatchBytes32` check is absent; only the preimage layout and the
  `toRollup` recomposition are compared.
* The `toRollup.*` comparisons are weak by construction (the literal is built
  from the same fixture). The load-bearing checks in this case are the 164-byte
  preimage layout and the keccak equality with the registered public inputs.

## What this evidence does not establish

* No refinement, simulation or equivalence between the Lean model and the Rust
  source, the generated circuit, or the Solidity bytecode.
* No proof soundness. Nothing here verifies a WHIR/plonky2 proof; the fixtures'
  `proof` blobs are read only for their `publicInputs` array.
* No hash-function property. The keccak recomputation is Python code compared
  against prover output; neither collision resistance nor injectivity is used or
  claimed anywhere.
* No coverage of the decoders' rejection paths, wrapping-scalar behaviour,
  out-of-u32 limbs, or the witness-projection (`toPublicInputs`) side of any
  module. Those live in the modules' own kernel-checked theorems.
* The `not-comparable` fields above are exactly the fields no checked-in record
  pins down. They are reported so the gap stays visible, not because they were
  judged unimportant.

## Files

| path | role |
| --- | --- |
| `.github/ci/lean-fixture-parity.py` | probe generator, Lean runner, comparator, reporter |
| `.github/ci/test-lean-fixture-parity.py` | offline unit tests (40); pass with `lake` absent from `PATH` |
| `doc/audit/zkp/fixture-parity.md` | this document |

The unit suite covers the keccak implementation against published vectors, the
limb packing, both Solidity recomputations against every checked-in fixture,
probe-output parsing (including the `DECODE_ERROR` path), the comparator's
PASS / FAIL / missing-field / not-comparable behaviour, case construction and
probe determinism, and the no-`lake` fallback. It never invokes `lake`, `lean`,
`git` or the network.
