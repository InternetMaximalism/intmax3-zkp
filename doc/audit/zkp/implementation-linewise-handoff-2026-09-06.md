# Line-by-line Lean formalization of the whole implementation / fund-soundness audit — handoff (2026-09-06, second round)

This is a record of carrying out Steps 1–7 of the previous handoff (as of `e604a36`).
For detailed counts and boundaries, see [implementation-linewise-progress.md](./implementation-linewise-progress.md).

## 0. Conclusion

The Lean formalization of the whole implementation and the proof that "funds cannot be stolen and cannot be lost" remain **incomplete**.
This round we built, independently reviewed, fixed and registered the 8 modules covering Balance / state update / channel state-update / the decryption gadget,
and got the main guard and the line guard to pass.
`--require-complete` fails as intended. This is not a release approval.

## 1. Work done this round

| Item | Result |
|---|---|
| `omega` failure in `DecryptionGadget` (`native_key_halves`) | Resolved by case-splitting on the sign. Matches source 717 / 726–727's `[-2,2]` and `e.max(0)` / `(-e).max(0)` |
| Building `ChannelStateUpdate` | The previous "standalone success" did not reproduce. `repeat' (apply every_bind; intro)` recursed unboundedly (over 19 GB) while unfolding `List.range slotCount`. Replaced with rewriting via `bind_ok_iff` and `split` at join points. Three proofs were also fixed. It now compiles in about 4 seconds |
| Independent review (4 items) | No blockers. Precision fixes applied: `channelTxDigest` narrowed to 7 inputs, unused `validateRecord` removed, theorem that transport bytes are forced empty, `core_row_integer` composition theorem, digit-255 boundary, native/target of `PrivateState` transcribed separately, name fix and vacuity guard for `UpdatePrivateState`, HashMap / cap count notes for `SwitchBoard` |
| line-map | 5 new (balance-public-inputs, switch-board, balance-circuit, channel-state-update, decryption-gadget). Together with the 3 existing ones, 8 registered |
| Registration | `Zkp.lean` import, guard `CURRENT`, manifest (156 hashes, 36 theorem_checks), `line_map` in the inventory |
| guard | main guard PASS (89 modules, 36 current modules, 1,273 theorems, kernel axioms only), line guard PASS (29 maps), regression 51/51, `git diff --check` clean |
| runtime | Zero diff in `src` / `contracts` / `Cargo.*` against `05ec7ae`. MLE `6cefc6a` clean |

Physical line classification: translated 9,632 / dependency-boundary 2,438 / non-executable 5,476 /
test-only 6,738 / untranslated 92,913. This is not a proof rate.

## 2. Items found while building the line-maps that need confirmation (reflected in the model; the judgement is a human's)

- Acceptance of send / fund import forces the transport envelope's proof bytes to be **empty**
  (`validate_signed_small_block`'s `transport_proof.is_empty()` and `== self.transport_proof.proof`).
  Whether the real verifier rejects empty bytes is outside this file.
- `require_accumulator_push` is not called from the state-update verifier (only on the wallet side).
- The nullifier root is only an inequality. Checks for insertion and freshness are not in this file.
- Fund import passes the small block's own `close_freeze_nonce` as the expected nonce (self-reference).
- In-channel sender authorization is only a structural check that `sender_hash_sig` is non-empty.
- `epoch + 1` / `state_version + 1` are profile-dependent u64 additions, U256 `+` panics on carry, and
  direct indexing (`member_pk_gs[depositor_slot]` and the like) panics rather than returning `Err`. Note the truncation in `depositor_slot as u16`.
- SwitchBoard: the VD carried by non-genesis candidates is not tied to the supplied balance VD. The outer
  cyclic-key check is the only boundary. The identity of the prove-time cap count and the constructor config is unproved.
- BalancePublicInputs: the target's checked assignment does not reject channel 0 (the native one does).
  `block_r ≤ block_number` is not enforced in this file.
- DecryptionGadget: `FieldProducts` is an undischarged premise. Uniqueness of the secret key (CRITICAL-1 in the module doc) is
  not formalized.

## 3. Git state

```text
checkout: /private/tmp/intmax3-node-preflight-audit-20260905.m7xtV6/checkout
branch:   codex/implementation-linewise-lean-20260906
push:     not done (will be done after an explicit instruction)
```

## 4. Next session

1. Translate the remaining validity / deposit / transfer / withdrawal circuits and Balance's send / receive circuits.
2. For the `Every`-family proofs, use `bind_ok_iff` rewriting rather than peeling with `apply` (see progress).
   Bisect heavy modules with a prefix compile using `lake env lean`.
3. Register a new module at all 5 places at once — Zkp.lean / guard CURRENT / line-map / manifest / inventory —
   and re-run the guard last if a hashed file was edited.
4. Do not make classification changes or admissions in order to get `--require-complete` to pass.
