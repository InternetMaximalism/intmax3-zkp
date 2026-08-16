# Handoff — small-block N-of-N binding (and the exit-path work before it)

Written 2026-08-14. Branch `feat/falcon-poseidon-sig`, tip `e492cec`, pushed.
Read this before continuing on another machine: the commit messages carry the
detail, but the *state* and the *dead ends* are only here.

---

## 1. Where this stands

**The branch does NOT merge as-is.** Phases 0–5 of
`doc/tasks/small-block-nofn-design.md` are done and pushed; 6 and 7 are not.

| Phase | State | Commit |
|---|---|---|
| 0 — measurement + A/B decision gate | done | (spike, not committed) |
| 1 — registration `delegate_count == 0`, native IMCH mirror | done | `9c02a2e` |
| 1b — registration vs manager delegate-count decoupling | done | `061a8c5` |
| 2 — `AggListStepCircuit` | done | `c2b69fb` |
| 3 — **`update_channel_tree` N-of-N binding (closes the hole)** | done | `2459aa6` |
| 4 — `ValidityCircuit` rewire to the agg chain | done | `b9cd1ed` |
| 5 — **prove the old attack is dead** | done | `e492cec` |
| 6 — wallet signing path | **NOT STARTED** | — |
| 7 — VK + fixture regeneration | **NOT STARTED** | — |

### Why it cannot merge yet

1. **VKs have been broken since Phase 1.** The added copy constraint changed
   `ChannelRegStepCircuit`'s verifier data, cascading up to `mleVk`. Every
   checked-in proof fixture is stale.
2. **Because of (1), `forge test` and the `#[ignore]` CLI E2Es were deliberately
   NOT run from Phase 1 onward.** They will fail. That is expected, not a
   regression — do not "fix" it by touching circuits. Phase 7 regenerates.
3. **Production still cannot sign.** `wallet_core.rs` `structural_small_block_sigs`
   emits literal stub bytes (`vec![1 + i]`). There has never been a real IMSB
   signing path; Phase 6 builds one for the first time. Until then the N-of-N
   binding is enforced in-circuit but nothing in production produces a
   satisfying witness.
4. **This is a hard fork.** `mleVk` is written only in `IntmaxRollup`'s
   constructor — no setter. Deploying this means a fresh rollup and a fresh
   account tree; **existing channels cannot migrate and must be drained.**

### What Phase 6 needs (from the design doc + what Phases 3–5 flagged)

The binding assumes the wallet's real `ChannelState.h2_tag` equals the block's
`tx_tree_root` at signing time. `channel.rs:549-553` documents exactly that for
inter-channel sends (and `0` for in-channel, which the `tx_tree_root != 0` gate
excludes). But the test generator currently supplies a *projected* IMCH preimage
(real H1′, advancing `small_block_number`) rather than the wallet's own state, so
that equality has never been exercised against a real wallet. Phase 6 must close
it, and its acceptance item includes measuring per-block signing cost against
`doc/benches/batch-cosign-throughput.md` — signing now scales with N.

---

## 2. The defect this closes, and the evidence

**Intended rule (owner):** a signature over `tx_tree_root` is the ACCOUNT's
signature — the whole channel's — and must be N-of-N. Block *posting* is
deliberately 1-of-N and is **not** a security control; all security rests on the
local ZKP chain and the withdraw-time verification.

**What the code did:** a signing block carried exactly ONE IMSB signature
(`update_channel_tree.rs:933` pre-change), from any slot in
`member_pubkeys_root`. `FalconAggCircuit` — the N-of-N aggregate already used by
close and cancel-close — appeared nowhere under `src/circuits/validity/`. The
base-layer proof chain never referenced the channel's N-of-N at all: grep for
`h2_tag` / `IMCH` / `member_signatures` across `src/circuits/balance/` and
`src/circuits/withdraw/` returned zero.

The rule *was* specified — `h2_tag` **is** the small block's `tx_tree_root` and
rides inside the IMCH preimage every member signs. The circuit never looked.
`state_commitment_root` sits in the IMSB preimage but its equality against the
signed H1 is enforced **off-circuit** (`small_block_message.rs:55-56`), which
binds only honest participants.

**Phase 5 proved this by execution, not argument.** Against the real pre-Phase-3
code (worktree at `c2b69fb`): a channel with 3 cosigners, members 1 and 2
depositing 6 and 4, the attacker at slot 0 depositing **nothing**. Holding only
`prev_private_state` and their own Falcon key, the attacker produced verifying
spend → send-tx → block → withdrawal proofs moving all 10 to an address they
chose, with zero involvement from the other two members.

Post-change the same construction dies at the block step. The load-bearing case
is `signer_count = 2` over {attacker, a key the attacker minted}: **both
signatures are real and natively verify**, and nothing in the signature stack
refuses it — only the recomputed member-root connect does.

### One conclusion that must not be misread

**A 1-of-N aggregate IS provable**, at `FalconAggCircuit` and through an
`AggListCircuit` step. That is by design (`agg.rs:81-83` deliberately allows
duplicate signers). What is unprovable is *applying* one to a block. If anyone
later reasons "the aggregate enforces N", that is wrong — enforcement is
entirely in `update_channel_tree`'s `2..=16` floor plus the member-root connect,
and the validity circuit's `C == final.bp_sig_chain` equality.

---

## 3. Why Design B, with the numbers

Design A reshapes the IMSB message and has members sign it. Design B verifies an
aggregate over the **IMCH digest that N members already sign**.

B was chosen because it needs **no new signing round**: the N real Falcon
signatures already exist in production in `ChannelState::member_signatures`, and
close already consumes them via `falcon_member_auth_from_signatures`. Design A
would have required signing IMSB *in addition to* IMCH — two N-of-N rounds per
transition, doubling the measured single-channel bottleneck.

Phase 0 measured with `NoopGate` ballast bisection (degree_bits is a power of two
and hides margin, so the bucket alone is not evidence):

| | spare rows in `UpdateUserCircuit` |
|---|---|
| baseline | 11,136 |
| M2′ (member-tree recompute) alone | 10,859 (+277) |
| Design A | 11,093 (+43) |
| **Design B** | **9,472 (+1,664)** |

Phase 3 measured the real thing at **9,567 spare** — 95 rows better than
predicted. `AggListStepCircuit` came out at **2^13 / 4,412 gates**, down from
`ListStepCircuit`'s 2^16 / 51,764, and step prove time is identical at n=2 and
n=16 (as it should be for a recursive verify).

**Known cost of B, recorded:** it consumes the `num_users = 4` headroom.
Baseline and A hold 2^16 up to `num_users = 4`; B holds it only to 3. Production
is `num_users = 2`, so this does not block adoption, but B forecloses a future
move to 4 channel slots per block that A would not.

---

## 4. Dead ends — do not redo these

- **Constraining `state_commitment_root == balance_state.h1()` in-circuit buys
  nothing.** The validity circuit has no `BalanceState`; asserting the equality
  means witnessing one, and the *prover chooses that witness*. It is a
  hash-preimage statement, not an authorization statement — the attacker simply
  supplies the `BalanceState` reflecting their own theft and its genuine `h1`.
  Most expensive possible witness, zero security. Only a signature proves N-of-N.
- **The doc's keccak cost model was wrong.** `plonky2_keccak` is not an
  in-circuit permutation network; it is a STARK-in-SNARK registered through a
  builder *hook*, so every keccak call in a circuit batches into ONE recursive
  verifier emitted at `build()`. Measured: 1 → 2,000 limbs all give 2^16; only
  4,000 reaches 2^17. Consequences: **2^16 is a floor, not a ceiling**, for any
  circuit containing a keccak; and §4A.4's warning that "close does this same
  IMCH recompute and sits at 2^17" is **misattributed** — a 139-limb recompute
  costs ~1,387 rows and cannot be what puts close at 2^17.
- **`bp_member_slot` / `bp_pk_g` ARE in the IMSB signing preimage**
  (`channel.rs:396-408`). An earlier analysis in this session claimed the slot
  was unpinned and could be spoofed; that was wrong. The real gap was never slot
  spoofing — it was that one signature sufficed and the channel's N-of-N was
  never consulted.
- **The Phase-0 spike's leaf construction was unsound** and was discarded in
  Phase 2: it reused the IMLL domain for a differently-shaped tuple.
  `PoseidonHashOut::hash_inputs*` is a **no-pad** sponge, so neither length nor
  tuple shape is encoded — the leading domain constant is the entire separation
  argument. Two schemas under one tag voids it. New tags IMAL/IMPL are registered
  in the pairwise-distinctness test.
- **The design doc's "`channel_id` limb 1, `channel_fund.channel_id` limb 6" are
  SEGMENT ORDINALS, not limb offsets.** Real offsets are **1 and 8**; `h2_tag` is
  **129..137**. Pinned as named constants in `channel_state_message.rs`. Using the
  wrong ones binds `tx_tree_root` to the wrong segment.

---

## 5. Environment gotchas that cost real time

- **Tests hardcode anvil ports 8549–8559 and CANNOT run concurrently.** Four
  separate incidents this session, one orphan blocking port 8554 for two days,
  another run at 0% CPU for 12 hours. Every time it presented as a mysterious
  test failure. `tests/anvil_harness/` now refuses to start when the port is
  already bound and distinguishes "a different process owns it" from "anvil
  itself failed" — but the underlying constraint remains: **serialise anvil
  suites, and never run several Foundry-using agents at once.**
- Circuit builds are the heaviest thing here. Peak RSS observed: 13.95 GB
  (`tests/e2e.rs`), 13.41 GB (the Phase 5 attack module). Strictly one at a time
  on a 36 GB box.
- Editing `Plonky2GateEvaluator.sol` — *even a comment* — moves the linked
  library address, hence the CREATE2 manager address, hence the baked payout
  recipient, so the four `close_*` fixtures regenerate. `foundry.toml` sets no
  `bytecode_hash`. This happened twice.

---

## 6. Still open, outside this work

From the exit-path sweep earlier in the same session (see
`doc/audit/exit-path-facade-sweep.md`, `doc/audit/doc-vs-code-exit-sweep.md`):

- **Partial withdrawal authorizes but never pays out**, on any chain.
  `cmd_partial_withdraw` has never existed. Design at
  `doc/tasks/partial-withdrawal-payout-design.md`; `api/API-DESIGN.md` now says
  so rather than claiming `pw-finalize` is implemented.
- **F-AUX-1 is unresolved.** Nothing checks base `Transfer.amount` against the
  channel-layer debit. An earlier analysis in this session **overstated** it by
  not establishing who can author a base-layer transfer; re-assessment at
  `doc/tasks/f-aux-1-severity.md` is written against the corrected constraint but
  its conclusions were not re-reviewed after the owner's clarification. Treat
  that file with care.
- **The L1 private key is passed as `cast --private-key <VALUE>` at 27 sites**,
  readable from `ps` by any local user.
- `POST /api/v1/keys/generate` mints a user's key server-side from a
  caller-supplied or default-`1` u64.
- Withdrawal salts use `seed_from_u64(1)` outside `cfg(test)`.
- **The live Sepolia rollups read `withdrawalVkInitialized = false`** — deposits
  work, withdrawals revert. Repairable by the deployer in one transaction. PR #33
  fixes the scripts that produced it; it does not fix the deployed contracts.
- **Every channel created before `898a586` has publicly derivable co-signer
  keys** and must be drained and retired, not merely redeployed
  (`doc/tasks/cosigner-key-provenance.md`).

CI exists as of `63e9087` and runs on PRs. A green PR check does **not** mean the
close lifecycle, inter-channel, partial-withdrawal or faucet flows work — those
are nightly. `--lib` unit tests, WASM and fixture *semantic* staleness are
uncovered; `ChannelSettlementInvariant.t.sol` try/catch-swallows all four
handlers and stays green under a total liveness break.

---

## 7. Working notes not in the repo

Claude's per-project memory (`~/.claude/projects/…/memory/`, 29 files) is
machine-local and does **not** transfer. Its contents are largely derivable from
git history and `doc/`; nothing in it is required to continue this work — this
document is intended to be sufficient.
