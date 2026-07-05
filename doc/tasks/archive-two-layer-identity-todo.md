# Task: Two-layer identity (base = channel_id) → base L1 withdrawal payout → channel close integration

Status: PLANNING — pre-implementation. Do not write code yet. This plan is a full revision based on the foundational decision in §1.

## 0. Confirmed model (agreed)

- **base intmax = channel-to-channel settlement layer.** The native "user" of base is
  **the channel itself**.
- **channel layer = intra-channel (member-to-member) confidential balance layer.** key_id is a concept only here.
- channel close = an L1 native withdrawal request of "the channel as a base user" (a time-consuming request + an override
  window). After withdrawal, the pool is distributed among members (key_id).
- The cap (total amount limit) is decided by the **base intmax withdrawal proof**. A channel can only
  withdraw the base balance it actually holds. The sole invariant to protect = **inter-channel isolation**. Internal misallocation is an accepted risk (within one's own channel pool).
- Final form of nullifiers: **#1 = base intmax withdrawal nullifier (newly added in this task)**, #2 = per-member flag
  (status quo). Internal ZK verification of #3 / post-close incoming is OUT this time (left as a stub, accepted risk).
  The aggregate **solvency upper bound** (all credit ≤ actual received amount) is not dropped.

## 1. FOUNDATIONAL DECISION (the core of this revision)

**Make the native account key of base intmax `channel_id` (4 bytes) only. Remove key_id from base.**

- Current: base `UserId = (channel_id << 32) | key_id` (8 bytes equivalent / u64). The account tree uses
  `user_id.as_u64()` as the leaf index (src/common/user_id.rs:30-38, account_state.rs:82).
  → The base account is **per-member**, and a single base account for "one channel" does not exist.
- After the change: base `UserId = channel_id` (u32, 4 bytes). account tree leaf index = `channel_id`.
  → **channel = one base account**. channel fund = that account's base native balance.
  → The "anchor the channel to the actual base balance" problem **disappears structurally** (no separate proof needed).
- key_id remains as **channel-layer-only (src/common/channel.rs)** (member identification / internal distribution).
  The base layer holds / sees no key_id at all.

### 1.1 Scope this decision touches (full = code impact map)

base layer (channel_id-ification):
- [ ] src/common/user_id.rs — change `UserId` to u32 (channel_id). Revise `new/from_*/to_*` / Target.
      Redefine the dummy reservation (currently channel_id=0 && key_id=0) into a channel_id=0 reservation.
- [ ] src/circuits/balance/common/account_state.rs — account leaf index = channel_id. Revisit tree depth
      (index space 64bit→32bit).
- [ ] balance-family circuits in general (src/circuits/balance/ : send_tx / receive_transfer / receive_deposit /
      tx_settlement / spend) treat user_id as channel_id.
- [ ] nullifier derivation (src/common/transfer.rs) — from = channel_id. Confirm that the uniqueness of the base
      withdrawal nullifier is preserved per channel.
- [ ] validity / block / signature (src/circuits/validity/) — base block signatures are the **channel's aggregate
      signature** (the channel signs as one user). member signatures move to the channel layer.
- [ ] deposit path — recipient/account = channel_id (recipient encoding of IntmaxRollup.sol deposit).

channel layer (key_id retained, bridging revised):
- [ ] src/common/channel.rs — keep channel `UserId = channel_id||key_id` for internal use.
      Revise/organize `bridge_user_to_channel_id/key_id` (1026-1032) on the "base=channel_id" premise.
- [ ] InterChannelFundImport etc. — unify the relationship between the base balance (channel_id account) and the channel fund.

## 1.2 Registration → Poseidon tree → ZKP binding (core of W3 / agreed)

**Registration is all on-chain** (DA secured):
- `registerKey(key_id, pubkeys[], threshold)` — emit public keys into calldata.
- `registerChannel(channel_id, member_key_ids[])` — emit the member keyID set into calldata.

**After registration, build a deterministic Poseidon tree and prove consistency with ZKP** (2 layers):
```
KeySetTree(pubkey hashes) → pk_set_root
KeyLeaf { pk_set_root, threshold }  →  KeyTree(keyID index) → key_tree_root
member_key_ids → member_key_ids_root
ChannelLeaf { member_key_ids_root, ... }  →  ChannelTree(channel_id index) → channel_tree_root
```

**SECURITY invariant (must achieve)**: the ZKP proves "the Poseidon tree **exactly matches** the on-chain registration
entries". It allows no insertion of unregistered keys / omission of registered keys / register-X→inject-Y.

**Binding means** (following existing patterns): just as deposit=`deposit_hash_chain`, block=`block_hash_chain` hash-chain
the calldata and `validity_circuit` binds on-chain via `keccak(ValidityPublicInputs)`,
registration is likewise hash-chained (or integrated into the block hash chain) → the ZKP proves the Poseidon tree
transition = the registration sequence → the root is bound on-chain. ← the primary target of the attacker pass.

## 2. Scope (Option A premised on this decision)

### IN (required)
- **The base identity two-layering of §1** (channel_id-ification).
- **base L1 user withdrawal payout (new)**:
  - On-chain verification of the aggregated withdrawal proof (reusing IntmaxRollup's existing MLE/WHIR+Groth16).
    The proof is bound to `IntmaxRollup.latestFinalizedStateRoot`.
  - Native transfer to the recipient (pull-payment / `pendingWithdrawals` scheme).
  - **base withdrawal nullifier mapping** (`mapping(bytes32=>bool)`) to prevent double withdrawal.
  - Expose `aux_data` on-chain (for recipient attribution).
- **Make the channel a user of base withdrawal**: close = base withdrawal of the channel_id account (recipient =
  `ChannelSettlementManager`, `aux_data = channel_id`). cap = **anchored to the actual received amount**.
  Abolish the stub verifier on the close/burn path.
- **solvency upper bound (cannot be left alone)**: bind all of the Manager's credit paths (withdrawal claim / post-close incoming)
  by the actual received burn total. `claimWithdrawalCredit` binds the actual native transfer by the balance.
  - Current hole: submitPostCloseClaim (ChannelSettlementManager.sol:599-600) has no cap check.
- **replace window** (§4).

### OUT (left alone this time = remains a stub, accepted risk. Closed within intra-channel)
- Internal ZK verification of #2 per-member withdrawal claim.
- Internal ZK verification of #3 late outgoing debit / post-close incoming.
- #2/#3 integration (separate task).

## 3. Phase 0 result (done) — the linchpin does not hold. Resolved by this decision.

1. The channel was not an actual base-intmax account (`intmax_state_root` unconstrained) → **resolved in §1 by making it a channel_id
   account**.
2. There is no on-chain user withdrawal payout in the base rollup (`withdraw()` is stake/fraud-only,
   no nullifier mapping, aux_data not exposed) → **newly added in §2**.

## 4. replace window design (new mechanism)

- A request is **allowed even from 1 member**. During the challenge period, it can be overridden by a **higher-version fully-signed state**.
  - [ ] Total-order the override priority rule (`close_nonce`/`epoch`/`final_small_block_number`/fully-signed).
- **Ordering with payout finalization (most important)**: once the base withdrawal lands on L1, override becomes impossible → separate the "request-acceptance phase
  (replace allowed)" from the "base withdrawal execution / landing phase (replace not allowed)". Guarantee that
  the window in which early landing makes replace meaningless = 0. Consistent with the special-close 5 medium block window.

## 5. Threat Model (independently verified by an attacker subagent before code)

- **Soundness of identity migration**: that channel_id-ification cannot "impersonate-withdraw another channel's balance".
  Effects of account tree index collision / mistaking the dummy reservation / index space shrinkage.
- **base withdrawal soundness**: the proof is always bound to `latestFinalizedStateRoot`; withdrawal from an unfinalized state is impossible.
  Fiat-Shamir / domain separation (channel close PIs vs base withdrawal PIs).
- **nullifier**: the newly added mapping reliably rejects a double payout of the same withdrawal. channel double-burn impossible.
- **burn↔channel binding**: the Manager derives amount/attributes from the actual receipt or a verified base state. It cannot
  misattribute another channel's withdrawal via aux_data spoofing.
- **solvency**: Σ(payable credits) ≤ actual received burn total (across all credit paths, including post-close incoming).
- **replace contention / old state replay / single-person request abuse**: after the winner is finalized, old-state withdrawal reverts. On censorship,
  cancel/special-close rescue. Argument that the window where order reversal of replace and landing yields a double native = 0.
- **payout safety**: reentrancy / reverting recipient (pull-payment compliant).

## 6. Falsifiable verification items (proven by tests)

- [ ] After channel_id-ification, base balance / send-receive / deposit remain sound (regression). Cannot withdraw another channel_id's balance.
- [ ] base withdrawal: a proof for an unfinalized state root reverts. Only a finalized root passes.
- [ ] Replaying a base withdrawal nullifier reverts (double payout impossible).
- [ ] After close, the channel's payable native ≤ the channel's actual base balance (cross-channel isolation).
- [ ] Σ(withdrawalCredits payable at any point in time) ≤ actual received burn native (solvency property test,
      including the post-close incoming path).
- [ ] `finalizedChannelFundAmount` is not influenced by submitter calldata.
- [ ] A burn to channel C cannot be claimed by C' (attribution test).
- [ ] replace: a low-version request is overridden by a high version, and after finalization the low-version withdrawal reverts. A
      replace after landing is invalid.

## 7. Implementation phases (after detailed-design approval / approval at each Phase)

1. **§1 base identity two-layering (channel_id-ification)** — change the foundation first. Confirm regression tests green.
2. **base L1 withdrawal payout** — on-chain verify + nullifier mapping + payout + aux_data exposure +
   Rust-side PI preparation.
3. **Make channel close a user of base withdrawal** — recipient=Manager, aux_data=channel_id, cap=actual receipt.
   Replace the close/burn path stub.
4. **Manager** — solvency upper bound on all credit paths / make `claimWithdrawalCredit` an actual transfer / replace window +
   phase separation.
5. Implement the tests (§6) by category (happy/boundary/malformed/cross-protocol/property).

## 8. Process (CLAUDE.md compliant)

- **Separate the implementation subagent and the security-review subagent**.
- For protocol changes, launch the **attacker subagent** in §5, review before merge.
- For unexpected test results, "security hypothesis first". Do not modify to make tests pass.
- base identity changes and payout are heavy changes involving on-chain fund movement and circuit-wide ripple →
  take approval at each Phase.

## 9. Assessment (updated as needed)

- Phase 0: done. The linchpin does not hold (§3). Direction = Option A.
- Foundational decision (§1): confirmed as base native account = channel_id (4 bytes), with key_id removed.
- §1 implementation (base ID two-layering + terminology rename + type unification): **done**. Unified base `UserId`→a single `ChannelId(u32)`+
  `ChannelIdTarget` (removed channel.rs's [u8;4] version, keccak preimage unchanged). All user-family symbols moved
  to channel-family (account_tree→channel_tree, USER_TREE_HEIGHT 64→CHANNEL_TREE_HEIGHT 32, etc.).
  The build is verified with only the known 21 logic errors and zero new ones. The channel-layer member id ([u8;8]) is unchanged.
- W3 step 2 (new tree types): **done**. Added `src/common/trees/key_tree.rs` (`KeyLeaf`/`KeyTree`
  =keyID index, `MemberKeyLeaf`/`MemberKeyTree`, domain separation tags KYLF/MKLF). Restructured `ChannelLeaf`
  (removed `pk_set_root`+`threshold` → added `member_key_ids_root`, domain tag CHLF). Added
  `KEY_TREE_HEIGHT`/`MEMBER_KEY_TREE_HEIGHT` to constants. The new code compiles with zero errors. design is
  doc/tasks/channel-key-tree-design.md. Total build errors 21→67 (downstream of the ChannelLeaf restructure = W3 sites, as expected).
- W3 step 3 (on-chain registration): **done**. Added `registerKey(keyId, pkHashes[], threshold)`
  and `registerChannel(channelId, memberKeyIds[])` to `IntmaxRollup.sol` (following the deposit hash-chain pattern). Registration hash chains
  `_pendingKeyRegHashChain`/`_pendingChannelRegHashChain` + counts + events. Arrays are tightly concatenated per element
  (avoiding the 32-byte padding footgun of abi.encodePacked). The keccak preimage is specified in comments (the target the Step4 Rust circuit
  matches). `forge build` OK. **Record only**; tree application is Step4. members are verified as ascending-unique and non-0.
- W3 step 4 (registration-application circuit): **design done** (channel-key-tree-design.md §6). Reflects the ChannelTree-shared ordering constraint.
- **MVP policy confirmed**: registration is genesis-done; KeyTree/ChannelTree are immutable (no further registration). Registration consumption (§3/§4) is
  out of MVP scope. The MVP is a self-contained module in a separate file that proves the signature rule (all member keyIDs clear the threshold) against the fixed tree.
  Spec = doc/tasks/channel-key-tree-mvp.md (a pointer is noted in the main design.md). The existing broken recursive flow is not a precondition of the MVP.
- Remaining (needed to green the main build, separate from the MVP):
  - W1-mechanical: key_id removal sites (tx_settlement / single_withdrawal / public_state /
    block_witness_generator / bridge_user_to_key_id). tx tree becomes channel_id-indexed.
    → **done** (2026-06-12 baseline repair): `cargo check` / `cargo check --all-targets` green.
    tx tree index = channel_id, ChannelTree index = channel_id alone, bridge_user_to_key_id removed.
  - W3-consensus: redesign signature_aggregation + ChannelLeaf to B2=A (the channel holds the member-keyID set root, and
    all member keyIDs clear the threshold). ← consensus signature rule. Threat-model recommended.
    → **incomplete (only mechanical migration done)**: moved the supply source of (pk_set_root, threshold) from ChannelLeaf to a `KeyLeaf`
    witness, but the inclusion binding to KeyTree (§3 2b) and the member binding to member_key_ids_root
    (§3 2a) await the key_tree_root PI wiring (design §6.4). `SECURITY: TODO` is noted at the relevant sites
    (update_channel_tree.rs / sig_agg_step.rs / sig_batch_step.rs). Until the binding is in, KeyLeaf is
    prover-chosen, and the soundness of signature verification is not restored to the old-model level.
  - Potential bug (pre-existing, to confirm): from_u64_slice width mismatch in channel PIs (&values[0..2] vs 1 word).

---

# Task: Lean safety proof of doc/architecture-audit/abstract.md (2026-06-10)

Status: DONE (2026-06-10)

## Plan

- [x] Document the threat model / trust base explicitly (doc/architecture-audit/lean-safety-proof.md)
- [x] `doc/architecture-audit/ChannelSafety.lean` — formalize and machine-verify the 4 properties of abstract.md §0 in Lean 4 (core, no mathlib)
  - [x] authorization (§4.1): all-signed + good-node discipline ⇒ a confirmed state is valid (`authorization`)
  - [x] signature atomicity (§3.4 invariant): transfer authorization ⇒ confirm of the post-subtraction state (`atomicity_no_loss_shift` — making the assumption explicit and noting it)
  - [x] double-spend / illegal-mint prevention (§4.2): supply conservation (`exec_conservation`) + nullifier uniqueness (`no_double_settlement`, M1-restricted)
  - [x] solvency (§4.3): balance-non-negative invariant (`exec_nonneg`) + state-valid preservation (`channelTx/interSend_preserves_validity`)
  - [x] close game: `close_no_overdraw` / `close_boundary_no_double_spend` / aggregate `exec_exit_bound`
  - [x] challenge game (§3.5.3): `challenge_latest_wins` (stale close impossible)
  - [x] sanity check: §9 Sanity (prove assumption satisfaction in both the all-good and the good-1/adversarial-2 configurations)
- [x] Compile-verify with `lean ChannelSafety.lean` (Lean 4.10.0, exit 0, 0 warnings, no sorry/axiom)
- [x] Adversarial review by a separate subagent → 18 findings. 4 reflected as code fixes, model limits M1–M4 noted in the header + commentary

## Assessment (Record Outcomes)

- The safety side of the 4 properties is all machine-verified under trust base A1–A4 / abstractions M1–M4.
- The essential gaps revealed in review (M1: 1-block-1-tx abstraction, M2: provenTotal–ledger unconnected,
  M3: OneStatePerVersion is a discipline assumption, M4: receiver-side/late-claim individual management unmodeled) are
  recorded in lean-safety-proof.md with strengthening proposals. The 2 recommended additions to the spec abstract.md are also noted in the same document.

## Lessons (equivalent to doc/tasks/lessons.md)

- Lean core's `omega` does not recognize atoms through `abbrev Amount := Int` (same in 4.30-rc2).
  In formalization, avoid type aliases and use plain `Int`/`Nat`.
- Unless you write the distinction between "proved" and "made the assumption explicit" in the docstring, formalization rather breeds overconfidence.
  Adversarial review was especially effective at detecting this overclaiming.

---

# Task: Create abstract2.md (Lattice version) + Lean safety proof v2 (2026-06-11)

Status: DONE

- [x] doc/architecture-audit/abstract2.md — reflect the LATTICE spec diff over v1 in a MECE manner
  (Regev confidentiality / H1/H2 two-part state / channelUpdateZKP / signature target hash(H1,H2) / close withdrawal ZKP,
  safety extended to 5 properties: + confidentiality)
- [x] doc/architecture-audit/ChannelSafety2.lean — v2 proof reusing v1 via import
  (Lean 4.10, exit 0, 0 warnings, no sorry/axiom. 2-step build:
  `lean ChannelSafety.lean -o ChannelSafety.olean` → `LEAN_PATH=$PWD lean ChannelSafety2.lean`)
  - New theorems: bridgeToV1 (theoremization of the v1 atomicity assumption), applyReceive/receive_preserves_validity,
    interChannel_conservation(_bound), challenge_latest_wins2, end_to_end_close_safety2
- [x] 2nd adversarial review (16 findings, CRITICAL 6) → 4 reflected in code, M4 revised + M5–M7 added
- [x] doc/architecture-audit/lean-safety-proof2.md — commentary / theorem correspondence table / findings record

## Assessment

- The major improvements of v2 (structural atomicity / receiver-side conservation law) are machine-verified.
- **Found 4 spec-level unspecified points (revision recommended for abstract2.md)**:
  1. M7: a race where a signed-but-unsettled subtraction state wins at close (an L1 inclusion proof requirement is needed)
  2. The retry / version reassignment semantics on transfer failure are undefined (contradicts OneStatePerVersion)
  3. H1 includes balanceProof but the proof is not generated at signing time (the commit target of H1 should be specified)
  4. The collision of the H2=0 reserved value with tx_tree_root / domain separation is unspecified
- The main target of v3 formalization: the signature model / tx-tree parameterization of Apply (M6), receiver replay prevention (M4 revised).

## Addendum (2026-06-11, spec revision per user instruction)

- [x] Resolved finding 5 (M5): make `channelTxZKP` (intra-channel range ZKP) mandatory in abstract2.md §2.2/§3.2.
  Lean: introduced `ChannelTxProven` + replaced the `channelTx2_preserves_validity` assumption + `claims_exactly_fill_cap`.
- [x] Resolved finding 3: bind state↔balanceProof with `settledTxChain` (a settle-history hash chain).
  H1 commits to the chain without including the proof, the circuit exposes the chain as a public input, and L1 cross-checks at close/challenge.
  Since the nullifier includes block_number and is uncomputable at signing time, it is not adopted (base-layer double-settle prevention continues).
  Lean §9: `chainOf_injective` / `chain_binding_resolves_attachment`.
- Remaining spec issues: M7 (signed-but-unsettled race), retry/version semantics, H2 domain separation.

## Threat model (summary — details in lean-safety-proof.md)

- Adversary: channel members up to 2/3, BP, outsiders. SPHINCS+ forgery / ZKP forgery / L1 censorship are the trust base (assumptions).
- What is protected: the safety side of the 4 properties of abstract.md §0 (authorization / no-double-spend / solvency / stale-close prevention).
- liveness (timeout reach / L1 inclusion) is explicitly out of model.
