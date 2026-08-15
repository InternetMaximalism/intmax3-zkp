# Threat model + design: N-of-N authorization of `tx_tree_root` in the validity proof

Status: **DESIGN ONLY — no code written.** Written against `feat/falcon-poseidon-sig` @ `69a8599`.

Owner rule being implemented: *a signature over `tx_tree_root` is the ACCOUNT's signature — the
whole channel's — and must be N-of-N.* Block **posting** is deliberately 1-of-N and is explicitly
NOT a security control; all security rests on the local ZKP chain and withdraw-time ZKP
verification.

---

## 0. Re-verification of the defect (independent, not assumed)

Every link was opened and read. All five hold. The defect is real.

| # | Claim | Verified at | Verdict |
|---|---|---|---|
| 1 | IMSB message carries `tx_tree_root` next to a **singular** signer identity | `src/common/channel.rs:377-390` (`bp_member_slot: u8`, `bp_pk_g: Bytes32`), digest `:393-412`, domain `SMALL_BLOCK_DOMAIN = 0x494d5342` at `:30` | CONFIRMED |
| 2 | Exactly one IMSB signature per signing block, one accumulator, one pubkey | `src/circuits/validity/block_hash_chain/update_channel_tree.rs:933` (comment), `:950` `let should_verify_sig = should_update;`, fold at `:1022-1027` | CONFIRMED |
| 3 | Verified by ONE recursive `ListCircuit` proof | `src/circuits/validity/block_hash_chain/validity_circuit.rs:236` (`add_proof_target_and_conditionally_verify(list_vd, …)`), `C == final.bp_sig_chain` at `:240-245` | CONFIRMED |
| 4 | `FalconAggCircuit` appears nowhere under `src/circuits/validity/` | `grep -rn FalconAggCircuit src/` → hits only in `falcon_sig/`, `wallet_core.rs`, `circuits/channel/close_circuit.rs`. Zero under `src/circuits/validity/` | CONFIRMED |
| 5 | Base layer never references the channel's N-of-N | `grep -rniE "signature\|falcon\|pk_g\|cosign\|h2_tag\|imch" src/circuits/balance/ src/circuits/withdraw/` → **0 hits**. `send_tx_circuit.rs:285-289` says semantic correctness "is enforced off-circuit at co-sign time" | CONFIRMED |

Two additional facts I found that the brief did not state, and that change the design:

**(A) The N-of-N signature the owner wants ALREADY EXISTS — one layer up, and the validity circuit
simply never looks at it.** `ChannelState.h2_tag` *is* the small block's `tx_tree_root`
(`src/common/channel.rs:549-553`: "the own small block's `tx_tree_root` for an inter-channel
send"), and `h2_tag` is inside the IMCH signing preimage (`:598`, digest fn at `:579`). That preimage is cosigned N-of-N
off-circuit: `validate_all_member_signatures` requires exactly `member_count` signatures, one per
slot (`src/common/channel.rs:1452-1468`, `:1485-1497`), and real Falcon verification over all of
them runs in `wallet_core::verify_all_signatures` (`src/wallet_core.rs:873-899`). The docstring at
`channel.rs:565-568` states the intent outright: these signatures "ARE the three-member `hash(H1,
H2)` signatures of abstract2 §3.1". So the protocol *specifies* N-of-N over `tx_tree_root`; the
divergence is that **the base-layer proof never verifies it**, and instead verifies a 1-of-N IMSB
signature that no honest-participant check can substitute for.

**(B) There is no production IMSB signing path at all.** The only place a real IMSB Falcon
signature is produced is the test witness generator
(`src/circuits/test_utils/block_witness_generator.rs:963-980`, `:1044-1050`). Production emits
**stub bytes**: `structural_small_block_sigs` returns `signature: vec![1 + i]`
(`src/wallet_core.rs:1941-1949`), with `aggregated_signature_proof: vec![9,9]` and
`confirmation_proof: vec![8,8]` (`:2204-2206`). This is not "change 1 signature to N" — it is
"build the real IMSB signing round for the first time, and make it N". Size accordingly (§8).

---

## 1. What the code enforces today, end to end

The in-circuit statement bound to a signing block, and nothing more:

1. `channel_id` and `tx_tree_root` in the IMSB digest are **not** witnessed — they are the block's
   own targets (`update_channel_tree.rs:793-800`), so a signature can never be verified over a
   different root than the one applied (`small_block_message.rs:11-15`, `:129-158`).
2. `tx_tree_root != 0` whenever a signature is applied (`update_channel_tree.rs:953-959`, detail2
   §C-2).
3. `msg_fields.bp_member_slot == i`, the slot that actually transitioned (`:961-977`).
4. `MemberLeaf { pk_g = bp_pk_g, pk_b, regev_pk_digest }` is included at slot `i` of
   `prev_user_leaf.member_pubkeys_root` (`:1000-1016`) — so the signer is *a* registered cosigner.
5. `(signed_digest, bp_pk_g)` is folded into `bp_sig_chain` (`:1022-1027`); the span-level
   `ListCircuit` proof re-derives the same chain and verifies one real Falcon signature per folded
   entry (`src/falcon_sig/list.rs:123`, `:233`); `validity_circuit.rs:229-245` binds
   `C == final.bp_sig_chain`, gated on the **computed** chain being nonzero (not a prover flag).

Every other IMSB field — `small_block_number`, `prev_small_block_root`, `state_commitment_root`,
`medium_epoch_hint`, `close_freeze_nonce` — is a free witnessed target with a 32-bit range check
and nothing else (`small_block_message.rs:101-127`). None appears in `UpdateUserPublicInputs`
(`update_channel_tree.rs:66-85`); `block_step.rs` threads only `prev/new_bp_sig_chain`
(`:195-200`, `:543-548`).

So the base layer's authorization predicate is exactly:

> "some key registered in this channel's genesis member tree signed this `tx_tree_root`."

That is 1-of-N. The intended predicate is N-of-N.

---

## 2. Threat model, part 1 — what one malicious cosigner can do TODAY

### 2.1 The attack, step by step

Attacker: a single registered cosigner of channel `c`, slot `j`, holding their own Falcon key and
the channel's last `prev_private_state`. Per the owner, **every cosigner holds the last private
state** — they all keep it. So the attacker set is *every member of every channel*.

| Step | What is needed | What blocks it | Cite |
|---|---|---|---|
| 1. Build a spend proof draining the channel's assets | `prev_private_state` preimage only. `SpendWitness` = `{tx_nonce, prev_private_state, transfers, before_balances, asset_merkle_proofs, sent_tx_merkle_proof}` — **no key target, no signature target** | nothing | `src/circuits/balance/spend_circuit.rs:111-119`, `:261-291` |
| 2. Wrap it in a send-tx proof | prior balance proof + public-state chaining. No member signature referenced | nothing | `send_tx_circuit.rs:219-317` |
| 3. Get `tx_tree_root` into a settled block | one IMSB Falcon signature by slot `j`; member-tree inclusion at slot `j` | **only** that slot `j` be registered — 1-of-N | `update_channel_tree.rs:950`, `:961-977`, `:1000-1016` |
| 4. Withdraw | single-withdrawal proof re-verifies the balance proof and merkle-verifies the tx under `account_state.send_leaf.tx_tree_root` — satisfied by step 3 | nothing | `src/circuits/withdraw/single_withdrawal_circuit.rs:425-495` |
| 5. Get paid on L1 | `finalizedStateRoots[extCommitment]` must hold | satisfied by a legitimately finalized block | `contracts/src/IntmaxRollup.sol:1638` |

Two would-be second factors do not fire:

- The IMPW authorization gate at `IntmaxRollup.sol:1512-1516` (native) / `:1560-1564` (ERC-20) only
  applies **when `w.auxData != bytes32(0)`**. `aux_data` is copied from the attacker-chosen
  `transfer.aux_data` (`single_withdrawal_circuit.rs:531`). Set it to zero and the gate is skipped.
- Setting `aux_data = 0` *also* makes the send fold nothing into `settled_tx_chain`
  (`send_tx_circuit.rs:293`, `do_push = is_valid AND aux_nonzero`), so the close-time chain
  equality in `close_circuit.rs` never sees the theft either. The two evasions are the same knob.
- `state_update_verifier.rs` — which *does* check the IMCH N-of-N and would catch this — is 3,375
  lines of **native Rust with zero `CircuitBuilder` references**. It is nobody's obligation: not
  invoked by any circuit, the withdraw path, or any contract. A prover who skips it produces an
  equally valid proof.

### 2.2 Bounds

- **How much:** the entire channel balance reachable from the private state the attacker holds —
  i.e. all other members' in-channel funds, up to the channel's escrowed `channel_fund`. Not
  bounded by the attacker's own balance slot; the spend circuit's only economic constraint is
  `prev_balance >= amount` per asset-tree leaf (`spend_circuit.rs:141-149`), and the attacker
  controls which leaves.
- **Whose funds:** the other N−1 cosigners' and all delegates' of the same channel. Not
  cross-channel: `channel_id` is a block-level target, not witnessed
  (`update_channel_tree.rs:793-794`), so an IMSB signature for channel A cannot be applied to
  channel B.
- **Detectable:** yes, after the fact and unstoppably. The victims see their channel drained when
  they next reconcile; `state_update_verifier` would have rejected the transition had it been
  consulted. There is no on-chain challenge that undoes a finalized withdrawal, and
  `submitSpecialClose` — the designed anti-BP remedy — is permanently disabled
  (`contracts/src/ChannelSettlementManager.sol:1012-1014`, `revert SpecialCloseDisabled()`).
- **Practical friction, not a control:** `postBlockAndSubmit` is permissioned
  (`IntmaxRollup.sol:839-841`), so the attacker needs a whitelisted producer to include their
  sub-block. That producer **cannot filter on channel consent** — the N-of-N signature is not
  visible on-chain or in the block. So this is friction against outsiders, zero protection against
  a cosigner who is (or can reach) a producer.

### 2.3 Severity

Total loss of channel funds by any single member, with no in-protocol recovery. The design docs
specify the opposite (`doc/architecture-audit/abstract2-1.md:33`, `:405`: "no unilateral path" /
"no unilateral withdrawal"). This is a spec/implementation divergence in the direction of
unsoundness, not a missing nice-to-have.

---

## 3. What the fixed design must guarantee

**G1 (the fix).** A `tx_tree_root` is applicable to channel `c`'s base-layer state only if
`member_count` distinct registered cosigners of `c` each produced a real Falcon signature over a
message that binds that exact `tx_tree_root` to that exact channel — verified **in-circuit**, in
the validity proof, not off-circuit.

**G2.** `signer_count` is bound to the channel's authenticated `member_count` — the count must be
authenticated by something the validity circuit can actually see, not by an off-circuit record.

**G3.** The signing key vector is bound to the channel's registered `member_pubkeys_root`, per
slot, so no non-member key and no duplicated key can be counted.

**G4.** No existing check is weakened. In particular the `tx_tree_root != 0` gate, the member-tree
inclusion, the Regev pubkey digest recompute, and the computed-not-flagged gating of the chain
proof all survive verbatim.

**G5.** Posting stays 1-of-N and stays explicitly non-security.

---

## 4. THE BLOCKER — and it is bigger than it looks

> **`member_count` is not authenticated anywhere the validity circuit can see it.**

- `ChannelLeaf` = `{ index, prev, send_tree_root, member_pubkeys_root }`
  (`src/common/trees/channel_tree.rs:94-105`); leaf preimage `:230-239`. **No `member_count`, in
  any form.** `grep member_count src/circuits/validity/block_hash_chain/*` → **0 hits across all 9
  files.**
- `member_count` is authenticated exactly once, at registration, as a **keccak limb of the
  reg-chain** (`src/common/channel_registration.rs:186-201` ↔ `IntmaxRollup.sol:1115-1128`). It is
  consumed there (`channel_reg_step.rs:361-374` range-checks `2..=16`, `bp_member_slot <
  member_count`) and then **discarded** — deliberately not carried into the leaf
  (`channel_reg_step.rs:196-204`, `:444-449`).
- It is not recoverable from `member_pubkeys_root` naively: padding slots are `MemberLeaf::default()`
  (all-zero triple, `key_tree.rs:100-102`), and **no code anywhere ever opens an empty member
  slot** — `MemberLeafTarget::empty_leaf` (`key_tree.rs:152-156`) has exactly one reference in the
  repo: its own definition.

So G2 cannot be satisfied by reading a field. Three ways out.

### M1 — add `member_count` to `ChannelLeaf`

Direct and self-evidently sound. Cost: the leaf preimage changes → every leaf hash changes → the
account tree root changes → the registration step, `update_channel_tree`, `public_state.rs:537,562`,
`block_step`, and every fixture move. **Not disqualifying** (see §10: a redeploy is mandatory
anyway), but it touches the most surface.

### M2 — derive occupancy by proving slot `k` empty

Prove slots `0..k` occupied and slot `k` is the empty leaf. No leaf change. But it leans on
registration's left-packing (`channel_reg_step.rs:375-413` thermometer over `active`) as an
unstated premise, and needs a special case at `k == MAX_COSIGNERS`. Weaker than it looks.

### M2′ — **RECOMMENDED** — recompute the whole member tree root in-circuit

Witness all 16 `MemberLeaf`s, recompute `member_pubkeys_root` from them exactly as
`channel_reg_step` does (`compute_member_tree_root`, `channel_reg_step.rs:588-609`), and connect
the result to `prev_user_leaf.member_pubkeys_root`. Then:

- Inactive slots (thermometer over `signer_count`) are asserted equal to the empty leaf.
- Active slots' `pk_g` are connected to the agg proof's pk-list entries.
- **Occupancy == `signer_count` becomes an in-circuit theorem with no premise about left-packing:**
  if a real member sits at slot 5 and the prover claims `signer_count = 3`, they must witness slot 5
  as the empty leaf, which changes the recomputed root and fails the connect.
- **G3 and signer-distinctness come free.** `FalconAggCircuit` deliberately does *not* enforce
  signer distinctness — "the same leaf proof may be placed in two slots… Deduplication /
  pk-in-member-set checks are CONSUMER obligations" (`src/falcon_sig/agg.rs:81-83`), which is why
  `close_circuit.rs:849-872` needs a whole indexed-Merkle insertion chain. Here, slot-wise
  connection to a *fixed* tree makes duplicates unrepresentable, and L1 already enforces the
  registered keys are nonzero and pairwise distinct (`IntmaxRollup.sol:1097-1107`). **We get the
  close circuit's distinctness guarantee without the indexed-Merkle machinery.**
- Cost: 16 leaf Poseidons + 15 tree Poseidons = 31, replacing the current 1 leaf hash + 4 inclusion
  hashes. ~26 extra Poseidon per block. Negligible.
- Cost trap to avoid: the existing per-slot Regev recompute is 2×`REGEV_N` = **4,096 range checks**
  (`update_channel_tree.rs:979-991`). Doing that for 16 slots is 65,536 range checks and would blow
  the circuit up. **Keep the Regev recompute for the bp slot only** (its purpose — binding the bp's
  Regev key — is unchanged); witness the other 15 slots' `regev_pk_digest` as free
  `PoseidonHashOut`s, authenticated by the root recompute. Do not weaken the bp-slot check (G4).

### M2′ has one prerequisite, and it must be named

`member_pubkeys_root_for` builds the tree over `active = member_count + delegate_count`
(`channel_reg_step.rs:102-114`), and the in-circuit thermometer uses `active_count`, not
`member_count` (`:375-393`). So occupancy == `member_count + delegate_count`, and M2′ derives
`active`, **not** `member_count`. For channels with `delegate_count > 0` this would force delegates
to sign — contradicting the delegate design (`constants.rs:45-52`, `key_tree.rs:16-21`: "Delegates
are NEVER in this tree").

Today `delegate_count = 0` is a **policy, not a constraint**: "Registration-producing paths emit
`delegate_count = 0`; legacy 16-slot records may carry delegates within the same 16 slots"
(`channel_registration.rs:88-97`, `channel_reg_step.rs:95-101`). The reg circuit range-checks
`active <= 16` but never forces `delegate_count == 0` (`:376-386`).

**Required companion change: assert `delegate_count == 0` in `channel_reg_step`.** This is a
*strengthening* (§G4 is satisfied — nothing is weakened), it makes `occupancy == member_count` an
in-circuit theorem, and it codifies the Option-B policy that the comments already claim. It rotates
the `channel_reg_hash_chain` VK — which is rebuilt anyway (§8). **Verify before implementing that
no live registered channel has `delegate_count > 0`;** if one does, it must be drained (§10).

---

## 5. The design

### 5.1 The signed message

Keep the IMSB digest (41 limbs, keccak, already mirrored limb-for-limb in-circuit). Do **not**
switch to the IMCH digest: recomputing IMCH in-circuit means witnessing the full 80-limb
multi-token amount vector plus `balance_state.h1()` (`channel.rs:582-600`) — the close circuit pays
that (`close_circuit.rs:651`) and sits at degree 2^17. The IMSB digest already binds
`tx_tree_root` structurally, which is the thing the owner's rule is about.

**Change to `SmallBlockRootMessage` (`src/common/channel.rs:377-390`):**

```
- pub bp_member_slot: u8,      // MOVE OUT of the signed preimage
- pub bp_pk_g: Bytes32,        // MOVE OUT of the signed preimage
```

They **must** leave the preimage: `FalconAggCircuit` aggregates N signatures over **one shared
message** (`FalconAggWitness { message, active }`, `agg.rs:199-221`; gated message equality at
`agg.rs:407-411`). A per-signer identity in the preimage makes N distinct digests, which the
aggregate cannot represent.

**Decision D2 (owner):** keep them as *unsigned transport fields* on the struct, or bake the poster
identity into the signed message so all N authorize the poster too?
**Recommendation: unsigned transport fields.** Posting is explicitly not a security control (G5);
signing the poster identity means any poster change forces a fresh N-of-N collection round — a pure
liveness cost for zero security gain. Keep `bp_member_slot` / `bp_pk_g` on the struct, exclude them
from `signing_digest()`, and document them `// INTENTIONALLY UNSIGNED: posting identity, not a
security control.`

Nothing is lost. Today `bp_pk_g` is bound to slot `j` of the member tree; under M2′ **all 16 slots**
are bound via the root recompute — strictly stronger. And the constraint `bp_member_slot == i`
(`:961-977`), whose job was to tie the folded identity to the transitioning slot, is superseded by
the `channel_id`-level binding, which was always the real tie.

New preimage (33 limbs):
`keccak(IMSB ‖ channel_id ‖ small_block_number ‖ prev_small_block_root ‖ tx_tree_root ‖
state_commitment_root ‖ medium_epoch_hint ‖ close_freeze_nonce)`.

`small_block_message.rs` (`SmallBlockMessageFields`, `SmallBlockMessageFieldsTarget`) drops the two
fields in lockstep; the golden-vector test at `:196-229` is the drift guard and must be updated in
the same commit.

### 5.2 Where the recursion goes — `AggListCircuit`

A validity span covers many blocks. `FalconAggCircuit` binds **one** message, so one agg proof per
signing block is needed. Two placements:

- **(P-a) Verify the agg proof inside `update_channel_tree`, per block.** Adds a recursive verifier
  of a 2^14 / 137-PI proof to the per-block circuit. Risks pushing `update_channel_tree` — and
  therefore `block_step`, `block_hash_chain`, `ValidityCircuit` — past 2^16, which is precisely
  what Phase 3 fought to avoid (`doc/tasks/falcon-sig-phase3-notes.md:16-18`).
- **(P-b) RECOMMENDED — swap `ListCircuit`'s *step* to consume an agg proof, keep everything else.**
  Today `ListStepCircuit` verifies one Falcon signature directly in-circuit
  (`src/falcon_sig/list.rs:123`). Define `AggListStepCircuit`: recursively verify **one
  `FalconAggCircuit` top proof at a constant VK** and fold its statement. The cyclic wrapper
  (`ListCircuit`, `list.rs:233`), the validity circuit's conditional-verify structure, and the
  `C == final.chain` binding are all **unchanged in shape**.

P-b is not a new aggregation — it composes two primitives already in the tree, and precedent says
the shape survives: the Phase-3 step grew 2^12 → 2^16 while the cyclic wrapper stayed 2^14 and
`ValidityCircuit` stayed 2^16 (`falcon-sig-phase3-notes.md:16-18`). A recursive verify (~2^13–2^14)
is *smaller* than the current 2^16 direct-Falcon step, so the step likely shrinks.

Watch item: `ListCircuit::new` byte-asserts its `CommonCircuitData` against a fixed template in a
**release-mode** `assert_eq!` (`src/utils/hash_chain/cyclic_chain_circuit.rs:76`). The fold tuple
widens (below), so this template must be re-derived, deliberately, in Phase 2 — not patched away.

### 5.3 The per-block fold

Today: `leaf_target(builder, &signed_digest, &bp_pk_g)` → `chain_step_target`
(`update_channel_tree.rs:1022-1027`).

New tuple: **`(signed_digest, signer_count, pk_list_digest)`**, where
`pk_list_digest = Poseidon(⟨16 pk_g entries, padding slots zero⟩)`.

- `update_channel_tree` computes `pk_list_digest` from the 16 witnessed member leaves it already
  uses for the M2′ root recompute.
- `AggListStepCircuit` recomputes the identical digest from the agg proof's PI slice
  `[FALCON_AGG_PK_LIST_OFFSET .. +128]` (`agg.rs:160-162`), connects the agg message PI
  `[0..8]` to `signed_digest`, and the agg count PI `[8]` to `signer_count`.

That closes the loop: the block says which keys and how many; the chain step proves those exact
keys really signed that exact digest. Padding slots are *constrained* zero inside the agg circuit
(`agg.rs:440-443`, `is_right_present * limb`), so the two digests agree on padding without extra
work.

### 5.4 Constraints added to `update_channel_tree`

Inside the existing `should_verify_sig = should_update` branch:

1. `signer_count` witnessed; thermometer `active_bits[i] = (i < signer_count)` (reuse
   `lt_const_threshold`, `channel_reg_step.rs:392`).
2. `signer_count >= 2`: keep the registration floor. **Note** `close_circuit.rs:538` only asserts
   `>= 1` in-circuit and enforces `>= 2` natively (`:909-914`) — do not repeat that gap here;
   assert `2 <= signer_count <= MAX_COSIGNERS` in-circuit.
3. 16 witnessed `MemberLeaf` targets; inactive slots asserted equal to the empty leaf.
4. Active slots' `pk_g` connected to the folded `pk_list_digest` inputs.
5. Recompute the member tree root and connect it to `prev_user_leaf.member_pubkeys_root`.
6. **Keep verbatim (G4):** the `tx_tree_root != 0` gate (`:953-959`); the bp-slot Regev digest
   recompute with its 4,096 range checks (`:979-991`); the computed-not-flagged gating.
7. **Drop:** `msg_fields.bp_member_slot == i` (`:961-977`) — the field leaves the preimage;
   superseded by the root connect + `channel_id` binding.

### 5.5 `ValidityCircuit` — minimal delta

`ValidityCircuit::new(block_hash_chain_vd, list_vd)` (`validity_circuit.rs:195`) becomes
`new(block_hash_chain_vd, agg_list_vd)`. Structure at `:229-245` is **unchanged**: gate on computed
`final.bp_sig_chain != 0`, conditionally verify, assert `C == final.bp_sig_chain`. Rename the field
to `sig_chain` for honesty (it is no longer a *bp* chain). Six call sites move
(`src/bin/generate_e2e_fixture.rs:120`, `src/bin/generate_c2c_fixture.rs:717`,
`src/wallet_core.rs:4959`, `tests/e2e.rs:497`, `tests/inter_channel_unified_e2e.rs:561`,
`tests/small_block_sig_validity.rs:219`, plus the unit test at `validity_circuit.rs:369`).

**`FalconAggCircuit` itself is NOT modified.** That is deliberate and load-bearing: its VK stays
fixed, so the close and cancel-close circuits — which bake `agg_vd` as a build-time constant
(`close_circuit.rs:461-470`) — **do not rotate**.

---

## 6. Threat model, part 2 — new attack surface N-of-N introduces

### 6.1 Liveness — **the fix costs nothing here, and this is the key finding**

The intuition "N-of-N means any member can now block a small block by withholding" is **already
true today**, before any change. A small block accompanies a `ChannelState` transition, and every
transition verifier calls `verify_next_state_signatures`
(`state_update_verifier.rs:1837-1843`) → `validate_all_member_signatures`
(`channel.rs:1452-1468`), which requires **exactly `member_count` signatures, one per slot**
(`:1485-1497`); `wallet_core::verify_all_signatures` (`:873-899`) rejects any missing slot, and the
CLI dies if not N-of-N (`src/bin/channel_member.rs:4560-4574`).

So: **one unresponsive member already halts the channel.** The fix moves an existing N-of-N
requirement from an off-circuit check into the proof. It adds **zero** new liveness exposure.

What it does *not* do is fix the pre-existing liveness posture, which is bad and should be recorded
as such: no forced-transaction queue exists (`ForcedTransaction` / `forced_tx`: **zero occurrences**
in `src/`, `contracts/src/`, `api/`), despite `abstract2-1.md:370` prescribing force-include on
censorship; and the designed remedy `submitSpecialClose` is disabled
(`ChannelSettlementManager.sol:1012-1014`). Out of scope here; flagging it.

### 6.2 Stale-signature replay — **LOUD: this design does not close it, and N-of-N makes the stolen artifact more valuable**

Nothing in-circuit chains a small block to its predecessor:

- `small_block_number` and `prev_small_block_root` are free witnesses
  (`small_block_message.rs:112`, `:117`), referenced nowhere in `update_channel_tree.rs` or
  `block_step.rs`. There is **no** `n+1` constraint and no chaining constraint.
- `prev_small_block_root` is never even *computed*: the only producer writes `Bytes32::default()`
  (`wallet_core.rs:2197`). It is a dead field in the preimage.
- `medium_epoch_hint` is unconstrained in-circuit; off-circuit it is compared only to
  `SignedSmallBlock.medium_block_number` (`state_update_verifier.rs:1879-1883`) — an *unsigned*
  envelope field with no in-circuit or Solidity twin. A digest signed "for epoch 3" is equally valid
  in epoch 3000.
- `close_freeze_nonce` is unconstrained in the validity circuit. The era fence is a close /
  cancel-close mechanism (`ChannelSettlementManager.sol:903`, `:932-937`;
  `cancel_close_pis.rs:111-120`), **not** a block-production mechanism. Worse, the import-side
  off-circuit check compares the message's field to *itself*
  (`state_update_verifier.rs:778-786`) — a tautology.

The only per-block uniqueness in force is `prev_user_leaf.prev != block_number`
(`update_channel_tree.rs:845-848`), which blocks two updates of the same channel *within one medium
block* — and nothing more. **Re-applying the identical `tx_tree_root` in a later medium block is
not blocked by anything in `update_channel_tree` / `block_step`.** The defences live in downstream
nullifiers and a CLI-local replay ledger (`src/bin/channel_member.rs:4399-4404`, `:4476-4480`).

Effect on this design: N-of-N **does** close the stated hole (a lone member cannot obtain N
signatures over a theft root). It does **not** stop a collected N-of-N signature set from acting as
a bearer token for `(channel_id, tx_tree_root)` forever, replayable into a later block. That is a
different bug (double-application of an *honest* tx) but it is serious, and after this change the
artifact worth stealing is a full N-of-N set rather than one signature.

**Recommended companion fix, and it needs an owner decision (D3).** The natural binding is the
channel leaf's `index`, which increments by exactly 1 per update (`update_channel_tree.rs:906-914`)
and is already in the leaf — no format change. But `ChannelState.small_block_number` also
increments on *in-channel* updates (`wallet_core.rs:2683`, `:3064`), so it drifts from `index` and
cannot simply be equated. Options:

- **(D3-a)** Assert `msg_fields.small_block_number == prev_user_leaf.index`, and change the wallet
  so `small_block_number` advances only on base-block-producing transitions. Cheapest in-circuit;
  a semantic change to the wallet, and it touches the IMCH preimage's meaning.
- **(D3-b)** Add `last_signed_small_block_number` to `ChannelLeaf` and assert strict monotonicity.
  Sound and semantics-preserving; costs the leaf format change (same class as M1).
- **(D3-c)** Defer as a separate finding; rely on downstream nullifiers.

**Recommendation: D3-a, in a phase of its own after N-of-N lands** — the two changes should be
falsifiable independently. If the owner wants one shot at the leaf format, take **M1 + D3-b
together** and skip M2′; that is the "do it once, do it properly" branch.

### 6.3 Signer-set changes mid-flight

Currently a non-issue, and the reason is worth stating because it is fragile:

- Registration is **one-shot**: `channel_reg_step` asserts the prior leaf equals
  `ChannelLeaf::default()` (`:185-194` native, `:435-442` in-circuit). A channel registers once.
- `member_pubkeys_root` is written once and copied verbatim on every transition
  (`update_channel_tree.rs:917-923`, `:359-364`; `public_state.rs:537`, `:562`). **There is no
  join/leave/add-member path that touches it** — `join_delegate` exists only as prose
  (`wallet_core.rs:609`).
- Delegate "joins" rebuild the *wallet* height-10 tree (`wallet_core.rs:648-705`,
  `WALLET_MEMBER_TREE_HEIGHT = 10`), a different tree never compared to the registered root
  (`constants.rs:73-78`, `key_tree.rs:12-21`).

So the registered cosigner set is frozen at genesis, and `signer_count` derived from it (M2′) is
stable for the channel's lifetime. **In-flight blocks cannot straddle a signer-set change because
signer-set changes do not exist.** If a future PR adds membership mutation, M2′'s derivation and
this whole section must be revisited — record that as an invariant comment at the recompute site.

### 6.4 Interaction with `close_freeze_nonce` / the era fence

A collected N-of-N IMSB set survives a `requestClose()` / `cancelClose()` cycle, because the
validity circuit never inspects `close_freeze_nonce` (§6.2). The IMCH era fence
(`wallet_core.rs:3649-3653`) does not extend to this lane. This design does not change that either
way. Note the known availability bug T-7a — the wallet never increments
`ChannelState.close_freeze_nonce` (set 0 at genesis, `wallet_core.rs:696`, `:776`, copied forward
via `..prev.clone()`), so after one cancelled close, L1 expects era k+1 and the wallet can only
produce era k (`doc/tasks/close-detached-signing-design.md:323-330`, `:813-818`). Unrelated;
listed so it is not mistaken for fallout from this change.

### 6.5 Adversarial pass on the new construction

| Attack | Blocked by |
|---|---|
| Same key in two slots to reach `signer_count` | Slot-wise connect to a fixed member tree (§4 M2′) + L1 distinctness (`IntmaxRollup.sol:1097-1107`). Note the agg circuit alone would *not* block this (`agg.rs:81-83`) |
| Non-member key in the pk list | Root recompute connect to `prev_user_leaf.member_pubkeys_root` |
| Under-count (`signer_count` < true `member_count`) to exclude members | Excluded slot must be witnessed as the empty leaf → recomputed root ≠ leaf root |
| Zero pk_g at an "active" slot to alias padding | `agg.rs:68-72`: a zero `pk_g` needs a Poseidon preimage of the zero digest; padding leaves are unprovable (`agg.rs:853-859`). Plus L1 nonzero check |
| Turn off chain verification while applying a signed update | Gate is the **computed** `final.bp_sig_chain`, not a prover flag (`validity_circuit.rs:236-239`) — preserved verbatim |
| Cross-context reuse of an IMCH cosignature as an IMSB one | Distinct keccak domains, `IMCH` vs `IMSB` (`channel.rs:23`, `:30`); pinned by `wallet_core.rs:5298-5336` |
| Wrong-arity agg proof | Build-time `num_public_inputs == FALCON_AGG_PUBLIC_INPUTS_LEN` assert, mirroring `close_circuit.rs:468-471` |
| Two channel-leaf updates in one block leaving the second unsigned | Pre-existing single-fold invariant, flagged in-code at `update_channel_tree.rs:963-971`. **Carry that comment forward verbatim** |
| Replay of an honest N-of-N set into a later block | **NOT BLOCKED** — see §6.2 |

---

## 7. What this design does NOT fix

1. **IMSB replay across medium blocks / epochs / close eras** (§6.2). Needs D3.
2. **`aux_data = 0` disables both the IMPW L1 gate and the `settled_tx_chain` fold**
   (`IntmaxRollup.sol:1512-1516`, `send_tx_circuit.rs:293`). One knob, two evasions, still open
   after this change. Separate finding.
3. **The spend circuit has no key at all** (`spend_circuit.rs:261-291`). After this fix a lone
   member can no longer *settle* a forged root, but private-state possession still authors
   arbitrary spend proofs. N-of-N at the block layer is the containment; the balance layer stays
   unauthenticated.
4. **`state_update_verifier.rs` remains entirely off-circuit and unobligated** (3,375 lines, zero
   `CircuitBuilder`). This design promotes *one* of its checks into the proof. The rest still bind
   only honest participants.
5. **Liveness**: no forced-transaction path, `submitSpecialClose` disabled (§6.1).

---

## 8. Sizing — honest numbers

### 8.1 Circuits that change

| Circuit | Change | VK rotates? |
|---|---|---|
| `FalconAggCircuit` (`falcon_sig/agg.rs`) | **none — reused as-is** | **no** (so close / cancel-close VKs stay) |
| `ListStepCircuit` → `AggListStepCircuit` (`falcon_sig/list.rs:123`) | rewritten: recursive agg-verify + wider fold | yes (new circuit) |
| `ListCircuit` cyclic wrapper (`list.rs:233`) | shape unchanged; `CommonCircuitData` template re-derived (`cyclic_chain_circuit.rs:76`) | yes |
| `update_channel_tree` (`:1204`) | 16-leaf root recompute, thermometer, wider fold, drop `bp_member_slot == i` | yes |
| `channel_reg_step` | add `delegate_count == 0` (M2′ prerequisite) | yes |
| `BlockStepCircuit` (`block_step.rs:408`) | bakes the two above | yes |
| `BlockHashChainCircuit` (`block_hash_chain_circuit.rs:53`) | bakes block_step | yes |
| `ValidityCircuit` (`validity_circuit.rs:195`) | `list_vd` → `agg_list_vd` | yes |
| `WrapperCircuit` (`utils/wrapper.rs:36`) | bakes validity VK | yes |
| MLE VK (`utils/mle_prover.rs:33`) | derived | yes → **constructor arg** |
| deposit chain, balance family, withdraw family, close, cancel-close | unchanged | no (PI *values* move; `withdrawal_mle.json`'s `circuitDigest` held across the Phase-3 VK change — `falcon-sig-phase5-notes.md:47`) |

Every recursive verify in this repo bakes the inner VK as a build-time constant
(`src/utils/recursively_verifiable.rs:27`, `:43`, `:58`, `:81`), so the cascade is unavoidable.

### 8.2 Fixtures

~20 committed JSON files under `contracts/test/data/` regenerate — `mle_fixture.json`,
`vpi_fixture.json`, `block_fixture.json`, `lifecycle*.json`, `close_lifecycle*`, `c2c_lifecycle*`,
and the withdrawal/close/claim MLE fixtures. The documented regen loop is **10 generator runs, 27
files, ~15 min wall, peak RSS up to 39 GB** (`doc/tasks/falcon-sig-phase5-notes.md:28-52`, `:84-95`).
The 4 `sepolia_*` files are a declared STOP point (`:70-81`) — they are the live-deployment artifact
set. Also: a tracked orphan tree at `contracts/contracts/test/data/{mle_fixture,vpi_fixture}.json`
has no generator; confirm it is dead before regen.

Rust-side: **9 literal `SmallBlockRootMessage { … }` construction sites**, none using
`..Default::default()`, so all 9 break on the field change —
`src/wallet_core.rs:2192` (production), `:6953`, `src/common/channel.rs:2139`,
`src/circuits/channel/e2e_flow.rs:489`, `post_close_claim_circuit.rs:825`,
`post_close_claim_pis.rs:316`, `small_block_message.rs:205`,
`tests/inter_channel_unified_e2e.rs:448`, `tests/inter_channel_e2e.rs:508`.
`bp_member_slot` / `bp_pk_g` occur **182 times across 22 Rust files** and **54 times in
`contracts/**.sol`** — most Solidity hits are the *registration* preimage
(`IntmaxRollup.sol:1040-1047`), which does **not** change under this design (the poster identity
stays a registration field; only the *IMSB preimage* drops it). No committed JSON embeds a
serialized `SignedSmallBlock`, so the fixture burden is VK-driven, not schema-driven.

### 8.3 Contracts

**`IntmaxRollup` must be fully redeployed.** `mleVk` is written at exactly one site — the
constructor, `contracts/src/IntmaxRollup.sol:643` — and `grep -n "mleVk" src/IntmaxRollup.sol`
returns no setter. Only the *withdrawal* VK has an initializer, and it is set-once
(`initializeWithdrawalVk`, `:703-726`, `WithdrawalVkAlreadySet` latch at `:712`). `_copyWhirParams`
(`:663`) appends and documents "each VK slot is written exactly once" — it is not even re-runnable.

Redeploying changes the CREATE2 address and hence the derived `ChannelSettlementManager` address
baked into close fixtures — a known loop (`doc/tasks/regen-and-redeploy-runbook.md:30-38`).

### 8.4 Proving time

Measured baselines (`falcon-sig-phase3-notes.md`, `falcon-sig-phase2_6-notes.md`, M-series / 36 GB):

| Item | Today | After |
|---|---|---|
| signature work per signing block | 1 Falcon sig in one 2^16 list step: **1.89 s** | `FalconAggCircuit::prove` for N sigs: N × 1.83 s leaf + ~0.54 s/level lift. **N=2 ≈ 6 s; N=16 ≈ 37 s** (16-sig tree measured at 36.9 s, 4.99 GB) |
| chain step | 2^16 direct-Falcon step, 1.89 s, 3.51 GB | recursive agg-verify step, est. 2^13–2^14, **~0.5–1.5 s** (likely *cheaper*) |
| `ValidityCircuit` | degree 2^16; `test_validity_circuit` 41 s / 7.34 GB; `small_block_sig_validity` 50 s / 7.39 GB | structure unchanged; **must be measured, not assumed** |
| `generate_e2e_fixture` (chain+validity+wrapper+MLE) | 50 s / 5.97 GB | + (N−1) × ~1.8 s per signing block |

**Net honest number: per signing block, signature proving goes from ~1.9 s to ~6 s (N=2) or ~37 s
(N=16) — roughly 3× to 20×.** For a span of B signing blocks it is B × that, and it is
embarrassingly parallel across leaves (the 16 leaf proofs are independent). Peak RSS for the agg
tree is 4.99 GB, well inside 36 GB.

**The unmeasured risk is degree.** Swapping a 16-PI cyclic proof for a 137-PI one
(`FALCON_AGG_PUBLIC_INPUTS_LEN = 137`, `agg.rs:162`) plus the 16-leaf root recompute could move
`update_channel_tree` or `ValidityCircuit` past 2^16, which is more than a VK-value change — it
changes the MLE wrapper's shape. Phase 3 explicitly preserved this and there is **no** release-mode
`CommonCircuitData` assert protecting `ValidityCircuit` (only `ListCircuit` has one,
`cyclic_chain_circuit.rs:76`). **Phase 1 exists to measure this before anything else is built.**

### 8.5 What does not exist yet and must be built

The real IMSB signing round. Today production emits stubs (`wallet_core.rs:1941-1949`). The
*collection* machinery exists and is exercised — `channel_member cosign`
(`src/bin/channel_member.rs:3997`, N-of-N loop `:4051-4062`) and `cosign-batch` (`:4099`,
`:4205-4216`) — but every current cosign round signs the **IMCH** digest, not IMSB. Extending the
round to also produce an IMSB signature per member, and to build the `FalconAggWitness`
(`agg.rs:212-221`, mirroring `wallet_core.rs:3487-3560` for close), is real work with no existing
counterpart. Do not price this as a circuit-only change.

---

## 9. Phased plan — falsifiable acceptance criteria

### Phase 0 — measurement spike (no behaviour change)
Prototype `AggListStepCircuit` and the 16-leaf root recompute in a throwaway branch purely to read
degrees and timings.
**Accept iff:** `update_channel_tree` degree, `AggListStepCircuit` degree, the `ListCircuit` cyclic
wrapper degree, and `ValidityCircuit` degree are all recorded; and `ValidityCircuit` is **still
2^16**. **If it is not 2^16, STOP and report** — the wrapper/MLE shape change is a separate,
larger project and must not be discovered in Phase 4.

### Phase 1 — message + registration prerequisite
Drop `bp_member_slot` / `bp_pk_g` from `SmallBlockRootMessage::signing_digest()` and
`SmallBlockMessageFields`; keep them as unsigned struct fields. Add `delegate_count == 0` to
`channel_reg_step`.
**Accept iff:** the native/in-circuit golden-vector test (`small_block_message.rs:196-229`) passes
against the new 33-limb preimage; the retired 41-limb layout is pinned in the repo-wide domain
non-collision test; a registration witness with `delegate_count = 1` is **unprovable**; all 9
construction sites compile; an audit confirms no live channel has `delegate_count > 0`.

### Phase 2 — `AggListStepCircuit`
Step verifies one `FalconAggCircuit` top proof at a constant VK and folds
`(message, signer_count, pk_list_digest)`. Re-derive the `CommonCircuitData` template deliberately.
**Accept iff:** a step over a real 2-of-2 and a real 16-of-16 agg proof verifies; a step whose agg
proof has the wrong arity fails the build-time assert; a step fed an agg proof over a *different*
message fails; the cyclic wrapper builds and `ListCircuit`-equivalent append/verify round-trips.

### Phase 3 — `update_channel_tree` N-of-N binding
16-leaf member-tree root recompute + thermometer + `2 <= signer_count <= 16` + wider fold. Keep the
`tx_tree_root != 0` gate, the bp-slot Regev recompute, and the single-fold invariant comment.
**Accept iff, as negative tests that must FAIL to prove:**
(a) a witness claiming `signer_count = member_count − 1` (excluding one member);
(b) a witness repeating one member's `pk_g` in two active slots;
(c) a witness with a non-registered `pk_g` in an active slot;
(d) a witness with a nonzero leaf in a slot ≥ `signer_count`;
(e) `signer_count = 1`;
(f) `tx_tree_root == 0` with a signature applied.
And as positive tests: real 2-of-2 and 16-of-16 blocks prove and verify.

### Phase 4 — `ValidityCircuit` rewire + span tests
`list_vd` → `agg_list_vd`; update the 7 call sites.
**Accept iff:** `tests/small_block_sig_validity.rs` passes end to end with real N-of-N; a span with
zero signing blocks still takes the dummy-proof path; a prover cannot verify the span while having
applied a signed update (the computed-gate property is re-tested, not assumed); measured degree
matches Phase 0.

### Phase 5 — **prove the old hole is closed** (non-negotiable)
A dedicated adversarial test module reproducing §2.1 verbatim:
1. Construct the *current* attack: one cosigner, `prev_private_state`, a self-signed IMSB over a
   theft `tx_tree_root`, `aux_data = 0`.
2. On the pre-change code path, assert it **succeeds** end to end (spend → send-tx → block →
   withdrawal). This is the regression witness; if it does not succeed, the threat model is wrong
   and the whole change must be re-derived.
3. On the post-change path, assert the block is **unprovable**, and name the failing constraint.
4. Assert that a 1-of-N agg proof (`signer_count = 1`) over the same digest is also unprovable.
**Accept iff:** step 2 succeeds on the old path and steps 3–4 fail on the new one. *A fix that does
not demonstrably close the hole is not a fix.*

### Phase 6 — signing round
Extend `cosign` / `cosign-batch` to collect IMSB signatures and build the `FalconAggWitness`;
replace `structural_small_block_sigs`.
**Accept iff:** a real end-to-end send produces a `SignedSmallBlock` with N real Falcon signatures
and a verifying agg proof; the stub helper is deleted, not left dead; withholding one member's
signature makes block production fail with a clear error (documenting §6.1's unchanged posture).

### Phase 7 — fixtures + redeploy
Regenerate the ~20 JSON fixtures; redeploy `IntmaxRollup`; re-derive the `ChannelSettlementManager`
address in close fixtures. **Do not touch `sepolia_*` without an explicit owner go.**
**Accept iff:** the Forge suite is green against regenerated fixtures; the MLE E2E verifies
on-chain; the `sepolia_*` set is untouched or explicitly re-cut on owner instruction.

### Phase 8 (separate PR) — D3 replay fence
Per §6.2. Independently falsifiable: a replayed `(channel_id, tx_tree_root)` in a later medium block
must become unprovable.

---

## 10. Migration — stated plainly

**There is no clean cutover. Existing channels must be drained.**

1. `mleVk` is constructor-only (`IntmaxRollup.sol:643`, no setter). Any validity-circuit change
   forces a **full redeploy**.
2. A new `IntmaxRollup` starts a fresh ext-state chain and a fresh account tree. Deposits are
   escrowed in the *old* contract. Blocks settled under the single-signature rule live in the old
   contract's `finalizedStateRoots` and are unreachable from the new one.
3. Therefore: channels registered under the old rule **cannot be carried over**. They must be closed
   or withdrawn against the old deployment, and re-registered against the new one.
4. This is a hard fork of the rollup, not a VK rotation. Schedule it as such.

Consequences to plan for:

- **Every open channel must close before cutover.** Close is N-of-N
  (`close_circuit.rs:791-795`) and blockable by one member, and `submitSpecialClose` is disabled
  (`ChannelSettlementManager.sol:1012-1014`). A channel whose member is gone **cannot close**.
  Enumerate live channels and confirm each can reach N-of-N *before* committing to a date.
- **T-7a interacts.** Any channel that has been through a cancelled close may already be stuck at
  the wrong `close_freeze_nonce` (`close-detached-signing-design.md:323-330`) and may not be able to
  close at all. Audit for this first; it is a pre-existing blocker on the drain, not a new one.
- **Blocks already settled under the old rule are not retroactively suspect** in the sense that the
  attack requires a malicious member; but they carry no N-of-N evidence, so no post-hoc audit can
  distinguish an authorized settlement from an unauthorized one. If any channel is believed
  compromised, that determination must be made off-chain, from members' own records, before drain.

Since the redeploy is mandatory anyway, **the marginal cost of a `ChannelLeaf` format change is near
zero.** That materially changes the M1-vs-M2′ trade (§4) and the D3 trade (§6.2): if the owner wants
one hard fork rather than two, take **M1 + D3-b** in this cutover and pay the leaf change once.

---

## 11. Owner decisions — do not decide these silently

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| **D1** | How is `member_count` authenticated for the validity circuit? | M1 leaf field / M2 empty-slot proof / M2′ full root recompute | **M2′ + `delegate_count == 0`** if this is the only fork; **M1** if bundling D3-b (§10) |
| **D2** | Do `bp_member_slot` / `bp_pk_g` stay in the signed preimage? | signed / unsigned transport fields | **Unsigned.** Posting is not a security control; signing it costs a re-collection round per poster change |
| **D3** | Replay fence for the IMSB message | (a) bind to leaf `index` + wallet semantic change / (b) new leaf field + monotonicity / (c) defer | **(a) as its own phase**, or **(b) if bundling with M1** |
| **D4** | Where does the agg recursion live? | P-a in `update_channel_tree` / P-b in the chain step | **P-b** — preserves the shape Phase 3 fought for |
| **D5** | Cutover scope | drain-and-redeploy now / stage behind the existing deployment | Must be **drain-and-redeploy** (§10); the only choice is *when* |
| **D6** | `sepolia_*` fixtures + live testnet | re-cut / freeze | Owner call. Live demo at `v3testnet.intmax.io` runs the old rule and is exposed to §2 until cutover |

---

## 12. Loud flags

1. **This is a hard fork, not a patch.** `mleVk` has no setter. Existing channels cannot be
   migrated; they must be drained. Any plan that assumes an in-place VK rotation is wrong (§10).
2. **`member_count` is not authenticated where the circuit can see it.** This is the single largest
   piece of hidden work and it was not visible from the brief. Every design option has a real cost
   (§4).
3. **Phase 0 is not optional.** If `ValidityCircuit` leaves 2^16, the MLE wrapper shape changes and
   this becomes a substantially larger project. Measure before building (§8.4).
4. **There is no production IMSB signing path at all** — today's signatures are literal stub bytes
   (`wallet_core.rs:1941-1949`). Phase 6 is new construction, not a modification (§8.5).
5. **N-of-N does not close the replay hole**, and it makes the stolen artifact more valuable. §6.2
   needs its own decision and its own phase.
6. **A channel whose member is unreachable cannot close**, and close is the drain path. Audit
   closability *before* scheduling the cutover (§10).
