# abstract2-1 — Minimal Specification (Small-Block + Bulk Inter-Channel)

This document is a **hypothetical minimal specification** for defining a "secure and confidential transfer function." Each piece of data is given a variable name, and each operation is given a function name.
No extraneous data or structures are added whatsoever (everything is enumerated in this document).

Based on [abstract2.md](./abstract2.md) (Lattice/Regev confidential v2), this revision (**v2.1**) adopts the **small-block posting model** (one sending channel = one small block = one tx) and **cross-channel bulk transfers** (multiple destination channels in a single tx).

**Normativity:** When [abstract2.md](./abstract2.md) and this document conflict, **this document takes precedence** for block structure, roles, `H2` semantics, and bulk transfer shape. Lattice confidentiality, close game, and the five security properties of abstract2 §0 are preserved.

**Implementation mapping:** [detail2.md](./detail2.md) describes how the current codebase satisfies (or intentionally diverges from) abstract specifications. See §6 for intentional gaps.

Machine-checked safety proofs: [ChannelSafety21.lean](./ChannelSafety21.lean) / [lean-safety-proof21.md](./lean-safety-proof21.md). The prior proofs for [abstract2.md](./abstract2.md) remain in [ChannelSafety2.lean](./ChannelSafety2.lean) (unchanged).

## Differences from abstract2.md (summary)

1. **Small-block model** — abolish multi-channel `TxV2Tree` aggregation. Each sending channel owns **one small block carrying exactly one tx** (bulk or single-leg). A **medium posting round** chains per-channel `SubBlock`s and posts them to L1 (`postBlockAndSubmit`).
2. **Role consolidation** — abolish the separate `ITS` role. The co-signing member at **`bp_member_slot ∈ {0,1,2}`** performs channel-local duties (rangeProof verification, tx propagation, handing `SignedSmallBlock` to the global BP).
3. **`H2` redefinition** — `H2` holds **this channel's own small-block `tx_tree_root`** (the root of a **1-leaf** Merkle tree), not the aggregated root of a multi-channel block. On the inter-channel path, verification **rejects `tx_tree_root = 0`**.
4. **Cross-channel bulk transfer** — one `BulkInterChannelTx` may contain **`transfer_entries[]`**: multiple `(destChannelId, recipient, amount, recipientDelta)` legs, possibly across **different destination channels**. The sender debits once: `senderDelta` encrypts `-(Σ_j amount_j)`.
5. **`TxLeafHash` generalization** — binds the sender wing and **all** receiver wings via a canonical Merkle/hash commitment. `settledTxChain` advances **once per tx** (one `TxLeafHash`), even for bulk.
6. **Safety unchanged** — as in detail2 §A-2: removing the aggregation tree does not weaken the five properties; `hash(H1,H2)` atomicity, `settledTxChain` binding, and `withdrawCap` enforcement are preserved.
7. **Batched intra-channel transfers (v2.1b)** — one intra-channel state transition (`H2 = 0`) may apply **K ≥ 1** `ChannelTx`s at once under a **single** agreement round (§2.2b, §3.2b). Each tx keeps its own mandatory `channelTxZKP`; the K proofs are mutually independent and verifiable **in parallel**. Soundness pivots on the **single-debit rule** (at most one debit per member slot per batch) and on the debit-then-credit canonical fold (§4.2b).

## Differences from v1 (inherited from abstract2)

Items 1–8 of [abstract2.md §"Differences from v1"](./abstract2.md) apply unchanged (Regev balances, `hash(H1,H2)`, `channelUpdateZKP`, structural atomicity, validity-circuit constraint, withdrawal ZKP, mandatory `channelTxZKP`, `settledTxChain` binding).

## 0. MECE skeleton

A transfer (`transfer`) splits into the following 2 exclusively and exhaustively. **Exclusivity and exhaustiveness are structurally guaranteed by the `H2` tag**:
- **A. Intra-channel transfer** `channelTransfer` (among the 3 people of the same channel) — agreement signature's `H2 = 0`
- **B. Inter-channel transfer** `interChannelTransfer` (channel → channel(s), via Intmax) — sending-side agreement signature's `H2 = own_small_block_tx_tree_root ≠ 0`
  - **B-burn. Partial withdrawal (base-layer L1 exit)** — a send-side leg whose `dest_channel_id = BURN_CHANNEL_ID` (§2.6). It is settled as a base-layer L1 `Withdrawal` instead of a destination-channel credit; **the channel stays open**. Same `H2 = tx_tree_root ≠ 0` and the same N-of-N authorization as B (no unilateral path — non-cooperative exit is the close game §3.5).

Security is divided into the following 5 properties (described later in §4):
1. **Authorization** authorization (all-member signature. Signature target = `hash(H1, H2)`)
2. **Double-spend / illicit mint prevention** no-double-spend (`commonState` + `validityProof`)
3. **Solvency** solvency (`balanceProof` + `rangeProof` = `channelUpdateZKP` verification)
4. **Exit / liveness** exit-liveness (close game + timeout + `lateBalanceProof` + withdrawal ZKP)
5. **Balance confidentiality** confidentiality (Regev encryption + ZK range proofs)

---

> **Naming policy:** The base intmax layer **adopts the type and field names of the existing implementation**. The channel layer and lattice-related parts use abstract names.

## 1. Overall premises [key / address]

- `Address` : public key = address. **1 person, 1 key, 1 account** (`address == pubkey`).
- `U256` : the type for quantities (plaintext balances and transfer amounts). In base-layer tx contents, per-leg quantities are plaintext.
- `SpxSigWitness` : SPHINCS+ signature. In this document, "signature" refers to this.
- `RegevPk` : each member's Regev (LWE) encryption public key. **Published to all within the channel.**
- `LatticeCt` : Regev ciphertext. The confidential representation of balances and balance changes (deltas). **Addition** to a balance ct is defined. A negative delta is a ct encrypting a negative-valued plaintext.

---

## 2. Data definitions (variables)

### 2.1 Multi-party payment channel (channel layer)

- `ChannelId` : channel identifier.
- `memberKeys : Map<ChannelId, [(Address, RegevPk); 3]>` : mapping from channel ID to the **3 (fixed) signing keys and Regev public keys**.
- `bp_member_slot : u8` : which member slot (`0..2`) is designated to perform channel-local block-producer duties for this channel (rangeProof, small-block handoff). **Must be a co-signing member slot.**
- `encBalances : [LatticeCt; 3]` : balances encrypted per member's own `RegevPk`. Plaintext balances appear nowhere in state.
- `balanceProof` : ZKP of channel total balance. Generation requires `validityProof`. Verified on L1 at withdrawal. **Not committed to `H1`**; bound via `settledTxChain` (audit finding 3).
- `settledTxChain` : hash chain of settle identifiers ingested by this channel. Genesis `0`. Inter-channel send/receive: `settledTxChain' = hash(settledTxChain, TxLeafHash)` **once per tx** (bulk included). Deposit: `hash(settledTxChain, deposit_hash)`. Invariant for intra-channel. `TxLeafHash` is known at small-block signing time.
- `BalancePublicInputs` : public input of `balanceProof`; **must expose `settledTxChain`**.
- `stateVersion` : balance-state version (monotonic; independent of `small_block_number`).
- `BalanceState { encBalances, settledTxChain, stateVersion }`.
- `H1 = hash(BalanceState)`.
- `H2` : transfer-type tag.
  - `H2 = 0` ⇔ intra-channel update / inter-channel **receive-side** reflection
  - `H2 = tx_tree_root ≠ 0` ⇔ inter-channel **send-side** small block (own channel's 1-leaf tree root)
- `balanceStateHash = hash(H1, H2)` : agreement/signature target.

### 2.2 Intra-channel tx (channel layer)

Unchanged from abstract2 §2.2: `ChannelTx { recipient, encAmount, nonce }` + mandatory `channelTxZKP`.

**Binding refinement (normative, matches implementation E-1):** `channelTxZKP`'s statement binds
the sender's **current stored ciphertext**: it proves, over public inputs
`(before = encBalances[sender], encAmount, after)`,
1. `encAmount` is a correct ciphertext to the recipient's `RegevPk` of a non-negative amount,
2. `plaintext(before) = plaintext(after) + amount` with all components non-negative n-bit integers (no borrow ⇒ sender post-update balance ≥ 0),
3. `after` is a well-formed fresh encryption to the sender's `RegevPk`.

Because `before` is read from the anchor state by the **verifier** (never supplied by the prover),
a `ChannelTx` is applicable **only** while the sender's slot ciphertext is unchanged since proof
generation. Applying the debit replaces that ciphertext, so **a tx can be applied at most once,
ever** — the `before`-binding acts as a natural nullifier (no separate spent-list is needed for
intra-channel txs). A tx that misses its batch simply remains valid for a later batch anchored at
any state where the sender's ciphertext is still the same (retry-friendly).

### 2.2b Intra-channel tx batch (channel layer, new in v2.1b)

```
ChannelTxBatch {
  anchor_digest : Hash,               -- digest of the BalanceState S the batch extends
  txs           : [SignedChannelTx; K]  -- K ≥ 1, canonical order (sorted by (sender_slot, nonce))
}
SignedChannelTx = ChannelTx + channelTxZKP + sender's tx signature
```

- **Single-debit rule (R1):** all `sender_slot`s in `txs` are **pairwise distinct**. Two debits from
  one slot in one batch would both prove against the same `before` ciphertext — accepting both
  applies one witness twice (double-spend). Verifiers MUST reject such a batch outright.
- **Sender-as-recipient is allowed (R2):** a slot may debit once *and* receive any number of
  credits in the same batch (fold order §3.2b).
- Every tx carries its own `channelTxZKP` bound to the **same** anchor state `S`
  (`before_i = S.encBalances[sender_i]`), so the K verifications share no state and are
  **embarrassingly parallel**.
- The batch is a **channel-layer construct only**: `H2 = 0`, no small block, `settledTxChain`
  invariant, and the base layer never sees it (nothing in §2.3 changes).

### 2.3 Intmax (base layer — small-block + bulk)

#### Roles and block kinds

- **Global `BP` (block producer)** : one entity per rollup. For each medium posting round, collects an **ordered list** of per-channel `SubBlock`s and posts to L1.
- **`member[bp_member_slot]`** : channel-local duties formerly assigned to abstract2's `ITS` — verifies `channelUpdateZKP` (`rangeProof`), propagates tx + post-deduction state to co-signers, delivers `SignedSmallBlock` to the global BP.
- **`BlockNumber`** : L2 block number (`U63`).
- **`small_block_number`** : per-channel counter of small blocks (independent of medium `BlockNumber`).
- **`MediumBlock`** : one L1 posting round = `SubBlock[]` chained by hash (implementation: `postBlockAndSubmit`).
- **`SubBlock`** : `{ channel_id, SignedSmallBlock, BulkInterChannelTx }` — **exactly one channel, exactly one tx**.
- **`SmallBlock`** : the sending channel's unit: `{ SmallBlockRootMessage, BulkInterChannelTx, member signatures }`.

#### Small-block root and signature (replaces abstract2 `channelStateSig` over aggregated root)

```
SmallBlockRootMessage {
  channel_id,
  small_block_number,
  prev_small_block_root,
  tx_tree_root,              -- = H2 on send path; root of 1-leaf TxV2 tree (≠ 0)
  state_commitment_root,     -- = H1' post-deduction
  bp_member_slot,
  ...
}
SignedSmallBlock = SmallBlockRootMessage + [SpxSigWitness; 3]
```

`SignedSmallBlock` is the substitute for signing `tx_tree_root` (§3.3.5). There is **no** signature target that authorizes transfer without binding `H1'`.

#### Bulk inter-channel tx

```
TransferEntry {
  dest_channel_id : ChannelId,
  recipient       : Address,
  amount          : U256,           -- plaintext at base layer (confidentiality boundary §4.5)
  recipient_delta : LatticeCt       -- positive ct to recipient's RegevPk
}

BulkInterChannelTx {
  source_channel_id : ChannelId,
  sender_addr       : Address,
  sender_delta      : LatticeCt,    -- encrypts -(Σ_j amount_j)
  transfer_entries  : [TransferEntry; N],   -- N ≥ 1; dest channels may differ
  channel_update_zkp,
  tx_inclusion_proof                 -- trivial 1-leaf proof vs own tx_tree_root
}
```

Canonical encoding fixes entry order (e.g. sorted by `(dest_channel_id, recipient)`). Duplicate legs are forbidden.

**`TxLeafHash`** (one per bulk tx):

```
sender_wing  = hash(TX_LEAF_DOMAIN, sender_addr, sender_delta)
recv_wing_j  = hash(TX_LEAF_DOMAIN, dest_channel_id_j, recipient_j, recipient_delta_j)
TxLeafHash     = MerkleRoot(sender_wing, recv_wing_0, …, recv_wing_{N-1})
```

Each destination channel verifies **Merkle inclusion of its own entry wing(s)** inside `TxLeafHash` before crediting (§3.4 flowReceive3).

**`channelUpdateZKP` (bulk)** — created by sender; proves:
1. `sender_delta` plaintext = `-(Σ_j amount_j)` with each `amount_j ≥ 0`.
2. Each `recipient_delta_j` encrypts `+amount_j` under the correct `recipient_j` `RegevPk`.
3. Sender post-update balance ≥ `Σ_j amount_j` (range).
4. `transfer_entries` match the committed Merkle leaves.

`rangeProof` = verification of this ZKP by `member[bp_member_slot]`.

#### Base-layer settlement from one small block

One small block may induce **multiple** base-layer `Transfer` settlements (one per `TransferEntry` with distinct `dest_channel_id`). The validity circuit processes them in **canonical entry order** within the same medium block step; each updates `ChannelLeaf.prev` for the **source channel once** (at the small-block's medium `BlockNumber`) and credits each destination channel.

- `SettledTransfer::nullifier()` : unchanged; binds `TxLeafHash`, `from`, `transfer_index`, `nonce`.
- `TxV2` : leaf of the **1-leaf** tree inside the small block (`transfer_index` disambiguates legs sharing one `TxLeafHash` at the nullifier layer).
- `tx_tree_root` : **this channel's** 1-leaf tree root (`SmallBlockRootMessage.tx_tree_root`), **not** a multi-channel aggregate.
- `TxV2MerkleProof` : degenerates to **1-leaf inclusion** against own `tx_tree_root`.
- `Block` / `PublicState` / `validityProof` / `ValidityPublicInputs` : as in abstract2; medium block carries `SubBlock[]` instead of one aggregated `tx_tree_root`.

### 2.4 Close (channel layer)

Unchanged from abstract2 §2.4 (`finalBalanceState`, `finalBalanceProof` + `settledTxChain` match, `withdrawCap`, `closeBurnTx`, `withdrawClaimZKP`, `lateBalanceProof`).

### 2.5 Timeout constants

Unchanged: `SIGN_TIMEOUT = 3 min`, `GRACE_BEFORE_PROCESS = 10 min`, `CHALLENGE_PERIOD = 1 day`.

### 2.6 Partial withdrawal (base-layer L1 exit, channel stays open)

A member may exit **part** of the channel balance to L1 **without closing** the channel, by routing a normal inter-channel send leg to a reserved burn channel. This is distinct from close (§2.4): close burns the **whole** `withdrawCap` and freezes the channel; partial withdrawal burns an **arbitrary amount** inside a regular signed small block and the channel continues.

- `BURN_CHANNEL_ID : ChannelId` : a **reserved** channel id that no channel may register (sentinel, e.g. `0xFFFF_FFFF`). A `TransferEntry` (§2.3) with `dest_channel_id = BURN_CHANNEL_ID` is a **burn leg**: it removes value from L2 spendable supply (the `closeBurnTx`/`burnAddress` role of abstract2 §2.4, generalized to a partial, mid-channel leg) and is settled as a base-layer `Withdrawal` rather than crediting a destination channel.
- **Burn-leg shape:** `TransferEntry { dest_channel_id = BURN_CHANNEL_ID, recipient : Address (L1 payout, ADDRESS_TAG form), amount : U256, recipient_delta = ⊥ }`. A burn leg carries **no `recipient_delta`** — no channel member is credited (value exits L2). Settlement MUST reject `recipient_delta ≠ ⊥` on a burn leg (else a leg could both burn and credit, §6).
- `Withdrawal { recipient, token_index, amount, nullifier, aux_data }` : the **existing base-layer withdrawal leaf** (pre-channel intmax; `single_withdrawal` → `withdrawal_chain` → `withdrawal_circuit`). For a burn leg: `recipient = leg.recipient`, `amount = leg.amount`, `nullifier = SettledTransfer::nullifier()` (binds source `channel_id`, `transfer_index`, `nonce` — §2.3; gives cross-channel-replay safety and a unique per-leg id), `aux_data` carried through.
- **L1 consumption is unchanged:** `withdrawNative(Withdrawal[], prover, withdrawalProof)` verifies the withdrawal ZKP, requires `extCommitment ∈ finalizedStateRoots` (anchored to a finalized validity state), checks `withdrawalNullifierUsed[nullifier]` (double-spend), decrements `totalEscrowed` (global solvency cap), credits `pendingWithdrawals[recipient]`. **No new L1 contract surface.**

---

## 3. Function definitions (operations)

**Actors:** `member[i]` (i∈{0,1,2}) / `sender` / `member[bp_member_slot]` / global `BP` / `L1`.

### 3.0 Channel composition (premise)

- `memberKeys[channel_id] = [(Address, RegevPk); 3]` at creation; `bp_member_slot < 3` fixed per channel.
- Each member publishes `RegevPk` (`publishRegevPk`).

### 3.1 Balance state agreement `agreeBalanceState`

Unchanged logic from abstract2 §3.1, with these substitutions in verification items:
- inter-channel send path: verify bulk `channelUpdateZKP` + **1-leaf** `tx_inclusion_proof` (§3.3.2).
- inter-channel receive path: verify entry Merkle inclusion for **this channel's** leg(s) inside propagated `TxLeafHash`.

### 3.2 Intra-channel transfer `channelTransfer` (`H2 = 0`)

Unchanged from abstract2 §3.2 (no small block created). A single transfer is the `K = 1` special
case of §3.2b (the flows coincide; §3.2b adds no obligation for `K = 1`).

### 3.2b Batched intra-channel transfer `channelTransferBatch` (`H2 = 0`, new in v2.1b)

Motivation: abstract2 §3.2 advances the state chain by **one link per tx**, forcing one full
agreement (co-sign) round per transfer. Since a credit is a **public homomorphic addition**
(commutative, requiring no secret), and each debit is justified by its own independent
`channelTxZKP`, K transfers can share **one** state transition and **one** agreement round, with
the K proof verifications running **in parallel**.

#### 3.2b.1 `buildChannelTx` — **actor: each sender**
- in: anchor `BalanceState S` (current finalized state), `recipient`, `amount`
1. As abstract2 §3.2.1 steps 1–2: encrypt `encAmount`, generate `channelTxZKP` with
   `before = S.encBalances[self]`, fresh `after` ct (+ retain its witness).
2. Sign `ChannelTx` (tx-level authorization). **Do not** build `BalanceState'` and do not sign any
   state hash — the sender cannot know the rest of the batch.
- out: `SignedChannelTx` (handed to the batch assembler).

#### 3.2b.2 `assembleBatch` — **actor: any member (or an untrusted coordinator)**
- in: pending `SignedChannelTx`s anchored at the same `S`
1. Select ≤ 1 tx **per sender slot** (R1; excess txs wait for the next batch).
2. Order canonically; set `anchor_digest = digest(S)`.
3. Compute the **canonical fold** (debits first, then credits — R3):

```
mid[i]   = if slot i debits in the batch then after_i else S.encBalances[i]
final[i] = mid[i] + Σ_{j : recipient_j = i} encAmount_j        -- homomorphic adds
BalanceState' = { encBalances = final, settledTxChain (invariant), stateVersion + 1 }
```

- out: `(ChannelTxBatch, BalanceState')` propagated to all members.

> The assembler is **untrusted**: every member re-verifies everything in §3.2b.3; a malicious
> assembler can at worst censor or delay txs (same liveness position as abstract2's sender-driven
> propagation — the close game §3.5 remains the exit).

#### 3.2b.3 `coSignBatch` — **actor: all members** (one agreement round)
- in: `ChannelTxBatch`, `BalanceState'`
1. `anchor_digest = digest(current head S)`; `stateVersion' = stateVersion + 1`; `H2 = 0`;
   `settledTxChain` unchanged.
2. **R1**: sender slots pairwise distinct; each tx's sender signature valid.
3. For each tx **in parallel**: verify `channelTxZKP` with `before_i` read from `S` (never from the
   payload).
4. Recompute the canonical fold (R3) and require `BalanceState'.encBalances = final` **exactly**;
   slots neither debiting nor credited must be bit-identical to `S`.
5. The recipient of any credit additionally decrypts its `encAmount`s (own-slot check, abstract2
   §3.1).
6. If all pass, sign `hash(H1', H2 = 0)`. All-member signatures finalize `BalanceState'`.
- out: finalized `BalanceState'` (one chain link for K transfers).

#### 3.2b.4 Witness invalidation (refresh interaction)
A slot that was **credited** in the batch no longer holds the encryption-randomness witness for its
new ciphertext (`final[i] ≠ mid[i]`): before that slot can debit it must refresh, exactly as in the
single-tx flow (detail2 D2/D3; out of scope here, §5). A slot that only **debited** keeps its fresh
`after` witness and can send again in the very next batch.

### 3.3 Intmax foundational primitives

#### 3.3.1 `rangeProof` — **actor: `member[bp_member_slot]`**
- in: `channelUpdateZKP`, `BulkInterChannelTx`, current `balanceProof`
1. Verify bulk `channelUpdateZKP` (equal magnitudes, sender solvency for **total** debit, ciphertext well-formedness).
- out: `bool` (if false, do not hand off to global BP).

#### 3.3.2 `signSmallBlock` — **actor: all channel members** (replaces abstract2 `signChannelState`)
- in: `SmallBlockRootMessage`, `tx_inclusion_proof` (1-leaf), `BulkInterChannelTx`, post-deduction `BalanceState'`
1. Verify `tx_inclusion_proof` against **own** `tx_tree_root` (1-leaf tree).
2. Verify bulk `channelUpdateZKP`; confirm `BalanceState'` applies `sender_delta` and `settledTxChain' = hash(settledTxChain, TxLeafHash)`.
3. Sign `SmallBlockRootMessage::signing_digest()` (= `hash(H1', H2 = tx_tree_root)`).
- out: `SignedSmallBlock`.
- **Atomicity (structural):** `H1'` and `H2` coexist in one preimage; inseparable authorization + deduction.

#### 3.3.2b Signature-free exceptions (deposit / close burn)

Unchanged from abstract2 §3.3.2b. Also applies to mid-channel L1 deposit import (§3.3.2c):
the deposit itself requires no per-deposit signature (accepted by the `receive_deposit` balance
circuit); the resulting channel state update is N-of-N co-signed.

#### 3.3.2c Mid-channel L1 deposit import (new)

- **actor:** depositing member (generates `receive_deposit` balance proof) + all N-of-N co-signers
- **precondition:** `channelStatus == Active`; deposit is Merkle-included in finalized `deposit_tree_root`
- **flow:**
  1. Member calls `IntmaxRollup.deposit{value}(recipient, tokenIndex, amount, auxData)` on L1, escrowing real ETH.
  2. Deposit is included in a block by the global BP; `deposit_tree_root` updated.
  3. Member generates `receive_deposit` balance proof (recursive IVC, `ReceiveDepositCircuit`). Nullifier tree insertion prevents double-fold.
  4. Two-step channel state transition (mirrors `InterChannelFundImport` + `ReceiverBundleApply`):
     - **Step 1 (fund import):** `channelFund.amount += amount`, `unallocated += amount`, `settledTxChain' = hash(settledTxChain, deposit_nullifier)`, `shared_native_nullifier_root` advances. All `encBalances` unchanged.
     - **Step 2 (bundle apply):** `encBalances[recipient_slot] += encrypt(amount, recipient_RegevPk)`, `unallocated -= amount`, `pending_adds[recipient_slot] += 1`.
  5. All N members co-sign both resulting states (`signSmallBlock`-equivalent).
- **post-condition:** `channelFund.amount` reflects total (genesis deposits + mid-channel deposits); `settledTxChain` includes all deposit nullifiers; channel remains `Active`.
- **trust anchor:** `verify_channel_backing` binds the balance proof's `settled_tx_chain` to the channel state's chain (same seam as genesis backing, detail2 §F-1).
- **threat mitigations:** (T1) unescrowded deposit → Merkle inclusion vs finalized tree; (T2) double-fold → `Deposit::nullifier()` + nullifier tree; (T3) wrong member/amount → recipient binding + N-of-N cosign; (T4) racing close → channel must be `Active`; (T5) fund inflation → `verify_channel_backing` + on-chain `receivedChannelFunds` ceiling.

#### 3.3.3 `produceMediumBlock` — **actor: global `BP`**
- in: `SubBlock[]` from participating channels (each: `SignedSmallBlock` + `BulkInterChannelTx`)
1. Chain `SubBlock`s in deterministic order (e.g. by `channel_id`, then `small_block_number`).
2. Construct medium block payload for L1.
- out: `MediumBlock`.

#### 3.3.4 `postBlock` — **actor: global `BP`**
- in: `MediumBlock`
1. Post to L1 (`postBlockAndSubmit`).
- out: finalized `BlockNumber` for the round.

#### 3.3.5 `generateValidityProof` — **actor: global `BP` (prover)**
- in: `SubBlock[]`, new `PublicState`
1. For each `SubBlock`, verify `SignedSmallBlock` and constrain **`H2` component = that SubBlock's `tx_tree_root`**; reject `tx_tree_root = 0` on inter-channel path.
2. Settle each `TransferEntry` in canonical order; update `ChannelLeaf.prev` for source channel **once per small block** at this `BlockNumber`.
- out: `validityProof`.

#### 3.3.6 `generateBalanceProof` — **actor: `member[bp_member_slot]` (per channel)**
Unchanged from abstract2 §3.3.6.

### 3.4 Inter-channel transfer `interChannelTransfer` (3 flows, send `H2 = own tx_tree_root`)

> **Atomicity:** unchanged — single signature target `hash(H1', H2 = own_tx_tree_root)`.

#### Transfer flow 1 `flowSend1` (sending channel)

- **actor: sender**
  1. Confirm on L1 that **no involved channel** (any `dest_channel_id` in entries, plus source) has a close request.
  2. Build `BulkInterChannelTx` (`transfer_entries[]`, `sender_delta`, bulk `channelUpdateZKP`).
  3. Pass to `member[bp_member_slot]`.
- **actor: `member[bp_member_slot]`**
  4. `rangeProof` (§3.3.1). If OK, prepare small block (1-leaf `tx_tree_root`).
  5. Share tx, `SmallBlockRootMessage`, post-deduction `BalanceState'` (`settledTxChain' = hash(settledTxChain, TxLeafHash)`).
- **actor: all members**
  6. `signSmallBlock` (§3.3.2). Partial signatures ⇒ transfer not authorized.
- **actor: `member[bp_member_slot]` → global `BP`**
  7. Deliver `SubBlock` for `produceMediumBlock` → `postBlock`.
- **actor: `member[bp_member_slot]` (sending channel)**
  8. After L1 inclusion, `generateBalanceProof` for post-send state.
  9. Propagate `(BulkInterChannelTx, tx_inclusion_proof, balanceProof')` to **each destination channel** (only entries targeting that channel).

#### Transfer flow 2 `flowSend2` (sending channel: balanceProof finalization)

Unchanged intent from abstract2 §3.4 flowSend2: store `balanceProof'` linked by `settledTxChain`; global BP generates `validityProof` in parallel.

> **No `transport_proof`.** Receivers verify L1 inclusion + `balanceProof` + ZKP directly (abstract2 design note preserved).

> **Inclusion liveness:** members sign only when intending inclusion; do not advance version until current small block is included; force-include if censored. Safety unchanged.

#### Transfer flow 3 `flowReceive3` (each receiving channel, `H2 = 0`)

Executed **independently per destination channel** that appears in `transfer_entries`.

- **actor: all members of destination channel D**
  1. Filter entries with `dest_channel_id = D`. Verify L1 inclusion of source small block, `balanceProof`, bulk `channelUpdateZKP`, and **Merkle inclusion of each filtered entry wing in `TxLeafHash`**. If invalid or absent, ignore.
- **actor: `member[bp_member_slot]` of D**
  2. `generateBalanceProof` on increase side.
  3. Build `BalanceState'` applying each filtered `recipient_delta` to the correct member ct; `settledTxChain' = hash(settledTxChain, TxLeafHash)` (same global `TxLeafHash` as sender).
- **actor: all members of D**
  4. `agreeBalanceState(BalanceState', H2 = 0)`.

### 3.5 Channel close game

Unchanged from abstract2 §3.5 (`requestClose` → grace → `startProcess` → challenge → `closeAndWithdraw` / `claimLateTx`).

**M7 (open):** a state signed under `.txRoot` before L1 inclusion must not be closable without an inclusion witness; see §7.

### 3.6 Partial withdrawal `partialWithdraw` (cooperative; channel stays open)

A partial withdrawal is a normal inter-channel send (§3.4 `flowSend1`/`flowSend2`) whose `BulkInterChannelTx` contains **one or more burn legs** (`dest_channel_id = BURN_CHANNEL_ID`, §2.6). A bulk tx MAY mix normal legs and burn legs. No new signing primitive is introduced — partial withdrawal **reuses** `signSmallBlock`, the validity settlement, and the base-layer withdrawal stack.

- **actor: sender**
  1. Confirm on L1 that the source channel has no open close request (as §3.4 flowSend1.1; `BURN_CHANNEL_ID` itself is never close-checked — it is not a real channel).
  2. Build `BulkInterChannelTx`: `sender_delta` encrypts `-(Σ_j amount_j)` over **all** legs (burn + normal); each burn leg sets `recipient_delta = ⊥`. Bulk `channelUpdateZKP` proves: each `amount_j ≥ 0`, sender post-update balance `≥ Σ_j amount_j`, and each normal leg's `recipient_delta_j` encrypts `+amount_j` (burn legs are excluded from the recipient-ciphertext checks since they have none).
  3. Pass to `member[bp_member_slot]`.
- **actor: `member[bp_member_slot]`**: `rangeProof` (§3.3.1); prepare the 1-leaf small block (`tx_tree_root`).
- **actor: all members**: `signSmallBlock` (§3.3.2) over `hash(H1', H2 = tx_tree_root)`. The burn is thereby **N-of-N authorized** and atomically bound to the post-deduction state `H1'`. Partial signatures ⇒ not authorized; a member who cannot obtain co-signatures exits via the close game (§3.5).
- **actor: global `BP`**: `produceMediumBlock` → `postBlock`; `generateValidityProof` (§3.3.5). For each settled leg in canonical order: if `dest_channel_id = BURN_CHANNEL_ID`, **emit a base-layer `Withdrawal`** into the block's withdrawal commitment and credit **no** destination channel; otherwise credit the destination as in §3.3.5. Debit the **source** channel once at this `BlockNumber` (`ChannelLeaf.prev`); advance `settledTxChain' = hash(settledTxChain, TxLeafHash)` once per tx (bulk included).
- **actor: `member[bp_member_slot]` (source channel)**: after L1 inclusion + `finalize`, `generateBalanceProof` for the post-send state, then build the withdrawal ZKP over the burn leg(s) via the existing `single_withdrawal_circuit` (it extracts `(recipient, amount, nullifier)` from the settled transfer) and submit `withdrawNative(Withdrawal[], prover, withdrawalProof)` to L1 (§2.6).
- **Channel continuity:** `stateVersion`/`settledTxChain` advance; members keep transacting. No freeze, no close.

**Security (the 5 properties, for the burn leg):**
1. **Authorization (§4.1):** the burn leg lives inside the N-of-N `signSmallBlock` over `hash(H1', H2)` — structurally inseparable from the post-deduction state; no unilateral withdrawal.
2. **No double-spend (§4.2):** `SettledTransfer::nullifier()` (source `channel_id` + `transfer_index` + `nonce`) + on-chain `withdrawalNullifierUsed`; `ChannelLeaf.prev` + `settledTxChain` forbid re-settling the same small block. `transfer_index` disambiguates multiple burn legs in one bulk tx.
3. **Solvency (§4.3):** `sender_delta = -(Σ_j amount_j)` is range-proven (sender post-balance ≥ total debit, burn included); on L1, `totalEscrowed` underflow caps the global outflow. A burn leg credits **no** channel (`recipient_delta = ⊥`), so value cannot be both burned and credited.
4. **Exit / liveness (§4.4):** partial withdrawal is the cooperative fast-path; the close game (§3.5) is the non-cooperative fallback.
5. **Confidentiality (§4.5):** the burn `amount` is plaintext at the base layer (an L1 exit is public by nature; matches the §4.5 per-leg-plaintext boundary); per-member channel balances remain Regev-encrypted.

---

## 4. Security mechanisms

### 4.1 Authorization
- All-member signatures over `hash(H1, H2)` for state updates; `signSmallBlock` for send path.
- Structural atomicity: `hash(H1', own_tx_tree_root)` inseparably binds transfer authorization and post-deduction state.
- Close with last all-signed state remains available.

### 4.2 Double-spend / illicit mint prevention
- `PublicState` / `ChannelLeaf.prev` updated **per source small block** (once per channel per medium block).
- `validityProof` verifies each `SignedSmallBlock` and binds `H2` to that SubBlock's `tx_tree_root`.
- 1-leaf `tx_inclusion_proof` at sign time (degenerate Merkle).
- Medium block is a **sequence of independent SubBlocks**; signature and `prev` updates are **per-channel**, not aggregated-tree dependent.
- `withdrawCap`, `closeBurnTx`, `settledTxChain` binding: unchanged from abstract2 §4.2.

**4.2b Batch soundness (§2.2b/§3.2b).** The batch preserves the inductive invariant of §3.1
("every component non-negative, total sum constant") for the same reason the single tx does.
When no debiting slot is also credited in the batch, the fold is **extensionally equal to a
sequential application** of its K txs (`batch_step_eq_seq`); in the sender-as-recipient case the
debit-before-credit fold order is normative and the invariant is proven directly
(`batch_preserves_validity`):

1. **Debits are independent and individually proven.** Each `channelTxZKP` proves conservation and
   non-negativity for its own slot against `before_i = S.encBalances[i]`. By R1 the K debited slots
   are distinct, so the K proofs talk about **disjoint** slots of the same anchor `S` — verifying
   them against `S` is equivalent to verifying them sequentially in any order.
2. **Credits are public homomorphic additions of non-negative amounts** (each `encAmount_j`'s
   non-negativity is inside tx j's ZKP). Additions commute and never decrease a component, so the
   canonical fold order (R3) is a mere encoding choice, not a soundness assumption.
3. **Conservation:** Σ final = Σ mid + Σ_j amount_j = (Σ S − Σ_j amount_j) + Σ_j amount_j = Σ S.
4. **No double-debit:** within a batch by R1; **across** batches by the `before`-binding natural
   nullifier (§2.2): once a debit is applied the sender's stored ciphertext changes, so the same
   (or any stale) `channelTxZKP` can never verify against a later state.
5. **Nothing else moves:** step §3.2b.3-4 pins every uninvolved slot bit-identical, and
   `settledTxChain`/`H2 = 0` keep the batch invisible to close/settlement accounting.

Consequently the five properties of §0 are unaffected: authorization is the unchanged all-member
signature over `hash(H1', 0)` (§4.1); solvency and confidentiality arguments are per-tx and carry
over verbatim (§4.3, §4.5); exit/liveness is untouched (§4.4). Formal statement + proof:
`ChannelSafety21.lean` §8 (`batch_step_eq_seq`, `batch_preserves_validity`).

### 4.3 Solvency
- Mandatory `balanceProof` on propagation; recipients ignore senders without it.
- Bulk `rangeProof` / `channelUpdateZKP`: sender solvency for **total** `Σ amount_j`.
- `channelTxZKP` for intra-channel path: unchanged.
- `TxLeafHash` + bulk ZKP: cannot debit little on sender and credit much across entries.
- Receive path: credit only entry wings **Merkle-proven inside `TxLeafHash`**.

### 4.4 Exit / liveness
Unchanged from abstract2 §4.4 (close game, timeouts, `withdrawClaimZKP`, `lateBalanceProof`).

### 4.5 Balance confidentiality
Unchanged boundary from abstract2 §4.5: per-leg `amount` plaintext at base layer; intra-channel amounts encrypted; channel total visible via `balanceProof` PI.

### 4.6 Mid-channel deposit safety (§3.3.2c)

All five properties (§4.1–§4.5) are preserved by mid-channel L1 deposit import:

1. **Authorization (§4.1):** The post-deposit channel state is N-of-N co-signed; no unilateral fund injection.
2. **No double-spend (§4.2):** `Deposit::nullifier()` + nullifier tree insertion (C15 circuit constraint) prevents double-fold. `settledTxChain` advances by the deposit nullifier, making the chain unique.
3. **Solvency (§4.3):** `channelFund.amount` increases by the deposited amount; `encBalances[recipient]` increases by the same. `provenTotal` in the Lean model tracks `Σ encBal`; both increase equally. On-chain `receivedChannelFunds` (authoritative ceiling) tracks real ETH pulled from `IntmaxRollup`.
4. **Exit / liveness (§4.4):** The close game captures the post-deposit state; `channelFundAmount` in `CloseIntent` reflects the total (genesis + deposits). If a close races a deposit, the deposited ETH is escrowed in `IntmaxRollup` and recoverable via `submitPostCloseClaim`.
5. **Confidentiality (§4.5):** The deposit `amount` is plaintext at the base layer (an L1 escrow is public by nature); per-member channel balances remain Regev-encrypted.

Formal proof: `ChannelSafety21.lean` §7a — `l1_deposit_preserves_validity` shows `ValidEncState21` is maintained; `end_to_end_close_safety21` (§7) is unchanged because `L1CloseRule` operates on `provenTotal` (which correctly includes deposits).

---

## 5. Relationship to detail2.md (implementation)

| Topic | abstract2-1 (this doc) | detail2.md (implementation) | Gap |
|---|---|---|---|
| Small-block model | §2.3, §3.3.3–4 | §A-2, §C-7, §H-1 | Aligned |
| `bp_member_slot` | §2.1, §3.3.1 | §A-2 consequence 3 | Aligned |
| Cross-channel bulk | §2.3 `transfer_entries[]` | Single `receiver_deltas[0]` only | **abstract2-1 ahead of implementation** |
| Intra-channel batch | §2.2b `ChannelTxBatch`, §3.2b | Single `SendPayload` (one `ChannelTx` + full `proposed_next_state`); `InChannelTransferUpdateWitness` pins exactly one sender/recipient pair | **abstract2-1 ahead of implementation** — needs `BatchSendPayload`, a batch update witness (fold recompute, R1 check, `pending_adds[i] += #credits`), parallel E-1 verification, and a browser `buildChannelTx` that does **not** pre-build the next state |
| Member count | 3 fixed | N ≤ 16 (D6) | detail2 extension; see detail2 |
| Signatures | `SpxSigWitness` abstract | Poseidon ZK two-key (§A-3, D8) | detail2 extension |
| Delegates / refresh | Out of scope here | §L, §B-3, D2/D3 | detail2 extensions |

When implementing bulk cross-channel, extend `InterChannelTx`, `channelUpdateZKP` (E-2), `tx_leaf_hash`, and validity settlement loop per this document.

---

## 6. Open issues

1. **M7 — signed-but-unsettled race:** post-deduction state signed at flowSend1 step 6 before L1 inclusion. Close must require inclusion witness for `.txRoot`-tagged states, or forbid version advance until inclusion (abstract2 audit / detail2 §K-1).
2. **Retry / version semantics** on failed small-block inclusion (abstract2 finding 12).
3. **Bulk receive replay:** each destination must ingest each `TxLeafHash` at most once; enforced by `settledTxChain` + `balanceProof` recomputation (A2).
4. **L2 validity ordering** when one small block settles multiple `dest_channel_id` legs — fixed canonical order in §2.3 (implementation must match).
5. **Burn-leg canonicality (§2.6/§3.6):** the validity settlement must (a) recognize `dest_channel_id = BURN_CHANNEL_ID` and route the leg to the withdrawal commitment with **no** channel credit, and (b) **reject** `recipient_delta ≠ ⊥` on a burn leg. `BURN_CHANNEL_ID` must be unregisterable (no `ChannelLeaf`), and the channel tree / settlement must never treat it as a creditable destination.
6. **Mixed bulk + withdrawal extraction:** a bulk tx may mix normal and burn legs under one `TxLeafHash`; the base-layer withdrawal circuit must extract exactly the burn legs (by `dest_channel_id = BURN_CHANNEL_ID`) and bind each to its own `transfer_index` nullifier. Confirm `single_withdrawal_circuit`'s `extract_address_from_recipient` accepts the burn leg's L1 `recipient` form and that non-burn legs are not extractable as withdrawals.
7. **Batch assembler fairness (§3.2b):** the assembler can censor/reorder txs within a batch. Ordering inside a batch has no value effect (§4.2b R3), and censorship is bounded by the existing liveness story (retry next batch; close game as exit), but a per-sender inclusion-latency policy (e.g. oldest-anchor-first) should be fixed at the implementation layer.
8. **Credit-budget interaction (detail2 D3):** a batch may push a slot's homomorphic-add counter (`pending_adds[i] += #credits_in_batch`) toward `MAX_HOMO_ADDS_BEFORE_REFRESH` in one step. The batch verifier must enforce the budget **post-fold** (reject batches that overflow it), and the implementation should cap credits-per-slot-per-batch so one batch cannot force an immediate refresh storm.

---

## Document lineage

```
abstract.md (v1) → abstract2.md (Lattice v2, aggregated TxV2Tree)
                 → abstract2-1.md (this file: small-block + bulk)
detail2.md       → implementation notes for enshrined-paymentchannel branch
ChannelSafety.lean → ChannelSafety2.lean (abstract2) → ChannelSafety21.lean (abstract2-1)
```
