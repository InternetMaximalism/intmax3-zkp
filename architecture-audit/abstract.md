# abstract — Minimal Specification and Security Mechanisms

This document is a **hypothetical minimal specification** for defining "secure transfer functionality." Each piece of data is given a variable name, and each operation is given a function name.
No extra data or structures are added at all (everything is enumerated in this document).

## 0. MECE Skeleton

A transfer (`transfer`) is divided exclusively and exhaustively into the following 2 categories:
- **A. Intra-channel transfer** `channelTransfer` (between the 3 people of the same channel)
- **B. Inter-channel transfer** `interChannelTransfer` (channel → channel, via Intmax)

Security is divided into the following 4 properties (described later in §4):
1. **authorization** (all-party signatures)
2. **no-double-spend** / prevention of illicit mint (`PublicState` + `validityProof`)
3. **solvency** (`balanceProof` + `rangeProof`)
4. **exit-liveness** (close game + timeout + `lateBalanceProof`)

---

> **Naming policy:** the base intmax layer (which does not involve channels) **adopts the type and field names of the existing implementation**. The channel layer
> (new design) retains abstract names while also noting existing types where they exist. Types/files conform to the code as of submission time.

## 1. Overall Premises [key / address]

- `Address` : public key = address (`src/ethereum_types/address.rs`). **1 person, 1 key, 1 account** (`address == pubkey`).
  The commitment to the SPHINCS+ key itself is `PkLeaf.pk_hash = Poseidon(pub_seed || pub_root)` (`src/common/key_set.rs`).
- `U256` : the type for quantities (balances and transfer amounts) (`src/ethereum_types/u256.rs`).
- `SpxSigWitness` : SPHINCS+ signature (`src/circuits/validity/block_hash_chain/sphincs_sig.rs`). In this document, "signature" refers to this.

---

## 2. Data Definitions (Variables)

### 2.1 Multi-party payment channel (channel layer = new. Existing types are noted alongside)

- `ChannelId` : channel identifier (existing type `ChannelId`, `src/common/channel_id.rs`).
- `memberKeys : Map<ChannelId, [Address; 3]>` : mapping from channel ID to **3 keys (= 3 people, fixed)**.
- `balances : [U256; 3]` : the balances of the 3 people in the channel.
- `balanceProof` : a **ZKP proof** of "how much balance the channel currently has" (the balance circuit's `ProofWithPublicInputs`). Its generation requires `validityProof`.
  **Verified on L1 at withdrawal time** (both the close `finalBalanceProof` and the late `lateBalanceProof`).
  Premise (soundness): once a tx is on L2 or has been broadcast, `balanceProof` reflects that tx, and it **cannot be forged** to an excessive balance.
- `BalancePublicInputs` (`src/circuits/balance/balance_pis.rs`): the **public inputs** of `balanceProof` (distinct from the proof). `{ channel_id, public_state, block_r, private_commitment }`.
- `stateVersion` : the version number of the balance state (channel layer, new).
- `BalanceState { balances, balanceProof, stateVersion }` : the content of the balance state (channel layer, new).
- `balanceStateHash = hash(BalanceState)` : the **agreement target** (= the hash of the 3 people's balances, the channel-wide balanceProof, and the stateVersion).

### 2.2 Intra-channel tx (channel layer, new)

- `ChannelTx { recipient, amount, salt }` : an intra-channel transfer tx.
  - `recipient : Address` (recipient public key), `amount : U256`, `salt` (one-time random value).

### 2.3 Intmax (base layer = uses the naming of the existing implementation)

- Role `BP` (Block producer): **only 1 person, fixed**. Collects each channel's tx and builds a block.
- Role `ITS` (intmax-tx-sender): **fixed within the channel**, 1 person. Responsible for the communication of sending tx to BP, and signing and returning the tx tree root.
- `BlockNumber` : block number (= `U63`, `src/common/u63.rs`).
- `Transfer { recipient, token_index, amount, aux_data }` (`src/common/transfer.rs`): the **content** of an inter-channel transfer tx.
  - The content of the tx = the **recipient channel's `ChannelId`** + the **actual recipient key's public key (`Address`)** + the **quantity (`amount : U256`)**.
    (Wrong: just "the recipient's public key and quantity." Correct: the recipient channel's ID is also included in the content.)
  - The nominal destination (routing unit) = the receiving `ChannelId`. Which member within the channel is the actual recipient is the actual recipient `Address`.
  - These are encoded into `recipient` / `aux_data`: the receiving `ChannelId`, the actual recipient `Address` (and the actual sender `Address`, the sending `ChannelId`) are
    **encoded into `aux_data : Bytes32`** (equivalent to the old `TxAux`). `recipient` itself is a recipient-derived value. `amount`/`token_index` are existing fields.
- `SettledTransfer::nullifier()` (`transfer.rs`): tx hash / nullifier.
  = Poseidon(recipient, token_index, amount, aux_data, from, transfer_index, block_number). Used for double-spend prevention.
- `TxV2 { tx_class, transfer_tree_root, nonce, channel_action_root }` (`src/common/tx.rs`): a leaf of the tx tree (a container of a group of transfers).
- `TxV2Tree = SparseMerkleTree<TxV2>` (`src/common/trees/tx_v2_tree.rs`): the Merkle tree of txs that BP has collected from multiple senders (channels).
- `tx_tree_root` : the root of `TxV2Tree` (`Block.tx_tree_root`).
- `TxV2MerkleProof = SparseMerkleProof<TxV2>` : the merkle proof that a certain tx is included in the tx tree.
- `senderRootSig` (type `SpxSigWitness`): the signature over `tx_tree_root` by the sender (= everyone, treating the channel as 1 user).
- `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }` (`src/common/block.rs`):
  posted to L1 as an L2 block. The abstract `txTreeRoot` = `tx_tree_root`. The block number is held by `PublicState.block_number`, not by `Block`.
- `PublicState { block_number, account_tree_root, deposit_tree_root, prev_public_state_root }` (`src/common/public_state.rs`):
  the **ZKP-provable shared state** (old `CommonState`). The state at a certain block point in time.
  - `block_number` : the current block number (old `CommonState.blockNumber`).
  - The old `lastIncluded : Map<ChannelId, lastBlockNumber>` is realized by `account_tree_root` (= `ChannelTree`), and
    each `ChannelLeaf.prev` represents "the block number at which that channel's tx was last included" (prevention of double-spend / illicit mint).
  - The hash chain is added by `ExtendedPublicState { ..., block_hash_chain, deposit_hash_chain }` (`ext_public_state.rs`).
- `validityProof` : a **ZKP proof** of the `PublicState` transition (the validity circuit's `ProofWithPublicInputs`). Generated per block and published off-chain.
- `ValidityPublicInputs { initial/final_block_number, initial/final_block_chain, initial/final_ext_commitment, prover }`
  (`src/circuits/validity/block_hash_chain/validity_circuit.rs`): the **public inputs** of `validityProof` (distinct from the proof). On-chain, `keccak(ValidityPublicInputs)` is bound.

### 2.4 Close (channel layer, new)

- `finalBalanceState` : the final `BalanceState` settled during the challenge period.
- `finalBalanceProof` : the settled `balanceProof` contained in the above (a proof object; its public inputs are `BalancePublicInputs`).
- `withdrawCap` : the total channel balance proved by `finalBalanceProof` (= `BalancePublicInputs`). The **maximum total withdrawal amount** after close.
  Whatever `finalBalanceState` claims, the total withdrawal cannot exceed `withdrawCap`.
- `burnAddress : Address` : a fixed burn address. A transfer to here removes value from the spendable supply of intmax L2 (renders it unspendable).
- `closeBurnTx : Transfer { recipient = burnAddress, token_index, amount = withdrawCap, aux_data }` :
  an intmax `Transfer`, submitted at close-state settlement time, that burns the channel balance.
- `lateBalanceProof` : a `balanceProof` after close (a proof of the same balance circuit; its public inputs are `BalancePublicInputs`). Stored on-chain as a **variable separate from the final state**.

### 2.5 Timeout Constants

- `SIGN_TIMEOUT = 3 min` : the allowable time for intra-channel signatures to fail to be assembled.
- `GRACE_BEFORE_PROCESS = 10 min` : the grace period from a close request to startProcess.
- `CHALLENGE_PERIOD = 1 day` : the challenge period.

---

## 3. Function Definitions (Operations)

Each operation is delimited one at a time by "**actor (who)**" and "**operation (what, on which data)**".
actor: `member[i]` (channel member, i∈{0,1,2}) / `sender` (the member who sends) / `ITS` (the fixed intmax-tx-sender, one of the members) / `BP` (the fixed Block producer) / `L1` (the on-chain contract).

### 3.0 Channel Composition (premise)

- `memberKeys[channel_id] = [Address; 3]` : the mapping of the 3 keys, settled at channel creation time (immutable thereafter).

### 3.1 Balance State Agreement `agreeBalanceState`

**actor: all of member[0..2]**
- in: candidate `BalanceState { balances, balanceProof, stateVersion }`
1. `member[i]` each verifies the validity of the candidate `BalanceState` (balance conservation, `balanceProof` consistency, `stateVersion` being current +1).
2. If invalid, do not sign (honest nodes do not agree).
3. If valid, `member[i]` signs `balanceStateHash = hash(BalanceState)` and produces an `SpxSigWitness`.
- out: `[SpxSigWitness; 3]`. When all 3 are assembled, `BalanceState` is settled.

### 3.2 Intra-channel transfer `channelTransfer`

Premise: the current `balanceProof`, `balances`, and a settled `BalanceState`. `balanceProof` is immutable.

#### 3.2.1 `signChannelTx` — **actor: sender**
- in: `ChannelTx { recipient, amount, salt }` (`recipient` = the receiving member's `Address`)
1. `sender` updates `balances`: `balances'[sender] -= amount`, `balances'[recipient] += amount`.
2. `sender` constructs `BalanceState' = { balances', balanceProof(immutable), stateVersion+1 }`.
3. `sender` signs **both** `ChannelTx` and `balanceStateHash' = hash(BalanceState')`.
- out: `(ChannelTx, BalanceState', SpxSigWitness_tx, SpxSigWitness_state)`.

#### 3.2.2 `propagateChannelTx` — **actor: sender**
1. `sender` propagates `ChannelTx` and `BalanceState'` to the remaining `member`s.

#### 3.2.3 `coSignBalanceState` — **actor: the remaining members (the 2 people other than the sender)**
- in: `ChannelTx`, `BalanceState'`
1. `member` verifies whether the result of applying `ChannelTx` to `balances` matches `BalanceState'.balances`.
2. If valid, signs `balanceStateHash'`.
- out: an additional `SpxSigWitness`. With all 3 signatures, `BalanceState'` is settled.

### 3.3 Intmax Foundational Primitives

#### 3.3.1 `rangeProof` — **actor: ITS**
- in: `balanceProof` (sending channel), `amount`
1. `ITS` verifies that "the sender balance indicated by `balanceProof` ≥ `amount`" (the balance exceeds the transfer amount).
- out: `bool` (if false, do not pass to `BP`).

#### 3.3.2 `signTxTreeRoot` — **actor: the sending 1 user (= all channel members = 1 user)**
- in: `tx_tree_root`, `TxV2MerkleProof`, one's own `TxV2` (containing the `Transfer` within)
1. Verifies the `TxV2MerkleProof` and confirms that one's own `TxV2` is included in `tx_tree_root` (`TxV2Tree`).
2. Once confirmed, signs `tx_tree_root`.
- out: `senderRootSig : SpxSigWitness` (the signature treating the channel as 1 user).

#### 3.3.2b Signature-exempt special cases (deposit mint / close burn) — **actor: validity / verification circuit**
- **deposit (mint) and `closeBurnTx` (burn) are accepted within the ZKP validity circuit / withdrawal verification circuit without an L2 signature (`signTxTreeRoot`).**
- Rationale: a deposit is an L1-originated deposit, and `closeBurnTx` is a withdrawal that arises L1/close-driven as a result of close settlement; neither requires the channel members' co-signature (`senderRootSig`).
- Effect: even during the signature halt after `requestClose` (§3.5.1), `closeBurnTx` can be settled on L2, resolving the contradiction between freeze and the burn signature.

#### 3.3.3 `produceBlock` — **actor: BP**
- in: the group of `TxV2` from each channel, each channel's `senderRootSig`
1. `BP` builds a `TxV2Tree` from the group of `TxV2` and obtains `tx_tree_root`.
2. `BP` constructs `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }`.
- out: `Block`.

#### 3.3.4 `postBlock` — **actor: BP**
- in: `Block`
1. `BP` posts `Block` to Ethereum L1 as an L2 block.
- out: the settled `BlockNumber`.

#### 3.3.5 `generateValidityProof` — **actor: BP (prover)**
- in: `tx_tree_root`, the group of `senderRootSig`, `Block`, the new `PublicState`
1. Consistently verifies `tx_tree_root`, each `senderRootSig`, `Block`, and the resulting `PublicState` transition in a ZKP circuit.
2. Updates each `ChannelLeaf.prev` of `PublicState.account_tree_root` to the "included `BlockNumber`" (prevention of double-spend / illicit mint).
- out: `validityProof` (public inputs = `ValidityPublicInputs`). Generated per block and published off-chain.

#### 3.3.6 `generateBalanceProof` — **actor: channel (represented by ITS)**
- in: `validityProof`, the state of the channel in question
1. With `validityProof` as input, generates a `balanceProof` asserting the channel balance (`validityProof` is required).
- out: `balanceProof` (public inputs = `BalancePublicInputs`).

### 3.4 Inter-channel transfer `interChannelTransfer` (3 flows)

Both the sending nominee and the receiving nominee are channels. Carries a `Transfer` of transfer amount `amount` from the sending channel → the receiving channel.

> **Atomicity of signatures (invariant)**: the authorization signature of a transfer tx (`senderRootSig` = the signature over `tx_tree_root`) and
> the signature over the post-subtraction `BalanceState'` reflecting that transfer (sender balance -= amount, `stateVersion`+1) are
> always performed by everyone simultaneously as **a single atomic operation**. **A signature of only one of them is invalid**.
> The same rule as intra-channel transfer (§3.2.1, already atomic) is applied to inter-channel transfer as well.
> This guarantees that "**authorizing a transfer ⇔ settling the internal subtraction**", thereby sealing the attack of refusing the subtraction signature after the transfer to
> shift the loss to co-members (intra-channel theft), and forced close with an over-stated state.

#### Transfer flow 1 `flowSend1` (sending channel: tx creation 〜 atomic authorization 〜 propagation)

- **actor: sender**
  1. `sender` confirms on `L1` that **neither channel (sending/receiving) has a close request**.
  2. `sender` creates `Transfer { recipient, token_index, amount, aux_data }`
     (with the actual sender address, the actual recipient address, and the sending/receiving `channel_id` in `aux_data`).
  3. `sender` passes the `Transfer` to `ITS`.
- **actor: ITS**
  4. `ITS` confirms `rangeProof(balanceProof, amount)` (balance ≥ transfer amount).
  5. `ITS` shares the `Transfer` (the `TxV2` containing it), the `TxV2Tree`, and the post-subtraction `BalanceState'` (sender balance -= amount, `stateVersion`+1) with everyone.
- **actor: all of the sending channel (member[0..2]) — atomic signature**
  6. Each `member` **simultaneously signs `tx_tree_root` and `BalanceState'` as a single atomic operation**.
     Unless everyone signs the post-subtraction `BalanceState'`, that `tx_tree_root` signature (`senderRootSig`) is **invalid**.
     - If not everyone is assembled, the transfer is **not authorized** (a partial signature is invalid = the transfer does not take effect, no loss to co-members).
- **actor: ITS → BP**
  7. `ITS` passes the assembled `senderRootSig` to `BP` (`BP` does `produceBlock` → `postBlock`).
- **actor: ITS (sending channel)**
  8. Once `tx_tree_root` is in an L1 block, `ITS` generates the post-subtraction `balanceProof'` via `generateBalanceProof`.
     Since `balanceProof'` is unforgeable and reflects the post-send L2 balance (`B-amount`), it **necessarily matches** the
     `BalanceState'.balances` (post-subtraction) already signed and settled at step6 (no new negotiation or signature is needed).
  9. `ITS` propagates `(Transfer data, TxV2MerkleProof, balanceProof')` to the **receiving channel**.

#### Transfer flow 2 `flowSend2` (sending channel: balanceProof settlement)

- **actor: ITS (sending channel)**
  1. Settles the `balanceProof'` of step8 as the `balanceProof` of the `BalanceState'` already signed at step6
     (`balances`/`stateVersion` are already signed and immutable at step6).
- **actor: BP (prover, concurrent)**
  2. Generates the `validityProof` of the block in question via `generateValidityProof`.
- Note: if the atomic authorization signature (flow1 step6) is not assembled, the transfer does not take effect. For general non-responsiveness, `requestClose` (§3.5) is available upon exceeding `SIGN_TIMEOUT` (3 minutes).

#### Transfer flow 3 `flowReceive3` (receiving channel: reflecting into the balance state)

- **actor: all of the receiving channel (member[0..2])**
  1. Everyone confirms whether the propagated `(Transfer data, TxV2MerkleProof, balanceProof)` is valid
     (inclusion verification of `TxV2MerkleProof` + consistency of `balanceProof`). If there is no `balanceProof`, the sender is ignored.
- **actor: ITS (receiving channel)**
  2. `ITS` confirms that the tx's **receiving `ChannelId` is its own channel** and updates `balanceProof` to the **increased** side (`generateBalanceProof`).
  3. `ITS` looks at the tx's **actual recipient key's public key (`Address`)**, identifies that member, and
     constructs `BalanceState' = { balances'(that recipient's balance += amount), balanceProof'(new), stateVersion+1 }`.
- **actor: all of the receiving channel (member[0..2])**
  4. Everyone agrees and signs via `agreeBalanceState(BalanceState')`.

### 3.5 Channel close game

Order: `requestClose` → (`GRACE_BEFORE_PROCESS`=10 min) → `startProcess` → (`CHALLENGE_PERIOD`=1 day) → `closeAndWithdraw`.

#### 3.5.1 `requestClose` — **actor: any member within the channel**
- in: `channel_id`
1. Any `member` requests a close on `L1`.
2. After the request, all `member`s **halt all signing actions** related to the channel in question (do not perform `agreeBalanceState`, `signTxTreeRoot`, etc.). Those outside the channel also do not transfer to the channel in question.
3. Due to the grace of `GRACE_BEFORE_PROCESS` (10 minutes), signatures and communication lag immediately before/after the request are regarded as "nonexistent".

#### 3.5.2 `startProcess` — **actor: the requester (or any member)**
- in: `BalanceState` (signed by everyone), and the `balanceProof` within it (= intmax-balanceProof)
1. 10 minutes after the request, `member` submits `BalanceState` and `balanceProof` to `L1`.
2. `L1` confirms the all-party signatures of `BalanceState` and starts the `CHALLENGE_PERIOD` (1 day).

#### 3.5.3 `challenge` — **actor: any member**
- in: a `BalanceState_newer` newer than the one already submitted (signed by everyone) and the `balanceProof` within it
1. `member` submits `BalanceState_newer` to `L1`.
2. `L1` confirms that **all submissions have all-party signatures**.
3. If `BalanceState_newer.stateVersion > the currently submitted stateVersion`, it is replaced.
4. At the end of the period, `finalBalanceState` / `finalBalanceProof` is settled (preventing a close with an old state).

#### 3.5.4 `closeAndWithdraw` — **actor: each member / L1 / intmax L2**
- in: the settled `finalBalanceState` / `finalBalanceProof`, `closeBurnTx`
1. **(burn tx submission)** After the close state is settled, `member` submits `closeBurnTx` (= `Transfer { recipient: burnAddress, amount: withdrawCap, ... }`) to `L1` together with `finalBalanceProof`.
2. **(processed as an L2 burn)** The same `closeBurnTx` is also processed on intmax L2 as a "burn tx at close-state settlement", and the channel balance is removed from the L2 spendable.
   - To burn `withdrawCap` on L2, **that amount must actually exist in the channel** (the same solvency verification as a normal `Transfer`). Old balances that have already been transferred away cannot be burned.
3. **(cap settlement)** `L1` verifies `finalBalanceProof` and settles `withdrawCap = the proved balance of finalBalanceProof = closeBurnTx.amount`.
4. **(capped distribution withdrawal)** `L1` distributes to each `member` according to `finalBalanceState.balances`, but enforces **Σ(withdrawal) ≤ `withdrawCap`**. Even if `finalBalanceState` claims an amount exceeding `withdrawCap`, the excess portion cannot be withdrawn.

#### 3.5.5 `claimLateTx` — **actor: recipient (the recipient of the late tx)**
- in: `lateBalanceProof`, `Transfer data`, `TxV2MerkleProof`
1. For an intmax `Transfer` to the channel in question that was made known after the settled close version, the recipient creates a new `balanceProof` via ZKP with `lateBalanceProof` as input (the balance circuit is identical to `balanceProof`).
2. Once verified on `L1`, the recipient receives it on-chain.
3. `lateBalanceProof` is stored on-chain as a **variable separate** from `finalBalanceProof`.

Supplement: `balanceProof` is always attached to the recipient when a tx is sent (`flowSend1`/`flowReceive3`). If the recipient does not have it, the sender is ignored.

---

## 4. Security Mechanisms

For each mechanism, we indicate which of the **4 properties of §0** it protects.

### 4.1 authorization
- **All-party signatures (`agreeBalanceState` / `coSignBalanceState`)**: a balance state update has the signatures of all 3 people as its agreement target.
  Since honest nodes do not sign an invalid state, an invalid update does not take effect.
- **Atomicity of signatures**: the transfer authorization (`senderRootSig` = the `tx_tree_root` signature) and the signature over the post-subtraction `BalanceState'` are
  indivisible (§3.2.1 / §3.4 invariant). This seals the attack of authorizing only the transfer and refusing the internal subtraction signature to shift the loss to co-members.
- **close is possible with the last agreed state**: even if agreement breaks down, an on-chain close can be done with the last `BalanceState` signed by everyone.

### 4.2 no-double-spend / prevention of illicit mint
- **`PublicState`**: each channel holds "the block number at which a tx was last included" in `account_tree_root` (each `ChannelLeaf.prev`),
  preventing double-spend of the same funds and illicit mint.
- **`validityProof`**: consistently verifies `tx_tree_root`, `senderRootSig`, `Block`, and `PublicState` via ZKP, and publishes per block.
- **The merkle verification of `signTxTreeRoot`**: the sending 1 user confirms that the tx is included in `TxV2Tree` via `TxV2MerkleProof` before signing.
- **Withdrawal cap (`withdrawCap`)**: the total withdrawal after close is capped by the balance proved by `finalBalanceProof` (enforcing `Σ(withdrawal) ≤ withdrawCap` in `closeAndWithdraw`).
  No matter how much `finalBalanceState` claims, exceeding is impossible → sealing theft with an inflated or stale state (audit C1/C2/C5).
- **close burn tx (`closeBurnTx`)**: for an L1 withdrawal, `closeBurnTx` (a `Transfer` to `burnAddress`) is submitted together with `finalBalanceProof`, and
  **the same tx is also processed as a burn on intmax L2**. Since burning `withdrawCap` on L2 requires the actual balance,
  old balances that have already been transferred away cannot be burned and cannot be withdrawn on L1 either (sealing the double-spend C1 of "usable on L2 too + withdrawal on L1 too" at the close boundary).

### 4.3 solvency
- **Mandatory `balanceProof` attachment**: a `balanceProof` must always be attached to a transfer tx. If absent, the recipient ignores the sender.
- **`rangeProof`**: ITS confirms that the sender balance exceeds the transfer amount before passing to BP.
- **Monotonic update of `balanceProof`**: the sending side updates by decreasing (`flowSend2`) and the receiving side by increasing (`flowReceive3`), fixed by all-party agreement.

### 4.4 exit-liveness
- **The order of the close game and challenge**: `requestClose` → 10 min → `startProcess` → 1-day challenge → close.
  During the challenge period, it can be replaced with **a newer version of the state**, and the final state is settled (preventing a close with an old state).
- **`GRACE_BEFORE_PROCESS` (10 min)**: due to the grace from the close request to startProcess, signatures and communication lag immediately before/after the request can be regarded as "all nonexistent".
- **`SIGN_TIMEOUT` (3 min)**: if signatures are half-finished and not assembled, it is regarded as a protocol violation, and exit is possible via close (ensuring liveness).
- **Confirmation of both channels' close requests (`flowSend1`)**: do not perform a transfer to a channel that has a close request.
- **`lateBalanceProof`**: funds of an intmax tx that arrived after the settled close version can also be received by the recipient by on-chain verifying a new `balanceProof` with `lateBalanceProof` as input (preventing the missing of funds). The same circuit as `balanceProof`.
