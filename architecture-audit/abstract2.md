# abstract2 — Minimal Specification and Security Mechanisms (Lattice version)

This document is a **hypothetical minimal specification** for defining a "secure and confidential transfer function." Each piece of data is given a variable name, and each operation is given a function name.
No extraneous data or structures are added whatsoever (everything is enumerated in this document).
Based on [abstract.md](./abstract.md) (v1), this is a revised version (v2) reflecting a balance-confidentiality specification using Lattice (Regev/LWE) encryption.

## Differences from v1 (summary)

1. **Balance confidentiality**: Each member publishes a Regev public key within the channel, and each person's balance is held as a
   lattice ciphertext (`LatticeCt`) encrypted with that key. Plaintext balances never appear in the state.
2. **Two-part structure of the balance state**: The agreement target becomes `hash(H1, H2)`. `H1` = hash of the balance state body,
   `H2` = transfer-type tag (0 = intra-channel / `tx_tree_root` = inter-channel).
3. **channelUpdateZKP**: The sender proves via ZKP the validity of the lattice balance change for an inter-channel transfer (sender −, receiver +).
   `rangeProof` is redefined as the verification of this ZKP.
4. **Structuring of signature atomicity**: In v1, "signing the tx_tree_root and the post-subtraction state simultaneously" was an **operational rule**
   (§3.4 invariant), but in v2 the signature target itself is `hash(H1', H2 = tx_tree_root)`, so
   the agreement on transfer authorization and balance subtraction is **structurally embedded into a single signature** (inseparable).
5. **Added constraint to the validity circuit**: The channel state signature is verified and constrained within the validity circuit as a **substitute** for
   signing the tx_tree_root.
6. **ZKP-ization of post-close withdrawal**: Since the finalized state contains only ciphertexts, each member proves their encrypted balance
   via ZKP to withdraw.
7. **Intra-channel range ZKP (`channelTxZKP`) — audit reflection**: For intra-channel transfers as well, a ZKP proving that the sender's
   "post-update encrypted balance ≥ 0" is made mandatory (the intra-channel version of `channelUpdateZKP`).
   In v1 everyone could visually verify plaintext balances, but in v2's encryption that defense was lost (audit finding 5).
8. **Binding of state↔balanceProof (`settledTxChain`) — audit reflection**: `H1` commits not to a proof object but to a
   hash chain of the settle history, the balance circuit exposes the same chain as a public input, and at close time
   L1 checks the match. This resolves the cycle of including a proof in the state that is not yet generated at signing time (audit finding 3).

## 0. MECE skeleton

A transfer (`transfer`) splits into the following 2 exclusively and exhaustively. **Exclusivity and exhaustiveness are structurally guaranteed by the `H2` tag**:
- **A. Intra-channel transfer** `channelTransfer` (among the 3 people of the same channel) — agreement signature's `H2 = 0`
- **B. Inter-channel transfer** `interChannelTransfer` (channel → channel, via Intmax) — agreement signature's `H2 = tx_tree_root ≠ 0`

Security is divided into the following 5 properties (described later in §4):
1. **Authorization** authorization (all-member signature. Signature target = `hash(H1, H2)`)
2. **Double-spend / illicit mint prevention** no-double-spend (`commonState` + `validityProof`)
3. **Solvency** solvency (`balanceProof` + `rangeProof` = `channelUpdateZKP` verification)
4. **Exit / liveness** exit-liveness (close game + timeout + `lateBalanceProof` + withdrawal ZKP)
5. **Balance confidentiality** confidentiality (Regev encryption + `channelUpdateZKP`) — newly added in v2

---

> **Naming policy:** The base intmax layer (which does not involve channels) **adopts the type and field names of the existing implementation**. The channel layer
> and lattice-related parts (new design) use abstract names (no corresponding implementation type exists yet).

## 1. Overall premises [key / address]

- `Address` : public key = address (`src/ethereum_types/address.rs`). **1 person, 1 key, 1 account** (`address == pubkey`).
- `U256` : the type for quantities (plaintext balances and transfer amounts) (`src/ethereum_types/u256.rs`). In base-layer tx contents, quantities are plaintext.
- `SpxSigWitness` : SPHINCS+ signature (`src/circuits/validity/block_hash_chain/sphincs_sig.rs`). In this document, "signature" refers to this.
- `RegevPk` : each member's Regev (LWE) encryption public key (new). **Published to all within the channel.**
- `LatticeCt` : Regev ciphertext (new). The confidential representation of balances and balance changes (deltas). **Addition** to a balance ct (adding a delta) is defined.
  A negative delta (subtraction) is represented as a ct encrypting a negative-valued plaintext.

---

## 2. Data definitions (variables)

### 2.1 Multi-party payment channel (channel layer = new)

- `ChannelId` : channel identifier (existing type `ChannelId`, `src/common/channel_id.rs`).
- `memberKeys : Map<ChannelId, [(Address, RegevPk); 3]>` : mapping from channel ID to the **3 (fixed) signing keys and Regev public keys**.
- `encBalances : [LatticeCt; 3]` : the balances of the 3 people within the channel. **Member i's balance is encrypted with member i's `RegevPk`**,
  decryptable only by that person. Plaintext balances are kept nowhere.
- `balanceProof` : the **ZKP proof** of "how much balance the whole channel currently has" (the balance circuit's `ProofWithPublicInputs`).
  Generation requires `validityProof`. **Verified on L1 at withdrawal time** (both close's `finalBalanceProof` and late's `lateBalanceProof`).
  Premise (soundness): once a tx is on L2 or has been broadcast, `balanceProof` reflects that tx and **cannot be forged** to an excessive balance.
  **`balanceProof` is not committed to `H1`** (because for inter-channel transfers the post-subtraction proof is not yet generated at signing time.
  Audit finding 3). The correspondence with the state is bound by `settledTxChain` below, and L1 checks it at close submission.
- `settledTxChain` : the **hash chain** of base-layer settle identifiers taken into this channel (channel layer, new).
  Genesis is 0. Each time an inter-channel transfer (send/receive) is taken in,
  `settledTxChain' = hash(settledTxChain, TxLeafHash)`; taking in a deposit updates it similarly with the deposit hash.
  Invariant for intra-channel transfers. **`TxLeafHash` is known at signing time (flowSend1 step 6)**, so the post-subtraction state's
  chain can be computed on the spot. The nullifier includes `block_number`, so it cannot be computed at signing time and
  cannot be used for this purpose (double-settle prevention via `block_number` binding continues to be handled by the base-layer nullifier).
- `BalancePublicInputs` : the **public input** of `balanceProof` (separate from the proof).
  **New requirement: the circuit exposes the `settledTxChain` of the settle history it took in as a public input.**
- `stateVersion` : the version number of the balance state (channel layer, new).
- `BalanceState { encBalances, settledTxChain, stateVersion }` : the contents of the balance state (channel layer, new).
- `H1 = hash(BalanceState) = hash(encBalances, settledTxChain, stateVersion)` : the hash of the balance state body.
  All components are known at signing time (it does not include a proof object).
- `H2` : the transfer-type tag. **Basically 0.** Only for an intmax transfer originating from one's own channel does the corresponding `tx_tree_root` enter.
  - `H2 = 0` ⇔ intra-channel update (intra-channel transfer / received-funds reflection)
  - `H2 = tx_tree_root ≠ 0` ⇔ inter-channel transfer (intmax transfer + simultaneous authorization of its balance subtraction)
- `balanceStateHash = hash(H1, H2)` : the **agreement/signature target**. This replaces v1's `hash(BalanceState)`.

### 2.2 Intra-channel tx (channel layer, new)

- `ChannelTx { recipient, encAmount, nonce }` : an intra-channel transfer tx.
  - `recipient : Address` (recipient's public key)
  - `encAmount : LatticeCt` (the transfer amount **encrypted with the recipient's `RegevPk`**)
  - `nonce` (one-time random value)
- `channelTxZKP` (new, audit reflection): a ZKP attached **mandatorily** to an intra-channel transfer. Generated by the sender, it
  1. that `encAmount` is a correct ciphertext to the recipient's `RegevPk` of a non-negative amount,
  2. **the sender's post-update encrypted balance ≥ 0** (the range constraint balance ≥ transfer amount)
  proves these without revealing the plaintext (the intra-channel version of the inter-channel `channelUpdateZKP`).
  Without it, 2 colluding people could make an over-balance transfer within the channel → create a negative balance component, and at close the sum of the
  non-negative components could exceed `withdrawCap` and steal an honest member's withdrawal (audit finding 5).

### 2.3 Intmax (base layer = uses the existing implementation's naming. Lattice extensions are new)

- Role `BP` (Block producer): **fixed to just 1 person**. Collects each channel's tx and builds blocks.
- Role `ITS` (intmax-tx-sender): **fixed within a channel**, 1 person. Sends tx to the BP and handles communication related to the tx tree root.
- `BlockNumber` : block number (= `U63`, `src/common/u63.rs`). There is 1 kind of block.
- `Transfer` (the **contents** of an inter-channel transfer tx, extended based on the existing type `src/common/transfer.rs`):
  - contents = the receiving channel's `ChannelId`, the actual recipient's public key `recipient : Address`, the quantity `amount : U256` (**plaintext in the base layer**).
- `TxAux` (new, ancillary data within the tx's hash structure):
  `{ senderAddr, recipientAddr, senderChannelId, recipientChannelId, senderDelta : LatticeCt, recipientDelta : LatticeCt }`
  - `senderDelta` : **the negative lattice ct added to the sender's balance in the sending channel** (the subtraction amount).
  - `recipientDelta` : **the positive lattice ct added to the receiver's balance in the receiving channel**.
- `TxLeafHash = hash( hash(senderAddr, senderDelta), hash(recipientAddr, recipientDelta) )` : the tx's hash structure (new).
  The sender's and receiver's respective public keys and lattice balance changes are **bound on both wings**.
- `channelUpdateZKP` (new): a ZKP **created by the sender**. It proves the following:
  1. `senderDelta` and `recipientDelta` correspond to the same `amount` (equal quantity, opposite sign).
  2. The sender's balance remains non-negative after applying `senderDelta` (the range constraint **balance ≥ transfer amount**).
  3. Each delta is a correct ciphertext for its respective `RegevPk`.
- `SettledTransfer::nullifier()` : tx hash / nullifier (existing). Binds `TxLeafHash`, `from`, `transfer_index`, `block_number`. Used for double-spend prevention.
- `TxV2 { tx_class, transfer_tree_root, nonce, channel_action_root }` (`src/common/tx.rs`): the leaf of the tx tree.
- `TxV2Tree = SparseMerkleTree<TxV2>` (`src/common/trees/tx_v2_tree.rs`): the Merkle tree of txs that the BP collected from multiple senders (channels).
- `tx_tree_root` : the root of `TxV2Tree` (`Block.tx_tree_root`).
- `TxV2MerkleProof = SparseMerkleProof<TxV2>` : the merkle proof that a certain tx is included in the tx tree.
- `channelStateSig` (type `SpxSigWitness`, **replaces v1's `senderRootSig`**):
  the **signature over `hash(H1', H2 = tx_tree_root)`** by all members of the sending channel.
  A direct signature over tx_tree_root **does not exist**. This signature is the **substitute** for signing the tx_tree_root, and
  it is verified and constrained in the validity circuit as "the method of proving the tx_tree_root" (§3.3.5).
- `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }` (`src/common/block.rs`):
  posted to L1 as an L2 block.
- `PublicState` (= `commonState` in the spec text, `src/common/public_state.rs`): the **ZKP-provable shared state**.
  Each channel holds in `account_tree_root` (each `ChannelLeaf.prev`) "at which block number it last signed a tx and was taken into a block"
  (double-spend / illicit-mint prevention).
- `validityProof` : the **ZKP proof** of the `PublicState` transition. Generated per block and published off-chain.
- `ValidityPublicInputs` : the public input of `validityProof`. On-chain, `keccak(ValidityPublicInputs)` is bound.

### 2.4 Close (channel layer, new)

- `finalBalanceState` : the final `BalanceState` finalized during the challenge period (still as encrypted balances).
- `finalBalanceProof` : the `balanceProof` **linked to** the finalized state. The link is checked by L1 via the match of the public input
  `settledTxChain` = `finalBalanceState.settledTxChain` (§2.1).
- `withdrawCap` : the channel total balance that `finalBalanceProof` proves. The **maximum total withdrawal** after close.
  No matter what `finalBalanceState` claims, the total withdrawal cannot exceed `withdrawCap`.
- `burnAddress : Address` : a fixed burn address. A transfer to here removes value from the intmax L2 spendable supply.
- `closeBurnTx : Transfer { recipient = burnAddress, amount = withdrawCap, ... }` :
  an intmax `Transfer` that burns the channel balance, submitted at close-state finalization.
- `withdrawClaimZKP` (new): after close, a ZKP by which each member proves on L1, without decrypting, that "the plaintext of **their own encrypted balance**
  within `finalBalanceState.encBalances` is their withdrawal amount."
- `lateBalanceProof` : a `balanceProof` after close (a proof of the same balance circuit). Stored on-chain as a **separate variable from the final state**.

### 2.5 Timeout constants

- `SIGN_TIMEOUT = 3 min` : the allowed time for intra-channel signatures not being assembled.
- `GRACE_BEFORE_PROCESS = 10 min` : the grace period from close request to startProcess.
- `CHALLENGE_PERIOD = 1 day` : the challenge period.

---

## 3. Function definitions (operations)

Each operation is delimited one at a time by "**actor (who)**" and "**operation (what, on which data)**".
actor: `member[i]` (channel member, i∈{0,1,2}) / `sender` (the member who sends) / `ITS` / `BP` / `L1` (the on-chain contract).

### 3.0 Channel composition (premise)

- `memberKeys[channel_id] = [(Address, RegevPk); 3]` : finalized at channel creation (immutable thereafter).
- Each member publishes their own `RegevPk` within the channel (`publishRegevPk`).

### 3.1 Balance state agreement `agreeBalanceState`

**actor: all of member[0..2]**
- in: candidate `BalanceState { encBalances, balanceProof, stateVersion }`, tag `H2`
1. `member[i]` individually verifies the validity of the candidate:
   - that `stateVersion` is the current +1.
   - consistency of `settledTxChain` (invariant for an intra-channel update, `hash(current chain, TxLeafHash)` for inter-channel).
   - that **`encBalances[i]` addressed to oneself** is correctly updated (verifiable with one's own Regev secret key).
   - for an intra-channel transfer, verification of `channelTxZKP` (sender's post-update balance ≥ 0. Do not sign if absent/invalid).
   - for inter-channel (`H2 ≠ 0`), verification of `channelUpdateZKP` and `TxV2MerkleProof` (§3.3.2).
   - Because balances are ciphertexts, others' plaintexts are not visible, but **since every update is accompanied by a range ZKP (`channelTxZKP` /
     `channelUpdateZKP`), starting from a valid state, the non-negativity of all components and total-sum consistency are inductively
     maintained**. Thereby Σ(non-negative components) = total = `withdrawCap` is preserved, and withdrawal theft at close does
     not occur (§4.3).
2. If invalid, do not sign (a good node does not agree).
3. If valid, `member[i]` signs `balanceStateHash = hash(H1, H2)` and emits `SpxSigWitness`.
- out: `[SpxSigWitness; 3]`. When 3 are assembled, `BalanceState` is finalized.

### 3.2 Intra-channel transfer `channelTransfer` (`H2 = 0`)

Premise: the current `balanceProof`, `encBalances`, and a finalized `BalanceState`. `balanceProof` is invariant.

#### 3.2.1 `signChannelTx` — **actor: sender**
- in: `ChannelTx { recipient, encAmount, nonce }`
1. `sender` encrypts `amount` with the recipient's `RegevPk` and creates `encAmount`.
2. `sender` **generates `channelTxZKP`** (validity of `encAmount` + post-update own balance ≥ 0, §2.2).
3. `sender` updates `encBalances`: adds the subtraction delta to their own ct, and adds `encAmount` to the recipient's ct.
4. `sender` constructs `BalanceState' = { encBalances', settledTxChain(invariant), stateVersion+1 }`.
5. `sender` signs **both** `ChannelTx` and `balanceStateHash' = hash(H1', H2 = 0)`.
- out: `(ChannelTx, channelTxZKP, BalanceState', SpxSigWitness_tx, SpxSigWitness_state)`.

#### 3.2.2 `propagateChannelTx` — **actor: sender**
1. `sender` propagates `ChannelTx`, `channelTxZKP`, and `BalanceState'` to the remaining `member`s.

#### 3.2.3 `coSignBalanceState` — **actor: the remaining members (the 2 other than sender)**
- in: `ChannelTx`, `channelTxZKP`, `BalanceState'`
1. All `member`s **verify `channelTxZKP`** (do not sign if absent/invalid). The recipient additionally decrypts `encAmount`
   to verify their balance increase. Each `member` checks the verification items of §3.1.
2. If valid, sign `hash(H1', 0)`.
- out: additional `SpxSigWitness`. `BalanceState'` is finalized with all 3 signatures.

### 3.3 Intmax foundational primitives

#### 3.3.1 `rangeProof` — **actor: ITS**
- in: `channelUpdateZKP`, `Transfer`, current `balanceProof`
1. `ITS` verifies `channelUpdateZKP` (this is called the **range proof**):
   equal quantity of deltas, sender balance ≥ transfer amount, validity of ciphertexts (§2.3).
- out: `bool` (if false, do not pass to `BP`).

#### 3.3.2 `signChannelState` — **actor: sending 1 user (= all channel members = 1 user). Replaces v1's `signTxTreeRoot`**
- in: `tx_tree_root`, `TxV2MerkleProof`, one's own `TxV2` (containing `Transfer` + `TxAux` + `channelUpdateZKP`), post-subtraction `BalanceState'`
1. Verify `TxV2MerkleProof` and confirm that one's own `TxV2` is included in `tx_tree_root`.
2. Verify `channelUpdateZKP` and confirm that `BalanceState'.encBalances` correctly applies the proven `senderDelta`.
3. Once confirmed, **sign `hash(H1', H2 = tx_tree_root)`**.
- out: `channelStateSig : SpxSigWitness`.
- **Atomicity (structural)**: this single signature simultaneously represents "authorization of the intmax transfer" and "agreement on the post-subtraction balance state".
  Because `H2` contains `tx_tree_root` and `H1'` contains the post-subtraction state, **signing only one of them is impossible by definition**.
  The operational invariant of v1 §3.4 is built into the hash structure in this specification.

#### 3.3.2b Signature-free exceptions (deposit mint / close burn) — **actor: validity / verification circuit**
- **deposit (mint) and `closeBurnTx` (burn) are accepted within the ZKP validity circuit / withdrawal verification circuit without an L2 signature (`signChannelState`).**
- Rationale: a deposit is an L1-originated inflow, and `closeBurnTx` is an L1/close-driven outflow that arises as a result of close finalization; neither requires a co-signature of the channel members.
- Effect: even during the signature halt after `requestClose` (§3.5.1), `closeBurnTx` can be settled on L2, resolving the contradiction between freeze and burn signing.

#### 3.3.3 `produceBlock` — **actor: BP**
- in: the group of `TxV2` from each channel, each channel's `channelStateSig`
1. `BP` builds `TxV2Tree` from the group of `TxV2` and obtains `tx_tree_root`.
2. `BP` constructs `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }`.
- out: `Block`.

#### 3.3.4 `postBlock` — **actor: BP**
- in: `Block`
1. `BP` posts `Block` to Ethereum L1 as an L2 block.
- out: finalized `BlockNumber`.

#### 3.3.5 `generateValidityProof` — **actor: BP (prover)**
- in: `tx_tree_root`, the group of `channelStateSig`, `Block`, the new `PublicState`
1. Consistently verify the `tx_tree_root`, each `channelStateSig`, `Block`, and the resulting `PublicState` (`commonState`) transition in the ZKP circuit.
   **Important**: the circuit verifies and constrains that `channelStateSig` (= the signature over `hash(H1', H2 = tx_tree_root)`) is the **substitute** for signing the tx_tree_root.
   That is, the circuit reveals and verifies "the signature target's `H2` component = the corresponding `tx_tree_root`", and
   rejects unsigned txs and `H2`-mismatched txs as invalid.
2. Update each `ChannelLeaf.prev` of `PublicState.account_tree_root` to "the `BlockNumber` taken in" (double-spend / illicit-mint prevention).
- out: `validityProof` (public input = `ValidityPublicInputs`). Generated per block and published off-chain.

#### 3.3.6 `generateBalanceProof` — **actor: channel (ITS as representative)**
- in: `validityProof`, the state of the channel in question
1. With `validityProof` as input, generate a `balanceProof` asserting the channel total balance (`validityProof` is required).
- out: `balanceProof` (public input = `BalancePublicInputs`).

### 3.4 Inter-channel transfer `interChannelTransfer` (3 flows, `H2 = tx_tree_root`)

Both the sending name and the receiving name are channels. Carries a `Transfer` of transfer amount `amount` from the sending channel → the receiving channel.

> **Atomicity (structural, replacing the v1 invariant)**: transfer authorization and post-subtraction state agreement are unified into a single signature target
> `hash(H1', H2 = tx_tree_root)` (§3.3.2). Because a signature that "authorizes only the transfer and refuses the subtraction"
> cannot exist, loss-shifting to co-members (intra-channel theft) and forced close with an inflated state are
> structurally sealed off.

#### Transfer flow 1 `flowSend1` (sending channel: tx + ZKP creation 〜 structural atomic authorization 〜 propagation)

- **actor: sender**
  1. `sender` confirms on `L1` that **neither channel (sending/receiving) has a close request**.
  2. `sender` creates the `Transfer` (receiving `ChannelId`, actual recipient public key, `amount`) and
     `TxAux` (both parties' addresses, both `ChannelId`s, `senderDelta`, `recipientDelta`), and
     **generates `channelUpdateZKP`**.
  3. `sender` passes `(Transfer, TxAux, channelUpdateZKP)` to `ITS`.
- **actor: ITS**
  4. `ITS` performs `rangeProof` (= verification of `channelUpdateZKP`, §3.3.1), and if OK passes the tx to `BP`.
  5. `ITS` shares with everyone the tx contents, `TxV2Tree`, and post-subtraction `BalanceState'` (`encBalances'` = `senderDelta` applied to the sender ct,
     `settledTxChain' = hash(settledTxChain, TxLeafHash)`, `stateVersion+1`).
     Since `TxLeafHash` is known, chain' can be computed at this point.
- **actor: all of the sending channel (member[0..2])**
  6. Each `member` **signs `hash(H1', H2 = tx_tree_root)`** via `signChannelState` (§3.3.2).
     - If not all are assembled, the transfer is **not authorized** (a partial signature is invalid = the transfer does not take effect, and there is no loss to co-members).
- **actor: ITS → BP**
  7. `ITS` passes the assembled `channelStateSig` to `BP` (`BP` does `produceBlock` → `postBlock`).
- **actor: ITS (sending channel)**
  8. Once `tx_tree_root` enters an L1 block, `ITS` generates the post-subtraction `balanceProof'` via `generateBalanceProof`.
     Because `balanceProof'` is unforgeable and reflects the post-send L2 balance (`B-amount`), it **necessarily matches** the
     `BalanceState'.encBalances` (post-subtraction) already finalized by signing at step6, and the public input `settledTxChain`
     matches `BalanceState'.settledTxChain` (no new negotiation or signing is needed).
  9. `ITS` propagates `(tx data (=Transfer, TxAux, channelUpdateZKP), TxV2MerkleProof, balanceProof')` to the **receiving channel**.

#### Transfer flow 2 `flowSend2` (sending channel: balanceProof finalization)

- **actor: ITS (sending channel)**
  1. **Store locally** the `balanceProof'` of step8 as a proof **linked to** the `BalanceState'` already signed at step6.
     The state itself is already finalized and immutable at step6. The link can be mechanically verified by "the public input `settledTxChain` of `balanceProof'` =
     `BalanceState'.settledTxChain`", and L1 checks it at close submission
     (**there is no need to "put" the proof into the state afterward** — resolving the cycle of the proof not being generated at signing time, audit finding 3).
- **actor: BP (prover, in parallel)**
  2. Generate the `validityProof` for the block via `generateValidityProof` (constraining `channelStateSig` as the substitute for the tx_tree_root signature).
- Note: if the structural atomic signature (flow1 step6) is not assembled, the transfer does not take effect. For general non-responsiveness, `requestClose` (§3.5) is available upon exceeding `SIGN_TIMEOUT` (3 minutes).

#### Transfer flow 3 `flowReceive3` (receiving channel: balance state reflection, `H2 = 0`)

- **actor: all of the receiving channel (member[0..2])**
  1. Everyone confirms whether the propagated `(tx data, TxV2MerkleProof, balanceProof)` is valid
     (inclusion verification of `TxV2MerkleProof` + consistency of `balanceProof` + **verification of `channelUpdateZKP`**).
     If `balanceProof` is absent, ignore the sender.
- **actor: ITS (receiving channel)**
  2. `ITS` updates `balanceProof` on the **increase** side (`generateBalanceProof`).
  3. `ITS` looks at the recipient public key in the tx and constructs
     `BalanceState' = { encBalances' (adds the recipientDelta proven by channelUpdateZKP to the receiver's ct),
     settledTxChain' = hash(settledTxChain, TxLeafHash), stateVersion+1 }`
     (`balanceProof'` is stored locally, linked by the chain).
- **actor: all of the receiving channel (member[0..2])**
  4. Via `agreeBalanceState(BalanceState', H2 = 0)`, everyone agrees and signs `hash(H1', 0)`.

### 3.5 Channel close game

Order: `requestClose` → (`GRACE_BEFORE_PROCESS`=10 minutes) → `startProcess` → (`CHALLENGE_PERIOD`=1 day) → `closeAndWithdraw`.

#### 3.5.1 `requestClose` — **actor: any member within the channel**
- in: `channel_id`
1. Any `member` requests close to `L1`.
2. After the request, all `member`s **halt all signing actions** concerning the channel (do not perform `agreeBalanceState`, `signChannelState`, etc.). Those outside the channel also do not transfer to the channel.
3. By the grace of `GRACE_BEFORE_PROCESS` (10 minutes), signatures or communication lag immediately before/after the request are regarded as "nonexistent".

#### 3.5.2 `startProcess` — **actor: the requester (or any member)**
- in: `BalanceState` (signed by all), the `balanceProof` within it (= intmax-balanceProof)
1. 10 minutes after the request, the `member` submits `BalanceState` and `balanceProof` to `L1`.
2. `L1` confirms the all-member signature over `balanceStateHash = hash(H1, H2)`, verifies `balanceProof`, and
   checks that **the public input `settledTxChain` matches `BalanceState.settledTxChain`**, then
   starts `CHALLENGE_PERIOD` (1 day).

#### 3.5.3 `challenge` — **actor: any member**
- in: a `BalanceState_newer` (signed by all) newer than the submitted one, and the `balanceProof` within it
1. The `member` submits `BalanceState_newer` to `L1`.
2. `L1` confirms that **all submissions have all-member signatures**, and checks that the public input
   `settledTxChain` of the attached `balanceProof` matches that of the state.
3. If `BalanceState_newer.stateVersion > current submission.stateVersion`, replace.
4. At the end of the period, `finalBalanceState` / `finalBalanceProof` are finalized (preventing close with an old state).

#### 3.5.4 `closeAndWithdraw` — **actor: each member / L1 / intmax L2**
- in: finalized `finalBalanceState` / `finalBalanceProof`, `closeBurnTx`, each member's `withdrawClaimZKP`
1. **(burn tx submission)** After close-state finalization, the `member` submits `closeBurnTx` (= `Transfer { recipient: burnAddress, amount: withdrawCap, ... }`) together with `finalBalanceProof` to `L1`.
2. **(processed as L2 burn)** The same `closeBurnTx` is also processed on intmax L2 as a "close-state-finalization burn tx", and the channel balance is removed from L2's spendable.
   - To burn `withdrawCap` on L2, **that amount must actually exist in the channel** (the same solvency verification as a normal `Transfer`). An old balance already transferred away cannot be burned.
3. **(cap finalization)** `L1` verifies `finalBalanceProof` and finalizes `withdrawCap = the balance proven by finalBalanceProof = closeBurnTx.amount`.
4. **(individual withdrawal with ZKP)** Each `member` withdraws by proving on `L1`, via **`withdrawClaimZKP`**, "the plaintext of their own encrypted balance within `finalBalanceState.encBalances` = their withdrawal amount".
   `L1` enforces **Σ(withdrawals) ≤ `withdrawCap`**. Even if `finalBalanceState` claims more than `withdrawCap`, the excess cannot be withdrawn.

#### 3.5.5 `claimLateTx` — **actor: the recipient (the receiver of a late tx)**
- in: `lateBalanceProof`, `tx data`, `TxV2MerkleProof`
1. For an intmax `Transfer` to the channel notified after the close-finalized version, the recipient creates a new `balanceProof` via ZKP with `lateBalanceProof` as input (the balance circuit is identical to `balanceProof`).
2. Once verified on `L1`, the recipient receives it on-chain.
3. `lateBalanceProof` is stored on-chain as a **separate variable** from `finalBalanceProof`.

Supplement: `balanceProof` is always attached to the recipient at tx send time (`flowSend1`/`flowReceive3`). If the recipient does not have it, they ignore the sender.

---

## 4. Security mechanisms

This shows which of the **5 properties of §0** each mechanism guards.

### 4.1 Authorization authorization
- **All-member signature (`agreeBalanceState` / `coSignBalanceState` / `signChannelState`)**: a balance state update
  has the signature of all 3 people over `hash(H1, H2)` as its agreement target. Because a good node does not sign an invalid state, an invalid update does not take effect.
- **Structuring of signature atomicity**: transfer authorization and post-subtraction state agreement are unified into a single signature target `hash(H1', H2 = tx_tree_root)`.
  "A signature of only one side is invalid", which was an operational rule in v1, becomes **inexpressible by definition** in v2
  (a signature that authorizes only the transfer does not exist). Because the validity circuit verifies and constrains this signature as the substitute for the tx_tree_root signature
  (§3.3.5), it cannot be separated at the circuit level either.
- **Close is possible with the last agreed state**: even if agreement breaks down, one can close on-chain with the last `BalanceState` signed by all.

### 4.2 Double-spend / illicit mint prevention no-double-spend
- **`PublicState` (`commonState`)**: each channel holds "the block number at which a tx was last taken in" in
  `account_tree_root` (each `ChannelLeaf.prev`), preventing double-spending of the same funds or illicit minting.
- **`validityProof`**: consistently verifies `tx_tree_root`, `channelStateSig`, `Block`, and `PublicState` with ZKP, and publishes per block.
- **merkle verification in `signChannelState`**: the sending 1 user confirms that the tx is included in `TxV2Tree` via `TxV2MerkleProof` before signing.
- **Withdrawal cap (`withdrawCap`)**: the total withdrawal after close is capped by the balance proven by `finalBalanceProof`
  (`closeAndWithdraw` enforces `Σ(withdrawals) ≤ withdrawCap`). This seals off theft with an inflated state or a stale state (audit C1/C2/C5).
- **close burn tx (`closeBurnTx`)**: for L1 withdrawal, `closeBurnTx` is submitted together with `finalBalanceProof`, and
  **the same tx is also processed as a burn on intmax L2**. Because burning `withdrawCap` on L2 requires the actual balance,
  an old balance already transferred away cannot be burned and cannot be withdrawn on L1 either (sealing off the close-boundary double-spend C1).
- **state↔proof binding via `settledTxChain`**: `H1` commits not to a proof object but to a
  hash chain of the settle history, the balance circuit exposes the same chain as a public input, and at close/challenge time L1
  checks the match. This seals off the **attack of attaching a `balanceProof` based on a different settle history** to a finalized state, and
  also resolves the cycle of "the proof not being generated at signing time" (audit finding 3).

### 4.3 Solvency solvency
- **`balanceProof` attachment mandatory**: a `balanceProof` is always attached to a transfer tx. If absent, the recipient ignores the sender.
- **`rangeProof` = `channelUpdateZKP` verification**: even with balances kept encrypted, "sender balance ≥ transfer amount" is
  proven as a ZKP range constraint (replacing v1's plaintext comparison). ITS verifies it before passing to BP.
- **`channelTxZKP` (intra-channel range ZKP)**: for intra-channel transfers as well, the sender's post-update balance ≥ 0 is proven via ZKP
  (a mandatory verification item of co-sign). Even with encrypted balances, **the non-negativity of all components is inductively maintained**, and
  Σ(components) = total = `withdrawCap` is preserved. This seals off the attack of creating a negative balance component and at close
  inflating the sum of non-negative components beyond the cap to steal an honest member's withdrawal (audit finding 5).
- **Monotonic update of `balanceProof`**: updated so that the sending side decreases (`flowSend2`) and the receiving side increases (`flowReceive3`), and fixed by all-member agreement.
- **Both-wing binding of deltas**: because `TxLeafHash` binds the sending-side `senderDelta` (negative) and the receiving-side `recipientDelta` (positive) into the same hash structure,
  and `channelUpdateZKP` proves equal quantity, the tampering of "decreasing the sending side by a little and increasing the receiving side by a lot" is impossible.

### 4.4 Exit / liveness exit-liveness
- **Order and challenge of the close game**: `requestClose` → 10 minutes → `startProcess` → 1-day challenge → close.
  During the challenge period one can replace with **a state of a newer version**, and the final state is finalized (preventing close with an old state).
- **`GRACE_BEFORE_PROCESS` (10 minutes)**: signatures or communication lag immediately before/after the request can be regarded as "all nonexistent".
- **`SIGN_TIMEOUT` (3 minutes)**: if signatures are half-assembled and incomplete, it is regarded as a protocol violation, and exit is possible via close (liveness assurance).
- **Close-request confirmation of both channels (`flowSend1`)**: do not transfer to a channel that has a close request.
- **`withdrawClaimZKP`**: even if balances are encrypted, each member can prove their own share and withdraw **by themselves** (without the cooperation of other members)
  (exit does not require the decryption cooperation of others).
- **`lateBalanceProof`**: funds of an intmax tx that arrived after the close-finalized version can also be received by the recipient by on-chain verifying
  the new `balanceProof` with `lateBalanceProof` as input (preventing the loss of funds). The same circuit as `balanceProof`.

### 4.5 Balance confidentiality confidentiality (newly added in v2)
- **Regev-encrypted balances (`encBalances`)**: each person's balance is a ciphertext decryptable only with that person's `RegevPk`.
  No one other than the person, including other members within the channel, the BP, and L1, can know the individual balance.
- **Confidentiality of intra-channel transfer amount (`ChannelTx.encAmount`)**: the transfer amount is encrypted with the recipient's key and is kept confidential even from the third member.
- **`channelUpdateZKP` / `channelTxZKP`**: proves validity (equal quantity, non-negativity, ciphertext consistency,
  post-update balance ≥ 0) without revealing the plaintext of balances and deltas. Thereby confidentiality and solvency verification (§4.3) coexist
  (verification of intra-channel transfers is also possible without plaintext disclosure).
- **Confidentiality boundary (explicit)**:
  - The `amount` of an inter-channel transfer is **plaintext** as base-layer tx content and is visible from the BP and L1 (§2.3).
    What is kept confidential is **the per-individual balances and breakdown within the channel**.
  - The channel total balance is visible as a public input of `balanceProof` (needed for determining the close cap).
  - The recipient of an intra-channel transfer naturally knows the amount addressed to them (they can decrypt it).
