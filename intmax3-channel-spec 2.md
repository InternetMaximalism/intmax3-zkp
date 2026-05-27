# Intmax3 Hub-Based Confidential Channel Specification

Status: Draft 0  
Scope: Specification design only. Implementation comes next.

## 1. Purpose

This document defines an extended `Intmax3` design that supports:

- in-channel transfers
- inter-channel transfers
- channel close
- channel-close cancellation
- post-close incoming claims
- direct L1 withdrawal after close

It is based on the current `intmax3-zkp` repository and
`InternetMaximalism/SIS-lattice-paymentchannel`.

This design fixes the following decisions:

- all account IDs use `hub_id` instead of `aggregator_id`
- every account ID is a composite of `hub_id + account_no`
- in-channel state updates use `Plonky3`
- inter-channel transfer, Intmax-side settlement, import, and close use `Plonky2`

This design intentionally does **not** redesign the whole Intmax3 base protocol.

The intended boundary is:

- the base Intmax3 validity / inclusion model remains mostly unchanged
- channel-related transport objects, account naming, memo/seal handling, and withdrawal/close logic are extended
- normal non-channel Intmax3 transfer flow remains conceptually the same

## 2. Assumptions About the Current Codebase

The current `intmax3-zkp` repository has the following structure:

- `src/common/user_id.rs`: `UserId = (aggregator_id, local_id)` packed into 63 bits
- `src/common/block.rs`: blocks contain `aggregator_id` and `local_ids`
- `src/common/trees/account_tree.rs`: the account tree leaf index is `UserId`
- `src/common/tx.rs` / `src/common/transfer.rs`: the normal Intmax3 transfer model
- `src/common/channel_message.rs`: a simple channel-close message format
- `src/plonky3/*`: the Plonky3 migration bridge
- `src/circuits/**/*`: the main validity / withdrawal / settlement circuits are still Plonky2-based

Because of this, adding channel functionality alone is not sufficient. We also need to redesign:

- the ID model
- block/account-tree naming and public inputs
- the off-chain channel state
- the transport object used for inter-channel transfers
- close / cancel / withdrawal handling around the channel boundary

At the same time, the following parts are intentionally preserved as much as possible:

- the ordinary Intmax3 deposit flow
- the ordinary account tree / send tree / block inclusion architecture
- the ordinary validity recursion flow for non-channel transactions
- the ordinary non-channel transfer semantics

## 3. ID Model Changes

### 3.1 New Common ID Type

The canonical model is `AccountId`, and every actor is represented by it.

During migration, `UserId` may remain as a compatibility alias in code, but the specification
uses only `AccountId`.

```rust
struct AccountId {
    hub_id: u32,      // 31 bits
    account_no: u32,  // account number inside the hub
}
```

The encoding remains compatible with the current 63-bit packed integer format.

```text
account_id_u64 = (hub_id << 32) | account_no
```

Constraints:

- `hub_id < 2^31`
- `account_no < 2^32`
- `(hub_id, account_no) = (0, 0)` is reserved as the dummy value

### 3.2 Naming Changes

The following terminology is replaced across the codebase:

- `aggregator_id` -> `hub_id`
- `local_id` -> `account_no`
- `UserId` -> `AccountId`
- `MAX_NUM_AGGREGATORS` -> `MAX_NUM_HUBS`
- `USER_ID_BITS` -> `ACCOUNT_ID_BITS`

### 3.3 Channels Also Have `AccountId`

A channel itself is also treated as a single Intmax3 account.

```rust
type ChannelId = AccountId;
type MemberId = AccountId;
```

This lets us map the following directly onto the existing Intmax3 account model:

- the Intmax3-side owner of the channel fund
- the sender during close
- the source channel in inter-channel send

## 4. Account Categories

`AccountId` is shared, but there are two conceptual account categories.

```rust
enum AccountKind {
    User,
    Channel,
}
```

### 4.1 User Account

- a normal Intmax3 user
- has deposit / receive / withdraw / channel-join destination behavior

### 4.2 Channel Account

- represented on Intmax3 as a multisig account
- `AccountLeaf.threshold = n`
- `AccountLeaf.pk_set_root = the signing-key set of the channel members`
- external transfers from the channel are sent by this channel account

This avoids introducing a separate ID namespace specifically for channels at L1.

## 5. Required Changes to Existing Intmax3 Types

### 5.1 `src/common/user_id.rs`

Replace `UserId` with `AccountId`.

```rust
impl AccountId {
    fn new(hub_id: u32, account_no: u32) -> Result<Self, AccountIdError>;
    fn hub_id(&self) -> u32;
    fn account_no(&self) -> u32;
    fn as_u64(&self) -> u64;
}
```

### 5.2 `src/common/block.rs`

```rust
struct BlockV2 {
    num_accounts: u32,
    hub_id: u32,
    timestamp: u64,
    account_nos: Vec<u32>,
    tx_tree_root: Bytes32,
    deposit_hash_chain: Bytes32,
    forced_tx_hash_chain: Bytes32,
}
```

Changes:

- rename `aggregator_id` to `hub_id`
- rename `local_ids` to `account_nos`
- replace `aggregator_id` with `hub_id` inside the block signing message as well

The meaning does not change. The important point is that the sequencing domain is now formally a
hub, and every account is explicitly associated with a hub.

### 5.3 `src/common/trees/account_tree.rs`

The leaf index uses the packed `AccountId` value.

```text
account_tree[account_id.as_u64()] = AccountLeaf
```

`AccountLeaf` itself does not need a major change.

```rust
struct AccountLeafV2 {
    index: u32,
    prev: BlockNumber,
    send_tree_root: PoseidonHashOut,
    pk_set_root: PoseidonHashOut,
    threshold: u32,
}
```

A channel account is represented as a multisig leaf with `threshold = member_count`.

### 5.4 `src/common/transfer.rs` and `src/common/tx.rs`

The current `Transfer` / `Tx` model is enough for normal transfers, but packing channel actions
into `aux_data` would be brittle and hard to maintain.

So `Tx` is extended into a typed-body format for channel-aware transport.

```rust
enum TxClass {
    UserTransfer,
    ChannelAction,
}

struct TxV2 {
    tx_class: TxClass,
    transfer_tree_root: PoseidonHashOut,
    nonce: u32,
    channel_action_root: PoseidonHashOut, // zero for UserTransfer
}
```

`ChannelAction` represents a channel-derived action included on Intmax3.

```rust
enum ChannelActionKind {
    InterChannelSend,
    ChannelClose,
}

struct ChannelAction {
    kind: ChannelActionKind,
    source_channel_id: AccountId,
    destination_channel_id: AccountId, // zero for close
    tx_hash: Bytes32,
    seal: Bytes32,
    payload_hash: PoseidonHashOut,
}
```

Notes:

- the plaintext amount is not stored directly inside `ChannelAction`
- only the public values required for Intmax transport are bundled by hash
- detailed amount / commitment / nullifier information stays in channel-side state
- channel-specific memo / seal / bridge payload is modeled explicitly rather than overloaded into legacy `aux_data`

## 6. Off-Chain Channel State

The `ParticipantLeaf`-based structure from `SIS-lattice-paymentchannel` is extended so that
inter-channel receive-side balance updates are prepared by the sender, including dummy receiver
entries for anonymity.

### 6.1 Lattice Commitment

```rust
struct LatticeCommitment {
    commitment: [u64; M];
}

struct LatticeOpening {
    amount: u64,
    randomness: [i64; N],
}
```

### 6.2 Channel Member

```rust
struct ChannelMember {
    member_id: AccountId,
    signing_pubkey: Bytes,
    intmax_claim_destination: AccountId,
}
```

### 6.3 User Fund

```rust
struct UserFund {
    channel_id: ChannelId,
    member_id: MemberId,
    balance_commitment: LatticeCommitment,
}
```

### 6.4 Receiver Balance Delta Bundle

For an inter-channel transfer, the sender prepares the receiver-side lattice deltas in advance.
This bundle contains the real receiver plus at least two dummy receivers whose amounts are `0` or
very small.

```rust
struct ReceiverBalanceDelta {
    receiver_id: MemberId,
    amount_commitment: LatticeCommitment,
}

struct ReceiverBalanceDeltaBundle {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    tx_hash: Bytes32,
    deltas: Vec<ReceiverBalanceDelta>,
    receiver_update_p3_proof: Bytes,
}
```

Here:

- exactly one delta is the real receiver amount
- at least two deltas are dummy amounts `0` or tiny values
- the sender includes the P3 proof that these deltas are the receiver-side state update to be signed
- the receiver channel signs the post-update state containing all real and dummy additions

### 6.5 Channel Fund

```rust
struct ChannelFund {
    channel_id: ChannelId,
    visible_amount_to_members: u64,
    intmax_state_root: Bytes32,
}
```

`visible_amount_to_members` is visible to the channel members but not part of the external public
state.

### 6.6 Channel State

```rust
struct ChannelStateV2 {
    channel_id: ChannelId,
    hub_id: u32,
    epoch: u64,
    channel_fund: ChannelFund,
    user_fund_root: Bytes32,
    channel_nullifier_root: Bytes32,
    prev_state_hash: Bytes32,
    transition_hash: Bytes32,
    proof_bridge_hash: Bytes32,
    member_signatures: Vec<Signature>,
}
```

Notes:

- `transition_hash`: typed hash of the current state transition
- `proof_bridge_hash`: digest used to connect Plonky2 and Plonky3 public values

## 7. Proof System Split

### 7.1 Responsibilities of Plonky3

Plonky3 proves channel-local state transitions.

Scope:

- in-channel transfer
- receiver-side delta application for inter-channel receive
- user-fund-root update
- untouched leaf invariance

What the P3 circuit verifies directly:

- lattice commitment add/sub consistency
- sender non-negativity
- amount range
- Merkle paths
- old/new state hashes

### 7.2 Responsibilities of Plonky2

Plonky2 proves the transitions that land on the Intmax3 side.

Scope:

- inter-channel send from the sender channel
- import into the receiver channel
- channel close
- inclusion / settlement of `TxV2(ChannelAction)` inside Intmax3

What the P2 circuit verifies directly:

- Intmax3 account-tree / send-tree / tx inclusion
- validity of the channel account multisig
- uniqueness of `seal` / `tx_hash`
- consistency of public inputs between sender and receiver channels
- consistency between the final state and the payout list during close

### 7.3 How Plonky2 and Plonky3 Are Connected

Plonky3 does not recursively verify the Plonky2 proof itself.

Reason:

- the repository is currently in a mixed Plonky2 / Plonky3 transition phase
- designing heterogeneous recursive verification first would make implementation much heavier

Instead, the channel state stores `proof_bridge_hash`, which is the hash of the Plonky2 public
values.

Flow:

1. the sender channel / receiver channel verifies the Plonky2 proof
2. the public values are canonical-encoded and hashed
3. that hash is inserted into `transition_hash` or `proof_bridge_hash`
4. Plonky3 treats that hash as part of the state-transition public input

With this design, P3 only needs to reason about the sender-supplied receiver delta bundle that is
part of the receiver channel state update.

## 8. Transaction Types

### 8.1 In-Channel Transfer

```rust
struct ChannelInTx {
    channel_id: ChannelId,
    epoch: u64,
    sender_id: MemberId,
    receiver_id: MemberId,
    amount_commitment: LatticeCommitment,
    sender_post_balance_proof: Bytes,
    p3_state_proof: Bytes,
    prev_state_hash: Bytes32,
    next_state_hash: Bytes32,
}
```

Verification:

- sender / receiver are channel members
- `sender_old_balance - amount >= 0`
- `receiver_new_balance = receiver_old_balance + amount`
- untouched members remain unchanged
- `next_state_hash` matches the P3 proof

### 8.2 Inter-Channel Transfer: Sender Side

```rust
struct InterChannelSendTx {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    source_member_id: MemberId,
    epoch: u64,
    amount_commitment: LatticeCommitment,
    seal: Bytes32,
    tx_hash: Bytes32,
    recipient_memo: Bytes,
    receiver_deltas: Vec<ReceiverBalanceDelta>,
    receiver_update_p3_proof: Bytes,
    sender_debit_p2_proof: Bytes,
    channel_signatures: Vec<Signature>,
}
```

Meaning:

- decreases the sender member's `UserFund`
- decreases `ChannelFund.visible_amount_to_members` in the source channel
- carries the receiver-side lattice deltas to be applied in the destination channel
- emits `ChannelAction(InterChannelSend)` from the channel account on Intmax3

Accounting note:

- `amount_commitment` is the total sender debit
- this total equals the sum of all receiver deltas, including dummy dust amounts

The sender side uses P2 to prove Intmax3 transport correctness, while the local `UserFund` debit
is handled as a signed channel-state update. The same transport object also carries the sender-made
receiver delta bundle and its P3 proof.

### 8.3 Inter-Channel Transfer: Receiver-Side Import

```rust
struct InterChannelImportTx {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    tx_hash: Bytes32,
    seal: Bytes32,
    amount_commitment: LatticeCommitment,
    receiver_deltas: Vec<ReceiverBalanceDelta>,
    receiver_update_p3_proof: Bytes,
    inclusion_proof: Bytes,
    sender_channel_signatures: Vec<Signature>,
}
```

At import time, the receiver channel applies all sender-supplied receiver deltas immediately.
This includes the true receiver and at least two dummy receivers.

The following are updated:

- `ChannelFund.visible_amount_to_members += amount`
- `channel_nullifier_root`
- `user_fund_root`

This is assigned to P2 because Intmax3 inclusion is the essential property here.

### 8.5 Channel Close

```rust
struct CloseIntent {
    channel_id: ChannelId,
    close_epoch: u64,
    final_state_hash: Bytes32,
    channel_fund_commitment: Bytes32, // commits to visible_amount_to_members + intmax_state_root
    intmax_state_root: Bytes32,
    transfers_root: Bytes32,
    close_p2_proof: Bytes,
    member_signatures: Vec<Signature>,
}

struct FinalizedClose {
    close_intent_hash: Bytes32,
    final_state_hash: Bytes32,
    channel_fund_commitment: Bytes32,
    challenge_start_block: u64,
    challenge_end_block: u64,
}

struct CloseTransfer {
    member_id: MemberId,
    l1_recipient: Address,
    amount_commitment: LatticeCommitment,
    amount_opening_proof: Bytes,
}
```

Close is a two-phase process.

Phase 1: submit `CloseIntent`.

What is fixed by `CloseIntent`:

- the final fully signed channel state
- the channel-fund snapshot used by that close
- the payout root derived from that final state

Phase 2: wait for challenge resolution, then finalize and distribute.

During close, P2 verifies:

- the final state is signed n-of-n
- the state's `channel_id` matches the channel account
- each withdrawal entry matches the corresponding `UserFund` opening
- the total matches `channel_fund.visible_amount_to_members`
- the close withdrawal object is emitted by the channel account

### 8.6 Close Challenge Rules

The close path needs a mandatory challenge window for **both**:

- the final `ChannelStateV2`
- the `ChannelFund` snapshot (`visible_amount_to_members`, `intmax_state_root`)

Reason:

- the Intmax-side balance itself cannot be forged arbitrarily
- but a malicious participant can intentionally submit a valid under-withdrawal / under-distribution close
- therefore the contract must allow one day for anyone to replace the submitted close with a newer or more complete valid close

```rust
const CLOSE_CHALLENGE_PERIOD: u64 = 1 day;
```

The following replacements must be allowed during the challenge window:

- newer `close_epoch`
- same `close_epoch` with a strictly better `ChannelFund` snapshot if the old one omitted valid incoming value
- same state but a valid cancellation proof

### 8.7 Close Cancellation

An inter-channel send may have triggered close because the corresponding Intmax-side transport was
censored. After the final state has already been submitted onchain, that Intmax tx can later become
fully signed and valid.

In that case, the close must be cancellable.

```rust
struct CancelCloseProof {
    close_intent_hash: Bytes32,
    channel_id: ChannelId,
    final_state_hash: Bytes32,
    reactivated_tx_hash: Bytes32,
    reactivated_seal: Bytes32,
    reactivated_transport_proof: Bytes,
    all_member_signatures: Vec<Signature>,
}
```

`CancelCloseProof` establishes:

- a close for `close_intent_hash` is currently pending
- after that close submission, a fully signed valid inter-channel Intmax tx exists
- the tx belongs to the same channel and is compatible with the submitted state
- therefore the pending close should be cancelled rather than finalized

This cancellation is a protocol requirement, not an optional enhancement.

### 8.8 Post-Close Incoming Claim

There is another case: after the final channel state has been submitted onchain, an incoming
inter-channel Intmax tx may become known to a participant, but that tx was not reflected in the
`ChannelFund` snapshot used by the submitted close.

This must not be lost. Instead, it becomes a post-close claim.

```rust
struct PostCloseIncomingClaim {
    close_intent_hash: Bytes32,
    channel_id: ChannelId,
    claimer_id: MemberId,
    incoming_tx_hash: Bytes32,
    seal: Bytes32,
    receiver_amount_commitment: LatticeCommitment,
    personal_nullifier: Bytes32,
    missing_incoming_proof: Bytes,
}
```

`PostCloseIncomingClaim` establishes:

- the incoming Intmax tx is addressed to this channel
- the tx was not reflected in the `ChannelFund` snapshot used by the finalized close
- the claim does not hit the claimer's personal nullifier
- the claimer is authorized by the memo
- the post-close withdrawal claimed after close is equivalent to the missed incoming value

This is the recovery path for valid late-known incoming transfers.

### 8.9 Close Distribution and Exit Modes

After a close is finalized, the contract does **not** directly trust arbitrary participant-declared
amounts. Instead, L1 withdrawal happens from a withdrawal list proven by ZKP.

Exit modes are:

- channel close exits to L1 withdrawal recipients fixed by the proved close output
- outside close, ordinary inter-channel Intmax transfer remains available
- outside close, unanimous external payment remains available if later specified

The intended rule is:

- outside a close, channel value leaves the channel only by
  - unanimous channel agreement for an external payment, or
  - a dedicated non-close withdrawal flow if the protocol later adds one
- after a finalized close, participant payouts are executed as direct L1 withdrawals derived from the final state

## 9. State Transition Hash

The current `ChannelMessage` is only a simple allocation format for close, and that is not enough
for the new design. It is replaced by a typed transition hash.

```rust
enum ChannelTransition {
    InChannel(ChannelInTxSummary),
    InterChannelSend(InterChannelSendSummary),
    InterChannelImport(InterChannelImportSummary),
    Close(CloseSummary),
}
```

`ChannelStateV2.transition_hash` stores the hash of this summary.

Purpose:

- fix the signing target separately for each transition type
- avoid ambiguous overloading of `aux_data`
- bind the P2/P3 bridge hash to the transition

## 10. Invariants

### 10.1 In-Channel Transfer

- `channel_fund.visible_amount_to_members` is unchanged
- `sum(user_funds)` is unchanged

### 10.2 Inter-Channel Send

- the source channel's `channel_fund.visible_amount_to_members` decreases
- the sender's `UserFund` decreases
- the decrease equals the sum of all receiver deltas, including dummy dust amounts

### 10.3 Inter-Channel Import

- the destination channel's `channel_fund.visible_amount_to_members` increases
- `user_fund_root` is updated immediately
- `sum(user_funds)` increases by exactly the imported delta total

### 10.5 Accounting Equation

```text
sum(opened_user_funds) = channel_fund.visible_amount_to_members
```

### 10.6 Close Safety Invariants

- a finalized close must bind both the final channel state and the channel-fund snapshot
- a close can be cancelled if a previously censored but now fully signed inter-channel Intmax tx becomes valid
- a valid incoming tx that was not reflected in the close snapshot remains claimable after close
- no participant can be forced into loss merely because another participant submitted a valid under-distribution close first

## 11. Implementation Boundary

### 11.1 Files to Change First

- [src/common/user_id.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/user_id.rs)
- [src/constants.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/constants.rs)
- [src/common/block.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/block.rs)
- [src/common/trees/account_tree.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/trees/account_tree.rs)
- [src/common/tx.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/tx.rs)
- [src/common/transfer.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/transfer.rs)
- [src/common/channel_message.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/channel_message.rs)

### 11.2 Main New Files Needed

- `src/common/account_id.rs` or a rename of `user_id.rs`
- `src/common/channel_state_v2.rs`
- `src/common/channel_transition.rs`
- `src/common/channel_action.rs`
- `src/plonky3/channel_state/`
- `src/circuits/channel_transport/` or channel-action circuits under the existing Plonky2 validity tree

### 11.3 Primary Implementation Workstreams

The close and post-close portion should be implemented as four explicit workstreams.

1. `onchain contract`
   - store `CloseIntent`
   - enforce the 1-day challenge period for both the final channel state and the channel-fund snapshot
   - allow replacement by newer valid state/fund evidence
   - support close cancellation, finalization, L1 withdrawal, and post-close incoming recovery

2. `Plonky2 close proof`
   - prove that the final signed channel state is valid for the channel account
   - prove that the L1 withdrawal list is equivalent to the final `UserFund` state
   - prove that the withdrawal total matches the challenged `ChannelFund`
   - output the withdrawal object used after close

3. `post-close claim proof`
   - prove that a late-known incoming Intmax tx belongs to the closed channel
   - prove that it was not reflected in the finalized close snapshot
   - prove memo authorization and personal-nullifier freshness
   - allow equivalent post-close withdrawal or recovery

4. `cancel proof`
   - prove that a previously censored inter-channel Intmax tx became fully signed after close submission
   - bind that tx to the pending `CloseIntent`
   - cancel the pending close before finalization

## 12. Implementation Order

1. rename to `AccountId` while keeping packed-ID compatibility
2. convert block / account tree / signing messages to `hub_id`
3. add `ChannelStateV2`, `ChannelAction`, and typed transition hashes
4. bind `tx_tree_root` to concrete `TxV2` / `ChannelAction` witnesses inside `block_hash_chain`
5. implement Plonky3 state-update proofs for `ChannelInTx` and `ReceiveClaimTx`
6. implement Plonky2 handling for `InterChannelSendTx`, `InterChannelImportTx`, `CloseIntent`, and close distribution
7. fix the P2/P3 boundary around `proof_bridge_hash`
8. implement close challenge / cancellation / post-close-claim on the contract boundary
9. merge the current `channel_message.rs` into the new spec or remove it

## 13. Design Decisions at This Stage

- the channel itself is an Intmax3 account
- the ID system is unified as `hub_id + account_no`
- the P2/P3 connection uses a public-values hash bridge instead of proof recursion
- receiver-side balance application is bundled directly into import, and the sender carries the P3 receiver-update proof
- on-chain logic does not require a Plonky3 verifier from the start; the fully signed state is the authoritative object
- channel close is not a single final action; it is a challenged intent with cancellation and post-close recovery paths

## 14. TODO

- improve hub-level nullifier sizing by changing the nullifier tree into a year/month-capped structure
- include year/month/day metadata in the transaction body and bind it in both ZKP public inputs and channel-state updates
- use the bound date metadata to separate old nullifier subtrees from active subtrees
- allow pruning of old date-partitioned nullifier data once it is outside the active retention window

This is a reasonable MVP. It preserves the existing Plonky2 validity path while also making use of
the already-added Plonky3 bridge with the minimum architecture needed to support both.
