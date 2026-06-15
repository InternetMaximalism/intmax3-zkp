# [DEPRECATED] Intmax3 Hub-Based Confidential Multi-Party Channel Specification

Status: **DEPRECATED — superseded by `architecture-audit/detail2.md`** (the authoritative spec on the enshrined-paymentchannel line).  
Scope: Historical design draft. Retained for reference only; **do not implement from this document.**

> **Why deprecated:** This draft conflicts with `detail2.md` on nearly every foundational decision and predates the
> Regev migration / one-key identity unification already implemented:
> - **Confidential primitive:** this draft uses SIS commitments with opening hand-off; detail2 uses Regev (Ring-LWE)
>   encryption and abolishes opening hand-off (detail2 §A-1).
> - **Identity model:** this draft keeps the packed `AccountId{hub_id, account_no}` / multisig-`threshold`/`pk_set_root`
>   model; detail2 deletes `KeyId`/`UserId`/`aggregator_id` and identifies members by SPHINCS+ public-key hash
>   ("1 person 1 key 1 account", detail2 §C-9 / DA / DC).
> - **Channel state / proof binding:** `ChannelStateV2` + `proof_bridge_hash` here vs.
>   `BalanceState{enc_balances, settled_tx_chain, state_version}` + chain-equality reconciliation in detail2.
> - **Tx / block typing, nullifier model, on-chain wrapper (MLE/WHIR-only):** all diverge from the implemented design.
>
> See `architecture-audit/detail2.md` and `architecture-audit/detail2-implementation-notes.md` for the current spec.

## 1. Goals

This document defines the target design for extending `intmax3-zkp` so that it supports:

- confidential in-channel transfers
- inter-channel transfers
- receiver-side asynchronous claims
- channel close back into Intmax3

The design is based on:

- the current `intmax3-zkp` repository
- `InternetMaximalism/SIS-lattice-paymentchannel`
- the MVP protocol requirements in `/Users/plasma/Desktop/intmax3-channel-spec.md`

The following constraints are fixed:

- all accounts use `hub_id + account_no`, not `aggregator_id + local_id`
- channel-local state transitions are proven with `Plonky3`
- inter-channel settlement and Intmax3 inclusion are proven with `Plonky2`
- channel members sign every accepted state transition `n-of-n`

## 2. Current Repository Reality

The current codebase is still centered on the old Intmax3 naming and Plonky2-first execution model:

- `src/common/user_id.rs` defines `UserId = (aggregator_id, local_id)` packed into 63 bits
- `src/common/block.rs` and the validity circuits use `aggregator_id` and `local_ids`
- `src/common/tx.rs` only models the normal `transfer_tree_root + nonce` transaction shape
- `src/common/channel_message.rs` only supports a simple close-allocation message
- there is no existing `src/plonky3/` channel implementation in this repository yet

Therefore this work is not just "adding channels". It requires a cross-cutting redesign of:

- identifier types
- block/account-tree terminology
- Intmax transaction typing for channel-originated actions
- off-chain channel state and state-transition summaries
- the proof boundary between `Plonky2` and `Plonky3`

## 3. Canonical Identifier Model

### 3.1 `AccountId`

`UserId` is replaced by `AccountId`.

```rust
struct AccountId {
    hub_id: u32,      // 31 bits
    account_no: u32,  // 32 bits
}
```

Packed representation stays compatible with the current 63-bit leaf-index model:

```text
packed_account_id = (hub_id << 32) | account_no
```

Constraints:

- `hub_id < 2^31`
- `account_no < 2^32`
- `(hub_id, account_no) = (0, 0)` is reserved as the dummy value

### 3.2 Terminology Replacement

The following names are replaced repository-wide:

- `aggregator_id` -> `hub_id`
- `local_id` -> `account_no`
- `UserId` -> `AccountId`
- `MAX_NUM_AGGREGATORS` -> `MAX_NUM_HUBS`
- `USER_ID_BITS` -> `ACCOUNT_ID_BITS`

This rename affects far more than `src/common/user_id.rs`. It also flows into:

- block hashing and signature messages
- account tree indexing
- balance public inputs
- forced transaction types
- withdrawal and validity circuits
- tests and docs that currently mention `aggregator_id` / `local_id`

### 3.3 Channel IDs and Member IDs

All channel-related identities also use `AccountId`.

```rust
type ChannelId = AccountId;
type MemberId = AccountId;
```

Interpretation:

- `ChannelId` is the Intmax3 account owned collectively by the channel members
- `MemberId` is an individual user account on Intmax3

No second ID namespace is introduced for channels.

## 4. Account Categories

`AccountId` is shared across the system, but registration metadata distinguishes account purpose.

```rust
enum AccountKind {
    User,
    Channel,
}
```

### 4.1 User Account

- normal Intmax3 account
- participates in deposits, sends, receives, and withdrawals
- can join a channel as a member

### 4.2 Channel Account

- represented inside the existing account tree as a multisig account
- `threshold = member_count` for the MVP
- `pk_set_root` commits to the channel member signing set
- emits inter-channel send and close actions on Intmax3

This keeps the existing account-tree abstraction usable without introducing a separate L1 object for channel funds.

## 5. Impact on Existing Intmax3 Core Types

### 5.1 `src/common/user_id.rs`

Replace `UserId` with `AccountId`, keeping the same packed width.

```rust
impl AccountId {
    fn new(hub_id: u32, account_no: u32) -> Result<Self, AccountIdError>;
    fn hub_id(&self) -> u32;
    fn account_no(&self) -> u32;
    fn as_u64(&self) -> u64;
}
```

All circuit target helpers currently defined on `UserIdTarget` move to `AccountIdTarget`.

### 5.2 `src/constants.rs`

The bit layout stays the same, but the names change.

```rust
pub const HUB_ID_BITS: usize = 31;
pub const ACCOUNT_NO_BITS: usize = 32;
pub const ACCOUNT_ID_BITS: usize = HUB_ID_BITS + ACCOUNT_NO_BITS;
pub const ACCOUNT_TREE_HEIGHT: usize = ACCOUNT_ID_BITS;
pub const TX_TREE_HEIGHT: usize = ACCOUNT_NO_BITS;
```

### 5.3 `src/common/block.rs`

The block format becomes:

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

Meaning:

- the sequencing domain is a hub
- a block still contains only the local account numbers for that hub
- full global identity is reconstructed as `(hub_id, account_no)`

The block signing message and block hash must also use `hub_id` and `account_nos`.

### 5.4 `src/common/trees/account_tree.rs`

The account tree leaf index remains the packed 63-bit identifier:

```text
account_tree[account_id.as_u64()] = AccountLeaf
```

`AccountLeaf` does not need a structural change for the MVP:

```rust
struct AccountLeafV2 {
    index: u32,
    prev: BlockNumber,
    send_tree_root: PoseidonHashOut,
    pk_set_root: PoseidonHashOut,
    threshold: u32,
}
```

A channel account is simply a multisig leaf with `threshold = member_count`.

### 5.5 `src/common/tx.rs`

The current transaction body is too narrow for channel-originated Intmax actions. It is extended to a typed form.

```rust
enum TxKind {
    UserTransfer,
    ChannelAction,
}

struct TxV2 {
    tx_kind: TxKind,
    transfer_tree_root: Bytes32,
    nonce: u32,
    channel_action_root: Bytes32, // zero for UserTransfer
}
```

Backward-compatible interpretation:

- ordinary user sends keep using `transfer_tree_root`
- channel-originated actions set `tx_kind = ChannelAction`
- `channel_action_root` commits to one or more typed channel actions

### 5.6 `src/common/transfer.rs`

The existing `Transfer` object remains the base Intmax3 transfer payload:

```rust
struct Transfer {
    recipient: Bytes32,
    token_index: u32,
    amount: U256,
    aux_data: Bytes32,
}
```

This is kept because:

- withdrawals still need `recipient: Bytes32`
- user-to-user Intmax3 transfers still use the current path

What changes is the sender/account identity around it:

- `SettledTransfer.from` becomes `AccountId`
- any channel-specific semantics are not overloaded into `aux_data`

### 5.7 New Channel Action Payload

Channel-originated Intmax actions are modeled separately from `Transfer`.

```rust
enum ChannelActionKind {
    InterChannelSend,
    ChannelClose,
}

struct ChannelAction {
    kind: ChannelActionKind,
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId, // zero for close
    tx_hash: Bytes32,
    seal: Bytes32,
    payload_hash: Bytes32,
}
```

Notes:

- `payload_hash` binds the transport payload without exposing channel-private openings
- close uses `destination_channel_id = 0`
- channel actions are signed and settled by the channel account on Intmax3

## 6. Channel State Model

The channel state must represent:

- confidential per-member balances
- imported but unclaimed inter-channel funds
- channel-wide nullifiers
- personal nullifiers for hidden claims
- the Intmax3 state root that the channel fund is synchronized to

### 6.1 Lattice Commitment

```rust
struct LatticeCommitment {
    commitment: Bytes,
}

struct LatticeOpening {
    amount: u64,
    randomness: Bytes,
}
```

The concrete vector dimensions come from the SIS / Module-SIS parameter set and are not fixed by this document.

### 6.2 Channel Member

```rust
struct ChannelMember {
    member_id: MemberId,
    signing_pubkey: Bytes,
    intmax_claim_destination: AccountId,
}
```

`intmax_claim_destination` is fixed for the MVP and used during close.

### 6.3 User Fund

```rust
struct UserFund {
    channel_id: ChannelId,
    member_id: MemberId,
    balance_commitment: LatticeCommitment,
}
```

Each member locally stores the opening of its own `balance_commitment`.

### 6.4 Imported Incoming Leaf

An imported inter-channel transfer is recorded before it is claimed into a member balance.

```rust
struct IncomingLeaf {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    tx_hash: Bytes32,
    seal: Bytes32,
    visible_amount: u64,
    intmax_transfer_commitment: Bytes32,
    recipient_memo_hash: Bytes32,
}
```

Important:

- the receiver-side lattice commitment is **not** created at import time
- `visible_amount` is known to the destination channel members
- `recipient_memo_hash` authorizes a later private claim

### 6.5 Channel Fund

```rust
struct ChannelFund {
    channel_id: ChannelId,
    visible_amount: u64,
    intmax_state_root: Bytes32,
}
```

`visible_amount` is shared among channel members but is not part of the public L1 state.

### 6.6 Nullifiers

```rust
struct ChannelNullifier {
    value: Bytes32,
}

struct PersonalNullifier {
    value: Bytes32,
}
```

Semantics:

- `channel_nullifier_root` prevents double import / double settlement at the channel level
- `personal_nullifier_root` prevents double claim while hiding which incoming leaf was claimed

### 6.7 Signed Channel State

```rust
struct ChannelStateV2 {
    channel_id: ChannelId,
    hub_id: u32,
    epoch: u64,
    channel_fund: ChannelFund,
    user_fund_root: Bytes32,
    incoming_root: Bytes32,
    channel_nullifier_root: Bytes32,
    personal_nullifier_root: Bytes32,
    prev_state_hash: Bytes32,
    transition_hash: Bytes32,
    proof_bridge_hash: Bytes32,
    member_signatures: Vec<Signature>,
}
```

Meaning:

- `transition_hash` is the typed summary signed by members for this step
- `proof_bridge_hash` binds the `Plonky2` transport statement to the `Plonky3` state update when both are needed

## 7. Proof Responsibility Split

The split is by responsibility, not by transaction name.

### 7.1 `Plonky3`

`Plonky3` proves every mutation of `ChannelStateV2`.

Scope:

- in-channel transfer
- sender-side balance debit inside inter-channel send
- receiver-side `ChannelFund` / `incoming_root` update during import
- receiver claim into `UserFund`
- untouched leaf invariants

What `Plonky3` checks:

- lattice commitment add/sub consistency
- range constraints
- sender non-negativity
- Merkle path validity for channel-local trees
- old/new state hashes
- correct insertion of `proof_bridge_hash` into the state transition

### 7.2 `Plonky2`

`Plonky2` proves every statement that touches the Intmax3 execution layer.

Scope:

- channel account action validity
- inter-channel send transport payload correctness
- inclusion of the channel action in Intmax3
- import eligibility in the destination channel
- channel close settlement back into Intmax3

What `Plonky2` checks:

- Intmax3 account-tree / send-tree / tx inclusion
- channel multisig validity on the Intmax3 side
- uniqueness and binding of `seal` / `tx_hash`
- consistency of sender and receiver transport payloads
- close payout consistency with the signed final channel state

### 7.3 Hybrid Transitions

Inter-channel transitions require both proofs:

- `Plonky3` proves the off-chain channel state delta
- `Plonky2` proves the Intmax3 transport / inclusion statement

The repository should treat these as one logical transition with two proof artifacts, not as two unrelated transactions.

### 7.4 Proof Bridge

`Plonky3` does not recursively verify `Plonky2`.

Instead:

1. canonical-encode the public values of the relevant `Plonky2` statement
2. hash them with a dedicated domain separator
3. store that digest as `proof_bridge_hash`
4. include `proof_bridge_hash` in both the `Plonky3` public input and the signed `transition_hash`

This keeps the first implementation simple while still cryptographically binding transport and state update.

## 8. Channel Transition Types

The existing `ChannelMessage` close-only object is replaced by typed transition summaries.

```rust
enum ChannelTransition {
    InChannel(ChannelInTxSummary),
    InterChannelSend(InterChannelSendSummary),
    InterChannelImport(InterChannelImportSummary),
    ReceiveClaim(ReceiveClaimSummary),
    Close(CloseSummary),
}
```

`ChannelStateV2.transition_hash` signs a domain-separated hash of one of these summaries.

Purpose:

- separate signing domains for different operations
- avoid overloading `Transfer.aux_data`
- bind `proof_bridge_hash` explicitly where needed

## 9. Transaction and Proof Shapes

### 9.1 In-Channel Transfer

```rust
struct ChannelInTx {
    channel_id: ChannelId,
    epoch: u64,
    sender_id: MemberId,
    receiver_id: MemberId,
    amount_commitment: LatticeCommitment,
    p3_state_proof: Bytes,
    prev_state_hash: Bytes32,
    next_state_hash: Bytes32,
}
```

Verification:

- sender and receiver are channel members
- sender balance is reduced by the committed amount
- receiver balance is increased by the same commitment
- sender post-balance is non-negative
- untouched members remain unchanged

This transition uses `Plonky3` only.

### 9.2 Inter-Channel Send

```rust
struct InterChannelSendTx {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    source_member_id: MemberId,
    epoch: u64,
    sender_amount_commitment: LatticeCommitment,
    seal: Bytes32,
    tx_hash: Bytes32,
    intmax_transfer_commitment: Bytes32,
    recipient_memo: Bytes,
    p3_state_proof: Bytes,
    p2_transport_proof: Bytes,
    channel_signatures: Vec<Signature>,
}
```

`Plonky3` proves:

- sender `UserFund` is debited
- `channel_fund.visible_amount` decreases
- `channel_nullifier_root` is updated
- state hash advances correctly

`Plonky2` proves:

- the channel account emits the matching Intmax3 channel action
- `seal`, `tx_hash`, and `intmax_transfer_commitment` are bound consistently
- the transport statement is valid on the Intmax3 side

### 9.3 Inter-Channel Import

```rust
struct InterChannelImportTx {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    epoch: u64,
    tx_hash: Bytes32,
    seal: Bytes32,
    visible_amount: u64,
    intmax_transfer_commitment: Bytes32,
    recipient_memo_hash: Bytes32,
    p2_inclusion_proof: Bytes,
    p3_state_proof: Bytes,
    sender_channel_signatures: Vec<Signature>,
}
```

`Plonky2` proves:

- the sender-side channel action exists in Intmax3
- the destination channel matches
- the sender channel authorization is valid

`Plonky3` proves:

- `channel_fund.visible_amount += visible_amount`
- a new `IncomingLeaf` is inserted
- `channel_nullifier_root` is updated
- the destination channel state advances correctly

Receiver `UserFund` is unchanged at this stage.

### 9.4 Receiver Claim

```rust
struct ReceiveClaimTx {
    channel_id: ChannelId,
    epoch: u64,
    receiver_id: MemberId,
    incoming_leaf_hash: Bytes32,
    receiver_amount_commitment: LatticeCommitment,
    personal_nullifier: Bytes32,
    p3_claim_proof: Bytes,
    prev_state_hash: Bytes32,
    next_state_hash: Bytes32,
}
```

`Plonky3` proves:

- `incoming_leaf_hash` is present in `incoming_root`
- the receiver is authorized by `recipient_memo_hash`
- `receiver_amount_commitment` opens to the same amount as the imported transfer
- `personal_nullifier` is correctly derived and unused
- the receiver `UserFund` is increased correctly

This is a channel-local update, so it uses `Plonky3` only.

### 9.5 Channel Close

```rust
struct CloseChannelTx {
    channel_id: ChannelId,
    final_state_hash: Bytes32,
    intmax_state_root: Bytes32,
    transfers_root: Bytes32,
    p2_close_proof: Bytes,
}

struct CloseTransfer {
    member_id: MemberId,
    destination: AccountId,
    amount_commitment: LatticeCommitment,
    amount_opening_proof: Bytes,
}
```

`Plonky2` verifies:

- the final `ChannelStateV2` is signed `n-of-n`
- the state corresponds to the channel account
- each close transfer matches the corresponding `UserFund`
- the close payout total matches `channel_fund.visible_amount`
- the close action is emitted by the channel account on Intmax3

No `Plonky3` verifier is required on-chain for the MVP. The signed final state is authoritative.

## 10. State and Accounting Invariants

### 10.1 In-Channel Transfer

- `channel_fund.visible_amount` is unchanged
- `sum(user_funds)` is unchanged

### 10.2 Inter-Channel Send

- source `channel_fund.visible_amount` decreases
- sender `UserFund` decreases

### 10.3 Inter-Channel Import

- destination `channel_fund.visible_amount` increases
- `sum(user_funds)` is unchanged
- `incoming_root` changes

### 10.4 Receiver Claim

- receiver `UserFund` increases
- `channel_fund.visible_amount` is unchanged
- `personal_nullifier_root` changes

### 10.5 Accounting Equation

```text
sum(opened_user_funds) + unclaimed_incoming = channel_fund.visible_amount
```

## 11. Implementation Boundary in This Repository

### 11.1 First-Round Files to Refactor

- `src/common/user_id.rs`
- `src/constants.rs`
- `src/common/block.rs`
- `src/common/trees/account_tree.rs`
- `src/common/public_state.rs`
- `src/common/forced_tx.rs`
- `src/common/tx.rs`
- `src/common/transfer.rs`
- `src/common/channel_message.rs`

### 11.2 New Files / Modules Needed

- `src/common/account_id.rs` or a rename of `user_id.rs`
- `src/common/channel_action.rs`
- `src/common/channel_state_v2.rs`
- `src/common/channel_transition.rs`
- `src/circuits/channel_transport/` for the `Plonky2` channel-action path
- `src/plonky3/channel_state/` or an equivalent new module for `Plonky3` channel-state circuits

### 11.3 Important Correction to Earlier Assumptions

The repository does **not** currently contain a usable `src/plonky3/*` channel implementation.  
Introducing `Plonky3` here is new work, not a small adaptation of an existing module.

## 12. Recommended Implementation Order

1. replace `UserId` with `AccountId` while preserving packed-ID compatibility
2. rename block/public-state/circuit terminology from `aggregator` to `hub`
3. add `TxV2` and `ChannelAction`
4. replace `ChannelMessage` with typed `ChannelTransition` summaries
5. add `ChannelStateV2`, `IncomingLeaf`, and nullifier roots
6. implement `Plonky3` channel-state circuits for:
   - in-channel transfer
   - sender-side state delta of inter-channel send
   - receiver-side import state delta
   - receiver claim
7. implement `Plonky2` transport/inclusion circuits for:
   - inter-channel send
   - inter-channel import
   - channel close
8. finalize the `proof_bridge_hash` encoding and signing rules

## 13. Design Decisions Fixed by This Draft

- the ID system is unified as `hub_id + account_no`
- a channel is an Intmax3 account, not a separate namespace object
- `Plonky3` owns all channel-state mutations
- `Plonky2` owns Intmax3 transport and inclusion statements
- inter-channel send/import are hybrid transitions bound by `proof_bridge_hash`
- receiver claim is separate from import and stays channel-local
- close is verified against the signed final channel state and settled by the channel account

This is the target MVP architecture for implementing inter-channel transfer support in this repository.
