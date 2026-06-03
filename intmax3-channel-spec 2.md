# Intmax3 Channel-Based Confidential Payment Specification

Status: Draft 1  
Scope: Specification design only. Implementation follows this document.

## 1. Purpose

This document defines an `Intmax3` extension that supports:

- confidential in-channel transfers
- channel-to-channel native Intmax transfers
- BP-driven small-block sequencing inside each channel
- normal close
- special close with BP slashing
- close cancellation
- post-close recovery of late-known incoming native transfers
- direct L1 withdrawal after close

This design uses the following terminology throughout:

- `channel balance`: a participant balance represented by a lattice commitment inside the channel
- `Intmax balance`: the channel fund on native Intmax, visible to channel members and owned by the channel

The protocol keeps the base Intmax architecture mostly unchanged, but changes the channel boundary
substantially:

- native authorization becomes `ChannelId / KeyId / UserId` based
- native channel-to-channel transfer becomes a fully signed small-block-root flow
- channel-local state updates use `Plonky3`
- Intmax-side transport, close, cancel, and post-close recovery use `Plonky2`
- close freezes the channel for further native sends

## 2. Core Update Summary

The core design update is:

1. a channel is a native authorization domain
2. each channel has an ordered member set of `KeyId`
3. each `KeyId` has its own SPHINCS+ key set and threshold
4. each signing identity is `UserId = ChannelId || KeyId`
5. BP collects many native channel txs into a small-block Merkle tree
6. all channel members verify the full small block and sign the same small-block root message
7. a small block is valid only when every member `KeyId` condition is satisfied on that root
8. sender-side and receiver-side channel state updates are both all-member state transitions
9. if a fully signed small block is not included within `5` medium blocks, anyone may trigger a
   special close and slash the BP
10. after close submission, that channel is frozen for new native sends

This replaces the older simplified model where native transport was treated as a channel-local
object with optional signatures attached.

## 3. Identity and Registry Model

### 3.1 Canonical IDs

The canonical native authorization IDs are:

```rust
type ChannelId = [u8; 5];
type KeyId = [u8; 5];
type UserId = [u8; 10]; // ChannelId || KeyId
```

Rules:

- `UserId` is exactly the byte concatenation `channel_id || key_id`
- byte order is fixed network byte order
- `ChannelId` is the native identifier of the hub/channel in MVP
- every signature message binds the exact `UserId`

### 3.2 Channel Record

Each channel has a registration record:

```rust
struct ChannelRecord {
    channel_id: ChannelId,
    bp_key_id: KeyId,
    member_key_ids: Vec<KeyId>, // strictly ordered, no duplicates
    member_key_ids_root: Bytes32,
    special_close_penalty: U256,
    status: ChannelStatus,
}

enum ChannelStatus {
    Active,
    ClosePending,
    Closed,
}
```

Constraints:

- MVP fixes exactly one BP per channel at a time
- `member_key_ids` is canonicalized as a strictly ordered list
- every `member_key_id` must exist in the key registry
- `status = ClosePending` freezes further outgoing native sends from this channel

### 3.3 Key Record

Each `KeyId` resolves to a SPHINCS+ threshold authorization record:

```rust
struct KeyRecord {
    key_id: KeyId,
    sphincs_pubkey_hashes_root: Bytes32,
    threshold: u32,
    num_keys: u32,
}
```

Semantics:

- one `KeyId` is one channel participant authorization domain
- that participant may itself use threshold SPHINCS+ signing internally
- native proof systems verify that the threshold condition of that `KeyId` is satisfied

### 3.4 Native Authorization Rule

For a native small-block root to be valid for a channel:

- for every `key_id` in `ChannelRecord.member_key_ids`
- there exists a valid threshold-signature proof for `UserId = channel_id || key_id`
- all such proofs are bound to the same small-block root message

This is stricter than a single multisig account threshold. The native channel root is valid only if
all registered participant domains sign it.

## 4. Native Message and Signature Model

### 4.1 Signed Message

Participants do not sign isolated channel-to-channel tx objects directly. They sign the small-block
root message:

```rust
struct SmallBlockRootMessage {
    channel_id: ChannelId,
    bp_key_id: KeyId,
    small_block_number: u64,
    prev_small_block_root: Bytes32,
    tx_tree_root: Bytes32,
    state_commitment_root: Bytes32,
    medium_epoch_hint: u64,
    close_freeze_nonce: u64,
}
```

Each signature proof additionally binds:

- `user_id`
- the corresponding `KeyRecord`
- the corresponding inclusion proof that `key_id` is a member of `channel_id`

### 4.2 Reuse of INTMAX PQ Signature Verification

The channel protocol should reuse the existing INTMAX PQ signature verification and aggregation
machinery wherever possible.

Required reuse points:

- verifying each `KeyId` threshold satisfaction on a small-block root
- proving that all `KeyId` conditions for a channel are satisfied
- proving all-member channel final-state signatures during close
- proving all-member confirmation during receiver-side Intmax-balance updates

This is preferred over inventing a second incompatible PQ signature stack just for channels.

## 5. BP and Block Hierarchy

### 5.1 BP Role

In MVP, each channel has one fixed BP chosen when the channel is registered.

BP responsibilities:

- collect native channel txs
- build a small-block Merkle tree
- provide all tx data, proofs, and resulting state commitments to every member
- collect all-member root signatures
- submit the signed small block into the native Intmax pipeline

### 5.2 Small / Medium / Large Blocks

The native sequence hierarchy is:

1. `small block`
   - cadence: seconds
   - contents: one channel-local Merkle tree of native txs
   - final off-chain condition: all member `KeyId` conditions satisfied on the same root

2. `medium block`
   - cadence: minutes
   - semantics: optimistic rollup-style aggregation of many small blocks
   - used as the timeout reference for special close

3. `large block`
   - cadence: hours
   - semantics: fully onchain verified ZKP checkpoint

The protocol must define deterministic inclusion relations:

- a small block is either included in a medium block or not
- a medium block is either included in a large block or not
- close and special close reason about the latest finalized medium-block boundary

## 6. Channel State

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
    key_id: KeyId,
    user_id: UserId,
    l1_withdrawal_recipient: Address,
}
```

### 6.3 Channel Balance

```rust
struct ChannelBalance {
    channel_id: ChannelId,
    key_id: KeyId,
    balance_commitment: LatticeCommitment,
}
```

This is the member's confidential in-channel balance.

### 6.4 Channel Fund

```rust
struct ChannelFund {
    channel_id: ChannelId,
    intmax_visible_amount_to_members: u64,
    intmax_state_root: Bytes32,
}
```

This is the native Intmax balance of the channel. It is part of the channel state and must be
agreed by all members.

### 6.5 Channel State

```rust
struct ChannelState {
    channel_id: ChannelId,
    epoch: u64,
    small_block_number: u64,
    channel_fund: ChannelFund,
    channel_balance_root: Bytes32,
    shared_native_nullifier_root: Bytes32,
    prev_state_hash: Bytes32,
    transition_hash: Bytes32,
    proof_bridge_hash: Bytes32,
    all_member_signatures: Vec<Signature>,
}
```

Notes:

- `channel_balance_root` commits to all confidential participant balances
- `shared_native_nullifier_root` is still required for native Intmax transport uniqueness
- the old receiver personal-nullifier claim path is not part of the normal receive flow anymore
- `all_member_signatures` means one satisfied authorization proof per registered `KeyId`

## 7. Proof System Split

### 7.1 Plonky3 Scope

`Plonky3` proves channel-local state transitions:

- in-channel transfer
- sender-side channel-balance debit for channel-to-channel send
- receiver-side application of sender-supplied receiver delta bundles
- channel-balance Merkle updates
- balance non-negativity and amount range
- dummy-commitment structure for receiver anonymity

### 7.2 Plonky2 Scope

`Plonky2` proves Intmax-side and close-side transitions:

- native transport correctness for sender-side and receiver-side channel updates
- inclusion of signed small blocks into medium/large-block flow
- normal close
- special close
- close cancellation
- post-close incoming recovery

### 7.3 Bridge Rule

The P2/P3 boundary is bridged by a public-values hash:

- native transport and inclusion results are canonicalized and hashed
- that hash enters `proof_bridge_hash`
- P3 channel-state proofs bind that bridge hash

This keeps the mixed P2/P3 architecture implementable in MVP.

## 8. Native Channel-to-Channel Transfer

### 8.1 Native Tx Object

The native channel-to-channel tx is hub-to-hub:

```rust
struct NativeChannelTransfer {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    source_key_id: KeyId,
    tx_hash: Bytes32,
    seal: Bytes32,
    amount_commitment: LatticeCommitment,
    recipient_memo: Bytes,
    sender_channel_balance_delta_p3_proof: Bytes,
    receiver_delta_bundle: ReceiverDeltaBundle,
    transport_p2_public_hash: Bytes32,
}
```

### 8.2 Receiver Delta Bundle

The sender prepares the receiver-side confidential additions in advance:

```rust
struct ReceiverDelta {
    receiver_key_id: KeyId,
    amount_commitment: LatticeCommitment,
}

struct ReceiverDeltaBundle {
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    tx_hash: Bytes32,
    deltas: Vec<ReceiverDelta>,
    receiver_bundle_p3_proof: Bytes,
}
```

Rules:

- exactly one delta is the real receiver amount
- at least two deltas are dummy amounts `0` or tiny dust
- the sender supplies the P3 proof that the bundle is the receiver-side confidential update
- the receiver channel later signs the post-update state containing all real and dummy additions

This replaces the older personal-nullifier-based confidential receive claim as the normal path.

### 8.3 Sender-Side Flow

Sender-side native send proceeds as follows:

1. sender prepares the native channel transfer and the sender-side P3 channel-balance debit proof
2. BP collects the tx into the channel's small-block Merkle tree
3. every channel member verifies:
   - the tx contents
   - the sender-side P3 debit proof
   - the native transport P2 bridge data
   - the resulting Intmax-balance update
4. every member signs the same small-block root message
5. once every `KeyId` condition is satisfied, the small block is a fully signed native root
6. after native confirmation, the sender channel updates:
   - `channel_fund.intmax_visible_amount_to_members -= amount`
   - sender channel balance decreases
   - shared native nullifier root updates
7. all members sign the resulting new `ChannelState`

If sender-side all-member signatures do not complete within the timeout, the channel closes.

### 8.4 Receiver-Side Flow

Receiver-side reflection proceeds as follows:

1. one sender-side participant communicates the fully signed native tx, inclusion data, and
   receiver bundle to the receiver channel
2. the receiver channel verifies:
   - the native tx belongs to this destination channel
   - the native transport proof and inclusion proof are valid
   - the tx is confirmed in the native flow
   - the sender-supplied receiver delta bundle and its P3 proof are valid
3. receiver channel first updates its `ChannelFund` Intmax balance state
4. all receiver members sign that updated state
5. receiver channel then applies the confidential receiver delta bundle to `channel_balance_root`
6. all receiver members sign the post-application state

If any receiver-side member refuses or the update is not propagated, the receiver channel cannot
reach consensus on state and must close.

## 9. Small-Block Finality and Failure

### 9.1 Fully Signed Small Block

A small block is fully signed only if:

- every registered `KeyId` of the channel has a satisfied threshold-signature proof
- all those proofs bind the same `SmallBlockRootMessage`
- the channel is not frozen by a pending close

### 9.2 Partial Signature Failure

If only a partial set of members sign:

- signing participants treat it as protocol failure
- the small block is not valid
- if the timeout expires without full signatures, the channel must close

```rust
const SMALL_BLOCK_SIGNATURE_TIMEOUT: u64 = 1 minute;
```

### 9.3 BP Penalty Reserve

BP must prove that its penalty reserve remains above the configured slashing amount.

The required statement is:

```text
special_close_penalty <= bp_available_native_balance < 2^64
```

This is the same range-proof family as ordinary balance proofs, but with lower bound
`special_close_penalty` instead of `0`.

If BP cannot prove this reserve condition, members must not sign outgoing native transfer blocks
proposed by that BP.

## 10. Close Freeze Rule

Once a close is submitted for `channel_id`:

- `ChannelRecord.status` becomes `ClosePending`
- `close_freeze_nonce` increases
- any later small block from that channel is invalid

This must be enforced by native validity constraints:

- the small-block root message binds `close_freeze_nonce`
- native inclusion circuits reject a small block whose `channel_id` is already `ClosePending`
- sender-side transport proofs from a frozen channel are invalid

This prevents a channel from continuing to issue native transfers after close submission.

## 11. Close Types

### 11.1 Normal Close

Normal close fixes:

- the final fully signed `ChannelState`
- the final `channel_balance_root`
- the final `ChannelFund` snapshot
- the burn-backed native withdrawal object

```rust
struct CloseWithdrawal {
    channel_id: ChannelId,
    final_state_hash: Bytes32,
    final_channel_balance_root: Bytes32,
    intmax_state_root: Bytes32,
    burn_tx_hash: Bytes32,
    burn_amount: U256,
    close_p2_proof: Bytes,
}

struct CloseIntent {
    channel_id: ChannelId,
    close_epoch: u64,
    final_state_hash: Bytes32,
    final_channel_balance_root: Bytes32,
    channel_fund_commitment: Bytes32,
    intmax_state_root: Bytes32,
    burn_tx_hash: Bytes32,
    close_withdrawal_digest: Bytes32,
    snapshot_medium_block_number: u64,
    all_member_signature_proof: Bytes,
}
```

The protocol intentionally does **not** build a plaintext payout list for all members at close.
That is rejected because confidential balances would require collecting every participant's balance
opening. Instead:

- close fixes the confidential root and burned native value
- each participant withdraws later with an individual proof

### 11.2 Special Close

If a fully signed small block is not included within `5` medium blocks, any channel participant may
trigger a special close:

```rust
struct SpecialCloseProof {
    channel_id: ChannelId,
    offending_bp_key_id: KeyId,
    fully_signed_small_block_root: Bytes32,
    small_block_number: u64,
    signed_medium_block_number: u64,
    latest_finalized_medium_block_number: u64,
    non_inclusion_proof: Bytes,
    all_member_signature_proof: Bytes,
}
```

Required statement:

- the small block was fully signed by the whole channel
- it still was not included by the time `latest_finalized_medium_block_number >= signed_medium_block_number + 5`
- therefore the channel may special-close and the BP is slashed by `special_close_penalty`

This is different from normal close because it additionally punishes BP censorship or failure.

### 11.3 Why Both Close Types Exist

- normal close handles ordinary exit, disagreement, or timeout
- special close handles a fully signed but withheld small block

Both freeze the channel immediately when submitted.

## 12. Individual Withdrawal After Close

After close finalization, L1 withdrawal is individual and root-based:

```rust
struct WithdrawalClaim {
    close_intent_hash: Bytes32,
    user_id: UserId,
    l1_recipient: Address,
    amount_commitment: LatticeCommitment,
    membership_proof: MK,
    withdrawal_nullifier: Bytes32,
    amount_opening_proof: Bytes,
}
```

The withdrawal proof must establish:

- the claimant leaf is included in `final_channel_balance_root`
- the lattice opening is valid
- the claimant `user_id` matches a registered channel member
- the `l1_recipient` matches the registered withdrawal recipient
- the `withdrawal_nullifier` is fresh

Contract rule:

- the total amount withdrawn from this close may not exceed the burned `ChannelFund` amount

The burn-backed close object is required so the same native value cannot remain spendable on L2 and
also be claimed on L1.

## 13. Close Challenge, Cancellation, and Recovery

### 13.1 Mandatory Challenge Window

Close must challenge both:

- the final channel state
- the `ChannelFund` snapshot

```rust
const CLOSE_CHALLENGE_PERIOD: u64 = 1 day;
```

Reason:

- a malicious participant may submit a valid but incomplete close
- the protocol must allow replacement by a newer or more complete valid close

### 13.2 Close Cancellation

If a channel tried to close because a native transfer appeared censored, but later that native tx
becomes fully signed and valid, the pending close must be cancellable.

```rust
struct CancelCloseProof {
    close_intent_hash: Bytes32,
    channel_id: ChannelId,
    final_state_hash: Bytes32,
    revived_small_block_root: Bytes32,
    revived_tx_hash: Bytes32,
    revived_seal: Bytes32,
    revived_transport_proof: Bytes,
    all_member_signature_proof: Bytes,
}
```

Required statement:

- the close is pending
- after close submission, a fully signed valid native transfer or small block exists
- that revived native object belongs to the same channel and invalidates the close assumption

If cancellation succeeds:

- the pending close is removed
- `ChannelRecord.status` returns to `Active`
- the revived native object may proceed through the normal inclusion path

### 13.3 Post-Close Incoming Recovery

If a valid incoming native transfer to the channel was not reflected in the close snapshot, it must
still be recoverable after close.

```rust
struct PostCloseIncomingClaim {
    close_intent_hash: Bytes32,
    channel_id: ChannelId,
    claimer_user_id: UserId,
    incoming_tx_hash: Bytes32,
    seal: Bytes32,
    receiver_amount_commitment: LatticeCommitment,
    missing_incoming_proof: Bytes,
    shared_native_nullifier: Bytes32,
}
```

Required statement:

- the incoming native tx is addressed to this channel
- it was not reflected in the finalized close snapshot
- it is not already consumed in the shared native nullifier root
- the claim amount is equivalent to the missed incoming value

This claim additionally updates the shared native nullifier so the value cannot be claimed twice.

### 13.4 Late Outgoing Debit at Close

If a native outgoing tx was created just before a participant tried to close using the previous
state, the sender-prepared Plonky3 channel-balance-decrease commitment and proof may be used to
carry that outgoing debit into the close state.

This means the close logic must support:

- proving that a sender-side native tx was already fully formed and signed at the channel level
- proving that its sender-side confidential debit proof exists
- adjusting the close state so the stale pre-send state cannot be used to avoid the debit

This is required to prevent a sender from closing on the immediately previous state after emitting a
native transfer.

## 14. Invariants

### 14.1 In-Channel Transfer

- `ChannelFund.intmax_visible_amount_to_members` is unchanged
- the sum of channel balances is unchanged

### 14.2 Native Inter-Channel Send

- sender-side `ChannelFund.intmax_visible_amount_to_members` decreases
- sender-side channel balance decreases
- the decrease equals the total of the receiver delta bundle, including dummy dust amounts

### 14.3 Receiver Intmax-Balance Import

- receiver-side `ChannelFund.intmax_visible_amount_to_members` increases
- `channel_balance_root` may remain temporarily unchanged until the delta bundle is applied

### 14.4 Receiver Bundle Application

- receiver-side `channel_balance_root` increases by the bundle total
- exactly one receiver delta is real
- at least two receiver deltas are dummy commitments

### 14.5 Accounting Equation

Because receiver import and receiver bundle application may be separate transitions:

```text
sum(opened_channel_balances) + unallocated_confirmed_incoming
    = ChannelFund.intmax_visible_amount_to_members
```

After the receiver bundle is fully applied:

```text
sum(opened_channel_balances) = ChannelFund.intmax_visible_amount_to_members
```

### 14.6 Close Safety

- no close may ignore a fully signed and provable outgoing native debit
- no valid late-known incoming native value may be lost
- no post-close claim may bypass the shared native nullifier
- once close is pending, the channel is frozen for new native sends
- a fully signed but withheld small block can trigger slashing special close

## 15. Implementation Boundary

### 15.1 Migration Impact

The current repository still contains a legacy packed `AccountId = hub_id + account_no` model in
multiple places. This specification supersedes that as the canonical native authorization model.

Implementation must therefore migrate:

- native signing identities: from `AccountId` to `UserId = ChannelId || KeyId`
- channel membership: from one account-threshold leaf to `ChannelRecord + KeyRecord`
- channel-level finality: from optional attached signatures to fully signed small-block roots

The legacy packed account model may remain temporarily only as an implementation bridge for
non-channel Intmax components.

### 15.2 Files and Modules That Must Change

- [src/common/user_id.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/user_id.rs)
- [src/common/trees/account_tree.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/trees/account_tree.rs)
- [src/common/key_set.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/key_set.rs)
- [src/common/tx.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/tx.rs)
- [src/common/channel.rs](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/common/channel.rs)
- [src/circuits/validity/signature_aggregation/](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/src/circuits/validity/signature_aggregation)
- [contracts/src/ChannelSettlementManager.sol](/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/contracts/src/ChannelSettlementManager.sol)

### 15.3 Main Workstreams

1. `registry refactor`
   - add `ChannelRecord`
   - add `KeyRecord`
   - bind `UserId = ChannelId || KeyId`

2. `native sign-back integration`
   - make small-block root signing the canonical native authorization event
   - prove that every `KeyId` condition of a channel is satisfied
   - reuse INTMAX PQ aggregation logic

3. `BP and special-close logic`
   - fixed BP registration for MVP
   - penalty reserve proof
   - special close with slashing if a fully signed small block is withheld

4. `receiver-flow rewrite`
   - sender-prepared receiver delta bundle
   - receiver-side Intmax-balance consensus
   - receiver-side channel-balance bundle application consensus
   - no ordinary personal-nullifier receive claim path

5. `close and post-close`
   - normal close
   - freeze rule
   - cancellation by revived native tx
   - post-close incoming recovery
   - stale close prevention for just-emitted outgoing native txs

## 16. Implementation Order

1. introduce `ChannelId`, `KeyId`, and `UserId`
2. add `ChannelRecord` and `KeyRecord`
3. change native signature messages to small-block root messages
4. integrate INTMAX PQ signature aggregation over all `KeyId` of a channel
5. bind sender-side and receiver-side native transport to fully signed small blocks
6. add BP penalty reserve proof and special close
7. add close freeze rule to native validity constraints
8. implement root-based close withdrawal claims
9. implement close cancellation and post-close incoming recovery
10. implement stale-close correction for already-emitted outgoing native txs

## 17. Design Decisions Fixed by This Draft

- a channel is the native authorization domain in MVP
- each channel has one fixed BP in MVP
- canonical native signing identity is `UserId = ChannelId || KeyId`
- a native small block is valid only if all channel member `KeyId` conditions are satisfied
- sender-prepared dummy receiver bundles replace the ordinary personal-nullifier receive-claim path
- `ChannelFund` Intmax balance is part of the all-member channel state
- after close submission, the channel is frozen for new native sends
- special close exists and slashes BP for withholding a fully signed small block
- close and small-block finality should reuse INTMAX PQ signature verification logic

## 18. TODO

- improve hub-level nullifier sizing by changing the nullifier tree into a year/month-capped structure
- include year/month/day metadata in the transaction body and bind it in both ZKP public inputs and channel-state updates
- use the bound date metadata to separate old nullifier subtrees from active subtrees
- allow pruning of old date-partitioned nullifier data once it is outside the active retention window
- add BP rotation and replacement rules after MVP
- add a deterministic rule for medium-block and large-block cutoff references during close challenges
