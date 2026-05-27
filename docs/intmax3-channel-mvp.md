# Intmax3 Channel MVP Integration Notes

This repository now contains the first implementation layer for the hub-based
Intmax3 channel model described in
`/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/intmax3-channel-spec 2.md`.

## Implemented foundations

- `src/common/user_id.rs`
  - introduced `AccountId`
  - canonical naming is now `hub_id + account_no`
  - backward-compatible `UserId` aliases remain so existing proofs still compile

- `src/constants.rs`
  - introduced `HUB_ID_BITS`, `ACCOUNT_NO_BITS`, `ACCOUNT_ID_BITS`, `MAX_NUM_HUBS`
  - old aggregator/local constants remain as aliases during migration

- `src/common/channel.rs`
  - added channel-side state objects:
    - `ChannelFund`
    - `UserFund`
    - `ChannelMember`
    - `ChannelState`
    - `Pay`
    - `InterChannelTx`
    - `ReceiverClaim`
    - `CloseWithdrawal`
  - inter-channel receive design is now changing toward:
    - sender-supplied receiver-side lattice delta bundles
    - at least two dummy receiver deltas per inter-channel receive
    - receiver channel signs the post-update state directly instead of using a later receiver claim flow
  - added transition classification:
    - channel state updates use `Plonky3`
    - Intmax transport / close settlement use `Plonky2`
    - concretely:
      - `InChannelTransfer` -> state proof `Plonky3`
      - `ReceiverClaim` -> state proof `Plonky3`
      - `InterChannelSend` -> state proof `Plonky3` + transport proof `Plonky2`
      - `InterChannelImport` -> state proof `Plonky3` + transport proof `Plonky2`
      - `ChannelClose` -> close settlement proof `Plonky2`
  - added close-side protocol objects:
    - `CloseIntent`
    - `CancelClose`
    - `PostCloseIncomingClaim`
  - these now define the hash-bound inputs for the future onchain contract and
    Plonky2 close/cancel/post-close-claim proofs

- `src/common/tx.rs`
  - added `TxV2`
  - added `ChannelAction`
  - preserved legacy `Tx` so current validity/balance circuits stay unchanged

## Current intent

This is an additive migration layer, not the final cut-over.

The existing Intmax3 circuits still operate on the legacy transaction and
account objects. The newly added types are intended to be the stable interface
for the next steps:

1. migrate block/account-tree flows from aggregator naming to hub naming
2. implement Plonky3-backed in-channel state transition proofs
3. implement Plonky2-backed inter-channel send/import/close proofs
4. connect `TxV2::ChannelAction` into block inclusion and settlement logic

## Spec Location

The canonical working spec is now stored in-repo at:

- `intmax3-channel-spec 2.md`

## Immediate follow-up files

- `src/common/block.rs`
- `src/common/public_state.rs`
- `src/circuits/validity/block_hash_chain/*`
- `src/circuits/balance/*`
- `src/common/channel_message.rs`

These areas still use legacy `aggregator_id` / `local_id` naming and will need
the next migration pass.

## Close Workstreams

The updated channel-close specification breaks implementation into four parallel
workstreams.

1. `onchain contract`
   - store `CloseIntent`
   - enforce the 1-day challenge period for both final state and channel-fund snapshot
   - support replacement, cancellation, and finalization
   - support direct L1 withdrawal exits and post-close payout claims

2. `Plonky2 close proof`
   - prove final-state validity against the channel account
   - prove L1-withdrawal-list equivalence to the final `UserFund` state
   - prove withdrawal total matches the challenged `ChannelFund`
   - emit the close-side L1 withdrawal settlement object
   - current repository state:
     - `src/circuits/channel/close_pis.rs` defines the witness/public-input boundary
     - `src/circuits/channel/close_circuit.rs` now proves the `CloseIntent` public inputs in Plonky2
     - `final ChannelState / ChannelFund snapshot / CloseWithdrawal` equivalence is enforced in witness generation today
     - the next step is moving those equality checks from Rust witness validation into dedicated circuit constraints where the payload is size-bounded

3. `post-close claim proof`
   - prove a late-known incoming Intmax transfer belongs to the closed channel
   - prove it was not reflected in the finalized close snapshot
   - prove memo authorization and personal-nullifier freshness
   - allow equivalent post-close withdrawal / recovery

4. `cancel proof`
   - prove that a previously censored inter-channel Intmax tx became fully signed after close submission
   - bind that tx to the pending `CloseIntent`
   - invalidate the pending close before finalization

## Current Rollout

- `TxV2::ChannelAction` now has a path into `Block` / `PublicState`
- `block_hash_chain::update_account_tree` now binds active slots to concrete
  `TxV2` witnesses, checks `TxClass`, verifies `ChannelAction` inclusion, and
  constrains `source_channel_id == hub_id + account_no`
- `src/circuits/channel/state_update_verifier.rs` now rejects channel updates unless:
  - the transition uses the required backend split (`Plonky3` for state updates, `Plonky2` for Intmax transport)
  - `Pay` and `ReceiverClaim` digests are correctly bound to sender/receiver/amount/state
  - `channel_fund`, `nullifier`, `incoming`, and `user_fund_root` transitions match the transition kind
- the next validity steps are:
  - propagate the same typed binding into the remaining settlement / receive paths
  - replace remaining public-input and naming paths that still expose
    `aggregator_id` / `local_id`
  - implement the four close workstreams on top of the typed transport

## Deferred TODOs

- partition hub nullifier trees by capped year/month buckets to reduce long-term nullifier size
- add year/month/day metadata to channel-related transactions and bind it in ZKP public inputs and state transitions
- use the bound date buckets to enable pruning of old nullifier data outside the active retention window
