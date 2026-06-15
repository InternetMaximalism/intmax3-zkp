# Intmax3 Channel MVP Integration Notes

This repository contains a partial implementation layer for the channel model
described in
`/Users/plasma/repos/intmax3-zkp-enshrined-paymentchannel/intmax3-channel-spec 2.md`.

The canonical specification now uses:

- `ChannelId`
- `KeyId`
- `UserId = ChannelId || KeyId`
- BP-produced fully signed small blocks
- all-member channel-state agreement on both channel balances and Intmax balances

Some code paths below still reflect the older `channel_id + key_id` migration
bridge. They are implementation leftovers, not the target design.

## Implemented foundations

- `src/common/user_id.rs`
  - introduced a migration bridge around the older packed user model
  - this is no longer the canonical native authorization model in the spec
  - it remains in code only to keep existing proofs compiling during refactor

- `src/constants.rs`
  - introduced `CHANNEL_ID_BITS`, `KEY_ID_BITS`, `USER_ID_BITS`, `MAX_NUM_CHANNELS`
  - old proof_submitter/local constants remain as aliases during migration

- `src/common/channel.rs`
  - added the first generation of channel-side state objects:
    - `ChannelFund`
    - `ChannelMember`
    - `ChannelState`
    - `InterChannelTx`
    - `CloseWithdrawal`
    - `CloseIntent`
    - `CancelClose`
    - `PostCloseIncomingClaim`
    - `WithdrawalClaim`
  - added sender-supplied receiver-side lattice delta bundles
  - added dummy receiver deltas for receiver anonymity
  - added the burn-backed close object and root-based withdrawal-claim direction
  - these objects now need refactoring toward the canonical
    `ChannelId / KeyId / UserId` and fully signed small-block model

- `src/common/tx.rs`
  - added `TxV2`
  - added `ChannelAction`
  - preserved legacy `Tx` so current validity/balance circuits stay unchanged

## Current intent

This is a migration layer, not the final cut-over.

The existing Intmax3 circuits still operate on the legacy transaction and
account objects. The newly added types are only partial precursors to the
current specification.

The current specification now requires the next steps to be:

1. introduce `ChannelRecord` and `KeyRecord`
2. move native signing identity to `UserId = ChannelId || KeyId`
3. make fully signed small-block roots the canonical native authorization event
4. make sender-side and receiver-side Intmax-balance updates explicit all-member channel-state transitions
5. add BP penalty reserve, special close, and close freeze semantics

## Spec Location

The canonical working spec is now stored in-repo at:

- `intmax3-channel-spec 2.md`

## Immediate follow-up files

- `src/common/block.rs`
- `src/common/public_state.rs`
- `src/circuits/validity/block_hash_chain/*`
- `src/circuits/balance/*`
- `src/common/channel_message.rs`

These areas still use legacy user naming and will need the next migration
pass.

## Current Workstreams

The updated specification breaks implementation into five main workstreams.

1. `registry refactor`
   - add `ChannelRecord`
   - add `KeyRecord`
   - bind `UserId = ChannelId || KeyId`

2. `native sign-back integration`
   - make fully signed small-block roots the canonical native authorization event
   - reuse INTMAX PQ aggregation logic for all `KeyId` conditions in a channel
   - remove the remaining assumption that attached transport signatures are enough by themselves

3. `BP and special-close logic`
   - fixed BP registration for MVP
   - BP penalty reserve proof
   - special close when a fully signed small block is withheld for `5` medium blocks

4. `receiver-flow rewrite`
   - sender-prepared receiver delta bundle
   - all-member receiver-side Intmax-balance state update
   - all-member receiver-side channel-balance bundle application
   - no ordinary personal-nullifier receive-claim path

5. `close and post-close`
   - normal close
   - close freeze
   - special close with slashing
   - cancellation by revived native tx
   - post-close incoming recovery
   - stale-close correction for just-emitted outgoing native txs

## Current Rollout

- `TxV2::ChannelAction` has a path into `Block` / `PublicState`
- `src/circuits/channel/state_update_verifier.rs` already distinguishes:
  - `Plonky3` channel-local state updates
  - `Plonky2` Intmax transport / close-side proofs
- sender-made receiver delta bundles and dummy receivers are already part of the evolving model
- burn-backed close and root-based withdrawal claims are already the intended exit direction

The major missing migration is no longer just naming. It is the move from the
legacy packed user model to:

- `ChannelId`
- `KeyId`
- `UserId`
- fully signed small-block roots
- explicit BP, freeze, and special-close semantics

## Deferred TODOs

- partition hub nullifier trees by capped year/month buckets to reduce long-term nullifier size
- add year/month/day metadata to channel-related transactions and bind it in ZKP public inputs and state transitions
- use the bound date buckets to enable pruning of old nullifier data outside the active retention window
