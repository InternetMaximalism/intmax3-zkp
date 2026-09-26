# Additional coverage for post-close receipts and partial withdrawals

This test expansion covers the late C2C receive path, its persisted continuation
state, and the partial-withdrawal submission path added in this session.

## Scenarios

| Layer | Coverage |
| --- | --- |
| Late-receipt contract lifecycle | Close, materialize, pay the original claims, receive additional ETH/ERC-20 credit, pull funds, and pay the additional claims. Original finalized funds remain unchanged. |
| Accounting | Independent claims for the same recipient, reverse payout order, exact funding boundaries, insufficient pulled funds, unrelated Rollup ledger surplus, and separation of ordinary versus additional claim budgets. |
| Atomicity and concurrency | Competing receipt branches, rejection without consuming the nullifier, successful rebasing, insufficient escrow followed by retry of the exact same receipt, and failed proof verification without state changes. |
| Contract proof boundary | Every one of the 59 public-input positions tested with a noncanonical value, obsolete/wrong lengths, zero amount/recipient, unchanged cursor, unbound manager, anchor equality/advance/regression/future, and maximum-u64 amounts. |
| Fuzzing | Three positive u64 receipts across ETH/ERC-20, with escrow, credit, funding, payouts, and remaining original claims checked throughout. 256 generated cases; related existing fuzz tests also run. |
| Real proof composition | Real receive and recipient-binding proofs, altered economic/state public inputs, altered sender/receiver parent proofs, incorrect finalized state, incorrect initial commitment/private state, duplicate receive-nullifier insertion, and an independently valid binding for another transfer. |
| Persistence | Restart with a pending receipt, refusal to promote an unconfirmed/competing cursor, corrupted channel/close metadata, immutable pending and confirmed generations, eight simultaneous writers, serialization failure and retry, and existing/dangling symlinks. |
| Partial-withdrawal orchestration | Interrupted settlement and retry with the same producer request ID; missing/wrong exit evidence; wrong channel, chain, signed head, or backing; insufficient finalized height followed by retry; substituted payout fields; and bounded historical-RPC retries. |
| Keyless calldata encoding | Rejection of overflow for all nine narrowed scalar fields and token-registry entries; short/long registry and short amount vectors; preservation of maximum-width values; exact manager, proof, withdrawal, and attestation encoding. |

## Defects found and fixed

1. A restored receipt could promote checkpoint metadata for another channel or
   close if its stored commitment still matched. Confirmation now checks channel,
   close-intent digest, and final H1; preparation also checks the checkpoint's
   channel against the verified Balance public inputs. This prevents accepting
   inconsistent local recovery artifacts; it does not imply that L1 accepted a
   cross-channel payment.
2. The partial-withdrawal encoder silently narrowed oversized JSON integers.
   It now checks the width before converting scalar values and registry entries.
   Tests also retain valid maximum-width values, including the uint256 payout
   amount. Contract semantic validation still applies to the encoded request.

## Running the tests

Run the contract suite from `contracts/`:

```sh
forge test --offline --match-path 'test/{LateIncomingLifecycle,SignerIndependentExit,ChannelSettlementManager,MultiTokenSettlement,CloseFundingAuthorization,ChannelSettlementAdversarial,CloseLifecycleHardening,CloseLifecycleRedTeam,PreparePartialWithdrawal,PartialWithdrawal,DeployGuards}.t.sol'
```

The encoder scenarios deliberately share one test entry point because Foundry
environment variables are process-wide. The suite reports 278 passing test
entries, including the four fuzz tests. The encoder entry point contains several
separately asserted scenarios and was rerun after expanding all scalar boundaries.

From the repository root:

```sh
node --test node/test/partial-withdrawal-live.test.js node/test/delegate-backing-vault.test.js node/test/api-public-live-backing.test.js

cargo test --release --locked --offline --features authenticated-tail-receive --lib late_incoming::tests
cargo test --release --locked --offline --features authenticated-tail-receive --lib late_incoming_composes_real_receive_and_recipient_binding -- --nocapture
cargo check --locked --offline --tests --bins --features authenticated-tail-receive
```

The Node suite has 39 passing tests. The persistence suite has six. Additional
fast Rust regressions cover the four `close_funding::tests`, the late-statement
parser, the 34-input backing statement, and rejection of obsolete claim versions.
The expanded real-proof composition test also passes (approximately 458 seconds),
including graceful rejection of the independently valid unrelated binding proof.
Together these are 14 passing Rust tests. Compilation checks pass both with and
without `authenticated-tail-receive`; existing compiler warnings remain.
Release-profile LTO may be disabled and codegen units increased to reduce build
time without changing these assertions.

## Test boundaries

The Solidity lifecycle uses production Manager/Materializer contracts, real
ETH/ERC-20 transfers, a test Rollup ledger, and mock pinned proof verifiers.
Cryptographic composition is checked separately in Rust. That Rust fixture uses
test cyclic Balance parents with real Spend/receive/binding relations. These
tests do not constitute a production-genesis-to-L1 MLE deployment test.

Persistence fixtures test serialization and state promotion; their placeholder
proof bytes do not assert cryptographic validity. Four persistence tests require
release mode because the existing indexed-tree sentinel initialization triggers
a canonical-field debug assertion; they are explicitly marked as such in debug
builds and all six are executed in release mode.

SpecialClose and channel migration remain outside this implementation's scope.
