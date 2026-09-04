# Pre-sign exit kits (signer-independent exit for asset-moving transitions)

> Status 2026-09-04: implemented across the live balance service, the block producer journal,
> the daemon, `channel_member` and the coordinator API. It replaces the blanket refusal that
> `StateSigningPurpose::requires_prepared_exit_kit` used to impose on every asset/composition-
> moving signature.

## Why a kit must exist before the signature

A channel head `H` is signer-independently exitable only while someone holds its exit kit: the
Balance proof plus the whole-vector backing proof whose statement key is
`(channel_id, settled_tx_chain, token_funds_digest)` of `H` (see
`doc/tasks/signer-independent-exit-handoff.md`). The live balance service proves that kit when it
adopts an N-of-N head. For an ordinary in-channel transition (`InChannelSend`, `InChannelBatch`,
`BalanceRefresh`) the successor keeps the statement key, so the predecessor's kit still backs it
and the CLI only has to check that a verified receipt for the predecessor is durable.

Every other transition moves the key:

| purpose | what moves | who can prove the kit before the signature |
|---|---|---|
| `TokenRegister` | `token_funds_digest` (registry, count) | the service, from the unchanged Balance proof |
| `L1DepositFundImport` / `L1DepositBundleApply` | fund vector + settle chain | the service, from the pending post-deposit Balance proof (`awaiting_channel_binding`) |
| `BurnDebit` / `InterChannelDebit` | fund vector + settle chain, posts a block | the service, against a **staged** producer block |
| `InterChannelFundImport` / `InterChannelBundleApply` (destination) | fund vector + settle chain, posts **no** block for this channel | not needed before signing (see below) |
| `CloseFunding` | terminal | retired on-chain (`CooperativeCloseFundingDeprecated`); stays refused |

Once the final N-of-N signature exists, a coordinator can post the block that makes the
predecessor's backing stale on L1 (`lastPostedBlock` moves) while withholding the new head and
its kit — the members would then be unable to exit at either head. The rule is therefore:

**a co-signer releases a signature over an asset/composition-moving successor `H'` only after a
verified, fsynced exit kit whose statement key is `H'`'s is durable in its own state.**

## Flow

1. `channel_member <cmd> --propose-exit-kit` builds the exact successor(s) the command would sign,
   writes `exit_kit_proposal.json`, prints it, and signs nothing. Commands: `register-token`,
   `cosign-l1-deposit-import`, `cosign-burn-send`, `cosign-inter-transfer`.
2. The API relays the proposal to the daemon (`livePrepareExitKit`,
   `api/lib/exit-kit.js::cliWithPreparedExitKit`).
   - `tokenRegister` / `l1DepositImport`: `LiveBalanceService::prepare_exit_kit` clones the
     snapshot, installs the proposed successor as the head candidate, proves the kit
     with the existing `install_signed_head_exit_kit`, and validates the candidate with the same
     semantic checks as a real adoption except that the head is structurally verified
     (`wallet_core::verify_snapshot_structure`) instead of N-of-N verified. Nothing is committed.
   - `interChannelDebit`: the daemon first calls
     `BlockProducerService::prepare_inter_channel_exit_kit`, which folds the descriptor's block for
     the proposed state (identified by its digest; the proposer's own partial signatures are
     ignored) into a durable `prepared` journal entry
     (`ProductionJournalAction::StagedInterChannelExitKit`) on a non-authoritative producer clone
     (`ProductionBlockProducer::produce_inter_channel_descriptor_block_unsigned_staging`,
     `BlockWitnessGenerator::unsigned_staging`). The block hash chain, account/deposit roots and
     the `bp_sig_chain` statement `(IMSB digest, registered signer pk list)` do not depend on the
     signature bytes, so the staged head snapshot is byte-identical to the one the real N-of-N
     block will produce. The service then runs the ordinary post-send Balance advance against the
     staged producer view and proves the kit, whose anchor is the staged block. Like a prepared
     close funding, the staged entry freezes every other producer mutation until it is committed
     or abandoned; it survives restarts (`verify_and_replay`).
   - The response is a `LiveChannelBackingArtifact` whose `signedHead` is the proposal and
     whose `signedHeadExitKit` is the kit; the API wraps it into the public backing envelope
     (`prepared_exit_kit.json`).
3. The API re-runs the command with `INTMAX_PREPARED_EXIT_KIT=prepared_exit_kit.json`. At the
   signing primitive (`enforce_exit_kit_before_signature_release` →
   `require_prepared_exit_kit`) the CLI verifies the envelope with
   `public_close_prover::verify_public_backing_proposed` (every Balance VD / Balance proof /
   backing proof check of the ordinary path; the N-of-N check is replaced by equality of the
   head's signing digest with the successor it is about to sign), archives the bytes content-addressed under
   `.signer-exit-kits/`, records `prepared_exit_kit_receipt` (predecessor digest + the
   `SignerExitKitReceipt` bound to the successor digest), **saves the state**, and only then
   signs. A crash between receipt and signature loses at most the signature.
4. When the command adopts the successor as the durable head,
   `adopt_head_with_exit_kit_receipts` promotes the prepared receipt into
   `signer_exit_kit_receipt` (statement key equality plus digest/`prev_digest` linkage). The
   second state of a two-state import chain (`*BundleApply`) shares the first state's key and
   reuses its kit.
5. `postInterChannel` with the real N-of-N head promotes the staged block in place: the entry is
   rebuilt with the signed state at the staged timestamp and must reproduce the identical head
   snapshot, else it fails closed (`abandon` + re-prepare). `liveSettleInterChannel` then installs
   a kit with the same statement key.

### Destination-side credits

An inter-channel credit posts a block for the **source** channel only. The destination's
`lastPostedBlock` does not move, so its pre-credit head stays exitable with the kit it already
holds. `require_credit_only_successor_with_head_exit_kit` therefore lets
`InterChannelFundImport` / `InterChannelBundleApply` sign when the successor is a pure
single-position credit of an unchanged registry **and** the durable head has a verified receipt.
Adoption leaves the credited head kit-pending (`signer_exit_kit_receipt = None`); the API installs
its kit right after `liveReceiveInterChannel` (`installHeadExitKit` → `install-exit-kit`), and
every H2=0 signature stays refused until then.

## State and schema changes

- `cli_state.json` schema 5: new required ledger key `prepared_exit_kit_receipt`
  (`migrate-state` inserts `null`).
- `ProductionJournalAction::StagedInterChannelExitKit` may only appear as the journal's
  `prepared` entry; a committed staged entry is rejected on replay.
- `verify_snapshot_semantics` takes `require_signed_head`; every existing caller passes `true`.
- `receive_deposit_unbound` now drops the previous head's kit when it enters
  `awaiting_channel_binding`, which also unblocks top-up deposits into an already bound channel.

## Daemon commands

- `livePrepareExitKit { channelId, proposal }` — `proposal.kind` ∈ `tokenRegister`
  (`successor`), `l1DepositImport` (`record`, `members`, `fundImportState`),
  `interChannelDebit` (`requestId`, `proposedState`, `debitPayload`, `descriptor`).
- `liveAbandonPreparedExitKit { channelId, requestId }` — drop a staged debit block whose
  transition will not be signed.
- Producer: `prepareInterChannelExitKit`, `abandonPreparedInterChannelExitKit`.

## Browser / wasm

`wallet_cosign` still refuses every asset/composition-moving successor
(`verify_exit_kit_preserving_successor`): the browser holds no Balance proof and no archive, so
it cannot hold a pre-sign receipt. Those transitions are co-signed through the coordinator API
(`/api/cosign-burn`, `/register-token`, `/deposit`, `/inter-channel`), which is exactly the path
this document covers.
