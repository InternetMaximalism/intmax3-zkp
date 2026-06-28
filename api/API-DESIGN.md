# INTMAX3 Channel API Design

All operations for the INTMAX3 payment channel protocol. Each entry covers what the operation does, its inputs/outputs, current implementation status, and what needs to be built for the public API.

Spec references: `architecture-audit/detail2.md` (detail2), `architecture-audit/abstract2-1.md` (abstract2-1).

---

## Terminology

| Term | Meaning |
|------|---------|
| **Client** | Browser/app running WASM proofs. Holds private keys. |
| **Co-signer** | Relay server that co-signs channel states (N-of-N). Manages channel_member CLI. |
| **BP** | Block Proposer. Posts blocks to L1, generates validity proofs. |
| **L1** | Ethereum (or testnet). Smart contracts hold escrow and verify proofs. |
| **BURN_CHANNEL_ID** | Sentinel channel ID for partial withdrawal burn legs. |

---

## A. Atomic Operations

---

### A1. keygen

**Overview:** Generate a member key pair from randomness or a deterministic seed. Produces a Regev key pair (encryption), Poseidon signature key, and derived public identifiers.

**Inputs:** Optional `seed: bytes32`
**Outputs:** `MemberKeys { regev_sk, regev_pk, sig_sk, pk_g, pk_b }`

**Current status:**
- WASM: `wallet_keygen()`, `wallet_keygen_seeded(seed)` — implemented
- CLI: implicit in `cmd_init` (keys generated from `INTMAX_CHANNEL` env)
- Relay: not exposed (browser does its own keygen)

**API implementation:**
Client-side only. Expose as `POST /api/keygen` returning the public components, or keep purely client-local. The private key material MUST NOT leave the client.

```
POST /api/v1/keys/generate
Request:  { seed?: string }
Response: { regev_pk: string, pk_g: string, pk_b: string }
```

---

### A2. publishRegevPk

**Overview:** Publish the member's Regev public key to channel peers so they can encrypt transfers to this member. (abstract2-1 §3.0)

**Inputs:** `regev_pk`, `channel_id`, `slot`
**Outputs:** Acknowledgement

**Current status:**
- Not a separate operation. Regev PK is embedded in the genesis contribution and stored in the channel snapshot (`members[].regevPk`). Peer discovery happens by reading the snapshot.

**API implementation:**
Not needed as a standalone endpoint. The `init` flow already handles this. For late-joining delegates, the PK is included in the `genesisContribution` payload.

---

### A3. exportRegRecord

**Overview:** Export the channel member registration record containing pubkey hash, Regev PK, and L1 recipient address. Used for on-chain channel registration. (detail2 K-6)

**Inputs:** (uses current keys)
**Outputs:** `{ sphincs_pubkey_hash, regev_pk, l1_recipient }`

**Current status:**
- CLI: `export-reg-record` — implemented
- WASM/Relay: not exposed

**API implementation:**
```
GET /api/v1/channel/{ch}/registration-record
Response: { pubkey_hash: string, regev_pk: string, l1_recipient: string }
```

---

### A4. genesisContribution

**Overview:** Create the initial state contribution for joining a channel. The client builds a genesis balance state with the specified initial balance (typically 0). (detail2 H-1)

**Inputs:** `balance: u64`
**Outputs:** Contribution JSON (contains the client's public key, initial enc_balance, etc.)

**Current status:**
- WASM: `wallet_genesis_contribution(balance)` — implemented
- CLI: `gen-contribution` (dev/test only)

**API implementation:**
Client-side computation. No server endpoint needed — the client calls WASM directly and passes the result to `init`.

---

### A5. init (cosign genesis)

**Overview:** Co-sign the genesis state to create or join a channel. If the channel doesn't exist yet, the co-signer creates it with the first N co-signing members. If it exists, the new member (delegate) is added. (detail2 H-1)

**Inputs:** `contribution: GenesisContribution`
**Outputs:** `ChannelSnapshot` (fully signed genesis state)

**Current status:**
- CLI: `init` — implemented
- Relay: `POST /api/init` — implemented
- WASM: client calls `importChannel` after receiving the snapshot

**API implementation:**
```
POST /api/v1/channel/{ch}/init
Request:  <GenesisContribution JSON>
Response: <ChannelSnapshot JSON>
```
Idempotent for the same member (re-join returns existing snapshot). Creates channel on first call.

---

### A6. importSnapshot

**Overview:** Import the latest channel snapshot into the client's local state. Decrypts own balance, checks signature validity, and updates internal state. (implicit in all flows)

**Inputs:** `snapshot: ChannelSnapshot`
**Outputs:** `{ balance: u64, slot: u8, state_version: u32, canSend: bool }`

**Current status:**
- WASM: `wallet_import_channel(snapshot_json)` — implemented
- Relay: `GET /api/snapshot` returns the raw snapshot

**API implementation:**
Two parts:
```
GET /api/v1/channel/{ch}/snapshot
Response: <ChannelSnapshot JSON>
```
Client imports the snapshot locally via WASM. Not a server-side operation.

---

### A7. send

**Overview:** Build an intra-channel transfer. Constructs a `ChannelTx` with Regev-encrypted amount and a `channelTxZKP` (Plonky3 STARK) proving sender solvency and ciphertext well-formedness. (detail2 C-5, abstract2-1 §3.2)

**Inputs:** `recipient_slot: u8`, `amount: u64`
**Outputs:** `SendPayload { channel_tx, zkp, proposed_state }`

**Preconditions:** `canSend == true` (if false, must refresh first). Sender balance >= amount.

**Current status:**
- WASM: `wallet_send(recipient_slot, amount)` — implemented
- wallet_core: `build_send(...)` — implemented

**API implementation:**
Client-side WASM computation. Result is passed to `cosign`.

---

### A8. cosign

**Overview:** Co-sign a proposed state transition. Each of the N co-signing members verifies the transition (ZKP, version increment, chain consistency) and signs. (detail2 C-3, abstract2-1 §3.1)

**Inputs:** `payload: SendPayload` (or refresh/burn payload)
**Outputs:** Updated `ChannelSnapshot` with new signature added

**Current status:**
- CLI: `cosign` — implemented
- Relay: `POST /api/cosign` — implemented
- WASM: `wallet_cosign(payload_json)` — implemented (for delegates to verify, but they don't co-sign)

**API implementation:**
```
POST /api/v1/channel/{ch}/cosign
Request:  <SendPayload JSON>
Response: <ChannelSnapshot JSON>  (with signatures)
```

---

### A9. finalize

**Overview:** Finalize a co-signed state update. The client imports the fully-signed state, verifies all N signatures, and updates its internal balance. (implicit)

**Inputs:** `state_json: string` (co-signed state)
**Outputs:** `{ balance: u64, slot: u8, state_version: u32, canSend: bool }`

**Current status:**
- WASM: `wallet_finalize(state_json)` — implemented
- CLI: `finalize` — implemented

**API implementation:**
Client-side only. No server endpoint.

---

### A10. refresh

**Overview:** Re-encrypt the member's Regev ciphertext to reduce accumulated homomorphic noise. Mandatory after receiving transfers (every MAX_HOMO_ADDS_BEFORE_REFRESH=64 additions). Uses RefreshAir (combined Decrypt+Encrypt STARK), NOT a zero-amount channelTxZKP. (detail2 B-3, L-4)

**Inputs:** (uses current state)
**Outputs:** `RefreshPayload { refreshed_state, refresh_proof }`

**Current status:**
- WASM: `wallet_refresh()` — implemented
- wallet_core: `build_refresh(...)` — implemented

**API implementation:**
Client-side WASM computation. Result is passed to `cosignRefresh`.

---

### A11. cosignRefresh

**Overview:** Co-sign a refreshed balance state. (detail2 B-3)

**Inputs:** `refresh_payload: RefreshPayload`
**Outputs:** Updated `ChannelSnapshot`

**Current status:**
- CLI: `cosign-refresh` — implemented
- Relay: `POST /api/refresh-cosign` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/cosign-refresh
Request:  <RefreshPayload JSON>
Response: <ChannelSnapshot JSON>
```

---

### A12. rangeProof

**Overview:** The `bp_member_slot` member verifies the `channelUpdateZKP` to confirm sender solvency before handing off to the global BP. Returns pass/fail. (abstract2-1 §3.3.1)

**Inputs:** `channelUpdateZKP`, `BulkInterChannelTx`, current `balanceProof`
**Outputs:** `bool`

**Current status:**
- Implicit in the co-signer's inter-channel transfer handling. The CLI's `cosign-inter-transfer` performs this verification internally before co-signing.
- Not a separately callable operation.

**API implementation:**
Internal to the co-signer. Not exposed as a public endpoint. The verification happens inside `cosignInterTransfer`.

---

### A13. signSmallBlock

**Overview:** N-of-N sign a `SmallBlockRootMessage` binding both the state update (H1') and the transaction tree root (H2 = tx_tree_root). This is the key signing primitive for inter-channel transfers. (abstract2-1 §3.3.2)

**Inputs:** `SmallBlockRootMessage`, `tx_inclusion_proof`, `BulkInterChannelTx`, post-deduction `BalanceState'`
**Outputs:** `SignedSmallBlock`

**Current status:**
- Embedded in the CLI's `cosign-inter-transfer` and `cosign-burn-send` flows.
- wallet_core: signing logic in `sign_state(...)` uses `ChannelState::signing_digest()` which embeds `hash(H1, H2)`.

**API implementation:**
Internal to `cosignInterTransfer` and `cosignBurn`. Not a standalone endpoint.

---

### A14. sendInterChannel

**Overview:** Build a single-destination inter-channel transfer. Constructs the debit payload and transfer descriptor with `channelUpdateZKP`. (abstract2-1 §3.4)

**Inputs:** `to_channel: u32`, `to_slot: u8`, `amount: u64`, `dest_recipient_json: string`
**Outputs:** `{ debitPayload, transferDescriptor }`

**Current status:**
- WASM: `wallet_send_inter_channel(...)` — implemented
- wallet_core: `build_inter_channel_send(...)` — implemented

**API implementation:**
Client-side WASM computation. Result is passed to `cosignInterTransfer`.

---

### A15. sendBulkInterChannel

**Overview:** Build a multi-destination inter-channel transfer. One `BulkInterChannelTx` with `transfer_entries[]` targeting multiple destination channels. The ZKP proves total sender solvency across all legs. (abstract2-1 §3.4)

**Inputs:** `entries: [{ to_channel, to_slot, amount, dest_recipient }]`
**Outputs:** `{ debitPayload, transferDescriptors[] }`

**Current status:**
- NOT IMPLEMENTED. Current `build_inter_channel_send` handles only one destination.
- The spec allows bulk, but the implementation is single-leg only.

**API implementation:**
```
Client WASM: wallet_send_bulk_inter_channel(entries_json)
→ Returns { debitPayload, transferDescriptors[] }
→ Pass to POST /api/v1/channel/{ch}/cosign-inter-transfer
```
Requires extending `build_inter_channel_send` to handle `Vec<TransferEntry>`.

---

### A16. cosignInterTransfer

**Overview:** Atomically co-sign an inter-channel transfer: debit the source channel and credit each destination channel. The co-signer verifies the ZKP (rangeProof), signs the small block, and applies the credit to each destination. (detail2 C-7, abstract2-1 §3.4)

**Inputs:** `{ debitPayload, transferDescriptor }`
**Outputs:** `{ aHead: ChannelSnapshot, bSnapshot: ChannelSnapshot }`

**Current status:**
- CLI: `cosign-inter-transfer` — implemented
- Relay: `POST /api/inter/send` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/inter-channel/send
Request:  { debitPayload, transferDescriptor }
Response: { sourceHead: <Snapshot>, destSnapshot: <Snapshot> }
```

---

### A17. receiveInterChannel

**Overview:** Process an incoming inter-channel transfer on the destination channel. Verify the entry wing Merkle inclusion in `TxLeafHash`, verify the sender's balance proof, and apply the `recipient_delta` to update balances. (abstract2-1 §3.4 flowReceive3)

**Inputs:** `transfer_entry`, `tx_inclusion_proof`, `sender_balance_proof`
**Outputs:** Updated `BalanceState` with credited amount

**Current status:**
- wallet_core: `build_inter_channel_credit(...)` — implemented
- CLI: handled inside `cosign-inter-transfer` (credit leg)
- The receive side is currently implicit — the co-signer applies the credit during `cosignInterTransfer`.

**API implementation:**
For the API, this remains internal to the co-signer for now. If channels span multiple co-signers in the future, this becomes a separate endpoint:
```
POST /api/v1/channel/{ch}/inter-channel/receive
Request:  { transferEntry, inclusionProof, balanceProof }
Response: <ChannelSnapshot JSON>
```

---

### A18. l1Deposit

**Overview:** Send an L1 deposit transaction. The member calls `IntmaxRollup.deposit{value}(recipient, tokenIndex, amount, auxData)` on L1, escrowing real ETH. (abstract2-1 §3.3.2c step 1)

**Inputs:** `amount: u256`, `rollup_address: address`
**Outputs:** `{ txHash: string, depositor: address }`

**Current status:**
- Browser: `sendDepositViaWallet(amount)` in wallet-live.html — implemented (via MetaMask/EIP-6963)
- CLI: `cast send` inside `cmd_setup_backing` — implemented
- Relay: `POST /api/l1-deposit` — implemented (calls `cast send`)

**API implementation:**
```
POST /api/v1/channel/{ch}/deposit/l1-send
Request:  { amount: string, depositor?: string }
Response: { txHash: string, depositor: string }
```
Or expose deposit info so the client can submit via their own wallet:
```
GET /api/v1/channel/{ch}/deposit/info
Response: { rollup: string, chainId: number, rpc: string, depositRecipient: string }
```

---

### A19. generateDepositBalanceProof

**Overview:** Generate a `receive_deposit` balance proof proving Merkle inclusion in the finalized `deposit_tree_root`. Includes nullifier tree insertion to prevent double-fold. (abstract2-1 §3.3.2c step 3, detail2 C-10 T2)

**Inputs:** Deposit data, current balance proof state
**Outputs:** Balance proof update

**Current status:**
- Implicit in the co-signer's deposit import flow. The CLI's `cosign-l1-deposit-import` calls `build_l1_deposit_import(...)` which handles the proof internally.
- Not a separately callable operation for the client.

**API implementation:**
Internal to the co-signer. The client doesn't generate this proof — the co-signer does it as part of `importDeposit`.

---

### A20. importDeposit

**Overview:** Import an L1 deposit into the channel. Two-step state transition: (1) fund import: `channelFund += amount`, `unallocated += amount`, advance `settledTxChain` by deposit nullifier; (2) bundle apply: `encBalances[recipient] += encrypt(amount)`, `unallocated -= amount`. All N co-signers must verify via `verify_l1_deposit_import_transition()`. (abstract2-1 §3.3.2c, detail2 C-10)

**Inputs:** `{ recipientSlot: u8, depositor: address, amount: u256 }`
**Outputs:** Updated `ChannelSnapshot`

**Preconditions:** Channel must be Active. Deposit Merkle-included in finalized `deposit_tree_root`. Nullifier unused.

**Current status:**
- CLI: `cosign-l1-deposit-import` — implemented
- Relay: `POST /api/import-deposit` — implemented
- wallet_core: `build_l1_deposit_import(...)`, `verify_l1_deposit_import_transition(...)` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/deposit/import
Request:  { recipientSlot: number, depositor: string, amount: string }
Response: <ChannelSnapshot JSON>
```

---

### A21. burnSend

**Overview:** Build a burn-send for partial withdrawal. The transfer targets `BURN_CHANNEL_ID` with `recipient_delta = null`. The ZKP excludes burn legs from recipient ciphertext checks. The channel remains active after burn. (abstract2-1 §3.6)

**Inputs:** `amount: u64`, `withdrawal_address: string` (L1 recipient)
**Outputs:** `{ debitPayload, transferDescriptor }`

**Preconditions:** No open close request on the source channel.

**Current status:**
- WASM: `wallet_burn_send(amount, withdrawal_address_hex)` — implemented
- wallet_core: `build_burn_send(...)` — implemented

**API implementation:**
Client-side WASM computation. Result is passed to `cosignBurn`.

---

### A22. cosignBurn

**Overview:** Co-sign a burn-send state transition. Verifies the burn proof and signs. Creates a ticket for tracking. Rejects with 409 if a burn is already pending settle. (abstract2-1 §3.6 step 4)

**Inputs:** `{ debitPayload, transferDescriptor, amount?, recipient? }`
**Outputs:** `{ ...cosigned_state, _ticket }`

**Current status:**
- CLI: `cosign-burn-send` — implemented
- Relay: `POST /api/cosign-burn` — implemented (with ticket + 409 duplicate prevention)

**API implementation:**
```
POST /api/v1/channel/{ch}/burn/cosign
Request:  { debitPayload, transferDescriptor, amount: string, recipient: string }
Response: { state: <CosignedState>, ticket: <Ticket> }
```

---

### A23. generateWithdrawalProof

**Overview:** Build a `single_withdrawal_circuit` ZKP proving that the burned amount corresponds to a valid withdrawal from the channel. This proof is verified on L1 during `withdrawNative`. (abstract2-1 §3.6 step 6)

**Inputs:** Burn transaction data, validity proof, balance proof
**Outputs:** Withdrawal ZKP

**Current status:**
- wallet_core: `build_channel_withdrawal(...)` — implemented (generates 4 JSON artifacts: pw_reg.json, etc.)
- CLI: `pw-submit` calls this internally

**API implementation:**
Internal to the co-signer's `pwSubmit` flow. Not a standalone endpoint.

---

### A24. pwSubmit

**Overview:** Submit a partial withdrawal to L1. Includes: deploy settlement (if not yet deployed), call `submitPartialWithdrawalIntent(...)` with the withdrawal proof, then `authorizePartialWithdrawal(...)`. (detail2 D row 4)

**Inputs:** `{ recipient: address }`
**Outputs:** `{ auth_digest: bytes32 }`

**Current status:**
- CLI: `pw-submit` — implemented (calls deploy-settlement if needed, then forge script)
- Relay: `POST /api/pw-submit` — implemented
- Contract: `submitPartialWithdrawalIntent(...)`, `authorizePartialWithdrawal(...)` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/partial-withdrawal/submit
Request:  { recipient: string }
Response: { authDigest: string }
```

---

### A25. pwFinalize

**Overview:** Finalize a partial withdrawal on L1. Calls `finalizePartialWithdrawal()` then claims the ETH. (detail2 D row 4)

**Inputs:** (none — uses on-chain state)
**Outputs:** `{ authDigest: string }`

**Current status:**
- CLI: `pw-finalize` — implemented
- Relay: `POST /api/pw-finalize` — implemented
- Contract: `finalizePartialWithdrawal()`, `claimWithdrawalCredit()` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/partial-withdrawal/finalize
Response: { ok: true, authDigest: string }
```

---

### A26. requestClose

**Overview:** Request channel closure on L1. Sets `channelStatus = ClosePending`, records `closeRequestedAt`, and sets `isNativeSendAllowed = false`. Starts the grace period (600s) before a close intent can be submitted. (detail2 H-2 §3.5.1)

**Inputs:** `channel_id`
**Outputs:** L1 tx confirmation

**Current status:**
- CLI: inside `cmd_close` (calls `requestClose()` then waits then `submitCloseIntent(...)`)
- Contract: `requestClose()` — implemented
- NOT a separate CLI command or relay endpoint.

**API implementation:**
```
POST /api/v1/channel/{ch}/close/request
Response: { txHash: string, closeRequestedAt: number }
```
Separate from `submitCloseIntent` so the API caller can control timing.

---

### A27. deploySettlement

**Overview:** Deploy the `ChannelSettlementManager` and `Verifier` contracts for a channel. Idempotent — returns existing deployment if already done. (implementation-specific)

**Inputs:** (uses channel state)
**Outputs:** `{ manager: address, verifier: address }`

**Current status:**
- CLI: `deploy-settlement` — implemented
- Relay: `POST /api/deploy-settlement` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/settlement/deploy
Response: { manager: string, verifier: string }
```

---

### A28. submitCloseIntent

**Overview:** Submit a close intent with a close proof after the grace period. The proof binds `final_balance_state_h1`, `final_state_version`, `final_settled_tx_chain`. Uses `CloseProver` to generate the MLE/WHIR proof. (detail2 H-2 §3.5.2)

**Inputs:** `{ manager: address, sv: address }` (settlement verifier)
**Outputs:** L1 tx confirmation

**Preconditions:** `block.timestamp >= closeRequestedAt + 600s`. Valid close proof. Member signatures over the final state.

**Current status:**
- CLI: inside `cmd_close` (after requestClose + wait) — implemented
- wallet_core: `CloseProver.prove_mle(...)` — implemented
- Contract: `submitCloseIntent(...)` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/close/submit-intent
Request:  { manager: string, verifier: string }
Response: { ok: true, log: string }
```

---

### A29. challengeClose

**Overview:** Replace a pending close with a newer state during the challenge period (86,400s). The challenger submits a `CloseIntent` with a strictly higher `(final_epoch, final_state_version)`. Implemented by calling `submitCloseIntent` again. (detail2 H-2 §3.5.3, H-4)

**Inputs:** Newer `CloseIntent` + close proof
**Outputs:** L1 tx confirmation

**Preconditions:** Within challenge period. Replacement `(epoch, version)` > current `(epoch, version)`.

**Current status:**
- Contract: `submitCloseIntent(...)` handles replacement logic — implemented
- CLI/Relay: NOT separately implemented. Would need to generate a close proof for the newer state.

**API implementation:**
```
POST /api/v1/channel/{ch}/close/challenge
Request:  { manager: string, verifier: string, newerState: <ChannelState> }
Response: { ok: true }
```
Internally: build close proof from newer state, call `submitCloseIntent` on L1.

---

### A30. cancelClose

**Overview:** Cancel a pending close by proving that the registered N-of-N members signed a state at a higher `state_version` than the pending close's `final_state_version`. Requires cooperation of all members. Channel returns to Active. (detail2 H-3 C1)

**Inputs:** `{ manager: address }`, newer co-signed state
**Outputs:** L1 tx confirmation

**Preconditions:** `revived.close_freeze_nonce + 1 == close.close_freeze_nonce`. `member_set_commitment` must match.

**Current status:**
- wallet_core: `CancelCloseProver` — implemented (prove, prove_mle)
- Contract: `cancelClose(...)` — implemented (real MLE/WHIR verification)
- CLI: NOT implemented (no `cancel-close` subcommand)
- Relay: NOT implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/close/cancel
Request:  { manager: string }
Response: { ok: true }
```
Requires new CLI command `cancel-close` that builds the `CancelCloseProver` proof and calls the contract.

---

### A31. finalizeClose

**Overview:** Finalize a channel closure after the challenge period expires. Any party can call. Enables withdrawal claims. (detail2 H-2 §3.5.4)

**Inputs:** `{ manager: address }`
**Outputs:** L1 tx confirmation

**Current status:**
- CLI: `settle` — implemented (calls `finalizeClose()`)
- Relay: `POST /api/settle` — implemented
- Contract: `finalizeClose()` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/close/finalize
Request:  { manager: string }
Response: { ok: true }
```

---

### A32. submitWithdrawalClaim

**Overview:** Submit a per-member withdrawal claim after channel finalization. Each member proves "the plaintext of my Regev ciphertext = claimed amount" via `withdrawClaimZKP`. No cooperation of other members needed (exit-liveness). (detail2 H-2 §3.5.4, E-3)

**Inputs:** `{ manager: address, slot: u8, recipient: address }`
**Outputs:** L1 tx confirmation

**Preconditions:** Channel finalized. Valid `withdrawClaimZKP`. `totalWithdrawn + amount <= finalizedChannelFundAmount`.

**Current status:**
- wallet_core: `WithdrawalClaimProver` — implemented
- CLI: `claim` — implemented (builds proof + submits + pulls credit)
- Relay: `POST /api/claim` — implemented
- Contract: `submitWithdrawalClaim(...)`, `claimWithdrawalCredit()` — implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/close/claim
Request:  { manager: string, slot: number, recipient: string }
Response: { ok: true }
```

---

### A33. claimWithdrawalCredit

**Overview:** Pull the ETH credit from a successful withdrawal claim. Transfers ETH to the member's registered `l1_recipient`. (detail2 H-2 §3.5.4)

**Inputs:** `{ manager: address }`
**Outputs:** ETH transferred

**Current status:**
- Contract: `claimWithdrawalCredit()` — implemented
- CLI: called inside `cmd_claim` after `submitWithdrawalClaim`

**API implementation:**
Bundled with A32 in the current implementation. Could be separated:
```
POST /api/v1/channel/{ch}/close/pull-credit
Request:  { manager: string }
Response: { ok: true, amount: string }
```

---

### A34. submitPostCloseClaim

**Overview:** Claim a late inter-channel transfer received after the channel was finalized. The member provides a `lateBalanceProof` verified inside a `claim_proof`. Uses `PostCloseClaimProver`. (detail2 H-2 §3.5.5, C-8)

**Inputs:** `{ manager: address, late_transfer_data }`, post-close claim proof
**Outputs:** Additional withdrawal credit

**Preconditions:** `usedSharedNativeNullifiers` prevents double receipt.

**Current status:**
- wallet_core: `PostCloseClaimProver` — implemented
- Contract: `submitPostCloseClaim(...)` — implemented
- CLI: NOT implemented (no CLI subcommand)
- Relay: NOT implemented
- Fixture generator: `generate_withdrawal_fixture.rs` has post-close fixture generation

**API implementation:**
```
POST /api/v1/channel/{ch}/close/post-close-claim
Request:  { manager: string, lateTransferData: ... }
Response: { ok: true }
```
Requires new CLI command `post-close-claim`.

---

### A35. postBlock

**Overview:** The Block Proposer posts a `MediumBlock` (containing `SubBlock[]`) to L1 via `postBlockAndSubmit`. (abstract2-1 §3.3.4)

**Inputs:** `SubBlock[]`
**Outputs:** Finalized block number

**Current status:**
- Handled internally by the CLI's `withdraw` and `pw-submit` commands, which call forge scripts.
- Not directly exposed as a relay endpoint (the relay IS the BP in the current architecture).

**API implementation:**
```
POST /api/v1/blocks/post
Request:  { subBlocks: SubBlock[] }
Response: { blockNumber: number, txHash: string }
```
BP-facing endpoint. In production, this would be a separate BP service.

---

### A36. generateValidityProof

**Overview:** Generate a validity proof for a block. Verifies all `SignedSmallBlock` signatures, checks `tx_tree_root != 0` on inter-channel path, and produces the validity proof. (abstract2-1 §3.3.5)

**Inputs:** `SubBlock[]`, `PublicState`
**Outputs:** Validity proof

**Current status:**
- Implemented in the circuit layer (`validity_circuit.rs`)
- CLI: invoked as part of `withdraw` and `pw-submit` flows
- Very heavy operation (minutes)

**API implementation:**
Internal to BP. No public endpoint needed in current architecture.

---

### A37. generateBalanceProof

**Overview:** Generate a per-channel balance proof (recursive IVC). Exposes `settled_tx_chain` as a public input for reconciliation. (abstract2-1 §3.3.6)

**Inputs:** Channel state, previous balance proof
**Outputs:** Balance proof

**Current status:**
- Implemented in the circuit layer
- CLI: invoked inside `setup-backing`, `withdraw`, `pw-submit`
- Very heavy operation (GB-scale memory)

**API implementation:**
Internal to BP/co-signer. No standalone endpoint.

---

### A38. getBalance

**Overview:** Get the current decrypted balance for the authenticated member.

**Inputs:** (uses current state)
**Outputs:** `{ balance: u64, slot: u8, canSend: bool }`

**Current status:**
- WASM: `wallet_balance()` — implemented
- CLI: `balance` — implemented

**API implementation:**
Client-side via WASM (decryption requires private key). Server provides the snapshot; client decrypts.

---

### A39. getSnapshot

**Overview:** Get the latest channel snapshot.

**Current status:**
- Relay: `GET /api/snapshot` — implemented

**API implementation:**
```
GET /api/v1/channel/{ch}/snapshot
Response: <ChannelSnapshot JSON>
```

---

### A40. getChannelStatus

**Overview:** Query the L1 channel status (Active / ClosePending / Finalized) and related timing info.

**Inputs:** `channel_id`
**Outputs:** `{ status, closeRequestedAt?, challengeDeadline?, finalizedAt? }`

**Current status:**
- NOT implemented as a relay endpoint. Contract state can be queried via `cast call`.

**API implementation:**
```
GET /api/v1/channel/{ch}/status
Response: { status: "active"|"close_pending"|"finalized", closeRequestedAt?: number, challengeDeadline?: number }
```

---

### A41. getTickets

**Overview:** Get all active operation tickets for a channel.

**Current status:**
- Relay: `GET /api/tickets` — implemented

**API implementation:**
```
GET /api/v1/channel/{ch}/tickets
Response: [ <Ticket>, ... ]
```

---

### A42. getDepositInfo

**Overview:** Get the L1 deposit parameters (rollup address, chain ID, RPC).

**Current status:**
- Relay: `GET /api/deposit-info` — implemented

**API implementation:**
```
GET /api/v1/channel/{ch}/deposit/info
Response: { rollup: string, chainId: number, rpc: string, depositRecipient: string }
```

---

### A43. getBacking

**Overview:** Get channel backing information (deposit tx, fund amount, rollup address).

**Current status:**
- Relay: `GET /api/backing` — implemented

**API implementation:**
```
GET /api/v1/channel/{ch}/backing
Response: { rollup: string, fund: string, depositTx: string }
```

---

### A44. setupBacking

**Overview:** Full initial channel setup: deploy IntmaxRollup, send L1 deposit, generate balance proof. Extremely heavy operation (~4GB memory, minutes). Admin-only. (implementation-specific)

**Current status:**
- CLI: `setup-backing` — implemented

**API implementation:**
Admin CLI only. Not exposed as a public API endpoint.
```
CLI: channel_member setup-backing <rpc>
```

---

### A45. cancelPartialWithdrawal

**Overview:** Cancel a pending partial withdrawal by proving a newer N-of-N signed state, similar to cancelClose. (contract-specific)

**Inputs:** `{ manager: address }`, cancel proof
**Outputs:** L1 tx confirmation

**Current status:**
- Contract: `cancelPartialWithdrawal(...)` — implemented (real logic, mirrors cancelClose)
- Rust prover: NOT implemented
- CLI/Relay: NOT implemented

**API implementation:**
```
POST /api/v1/channel/{ch}/partial-withdrawal/cancel
Request:  { manager: string }
Response: { ok: true }
```
Requires building a `CancelPartialWithdrawalProver` (likely can reuse `CancelCloseProver` structure).

---

## W. Compound Workflows

---

### W1. Join Channel

**Overview:** Create or join a payment channel.

```
A1 keygen (client)
 → A4 genesisContribution (client)
   → A5 init / cosign genesis (co-signer)
     → A6 importSnapshot (client)
```

**Branching:**
- Channel doesn't exist → co-signer creates it with N co-signing members + delegate
- Channel exists → delegate joins existing channel

**Error handling:**
- Channel full (16 members) → reject
- Duplicate key → reject

**API (single call):**
```
POST /api/v1/channel/{ch}/join
Request:  { contribution: <GenesisContribution> }
Response: { snapshot: <ChannelSnapshot>, slot: number, balance: string }
```

---

### W2. Join Channel + Initial Deposit

**Overview:** Join a channel and immediately fund it with an L1 deposit.

```
W1 (Join)
 → A18 l1Deposit (client/L1)
   → [L1 tx confirmation polling]
     → [block inclusion wait]
       → A20 importDeposit (co-signer)
         → A6 importSnapshot (client)
```

**Branching:**
- `depositAmount == 0` → skip A18-A20
- L1 tx reverts → error, channel joined with 0 balance (user can retry via W7)
- Import fails → channel joined with 0 balance, deposit ticket at `l1_done` for retry

**API (orchestrated):**
```
POST /api/v1/channel/{ch}/join-and-deposit
Request:  { contribution: <GenesisContribution>, depositAmount: string }
Response: { snapshot: <ChannelSnapshot>, slot: number, balance: string, depositTxHash?: string }
```

---

### W3. Intra-Channel Send

**Overview:** Send tokens to another member in the same channel.

```
A6 importSnapshot
 → canSend?
   → NO:  A10 refresh → A11 cosignRefresh → A9 finalize
   → YES: (continue)
 → A7 send (client)
   → A8 cosign (co-signer)
     → A9 finalize (client)
```

**Branching:**
- `canSend == false` → must refresh first (received funds need noise reduction)
- "does not extend the current head" error → re-import snapshot, retry (max 1)

**API (single call):**
```
POST /api/v1/channel/{ch}/send
Request:  { to: "channel-slot", amount: string, payload: <SendPayload> }
Response: { snapshot: <ChannelSnapshot>, balance: string }
```
The client builds the payload via WASM; the API handles cosign + finalize.

---

### W4. Inter-Channel Send (Single Destination)

**Overview:** Send tokens to a member in a different channel.

```
A6 importSnapshot
 → A10 refresh → A11 cosignRefresh → A9 finalize (refresh always required)
 → fetch destination snapshot
 → A14 sendInterChannel (client)
   → A16 cosignInterTransfer (co-signer: atomic debit+credit)
     → A9 finalize (client)
```

**Branching:**
- Destination channel unavailable → error
- Destination slot doesn't exist → error
- rangeProof fails (inside cosign) → abort

**API (single call):**
```
POST /api/v1/channel/{ch}/inter-channel/send
Request:  { debitPayload, transferDescriptor }
Response: { sourceHead: <Snapshot>, destSnapshot: <Snapshot> }
```

---

### W5. Inter-Channel Bulk Send (Multiple Destinations)

**Overview:** Send tokens to multiple members across multiple channels in one atomic operation.

```
A6 importSnapshot
 → A10 refresh → A11 cosignRefresh → A9 finalize
 → fetch all destination snapshots
 → A15 sendBulkInterChannel (client)
   → A16 cosignInterTransfer (co-signer: atomic multi-dest)
     → A9 finalize (client)
```

**Branching:**
- Any destination unavailable → error (entire bulk fails)
- Mixed burn + normal legs → see W9

**API (single call):**
```
POST /api/v1/channel/{ch}/inter-channel/send-bulk
Request:  { debitPayload, transferDescriptors: [...] }
Response: { sourceHead: <Snapshot>, destSnapshots: { [channelId]: <Snapshot> } }
```

**Current status:** NOT IMPLEMENTED. Requires extending `build_inter_channel_send` for bulk.

---

### W6. Inter-Channel Receive

**Overview:** Process incoming inter-channel transfers on the destination channel.

```
(notification/polling: new transfer available)
 → A6 importSnapshot
   → verify entry wing Merkle inclusion
     → A17 receiveInterChannel
       → A8 cosign → A9 finalize
```

**Branching:**
- Invalid inclusion proof → ignore transfer
- Multiple entries for this channel → apply all in one state update

**Current status:** The receive side is handled implicitly inside `cosignInterTransfer`. In a multi-co-signer architecture, this would be a separate flow.

---

### W7. Additional Deposit (Mid-Channel)

**Overview:** Add funds to an active channel via a new L1 deposit.

```
A18 l1Deposit (client/L1)
 → [L1 tx confirmation: poll receipt]
   → [block inclusion: wait for deposit to appear in deposit tree]
     → A20 importDeposit (co-signer: 2-step fund import + bundle apply)
       → A6 importSnapshot (client)
```

**Branching:**
- L1 tx fails → retry
- L1 tx succeeds but import fails → ticket at `l1_done`, resume via `/api/import-deposit`
- Nullifier already used → reject (double-fold prevention, detail2 C-10 T2)

**API (orchestrated):**
```
POST /api/v1/channel/{ch}/deposit
Request:  { recipientSlot: number, depositor: string, amount: string }
Response: { snapshot: <ChannelSnapshot>, balance: string }
```

---

### W8. Partial Withdrawal (Channel Stays Open)

**Overview:** Withdraw funds to L1 while keeping the channel active. A "burn" debits the channel; a "settle" claims the ETH on L1.

```
A6 importSnapshot
 → [refresh if !canSend]
   → A21 burnSend (client: dest=BURN_CHANNEL_ID)
     → A22 cosignBurn (co-signer)
       → A9 finalize (client)
         ── ticket: burn_done ──
         (can pause here; resume on page reload)
         → [L1 inclusion wait + balance proof]
           → A24 pwSubmit (co-signer/L1: deploy-settlement if needed → submit intent → authorize)
             ── ticket: settle_pending ──
             → A25 pwFinalize (co-signer/L1: finalize + claim ETH)
               ── ticket: settle_done ──
```

**Branching:**
- Close request pending → burn rejected (abstract2-1 §3.6: no PW during close)
- Settlement not deployed → `pwSubmit` deploys it first (idempotent)
- Burn already pending settle → 409 duplicate prevention
- Page reload mid-flow → ticket system restores state, "Resume Settle" button

**API (two-phase):**
```
Phase 1 — Burn:
POST /api/v1/channel/{ch}/partial-withdrawal/burn
Request:  { debitPayload, transferDescriptor, amount: string, recipient: string }
Response: { state: <CosignedState>, ticket: <Ticket> }

Phase 2 — Settle:
POST /api/v1/channel/{ch}/partial-withdrawal/settle
Request:  { recipient: string }
Response: { authDigest: string }
```

---

### W9. Mixed Partial Withdrawal + Inter-Channel Send

**Overview:** Combine burn legs (partial withdrawal) and normal legs (inter-channel transfer) in a single `BulkInterChannelTx`. One ZKP proves sender solvency for the total. (abstract2-1 §3.6)

```
Same as W5, but some transfer_entries have dest_channel_id = BURN_CHANNEL_ID:
 → Burn legs: no recipient_delta, emit Withdrawal on L1
 → Normal legs: recipient_delta applied to destination channels

After L1 inclusion:
 → Burn legs follow W8's settle flow (A24, A25)
 → Normal legs follow W6's receive flow (A17)
```

**Current status:** NOT IMPLEMENTED. Requires bulk send support (A15) + burn leg routing.

**API:**
Same as W5 (`/inter-channel/send-bulk`), but the server detects burn legs by `dest_channel_id == BURN_CHANNEL_ID` and routes accordingly.

---

### W10. Full Withdrawal (Cooperative Channel Closure)

**Overview:** Close the channel, wait out the challenge period, and claim all funds on L1.

```
A27 deploySettlement
 → A26 requestClose (L1: ClosePending, grace starts)
   → [wait 600s grace period]
     → A28 submitCloseIntent (L1: close proof + intent)
       → [challenge period: 86,400s]
         ↙ (no challenge)        ↘ (challenge/cancel: see W11/W12)
       → A31 finalizeClose (L1)
         → A32 submitWithdrawalClaim (× member_count, each with Regev decryption ZKP)
           → A33 claimWithdrawalCredit (× member_count, ETH payout)
             → [optional] A34 submitPostCloseClaim (late transfers: see W13)
```

**Branching:**
- During challenge: another member calls W11 (challenge) → pending close replaced
- During challenge: members cooperate on W12 (cancel) → channel returns to Active
- `settle` called before challenge period ends → error, retry later
- Multiple members need to claim → A32+A33 per member (can be parallelized)

**API (multi-step with ticket tracking):**
```
POST /api/v1/channel/{ch}/full-withdrawal/deploy    → { manager, verifier }
POST /api/v1/channel/{ch}/full-withdrawal/request    → { txHash, closeRequestedAt }
POST /api/v1/channel/{ch}/full-withdrawal/submit     → { ok: true }
POST /api/v1/channel/{ch}/full-withdrawal/finalize   → { ok: true }
POST /api/v1/channel/{ch}/full-withdrawal/claim      → { ok: true, slot, recipient }
```
Or single orchestrated call (long-running, returns ticket for polling):
```
POST /api/v1/channel/{ch}/full-withdrawal/start
Response: { ticketId: string }

GET /api/v1/channel/{ch}/full-withdrawal/status
Response: { step: "deploy_done"|"close_done"|..., canProceed: bool }
```

---

### W11. Close Challenge

**Overview:** Replace a pending close with a newer signed state during the challenge period.

```
(observe: close pending with version V)
 → obtain state with version V' > V (all N members must have signed it)
   → build close proof for V' (CloseProver)
     → A29 challengeClose (= submitCloseIntent with higher version on L1)
```

**Preconditions:** Within challenge period (86,400s from last submitCloseIntent). `(epoch', version') > (epoch, version)`.

**Current status:** Contract supports this (re-calling `submitCloseIntent`). CLI/relay NOT implemented as a separate flow.

**API:**
```
POST /api/v1/channel/{ch}/close/challenge
Request:  { manager: string, newerStateVersion: number }
Response: { ok: true }
```

---

### W12. Close Cancellation

**Overview:** Cancel a pending close by cooperatively proving a newer state exists. All N members must sign the newer state. Channel returns to Active.

```
(observe: close pending)
 → all N members agree on a state with version > pending.final_state_version
   → build cancel close proof (CancelCloseProver)
     → A30 cancelClose (L1)
       → channel status = Active
```

**Preconditions:** `close_freeze_nonce` alignment. All N members cooperating.

**Current status:**
- Rust: `CancelCloseProver` — implemented
- Contract: `cancelClose(...)` — implemented
- CLI: NOT implemented
- Relay: NOT implemented

**API:**
```
POST /api/v1/channel/{ch}/close/cancel
Request:  { manager: string }
Response: { ok: true }
```

---

### W13. Post-Close Late Claim

**Overview:** After channel finalization, claim a late inter-channel transfer that was received but not yet settled at close time.

```
(channel finalized, have unreceived transfer)
 → build late balance proof (lateBalanceProof)
   → build post-close claim proof (PostCloseClaimProver)
     → A34 submitPostCloseClaim (L1)
       → A33 claimWithdrawalCredit (L1, additional ETH)
```

**Current status:**
- Rust: `PostCloseClaimProver` — implemented
- Contract: `submitPostCloseClaim(...)` — implemented
- CLI: NOT implemented
- Relay: NOT implemented

**API:**
```
POST /api/v1/channel/{ch}/close/late-claim
Request:  { manager: string, transferData: ... }
Response: { ok: true }
```

---

### W14. Delegate Send

**Overview:** A delegate member sends tokens. Same proving flow as W3, but the delegate does NOT co-sign. Authorization is via BabyBear A11 hash-sig over IMPA digest. Honest co-signing members verify the hash-sig before signing. (detail2 L-4, DLG-1)

```
A6 importSnapshot
 → [refresh if !canSend] (delegate proves RefreshAir, but does not co-sign)
   → A7 send (delegate builds channelTxZKP)
     → A8 cosign (co-signers verify hash-sig + ZKP, then sign; delegate does NOT sign)
       → A9 finalize
```

**Branching:**
- Hash-sig invalid → co-signers refuse to sign (DLG-1)
- Delegate has no signing obligation → fewer signatures in the state

**API:** Same endpoints as W3. The co-signer internally distinguishes delegate vs member.

---

### W15. Channel Initial Setup (Backing)

**Overview:** Full infrastructure setup for a new channel: deploy rollup, deposit ETH, generate balance proof. Admin-only, extremely heavy.

```
A44 setupBacking:
 → deploy IntmaxRollup contract (forge script)
   → send L1 deposit tx (cast send)
     → wait for confirmation
       → generate balance proof (recursive IVC, ~4GB, minutes)
         → save channel_backing.json + attestation + balance_vd
```

**Current status:** CLI `setup-backing` — implemented. Not a public API.

**API:** Admin CLI only.
```
CLI: INTMAX_CHANNEL=7 channel_member setup-backing http://127.0.0.1:8545
```

---

## Implementation Priority

### Phase 1: Core API (existing operations, new endpoints)

All operations that are already implemented in CLI/relay but need proper API surface:
- A1-A11, A14, A16, A18, A20-A22, A24-A25, A27-A28, A31-A33 → REST endpoints
- W1-W4, W7-W8, W10, W14 → orchestrated endpoints

### Phase 2: Missing Close Game Operations

Operations with Rust provers and contracts but no CLI/relay wiring:
- A30 cancelClose → new CLI `cancel-close`, new relay endpoint
- A34 submitPostCloseClaim → new CLI `post-close-claim`, new relay endpoint
- A45 cancelPartialWithdrawal → new Rust prover + CLI + relay
- W11, W12, W13 → orchestrated endpoints

### Phase 3: Bulk Operations

Operations not yet implemented at any layer:
- A15 sendBulkInterChannel → extend `build_inter_channel_send` for `Vec<TransferEntry>`
- W5, W9 → new workflows

### Phase 4: BP Separation

Operations currently embedded in the co-signer that should be separated for production:
- A35 postBlock → separate BP service
- A36 generateValidityProof → separate prover service
- A37 generateBalanceProof → separate prover service
