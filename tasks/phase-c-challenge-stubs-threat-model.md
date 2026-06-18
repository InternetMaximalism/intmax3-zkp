# Phase C threat model — real cancelClose / specialClose / lateOutgoingDebit

Status: **THREAT MODEL. C1 (cancelClose) → implement now; C2/C3 have open design questions, surfaced below.**
These are §H-3 "additional defenses" — CHALLENGE/GRIEFING primitives (reset pending close / slash BP bond), NOT
value payout. The `receivedChannelFunds` cap does NOT bound them (no funds move on reset; BP slash is a separate
pot). So the stub forgeries are real: griefing/liveness DoS + BP-bond theft.

## Severity (forged proof today = trivial: pass keccak(PI) as the 32-byte "proof")
- **cancelClose — HIGH (unbounded griefing):** resets an honest pending close to Active, no nullifier, no cost
  → indefinite denial of settlement. PLUS a pre-existing soundness hole: `CancelCloseWitness::to_public_inputs`
  (`cancel_close_pis.rs:40-60`) checks only `revived_tx.source_channel_id == close.channel_id` — NOT that the
  revived block post-dates the close. Even a real circuit is a griefing primitive unless staleness is proven.
- **specialClose — MEDIUM (BP-bond theft + unjust freeze):** forged proof slashes `specialClosePenalty` from
  `bpBondCredits` to the caller + freezes an Active channel. Bounded by the bond.
- **lateOutgoingDebit — HIGH (griefing):** resets pending close; the `debitNullifier` is CALLER-SUPPLIED and
  NOT recomputed by the manager (`ChannelSettlementManager.sol:357,845`), so the replay guard is vacuous against
  a forger who varies it.

## C1 — cancelClose — REDESIGN REQUIRED (implementer halted at the security gate, 2026-06-18)
Two blocking findings; the pinned 41-limb cancel design is UNSOUND:
- **Finding D (CRITICAL forgery):** `ListCircuit` proves "key signed msg", NOT "key ∈ channel members"
  (`poseidon_sig/list.rs:300-310`). The 41-limb `CancelClosePublicInputs` has NO member binding, and the
  manager passes NO registered-member value to `verifyCancelClose`. ⇒ ANY third party fabricates an IMSB
  (channel_id=victim, small_block_number=final+1, own keys), forges cancel → permanent settlement DoS.
- **Finding B (unsound predicate):** "a later signed small block exists ⇒ stale close" FAILS as a defense — the
  BP unilaterally produces small blocks and can sign block final+1 AFTER an honest close starts. Bare
  block-number succession ≠ stale close.
- **Finding C (correct, keep):** era fence `revived.close_freeze_nonce + 1 == close.close_freeze_nonce` is right
  (`CloseIntent::new` advances +1, `channel.rs:763`); do NOT relax to `>=`.

### CORRECTED cancelClose statement (pending user sign-off — changes the pinned PI)
Prove: **the registered channel members N-of-N signed a channel state/IMCH at a version STRICTLY HIGHER than the
pending close's `final_state_version`** ⇒ the members agreed to keep operating ⇒ the close is superseded ⇒ cancel.
Reuse the CLOSE circuit's machinery: N-of-N member single-sig `ListCircuit` over the revived IMCH + expose
`member_set_commitment` (keccak over the registered member pk_g set) which L1 matches against
`registeredMemberSetCommitment()` (Finding D fix); add `revived_state_version` and prove
`revived_state_version > close.final_state_version` (Finding B fix); keep the era fence (C). This CHANGES the
41-limb `cancel_close_pis.rs` layout (add member_set_commitment + revived version) and threads the registered
member commitment into the manager — needs sign-off, not a silent rewrite.

## C1-OLD — cancelClose (superseded sketch below)
Statement: a SIGNED `InterChannelTx` from this channel that STRICTLY POST-DATES the close snapshot exists ⇒ the
close froze a stale state ⇒ cancel. PI struct EXISTS (`cancel_close_pis.rs`, 41 limbs). NO circuit yet.
Circuit must prove (reusing close's machinery):
- The revived tx's member signatures (recursive `ListCircuit` over member single-sigs, as `close_circuit.rs`),
  binding `revived_inter_channel_tx_digest` (IMIT) + `revived_small_block_root` (IMSB via
  `small_block_message::recompute`).
- `revived_tx.source_channel_id == close_intent.channel_id`.
- **STALENESS (the key addition):** `revived.small_block_number > close_intent.final_small_block_number`
  (in-circuit u64 comparison), with `close_freeze_nonce` consistency. Without it cancel is unconditional griefing.
- Expose the 41-limb `CancelClosePublicInputs` (to_u64_vec order); on-chain `_bindLimbsStrict` + MleVerifier,
  per-statement set-once VK, replace `_matches`. No replay guard needed (one cancel deletes pendingClose).
Reuse: ListCircuit/member-sig binding, small-block digest recompute, tx-digest recompute, strict limb binding.

## C2 — specialClose (DESIGN QUESTION before code)
On-chain ALREADY enforces: offender == registered BP (`Sol:759-762`), the 5-medium-block non-finalization
window (`:763-766`). Residual ZK obligation = "BP fully signed `fully_signed_small_block_root`" (single-sig
over the IMSB digest — reuse close's primitive) AND **non-inclusion of that block in the finalized medium-block
chain**. OPEN: the verifier has no commitment to the finalized medium-block chain to prove non-finalization
against — only caller-supplied `latestFinalizedMediumBlockNumber` (trusted via on-chain compare). DECIDE: does
the ZK proof add the signature-existence half only (and trust the on-chain window numbers), or must it also
prove non-inclusion (needs a new finalized-chain commitment exposed to the verifier)? No Rust struct/circuit yet
(only the native `SpecialClose` data + opaque `non_inclusion_proof`/`aggregated_signature_proof` blobs).

## C3 — lateOutgoingDebit (HARDEST; open design question)
Statement: a sender-signed outgoing tx was OMITTED from the close's final balance (close undercounts a debit).
Needs a **non-membership/omission** proof — NOT supported by `IncrementalMerkleProofTarget` (inclusion only).
OPEN: how to prove omission against the close's `final_settled_tx_chain`/accumulator? Candidate framings:
(a) ordering/version contradiction; (b) a new commitment enabling non-membership. ALSO must: derive the
`debitNullifier` in-circuit + recompute on L1 (fix the vacuous replay guard); thread `pendingClose.finalBalance
StateH1`/roots to the verifier (late-debit runs pre-finalize, anchors to close-intent not finalized storage).
No Rust struct/circuit/PI exists. Least developed; most uncertain — resolve the non-membership framing before code.

## Plan
- **C1 now**: implement cancelClose circuit (+ staleness fix) → independent review → commit.
- **C2/C3**: present the non-inclusion / non-membership design questions after C1; they may need a new commitment.
- Each: separate implementer/reviewer; NO git commands in impl subagents (prior incident); strict limb binding +
  per-statement set-once VK; fixtures regenerated by the user.
