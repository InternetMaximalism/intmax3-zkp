# Multi-token channels (up to 10 currencies per channel) — threat model

Status: design fixed 2026-07-27 (owner decisions below); implementation NOT started.
Spec: detail2.md §N. Implementation plan: doc/tasks/multitoken-todo.md.
Adversarial review: dedicated attacker subagent pass 2026-07-27; findings TM-1..TM-15 below.
Per CLAUDE.md, this document must be re-reviewed (fresh attacker pass on the actual diffs)
before any implementation phase is merged.

## Owner decisions (2026-07-27, fixed)

1. L1 scope: FULL — real ERC-20 escrow in IntmaxRollup (registry, safeTransferFrom, withdrawERC20).
2. Balance representation: Option A — fixed 10-wide ciphertext vector in the balance-slot leaf.
3. Token set: fixed at channel init + append-only cosigned `TokenRegister` transitions.
4. In-channel cross-token swap: OUT OF SCOPE v1. Every tx conserves within exactly one token.
5. No live migration: v3 testnet is reset. v1 state ≡ `registry=[ETH]`, all balances at token slot 0.

## Assets / adversary model

- Assets: per-token L1 escrow in IntmaxRollup (ETH + each registered ERC-20); per-channel per-token
  funds in ChannelSettlementManager; each member's per-token hidden balances.
- Adversaries: (a) a malicious member/delegate (crafts txs, claims, imports); (b) a colluding
  N-of-N cosigner set (can sign arbitrary channel states — intra-channel theft is the accepted
  model today, but must remain UNABLE to touch other channels' or other tokens' L1 escrow);
  (c) a malicious ERC-20 token contract (hooks, fees, rebasing); (d) a wire/relay observer.
- Trust unchanged from detail2 §H-3: intra-channel safety rests on ≥1 honest cosigner; the L1
  contracts are the cross-channel/cross-token solvency backstop and must not trust channel state.

## The three load-bearing properties

Every finding below reduces to one of these. Each must hold independently; a gap in any one is a
funds-loss bug even if the other two are perfect.

- **P1 — token binding triple.** For every state transition, the token slot in the SIGNED digest,
  the token slot in the ZKP public inputs, and the ciphertext position actually mutated in the
  leaf must be one constrained equality — and the other 9 positions must be proven unchanged.
- **P2 — per-token conservation on every path.** send, C2C, deposit import, refresh, close:
  for each token t, Σ slot balances[t] + unallocated[t] == channel_fund[t]. No path may move
  value between t and t'.
- **P3 — L1 per-token isolation.** Token-t claims are paid ONLY from token-t escrow, accounting
  keyed by BASE token_index (never channel-local slot), with no residual single-asset variable.

## Findings (attacker review 2026-07-27), with binding mitigations

Severity: FUNDS > SOUNDNESS > GRIEFING > PRIVACY. Each mitigation is a falsifiable obligation;
the todo checklist cites these IDs.

### TM-1 (FUNDS) Duplicate base token_index → double-drain of one escrow
Registry injectivity on base `token_index` is what per-token isolation stands on. If duplicate
detection is off-chain only, a colluding cosigner set registers token X at local slots t1,t2 and
withdraws `amounts[t1]+amounts[t2]` against one L1 pool — draining OTHER channels' token-X escrow.
**Mitigation:** duplicate rejection is (a) in-circuit in the `TokenRegister` transition AND the
close circuit (registry injectivity over `[0..token_count)`), and (b) irrelevant to L1 solvency
anyway because ALL L1 accounting keys on base token_index with a per-base-token ceiling
(`escrowed[t] -= amount` underflow-revert), mirroring today's global `totalEscrowed` discipline
(IntmaxRollup.sol withdrawNative). Both layers required; neither alone.

### TM-2 (FUNDS/SOUNDNESS) Binding-triple gap: signed token ≠ moved token
E-1/E-2/E-3 AIRs are reused unchanged, so token selection lives entirely in the WRAPPER
(transition verifier / claim circuit). If the one-hot select on `token_slot` is not forced equal
to the slot in the IMPA-v2 digest, or the other 9 ciphertexts are not proven identical prev→next,
a prover signs "move token 0" and mutates token 5.
**Mitigation (P1):** the transition verifier enforces, as connected constraints: `tx.token_slot`
(from the signed digest preimage) == leaf-select index == the ONLY position of 10 whose ct digest
changes on sender AND recipient leaves; `pending_adds` increments only at that position; E-1 is
handed exactly the (prev, after) ciphertexts selected by that index. Negative tests required:
tampered token_slot, mutated bystander ciphertext, pending_adds cross-slot increment.

### TM-3 (FUNDS) Residual single-asset variable in ChannelSettlementManager
Every one of `finalizedChannelFundAmount`, `totalWithdrawn`, `receivedChannelFunds`,
`totalCreditedOut`, `withdrawalCredits[address]` (Manager ~:500-513, cap checks :1067/:1129/:1168)
must become per-base-token. Any single one left global lets token-A claims draw on the sum of all
tokens (or on ETH-derived capacity → cross-asset theft).
**Mitigation (P3):** exhaustive conversion, per-token CapInv
`totalCreditedOut[t] + amount <= receivedChannelFunds[t]`, payout dispatch by t (0 → ETH,
else ERC-20 at the L1-registered address). Lean `CapInv` re-proven PER BASE TOKEN.

### TM-4 (FUNDS) ERC-20 fee-on-transfer / rebasing escrow inflation
Crediting the STATED amount while receiving less (fee-on-transfer) under-collateralizes escrow;
rebasing breaks the fixed-escrow invariant entirely.
**Mitigation:** measure `balanceOf(this)` delta around `safeTransferFrom`; REVERT unless
delta == stated amount (the deposit hash chain must never record an amount that was not
received). Rebasing/fee-on-transfer/hook-reentrant tokens are UNSUPPORTED — documented, and the
delta+revert rule fails them closed rather than silently.

### TM-5 (FUNDS) Claim nullifier must key on slot regev_pk_digest, NOT member_pk_g
The original proposal text said nullifier `[IMCW, close_intent, member_pk, token_slot]`. Keying
on a grindable `member_pk_g` reintroduces the B-2 multi-withdraw grinding attack (see
channel.rs:857-870 security note) — now ×10. Keying without token_slot collapses 10 tokens to one
nullifier (completeness break: only one token claimable per member).
**Mitigation:** nullifier = `[IMCW_V2, close_intent_digest(8), slot_regev_pk_digest(8),
token_slot]` — the leaf-bound Regev pk digest exactly as today, PLUS the token slot as its own
limb. Exactly one nullifier per (slot, token). Both regression directions get negative tests.

### TM-6 (SOUNDNESS) C2C cross-registry resolution unconstrained
Source and destination channels map the same base token_index to different local slots. If either
side's `base token_index → local slot` resolution is prover-chosen rather than constrained against
that side's H1-committed registry, the credit lands in the wrong token's ciphertext.
**Mitigation:** the C2C descriptor carries BASE token_index; E-2 PI gains it; BOTH sides'
transition verifiers constrain `registry[local_slot] == token_index ∧ local_slot < token_count`
against their own signed registries; unregistered on either side ⇒ reject in-circuit.

### TM-7 (FUNDS/SOUNDNESS) Deposit import three-way binding
`l1_deposit_import_digest` (IMLD, channel.rs:1217) gains token_index. It must simultaneously bind:
(a) which `channel_fund[base t]` grows, (b) which token position of the depositor leaf ciphertext
is credited, (c) `token_index ∈ registry` resolving to exactly that local slot — all in-circuit.
A gap between (a) and (b) diverges fund and balances per token → insolvency or stuck funds.

### TM-8 (FUNDS/SOUNDNESS) token_count bounds + fail-closed unused positions
Verified safe: the canonical zero ciphertext (all-zero coeffs, `RegevCiphertext::padding()`)
decrypts to 0 under ANY key, so a claim on an unused position provably yields 0, and no real
nonzero ciphertext can share the zero digest (collision resistance).
The DANGER is enforcement coverage: `validate()` (balance_state.rs:287-379 pattern) must enforce
per (slot, token): every position `t >= token_count` equals the canonical zero digest with
`pending_adds == 0`; `1 <= token_count <= 10` at init; `token_slot < token_count` rejected at ALL
of: leaf select, E-3 PI, Solidity claim verifier, Manager cap lookup.

### TM-9 (SOUNDNESS) Registry AND token_count both inside the signed H1 header
Mirror the member_count/delegate_count discipline (balance_state.rs:258-280). If token_count is
outside the header, the active/unused boundary is unsigned and reinterpretable under existing
signatures. Header stays fixed-width injective: new domain constant, registry always 10 canonical
u32 limbs zero-padded, token_count its own limb. Leaf widening (23 → 104 elems; recipient is
canonically 5 u32 limbs) applies to ALL
leaves including padding slots simultaneously, with a new leaf domain — same discipline as the
18→23 change (D14 lineage).

### TM-10 (FUNDS) ERC-20 reentrancy + L1 token address registry mutability
(a) `safeTransferFrom` is an external call into arbitrary token code (ERC-777 hooks): require
`nonReentrant` + effects-before/measured-delta ordering on deposit and all payout paths.
(b) The L1 `tokenIndex → ERC-20 address` registry must be APPEND-ONLY and IMMUTABLE per index
(set-once). A remappable index turns token-A escrow into token-B withdrawals; channels' H1-frozen
registries reference these indices forever.

### TM-11 (SOUNDNESS) token_funds_digest fixed-width + Rust↔Solidity re-pin
`token_funds_digest = keccak(DOMAIN ‖ registry[10×u32, zero-padded] ‖ token_count ‖
amounts[10×U256, zero-padded])` — always full width; omitting unused entries makes the preimage
variable-length (aliasing). Close PI length changes (95 → 103 limbs): re-pin
`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN` and the Solidity `closePIHash` preimage with a byte-for-byte
differential test (the `#[ignore]`d mismatch at channel.rs:1197-1200 is a live example of this
hazard class).

### TM-12 (PRIVACY, ACCEPTED) token_slot cleartext + per-token close claims
Wire observers and cosigners learn which asset each transfer moves; per-(member,token) claims
reveal each member's holdings distribution at close. Inherent to the fixed design (amounts stay
hidden; asset identity does not). ACCEPTED DEVIATION — recorded in detail2 §N-8; revisit only if
a future version encrypts the token selector.

### TM-13 (GRIEFING/completeness) Per-token noise budget coverage
`validate()` must range-check ALL 10 `pending_adds[slot][*] <= MAX_HOMO_ADDS_BEFORE_REFRESH`
(regev/params.rs:38). An unchecked counter ⇒ noise overflow ⇒ that token permanently unexitable
for that member (the exact D3 failure). Refresh-storm griefing across 10 tokens is a bounded
amplifier (N-of-N-gated); accepted.

### TM-14 (SOUNDNESS) Batch cosign per-tx obligation total over all 10 positions
v2.1b solo-rebuild generalizes per token; the danger is a UNIFORM under-check shared by all
cosigners (e.g. verifying only nonzero-delta tokens). The per-tx obligation must cover the full
binding triple including the 9-unchanged property, for every tx in a mixed-token batch.
Cosigner-state divergence is fail-closed (signatures don't aggregate) — safe.

### TM-15 (SOUNDNESS) Domain re-versioning + no bit-packing
Every preimage that gains a field gets a NEW domain constant (IMPA, IMLD, IMCW, slot-leaf, H1
header, E-2 PI, token_funds_digest), checked against the G-2 registry for non-collision. New
fields occupy their OWN canonical u32 limb — never bit-packed into an existing word (e.g. NOT
`(token<<16)|slot`), which would alias distinct pairs. The v3 reset closes v1↔v2 state replay;
the new domains close v1-observed nullifier/digest reuse.

## CLAUDE.md cryptographic-invariant checklist mapping

- Fiat-Shamir / MLE-WHIR wrapper: untouched by this feature (no transcript changes). Any close-PI
  length change flows through the EXISTING keccak-PI-hash binding — covered by TM-11's
  differential test.
- Commitment binding: the balance commitment (H1) changes shape; TM-9 preserves the fixed-width
  injective preimage discipline. No new PCS.
- Sumcheck/permutation: N/A (AIRs unchanged, TM-2 keeps them honest via wrapper binding).
- Randomness/parameters: no new randomness; Regev parameters (D1) unchanged per ciphertext.

## Residual / accepted risks

1. TM-12 privacy deviation (asset identity visible).
2. Fee-on-transfer / rebasing ERC-20s unsupported (fail closed, TM-4).
3. Intra-channel theft by a fully colluding cosigner set remains the accepted model — bounded now
   PER TOKEN by the L1 per-base-token ceilings (TM-1/TM-3), never cross-token or cross-channel.
4. A channel may register a token_index with no L1 ERC-20 registration; its fund[t] can never be
   funded via L1 deposits, so claims are 0 — inert by construction (no obligation beyond TM-7's
   import-side registry check).
