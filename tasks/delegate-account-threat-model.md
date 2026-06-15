# Threat model & design — Delegate account (branch `real-delegate-paymentchannel`)

Status: SECURITY MODEL CONFIRMED (user, 2026-06-16). No code yet (threat model first).
Base: `60b9561` (post SPHINCS+→Poseidon migration).

A **delegate account** is a channel participant that has a lattice (Regev) balance and can SEND/RECEIVE
with the exact same proofs a normal member uses, but does **NOT** participate in the N-of-N multisig
that co-signs channel-state updates. It relies on the co-signing members for state maintenance.

## 0. Security model (the load-bearing interpretation — please confirm/correct)

From the spec ("送金時の署名しかしない" + "range proof 等 証明・検証は通常アカウントと同じ" + "自分の残高
維持・他人の残高健全性は完全にメンバーに頼り切る"; 検閲/liveness は当面スコープ外):

- **DLG-1 (theft protection — TRANSITION LAYER ONLY, confirmed):** a debit of a delegate's balance is
  bound to the delegate's OWN send signature, and **honest signing members will NOT co-sign a state
  update that debits any party via a send lacking that sender's signature.** A delegate send is the
  identical mechanism as a member send: E-1 `channelTxZKP` (range/non-negativity, `before = after +
  amount`) + the BabyBear hash-sig over the IMPA digest (A11-bound to the delegate's registered
  `(pk_g, pk_b, regev_pk)`). So under HONEST members, a delegate's funds move only by its own
  authorization. This protection is enforced by member honesty at sign-time, **NOT** cryptographically
  at close.
- **DLG-2 (final balance is TRUSTED to the members, confirmed):** the delegate does NOT co-sign state.
  **Colluding members CAN forge the delegate's final balance** (e.g. under-report it and over-report
  their own) — the delegate has no cryptographic recourse, by design. The N-of-N members' co-signature
  over the final state is authoritative. The delegate also trusts members for OTHERS' balance soundness
  and sum conservation (it does not verify state itself).
- **DLG-3 (censorship / liveness): OUT OF SCOPE for now** (user). The delegate relies on members for
  inclusion of its sends and for close cooperation.

### Close / withdraw flow for a delegate (confirmed)
The delegate is NOT among the IMCH close co-signers (only `member_count` members sign the close state).
After the members sign and the close is finalized on-chain, **the delegate obtains the finalized,
member-signed state from any one member**, decrypts its own balance slot, and withdraws via the same
`WithdrawalClaim` + E-3 `withdrawClaimZKP` a member uses (proving its final-balance ct decrypts to
`amount` under its key), bound to the on-chain-finalized `close_intent_digest` + a per-(channel,close,
delegate) nullifier + the solvency guard `totalWithdrawn <= finalizedChannelFundAmount`.

### §4 RESOLVED (no attacker pass needed for theft-at-close)
The user accepts that the close does **not** cryptographically enforce per-transition authorization for
the delegate's final balance (DLG-2). So the implementation does **not** add close-level per-transaction
enforcement for delegate slots. The only on-chain guarantees the delegate inherits (same as members) are
**solvency** (Σ all withdrawals ≤ channel fund) and **no double-withdraw** (nullifier) — these MUST hold
for delegate slots too.

## 1. Current model (why a delegate doesn't fit as-is)

`member_count` currently fuses THREE roles for slots `0..member_count` (Explore map):
1. **has a balance slot** in `BalanceState.enc_balances[16]` (+ `pending_adds`);
2. **can send** (E-1 debits the slot; BabyBear hash-sig authorizes; A11 binds `sender_pk_g/pk_b` to
   the registered `MemberLeaf` at that slot);
3. **MUST co-sign** every IMCH state update — enforced by `verify_all_signatures`
   (`for slot in 0..member_count`), the close circuit's `active_bits`/list-commitment rebuild, and H1/
   IMCR committing `member_count`.

A delegate needs roles (1)+(2) but NOT (3). So role (3) must be split from (1)+(2).

## 2. Design — separate "co-signers" from "balance/send participants"

**Introduce `delegate_count` alongside `member_count`** (contiguous slot regions in the fixed-16 array):
- slots `0 .. member_count`                          → **co-signing members** (balance + send + N-of-N).
- slots `member_count .. member_count+delegate_count` → **delegates** (balance + send/receive/withdraw,
  **NO** co-sign).
- slots `member_count+delegate_count .. 16`           → padding.

Invariant: `2 <= member_count`, `member_count + delegate_count <= MAX_CHANNEL_MEMBERS (16)`.
`delegate_count` is committed into `BalanceState.h1()` and `ChannelRecord.signing_digest()` (IMCR) just
like `member_count`, so the member/delegate/padding split is fixed under the members' signatures.

Per-role behavior:
- **Identity (registration):** a delegate has a `MemberLeaf{pk_g, pk_b, regev_pk_digest}` exactly like a
  member (it needs `pk_b`+regev to send, and a key to withdraw at close). It is registered in its slot;
  the only difference is its slot index is `>= member_count` (a delegate region), recorded via
  `delegate_count`. `member_pubkeys_root` + the L1 keccak reg-chain cover ALL slots (members+delegates),
  unchanged in structure.
- **Co-sign (IMCH):** the N-of-N loops/commitments stay `0..member_count` → **delegates excluded**
  (`verify_all_signatures`, close `active_bits`, close list-commitment rebuild, validity bp set). No
  change other than the loop bound already being `member_count`.
- **Send (delegate as sender):** identical to a member send. The A11 check
  (`verify_channel_tx_sender_hash_sig`) must accept a sender slot in the **delegate region**
  (`member_count..member_count+delegate_count`), matching the delegate's registered `(pk_g, pk_b)`. The
  E-1 debits the delegate's slot; the hash-sig authorizes (DLG-1). The resulting state is co-signed by
  the **members** (n-of-n), not the delegate.
- **Receive (delegate as recipient):** identical — homomorphic credit to the delegate's slot, no sig.
- **Close / withdraw:** the final `BalanceState` (signed by members) includes the delegate slots. A
  delegate withdraws via the same `WithdrawalClaim` + E-3 `withdrawClaimZKP` as a member (proves its
  final-balance ct decrypts to `amount` under its key). The delegate is NOT among the IMCH close
  co-signers (only `member_count` members sign the close state). The delegate's final balance is thus
  attested by the members (DLG-2).

## 3. Threat enumeration (delegate-specific)

- **DA1 — members fabricate a delegate debit.** A member-co-signed state that lowers a delegate's
  balance with NO corresponding delegate send-tx. Prevented at the TRANSITION layer only: honest members
  refuse to co-sign a send lacking the sender's hash-sig (DLG-1). **Against fully-colluding members this
  is an ACCEPTED risk (DLG-2): they can forge the delegate's final balance.** Not closed cryptographically
  at close (per user). The non-negotiable on-chain guards that DO bind delegates: solvency + no
  double-withdraw (DA4/DA6).
- **DA2 — delegate sends without authorization.** A send debiting a delegate slot whose hash-sig is not
  the delegate's registered `pk_b`. Closed by the A11 check extended to the delegate region.
- **DA3 — delegate counted as a co-signer / member miscount.** If `verify_all_signatures` or close
  required the delegate to sign, the delegate (which doesn't co-sign) would break N-of-N; conversely a
  member must not be skippable by mislabeling it a delegate. The member/delegate split is signed
  (`member_count`+`delegate_count` in H1/IMCR), so neither side can be relabeled without all members'
  consent.
- **DA4 — delegate withdraws more than its balance / double-withdraw.** Same protection as members:
  E-3 proves decryption of the registered final-balance ct; `WithdrawalClaim` nullifier
  `keccak([IMCW, close_intent_digest, member_pk_g])` (use the delegate's `pk_g`) prevents double-claim;
  `totalWithdrawn <= finalizedChannelFundAmount` underflow guard.
- **DA5 — cross-region confusion (delegate slot treated as member or vice versa).** The slot regions are
  defined by `member_count`/`delegate_count` (signed); active/padding/region checks must be exact in
  every circuit (H1, IMCR, close, validity, registration).
- **DA6 — sum/solvency.** The channel fund (L1 escrow) must cover members + delegates. Σ over ALL active
  balance slots (0..member_count+delegate_count) ≤ channel fund. Existing conservation arguments must
  include delegate slots.

## 4. RESOLVED (user, 2026-06-16)

The delegate's final balance is **trusted to the N-of-N members** (DLG-2): the close does NOT
cryptographically enforce per-transition authorization for delegate balances, and colluding members can
forge a delegate's final balance. Accepted. ⇒ no close-level per-transaction enforcement is added for
delegates; the delegate's theft-protection is honest-member-only at the transition layer (DLG-1). The
on-chain guards the delegate DOES inherit (must hold): **solvency** (Σ all withdrawals ≤ channel fund)
and **no double-withdraw** (nullifier).

## 5. Implementation surface (once §0 confirmed + §4 resolved)

- `BalanceState` / `ChannelRecord` / registration: add `delegate_count`; commit it in H1 + IMCR + the
  reg-chain preimage (Rust + Solidity, re-pin differentials). Region validation.
- A11 sender check + `verify_send_transition`: accept sender slots in the delegate region.
- `verify_all_signatures` / close / validity: confirm N-of-N stays `0..member_count` (delegates
  excluded) and balance/solvency includes `0..member_count+delegate_count`.
- Close / withdraw: allow delegate-slot `WithdrawalClaim` (E-3) exactly like members.
- Registration / wallet / e2e: a delegate-creation path; a delegate send + a delegate withdraw test.
- Threat tests: DA1 (fabricated delegate debit rejected), DA2 (unauth delegate send rejected), DA4
  (delegate over/double-withdraw rejected), DA5/DA6.

## 6. Plan
1. Confirm §0 (security model) + resolve §4 (close enforcement) — adversarial pass.
2. Data layer: `delegate_count` + region validation + commitments (Rust+Solidity), green differentials.
3. Send/A11 + verify_send_transition for delegate senders; tests (DA1/DA2).
4. Close/withdraw for delegates; tests (DA4); solvency (DA6).
5. Registration + wallet + e2e (delegate create → send → withdraw).
6. Separate security review + attacker pass.
