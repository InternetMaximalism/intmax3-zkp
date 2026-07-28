# Threat model — L1 deposit import (`cosign-l1-deposit-import`)

Status: written BEFORE the fix (CLAUDE.md §Security-Critical Mindset).
Scope: the mid-channel L1→channel deposit import path, end to end
(browser → relay/api → CLI → `build_l1_deposit_import`).

---

## 1. The asset and the trust boundary

An L1 deposit import credits a channel balance slot with `amount` of `token_index`
*because the depositor escrowed that value in `IntmaxRollup`*. The entire economic
meaning of the operation is the claim **"this deposit really happened on L1, for this
channel, and has not been credited before."**

Before this change, nothing anywhere verified that claim.

- `hosting/wallet/wallet-relay-ec2.js:595` / `wallet-relay.js:533` `POST /api/import-deposit`:
  unauthenticated, takes `recipientSlot`/`depositor`/`amount` from `req.body`, no chain read.
- `api/routes/deposit.js:72-75` and `:119`: when the body carries `depositor` **and** `amount`,
  the server-written `pending_deposit.json` (the only tx-tied artifact) is bypassed.
  `api/routes/channel-init.js:87`: same body-trust shape on the join path.
- `src/bin/channel_member.rs:3943` `cmd_cosign_l1_deposit_import`: builds the `Deposit`
  **wholly from argv**, with `deposit_index: Default::default()` and
  `block_number: Default::default()`. There is no RPC call in the command at all.

The only sound caller was `node/cosigner/branches/deposit.js`, which is driven by the
chain-watcher's `Deposited` event — but even it re-serialized the decoded fields into argv,
so the CLI could not tell an event-derived call from a fabricated one. Its own header comment
("The CLI reconciles the deposit against the on-chain depositHashChain and enforces
nullifier-unused") was **factually false**; that reconciliation exists only in `setup-backing`
(`channel_member.rs:544-562`).

**Trust boundary decision.** The relay, the api service, the cosigner node and a human operator
all invoke the same CLI. A check placed in any one caller leaves the others open. The
verification therefore belongs at the **CLI**, which is the single choke point, and the
lying-capable parameters are **removed** from the interface rather than cross-checked — you
cannot fail to validate an input that no longer exists.

## 2. Blast radius (established, restated for completeness)

A fabricated import inflates `channel_fund.amounts[token_slot]` and the recipient's
`enc_balances[slot][token]`, and is then N-of-N co-signed by honest members whose gate returns
`Ok`. Consequences:

- **(a) Fake spendable in-channel balance.** Real, and the obvious harm.
- **(b) Irreversible exit-wedging.** The import pushes the deposit nullifier into
  `settled_tx_chain` (`wallet_core.rs:2925`). The close circuit recursively verifies a
  base-layer balance proof whose `settled_tx_chain` must match, and no balance proof can exist
  for a fabricated deposit nullifier. So close/claim and partial withdrawal are *blocked* — one
  curl **permanently** wedges the channel's exit at any later state. This is the worse harm:
  it is a griefing primitive that costs the attacker nothing and cannot be undone.

L1 fund theft is **not** in the blast radius: escrow release is gated by the withdrawal proof's
finalized-root check (`IntmaxRollup.sol:1262`). The damage is confined to channel state, but is
irreversible.

## 3. Confidentiality premise

In-channel amount confidentiality **is** a design goal (owner-confirmed; the Regev parameter fix
lands on a separate branch). Amounts are therefore *not* treated as public in this design.

Note the pre-existing comment at `channel_member.rs:3990-3998` justifying a fixed Regev seed on
this path with "it encrypts `amount`, which is a PUBLIC L1 deposit value". That justification is
narrow but **survives** this change and is not weakened by it: the imported amount is, by
construction after this fix, exactly the `amount` field of a public `Deposited` log. The seed is
also load-bearing for the TM-7 rebuild-equality gate. I am not touching it; flagged here so the
reviewer can see it was considered rather than missed.

---

## 4. VERIFY item 1 — Replay protection

### Question
With the REAL `deposit_index` populated, is each real deposit's `Deposit::nullifier()` unique,
and is that nullifier actually *enforced* against the channel's shared nullifier root?

### Finding A — uniqueness: YES, but only after this fix

`Deposit::to_u64_vec()` (`src/common/deposit.rs:58-68`) **does** include `deposit_index` and
`block_number`, and `nullifier()` is the Poseidon hash of that vector (`deposit.rs:82-88`).

> The struct comment at `deposit.rs:32` ("These two fields are not included in the hash") is
> **stale and misleading**: it describes `hash_with_prev_hash` (the on-chain `depositHashChain`
> fold, `deposit.rs:90-102`), not `poseidon_hash`/`nullifier`. Corrected in this change.

Consequence of the *old* code: because the CLI zeroed both fields, two genuinely distinct
on-chain deposits with the same `(depositor, token_index, amount)` produced the **identical**
nullifier. The value that is supposed to be the replay key was not even unique.

After this fix `deposit_index` is the contract's `depositCount++` counter
(`IntmaxRollup.sol:1009`), strictly monotone and unique per rollup contract, so `nullifier()` is
unique per real deposit. Uniqueness: **restored**.

### Finding B — enforcement: NO. It does not exist.

There is **no nullifier set at the channel layer at all**.
`ChannelState.shared_native_nullifier_root` (`src/common/channel.rs:554`) is a keccak **hash
chain**, not a set:

- `build_l1_deposit_import` (`wallet_core.rs:2893-2928`) folds the nullifier via
  `advance_nullifier` → `settled_tx_chain_push` = `keccak([DOMAIN, chain, leaf])`
  (`balance_state.rs:901-910`), and appends it to an `IncrementalMerkleTree`, which stores
  duplicates happily. There is no membership query, no indexed tree, no non-membership witness.
- The native gate `L1DepositImportUpdateWitness::verify`
  (`state_update_verifier.rs:896-937`) checks only `require_chain_push` (the fold is
  well-formed) and `ensure_different_root` (`before != after`). Because the fold is
  prev-bound, **replaying the identical nullifier always yields a different root**, so
  `ensure_different_root` passes on a replay *by construction*.
- The co-signer path `verify_l1_deposit_import_transition` (`wallet_core.rs:3066-3122`) is a
  rebuild-equality gate. It defends TM-7 leg (b) (wrong slot / wrong token / doctored delta)
  but does **zero** freshness checking. Feed it the same deposit twice against the new head and
  it returns `Ok(())` both times.
- `ChannelTransitionKind::L1DepositImport` requires no proof backend at all
  (`channel.rs:131-160`: `required_state_backend()` → `None`), so no circuit can enforce it.

The only real nullifier *set* in the repo is the base-layer indexed Merkle tree used by
`receive_deposit_circuit` (`update_private_state.rs:56-63`), hardened by the
BAL-CRIT-001 regression test. **`build_l1_deposit_import` never receives such a proof.**
`doc/architecture-audit/detail2.md:407-410` claims the T2 double-fold mitigation comes from
that tree via `verify_channel_backing`; that link is **unimplemented on this path**, and
structurally cannot be wired as-is (the import pushes the nullifier *twice*, the base layer
pushes it *once*, so the chains can never agree).

The codebase already admits this gap for the sibling inter-channel path
(`wallet_core.rs:1787-1790`, "this module does NOT maintain a consumed-tx ledger … Replay
protection is the CLI's responsibility"), and for inter-channel that CLI ledger **was** wired
(`applied_tx_identities` / `spent_tx_identities`, `channel_member.rs:252-261`). **The equivalent
ledger for L1 deposit imports does not exist.**

### Decision: add an explicit consumed-deposit ledger

Per the mandate, I do not hand-wave this. I add `imported_deposits: HashSet<String>` to
`CliState`, keyed on the **canonical L1 deposit identity**

```
{chain_id}:{rollup_address_lowercase}:{deposit_index}
```

checked before building and inserted in the same save as the new snapshot. Rationale for the
key: `deposit_index` is the contract's own monotone counter, so it is the minimal complete
identity of a deposit *within* a rollup; `rollup` and `chain_id` are included so the same index
on a different contract or a forked chain is a different entry. Keying on `deposit_index`
rather than the tx hash is deliberate — one transaction can contain several `Deposited` logs, so
a tx-hash key would under-count.

Additionally, the channel's **own backing deposit** (`channel_backing.json.deposit_tx`) is a real
`Deposited` log from this rollup to this `deposit_recipient` and therefore passes every chain
check — but its value is already counted in the genesis fund. Importing it would credit the channel
twice against one L1 escrow, so it is refused by name.

**Residual risks (stated, not hidden).**

1. This ledger is *local CLI state*, exactly like the already-accepted inter-channel ledgers. It is
   not cryptographically enforced: an operator who deletes `cli_state.json`, or a second CLI
   instance with a fresh state dir, could still replay.
2. **OPEN — no cross-process lock.** The sequence `load_state()` → check `imported_deposits` →
   … → `save_state()` is a read-modify-write with **no file lock**. `withLock` in the JS callers is
   per-process only, and the api service, the wallet relay and the node co-signer can all target
   the same channel work dir. Two concurrent imports of the same txHash landing in two different
   processes would both pass the check and both credit — the exact double-credit the ledger
   exists to stop, and unlike (1) it is *remotely* reachable. **This is not fixed here.** The fix
   is an advisory `flock` on `cli_state.json`, which needs a new dependency (`fs2`/`libc` — the
   crate has neither) and applies equally to the pre-existing `applied_tx_identities` /
   `spent_tx_identities` ledgers. Deliberately escalated rather than patched under time pressure:
   a hand-rolled lockfile risks deadlocking production on a stale lock. Until then, run exactly
   one writer process per channel.

The protocol-level fix for both — a real indexed nullifier set in the channel state, checked in a
circuit — is a design change well beyond this vulnerability and is **left open**. What this change
does guarantee is that a *single-writer* deployment cannot be made to replay by an unauthenticated
remote caller through any relay or api endpoint, which is the actual exposure being closed.

## 5. VERIFY item 2 — Credit misdirection

### Question
`recipient_slot` remains caller-supplied and decides who gets credited. Mallory can import
Alice's genuine deposit into Mallory's own slot. Should we require
`recipients[recipient_slot] == deposit.depositor`?

### The available binding
`BalanceState.recipients[slot]` (`src/common/balance_state.rs:277`) is the per-slot L1 exit
address (the B-1b binding), folded into the cosigner-signed H1 and immutable across state
updates (`state_update_verifier::verify_balance_state_common`). It is the right anchor.

### Who holds what, in practice
- **Browser delegate slot** — `recipients[delegate_slot]` is the joining user's own MetaMask
  address (`channel_member.rs:2318-2327`, from the contribution), and that is *the same wallet
  that signs the `deposit()` transaction* (`wallet-live.html:583-621` returns
  `{ txHash, depositor: walletAccount }`). The binding **holds exactly** for the entire browser
  deposit flow — the flow this vulnerability is actually exposed through.
- **CLI cosigner slots** — `recipients[slot] = test_recipient_for(channel_id, slot)`, a
  deterministic *synthetic* address that no one holds a key for. The binding **cannot** hold for
  the operator funding the $ITX faucet slot from the deployer account
  (`tests/itx_faucet_cli_e2e.rs:450`).

So an unconditional rule would break a legitimate flow. Per the mandate, it becomes the
**default** with one narrow exception.

### The rule

1. **Default (no flag): require `recipients[recipient_slot] == deposit.depositor`.**
2. **`--allow-unbound-depositor`** relaxes rule 1 *only* when the depositor is provably not a
   participant: if `deposit.depositor` equals `recipients[j]` for **any** active slot `j`, the
   import is **refused unconditionally** and no flag can override it.
3. `recipient_slot` may be given as `auto`, resolving to the unique active slot whose bound
   recipient equals the depositor (0 matches → refuse; >1 → refuse as ambiguous).
4. **Exit addresses must be DISTINCT across active slots** — enforced at the join
   (`join_delegate`), and re-checked at import (>1 match → refuse).

Rule 4 is not cosmetic; it was found by adversarial review after the first implementation. Without
it, `join_delegate` let a joining member declare **someone else's** L1 address as its own B-1b
recipient. A first-match resolution would then hand the victim's genuine deposit to the attacker's
slot whenever the attacker's slot index is lower — and `auto` is exactly what the chain-driven
co-signer path uses, since the `Deposited` event carries no slot. Even without `auto`, the victim's
own imports would hit the misdirection refusal forever, i.e. an irreversible exit-wedge. Both the
join-time rejection and the import-time ambiguity refusal are now implemented; the import-time half
also covers states created before the join check existed.

Rule 2 is the security-load-bearing half. The attack under consideration is *Mallory redirects
Alice's deposit*, and Alice — being a channel participant — necessarily has her address in
`recipients`. That triggers the unconditional refusal, so **the flag cannot enable the attack it
appears to relax.** The flag only covers the genuinely different case of a third party (the
operator's deployer key) funding a slot bound to a synthetic address.

The flag is a *CLI argv flag*, not an env var, so it is visible in the command line and in
process logs. **No relay or api endpoint accepts or forwards it**; only the faucet E2E and the
operator runbook pass it. It does not bypass any other check (chain read, recipient match,
rollup match, confirmations, replay ledger) — it narrows exactly one binding, under a
precondition that is itself checked on-chain data.

### Who passes the flag (revised after review)
The first implementation asserted "no relay or api endpoint passes this flag". Adversarial review
showed that would have **broken every server-key deposit flow**: `api/routes/deposit.js`
(`/l1-send`, `/import`, `POST /`) and `api/routes/channel-init.js` all sign the deposit with the
server's own `depositKey()`, so the on-chain depositor is the *operator*, bound to no slot, and the
default binding can never hold there. The corrected rule is:

| Caller | Who signs the deposit | Flag |
|---|---|---|
| `wallet-live.html` → relay `/api/import-deposit` (txHash in body) | the **user's MetaMask wallet** = the slot's bound B-1b address | **no** — binding enforced |
| relay `/api/import-deposit` falling back to `pending_deposit.json` | the server's `depositKey()` | yes |
| the whole `api/` service (no user-signed path exists there) | the server's `depositKey()` | yes |
| faucet / operator runbook | the operator's deployer key | yes |

In every flagged case the unconditional half (rules 2 and 4) still applies, so the flag can never
enable the attack it appears to relax.

### What remains open
- A third-party funder whose address is bound to no slot can have its deposit credited to any slot
  the CLI operator chooses. The operator already runs the co-signing keys, so this grants no
  authority they lack. Accepted.
- **Deposits from a contract wallet** (Safe, router, exchange) have `msg.sender` = the contract,
  not the user's bound EOA, so they hit the default refusal with no remote recovery path. Accepted
  for now; a contract-wallet deposit flow would need its own binding design.

Also open: `recipients[]` binds an address, and an attacker who *controls* an address bound to a
slot can of course deposit and credit that slot — that is the intended behavior, not an attack.

---

## 6. Adversary enumeration against the NEW design

| # | Attack | Defense |
|---|---|---|
| A1 | Fabricated `txHash` (no such tx) | `cast receipt --async` errors → CLI dies. `--async` is **mandatory**: without it `cast` blocks forever waiting for the tx, turning a refusal into a hang. |
| A2 | Real tx, but reverted | Require `status == 0x1`. |
| A3 | Real tx on a *different* contract emitting a look-alike `Deposited` | Require `log.address == backing.rollup` (case-insensitive compare of the 20-byte value). |
| A4 | Real deposit, but made for a **different channel** | Require `log.recipient == backing.deposit_recipient`. |
| A5 | Tx with several `Deposited` logs, attacker points at the fat one | Filter by rollup+topic0+recipient; 0 matches → refuse; >1 match → refuse as **ambiguous** (fail closed, no disambiguation parameter, so there is no lever to misuse). |
| A6 | Reorg: import a deposit that is later orphaned | Minimum confirmations (§7). |
| A7 | Replay the same deposit twice | Consumed-deposit ledger (§4). |
| A8 | Credit misdirection | Depositor↔slot binding (§5). |
| A9 | Inflate `amount` / change `token_index` / spoof `depositor` | **Structurally impossible**: those parameters no longer exist in the CLI interface. They are read from the log. |
| A10 | Argv injection via a caller-supplied hex string | `tx_hash` is shape-validated (`^0x[0-9a-fA-F]{64}$`) in the relays *and* parsed strictly in Rust before reaching `cast`; a leading `-` cannot survive either. |
| A11 | `amount` exceeding `u64` (the import encrypts a `u64`) | Explicitly checked and refused, rather than silently truncating — a truncating cast would credit a *wrong* amount, which is worse than refusing. |
| A12 | Relay keeps the old body-trust path as a "fallback" | Removed; `pending_deposit.json` is honored **only** when it carries a `txHash`, and that txHash is then verified on-chain like any other. |
| A13 | Malicious RPC endpoint lies about the receipt | **Out of scope / accepted**: the operator chooses the RPC. Noted because it is the trust root of the whole check — an attacker who controls the RPC controls the import. Mitigated in deployment by pointing at a trusted node. |

## 7. Confirmations and what "confirmed" means

Reorg safety needs a depth. `confirmations = latest_block - receipt_block + 1`.

- **Dev chain (`chain_id == 31337`, anvil):** default floor **0**. Anvil mines instantly and has
  no reorg model; requiring depth would just deadlock every local E2E. The transaction must
  still exist, be mined, and have `status == 1` — authenticity is *not* relaxed, only reorg
  depth, which is the only thing that is meaningless there.
- **Any other chain:** default **12**, floor **1**.

An explicit `[min_confirmations]` argument is honored, but is **clamped up to the floor** on a
non-dev chain. So an operator may knowingly tune 12 → 3, and can never tune a public chain to 0.
This is deliberately not an env var and deliberately not overridable to zero.

**KNOWN DEPLOYMENT CONSEQUENCE (open, deliberately not "fixed" by weakening).** On Sepolia
(`v3testnet.intmax.io`) the browser calls `/api/import-deposit` immediately after its deposit
receipt, i.e. at 1 confirmation, so the import will refuse until ~12 blocks (~2.5 min) have passed.
The existing deposit **ticket** makes this recoverable — the pending ticket keeps a "Resume Import"
button and the deposit is not lost — but the first attempt now fails where it previously
succeeded. The correct fix is a **relay-side wait/retry loop** before invoking the CLI (or an
explicit smaller depth chosen knowingly by the operator); it is *not* to lower the default, which
would trade reorg safety for a progress bar. Flagged for the deployment follow-up.

## 7b. Other accepted limitations (from adversarial review)

- **Amounts ≥ 2⁶⁴ are unimportable.** The import encrypts a `u64`, so `abi_word_u64` refuses
  anything wider (~18.44 ETH, or any 18-decimal ERC-20 above that) rather than truncating.
  Refusing is correct — a truncating cast would credit a *wrong* amount — but the L1 deposit is
  irreversible, so the **deposit side** (UI / relay / contract) needs a matching cap so such a
  transaction is never broadcast. Open follow-up.
- **`auxData` is now attacker-chosen** and folded into the nullifier. This is deliberate and
  strictly more correct than the previous hardcoded zero: it matches what the contract actually
  hashed. Recorded so it is a decision, not an accident.
- **The chain is not pinned to the channel.** `ChannelBacking` has no `chain_id`, so the ledger
  key and the confirmation floor both follow whatever RPC the operator points at. Combined with
  A13 (a malicious RPC is out of scope) this is accepted, but storing `chain_id` in the backing at
  `setup-backing` time is a cheap hardening worth doing later.
- **`setup-backing` still builds its own `Deposit` with `deposit_index: 0`**
  (`channel_member.rs:574`), which the corrected doc comment on `Deposit` now calls out as wrong
  in general. It is harmless there (that deposit's nullifier is not used for replay keying and the
  `depositHashChain` reconciliation excludes the index), but it is inconsistent. Left for a
  separate change rather than widened into this one.
- **Channels whose `channel_backing.json` predates `deposit_recipient`** now fail closed at
  import. Correct behavior, but a migration break worth noting in the runbook.

## 8. Explicitly NOT done

- **No `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` equivalent.** There is no env bypass, no
  "skip chain check" flag, no test-only path. The faucet E2E already makes a real ERC-20
  deposit against anvil; it now passes that transaction's real hash.
- **`block_number` is deliberately left at `Default::default()` (0).** **DEVIATION — see §9.**

## 9. DEVIATION from the assignment

The assignment says to populate "the REAL `deposit_index` **and** `block_number`". I populate
`deposit_index` and **deliberately do not populate `block_number`**, because they are not the
same kind of value:

`Deposit::block_number` is the **INTMAX rollup block number** in which the deposit was folded
into a validity block, not an L1 block number. `receive_deposit_circuit.rs:194` and `:322-323`
enforce `deposit.block_number <= new_block_r <= public_state.block_number` against *intmax*
block numbers. Writing an L1 block number (e.g. 8,900,000 on Sepolia) into that field would be a
unit/type confusion that silently poisons any future base-layer reconciliation of this deposit,
in a way that is hard to detect and impossible to undo — precisely the class of bug this task is
fixing.

For a deposit that has just landed on L1 and is not yet in any intmax validity block, the honest
value is "not yet assigned" = 0, which is what `Default::default()` already means. Nullifier
uniqueness does not depend on it: `deposit_index` alone is unique per rollup contract (§4).

Populating it correctly would require reading the intmax block that folded the deposit, which
does not exist at import time. Flagged for the reviewer rather than silently done either way.
