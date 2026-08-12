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
  > **SUPERSEDED — see §10.** This bullet is *narrowly* true (the import command itself adds no
  > env bypass) but it was read as a broader claim and it is wrong in that reading. The env var it
  > names disables one of the import path's OWN guards from the other side, and there is a second,
  > env-independent hole in the same guard. Do not cite this bullet without §10.
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

---

## 10. The backing-deposit guard can silently not run (investigation, 2026-08-10)

Status: **investigated, confirmed, and FIXED (2026-08-10).** Finding B below is
production-reachable, so per the standing rule ("escalate, don't patch") this section reported
before any change was made; the fix in §10.6 has since been implemented as specified, together
with the §10.8 finding-2 follow-up. See §10.9 for what landed and what residual remains.

### 10.1 The guard

`src/bin/channel_member.rs:4519-4530` — the refusal that stops a channel from importing its own
backing deposit (adversarial review finding 5):

```rust
let strip0x = |s: &str| s.trim_start_matches("0x").to_ascii_lowercase();
if !backing.deposit_tx.is_empty() && strip0x(&backing.deposit_tx) == strip0x(tx_hash) {
    die("REFUSING: this is the channel's BACKING deposit (channel_backing.json deposit_tx). …");
}
```

It is the *only* thing standing between the import path and a deposit whose value is already
counted in the channel's genesis fund. It compares against exactly one recorded transaction
hash, and it **skips entirely** when that hash is the empty string.

### 10.2 Finding A — `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` disables the guard permanently

Verified chain of evidence:

1. `channel_member.rs:607` — `let no_onchain_deposit = std::env::var("SETUP_BACKING_NO_ONCHAIN_DEPOSIT").is_ok();`
   Note `.is_ok()`: **any** value, including the empty string, activates it.
2. `channel_member.rs:608-617` — the deferred branch makes no `deposit()` call and yields
   `txhash = String::new()`.
3. `channel_member.rs:743-755` — that empty string is persisted as `deposit_tx`.
4. `BACKING_FILE` is written at **exactly one site** (`:744`) and read at exactly one site
   (`:524`). Nothing backfills `deposit_tx` afterwards. Confirmed by exhaustive grep of
   `BACKING_FILE` across `src/`, `tests/`, `api/`.
5. `channel_member.rs:1965-2002` — `withdraw` *does* make the deferred deposit, to
   `lc["deposit"]["recipient"]`. `wallet_core.rs:4374-4375` derives that recipient as
   `calculate_recipient_from_user_id(user_id, deposit_salt)` with `deposit_salt` loaded from the
   backing (`channel_member.rs:1768`) — i.e. **the identical `deposit_recipient` the import
   checks against**. The `cast(...)` return value at `:1988` is discarded; the tx hash is not
   captured, not printed, and not persisted anywhere.

⇒ For a channel created in deferred mode the guard is a permanent no-op, **including after the
backing deposit actually lands on-chain**. The reporter's hypothesis is confirmed in full.

Two aggravating details found while verifying:

- **The success message lies in deferred mode.** `channel_member.rs:756-760` prints
  `"setup-backing OK: REAL on-chain deposit {fund} … tx {txhash})"` unconditionally, so stdout
  reads `… tx )` with an empty hash. The only warning goes to **stderr** (`:614-616`). An
  operator or a stdout-scraping script reads "OK: REAL on-chain deposit".
- **The mode is not tied to a dev flag.** Contrast `api/lib/cli.js:18-26`, where the anvil dev
  key is gated on `INTMAX_DEV=1` and throws otherwise. `SETUP_BACKING_NO_ONCHAIN_DEPOSIT` has no
  such interlock, so "deferred mode against a production RPC" is not a contradiction the code
  refuses.

### 10.3 Finding A does NOT reach production

Swept `api/`, `hosting/`, `doc/docs/deploy-runbook.md`, `doc/tasks/regen-and-redeploy-runbook.md`,
all `*.sh`, `package.json`, `contracts/`. The env var appears in **three test files only**
(`tests/close_lifecycle_cli_e2e.rs:327`, `tests/itx_faucet_cli_e2e.rs:322`,
`tests/two_token_cli_e2e.rs:417`) plus docs. `api/` never invokes `setup-backing` at all
(`api/API-DESIGN.md:926-933` — "Admin CLI only"). The only non-test caller is
`hosting/wallet/wallet-relay.js:1033`, the dev-only localhost relay, and it does not set the var.

Empirically, every shipped backing record has a populated `deposit_tx`:
`deploy-staging/ch7`, `deploy-staging/ch8`, `wallet-live-work/ch7`, `wallet-live-work/ch8`.

**Residual (procedural, real).** Production `setup-backing` is a hand-run shell command —
`doc/docs/deploy-runbook.md:98-101` — and all three CLI spawners inherit the ambient environment
without clearing or whitelisting (`api/lib/cli.js:47`, `hosting/wallet/wallet-relay.js:53`,
`hosting/wallet/wallet-relay-ec2.js:46`). An operator who exported the var earlier in the same
shell (e.g. reproducing an E2E by hand) would produce Sepolia artifacts with no deposit and a
disarmed guard, and the stdout line would still say "OK: REAL on-chain deposit".

### 10.4 Finding B — the guard misses `withdraw`'s deposit in EVERY mode (production-reachable)

This is **not** gated on the env var and is the more serious half.

`channel_member.rs:1965` is explicit: *"`withdraw` ALWAYS makes the deposit here"*. In integrated
mode it deposits `backing.fund` at token index 0 to `backing.deposit_recipient` — the same
recipient, the same amount. Its transaction hash is captured nowhere. `deposit_tx` still names
only the `setup-backing` transaction. (The stale comment at `channel_member.rs:1756-1757` claims
the opposite — "the deposit was already made on-chain by `setup-backing`, so we do NOT deposit
again here" — and should be corrected either way.)

So in **default, non-deferred, production** configuration, once a channel has run `withdraw`
there exists a real on-chain `Deposited` log that:

- is emitted by `backing.rollup` (passes A3),
- names `backing.deposit_recipient` (passes A4),
- is unique in its transaction (passes A5),
- has a fresh `deposit_index`, so the replay ledger does not know it (passes A7),
- is unknown to the backing guard, because `deposit_tx` names a different transaction.

Reachability: `POST /api/v1/channel/:ch/full-withdrawal/submit` runs `withdraw`
(`api/routes/full-withdrawal.js:127`). `POST /api/v1/channel/:ch/deposit/import` accepts an
**arbitrary** caller-supplied `txHash` — validated only as `^0x[0-9a-fA-F]{64}$`
(`api/routes/deposit.js:79-87`) — and passes `--allow-unbound-depositor`
(`api/routes/deposit.js:98`). Because the depositor is the operator key, bound to no slot,
`depositor_slot` is `None` and the flag lets the caller name **any** active
`recipientSlot`. There is no close-freeze check on the import path.

**Authority required:** the shared API bearer token (`api/lib/security.js:49-67`). One token for
all writes, no per-member scoping — so any legitimate client of the relay is inside this boundary.
Not remote-unauthenticated.

### 10.5 What the damage actually is (concrete, and it is bounded)

Per §2 of this document, and re-verified against the contracts:

- **Not L1 theft.** Escrow release is gated by the withdrawal proof's finalized-root check
  (`IntmaxRollup.sol:1262`). On the settlement side the authoritative payout cap is
  `ChannelSettlementManager.claimWithdrawalCredit` :1460-1465, checked against
  `receivedChannelFunds[t]` — a **measured** balance delta (`pullChannelFunds` :1413-1419,
  `pullChannelTokenFunds` :1432-1440), not a declared figure. `receive()` :684-686 reverts unless
  the sender is the registry, so force-fed ETH cannot raise the ceiling.
  `finalizedChannelFundAmount` (:1051, from the signed close intent) is only an accrual bound and
  is documented as "non-authoritative" at :615-617. An inflated in-channel balance therefore does
  **not** by itself let a channel pull more escrow: pulling more requires a *new* real deposit,
  which is a wash.
- **Worth stating plainly, because it surprised me:** the rollup has **no per-channel escrow
  accounting**. `withdrawNative` :1519-1521 decrements the global `totalEscrowed`; the only thing
  preventing a channel from drawing on other channels' ETH is the Solidity 0.8 underflow revert
  plus the withdrawal proof. The comment at `IntmaxRollup.sol:1477-1479` calling cross-channel
  theft "impossible" is true only in the "cannot become insolvent" sense. That is a *separate*
  observation, not something this bug reaches — but it means the withdrawal proof is the sole
  cross-channel boundary, so anything that weakens it is a much bigger deal than it looks.
- **The realized harm is §2(b): irreversible exit-wedging.** The import pushes the deposit
  nullifier into `settled_tx_chain` (`wallet_core.rs:2925`). The backing deposit's nullifier was
  already consumed by the genesis balance proof (`channel_member.rs:700-711`), and `withdraw`'s
  deposit is consumed by the withdrawal proof's chain — so no base-layer balance proof can consume
  it a second time. Close / claim / partial withdrawal are then blocked **permanently**. One
  authenticated POST wedges the channel's exit at zero cost to the attacker and cannot be undone.
- **Plus §2(a):** a fake spendable in-channel balance for the named slot, which within the
  channel is a member-vs-member loss bounded by that channel's own pulled funds
  (`receivedChannelFunds[t]`), realized as later claimants' `claimWithdrawalCredit` reverting.

So: **griefing/DoS with irreversible effect on one channel, plus intra-channel misallocation.
Not cross-channel fund theft.** Bounded, but real, and reachable in the shipped configuration.

### 10.6 Proposed fix — IMPLEMENTED as specified (see §10.9)

Two layers. Both are needed; neither alone is sufficient.

**L1 — record every backing-recipient deposit the CLI itself makes.** Replace the single
`deposit_tx` scalar with a set, because there is provably more than one such deposit:

```rust
/// Every transaction in which THIS CLI deposited to `deposit_recipient`. A set, not a scalar:
/// `setup-backing` makes at most one, and `withdraw` makes one or two more (native + ERC-20 lane).
#[serde(default)]
backing_deposit_txs: Vec<String>,
```

`cmd_setup_backing` seeds it in the real-deposit branch; `cmd_withdraw` sends its `deposit()`
calls with `--json`, parses the hash, and **appends + persists before proceeding**. `deposit_tx`
is retained and still consulted, for compatibility with the four shipped backing files.

**L2 — make the guard's inapplicability explicit instead of implicit.** An empty string cannot
distinguish "no backing deposit exists yet" from "one exists and we lost its hash". Add an
explicit tri-state whose serde default is the unsafe case, so old files fail closed:

```rust
#[derive(Serialize, Deserialize, Default, PartialEq)]
enum BackingDepositStatus {
    #[default] Unknown,   // pre-dates this field → FAIL CLOSED
    Deferred,             // setup-backing deferred it; it is NOT on-chain yet
    Landed,               // it is on-chain and backing_deposit_txs names it
}
```

Guard becomes: always check set membership; then `Landed` with an empty set → die;
`Unknown` → die; `Deferred` → proceed but **print an explicit SECURITY note naming the guard as
not-applicable and why**, so "did not run" is never indistinguishable from "ran and passed".

**Why not blanket fail-closed on empty (the question asked).** It would break a legitimate flow.
`tests/itx_faucet_cli_e2e.rs` performs genuine mid-channel ERC-20 imports (`:569`, `:586`,
`:693`, `:721`, `:750`) while in deferred mode, before `withdraw` has run. At that moment the
backing deposit provably does not exist on-chain, so no import can be it, and refusing would be
refusing a safe operation. The tri-state is what makes "not applicable" a *justified, stated*
conclusion rather than a silent skip. Blanket fail-closed is rejected on those grounds.

**Known migration break:** a `channel_backing.json` written by the current code in deferred mode
deserialises to `Unknown` and will fail closed at import until `setup-backing` is re-run. The four
shipped production files are unaffected (they take the `Landed` path via non-empty `deposit_tx`).
Same class as the `deposit_recipient` migration break already noted in §7b; must go in the runbook.

**Out of scope but should be filed separately:** gate the deferred mode behind `INTMAX_DEV=1` the
way `api/lib/cli.js:18-26` gates the anvil key; make `channel_member.rs:756-760` stop printing
"REAL on-chain deposit" when it made none; fix the stale comment at `channel_member.rs:1756-1757`.

### 10.7 Test coverage — the check has never actually run

`grep` for the refusal string `"BACKING deposit"` across `tests/` yields exactly one site:
`tests/itx_faucet_cli_e2e.rs:685`. That test runs `setup-backing` in deferred mode
(`:321-324`), so `deposit_tx` is `""`, so the old `if !backing_tx.is_empty()` wrapper at the
call site skipped the whole block. **The guard has never been exercised by any test.** The
uncommitted edit that turns that wrapper into an assertion is therefore correct in intent and
correctly fails today — it is reporting a true negative, not a broken test.

Required coverage (not yet written):

1. **Explicit, justified skip.** In `itx_faucet_cli_e2e`, assert deferred mode *positively*
   (status `Deferred`, `backing_deposit_txs` empty) and assert the CLI emits the
   not-applicable SECURITY note. A skip must be something the test proves, never something it
   infers from an empty string.
2. **The guard actually firing.** Needs a run with a populated set. Cheapest home is
   `close_lifecycle_cli_e2e` / `two_token_cli_e2e`, which both call `withdraw` (`:383`, `:527`):
   after `withdraw` the L1 backfill populates `backing_deposit_txs`, so an import of that hash
   must be refused with "BACKING deposit" — covering Finding B and the backfill in one assertion,
   with no extra proving cost.
3. **Fail-closed.** A backing file with status `Unknown` must be refused.

### 10.8 Same-shape sweep

The bug class is: *a refusal conditioned on a field being non-empty/`Some`, where a supported
mode leaves that field empty.* Swept `src/`, `api/`, `contracts/src/`. The house style is
overwhelmingly fail-closed (`die`-on-empty, `ok_or_else`, `tokenFound` flags), so hits are few.

**Genuinely silently-off (2):**

1. `channel_member.rs:4524` — the subject of this section. Note the line *directly above it*,
   `:4515` `if backing.rollup.is_empty() { die(...) }`, is the same struct in the same function
   and is fail-closed. `deposit_tx` is the odd one out.
2. **`channel_member.rs:252 / 261 / 286` — the three `#[serde(default)]` replay ledgers**
   (`applied_tx_identities`, `spent_tx_identities`, `imported_deposits`), backing the refusals at
   `:3560`, `:3483`, `:4559`. `load_state()` (`:465`) dies if `cli_state.json` is missing, but
   `#[serde(default)]` makes *field-level* absence silent: a state file from any build that
   lacked or differently-named these keys deserialises to an **empty ledger**, and every
   `contains()` refusal silently passes. The code records that this has already happened once —
   `:243-245`, "Pre-TM-16 entries under the old field name are dropped by the serde default." A
   field rename is a total, silent reset of a security ledger with no diagnostic.
   **This matters here specifically because `imported_deposits` is the only backstop that would
   otherwise catch Finding B.** Both legs of the defence fail silently, and they fail
   independently. **FIXED (§10.9):** the `#[serde(default)]`s were REMOVED (the suggested
   "keep the default plus a version" shape was rejected — a version field alone still lets an
   absent key produce an empty ledger); `load_state` now checks each ledger key BY NAME and dies
   with a migration instruction, `CliState` is `deny_unknown_fields` so a renamed ledger is loud
   from both sides, and the only way past is the acknowledged `migrate-state` command.

**Permissive default feeding a security decision (different mechanism, same outcome) — low:**

- `channel_member.rs:4841` `burn["token_index"].as_u64().unwrap_or(0)` — a lone `unwrap_or`
  among six sibling `die`s (`:4779, :4782, :4786, :4792, :4799, :4809, :4815`), silently meaning
  "ETH". Bound into the IMPW `authDigest` (`:4846`), which selects `withdrawNative` vs
  `withdrawERC20`. Low: the digest is only a veto on a proof-verified leaf
  (`IntmaxRollup.sol:1500-1516`) and the payout path is deliberately dead (`:5097` `exit(1)`).
- `channel_member.rs:4302` — the comment says an explicit `[min_confirmations]` is clamped up to
  the floor, but the floor is **1**, not `DEFAULT_MIN_CONFIRMATIONS` (12). §7 above describes the
  intended behaviour correctly; the code comment at `:4302` is the thing that is misleading. No
  API route passes the positional, so this is operator-only.
- `api/routes/channel-init.js:68-97` — the deposit + import leg is wrapped in a `try/catch` that
  logs and returns **200** with the pre-deposit snapshot. A CLI *security refusal* (misdirection,
  replay, unregistered token, under-confirmed) becomes indistinguishable from success at the API
  boundary. Detection/operational, not a bypass, but it erases a fail-closed signal.

**Conditional by design, checked and cleared:** `IntmaxRollup.sol:1512`/`:1560`
`if (w.auxData != bytes32(0)) require(partialWithdrawalAuthorized)` — `auxData == 0` *is* the
definition of "not a channel partial withdrawal" (`send_tx_circuit.rs:179`,
`receive_transfer_circuit.rs:322` only advance `settled_tx_chain` when `aux_data != 0`), and it
is a veto rather than a payout gate; `recipient_sk: Option<..>` decryption checks
(`state_update_verifier.rs:526`, `:1106`, `wallet_core.rs:1522`, `:900`) — optional by
construction, soundness carried by the mandatory E-1/E-2 Regev proof; `api/routes/burn.js:25`
and `partial-withdrawal.js:30` client-intent cross-checks; `api/lib/security.js:54` read-auth
default; `channel_member.rs:224` `token_witnesses` (skips in the *safe* direction — an absent
witness makes `witness_source` return `None`, refusing the send);
`IntmaxRollup.sol:1802` (explicitly fail-closed). `ChannelSettlementManager.sol:1125-1140` and
`:1355-1363` are the pattern to copy: a `tokenFound` flag plus `revert TokenRegistryMismatch()`.

### 10.9 What landed (2026-08-10)

**Fix 1 — the backing-deposit guard (`src/bin/channel_member.rs`).**

- `ChannelBacking` gains `backing_deposit_txs: Vec<String>` (a SET — `withdraw` provably makes one
  or two more deposits than `setup-backing`) and `backing_deposit_status: BackingDepositStatus`
  (`Unknown | Deferred | Landed`, serde default `Unknown`).
- `cmd_withdraw` sends both of its `deposit()` calls with `--json`, parses the hash through the
  fail-closed `parse_cast_tx_hash`, and APPENDS + PERSISTS via `record_backing_deposit_tx` before
  proceeding — so a crash later in the pipeline still leaves the guard armed.
- The guard is now two parts: unconditional SET MEMBERSHIP over every known hash, then an
  APPLICABILITY match. `Landed` + empty set → die; `Unknown` → die; `Deferred` → proceed and PRINT
  a SECURITY note naming the guard as not-applicable and why. Blanket fail-closed on empty stays
  rejected for the reason in §10.6 (genuine mid-channel imports before `withdraw`).
- Legacy compatibility is an evidence-backed inference, not an assumption:
  `resolved_backing_deposit_status()` maps `Unknown` + non-empty `deposit_tx` → `Landed`. Verified
  live against `wallet-live-work/ch7`: it loads and the guard refuses its recorded `deposit_tx`.
- `setup-backing`'s stdout no longer claims "REAL on-chain deposit" when it made none, and the
  stale "we do NOT deposit again here" comment at the top of `cmd_withdraw` is corrected.

**Fix 2 — the replay ledgers.** `STATE_SCHEMA_VERSION` + `REQUIRED_LEDGER_KEYS`; the three ledgers
lost `#[serde(default)]`; `CliState` is `deny_unknown_fields`; `load_state` gates on version, then
on ledger-key presence by name, then deserializes strictly, and ANNOUNCES a pre-versioning file
instead of accepting it silently. `migrate-state --i-understand-this-resets-replay-ledgers` is the
one deliberate path, and it REFUSES outright if the file carries an unrecognised key (the
signature of a renamed ledger whose entries would be discarded). The single retained default is
`state_schema_version` itself, justified inline: it makes no security claim on its own, every
existing file pre-dates it, and its use is observable.

**Residual, not fixable retroactively.** A backing file written BEFORE this fix whose channel has
already run `withdraw` has an unrecorded second deposit; its hash is not in the file and cannot be
recovered from it, so the guard cannot name it. Any future `withdraw` backfills, and re-running
`setup-backing` re-arms from scratch. The §10.6 "out of scope" items (gating deferred mode behind
`INTMAX_DEV=1`, `api/routes/channel-init.js`'s 200-on-refusal) are still open.

**Coverage added.** `close_lifecycle_cli_e2e` (native lane) and `two_token_cli_e2e` (both lanes,
asserting the set holds TWO entries — the case a scalar could never refuse) assert the backfill and
then that importing each recorded hash is REFUSED; `itx_faucet_cli_e2e`'s deferred-mode skip is now
PROVED from the recorded status + empty set + the CLI's not-applicable note, instead of inferred
from an empty string; `inter_channel_cli::cli_state_missing_replay_ledger_fails_loudly` covers
absence, rename, newer schema, the announced pre-versioning acceptance, and both halves of
`migrate-state`.

### 10.10 The recurring pattern (three instances in one session)

All three of these were the SAME failure, in three different mechanisms: **a security check that
silently does not run, in a configuration the code supports.**

1. `channel_member.rs:4524` — a refusal conditioned on `!field.is_empty()`, where a supported mode
   leaves the field empty (§10.1–10.4).
2. `channel_member.rs:252/261/286` — `#[serde(default)]` on a security LEDGER, so an absent or
   renamed key yields an empty ledger and every `contains()` refusal passes (§10.8 finding 2).
3. `tests/inter_channel_cli.rs` — a serde MIRROR that drifted from the binary's field names, so
   every ledger assertion in the test read an empty vector regardless of what the binary wrote;
   and `tests/itx_faucet_cli_e2e.rs` — `unwrap_or("")` upstream of an assertion, which turned the
   assertion's own precondition into a skip.

The common shape is **a default standing in for a conclusion.** The check does not fail; it
evaluates to a vacuous truth, and vacuous truth is indistinguishable from a passing check in every
log, test report and code review.

The rule this yields, applied throughout the fix: **a security check may only be skipped on a
POSITIVE, RECORDED statement that it does not apply, and the skip must be observable** — the
tri-state `Deferred` plus its printed note, rather than an empty string; an explicit key-presence
check plus `migrate-state`, rather than `#[serde(default)]`; `deny_unknown_fields` plus no
defaults on a test mirror, rather than a forgiving one. Where a default genuinely must remain
(`state_schema_version`), it makes no security claim by itself and its use is announced.

Detection heuristic for future review: grep for a guard whose condition is `is_empty()`, `is_some()`,
`unwrap_or`, or `#[serde(default)]` and ask "which SUPPORTED configuration makes this false?" If
the answer is a real mode, the guard is off in that mode.
