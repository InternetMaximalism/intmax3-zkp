# Threat model: CLI co-signer key provenance

Status: **ACTIVE INCIDENT** — the vulnerability below is live on `feat/falcon-poseidon-sig`
(HEAD `4574348`) and on everything deployed from it, including the public demo at
`v3testnet.intmax.io`, which is backed by real Sepolia deposits.

Written before the code change, per `CLAUDE.md` § "Default to Planning Mode" / "For any change
touching proof logic, cryptographic protocols, or security-sensitive components: write a full
threat model before writing any code".

---

> **Line-number convention:** citations of `src/bin/channel_member.rs` refer to the **pre-fix**
> file (HEAD `4574348`). The fix inserts ~190 lines near the top, so post-fix numbers are shifted;
> grep for the named symbol rather than trusting the number.

## 1. The vulnerability

`src/bin/channel_member.rs` mints every co-signer identity from a compile-time constant:

```rust
fn keys_for(seed: u64) -> MemberKeys {
    MemberKeys::generate(&mut StdRng::seed_from_u64(seed))   // :382-384
}

pub(crate) const CLI_COSIGNER_SEED_BASE: u64 = 0xC1_0000;    // :396

fn cli_cosigner_keys(active: usize) -> Vec<MemberKeys> {     // :401-405
    (0..active).map(|slot| keys_for(CLI_COSIGNER_SEED_BASE + slot as u64)).collect()
}
```

`MemberKeys::generate` (`src/wallet_core.rs:168-193`) is documented as, and is, a **pure
deterministic function of the RNG stream**: the Falcon-512 signing key, the BabyBear hash-sig key
and the Regev secret key are all drawn in a fixed order from the caller's `StdRng`
(ChaCha-based, specified byte stream, platform-independent by design — that reproducibility is a
feature for seed-restore, and it is exactly what makes this fatal here).

There is **no env override for the co-signer seeds**. `DELEGATE_SEED` (`:427-430`) is env-driven
but defaults to the literal `1`. `INTMAX_CLI_COSIGNERS` (`:157-166`) only changes *how many*
slots are derived, not *from what*.

The repository is **public** (`github.com/InternetMaximalism/intmax3-zkp`).

**Therefore: anyone who can read the repository can recompute the Falcon, BabyBear and Regev
secret keys of every co-signer slot of every CLI-driven or API-driven channel, by running four
lines of code.** No network access, no side channel, no timing — just the published source.

### 1.1 Why this is total loss of custody, not a partial weakness

The co-signers are the channel's **N-of-N** authority. Concretely, with all N co-signer keys an
attacker can:

1. **Forge channel state transitions.** `sign_state(&keys_for(...), slot, &state)` is the only
   gate on a state update; holding every slot's key means signing any state, including one that
   reassigns all balances to an attacker-chosen delegate slot.
2. **Sign a `CloseIntent` and drive the on-chain close.** `close` / `export-reg-record` /
   `withdraw` all read the identity off the same `MemberKeys` object (`:392-397`). The L1
   registration binds `ChannelRecord.member_pk_gs` to exactly these `pk_g` values, so an
   attacker's forged close **is the canonical close** as far as `IntmaxRollup` is concerned.
3. **Choose the payout address.** The close/withdrawal path carries a leaf-bound recipient. An
   attacker who signs the state signs the recipient too.
4. **Decrypt every balance.** The Regev secret key is part of `MemberKeys`. Channel balances are
   Regev ciphertexts under member keys, so confidentiality of every CLI member's balance is gone
   independently of the fund path.

The fund path is therefore: *read public repo → derive slot keys → sign a close state paying an
attacker address → submit the withdrawal proof → drain the channel's L1 escrow.* The escrow is
funded by real Sepolia deposits (`setup-backing`).

### 1.2 Blast radius: keys are not even channel-separated

`keys_for` takes only `CLI_COSIGNER_SEED_BASE + slot`. `channel_id_env()` is **not** an input.
Slot 0 of channel 7 and slot 0 of channel 8 (the two demo channels, `INTMAX_CHANNELS` default
`'7,8'` in `api/lib/cli.js:9`) are the *same key*. Every channel ever created by this CLI, on any
network, past and future, shares one key set. This is unchanged by the fix below (see §6.1) and
is recorded here as a known residual.

### 1.3 The production reach is real, not theoretical

`api/lib/cli.js:41-48` shells out to the compiled `channel_member` binary with
`env: { ...process.env, INTMAX_CHANNEL: String(ch), ...extraEnv }`. It supplies **no seed and no
key material**. So every channel the REST API creates — which is every channel behind
`v3testnet.intmax.io` — has co-signers whose keys are in the public source tree.

---

## 2. What a code change CANNOT fix

**This is the part that must not be softened.**

A key-provenance fix changes what *future* invocations derive. It does nothing to channels that
already exist, because those channels' identities are **already committed**:

- `ChannelRecord.member_pk_gs` on L1 (Sepolia) is bound to the derivable `pk_g` values. That is
  immutable on-chain data.
- The signed genesis snapshot and every subsequent co-signed state in
  `wallet-live-work/ch*/cli_state.json` and the exported snapshots are bound to the same keys.
- Any Regev ciphertext ever produced under those member keys is decryptable forever.

Rotating the code does not rotate an on-chain member set. Consequently:

> **Every channel created by this CLI or by the API before this fix must be treated as fully
> compromised, and every fund in it as spendable by any member of the public. The compromise is
> retroactive and permanent: even after the code fix, those channels' keys remain public
> knowledge.**

### 2.1 Required operational response (code alone is insufficient)

1. **Treat the funds as already lost until moved.** Assume an attacker may act at any moment; a
   passive observer of the public repo has had the capability for the entire life of the branch.
2. **Drain the affected channels to a safe address now**, using the current (compromised) keys,
   before anything else. This is a race the operator may already have lost, but it is the only
   recovery move available.
3. **Do not create new channels from the old binary.** Any channel created before the operator
   provisions real key material inherits the same fate.
4. **Retire the affected channels.** After draining, close them and never reuse those member
   sets. There is no "rotate the key in place" — the member set is on-chain.
5. **Re-provision and re-create.** New channels, created only after §4's key material is in
   place, with a freshly generated master secret that has never been in a repo, a shell history,
   a log, or a CI variable.
6. **Assume disclosure.** The repo is public and the constant is in git history. Removing the
   constant does not un-publish it; git history retains it, and clones exist.
7. **Audit the Sepolia escrow balances** of the affected `ChannelFund`s for withdrawals the
   operator did not initiate. If any exist, the keys were already exploited.

---

## 3. Attacker model

| # | Attacker | Capability | Reachable today? |
|---|----------|-----------|------------------|
| A1 | Anonymous internet reader | Reads the public repo, derives all co-signer keys, drains any CLI/API channel | **YES — the live vulnerability** |
| A2 | Same, targeting confidentiality only | Decrypts all CLI members' Regev balances | **YES** |
| A3 | Local unprivileged user on the API/demo host | Reads another user's process argv via `ps` | **YES** — see §5.4 |
| A4 | Anyone who reads deploy logs / CI output | Recovers whatever the operator echoed | Depends on operator; §5.3 |
| A5 | Operator who mis-provisions | Runs production against test keys | Prevented by §4's fail-closed design; see §5.1, §5.5 |
| A6 | Attacker who compromises the API host filesystem | Reads the master key file | In scope, accepted; the key must live *somewhere* the process can read it |

A6 is the irreducible residual: a process that can sign must be able to reach its signing key.
The fix moves the trust boundary from *"anyone on the internet"* (A1) to *"whoever already owns
the host"* (A6). That is the whole point, and it is a very large improvement, but it is not
"secure against a compromised host".

---

## 4. The fix: external key material, fail closed

### 4.1 Mechanism chosen — a keystore FILE named by env, not an env-supplied secret

Three candidates were considered:

| Option | Rejected/chosen | Reason |
|---|---|---|
| Per-slot key files | rejected | N files to provision, N chances to half-provision (see §5.2); no benefit — one host holds all N slots anyway |
| Secret *in* an env var (`INTMAX_COSIGNER_SEED_HEX=...`) | rejected | Environment is readable via `ps -E` / `/proc/PID/environ`, is inherited by every child process (including the ~27 `cast` subprocesses), leaks into crash dumps and process managers, and lands in shell history when set interactively |
| **File path in an env var, secret in the file** | **chosen** | The env carries only a path (harmless if seen); the secret is reachable only through the filesystem, where it is protected by unix permissions that we can *verify*. Matches `CLAUDE.md`'s existing rule for `.claude/priv`: "Store any new secret under `.claude/` or another gitignored path" and "hand the key to local processes directly" |

**`INTMAX_COSIGNER_KEYFILE=/path/to/secret`** — a file holding >= 32 bytes of hex.

Validation, all fail-closed (`die`, exit 1):

- path must exist and be a **regular file** (not a symlink to something surprising, not a fifo);
- **mode must have no group or other bits** (`0o077 & mode == 0`). A world-readable key file is
  the same class of bug we are fixing, so it is refused rather than warned about;
- contents must hex-decode to **>= 32 bytes**, rejecting an empty/truncated file;
- the decoded material must not be **all zeros** (catches a file of `0000...`, a
  `truncate`-created placeholder, or a device that reads as zeros).

### 4.2 Derivation

```
master   = keccak256( b"INTMAX3/CLI-COSIGNER-MASTER/v1" || file_bytes )
seed(i)  = keccak256( b"INTMAX3/CLI-COSIGNER-KEYS/v1"   || master || u64_le(i) )
keys(i)  = MemberKeys::generate(&mut StdRng::from_seed(seed(i)))
```

- Keccak-256 comes from `keccak-hash` 0.8, already a direct dependency and already the repo's
  hash for `falcon_sig` (`src/falcon_sig/mod.rs:167`). **No primitive is implemented from
  scratch** (`CLAUDE.md` cryptographic-invariant checklist).
- Keccak is a sponge, so there is no length-extension concern; the two distinct ASCII domain
  tags give domain separation between the normalisation step and the per-slot step, so a master
  can never collide with a slot seed.
- The label `i` is the existing `u64` "seed" value (`CLI_COSIGNER_SEED_BASE + slot`, or
  `DELEGATE_SEED`). It is now a **public, non-secret slot label**, not key material. It stays a
  `u64` so that the persisted `ControlledMember.keygen_seed` field in `cli_state.json` keeps its
  on-disk shape and meaning — no state-file migration, and no second derivation path (the
  Phase-3 finding-7 identity-divergence trap, `channel_member.rs:386-395`).
- The master is held in a `Zeroizing` buffer and is never returned, printed, or `Debug`-derived.

### 4.3 Single choke point

`keys_for` is the **only** place in the binary where `MemberKeys` is born. Two call sites
currently bypass it (`cmd_gen_contribution` at `:3123`, and the delegate-send reconstruction at
`:3211`, both `MemberKeys::generate(&mut StdRng::seed_from_u64(seed))` inline). Both are routed
through `keys_for` as part of this change — not merely for tidiness: if they kept the old
derivation while `cli_active_keys` used the new one, the delegate identity would silently diverge
between `gen-contribution` and `init`, which is precisely the Phase-3 finding-7 failure (channel
becomes unclosable). One derivation, one function, enforced by there being no other constructor
call.

### 4.4 Fail-closed resolution table

Resolved **once** per process (`OnceLock`) so the decision cannot differ between two calls in one
invocation:

| `INTMAX_COSIGNER_KEYFILE` | `INTMAX_INSECURE_DETERMINISTIC_KEYS` | Result |
|---|---|---|
| set | unset | **Production.** Derive from file. |
| unset | `1` | **Test.** Old `seed_from_u64` path + loud stderr banner every run. |
| set | set (any value) | **DIE.** Ambiguous provenance is refused, never resolved by precedence. |
| unset | unset | **DIE** with a message naming both vars and what to do. |
| unset | anything other than `1` | **DIE.** No truthiness parsing — `0`, `false`, `no`, `""` all die rather than being interpreted. |

The insecure branch is unreachable without a human typing a variable named
`INTMAX_INSECURE_DETERMINISTIC_KEYS=1`. There is no default, no precedence rule, and no partial
configuration that silently lands on it. **This is deliberate: this session has already found
three separate "the security check silently does not run" bugs, so the requirement here is that
the insecure state be structurally unreachable, not merely discouraged.**

---

## 5. Failure modes of the NEW design

Enumerated as required, with the mitigation actually implemented.

### 5.1 Missing configuration → silently insecure
**Mitigated.** Neither-set is a hard `die`. There is no fallback branch to land on. The failure
mode inverts: a mis-provisioned production host *stops working loudly* instead of *working
insecurely and silently*. That trade is correct.

### 5.2 Partially-configured slots
**Structurally impossible.** One master secret generates all slots by KDF, so there is no state
where slot 0 is provisioned and slot 2 is not. This is the main reason per-slot key files were
rejected. The count of slots (`INTMAX_CLI_COSIGNERS`) is independent of provenance.

### 5.3 Key material logged, echoed, or committed
- The master is never printed. The `die` messages name **the env var and the path**, never the
  contents; a path is not a secret.
- No `Debug`/`Display` on any type holding the master; it lives in a `Zeroizing<[u8;32]>` behind
  a `OnceLock` and is only consumed by the KDF.
- Panics: `keys_for` and its helpers use `die(...)` (message + `exit(1)`), so no `unwrap` on a
  buffer containing key bytes can print them in a panic payload. The buffer is never formatted.
- Committing: the recommended location is `.claude/` (already gitignored, `.gitignore:76,80`);
  `*.key` is also ignored (`.gitignore:83`). The runbooks direct operators to those paths. This
  is a *convention*, not enforcement — an operator can still put the file in a tracked directory.
  **Residual, accepted, documented in the runbooks.**

### 5.4 Keys in process argv, visible via `ps` — FIXED 2026-08-20
All CLI/API L1 writes now resolve the RPC chain id before choosing a signer. Chain 31337 may use
Anvil's public throwaway key; every other chain rejects `INTMAX_DEPOSIT_KEY` and requires a
validated Foundry keystore name in `INTMAX_L1_ACCOUNT`, emitted only as `--account <name>`.
Non-interactive CLI/API processes obtain the encrypted-keystore password from the password file
named by Foundry's standard `ETH_PASSWORD` env alias, never from child argv. The only
production-code `--private-key` literals
left are inside the explicitly local branch of the shared signer abstraction (plus the dev-only
localhost relay). Focused Rust and Node tests cover the real-chain refusal and argv selection.

### 5.5 The test path re-enabled in production by accident
Ranked by likelihood:

- **Env inheritance.** `api/lib/cli.js:47` spreads `...process.env` into every CLI child. If
  `INTMAX_INSECURE_DETERMINISTIC_KEYS=1` is ever exported in the API server's environment — a
  systemd unit, a `.env`, a Dockerfile `ENV`, a developer's shell that later starts the server —
  **every** channel it creates silently reverts to public keys. Mitigations: (a) the variable
  name is long, screaming, and un-guessable by accident; (b) a red banner is printed to stderr on
  **every** invocation that takes the branch, not once per process-tree, so it appears in the API
  server's captured logs repeatedly; (c) setting *both* vars dies, so a host that has correctly
  provisioned a keyfile cannot be downgraded by additionally setting the insecure flag — it
  breaks instead. (c) is the strong one: on a properly configured production host the insecure
  flag is not a downgrade, it is an outage.
- **Copy-pasted runbook.** Mitigated by the runbook text marking the flag test-only and never
  showing it in a production command block.
- **CI leaking into deploy.** The flag lives in test harness code (`.env(...)` on the spawned
  command), not in any shell profile or exported variable, so it is scoped to the test process
  and cannot escape into a deploy shell.

### 5.6 The master file is readable by the wrong user
Mode is checked (`0o077` must be clear) and the run dies otherwise. Not checked: ownership by the
running uid (a root-owned 0600 file readable because the process *is* root is fine), or ACLs, or
the permissions of the *parent directories*. **Residual, accepted** — directory traversal
hardening is beyond a single-file check and the host-compromise case is A6 anyway.

### 5.7 Operator generates a weak master
The file is required to be >= 32 bytes of hex and non-zero, but nothing can stop an operator
writing 32 bytes of `deadbeef` repeated. The runbooks give an exact `openssl rand -hex 32`
command with the correct `umask`. **Residual, accepted.**

### 5.8 Losing the master = losing the channel
Because keys are derived, the master file is the *only* copy of the channel's signing authority.
Deleting it makes every channel derived from it permanently unclosable (funds locked, not
stolen). This is a new availability risk that the old constant did not have. The runbooks call
for backing it up to the operator's secret store before any channel is created. **Accepted:
availability risk traded for the removal of a total-custody-loss risk.**

---

## 6. Related findings — same class, NOT all fixed here

### 6.1 Co-signer keys are not channel-separated (unfixed, documented)
§1.2. `channel_id_env()` is deliberately **not** folded into the KDF. Folding it would be
strictly better for blast radius, but `channel_id_env()` has a silent default of `7`
(`:113-118`), so any invocation that forgot `INTMAX_CHANNEL` would derive a *different, wrong*
key set and produce exactly the silent identity divergence this file warns about twice. Given the
choice between "one master compromise affects all channels" (already true, and A6-gated) and "a
missing env var silently bricks a channel", the former is the safer default. Revisit only
together with making `INTMAX_CHANNEL` itself fail-closed.

### 6.2 L1 private key in argv (fixed)
§5.4. The CLI and API use a Foundry keystore plus `--account` off-devnet. A legacy raw-key variable
is rejected on all non-31337 chains, so production child argv cannot contain L1 private material.

### 6.3 Anvil dev-key fallback (fixed and chain-bound)
The fallback exists only after the RPC reports chain id 31337. Both Rust and JS fail closed on
every other chain unless `INTMAX_L1_ACCOUNT` is set, and both reject a legacy raw key there.

### 6.4 `DELEGATE_SEED` defaults to `1` (fixed by this change)
`:427-430`. `keys_for(1)` was a fully derivable delegate identity. It now routes through the same
provenance switch, so in production it is a KDF label, not key material. The *default of 1*
remains as a label default, which is harmless once labels are not secrets.

### 6.5 Regev encryption randomness in the dev-only contribution path (unfixed, documented)
`cmd_gen_contribution` uses `StdRng::seed_from_u64(seed ^ 0xA11CE)` (`:3125`, `:3252`) as Regev
encryption randomness. Reusing one `r` across two different plaintexts under one key leaks their
difference (the exact hazard `fresh_seed32`'s doc comment at `:3321-3324` describes). These two
commands are marked DEV/TEST ONLY and simulate the browser; the real browser supplies its own
contribution. **Reported; not on the production path.**

### 6.6 `POST /api/v1/keys/generate` mints keys server-side from a caller-chosen u64 (UNFIXED — needs a decision)
`api/routes/keys.js:11-16` shells `gen-contribution` with an optional caller-supplied `seed`,
defaulting to none, which the CLI parses as `unwrap_or(1)`. So:

- a request with no body returns **the same identity on every call, for every user**;
- a caller who supplies `seed` **chooses** the label, and before this fix could therefore compute
  the corresponding secret key themselves;
- a non-numeric `seed` silently parses to `1` (`unwrap_or`, no error).

`cmd_gen_contribution` is documented "DEV/TEST ONLY" in the Rust source, yet it is exposed on a
mounted production API route. This change fixes the *provenance* (the derived key is now KDF'd
from the host master, so it is no longer publicly computable), but **not the design**: the server
still generates what is supposed to be a user-held key, and all seedless callers still collide on
one identity. The route's own comment says "In production the private key MUST NOT leave the
client". **Recommend removing or gating this route.** Not changed here — it is an API surface
decision, not a key-provenance bug.

### 6.7 Fixed `seed_from_u64(1)` in the production withdrawal path (unfixed, reported)
`src/wallet_core.rs:4282-4284` — `let mut rng = StdRng::seed_from_u64(1); … Salt::rand(&mut rng)`,
commented "FIXED rng seed for deterministic / reproducible output". This is the **user
private-state salt** of the withdrawal witness, and the same stream feeds the ERC-20 lane's
`deposit_salt` (`:4374`, `:4394`; the CLI always passes `deposit_salt: None`,
`channel_member.rs:2233`). `:4654-4655` derives the withdrawal *prover address* from
`seed_from_u64(777)`. This code is **not** under `#[cfg(test)]` and is reached from
`POST /full-withdrawal/withdraw`. Salts here are privacy blinders rather than signing keys, so
this is unlinkability loss, not custody loss — but it is the same "constant seed in production"
pattern. **Reported; needs its own change.**

### 6.8 Hardcoded anvil key in the hosting relay (accepted, dev-only file)
`hosting/wallet/wallet-relay.js:1005` embeds the anvil key literally (used at `:732`, `:735`,
`:1017`), with no `INTMAX_DEV` guard. It is the local dev relay, but it lives in `hosting/`.
`hosting/wallet/wallet-relay-ec2.js` passes ambient environment to the CLI, whose shared signer now
rejects `INTMAX_DEPOSIT_KEY` off-devnet and requires `INTMAX_L1_ACCOUNT`.

### 6.9 Synthetic delegate exit address (noted)
`channel_member.rs` derives the simulated delegate's L1 exit address as
`Address::from_u32_slice(&[0xDE1E_0000u32.wrapping_add(seed as u32); 5])` — an address nobody
holds a key for. Funds routed there are unclaimable. Dev-simulator path only.

### 6.10 Confirmed NOT vulnerable
- `fresh_seed32()` (`:3325-3332`) draws from `rand010::rng()`, an OS-seeded CSPRNG. Correct.
- `TokenWitness.seed_hex` persists Regev *encryption* randomness, not a signing key, and is drawn
  per-refresh from `fresh_seed32()`. Correct, and its doc comment states the invariant.
- `balance_seed = 0xBA_0000 + slot` (`:2796`) seeds genesis *balance* ciphertext randomness for
  CLI members, not key material. It is predictable, which means a CLI member's genesis balance
  ciphertext is not hiding — but those balances are the hardcoded `genesis_amount()` constants
  (`:172-179`), i.e. already public. No additional loss. **Noted, not fixed.**

---

## 7. Verification that the fix is real

Automated, in `tests/inter_channel_cli.rs` (5 new tests, all spawning the real compiled binary
with `env_clear()` so an inherited `INTMAX_*` cannot mask a regression):

| Test | Proves |
|---|---|
| `keygen_fails_closed_when_no_provenance_is_configured` | unconfigured => dies, names the var, and writes **no** key material |
| `keygen_fails_closed_when_both_provenances_are_set` | ambiguity is refused, never resolved by precedence |
| `insecure_flag_is_not_truthiness_parsed` | `0/false/no/true/yes` all die; only `"1"` opts in |
| `malformed_key_files_are_rejected` | world-readable, all-zero, short and non-hex files refused |
| `external_secret_changes_the_derived_identity_and_insecure_mode_warns` | **the fix is not a no-op**: secret-derived `pk_g` != publicly-derivable `pk_g`; two secrets => two identities; one secret => reproducible; banner printed in test mode and absent in production mode |

The last row is the load-bearing one. If `keys_for` still fell through to the constant, or if the
KDF ignored the file, those `assert_ne!`s would collide and the test would fail.

Structural invariants (checked by review, stated in the code):

- Every `MemberKeys::generate` in the binary is inside `keys_for` (two arms, one per provenance).
  A hit anywhere else is a second derivation and must be rejected in review.
- Provenance is memoised in a `OnceLock`, so two calls in one process cannot disagree.
- No test was deleted and no assertion weakened; the E2E harnesses opt in via the explicit flag.

### 7.1 UNVERIFIED

The three heavy on-chain CLI E2Es (`close_lifecycle_cli_e2e`, `two_token_cli_e2e`,
`itx_faucet_cli_e2e`) received the identical mechanical `.env(INSECURE_KEYS_ENV, "1")` edit in
their CLI spawn helpers and all compile, but **none was run to completion**. They hang — in this
environment, before this change, and unrelated to it — at
`forge script script/DeployCloseCli.s.sol --broadcast`:

- observed on two independent runs (ports 8554 and 8557), including one started before any edit
  in this change existed;
- the forge process sits in state `S` accumulating ~1 s of CPU over 20-50 minutes of wall time,
  with the local anvil still at **block 0** (nothing broadcast) and several open TCP fds — it
  looks blocked on a network call, plausibly sandbox-blocked;
- **no `channel_member` process ever spawns**, i.e. the hang is strictly upstream of the code this
  change touches.

What this leaves unproven: that a full on-chain close/withdraw lifecycle still completes under the
test flag. What *is* proven: the CLI binary itself runs correctly under both provenances
(`tests/inter_channel_cli.rs`, 13/13, which drives the real binary through init / send / cosign /
burn / join / inter-channel-transfer), and every provenance branch behaves as specified. Re-run one
heavy E2E on a host where `forge script --broadcast` works before relying on this.
