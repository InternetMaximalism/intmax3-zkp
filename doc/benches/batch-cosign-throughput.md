# Batched intra-channel co-sign — throughput study (2026-07-22 → 2026-07-24)

How many confidential transfers can one payment channel settle per second, and how does that
number scale with CPU cores? This note records the measurements, the code that produced them, the
bottlenecks found and removed, and the resulting scaling law.

**Headline:** on a single 96-vCPU arm64 box, one channel co-signs **≈ 1,310 batched transfers per
second** into a single state transition. Throughput is **per channel**; channels are independent
(separate lock, fold, N-of-N signing, and snapshot), so **N channels ≈ N × the per-channel rate**.

All figures are for the **INTMAX3 multi-party payment channel** intra-channel transfer path
(abstract2-1 §2.2b / §3.2b, detail2 §M). Each transfer carries a mandatory Regev channel-tx STARK
(E-1, `DualKeyTransferAir`) proving `plaintext(before) = plaintext(after) + amount` with
non-negativity, plus the sender's BabyBear hash-sig (A11). The relay verifies every proof and folds
K same-anchor transfers into **one** co-signed state transition (one N-of-N round for the whole
batch), exploiting the fact that a credit is a public homomorphic addition.

---

## 1. Method

- **Hardware:** AWS Graviton arm64. Scaling sweep on `c8g.4xlarge` (16 vCPU, Graviton4) and
  `c8g.48xlarge` (192 vCPU, Graviton4). Earlier baselines on `t4g.medium` (2 vCPU, Graviton2).
- **Workload:** a channel with 16 co-signers + 1,000 delegate members (1,016 active balance slots,
  the Option B maximum region in use). K = 1,000 distinct-sender transfers (R1: one debit per slot),
  all anchored at the same head, forming one batch.
- **What is measured:** wall-clock of the CLI `cosign-batch` command over the K-payload manifest —
  i.e. verify all K proofs (parallel) + canonical fold + N-of-N sign + republish snapshot (serial).
  This is the real per-batch cost a relay pays.
- **Isolating CPU scaling:** payloads and channel state were placed in a self-mounted `tmpfs`
  (`/mnt/ram`), not `/dev/shm`. (`systemd-logind` runs `RemoveIPC=yes` by default and wipes a user's
  `/dev/shm` files when their last SSH session closes — this silently deleted the payloads twice
  before we switched mounts. It also means the whole run must live in one SSH session.) With the
  1.4 GB of payloads served from RAM, the sweep measures CPU, not the gp3 EBS ceiling (~800 MB/s,
  which the 16-vCPU on-disk run was already hitting).
- **Parallelism control:** `RAYON_NUM_THREADS`. No code change between points — rayon's global pool
  auto-sizes to this value (default = `nproc`). The channel head is restored between runs so every
  run verifies the identical K payloads against the identical anchor.

---

## 2. Results

### 2.1 Thread scaling (c8g.48xlarge, 192 vCPU, RAM-backed, K = 1,000, 16 co-signers)

| threads | wall (1,000 tx) | tx/s | speed-up | efficiency |
|--------:|----------------:|-----:|---------:|-----------:|
| 1   | 22.14 s | 45.2   | 1.00× | 100 % |
| 2   | 11.47 s | 87.2   | 1.93× |  97 % |
| 4   |  5.84 s | 171.3  | 3.79× |  95 % |
| 8   |  3.16 s | 316.6  | 7.01× |  88 % |
| 16  |  1.83 s | 545.9  | 12.08× | 76 % |
| 24  |  1.37 s | 732.7  | 16.22× | 68 % |
| 32  |  1.15 s | 869.2  | 19.24× | 60 % |
| 48  |  0.92 s | 1089.4 | 24.11× | 50 % |
| 64  |  0.83 s | 1201.7 | 26.60× | 42 % |
| 96  |  0.76 s | **1310.4** | 29.01× | 30 % |
| 128 |  0.78 s | 1279.1 | 28.31× | 22 % |
| 192 |  1.15 s | 872.7  | 19.32× | 10 % |

**Shape:** near-linear to ~4 cores (95–98 % efficiency), useful gains to ~64–96 cores, **peak
≈ 1,310 tx/s at ~96 cores**, then flat (128) and a **regression at 192** (873 tx/s — slower than
48 cores). Past ~96 threads, with only ~5 tx per thread, rayon/OS/NUMA overhead plus the fixed
serial tail dominate; over-subscription is counter-productive. **Sweet spot: 48–96 cores.**

The 16-core point here (545.9 tx/s) matches an independent `c8g.4xlarge` run (561 tx/s) — the curve
is reproducible.

### 2.2 The ceiling is the serial tail, not the crypto

The verification phase (E-1 STARK + A11 per tx) parallelised cleanly all the way to 96 cores. The
wall-time **floor of ≈ 0.76 s for K = 1,000** is a per-batch **serial tail ≈ 0.55–0.6 s**, dominated
by:

1. the **N-of-N signing** — here 16 `SingleSigCircuit` proofs produced **sequentially**, and
2. the **~10 MB JSON snapshot** re-serialised and written once per batch.

Neither is fundamental. Levers to raise the single-channel ceiling:

- **Parallelise the N-of-N signing** (16 proofs → concurrent).
- **Bigger batches** amortise the fixed tail — K = 5,000 pushes the peak well past 1,310 tx/s.
- **Fewer co-signers** — the live default is 3, not 16; a 3-sig tail is ~⅕ the signing cost.
- **Binary snapshot** (bincode) instead of the 10 MB JSON write.

### 2.3 The per-tx verification cost itself (microbench)

`tests/slim_verify_bench.rs` (Production params, padded 1,024-slot state, single core):

| stage | before perf pass | after perf pass |
|---|---:|---:|
| `verify_slim_send_tx` (A11 + E-1 STARK + bindings) | 23.5 ms | **11.4 ms** |
| slim payload JSON | 4.5 MB (pretty) | **1.40 MB** (compact) |

The perf pass (commit `f85b263`) stopped routing each tx through the solo-state witness machinery
(which re-derived and re-hashed a full 1,024-slot next state per tx — O(K·MAX) hashing across a
batch, checking nothing the single folded state doesn't already guarantee; Lean
`batch_preserves_validity`). `verify_slim_send_tx` now performs only the abstract2-1 §3.2b.3 per-tx
checks directly, `regev_pks` is built once per batch, and `cosign-batch` is a flat rayon `par_iter`
(no chunk barriers). CLI `write_json` was switched from pretty to compact.

### 2.4 End-to-end progression on the 2-vCPU stress clone (t4g.medium)

| date | change | 1,000-tx result |
|---|---|---:|
| 2026-07-18 | first batch co-sign (fat 16.8 MB payloads) | K ≤ 30 (V8 512 MB stringify cap); relay core-dump at K = 1,000 |
| 2026-07-23 | slim wire (detail2 §M): 4.5 MB payloads, spool-to-disk ingest, manifest handoff | 1,000/1,000 in ONE transition, 236.5 s e2e (6.8 tx/s CLI) |
| 2026-07-23 | perf pass (`f85b263`): direct verify, compact JSON, barrier-free | 56.2 s e2e, **48 tx/s CLI** (7×) |

---

## 3. Scaling law and the path to high aggregate TPS

**Per channel, single box:** peaks at **≈ 1,310 tx/s (~96 cores, K = 1,000, 16 co-signers)**. Raising
K, cutting co-signers, parallel signing, and a binary snapshot each lift this ceiling.

**Aggregate:** channels are fully independent — separate on-disk state, per-channel lock, own fold /
N-of-N / snapshot. Nothing is shared across channels, so **aggregate TPS = per-channel TPS × number
of channels**, and channels can be sharded across boxes with no coordination. Reaching, e.g.,
10,000 TPS is ~8 channels at the measured per-channel rate, or fewer once the serial-tail levers
(§2.2) raise the per-channel ceiling.

---

## 4. Reproducing it

### Microbench (any machine, in-repo)

```bash
cargo test --release --test slim_verify_bench -- --nocapture
```

Prints the per-tx `verify_slim_send_tx` breakdown at Production params.

### Thread-scaling sweep (multi-core box)

The batch path is exercised by `cosign-batch <manifest.json> <out>` where the manifest lists K slim
`SendPayload` files. To build a realistic batch:

> **CHANGED by A-1 (2026-08-08) — read before reusing this recipe.** A delegate no longer opens with
> an operator-chosen balance. `create_channel` and `join_delegate` both install the CANONICAL ZERO
> ciphertext at the new slot, because a self-declared, Regev-encrypted opening balance is unbacked
> value that no cosigner can inspect (see `doc/tasks/b2-implementation-notes.md` §7). Consequences
> for this sweep: `<bal>` must be `0` in both steps below, and a storm of nonzero *sends* now needs
> the delegates to be FUNDED first, through one of the two real lanes — `cosign-l1-deposit-import`
> (reads amount/depositor/token from the chain, moves `channel_fund` and the slot leaf together) or
> an in-channel transfer from an already-funded slot. Once a delegate is funded, its ciphertext is no
> longer reproducible from `(bal, seed)` and `gen-send` **cannot build for it at all** — it fail-
> closes rather than guessing. So the throughput harness must either (a) keep every simulated send at
> amount 0 (fine for measuring cosign/verify throughput, which is what this document measures — the
> per-tx cost does not depend on the plaintext), or (b) grow its own witness-carrying payload builder.
> Option (a) is the intended path; the numbers in §2/§3 are unaffected because they time
> `verify_slim_send_tx` and the batch cosign, neither of which is amount-dependent.

1. `channel_member gen-contribution 0 <seed> <out>` for each simulated delegate, then
   `POST /api/init` to join them (or drive the CLI `init` directly). The `<bal>` argument is retained
   for wire shape only — `init` ignores the emitted `genesisCt` (A-1).
2. `channel_member gen-send 0 <seed> <to_slot> <amount> <snapshot> <out>` per delegate — a
   **stateless** slim `SendPayload` builder. It fail-closes unless it can OPEN the delegate's current
   slot ciphertext: either the canonical zero opening (balance must be `0`, opened by the public
   all-zero witness) or, for legacy seeded snapshots, the deterministic `(bal, seed)` ciphertext.
3. Build a manifest `{"files":[...]}` and run, sweeping the pool size:
   ```bash
   for T in 1 2 4 8 16 32 48 64 96; do
     RAYON_NUM_THREADS=$T channel_member cosign-batch manifest.json /tmp/out.json
   done
   ```
   Serve the payloads from `tmpfs` to isolate CPU from disk. Restore the channel head between runs
   (the command advances it).

`INTMAX_CLI_COSIGNERS` (default 3, ≤ 16) sets how many co-signers the CLI drives, so the same harness
measures a 3-co-signer live channel or a 16-co-signer stress channel.

---

## 5. Code and deployment provenance

**In-repo (committed to `main`):**

| commit | date (JST) | what |
|---|---|---|
| `4463193` | 2026-07-22 19:10 | env-configurable CLI co-signer count, stateless `gen-send`, multi-channel relay knobs (`CHANNELS`, `FORCE_CHANNEL_ID`) |
| `ca8a72b` | 2026-07-23 11:35 | design: slim wire format + streaming verification (detail2 §M) |
| `4d0a926` | 2026-07-23 11:52 | impl: `SlimSendPayload`, `verify_slim_send_tx`, manifest `cosign-batch`, `/api/cosign2` spool ingest |
| `7fbbd23` | 2026-07-23 12:15 | browser sends over the slim wire (client-side projection, fat fallback) |
| `0b057ce` | 2026-07-23 12:19 | abstract2-1 §5 doc row |
| `3bee3c3` | 2026-07-23 12:26 | `tests/slim_verify_bench.rs` — per-tx timing breakdown |
| `f85b263` | 2026-07-23 14:00 | perf pass: direct slim verify, compact JSON, barrier-free pipeline |

**Test / bench code:** `tests/slim_verify_bench.rs` (in-repo, §2.3), `tests/batch_cosign_e2e.rs`
(fat/slim equivalence, R1 rejection, K = 1 digest identity, stale-anchor). The throughput-sweep
harness (`pregen_sends.py`, `sweep192.sh`, `sendstorm.js`) is operational scaffolding run on the
throwaway stress boxes, not committed.

**Live deployment:** v3testnet (`v3testnet.intmax.io`).

- 2026-07-23 — Option B (1024-slot / u16 ABI) + slim batch co-sign deployed (state reset, deposit
  backing kept; testers re-join). Verified: genesis on both channels, slim send E2E 0.77 s, browser
  wasm 2-thread init on the real origin.
- 2026-07-23 (later) — perf-pass binary shipped (restart only, wire-compatible).

**Formal model:** the batch transition is machine-checked in `ChannelSafety21.lean` §8
(`batch_preserves_validity`, `batch_step_eq_seq`). The slim wire changed nothing at the spec level
— it drops only data the co-signers re-derive — so no proof update was needed.

_Infrastructure note: all throughput runs were on isolated, disposable stress/bench instances,
stopped or terminated after each run; the production testnet was untouched except for the two
deployments above._
