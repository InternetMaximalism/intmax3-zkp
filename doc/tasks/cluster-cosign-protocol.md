# Cluster co-signing protocol (sig-cluster, N ≤ 8 hosts)

Status: implemented 2026-09-21 — `api/lib/cluster.js` (protocol), `hosting/wallet/wallet-relay.js`
(HTTP wiring), `channel_member cosign-partial` / `cosign-merge` (signing and assembly).
Tests: `node/test/cluster-cosign.test.js` (N in-process hosts, manual clock).

## Before

One host held every cosigner key of the sig-cluster: `channel_member cosign` signed all
`controlled` slots in a `for` loop (`ledger_sign_all_controlled`) and there was no inter-host
communication at all. A co-signer could neither verify independently nor withhold a signature.

## Protocol

Each host holds its own slot key(s) (`INTMAX_CLUSTER_SIGN_SLOTS`) and runs the wallet relay with
`INTMAX_CLUSTER_SELF_URL` + `INTMAX_CLUSTER_PEERS` (JSON `[{"url","slots"}]`, at most 8 hosts,
each slot on exactly one host).

1. **Propose.** The relay that receives a wallet's `SendPayload` (`POST /api/cosign`) runs
   `cosign-partial`: the full co-sign gate (`verify_send_transition` — E-1 or its decrypted twin,
   A11 sender signature, structural fold, recipient decryption) and its own slot signatures over
   the successor digest, recorded in the anti-equivocation ledger, **head not advanced**. It
   broadcasts the payload to every peer (`POST /api/cluster/propose`).
2. **Sign and fan out (N-to-N).** Every peer acknowledges at once, runs the same gate and
   `cosign-partial` with its own slots, and sends its signatures to **every** host
   (`POST /api/cluster/signature`). Signatures may arrive before the proposal; they are pooled by
   `nextDigest` and merged once the payload is known.
3. **Assemble.** Any host holding all `memberCount` slots runs `cosign-merge`, which re-runs the
   gate, verifies **each** pooled signature individually (`wallet_core::verify_member_signature`:
   cosigner slot, registered `pk_g` at that slot, Falcon over the recomputed IMCH digest) and adopts
   the N-of-N head (`channel_snapshot.json`, `cli_state.json`). The coordinator answers the wallet
   with that head. Every host adopts independently.
4. **Close warning (1 min, repeating every minute).** A host whose round is incomplete broadcasts
   `POST /api/cluster/missing {nextDigest, missing:[slots], from}`. Every host that holds any of
   those signatures — its own **or one received from a third host** — sends them to the warner.
5. **Halt (5 min).** Still incomplete: the channel is **HALTED** (`cluster_halt.json`
   `{nextDigest, since, missing}`, broadcast as `POST /api/cluster/halt`). Every mutating relay
   route answers `503 channel … is HALTED` except the close/settle/withdraw family. A complete set
   that arrives later still finishes the round and lifts the halt.
6. **Auto-close (24 h) — node-program rule.** A watchdog (every minute) closes a channel that has
   been halted for 24 h at its **last fully signed state** (the adopted head, never the stalled
   proposal): `channel_member close <manager> <rpc>` with the ACTIVE settlement binding
   (`cli_state.settlement_binding.manager`, or `INTMAX_CLUSTER_CLOSE_MANAGER`). A failed close is
   retried on every tick; a lifted halt is never closed.

Timings are `INTMAX_CLUSTER_WARN_MS` / `INTMAX_CLUSTER_HALT_MS` / `INTMAX_CLUSTER_CLOSE_MS` /
`INTMAX_CLUSTER_WATCHDOG_MS` (defaults 60 s / 5 min / 24 h / 60 s). `GET /api/cluster/status`
shows the pool, missing slots, warnings and halt per channel.

## Security notes

- Pooling never trusts a signature: `cosign-merge` verifies each one against the registered
  member set before the N-of-N is adopted; `cosign-partial` re-runs the transition gate before
  this host signs anything. A forged or mis-slotted signature is rejected at merge.
- `cosign-partial` writes the signing ledger like `cosign`, so a host that signed successor X at
  head P can never sign a sibling successor at P even if the round stalls (the halt/close path is
  the only way forward).
- Cluster mode forces a batch window of 1 (`cosign-batch` has no partial/merge form yet).
- Other single-host co-sign purposes (refresh, inter-channel debit/credit, deposit import, token
  registration, member-set update) still sign every slot on the receiving host; extending them is
  the same split (gate → partial → merge) and is not done here.
