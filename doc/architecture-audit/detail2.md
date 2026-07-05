# detail2 — Detailed implementation spec for abstract2.md (data structures / file layout / numerics)

This document treats [abstract2.md](./abstract2.md) (v2 = the minimal spec of the Lattice/Regev confidential version) as a **necessary condition**, and
describes the **updated spec** of the current implementation (the enshrined-paymentchannel branch) at the level of data structures, file
layout, and numeric constants. abstract2.md defines "what must be satisfied," and this document defines "how the current
implementation's types and files satisfy it."

**Normativity**: When abstract2.md and this document conflict, abstract2.md takes precedence except for the items enumerated in §A (intentional differences).

## A. Intentional differences from abstract2.md (2 points)

### A-1. SIS commitment → Regev encryption (form change)

The current implementation's lattice layer (`src/lattice/proof_adapter.rs`) is a **SIS commitment**
(Q = 8,380,417, M = 128, N = 256, `LatticeCommitment` + `LatticeOpening`).
This spec replaces it with **Regev (Ring-LWE) encryption**.

- Source of port: `/Users/plasma/repos/SIS-lattice-paymentchannel` (despite the repository name,
  the contents are a Regev/Ring-LWE implementation. `crates/regev-adapter`, `crates/channel-types`,
  `crates/channel-state`, `regev_plonky3`).
- **The biggest formal change**: With SIS, the recipient cannot verify the amount unless they receive the opening (amount + randomness),
  and the source implementation also sent `ReceiverWitnessShare` (the full share of the encryption randomness `r`, `e1u/e1v/e2u/e2v`).
  By **encrypting to the recipient's `RegevPk`** with Regev, the recipient
  can verify the amount **simply by decrypting with their own secret key**. The **randomness share structure is abolished**
  (no type equivalent to `ReceiverWitnessShare` is carried over). The encryption randomness becomes a
  **STARK private witness** held only by the sender.
- Since a third party (a co-member who is neither the recipient nor the sender) cannot decrypt, verification
  relies on `channelTxZKP` / `channelUpdateZKP` (§E) — this is exactly as designed in abstract2.md §3.1.

### A-2. Small-block model: 1 channel = 1 small block = 1 tx

abstract2.md §2.3 is a model where "the BP **collects txs from multiple senders (channels)** to build a `TxV2Tree`, and binds to its
root (`tx_tree_root`)." The current implementation differs, and **this spec does not match abstract2.md on this point**
(user decision):

- **One small block is owned exclusively by one channel and effectively carries 1 tx** (1 block = 1 user / 1 tx).
- The BP concatenates a **sequence** of per-channel `SubBlock`s for each posting round and posts it to L1
  (`IntmaxRollup.postBlockAndSubmit`, `SubBlock[]`). Rather than "collecting multiple channels' txs into a single tree,"
  it "chains per-channel small blocks with a hash chain."
- Consequence 1: abstract2's `tx_tree_root` corresponds in this spec to **the `tx_tree_root` of
  one's own channel's small block** (`SmallBlockRootMessage.tx_tree_root`). The contents are effectively 1 leaf, and
  `TxV2MerkleProof` (inclusion proof) is a **trivial proof against a 1-leaf tree** (`MerkleInclusionProof` is
  formally retained).
- Consequence 2: `H2` (the transfer-type tag) holds **the `tx_tree_root` of one's own channel's small block** rather than
  abstract2's "the tx_tree_root of the entire block." The argument for atomicity (a single signature over authorization and subtraction)
  is unchanged (§D-3).
- Consequence 3: The ITS (intmax-tx-sender) role is, in the current implementation, served by **the member designated by `bp_member_slot`**
  (`ChannelRecord.bp_member_slot ∈ {0,1,2}`, whose slot's `member_sphincs_pubkey_hashes[bp_member_slot]`
  is the BP-duty key). Identification of the role is done by **member slot**, not by key hash (array index).

This difference does not weaken the safety properties (the 5 properties of abstract2.md §4): the inclusion proof degenerates because there is no aggregation tree, but
the structure of the signing target `hash(H1, H2)`, the chain binding, and the cap enforcement are all preserved.

### A-3. Signatures: SPHINCS+ → Poseidon-preimage ZK signature (two-key)

The member signatures this spec describes as SPHINCS+ (§B-4, §C, §D, §F) were **replaced by a
Poseidon-preimage ZK signature** (a ZK proof of knowledge of `sk` with `pk = Poseidon(sk)`, message
bound as a public input), and SPHINCS+ was removed entirely. Two keys per member, each native to its
proof system: a **Goldilocks** key `pk_g` (Plonky2 — channel-state agreement / close / small-block,
via `SingleSigCircuit`) and a **BabyBear** key `pk_b` (Plonky3 — the in-channel channel-tx sender
authorization, via `Poseidon2HashSigAir`). The member identity `pk_g` occupies the same `Bytes32`
slot the SPHINCS+ pubkey hash did; `pk_b` is added to `MemberLeaf`. The full delta (validity
`bp_sig_chain` accumulator, close list-proof consumer, two-key A11 binding, wallet Goldilocks
co-signing, SPHINCS+ removal) is **D8 in detail2-implementation-notes.md**; threat model in
`doc/tasks/poseidon-signature-threat-model.md`.

**Aggregation shape (updated by D13):** the `SingleSigCircuit` proofs feed two aggregators, one per
consumer path. The **validity** `bp_sig_chain` path keeps the linear recursive hash-chain
**`ListCircuit`** (`src/poseidon_sig/list.rs`, D8). The **close / cancel-close** path no longer
consumes the `ListCircuit`: cosigner single-sig proofs are aggregated PAIRWISE per level by the
**binary-tree aggregated sign-zkp** (`src/poseidon_sig/aggregate.rs`, `AggLevelCircuit` ×
`AGG_LEVELS = 4`, pk-slot widths 2 → 4 → 8 → 16) whose public inputs expose
`[message(8), signer_count(1), pk list (2^k × 8)]`; the close/cancel circuits recursively verify ONE
level-4 proof and wire the cosigner key vector directly from its PI signer list (§F-3, D13 in
detail2-implementation-notes.md).

---

## B. Cryptographic primitives and parameters

### B-1. Regev (Ring-LWE) parameters

Follows the `channel_params` of the port source `SIS-lattice-paymentchannel/crates/regev-adapter`:

| Parameter | Value | Description |
|---|---|---|
| `q` (residue field) | BabyBear `2^31 − 2^27 + 1 = 2,013,265,921` | Matches the native field of the Plonky3 STARK |
| `n` (ring degree) | **128** (power of 2, requires ≥ 64) | Number of coefficients of one polynomial |
| `eta` (noise) | 2 | CBD (centered binomial) parameter |
| `plain_bits` | 8 | Plaintext bits per coefficient |
| Amount type | `u64` | Encoded into 8 bits × 8 coefficients (remaining coefficients are 0) *(superseded by D1: 1 bit/coefficient × 64 coefficients, t=256)* |

### B-2. Types and sizes

```rust
/// Each member's Regev public key (public within the channel, fixed at channel creation)
pub struct RegevPk {
    pub a: Vec<u32>,   // n coefficients (mod q)
    pub b: Vec<u32>,   // n coefficients; b = a·s + e
}
/// Regev ciphertext (abstract2.md's `LatticeCt`)
pub struct RegevCiphertext {
    pub c1: Vec<u32>,  // n coefficients (mod q)
    pub c2: Vec<u32>,  // n coefficients (mod q)
}
```

| Item | Size (n = 128) |
|---|---|
| `RegevPk` | 2 × 128 × 4 = **1,024 bytes** |
| `RegevCiphertext` | 2 × 128 × 4 = **1,024 bytes** |
| `encBalances` (per slot) | **1,024 bytes** (one per balance slot; slot capacity `MAX_CHANNEL_MEMBERS` = 1024, D6 → D12 — cosigners ≤ 16, the rest delegates + padding) |
| Decryption key `RegevSk { s: Vec<i8> }` | 128 bytes (held only by the owner. Does not appear in any struct) |

`RegevCiphertext::digest() = hash_words([REGEV_CT_DOMAIN, c1.len() as u32, c1…, c2…]) → Bytes32`
(keccak256. What enters state or the PI is always this digest).

### B-3. Homomorphic addition and noise budget (A5)

- `ct_a + ct_b` (component-wise mod q addition) corresponds to plaintext addition. Applying a delta to the recipient-side balance
  (abstract2.md §3.2 step 3 "add `encAmount` to the recipient's ct") uses this.
- **The sender's own balance update is fresh re-encryption, not homomorphic**: the sender **re-encrypts** the updated balance
  **anew**, and `channelTxZKP` / `channelUpdateZKP`
  proves "the plaintext of the old ct = the plaintext of the new ct + the delta plaintext" (isomorphic to the source transfer STARK).
  This way, the sender-side ct's noise does not accumulate.
- The recipient-side ct accumulates noise via homomorphic addition. It is mandatory that **for every `MAX_HOMO_ADDS_BEFORE_REFRESH` additions,
  the recipient themselves performs a fresh re-encryption (refresh) in the version where they next author state**.
  The validity of refresh is proved by a separate `RefreshAir` (a combined Decrypt+Encrypt AIR proving plaintext
  equality in-circuit), **not** by `channelTxZKP` with delta = 0 (see D2, `src/regev/transfer_stark.rs`).
- Noise condition (decryption correctness): the ∞-norm of the accumulated noise must be less than `q / 2^(plain_bits+1)`.
  `MAX_HOMO_ADDS_BEFORE_REFRESH` is derived from the per-ct noise upper bound of CBD (eta=2).
  > **SECURITY (approved)**: `MAX_HOMO_ADDS_BEFORE_REFRESH = 64` is an **approved** security parameter
  > (see D1 in detail2-implementation-notes.md and `doc/docs/regev-noise-analysis.md`: worst-case digit headroom ≈ 4×,
  > noise headroom ≈ 120×, zero decryption-failure within the budget for eta=2 / n=128 / q=BabyBear).
  > Do not change it silently (CLAUDE.md general rule).

### B-4. ZK proof systems

| Proof | Backend | Port source / existing |
|---|---|---|
| `channelTxZKP` / `channelUpdateZKP` / refresh proof | **Plonky3 STARK** (BabyBear) | The transfer STARK of `SIS-lattice-paymentchannel` (proves `before = after + delta` as an n-bit integer + well-formedness of 3 cts). **A range proof is built in via the ripple-carry constraint where no digit borrow occurs**, making underflow (negative balance) constructively impossible |
| `withdrawClaimZKP` | Plonky3 STARK | A degenerate form of the above ("the plaintext of my own ct = the public withdrawal amount") |
| `balanceProof` / `validityProof` | Plonky2 (existing) | `src/circuits/balance/`, `src/circuits/validity/` (changes are in §F) |
| close / claim PI binding | Plonky2 (existing) | `src/circuits/channel/close_circuit.rs` and others |
| Signature | ~~SPHINCS+ (Poseidon)~~ → **Poseidon-preimage ZK sig (two-key)** | **SUPERSEDED — see D8 (+ D13)** in detail2-implementation-notes.md. Goldilocks `pk_g` (Plonky2 `SingleSigCircuit`; validity path aggregated by the recursive `ListCircuit`, close/cancel path by the binary-tree `AggLevelCircuit` sign-zkp, D13) for state/close/IMSB; BabyBear `pk_b` (Plonky3 `Poseidon2HashSigAir`) for the channel-tx sender. SPHINCS+ fully removed. |

`ChannelProofEnvelope { role, backend, proof }` (`state_update_verifier.rs:20-24`) is retained, and
`ProofBackend::Plonky3` is used to carry the lattice STARKs (as in the existing design).

---

## C. Data structures (updated version)

Legend: **[New]** = new type / **[Chg]** = change to existing type / **[Keep]** = unchanged / **[Del]** = abolished.

### C-1. [Del] SIS-related

- `LatticeCommitment` (`src/common/channel.rs:293-305`) → replaced by `RegevCiphertext`.
- `LatticeOpening` (`channel.rs:309-313`) → **abolished**. A structure passing amount/randomness to the counterparty is
  unnecessary with Regev (§A-1). Verification has only 2 paths: (a) the recipient's decryption, (b) STARK proof.
- `LatticeBindingVerifier` trait / `LatticeProofPurpose` (`state_update_verifier.rs:88-102`) →
  renamed and retyped to the `RegevProofVerifier` trait (§E-4).

### C-2. [New] BalanceState (the core of abstract2.md §2.1)

```rust
/// abstract2.md: BalanceState { encBalances, settledTxChain, stateVersion }
pub struct BalanceState {
    pub channel_id: ChannelId,
    pub member_count: u8,                                  // co-signing COSIGNERS = slot 0..member_count (2..=MAX_COSIGNERS = 16, D6/D12)
    pub delegate_count: u8,                                // DELEGATES = slot member_count..member_count+delegate_count (§L, D9)
    pub enc_balances: [RegevCiphertext; MAX_CHANNEL_MEMBERS],   // 1024 balance slots; active = cosigners+delegates, padding default/zero
    pub regev_pk_digests: [Bytes32; MAX_CHANNEL_MEMBERS],  // per-slot Regev pk Poseidon digests (decryption Stage 1); padding = default
    pub settled_tx_chain: Bytes32,                          // genesis = 0x00…00
    pub settled_tx_accumulator_root: Bytes32,               // Stage 3: settled-tx Merkle accumulator root (post-close source-tx anchoring)
    pub state_version: u64,                                 // +1 on both intra- and inter-channel updates
    pub pending_adds: [u32; MAX_CHANNEL_MEMBERS],           // per-slot homomorphic-add counters (D3); padding = 0
}
impl BalanceState {
    /// H1 = hash(BalanceState). Does not include the proof object (all components known at signing time).
    /// D14 ("tree in storage, root in state"): H1 is a FIXED-width 26-element Poseidon header over the
    /// ROOT of the balance-slot Poseidon Merkle tree — the flat keccak over all slots is retired:
    ///
    ///   leaf_i = Poseidon([BALANCE_SLOT_LEAF_DOMAIN "IMSL", regev_pk_digests[i] (8 u32 limbs),
    ///                      enc_balances[i].digest() (8 u32 limbs), pending_adds[i] (1 u32 limb)])
    ///            // 18 elements, fixed width; leaf INDEX i = Merkle position (slot order bound structurally)
    ///   slot_tree_root = height-BALANCE_SLOT_TREE_HEIGHT (= 10 = log2(1024), const-asserted)
    ///                    IncrementalMerkleTree<PoseidonHashOut> root over ALL 1024 leaves
    ///   H1 = Bytes32::from(Poseidon([BALANCE_STATE_DOMAIN "IMBS", channel_id, member_count, delegate_count,
    ///                                slot_tree_root (4 Goldilocks elements), settled_tx_chain (8),
    ///                                settled_tx_accumulator_root (8), split_u64(state_version) (hi, lo)]))
    ///
    /// delegate_count sits IMMEDIATELY AFTER member_count (§L, D9). Semantics unchanged — the same
    /// values are bound and H1 keeps the same signing role; only the commitment STRUCTURE became a
    /// tree root, O(1) in-circuit regardless of slot capacity (src/common/balance_state.rs;
    /// threat model tasks/h1-poseidon-root-threat-model.md; D14).
    pub fn h1(&self) -> Bytes32 { … }
}
/// Agreement / signing target (abstract2.md: balanceStateHash = hash(H1, H2))
pub fn balance_state_hash(h1: Bytes32, h2: Bytes32) -> Bytes32 {
    // [BALANCE_STATE_HASH_DOMAIN, h1, h2] → keccak256
}
```

- **Balance-slot capacity vs cosigners (`MAX_CHANNEL_MEMBERS = 1024`, `MAX_COSIGNERS = 16`; pad-to-MAX,
  §G, D6 → D12).** The two roles D6's single `MAX_CHANNEL_MEMBERS = 16` conflated are now separate
  constants: `MAX_CHANNEL_MEMBERS = 1024` is the BALANCE-SLOT capacity (cosigners + delegates +
  padding) sizing `enc_balances` / `regev_pk_digests` / `pending_adds` / `ChannelRecord.member_pk_gs`
  (`[_; 1024]`, serde-big-array), while `MAX_COSIGNERS = 16` caps the N-of-N close SIGNERS:
  `member_count: u8` (`2 <= member_count <= MAX_COSIGNERS`) counts cosigners only, and
  `member_count + delegate_count <= MAX_CHANNEL_MEMBERS`. The circuit does not branch — balance/H1
  work covers all 1024 slots (via the D14 slot-tree root), and all close/cancel SIGNATURE work
  (member_set_commitment, aggregated sign-zkp pk slots, A5 distinctness, active-bits gating) is sized
  `MAX_COSIGNERS`. A participant is referenced by **slot** as the array index into `enc_balances` /
  `pending_adds` (D3). **A member's identity is the `pk_g` pubkey (`Bytes32`)** (DA → D8), and the
  slot is merely an array position. `ChannelRecord::validate()` requires that active slots be
  **distinct non-zero hashes**, that padding slots be default, and that
  `bp_member_slot < member_count`. The channel→member binding tree is the `MemberTree`
  (`src/common/trees/key_tree.rs`, height `MEMBER_TREE_HEIGHT = 10` = 1024 leaves =
  `MAX_CHANNEL_MEMBERS`), whose root is `ChannelLeaf.member_pubkeys_root` (§G, DB).
  *(abstract2.md §2.1's `[(Address,RegevPk);3]` is fixed at 3 people, so N members is a spec deviation.
  The authoritative deltas are D6 and D12 in detail2-implementation-notes.md.)*
- Range of `H2`: `0x00…00` (intra-channel) / one's own small block's `tx_tree_root` (inter-channel, §A-2).
  **Reservation of `H2 = 0`**: on the inter-channel path, `tx_tree_root == 0` is rejected at verification (guaranteeing that the
  empty-tree root does not become 0 via the keccak-based tree. The implementation answer to v2 audit finding 4).

### C-3. [Chg] ChannelState

Change `ChannelState` of `src/common/channel.rs:431-470` as follows:

| Field | Treatment |
|---|---|
| `channel_id, epoch, small_block_number, close_freeze_nonce` | [Keep] |
| `channel_fund: ChannelFund` | [Keep] (the source of `withdrawCap`) |
| `channel_balance_root: Bytes32` | [Chg] **replaced by `balance_state: BalanceState`** (holds the body rather than the root. Uses `h1()` at L1 submission) |
| `shared_native_nullifier_root, unallocated_confirmed_incoming, prev_digest, digest` | [Keep] |
| `member_signatures: Vec<MemberSignature>` | [Chg] the signing target changes (below) + `MemberSignature` retyped: `{ member_slot: u8, sphincs_pubkey_hash: Bytes32, signature }` (old `key_id`/`user_id`/`key_condition_proof` abolished, DA/DC). N-of-N (3/3): `signatures[i].member_slot == i` and `signatures[i].sphincs_pubkey_hash == record.member_sphincs_pubkey_hashes[i]` |
| **(new) `h2_tag: Bytes32`** | The tag used to finalize this version. Intra-channel update = 0 |

Change the preimage of `ChannelState::signing_digest()` (domain `0x494d4348` "IMCH"):
put **`balance_state.h1()`** in the position of `channel_balance_root`, and append **`h2_tag`** and
**`split_u64(balance_state.state_version)`** at the end. Thereby
**`signing_digest()` itself embeds `hash(H1, H2)`**, and `member_signatures`
realizes abstract2.md §3.1's "all-3 signatures over `hash(H1, H2)`."

- `state_version` is a **monotonic counter independent of epoch and small_block_number** (since intra-channel transfers
  do not create small blocks, versions cannot be counted by `small_block_number`).
- Invariant: `state_version` strictly increases, 1 version 1 state (challenge order is §H-4).

### C-4. [Chg] ChannelBalance

```rust
pub struct ChannelBalance {
    pub channel_id: ChannelId,
    pub sphincs_pubkey_hash: Bytes32,          // old: user_id: UserId (DA: member identification = public-key hash)
    pub balance_ciphertext: RegevCiphertext,   // old: balance_commitment: LatticeCommitment
}
```

### C-5. [Chg] Pay → ChannelTx (intra-channel transfer, abstract2.md §2.2)

Retype existing `Pay` (`channel.rs:501-529`):

```rust
pub struct ChannelTx {
    pub recipient_sphincs_pubkey_hash: Bytes32,  // old: recipient_user_id: UserId (DA)
    pub enc_amount: RegevCiphertext,        // encrypted with the recipient's RegevPk (the sent amount)
    pub nonce: Bytes32,                     // one-time random value
    pub channel_tx_zkp: ChannelProofEnvelope,  // mandatory (co-sign rejected if absent)
    pub sender_sphincs_pubkey_hash: Bytes32,     // old: sender_user_id: UserId (DA)
    pub sender_signature: SignatureBytes,
}
```

- `signing_digest` (domain `PAY_DOMAIN = 0x494d5041` retained): change the preimage to
  `[domain, channel_id, prev_state_digest, enc_amount.digest(), nonce, sender_sphincs_pubkey_hash(8), recipient_sphincs_pubkey_hash(8)]`
  (the member portion is 2→8 limbs each).
- Old `Pay.amount: LatticeCommitment` (which assumed an attached plaintext opening) is abolished. Only the recipient learns the amount by decryption.

### C-6. [Chg] InterChannelTx (inter-channel transfer, corresponds to abstract2.md §2.3 `TxAux`)

Retype existing `InterChannelTx` (`channel.rs:541-597`). Map abstract2's `TxAux` /
`TxLeafHash` / `channelUpdateZKP` to the current implementation's fields:

| abstract2.md | This spec's field | Treatment |
|---|---|---|
| `senderAddr / recipientAddr` | `source_sphincs_pubkey_hash: Bytes32` / `receiver_deltas[i].receiver_sphincs_pubkey_hash: Bytes32` | [Chg] (old `UserId` → public-key hash, DA) |
| `senderChannelId / recipientChannelId` | `source_channel_id / destination_channel_id` | [Keep] |
| `senderDelta : LatticeCt` | **(new) `sender_delta_ct: RegevCiphertext`** (addressed to the sender's `RegevPk`, negative-value plaintext) | replaces old `sender_amount: LatticeCommitment` |
| `recipientDelta : LatticeCt` | retype the `amount` of `receiver_deltas: Vec<ReceiverBalanceDelta>` to `RegevCiphertext` (addressed to the recipient's `RegevPk`, positive-value plaintext) | [Chg] |
| `channelUpdateZKP` | **(new) `channel_update_zkp: ChannelProofEnvelope`** (consolidates old `sender_balance_update_proof` / `receiver_update_proof`) | [Chg] |
| `TxV2MerkleProof` | `tx_inclusion_proof: MerkleInclusionProof` (1-leaf tree, §A-2) | [Keep] |
| (binding to tx_tree_root) | `signed_small_block: SignedSmallBlock` | [Keep] |
| `tx_hash` etc. | `seal, tx_hash, intmax_transfer_commitment, recipient_memo, transport_proof` | [Keep] |

> **`transport_proof` is DEPRECATED (no separate verifier).** Per the abstract2.md §3.4 design note,
> the inter-channel transfer carries no bundled transport proof: the receiving channel verifies
> settlement DIRECTLY against L1 (`flowReceive3` step 1 — `TxV2MerkleProof` inclusion of the
> `tx_tree_root` in a validity-proven block + the sender's `balanceProof`), and the small-block
> `channelStateSig` (`hash(H1', tx_tree_root)`) is verified by the REAL validity proof
> (`update_channel_tree` / `bp_sig_chain`, §F-2). The `transport_proof` field is retained only as a
> vestigial carrier and is NOT verified by a dedicated `ChannelProofVerifier` (verified end-to-end in
> `tests/small_block_sig_validity.rs`).
>
> Inclusion liveness is handled by member incentive, NOT a proof. Because a channel's members only
> sign `hash(H1', tx_tree_root)` when they intend the small block to be included on L1:
> 1. **a member does not sign the next intmax-native tx until the current one is included** (one state
>    per version — never advance on an unconfirmed state); and
> 2. **if no one (the BP) includes the small block, a member includes it themselves** (force-include /
>    self-post the small block to L1).
>
> This is the standard rollup force-inclusion argument; it costs only liveness (eventual inclusion),
> never safety — the receiver only ever applies a *confirmed* incoming (verified on L1; absent ⇒ the
> sender is ignored), so delay/censorship reflects no incorrect balance.

**[New] TxLeafHash** (abstract2.md §2.3. The update unit of `settledTxChain`):

```rust
pub fn tx_leaf_hash(tx: &InterChannelTx) -> Bytes32 {
    // hash( hash(TX_LEAF_DOMAIN, source_sphincs_pubkey_hash(8), sender_delta_ct.digest()),
    //       hash(TX_LEAF_DOMAIN, receiver_sphincs_pubkey_hash(8), receiver_delta_ct.digest()) )
    // → binds the sender-side and receiver-side public-key hashes (DA) and the lattice balance changes on both wings (member portion 2→8 limbs)
}
```

`settledTxChain` update rule (abstract2.md §2.1):
- Inter-channel transfer (both send and receive): `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain, tx_leaf_hash])`
- Deposit ingestion: `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain, deposit_hash])`
- Intra-channel transfer: unchanged.
- `TxLeafHash` is known at signing time (flowSend1 step 6 = small block signing time) and is the canonical
  settle/tx identity the chain uses. The base-layer nullifier (`SettledTransfer::nullifier()`, now binding
  `nonce` — settlement-independent, F-WD-2) remains dedicated to double-settle / anti-replay prevention in the
  base layer: two settlements of one deduction now collide to the same nullifier (as in the note of abstract2.md §2.1).

### C-7. [Chg] SmallBlockRootMessage (the carrier of H1/H2)

`channel.rs:324-352`. The field set is retained and the **meaning is redefined**:

| Field | Redefinition |
|---|---|
| `tx_tree_root` | **= `H2`**. In an inter-channel transfer small block, the root of that 1-tx tree (≠ 0). |
| `state_commitment_root` | **= `H1'`** (the `h1()` of the post-subtraction `BalanceState`). Replaced from the old "root of the lattice commitment group." |
| Other fields | [Chg] `bp_key_id` → **`bp_member_slot: u8` + `bp_sphincs_pubkey_hash: Bytes32`** (DA, in lockstep with `sphincs_sig.rs`). The rest (`channel_id, small_block_number, prev_small_block_root, medium_epoch_hint, close_freeze_nonce`) is [Keep] |

The preimage of `signing_digest()` (domain `0x494d5342` "IMSB") updates only the member portion
(`bp_key_id` → `bp_member_slot`(1)+`bp_sphincs_pubkey_hash`(8)), but the structure **containing both** `tx_tree_root` (= H2) and
`state_commitment_root` (= H1′) is unchanged, so this single signature realizes abstract2.md §3.3.2's
`hash(H1', H2 = tx_tree_root)` signature (= `channelStateSig`, structural atomicity).
**There is no signing target that signs only one side** (inseparable, the structuring of the abstract2.md §3.4 invariant).

`SignedSmallBlock` (`channel.rs:365-403`) is [Keep].

### C-8. [Chg] Close-related (abstract2.md §2.4)

| Type | Treatment |
|---|---|
| `CloseWithdrawal` (`channel.rs:601-626`) | [Chg] `final_channel_balance_root` → **`final_balance_state_h1: Bytes32`**. `burn_amount = withdrawCap` (abstract2's `closeBurnTx.amount`). |
| `CloseIntent` (`channel.rs:615-`) | [Chg] the same replacement + add **(new) `final_state_version: u64`** and **(new) `final_settled_tx_chain: Bytes32`** (for L1 reconciliation). Append both to the `signing_digest` (IMCI) preimage. |
| `WithdrawalClaim` (`channel.rs:727-`) | [Chg] `user_amount: LatticeCommitment` → `user_amount_ct: RegevCiphertext`. Member identification `user_id: UserId` → **`member_sphincs_pubkey_hash: Bytes32`** (DA). `claim_proof` = `withdrawClaimZKP` (§E-3). Nullifier derivation is **`[IMCW, close_intent_digest(8), member_sphincs_pubkey_hash(8)]`** (collision-safe since close_intent_digest embeds channel_id, member portion 2→8 limbs). |
| `PostCloseIncomingClaim` (`channel.rs:856-`) | [Chg] make `receiver_amount` a `RegevCiphertext`. Member identification `receiver_user_id: UserId` → **`receiver_sphincs_pubkey_hash: Bytes32`** (DA). Implementation of abstract2.md §3.5.5 `claimLateTx`. `lateBalanceProof` is verified inside `claim_proof`, and is managed as a **separate variable** from `finalBalanceProof` (also separated in contract storage via the `usedSharedNativeNullifiers` family). |
| `SpecialClose` / `CancelClose` | [Chg] hash only the member identifiers to pubkey hashes (`SpecialClose`'s censorship BP designation = `offending_bp_member_slot: u8` + `offending_bp_sphincs_pubkey_hash: Bytes32`, DA). Otherwise [Keep] (additional defenses outside the scope of abstract2.md. Retained since they are additions that do not weaken the safety properties. §I-3) |

**[New] close PI's `member_set_commitment` (F5 SECURITY, DB; D6/D12)**: the full channel-close circuit
**exposes `member_set_commitment = keccak([CLOSE_MEMBER_SET_DOMAIN, member_count(1), pk_g_0(8) …
pk_g_15(8)])`** — a fixed **`MAX_COSIGNERS` = 16-slot** keccak (2 + 16×8 = 130 u32 words, padding
slots zeroed, D6; `close_member_set_commitment`, domain `CLOSE_MEMBER_SET_DOMAIN = 0x494d434d`
"IMCM") over the **COSIGNERS only** — the array is sized by the cosigner cap, NOT the 1024
balance-slot capacity; delegates never enter it (D12) (code: `src/common/channel.rs`,
`close_member_set_commitment`). In the current 95-limb close-PI layout it **occupies limbs 85–92**,
with `member_count` at limb 93 and `delegate_count` at limb 94 (`close_pis.rs`, §F-3). L1
(`ChannelSettlementManager`) recomputes the same keccak from the registered cosigner `pk_g`s +
`member_count` and reconciles, **binding that the keys whose N-of-N signatures were verified inside the circuit
are the registered member set of that channel** (excluding signature substitution by non-member keys).
The Solidity mirror's internal 16-slot form is byte-identical to the Rust `MAX_COSIGNERS` form
(shared vector `close_member_set_commitment_matches_solidity_shared_vector`), so this commitment
survives the D12 split unchanged.

### C-9. [Keep/Del] base-layer types

`Transfer` (`transfer.rs:34-42`, TRANSFER_LEN = 25), `SettledTransfer` (including the nullifier),
`Block`, `PublicState`, `ValidityPublicInputs`, `ChannelId` — all unchanged.

- **[Del]** `KeyId` / `UserId` / `KeyRecord` (and `KEY_RECORD_DOMAIN`) were **deleted** (DA/DC, §D5).
  These were remnants of the old 2-layer identity (multisig/threshold), and were inconsistent with abstract2.md §1 ("1 person 1 key 1 account,
  address == pubkey"). Member identifiers are unified across all layers to the **SPHINCS+ public-key hash `Bytes32`**.
- **[Chg]** `ChannelRecord` / `MemberSignature` are hashed to pubkey hashes as in §C-3 / §H-1 (not unchanged).
- **`Block.key_ids`**: the field name is retained, but the meaning is reinterpreted as **"active member slots (0/1/2)"**
  (it remains in the block hash preimage). It represents the set of slots of members who signed in that block, not the multisig
  key identity.

### C-10. [New] Mid-Channel L1 Deposit Import

An L1 deposit can be folded into an already-open channel, increasing `channelFund.amount` and
crediting the depositing member's encrypted balance — the channel stays `Active` throughout
(the symmetric ENTRY half of partial withdrawal §GAP2).

**Transition kind:** `ChannelTransitionKind::L1DepositImport` (no Plonky3 STARK, no Plonky2 transport
proof — trust anchor is the `receive_deposit` balance proof verified via `verify_channel_backing`).

**Two-step state transition** (mirrors `InterChannelFundImport` + `ReceiverBundleApply`):

| Step | `channel_fund.amount` | `unallocated` | `enc_balances` | `settledTxChain` | `shared_native_nullifier_root` |
|------|----------------------|---------------|----------------|-----------------|-------------------------------|
| 1 (fund import) | `+= amount` | `+= amount` | unchanged | push `deposit.nullifier()` | advances |
| 2 (bundle apply) | unchanged | `-= amount` | `recipient_slot += delta` | push `deposit.nullifier()` | unchanged |

**Trust anchor:** The `receive_deposit` balance proof (recursive IVC, `ReceiveDepositCircuit`)
proves Merkle inclusion of the deposit in the finalized `deposit_tree_root` (T1 mitigation) and
inserts `Deposit::nullifier()` into the nullifier tree (T2 double-fold mitigation, C15 verified).
`verify_channel_backing` binds the balance proof's `settled_tx_chain` to the channel state's chain.

**Transition digest:** `l1_deposit_import_digest = keccak([IMLD, channel_id, deposit_nullifier,
amount_lo, amount_hi, depositor_slot])` (domain `0x494d4c44` "IMLD", `channel.rs`).

**Verification (`L1DepositImportUpdateWitness::verify()`):** identical to
`InterChannelFundImportUpdateWitness::verify()` EXCEPT no transport proof verification — the
balance proof is the external trust anchor (not an inter-channel transport envelope).

**Co-signer gate:** `verify_l1_deposit_import_transition()` — every N-of-N co-signer MUST call
this before signing the proposed state. Fail-closed.

**`settledTxChain` update rule** (extending §C-6 line 300): Mid-channel deposit import uses the
same rule as deposit ingestion: `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain,
deposit_nullifier])`.

---

## D. Unification of signing targets (abstract2.md §3.1 / §3.3.2)

| Update kind | Signing target | H2 | Implementation signing digest |
|---|---|---|---|
| Intra-channel transfer (`ChannelTx`) | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()` (h2_tag = 0, §C-3) |
| Inter-channel transfer (sender side) | `hash(H1', tx_tree_root)` | the small block's `tx_tree_root` | `SmallBlockRootMessage::signing_digest()` (§C-7) |
| Inter-channel receipt (receiver side) | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()` (the receiver side does not create a small block) |
| deposit / closeBurnTx | **No signature required** (abstract2.md §3.3.2b) | — | Accepted within the validity / close circuit |
| Mid-channel L1 deposit import | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()` — N-of-N co-sign the post-import state (§C-10) |

- **D-3 (atomicity)**: In an inter-channel transfer, a signature that "authorizes the transfer but refuses the subtraction" **does not exist by definition**, because
  `H1'` (post-subtraction state) and `H2` (tx_tree_root) coexist in a single preimage in the signing target.
  The validity / confirmation circuit verifies this signature as a **substitute** for a signature over tx_tree_root
  (constraining that the `H2` component = the `tx_tree_root` of the posted small block. §F-2).
- **D-4 (cosigner aggregation shape, D13)**: each cosigner produces ONE `SingleSigCircuit` sign-zkp
  over the common message (the recomputed IMCH digest for close/cancel); the proofs are aggregated
  PAIRWISE per level by `poseidon_sig::aggregate::AggLevelCircuit` (one circuit per level,
  `AGG_LEVELS = 4`, pk-slot widths 2 → 4 → 8 → 16 = `MAX_AGG_SIGNERS`), each level's PI layout being
  `[message(8), signer_count(1), pk_0..pk_{2^k−1} (8 each)]` — combining two aggregated proofs
  concatenates their signer lists. Left-packing is enforced **in-circuit** (a present right child
  forces the left child FULL, so zero-pk padding is provably a suffix) and `signer_count` counts
  exactly the verified leaf signatures. The close / cancel-close circuits recursively verify ONE
  level-`AGG_LEVELS` proof at constant VK, bind `message == recomputed IMCH digest` and
  `signer_count == member_count`, and WIRE the cosigner key vector from the proof's PI signer list
  (zero witnessed freedom) into the `member_set_commitment` keccak and the A5 distinctness chain
  (§F-3). The validity `bp_sig_chain` path keeps the linear `ListCircuit` (D8) — only close/cancel
  moved to the tree aggregator.

---

## E. lattice ZKPs (new circuits, Plonky3)

### E-1. channelTxZKP (intra-channel, abstract2.md §2.2 / audit finding 5)

**Proof statement** (public: `prev_sender_ct.digest()`, `next_sender_ct.digest()`, `enc_amount.digest()`,
the `RegevPk` digests of sender / recipient. private: plaintext balance, amount, encryption randomness):
1. `enc_amount` is a correct ciphertext to the recipient `RegevPk`, with plaintext `amount ≥ 0`.
2. The plaintext of `prev_sender_ct` = the plaintext of `next_sender_ct` + `amount`, and each plaintext is an n-bit non-negative integer
   (**underflow is impossible via the ripple-carry constraint → updated sender balance ≥ 0 is built in**).
3. `next_sender_ct` is well-formed as a fresh encryption to the sender `RegevPk`.

### E-2. channelUpdateZKP (inter-channel, abstract2.md §2.3)

**Proof statement** (public: `sender_delta_ct.digest()`, `receiver_delta_ct.digest()`,
`prev/next_sender_ct.digest()`, both `RegevPk` digests, `amount` (plaintext in the base layer)):
1. The absolute values of the plaintexts of `sender_delta_ct` and `receiver_delta_ct` are both `amount` (equal magnitude, opposite sign).
2. Update of the sender balance (the same ripple-carry as E-1, `balance ≥ amount`).
3. Both deltas are correct ciphertexts to their respective `RegevPk`.

`rangeProof` (abstract2.md §3.3.1) = the **verification** of this ZKP (performed by ITS = the member designated by `bp_member_slot` before handing it to the BP).

### E-3. withdrawClaimZKP (post-close withdrawal, abstract2.md §2.4)

**Proof statement** (public: one's own component `user_amount_ct.digest()` within `final_balance_state_h1`,
the withdrawal amount `amount` (plaintext, public), one's own `RegevPk` digest):
"the plaintext of `user_amount_ct` = `amount`." The decryption key is a private witness. No cooperation of other members is needed
(exit-liveness, abstract2.md §4.4).

### E-4. Verification trait (refactor of `state_update_verifier.rs`)

```rust
pub enum RegevProofPurpose {
    ChannelTx,        // E-1
    ChannelUpdate,    // E-2
    WithdrawClaim,    // E-3
    BalanceRefresh,   // §B-3 refresh (delta = 0 special case)
}
pub trait RegevProofVerifier {
    fn verify(&self, envelope: &ChannelProofEnvelope, purpose: RegevProofPurpose,
              public_inputs: &[u32]) -> Result<(), ChannelStateUpdateError>;
}
```

The old `LatticeBindingVerifier` / `LatticeProofPurpose::{TransferAmount, BalanceOpening}` and the
`LatticeOpening` field family (which assumed opening hand-off) inside
`ReceiverDeltaApplicationWitness` / `InChannelTransferUpdateWitness` are abolished.
The external helper process (`tools/lattice-proof-helper`) is also abolished, and the Plonky3 STARK is verified in-process.

> **Note (D2):** `RegevProofPurpose` is defined in `src/regev` and only re-exported by
> `state_update_verifier.rs:14`. The four shipped AIRs that back these purposes are
> `DualKeyTransferAir` (E-1) / `ChannelUpdateAir` (E-2) / `DecryptionAir` (E-3) / `RefreshAir` (§B-3 refresh)
> in `src/regev/transfer_stark.rs` — refresh is a separate `RefreshAir`, not E-1 with delta = 0.

---

## F. Changes to the balance / validity circuits

### F-1. BalancePublicInputs (`src/circuits/balance/balance_pis.rs:47-63`)

```rust
pub struct BalancePublicInputs {
    pub channel_id: ChannelId,                 // [Keep]
    pub public_state: PublicState,             // [Keep]
    pub block_r: BlockNumber,                  // [Keep]
    pub private_commitment: PoseidonHashOut,   // [Keep]
    pub settled_tx_chain: Bytes32,             // [New] the chain of the settle history ingested by the circuit
}
// BALANCE_PUBLIC_INPUTS_LEN += 8 (for Bytes32)
```

Each time the balance circuit ingests one settle (transfer / deposit), it computes
`chain' = hash(chain, TxLeafHash or deposit_hash)` **inside the circuit** and exposes the final value as a public
input (a new requirement of abstract2.md §2.1). Since `H1` does not include the proof object, the
state↔proof correspondence can be mechanically verified by the
**equality reconciliation** "`balanceProof.PI.settled_tx_chain == BalanceState.settled_tx_chain`" (resolving the circularity of "proof not generated at signing time" = audit finding 3).

> **Note (mid-channel deposit):** `verify_channel_backing` (wallet_core.rs) enforces this
> reconciliation at TWO points: (a) genesis backing (the initial deposit's balance proof) and
> (b) mid-channel L1 deposit import (§C-10). In both cases the `settled_tx_chain` equality check
> binds the balance proof to the channel state, preventing unescrowded deposit claims.

### F-2. validity / confirmation circuit (abstract2.md §3.3.5)

- To the verification of the small-block signature (equivalent to `channelStateSig` = `SignedSmallBlock.signatures`),
  add the constraints **"the `tx_tree_root` component of the signature preimage = the `tx_tree_root` of that small block" and
  "on the inter-channel path, `tx_tree_root ≠ 0`"**. Signature verification is done **in-circuit in the per-slot loop of `update_channel_tree`
  (UpdateUserTree)** (the old `signature_aggregation/` pipeline is dead code not connected to the
  live validity path, and is deleted, DC / §D5). The same loop also proves that the signing pubkey is
  included in a slot under the channel's Poseidon `member_pubkeys_root` (the soundness binding of §F-3).
- The `ChannelLeaf.prev` update of `PublicState.account_tree_root` (the ingested block number, double-spend prevention) is [Keep].

### F-3. ChannelClosePublicInputs (`close_pis.rs`)

Added fields: `final_state_version: u64` (2 limbs), `final_settled_tx_chain: Bytes32` (8 limbs),
**`member_set_commitment: Bytes32` (8 limbs, §C-8) + `member_count` (1 limb, D6)**.
`final_channel_balance_root` is renamed to `final_balance_state_h1`.
**`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN` = 77 → 86 (D6) → 87 (D9) → 95 (current)**: the Stage-3
`final_settled_tx_accumulator_root` (8 limbs, §C-2) sits at limbs 77..85, shifting
`member_set_commitment` to 85..93; `member_count` is limb 93 and `delegate_count` limb 94
(code: `close_pis.rs:37 = 95`). The original 77-limb prefix is unchanged.

Other close PIs. (The D5 values — withdrawal claim 42→48, post-close 34→40, cancel 41 — were further
changed by the subsequent close-game hardening / Stage-3 work; the table shows the CURRENT pinned
constants in `src/circuits/channel/*_pis.rs`.)

| Circuit | PI length (current) | Note |
|---|---|---|
| close (`close_pis.rs`) | **95** | 77-limb legacy prefix + `final_settled_tx_accumulator_root` (8) + `member_set_commitment` (8) + `member_count` (1) + `delegate_count` (1) |
| withdrawal claim (`withdrawal_claim_pis.rs`) | **48** | member identifier is the 8-limb `pk_g` (DA → D8); claimant slot opened via a height-10 Merkle inclusion against the H1 slot-tree root (D14) |
| post-close claim (`post_close_claim_pis.rs`) | **56** | 40 (D5) + Stage-3 accumulator-anchored source-tx binding; claimed slot opened via the same height-10 inclusion (D14) |
| cancel close (`cancel_close_pis.rs`) | **27** | CORRECTED C1 statement: `channelId(1) \| closeIntentDigest(8) \| memberSetCommitment(8) \| revivedStateVersion(2) \| revivedChannelStateDigest(8)` (replaces the forgeable legacy 41-limb revived-tx layout) |

**Close/cancel-circuit machinery (current, D11–D14):** the close and cancel-close circuits each
recursively verify **one level-`AGG_LEVELS` (16-slot) aggregated sign-zkp proof** (§D D-4, D13) at a
constant baked VK (`const`-asserted `MAX_COSIGNERS == MAX_AGG_SIGNERS`); the cosigner `pk_g` vector
is **wired from the verified proof's PI signer list** (the former per-slot signature verification /
in-circuit C' `ListCircuit` fold is deleted), with `message == recomputed IMCH digest` and
`signer_count == member_count` enforced in-circuit. `member_count` is range-checked
`2..=MAX_COSIGNERS` via the 16-bit unary active-bits decomposition. **A5 pk_g distinctness** is an
indexed-Merkle **insertion chain** (D11): each active cosigner `pk_g` is inserted in slot order into
a fresh `IndexedMerkleTree` of height `MEMBER_DISTINCTNESS_TREE_HEIGHT = 5` via the audited
`conditional_get_new_root` gadget — a duplicate key has no valid low-leaf, so it is unprovable
(replaces the O(N²) all-pairs loop). `member_set_commitment` stays the **fixed `MAX_COSIGNERS` =
16-slot keccak over the COSIGNERS** (§C-8). The in-circuit H1 recompute is the O(1) D14 header: the
slot-tree root is witnessed (bound by the cosigner signatures over H1), and the 1024-slot target
vectors + flat keccak are deleted.

**Soundness binding**: validity (`update_channel_tree`) proves, via a slot inclusion proof, that the **signing pubkey ∈ the channel's Poseidon
`member_pubkeys_root`** (bound to the `ChannelLeaf` under `account_tree_root`) (DB). close exposes `member_set_commitment`, and L1 keccak-reconciles it against the registered member set
(§C-8). Thereby "signing key = registered member" is bound both inside the circuit (Poseidon) and at the L1 boundary (keccak).

---

## G. List of numeric constants

### G-1. Newly established

| Constant | Value | Rationale |
|---|---|---|
| `MAX_CHANNEL_MEMBERS` | **1024** | BALANCE-SLOT capacity (cosigners + delegates + padding; pad-to-MAX, D6 → D12). Sizes `BalanceState.enc_balances` / `regev_pk_digests` / `pending_adds` and `ChannelRecord.member_pk_gs` (`[_; 1024]`). A spec deviation from abstract2.md §2.1's fixed 3 people (replaces old `CHANNEL_MEMBERS = 3`; was 16 before D12) |
| `MAX_COSIGNERS` | **16** (NEW, D12) | Cap on the N-of-N close SIGNERS. `member_count: u8` is range-checked `2..=MAX_COSIGNERS` (native + in-circuit via the 16-bit unary active-bits sum); all close/cancel SIGNATURE-side arrays/circuits (member_set_commitment, aggregated sign-zkp pk slots, A5 chain, activeness gating) are sized by this, keeping the close/cancel degree tractable while balance/H1 arrays stay 1024 |
| `MEMBER_TREE_HEIGHT` | **10** (= log2(1024) leaves = `MAX_CHANNEL_MEMBERS`) | The Poseidon Merkle height of the validity-side `MemberTree` (DB / D6 / D12; invariant `1 << height == MAX_CHANNEL_MEMBERS`). **Replaces and deletes** old `KEY_TREE_HEIGHT` / `KEY_SET_TREE_HEIGHT` / `MEMBER_KEY_TREE_HEIGHT` / `KEY_ID_BITS` |
| `BALANCE_SLOT_TREE_HEIGHT` | **10** (const-asserted `1 << height == MAX_CHANNEL_MEMBERS`) | Height of the H1 balance-slot Poseidon Merkle tree (D14, §C-2). Distinct from `MEMBER_TREE_HEIGHT` (the validity-side pubkey tree) — same value only because both are indexed by the slot space `0..MAX_CHANNEL_MEMBERS` |
| `MEMBER_DISTINCTNESS_TREE_HEIGHT` | **5** (= ceil(log2(`MAX_COSIGNERS` + 1)), derived const) | Height of the in-circuit indexed-Merkle tree of the A5 pk_g distinctness insertion chain in close/cancel (D11): one sentinel leaf + up to 16 cosigner keys ⇒ 2^5 = 32 leaf slots |
| `AGG_LEVELS` / `MAX_AGG_SIGNERS` | **4** / **16** (= `1 << AGG_LEVELS`) | Binary-tree aggregated sign-zkp (`src/poseidon_sig/aggregate.rs`, D13): one `AggLevelCircuit` per level, top-level pk list = 16 slots; `const`-asserted `MAX_AGG_SIGNERS == MAX_COSIGNERS` at the close-circuit consumer |
| `SIGN_TIMEOUT_SECS` | **180** | abstract2.md §2.5 (3 min). Replaces old `SMALL_BLOCK_SIGNATURE_TIMEOUT_SECS = 60` |
| `GRACE_BEFORE_PROCESS_SECS` | **600** | abstract2.md §2.5 (10 min). §H-2 |
| `CHALLENGE_PERIOD_SECS` | **86,400** | abstract2.md §2.5 (1 day). Set to the immutable `challengePeriod` of `ChannelSettlementManager` |
| `MAX_HOMO_ADDS_BEFORE_REFRESH` | **64 (approved — see D1 and doc/docs/regev-noise-analysis.md)** | §B-3 |
| `REGEV_N` / `REGEV_ETA` / `REGEV_PLAIN_BITS` | 128 / 2 / 8 | §B-1 |

### G-2. Newly established domain constants (non-collision with existing IMxx confirmed)

| Constant | Value | ASCII |
|---|---|---|
| `BALANCE_STATE_DOMAIN` | `0x494d4253` | "IMBS" |
| `BALANCE_STATE_HASH_DOMAIN` | `0x494d4248` | "IMBH" |
| `TX_LEAF_DOMAIN` | `0x494d544c` | "IMTL" |
| `SETTLED_TX_CHAIN_DOMAIN` | `0x494d5443` | "IMTC" |
| `REGEV_CT_DOMAIN` | `0x494d5243` | "IMRC" |
| `CHANNEL_TX_ZKP_DOMAIN` | `0x494d435a` | "IMCZ" |
| `CHANNEL_UPDATE_ZKP_DOMAIN` | `0x494d555a` | "IMUZ" |
| `CLOSE_MEMBER_SET_DOMAIN` | `0x494d434d` | "IMCM" (keccak, §C-8 close PI `member_set_commitment`. L1 reconciliation) |
| `MEMBER_LEAF_DOMAIN` | `0x4d424c46` | "MBLF" (**Poseidon**. Leaf domain separation of `MemberTree`, `key_tree.rs`, DB) |
| `REGEV_PK_POSEIDON_DOMAIN` | `0x494d5250` | "IMRP" (**Poseidon**. The member-tree leaf's `regev_pk_digest = Poseidon([IMRP, n, a…, b…])`, `regev/keys.rs`) |
| `BALANCE_SLOT_LEAF_DOMAIN` | `0x494d534c` | "IMSL" (**Poseidon**. Per-slot leaf of the H1 balance-slot Merkle tree, `src/common/balance_state.rs`, D14. Distinct from every existing IMxx domain — covered by the repo-wide domain non-collision test in `poseidon_sig`) |
| `LIST_LEAF_DOMAIN` | `0x494d4c4c` | "IMLL" (**Poseidon**. Sign-zkp list leaf `Poseidon([IMLL] ‖ m ‖ pk)`, `src/poseidon_sig/list.rs`, D8 — the validity `bp_sig_chain` aggregation path; close/cancel moved to the tree aggregator, which introduces NO new domain of its own — the aggregation statement is carried by recursive proof PIs, not a hash chain, D13) |

> Note: `MEMBER_LEAF_DOMAIN` / `REGEV_PK_POSEIDON_DOMAIN` are domains of **in-circuit Poseidon** (member-tree binding, DB).
> `CLOSE_MEMBER_SET_DOMAIN` is a domain of **L1 keccak** (close PI reconciliation). It is the design of DB that the same member set is represented by
> two systems: in-circuit (Poseidon) / L1 boundary (keccak). `regev_pk_root` (keccak "IMRR" `0x494d5252`) is for the L1 anchor of §H-1.
>
> **D14 update:** `BALANCE_STATE_DOMAIN` "IMBS" is now a **Poseidon** domain — the H1 header is
> `Poseidon([IMBS, …])` (keccak is retired from H1; §C-2). `BALANCE_STATE_HASH_DOMAIN` "IMBH" and the
> other chain/L1 domains remain keccak.

### G-3. Existing (unchanged, reference)

Domains: IMCH / IMPA / IMSB / IMSS / IMIT / IMCL / IMCI / IMSC / IMCN / IMCP / IMCW / IMUF /
IMCR / IMLD. Trees: `CHANNEL_TREE_HEIGHT = 32`,
`TRANSFER_TREE_HEIGHT = 6`, `TX_TREE_HEIGHT = 32`, `BLOCK_NUMBER_BITS = 63`.
`MAX_CLOSE_TRANSFERS = 16`, `SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW = 5`.
**Deleted**: `KEY_ID_BITS` / `KEY_TREE_HEIGHT` / `KEY_SET_TREE_HEIGHT` / `MEMBER_KEY_TREE_HEIGHT`,
and `IMKR` (`KEY_RECORD_DOMAIN`) and the threshold / num_keys constants (DA/DC, §D5).

---

## H. Flow correspondence (abstract2.md §3 → implementation)

### H-1. Normal operation

| abstract2.md | Implementation (updated version) |
|---|---|
| §3.0 `publishRegevPk` | At channel creation, `registerChannel` fixes a per-channel variable of **2..16 cosigners** (+ optional delegates up to the 1024-slot capacity, §L) `(pk_g, pk_b, regev_pk, l1_recipient)` + `member_count` (per-key_id threshold / key-set registration is abolished, DA/DC). `ChannelSettlementManager` stores the registered cosigner set + `activeMemberCount` (its internal mirror is the 16-slot cosigner form, byte-identical to the Rust `MAX_COSIGNERS` commitment; **the contract-side alignment to the 1024 balance-slot capacity — registration reg-chain preimage, H1 slot mirrors — is PENDING, D12**). `memberKeys[channel_id]` is a spec deviation generalizing abstract2 §1's `Map<ChannelId,[(Address,RegevPk);3]>` to N members (D6/D12). L1 anchor: take `ChannelRecord`'s `member_pk_gs` (all `MAX_CHANNEL_MEMBERS` = 1024 slots) + `member_count` + `member_pubkeys_root` + `regev_pk_root` (keccak "IMRR") into the IMCR `signing_digest`. The in-circuit binding is the Poseidon `MemberTree` assembled from the same members (DB) |
| §3.1 `agreeBalanceState` | Collect active-member (`0..member_count`) signatures over `ChannelState::signing_digest()` (= embeds hash(H1,H2)). Verification items are as in abstract2 §3.1 (version+1 / chain consistency / own-component decryption verification / `channelTxZKP` / `channelUpdateZKP` + inclusion proof) |
| §3.2 `channelTransfer` | Build `ChannelTx` (§C-5) → generate `channelTxZKP` (§E-1) → propagate → co-sign. `ChannelTransition::InChannelTransfer` |
| §3.3.1 `rangeProof` | The member designated by `bp_member_slot` verifies `channelUpdateZKP` with `RegevProofVerifier` |
| §3.3.2 `signChannelState` | `SmallBlockRootMessage` signature (§C-7). Inclusion confirmation is `tx_inclusion_proof` against a 1-leaf tree (§A-2) |
| §3.3.3–3.3.4 `produceBlock` / `postBlock` | The BP constructs the posting round's `SubBlock[]` and calls `IntmaxRollup.postBlockAndSubmit` (`IntmaxRollup.sol:433-445`). 1 SubBlock = 1 channel |
| §3.3.5 `generateValidityProof` | Existing validity stack + the §F-2 constraints |
| §3.3.6 `generateBalanceProof` | Existing balance stack + the §F-1 chain expose |
| §3.4 flowSend1/2, flowReceive3 | Implemented with `InterChannelTx` (§C-6). The `chain'` of step 5 is computed from `TxLeafHash` before signing. The receiver side is `ChannelTransition::ReceiverBundleApply` |

### H-2. close game (abstract2.md §3.5 → `ChannelSettlementManager.sol`)

| abstract2.md | Implementation (updated version) | Change |
|---|---|---|
| §3.5.1 `requestClose` | **[New] `requestClose()`**: immediately makes `channelStatus` `ClosePending` and records `closeRequestedAt = block.timestamp` (the signal to stop signing. `isNativeSendAllowed` becomes false) | Since the current contract does not separate request/startProcess, **a function is added** |
| §3.5.2 `startProcess` | Add **`require(block.timestamp ≥ closeRequestedAt + GRACE_BEFORE_PROCESS_SECS)`** to `submitCloseIntent(CloseIntent, proof)` (`ChannelSettlementManager.sol:submitCloseIntent` :558; GRACE check :587). Add to L1 verification: **(new) "the PI `settled_tx_chain` of `finalBalanceProof` == `CloseIntent.final_settled_tx_chain`" "all member signatures are over a `hash(H1,H2)`-family digest"** | Adding chain reconciliation is the core of v2 |
| §3.5.3 `challenge` | Existing "replacement by a newer close intent within the challenge period" (the ClosePending branch inside `submitCloseIntent`). Change the replacement order from `(final_epoch, closeNonce)` to **`(final_epoch, final_state_version)`**. Perform chain reconciliation for each submission | To `final_state_version` comparison |
| §3.5.4 `closeAndWithdraw` | `finalizeClose()` (`:752`) → each member's `submitWithdrawalClaim` (`:785`, claim_proof = withdrawClaimZKP §E-3) → `claimWithdrawalCredit()` (`:905`). **Σ(withdrawals) ≤ withdrawCap** is enforced by the existing `totalWithdrawn + amount ≤ finalizedChannelFundAmount`. `closeBurnTx` is submitted to L1 as `burn_tx_hash` + L2 burn processing (no signature required, §D table row 4) | The contents of claim_proof become Regev-based |
| §3.5.5 `claimLateTx` | `submitPostCloseClaim` (`:835`). `lateBalanceProof` is verified inside claim_proof, with `usedSharedNativeNullifiers` preventing double receipt | [Keep] |

### H-3. Implementation-specific additional defenses (outside the scope of abstract2.md)

Three challenge primitives sit outside abstract2's 5 properties (they strengthen exit-liveness, not
fund-custody safety). Status after the A1 settlement-verifier hardening (2026-06; the value-bearing
`verifyCloseIntent` / `verifyWithdrawalClaim` / `verifyPostCloseClaim` are now REAL MLE/WHIR proofs, not
`_matches` stubs):

**`cancelClose` (C1) — REAL.** A pending close is cancelled by a ZK proof that the channel's REGISTERED members
N-of-N signed a channel state at `state_version > pending_close.final_state_version`, in the same close-freeze
era (`revived.close_freeze_nonce + 1 == close.close_freeze_nonce`). The cancel circuit exposes
`member_set_commitment`, matched on-chain against `ChannelSettlementManager.registeredMemberSetCommitment()`, so
ONLY the registered members can cancel — a third party signing a revival block with their own keys is rejected
(member-set mismatch). NOTE: "a later signed BP small block exists" alone is NOT a sound staleness condition (the
BP unilaterally produces small blocks and can race a later block after an honest close starts); the sound
condition is "a strictly-newer N-of-N member-signed state exists", which is what the circuit proves.

**`submitSpecialClose` (C2) — DISABLED (IMPLEMENTED 2026-06, P6-A): the entry point now reverts
`SpecialCloseDisabled()` unconditionally (`ChannelSettlementManager.sol`); the stub verifier is left in place but
unreachable. Adversarial-reviewed (no defects; freeze-grief removed, no member funds move). Forgeable stub;
revert the entry point.** Intended fault: the BP fully
signed a small block but failed to finalize it within `SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW = 5` medium blocks
(censorship); on success it slashes `min(specialClosePenalty, bpBondCredits)` to the caller and freezes the
channel. A SOUND proof of this fault requires **non-inclusion of the BP-signed block in the finalized
medium-block chain** — proving a negative (it was never finalized) — and that finalized-chain commitment lives
in the validity / `IntmaxRollup` layer, not in the settlement contract (a cross-layer commitment, deferred). The
current `verifySpecialClose` is a tautological `_matches` stub (the "proof" is just `keccak(public inputs)`,
computable by anyone), so anyone can fabricate the accusation and slash an honest BP. **Disposition: disable
(revert) `submitSpecialClose`** until the cross-layer non-inclusion commitment exists. **Safety while disabled:**
the BP-censorship slash is simply unavailable; no member funds move; the BP bond (`bpBondCredits`) is a separate
pot, and if it is unfunded (= 0) the forged-slash steals nothing — disabling only removes the freeze-grief.

**`submitLateOutgoingDebitCorrection` (C3) — DISABLED (IMPLEMENTED 2026-06, P6-A): the entry point now reverts
`LateOutgoingDebitDisabled()` unconditionally; the stub verifier is left in place but unreachable.
Adversarial-reviewed (no defects; double-pay still prevented by the nullifier used-sets + cancelClose).
Forgeable stub; redundant. The threat it targets is already prevented; the conditions are:**
1. **No double-withdrawal — guaranteed by on-chain nullifier used-sets** (the "non-inclusion list of
   withdrawals" is a Solidity `mapping(bytes32 => bool)`, O(1), at EVERY payout path):
   `IntmaxRollup.withdrawalNullifierUsed` (base `withdrawNative`),
   `ChannelSettlementManager.usedWithdrawalNullifiers` (per-member claim), and `usedSharedNativeNullifiers`
   (post-close claim). Each nullifier is **derived deterministically in-circuit and bound** to the withdrawal
   identity (e.g. `keccak(IMCW, close_intent_digest, member_pk_g)`; post-close `keccak(IMCK, close_intent_digest,
   incoming_tx_hash, receiver_pk_g)`, recomputed by the manager), so re-running the ZKP cannot dodge it. The same
   tx pays out EXACTLY ONCE (check-then-set CEI). **A ZK proof for one withdrawal cannot be paid twice.**
2. **A co-signed outgoing debit cannot be silently omitted at the same version**: `H1` commits `settled_tx_chain`
   AND the (already-debited) `enc_balances` under the SAME N-of-N member signatures, so members never sign an H1
   whose settle chain contains the tx but whose balance is un-debited.
3. **Omitting a co-signed debit ⇒ closing on an older `state_version` ⇒ a stale close**, which is rejected by
   `cancelClose` (C1).
4. **A merely sender-signed (not co-signed/settled) tx is NOT a committed debit.** The 10-minute close grace
   (`GRACE_BEFORE_PROCESS_SECS = 600`) lets members settle any pending tx into a block before the close
   processes; afterwards honest members stop signing. There is **no mid-channel withdrawal** in the protocol
   (the only L1 exit is channel close: `finalizeClose → submitWithdrawalClaim → claimWithdrawalCredit`), so there
   is no "in-flight withdrawal" that a close could omit.
5. **Explicitly out of scope (accepted):** a time-difference grief where a non-settled tx is used to block a
   close. The only required property — "the same withdrawal cannot be paid more than once" — is met by (1).
   Therefore C3 is **redundant** with the nullifier used-sets + `cancelClose`. **Disposition: disable (revert)
   `submitLateOutgoingDebitCorrection`.**

These disables are **safety-neutral**: cross-channel isolation (the `Σ paid ≤ receivedChannelFunds` cap) and the
no-double-withdraw guarantee (nullifier used-sets) do NOT depend on C2/C3. Disabling only removes the
forgeable-while-stubbed BP-censorship slash (C2) and the redundant late-debit cancel (C3).

FOLLOW-UP (non-security, deferred): with C2/C3 disabled, the symbols only their removed bodies touched are now
dead — `latestSpecialCloseDigest`, `usedLateOutgoingDebitNullifiers`, the `SpecialCloseSubmitted` /
`LateOutgoingDebitAccepted` events, and `computeSpecialCloseDigest`. The adversarial review confirmed these are
harmless (no invariant reads them). They are intentionally LEFT for a future cleanup PR, since removing them
changes the Manager bytecode again (CREATE2 manager drift → another close-fixture regeneration).

### H-4. Invariant of the challenge order

L1's replacement rule is "larger `final_epoch`, and on a tie, larger `final_state_version`."
Discipline of an honest member (A3): sign only 1 state per version (`OneStatePerVersion`).
Thereby "the all-signed state of the highest version is uniquely determined" (consistent with the premise of ChannelSafety2.lean's
`challenge_latest_wins2`).

---

## I. File layout (change map)

### I-1. New

| Path | Contents |
|---|---|
| `src/regev/mod.rs` | Module declaration |
| `src/regev/params.rs` | §B-1 parameters (port of `channel_params`) |
| `src/regev/keys.rs` | `RegevPk` / `RegevSk` / keygen (port source `regev-adapter/src/lib.rs:110-123`) |
| `src/regev/encrypt.rs` | encrypt / decrypt / homomorphic addition / amount encoding (port of `encode_value_message`) |
| `src/regev/transfer_stark.rs` | The Plonky3 AIR of E-1/E-2/E-3/refresh (extends the port source transfer STARK to 4 purposes) |
| `src/common/balance_state.rs` | `BalanceState` / `balance_state_hash` / `tx_leaf_hash` / chain update (§C-2, C-6) |

### I-2. Changed

| Path | Change |
|---|---|
| `src/common/channel.rs` | The full set of type changes of §C-1 through C-8. Delete `LatticeCommitment` / `LatticeOpening` |
| `src/lattice/proof_adapter.rs` | **Deleted** (SIS-related). `tools/lattice-proof-helper` also deleted |
| `src/circuits/channel/state_update_verifier.rs` | Make it `RegevProofVerifier` (§E-4). Remove `LatticeOpening` from witness structures |
| `src/circuits/balance/balance_pis.rs` / `balance_circuit.rs` | Expose `settled_tx_chain` (§F-1) |
| `src/circuits/validity/…` (confirmation family) | The H2 constraints of §F-2 |
| `src/circuits/channel/close_pis.rs` / `close_circuit.rs` | §F-3 |
| `src/circuits/channel/withdrawal_claim_pis.rs` | Change the meaning of `user_amount_digest` to `RegevCiphertext::digest()` |
| `contracts/src/ChannelSettlementManager.sol` | Add `requestClose()` / enforce GRACE / chain reconciliation / `final_state_version` comparison (§H-2) |
| `contracts/src/ChannelSettlementVerifier.sol` | Add `final_state_version` / `final_settled_tx_chain` to the close PI hash |
| `src/constants.rs` | Add the §G constants; `MAX_CHANNEL_MEMBERS = 1024` (balance-slot capacity) split from `MAX_COSIGNERS = 16` (variable `member_count`, D6 → D12) |
| `src/circuits/channel/e2e_flow.rs` | Make E2E Regev-based (remove opening hand-off, make ZKP mandatory) |

### I-3. Unchanged

`src/common/transfer.rs` (`Transfer` / `SettledTransfer` / nullifier), `src/common/block.rs`,
`src/common/public_state.rs`, `src/utils/hash_chain/`, the SPHINCS+ family
(`sphincs_sig.rs`), the MLE/WHIR wrapper.

> **Update — `IntmaxRollup.sol` is no longer "Unchanged".** Its escrow / withdraw / registration
> surface changed: payable `deposit()` escrow tracked by `totalEscrowed` (`IntmaxRollup.sol:428,723-737`),
> `withdrawNative()` (`:1155`), `withdraw()` (`:1060`), `reclaimStake()` (`:1117`), and
> `registerChannel()` (`:789`, the D7 on-chain registration surface). `finalize` / `fraudProof` / `verify`
> are now MLE/WHIR-only with Groth16 removed (D6 — see the D6 Change B note above). Only the
> postBlock / deposit ingestion flow is structurally as before.

> **Update (D6 Change B):** `IntmaxRollup`'s `finalize` / `fraudProof` / `verify` / `fullVerify` become
> **MLE/WHIR-only**, removing Groth16 (no longer taking `Groth16Params`). The validity-PI binding that
> the former Groth16 PI-hash check alone carried is replaced by `_mlePublicInputsMatch(mleProof.publicInputs,
> keccak256(ValidityPublicInputs))` (soundness-critical). Delete `Groth16Verifier.sol` /
> `GnarkGroth16Verifier.sol` / `E2E_RealGroth16.t.sol` / `src/utils/groth16_wrapper.rs`.
> Details and verification tests are in detail2-implementation-notes.md D6.

---

## J. abstract2.md necessary-condition checklist

| abstract2.md requirement | Satisfaction in this spec | Status |
|---|---|---|
| §1 `RegevPk` / `LatticeCt` | §B-2 (`RegevPk` / `RegevCiphertext`) | New |
| §2.1 `BalanceState { encBalances, settledTxChain, stateVersion }` | §C-2 | New |
| §2.1 do not include the proof in `H1` | §C-2 `h1()` (digest only) | New |
| §2.1 expose chain in `BalancePublicInputs` | §F-1 | Changed |
| §2.2 `ChannelTx` + `channelTxZKP` mandatory | §C-5 + §E-1 | New |
| §2.3 `TxAux` / `TxLeafHash` / `channelUpdateZKP` | §C-6 + §E-2 | Changed |
| §2.3 `channelStateSig` (hash(H1', H2) signature) | §C-7 / §D | Changed (redefined) |
| §2.4 chain reconciliation of `finalBalanceProof` | §H-2 startProcess/challenge | Changed |
| §2.4 `withdrawClaimZKP` / `lateBalanceProof` | §E-3 / §H-2 | Changed |
| §2.5 the 3 timeout constants | §G-1 | Changed (60s→180s etc.) |
| §3.2 / §3.4 flow | §H-1 | Changed |
| §3.3.2b no-signature special case (deposit / closeBurnTx) | §D table | Consistent with existing |
| §3.5 close game (request → 10min → start → 1day → close) | §H-2 (add `requestClose`) | Changed |
| §4.2 Σ(withdrawals) ≤ withdrawCap | Existing `totalWithdrawn` enforcement | Existing |
| §4.5 confidentiality boundary (amount is base-layer plaintext, total balance is PI-visible) | §E-2 public `amount` / balanceProof PI | Consistent |
| (difference) `TxV2Tree` aggregation | **Not satisfied** (§A-2, user decision) | Intentional difference |

## K. Open items (abstract3 / to be resolved at implementation time)

1. **M7 (signed-but-unsettled race)**: the window in which the all-signed state of flowSend1 step 6 exists before
   L1 ingestion. Unresolved even in abstract2.md (lean-safety-proof2.md). Candidate implementation countermeasure:
   when adopting a `.txRoot`-tagged state (a `ChannelState` with `h2_tag ≠ 0`) for close,
   L1 requires the inclusion proof of that small block — it is expected that the existing mechanisms of `CancelClose` / confirmation proof
   (`SignedSmallBlock.confirmation_proof`) can be reused. Spec finalization is in abstract3.
2. **Semantics of retry / version reassignment** (audit finding 12): clarification of the version-consumption rule when a transfer does not succeed.
3. **Rigorous analysis of the noise budget** (the parameter requiring approval in §B-3).
4. **Authenticity of `RegevPk`**: the key-substitution attack surface of `publishRegevPk`. It is anchored to L1 by taking
   `regev_pk_root` into `ChannelRecord` (§H-1), but the procedure for registration-time verification (e.g., confirming decryption of a test ct
   encrypted with one's own key) is to be designed at implementation time.
5. **Following up the Lean model**: reflect `final_state_version` comparison, the 1 block = 1 tx degeneration, and the refresh operation
   into the v3 revision of ChannelSafety2.lean (parameterizing the signature of `Apply`).
6. **Registration mechanism (genesis ingestion of the member tree)** (DA/DB, §D5) — **RESOLVED by D7.**
   The in-circuit binding (`update_channel_tree` proving slot inclusion under `member_pubkeys_root`) is
   implemented and unit-tested, and the registration path is now in place: channels enter via a **registration
   block** (`src/circuits/validity/channel_reg_hash_chain/` + `src/common/channel_registration.rs` +
   `IntmaxRollup.registerChannel`), whose ZK proof deterministically rebuilds the channel tree from the on-chain
   registration hash chain (mirroring the deposit mechanism). `tests/e2e.rs:94` calls `add_channel_registration`
   and the full-stack e2e (register block → deposit → transfer → close) **PASSES**. The
   `switch_board.rs:230` empty-genesis is **intentional** — channels enter through a registration block, not
   genesis. (Residual unification items between the validity-path and close-path registration surfaces are
   tracked in D7's "Residual".)

---

## L. Delegate account (added feature, 2026-06; D9)

A **delegate account** is a channel participant that has a lattice (Regev) balance and SENDs / RECEIVEs /
WITHDRAWs with the **identical proofs** a co-signing member uses, but does **NOT** participate in the
N-of-N multisig that co-signs channel-state updates. It relies on the co-signing members for state
maintenance. Not in abstract2.md; authoritative delta = **D9** in detail2-implementation-notes.md.
Threat model + adversarial review: `doc/tasks/delegate-account-threat-model.md` (DA1–DA6).

### L-1. Slot regions (one fixed-`MAX_CHANNEL_MEMBERS` array, contiguous regions)
`delegate_count: u8` is added alongside `member_count: u8` on `BalanceState`, `ChannelRecord`, and the
registration record. With `active = member_count + delegate_count` (slot capacity
`MAX_CHANNEL_MEMBERS` = **1024** since D12; it was 16 when this section was written):
- slots `0 .. member_count`            → **co-signing members** (balance + send/receive + N-of-N co-sign; `member_count <= MAX_COSIGNERS = 16`, D12).
- slots `member_count .. active`       → **delegates** (balance + send/receive/withdraw; **NO** co-sign).
- slots `active .. MAX_CHANNEL_MEMBERS` → padding (canonical empty ciphertext, `pending_adds = 0`).

Invariants (enforced natively + in-circuit + Solidity): `2 <= member_count <= MAX_COSIGNERS`,
`active <= MAX_CHANNEL_MEMBERS` (overflow-safe `checked_add`), active slots non-padding and
pairwise-distinct `pk_g`, padding slots canonical,
`bp_member_slot < member_count` (the block proposer must be a co-signing member, never a delegate).

### L-2. Trust model (DLG-1 / DLG-2 / DLG-3)
- **DLG-1 (theft protection — TRANSITION LAYER, honest-member only):** a debit of a delegate's slot is
  bound to the delegate's OWN send authorization (E-1 `channelTxZKP` + the BabyBear A11 hash-sig over the
  IMPA digest). **Honest signing members refuse to co-sign a state update that debits any slot via a send
  lacking that sender's signature.** So under honest members, a delegate's funds move only by its own
  authorization. Enforced by member honesty at sign time, NOT cryptographically at close.
- **DLG-2 (final balance is TRUSTED to the members):** the delegate does not co-sign state, so **fully
  colluding members CAN forge the delegate's final balance** (under-report it). Accepted by design — the
  delegate has no cryptographic recourse; the N-of-N members' co-signature over the final state is
  authoritative. The delegate also trusts members for others' balance soundness + sum conservation.
- **DLG-3 (censorship / liveness): OUT OF SCOPE.** The delegate relies on members for inclusion of its
  sends and close cooperation. Also covers the on-chain deployer-asserted delegate binding (L-5) — a
  misbind only DENIES the delegate's honest claim (it cannot steal; E-3 needs the delegate's Regev key),
  i.e. griefing, not theft.

The only non-negotiable on-chain guarantees the delegate inherits (same as members): **solvency**
(Σ all withdrawals ≤ channel fund) and **no double-withdraw** (nullifier).

### L-3. Data layer — where `delegate_count` is committed
`delegate_count` is committed as ONE u32 limb **IMMEDIATELY AFTER `member_count`**, byte-identically,
in every "twin" preimage so the member/delegate/padding split is fixed under the members' signatures:
- `BalanceState::h1()` (IMBS) + the close-circuit in-circuit H1 recompute (`close_circuit.rs`).
- `ChannelRecord::signing_digest()` (IMCR) — NATIVE-ONLY digest (no circuit/Solidity twin).
- Registration reg-chain keccak preimage: native `ChannelRegRecord::hash_with_prev_hash` + in-circuit twin
  `channel_reg_step` (`channel_reg_hash_with_prev_hash_circuit`) + Solidity `IntmaxRollup.registerChannel`.
  `CHANNEL_REG_PREIMAGE_U32_LEN`: **475 → 476**. (Re-pinned differentials `PINNED_MC2/8/16`.)
- Close PI vector: `delegate_count` appended at the END (limb 86, after `member_count` at 85);
  `CHANNEL_CLOSE_PUBLIC_INPUTS_LEN`: **86 → 87** *(now 95: the Stage-3 accumulator insertion shifted
  `member_count`/`delegate_count` to limbs 93/94 — §F-3)*; Solidity `closePIHash` appends it (packed
  `(memberCount<<8)|delegateCount` into one uint16 in `CloseProofFields`).
- **IMCM** close member-set commitment (`close_member_set_commitment`) STAYS **member-only**
  (`0..member_count`) — delegates do not co-sign, so they are excluded.
- `member_pubkeys_root` / the reg `MemberTree` COVER active (members + delegates) — a delegate has a real
  `MemberLeaf{pk_g, pk_b, regev_pk_digest}` identity so it can send + withdraw.

> **Gotcha (D9):** adding the `delegate_count` limb changes every hash that includes the registration
> EVEN when `delegate_count = 0`. The reg preimage is folded on-chain into `_pendingChannelRegHashChain`,
> which is bound into the validity proof's block-hash-chain, so ALL baked validity/c2c/withdrawal/close MLE
> fixtures were regenerated. "delegate_count = 0 ⇒ byte-identical" holds for newly-generated artifacts
> (Rust ↔ circuit ↔ Solidity agree) but NOT for baked proofs. A conditional-omit-when-0 encoding was
> rejected (it would make the R3 word-aligned fixed-length single-keccak preimage variable-length).

### L-4. Send / receive / withdraw / refresh (active-region; co-sign stays member-only)
- **Send (delegate as sender):** identical to a member send — E-1 debits the delegate's slot, the BabyBear
  A11 hash-sig authorizes (DLG-1). The off-chain checks (`wallet_core`: `check_slot`, `member_pubkeys_root`,
  the member-list bijection, `verify_send_transition`/A11) admit the full active region
  (`member_count + delegate_count`). The in-circuit `state_update_verifier` E-1 path is slot-agnostic.
  `build_send` self-signs the next state ONLY for a member sender (`slot < member_count`); a DELEGATE is
  send-only and adds NO state signature.
- **Receive:** homomorphic credit to the delegate's slot, no signature (slot-agnostic).
- **Balance refresh (detail2 §B-3):** after RECEIVING, a slot's `pending_adds` raises and it becomes
  receive-only until a refresh (re-encrypt to clean digits, same value, `RefreshAir` proof). Wallet API:
  `wallet_core::build_refresh` / `verify_refresh_transition` (+ `regev::prove_balance_refresh_witnessed`,
  which also returns the fresh `AmountWitness` so the wallet can spend again) → wasm `wallet_refresh()` →
  CLI `cosign-refresh`. Works identically for a member or a delegate slot; the members co-sign, the
  delegate does not.
- **Withdraw (delegate at close):** the final member-signed `BalanceState` includes the delegate slots. A
  delegate withdraws via the SAME `WithdrawalClaim` + E-3 `withdrawClaimZKP` a member uses — the claimant
  slot gate is `member_index < member_count + delegate_count` (`withdrawal_claim_pis.rs`); H1 (signed) binds
  the active/padding boundary, the ciphertext binding + E-3 decryption are slot-agnostic; the per-(close,
  pk_g) nullifier + solvency cap bound double/over-withdraw (DA4). The delegate is NOT among the IMCH close
  co-signers (only `member_count` members sign the close state — DLG-2).
- **Co-sign (UNCHANGED, member-only):** `verify_all_signatures` / `validate_all_member_signatures`, the
  close circuit `active_bits` + IMCM member-set rebuild, and the validity bp set ALL stay `0..member_count`.
  The split is signed (both counts in H1/IMCR), so neither side is relabelable without all members' consent.

### L-5. On-chain (Solidity)
- `IntmaxRollup.registerChannel(channelId, bpSlot, delegateCount, memberPkGs, pkBs, regevPkDigests, recipients)`
  — the arrays carry the ACTIVE participants (members first, then delegates); `memberCount = arrayLength −
  delegateCount`; `delegateCount` is committed in the reg preimage after `memberCount`. (Four registerChannel
  require-strings were converted to custom errors to keep IntmaxRollup runtime under the EIP-170 24,576-byte
  limit after the delegate logic.)
- `ChannelSettlementManager` constructor takes a `delegateBindings` array (length = `delegateCount_`).
  `_registerDelegates` records each delegate's `(pk_g → recipient)` in `registeredMemberIndexPlusOne`
  (non-zero presence marker), `registeredRecipientOf`, and `isMemberRecipient`, so `submitWithdrawalClaim` /
  `submitPostCloseClaim` accept delegates. Delegates are NOT added to `registeredMemberPkGs` / `memberPkGs`,
  so the IMCM member-set commitment (`closeMemberSetCommitment`, uses `activeMemberCount`) and the N-of-N set
  stay member-only. Delegate pk_g must be distinct from every member AND every other delegate. The global
  solvency cap `totalWithdrawn ≤ finalizedChannelFundAmount` already covers members + delegates. TRUST:
  delegate bindings are deployer-asserted (not re-checked vs the member-only registry IMCM) — DLG-3.
- `closePIHash` takes the `CloseProofFields` struct (byte-identical 87-limb preimage) to keep callers within
  the via-IR stack budget once the trailing limb count grew from 1 to 2.

### L-6. Status
Implemented + independently security-reviewed (separate adversarial agent: GO, no CRITICAL/HIGH; DA1–DA6 all
blocked or accepted-as-designed). Branch `real-delegate-paymentchannel`. GREEN end-to-end: Rust native +
circuits, Solidity forge full suite, and a real 2-session browser test (Playwright) of the wallet-live
delegate demo (open as distinct delegate slots → send → receive → refresh → send again). A wallet-live demo
runs 3 CLI co-signing members + browsers as send-only delegates (`channel_member` / `wallet-relay.js` /
`wallet-live.html`).
