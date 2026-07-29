# Lessons Learned

## Phase C1 cancelClose — adversarial review caught a forgeable design BEFORE coding, 2026-06

1. **A recursive signature-list proof proves "this key signed", never "this key is a member."**
   The cancel-close design proposed reusing close's `ListCircuit` to authorize a "revived" small
   block, but `ListCircuit` (src/poseidon_sig/list.rs) only binds `(message, pk)` pairs to verified
   single-sigs — member-set membership is a SEPARATE binding. In the codebase it comes from EITHER
   an on-chain `member_set_commitment` match (close: Manager:592/1116-1154) OR an in-circuit
   MemberTree inclusion against `member_pubkeys_root` (validity: update_channel_tree.rs:108-130).
   The cancel PI struct (cancel_close_pis.rs, 41 limbs) had neither ⇒ anyone could fabricate an IMSB
   with arbitrary keys and forge a cancel. ALWAYS ask "what binds the signer to the authorized set?"
   separately from "is the signature valid?".

2. **Running the adversarial subagent BEFORE writing code (CLAUDE.md §Adversarial Thinking) paid
   off.** It surfaced both a total break (no member binding) and a spec-level flaw ("a later block
   exists" ≠ "the close was stale" — a racing/colluding BP can always produce block final+1) with
   zero wasted implementation. A pinned PI layout (41 limbs) is NOT evidence the statement is sound;
   it is just a serialization. When the fix requires changing a pinned spec, that is an escalation,
   not a silent redesign.

## detail2.md (SIS → Regev) migration, 2026-06

1. **Spec text and reference code can silently diverge — read the port source, not just the
   spec.** detail2 §B-1 specified "8 bits × 8 coefficients" amount encoding, which digit-overflows
   after a single homomorphic add. The upstream port's *code* already used 1 bit/coefficient; the
   contradiction was only caught by reading the source. When porting a cryptographic design,
   cross-check every constant in the spec against the implementation it claims to describe.

2. **Published evaluations of private polynomials are a dictionary-attack oracle.** An early
   refresh design published `m(z)` for a low-entropy plaintext (a balance amount), letting an
   attacker enumerate candidate amounts offline. Anything derived from secret low-entropy data
   that crosses a trust boundary must be treated as a leak channel, even if it "looks like a hash".

3. **Power-of-2 range checks alias when the actual bound is not a power of 2.** The E-3 noise
   bound is Δ = 15·2^19; a naive 23-bit decomposition admits values up to 2^23−1, allowing the
   noise term to alias across plaintext digits. Use exact-range decompositions matched to the real
   bound, and write a negative test at bound+1.

4. **A dummy recursive circuit is only safe with a structural canary.** When baking a verifier key
   into a recursive circuit (close → balance), a placeholder/dummy inner circuit can make all tests
   pass vacuously. A ConstantGate-count canary on the baked VK catches the case where the "real"
   circuit was never actually wired in.

5. **Pin public-input layouts with cross-language shared test vectors.** The stale 2-limb
   ChannelId assumption survived in four PI layout constants (close/withdrawal/post-close/cancel)
   until a shared Rust↔Solidity golden vector forced both sides to agree byte-for-byte. Any
   constant that two languages must agree on needs a single shared fixture, not two hand-kept
   copies.

6. **"Impossible to instantiate" is a valid and important review outcome.** §B-3's
   "refresh = channelTxZKP with delta 0" cannot be implemented because no one holds an encryption
   witness for a homomorphic sum. Attempting to force the spec shape (e.g. with a fake witness)
   would have destroyed soundness; the correct move was to halt, redesign (combined
   Decryption+Encryption AIR), and get the deviation approved.

## CREATE2 address prediction vs external-library linking (2026-06-14, close e2e)

When baking a contract's CREATE2 address into a ZK proof ahead of time (the channel-close
withdrawal proof bakes the ChannelSettlementManager address as the L1 recipient), the address
MUST be computed in the SAME execution context that will deploy it. `MleVerifier` links external
libraries (Plonky2GateEvaluator / SpongefishWhirVerify) via delegatecall, and their addresses are
baked into `type(MleVerifier).creationCode`. Foundry resolves those library addresses DIFFERENTLY
in a forge SCRIPT vs a forge TEST, so a manager address predicted/deployed from a script does NOT
match the address the lifecycle TEST deploys. Symptom: identical VK/genesis/registration fixtures
(verified byte-equal) yet a different CREATE2 manager address script-vs-test; the rollup INITCODE
HASH was identical within a context but the contexts disagreed on the linked MleVerifier address.
Fix: compute the address with a forge TEST (CloseManagerAddr.t.sol), deploy everything via the
canonical CREATE2 factory (deployer-independent) with fixed salts, and reuse the EXACT same deploy
path (CloseE2EBase._deployAll) in both the address-printer test and the lifecycle test. The VK is
witness-independent, so the plain P2 fixtures predict the same address as the close fixtures —
which lets the address be known before the close proof is generated.

## A "one-shot" assumption is a security assumption (2026-07-28, in-channel $ITX faucet)

Two lessons from making a CLI co-signing member hand out repeated in-channel drips.

1. **A deterministic seed that is safe once is unsafe twice — and the safety argument lived only
   in a comment.** `channel_member send` seeded its Regev encryption RNG with the constant
   `0x5E_0000 + sender_slot`. That was fine only under the module header's assertion that *"each
   CLI member sends at most once from its fresh genesis balance"*. A faucet member sends
   repeatedly, and reusing one `r` across two different plaintexts under one key reveals their
   difference (`c2 − c2' = Δ·(m − m')`) — for balances, the balance itself. The bug was not the
   constant; it was that a load-bearing usage constraint was documented in prose instead of being
   enforced or removed. When a new caller violates a prose-only precondition, treat it as a
   security finding, not a refactor. Fix: draw the seed from the OS CSPRNG per invocation.

   The follow-on is sharper still: `gen-send` had the same defect behind what LOOKED like a
   sufficient guard. It refuses unless the position is still its untouched genesis ciphertext,
   which stops reuse across CO-SIGNED states — but two drafts against the same uncosigned state
   both pass and replay the same `r`. A guard that keys on committed state says nothing about
   concurrent uncommitted drafts. And the check that this test was not vacuous mattered: reverting
   the fix made two identical-input payloads byte-identical, which is what proved the randomness
   was genuinely being replayed rather than the prover merely being deterministic.

2. **The witness store, not the circuits, was the thing that could not do multi-token.** The
   circuits and `wallet_core` supported non-genesis token positions completely; what blocked an
   in-channel ERC-20 transfer from the CLI was that `cli_state.json` tracked ONE scalar balance
   seed per member — implicitly the genesis token. A homomorphically credited position (deposit
   import, incoming transfer) has `pending_adds > 0` AND no local encryption witness, so it is
   unspendable by construction; `build_refresh` is the only value-preserving way out, and the CLI
   had no command for it. Before concluding a feature "needs new protocol", check whether the gap
   is only in the local key/witness bookkeeping. Related: when persisting a reconstructible
   witness by SEED, the reproducibility depends on an upstream RNG-consumption order
   (`prove_balance_refresh_witnessed` consumes randomness only in its `encrypt_amount`) — do not
   assume it, re-derive and compare against the co-signed state, and fail closed.

3. **Verifying an address does not verify the metadata attached to it.** The token registry read
   `tokenAddressOf` back from chain and called the entry `verified`, but `decimals` — whose whole
   documented hazard is a 10^k misrender — was never read back and rested on the operator's file
   alone. When a gate's contract names several fields, check each one is actually attested by the
   read that sets the flag; "verified" is not transitive across fields. Same split as everywhere
   else here: a CONTRADICTION is fatal, an ABSENCE degrades to null, and a guess is never allowed.

4. **A negative test that probes guessed selectors proves almost nothing.** The "no mint entry
   point" test called four hardcoded signatures and asserted they failed — which misses any
   differently-named minter and cannot distinguish "no such function" from "owner-gated and
   reverted for this caller". Asserting over the COMPILED ARTIFACT ABI (every state-changing
   function must be in an exhaustive allowlist) is a real proof, and injecting an owner-gated
   `issueTo` confirmed it catches both missed cases.
