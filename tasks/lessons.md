# Lessons Learned

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
