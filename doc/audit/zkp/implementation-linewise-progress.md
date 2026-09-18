# Line-by-line Lean formalization of the implementation — work record of 2026-09-11

## Conclusion and scope

**The formalization of every line of the implementation and the proof of fund soundness are incomplete.** This record is the
result of partial implementation correspondence and conditional proofs; it is not a release approval, nor a proof that
"neither theft nor loss is possible." To avoid confusing the earlier proofs about the design model with the proofs about the
current implementation, an independent `Zkp.Implementation.*` has been added to the existing Lean project.

The target runtime is the parent `05ec7ae94701f05d2aaf97ff796b7f800a6ce1f8`, and the MLE submodule is
`6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78`. The preceding specification sync and Lean integration is `acfaa78`.
The working branch is `codex/implementation-linewise-lean-20260906`.
At this stage we have not changed the runtime, the circuits, the proof parameters, the proof format, or the generated artifacts.
We make no benchmark claim that the proof size or proof generation time has improved or worsened.

The trust model is as before. **Dishonest distribution inside a channel** by collusion of the whole cluster is tolerated, while
consumption of another channel's funds is not. We maintain the requirement that exiting via the last N-of-N signed state H and
the corresponding retained exit kit does not require a new channel signature.
The KZG ceremony is an accepted trust assumption. But trusting the ceremony is one thing, and the codec, the
KZG invocation, the hash binding, and the correctness of the circuit and Solidity implementations are another.

## The whole-line inventory and what the checks mean

[implementation-inventory.json](./implementation-inventory.json) enumerates the following by file name, SHA-256 and
physical line count.

| Category | Files | Physical lines |
|---|---:|---:|
| The parent's `contracts/src/**/*.sol`, `src/circuits/**/*.rs` | 71 | 45,178 |
| The enumerated common components, cryptographic components and MLE Rust/Solidity dependencies | 165 | 72,019 |
| Total | 236 | 117,197 |

The dependencies are common, ethereum_types, utils, regev, falcon_sig, poseidon_sig, deprecated,
constants, wrapper_config, and MLE's src / contracts/src.
This is **not the full transitive dependency set** including Cargo, plonky2 itself, external u32 gadgets, the compiler and so on.
Test-only files and comments are also included in the physical line counts.

Each [line-map](./line-map/) partitions the original file from line 1 to EOF with no overlaps and no gaps.
Every original line falls into exactly one span, and that span is tied to a Lean definition or theorem that really exists.
However, this is not a mechanical word-for-word conversion of "1 source line = 1 Lean line"; it is a
**hand-written semantic model** at the granularity of operations, branches and loops. These correspondence tables do not themselves
prove the semantic equivalence of the translation.

The statuses are separated into `translated` (hand-written semantic model), `dependency-boundary` (a guarantee from the dependency is required),
`untranslated`, `test-only` and `non-executable`.
A file not yet covered is marked `untranslated` in its entirety; the existence of an older abstract model does not
automatically make it complete. We do not convert physical line counts or theorem counts into a "proof rate of safety."
Because some classifications include comment and syntax lines inside a span, the physical line count of a translated span is not a count of executable statements.

## Current implementation correspondence

| Model / original implementation | Properties derived at this stage | Main unproved boundaries |
|---|---|---|
| [SafeERC20](./Zkp/Implementation/SafeERC20.lean) / `SafeERC20.sol` | Handling of CALL failure, short responses, false and non-canonical bools; identity of the arguments; normal empty response / true response | ABI/CALL/rollback, the actual balance change, the caller's reentrancy protection |
| [BlobJournal](./Zkp/Implementation/BlobJournal.lean) / `BlobKZGVerifier.sol` | The journal, the sidecar, the payload byte-address, the forward prefix-product / backward batch-inversion / final scaling processing, the modular identities of the root constants, the bit-reversal involution for all 4096 indices | The full correctness of the barycentric interpolation, the SimpleCoder assembly, the implementations of SHA / modexp / point-evaluation, memory / CALL |
| [SettlementVerifier](./Zkp/Implementation/SettlementVerifier.lean) / `ChannelSettlementVerifier.sol` | The pinned adapter/core calls, the exact PI length, u32 and per-position correspondence, and the binding to the close / withdrawal / cancel / claim arguments | Proof soundness, ABI/staticcall, canonical hash encoding, the caller's ownership and recency |
| [CloseFunding](./Zkp/Implementation/CloseFunding.lean) / `CloseFundingMaterializer.sol` | The freeze generation, the current anchor, the exact proof receipt and re-verification, the correspondence of all vectors and the registry, materialization only once, the per-token escrow decrement and credit increment | The same snapshot across Manager getters, the Rollup calls, authenticated ownership, EVM atomicity |
| [CloseAssetBacking](./Zkp/Implementation/CloseAssetBacking.lean) / `close_asset_backing_circuit.rs` | From an arbitrary activity witness: a canonical prefix and zero suffix, prohibition of duplicates, reconstruction of the full-amount vector from an empty tree, zero outside the enumeration, 26 PIs and a 92-word digest, the binding of private / recursive state | Finitely many per-path Merkle/hash bindings, field gate lowering, the recursive verifier, the conservation of Balance itself |
| [U256Arithmetic](./Zkp/Implementation/U256Arithmetic.lean) / the target add/sub of `ethereum_types/u256.rs` | Inductive composition of carry/borrow across all limbs, exact addition and subtraction from a final zero, exclusion of underflow / wrap, examples of normal carry/borrow | The local equations and canonical range of the imported u32 gates, native shifts/casts, the remaining type conversions |
| [ManagerValue](./Zkp/Implementation/ManagerValue.lean) / all explicit functions of `ChannelSettlementManager.sol` | Finalization of all close vectors, the exact deadline and absolute horizon, the generation and nonce of request / cancel, consumption before PW authentication and rejection of re-execution, per-token counting of claim / pull / payout | Proofs, ABI, tokens, callback frames, the ordering of external logs, invariants of reachable states including all entrypoints, EVM refinement |
| [RollupValue](./Zkp/Implementation/RollupValue.lean) / all functions and modifiers of `IntmaxRollup.sol` | Deposit and withdrawal, posting, finalization, fraud, reverse-order rollback, stake splitting, retention of the permanent root across finalize / rollback traces, per-token accounting over the whole withdrawal-set loop | Proofs / hashes, real token balances, callback frames, proofs of chronology and ownership including all entrypoints, EVM refinement |
| [Spend](./Zkp/Implementation/Spend.lean) / `spend_circuit.rs` | 64 ordered subtractions, cumulative conservation of repeated subtraction on the same token, non-underflow from the local borrow equations, the difference between native and target, the correspondence of PIs, the proof wrapper and the constructor | Finite Merkle paths, field / u32 gadgets, the transfer tree and hashes, nonce overflow, the is_valid requirement on the consuming side, the connection to sending and receiving as a whole |
| [CloseCircuit](./Zkp/Implementation/CloseCircuit.lean) / `close_circuit.rs` | Member / token prefixes for an arbitrary witness, 103 PIs, the IMCH / H1 / TFD full-amount vector binding, the binding to the signed object, rejection of duplicates via a finite indexed Merkle insertion | The Falcon aggregate / Balance proof, field lowering, hash binding, the fixture generation part, the caller's high-water / backing / finality |
| [ClosePublicInputs](./Zkp/Implementation/ClosePublicInputs.lean) / `close_pis.rs` | The native 103-word codec, the round trip under the type widths and canonical forms, the witness projection after comparing all intents, the 92-word TFD | The difference between the scalar pair's raw shift / OR and the circuit's u32 check, the body of CloseIntent::new, Serde / the Rust compiler, the equivalence between the circuit and Solidity types |
| [CloseEncodingBridge](./Zkp/Implementation/CloseEncodingBridge.lean) / the native and circuit type conversions | Bidirectional conversion of all 20 fields, the identity of all 103 words, and that under the native canonical domain both parsers read the same statement | Solidity / ABI byte conversion, the Rust compiler and the real gate sequence, Keccak / proof soundness. Codec equivalence between models and equivalence in the real languages are different things |
| [FundFlow](./Zkp/Implementation/FundFlow.lean) / the composition of the Manager, Rollup and Materializer above | Projection equivalence between the credit helpers including successes and errors, per-token total conservation over the accounting traces in scope, paid ≤ received, retention of nullifier tombstones and unpaid records, a non-empty normal trace | The binding to the real dispatch / callback of pull, the whole fund flow including other Managers, physical custody, the composition of all traces including deposit, stake and rollback |
| [CancelCloseCircuit](./Zkp/Implementation/CancelCloseCircuit.lean) and [native PI](./Zkp/Implementation/CancelClosePublicInputs.lean) | The exact version increase of a cancellation, the non-wrapping successor of the freeze nonce, the binding of the registered member commitment and the signed object, the 29-word codec, the separation of native admission from an arbitrary witness | The semantics of the aggregate / Merkle / hash / gates, the Manager's cancellation history and pending generation, the optional-feature fixtures |
| [WithdrawalClaimCircuit](./Zkp/Implementation/WithdrawalClaimCircuit.lean) and [native PI](./Zkp/Implementation/WithdrawalClaimPublicInputs.lean) | 50 words, the active member/delegate slot, one-hot token selection and the same position in the registry and the ciphertext, the recipient inside the leaf, the same decryption core input and amount, the IMW2 nullifier, the native pre-checks | Authentication of the decryption polynomial / Merkle / signed head, backing, the high-water mark, the replay ledger, proof / compiler / gates, the optional-feature fixtures |
| [PostCloseClaimCircuit](./Zkp/Implementation/PostCloseClaimCircuit.lean) and [native PI](./Zkp/Implementation/PostCloseClaimPublicInputs.lean) | 57 words, the source tx including the token, the height-20 accumulator / height-10 slot calls, the recipient shared by member and delegate, the decryption core amount, the IMCK nullifier | Authentication of the reference roots of the decryption and the trees, the latest head / finality / remaining amount / replay, proof / compiler / gates, the optional-feature fixtures |
| [H1Gadget](./Zkp/Implementation/H1Gadget.lean) / the common H1 and leaf, and selected native/hash-output helpers | All fields of the 37-element header / 104-element leaf, the native/target ordering, derivation of the canonical 32/32 split from Goldilocks comparison, multiplication and zero constraints, the difference between the native cast and the target encode-back | The lowering of the imported gates to real constraints, Poseidon, the native tree computation, the Rust representation and the compiler, the remaining BalanceState / hash helpers |
| [SettlementCloseBridge](./Zkp/Implementation/SettlementCloseBridge.lean) | From the accepted return value of the same adapter/proof, the exact 103-word record, the agreement of the IMCS 48 bytes / IMTF 368 bytes, the injectivity of the u32 byte encoding, and under a concrete hash binding the agreement of the entire 10-token vector | Soundness from proof to circuit gates, the correspondence between the real gates and the hash implementation, the Manager's asset ownership / backing |
| [CancelCloseBridge](./Zkp/Implementation/CancelCloseBridge.lean) and [ClaimSettlementBridge](./Zkp/Implementation/ClaimSettlementBridge.lean) | The equivalence of Solidity's 29 / 50 / 57 words with all fields of the circuit, the connection of amount, recipient and asset via the same accepted return value, and the connection of the claim to the common H1/leaf/canonical root | The caller's wiring of the stored Manager head / nullifier / generation, proof soundness, the execution environment, fund ownership along every path |
| [PrivateState](./Zkp/Implementation/PrivateState.lean) / `common/private_state.rs` | The exact 21-word preimage of 4 roots × 4 words + nonce + salt, nonce offset 16 and salt offset 17, injectivity of the layout, the ordering agreement obtained by transcribing native `to_u64_vec` and target `to_vec` separately, the root projection FullState → PrivateState, genesis's empty roots / nonce 0 / salt retention, target assignment and the order of witness writes | Injectivity of Poseidon, the identity of `AssetTree::init` and `AssetTree::new(height)`, the trees' root computation, compiler refinement |
| [UpdatePrivateState](./Zkp/Implementation/UpdatePrivateState.lean) / `balance/common/update_private_state.rs` | The processing order nullifier insertion → old asset opening → U256 addition → new asset root → updated state, priority of the nullifier error, that an opening mismatch returns before the addition, that native overflow panics, the 3 fields updated on success and the retained sent root / nonce / salt, 32 siblings, the presence or absence of `is_checked`, exact addition and non-wrapping from `AddGates`, and the existence of a witness satisfying the local gate family along the native success path | Nullifier freshness / non-reuse, the ordered-set soundness of IndexedInsertionProof, asset Merkle ownership, Regev / transfer authorization, the agreement of native/target U256 (an explicit premise), gate lowering |
| [UpdatePublicState](./Zkp/Implementation/UpdatePublicState.lean) / `balance/common/update_public_state.rs` | That `new == old` gives a dummy proof of 63 siblings, that a proof is required for differing states, the Merkle connection at the old block number and the comparison with `new.previousRoot`, the target's unconditional path evaluation and conditional final root equality, the 5-field equality including timestamp hi/lo, the target witness from native verification success | Block increase, timestamp monotonicity, the canonical L1 chain, finality, reorgs, Merkle hash / gate / compiler lowering |
| [BalancePublicInputs](./Zkp/Implementation/BalancePublicInputs.lean) / `balance/balance_pis.rs` | The offsets of the 29-word prefix (public state 15, block_r, private commitment 4, settled chain 8), the native exact-length parser and its rejection of channel 0, raw field bounds, the separation of the target's suffix acceptance from its non-rejection of channel 0, the parsing of the verifier data digest / cap, the handling of the extra native cap root | The implementation of the imported parser guards (channel_id / u63 / u32limb), the field-conversion callback, Poseidon, the enforcement of `block_r ≤ block_number` on the caller's side |
| [SwitchBoard](./Zkp/Implementation/SwitchBoard.lean) / `balance/switch_board.rs` | Unique selection from the sum-one of 4 flags, application of the selector to all public words and to the verifier-data tail, binding of the inactive branch's dummy verifier and the active branch's real verifier, the error on a missing dummy index, the genesis candidate's empty roots / nonce 0 / virtual salt, selection of the full candidate rather than a prefix, explicit statement of the HashMap duplicate and ordering boundaries | The soundness of the proof gadget, the non-binding of the carried VD to the supplied balance VD (the outer cyclic-key check is a separate boundary), the implementation of `select_vec`, the prove-time config of the cap count, the binding of the branch proof to real funds |
| [BalanceCircuit](./Zkp/Implementation/BalanceCircuit.lean) / `balance/balance_circuit.rs` | The fixed switch verifier call, full PI parsing and registration, the common-data equality and build-success assertions, ordinary verification after the cyclic tail's cap → digest order check, the source behavior of discarding the consumed-byte count on serialization, and the fact that the constructor checks are not re-run after deserialization | The soundness of the recursive verifier gadget, the validity of `generate_cd`'s common data, agreement with plonky2's `check_cyclic_proof_verifier_data`, `CircuitData::verify`, the bincode / gate / generator codecs |
| [ChannelStateUpdate](./Zkp/Implementation/ChannelStateUpdate.lean) / `channel/state_update_verifier.rs` | The 7 verifiers and helpers, state / record / descriptor, the Regev envelope, 20 PI fields (266 words), the ordering of the channel / member / delegate / token slot guards, same-channel funds, the ciphertext of the selected token, pending increment / reset, send's `fundAfter + amount = fundBefore`, the import debit, fund invariance of refresh, the full state reconstruction of token-register, the u64 overflow profile and the U256 final carry panic, the signing-digest callee that takes only 7 fields, and that transport bytes are forced to be empty (a source observation) | The validity of the Falcon / A11 signatures (the helper is a structural check only), a durable replay ledger, L1 backing / finality, the wallet frontier; `root != oldRoot` is not freshness; gate / compiler refinement |
| [DecryptionGadget](./Zkp/Implementation/DecryptionGadget.lean) / `channel/decryption_gadget.rs` | Ring `N=2048`, `q=2013265921`, Δ / rounding, signed / unsigned representations, negacyclic schoolbook reduction, quotient / wrap / carry, ternary / residual / noise bounds, uniqueness of the digits, the decomposition of a u64 amount, the rejection conditions of the native build, the ordering of the row fill and the hash payload, the composition from `CoreGates` to the integer equations of each row, the gate non-satisfiability of the digit-255 boundary, a satisfying example with an all-zero assignment | The semantics of the decryption oracle / plaintext, uniqueness of the secret key, ciphertext authenticity, recipient entitlement, the `FieldProducts` premise, Boolean / range-check lowering, Keccak / Poseidon binding, Rust / gate / compiler / NTT refinement |

For the Manager and the Rollup, we extended the hand-written model from the selected paths of last time to all explicit functions.
However, the interface / generated getter / assembly / callback boundaries remain in a separate classification, and
**having a definition for every function is not the same as having proved fund safety for every execution.**
Do not judge each model's whole-line coverage from the table above alone; check the inventory / line-maps and the verification results.

`IPinnedMleVerifierV2.sol` is an interface with no function bodies. We added its 4 ABI signatures to
`SettlementVerifier.PinnedInterface` and to a [dedicated correspondence table](./line-map/pinned-interface.json).
We do not claim to have proved the safety of the MLE verifier from the existence of the interface.

### The extent to which we advanced from individual proofs to composition

`FundFlow` directly imports the existing Materializer / Rollup / Manager definitions.
It proves an equality that projects the Materializer's Rollup-credit expansion and the Rollup side's native / ERC20 dispatch,
guards and errors onto the same ledger and compares them. We do not simply build another similar accounting model
and treat "both are safe."

On top of that, for finite traces of credit → pull → claim → payout, it proves that per token
`Rollup escrow + that Manager's pending credit + Manager received` is conserved, and that
`paid ≤ received` is maintained. This includes the decomposition into `received − paid` and the amount already paid,
the persistence of consumed nullifiers, and the rejection of overwriting an unpaid payout record.
There is also a non-empty normal trace that, after 100 units of credit / pull, pays 5 units and retains 95.

However, this trace does not exhaust all entrypoints, and the condition tying pull's source call to the same
Rollup debit is stated explicitly. For native, we also added a lemma deriving the ledger debit from the actual modeled
`withdraw` wrapper, but the callback's storage frame is an unproved environmental condition. **Even if the total is conserved,
whether funds were stolen from another channel is a separate matter.**
Do not read deposit / stake / rollback, all Managers, fund ownership, real token custody, or the EVM call trace into the scope of
this theorem.

Cross-review found a correction point: to make visible in the model the intermediate state writes that Solidity performs before the
external digest call in Manager finalization. This is a matter of the hand-written model's precision, not
a demonstration of a new runtime vulnerability. Not only the final values but also the state visible to the callee is
now part of what is compared.

For the native and circuit public inputs, too, we advanced from a visual confirmation that the ordering is the same to
`CloseEncodingBridge`'s field-by-field conversion and the 103-word equality.
It is an interoperability result that does not erase the native decoder's narrow u8 / u16 counts and raw u64 joins, but instead states the
required canonicality conditions explicitly. It does not extend to equivalence with Solidity's recomputed digest or with ABI bytes.

### Checks to avoid overclaiming the boundaries

- Even when a helper succeeds, this does not mean the real ERC20 balance increased or decreased. The balance difference, canonical tokens,
  reentrancy and the rollback of the whole transaction must be connected to the caller and the environment.
- CloseFunding's actual code re-verifies the signed-head proof. We have not modeled it as "authorized by the receipt alone"
  on the basis of reading only an old comment.
- The pooled escrow total being sufficient is not a proof that nothing was stolen from another channel.
  That separately requires the authentication of an exact ownership vector and its binding to the channel.
- We do not automatically assume CloseAssetBacking's native witness-constructor checks for an arbitrary malicious
  witness. The circuit constraints and the native admission before proof generation are kept separate.
- In Spend, we do not place "subtraction is safe" as a premise of the conclusion; we derive non-underflow from each limb's
  borrow equations and the binding of inputs and outputs, and connect it to per-path conservation laws. We do not identify the native nonce's u32 overflow
  with field addition, nor the native PI parser's truncation with its non-zero test.
- The Manager's callback is a projection under an explicitly stated storage frame. The Rollup's callback is left in a form
  that may modify storage. We do not assume that `nonReentrant` guarantees anything about every unmodified entrypoint or about
  the ordering of external logs.
- The public / private commitments are bindings with the premises stated. We do not posit collision-freeness of a finite hash over
  infinitely many inputs. Merkle updates, too, are local guarantees for the finitely many trees and paths actually traversed.
- We have not added `sorry`, `admit`, custom `axiom`s or `native_decide` beyond the ordinary Lean kernel axioms. However, the
  cryptographic and execution-environment premises stated explicitly in a theorem's arguments are unproved.
- We permitted composition imports among current modules, but all modules are registered in the manifest and the
  theorem inventory and are checked. We added regression tests rejecting unregistered / historical imports, cycles, and
  local shadowing of standard module names.

Independent review improved the explicitness of the Blob context's callee / submission ID, the explicitness of the returned digest, and the
restriction of the Merkle premises to finite traces. This is an improvement in the precision of the formal model, not
a report of a newly discovered theft vulnerability in the implementation.

## Re-verification

### 2026-09-11 (4th loop): backing of the close vector (c), NTT correctness (d2'), mechanical faithfulness evidence, public document

Operator instruction: "it can be somewhat loose; fill the gaps at your own discretion so that it can be published externally as a practical
proof of safety" ((a0)(d3) out of scope). The plan is `tasks/loop-2026-09-11-backing-and-evidence-plan.md`.

**Reformulation of (c).** The old `closeVectorBacked` was "the amount at the time a close intent is accepted ≤ an opaque per-channel deposit map."
This (i) was attached to an event that credits nothing (crediting happens at materialization), and
(ii) is not a correct invariant in a system with L2 transfers. What the deployed contract requires before crediting from escrow
is a **backing proof** (`CloseAssetBacking`: recursively verify the Balance proof, open the private commitment,
require that the extended state's commitment is a root finalized on L1, and reconstruct the asset tree from the token vector).
So we decomposed (c) into 7:
(c0) the materializer's staticcall view = the Manager's storage snapshot (a cross-contract premise of the same kind as (f1);
investigation B2 confirmed the fact that the `fe` of `SystemSafety.Step.materialize` was not tied to the Manager state),
(c0b) the Manager's `tokenFundsDigest` = the reference Keccak (Sol :1685-1686), (c1) soundness of the backing verifier
(the same artifact as (a0) but at the Materializer's adapter), (c2) per-instruction lowering of `CloseAssetBacking`,
(c3a)(c3b) hash reference agreement and collision resistance for an equal-length pair, **(c4) `finalizedBalanceIsBacked` — the remainder**:
the amount in an active row of a witness satisfying `CircuitConstraints` is at most
`l2Entitlement root channel token` (the L2 entitlement accounted by the validity chain, a parameter) at the root the head finalized.
Derived theorem `materialized_credits_are_finalized_l2_balances_of_boundary`: each credit of an accepted materialization
equals the amount in an active row of the backing witness at the head-finalized root, and is at most the L2 entitlement.
`SystemSafety.mle_assumption_does_not_imply_fund_safety` was rewired to refute (c4) with a concrete witness (active row 22,
entitlement 0). Discharging it requires composing BalanceCircuit → SwitchBoard → ValidityChain →
DepositChain/WithdrawalChain, and that is the next project.

**B1: making `CloseAssetBacking` per-instruction (30 → 110 theorems).** We gave `holds` to the existing `constructorProgram`
(468 entries, 45 constructors) and proved `program_satisfied_implies_constraints` with no side assumptions
(`True` for 25 entries: allocation, config, build). `CircuitConstraints` matches byte for byte.
**B2: `BackingBridge` (new module, 52 theorems).** The receipt from acceptance of `materializeSignedHead`
(30 conjuncts: verifyCompact's words, `validateBackingPublicInputs`, the root's finality, the attestation,
agreement with the view getters, the 26-word decode), `limbsToBytes32 = Words8.value`, byte injectivity of the token vector
(`word_bytes_token_vector_binding`), and that the credit is the registry vector itself.

**N: proof of NTT correctness (new module `NttCorrectness`, 157 theorems).**
`ntt_computes_negacyclic_product : FalconGadgetProgram.NttComputesNegacyclicProduct` is proved unconditionally.
The forward direction is "evaluation at ψ^(2·bitrev(j)+1)" via a stage invariant, pointwise is a ring homomorphism, and the inverse is GS inverting CT
butterfly by butterfly (×2 at each stage, and over 9 stages `n⁻¹` cancels the 512). Neither an inverse table nor the primality of q is needed.
With this, field (d2') was deleted and became a theorem.

**M: mechanical faithfulness evidence (Rust, test-only).** `src/faithfulness.rs` reads the built `CircuitData`'s
`representative_map`, constant wires, `range_check` widths and public-input ordering, and checks them against the structural claims of
Lean's `holds` (connect / constants / registration order / range widths). 7 programs, 275 rows, 177 rows ok, 8 rows are
mutations (proof failure confirmed), and `not-static` (arithmetic and gadget semantics) remains a premise. **Zero mismatches.**
The probes are `#[cfg(test)]` insertions only (zero deletions; `shift-linemap.py` fails unless the change is insert-only).
6 line maps were renumbered and the inserted parts made `test-only` spans (the line citations in the Lean docstrings keep the pre-insertion numbers,
with a correspondence table in `evidence/README.md`). Execution: 18 tests / 209 s / peak 26.6 GB.

**P: public document `PRACTICAL-SAFETY-PROOF.md`.** English body plus a Japanese summary. The main theorems, the ledger of the 23 premise fields
(evidence, refutation conditions and how to check each premise), the composition theorems, the reproduction procedure, and the known gaps.

`TrustBoundary` went from 18 to **23 fields** ((c) → 7, (d2') deleted). Verification: main guard PASS (132 modules /
79 current / 497 hashes), line guard PASS (169 maps; test-only increased to 25,892 lines), the regression suite,
ledger-writers and fixture parity green, and `--require-complete` exits 1. Current named theorems **5,311**
(74 implementation modules, 5,092). The runtime's non-test paths are unchanged.

### 2026-09-11 (3rd loop): making the aggregation stack per-instruction and inventorying the replay ledger's write sites

The plan is `tasks/loop-2026-09-11-aggregate-program-plan.md`. The one premise assuming a whole circuit that remained in the structure after the previous loop,
(d1), and (d2), which ties an opaque callback to a gate set, were brought down to the same per-instruction level as the close-family circuits.
Together with that, (g1)(g2) are reduced to an inventory of Solidity write sites. `TrustBoundary` went from 17 to **18 fields**.

**G: the Falcon gadget's instruction sequence (new module `FalconGadgetProgram`, 47 theorems).** The 23 builder calls of `FalconSigVerifyTarget::build`
(gadget.rs:651-736) are transcribed as `GadgetOp` (`True` for 3: the twiddle table,
the β constant, build). **The NTT is not folded away but transcribed concretely** (`powModQ`, `bitReverse9`, the 9 CT-DIT stages of
`nttForward`, GS's `nttInverse`, `pointwise`, with `modQGates` imposed on the quotient wires of all 15,872 mod-q reductions).
`gadget_program_satisfied_implies_circuit_satisfied : ProgramSatisfied gadgetProgram a → CircuitSatisfied e circuitProduct (readWitness a)`
is proved **with no side assumptions**. The previously opaque `PolynomialProduct.mul` has been replaced by the concrete `circuitProduct`, and
the only remaining boundary is "this transcribed NTT equals the negacyclic product" (`NttComputesNegacyclicProduct`,
transcribed from `schoolbook_negacyclic`, unproved). The order of ψ, `n⁻¹` and twiddle spot checks are pinned with `decide`.

**A: the aggregation tree's instruction sequence (new module `FalconAggProgram`, 78 theorems).** The leaf circuit (agg.rs:268-305, 8 ops) and
the level circuit (:370-479, 23 + 8·2^(k−1) ops at level k) are transcribed. `sub/mul/add` over Goldilocks are written in `holds` as modular
operations, and Nat equalities are derived from range assumptions (count ≤ 2^(k−1), limb < 2^32).
`leaf_program_satisfied_implies_statement`, `level_program_satisfied_implies_compose`
(agreeing with the existing `levelCompose`), the inductive theorem over the abstract satisfaction relation `Sat`
`satisfiable_top_level_gives_witness_list` (satisfaction at level 3 ⇒ 1 to 8 `CircuitSatisfied` witnesses and
a left-packed sequence of key digests), the derivation of `SignerEvidence` via `sigEnvOf e`
(`pkDigest := limbsOfNat ∘ falconPkDigest e`), and `GadgetLevelLowering`, which splices the gadget instruction sequence into the leaf
(every conjunct is a transcription of a builder call and does not contain a whole gate structure), are all proved.
There is a concrete level-1 example with 2 signers.

**I: inventory of the replay ledger's write sites (new module `LedgerWriters`, 57 theorems).** By a read-only investigation, we confirmed that
the storage targeted by (g1)(g2) has exactly one write site each:
`usedWithdrawalNullifiers` :2231 (set only), `receivedChannelFunds` :2364, `totalCreditedOut` :2398,
`finalizedChannelFundAmount` :1681 (`+=` only), `materializedChannelExit` :461 (with a `== 0` guard).
There is no proxy, `delegatecall`, `selfdestruct` or assembly `sstore`, and the Rollup cannot write Manager storage.
On the Lean side we enumerated 13 Manager entrypoints and 7 Materializer entrypoints and proved
`manager_entrypoints_are_ledger_monotone`, `non_step_manager_entrypoints_are_ledger_neutral_except_cap`,
`finalize_close_only_raises_cap` (the exact form of the increment) and `materializer_entrypoints_keep_the_latch`.
The inventory is checked by `.github/ci/check-ledger-writers.py`, which scans the Solidity (6 self-tests), and it is wired into CI.

**Finding: the `cap t = cap s` clause of the old (g1) is refuted by the deployed contract.** `finalizeCloseGuarded`
(`cap += …` at `_finalizeClose` :1681) is modeled as `ManagerValue.finalizeCloseCore` but is not
a constructor of `SystemSafety.Step`, so an `Unmodeled` transition writes `cap`.
Since `SystemSafety` does not consume (g1)(g2), downstream is unchanged; the clause was corrected to the monotone `cap s ≤ cap t`, and
`only_cap_writer_is_outside_step` pins it as the sole exception.

**T2: replacement of fields.**

| Old | New | Theorem stating the old conclusion |
|---|---|---|
| (d1) `aggregateStatementLowering` (the whole circuit), (d2) `falconPredicateIsGadget`, `Models.sigEnv`/`falconMul` | (d0') `levelRecursionSoundness` (soundness of the recursive verification at a constant key at each level), (d1') `aggregatePrimitiveLowering` (`GadgetLevelLowering`), (d2') `nttComputesNegacyclicProduct` | `signature_validity_of_boundary` (the conclusion is `SignerEvidence (sigEnvOf m.falconHash) …`), `level_lowering_of_boundary` |
| (g1) `durableNullifierLedger`, (g2) `durableMaterializationLatch` | (g1') `ledgerWritersAreInventoried`, (g2') `latchWritersAreInventoried` (a source refinement of the same kind as (h): "a transition outside the model that touches the target storage is the execution of an inventoried entrypoint") | `durable_nullifier_ledger_of_boundary` (cap monotone), `durable_materialization_latch_of_boundary` (the old statement verbatim) |

`Models` carries `aggregateLevelDigest : Nat → List Nat` (levels 0 to 3) and `aggEnv` (the opaque child-verification relation inside the level circuit).
Digest pinning is separated out as `AggregateLevelPinnedDigestIsProgramDigest`.
`signature_gap_is_now_per_primitive` enumerates the 4 remaining premises. **There is no longer any field in the structure that assumes a whole circuit.**
`SystemSafety`, the individual circuit modules, `FalconAggregate` and `FalconCore` are unchanged.

Verification: main guard PASS (130 modules / 77 current / 478 hashes / 1 submodule pin), line guard PASS (169 maps),
3 regression suites + the ledger-writers self-test green, fixture parity green, and `--require-complete` exits 1.
Current named theorems 5,043 (72 implementation modules, 4,824). No runtime diff.

### 2026-09-11 (2nd loop): shrinking the premises for the hash bindings (e1, e2) and signature validity (d)

The division of roles is the same as the previous loop (Fable 5.1 plans and verifies, Opus 5 implements). The plan is
`tasks/loop-2026-09-11-hash-signature-plan.md`. `TrustBoundary` went from 13 fields to **17 fields**;
the opaque `signers` relation was removed from `Models`, and `sigEnv`, `falconHash`, `falconMul`,
`aggregateCircuitDigest` and `authorized` (the "the key holder approved it" relation at the granularity of a single signature) were added.

**K: a reference specification for Keccak-256 (new module `Keccak256`, 45 theorems).** Keccak-f[1600], rate 1088 and
the original Keccak padding (`0x01…0x80`) are defined over `List Nat`, and output length 32, byte canonicality and injectivity of big-endian
`bytesToNat` are proved. Two published vectors (the empty string, `"abc"`) and two of our own (a 135-byte
padding boundary, a 200-byte 2-block case) are included as **kernel proofs by `decide`** (1 to 4 seconds each;
the Lean 4.10 kernel accelerates `Nat.land/lor/xor/shiftLeft/shiftRight` with GMP).
All 4 were independently recomputed with the runtime's own `keccak-hash 0.8.0` crate and confirmed to agree.
This module has no in-repo source lines (on the circuit side it is the external crate `plonky2_keccak`, pinned to
`2507786148ae…` by Cargo.lock; on the contract side it is an EVM opcode).
We added Cargo.lock to the manifest's tooling hashes so that a change of the pin is visible to the guard.

**E: ABI faithfulness of the token-funds preimage (`SettlementCloseBridge`, +9 theorems).** We proved that the Solidity-side
`tokenFundsPreimage` is 368 bytes of fixed length and injective in `(registry, count, amounts)`, and that the circuit side's
`wordBytes (tokenFundsPreimage w)` is likewise 368 bytes under `Shape`
(`token_funds_preimage_injective`, `token_funds_compared_strings_same_length`, `be_bytes_injective`).
Of the two things the old (e2) docstring called "collision resistance and the faithfulness of the ABI encoding," the latter is gone.

**D1: the signature bridge (new module `CloseSignatureBridge`, 21 theorems).** We proved that the close circuit's
`AggregateStatement` and `FalconAggregate.AggStatement` have the same 73-word layout
(`to_agg_statement_public_inputs`), and that an accepted level-3 aggregation tree yields `SignerEvidence`
(the signer count, the left-packed sequence of key digests with a zero suffix, a single message, and approval at each active slot)
(`accepted_aggregate_tree_gives_signer_evidence`). The correspondence between `SlotWitness` and `FalconCore.CircuitWitness`
is the identity field by field, and the only conversion, `digestOfLimbs` (big-endian packing of 8 limbs,
bytes32.rs:18-22 / hash_to_point.rs:73-76 / gadget.rs:378-380), has been proved injective.
There is a non-emptiness example with a concrete 2-signer tree satisfying all 4 premises.

**T: replacement of fields (`TrustBoundary` 35 → 43 theorems).**

| Old field | New field | Conclusion of the old field |
|---|---|---|
| (e1) `circuitKeccakIsSolidityKeccak` | (e1a) `solidityKeccakIsReference` (EVM opcode = the reference specification), (e1b) `circuitKeccakIsReference` (`plonky2_keccak` = the reference specification, independent of (a)'s "the gadget enforces `out = e.keccak preimage`") | `circuit_keccak_is_solidity_keccak_of_boundary` |
| (e2) `tokenFundsHashBinding` (an opaque callback) | (e2) same name, collision resistance for the same pair over the reference `Keccak256.keccak256` | `token_funds_hash_binding_of_boundary` |
| (d) `signatureValidity` (aggregate verification ⇒ the opaque `signers`) | (d0) `aggregateRecursiveVerifierSoundness`, (d1) `aggregateStatementLowering`, (d2) `falconPredicateIsGadget`, (d3) `falconUnforgeability` | `signature_validity_of_boundary` (⇒ `SignerEvidence`) |

(d0) is the soundness of plonky2's FRI recursive verifier, and **it is not included in the acceptance of (a0)** (it lives in the same pinned
submodule, but the operator's acceptance was a judgement limited to the MLE/WHIR verifier).
(d1) remains the only whole-circuit premise in the structure because `FalconAggregate` does not yet have a `BuildOp` program
(it also subsumes digest pinning). (d3) is the NTRU/GPV lattice assumption and (e2) is the collision resistance of Keccak-256, and neither
can in principle be discharged within this project. `rejecting_environment_satisfies_every_premise`
takes hypotheses for the new fields (2 reference equalities, `noFalconAccept`, `authorizedTrivially`), and
`reference_keccak_models_satisfy_hash_premises` shows the non-emptiness of the hash premise pair.
`SystemSafety` is unchanged (it does not refer to `signers` or the old fields).

Verification: main guard PASS (127 modules / 74 current / 473 hashes / 1 submodule pin), line guard PASS
(169 maps; the new modules are registered by composition into existing maps), 3 regression suites and fixture parity green, and
`--require-complete` exits 1. Current named theorems 4,858 (69 implementation modules, 4,639).
No runtime diff.

### 2026-09-11: shrinking the gate-lowering premise from whole circuits to per-instruction

The targets are `CloseStatementLowering` and the claim-side premises (b1)(b2). The whole-circuit black box "from an accepted plonky2
statement to the hand-written `CircuitGates`" was decomposed into 3 layers. The division of roles is that
Fable 5.1 plans and confirms the results and Opus 5 implements.

**L1 (unifying the shape).** (b1)(b2) were also split into a `StatementLowering` isomorphic to close's, aligning everything to
`MLE premise (a0) + each circuit's lowering`. The conclusions of the old fields remain as compatibility theorems such as
`close_proof_soundness_of_boundary`, and `SystemSafety`'s calls pass unchanged.
Verification caught one problem. The compatibility theorems had been declared in camelCase inside a nested `namespace`, so
the constant names the registrar assembles disagreed with the actual entities and the guard's axiom probe failed.
This was resolved by renaming them to top-level snake_case.

**L2 (per-circuit derivation).** To the builder call sequence `constructorProgram : List BuildOp` that each circuit already held as data,
we gave a local per-instruction satisfaction semantics `BuildOp.holds`, and proved
`program_satisfied_implies_gates : ProgramSatisfied constructorProgram a → CircuitGates e (readPublic a) (readWitness a)`
for all 3 circuits. **The only premise is `ProgramSatisfied`, and the residual `EnvironmentGates` is zero for all 3 circuits.**

| Circuit | Theorems | `BuildOp` additions | Instructions emitting no constraint (`True`) | Change to `CircuitGates` |
|---|---:|---|---|---|
| CloseCircuit | 58 → 92 | 0 | 4 of 47 instructions (config, build, raw allocation, insertion path) | None (byte agreement against the commit baseline confirmed) |
| WithdrawalClaimCircuit | 37 → 53 | 0 | 10 of 32 instructions (config, profiling observe, build, raw allocation) | None |
| PostCloseClaimCircuit | 32 → 54 | 1 (`add_virtual_target` :372, a transcription omission) | a few | None |

All of them have non-emptiness examples (2 cosigners, a non-zero genesis fund, a real freeze-nonce increment, and so on), and
it is also made a theorem that `readPublic` reads back the expected statement.
Each case of `holds` cites the source lines in its docstring, and no constraint that the source does not emit has been added.
PostClose's `DecryptionHolds` is stronger than the gate record (canonicality of the 8192 coefficients and `a ≠ 0` / `c1 ≠ 0`),
which means the hand-written `ConstructorGates` was an under-approximation of the real circuit.

**L3 (promoting the premises).** 3 fields of `TrustBoundary` were replaced by `ClosePrimitiveLowering` /
`WithdrawalPrimitiveLowering` / `PostClosePrimitiveLowering`. Their content is
"if the plonky2 statement of the pinned digest is satisfiable, then there exists an assignment satisfying **the same** `constructorProgram`
under our instruction semantics, and it reads that statement back." The old `*StatementLowering` are re-derived as
theorems over instances, and `*_gap_is_now_per_primitive` shows that acceptance yields both a "satisfying assignment of the program" and
"gates." Digest pinning is separated out as `*PinnedDigestIsProgramDigest m digestOf` and tied to the field by
`*_digest_pinning_and_program_lowering_give_primitive_lowering`.
`TrustBoundary` went from 8 to 35 theorems; the field count stays at 13.

**The remaining premises have been narrowed to the following 2.**
(i) that each case of `BuildOp.holds` agrees with what the corresponding plonky2 primitive enforces (a finite check per instruction kind), and
(ii) that `pinnedCircuitDigest adapter` is the digest of `constructorProgram`.
The places assuming a whole circuit as a black box have disappeared from the premises. (a0) and (c) through (h) are as before.

The new theorems were tied into the line-maps (close 46→57, withdrawal 32→46, post-close 30→42 theorems), and
the boundary `primitive-semantics-faithfulness` was added to 3 maps. The source hashes, line counts and span partitions are unchanged.

Verification: main guard PASS (125 modules / 72 current / 470 hashes), line guard PASS (169 maps),
3 regression suites and fixture parity green, and `--require-complete` exits 1. Current named theorems 4,775
(67 implementation modules, 4,556). No runtime diff.

### 2026-09-10: running all 711 lib unit tests

The circuit- and crypto-family lib tests that were left "unconfirmed" last time were run in full, serially and in the background,
split into chunks by submodule. The result is **711 of 711 executed, and all passing except the 1 that has been fixed**.
We cross-checked the executed set against the 711 from `cargo test -- --list` and confirmed zero unexecuted and zero not passing.

| chunk | Count | Seconds | Notes |
|---|---:|---:|---|
| Middle layer (wallet_core, the publisher family and 14 other modules) | 195 | 1,093 | wallet_core is ~18 GB RSS |
| regev | 51 | 6 | Pure arithmetic |
| falcon_sig (excluding measure/bench) | 77 | 390 | Includes recursive proofs |
| circuits::balance / close / cancel_close / close_asset_backing | 49 | 249 | |
| circuits::channel claim family + decryption_gadget | 35 | 3,337 | Of these, `property_vs_native_oracle` alone takes **45 minutes and 30 GB** over 40 iterations |
| circuits::channel::state_update_verifier | 50 | 27 | The heaviest file, but the tests are light |
| circuits::channel::e2e_flow / validity / withdraw / witness | 63 | 667 | |
| measure / bench family | 6 | 158 | Passes when run on its own. The earlier OOM was caused by memory accumulation in an unfiltered run |
| 6 individually missed items (close_pis, h1_gadget, review_hardening) | 6 | 2 | |

**One newly found failure (a stale test, fixed in `31aaf6c`).**
`wallet_core::slot_capacity_tests::join_path_reaches_slot_256_and_beyond` gave fabricated members
`RegevPk::padding()` (the zero polynomial) and noted for itself that "build_record does not check keys."
In `b5bafb7` (2026-09-06), `build_record` came to require shape, canonicality, non-zeroness and distinctness of the Regev keys of active slots,
and the test was left behind. The test dates from `f08ba2e` of 2026-07-19 and is
7 weeks older than the check, and the check side is legitimate (a zero `a` is only for padding slots). The fix is on the test side only:
it now gives a distinct, non-zero, canonical `a[0]` per slot, and the note was corrected. The runtime is unchanged.
For verification, Fable 5.1 handled the classification and planning and Opus 5 the implementation, and the grounds for the classification
(the dates of both commits, `git show`) were independently confirmed on the implementation side as well.

**Two operational lessons.**
- **libtest filters are substring matches**, and `withdrawal_claim::` does not match `withdrawal_claim_circuit::`.
  On the first pass, 47 tests were not executed yet reported `ok`, which came to light on cross-checking against `--list`.
  Do not use submodule filters with a trailing `::`; always reconcile against the full list.
- **A SIGKILL from OOM looks like a test failure.** An unfiltered `--lib` dies even with `--test-threads=1`, but
  the same tests pass when a chunk is run on its own. Chunking and the discrimination of `signal: 9` are built into the runner.

**Reflection in CI.** `regev::`, which fits on a 16 GB `ubuntu-latest`, was added to the lib step (189 → 240 tests).
`wallet_core::` (18 GB), `circuits::` (up to 30 GB) and `falcon_sig::` (recursive proofs of several GB) cannot be made a routine step,
so the measured figures are left in the step's comments and they are delegated to the existing dedicated `--test` steps.

### 2026-09-09: fixing a confirmed defect, updating stale tests, and closing the CI hole

This is the first checkpoint since the audit began at which **a runtime diff** appears. The changes against the baseline `05ec7ae` are the 4 files
`src/utils/poseidon_hash_out.rs`, `src/utils/error.rs`, `src/common/balance_state.rs` (test portion only) and
`.github/workflows/ci.yml`. The circuits, proof parameters and proof format are unchanged.

**1. Fixing the unreachable canonicality check (the root cause).**
The round-trip check of `TryFrom<Bytes32> for PoseidonHashOut` **held for every input and never fired**, because
`reduce_to_hash_out` merely regroups 8 u32 limbs into 4 u64s and `From<PoseidonHashOut> for Bytes32` is its strict inverse.
As a result, the 3 kinds of non-canonical identity rejection in `ChannelRegRecord::validate` were dead code, and
the repository's own test was failing.
The fix places an explicit element check against the Goldilocks order **before** the round trip and adds the error variant
`PoseidonHashOutError::NonCanonicalElement(usize)`. `reduce_to_hash_out` and the
`From` impl are unchanged, so the many callers that intentionally use the many-to-one reading are unaffected.

**2. Updating stale tests.** Two tests in `balance_state` asserted that member_count 16 passes
(wrong ever since `fd467ea` restricted the sig-cluster to 8). They were updated to use `MAX_SIG_CLUSTER`, and
together with that the 3 negative tests that had been built from the invalid base 16 were fixed to use a valid base. These were tests
that claimed "exceeding the limit is rejected" while in fact passing because the base itself was invalid.

**3. Closing the CI hole.** The workflow ran only the named `--test` integration tests and never ran `cargo test --lib`
even once. All 3 of the failures above had fallen into this hole.
We added a `lib unit tests (pure-logic modules)` step that runs the
**189 tests, 0 ignored** of `common:: utils:: ethereum_types::` under the repository's own `rust-test-guard.sh` (about 20 seconds).
`circuits::` / `regev::` / `falcon_sig::` were excluded because they build real circuits. In measurements, `circuits::` alone
**did not finish even at 37 minutes and 25 GB RSS**, and an unfiltered `--lib` is SIGKILLed by OOM even with `--test-threads=1`
(this SIGKILL looks like a test failure). These are handled by the existing dedicated `--test` steps.

**4. The model following suit.** The guard immediately detected the source hash change and stopped, demanding, as intended,
"revise the model correspondence before updating the manifest." As a result of that revision, the 5 modules that independently modeled
the conversion were updated.

| module | Correspondence |
|---|---|
| `H1Gadget` | `nativeTryFrom` was made `Except`-returning with the canonicality check placed first. `native_try_from_requires_canonical_elements`, `goldilocks_order_bytes_are_now_rejected` and others. That half of the round trip is still unreachable is retained as `native_try_from_roundtrip_test_alone_is_unreachable` |
| `UtilGadgets` | A variant was added to the error enum, and the variant set, the Display wording and the error priority (canonicality precedes the round trip) were pinned |
| `ChannelRegChain` | `Words8.canonical` was split into "Goldilocks element check ∧ round trip". `native_canonicality_check_cannot_fail` was renamed to **`byte_round_trip_alone_cannot_reject`** (the proposition is retained; the name and description disagreed with the current state). `non_goldilocks_record_rejected` proves the rejection is live |
| `BlockTypes` | The proposition is retained and the docstring corrected. `non_canonical_pk_g_rejection_is_reachable` was added to record both directions |
| `TxSettlement` | `native_try_from_never_rejects_u32_limbs` and `modulus_encoding_passes_native_try_from` were renamed and reversed. **This circuit's own path does not change**: because `tx_settlement.rs` reads `send_leaf.tx_tree_root` through the unchanged many-to-one `reduce_to_hash_out`, it still accepts byte sequences that the fixed conversion rejects (`native_settlement_accepts_bytes_the_fixed_try_from_rejects`). The native rejection of a non-canonical tx-tree root is still the `CanonicalRoots` premise, and the circuit side depends on `ToHashOutGates` |

**5. A safety catch in the registrar.** `register2.py` refuses implementation hash changes by default. We added a path for
explicitly accepting them with `--accept-source-change=<path>` only when, as in this case, a legitimate revision has taken place.
Hashes never move as a side effect of re-running it.

Verification: main guard PASS (125 modules / 72 current modules / 470 hashes), line guard PASS (169 maps),
51 regression tests, 40 fixture-parity tests and 18 fixtures / 177 items green, and `--require-complete` exits 1.
The line classification is translated 31,095 / untranslated 41,784.

### 2026-09-08 (addendum): introducing the MLE submodule as a trust assumption

By operator judgement, we decided to **trust rather than translate** the pinned MLE/WHIR submodule.
It is treated the same way as the KZG ceremony. This decision is recorded in the following 3 places and is not treated as a proof.

1. **A named premise in Lean.** `TrustBoundary.mleVerifierSoundness` (premise (a0)).
   It is the claim that if, against the pinned adapter, the EVM view's `verifyCompactPublicInputs` returned a word sequence, then
   that word sequence is the public input of a plonky2 statement of the circuit identified by the adapter's pinned circuit digest,
   and that statement is satisfiable. It is not an axiom; it is a structure field
   on a par with the other 12 premises.
2. **A scope note in the inventory.** MLE's 68 files and 33,974 lines continue to be classified **untranslated** and
   are not counted as verified. The line classification figures do not change before and after the introduction of the assumption.
3. **A commit pin in the manifest.** `contracts/lib/polygon-plonky2` is pinned to
   `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78`. The assumption extends only to this commit;
   another revision is a different, unaccepted artifact.

**What this assumption buys.** For the close path, the gap of premise (a) shrinks to a single step
(`mle_assumption_reduces_close_soundness_to_gate_lowering`). What remains is only
`CloseStatementLowering`, that is, the step that the plonky2 statement the digest identifies is the circuit this model describes and that
its satisfying assignment gives a witness for `CircuitGates`.
That requires gate generation and `CloseCircuit.FieldAndGadgetLowering`, and it is not proved.

**What this assumption does not buy (with kernel-verified counterexamples).**
`SystemSafety.mle_assumption_does_not_imply_fund_safety` gives an environment in which (a0) holds while
no instance of `TrustBoundary` exists. The adapter does accept and returns a
103-word close statement, but that channel claims 1 unit of a token it has not deposited, so
premise (c) breaks. `mle_assumption_alone_does_not_yield_close_gate_soundness` gives
an environment in which the lowering breaks. Neither is a vacuous assumption; both stand on an actual acceptance.

Still unproved: the lowering from circuit to gates, KZG / DA availability, that the public inputs the caller passes
represent a real channel, the backing of the close vector by deposits (c), signature validity (d),
hash agreement and binding (e1, e2), the L1 canonical head / finality (f1, f2),
storage persistence against unmodeled entrypoints (g1, g2), source / EVM / compiler refinement (h),
and the claim-side premises (b1, b2).

### 2026-09-08: translating the dependency and cryptography layers; 3 real test failures

- **125 Lean modules** built. The main guard and the line guard both succeeded, verifying **72 current modules**, **470 reviewed-source hashes**
  and **169 source maps**.
- Physical line classification: hand-written translation **31,085**, dependency boundary **10,850**, non-executable **9,816**,
  test-only **23,834**, untranslated **41,783**. Translation increased from 19,450 to 31,085 since the previous checkpoint.
- The added modules number 15 with roughly 1,790 theorems. They are the trees (Merkle / sparse / incremental / indexed),
  the ethereum_types codec, common's value types and channel.rs, the block-family types, the utils gadgets and constants,
  Falcon (aggregate / core / vendor), Regev (encryption / transfer STARK / hash signature), the tree instantiations and
  hash chains, and the MLE prover bridge.

**Premises that were derived from the implementation.**

| Premise | Result |
|---|---|
| nullifier freshness | `IndexedMerkleTree.accepted_insertion_implies_key_absent`. An accepted insertion proof implies the absence of the key. The premises are only three: collision resistance of Poseidon (injectivity of the leaf's 18-word encoding is proved), the ordered-set invariant (holds for the empty tree, preserved by insertion), and the range of the key. `insert_fails_iff_key_present` holds even without the hash assumption |
| The selection semantics of `select_vec` | `UtilGadgets.select_vec_one_hot_selects_candidate`. The 4-term sum-of-products selection that SwitchBoard had assumed is proved from the implementation. One-hotness, however, is not enforced by `select_vec` itself |
| Regev's constants and encoding | `RegevCore.constants_agree_with_decryption_gadget`. N=2048, q=2013265921 and Δ=(q−1)/256 agree with the circuit side. The amount encoding is injective over u64 |
| Tree heights and backing | `TreeInstances` fixes all 13 trees. There are zero numerical mismatches with the values pinned by already-registered modules |
| Constants | `UtilGadgets` pins every constant of constants.rs. There are zero mismatches with other modules' claims |

**3 failures of the repository's own tests (undetected because CI does not run `cargo test --lib`).**

1. **A real defect.** `common::channel_registration::tests::test_channel_reg_validate_rejects_noncanonical_identity_encodings` fails. The rejection of non-canonical identities in `ChannelRegRecord::validate` is unreachable, because `PoseidonHashOut::try_from(Bytes32)` is a total function that reassembles the same 32/32 split. The test asserts the correct intent; the defect is in the code. On the Lean side too,
   `ChannelRegChain.byte_round_trip_alone_cannot_reject` (formerly `native_canonicality_check_cannot_fail`) and
   `BlockTypes.canonicality_rejections_come_only_from_the_callback` had independently reached the same conclusion.
   **Fixed on 2026-09-09.** See the addendum below.
2. **Stale tests.** `common::balance_state::tests::balance_state_validate_multi_n` and
   `balance_state_delegate_count_regions_and_h1` assert that member_count 16 passes, but
   since `fd467ea` (restricting the sig-cluster to 8), 2..=8 is correct. The tests were not updated.
3. **The CI blind spot itself.** `.github/workflows/ci.yml` runs only the individual integration tests and never runs
   `--lib`. All 3 of the above fell into this blind spot. Note also that running the whole lib is SIGKILLed by OOM
   on the heavy circuit tests, so a split run excluding the measurement family is needed.

**The authorization chain established at the cryptography layer (human judgement required).**

- **The Falcon verifier does not exist in the vendor tree.** There are 0 occurrences of `fn verify` in `src/falcon_sig/vendor/`, and
  the verification lives in `mod.rs` and the circuit-side `batch.rs`. If 512 copies of the maximum coefficient 2047 that the decoder allows are lined up,
  the squared norm is about 2.15 billion, greatly exceeding `beta^2 = 34,034,726`
  (`FalconVendor.decode_range_does_not_imply_norm_bound`). The bound check is the caller's responsibility.
- **Whether the circuit gadget verifies a signature depends on a single wire that the gadget itself does not constrain.**
  If the wire is 1 it verifies the entire native predicate; if it is 0 only the key commitment and the algebraic relations remain, and
  the norm-bound check, which is the scheme's sole acceptance test, is replaced by a range check on the constant 0
  (`FalconCore.padding_slot_norm_gate_is_trivial`). close / cancel-close bind it to `member_count`.
- **An accepted aggregate proof shows neither distinctness of the signers nor membership in the member set.**
  It is proved that the signer count agrees with the number of slots actually accepted, that the key list is left-packed with the remainder strictly zero,
  and that all slots were evaluated against the same message
  (`FalconAggregate.agg_tree_ok_characterization`).
- **`range_check(count_minus_one, 4)` at `agg_list.rs:329` allows a signer count of 1 to 16.**
  The upper bound of 8 comes only from the structure of the aggregation circuit, not from this check.
- **A hash signature is a replayable token.** What verification establishes is only knowledge of a Poseidon2 preimage of the public value `pk_b` and
  the Fiat-Shamir binding of the message; the public value vector contains neither a nonce nor an expiry. Soundness requires
  the relying side to resolve `pk_b` from a registered member leaf and to make the IMPA digest unique and accept it at most once,
  and neither is enforced in the file in question.
- **The carry constraint family of the transfer STARK is sound over the integers.** `value(before) = value(after) + value(delta)`
  and the absence of underflow are derived from the field constraints (`RegevProofs.conservation_over_integers`).

**Other observations from the source.**

- There is no domain separation between leaves and nodes, and the roots of an empty SendTree and an empty TxV2Tree of height 32 agree without any hash assumption
  (`TreeInstances.empty_send_tree_root_equals_empty_tx_v2_tree_root`). Separation depends on the consuming circuit.
- The comment in `channel_tree.rs` says member_pubkeys_root is 1024 slots, but it is actually 8 slots at height 3.
- `validate()` in `channel.rs` constrains structure only, and passes even if the entire key set is substituted while keeping both roots
  (`ChannelTypes.validate_accepts_substituted_member_set`). The signature verifier does not react to the blob's contents.
- The domain non-collision check is test-only and disabled in release. On the Lean side we proved the non-collision of 63 values.
- `U32LimbTargetTrait::get_witness` silently truncates a field wire at 2^32.
- An out-of-range index update on a sparse tree records the leaf while leaving the root unchanged.
- The retired member-set-update path is not compiled in the default build (the `deprecated-msu` feature).
  However, this is a modeling of what the manifest says, not a claim that the path is safe.
- The comment in `agg.rs` says `AGG_LEVELS = 4` and 137 public inputs, but the code says 3 and 73.
  The assert message at `batch.rs:695` still says 137 as well, and that is the wording an operator reads when the assert fires.

### 2026-09-07: checkpoint of full core-file coverage, consolidation of the trust boundary, and composition over all entrypoints

- **110 Lean modules** built. The main guard succeeded, checking the existence, kind and transitive kernel axioms of
  **57 current modules and 2,839 named theorems**. The implementation correspondence is **52 modules and 2,620 theorems**, and
  the preceding specification side is 5 modules and 219 theorems. **1,566 theorems** were added since the previous `680146f`.
- The line guard succeeded, verifying **273 reviewed-source hashes, 1 MLE gitlink and 76 source maps**.
- In addition to the 51 guard regression tests (main 29 + line 22), the 40 fixture-parity regressions also succeeded.
- Physical line classification: hand-written translation **19,450**, dependency boundary **4,948**, non-executable **6,832**,
  test-only **13,927**, untranslated **72,211**. **All 71 core files have correspondence tables**
  (0 lines of uncovered core). All the remaining untranslated lines are on the dependency side: `src/common`, `src/utils`, `src/regev`,
  `src/falcon_sig`, MLE and so on. This is not a proof rate.

**Consolidation of the trust boundary.** [TrustBoundary](./Zkp/Implementation/TrustBoundary.lean) consolidates the unproved premises that had been
scattered across individual theorems' arguments into 12 named fields written in the types of the existing models.
They are close proof soundness, claim proof soundness, backing of the close vector by the channel's own deposits,
the signature validity oracle, hash binding for finitely many compared pairs, the L1 canonical head / finality,
a durable replay ledger, and source/EVM/compiler refinement. No axioms have been added.
We show inhabitation only in a degenerate environment where every verifier rejects, and we also state that in that environment
no fund movement whatsoever is authorized.

**Composition over all entrypoints.** [SystemSafety](./Zkp/Implementation/SystemSafety.lean) covers Rollup deposit,
withdrawNative / withdrawERC20, materializer credit, Manager pull, submitClaim,
claimCredit payout, close request / cancel / finalize, and rollback with 12 `Step`s, and proves the following
**with no premises** for any finite trace.

- `trace_conserves_per_token`: per-token conservation of `Rollup escrow + pending + Manager unspent`.
- `trace_channel_attribution`: that the Manager's `received` does not exceed its own channel's cap,
  that the cap is not rewritten, and that materialization is retained once latched.
- `trace_nullifier_single_use`: the persistence of a consumed nullifier and that resubmission necessarily fails.
- `trace_paid_bounded`: conservation of `paid ≤ received` and the paid / unspent decomposition of the conservation law.

The only thing that depends on premises is the jump from close / claim acceptance to circuit gate satisfaction
(`close_acceptance_binds_statement`, `claim_acceptance_binds_statement`).
**The remaining gap is made explicit by `close_vector_backing_is_exactly_premise_c`.**
Because the Rollup escrow is pooled, the part tying the cap to the channel's own deposited amount is still premise (c).

**Agreement between circuit and Solidity (4 of them).** Not a comparison between two hand-written models: we derived that the circuit-side
word / byte sequence agrees with the computation of the model of the Solidity implementation.

| Theorem | Content |
|---|---|
| `DepositChain.chain_matches_rollup_fold` | The deposit chain's fold agrees with `pendingDepositChain`. The byte agreement of the preimage is kernel-verified with no hash premise |
| `ChannelRegChain.chain_matches_rollup_fold` | The registration chain's 244-word preimage agrees byte for byte with `hashPreimage (.channelRegistration …)` |
| `ValidityChain.circuit_pi_layout_matches_solidity_preimage` | The 41-word, 164-byte public input agrees with `finalize`'s hash preimage |
| `WithdrawalChain.circuit_layout_matches_rollup_verifier` | The 17 words agree with `verifyWithdrawalSet`'s recomputation. It also derives that the limb mask is equivalent to `% 2^253` |

**Refinement evidence from real fixtures.** [fixture-parity](./fixture-parity.md) and
`.github/ci/lean-fixture-parity.py` run the Lean codecs on actual prover fixtures and compare them field by field against the
Rust / Solidity values. 18 fixtures and 177 items agree, with 0 mismatches.
The 17-word withdrawal public input agrees along 4 routes: the Lean decoder, the Lean model of the Solidity helper, the prover's registered words,
and a keccak recomputation in Python. **This is not a proof of refinement; it is evidence that
the hand-written model and the real output agree.**

**Modeling of the replay ledger.** [SignatureReleaseLedger](./Zkp/Implementation/SignatureReleaseLedger.lean)
targets the wallet-side `hosting/wallet/signature-release-ledger.mjs` and proves that signatures for different successors are not published
for the same (signer, channel, previous digest), and that a retry reproduces the stored bytes.
A different device, a different store, storage erasure and IndexedDB durability remain premises.

### Observations found on the source side (items requiring human judgement)

All of them are fixed as theorems and are not demonstrations of vulnerabilities.

1. **The channel tree does not enforce fund conservation across blocks.** `ChannelLeaf` has no fund vector, and
   the published channel-tree root is unchanged even if the IMCH preimage is substituted wholesale
   (`UpdateChannelTree.native_account_root_ignores_channel_state_fields`).
2. **No signature is verified at all in `update_channel_tree.rs`.** Neither the N-of-N Falcon aggregate nor the BP signature is
   verified; there is only the fold into `bp_sig_chain`. Proving existence is the responsibility of a recursive proof of a different circuit.
3. **Matching up inter-channel transfers is not done on the block side.** The channel-tree index opened is only the one from
   `block.channel_id`, and `destination_channel_id` is never read by anything.
4. **In the first of the block steps, the initial public state and the cyclic verifier key are free witnesses**, and
   the timestamp is unconstrained too (`BlockStep.gates_first_step_verifier_key_is_free` and others).
5. **The canonicality check in `ChannelRegRecord::validate` is unreachable.** It never failed, because `try_from` reassembles the same 32/32 split
   (`ChannelRegChain.byte_round_trip_alone_cannot_reject`). Fixed on 2026-09-09.
   A non-canonical identity fails at proving time rather than at witness construction time.
6. **The member recipient is not constrained on the circuit side.** There exists a satisfying witness that assigns an arbitrary recipient without changing
   `member_pubkeys_root`, and the only binding is agreement with the L1 chain.
7. **`test_utils` in `src/circuits/mod.rs` is a public module without cfg(test)**, and the harness's deterministic
   Falcon key derivation is reachable from production (`CrateLayout.test_utils_not_test_only`,
   `WitnessGenerators.harness_key_material_is_production_reachable`). The key is a pure function of the public channel id,
   and the slot encoding collides at 256 (`assert!(slot < 255)` is what prevents it).
8. **The native check of the transfer witness has no range check on the index**, and index and index+64 are not distinguished.
   The 6-bit boundary exists only on the circuit side. **The transfer's token index is not range-checked in the circuit either.**
9. **A user-id recipient commits to only 248 bits, because the tag overwrites the high byte of the Poseidon output.**
10. **The block-number comparison differs between native and circuit.** The native side of send_tx / tx_settlement allows
    `tx_block_number >= block_r`, while the circuit imposes a strict `>` (a mismatch on the prover side).
11. **`U63Target::enforce_ge` is not an ordering check at the top of the domain** (it accepts 0 on the low side and `2^63-1` on the high side).
    The ordering holds when the lower operand is at most `2^63 - 2^32 + 1`.
12. **`withdrawal_prover` is not included in the 17-word public input** and is bound only via the keccak preimage.
    Also, the contract rejects an empty withdrawal set, but the circuit does not.


### Since `e604a36`: the Balance / state-update / decryption-gadget checkpoint

- **89 modules** built; the main guard succeeded, checking the existence, kind and transitive kernel axioms of
  **36 current modules and 1,273 named theorems**. **278 theorems** added since the previous time.
  The implementation correspondence is **31 modules and 1,054 theorems**, and the preceding specification side is 5 modules and 219 theorems.
- **156 reviewed-source hashes, 1 MLE gitlink and 29 source maps** verified.
  The line guard succeeded, with all correspondence tables' declaration references confirmed by the Lean compiler.
- **51** guard regression tests (main 29 + line 22). The diff in
  `src`, `contracts`, `Cargo.toml` and `Cargo.lock` against the runtime baseline `05ec7ae` is zero. The MLE submodule is clean.
  No benchmarks were run, and the runtime / proof parameters / proof format are unchanged.
- Physical line classification: hand-written translation **9,632**, dependency boundary **2,438**, non-executable **5,476**,
  test-only **6,738**, untranslated **92,913**. Because this includes moving 1,587 `cfg(test)` lines of `state_update_verifier.rs`,
  221 lines of `decryption_gadget.rs` and 223 lines of `switch_board.rs` into test-only,
  the decrease in untranslated cannot be converted into "executable lines proved safe."

The 8 modules added this round are hand-written semantic models of Balance's public inputs / switch board / outer circuit,
the private / public state updates, the channel state-update verifier and the decryption gadget.
Each module received an independent review, and the following were fixed. These are corrections to the model's precision, not
reports of newly discovered vulnerabilities in the implementation.

- The 7 output theorems of `ChannelStateUpdate` relied on peeling binds with `apply`, but
  when the last `apply` failed the unifier unfolded `List.range slotCount` (1024 elements) and fell into
  near-infinite recursion (over 19 GB of memory). We replaced them with proofs that rewrite the acceptance hypothesis into a conjunction with
  `bind_ok_iff`, and handle the do-notation join points (burn / non-burn, presence or absence of a receiver) with `split`.
  The "standalone compilation success" of the previous handoff could not be reproduced, and 3 proofs such as
  `first_index_found` also needed fixing. The whole thing compiles in 4 seconds.
- `ChannelStateUpdate.channelTxDigest` was narrowed to take only the same
  7 inputs as the original implementation's `ChannelTx::signing_digest` (a callee that cannot read the signature fields). The unused
  `validateRecord` was deleted, and the work is delegated to `record.validate()` inside `validate_member_signature_slots`.
  We made a theorem of the fact that acceptance of send / fund import forces the transport envelope's proof bytes to be empty
  (a source observation, not a soundness claim).
- We added to `DecryptionGadget` the composition theorem
  `core_row_integer`, which derives each row's integer equations (reduction, key binding, decryption, digit decomposition) from
  `CoreGates` / `Representatives` / `FieldProducts`. It shows the digit-255 boundary to be unsatisfiable as a gate, and
  the `omega` failure in `native_key_halves` was resolved by case-splitting on the sign.
  The satisfying example with an all-zero assignment is explicitly marked in its name as not being a production trace.
- The native / target ordering agreement of `PrivateState` had been `rfl` on the same definition, but
  it was changed to transcribe `to_u64_vec` and `to_vec` separately and compare them. The identity of `AssetTree::init` and
  `AssetTree::new(height)` is stated explicitly as a premise.
- `UpdatePrivateState` had the nullifier gadget's call relation renamed so it is not misread as "insertion," and
  a vacuity guard was added that constructs, from the native success path, a witness satisfying the local gate family.
  The agreement of native/target U256 remains an explicit premise.
- `SwitchBoard` now states explicitly that HashMap duplicates (which serde collapses last-wins) and ordering, and the identity of the prove-time
  cap count with the constructor config, are not proved.

`--require-complete` should continue to fail. The semantics of the decryption oracle, uniqueness of the secret key,
cryptographic validity of the signatures, the replay ledger, L1 finality, Rust / gate / EVM refinement, and
asset ownership including all entrypoints are unproved.

### Since the previous `9a67d8e`: checkpoint of cancel / claim / common H1 / the Solidity connection (history)

- **81 modules** built; the main guard succeeded, checking the existence, kind and transitive kernel axioms of
  **28 current modules and 995 named theorems**. **234 theorems** added since the previous time.
  The implementation correspondence is **23 modules and 776 theorems**, and the preceding specification side is 5 modules and 219 theorems.
- **133 reviewed-source hashes, 1 MLE gitlink and 21 source maps** verified.
  The line guard succeeded, with all correspondence tables' declaration references confirmed by the Lean compiler.
- **51** guard regression tests (main 29 + line 22). The diff in
  `src`, `contracts`, `Cargo.toml` and `Cargo.lock` against the runtime baseline `05ec7ae` is zero. No comparative measurement of proof size or
  time was carried out, and neither the benchmarked code nor the proof parameters were changed.
- Physical line classification: hand-written translation **6,686**, dependency boundary **1,666**, non-executable **4,593**,
  test-only **4,542**, untranslated **99,710**. Because this also includes reclassification of tests and comments,
  this decrease cannot be converted into "executable lines proved safe."

The composition this round starts from comparing **the same adapter, proof and return value**. We tied Solidity's
103 / 29 / 50 / 57 words for close / cancel / withdrawal / post-close to all fields of the respective circuits.
For the 48 bytes of IMCS and the 368 bytes of IMTF for the whole token vector, rather than simply assuming
"they should be the same," we derived the agreement from integer decomposition and the injectivity of the byte encoding.
We do not assume that `CircuitGates` can be extracted automatically from adapter acceptance; that is still a separate premise.
Therefore this is **not an end-to-end proof including the cryptographic verifier**.

In H1 we connected the ordering of the 37-element header and the 104-element leaf across the common helper and each claim's call site, and
derived the canonicality and uniqueness of the 32/32 split from the local equations of Goldilocks split / equality indicator / multiplication /
assert-zero. The native `TryFrom<Bytes32>` is a restoration of raw u64s and a byte round trip, and it is not
the same check as the target `to_hash_out`'s modular reduction + canonical encode-back.
We have not erased this difference in the proofs.

In cross-review we added a fix to the previous CloseCircuit's native member helper to reflect the padding mask **after** the u8 cast.
Even for oversized lists that ordinary admission would not permit, the auxiliary function's definition was
aligned with the original implementation. It is not a runtime fix nor a demonstration of a theft path.
We also fixed direct references from a correspondence table to another module, the handling of imports / derives, and confusion between
feature fixtures and `cfg(test)`, and re-verified without loosening the strict guard.

What is centrally still missing is the real processing of decryption and state update, all Balance / validity paths, soundness from proof
acceptance to real gate constraints, Rust/Solidity/EVM refinement, and the composition of asset ownership, physical custody and
reachability of a normal exit across all Managers and all entrypoints. This is not overall completion or a release approval.

### Integrated verification of the previous `9a67d8e` (history)

- **71 Lean modules** built. The existence, theorem kind and transitive kernel axioms of
  **18 current modules and 761 named theorems** were confirmed, and the main guard succeeded.
  The implementation correspondence and composition is **13 modules and 542 theorems**, and the preceding specification side is 5 modules and 219 theorems.
  **216 theorems were added** since the previous `85f243b`. The counts are not a proof rate for the whole implementation.
- **106 reviewed-source hashes, 1 MLE gitlink and 12 source maps** verified.
  The source maps' declaration references were also confirmed by the Lean compiler, and the line guard succeeded.
- **51** guard regression tests succeeded (main 29 + line inventory 22).
- `git diff --check` succeeded. The diff in `src`, `contracts`,
  `Cargo.toml` and `Cargo.lock` against the runtime baseline `05ec7ae` is zero. The MLE submodule's working tree is clean too.

The physical line classification of the current inventory is hand-written translation **4,824**, dependency boundary **1,124**,
non-executable **3,686**, test-only **1,530** and untranslated **106,033** lines.
Comments and tests of uncovered files are also counted as untranslated. This is not a test pass rate or
a residual vulnerability rate.

**`--require-complete` should continue to fail.**
Proofs for every line and every fund flow, Rust / Solidity / gate / EVM refinement, and verification of the cryptographic and
execution-environment premises are not achieved. We have not filled the unproved parts with admissions or an "acceptance ⇒ safe" assumption,
nor have we loosened the completion check. Unproved does not immediately mean an actually existing vulnerability, but
it cannot be used to certify that "theft and loss are impossible."

### Verification results of the previous `85f243b` (history)

The following are the results of the previous commit and are not the latest counts including the added implementation.

- Successful build of **67 Lean modules** including the existing ones.
- Successful compiler / transitive-axiom check of **14 current modules and 545 named theorems**.
  Of these, this round's implementation correspondence is **9 modules and 326 theorems**. The preceding side is 5 modules and 219 theorems.
- The **97 files** of the reviewed-source manifest and the MLE gitlink verified.
- Successful check of the original line spans, the whole-source inventory and the Lean declaration references of **9 source maps**.
- **45 guard regression tests succeeded** (23 existing + 22 line inventory).
- **28 local links** in the updated index and report confirmed.

The physical line classification of the previous inventory is hand-written translation 2,485, dependency boundary 562, non-executable 2,368,
test-only 512 and untranslated 111,270 lines. It is a coarse classification that also counts the comments and tests of uncovered files as
untranslated, and it does not mean that 67 modules or 545 theorems cover all of this.

Lean 4.10.0 is used from each project's `lean-toolchain`. Do not claim to have verified by starting
a different default Lean at the repository root.

```sh
python3 -B .github/ci/test-lean-safety-guard.py
python3 -B .github/ci/test-lean-line-coverage.py
bash .github/ci/lean-safety-guard.sh
python3 -B .github/ci/lean-line-coverage.py
```

`lake` must be on PATH. The guard builds both Lean projects and checks, for every named theorem of the current modules,
the theorem kind and transitive axioms in the compiler environment.
The line guard checks source additions and changes, the whole-line spans, the referenced declarations, and the list of uncovered files.

A PASS from `lean-line-coverage.py` is **only about the consistency of the inventory and links**.
`--require-complete` fails deliberately with the current, incomplete model. This schema has no
form for a source-refinement certificate at all, and no capability to certify the safety of every line.

## What is needed to continue

0. **The correspondence tables for the 71 core files and the main parts of the dependency side are complete.** 41,783 lines are untranslated,
   and most of them are the MLE submodule (just under 34,000 lines), which has been accepted as a trust assumption (premise (a0)). The remaining main work is that, plus
   fixing the unreachable canonicality check in `channel_registration`, updating the 2 stale tests in `balance_state`,
   and adding `cargo test --lib` to CI.
1. (history) Translating the rest of the dependency side. Until the implementations of Poseidon / keccak / Merkle / Falcon / Regev replace the current opaque callbacks,
   hash binding and signature validity remain premises.
1. (history) Add hand-written translations of the remaining validity / deposit / transfer / withdrawal circuits and of Balance's send / receive circuits.
   The bodies of `state_update_verifier.rs` and `decryption_gadget.rs`,
   Balance's PIs / switch board / outer circuit, and the private / public state updates have been added, but
   the Manager / Rollup ABI, callbacks and generated getters, the proof over all reachable states, and
   feature-gated fixture generation remain untranslated and unproved.
2. Translate each of the Balance / validity / deposit / transfer / withdrawal circuits with native admission and
   an arbitrary satisfying witness kept separate. Do not treat Spend alone as proving sending and receiving as a whole.
3. Derive the local guarantees of U256, Merkle, Keccak/Poseidon, signature / decryption, and the recursion / pinned proof verifier from the
   implementation rather than leaving them as they are in the theorems' arguments. H1's canonical split has been derived from local
   modular equations, but the proof of the primitive gate implementations is not complete.
4. Build a refinement into the hand-written Lean models for Solidity execution including calldata / ABI / revert / reentrancy / checked arithmetic, and for the
   real gate sequence of the Rust builder.
5. Connect each slice into a single state transition system and show, over an arbitrary trace, that per token "deposited funds = unspent funds + exited amount",
   together with separation by channel / nullifier / generation.
6. Separately from safety, show that under conditions where the retained last signed H, the proof/config and DA are available,
   a normal exit is reachable without an additional channel signature. Do not fabricate L1 inclusion / gas / finality /
   storage availability out of mathematical conservation laws.

Until every item is finished, do not cite the tables or a successful build as "a proof over the whole implementation that funds cannot be
stolen or lost."
