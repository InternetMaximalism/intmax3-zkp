# CLAUDE.md

## Workflow Coordination

### 1. Default to Planning Mode
- Switch to planning mode for every non-simple task (those with 3 or more steps or design choices)
- If issues arise, halt and revise the plan immediately — never force progress
- Apply planning mode to verification and confirmation processes, not just construction
- Draft thorough specifications in advance to eliminate ambiguity
- **For any change touching proof logic, cryptographic protocols, or security-sensitive components: write a full threat model before writing any code**

### 2. Subagent Approach to Maintain Clear Main Context
- Delegate investigation, discovery, and parallel evaluations to subagents
- For complex or ambiguous issues, allocate additional reasoning through subagents
- Assign a single responsibility per subagent for concentrated, focused analysis
- **Use dedicated subagents for security review — separate from the implementation subagent. Never let the same subagent both implement and security-review its own work**
- Spin up an explicit "attacker subagent" for any protocol-level design or change (see §Adversarial Thinking)

### 3. Task Oversight
1. **Prioritize Planning**: Document the strategy in `tasks/todo.md` with verifiable, falsifiable elements
2. **Approve the Plan**: Consult the user before beginning execution
3. **Monitor Advancement**: Check off elements as they are completed
4. **Clarify Modifications**: Provide a high-level summary at each phase
5. **Record Outcomes**: Include an assessment in `tasks/todo.md`
6. **Log Insights**: Update `tasks/lessons.md` after adjustments — but never suppress a security concern to reduce "interruption frequency"

---

## Security-Critical Mindset

### The Core Principle
**"It works" and "it is secure" are entirely different claims.** Never conflate them. A passing test suite is not evidence of cryptographic soundness. When in doubt, stop and surface the question to the user — this is always the correct action.

### 1. Critical Security Thinking
- Before declaring any task complete, explicitly ask: *"What could go wrong if an adversary sees this output / controls this input / replays this message?"*
- Treat every assumption as a potential vulnerability until it is justified
- If you cannot articulate the security argument for a design decision, do not proceed — escalate to the user
- Complexity is not an excuse to skip security reasoning; if something is hard to analyze, that itself is a security concern
- **Never silently work around a failing security check. A failing check is a signal, not an obstacle.**

### 2. Adversarial Thinking (Attacker Subagent)
For every protocol design, proof system change, or cryptographic interface, spawn a dedicated subagent with the following mandate:

```
You are an adversary. Your goal is to break soundness, completeness, or zero-knowledge.
Enumerate:
  - Malformed inputs the prover or verifier might accept incorrectly
  - Transcript manipulations that bypass Fiat-Shamir binding
  - Evaluation point collisions or reuse across sub-protocols
  - Batch opening attacks (e.g., linear combination forgery)
  - Missing domain separation that allows cross-protocol attacks
  - Timing or side-channel leakage in non-constant-time code
Report every suspicion, no matter how speculative.
```

This subagent's output must be reviewed before any implementation is merged.

### 3. Cryptographic Invariant Checklist
Before completing any task that touches cryptographic code, verify **all** of the following. If any item cannot be confirmed, stop and report.

**Fiat-Shamir Transform**
- [ ] Every message included in the proof is also absorbed into the transcript, in the correct order
- [ ] The transcript is domain-separated (protocol ID, version, context string)
- [ ] No value is used as a challenge before it is derived from the transcript
- [ ] The challenge derivation is deterministic and not reused across invocations

**Polynomial Commitment Binding**
- [ ] The evaluation point used in the commitment proof is the same point derived from the verifier's challenge (e.g., from sumcheck output) — not a separately derived point
- [ ] Batch opening random scalars are freshly derived and not reused across protocols
- [ ] The commitment scheme is binding: the prover cannot open to two different values at the same point

**Sumcheck Protocol**
- [ ] The claimed sum matches the polynomial being proved
- [ ] The verifier's random challenges at each round are derived after the prover's message for that round
- [ ] The final evaluation is verified against an external oracle (e.g., WHIR), not trusted from the prover

**Permutation / Copy Constraints**
- [ ] The grand product or multilinear permutation argument covers all wires
- [ ] β and γ challenges are derived after all wire commitments are fixed
- [ ] "Next row" semantics are correct for the chosen arithmetization (univariate vs. multilinear)

**Fiat-Shamir × Commitment Binding**
- [ ] The evaluation point `r` and the commitment opening are bound to the same transcript
- [ ] There is no gap where the prover can choose the evaluation point after seeing the commitment randomness

**General**
- [ ] No cryptographic primitive is implemented from scratch — use audited libraries
- [ ] All randomness comes from a cryptographically secure source, explicitly documented
- [ ] Security parameter choices are documented and approved, never changed silently

### 4. Test Coverage: Always Maximize Patterns
- **Correctness tests** are necessary but not sufficient — they do not cover adversarial inputs
- For every function, write tests in the following categories:
  1. Happy path (expected valid inputs)
  2. Boundary cases (empty, max-size, all-zeros, all-ones)
  3. **Malformed prover behavior** (wrong evaluation, tampered commitment, replayed transcript)
  4. **Cross-protocol confusion** (reused challenges, mismatched evaluation points)
  5. **Randomized / property-based tests** — generate hundreds of random valid and invalid instances
- Aim for test patterns that **would catch a subtle soundness bug**, not just implementation bugs
- Use parameterized tests to run the same security check across multiple field sizes, curve parameters, or protocol variants
- Document what each test is *intended to prove about security*, not just what it checks mechanically

### 5. Unexpected Test Results → Security-First Hypothesis
When any test produces an unexpected result:

**Default hypothesis: this is a security problem, not an implementation bug.**

Follow this protocol before attempting a fix:
1. **Do not modify the test** to make it pass
2. Ask: *"Could an adversary trigger this condition intentionally?"*
3. Ask: *"Does this reveal an incorrect assumption in the security argument?"*
4. Document the unexpected result in `tasks/todo.md` with the security hypothesis
5. Spawn a subagent to analyze the failure from an adversarial perspective
6. **Only after ruling out a security issue** proceed to treat it as a normal bug

If the root cause is unclear after analysis, **stop and report to the user** with a full description of the unexpected behavior and the hypotheses considered.

---

## Fundamental Guidelines

- **Security over Speed**: A correct incomplete implementation is always preferable to an incorrect complete one
- **Escalate, Don't Patch**: If a fix to a cryptographic component is not fully understood, do not apply it — surface the question
- **No Unauthorized Heavy Computation**: Never run model training, large-scale tests, or heavy computation without explicit user permission
- **Limited Scope**: Changes must affect only what is necessary; prevent introduction of new attack surface
- **No Silent Workarounds**: Never disable, skip, or weaken a security check to make progress. Always escalate

---

## Documentation Standards

- **All documentation, comments, commit messages, and notes must be written in English**
- Security assumptions must be stated explicitly in comments adjacent to the code that relies on them
- Every cryptographic protocol step must reference the corresponding line in the specification or paper
- When a design decision has a non-obvious security rationale, document it inline: `// SECURITY: ...`
- When a piece of code is intentionally left simple to minimize attack surface, note it: `// INTENTIONALLY SIMPLE: ...`
