# Task: Replace SPHINCS+ with a Poseidon2-preimage ZK signature

Status: P1 + P2a + P2b-0 COMPLETE. **P2b-1/2/3 IN PROGRESS** (this session) — the atomic
identity-swap + validity/close list-proof wiring.

Branch: `paymentchannel-delegate`. Threat model: `tasks/poseidon-signature-threat-model.md`.

LOCKED decisions (do not deviate):
1. pk_b DEFERRED to P3. `MemberLeaf` is a PURE RENAME `sphincs_pk_hash` -> `pk_g` (same type,
   same leaf-hash preimage, same registration keccak). No new field.
2. One shared SingleSig/List family for validity (IMSB) and close (IMCH); isolation via message
   domain separation.
3. Validity empty-span = CONDITIONAL verify gated on COMPUTED `final.bp_sig_chain != 0`.
   When non-zero: verify list proof AND assert `C == final.bp_sig_chain`. Also assert
   `initial.bp_sig_chain == 0`. Use `add_proof_target_and_conditionally_verify`.
4. Close folds C' over active slots only (select prev on padding).
5. Exactly ONE IMSB sig per signing block (the bp's; should_verify_sig true only for bp slot).

## Plan (falsifiable steps)

### Phase A — primitive plumbing (foundational, low risk)
- [ ] A1. `key_tree.rs`: rename `MemberLeaf.sphincs_pk_hash` -> `pk_g` (field + target + accessors),
      leaf preimage byte-identical.
- [ ] A2. `channel_registration.rs`: rename `sphincs_pk_hash` -> `pk_g`, keccak preimage identical.
- [ ] A3. `common/channel.rs`: rename all `*sphincs_pubkey_hash*` -> `*pk_g`, preserving prefixes
      (`member_`/`bp_`/`sender_`/`recipient_`/`source_`/`receiver_`/`offending_bp_`). Keccak identical.
- [ ] A4. Ripple renames across close_pis, cancel_close_pis, post_close_claim_pis,
      withdrawal_claim_pis, balance_state, state_update_verifier, channel_tree, constants,
      channel_reg_step/processor, e2e_flow, wallet_core, wasm_wallet, bins.

### Phase B — validity accumulator threading (soundness-critical)
- [ ] B1. `ext_public_state.rs`: add `bp_sig_chain: Bytes32` mirroring `channel_reg_hash_chain`
      end-to-end (struct, target, len, to_u64_vec, from_u64_slice, new/constant/set_witness/
      connect/select/to_vec/from_slice). LEN += BYTES32_LEN.
- [ ] B2. `update_channel_tree.rs`: remove SPHINCS+ verify_circuit + SpxSig plumbing. Keep
      MemberLeaf{pk_g, regev_pk_digest} slot inclusion, IMSB signed_digest recompute, tx_tree_root!=0.
      Only the bp slot signs: fold leaf=leaf_target(signed_digest, bp_pk_g);
      new_bp_sig_chain = should_verify_sig ? chain_step_target(prev, leaf) : prev. bp_pk_g/
      signed_digest are the SAME wires bound to member_pubkeys_root/tx_tree_root. Surface
      prev/new bp_sig_chain in UpdateUserPublicInputs(+Target).
- [ ] B3. `block_step.rs`: thread prev/new bp_sig_chain through ext-state (mirror reg chain).
- [ ] B4. `block_chain_pis.rs` / `block_hash_chain_circuit.rs` / processor: thread; initial=0.
- [ ] B5. `validity_circuit.rs`: conditionally verify ListCircuit proof gated on
      final.bp_sig_chain!=0; assert C==final.bp_sig_chain; assert initial.bp_sig_chain==0.
      ListCircuit vd is a build-time constant.

### Phase C — close wiring (soundness-critical)
- [ ] C1. `close_circuit.rs`: remove per-slot verify_circuit. Recursively verify a ListCircuit proof;
      rebuild C' folding (IMCH state_digest, pk_g_i) over active slots only (select prev on padding);
      assert C'==C; assert pk_g distinctness over active set. Keep member_set_commitment keccak.

### Phase D — registration + e2e + signing
- [ ] D1. Registration: build MemberLeaf{pk_g, regev_pk_digest} from registered pk_g.
- [ ] D2. e2e/signing: replace SPHINCS+ keygen+sign with GoldilocksSecretKey. Per signing block
      produce bp SingleSig proof over IMSB digest; aggregate into one ListCircuit proof threaded into
      validity. For close produce N member SingleSig proofs over IMCH; aggregate into one ListCircuit.
- [ ] D3. Solidity `ChannelSettlementManager.sol`: rename semantics only; keccak byte-identical.

### Phase E — build/test
- [ ] E1. cargo build --release green.
- [ ] E2. channel + validity lib tests + e2e green. (NO Groth16/gnark.)

## STATUS: P2b COMPLETE — implementation + green tests + independent security review PASSED

Independent security review (separate agent, read-only diff vs afd500d): **NO real soundness hole**
within P2b's locked scope. All 8 attack vectors OK; all 5 flagged uncertainties confirmed/dispositioned.
Verified: accumulator ≡ `list_commitment` bit-for-bit; conditional-verify gated on the COMPUTED
`bp_sig_chain` (not a prover flag) with `initial==0` and `C==final` asserted; both old SPHINCS+ bindings
survive (signer ∈ member tree AND signer actually signed the exact domain-separated message, now via the
recursively-verified ListCircuit); close `C'==C` + active-set distinctness + `member_set_commitment`
byte-identical to L1; IMSB/IMCH domain separation prevents cross-consumer replay (A4). `bp_sig_chain` is
bound into `ValidityPublicInputs` (on-chain). Added a greppable `// INVARIANT (single-fold soundness)`
note at the bp-slot assertion per the reviewer's regression-guard recommendation. Tests re-run by the
main agent: all scoped lib modules green + full `cargo test --test e2e` 1/1 (114s).

Phases A–E all done. Lib builds clean; all scoped tests green:
- poseidon_sig 25/25; update_channel_tree 3/3; validity_circuit 1/1; block_step 1/1;
  channel_reg 3/3; channel native 14/14; close_circuit 9/9; e2e_flow 12/12;
  state_update_verifier 9/9; balance_state 8/8; `cargo test --test e2e` 1/1.
- Solidity: forge build clean; reg-preimage + member-set differential tests pass (byte-identical).
- Groth16/gnark fixture tests intentionally NOT run (project rule).

## Soundness uncertainties / pressure points (for separate security review)
1. `bp_member_slot == updating slot` assumption: the circuit asserts (gated on should_verify_sig)
   that the updating slot index == msg_fields.bp_member_slot, relying on the invariant that exactly
   ONE slot updates per block (all slots reference the same channel leaf). If a future block layout
   allowed two distinct channel leaves to update in one block, the single-fold accumulator would
   miss the second signature. CURRENTLY SOUND under the one-channel-leaf-per-block model; flagged.
2. Close C' rebuild uses `select prev on padding` and verifies the ListCircuit unconditionally via
   `_true`. A close always has >=2 active members so C != 0; if member_count could be 0/1 the empty
   list (C==0, no proof) would be unrepresentable — but member_count is range-checked 2..=MAX.
3. The validity gate `final.bp_sig_chain != 0` assumes the empty list commits to exactly
   Bytes32::default(). `list_commitment(&[])` = PoseidonHashOut::default().into() = zero — confirmed
   by `current_bp_sig_chain` over empty events. A (vanishingly unlikely) Poseidon collision to zero
   on a non-empty list would skip verification; standard Poseidon preimage assumption covers this.
4. No new domain separation gap found: IMSB digest (validity) vs IMCH digest (close) differ by their
   keccak domain bytes, and each consumer matches the exact m it computed (A4 holds).
5. pk_b deferred to P3 (LOCKED): MemberLeaf is a pure rename; no two-key binding yet. A11 is a P3
   obligation, explicitly out of scope here.
