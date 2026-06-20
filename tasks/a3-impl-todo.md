# A-3 本実装 進捗トラッカ

仕様: `tasks/a3-close-lifecycle-spec.md`(承認済み・全スコープ)
ブランチ: `fix/audit-soundness-and-tests`(A-2 等と同ブランチ)

承認決定: ①on-chain anchor チェックあり ②全部実装 ③liveness grief は明記のみ

## P1 — 実 L1-close anchor ✅
- [x] 脅威モデル(attacker subagent)— Threat 1-9 列挙。anchor は fund-safe(Option B)、real custody は既存 withdrawal gate(IntmaxRollup.sol:1262)が担保
- [x] PART A: `setup-backing` が `latestFinalizedStateRoot()` を取得→`ChannelBacking.intmax_state_root` に格納、placeholder 廃止、zero 時は警告(liveness 明記)。コンパイル OK
- [x] **PART B は不採用(ユーザー決定 A)**: EIP-170(IntmaxRollup margin 10B、getter ~70B 不可)+ 既存 withdrawal gate と冗長(資金安全に寄与せず)。→ Solidity 変更なし=close fixture 再生成不要、forge 全緑のまま
- [x] テスト回帰なし(setup-backing を駆動する自動テストは存在しない=relay/demo のみ live。anchor 動作確認は P5 E2E)
- 注: anchor 動作の live 確認は P5 の完全 E2E に委譲

## P2 — wallet_core close ビルダ
- [x] 脅威モデル(attacker subagent)— 下記「P2 精密設計」に結論を反映

### P2 精密設計(脅威モデル確定済み、実装ガイド)

**新規 `CloseProver`(wallet_core.rs、非テスト):**
```
pub struct CloseProver { single_sig: &'static SingleSigCircuit, list: ListCircuit, close_circuit: ChannelCloseCircuit<F,C,D> }
CloseProver::new(balance_vd: &VerifierCircuitData) -> Self   // list = ListCircuit::new(single_sig.vd); close = ChannelCloseCircuit::new(balance_vd, list.vd)
```
- `single_sig_circuit()`(L204, 既存共有)を流用。`list_circuit()` も共有 OnceLock 化可。

**`build_close_full_witness(state, member_keys[N], balance_proof, close_nonce, burn_tx_hash, snapshot_mbn) -> ChannelCloseFullWitness`:**
- close_tx = CloseWithdrawal{ channel_id, final_channel_state_digest=state.digest, final_balance_state_h1=state.balance_state.h1(), intmax_state_root=state.channel_fund.intmax_state_root, burn_tx_hash, burn_amount=state.channel_fund.amount, zkp=vec![] }
- close_intent = CloseIntent::new(close_nonce, &state, &close_tx, snapshot_mbn)?  ← **既に fail-closed 束縛検査内蔵**(channel_id/digest/h1/anchor/amount)
- member_auth + list_proof: 各 member_keys[i] で `single_sig.prove(signing_key, state.digest)` → `list.prove_append(&sig, list_commitment(pairs[0..i]), &prev)` を slot 順に fold(fixture::member_auth_for_digest_n と同型、実鍵版)
- **Rust fail-closed 前提(脅威モデル):** 2≤member_count≤MAX、member_keys.len()==member_count、state.digest 計算済み、h1 一致、unallocated_confirmed_incoming==0、pk_g 全 distinct、balance_proof の channel_id/settled_tx_chain が close PI と一致

**`prove_close(full_witness) -> close_proof` = close_circuit.prove(&w)**(member_set_commitment は prove が正値で上書き=tamper 不可)

**`prove_close_mle(close_proof) -> (mle_json, CloseProofFields)`** = WrapperCircuit + setup_mle_vk + prove_with_mle + export_mle_json(generate_close_fixture.rs と同手順)

**IN-CIRCUIT soundness(ビルダが迂回不可、脅威モデル確認済み):** H1/IMCH 再計算束縛、balance proof の channel_id/settled_tx_chain 束縛、ListCircuit C'==C(実署名)、member_set_commitment keccak、active_bits、member pk_g distinct。

**`build_withdrawal_claim(final_balance_state, member_index, regev_sk, recipient) -> claim+proof`:** amount は decryption_core で復号値に in-circuit 束縛(over-claim 不可)、regev pk は H1 commit に Poseidon 束縛。前提: member_index<active、復号 amount 一致、pk digest 一致。
**`build_cancel_close(revived_state, close_intent)` / `build_post_close_claim(...)`:** 同様に既存回路へ配線。

- [x] **CloseProver(new + build_full_witness + prove + close_vd)実装、実証明テストで検証 PASS(48.9s)**。build→prove→verify が通り、negative(鍵数不一致→Err)も。全 public 型を un-gate なしで使用、CloseIntent::new が binding を fail-closed 検査。
- [x] **prove_mle(WrapperCircuit + MLE export、generate_close_fixture 同手順)実装、コンパイル OK**(MLE self-verify 込み。ランタイム検証は P3 の close fixture 生成 or 専用テストで)
- [x] **build_withdrawal_claim(WithdrawalClaimProver)実装、実証明テスト PASS(14.3s)**。slot 復号→amount 導出、E-3 + claim 回路で証明・検証、amount==復号値(over-claim 不可)、padding slot 拒否。wrap+MLE は共有 `wrap_and_export_mle` ヘルパに切り出し(CloseProver も使用)。
- [x] **build_cancel_close(CancelCloseProver)実装、実証明テスト PASS(12.2s)**。revived state の IMCH に member 署名 + list fold、revived_version > close_version の前提を fail-closed、stale 状態 negative。
- [x] **build_post_close_claim(PostCloseClaimProver)実装、実証明テスト PASS(13.7s)**。source_tx から delta 抽出・復号、accumulator から inclusion proof、Stage-3 FullWitness 構築。**P2 全4ビルダ完了。**
- [x] **セキュリティレビュー(別 subagent、攻撃者視点)完了 — soundness 欠陥なし**。全5ビルダが検証済み fixture と field-by-field 一致、soundness は in-circuit、秘密鍵は適切スコープ、nullifier 正規導出、amount は復号由来。任意の防御的改善(必須でない、in-circuit で fail-closed):
  - (任意)CancelCloseProver に era-fence 早期チェック
  - (任意)PostCloseClaimProver に `incoming_tx_index < accumulator.len()` 早期チェック
  - (任意)WithdrawalClaim/PostClose の Regev pk 長/canonical 早期検証

### P2 検証済み(release専用 #[ignore] テスト)
- `a3_close_prover_builds_and_verifies_real_close_proof`(49s): 実 genesis state + 実 balance proof + 3 member 署名 → close 証明生成・検証。
- `a3_withdrawal_claim_prover_builds_and_verifies`(14s): slot0 が復号値 77 を主張・検証、padding slot negative。

## P3 — CLI close + cancel-close
- [x] **`cmd_close <manager> [rpc]` 実装(コンパイル OK)**: load_state + N member 鍵 + balance proof → 検証済み CloseProver で close 証明 + MLE 生成 → `close_intent.json`/`close_intent_mle.json` 出力(generate_close_fixture と同スキーマ、実状態版)→ requestClose(cast)+ submitCloseIntent(RunClose forge step、large calldata)。共署名集約 = CLI 制御 member 全鍵で署名。
  - 生成は検証済み CloseProver を使用。live(deploy+VK init 要)検証は P5 E2E。
- [ ] `cancel-close` 実装
- [ ] anvil で requestClose→submitCloseIntent 確認(P5 E2E)

## P4 — settle + withdraw + claim
- [ ] `settle` / `withdraw` / `claim`
- [ ] anvil で member が実 ETH 受領

## P5 — relay + 完全 E2E
- [ ] `/api/close|settle|withdraw|claim`
- [ ] `tests/close_lifecycle_cli_e2e.rs`(real proof, 強 negative)

## P6 — post-close-claim + stub revert 化 + 後始末
- [ ] post-close-claim CLI/relay
- [ ] specialClose / lateOutgoingDebit entry point を revert 化(forgeable stub を塞ぐ)
- [ ] fail-closed スタブを実装へ置換、followup を closed に

## 所見ログ
- (P1着手)
