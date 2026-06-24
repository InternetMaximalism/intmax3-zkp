# 監査指摘の修正 (A-2〜A-5, B-1〜B-5)

ブランチ: `fix/audit-soundness-and-tests`(main から分岐)
計画: `/Users/plasma/.claude/plans/sleepy-questing-creek.md`

## Phase 1: A-2 + B-2 — validity VK degreeBits==0 の on-chain 強制
- [x] `IntmaxRollup.sol`: `error ValidityVkDegreeBitsZero`、`bool immutable allowMleDisabled`、コンストラクタ guard、`_verifyMle` 二重ガード
- [x] 全 `new IntmaxRollup(...)` / `BlockHashHarness` 呼び出しに引数追加(本番scripts=false、tests=true、close CREATE2=false)
- [x] B-2: 空プレースホルダ `test_finalize_realE2E_PENDS_F6` 削除＋実カバレッジ所在をコメント化、`test_finalize_success` にPI束縛限定の注記
- [x] 新テスト: 本番モード+空VKで revert、test opt-in で許可 → 2本 PASS
- [x] forge build OK / IntmaxRollup スイート 48 PASS
- [x] **A-2 完全解決**: close-lifecycle fixture を新 manager アドレス(`0x219Bb8e259Ec550aE8Ea9B9cc250149812b5C7Ca`)で再生成(`WD_RECIPIENT=... WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture`)。CloseLifecycleE2E PASS。**forge 全 140/140 PASS、0 failed**。
  - 注意(既存設計の脆さ): baked CREATE2 アドレスは Solidity metadata hash 経由で IntmaxRollup 系ソースのコメント変更にも反応する。今後 IntmaxRollup.sol / BlobKZGVerifier.sol 等を編集したら close-lifecycle fixture の再生成が必要(A-2 起因ではない)。

## Phase 2: A-3 — close ライフサイクルのスタブ安全化(本体は別PR)
- [x] `channel_member.rs` の全ゼロ anchor を named 定数化＋OPEN明示、`close`/`withdraw`/`settle` を fail-closed スタブ化
- [x] フォローアップ票 `tasks/a3-close-lifecycle-followup.md` 作成

## Phase 3: A-4 — チケット更新のみ(doc)
- [x] `tasks/inter-channel-live.md` の CRITICAL-1 を CLOSED に(根拠付き)

## Phase 4: A-5 — コメント補強のみ(バグなし)
- [x] `BlobKZGVerifier.sol` fast path に SECURITY コメント追記

## Phase 5: B-1 — mle_onchain_e2e を本物の on-chain 検証に
- [x] `tests/mle_onchain_e2e.rs` で fixture 生成後に forge(MleE2E/MleFinalize)起動＋実 verify をアサート、forge 不在時は明示スキップ

## Phase 6: B-3 / B-4 — 実 verifier/manager に negative 追加
- [x] B-4: `MleE2E.t.sol`(baseline+3 negative) / `MleFinalizeE2E.t.sol`(tamper→false) → PASS
- [x] B-3: `ChannelSettlementManager.t.sol` に verdict=false の reject negative → PASS

## Phase 7: B-5 — Rust テストのハリボテ解消
- [x] B-5a `verify_wasm_proof.rs` vacuous skip → `#[ignore]`+doc、不在時 panic(vacuous green 排除)
- [x] B-5b `wasm_proofs.rs::wasm_balance_processor_flow` に sender/receive proof の `.verify()` 追加
- [x] B-5c `inter_channel_e2e.rs` に軽量 negative(空 transport 拒否)＋smoke 位置づけ明示
- [x] B-5d `inter_channel_validity_b2.rs` → `small_block_sig_validity.rs` にリネーム＋scope注記、detail2.md 参照更新
- [x] B-5e `wallet_delegate_demo.rs` の join に state-preserving 遷移不変条件アサート追加

## 重い計算(要許可・未実施)
- [ ] close_lifecycle fixture 再生成(A-2 起因、CloseLifecycleE2E setUp の baked manager アドレス更新)
- [ ] Rust コンパイル + 該当 Rust テスト実行(mle_onchain_e2e, wasm_proofs, inter_channel_e2e, wallet_delegate_demo, small_block_sig_validity)— 証明生成で重い

## Solidity 検証状況(完了)
- forge build OK / IntmaxRollup 48 / ChannelSettlementManager 66 / MleE2E 6 / MleFinalizeE2E 2 PASS
- 全 forge: 133/134 PASS、唯一 CloseLifecycleE2E が fixture 再生成待ち(上記)

## 所見ログ
- A-2 採用方式: 明示デプロイフラグ(constructor `_allowMleDisabled`)。本番は false で degreeBits==0 を revert、`_verifyMle` も flag で二重ガード。
- gotcha 再確認: IntmaxRollup の bytecode を変えると close 系 fixture の baked CREATE2 アドレスが無効化する(メモリ project_delegate_account.md と一致)。A-2 は本質的にこれを誘発するため fixture 再生成は不可避。
