# Task: detail2.md 準拠実装アップデート（SIS → Regev/Ring-LWE 移行）

Status: DONE — 全フェーズ P0–P9 完了（計画全文: /Users/plasma/.claude/plans/golden-munching-badger.md）。
前タスクは tasks/archive-two-layer-identity-todo.md にアーカイブ。

## ユーザー承認済み設計決定

- **D1**: 金額エンコーディング = 1 bit/係数（64係数、t=256）。`MAX_HOMO_ADDS_BEFORE_REFRESH = 64` 承認
  （detail2 §B-1 の「8bits×8係数」は準同型加算1回で桁あふれするため訂正）
- **D2**: refresh / withdrawClaimZKP は新規 **復号AIR**（sk を private witness）で構成
  （§B-3 の「channelTxZKP delta=0 特例」は暗号化乱数 witness 不在のため実現不可能）
- **D3**: `BalanceState.pending_adds: [u32; 3]`（member別準同型加算カウンタ）を H1 にハッシュ
  （ノイズ/桁フラッディングによる exit-liveness DoS 対策）
- **D4**: close 回路は **全部今回実装**（3 member SPHINCS+ 署名検証 + finalBalanceProof 再帰検証 + chain 等値制約）

## フェーズチェックリスト（検証可能・反証可能な完了条件付き）

- [x] **P0** 依存関係: `regev_plonky3` git pin (377dfc2) 追加、p3 0.4.2/0.5.3 共存。
      完了条件: `cargo check` 通過、`cargo tree -i p3-field` で両バージョン解決確認
- [x] **P1** `src/regev/{mod,params,keys,encrypt}.rs`。
      完了条件: roundtrip / 準同型加算 / digest 安定性 / **非正準ct拒否** / 64回加算後復号 のユニットテスト全通過
- [x] **P2** `src/regev/transfer_stark.rs`: E-1 DualKeyTransferAir / E-2 ChannelUpdateAir(公開amount) /
      E-3 DecryptionAir / BalanceRefresh バッチ + `RealRegevProofVerifier`。
      完了条件: 正例 + 敵対的負例（改竄ct/改竄amount/purpose間リプレイ/非正準ct）全通過。
      最悪ケースノイズ解析を docs に記録
- [x] **P3** `src/common/balance_state.rs` 新設 + `channel.rs` 型一括改修 + `constants.rs`。
      完了条件: `cargo build --release` 復帰、channel.rs ユニットテスト通過
- [x] **P4** `state_update_verifier.rs` RegevProofVerifier 化 + witness 再設計 + `e2e_flow.rs` 全面書き換え。
      完了条件: e2e_flow 正例 + 負例（ZKP無し/改竄slot/tx_tree_root==0/version飛び/pending_adds超過）通過
- [x] **P5** balance 回路 F-1: `settled_tx_chain` PI 化（LEN 20→28）+ keccak chain step。
      完了条件: balance/switch_board 回路テスト通過、degree_report で degree 記録（2^16 超過なら poseidon 切替を escalate）
- [x] **P6** validity 回路 F-2: IMSB digest 署名 + `tx_tree_root != 0` 制約。
      完了条件: validity 系回路テスト + 空木 root ≠ 0 ユニットテスト通過
- [x] **P7** close 回路 F-3 全実装: PI 78 limbs + H1 回路内再計算 + balance proof 再帰検証 + member 署名検証。
      完了条件: close 回路テスト（正例 + chain 不一致拒否 + 署名欠落拒否）通過
- [x] **P8** Solidity: requestClose / GRACE / (finalEpoch, finalStateVersion) 順 / closePIHash 更新。
      完了条件: `SKIP_GROTH16=true forge test` 全通過（新規8テスト含む）、Rust↔Solidity 共有テストベクタ一致
- [x] **P9** クリーンアップ（src/lattice, tools/lattice-proof-helper, vendor/sis_amount_stark 削除）+
      docs（D1–D4 逸脱、秘匿境界、ノイズ解析）+ 全体 `cargo test --release --lib` / clippy / fmt。
      **フルlibスイート 243 passed / 0 failed（948s）**。Groth16 test 無効化済み（0 tests）。
      ⚠️ 統合テスト e2e.rs / mle_onchain_e2e.rs は**コンパイル不可**（plonky2_u32/[patch] 二重解決、
      CLAUDE.md 記載のmacOS既知問題）。これらは MLE/WHIR/Groth16 ラッパー = 別スコープ（CLAUDE.md「Known follow-up」）。
      回帰ではない（私のCargo.lock差分はplonky2系を無変更、ブランチは元々WIP破損）。要ユーザー判断: [patch]修正 or 据え置き

## 脅威モデル（attacker subagent レビュー結果、計画織込み済み）

F0-A(新規AIR扱い) / F0-B+F7(close回路→D4) / F1-A/B(ct正準性→P1) / F2-A/B/C(transcript束縛→P2) /
F3-A(aux_data多層検証→P4+P5) / F5-A/B(pending_adds→D3) / F6-B/C(L1→P8) / F9-A(regev_pk_root→P3)

## 残課題（実装しない・文書化のみ）

M7 race (§K-1) / retry version 意味論 (§K-2) / publishRegevPk 完全セレモニー (§K-4) /
Lean v3 追随 (§K-5) / requestClose 反復凍結グリーフィング（残存リスク）

### D1 / D3 関連の据え置き（ユーザー指示 2026-06-13: todoに残し一旦無視）
- **D1**: MAX_HOMO_ADDS_BEFORE_REFRESH=64 の厳密な最悪ケースノイズ sign-off（docs/regev-noise-analysis.md に暫定解析あり、detail2 §B-3 の正式承認は保留）
- **D3**: pending_adds カウンタの consensus 導出規則のフルスタック検証（off-circuit カウンタの整合性、retry 時の意味論 §K-2 と連動）

## 完了: 統合テスト [patch] 衝突の修正（ユーザー承認 2026-06-13）
根本原因 = submodule plonky2 の `crate-type=["cdylib","rlib"]` が macOS で `libplonky2.dylib` を
二重生成し output filename collision → E0463（plonky2_keccak/sphincsplus/intmax3_zkp not found）。
**修正2点**: (1) ルート Cargo.toml に `[workspace] resolver="2"` + `exclude`（nested workspace 分離）、
(2) submodule plonky2 を `crate-type=["rlib"]` に（cdylib除去、wasm-pack flow に不要）。
結果: `cargo build --release --tests --benches` クリーン、nullifier POC 2 passed、regev 30 passed、forge build OK。
⚠️ 修正(2)は submodule 作業ツリー編集 = 親repo未追跡。submodule内コミット or `git submodule update`後に再適用が必要
（詳細は detail2-implementation-notes.md の SETUP節）。

## 結果記録

- **P0 完了**: regev_plonky3 (git 377dfc2) 追加、p3 0.4.3/0.5.3 共存確認（`cargo tree`）。vendor/p3-*-0.5.3 を renamed patch で再利用
- **P0.5 完了（計画外）**: 前セッションの未完了 two-layer-identity リファクタ（ChannelLeaf 統合・ChannelId 単一化）の67コンパイルエラーを修復。
  既知の残存 SECURITY TODO: KeyLeaf witness の KeyTree 包含証明束縛が未実装（前タスクの §6.4 deferred 項目、コード内に `// SECURITY: TODO` 明記）
- **P1 完了**: src/regev/{params,keys,encrypt}.rs。upstream decrypt_value の panic-DoS を回避する独自デコード採用。11テスト
- **P2 完了**: transfer_stark.rs に4 AIR（E-1 DualKeyTransfer / E-2 ChannelUpdate 公開amount / E-3 Decryption / BalanceRefresh 結合AIR）。
  FS transcript順序は健全と検証（公開値はz導出前に吸収）。E-3はΔ=15·2^19の正確なノイズ範囲分解（素朴な23bit分解はエイリアス可能と判明し回避）。
  RefreshはバッチでなくAIR結合（published m(z)の辞書攻撃リーク回避）。敵対的テスト含め29テスト。
  独立セキュリティレビュー実施: MEDIUM 1件（digest正準性がdebug_assertのみ）→ assert! に修正済み。docs/regev-noise-analysis.md 作成（MAX=64承認: 桁余裕4倍、ノイズ余裕~120倍、失敗確率0）
- **P3 完了**: balance_state.rs（pending_adds入りH1）+ channel.rs 全面移行 + state_update_verifier.rs 再設計（5 witness + BalanceRefresh遷移）+
  src/lattice・tools/lattice-proof-helper・plonky3_state.rs 削除。既存PIレイアウトの潜在バグ発見・修正（ChannelId 1 limb化未追従: close 68→67, withdrawal 44→42, post_close 36→34, cancel 42→41 — **P8でSolidity側に反映必須**）
- **P4 完了**: e2e_flow.rs 全面書き換え（happy path 8段階 + 負例11種、各セキュリティ性質を個別エラーvariantで実証）。lib 237 passed
  （既知の例外: groth16_wrapper の環境依存2失敗は本作業と無関係・既存）
- **P5 完了**: balance PI に settled_tx_chain 追加（+8 limbs）、keccak chain step 回路（オフチェーン関数と等値性テスト済み）、
  receive_transfer（aux_data≠0ゲート）/receive_deposit（nullifier無条件）/send_tx（index-0 transfer witness + is_valid&&aux_data≠0ゲート）/switch_board genesis=0。
  CD不一致修復: receive_deposit に add_const_gate 追加（keccak hook が定数wireを供給しConstantGate自動挿入が消えたため）、serializer に Keccak256 generator登録。balance/test_utils 15テスト・channel 26テスト green
- **P8 完了**: ChannelSettlementManager に requestClose()/GRACE(600s)強制/Active直接close禁止/(finalEpoch,finalStateVersion)厳密順 _isNewer。
  CloseIntent rename(finalBalanceStateH1)+finalStateVersion/finalSettledTxChain追加。Verifier closePIHash 14引数化。
  postCloseClaimPIHash の stale receiverAmountDigest 削除（v2でE-3が回路内束縛）。**Rust↔Solidity 共有digestテストベクタ一致**（0xa2679bf7...）。forge 56 passed
  - P8 注記: P7 が出すべき close PI outer-hash limb順 = 既存67 + split_u64(final_state_version) + final_settled_tx_chain(8) = 77
- **Groth16テスト無効化（ユーザー指示）**: src/utils/groth16_wrapper.rs の test mod を `cfg(all(test, feature="groth16_tests"))`（未定義feature）でゲート。0 tests に確認済み
- **P6 完了（接続エラー後に検証）**: IMSB digest を回路内 keccak 再計算（compute_signing_digest、native signing_digest と同一preimage順）、
  channel_id/tx_tree_root を block の実 target に connect（構造的(a)担保）、tx_tree_root≠0 を update_channel_tree（slot毎ゲート）と channel_apply_block（無条件）で強制(b)、
  SPX_MSG_GL_LEN 11→8、signed_digest を sig_agg/sig_batch/sig_merge PI にスレッド、空 TxV2Tree root≠0 単体テスト追加
- **P6 完了**: validity 回路に IMSB `SmallBlockRootMessage::signing_digest()` 署名検証を導入（block_hash_chain/sphincs_sig.rs）。
  `tx_tree_root != 0` 制約を block step に追加（空木 root ≠ 0 のユニットテストで反証可能性確認）。
  回路内 IMSB preimage とオフチェーン serializer のドリフトを golden テストで防止
- **P7 完了**: close 回路 F-3 全実装（close_circuit.rs）。最終 PI は 78 でなく **77 limbs**（ChannelId 1 limb 化反映後の確定値）。
  H1 回路内再計算（pending_adds 込み）+ IMCH digest（`ChannelState::signing_digest()`）回路内 keccak 再計算 +
  finalBalanceProof 再帰検証（balance VK を定数焼き込み、settled_tx_chain / channel_id 等値制約）+ 3/3 member SPHINCS+ 署名検証。
  正例 + chain 不一致拒否 + 署名欠落拒否テスト通過
- **P8 完了**: Solidity close ゲーム更新（requestClose / GRACE 期間 / (finalEpoch, finalStateVersion) 順序 / closePIHash 77 limbs）。
  post_close は receiverAmountDigest を L1 ハッシュから除外（PI 34）。Rust↔Solidity 共有 IMCI digest テストベクタ一致。
  `SKIP_GROTH16=true forge test` 全通過
