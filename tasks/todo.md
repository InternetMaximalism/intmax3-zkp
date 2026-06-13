# Task: N人メンバー対応（MAX=16, pad-to-MAX）+ オンチェーン検証 MLE/WHIR 化（Groth16 除去）

Status: IN PROGRESS — 計画承認済み（/Users/plasma/.claude/plans/zazzy-hugging-zephyr.md）。
直前: 一人一鍵リファクタ完了・push（commit f86eacd）。

## 確定設計決定（ユーザー選択 2026-06-13）
- MAX_CHANNEL_MEMBERS=16（member 木高さ4=16葉）
- pad-to-MAX 単一回路（全チャネル16スロット、未使用は padding）
- Groth16 を契約 finalize/fraudProof から除去（コード・引数削除、MLE PI binding 依存）

## 重要 soundness 要件（Task2）
Groth16 除去時、`mleProof.publicInputs == keccak256(ValidityPublicInputs)` 照合を finalize に**追加必須**
（現状この束縛は Groth16 PI binding のみが担う。単純削除は任意 validityPIs を通せる穴）。

## フェーズチェックリスト
- [x] **F1** constants(MAX=16, MEMBER_TREE_HEIGHT=4) + balance_state(配列16, h1にmember_count) +
      channel.rs(ChannelRecord [Bytes32;16]+member_count, validate, IMCR, close_member_set_commitment は active のみ)
- [x] **F2** member 木高さ4 + close 回路 pad-to-MAX（slot<member_count ゲート）+ state_update_verifier(0..MAX) + PIs。
      **🔴 最優先: close 回路 degree 早期計測。2^20超/proving数分超なら per-count variant へ切替を escalate**
- [ ] **F3** test_utils + e2e_flow（複数 N=2/3/8/16 テスト + binding 負例）
- [x] **F4** Solidity Task1: registerChannel 可変2..16, bytes32[16]+activeMemberCount, closePIHash 86, closeMemberSetCommitment 固定16形
- [x] **F5** Solidity Task2: Groth16 完全除去 + **MLE PI binding 追加（_mlePublicInputsMatch, soundness-critical, 負例テスト付き）**。
      Groth16Verifier.sol/Gnark/E2E_RealGroth16.t.sol/groth16_wrapper.rs 削除。forge 60/60、共有ベクタ再pin(0x12450612...)
- [x] **F6** MLE fixture 再生成完了 + Forge 20テスト(MleE2E real proof, finalize, fraudProof) PASS + mle_onchain_e2e PASS(44s)。tampered validityPIs/unbound MLE PI 拒否=soundness束縛OK + Forge MLE/finalize + mle_onchain_e2e PASS 確認
- [ ] **F7** detail2-implementation-notes.md に D6 ノート + 最終検証（lib/forge/clippy/fmt）+ 改竄validityPIs拒否のForge実証

## リスク
- 🔴 close 回路 degree 激増（16 SPHINCS+）— F2 早期計測、実用外なら escalate
- 🔴 Task2 soundness — Groth16 除去 = MLE PI binding 追加と一体
- member_count を H1/IMCR/close PI/L1 全一貫
- VK 再生成 → MLE fixture 再生成は Task1 後
- 一人一鍵 registration follow-up は未解決のまま（本計画対象外）
- abstract2.md 3固定 → N は spec 逸脱（D6）

## 結果記録
- **degree de-risk（最大リスク解消）**: SPHINCS+ verify_circuit degree 計測 N=1→2^14, 3→2^16, 8→2^17, **16→2^18**。
  close 回路全体は 2^18〜2^19 見込み = 実用範囲内。**pad-to-MAX=16 フィージブル、escalate 不要**。
