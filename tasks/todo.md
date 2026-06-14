# Task: registration 機構（オンチェーン受付 → 決定論的 channel tree → validity proof で証明）

Status: IN PROGRESS — 計画承認済み（/Users/plasma/.claude/plans/zazzy-hugging-zephyr.md）。
直前: N人化 + MLE/WHIR化 完了・push（commit c71ac3e）。これで D5/Finding D の registration 穴を塞ぎ e2e green 化。

## 確定設計（R1-R6）
- R1: deposit パターン踏襲（新 channel_reg_step 回路、block_step 統合）
- R2: cross-binding（同一 Poseidon member 値が keccak preimage と Poseidon MemberLeaf 両方に → Finding C 解決）
- R3: registration preimage を固定16・word-aligned 形に（registerChannel 改修、回路 keccak 1個）
- R4(改訂 2026-06-14): registration を **block hash に含める**（deposit と同様、オンチェーン真正性アンカー）。ext-commitmentのみは捏造登録で channel 乗っ取り可能と判明
- R5: one-time registration（prev ChannelLeaf == default の unregistered guard）
- R6: intra-block 排他（registration block vs user-update block）

## フェーズ
- [x] **G1** ChannelRegRecord（src/common/channel_registration.rs）+ native hash_with_prev_hash（R3 固定形）+
      registerChannel preimage を R3 形に改修 + **byte-exact 差分テスト（Rust↔Solidity, member_count 2/8/16）**
- [x] **G2** channel_reg_step 回路（src/circuits/validity/channel_reg_hash_chain/、deposit_hash_chain 雛形）:
      keccak chain 消費 + Poseidon MemberTree 構築（R2）+ ChannelLeaf set + unregistered guard（R5）+ 単体テスト（含 上書き拒否負例）
- [x] **G3** ExtendedPublicState に channel_reg_hash_chain 追加（commitment ripple）
- [x] **G4** block_step 統合（条件検証 + R6 排他 + account_tree_root select）
- [x] **G5** ✅ e2e GREEN化(180.6s)。registration block→deposit→transfer→close、member binding 充足。Finding D 穴を閉鎖 test_utils: register_channel → add_channel_registration（in-band）。e2e: register→deposit→transfer→close
- [x] **G6** ✅ block-hash アンカー(R4改訂) byte-exact 差分テスト PASS、postBlock accumulator+rollback、block_step が reg chain 強制、e2e PASS、forge 62/62 block-hash アンカー(R4改訂): Block.channel_reg_hash_chain + _computeBlockHash + 回路内block hash再計算 + generator + postBlock snapshot + channelRegHashChain accumulator、byte-exact。registerChannel R3 は G1 済み
- [~] **G7** fixture 再生成済み、forge MLE/finalize 17 PASS(realProof オンチェーン検証 + 負例)。セキュリティレビュー: validity-path binding SOUND・Finding C 閉鎖。全体lib/clippy 実行中 VK 再生成 + MLE fixture 再生成 + **フルスタック e2e PASS（以前 red の解消実証）** + forge + 全体 lib + clippy/fmt + セキュリティレビュー

## 検証の要
- **R3 byte-exact**: native == 回路内 keccak == Solidity preimage（差分テスト）
- **フルスタック e2e green**: register block 後の更新ブロックで member binding 充足
- VK/fixture 一括再生成（ext layout 変化）

## リスク
- 🔴 keccak byte-exactness（R3 固定形で軽減も差分テスト必須）
- ext commitment 変化 → genesis/MLE fixture/VK 一括再生成
- R6 排他制約漏れ / R5 full-default guard / distinctness は契約委譲

## 結果記録
（各フェーズ完了時に追記）

## セキュリティレビュー結果（G7、2026-06-14）
- **validity-path member binding は SOUND**（prover はオンチェーン登録メンバーにしか束縛不可、Finding C keccak↔Poseidon 閉鎖、block-hash 真正性アンカー airtight、R5/R6 成立）
- **MEDIUM (Finding E)**: validity-path 登録(IntmaxRollup.registerChannel→member_pubkeys_root) と close-path(ChannelSettlementManager→registeredMemberSetCommitment) が独立別登録面、等価未強制。bp_member_slot も authenticated だが validity 回路で未束縛 → **要ユーザー判断: close-path を validity-path member 集合に統一**
- **LOW**: registerChannel アクセス制御なし → channel_id squatting/DoS（soundness 破壊ではない、trust model 確認）
