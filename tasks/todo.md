# Task: 一人一鍵（one SPHINCS+ key per member）簡素化 + KeyLeaf↔member木 束縛 soundness 修復

Status: IN PROGRESS — 計画承認済み（/Users/plasma/.claude/plans/zazzy-hugging-zephyr.md）。
直前の detail2.md Regev 移行は完了・push 済み（commit c9f8787）。

## 確定設計決定
- **DA**: メンバー識別子 = SPHINCS+ 公開鍵ハッシュ Bytes32（digest/claim/nullifier/契約全て）。slot(0/1/2) は配列添字のみ
- **DB**: Regev 鍵束縛は回路内 Poseidon member 木への slot 包含のみ。keccak は L1 境界（ChannelRecord IMCR）のみ
- **DC**: signature_aggregation/（死蔵コード ~6.3K LOC）全削除。実署名検証は update_channel_tree.rs
- **DD**: N-of-N（3/3）、threshold なし

## フェーズチェックリスト（完了条件付き）
- [ ] **F1** constants + trees: key_tree.rs を MemberTree/MemberLeaf に書換、key_set.rs 削除、channel_tree.rs rename(member_pubkeys_root)、constants 整理(MEMBER_TREE_HEIGHT=2)。完了: 当該モジュール compile
- [ ] **F2** signature_aggregation/ 全16ファイル削除 + validity/mod.rs の mod 行。完了: 参照ゼロ確認
- [ ] **F3** sphincs_sig.rs(bp_key_id除去) + channel.rs 型一括(KeyId/UserId廃止→pubkey hash、全 digest 更新、validate)。完了: channel.rs ユニットテスト
- [ ] **F4** update_channel_tree.rs 束縛修復(member 木 slot 包含証明、KeyLeaf 撤廃)。完了: validity 回路テスト + **偽pubkey拒否の負例テスト**
- [x] **F5** close_circuit.rs member-set commitment 束縛(close PI 77→85)。native helper close_member_set_commitment + 回路内 keccak(IMCM)。負例(b/c)+正例テスト追加。close_pis/withdrawal(48)/post_close(40)/cancel(41) roundtrip PASS（cheap tests green）。重い回路テストは F6 後にまとめて実行
- [~] **F6** test_utils member witness 能力は実装済み。e2e は registration 整合ブロッカーで red →
      **ユーザー決定(2026-06-13): binding 修復を完了確定、registration 整合は follow-up**（別 deferred）
- [ ] **F7** Solidity(registration 簡素化、keyIds 除去、claim を bytes32 pubkey hash、closePIHash 77→85 +
      member_set_commitment 照合、withdrawal 48/post_close 40 mirror) + 共有ベクタ再 pin。完了: forge test
- [ ] **F8** detail2.md 書換 + detail2-implementation-notes.md に D5 ノート
- [ ] **F9** 全体 `cargo test --release --lib`(243+) / forge / clippy / fmt + 独立セキュリティレビュー(束縛)。
      e2e は registration follow-up までブロック該当で red（文書化）

## 確定: soundness 修復完了（ユーザー決定 2026-06-13）
KeyLeaf↔KeyTree 束縛穴は validity(update_channel_tree) + close(member_set_commitment) 両経路で修復・検証済み。
負例テスト PASS: update_user_tree_rejects_pubkey_not_in_member_tree / channel_close_circuit_binds_member_set_commitment /
channel_close_circuit_rejects_invalid_member_signature。prover-choice 排除。

## Follow-up（別タスク、本リファクタ範囲外）— 独立セキュリティレビュー(2026-06-13)で精緻化

**レビュー結論**: close 経路は SOUND（L1 照合実装済み、prover-chosen-key 穴排除）。validity 経路は
binding ロジックは正しい（負例テスト妥当）が **registration 機構欠如で production では inert**。
空ルートは空葉にしか開けず任意鍵偽造は不可だが、実チャネルで署名可能スロットが無い。

registration follow-up が満たすべき要件（レビュー Finding D/C）:
1. **member_pubkeys_root を account tree に書き込み認証する registration 遷移**を実装
   （現状 IntmaxRollup.registerChannel は "recorded only, validity proof で未消費"、
   validity は root を「保持」のみ、balance genesis は空 tree ハードコード switch_board.rs:230）。
2. **回路ガード追加**: 署名要求時に `member_pubkeys_root != empty/default ⇒ reject`
   （現状 unregistered チャネルが「署名可能スロット無しで valid」と silently 扱われる、fail-open 気味）。
3. **Finding C (HIGH)**: Poseidon `member_pubkeys_root`(validity) と keccak `ChannelRecord`(close/L1) は
   別コミットメントで cross-binding 未証明。registration 実装時に単一 source of truth 化 or 回路内相互束縛必須
   （現状 Poseidon 側=空、keccak 側=populated で異なる集合を表す）。
4. balance 回路 genesis(空) と登録済み account tree の整合（VK 再生成要）。
registration soundness 自体は genesis-trust deferred(intmax3-channel-mvp.md)。これが揃うまで e2e は red。

## リスク
- L1 member→channel 束縛（bare pubkey hash は channel 非内包 → claim で registeredMemberPubkeyHashes 包含 + 回路 slot 包含で緩和、要レビュー）
- 登録時 Poseidon↔keccak 整合（genesis trust 前提、registration soundness は既存 deferred）
- VK/degree 変化、巨大 blast radius（key_id 707 / user_id 665 参照）

## F5/F6 実装メモ（approved design — member-set commitment binding）
- F5 close binding: 回路内で 3 つの `sphincs_pk_hash_i`(slot order) を Bytes32Target 化し、
  `member_set_commitment = keccak([IMCM=0x494d434d, h0(8), h1(8), h2(8)])` を計算、新 close PI に connect。
  native helper `close_member_set_commitment(&[Bytes32;3])` を channel.rs に追加（hash_words 使用、byte-for-byte 一致）。
- close PI LEN 77 → 85（member_set_commitment を末尾に追加、既存 IMCI ベクタ温存）。
- close path の `regev_pk_digest`/`MemberLeaf` 撤廃（close は sphincs hash のみで束縛）。
- F6: block_witness_generator が channel 登録時に実 MemberTree(3 葉) を構築、root を ChannelLeaf へ。
  更新 slot i ごとに 実 SpxSigWitness + MemberMerkleProof(slot i) + RegevPk + msg_fields を生成。

## Solidity follow-ups for F7 (本フェーズでは実装しない、TODO のみ)
- `ChannelSettlementVerifier.sol`: `closePIHash` 77 → 85（末尾に member_set_commitment 8 BE u32 words）。
- `ChannelSettlementManager.sol`/`Verifier`: `member_set_commitment ==
  keccak([IMCM, registered member_sphincs_pubkey_hashes(slot order)...])` を登録 ChannelRecord と照合。

## 結果記録

### F5 — COMPLETE & VERIFIED
- close PI 77 → 85（member_set_commitment 末尾 8 limbs）。native `close_member_set_commitment`
  (IMCM=0x494d434d) + 回路内 keccak、byte-for-byte 一致。close path から MemberLeaf/regev_pk_digest 撤廃。
- テスト: `channel_close_circuit_proves_full_close_statement`（commitment == keccak(3 signing keys)）,
  `channel_close_circuit_binds_member_set_commitment`（(a)正値 (b)鍵差し替えで commitment 変化
  (c)改竄 commitment PI を回路内 keccak が拒否）。
- `cargo test --release --lib -- circuits::channel` → 30 passed（close 群含む）。
- close_pis(85)/withdrawal_claim(48)/post_close(40)/cancel_close(41) roundtrip PASS。
- Solidity TODO（F7）: closePIHash 85 mirror + member_set_commitment == keccak([IMCM, registered
  member_sphincs_pubkey_hashes]) 照合（close_circuit.rs + 本ファイルに明記）。

### F6 — BLOCKED（genesis-consistency design gap、要エスカレーション）
- block_witness_generator は **登録済みチャネルに対し実 SpxSigWitness + MemberMerkleProof(slot i)
  + RegevPk + msg_fields を生成**する能力を実装済み（`register_channel` + per-slot 署名）。
  未登録チャネルは従来どおり dummy にフォールバック（balance-only テストは緑のまま）。
- **ブロッカー**: 実署名のためにはチャネルの member root が **genesis の account tree** に入って
  いる必要がある（validity 回路は member_pubkeys_root を「保持」するのみで、ブロック遷移で
  「設定」する機構が無い＝registration は genesis-trust 前提、本リファクタ範囲外の deferred）。
  しかし balance 回路の genesis は `PublicState::default()` = `ChannelTree::init()`（空 = member root
  なし）にハードコードされている（balance_pis.rs:83 / public_state.rs:84）。
  `register_channel` で genesis にメンバーを書くと account tree root が変わり、
  `receive_deposit_witness` の `update_public_state.old == prev_balance_pis.public_state`
  アサート（= 空 genesis）と不一致。逆に登録しないと block 2/3 の updating slot で live binding が
  dummy proof を拒否（実測: e2e は block 2 で member merkle proof 不一致で fail）。
- 中間登録（ブロック間で tree を変更）は validity の per-block prev/new account-root チェーンを破壊
  （block N の new root ≠ block N+1 の chained prev root）→ 不可。
- **必要な解決（範囲外・要承認）**: 次のいずれか。(i) balance 回路 genesis を登録済み account tree
  root に対応させる（`PublicState::default()` 変更＝VK 再生成 = plan F9）。または (ii) validity に
  registration-block 機構を追加し member root をブロック遷移で導入（新回路・VK 再生成）。
  どちらも proof logic / VK 変更で、CLAUDE.md「Escalate, Don't Patch」に従い未着手のまま報告。
- 現状: lib + all-targets clean、channel/validity/test_utils 群 green、**e2e は F6 ブロッカーにより
  block 2 の member binding で fail（実署名を満たせない）**。チェックを弱めて通すことは行っていない。
