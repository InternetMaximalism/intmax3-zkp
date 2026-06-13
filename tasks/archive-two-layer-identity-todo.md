# Task: 二層アイデンティティ化(base = channel_id) → base L1 出金 payout → channel close 統合

Status: PLANNING — 実装前。コードはまだ書かない。本計画は §1 の foundational decision に基づく全面改訂版。

## 0. 確定モデル(合意済み)

- **base intmax = チャネル間(channel-to-channel)決済レイヤー。** base のネイティブ「ユーザー」は
  **チャネルそのもの**。
- **channel レイヤー = チャネル内(member-to-member)機密残高レイヤー。** key_id はここだけの概念。
- channel close = 「channel という base ユーザー」の L1 native 出金申請(時間のかかる申請+上書き
  ウィンドウ)。出金後にプール内をメンバー(key_id)で分配。
- cap(総額上限)は **base intmax の出金 proof** が決める。channel は自分が実際に持つ base 残高しか
  出せない。守るべき唯一の不変条件 = **チャネル間隔離**。内部誤配分は受容リスク(自チャネル pool 内)。
- nullifier 最終形: **#1 = base intmax 出金 nullifier(本タスクで新設)**、#2 = per-member フラグ
  (現状維持)。#3 / post-close incoming の内部 ZK 検証は今回 OUT(stub のまま、受容リスク)。
  集約 **solvency 上限**(全 credit ≤ 実受領額)は外さない。

## 1. FOUNDATIONAL DECISION(本改訂の中核)

**base intmax のネイティブ口座キーを `channel_id`(4 bytes)のみにする。key_id を base から抜く。**

- 現状: base `UserId = (channel_id << 32) | key_id`(8 bytes 相当 / u64)。account tree は
  `user_id.as_u64()` を leaf index にしている(src/common/user_id.rs:30-38, account_state.rs:82)。
  → base 口座が**メンバー単位**になっており、「channel 1つ」の単一 base 口座が存在しない。
- 変更後: base `UserId = channel_id`(u32, 4 bytes)。account tree leaf index = `channel_id`。
  → **channel = base の 1 口座**。channel fund = その口座の base ネイティブ残高。
  → 「channel を base 実残高にアンカーする」問題が**構造的に消滅**(別 proof 不要)。
- key_id は **channel レイヤー(src/common/channel.rs)専用**として残す(メンバー識別・内部分配)。
  base レイヤーは key_id を一切持たない/見ない。

### 1.1 この決定が触る範囲(全面 = code impact map)

base レイヤー(channel_id 化):
- [ ] src/common/user_id.rs — `UserId` を u32(channel_id)へ。`new/from_*/to_*` / Target を改訂。
      dummy 予約(現 channel_id=0&&key_id=0)を channel_id=0 予約へ再定義。
- [ ] src/circuits/balance/common/account_state.rs — account leaf index = channel_id。tree 深度見直し
      (index 空間 64bit→32bit)。
- [ ] balance 系回路全般(src/circuits/balance/ : send_tx / receive_transfer / receive_deposit /
      tx_settlement / spend)で user_id を channel_id として扱う。
- [ ] nullifier 派生(src/common/transfer.rs)— from = channel_id。base 出金 nullifier の一意性が
      channel 単位で保たれることを確認。
- [ ] validity / block / signature(src/circuits/validity/)— base ブロック署名は**チャネルの集約
      署名**(channel が 1 ユーザーとして署名)。member 署名は channel レイヤーへ。
- [ ] deposit 経路 — recipient/account = channel_id(IntmaxRollup.sol deposit の recipient 符号化)。

channel レイヤー(key_id 維持・橋渡し改訂):
- [ ] src/common/channel.rs — channel `UserId = channel_id||key_id` は内部用に維持。
      `bridge_user_to_channel_id/key_id`(1026-1032)を「base=channel_id」前提に改訂/整理。
- [ ] InterChannelFundImport 等 — base 残高(channel_id 口座)と channel fund の関係を一本化。

## 1.2 登録 → Poseidon tree → ZKP 束縛(W3 の中核 / 合意済み)

**登録系は全て on-chain**(DA 確保):
- `registerKey(key_id, pubkeys[], threshold)` — 公開鍵を calldata に出す。
- `registerChannel(channel_id, member_key_ids[])` — member keyID 集合を calldata に出す。

**登録後、決定論的 Poseidon tree を構築し ZKP で一致を証明**(2 層):
```
KeySetTree(pubkey hashes) → pk_set_root
KeyLeaf { pk_set_root, threshold }  →  KeyTree(keyID 索引) → key_tree_root
member_key_ids → member_key_ids_root
ChannelLeaf { member_key_ids_root, ... }  →  ChannelTree(channel_id 索引) → channel_tree_root
```

**SECURITY 不変条件(必達)**: ZKP は「Poseidon tree が on-chain 登録エントリと**過不足なく一致**」を
証明する。未登録鍵の混入 / 登録鍵の省略 / X 登録→Y 投入、を一切許さない。

**束縛手段**(既存パターン踏襲): deposit=`deposit_hash_chain`, block=`block_hash_chain` で calldata を
hash chain 化し `validity_circuit` が `keccak(ValidityPublicInputs)` で on-chain 束縛しているのと同様、
登録も hash chain(または block hash chain へ統合)→ ZKP が Poseidon tree 遷移=登録列を証明 →
root を on-chain 束縛する。← attacker pass の主対象。

## 2. スコープ(本決定を前提とした Option A)

### IN(必須)
- **§1 の base アイデンティティ二層化**(channel_id 化)。
- **base L1 ユーザー出金 payout(新規)**:
  - aggregated withdrawal proof をオンチェーン検証(IntmaxRollup の既存 MLE/WHIR+Groth16 再利用)。
    proof は `IntmaxRollup.latestFinalizedStateRoot` に束縛。
  - recipient へ native 送金(pull-payment / `pendingWithdrawals` 方式)。
  - **base withdrawal nullifier mapping**(`mapping(bytes32=>bool)`)で二重出金防止。
  - `aux_data` をオンチェーン露出(recipient 属性付け用)。
- **channel を base 出金の利用者に**: close = channel_id 口座の base 出金(recipient =
  `ChannelSettlementManager`, `aux_data = channel_id`)。cap = **実受領額にアンカー**。
  close/burn 経路の stub verifier を廃止。
- **solvency 上限(放置不可)**: Manager の全 credit パス(withdrawal claim / post-close incoming)を
  実受領 burn 総額で縛る。`claimWithdrawalCredit` は実 native 送金を残高で縛る。
  - 現状の穴: submitPostCloseClaim (ChannelSettlementManager.sol:599-600) は cap チェック無し。
- **replace ウィンドウ**(§4)。

### OUT(今回放置=stub のまま、受容リスク。intra-channel に閉じる)
- #2 per-member withdrawal claim の内部 ZK 検証。
- #3 late outgoing debit / post-close incoming の内部 ZK 検証。
- #2/#3 統合(別タスク)。

## 3. Phase 0 結果(完了) — linchpin 不成立。本決定で解消する。

1. channel は base-intmax の実口座ではなかった(`intmax_state_root` 未制約)→ **§1 で channel_id 口座化
   して解消**。
2. base rollup にユーザー出金 payout がオンチェーンに存在しない(`withdraw()` は stake/fraud 専用、
   nullifier mapping 無し、aux_data 未露出)→ **§2 で新設**。

## 4. replace ウィンドウ設計(新規メカニズム)

- 申請は **1 メンバーでも可**。チャレンジ期間中、**より高バージョンの fully-signed state** で上書き可。
  - [ ] 上書き優先規則の全順序化(`close_nonce`/`epoch`/`final_small_block_number`/fully-signed)。
- **payout 確定との順序(最重要)**: base 出金が L1 着金すると上書き不能 → 「申請受付フェーズ
  (replace 可)」と「base 出金実行・着金フェーズ(replace 不可)」を分離。早期着金で replace を
  無意味化する窓=0 を保証。special-close の 5 medium block 窓と整合。

## 5. Threat Model(コード前に attacker subagent で独立検証)

- **アイデンティティ移行の健全性**: channel_id 化で「別チャネルの残高をなりすまし出金」できないこと。
  account tree index 衝突・dummy 予約の取り違え・index 空間縮小の影響。
- **base 出金 soundness**: proof が必ず `latestFinalizedStateRoot` に束縛、未確定 state からの出金不可。
  Fiat-Shamir / domain 分離(channel close PIs vs base withdrawal PIs)。
- **nullifier**: 同一出金の二重 payout を新設 mapping が確実に弾く。channel double-burn 不可。
- **burn↔channel 束縛**: Manager は amount/属性を実受領 or 検証済み base 状態から得る。aux_data
  spoofing で別チャネルの出金を誤属性できないこと。
- **solvency**: Σ(payable credits) ≤ 実受領 burn 総額(全 credit パス横断、post-close incoming 含む)。
- **replace 競合 / 古い state リプレイ / 1 人申請悪用**: 勝者確定後に旧 state 出金 revert。検閲時は
  cancel/special-close 救済。replace と着金の順序逆転で二重 native が出る窓=0 の論証。
- **payout 安全**: reentrancy / reverting recipient(pull-payment 準拠)。

## 6. Falsifiable 検証項目(テストで証明)

- [ ] channel_id 化後も base 残高/送受信/deposit が健全(回帰)。別 channel_id の残高を出金不可。
- [ ] base 出金: 未確定 state root への proof は revert。確定 root のみ通る。
- [ ] base 出金 nullifier の再生は revert(二重 payout 不可)。
- [ ] close 後 channel 払い出し可能 native ≤ channel の実 base 残高(クロスチャネル隔離)。
- [ ] Σ(任意時点 payable な withdrawalCredits) ≤ 実受領 burn native(solvency property test、
      post-close incoming 経路含む)。
- [ ] `finalizedChannelFundAmount` が submitter calldata に影響されない。
- [ ] channel C への burn を C' が claim 不能(属性テスト)。
- [ ] replace: 低バージョン申請が高バージョンで上書き、確定後に低バージョン出金 revert。着金後の
      replace は無効。

## 7. 実装フェーズ(詳細設計承認後 / 各 Phase で承認)

1. **§1 base アイデンティティ二層化(channel_id 化)** — 最初に土台を変える。回帰テスト緑を確認。
2. **base L1 出金 payout** — オンチェーン verify + nullifier mapping + payout + aux_data 露出 +
   Rust 側 PI 整備。
3. **channel close を base 出金の利用者に** — recipient=Manager, aux_data=channel_id, cap=実受領。
   close/burn 経路 stub 置換。
4. **Manager** — 全 credit パスに solvency 上限 / `claimWithdrawalCredit` 実送金化 / replace ウィンドウ+
   フェーズ分離。
5. テスト(§6)を category 別(happy/boundary/malformed/cross-protocol/property)で実装。

## 8. プロセス(CLAUDE.md 準拠)

- 実装 subagent と **security-review subagent を分離**。
- protocol 変更につき **attacker subagent** を §5 で起動、merge 前にレビュー。
- 想定外テスト結果は「まず security 仮説」。test を通すための改変はしない。
- base のアイデンティティ変更と payout はオンチェーン資金移動・全回路波及を伴う重い変更 →
  各 Phase で承認を取る。

## 9. Assessment(随時更新)

- Phase 0: 完了。linchpin 不成立(§3)。方向 = Option A。
- Foundational decision(§1): base ネイティブ口座 = channel_id(4 bytes)、key_id 除去で確定。
- §1 実装(base ID 二層化 + 用語リネーム + 型統一): **完了**。base `UserId`→単一 `ChannelId(u32)`+
  `ChannelIdTarget` に統一(channel.rs の [u8;4] 版削除、keccak preimage 不変)。user 系シンボル全部
  channel 系へ(account_tree→channel_tree, USER_TREE_HEIGHT 64→CHANNEL_TREE_HEIGHT 32 等)。
  build は既知の論理エラー21個のみ・新規ゼロで検証済み。channel 層 member id([u8;8])は不変。
- W3 ステップ2(新ツリー型): **完了**。`src/common/trees/key_tree.rs` 新設(`KeyLeaf`/`KeyTree`
  =keyID索引、`MemberKeyLeaf`/`MemberKeyTree`、domain 分離タグ KYLF/MKLF)。`ChannelLeaf` 再構成
  (`pk_set_root`+`threshold` 除去 → `member_key_ids_root` 追加、domain タグ CHLF)。constants に
  `KEY_TREE_HEIGHT`/`MEMBER_KEY_TREE_HEIGHT`。新コードはエラーゼロでコンパイル。design は
  tasks/channel-key-tree-design.md。build 総エラーは 21→67(ChannelLeaf 再構成の下流=W3 サイト、想定内)。
- W3 ステップ3(on-chain 登録): **完了**。`IntmaxRollup.sol` に `registerKey(keyId, pkHashes[], threshold)`
  と `registerChannel(channelId, memberKeyIds[])` を追加(deposit hash-chain パターン踏襲)。登録 hash chain
  `_pendingKeyRegHashChain`/`_pendingChannelRegHashChain` + counts + events。配列は要素ごとに tight 連結
  (abi.encodePacked の 32byte パディング footgun 回避)。keccak 前像をコメントで明記(Step4 の Rust 回路が一致
  させる対象)。`forge build` OK。**記録のみ**で tree 適用は Step4。member は昇順一意・非0を検証。
- W3 ステップ4(登録適用回路): **設計完了**(channel-key-tree-design.md §6)。ChannelTree 共有の順序制約を反映。
- **MVP 方針確定**: 登録は genesis 済み・KeyTree/ChannelTree は不変(以降の登録なし)。登録消費(§3/§4)は
  MVP 対象外。MVP は別ファイルの自己完結モジュールとして署名規則(全 member keyID 閾値クリア)を固定木に対し証明。
  仕様 = tasks/channel-key-tree-mvp.md(本体 design.md にポインタ明記済み)。既存の壊れた再帰 flow は MVP の前提条件ではない。
- 残り(本体 build 緑化に必要、MVP とは別):
  - W1-mechanical: key_id 除去サイト(tx_settlement / single_withdrawal / public_state /
    block_witness_generator / bridge_user_to_key_id)。tx tree は channel_id index 化。
    → **完了**(2026-06-12 ベースライン修復): `cargo check` / `cargo check --all-targets` 緑。
    tx tree index = channel_id、ChannelTree index = channel_id 単独、bridge_user_to_key_id 削除。
  - W3-consensus: signature_aggregation + ChannelLeaf を B2=A(channel が member-keyID 集合 root を持ち、
    全 member keyID が閾値クリア)へ再設計。← コンセンサス署名規則。threat model 推奨。
    → **未完(機械移行のみ実施)**: (pk_set_root, threshold) の供給源を ChannelLeaf から `KeyLeaf`
    witness へ移したが、KeyTree への inclusion 束縛(§3 2b)と member_key_ids_root への member 束縛
    (§3 2a)は key_tree_root の PI 配線(design §6.4)待ち。該当箇所に `SECURITY: TODO` を明記
    (update_channel_tree.rs / sig_agg_step.rs / sig_batch_step.rs)。束縛が入るまで KeyLeaf は
    prover-chosen であり、署名検証の健全性は旧モデル相当に未回復。
  - 潜在バグ(先在・要確認): channel PIs の from_u64_slice 幅不整合(&values[0..2] vs 1 word)。

---

# Task: architecture-audit/abstract.md の Lean 安全性証明(2026-06-10)

Status: DONE(2026-06-10)

## 計画

- [x] 脅威モデル・信頼基盤(trust base)を明文化(architecture-audit/lean-safety-proof.md)
- [x] `architecture-audit/ChannelSafety.lean` — abstract.md §0 の 4 性質を Lean 4 (core, mathlib 不使用) で形式化・機械検証
  - [x] 認可 authorization(§4.1): 全員署名 + 善良ノード規律 ⇒ confirmed state は valid(`authorization`)
  - [x] 署名アトミック性(§3.4 不変則): 送金認可 ⇒ 減算後 state の confirm(`atomicity_no_loss_shift` — 仮定の明示化と明記)
  - [x] 二重支払い/不正 mint 防止(§4.2): 供給量保存(`exec_conservation`)+ nullifier 一意性(`no_double_settlement`、M1 制限付き)
  - [x] 支払い能力 solvency(§4.3): 残高非負不変(`exec_nonneg`)+ 状態 valid 保存(`channelTx/interSend_preserves_validity`)
  - [x] close ゲーム: `close_no_overdraw`・`close_boundary_no_double_spend`・集約 `exec_exit_bound`
  - [x] challenge ゲーム(§3.5.3): `challenge_latest_wins`(stale close 不能)
  - [x] 健全性チェック: §9 Sanity(全員善良 + 善良1人/敵対2人 の両構成で仮定充足を証明)
- [x] `lean ChannelSafety.lean` でコンパイル検証(Lean 4.10.0、exit 0、警告 0、sorry/axiom なし)
- [x] 別 subagent による敵対的レビュー → 18 所見。4 件をコード修正で反映、モデル限界 M1–M4 としてヘッダ+解説に明示

## 評価(Record Outcomes)

- 4 性質の safety 側は信頼基盤 A1–A4・抽象化 M1–M4 の下で全て機械検証済み。
- レビューで判明した本質的ギャップ(M1: 1 block 1 tx 抽象、M2: provenTotal–ledger 未接続、
  M3: OneStatePerVersion は規律仮定、M4: 受信側/late claim 個別管理未モデル)は
  lean-safety-proof.md に強化案付きで記録。仕様 abstract.md への追記推奨 2 点も同文書に記載。

## Lessons(tasks/lessons.md 相当)

- Lean core の `omega` は `abbrev Amount := Int` 越しの atom を認識しない(4.30-rc2 でも同様)。
  形式化では型エイリアスを避け素の `Int`/`Nat` を使うこと。
- 「証明した」と「仮定を明示した」の区別を docstring に書かないと、形式化はかえって過信を生む。
  敵対的レビューはこの過大主張の検出に特に有効だった。

---

# Task: abstract2.md(Lattice 版)作成 + Lean 安全性証明 v2(2026-06-11)

Status: DONE

- [x] architecture-audit/abstract2.md — v1 をベースに LATTICE 仕様差分を MECE で反映
  (Regev 秘匿・H1/H2 二部 state・channelUpdateZKP・署名対象 hash(H1,H2)・close 出金 ZKP、
  安全性は 5 性質に拡張: + confidentiality)
- [x] architecture-audit/ChannelSafety2.lean — v1 を import 再利用した v2 証明
  (Lean 4.10、exit 0、警告 0、sorry/axiom なし。2 ステップビルド:
  `lean ChannelSafety.lean -o ChannelSafety.olean` → `LEAN_PATH=$PWD lean ChannelSafety2.lean`)
  - 新規定理: bridgeToV1(v1 アトミック性仮定の定理化)、applyReceive/receive_preserves_validity、
    interChannel_conservation(_bound)、challenge_latest_wins2、end_to_end_close_safety2
- [x] 第 2 回敵対的レビュー(16 所見、CRITICAL 6)→ 4 件コード反映、M4 改訂 + M5–M7 新設
- [x] architecture-audit/lean-safety-proof2.md — 解説・定理対応表・所見記録

## 評価

- v2 の主要改善(構造的アトミック性・受信側保存則)は機械検証済み。
- **仕様レベルの未規定 4 点を発見(abstract2.md への修正推奨)**:
  1. M7: 署名済み・未 settle の減算 state が close で勝つ race(L1 包含証明の要求が必要)
  2. 送金失敗時の retry / version 再割当意味論が未定義(OneStatePerVersion と矛盾)
  3. H1 が balanceProof を含むが署名時点で proof 未生成(H1 のコミット対象を明文化すべき)
  4. H2=0 予約値と tx_tree_root の衝突・ドメイン分離未規定
- v3 形式化の本命: Apply の署名モデル/tx 木パラメータ化(M6)、受信 replay 防止(M4 改)。

## 追補(2026-06-11、ユーザー指示による仕様修正)

- [x] 所見 5(M5)解消: `channelTxZKP`(チャネル内 range ZKP)を abstract2.md §2.2/§3.2 に必須化。
  Lean: `ChannelTxProven` 導入 + `channelTx2_preserves_validity` 仮定置換 + `claims_exactly_fill_cap`。
- [x] 所見 3 解消: `settledTxChain`(settle 履歴 hash chain)で state↔balanceProof を束縛。
  H1 は proof を含まず chain にコミット、回路が chain を公開入力 expose、L1 が close/challenge で照合。
  nullifier は block_number を含み署名時点で計算不能のため不採用(base 層の二重 settle 防止は続投)。
  Lean §9: `chainOf_injective` / `chain_binding_resolves_attachment`。
- 残る仕様課題: M7(signed-but-unsettled race)、retry/version 意味論、H2 ドメイン分離。

## 脅威モデル(要約 — 詳細は lean-safety-proof.md)

- 敵対者: channel メンバー最大 2/3、BP、外部者。SPHINCS+ 偽造・ZKP 偽造・L1 検閲は信頼基盤(仮定)。
- 守るもの: abstract.md §0 の 4 性質のうち safety 側(認可・no-double-spend・solvency・stale-close 防止)。
- liveness(タイムアウト到達・L1 包含)はモデル外と明記。
