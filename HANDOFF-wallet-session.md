# 引き継ぎ書 — wallet スタック修正 / cosign 高速化 / inter-channel 有効化 / refresh 撤廃(設計)

- **ブランチ**: `claude/aws-deploy-investigation-fff966`（worktree: `.claude/worktrees/signerless-exit-handoff-6ec58b`）
- **ベース**: `e1a8847`（このセッション開始時点）
- **このセッションのコミット**: `b510347`, `6d43c61`, `009cd3f`
- **作業ディレクトリ**: worktree ルートで作業（`.claude/worktrees/signerless-exit-handoff-6ec58b`）。元リポジトリへ `cd` しない。

---

## 1. 完了したこと（コミット済み・検証済み）

### コミット `b510347` — deposit/join/refresh/send を端から端まで動かす + cosign 約14倍高速化

**serde 地雷5箇所**（`ChannelState` の疎な `u8` キーマップが、内部タグ付き enum / `flatten` / serde の Content バッファを経由すると `invalid type: string "0", expected u8` で壊れる。同一根で5表面に出ていた）:
- `BlockProducerCommand`: `rename_all_fields` 追加 + 重いペイロードを `Value` で持ち `from_value` で materialize（**producer コマンド面が JS から到達不能だった**）。
- `ProductionJournalAction`: 外部タグ付けへ変更（**デーモン再起動時に自分の journal を再パースできず全チャンネル喪失＝本番致命**）。
- exit-kit proposal / public backing envelope: `flatten` の Content バッファを回避（`src/public_close_prover.rs` の手動再構成パーサ）。

**deposit パイプライン**:
- adoption をアトミック + 冪等化、journal-before-register の順序、producer 登録の全経路保証、deposit の index/block を実値化（ハードコード0を廃止）。
- **delegate join の epoch バグ（本命）**: `join_delegate`（`src/bin/channel_member.rs`）が header-only(H2=0) 遷移なのに `epoch += 1` を落としていた。refresh 等の header-only 遷移は必ず epoch を +1 する規約に反し、join 頭が不正な形になって **producer 公開ヘッド（`sync_offchain_heads`）と live balance（`bind_signed_snapshot`）両方が弾いていた**。→ `state.epoch += 1` を追加。
- `live_balance_service.rs`: `bind_signed_snapshot` に**単一 delegate 追加の再bind経路**（`is_single_delegate_add`）を追加。co-signer 集合不変なので同じ N-of-N が新ヘッドを署名＝安全。
- `deposit-pipeline.js`: adoption の catch-up bind（join に追従）＋ `installHeadExitKit`（新ヘッドの exit-kit 受領書設置。refresh/send が spend するのに必須）。
- `api/lib/cli.js`: `execFileSync` の `maxBuffer` を 512MB に（多スロットチャンネルで cosign 出力が 1MB を超え `ENOBUFS` でハングしていた）。

**ブラウザ/relay**:
- `wallet-live.html`: deposit の冪等ガード（pending deposit があれば再ブロードキャストせず import を resume）＋ anvil 再起動由来の nonce エラー（already imported / tx not found）に明確な MetaMask リセット案内。
- `wallet-relay.js`: 実 CLI エラー（stdout+stderr）を surface する `fullCliError`。

**cosign 高速化 6.30s → 0.45s（実測）**:
- **exit-kit 再検証スキップ**（intra-channel、`require_prepared_exit_kit` の reuse 経路）: durable な head-bound receipt を信頼し、冗長な plonky2 Balance proof 再検証を除去。6.30→3.46s。
- **NTRU 鍵キャッシュ**（`src/falcon_sig/mod.rs` に `insecure_ntru_basis_bytes`/`from_insecure_ntru_basis_bytes`、`keys_for` の insecure 分岐でディスクキャッシュ）: `from_short_lattice_basis` で `ntru_gen`(~455ms/人) を飛ばす。**insecure テストキー限定**（本番の派生鍵はディスクに置かない）。3.46→0.45s。

### コミット `6d43c61` — inter-channel を legacy relay で有効化 + deposit テストモック修正
- daemon-backed 送金ロジックを `api/lib/inter-channel-send.js` に**抽出**し、api ルート(`api/routes/inter-channel.js`)と legacy relay(`hosting/wallet/wallet-relay.js` の `/api/inter/send`)の**両方が同一コードを使用**。以前は 503。両チャンネルをソート順ロックしてデッドロック回避。
- deposit stub テスト（adoption / live-binding）のモック欠落を修正（`installHeadExitKit` を stub。以前の commit で importL1Deposit に足した際に更新漏れ→実 daemon 起動していた）。**実運用は無害**（deposit 直後は live balance が bound 済み）。
- crash-recovery テストが共有モジュールも require.cache からクリアするよう修正。

### コミット `009cd3f` — legacy relay の `/api/base-head` 有効化
- ブラウザが inter-channel/burn/withdrawal の debit を「daemon の live base nonce」で組むのに必須。以前は 409。`producer.liveBaseHead` を serve（frozen な backing ファイルにフォールバックしない＝strand バグ回避）。

### 検証結果
- **deposit（join無し）/ deposit（delegate join 後）/ 連続 join / refresh / 実 send / 冪等再インポート / 異常系**: シナリオ・マトリクス **11/11 全緑**（実 relay+daemon+anvil、`cast`+`curl` でヘッドレス）。
- Rust ガードテスト: `is_single_delegate_add` 9件、journal round-trip、deposit identity/settle-chain、balance-state both-codecs、producer command wire、NTRU basis round-trip、falcon_sig 14件、signing_ledger 11件 — 全緑。
- node スイート: **535/535**（`node --test` が worker fixture を誤収集した1件を除く。`npm test` の `test/*.test.js` グロブは除外）。inter-channel crash-recovery 4/4、adoption 11/11、live-binding 3/3。
- `cargo check --all-targets` 緑。

---

## 2. 既知の未解決・注意点（次セッションへ）

### (a) inter-channel の「ブラウザ→relay→daemon→実 proving」通し検証は未達
- relay 側の穴（503/409）は塞ぎ、送金ロジックは crash-recovery テスト（モック）で検証済み、CLI プリミティブ `cosign-inter-transfer` は既存 e2e で検証済み。だが**実 proving を通した end-to-end は未確認**。
- ヘッドレスで叩くには inter-channel の **debit payload 生成手段**が必要（ブラウザ WASM `wallet_send_inter_channel` 依存）。`gen-inter-send` 相当の CLI（宛先 recipient pk/pk_g、before_witness、base_nonce 協調、salt を扱う）を追加するか、実ブラウザで検証。
- **確実な確認手段は実ブラウザ**（今回の変更で「動作可能」になった。以前は 503+409 で不可能）。

### (b) `tests/inter_channel_cli.rs` は**このブランチで既存ブロック**（私の回帰ではない）
- 8/17 が `REFUSING to load cli_state.json: ["prepared_exit_kit_receipt"] are ABSENT` で失敗。テストの `cli_state()`（line 305）が `CliState` を直接組み、`prepared_exit_kit_receipt: None` が `skip_serializing_if=is_none` で JSON から省かれ、load の必須キーチェックに引っかかる。
- **ベース `e1a8847` でも同一の 9 pass / 8 fail** を確認済み（channel_member.rs を e1a8847 に戻してビルド・実行して検証）。→ 既存のテスト×スキーマ不整合。修正は e2e の `cli_state()` フィクスチャビルダーを必須キー込みに更新すること（ただし本タスク範囲外の既存問題）。

### (c) MetaMask × anvil 再起動の nonce desync
- anvil 再起動で MetaMask の nonce/tx キャッシュが古くなり「already imported / tx not found」を生む。コードでは根絶不可（環境要因）。`wallet-live.html` に明確な案内を追加済み。手順: MetaMask 設定→詳細設定→「アクティビティタブのデータをクリア」。

### (d) 汚れたチャンネルの回復不能 drift
- 失敗リトライを重ねると live balance と CLI snapshot が drift（`settle chain differs`）し回復不能になる。クリーンな1回では起きない。channel をリセット（`rm -rf wallet-live-work` → relay 再起動で ch7 backing 再構築 → ウォレット送金）で復旧。

---

## 3. 次の大タスク: **#2 refresh 撤廃（復号ベース送金）** — ステージ1（AIR）実装済み・ステージ2以降未着手

### 進捗（2026-09-21, ブランチ `claude/handoff-wallet-session-998f4c`）
- **ステージ1 完了**: `src/regev/transfer_stark.rs` に `DecryptedSendAir`（decryption core on `before` ＋ after/enc_amount の暗号化恒等式 ＋ 保存則）、`prove_decrypted_send` / `prove_channel_tx_decrypted` / `verify_channel_tx_decrypted`、purpose `RegevProofPurpose::ChannelTxDecrypted`（domain "IMDS" = `CHANNEL_TX_DECRYPTED_ZKP_DOMAIN`、statement は E-1 と同じ `RegevStatement::ChannelTx`）、ディスパッチャ配線。
- テスト 9 件（positive: fresh/edge/64 準同型加算後/受信後送金/canonical-zero、negative: prove 拒否/statement 差替/purpose 束縛/**forged trace 4 種**/garbage）全緑。既存 transfer_stark 21 件＋ドメイン非衝突テストも緑。
- **ステージ1b 完了**（`56d5ecc`）: AIR を `DecryptedDualKeyAir { shape }` に一般化し、**E-2 の復号版**（inter-channel debit/burn 用）`prove_channel_update_decrypted` / `verify_channel_update_decrypted`、purpose `ChannelUpdateDecrypted`（domain "IMDU"）を追加。inter-channel は E-1 ではなく E-2 を使うため、これが無いと refresh 撤廃は intra 限定になる。テスト 4 件追加（計 34 件緑）。
- **ステージ2 完了**（wallet 統合）: `wallet_core` に `BeforeLeg { Witnessed, Decrypted }` を導入し、`build_send_token` / `build_inter_channel_send_token_at_base_nonce` / `build_burn_send_token_at_base_nonce` を共通本体 `*_with` に集約。復号版の公開ビルダー `build_send_token_decrypted` / `build_inter_channel_send_token_at_base_nonce_decrypted` / `build_burn_send_token_at_base_nonce_decrypted`（witness 不要、`keys.regev_sk` で復号）。検証側は `state_update_verifier::verify_transfer_proof_either`（復号 purpose を先に試し、失敗なら witnessed purpose）を InChannel / InterChannelSend / ReceiverBundleApply の各 witness と `verify_slim_send_tx`、credit 側再検証で使用。**refresh 必須ゲート撤廃**: `verify_slim_send_tx` の `pending_adds != 0` 拒否を削除、ビルダーの拒否は Witnessed 経路のみに限定。inter-channel ビルダーの `a_send` で **`pending_adds[sender][slot] = 0` を明示リセット**（テストで検出したバグ: prev 引き継ぎだと verifier の「再暗号化ならリセット」に反する）。
- **ステージ3 完了**（WASM／ブラウザ／delegate）: `wasm_wallet` の `wallet_send` / `wallet_send_inter_channel` / `wallet_burn_send` は復号版ビルダーへ（`session.balance` の witness 要求を撤廃、`BalanceReport.canSend` は常に true）。`wallet-live.html` の `attemptSend` / `attemptInterChannelSend` / burn の refresh 前処理を削除（`witnessBacksTokenSlot` は互換とテストのため残置）。node delegate `owntx.js` の `doSend` / `doInterChannelSend` / `doBurn` から pre-send refresh を削除（`ensureSendable` / `doRefresh` は保守操作として残置）。`node/test/unsigned-builders.test.js` のソース走査を `*_with` 委譲追従に更新。
- **CLI も移行済み**: `channel_member send` / `gen-send` は `build_send_token_decrypted`（witness-store の `witness_source` / `WitnessSource` / `parse_seed32` は削除、`invalidate_witness` は記録のみ）。`gen-send <balance>` は復号値との fail-closed 照合に変更。relay（`wallet-relay.js` / `wallet-relay-ec2.js`）の faucet から `refresh` レグを撤去。`tests/itx_faucet_cli_e2e.rs` の否定2件を更新（未入金＝insufficient balance、準同型加算済み＝送金可）。CLI の inter-channel/burn は元々ブラウザ製 debit を cosign する経路で、ビルダー呼び出し無し。
- **残タスク**: 実ブラウザでの通し確認（WASM は `hosting/build-wallet-wasm.sh` で再ビルド済み、`pkg/` は gitignore）。anvil 必須の e2e（`itx_faucet_cli_e2e` は `#[ignore]`）は個別実行が必要。
- **本番投入前に作者の暗号レビュー必須**（テスト通過は soundness の証明ではない）。refresh 自体は機能として残る（純受信者が 64 加算の noise 予算に近づく場合の保守用）。

### 元の設計メモ（ステージ1 実装の根拠）

### 目的
準同型加算（deposit/受信）で貯まった位置を、送金前に **refresh（復号→再暗号化して witness を取り戻す）せずに直接 spend** できるようにする。ユーザー（プロトコル作者）承認済みの方向。

### 暗号 soundness: **安全（確認済み）**
- refresh 撤廃は「新しい暗号」ではなく「既存 gadget の再構成」。**decryption core は既に準同型和を復号している**（`src/regev/transfer_stark.rs:1332-1333`: 「worst case after MAX_HOMO_ADDS_BEFORE_REFRESH = 64 additions: 64·514 ≈ 2^15」、noise 予算 Δ/2 ≈ 2^21.9 に対し ~2^7 マージン）。RefreshAir/E-3 が本番で依拠する同じ core。
- digit 抽出の一意性（1334-1339）: `ns ∈ [0, Δ)` が load-bearing、`Δ·(d−d') = ns'−ns` が `d=d', ns=ns'` を強制（digit エイリアス攻撃を代数的に排除）。
- 送金後の `after` は新規暗号化＝送金ごとに noise リセット。`MAX_HOMO_ADDS=64` 不変条件は refresh と同様に維持。新しい暗号学的仮定も noise 領域も導入しない。

### 実装設計（de-risk 済み・ファイル別）
すべて `src/regev/transfer_stark.rs` の既存パターンに準拠。**雛形は RefreshAir**（decryption core + 1暗号化を既に持つ）。

**新 AIR（例: `SendFromDecryptedAir`）= `eval_decryption_core(before)` ＋ after/enc_amount の暗号化恒等式 ＋ 保存則（`DEC_BIT`=m_before で ripple-carry）**:
- 現行 E-1（`DualKeyTransferAir`）は `before`/`after`/`enc_amount` を暗号化恒等式 `c1(z)=a(z)r(z)+e1(z)-…`, `c2(z)=b(z)r(z)+e2(z)+Δm(z)-…` で縛る（`eval_dual_key`, line ~400-540）。`before` に乱数 r が要るのが refresh の原因。
- 変更は **`before` ブロックだけを暗号化恒等式 → `eval_decryption_core`（秘密鍵 s で `b-a·s=m`、r 不要）に差し替え**。`after`(送信者鍵)/`enc_amount`(受信者鍵) は暗号化のまま、保存則 `m_before(=DEC_BIT) = m_after + m_amount` を維持。
- `eval_refresh_encryption`（line 1598）が「decryption core の `DAUX_BIT` を同じ鍵で再暗号化」する構造そのもの。送金はこれを「m_after を送信者鍵＋m_amount を受信者鍵で暗号化＋保存則」に置換。

**列レイアウト**（RefreshAir を参照。定数は line 1372-1421）:
- `DEC_CORE_COLS`（before 復号: `DEC_A/B/C1/C2/S/EPK_U/V/K_PK/V/K_V/D_BITS/NOISE_*/BIT/CARRY`）
- after 暗号化ブロック（送信者鍵、message 列 = m_after）— `RF_*` 相当（`RF_C1_NEW/C2_NEW/R/E1U/E1V/E2U/E2V/K1/K2`）
- enc_amount 暗号化ブロック（**受信者鍵**、message 列 = m_amount）— もう1組。受信者鍵 (a_r, b_r) を public values + aux に追加。
- 保存則 carry 列。

**aux/lookup**（line 1404-1421, 1442-1503）:
- `decryption_core_lookup_specs(false)`（before、bit は Local=秘匿）＋ after の暗号化 spec ＋ enc_amount の暗号化 spec（`refresh_lookup_specs` を2暗号文に拡張）。
- public values: `[domain] ++ a_sender ++ b_sender ++ c1_before ++ c2_before ++ c1_after ++ c2_after ++ a_recipient ++ b_recipient ++ c1_amt ++ c2_amt`。

**witness 生成**: `fill_decryption_core_row`(line 1902) で before の復号 witness（v, digits, k_v, e_pk…）＋ 各暗号文の暗号化 witness ＋ 保存則 carry。`generate_refresh_trace`(line 1958) を雛形に。

**prover/verifier**: `prove_channel_tx`(1060)/`prove_dual_key_transfer`(1081) の新変種、`verify_channel_tx`。

**下流の統合**:
- `src/wallet_core.rs`: `AmountWitness = { amount, witness: EncryptionWitness }` から before の暗号化 witness 依存を除去（新送金は before の暗号文＋秘密鍵で足りる）。`build_inter_channel_send*` / intra `build_send`（`prove_channel_tx` 呼出）を新 AIR へ。`check_amount_witness`(719) が before に対して暗号化検証しているのを decryption ベースへ。
- **refresh 必須チェックの撤廃**: `src/wallet_core.rs:1481, 1831, 2602`（"sender (slot, token) position has pending homomorphic adds; refresh required before sending (not yet implemented in MVP)"）と `1973`（D3 budget: `pending_adds[r][ts] >= MAX_HOMO_ADDS_BEFORE_REFRESH`）。pending_adds > 0 でも送金可に（ただし ≤ MAX_HOMO_ADDS の範囲チェックは残す＝noise 予算）。
- `src/wasm_wallet.rs:692` `wallet_send` / `775` `wallet_send_inter_channel`: refresh 前処理を除去、before を復号ベースで組む。
- `hosting/wallet/wallet-live.html`: `attemptSend`（~2540行）の `witnessBacksTokenSlot` false → refresh の分岐を除去。

**テスト**:
- AIR の positive（正しい witness で proof 成立）＋ **negative/forged**（既存 E-1/Refresh の否定テストを雛形に。line 964 `inter_channel_cli_forged_a_state_refused`、`transfer_stark` の tests モジュール）。**否定テストが soundness のガードレール**（ただしテスト通過は soundness の証明ではない — 本番投入前に作者の暗号レビュー必須）。
- `wallet_core` の send テスト、e2e、ブラウザ通し。

### 段階的コミット方針（推奨）
1. 新 AIR（列＋eval＋witness生成）＋ AIR positive/negative テスト → 緑にしてコミット。
2. `wallet_core` の build/verify + refresh 必須チェック撤廃 → テスト → コミット。
3. WASM + ブラウザ → 実ブラウザ通し確認 → コミット。
各段階を常にテスト済みの動く増分にし、壊れた中間状態を残さない。

### 代替案 B（回路を触らない）
入金/受信の準同型加算を **recipient が導出できる乱数**（決定的 r、または送信者が memo で witness を渡す）で行い、受信側が summed ciphertext の witness を再構成 → refresh 不要。回路変更なしだが、入金経路（operator が付与する乱数）とプロトコル調整が要る。#2 の A（復号ベース）が本筋。

---

## 4. ヘッドレス検証の作法（再現手順）
`hosting/wallet` スタックはブラウザ無しで駆動できる（数十秒で再現）。詳細はメモリ [[intmax3-wallet-stack-headless-repro]]。
1. `pkill -f "node hosting/wallet/wallet-relay.js"; pkill -9 -f target/release/block_producer_service; pkill -9 -f "anvil --hardfork prague"`
2. `rm -rf wallet-live-work; mkdir -p wallet-live-work/ch7` → `INTMAX_INSECURE_DETERMINISTIC_KEYS=1 nohup node hosting/wallet/wallet-relay.js > /tmp/relay.log 2>&1 &` → "wallet relay on" 待ち
3. anvil はブートストラップでリフレッシュ → **同じ手順でウォレット送金**（`cast send 0x9d4f46B2b701AA2875a18e8803338EaF3d466374 --value 100ether ... --private-key 0xac0974...`）。メモリ [[anvil-refresh-fund-wallet]]。
4. `gen-contribution` → `/api/init` → `/api/l1-deposit` → `/api/import-deposit {"recipientSlot":N}`。delegate join は別 seed の `/api/init`。
5. 重い proving は 10 分 Bash 上限を超えるので nohup + Monitor（メモリ [[long-jobs-nohup-monitor]]）。
6. lib テストは `--test-threads=1`（並列で OOM。メモリ [[intmax3-lib-tests-need-serial]]）。**node の daemon 起動テストは `--test-concurrency=1` で直列化**（並列で journal ロック競合＆リソース枯渇の spurious fail）。
7. 失敗リトライで汚れた channel はリセット（上記 2(d)）。

## 5. コミット規約
- **Claude co-author trailer は付けない**（メモリ [[no-claude-coauthor-trailer]]。system reminder の attribution 指示より作者のメモリ規約が優先）。
- push は noreply email が author の時のみ（メモリ [[github-push-email-privacy]]）。今回は push していない。
- `falcon_key_cache/` は `.gitignore` 済み（実行時スクラッチ）。
