# A-3 本実装 仕様書: channel close / withdraw-to-L1 / settle ライフサイクル

ステータス: **承認済み(2026-06-20)**。実装はフェーズごとに、着手前に専用の attacker subagent レビューを通す(CLAUDE.md §Adversarial)。

**承認された決定(§7):**
1. **anchor の on-chain チェックを入れる**(`finalizeClose` で `finalizedStateRoots(root)` 要求)。Manager bytecode 変更 → close fixture 再生成を伴う。
2. **今すべて実装する**(P1–P6 全部。post-close-claim、specialClose/lateOutgoingDebit の **revert 化**=forgeable stub を塞ぐ、も含む)。
3. **liveness grief は明記に留める**(健全な救済は cross-layer 証明待ちで別途)。

## 0. ゴールと前提

CLI(`channel_member`)から、実 L1 を相手に **deposit → 運用 → close → challenge → withdraw → claim** の完全な channel ライフサイクルを駆動できるようにする。現状 `close`/`withdraw`/`settle` は fail-closed スタブ(A-3 安全化済み)。

**決定的事実(調査・攻撃者レビュー済み):**
- on-chain の settlement 機構(`ChannelSettlementManager.sol` / `ChannelSettlementVerifier.sol`)と close 系回路(close / withdrawal-claim / post-close-claim / cancel-close)は **既に REAL でほぼ完成**。`CloseLifecycleE2E` が fixture でこの全経路を緑にしている。
- 欠けているのは **接続層**:(1) 実 L1-anchor のソーシング、(2) wallet_core の close ビルダ、(3) CLI コマンド、(4) on-chain 提出、(5) relay/E2E。
- 新しい暗号プリミティブは不要。member の N-of-N 共署名・balance proof・withdrawal proof はすべて既存。

## 1. 現状(既に REAL なもの)

| 層 | 状態 |
|---|---|
| `ChannelSettlementManager`: requestClose / submitCloseIntent / cancelClose / finalizeClose / submitWithdrawalClaim / submitPostCloseClaim / pullChannelFunds / claimWithdrawalCredit | **REAL** |
| state machine: Active → ClosePending → Closed、GRACE=600s / CHALLENGE=86400s | **REAL** |
| 払い出し: `pullChannelFunds`(rollup→manager)→ `claimWithdrawalCredit`(member へ)、`totalCreditedOut ≤ receivedChannelFunds` 大域ソルベンシー上限 | **REAL** |
| `ChannelSettlementVerifier`: verifyCloseIntent(95 limbs)/ verifyWithdrawalClaim(48)/ verifyPostCloseClaim(56)/ verifyCancelClose(27)、VK set-once | **REAL MLE/WHIR** |
| close 系回路 + `test_fixture` witness builders | **REAL** |
| 資金カストディ: `IntmaxRollup.withdrawNative` が finalized state root に束縛し manager の `pendingWithdrawals` を満たす | **REAL** |
| `verifySpecialClose`(C2)/ `verifyLateOutgoingDebit`(C3) | **DISABLED stub**(detail2 §H-3、本仕様の対象外。下記 §3.5) |

## 2. ギャップ(本実装で作るもの)

1. **実 L1-close anchor**(`channel_fund_intmax_state_root`)— 現状ゼロ placeholder。
2. **wallet_core の close ビルダ** — `build_close_full_witness` / close 証明生成 / `build_withdrawal_claim` / channel withdrawal proof(recipient=manager)。
3. **CLI コマンド** — `close` / `settle`(=finalize)/ `withdraw` / `claim`(+ challenge 用 `cancel-close`)。
4. **on-chain 提出** — `cast send` で Manager / IntmaxRollup を叩く。
5. **relay エンドポイント + 実 E2E**(anvil、fixture ではなく CLI 駆動)。

## 3. 設計

### 3.1 L1-close anchor(`channel_fund_intmax_state_root`)— 攻撃者レビュー結論

**結論(Option B、攻撃者 subagent 検証済み):** この値は **channel 内部の member 署名値**で、IMCH/IMCL/IMCI に keccak 折り込みされるのみ。回路は外部 rollup root と一切照合しない。資金安全性は **別経路の withdrawal proof**(`ext_public_state_commitment` を `IntmaxRollup.finalizedStateRoots[]` で検証 + nullifier)が**完全に**担保。
- ゼロ anchor:**SAFE**(over/double-withdraw 不可、払い出しは withdrawal proof が gate)。
- 偽造 anchor:**SAFE**(IMCH が変わり member の list-proof が通らない=第三者偽造不可。member 自身が署名しても払い出しは別 gate)。
- double-backing:**SAFE**(deposit nullifier + settled_tx_chain 分離 + manager ソルベンシー上限)。

**採用方針:**
- **(必須)実値のソーシング**:`setup-backing` 時に `IntmaxRollup.latestFinalizedStateRoot()` を RPC 取得し、`ChannelBacking.intmax_state_root` に格納(placeholder 廃止)。genesis 組み立てで `ChannelFund.intmax_state_root` に流す。→ 意味論を正す+将来の post-close 機能の前提を満たす。
- **(推奨・低コスト)on-chain 整合チェック**:`finalizeClose()` で `finalizedChannelFundIntmaxStateRoot != 0` なら `IntmaxRollup.finalizedStateRoots(root)` を要求(`CloseFundAnchorNotFinalized`)。将来の誤用を防ぐ防御的措置。**※これは IntmaxRollup bytecode を変えないが Manager bytecode は変わる → close fixture 再生成が必要**(A-2 と同じ metadata-hash 性質)。採否は §7 で要決定。

### 3.2 wallet_core の close ビルダ(新規 pub fn)

すべて既存機構の配線。新暗号なし。

| 関数 | 入力(wallet が既に持つ) | 出力 | 補助(既存) |
|---|---|---|---|
| `build_close_intent(state, close_nonce, burn_tx_hash, snapshot_medium_block_number)` | 署名済み `ChannelState` | `ChannelCloseWitness`(intent+close_tx) | `CloseIntent::new` |
| `build_close_full_witness(close_witness, member_auth, balance_proof, member_sigs)` | record.member_pk_gs、`channel_attestation.bin`(=balance proof)、member の IMCH 共署名 | `ChannelCloseFullWitness` | `ListCircuit::prove_append` で N sig を fold |
| `prove_close(full_witness) → MleProof JSON + CloseProofFields` | 上記 | close MLE 証明 + descriptor | `generate_close_fixture.rs` と同じ wrap+MLE |
| `build_channel_withdrawal(state, manager_addr, finalized_root)` | 署名済み state、manager アドレス、finalized root | withdrawal proof(recipient=manager) | 既存 withdraw 回路(withdrawNative 経路) |
| `build_withdrawal_claim(final_balance_state, member_index, regev_sk, recipient)` | finalized balance、member の regev_sk | `WithdrawalClaim` + E-3 proof + MLE | 既存 withdrawal_claim 回路 |
| (任意/後) `build_post_close_claim(...)` / `build_cancel_close(revived_state, close_intent)` | — | post-close / cancel MLE | 既存回路 |

**鍵となる現実的論点**:close 証明は **N-of-N member が IMCH digest に共署名**する必要がある(threshold なし)。これは `cosign` と同じ機構で、relay が全 member を所有する構成(現状の delegate demo)なら 1 コマンドで集められる。**1 人でも拒否すると close は作れない**(liveness は cancel/special-close 側の話 → §3.5)。

### 3.3 CLI コマンド仕様

| サブコマンド | 役割 | 主な処理 | on-chain |
|---|---|---|---|
| `close <manager_addr>` | close 意図の生成 | 最終 state を読み、N-of-N IMCH 共署名を集め、`prove_close` で close MLE 生成 → `close_intent.json` + `close_intent_mle.json`。`requestClose` 未了なら先に投げる | `cast send Manager.requestClose()` → `submitCloseIntent(intent, mleProof)` |
| `cancel-close <manager_addr> <revived_state.json>` | challenge: 新しい署名済み state で close を撤回 | `build_cancel_close` → MLE | `cast send Manager.cancelClose(req, mleProof)` |
| `settle <manager_addr>` | challenge 期間後に finalize | challengeDeadline 経過を確認 | `cast send Manager.finalizeClose()` |
| `withdraw <rollup_addr> <manager_addr>` | rollup から manager へ資金移動 | `build_channel_withdrawal`(recipient=manager、finalized root)→ withdrawal proof | `cast send IntmaxRollup.withdrawNative(...)` → `Manager.pullChannelFunds()` |
| `claim <manager_addr> <member_slot>` | member ごとの取り分主張+引き出し | `build_withdrawal_claim`(member の regev_sk)→ MLE | `cast send Manager.submitWithdrawalClaim(claim, mleProof)` → `claimWithdrawalCredit()` |

- 状態ファイル:`close_intent.json` / `close_intent_mle.json` / `withdrawal_claim_*.json` を channel dir に出力(既存 fixture と同スキーマ)。
- 秘密鍵の扱いは CLAUDE.md 準拠(`.claude/priv` を shell 展開、assistant に載せない)。

### 3.4 relay エンドポイント(任意・E2E 用)

`/api/close`(N-of-N 共署名を集め close MLE 生成)、`/api/settle`、`/api/withdraw`、`/api/claim`。relay が全 channel を所有する前提で、各々 CLI を cwd 切替で起動(既存 `/api/inter/send` と同型)。

### 3.5 対象外(明示)

- **specialClose(C2)/ lateOutgoingDebit(C3)**:detail2 §H-3 で「forgeable stub → DISABLE」。本実装では**実装しない**。むしろ別 PR で **entry point を revert 化**して forgeable stub を塞ぐのが正(安全側)。本仕様では「呼ばない/触らない」。
- **post-close-claim**:回路は REAL だが happy-path close には不要。フェーズ後半 or 別 PR。

## 4. 脅威モデル(CLAUDE.md チェックリスト)

| 脅威 | 緩和 | 状態 |
|---|---|---|
| 第三者が close を偽造 | close 回路が N-of-N member IMCH 署名を ListCircuit で検証。非 member 鍵は member_set_commitment 不一致で拒否(Finding E/D) | 既存 REAL |
| stale state で close(古い残高を凍結) | challenge 期間(86400s)+ `cancelClose`(REAL):より新しい N-of-N 署名 state を提示で撤回。`revived_version > close_version` を回路強制(Finding B) | 既存 REAL |
| over-withdraw / double-withdraw | nullifier 使用済みマップ + `totalWithdrawn ≤ fund` + `totalCreditedOut ≤ receivedChannelFunds`(実受領額上限) | 既存 REAL |
| ゼロ/偽造 anchor | §3.1 攻撃者結論=資金安全(別 withdrawal proof が gate)。実値化は意味論+将来防御 | 本実装で実値化 |
| 払い出し先すり替え | `registeredRecipientOf[pkG]` が registration 時固定、member pk→recipient 1:1 束縛 | 既存 REAL |
| close の liveness grief(1 member 拒否で close 不能) | **残存リスク**:N-of-N 必須のため悪意 member は close を妨害可。special-close(本来の救済)は DISABLED。→ 既知の制約として明記、別途設計 | 設計課題(明記) |
| challenge 期間の anvil 時間操作(テスト) | `vm.warp` / anvil `evm_increaseTime` で制御 | テスト手段 |
| manager アドレスの fixture 焼き込み(CREATE2 metadata-hash 脆さ) | 本番は通常デプロイ済み manager の実アドレスを使う(CREATE2 はテスト専用)。Manager bytecode を変える変更(§3.1 推奨チェック等)は close fixture 再生成が必要 | 留意点 |

**着手前**:各フェーズ実装の直前に専用 attacker subagent を回し、上記 + 新規発見を確認する(CLAUDE.md 必須)。

## 5. フェーズ分割(falsifiable な成果物)

- **P1 — 実 anchor**:`setup-backing` で `latestFinalizedStateRoot()` 取得→`ChannelBacking.intmax_state_root` に格納、genesis に伝播。placeholder 廃止。(任意)`finalizeClose` の on-chain チェック追加 → 採否は §7。**検証**:backing JSON に実 root、既存テスト緑。
- **P2 — wallet_core close ビルダ**:`build_close_intent` / `build_close_full_witness` / `prove_close`。**検証**:新規 Rust 単体テストで close MLE を生成・self-verify、negative(改竄署名/非 member)で拒否。
- **P3 — CLI `close` + `cancel-close`**:意図生成 + 共署名集約 + on-chain 提出。**検証**:anvil で requestClose→submitCloseIntent が通る。
- **P4 — `settle` + `withdraw` + `claim`**:finalize → withdrawNative → pull → submitWithdrawalClaim → claimWithdrawalCredit。**検証**:anvil で member が実 ETH を受領。
- **P5 — relay + 完全 E2E**:`/api/close|settle|withdraw|claim`、CLI 駆動の anvil E2E(deposit→運用→close→challenge→withdraw→claim)。**検証**:新 `tests/close_lifecycle_cli_e2e.rs`(real proof、強 negative、エラー文字列固定)。
- **P6 — 後始末**:`tasks/a3-close-lifecycle-followup.md` を closed に、fail-closed スタブを実装に置換。specialClose/lateDebit の revert 化は別 PR 提案。

各フェーズ末で `tasks/audit-fixes-todo.md` 系に成果を記録。

## 6. テスト計画

- **単体(Rust, release)**:close/withdrawal-claim/cancel の witness ビルダ correctness + negative(改竄 IMCH、非 member 署名、stale version、amount 改竄)。`tests/inter_channel_live.rs` のエラー文字列固定パターンに倣う。
- **on-chain(forge)**:`CloseLifecycleE2E` を CLI 駆動版に拡張、または新 `ChannelSettlementManager` negative(verdict・期間境界)。
- **E2E(anvil, Rust 駆動)**:`tests/close_lifecycle_cli_e2e.rs` — deposit→close→challenge(cancel で撤回も)→settle→withdraw→claim、member の L1 残高増を assert。重い(実証明)ので明示的にユーザー許可を取る。
- **回帰**:`generate_*` fixture と `CloseLifecycleE2E` が緑のまま。Manager bytecode を変えたら close fixture 再生成(§3.1 留意点)。

## 7. ユーザー決定が必要な点

1. **anchor の on-chain チェック(§3.1 推奨)を入れるか**:入れる=意味論強化+将来防御だが Manager bytecode 変更→close fixture 再生成が必要。入れない=実値化のみ(資金安全は変わらず)。**推奨:入れる**(防御的、低コスト、A-2 と同じ再生成を 1 回行う)。
2. **スコープ**:happy-path(P1–P5)までか、post-close-claim / specialClose revert 化まで含めるか。**推奨:まず happy-path + cancel-close を完成(P1–P5)、post-close と stub revert 化は別 PR**。
3. **liveness grief(1 member 拒否で close 不能)**の扱い:本実装では「既知の制約」として明記に留めるか、救済(special-close の健全版=cross-layer non-inclusion 証明)まで設計するか。**推奨:今回は明記に留め、救済は別途**(detail2 §H-3 が cross-layer commitment 待ちとしている)。
