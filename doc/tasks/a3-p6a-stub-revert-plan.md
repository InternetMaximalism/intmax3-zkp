# A-3 P6-A: specialClose(C2) / lateOutgoingDebit(C3) revert 化 — 計画 + 脅威モデル

母艦: `doc/tasks/a3-p5-plus-plan.md`, detail2 §H-3(承認済み disposition)。

## 0. 何を・なぜ
conformance 監査の live 乖離を解消: detail2 §H-3 は C2/C3 を「forgeable stub なので entry を revert」と明記
だが、現状 `ChannelSettlementManager.sol` の `submitSpecialClose`(C2)/`submitLateOutgoingDebitCorrection`(C3)
は **live**(誰でも `_matches` 恒真スタブ証明を作って呼べる)。

- **C2 リスク**: 偽の検閲告発で channel を freeze(`channelStatus=ClosePending`)+ BP bond を slash。
  資金流出なし(slash 先 `bpBondCredits` は別ポット、未積立なら 0)だが **freeze-grief** 可能。
- **C3 リスク**: redundant。二重出金は各払出経路の nullifier used-set で既に防止済(§H-3 (1)-(5))。

## 1. 脅威モデル(disposition の安全性)
**revert 化後に失われる機能と、その安全性:**
- C2 無効化 → BP 検閲 slash が使えなくなるだけ。member 資金は動かない。健全な BP が偽 slash される footgun が消える(改善)。
  健全な non-inclusion 証明は validity/IntmaxRollup 層の cross-layer commitment が要る(未実装)→ それまで無効が正。
- C3 無効化 → 二重出金防止は nullifier used-set(`withdrawalNullifierUsed` / `usedWithdrawalNullifiers` /
  `usedSharedNativeNullifiers`、in-circuit 導出 + check-then-set CEI)+ stale close 拒否(cancelClose C1)で**完全に**担保。
  C3 は冗長。time-difference grief は accepted out-of-scope。

**revert 化が新たな攻撃面を作らないか:**
- 関数は即 revert(状態変更ゼロ)→ 攻撃面は減るのみ。
- ABI selector は型不変なので維持(呼ぶと dedicated error で確実に失敗 = fail-closed)。
- 他経路から内部呼び出しなし(external のみ、呼ぶのはテストだけ)→ 回帰なし。
- stub verifier(`verifySpecialClose`/`verifyLateOutgoingDebit`)は残置で可(entry が塞がれば到達不能)。

## 2. 実装
- [ ] `ChannelSettlementManager.sol`: error `SpecialCloseDisabled()` / `LateOutgoingDebitDisabled()` 追加。
- [ ] `submitSpecialClose` / `submitLateOutgoingDebitCorrection` の本体を **即 revert** に(引数名は省略=未使用警告回避、selector 維持)。
  `// SECURITY:` コメントで detail2 §H-3 disposition を参照。
- [ ] 影響テスト(`ChannelSettlementManager.t.sol` の3件)を「disabled→revert」アサートに置換
  (positive-path シナリオは仕様変更で消滅。テストを通すための改変ではなく**仕様変更の反映**)。

## 3. fixture 再生成(Manager bytecode 変更 → CREATE2 manager drift)
- [ ] forge build → 新 manager CREATE2 アドレス算出(`CloseManagerAddr.t.sol` 等)。
- [ ] `WD_RECIPIENT=<新 manager> WD_OUT_PREFIX=close_ generate_withdrawal_fixture`(heavy)で
  close_withdrawal_*/close_lifecycle* 再生成。close_intent*(generate_close_fixture)は manager 非依存=不要。
- [ ] `forge test --match-contract CloseLifecycleE2E` + `ChannelSettlementManager` 緑。

## 4. レビュー + 後始末
- [ ] **別エージェント(攻撃者視点)で revert 化をレビュー**(実装と別)。
- [ ] detail2 §H-3 を「実装済み(disposition 適用)」に更新。

## 5. 鉄則
IntmaxRollup/Manager bytecode を他に変えない。soundness は in-circuit + on-chain。秘密鍵は触らない。

## 所見ログ
- **実装完了**: 両 entry を `revert SpecialCloseDisabled()` / `revert LateOutgoingDebitDisabled()` に(signature 維持=selector 不変、`external pure`)。新 error 2 件追加。
- **テスト**: 影響 3 件を disabled→revert アサートに置換(仕様変更の反映)。Manager 全 66 件 PASS。
- **fixture 再生成**: Manager bytecode 変更 → 新 CREATE2 manager `0xED5e1c643d4726735cC564EfFA5D6AC2cC1A8FA8`。
  `WD_RECIPIENT=<新> WD_OUT_PREFIX=close_ generate_withdrawal_fixture` で close_ 再生成。CloseLifecycleE2E PASS。
  (close-intent section の skip は member-set 比較に由来する **既存**挙動。registration は git と byte 一致で確認。)
- **別エージェント攻撃者レビュー**: **critical 欠陥なし**。forgery 不能化・freeze liveness は cancelClose(C1)で維持・資金不動・spec 一致を確認。
- **deferred follow-up(非セキュリティ)**: dead code(`latestSpecialCloseDigest` / `usedLateOutgoingDebitNullifiers` /
  2 events / `computeSpecialCloseDigest`)は無害。除去は再び bytecode 変更=fixture 再生成を招くため将来 PR へ。detail2 §H-3 に明記。
- detail2 §H-3 を「IMPLEMENTED 2026-06, P6-A」に更新。

## 完了サマリ
P6-A 完了。C2/C3 の forgeable stub entry を revert 化(freeze-grief footgun 解消)。資金安全は不変
(soundness は nullifier used-set + cancelClose + in-circuit、C2/C3 非依存)。攻撃者レビュー GO。
