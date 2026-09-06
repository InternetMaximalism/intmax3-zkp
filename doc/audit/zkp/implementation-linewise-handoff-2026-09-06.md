# 実装全行 Lean 化・資金健全性監査 — handoff（2026-09-06 第 2 回）

前回 handoff（`e604a36` 時点）の Step 1〜7 を実施した記録です。
詳細な件数と境界は [implementation-linewise-progress.md](./implementation-linewise-progress.md) を参照してください。

## 0. 結論

全実装の Lean 化と「資金を盗めず、失わない」証明は、引き続き**未完了**です。
今回は Balance / 状態更新 / channel state-update / 復号 gadget の 8 モジュールを
build・独立レビュー・修正・登録し、main guard と line guard を通しました。
`--require-complete` は意図どおり失敗します。リリース承認ではありません。

## 1. 今回の作業

| 項目 | 結果 |
|---|---|
| `DecryptionGadget` の `omega` 失敗（`native_key_halves`） | 符号で場合分けして解消。source 717 / 726–727 の `[-2,2]` と `e.max(0)` / `(-e).max(0)` と一致 |
| `ChannelStateUpdate` の build | 前回の「standalone 成功」は再現せず。`repeat' (apply every_bind; intro)` が `List.range slotCount` の展開で無限再帰（19 GB 超）。`bind_ok_iff` による書換えと join point の `split` へ置換。加えて 3 証明を修正。現在は約 4 秒で compile |
| 独立レビュー（4 件） | blocker なし。精度修正を適用：`channelTxDigest` を 7 入力へ、未使用 `validateRecord` 削除、transport bytes 空強制の定理、`core_row_integer` 合成定理、digit-255 境界、`PrivateState` の native/target を別転記、`UpdatePrivateState` の名前修正と vacuity guard、`SwitchBoard` の HashMap / cap count 注記 |
| line-map | 5 件新規（balance-public-inputs、switch-board、balance-circuit、channel-state-update、decryption-gadget）。既存 3 件と合わせ 8 件を登録 |
| 登録 | `Zkp.lean` import、guard `CURRENT`、manifest（156 hashes、36 theorem_checks）、inventory の `line_map` |
| guard | main guard PASS（89 modules、36 current modules、1,273 theorems、kernel axioms のみ）、line guard PASS（29 maps）、回帰 51/51、`git diff --check` clean |
| runtime | `05ec7ae` に対し `src` / `contracts` / `Cargo.*` の差分ゼロ。MLE `6cefc6a` clean |

物理行分類：translated 9,632 / dependency-boundary 2,438 / non-executable 5,476 /
test-only 6,738 / untranslated 92,913。証明率ではありません。

## 2. line-map 作成時に見つかった要確認事項（モデルは反映済み、判断は人間）

- send / fund import の受理は transport envelope の proof bytes が**空**であることを強制する
  （`validate_signed_small_block` の `transport_proof.is_empty()` と `== self.transport_proof.proof`）。
  実 verifier が空 bytes を拒否するかはこのファイルの外。
- `require_accumulator_push` は state-update verifier から呼ばれない（wallet 側のみ）。
- nullifier root は不等式のみ。挿入・freshness の検査はこのファイルにない。
- fund import は small block 自身の `close_freeze_nonce` を期待 nonce に渡す（自己参照）。
- in-channel の送信者認可は `sender_hash_sig` 非空の構造検査のみ。
- `epoch + 1` / `state_version + 1` は profile 依存の u64 加算、U256 `+` は carry で panic、
  直接 index（`member_pk_gs[depositor_slot]` 等）は `Err` でなく panic。`depositor_slot as u16` の切詰め。
- SwitchBoard：genesis 以外の候補が持ち回る VD は supplied balance VD と未結合。outer の
  cyclic-key check が唯一の境界。prove-time の cap count と constructor config の同一性は未証明。
- BalancePublicInputs：target の checked 割当は channel 0 を拒否しない（native は拒否）。
  `block_r ≤ block_number` はこのファイルで強制されない。
- DecryptionGadget：`FieldProducts` は未放電の前提。秘密鍵の一意性（module doc の CRITICAL-1）は
  形式化されていない。

## 3. Git 状態

```text
checkout: /private/tmp/intmax3-node-preflight-audit-20260905.m7xtV6/checkout
branch:   codex/implementation-linewise-lean-20260906
push:     未実施（明示指示後に行う）
```

## 4. 次セッション

1. 残る validity / deposit / transfer / withdrawal 回路と Balance の send / receive 回路の翻訳。
2. `Every` 系の証明は `apply` 剥離ではなく `bind_ok_iff` 書換えを使う（progress 参照）。
   重い module は `lake env lean` の prefix compile で bisect する。
3. 新 module 登録は Zkp.lean / guard CURRENT / line-map / manifest / inventory の 5 点を同時に行い、
   hashed file を編集したら guard を最後に再実行する。
4. `--require-complete` を通すための分類変更や admission は行わない。
