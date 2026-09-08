# 実装全行 Lean 化 — 2026-09-08 時点の再開手引き

この文書だけで作業を再開できるように書いています。会話の記憶を前提としません。

## 0. 現在地（一行で）

core 71 file と依存側の主要部の行対応が完了し、全 entrypoint の資金保存を一本の定理に合成し、
未証明の前提を 13 個の名前付き field に集約した状態です。**全体完了でもリリース承認でもありません。**

## 1. 場所と状態

```text
worktree : /Users/andropov/repos/intmax3-zkp/.claude/worktrees/mle-plonky2-proof-completion-48398c
branch   : codex/implementation-linewise-lean-20260906
HEAD     : b3e19c2  feat(lean): accept the pinned MLE submodule as a named trust assumption
base     : 680146f からこの HEAD まで 59 commit
submodule: contracts/lib/polygon-plonky2 = 6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78 (clean)
push     : **未実施**。ローカル commit のみ。指示があるまで push しません。
```

作業ツリーは clean です。`git status` に何も出ないのが正常な再開時の状態です。

**重要な事故の記録。** 以前この作業は `/private/tmp` 配下の worktree で行っており、macOS の再起動で
その worktree ごと消えました（未 commit の 21 module と 30 以上の対応表が失われ、作り直しました）。
現在の worktree は永続ボリューム上にあります。**`/private/tmp` に作業を置かないでください。**
agent 出力は 10 分ごとに WIP commit する `doc/audit/zkp/agent-tools/autocommit.sh` を回すのが安全です。

## 2. 検証コマンド（再開後まず全部通ること）

```sh
cd /Users/andropov/repos/intmax3-zkp/.claude/worktrees/mle-plonky2-proof-completion-48398c
export PATH=/Users/andropov/.elan/bin:$PATH        # pinned Lean 4.10.0。他の lean を使わない
bash .github/ci/lean-safety-guard.sh               # → PASS
python3 -B .github/ci/lean-line-coverage.py        # → PASS
python3 -B .github/ci/lean-line-coverage.py --require-complete   # → exit 1 が正しい
python3 -B .github/ci/test-lean-safety-guard.py    # 29 tests OK
python3 -B .github/ci/test-lean-line-coverage.py   # 22 tests OK
python3 -B .github/ci/test-lean-fixture-parity.py  # 40 tests OK
python3 -B .github/ci/lean-fixture-parity.py       # 18 fixtures / 177 fields / 0 FAIL
git diff --check
```

期待値：main guard は **125 Lean modules / 現行 72 modules / 470 reviewed-source hashes / 1 submodule pin**、
line guard は **169 source maps**、行分類は
`translated 31,085 / dependency-boundary 10,850 / non-executable 9,816 / test-only 23,834 / untranslated 41,783`。

`lake build` を全体で回すと 10 分程度かかります。個別 module は
`cd doc/audit/zkp && lake build Zkp.Implementation.<Name>` です。

## 3. 作業用 tooling（リポジトリ内・版管理下）

`doc/audit/zkp/agent-tools/` にあります。絶対パス依存はなく、自身の位置から repo root を導きます。

| ファイル | 用途 |
|---|---|
| `module-README.md` | 新規 module を書く agent への指示書。CI 規則、証明の落とし穴（kernel timeout poisoning ほか）を含む |
| `linemap-README.md` | line-map JSON の schema と正直さの規則 |
| `validate-linemap.py` | 対応表 1 件を検証。`PROBE OK` が出るまで直す。`--no-probe` で Lean 起動を省略 |
| `register2.py` | 未登録 module を一括登録（Zkp.lean import / guard CURRENT / manifest / inventory）。既登録 module の定理一覧も再生成するので、定理を足したあとの hash 更新にも使う。引数なしで冪等 |
| `tmo.py` | macOS に `timeout` がないための代替。`python3 tmo.py 300 lake env lean <file>` |
| `autocommit.sh` | 10 分ごとに agent 出力を WIP commit する保険。バックグラウンドで回す |

agent に指示するときは README 内の `<root>` を実際の worktree 絶対パスに置換して渡してください。

## 4. 何が証明できていて、何が前提か

### 4.1 前提なしで証明済み（`Zkp.Implementation.SystemSafety`）

任意の有限 trace（Rollup 入金、withdrawNative / withdrawERC20、materializer credit、Manager pull、
submitClaim、claimCredit payout、close の request / cancel / finalize、rollback を覆う 12 の `Step`）について:

- `trace_conserves_per_token` — token ごとの保存則。
- `trace_channel_attribution` — Manager の `received` が自チャネルの cap を超えない、cap は書き換わらない、
  materialization は一度 latch されたら保持される。
- `trace_nullifier_single_use` — 消費済み nullifier の永続と再提出の失敗。
- `trace_paid_bounded` — `paid ≤ received` の保存と paid / unspent 分解。

### 4.2 実装から導出できた前提（もはや仮定ではない）

- **nullifier freshness**: `IndexedMerkleTree.accepted_insertion_implies_key_absent`。
  受理された挿入証明は key の不在を含意します。前提は Poseidon の衝突耐性（葉の 18 語符号化の
  単射性は証明済みなので残るのは hash 本体のみ）、順序集合不変条件（空木で成立・挿入で保存）、
  key の範囲の 3 つだけ。hash 仮定なしでも `insert_fails_iff_key_present` が成立します。
- **選択回路の意味論**: `UtilGadgets.select_vec_one_hot_selects_candidate`。
  SwitchBoard が仮定していた 4 積和選択を実装から証明。ただし one-hot 性は強制されません。

### 4.3 回路と Solidity の一致（4 本）

`DepositChain.chain_matches_rollup_fold`、`ChannelRegChain.chain_matches_rollup_fold`、
`ValidityChain.circuit_pi_layout_matches_solidity_preimage`、
`WithdrawalChain.circuit_layout_matches_rollup_verifier`。
いずれも手書きモデル同士の照合ではなく、回路側の語列・byte 列が Solidity 実装モデルの計算と
一致することを導出したものです。

### 4.4 名前付き前提 13 個（`Zkp.Implementation.TrustBoundary`）

`closeProofSoundness` / `withdrawalProofSoundness` / `postCloseProofSoundness` /
`closeVectorBacked` / `signatureValidity` / `circuitKeccakIsSolidityKeccak` /
`tokenFundsHashBinding` / `finalizedRootObservation` / `finalizedHeightObservation` /
`durableNullifierLedger` / `durableMaterializationLatch` / `sourceRefinement` /
`mleVerifierSoundness`。

**`mleVerifierSoundness`（前提 a0）は運用者判断で受容した信頼仮定です。** KZG ceremony と同格。
pinned MLE/WHIR サブモジュール（commit `6cefc6ac` に限定）を翻訳せず信頼します。
これが買うのは `mle_assumption_reduces_close_soundness_to_gate_lowering`（close 経路の隙間が
`CloseStatementLowering` の 1 段だけになる）で、買わないことは
`SystemSafety.mle_assumption_does_not_imply_fund_safety` と
`mle_assumption_alone_does_not_yield_close_gate_soundness` が反例で示します。
MLE の 68 file・33,974 行は inventory 上 **untranslated のまま**で、検証済みには算入していません。

**残る隙間の位置**は `SystemSafety.close_vector_backing_is_exactly_premise_c` が明示します。
Rollup escrow が pooled であるため、cap をチャネル自身の預入に結ぶ部分は前提 (c) のままです。

## 5. 次にやるべきこと（優先順）

1. **`ChannelRegRecord::validate` の到達不能な canonicality 検査を直す。** 下記 6 の実在不具合。
2. **`balance_state` の古いテスト 2 件を更新する。** member_count 16 → 2..=8。
3. **CI に `cargo test --lib` を足す。** これがない限り同種の失敗は今後も検出されません。
   ただし lib 全体は重い回路テストで OOM します。`--release --locked --lib <module>::` の分割実行か、
   `--skip measure --skip bench` が必要です（`.github/ci/rust-test-guard.sh` の作法に合わせること）。
4. **残る前提の削減。** `CloseStatementLowering`（gate 生成）と claim 側 (b1, b2) の lowering、
   hash binding (e1, e2)、署名妥当性 (d) が主対象。(f) finality と (h) refinement は
   形式化しても仮定のままです。
5. **未翻訳 41,783 行**は MLE 33,974 行（受容済み）＋残り約 7,800 行（falcon vendor の f64 FFT、
   各 module が untranslated と明記した部分）。無理に translated へ付け替えないこと。

## 6. 人間の判断が要る発見

いずれも定理として固定済み。脆弱性の実証ではありません。番号は進捗文書と対応します。

**実在する不具合（1 件）**
- `ChannelRegRecord::validate` の非 canonical identity 拒否は **到達不能**。
  `PoseidonHashOut::try_from(Bytes32)` が同じ 32/32 分割を組み直す全域関数のため。
  リポジトリ自身のテスト `common::channel_registration::tests::test_channel_reg_validate_rejects_noncanonical_identity_encodings`
  が実際に失敗します（`cargo test --release --locked --lib` で再現確認済み）。
  Lean 側でも `ChannelRegChain.native_canonicality_check_cannot_fail` と
  `BlockTypes.canonicality_rejections_come_only_from_the_callback` が独立に同結論。

**古いテスト（2 件）**
- `common::balance_state::tests::balance_state_validate_multi_n` と
  `balance_state_delegate_count_regions_and_h1` が member_count 16 の通過を主張。
  `fd467ea`（sig-cluster を 8 に制限）以降 2..=8 が正。テスト側の更新漏れ。

**設計上の観察**
- **チャネル木はブロックを通じた資金保存を強制しない。** `ChannelLeaf` に fund vector がなく、
  公開 root は IMCH preimage を差し替えても不変（`UpdateChannelTree.native_account_root_ignores_channel_state_fields`）。
- **`update_channel_tree.rs` では署名が一切検証されない。** `bp_sig_chain` への fold のみ。
- **チャネル間送金の対応付けはブロック側で行われない。** `destination_channel_id` はどこからも読まれない。
- **Falcon 検証器は vendor 木に存在しない。** 復号器の係数範囲はノルム境界を含意しない
  （`FalconVendor.decode_range_does_not_imply_norm_bound`）。
- **回路 gadget が署名を検証するかは、gadget 自身が制約しない 1 本の wire 次第。**
  wire が 0 だとノルム境界検査が定数 0 の範囲検査に置き換わる（`FalconCore.padding_slot_norm_gate_is_trivial`）。
- **受理された集約証明は署名者の相異性も member 集合への所属も示さない。**
- **`agg_list.rs:329` の `range_check(count_minus_one, 4)` は署名者数 1〜16 を許す。** 上限 8 は構造由来。
- **hash 署名は再生可能なトークン。** 公開値に nonce も期限もない。健全性は依拠側が
  `pk_b` を登録済み leaf から解決し IMPA digest を高々一度受理することに依存。
- **`channel.rs` の `validate()` は構造のみを制約。** 両 root を保ったまま鍵集合全体を差し替えても通る
  （`ChannelTypes.validate_accepts_substituted_member_set`）。署名検証器は blob 内容に反応しない。
- **葉と節点で domain 分離がなく**、高さ 32 の空 SendTree と空 TxV2Tree の root が hash 仮定なしで一致。
- **`test_utils` は cfg(test) なしの公開 module**。harness の決定的 Falcon 鍵導出が production 到達可能。
- **domain 非衝突検査は test 専用かつ release 無効。**
- **`U32LimbTargetTrait::get_witness` は field wire を 2^32 で黙って切り捨てる。**
- **`U63Target::enforce_ge` は上端の窓（正確に `2^32 - 2` 値）で順序検査にならない。** 32 bit 版は健全。
- **sparse 木の範囲外 index 更新は葉を記録しつつ root を変えない。**
- **文書と実装の不一致**: `channel_tree.rs` は member root を 1024 slot と書くが実際は高さ 3 の 8 slot。
  `agg.rs` は `AGG_LEVELS = 4` / 公開入力 137 と書くがコードは 3 と 73（`batch.rs:695` の
  assert メッセージも 137 のまま。assert 発火時に運用者が読む文言）。

## 7. 禁止事項（前任からの引き継ぎ、継続）

- `--require-complete` を通すために未翻訳区間を根拠なく translated にしない。
- callback の成功を proof soundness / ownership / freshness とみなさない。
- `root != oldRoot` を freshness とみなさない。`paid ≤ received` を他チャネル非越境の証明とみなさない。
- cluster 署名を利用者資産の正当性とみなさない。
- MLE の信頼仮定を他の未証明依存へ拡張しない。commit `6cefc6ac` にのみ及ぶ。
- benchmark 確認なしに runtime、proof parameter、proof format を変更しない
  （runtime 基準 `05ec7ae` に対する `src` / `contracts` / `Cargo.toml` / `Cargo.lock` の差分は現在ゼロ）。
- main checkout や MLE submodule を reset / checkout / 削除しない。
- 20 並列を超えて agent を投入しない（ハード上限）。credit を使い切ると全 agent が同時に落ちます。
