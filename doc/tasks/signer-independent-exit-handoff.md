# Signer-independent exact-vector exit: handoff

## 作業対象

- 作業ブランチ: `codex/signerless-latest-head-exit-20260903`
- 開始コミット: `9f5d820` (`fix: close release blockers and retire direct MSU`)
- 作業ツリー: `/private/tmp/intmax3-signerless-exit.2qrfge`
- `contracts/lib/polygon-plonky2` はサブモジュールであり、この作業では変更していない。
- KZG trusted setup は、依頼どおり信頼仮定として扱い、blocker にしていない。

## ここまでに実施したこと

### 1. 最新署名済み state を単一の close 対象に固定

`V` と `B` を token ごとに混ぜる経路を廃止し、close は一つの認証済み whole-state vector を対象にした。`ChannelSettlementManager` と `CloseFundingMaterializer` は、channel、settled chain、TFD、拡張 state root、anchor を同一 proof から読み、exact vector を原子的に materialize する。古い close、異なる identity、stale-burn、異なる generation は fail-closed になる。

### 2. 署名者不在の退出材料

`src/live_balance_service.rs` に signed-head exit kit を追加し、完全な N-of-N state `H` が durable になる時点で、その state に対応する Balance proof、whole-vector backing proof、固定 public inputs、root、anchor を保存・検証する設計にした。L1 側は channel の追加署名を要求せず、保存済み kit と permissionless backing attestation を使って close/finalize/materialize を進める。

### 3. Close backing circuit

`src/circuits/channel/close_asset_backing_circuit.rs` を追加した。Balance proof/VK、PrivateState、ExtendedPublicState、asset registry、canonical zero limbs を再構成し、全 token の asset tree と TFD を exact に拘束する。public inputs は固定 26 limbs で、proof size/既存 close circuit ABI を変更しない additive な回路である。

### 4. Solidity の安全境界

- `ChannelSettlementManager.sol`: whole-state close、finalized/pending high-water mark、reorg rollback、exact TFD、historical authenticated partial withdrawal を実装。
- `CloseFundingMaterializer.sol`: permissionless backing attestation、attestation receipt、exact vector credit、channel/generation/freeze guard、二重 materialization 防止を実装。
- `IntmaxRollup.sol`: materializer の set-once、post/rollback journal、release runtime guard を実装。
- 旧 MSU の安全でない経路は production から停止・隔離した。

### 5. 公開 prover/publisher/deployment

- `public_close_prover` の bundle schema を更新し、backing proof、MLE proof、26 PI、root/anchor、protocol metadata を bundle に含めた。
- `public_close_publisher` は attestation → submit → finalize authorization → finalize → materialize の順序を WAL に記録する。raw signed transaction は broadcast 前に fsync する。
- attestation は permissionless で、他 watchtower の勝者を exact event/receipt/getter で採用できる。
- `DeployCloseCli.s.sol` と `channel_member` は既存 Rollup への materializer 接続、distinct backing VK、bundle hash/PI/root/metadata pin、nonce/target/calldata の再検証を行う。

### 6. 検証済みテスト・サイズ

- SignerIndependentExit: 11/11
- ChannelSettlementManager: 79/79
- PartialWithdrawal: 42/42
- DeployGuards: 30/30
- Node focused tests: 14/14
- EIP-170 サイズ: IntmaxRollup 24,533 B、Manager 23,988 B、Materializer 15,339 B（いずれも上限内）。
- Rust の backing circuit fixed-width PI test、`cargo check`、publisher の既存テストを実行済み。ただし publisher の最終 attestation 順序テストと全体再実行は引き継ぎ後に必ず再確認する。

## 引き継ぎ後に必ず行うこと

1. **作業ツリーと差分を確認**
   ```sh
   cd /private/tmp/intmax3-signerless-exit.2qrfge
   git status --short
   git diff --check
   ```

2. **publisher の最終整合性を完成**
   - completed journal の schema を `PUBLICATION_VERSION`（現在 3）に合わせる。
   - completed publication の `attest_transaction_hash` を journal の exact attestation observation と比較する。
   - 全ての `submit_observation` 採用箇所で、`CloseSubmitted` の semantic position が attestation より厳密に後であることを要求する。
   - 再起動、同一 block 内 tx 順序、attestation の race、reorg/rollback、stale event 混入をテストする。

3. **channel_member の signer-independent 運用を再確認**
   - kit は完全な N-of-N state `H` の受理時に durable であること。
   - `H` の後に cosigner signature を要求する経路がないこと。
   - 内部中間遷移を外部の canonical head と誤認しないこと。
   - browser/wasm の raw signing 経路が公開環境で kit なしに canonical head を公開できないか再監査する。

4. **3 ラウンドの攻撃・防御レビューを完了**
   - Round 1: whole-vector mixing、stale burn、double materialization、cross-channel backing を攻撃。
   - Round 2: attestation race、reorg、cancel/replay、delegate/partial-withdrawal の exact-vector 不整合を攻撃。
   - Round 3: signer 不在、WAL crash、同一 block の ordering、RPC 差し替え、browser/public claim を攻撃。
   各ラウンドで再現テスト、修正、同じ攻撃の再実行を記録する。

5. **全テストとベンチマーク**
   ```sh
   /Users/andropov/.cargo/bin/cargo check --bin public_close_publisher
   /Users/andropov/.cargo/bin/cargo test --lib close_asset_backing_circuit
   forge build --sizes --skip test --skip script
   forge test --match-contract SignerIndependentExit -vvv
   forge test --match-contract ChannelSettlementManager -vvv
   forge test --match-contract PartialWithdrawal -vvv
   forge test --match-contract DeployGuards -vvv
   ```
   既存 close proof の proof size/time と backing proof の size/time を比較し、既存 ABI・本番ベンチマークを悪化させていないことを記録する。

6. **公開環境の境界を確認**

   MLE/WHIR PCS の constituent-evaluation 問題は別サブモジュール監査の範囲であり、本ブランチで暗号学的に修復しない。公式 deploy、Rollup/Manager の value boundary、chain ID、MLE VK、bundle hash が本番では fail-closed であることを再確認する。

7. **レビュー後に commit/push**

   ```sh
   git diff --check
   git add HANDOFF_SIGNER_INDEPENDENT_EXIT.md
   git commit -m "docs: add signer-independent exact-vector exit handoff"
   git push -u origin codex/signerless-latest-head-exit-20260903
   ```

## 既知の注意点

- 実チェーンへの broadcast は未実施。deployment bundle、nonce、manager/materializer address、MLE verifier code、backing VK、finalized readback を実チェーンで確認してから行う。
- MLE/WHIR PCS の Critical は別スレッドで扱う。これを解決済みと記載してはいけない。
- Foundry は sandbox 内で macOS SystemConfiguration により落ちる場合があるため、その場合は承認済みの `forge test` 実行環境で再実行する。
- 最終的な release 判定は、上記の publisher 順序検証、3 ラウンド攻撃レビュー、全テスト、ベンチマーク、実デプロイ readback が揃ってから行う。

---

# 引き継ぎ後の実施記録（2026-09-03、`codex/signerless-latest-head-exit-20260903` 8f70b73 以降）

上記「引き継ぎ後に必ず行うこと」1〜7 を実施した結果。行番号は本記録時点のもの。

## 1. 作業ツリー

`8f70b73` を fast-forward で取り込み、submodule を初期化。`git diff --check` はクリーン。
この handoff 文書はコミット `8f70b73` に含まれていなかったため `doc/tasks/` に取り込んだ。

## 2. publisher の最終整合性（`src/public_close_publisher.rs`）

見つかったギャップと修正:

- **完了 journal の schema 検証がハードコード `!= 2`** だった（`PUBLICATION_VERSION` は 3）。publisher が自分で書いた完了 journal を次回起動で常に拒否する liveness バグ。`PUBLICATION_VERSION` と比較するよう修正し、`load_or_create_journal` でも検証する。
- **`attest_transaction_hash` が再検証パスで一切参照されていなかった。** 完了 journal の再検証と journal ロード時に、`attest_observation`（`advance_attestation` が毎回オンチェーン再検証する）の tx hash と照合する。
- **`CloseSubmitted` の semantic position が attestation より厳密に後である要求が存在しなかった。** `discover_semantic_confirmation` に `strictly_after` を追加し 9 箇所すべての呼び出しで attestation observation を下限として渡す。ローカル receipt 採用箇所（`ReceiptState::Finalized`）、完了 journal 再検証、journal ロード時にも `require_after_attestation` を適用。順序は `(block_number, transaction_index)` の辞書順で、同一 block 内は transaction index で決まる。
- **テストハーネスが attestation ステージ未対応**で 30 中 16 件が失敗していた（`SignedHeadBackingAttested provenance count 0 != 1`）。`FakeBackend::new` が外部 watchtower の attestation receipt（block 10, index 1）を持つようにし、`attested_backend()` で採用済み状態から close 状態機械へ入る。

追加テスト（すべて通過、計 37 件）:

| テスト | 対象 |
|---|---|
| `permissionless_attestation_winner_is_adopted_and_local_raw_is_superseded` | attestation race: ローカル raw 送信後に他者の attestation が先に finalize → 採用、ローカル loser の revert 確定まで nonce lane を解放しない |
| `close_submitted_in_the_attestation_block_must_follow_the_attestation_index` | 同一 block 内順序: index が attestation より小さい submit は拒否、大きい submit は採用 |
| `local_submit_receipt_ordered_before_the_attestation_is_rejected` | RPC 差し替えで自分の submit が attestation 前に見える場合の拒否 |
| `adopted_attestation_is_revalidated_and_fails_closed_after_reorg` | attestation block の reorg |
| `foreign_attestation_events_are_filtered_and_duplicate_exact_attestations_fail_closed` | stale/foreign event 混入、重複 exact attestation |
| `completed_publication_attestation_provenance_and_schema_are_revalidated` | 完了 journal の attest hash / schema 改竄 |
| `journal_load_rejects_close_provenance_at_or_before_the_attestation` | journal ロード時の順序不変条件 |

契約側は同一 `proofId` の `SignedHeadBackingAttested` を一度しか emit しない（`CloseFundingMaterializer.sol` `attestSignedHeadBacking`）ため、重複 exact attestation は RPC 側の異常であり fail-closed が正しい。

## 3. channel_member / kit の再監査

- kit は N-of-N head と同一スナップショット（`persist_snapshot`: create_new 0600 → fsync → rename → dir fsync）で原子的に永続化され、`verify_snapshot_semantics(require_exit_kit=true)` が commit/load ごとに proof を再検証する。head だけ durable で kit が無い窓は無い。
- H 以後に cosigner 署名を要求する退出経路は無い。`cmd_close` は cosigner 鍵を導出しない。資産/構成を動かす 8 つの署名 purpose は `requires_prepared_exit_kit` で署名プリミティブ前に一律拒否されている（pre-sign prepare+fsync receipt の API 化まで）。
- 内部中間遷移は canonical head にならない（`live_balance_service.rs` の線形進行チェック: epoch+1 / state_version+1 / small block・fund・settled chain・accumulator・nullifier root・import cursor 不変）。
- **wasm/browser のギャップを修正**: `wallet_cosign` に kit ゲートが無かった。`wallet_core::verify_exit_kit_preserving_successor` を追加し、`wasm_wallet::wallet_cosign` が署名解放前に「H2=0 かつ backing statement 完全不変の後続」だけを許可する（CLI の拒否と同じ境界）。テスト `cosign_gate_refuses_every_asset_or_composition_moving_successor`（release）。
- 未修正の注意点: `receive_deposit_unbound` は bound 済み channel への追加 deposit を stale kit 検出で fail-closed にする（機能制限）。`settle_close_funding` は deprecated で kit を install しない dead path。kit 再利用判定は anchor を比較しない（意図的、文書化のみ）。

## 4. 3 ラウンドの攻撃・防御レビュー

### Round 1（Solidity: mixing / stale burn / double materialization / cross-channel）

既存ガードはすべて有効（`BackingPublicInputsMismatch` は TFD かつ settledTxChain の一致、`proofId` が proof 全体を束縛、`ChannelAlreadyExited` latch は credit 前に書かれ rollback でも消えない）。未カバーだった攻撃に `contracts/test/SignerIndependentExit.t.sol` へ 10 件追加（21/21）: settledTxChain 交差、anchor 改竄、cross-channel、未 bind manager、未 freeze materialize、未 finalize root、複数 channel 交錯 rollback（順序違反含む）、rollback 後の再 materialize、escrow 不足時の原子的 revert。

**重大バグ（修正済み）: `IntmaxRollup.registerSettlementManager` が materializer を一度も install しない。** Yul は引数を右から左に評価するため `and(staticcall(...), eq(returndatasize(), 32))` は call 前の `returndatasize()==0` を読んで常に偽だった。実デプロイでは `requestClose` が `NotBoundManager` で常時 revert し、`creditChannelExit` が永久に閉じる。既存 suite は stub materializer しか使っていなかったため緑だった。`let ok := staticcall(...)` に直し、`DeployGuards.t.sol` に `MaterializerSetOnceTest`（set-once、credit gate、registration が bind を呼ぶ）を追加。EIP-170 サイズは不変（24,533 B）。**Rollup バイトコードが変わったため close fixture 一式を再生成**（§5）。

### Round 2（attestation race / reorg / cancel-replay / delegate・PW の exact-vector）

Rust 側は §2 のテストで再現。node delegate 側の監査で実害のある 3 点を修正:

- `node/delegate/branches/owntx.js` `doBurn`: cosigner 応答の state が top-level だと `verifyCosignedStructural` は通るのに import がスキップされ、`acceptedHead` が burn 前のまま `BURN_FINALIZED` になっていた。以後の close は `CloseOlderThanAuthorizedBurn` で永久拒否。nested `state` を必須化し import を無条件化、import 後に head が進んだことを確認、PW ticket に `burnHead {digest, epoch, stateVersion}` を記録。
- `node/delegate/branches/exit.js`: close 進行中に chain 由来の deposit import で `acceptedHead` が進むと publisher が別 digest の journal を開き、元の journal が二度と進まない liveness wedge。`publicClosePublication.acceptedHeadDigest` に head をピン留めし、`CloseCancelled`/reconcile の CANCELLED 変換でのみ解除。
- `exit.js`: ローカル burn 高水位マーク（`burnHead`）より古い head での close request / publication を `CLOSE_BELOW_AUTHORIZED_BURN` で拒否（`Store.listTickets` を追加）。
- `api/routes/close.js`: caller 指定 `manager` を無検証で CLI argv に渡し devnet ゲートも無かった。`full-withdrawal.js` と同様に chain 31337 限定にし、アドレス形式を検証。

テスト: `node/test/delegate-burn-head.test.js`（5 件）、`node/test/api-close-route-devnet.test.js`（2 件）、`delegate-close-lifecycle.test.js` に 2 件追加。

### Round 3（signer 不在 / WAL crash / 同一 block / RPC 差し替え / browser）

- WAL: 4 ステージすべて reservation → sign → offline decode 検証 → journal fsync → broadcast の順。復旧は保存 raw bytes のみ再送し、nonce が動いていれば停止。
- RPC 差し替え: 5 つの runtime code hash、pinned block での二重読み、same-height replacement 拒否、receipt の二重読み、event+getter の完全一致が必要。calldata/target は bundle と manifest の sha256 から局所生成され RPC に依存しない。
- 同一 block: §2 で `(block, tx index)` 厳密順序を導入・テスト。
- browser: §3 の wasm ゲート。`/api/backing` は kit 材料を配らず、claim ルートは 50 PI の withdrawal claim であり canonical head を公開できない。

## 5. テストとサイズ

| suite | 結果 |
|---|---|
| `cargo check --bin public_close_publisher` | OK |
| `cargo test --release --lib close_asset_backing_circuit` | 4/4 |
| `cargo test --release --lib public_close_publisher` | 37/37（引き継ぎ時点は 16 失敗） |
| `cargo test --release --lib cosign_gate_refuses_every_asset_or_composition_moving_successor` | 1/1 |
| forge `SignerIndependentExit` | 21/21（+10） |
| forge `ChannelSettlementManager` | 79/79 |
| forge `PartialWithdrawal` | 4 suite 59/59 |
| forge `DeployGuards` + `MaterializerSetOnceTest` | 33/33 |
| forge 全体（fixture 再生成後） | 551 件中 550 通過、1 失敗（CloseLifecycleE2E、下記）、skip 0 |
| node 全体 | 441 件、失敗 0 |
| EIP-170 | IntmaxRollup 24,533 B / Manager 23,988 B / Materializer 15,339 B（不変） |

**forge 全体で引き継ぎ時点に失敗していた 32 件**の内訳と処置:

- `CloseFundingAuthorization.t.sol`（15）: 退役した cooperative close funding API を叩いていた。tombstone テスト 3 件に置換し、生きている pull/claim nullifier のテストは維持（10/10）。
- stale close を許容していた旧仕様のテスト（14: `AuthorizedBurnFenwick`、`CloseExitLivenessInvariant`、`CloseLifecycleHardening`、`CloseLifecycleRedTeam`、`RedTeamRound3`）: `CloseOlderThanAuthorizedBurn` / `CloseForksAuthorizedBurn` を主張する fail-closed テストに書き換え。invariant handler は admissible な close を生成するよう修正（256 runs / 128,000 calls）。
- `CloseLifecycleE2E`（2）: Manager/Rollup 初期コードが変わったため close fixture が stale。再生成で解消。

**fixture 再生成**: runbook Step 1 に従い plain set → printer → close family（`close_` withdrawal / close / withdrawal_claim / post_close_claim / cancel_close / c2c / wasm）を一括生成。printer（`test_printCloseManagerAddress`）は `setUp` が `close_lifecycle*.json` を無条件に読むため、旧 close set を退避するのではなく plain set を `close_` 名にコピーして両予測を一致させる必要がある（runbook 未記載）。さらに予測アドレスはテスト contract のライブラリリンク先に依存し、**任意の Solidity テストファイルを編集するだけで動く**（本作業中に `0x894a…`→`0xb1f6…`→`0x894a…` と変化した）。したがって close family の焼き込みは Solidity 側の編集がすべて確定した後に行うこと。最終的に焼き込んだ Manager アドレスは `0x894a113DB75C344CCC287A7C1ECC5CfDC2B06d1B`。

`ClaimMleVerify.test_realMleVerifier_rejectsMismatchedFinalDuplicateRow` は特定 fixture のバイトオフセットを固定していた。WHIR の final round は 2^11 の domain から 16 query を引くため、再生成した proof に重複 query が含まれる確率は fixture あたり約 6% しかない。テストは現在の WHIR 形状から重複 row を動的に探索し、どの fixture にも無い場合は理由付きで skip する。今回は cancel_close を繰り返し再生成し（1 回目の batch では 30 回不発）、重複 query を含む proof が得られた時点の `cancel_close_mle.json` を採用したので skip は発生していない。

**CloseLifecycleE2E（残る唯一の赤）**: アドレス一致後、E2E は `submitCloseIntent` で `ChannelFundStateRootNotFinalized(0x00000001…04…)` で止まる。原因は fixture 設計が新設計に追随していないこと:
1. `close_circuit::test_fixture::build_close_full_witness_two_token` が `channel_fund.intmax_state_root` にプレースホルダ `[1,2,3,4]` を入れており、Manager は `registry.isFinalizedStateRoot` を要求する（E2E で finalized なのは lifecycle の genesis root と `final_state_root` のみ）。
2. 新設計では `_checkCloseProof` が `requireSignedHeadBacking` を要求するため、同じ署名済み state に対する whole-vector backing proof（26 PI、MLE ラップ）を E2E 内で `attestSignedHeadBacking` する必要がある。backing proof の `finalized_extended_state_commitment` は lifecycle chain が finalize する拡張状態のコミットメントそのもの（channel の asset leaf が close vector `[77, 55]` と一致する状態）でなければならず、backing fixture の生成器は存在しない（`close_asset_backing_circuit` を使うのは `channel_member` のみ）。
つまり close fixture と lifecycle chain の拡張状態を共生成する新しい生成器（`DeployCloseCli.s.sol` が期待する `close_asset_backing_{manifest,mle,public_inputs}.json` を出力）と E2E の backing VK 初期化・attestation 手順の追加が必要で、本セッションでは着手していない。E2E は明示的な revert で失敗し続ける（skip にはしていない）。

ベンチマーク: backing circuit は既存 close circuit と独立な追加回路で、close proof の size/time と Manager/Verifier ABI は変更していない（`public_inputs_roundtrip_is_fixed_width` で 26 limbs 固定を確認）。

## 6. 公開環境の境界（未解決事項、release 判定の前提）

- **MLE/WHIR PCS の constituent-evaluation 問題は未解決**（別サブモジュール監査）。本ブランチでは扱っていない。
- `IntmaxRollup.releaseRuntime` は `creditChannelExit` を含む価値移動を chain 31337 に固定している。signer-independent exit は現時点で公開チェーンでは実行できない設計（MLE エンジン未リリースのため）。Manager 側の `releaseRuntime` は challenge-period floor のみで、両者の「production」の定義がずれている。
- `DeployCloseCli.s.sol` の既存 Rollup 接続ブランチ（`EXISTING_ROLLUP`）は fixture/driver/テストが無く、一度も実行されていない。読み込むファイル名（`close_asset_backing_{manifest,mle,public_inputs}.json`）は prover の出力名（`public_close_manifest.json` / `backing_mle.json` / `backing_public_inputs.json`）と一致せず、rename 手順が未定義。backing VK ≠ close VK の明示的比較も無い（provenance のみ）。
- publisher は `cast mktx` の nonce を RPC から取るため、悪意ある RPC が nonce を膨らませると journal 済み raw が永久に broadcast 不能になる（資金は動かない liveness 問題）。`finalized` タグは単一 RPC 依存。
- Rollup の value boundary は global `totalEscrowed` / per-token のみで per-channel 台帳は無い（健全性は proof に依存）。
- JS publisher は `bundles/<digest>/` の存在だけで再 prove を省略する（内容の sha256 束縛無し、局所的）。

## 7. commit/push

本記録の変更は同一ブランチ上に論理単位でコミットする。実チェーンへの broadcast は未実施。

---

# 追記（2026-09-04）: 資産移動 8 purpose の解放と close 経路の残件

前節「テストネットを止めているもの」のうち、このリポジトリ内で完結する 2 項目を実装した。

## 1. pre-sign exit kit（`doc/docs/pre-sign-exit-kit.md`）

`requires_prepared_exit_kit` の一律拒否を、「署名対象の後続状態 H' の kit が検証・fsync 済みで
durable であること」を要求する本来のゲートに置き換えた。

- **live balance service** `prepare_exit_kit`: 提案（未署名）の後続状態に対し、commit せずに
  kit を証明し、署名検証を構造検証（`verify_snapshot_structure`）に置き換えた意味検証を通した
  artifact を返す。TokenRegister / L1DepositImport / InterChannelDebit の 3 proposal。
- **producer staging**: debit 系は後続の settle chain が「N-of-N 済みブロックの投稿」に依存する
  ため、未署名の提案状態でブロックを journal の `prepared` entry として staging する
  （`StagedInterChannelExitKit`、`BlockWitnessGenerator::unsigned_staging`）。ブロックハッシュ・
  各 root・`bp_sig_chain` の statement `(IMSB digest, 登録 signer pk 列)` は署名バイトに依存
  しないため、staging 時の head snapshot は実 N-of-N ブロックと byte 一致し、`post_inter_channel`
  はそれを検証したうえで in-place で promote する（不一致は fail-closed）。staging 中は close
  funding の prepared と同様に他の producer 変更を凍結し、`abandon` で解除できる。
- **CLI**: `cli_state.json` schema 5（`prepared_exit_kit_receipt` 必須キー）、
  `--propose-exit-kit`、`INTMAX_PREPARED_EXIT_KIT`、`verify_public_backing_proposed` による
  検証・content-addressed アーカイブ・署名前 save、採用時の receipt promote。宛先側 credit
  （InterChannelFundImport/BundleApply）は「純増のみ ＋ 現 head の receipt 検証済み」で署名し、
  受領後に `install-exit-kit` で kit を入れる（kit-pending 状態）。CloseFunding は on-chain で
  退役済みのため拒否のまま。
- **API**: `api/lib/exit-kit.js`（propose → `livePrepareExitKit` → 署名、失敗時 abandon）、
  register-token / deposit import / burn / inter-channel の各ルートを二相化。
- **wasm**: 変更なし（ブラウザは資産移動 purpose の署名者ではない。前節の cosign ゲートは維持）。

副作用の修正: `receive_deposit_unbound` が awaiting 遷移時に旧 kit を落とすようにし、bound 済み
channel への追加 deposit が fail-closed で止まる問題を解消。

テスト: `signing_ledger_tests` 10/10（新規 4 件: exact successor 解放と promote、二段 import の
kit 共有、宛先 credit の kit-pending、CloseFunding 退役）、`tests/live_balance_service.rs` に
staging → prepare → 検証（提案 digest のみ受理、N-of-N 検証は拒否）→ 署名 → promote → settle の
実 proof 統合テスト、node `api-exit-kit.test.js` 3 件と既存ルートテストの更新。

## 2. close 経路の残件

- **backing fixture 共生成器**（`generate_close_fixture`）: lifecycle chain（deposit 6 / withdraw 3）
  の最終 `ExtendedPublicState`・balance proof・asset vector から close witness と whole-vector
  backing proof を共生成し、`close_asset_backing_{manifest,mle,public_inputs}.json` を出力。
  `intmax_state_root` は finalized な `final_state_root`、anchor は 3。
- **CloseLifecycleE2E**: `initializeBackingVk` と `attestSignedHeadBacking` を追加し、実 contract
  で request → attest → submit → finalize → payout が通る。
- **DeployCloseCli 接続ブランチ**: `DeployGuards.t.sol` に `EXISTING_ROLLUP` ブランチのテストを
  追加（`Deploy.s.sol` で作った Rollup に接続し、backing VK 初期化と readback を検証）。
- **deploy readback**: `channel_member export-close-deployment-manifest <out> <rpc>` を追加。
  ACTIVE settlement binding から publisher の deployment manifest v3 を生成し、activation
  checkpoint で runtime code hash と MLE verifier（`allowedChainId`）を再読込・照合する。
  `doc/docs/public-close-publisher.md` の例を v3 に更新。Sepolia 等の実チェーンでの実行は
  鍵と資金が必要なため未実施。

## 残る前提

MLE/WHIR PCS の Critical と `IntmaxRollup.releaseRuntime` の chain 31337 固定は変わらず、
公開チェーンでの価値移動はその解決後になる。
