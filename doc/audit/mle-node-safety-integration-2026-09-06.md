# MLE更新とノード安全性修正の統合記録

日付: 2026-09-06。
親ブランチ: `codex/node-presign-safety-20260905`。
作業場所: `/private/tmp/intmax3-node-preflight-audit-20260905.m7xtV6/checkout`。
本書の統合はローカルのみ。push・デプロイ・L1送信は実施していない。

## 1. 何を取り込んだか

リモートを確認した結果、MLEの新しい修復統合は
`InternetMaximalism/intmax-plonky2` の
`origin/codex/main-mle-whir-repair-20260905`、
`ca5c8fc6a4d3bd40bc9616af0e62df82ff764a2f` だった。

ただし、親が既に使っていた `b569e0d7` の直系後継ではない。
共通起点 `5b1c28ae` から分岐しており、単純な参照置換では既存の
target-105 / inverse-rate-6 とガス最適化を失う。
したがって両方を残す実際のマージをサブモジュール内で作成した。

| 対象 | コミット |
| --- | --- |
| ノード修正の基点 | `a2886fff08c2619ba47604e4d2fa5634b9e17471` |
| 前回のノード修正を保全したコミット | `b5bafb7` |
| 更新前のMLE pin | `b569e0d71c6a7a180fe616915b7a76976540b155` |
| 取り込んだMLE更新 | `ca5c8fc6a4d3bd40bc9616af0e62df82ff764a2f` |
| 統合後のMLE pin | `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78` |

MLE側ブランチは `codex/mle-node-safety-integration-20260906`。
統合コミットは更新前pinと取り込んだ更新の双方を親に持つ。
親リポジトリの `main` 全体や、過去のPCS修復を戻す別ブランチは取り込んでいない。

## 2. 維持・変更したもの

- 前回の署名前・入金前・永続化・復旧のノード修正は、`b5bafb7` に保存したまま維持。
  詳細は `doc/audit/audit05-09-2026-node-presign-remediation.md`。
- productionのwire形式、profile JSON、Solidity生成定数、v3 verifier、
  canonical v3 fixtureは既存の最適化済み版と同一。親のproof/config/companion一式も再生成していない。
- 新しい変更として、Rust旧APIの `legacy-conformance` 隔離、旧Solidity
  `MleVerifier` のabstract化、CI、過去のLean文書を統合した。
- 親の `deprecated-msu` は、明示的な旧fixture用ビルドに限り
  `plonky2_mle/legacy-conformance` を伝播する。通常版・WASM版で旧APIやMSUを有効化しない。
- `.gitmodules` の追跡先を統合ブランチへ修正。リリースで使うのは常に親のgitlink。
  `git submodule update --init --recursive` を使い、`--remote` で古い別系統へ移動しない。
- 文書の競合は履歴を区別して解消。旧transcriptテストは同じ値の生成済み定数を参照する。
  古いLean監査や上流Plonky2監査を、現在のMLE/WHIR全体の保証と読み替えない旨を明記した。

元の `/Users/andropov/repos/intmax3-zkp` のチェックアウトと未追跡監査文書は変更していない。
専用作業ツリーにあったソース展開コピーは、同じpinの実Git作業ツリーに置き換えた。
旧コピーは専用一時ディレクトリ内の `polygon-plonky2-b569-export-backup` と
`forge-std-export-backup` に保全。forge-stdの依存pinは変更していない。

## 3. 確認結果

Rustは固定nightly `nightly-2025-03-23` と `--locked --offline`、
Solidityは `0.8.29` / via-IR / optimizer 200 / Prague で確認した。

| 確認 | 結果 |
| --- | --- |
| 親Rust全target + 現行4種のfixture生成featureのコンパイル | 成功 |
| WASMライブラリのコンパイル | 成功 |
| MLEの通常版旧API隔離doctest | 4/4 |
| MLE v3 schemaとWHIR profileのdrift確認 | 3/3 |
| 明示的legacy版の旧schema確認 | 1/1 |
| 正常な小回路での新規証明生成・native/JSON/compact/ABI/config roundtrip | 1/1 |
| MLE旧artifact隔離・凍結transcriptのSolidityテスト | 5/5 |
| 親の既存正常証明・public input・ガス検査 | 32/32 |
| 親のrelease fixture整合性（既存cohort/config/proof/companion） | 選択した9/9、失敗0 |
| production Solidityのサイズ確認 | 成功 |

親の32件は、fixture網羅性17、claim正常検証5、compact正常検証3、
public-input-returnガス6、Managerクローズガス1。
Rustのfixtureテストは `mle_v2_fixture_release` の10件中、
既存生成物の整合性を確認する9件を選択。入力変形を行うhelperテスト1件は今回の選択外。
テスト全体の表示ガスにはfixture読込・準備も含むので、それを実トランザクションのガスと混同しない。

現fixtureによるcold Managerクローズの計測値は、
実行 `16,963,263` + intrinsic calldata `2,060,788` = **`19,024,051` gas**。
2,000万上限に `975,949` gasの余裕がある。compact proofは `131,716` bytes。
これは今回のfixtureによるローカルharness測定であり、過去の別fixtureの測定値との直接比較ではない。

主要runtimeサイズは `MleVerifierV2` 20,053 B、`PinnedMleVerifierV2` 12,570 B、
`SpongefishWhirVerify` 23,656 Bで既存の記録と同じ。
`ChannelSettlementManager` は24,398 Bで、EIP-170上限まで178 B。
証明時間の比較ベンチマークは実施していない。productionの証明生成アルゴリズムと設定は維持したが、
全実行環境で性能不変と測定済みである、とは主張しない。

既存のunused／dead-code／Solidity lint等の警告は残る。
今回の確認は統合互換性の確認であり、新しい全面的な脆弱性監査や攻撃再現ではない。

## 4. 次の作業・共有順序

1. pushする場合は、先にMLE側 `codex/mle-node-safety-integration-20260906` をpushし、
   `6cefc6acee18d0d76b52f1c22c0113e3ae8fbf78` がリモートから取得できることを確認する。
   その後、親の `codex/node-presign-safety-20260905` をpushする。
   親だけを先に共有すると、取得できないsubmoduleを参照する状態になる。
2. 別環境で親の固定gitlinkを取得し、nativeとWASMを再ビルドする。
   本マージだけを理由に既存state、署名履歴、入金予約、outbox、exit-kitを削除しない。
3. 前回からの残作業である通常PWのexact backing attestation自動接続、
   watcherの確定済み履歴による入金分類、browser／daemon／chainを通した本番同等E2Eを継続する。
   今回の統合だけでこれらが完了したとはしない。
4. 本番配布では既存の `doc/tasks/regen-and-redeploy-runbook.md` に従い、
   circuit/config/profile/runtime hashと実デプロイ先を照合する。
   既存の今回対象fixtureに形式変更はないため、マージ作業中の一律再生成・再デプロイは行っていない。
5. MLE独立レビューと残るrelease gateは、サブモジュールの `mle/README.md`、
   `mle/audit/node-safety-integration-2026-09-06.md` の対象範囲を守って扱う。

KZG ceremonyの信頼、少なくとも一人の正直な署名者によるオフチェーン検査、
自チャネル内の全署名者結託の許容、MSU廃止の方針は変更していない。
