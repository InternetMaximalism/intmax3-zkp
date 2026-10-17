# Poseidon signature 残存モジュールのレビュー — 2026-10-16

**今回の対象で、新規の具体的な健全性の欠陥は確認しなかった。** 現行の `src/poseidon_sig` は旧署名方式の実装ではなく、ハッシュ列の形式と共通回路ガジェットだけである。native と回路の入力順序・範囲・canonicality、実際の Falcon／validity 側の接続を確認した。

ただし、前回 Falcon レビューで指摘した **P1：validity 回路での cyclic proof 内部検証鍵の結合漏れ**は、同じ HEAD で未修正である。この既報の問題を新規の Poseidon 問題として数え直さず、下流の署名履歴全体の保証を制限する事項として記載する。

## 対象とバージョン

ローカル `main` と、読み取り専用の `git ls-remote origin refs/heads/main` で確認したリモート main は、共に **`0a2f5a284c0ae6cf6d23e53b810240151e696724`**。対象は次の2ファイル、計177行で、HEAD との差分はない。

| ファイル | 現行の役割 |
|---|---|
| [mod.rs](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/mod.rs:1) | 旧方式の廃止説明、`list` の公開、予約済みの旧 domain 定数2個 |
| [list.rs](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/list.rs:1) | IMLL leaf・順序付き hash chain の native 関数と共通回路ガジェット |

`GoldilocksSecretKey`、`SingleSigCircuit`、旧方式の署名・検証器・fallback は現行の実行コードに残っていない。検索で残る参照は、廃止説明・予約 domain のテスト・旧 proof のテスト fixture である。[参照検索結果](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/retirement-reference-search.txt) を保存した。

関連する Plonky2 submodule の HEAD は `3a20a05fb99d2653c4d37debb4f1ead2f422dfb2`。対象・関連29ファイルの SHA256 とバージョン情報は [source-manifest.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/source-manifest.json) に保存した。製品コードは変更していない。既存の作業ツリー変更は維持し、テストは現在の Cargo patch／依存グラフを使った。変更のない HEAD 全体を別 checkout でビルドした結果ではない。

メンバー認証の接続を追う前に [sig-cluster と delegates の規則](/Users/andropov/repos/intmax3-zkp/doc/docs/sig-cluster-vs-delegates.md) を読んだ。以下の N-of-N は署名する sig-cluster のことであり、delegate の加入規則を制限する指摘ではない。

## native と回路の計算

IMLL 形式は次の固定レイアウトである。

```text
leaf_i = Poseidon(IMLL || message_i の8個のu32 || public_key_i の8個のu32)
C_0    = 0（4 field elements）
C_i    = Poseidon(C_{i-1} の4 field elements || leaf_i の4 field elements)
output = C_N を canonical な Bytes32 に変換
```

[list_leaf](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/list.rs:46) と [leaf_target](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/list.rs:84) は、同じ IMLL 定数、message、public key の順に、厳密に17個の field input を hash する。[list_chain_step](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/list.rs:55) と [chain_step_target](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/list.rs:99) は、前段4要素・leaf4要素の順に8個を hash する。native と target の両方が、同じ Poseidon no-pad sponge を使う。

各呼出しの arity は固定で、message／key の境界も固定なので、この API に可変長の切分けや padding の曖昧性はない。IMLL、現行 aggregate leaf の IMAL、鍵リストの IMPL、および予約済み旧 domain の値を確認し、現行の domain 非衝突テストも実行した。

native の `Bytes32` は8個の u32 なので、各 limb は `<2^32<p_Goldilocks` として単射的に field に入る。最終 hash output は4個の canonical field element から high／low の32-bit limb に変換される。順序を変えたり、末尾へ entry を加えたりした場合に commitment が変わることも既存テストで確認した。

これらは**ハッシュ計算の関数**であり、それだけで署名検証・公開鍵の所属・重複禁止・全員分の存在を検証しない。同じ pair の重複は仕様上許され、別の順序付き列を作る。署名された entry だと扱えるのは、署名を実際に検証する producer と、その commitment を必要な statement に結合する consumer を通した場合である。hash chain 単体を署名検証器として使う現行 caller は見つけていない。

## 入力範囲と canonicality の呼出元

`leaf_target` 自体は `Bytes32Target` の limb に range check を追加しない。この点は型の名前だけで保証されたとせず、現行の全 caller を確認した。

- 唯一の caller は [Falcon ListStepCircuit](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/list.rs:138)。署名検証ガジェットの `message_digest` と `pk_g` を、そのまま leaf に渡す。
- [Falcon ガジェット](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/gadget.rs:693) は両入力を `Bytes32Target::new(builder, true)` で作り、全 limb を32 bitに制約する。`pk_g` は内部で計算した公開鍵 digest に接続される。H2P が使う message と、leaf が使う message は同じ wire で、別の自由な witness はない。
- 前段 commitment は、[Falcon list](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/list.rs:153)、[aggregate list](/Users/andropov/repos/intmax3-zkp/src/falcon_sig/agg_list.rs:338)、[update_channel_tree](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/update_channel_tree.rs:1335) のすべてで `to_hash_out` を通す。

[Bytes32Target::to_hash_out](/Users/andropov/repos/intmax3-zkp/src/utils/poseidon_hash_out.rs:349) は、64-bit pair を単に mod p に還元するだけではなく、canonical な32/32 split に戻して元の Bytes32 と接続する。split は `hi=2^32-1` のとき `lo=0` を要求し、`x` と `x+p` の第二表現を排除する。出力も同じ canonical conversion を使う。

native の現行 consumer も [TryFrom による検査](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/update_channel_tree.rs:476) を通す。native list builder はゼロから hash の生成値だけを連結する。公開 field 配列を手作業で作れる utility の存在を、外部 Bytes32 の無検証取込みと混同しない。調べた実際の chain 境界では、mod-p alias による native／circuit の解釈差は確認していない。

## 現行の production 経路

production の [回路 factory](/Users/andropov/repos/intmax3-zkp/src/validity_prover_service.rs:2205) は `FalconAggCircuit → AggListCircuit → ValidityCircuit` を構成する。古い単一署名用 IMLL ListCircuit を validity producer として使う経路はない。

現行 validity path の leaf は、IMLL pair ではなく、次の IMAL statement である。

```text
pk_list_digest = Poseidon(IMPL || 全8署名者slotのBytes32、非active slotはゼロ)
leaf          = Poseidon(IMAL || IMCH digestの8 limb || signer_count || pk_list_digestの4要素)
chain step    = 共通の poseidon_sig::list::chain_step_target / list_chain_step
```

aggregate-list producer は、定数の外側 VK で検証した Falcon aggregate proof の PI から message・count・全鍵 slot を取り、そのまま leaf に結合する。consumer の [update_channel_tree](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/update_channel_tree.rs:1090) は、同じ IMPL／IMAL helper を使って同じ statement を再構成する。IMCH は実際の block の channel ID と tx root から計算される。署名イベントでは、member root の結合、signer_count の2–8範囲、active／padding slot の占有条件が課される。

chain は前段 extended state に接続され、その次の state と commitment にも入る。実際の [累積 proof builder](/Users/andropov/repos/intmax3-zkp/src/circuits/witness/block_witness_generator.rs:1141) は記録した署名イベントを順にすべて prove し、今回 span のイベントだけへ切り詰める処理ではない。これは処理順序と hash の接続を確認した結果であり、次の既報 P1 を解消するものではない。

## 既報 P1 の残存

[validity_circuit.rs:249](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/validity_circuit.rs:249) は、引き続き通常の `add_proof_target_and_conditionally_verify` で cyclic aggregate-list proof を検証している。cyclic proof の public inputs に入る内部 VK を、期待する wrapper の VK に固定する追加制約がない。外側 proof の検証と `C == final.bp_sig_chain` だけでは、署名履歴の prefix の帰納的保証を閉じられない。

位置、影響、既存の cyclic 用 helper を使う修正方針は [Falcon レビュー F1](/Users/andropov/repos/intmax3-zkp/doc/audit/docs/falcon-soundness-review-2026-10-16.md:21) に記載済み。今回、新しい偽造 proof や L1 受理を再現してはいない。正常な list proof の roundtrip は honest helper が正しい内部 VK を入れるため、この欠落の反証にはならない。

## 説明の修正点

[poseidon_sig/mod.rs:13](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/mod.rs:13) と [list.rs:20](/Users/andropov/repos/intmax3-zkp/src/poseidon_sig/list.rs:20) は、現行 update consumer が IMLL `(IMSB digest, bp_pk_g)` を再構成するように説明している。実際には上記の IMAL `(IMCH digest, signer_count, pk_list_digest)` で、共用するのは chain step である。list.rs の shared-gadget コメントにも削除済み `consumer` module への参照が残る。

[ExtendedPublicState の説明](/Users/andropov/repos/intmax3-zkp/src/circuits/validity/block_hash_chain/ext_public_state.rs:47) などにも旧 IMSB の表記が残る。現行 code は対応しており、これらの説明の古さだけから新たな bypass は確認していない。将来の誤接続を防ぐための文書修正点として扱う。旧方式の entropy note も、現行の署名方式の安全性を説明する文書としては使わない。

## 実行結果と限界

固定 nightly と現在の release build で、**20個の異なる既存テストが成功**した。

| 分類 | 結果 |
|---|---|
| IMLL native chain の順序・重複・空列 | 2 passed |
| Poseidon hash output／Bytes32 の native・回路変換 | 13 passed |
| 実際の Falcon 署名3件を累積し native commitment と比較 | 1 passed |
| 全 domain registry と Falcon domain 非衝突 | 2 passed |
| 旧 proof blob の parser／wallet での拒否 | 2 passed |

toolchain は `rustc 1.87.0-nightly (b48576b4d 2025-03-22)`。コマンド、個々のテスト名と実行ログは [test-results.json](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/test-results.json) と同じディレクトリに保存した。

さらに、元の `poseidon_sig` ソースを `#[path]` で直接取り込む [補助プログラム](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/fixture/src/main.rs) で2個の小さな回路を構築し、両 proof の検証が成功した。第1はゼロ・全u32最大値を含む3組の順序付き pair について、元の native／target leaf と各 chain step が完全に一致すること、第2は `0,1,p-2,p-1` の canonical field／Bytes32 roundtrip を確認する。署名の偽造や不正 proof の検証ではなく、形式の正常境界値テストである。[出力](/Users/andropov/repos/intmax3-zkp/doc/audit/zkp/evidence/poseidon-sig-review-20261016/boundary-probe.log)、Cargo manifest と lockfile も保存した。

hash chain の commitment としての意味は Poseidon の collision／second-preimage resistance に依存する。本レビューはその暗号解析、全再帰証明・プロトコルの形式証明、WASM での新たな実行測定ではない。新規指摘がないことと、既報 P1 を含むシステム全体の健全性が認定されたことは区別する。
