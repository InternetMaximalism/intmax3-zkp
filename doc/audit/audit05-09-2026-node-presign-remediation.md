# ノード署名前・入金前検査の修正と運用引継ぎ

日付: 2026-09-05。基点: `a2886fff08c2619ba47604e4d2fa5634b9e17471`。
作業ブランチ: `codex/node-presign-safety-20260905`。
作業場所: `/private/tmp/intmax3-node-preflight-audit-20260905.m7xtV6/checkout`。
本書の初版作成時点では未コミット・未 push。2026-09-06 の MLE 更新統合に先立ち、このノード修正を独立した保存コミットにまとめる。元の作業ディレクトリ／ブランチは変更していない。

## 1. 結論と対象

前回の監査の主要6件（N-01〜N-06）に対する防御を実装した。条件付き指摘のうち、ブラウザ署名履歴、退出鍵の重複、claim の非退化条件、Node 数値変換、burn／destination の復旧、freeze 前の投稿準備確認にも対応した。

「確認できない状態を署名して進める」のではなく、正常な取引を早い段階で検査し、一時失敗では保存済みの同じ処理から再開する方針である。**全リリース条件の完了宣言ではない。** 通常 PW の backing attestation 自動接続、watcher の入金分類、および本番同等 E2E は後述の残作業。

設計上の信頼条件は変更していない。

- 自チャネル内の全 sig-cluster 結託による自チャネル資産の不正配分は許容する。他チャネルの原資は保護する。
- 少なくとも一人の正直な署名者がオフチェーン検査を実施する設計を受容する。
- 最後の N-of-N 署名済み H から、追加のチャネル署名なしに退出できることを目標とする。
- KZG ceremony は信頼する。MLE/WHIR submodule と Solidity は今回変更していない。MSU／旧 CloseFunding は再有効化していない。
- ノードの local service・設定・private state は信頼境界内。外部入力の残高申告や recipient 申告を、private な検証済み記録と同一視しない。

## 2. 主要6件

| 指摘 | 変更 | 正常系・再開への配慮 |
| --- | --- | --- |
| N-01 提案生成時の早過ぎる状態署名 | `wallet_core` の send、refresh、inter-send／credit、deposit、token-register の builder は状態を未署名で返す。native／browser の明示的な検査済み署名境界を使う | 送信者本人の A11 取引認証は維持。二段階 import の構造検査と正常テストも未署名提案に対応 |
| N-02 通常遷移の close metadata | trusted record の参加人数、前 H の close-freeze nonce を照合。通常 send／refresh の small-block number も維持 | 正当な close-cancel 後の新しい era を、genesis の値に固定して拒否しない。import 固有のカウンタ増分は維持 |
| N-03 累積受取残高の u64 範囲 | `channel_credit_safety` で、検証済み保存則・token fund・自分の復号・private な保守的上限から、変更後の cell を署名前に確認 | チャネル全体に u64 の fund 上限を設けない。不明な残高をゼロ扱いしない。関係しない不明 cell だけでは全操作を止めない |
| N-04 架空の初期回収先 | 本番 `setup-backing`／genesis は全 controlled cosigner の回収先を明示必須化。形式不正、ゼロ、既知の synthetic 既定値を拒否 | 既存の署名済み recipient は変更しない。既存チャネルの操作に新規 genesis 設定を一律要求しない。明示 insecure テストだけ既定値を維持 |
| N-05 再加入後の誤った入金 slot | contribution の pkG・pkB・Regev key・署名済み recipient から元の正確な slot を解決 | 再加入者を「末尾 slot」と仮定しない。異なる intent への request ID 再利用は拒否 |
| N-06 支出後に初めて入金不可と判明 | native と同じ amount／token／slot／加算回数／受取余力を支出前に検査。余力を予約し、raw L1 transaction を永続化後に送信 | タイムアウトで新しい送金を作らない。同じ request ID・同じ raw・同じ tx hash で再開。完了した予約は再 credit しない tombstone として保持 |

### N-03 の限界を正確に読む

保存するのは private な上限であり、公開 snapshot や証明の public input は増やしていない。自分の暗号鍵で復号できる残高は exact に確認する。大きい fund でも、対象 cell の十分な上限が分かれば処理できる。

一方、巨大な token fund の下で他人の残高上限が分からない場合、正当な credit でも保守的に拒否することはある。これを完全に取り除くには、必要な範囲情報を安全に得る別の設計が要る。既存 refresh proof だけが u64 上限の証明になる、とは扱っていない。加算回数不足は通常 refresh で解消できるが、**隠れた残高の範囲情報不足が refresh だけで常に解消するわけではない**。

新しい入金予約を追加した際は、未署名の将来 head に対する以前の admission cache を破棄する。入金自身の予約は、その入金の検査時だけ二重計上から除き、署名途中では解放しない。全 N-of-N 完成後の状態と同じ WAL で完了させる。

## 3. 入金の保存・再開順序

1. private な signed head と recipient identity から受入条件を検査する。
2. trusted local live service が自チャネルの one-time deposit recipient を発行・保存する。
3. operation journal と native capacity reservation に intent／候補 slot／その recipient を固定する。
4. L1 transaction を署名し、raw bytes を fsync してから broadcast する。
5. reservation に exact tx hash を固定する。別 hash への付替えは禁止。
6. canonical chain receipt、recipient、depositor、amount、token、producer/live の処理を検証する。
7. fund-import と bundle の両後継を検査し、必要な exit kit と N-of-N を用意する。
8. `.pending-deposit-import.json` に完成後の状態と結果を保存してから head／結果を反映する。
9. 完了 receipt を `.deposit-import-receipts/` に保存し、同じ import の再試行は既存結果を返す。

回転する one-time recipient は、任意の HTTP パラメータから選択させない。`inspect`／`import` は private reservation と一致する tx hash からのみ、新しい期待 recipient を解決する。予約のない従来入口は `channel_backing.json` の recipient 照合を維持する。recipient の tag 検査だけでチャネル所有が証明できるという意味ではない。

request ID を省略した同一リクエストも同じ入金として再開する。**同額の新しい入金には新しい request ID を使う。** pending 処理があるというエラーを「未送金」と読み替えない。journal／reservation／raw bytes を消して再試行しない。

## 4. 追加で修正した保存・退出経路

- **Burn:** `.pending-burn-publication.json` が signed head と `last_burn.json`／`burn_cosigned.json` を束ねる。両 burn API は結果ファイルを見る前に native recovery を実行し、保存済みの burn を再署名しない。
- **Inter-channel:** A・B 両方の native process lock を保持する。逆方向の同時操作は非ブロッキングで競合を検出し、deadlock せず再試行する。無関係なチャネル pair の journal は復旧対象にしない。
- **B の保留操作:** B の deposit／burn／inter WAL が未復旧なら A の署名前に止める。標準 API は A と B の両方を事前復旧する。
- **B の kit:** archive、Balance verifier data、backing をすべて B のディレクトリで検証する。A の cwd にある別チャネルのファイルを使わない。
- **Inter WAL v2:** 保存された JSON に対して checksum を確認してから型付き状態を復元する。HashSet の再シリアライズ順序で正常な journal が破損扱いにならない。v1 は元の compact bytes と旧 checksum が一致する場合のみ読み込む。
- **Destination-only recovery:** `incoming_inter_transfer_recovery.json` を 2PC の保存対象に加える。B は保存済みの source input、producer receipt、live source artifact から receive と kit インストールまで再開できる。A の後続操作が source の便宜ファイルを上書きしても、それらに依存しない。
- **旧 inter 処理:** 完成済み入力に限る sidecar 補完、同一 request／input に限る旧 argv の再利用を実装。履歴削除や署名判断のリセットは行わない。
- **API exit-kit:** 子プロセス開始後の曖昧失敗を無条件 abandon しない。正確な提案・kit・request ID を保持し、受理済み head から完了状態を回復する。
- **Participant close／credit pull:** read-only `staticCall` に本人の `from` を明示する。
- **新規 freeze 前の readiness:** 完全な public-close bundle と pinned deployment に対し、exact H、両 state root、anchor、L1 finality、runtime/config、Active 状態、次の nonce を読取専用で確認する。同じ bundle を後段 publisher でも使う。既存 raw transaction の復旧には新たな readiness を要求しない。
- **Publisher 接続:** native の attest／materialize を含む全進行 phase と schema 3 の結果を Node 側で厳密に解釈する。

readiness は「未投稿・未確定の依存データがあるまま自分から freeze する」ことを抑える検査である。検査と実際の L1 transaction の間を契約上の原子的操作にするものではなく、他の L1 操作との全 race を排除する保証ではない。

## 5. ブラウザ・鍵・数値

- browser member mode は、署名を worker の外へ返す前に strict IndexedDB transaction の完了を待つ。同じ predecessor の別 successor は拒否し、同じ successor は保存済み signature を返す。通常 delegate 送信には不要な保存を追加しない。
- `wallet_sign_state` は contribution 時の期待 recipient と own Regev digest を署名前に照合する。
- 新規参加者／genesis では Regev exit key の重複、padding digest、退化した key を拒否する。変更された balance ciphertext は既存 withdrawal claim の非退化条件も確認する。資産ゼロの canonical empty slot は許可する。
- Node の金額・slot・token・channel・nonce を WASM 呼出し前に検査し、JS／WASM の数値切り詰めを資金移動の intent と取り違えない。

browser ledger は同一 origin／profile の永続領域である。削除、古いバックアップへの巻戻し、別 profile で同じ signer key を使う運用を安全化するものではない。raw WASM を直接利用する独自 host は同等の永続署名境界を必要とする。

## 6. 配布・移行

1. 旧／新 native を同じ state directory に混在させず、native・API・Node を合わせて更新する。private schema は6、inter WAL writer は2。旧バイナリへのそのままの downgrade はしない。
2. 既存の必要な security ledger が存在する旧 schema は読み込み可能。新しい bounds の欠落を「残高ゼロ」や「検査済み」として補完しない。
3. `channel_member`／`public_close_publisher` と WASM package を再ビルドする。ソースだけ更新して古い生成 WASM を配布しない。
4. `wallet-worker.js` と新しい `signature-release-ledger.mjs` を同じリリースで配布する。詳しい配布コマンドは `doc/docs/deploy-runbook.md`。
5. 新規チャネルは `doc/tasks/node-presign-recipient-setup.md` に従って全 cosigner の回収先を設定する。EOA の鍵保有・smart wallet の実回収方法は運用側でも確認する。
6. `api/` と `node/` の両 lockfile の依存をインストールし、同じ L1 signer を使う全 publisher／deposit sender で signer lock root を共有する。
7. state、replay ledger、exit-kit archive、入金／burn／inter journal、L1 outbox、browser signing ledger は一貫した世代で保全する。可用性を戻すために削除・TTL解除しない。

この作業は既存 H の不適切な recipient、既に範囲を超えた残高、重複 exit key を書き換えない。追加署名なしで既存の不整合を必ず救済できる、とは宣言しない。

## 7. 検証と性能

Node の最終全 suite は **506件中497成功、失敗0、既存 skip 9**。skip は未ビルドの daemon 条件1件と、未生成の state-delta fixture 条件8件。

| Rust の対象テスト | 成功数 |
| --- | ---: |
| private credit bounds | 11 |
| native capacity reservation | 11 |
| deposit recovery | 6 |
| burn publication recovery | 2 |
| inter WAL codec／正常ファイル永続化 | 5 |
| cosigner recipient 設定 | 5 |
| 通常 metadata の単体検査 | 4 |
| native signing ledger／B の kit context | 11 |
| 正常 send／deposit／refresh／inter／register／close-era（release） | 9 |
| 正常 participant record／鍵 admission（release） | 1 |
| public-close publisher 全42件（readiness 3件を含む） | 42 |
| public-close publisher CLI 引数 | 3 |

上表は選択した対象テストであり、Rust リポジトリ全 suite の完走ではない。native の最終 library／`channel_member`／`public_close_publisher` test build と WASM target check は offline・lockfile 固定で成功。既存 warning は残る。実サービスやチェーンに接続せず、publisher は既存の fake backend で動作を検証した。`git diff --check` も成功。

- Rust の正常な send／deposit／refresh／inter／token-register と close-era metadata の release テスト9件は成功。
- 新しい private bounds、capacity reservation、deposit recovery、inter WAL codec、recipient 設定と署名 ledger の対象テストを実行。
- 実際の `cast mktx` 出力は公開ダミー鍵・金額ゼロ・全 tx field 明示・通信なしで確認した。実資金／実チェーンの送信は行っていない。
- WASM target の `cargo check` は成功。生成 package のブラウザ実行・IndexedDB の実ブラウザ E2E は未実施。
- 正常運用の proof circuit／public input／proof format は増やしていない。サブモジュールの暗号実装は変更していない。pre-freeze proof は後段に再利用し、二重生成しない。
- 一方、復号・host 検査・fsync と private journal／sidecar の保存量は増える。変更前後の証明時間・end-to-end latency・メモリ／disk の比較測定は未実施で、実測で性能不変とは主張しない。

## 8. 残作業 — 完了扱いにしないもの

### A. 通常 PW の exact backing attestation

通常 API／CLI の PW submit は、exact signed-head backing が既に L1 attested なら進めるが、それを自動的に成立させる接続は未実装。契約の後段検査は維持しているため、欠けていれば拒否する。

次の実装は、PW が生成する既存 close proof と public-close bundle を一本化し、同じ artifact を backing attest と PW submit に再利用する形が候補。単に別の full close proof 生成を追加すると二重生成になる。devnet の fixture attestation script を production の代用品にしない。追加の channel signature は不要だが permissionless L1 transaction の gas signer と durable outbox が必要。

### B. Watcher の無関係 deposit による停止

現在の watcher は、無関係な入金を native が拒否すると同じ block で再試行し、後続の監視を妨げる場合がある。今回、拒否エラーを無視して cursor を進める変更はしていない。

安全な修正には、live service の現在分だけでなく履歴分も含む authoritative な `required / proven-unrelated / unresolved` 判定が必要。salt は消費後に current getter から消えるため、現在の recipient と不一致というだけでは「無関係」と証明できない。RPC エラー、reorg、未知 recipient も skip の根拠にしない。履歴照会と監視進行の分離は次の優先タスク。

### C. 本番同等の通し検証

実ブラウザの永続署名、実 daemon、L1 posting/finality、入金から最新 H の signer-independent exit／claim までの通し検証は残る。新しい readiness も本番同等で計測する。実資金を入れる前に、正常系・中断後再開・複数 token・同時処理を隔離した環境で確認する必要がある。
