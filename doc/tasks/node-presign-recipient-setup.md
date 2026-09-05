# 初期入金前の cosigner 回収先設定

対象: native CLI、および同じ CLI を利用する API／Node の新規チャネル初期化。

## 新しい本番チャネル

`INTMAX_COSIGNER_KEYFILE` を使う本番鍵モードでは、`setup-backing` より前に、全 controlled cosigner の `CLI_RECIPIENT_SLOT_<slot>` を明示する。既定の cosigner 数は3なので、その場合は slot 0・1・2 が対象。`INTMAX_CLI_COSIGNERS` を増やした場合は追加 slot も必要であり、初期残高がゼロでも省略できない。

各値には、その参加者が実際に回収操作を行える20-byte L1アドレスを指定する。API／Node から CLI を起動する場合も、その子プロセスに同じ設定を渡す。設定だけで鍵の保有が証明されるわけではないため、運用側で対象チェーン上の回収方法を確認する。

- EOA は対応する署名鍵を本人が保有し、安全にバックアップしていること。
- smart wallet は、その wallet 自身から Manager の `claimWithdrawalCredit` を呼び、必要な native/token を受け取れること。
- 全員を operator のアドレスへ自動割当てしない。新しい鍵も自動生成しない。
- 設定は `setup-backing` と `init` の両方で利用可能にしておく。genesis の署名前には、出来上がった各 slot の recipient が意図した回収先か確認する。

本番鍵モードでは、未設定・空値・形式不正・ゼロアドレスと、このチャネルの既知の synthetic cosigner 既定値を拒否する。`setup-backing` は、証明生成と L1 signer 利用より前に全 slot を検査する。`init` の genesis 作成も同じ resolver を使う。

## テストモード

`INTMAX_INSECURE_DETERMINISTIC_KEYS=1` を明示した既存テストモードだけは、未設定時に従来の `test_recipient_for` を使える。このアドレスは実資金の回収先ではない。実払い出しを確認するテストでは、回収可能なアドレスを明示する。

テストモードでも、明示した値が不正またはゼロなら拒否する。本番 keyfile と insecure flag の併用拒否は従来どおり。

## 既存の署名済み H に関する警告

この変更は、既存 H の recipient を書き換えない。環境変数を後から設定しても、既に署名された recipient は修正されない。また、正常な既存チャネルの通常操作・close・claim を、新規 genesis 用設定の不足だけで停止させない。

既存 H に synthetic recipient と正残高がある場合、そのまま close すると当該 slot の払い出しを引き出せる既知の鍵がない。まず最新の完全署名済み H、各 slot の recipient、本人が回収可能な鍵／wallet を照合する。状態ファイルや recipient の直接書換えで解決しようとしない。

全員が協力でき、通常の正規遷移がまだ可能な場合は、回収可能な既存 slot への合意済み移動や、新しい正しく構成したチャネルへの移行を検討する。宛先を変更する遷移や、停止済み MSU を勝手に再有効化しない。既に凍結・close 済み、または必要な署名者が不在なら、そのような救済が可能とは保証しない。追加署名不要の正常退出が可能になったと見なしてはいけない。
