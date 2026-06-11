# abstract — 最小仕様とセキュリティ機構

本書は「安全な送金機能」を定義するための**仮想的な最小仕様**である。各データに変数名、各動作に関数名を付ける。
余計なデータ・構造は一切増やさない(本書に列挙したものが全て)。

## 0. MECE の骨格

送金(`transfer`)は次の 2 つに排他かつ網羅的に分かれる:
- **A. チャネル内送金** `channelTransfer`(同一 channel の 3 人の間)
- **B. チャネル間送金** `interChannelTransfer`(channel → channel、Intmax 経由)

安全性は次の 4 性質に分割される(後述 §4):
1. **認可** authorization(全員署名)
2. **二重支払い/不正 mint 防止** no-double-spend(`PublicState` + `validityProof`)
3. **支払い能力** solvency(`balanceProof` + `rangeProof`)
4. **退出/活性** exit-liveness(close ゲーム + タイムアウト + `lateBalanceProof`)

---

> **命名方針:** base intmax(channel が関わらない)層は**既存実装の型・フィールド名を採用**する。channel 層
> (新規設計)は抽象名を残しつつ、既存型があるものは併記する。型/ファイルは投稿時点のコードに準拠。

## 1. 全体前提 [key / address]

- `Address` : 公開鍵 = アドレス(`src/ethereum_types/address.rs`)。**1 人 1 key 1 account**(`address == pubkey`)。
  SPHINCS+ 鍵そのもののコミットは `PkLeaf.pk_hash = Poseidon(pub_seed || pub_root)`(`src/common/key_set.rs`)。
- `U256` : 数量(残高・送金額)の型(`src/ethereum_types/u256.rs`)。
- `SpxSigWitness` : SPHINCS+ 署名(`src/circuits/validity/block_hash_chain/sphincs_sig.rs`)。本書で「署名」はこれを指す。

---

## 2. データ定義(変数)

### 2.1 多人数ペイメントチャネル(channel 層 = 新規。既存型は併記)

- `ChannelId` : チャネル識別子(既存型 `ChannelId`, `src/common/channel_id.rs`)。
- `memberKeys : Map<ChannelId, [Address; 3]>` : channel ID から **3 つの key(= 3 人、固定)** への mapping。
- `balances : [U256; 3]` : channel 内 3 人の残高。
- `balanceProof` : 「今 channel にいくら残高があるか」の **ZKP proof**(balance 回路の `ProofWithPublicInputs`)。生成には `validityProof` が必要。
  **出金時に L1 で検証される**(close の `finalBalanceProof`、late の `lateBalanceProof` とも)。
  前提(健全性): 一旦 tx が L2 にあるか broadcast されている場合、`balanceProof` はその tx を反映し、過大な残高には**偽造できない**。
- `BalancePublicInputs`(`src/circuits/balance/balance_pis.rs`): `balanceProof` の**公開入力**(proof とは別物)。`{ channel_id, public_state, block_r, private_commitment }`。
- `stateVersion` : 残高ステートの版番号(channel 層・新規)。
- `BalanceState { balances, balanceProof, stateVersion }` : 残高ステートの内容(channel 層・新規)。
- `balanceStateHash = hash(BalanceState)` : **合意対象**(= 3 人の残高・channel 全体の balanceProof・stateVersion のハッシュ)。

### 2.2 チャネル内 tx(channel 層・新規)

- `ChannelTx { recipient, amount, salt }` : チャネル内送金 tx。
  - `recipient : Address`(受け取り人公開鍵)、`amount : U256`、`salt`(ワンタイムランダム値)。

### 2.3 Intmax(base 層 = 既存実装の命名を使用)

- 役割 `BP`(Block producer): **1 人だけ固定**。各 channel の tx を集めてブロックを作る。
- 役割 `ITS`(intmax-tx-sender): **channel 内で固定**の 1 人。BP に tx を送り、tx tree root に署名して返す通信を担う。
- `BlockNumber` : ブロック番号(= `U63`, `src/common/u63.rs`)。
- `Transfer { recipient, token_index, amount, aux_data }`(`src/common/transfer.rs`): チャネル間送金 tx の**内容**。
  - tx の内容 = **受信者 channel の `ChannelId`** + **実受信者 key の公開鍵(`Address`)** + **数量(`amount : U256`)**。
    (誤: 「受信者の公開鍵と数量」だけ。正: 受信者 channel の ID も内容に含む。)
  - 名義上の宛先(routing 単位)= 受金 `ChannelId`。channel 内のどの member が実受取人かは 実受信者 `Address`。
  - これらは `recipient` / `aux_data` に符号化される: 受金 `ChannelId`・実受信者 `Address`(と実送信者 `Address`・送信 `ChannelId`)は
    **`aux_data : Bytes32` に符号化**(旧 `TxAux` 相当)。`recipient` 自体は受信者導出値。`amount`・`token_index` は既存フィールド。
- `SettledTransfer::nullifier()`(`transfer.rs`): tx hash / nullifier。
  = Poseidon(recipient, token_index, amount, aux_data, from, transfer_index, block_number)。二重支払い防止に使う。
- `TxV2 { tx_class, transfer_tree_root, nonce, channel_action_root }`(`src/common/tx.rs`): tx tree の leaf(transfer 群のコンテナ)。
- `TxV2Tree = SparseMerkleTree<TxV2>`(`src/common/trees/tx_v2_tree.rs`): BP が複数の送信者(channel)から集めた tx のマークル木。
- `tx_tree_root` : `TxV2Tree` の root(`Block.tx_tree_root`)。
- `TxV2MerkleProof = SparseMerkleProof<TxV2>` : ある tx が tx tree に含まれることの merkle proof。
- `senderRootSig`(型 `SpxSigWitness`): 送信者(= channel を 1 user とみなした全員)による `tx_tree_root` への署名。
- `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }`(`src/common/block.rs`):
  L1 に L2 ブロックとして投稿。抽象の `txTreeRoot` = `tx_tree_root`。ブロック番号は `Block` ではなく `PublicState.block_number` が保持。
- `PublicState { block_number, account_tree_root, deposit_tree_root, prev_public_state_root }`(`src/common/public_state.rs`):
  **ZKP 証明可能共有ステート**(旧 `CommonState`)。あるブロック時点の状態。
  - `block_number` : 現ブロック番号(旧 `CommonState.blockNumber`)。
  - 旧 `lastIncluded : Map<ChannelId, lastBlockNumber>` は `account_tree_root`(= `ChannelTree`)で実現され、
    各 `ChannelLeaf.prev` が「その channel の tx が最後に取り込まれたブロック番号」を表す(二重支払い・不正 mint の防止)。
  - hash chain は `ExtendedPublicState { ..., block_hash_chain, deposit_hash_chain }`(`ext_public_state.rs`)が付加。
- `validityProof` : `PublicState` 遷移の **ZKP proof**(validity 回路の `ProofWithPublicInputs`)。各ブロックごとに生成・オフチェーン公開。
- `ValidityPublicInputs { initial/final_block_number, initial/final_block_chain, initial/final_ext_commitment, prover }`
  (`src/circuits/validity/block_hash_chain/validity_circuit.rs`): `validityProof` の**公開入力**(proof とは別物)。on-chain には `keccak(ValidityPublicInputs)` が束縛される。

### 2.4 Close(channel 層・新規)

- `finalBalanceState` : challenge 期間で確定した最終 `BalanceState`。
- `finalBalanceProof` : 上記に含まれる確定した `balanceProof`(proof object。公開入力は `BalancePublicInputs`)。
- `withdrawCap` : `finalBalanceProof`(= `BalancePublicInputs`)が証明する channel 総残高。close 後の**最大出金総額**。
  `finalBalanceState` が何を主張しても、合計出金は `withdrawCap` を超えられない。
- `burnAddress : Address` : 固定の burn アドレス。ここへの送金は intmax L2 の spendable supply から価値を除去する(支出不能化)。
- `closeBurnTx : Transfer { recipient = burnAddress, token_index, amount = withdrawCap, aux_data }` :
  close state 確定時に提出される、channel 残高を burn する intmax `Transfer`。
- `lateBalanceProof` : close 後の `balanceProof`(同じ balance 回路の proof。公開入力は `BalancePublicInputs`)。**最終ステートとは別変数**として onchain に保管される。

### 2.5 タイムアウト定数

- `SIGN_TIMEOUT = 3 min` : channel 内署名が揃わない許容時間。
- `GRACE_BEFORE_PROCESS = 10 min` : close 申請から startProcess までの猶予。
- `CHALLENGE_PERIOD = 1 day` : challenge 期間。

---

## 3. 関数定義(動作)

各動作を「**actor(誰が)**」「**操作(何を、どのデータに)**」で 1 動作ずつ区切る。
actor: `member[i]`(channel メンバー、i∈{0,1,2})/ `sender`(送信する member)/ `ITS`(固定の intmax-tx-sender、member の 1 人)/ `BP`(固定の Block producer)/ `L1`(オンチェーン契約)。

### 3.0 チャネル構成(前提)

- `memberKeys[channel_id] = [Address; 3]` : channel 作成時に確定する 3 人の鍵 mapping(以降不変)。

### 3.1 残高ステート合意 `agreeBalanceState`

**actor: member[0..2] 全員**
- in: 候補 `BalanceState { balances, balanceProof, stateVersion }`
1. `member[i]` が候補 `BalanceState` の正当性(残高保存・`balanceProof` 整合・`stateVersion` が現行 +1)を各自検証。
2. 不正なら署名しない(善良ノードは合意しない)。
3. 正当なら `member[i]` が `balanceStateHash = hash(BalanceState)` に署名し `SpxSigWitness` を出す。
- out: `[SpxSigWitness; 3]`。3 つ揃ったとき `BalanceState` が確定。

### 3.2 チャネル内送金 `channelTransfer`

前提: 現行 `balanceProof`・`balances`・確定済み `BalanceState`。`balanceProof` は不変。

#### 3.2.1 `signChannelTx` — **actor: sender**
- in: `ChannelTx { recipient, amount, salt }`(`recipient` = 受取 member の `Address`)
1. `sender` が `balances` を更新: `balances'[sender] -= amount`、`balances'[recipient] += amount`。
2. `sender` が `BalanceState' = { balances', balanceProof(不変), stateVersion+1 }` を構成。
3. `sender` が `ChannelTx` と `balanceStateHash' = hash(BalanceState')` の**両方**に署名。
- out: `(ChannelTx, BalanceState', SpxSigWitness_tx, SpxSigWitness_state)`。

#### 3.2.2 `propagateChannelTx` — **actor: sender**
1. `sender` が残りの `member` に `ChannelTx` と `BalanceState'` を伝播。

#### 3.2.3 `coSignBalanceState` — **actor: 残り member(sender 以外の 2 人)**
- in: `ChannelTx`, `BalanceState'`
1. `member` が `ChannelTx` を `balances` に適用した結果が `BalanceState'.balances` と一致するか検証。
2. 正当なら `balanceStateHash'` に署名。
- out: 追加 `SpxSigWitness`。全 3 署名で `BalanceState'` 確定。

### 3.3 Intmax 基盤プリミティブ

#### 3.3.1 `rangeProof` — **actor: ITS**
- in: `balanceProof`(送信 channel), `amount`
1. `ITS` が「`balanceProof` の示す送信者残高 ≥ `amount`」を検証(送金額より残高が多い)。
- out: `bool`(偽なら `BP` に渡さない)。

#### 3.3.2 `signTxTreeRoot` — **actor: 送信 1 user(= channel メンバー全員 = 1 user)**
- in: `tx_tree_root`, `TxV2MerkleProof`, 自分の `TxV2`(内に `Transfer`)
1. `TxV2MerkleProof` を検証し、自分の `TxV2` が `tx_tree_root`(`TxV2Tree`)に含まれることを確認。
2. 確認できたら `tx_tree_root` に署名。
- out: `senderRootSig : SpxSigWitness`(channel を 1 user とみなした署名)。

#### 3.3.2b 署名不要の特例(deposit mint / close burn) — **actor: validity / 検証回路**
- **deposit(mint)と `closeBurnTx`(burn)は、ZKP の validity 回路 / 出金検証回路の中で L2 署名(`signTxTreeRoot`)なしで受理される。**
- 根拠: deposit は L1 発の入金、`closeBurnTx` は close 確定の結果として L1/close 駆動で生じる出金であり、いずれも channel メンバーの共署名(`senderRootSig`)を要しない。
- 効果: `requestClose` 後の署名停止(§3.5.1)中でも `closeBurnTx` を L2 決済でき、freeze と burn 署名の矛盾を解消する。

#### 3.3.3 `produceBlock` — **actor: BP**
- in: 各 channel からの `TxV2` 群, 各 channel の `senderRootSig`
1. `BP` が `TxV2` 群から `TxV2Tree` を構築し `tx_tree_root` を得る。
2. `BP` が `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }` を構成。
- out: `Block`。

#### 3.3.4 `postBlock` — **actor: BP**
- in: `Block`
1. `BP` が `Block` を Ethereum L1 に L2 ブロックとして投稿。
- out: 確定 `BlockNumber`。

#### 3.3.5 `generateValidityProof` — **actor: BP(プルーバ)**
- in: `tx_tree_root`, `senderRootSig` 群, `Block`, 新 `PublicState`
1. `tx_tree_root`・各 `senderRootSig`・`Block`・結果としての `PublicState` 遷移を ZKP 回路で一貫検証。
2. `PublicState.account_tree_root` の各 `ChannelLeaf.prev` を「取り込んだ `BlockNumber`」に更新(二重支払い・不正 mint 防止)。
- out: `validityProof`(公開入力 = `ValidityPublicInputs`)。各ブロックごとに生成・オフチェーン公開。

#### 3.3.6 `generateBalanceProof` — **actor: channel(ITS が代表)**
- in: `validityProof`, 当該 channel の状態
1. `validityProof` を入力に、channel 残高を主張する `balanceProof` を生成(`validityProof` が必須)。
- out: `balanceProof`(公開入力 = `BalancePublicInputs`)。

### 3.4 チャネル間送金 `interChannelTransfer`(3 フロー)

送信名義も受信名義も channel。送金額 `amount` の `Transfer` を送信 channel → 受金 channel に運ぶ。

> **署名のアトミック性(不変則)**: 送金 tx の認可署名(`senderRootSig` = `tx_tree_root` への署名)と、
> その送金を反映した減算後 `BalanceState'`(送信者残高 -= amount, `stateVersion`+1)への署名は、
> 常に **1 つのアトミックな動作**として全員が同時に行う。**片方だけの署名は無効**。
> チャネル内送金(§3.2.1、既にアトミック)と同じ規則をチャネル間送金にも適用する。
> これにより「**送金を認可する ⇔ 内部減算が確定する**」が保証され、送金後に減算署名を拒否して
> co-member へ損失を転嫁する攻撃(intra-channel 窃取)と、過大 state での強制 close を封じる。

#### 送金フロー 1 `flowSend1`(送信 channel:tx 作成 〜 アトミック認可 〜 伝播)

- **actor: sender**
  1. `sender` が**両 channel(送信・受金)に close 申請がないこと**を `L1` で確認。
  2. `sender` が `Transfer { recipient, token_index, amount, aux_data }` を作る
     (`aux_data` に実送信者アドレス・実受信者アドレス・送信/受金の `channel_id`)。
  3. `sender` が `Transfer` を `ITS` に渡す。
- **actor: ITS**
  4. `ITS` が `rangeProof(balanceProof, amount)` を確認(残高 ≥ 送金額)。
  5. `ITS` が `Transfer`(を含む `TxV2`)・`TxV2Tree`・減算後 `BalanceState'`(送信者残高 -= amount, `stateVersion`+1)を全員に共有。
- **actor: 送信 channel 全員(member[0..2])— アトミック署名**
  6. 各 `member` が **`tx_tree_root` と `BalanceState'` を 1 つのアトミック動作として同時署名**。
     減算後 `BalanceState'` に全員署名しない限り、その `tx_tree_root` 署名(`senderRootSig`)は**無効**。
     - 全員が揃わなければ送金は**認可されない**(部分署名は無効 = 送金不成立、co-member に損失なし)。
- **actor: ITS → BP**
  7. 揃った `senderRootSig` を `ITS` が `BP` に渡す(`BP` が `produceBlock` → `postBlock`)。
- **actor: ITS(送信 channel)**
  8. `tx_tree_root` が L1 ブロックに入ったら、`ITS` が `generateBalanceProof` で減算後 `balanceProof'` を生成。
     `balanceProof'` は偽造不可で post-send の L2 残高(`B-amount`)を反映するため、step6 で署名確定済みの
     `BalanceState'.balances`(減算後)と**必ず一致**する(新たな交渉・署名は不要)。
  9. `ITS` が `(Transfer データ, TxV2MerkleProof, balanceProof')` を**受金 channel** に伝播。

#### 送金フロー 2 `flowSend2`(送信 channel:balanceProof 確定)

- **actor: ITS(送信 channel)**
  1. step8 の `balanceProof'` を、step6 で署名済みの `BalanceState'` の `balanceProof` として確定
     (`balances`・`stateVersion` は step6 で署名済み・不変)。
- **actor: BP(プルーバ、並行)**
  2. `generateValidityProof` で当該 block の `validityProof` を生成。
- 註: アトミック認可署名(flow1 step6)が揃わなければ送金は不成立。一般の無応答には `SIGN_TIMEOUT`(3 分)超過で `requestClose`(§3.5)。

#### 送金フロー 3 `flowReceive3`(受金 channel:残高ステート反映)

- **actor: 受金 channel 全員(member[0..2])**
  1. 伝播された `(Transfer データ, TxV2MerkleProof, balanceProof)` が valid か全員が確認
     (`TxV2MerkleProof` の包含検証 + `balanceProof` の整合)。`balanceProof` が無ければ送信者を無視。
- **actor: ITS(受金 channel)**
  2. `ITS` が tx の**受金 `ChannelId` が自 channel** であることを確認し、`balanceProof` を**増加**側に更新(`generateBalanceProof`)。
  3. `ITS` が tx の**実受信者 key の公開鍵(`Address`)**を見て、その member を特定し、
     `BalanceState' = { balances'(その受金者の残高 += amount), balanceProof'(新), stateVersion+1 }` を構成。
- **actor: 受金 channel 全員(member[0..2])**
  4. `agreeBalanceState(BalanceState')` で全員が合意署名。

### 3.5 チャネル close ゲーム

順番: `requestClose` →(`GRACE_BEFORE_PROCESS`=10 分)→ `startProcess` →(`CHALLENGE_PERIOD`=1 日)→ `closeAndWithdraw`。

#### 3.5.1 `requestClose` — **actor: channel 内の任意の member**
- in: `channel_id`
1. 任意の `member` が `L1` に close を申請。
2. 申請後、全 `member` は当該 channel に関する**全署名行為を停止**(`agreeBalanceState`・`signTxTreeRoot` 等を行わない)。channel 外の者も当該 channel に送金しない。
3. `GRACE_BEFORE_PROCESS`(10 分)の猶予により、申請直前/直後の署名や通信ラグは「無いもの」とみなす。

#### 3.5.2 `startProcess` — **actor: 申請者(または任意 member)**
- in: `BalanceState`(全員署名済み), その中の `balanceProof`(= intmax-balanceProof)
1. 申請から 10 分後、`member` が `L1` に `BalanceState` と `balanceProof` を提出。
2. `L1` が `BalanceState` の全員署名を確認し、`CHALLENGE_PERIOD`(1 日)を開始。

#### 3.5.3 `challenge` — **actor: 任意 member**
- in: 提出済みより新しい `BalanceState_newer`(全員署名済み)とその中の `balanceProof`
1. `member` が `BalanceState_newer` を `L1` に提出。
2. `L1` が提出物すべてに**全員署名がある**ことを確認。
3. `BalanceState_newer.stateVersion > 現提出.stateVersion` なら置換。
4. 期間終了で `finalBalanceState` / `finalBalanceProof` が確定(古い state での close を防ぐ)。

#### 3.5.4 `closeAndWithdraw` — **actor: 各 member / L1 / intmax L2**
- in: 確定 `finalBalanceState` / `finalBalanceProof`, `closeBurnTx`
1. **(burn tx 提出)** close state 確定後、`member` が `closeBurnTx`(= `Transfer { recipient: burnAddress, amount: withdrawCap, ... }`)を `finalBalanceProof` と共に `L1` に提出。
2. **(L2 burn として処理)** 同じ `closeBurnTx` は intmax L2 でも「close state 確定時 burn tx」として処理され、channel 残高が L2 の spendable から除去される。
   - L2 で `withdrawCap` を burn するには **その額が現に channel に存在**する必要がある(通常の `Transfer` と同じ solvency 検証)。既に送金済みの古い残高は burn できない。
3. **(cap 確定)** `L1` が `finalBalanceProof` を検証し、`withdrawCap = finalBalanceProof の証明残高 = closeBurnTx.amount` を確定。
4. **(上限付き配分出金)** `L1` は `finalBalanceState.balances` に従い各 `member` に配分するが、**Σ(出金) ≤ `withdrawCap`** を強制。`finalBalanceState` が `withdrawCap` 超を主張しても超過分は出金不可。

#### 3.5.5 `claimLateTx` — **actor: 受信者(late tx の受取人)**
- in: `lateBalanceProof`, `Transfer データ`, `TxV2MerkleProof`
1. close 確定 version より後に知らされた当該 channel への intmax `Transfer` について、受信者が `lateBalanceProof` を入力に新しい `balanceProof` を ZKP で作る(balance 回路は `balanceProof` と同一)。
2. `L1` で verify されると受信者が onchain で受け取る。
3. `lateBalanceProof` は `finalBalanceProof` とは**別変数**で onchain 保管。

補足: `balanceProof` は tx 送信時に必ず受信者に添付する(`flowSend1`/`flowReceive3`)。受信者はそれが無い場合、送信者を無視する。

---

## 4. セキュリティ機構

各機構が **§0 の 4 性質**のどれを守るかを示す。

### 4.1 認可 authorization
- **全員署名(`agreeBalanceState` / `coSignBalanceState`)**: 残高ステート更新は 3 人全員の署名が合意対象。
  善良なノードは不正ステートに署名しないため、不正更新は成立しない。
- **署名のアトミック性**: 送金認可(`senderRootSig` = `tx_tree_root` 署名)と減算後 `BalanceState'` の署名は
  不可分(§3.2.1 / §3.4 不変則)。送金だけ認可して内部減算署名を拒否し co-member に損失転嫁する攻撃を封じる。
- **close は最後の合意 state で可能**: 合意が壊れても、最後に全員署名した `BalanceState` で onchain close できる。

### 4.2 二重支払い / 不正 mint 防止 no-double-spend
- **`PublicState`**: 各 channel が「最後に tx を取り込まれたブロック番号」を `account_tree_root`(各 `ChannelLeaf.prev`)に持ち、
  同一資金の二重支払いや不正な mint を防ぐ。
- **`validityProof`**: `tx_tree_root`・`senderRootSig`・`Block`・`PublicState` を ZKP で一貫検証し、各ブロックで公開。
- **`signTxTreeRoot` の merkle 検証**: 送信 1 user は tx が `TxV2Tree` に含まれることを `TxV2MerkleProof` で確認してから署名。
- **出金 cap(`withdrawCap`)**: close 後の総出金は `finalBalanceProof` が証明する残高で上限化(`closeAndWithdraw` で `Σ(出金) ≤ withdrawCap` を強制)。
  `finalBalanceState` がいくら主張しても超過不可 → 膨張ステートや stale ステートでの窃取(監査 C1/C2/C5)を封じる。
- **close burn tx(`closeBurnTx`)**: L1 出金には `closeBurnTx`(`burnAddress` への `Transfer`)を `finalBalanceProof` と共に提出し、
  **同じ tx を intmax L2 でも burn として処理**する。L2 で `withdrawCap` を burn するには実残高が必要なので、
  既に送金済みの古い残高は burn できず L1 でも引き出せない(close 境界で「L2 でも使える + L1 でも出金」の二重支払い C1 を封じる)。

### 4.3 支払い能力 solvency
- **`balanceProof` 添付必須**: 送金 tx には必ず `balanceProof` を添付。無ければ受信者は送信者を無視。
- **`rangeProof`**: ITS が送金額より送信者残高が多いことを確認してから BP に渡す。
- **`balanceProof` の単調更新**: 送信側は減少(`flowSend2`)、受金側は増加(`flowReceive3`)するように更新し、全員合意で固定。

### 4.4 退出 / 活性 exit-liveness
- **close ゲームの順序と challenge**: `requestClose` → 10 分 → `startProcess` → 1 日 challenge → close。
  challenge 期間で**より新しい version の state**に置換でき、最終ステートが確定する(古い state での close を防ぐ)。
- **`GRACE_BEFORE_PROCESS`(10 分)**: close 申請から startProcess までの猶予により、申請直前・直後の署名や通信ラグを「全部ないもの」とみなせる。
- **`SIGN_TIMEOUT`(3 分)**: 署名が中途半端で揃わない場合はプロトコル違反とみなし、close で退出可能(活性確保)。
- **両 channel の close 申請確認(`flowSend1`)**: close 申請のある channel への送金を行わない。
- **`lateBalanceProof`**: close 確定 version より後に届いた intmax tx の資金も、`lateBalanceProof` 入力の新 `balanceProof` を onchain verify することで受信者が受け取れる(資金の取りこぼし防止)。`balanceProof` と同一回路。
