# abstract2 — 最小仕様とセキュリティ機構(Lattice 版)

本書は「安全かつ秘匿な送金機能」を定義するための**仮想的な最小仕様**である。各データに変数名、各動作に関数名を付ける。
余計なデータ・構造は一切増やさない(本書に列挙したものが全て)。
[abstract.md](./abstract.md)(v1)をベースに、Lattice(Regev/LWE)暗号による残高秘匿仕様を反映した改訂版(v2)。

## v1 からの差分(要約)

1. **残高の秘匿化**: 各 member が Regev 公開鍵を channel 内で公開し、各人の残高はその鍵で暗号化された
   lattice 暗号文(`LatticeCt`)として保持される。平文残高は state に現れない。
2. **残高ステートの二部構成**: 合意対象が `hash(H1, H2)` になる。`H1` = 残高ステート本体のハッシュ、
   `H2` = 送金種別タグ(0 = チャネル内 / `tx_tree_root` = チャネル間)。
3. **channelUpdateZKP**: チャネル間送金の lattice 残高変化(送信側 −、受信側 +)の正当性を送信者が ZKP で証明。
   `rangeProof` はこの ZKP の検証として再定義される。
4. **署名アトミック性の構造化**: v1 では「tx_tree_root 署名と減算後 state 署名を同時に行う」は**運用規則**
   (§3.4 不変則)だったが、v2 では署名対象そのものが `hash(H1', H2 = tx_tree_root)` であるため、
   送金認可と残高減算の合意が**1 つの署名に構造的に内蔵**される(分離不可能)。
5. **validity 回路の制約追加**: channel ステート署名が tx_tree_root への署名の**代替**として
   validity 回路内で検証・制約される。
6. **close 後出金の ZKP 化**: 確定 state は暗号文しか含まないため、各 member は自分の暗号化残高を
   ZKP で証明して出金する。
7. **チャネル内 range ZKP(`channelTxZKP`)— 監査反映**: チャネル内送金にも、送信者が
   「更新後の自分の暗号化残高 ≥ 0」を証明する ZKP を必須化(`channelUpdateZKP` のチャネル内版)。
   v1 では平文残高を全員が目視検証できたが、v2 の暗号化でその防御が消えていた(監査所見 5)。
8. **state↔balanceProof の束縛(`settledTxChain`)— 監査反映**: `H1` は proof オブジェクトではなく
   settle 履歴の hash chain にコミットし、balance 回路が同じ chain を公開入力に expose、close 時に
   L1 が一致を照合する。署名時点で未生成の proof を state に含める循環(監査所見 3)を解消。

## 0. MECE の骨格

送金(`transfer`)は次の 2 つに排他かつ網羅的に分かれる。**排他性・網羅性は `H2` タグが構造的に保証する**:
- **A. チャネル内送金** `channelTransfer`(同一 channel の 3 人の間)— 合意署名の `H2 = 0`
- **B. チャネル間送金** `interChannelTransfer`(channel → channel、Intmax 経由)— 合意署名の `H2 = tx_tree_root ≠ 0`

安全性は次の 5 性質に分割される(後述 §4):
1. **認可** authorization(全員署名。署名対象 = `hash(H1, H2)`)
2. **二重支払い/不正 mint 防止** no-double-spend(`commonState` + `validityProof`)
3. **支払い能力** solvency(`balanceProof` + `rangeProof` = `channelUpdateZKP` 検証)
4. **退出/活性** exit-liveness(close ゲーム + タイムアウト + `lateBalanceProof` + 出金 ZKP)
5. **残高秘匿** confidentiality(Regev 暗号 + `channelUpdateZKP`)— v2 で新設

---

> **命名方針:** base intmax(channel が関わらない)層は**既存実装の型・フィールド名を採用**する。channel 層
> および lattice 関連(新規設計)は抽象名を用いる(対応する実装型は未存在)。

## 1. 全体前提 [key / address]

- `Address` : 公開鍵 = アドレス(`src/ethereum_types/address.rs`)。**1 人 1 key 1 account**(`address == pubkey`)。
- `U256` : 数量(平文の残高・送金額)の型(`src/ethereum_types/u256.rs`)。base 層の tx 内容では数量は平文。
- `SpxSigWitness` : SPHINCS+ 署名(`src/circuits/validity/block_hash_chain/sphincs_sig.rs`)。本書で「署名」はこれを指す。
- `RegevPk` : 各 member の Regev(LWE)暗号公開鍵(新規)。**channel 内で全員に公開**される。
- `LatticeCt` : Regev 暗号文(新規)。残高・残高変化(delta)の秘匿表現。残高 ct への**加法**(delta の加算)が定義される。
  負の delta(減算)は負値の平文を暗号化した ct として表す。

---

## 2. データ定義(変数)

### 2.1 多人数ペイメントチャネル(channel 層 = 新規)

- `ChannelId` : チャネル識別子(既存型 `ChannelId`, `src/common/channel_id.rs`)。
- `memberKeys : Map<ChannelId, [(Address, RegevPk); 3]>` : channel ID から **3 人(固定)の署名鍵と Regev 公開鍵**への mapping。
- `encBalances : [LatticeCt; 3]` : channel 内 3 人の残高。**member i の残高は member i の `RegevPk` で暗号化**され、
  本人のみ復号できる。平文残高はどこにも置かない。
- `balanceProof` : 「今 channel 全体にいくら残高があるか」の **ZKP proof**(balance 回路の `ProofWithPublicInputs`)。
  生成には `validityProof` が必要。**出金時に L1 で検証される**(close の `finalBalanceProof`、late の `lateBalanceProof` とも)。
  前提(健全性): 一旦 tx が L2 にあるか broadcast されている場合、`balanceProof` はその tx を反映し、過大な残高には**偽造できない**。
  **`balanceProof` は `H1` にコミットされない**(チャネル間送金では署名時点で減算後 proof が未生成のため。
  監査所見 3)。state との対応は下記 `settledTxChain` で束縛し、close 提出時に L1 が照合する。
- `settledTxChain` : この channel に取り込まれた base 層 settle 識別子の **hash chain**(channel 層・新規)。
  genesis は 0。チャネル間送金(送・受)を取り込むたびに
  `settledTxChain' = hash(settledTxChain, TxLeafHash)`、deposit の取り込みは deposit hash で同様に更新。
  チャネル内送金では不変。**`TxLeafHash` は署名時点(flowSend1 step 6)で既知**なので、減算後 state の
  chain はその場で計算できる。nullifier は `block_number` を含むため署名時点では計算できず、
  この用途には使えない(`block_number` 束縛による二重 settle 防止は base 層の nullifier が引き続き担う)。
- `BalancePublicInputs` : `balanceProof` の**公開入力**(proof とは別物)。
  **新規要件: 回路が取り込んだ settle 履歴の `settledTxChain` を公開入力に expose する。**
- `stateVersion` : 残高ステートの版番号(channel 層・新規)。
- `BalanceState { encBalances, settledTxChain, stateVersion }` : 残高ステートの内容(channel 層・新規)。
- `H1 = hash(BalanceState) = hash(encBalances, settledTxChain, stateVersion)` : 残高ステート本体のハッシュ。
  署名時点で全成分が既知(proof オブジェクトを含まない)。
- `H2` : 送金種別タグ。**基本は 0**。自 channel 発の intmax 送金時のみ当該 `tx_tree_root` が入る。
  - `H2 = 0` ⇔ チャネル内更新(チャネル内送金・受金反映)
  - `H2 = tx_tree_root ≠ 0` ⇔ チャネル間送金(intmax 送金 + その残高減算の同時認可)
- `balanceStateHash = hash(H1, H2)` : **合意・署名対象**。v1 の `hash(BalanceState)` をこれで置き換える。

### 2.2 チャネル内 tx(channel 層・新規)

- `ChannelTx { recipient, encAmount, nonce }` : チャネル内送金 tx。
  - `recipient : Address`(受け取り人公開鍵)
  - `encAmount : LatticeCt`(**受け取り人の `RegevPk` で暗号化**された送金額)
  - `nonce`(ワンタイムランダム値)
- `channelTxZKP`(新規・監査反映): チャネル内送金に**必須**で添付される ZKP。送信者が生成し、
  1. `encAmount` が非負の額の、受取人 `RegevPk` への正しい暗号文であること、
  2. **送信者の更新後暗号化残高 ≥ 0**(残高 ≥ 送金額の range 制約)
  を平文を明かさず証明する(チャネル間の `channelUpdateZKP` のチャネル内版)。
  これが無いと、結託した 2 人がチャネル内で残高超過送金 → 負残高成分を作り、close 時に非負成分の
  合計が `withdrawCap` を超えて正直メンバーの出金を横取りできる(監査所見 5)。

### 2.3 Intmax(base 層 = 既存実装の命名を使用。lattice 拡張は新規)

- 役割 `BP`(Block producer): **1 人だけ固定**。各 channel の tx を集めてブロックを作る。
- 役割 `ITS`(intmax-tx-sender): **channel 内で固定**の 1 人。BP に tx を送り、tx tree root に係る通信を担う。
- `BlockNumber` : ブロック番号(= `U63`, `src/common/u63.rs`)。block は 1 種類。
- `Transfer`(チャネル間送金 tx の**内容**、既存型 `src/common/transfer.rs` を基に拡張):
  - 内容 = 受信 channel の `ChannelId`、実質の受信人の公開鍵 `recipient : Address`、数量 `amount : U256`(**base 層では平文**)。
- `TxAux`(新規・tx のハッシュ構造内の付随データ):
  `{ senderAddr, recipientAddr, senderChannelId, recipientChannelId, senderDelta : LatticeCt, recipientDelta : LatticeCt }`
  - `senderDelta` : **送信 channel の送信者残高に加算される負の lattice ct**(減算分)。
  - `recipientDelta` : **受信 channel の受金者残高に加算される正の lattice ct**。
- `TxLeafHash = hash( hash(senderAddr, senderDelta), hash(recipientAddr, recipientDelta) )` : tx のハッシュ構造(新規)。
  送信者・受信者それぞれの公開鍵と lattice 残高変化が**両翼で束縛**される。
- `channelUpdateZKP`(新規): **送信者が作る** ZKP。次を証明する:
  1. `senderDelta` と `recipientDelta` が同一の `amount` に対応する(等量・符号逆)。
  2. `senderDelta` 適用後も送信者残高が非負(**残高 ≥ 送金額**の range 制約)。
  3. 各 delta がそれぞれの `RegevPk` に対する正しい暗号文である。
- `SettledTransfer::nullifier()` : tx hash / nullifier(既存)。`TxLeafHash`・`from`・`transfer_index`・`block_number` を束縛。二重支払い防止に使う。
- `TxV2 { tx_class, transfer_tree_root, nonce, channel_action_root }`(`src/common/tx.rs`): tx tree の leaf。
- `TxV2Tree = SparseMerkleTree<TxV2>`(`src/common/trees/tx_v2_tree.rs`): BP が複数の送信者(channel)から集めた tx のマークル木。
- `tx_tree_root` : `TxV2Tree` の root(`Block.tx_tree_root`)。
- `TxV2MerkleProof = SparseMerkleProof<TxV2>` : ある tx が tx tree に含まれることの merkle proof。
- `channelStateSig`(型 `SpxSigWitness`、**v1 の `senderRootSig` を置換**):
  送信 channel 全員による **`hash(H1', H2 = tx_tree_root)` への署名**。
  tx_tree_root への直接署名は**存在しない**。この署名が tx_tree_root への署名の**代替**となり、
  validity 回路で「tx_tree_root への証明方法」として検証・制約される(§3.3.5)。
- `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }`(`src/common/block.rs`):
  L1 に L2 ブロックとして投稿。
- `PublicState`(= 仕様文中の `commonState`, `src/common/public_state.rs`): **ZKP 証明可能共有ステート**。
  各 channel が「最後に tx に署名してブロックに取り込まれたのが何ブロック目か」を
  `account_tree_root`(各 `ChannelLeaf.prev`)に持つ(二重支払い・不正 mint の防止)。
- `validityProof` : `PublicState` 遷移の **ZKP proof**。各ブロックごとに生成・オフチェーン公開。
- `ValidityPublicInputs` : `validityProof` の公開入力。on-chain には `keccak(ValidityPublicInputs)` が束縛される。

### 2.4 Close(channel 層・新規)

- `finalBalanceState` : challenge 期間で確定した最終 `BalanceState`(暗号化残高のまま)。
- `finalBalanceProof` : 確定 state に**紐づく** `balanceProof`。紐付けは公開入力の
  `settledTxChain` = `finalBalanceState.settledTxChain` の一致で L1 が照合する(§2.1)。
- `withdrawCap` : `finalBalanceProof` が証明する channel 総残高。close 後の**最大出金総額**。
  `finalBalanceState` が何を主張しても、合計出金は `withdrawCap` を超えられない。
- `burnAddress : Address` : 固定の burn アドレス。ここへの送金は intmax L2 の spendable supply から価値を除去する。
- `closeBurnTx : Transfer { recipient = burnAddress, amount = withdrawCap, ... }` :
  close state 確定時に提出される、channel 残高を burn する intmax `Transfer`。
- `withdrawClaimZKP`(新規): close 後、各 member が「`finalBalanceState.encBalances` 内の**自分の暗号化残高**の平文が
  自分の出金額である」ことを、復号せず L1 上で証明する ZKP。
- `lateBalanceProof` : close 後の `balanceProof`(同じ balance 回路の proof)。**最終ステートとは別変数**として onchain に保管される。

### 2.5 タイムアウト定数

- `SIGN_TIMEOUT = 3 min` : channel 内署名が揃わない許容時間。
- `GRACE_BEFORE_PROCESS = 10 min` : close 申請から startProcess までの猶予。
- `CHALLENGE_PERIOD = 1 day` : challenge 期間。

---

## 3. 関数定義(動作)

各動作を「**actor(誰が)**」「**操作(何を、どのデータに)**」で 1 動作ずつ区切る。
actor: `member[i]`(channel メンバー、i∈{0,1,2})/ `sender`(送信する member)/ `ITS` / `BP` / `L1`(オンチェーン契約)。

### 3.0 チャネル構成(前提)

- `memberKeys[channel_id] = [(Address, RegevPk); 3]` : channel 作成時に確定(以降不変)。
- 各 member は自分の `RegevPk` を channel 内で公開する(`publishRegevPk`)。

### 3.1 残高ステート合意 `agreeBalanceState`

**actor: member[0..2] 全員**
- in: 候補 `BalanceState { encBalances, balanceProof, stateVersion }`, タグ `H2`
1. `member[i]` が候補の正当性を各自検証:
   - `stateVersion` が現行 +1 であること。
   - `settledTxChain` の整合(チャネル内更新なら不変、チャネル間なら `hash(現行 chain, TxLeafHash)`)。
   - **自分宛ての `encBalances[i]`** が正しく更新されていること(自分の Regev 秘密鍵で検証可能)。
   - チャネル内送金なら `channelTxZKP` の検証(送信者の更新後残高 ≥ 0。無い/不正なら署名しない)。
   - チャネル間(`H2 ≠ 0`)なら `channelUpdateZKP` と `TxV2MerkleProof` の検証(§3.3.2)。
   - 残高は暗号文のため他人の平文は見えないが、**全ての更新に range ZKP(`channelTxZKP` /
     `channelUpdateZKP`)が付くため、有効な state から始めれば全成分の非負と総和整合が帰納的に
     維持**される。これにより Σ(非負成分) = 総額 = `withdrawCap` が保たれ、close での出金横取りは
     生じない(§4.3)。
2. 不正なら署名しない(善良ノードは合意しない)。
3. 正当なら `member[i]` が `balanceStateHash = hash(H1, H2)` に署名し `SpxSigWitness` を出す。
- out: `[SpxSigWitness; 3]`。3 つ揃ったとき `BalanceState` が確定。

### 3.2 チャネル内送金 `channelTransfer`(`H2 = 0`)

前提: 現行 `balanceProof`・`encBalances`・確定済み `BalanceState`。`balanceProof` は不変。

#### 3.2.1 `signChannelTx` — **actor: sender**
- in: `ChannelTx { recipient, encAmount, nonce }`
1. `sender` が `amount` を受取人の `RegevPk` で暗号化し `encAmount` を作る。
2. `sender` が **`channelTxZKP` を生成**(`encAmount` の正当性 + 更新後の自残高 ≥ 0、§2.2)。
3. `sender` が `encBalances` を更新: 自分の ct に減算 delta を加算、受取人の ct に `encAmount` を加算。
4. `sender` が `BalanceState' = { encBalances', settledTxChain(不変), stateVersion+1 }` を構成。
5. `sender` が `ChannelTx` と `balanceStateHash' = hash(H1', H2 = 0)` の**両方**に署名。
- out: `(ChannelTx, channelTxZKP, BalanceState', SpxSigWitness_tx, SpxSigWitness_state)`。

#### 3.2.2 `propagateChannelTx` — **actor: sender**
1. `sender` が残りの `member` に `ChannelTx`・`channelTxZKP`・`BalanceState'` を伝播。

#### 3.2.3 `coSignBalanceState` — **actor: 残り member(sender 以外の 2 人)**
- in: `ChannelTx`, `channelTxZKP`, `BalanceState'`
1. 全 `member` が **`channelTxZKP` を検証**(無い/不正なら署名しない)。受取人はさらに `encAmount` を
   復号して自分の残高増加を検証。各 `member` は §3.1 の検証項目を確認。
2. 正当なら `hash(H1', 0)` に署名。
- out: 追加 `SpxSigWitness`。全 3 署名で `BalanceState'` 確定。

### 3.3 Intmax 基盤プリミティブ

#### 3.3.1 `rangeProof` — **actor: ITS**
- in: `channelUpdateZKP`, `Transfer`, 現行 `balanceProof`
1. `ITS` が `channelUpdateZKP` を検証する(これを **range proof** と呼ぶ):
   delta の等量性・送信者残高 ≥ 送金額・暗号文の正当性(§2.3)。
- out: `bool`(偽なら `BP` に渡さない)。

#### 3.3.2 `signChannelState` — **actor: 送信 1 user(= channel メンバー全員 = 1 user)。v1 の `signTxTreeRoot` を置換**
- in: `tx_tree_root`, `TxV2MerkleProof`, 自分の `TxV2`(内に `Transfer` + `TxAux` + `channelUpdateZKP`), 減算後 `BalanceState'`
1. `TxV2MerkleProof` を検証し、自分の `TxV2` が `tx_tree_root` に含まれることを確認。
2. `channelUpdateZKP` を検証し、`BalanceState'.encBalances` が証明済み `senderDelta` を正しく適用したものであることを確認。
3. 確認できたら **`hash(H1', H2 = tx_tree_root)` に署名**する。
- out: `channelStateSig : SpxSigWitness`。
- **アトミック性(構造的)**: この 1 署名が「intmax 送金の認可」と「減算後残高ステートの合意」を同時に表す。
  `H2` に `tx_tree_root` が、`H1'` に減算後ステートが入っているため、**片方だけに署名することは定義上不可能**。
  v1 §3.4 の運用上の不変則は、本仕様ではハッシュ構造に内蔵される。

#### 3.3.2b 署名不要の特例(deposit mint / close burn) — **actor: validity / 検証回路**
- **deposit(mint)と `closeBurnTx`(burn)は、ZKP の validity 回路 / 出金検証回路の中で L2 署名(`signChannelState`)なしで受理される。**
- 根拠: deposit は L1 発の入金、`closeBurnTx` は close 確定の結果として L1/close 駆動で生じる出金であり、いずれも channel メンバーの共署名を要しない。
- 効果: `requestClose` 後の署名停止(§3.5.1)中でも `closeBurnTx` を L2 決済でき、freeze と burn 署名の矛盾を解消する。

#### 3.3.3 `produceBlock` — **actor: BP**
- in: 各 channel からの `TxV2` 群, 各 channel の `channelStateSig`
1. `BP` が `TxV2` 群から `TxV2Tree` を構築し `tx_tree_root` を得る。
2. `BP` が `Block { num_users, channel_id, timestamp, key_ids, tx_tree_root, deposit_hash_chain }` を構成。
- out: `Block`。

#### 3.3.4 `postBlock` — **actor: BP**
- in: `Block`
1. `BP` が `Block` を Ethereum L1 に L2 ブロックとして投稿。
- out: 確定 `BlockNumber`。

#### 3.3.5 `generateValidityProof` — **actor: BP(プルーバ)**
- in: `tx_tree_root`, `channelStateSig` 群, `Block`, 新 `PublicState`
1. `tx_tree_root`・各 `channelStateSig`・`Block`・結果としての `PublicState`(`commonState`)遷移を ZKP 回路で一貫検証。
   **重要**: `channelStateSig`(= `hash(H1', H2 = tx_tree_root)` への署名)が tx_tree_root への署名の**代替**であることを
   回路が検証・制約する。すなわち回路は「署名対象の `H2` 成分 = 当該 `tx_tree_root`」を开示・検証し、
   署名なし tx・`H2` 不一致 tx を不正として弾く。
2. `PublicState.account_tree_root` の各 `ChannelLeaf.prev` を「取り込んだ `BlockNumber`」に更新(二重支払い・不正 mint 防止)。
- out: `validityProof`(公開入力 = `ValidityPublicInputs`)。各ブロックごとに生成・オフチェーン公開。

#### 3.3.6 `generateBalanceProof` — **actor: channel(ITS が代表)**
- in: `validityProof`, 当該 channel の状態
1. `validityProof` を入力に、channel 総残高を主張する `balanceProof` を生成(`validityProof` が必須)。
- out: `balanceProof`(公開入力 = `BalancePublicInputs`)。

### 3.4 チャネル間送金 `interChannelTransfer`(3 フロー、`H2 = tx_tree_root`)

送信名義も受信名義も channel。送金額 `amount` の `Transfer` を送信 channel → 受金 channel に運ぶ。

> **アトミック性(構造的・v1 不変則の置換)**: 送金認可と減算後ステート合意は、単一の署名対象
> `hash(H1', H2 = tx_tree_root)` に統合されている(§3.3.2)。「送金だけ認可して減算を拒否する」
> 署名は存在し得ないため、co-member への損失転嫁(intra-channel 窃取)と過大 state での強制 close は
> 構造的に封じられる。

#### 送金フロー 1 `flowSend1`(送信 channel:tx + ZKP 作成 〜 構造的アトミック認可 〜 伝播)

- **actor: sender**
  1. `sender` が**両 channel(送信・受金)に close 申請がないこと**を `L1` で確認。
  2. `sender` が `Transfer`(受信 `ChannelId`・実受信者公開鍵・`amount`)と
     `TxAux`(両者のアドレス・両 `ChannelId`・`senderDelta`・`recipientDelta`)を作り、
     **`channelUpdateZKP` を生成**する。
  3. `sender` が `(Transfer, TxAux, channelUpdateZKP)` を `ITS` に渡す。
- **actor: ITS**
  4. `ITS` が `rangeProof`(= `channelUpdateZKP` の検証、§3.3.1)を行い、OK なら `BP` に tx を渡す。
  5. `ITS` が tx の内容・`TxV2Tree`・減算後 `BalanceState'`(`encBalances'` = 送信者 ct に `senderDelta` 適用、
     `settledTxChain' = hash(settledTxChain, TxLeafHash)`、`stateVersion+1`)を全員に共有。
     `TxLeafHash` は既知なので chain' はこの時点で計算できる。
- **actor: 送信 channel 全員(member[0..2])**
  6. 各 `member` が `signChannelState`(§3.3.2)で **`hash(H1', H2 = tx_tree_root)` に署名**。
     - 全員が揃わなければ送金は**認可されない**(部分署名は無効 = 送金不成立、co-member に損失なし)。
- **actor: ITS → BP**
  7. 揃った `channelStateSig` を `ITS` が `BP` に渡す(`BP` が `produceBlock` → `postBlock`)。
- **actor: ITS(送信 channel)**
  8. `tx_tree_root` が L1 ブロックに入ったら、`ITS` が `generateBalanceProof` で減算後 `balanceProof'` を生成。
     `balanceProof'` は偽造不可で post-send の L2 残高(`B-amount`)を反映するため、step6 で署名確定済みの
     `BalanceState'.encBalances`(減算後)と**必ず一致**し、公開入力の `settledTxChain` は
     `BalanceState'.settledTxChain` と一致する(新たな交渉・署名は不要)。
  9. `ITS` が `(tx のデータ(=Transfer, TxAux, channelUpdateZKP), TxV2MerkleProof, balanceProof')` を**受金 channel** に伝播。

#### 送金フロー 2 `flowSend2`(送信 channel:balanceProof 確定)

- **actor: ITS(送信 channel)**
  1. step8 の `balanceProof'` を、step6 で署名済みの `BalanceState'` に**紐づく proof としてローカル保管**する。
     state 自体は step6 で確定済み・不変。紐付けは「`balanceProof'` の公開入力 `settledTxChain` =
     `BalanceState'.settledTxChain`」で機械的に検証でき、close 提出時に L1 が照合する
     (**proof を後から state に「入れる」必要はない** — 署名時 proof 未生成の循環、監査所見 3 の解消)。
- **actor: BP(プルーバ、並行)**
  2. `generateValidityProof` で当該 block の `validityProof` を生成(`channelStateSig` を tx_tree_root 署名の代替として制約)。
- 註: 構造的アトミック署名(flow1 step6)が揃わなければ送金は不成立。一般の無応答には `SIGN_TIMEOUT`(3 分)超過で `requestClose`(§3.5)。

#### 送金フロー 3 `flowReceive3`(受金 channel:残高ステート反映、`H2 = 0`)

- **actor: 受金 channel 全員(member[0..2])**
  1. 伝播された `(tx のデータ, TxV2MerkleProof, balanceProof)` が valid か全員が確認
     (`TxV2MerkleProof` の包含検証 + `balanceProof` の整合 + **`channelUpdateZKP` の検証**)。
     `balanceProof` が無ければ送信者を無視。
- **actor: ITS(受金 channel)**
  2. `ITS` が `balanceProof` を**増加**側に更新(`generateBalanceProof`)。
  3. `ITS` が tx 内の受信者公開鍵を見て、
     `BalanceState' = { encBalances'(受金者 ct に channelUpdateZKP で証明済みの recipientDelta を加算),
     settledTxChain' = hash(settledTxChain, TxLeafHash), stateVersion+1 }` を構成
     (`balanceProof'` は chain で紐づくローカル保管)。
- **actor: 受金 channel 全員(member[0..2])**
  4. `agreeBalanceState(BalanceState', H2 = 0)` で全員が `hash(H1', 0)` に合意署名。

### 3.5 チャネル close ゲーム

順番: `requestClose` →(`GRACE_BEFORE_PROCESS`=10 分)→ `startProcess` →(`CHALLENGE_PERIOD`=1 日)→ `closeAndWithdraw`。

#### 3.5.1 `requestClose` — **actor: channel 内の任意の member**
- in: `channel_id`
1. 任意の `member` が `L1` に close を申請。
2. 申請後、全 `member` は当該 channel に関する**全署名行為を停止**(`agreeBalanceState`・`signChannelState` 等を行わない)。channel 外の者も当該 channel に送金しない。
3. `GRACE_BEFORE_PROCESS`(10 分)の猶予により、申請直前/直後の署名や通信ラグは「無いもの」とみなす。

#### 3.5.2 `startProcess` — **actor: 申請者(または任意 member)**
- in: `BalanceState`(全員署名済み), その中の `balanceProof`(= intmax-balanceProof)
1. 申請から 10 分後、`member` が `L1` に `BalanceState` と `balanceProof` を提出。
2. `L1` が `balanceStateHash = hash(H1, H2)` への全員署名を確認し、`balanceProof` を検証し、
   **公開入力の `settledTxChain` が `BalanceState.settledTxChain` と一致**することを照合して、
   `CHALLENGE_PERIOD`(1 日)を開始。

#### 3.5.3 `challenge` — **actor: 任意 member**
- in: 提出済みより新しい `BalanceState_newer`(全員署名済み)とその中の `balanceProof`
1. `member` が `BalanceState_newer` を `L1` に提出。
2. `L1` が提出物すべてに**全員署名がある**ことを確認し、添付 `balanceProof` の公開入力
   `settledTxChain` が当該 state のものと一致することを照合。
3. `BalanceState_newer.stateVersion > 現提出.stateVersion` なら置換。
4. 期間終了で `finalBalanceState` / `finalBalanceProof` が確定(古い state での close を防ぐ)。

#### 3.5.4 `closeAndWithdraw` — **actor: 各 member / L1 / intmax L2**
- in: 確定 `finalBalanceState` / `finalBalanceProof`, `closeBurnTx`, 各 member の `withdrawClaimZKP`
1. **(burn tx 提出)** close state 確定後、`member` が `closeBurnTx`(= `Transfer { recipient: burnAddress, amount: withdrawCap, ... }`)を `finalBalanceProof` と共に `L1` に提出。
2. **(L2 burn として処理)** 同じ `closeBurnTx` は intmax L2 でも「close state 確定時 burn tx」として処理され、channel 残高が L2 の spendable から除去される。
   - L2 で `withdrawCap` を burn するには**その額が現に channel に存在**する必要がある(通常の `Transfer` と同じ solvency 検証)。既に送金済みの古い残高は burn できない。
3. **(cap 確定)** `L1` が `finalBalanceProof` を検証し、`withdrawCap = finalBalanceProof の証明残高 = closeBurnTx.amount` を確定。
4. **(ZKP 付き個別出金)** 各 `member` は **`withdrawClaimZKP`** で「`finalBalanceState.encBalances` 内の自分の暗号化残高の平文 = 自分の出金額」を `L1` 上で証明して出金する。
   `L1` は **Σ(出金) ≤ `withdrawCap`** を強制。`finalBalanceState` が `withdrawCap` 超を主張しても超過分は出金不可。

#### 3.5.5 `claimLateTx` — **actor: 受信者(late tx の受取人)**
- in: `lateBalanceProof`, `tx のデータ`, `TxV2MerkleProof`
1. close 確定 version より後に知らされた当該 channel への intmax `Transfer` について、受信者が `lateBalanceProof` を入力に新しい `balanceProof` を ZKP で作る(balance 回路は `balanceProof` と同一)。
2. `L1` で verify されると受信者が onchain で受け取る。
3. `lateBalanceProof` は `finalBalanceProof` とは**別変数**で onchain 保管。

補足: `balanceProof` は tx 送信時に必ず受信者に添付する(`flowSend1`/`flowReceive3`)。受信者はそれが無い場合、送信者を無視する。

---

## 4. セキュリティ機構

各機構が **§0 の 5 性質**のどれを守るかを示す。

### 4.1 認可 authorization
- **全員署名(`agreeBalanceState` / `coSignBalanceState` / `signChannelState`)**: 残高ステート更新は
  `hash(H1, H2)` への 3 人全員の署名が合意対象。善良なノードは不正ステートに署名しないため、不正更新は成立しない。
- **署名アトミック性の構造化**: 送金認可と減算後ステート合意は単一の署名対象 `hash(H1', H2 = tx_tree_root)` に
  統合されている。v1 では運用規則だった「片方だけの署名は無効」が、v2 では**定義上表現不可能**になる
  (送金だけ認可する署名というものが存在しない)。validity 回路がこの署名を tx_tree_root 署名の代替として
  検証・制約する(§3.3.5)ため、回路レベルでも分離できない。
- **close は最後の合意 state で可能**: 合意が壊れても、最後に全員署名した `BalanceState` で onchain close できる。

### 4.2 二重支払い / 不正 mint 防止 no-double-spend
- **`PublicState`(`commonState`)**: 各 channel が「最後に tx を取り込まれたブロック番号」を
  `account_tree_root`(各 `ChannelLeaf.prev`)に持ち、同一資金の二重支払いや不正な mint を防ぐ。
- **`validityProof`**: `tx_tree_root`・`channelStateSig`・`Block`・`PublicState` を ZKP で一貫検証し、各ブロックで公開。
- **`signChannelState` の merkle 検証**: 送信 1 user は tx が `TxV2Tree` に含まれることを `TxV2MerkleProof` で確認してから署名。
- **出金 cap(`withdrawCap`)**: close 後の総出金は `finalBalanceProof` が証明する残高で上限化
  (`closeAndWithdraw` で `Σ(出金) ≤ withdrawCap` を強制)。膨張ステートや stale ステートでの窃取(監査 C1/C2/C5)を封じる。
- **close burn tx(`closeBurnTx`)**: L1 出金には `closeBurnTx` を `finalBalanceProof` と共に提出し、
  **同じ tx を intmax L2 でも burn として処理**する。L2 で `withdrawCap` を burn するには実残高が必要なので、
  既に送金済みの古い残高は burn できず L1 でも引き出せない(close 境界の二重支払い C1 を封じる)。
- **`settledTxChain` による state↔proof 束縛**: `H1` は proof オブジェクトでなく settle 履歴の
  hash chain にコミットし、balance 回路が同じ chain を公開入力に expose、close/challenge 時に L1 が
  一致を照合する。確定 state に対して**別の settle 履歴に基づく `balanceProof` を添付する攻撃**を封じ、
  「署名時点で proof 未生成」の循環(監査所見 3)も解消する。

### 4.3 支払い能力 solvency
- **`balanceProof` 添付必須**: 送金 tx には必ず `balanceProof` を添付。無ければ受信者は送信者を無視。
- **`rangeProof` = `channelUpdateZKP` 検証**: 残高が暗号化されたままでも「送信者残高 ≥ 送金額」が
  ZKP の range 制約として証明される(v1 の平文比較を置換)。ITS が検証してから BP に渡す。
- **`channelTxZKP`(チャネル内 range ZKP)**: チャネル内送金でも送信者の更新後残高 ≥ 0 を ZKP で証明
  (co-sign の必須検証項目)。暗号化残高でも**全成分の非負が帰納的に維持**され、
  Σ(成分) = 総額 = `withdrawCap` が保たれる。負残高成分を作って close で非負成分の合計を cap 超に
  膨らませ、正直メンバーの出金を横取りする攻撃(監査所見 5)を封じる。
- **`balanceProof` の単調更新**: 送信側は減少(`flowSend2`)、受金側は増加(`flowReceive3`)するように更新し、全員合意で固定。
- **delta の両翼束縛**: `TxLeafHash` が送信側 `senderDelta`(負)と受信側 `recipientDelta`(正)を同一 hash 構造に
  束縛し、`channelUpdateZKP` が等量性を証明するため、「送信側は小さく減らし受信側は大きく増やす」改竄ができない。

### 4.4 退出 / 活性 exit-liveness
- **close ゲームの順序と challenge**: `requestClose` → 10 分 → `startProcess` → 1 日 challenge → close。
  challenge 期間で**より新しい version の state**に置換でき、最終ステートが確定する(古い state での close を防ぐ)。
- **`GRACE_BEFORE_PROCESS`(10 分)**: 申請直前・直後の署名や通信ラグを「全部ないもの」とみなせる。
- **`SIGN_TIMEOUT`(3 分)**: 署名が中途半端で揃わない場合はプロトコル違反とみなし、close で退出可能(活性確保)。
- **両 channel の close 申請確認(`flowSend1`)**: close 申請のある channel への送金を行わない。
- **`withdrawClaimZKP`**: 残高が暗号化されていても、各 member は**自力で**(他 member の協力なしに)
  自分の取り分を証明して出金できる(退出に他者の復号協力を要しない)。
- **`lateBalanceProof`**: close 確定 version より後に届いた intmax tx の資金も、`lateBalanceProof` 入力の
  新 `balanceProof` を onchain verify することで受信者が受け取れる(資金の取りこぼし防止)。`balanceProof` と同一回路。

### 4.5 残高秘匿 confidentiality(v2 新設)
- **Regev 暗号化残高(`encBalances`)**: 各人の残高は本人の `RegevPk` でのみ復号可能な暗号文。
  channel 内の他 member・BP・L1 を含め、本人以外は個別残高を知り得ない。
- **チャネル内送金額の秘匿(`ChannelTx.encAmount`)**: 送金額は受取人の鍵で暗号化され、第三 member にも秘匿される。
- **`channelUpdateZKP` / `channelTxZKP`**: 残高・delta の平文を明かさずに正当性(等量・非負・暗号文整合・
  更新後残高 ≥ 0)を証明する。これにより秘匿と solvency 検証(§4.3)が両立する
  (チャネル内送金の検証も平文開示なしで可能)。
- **秘匿境界(明示)**:
  - チャネル間送金の `amount` は base 層 tx 内容として**平文**であり、BP・L1 から可視(§2.3)。
    秘匿されるのは**チャネル内の個人別残高と内訳**である。
  - channel 総残高は `balanceProof` の公開入力として可視(close の cap 決定に必要)。
  - チャネル内送金の受取人は自分宛て金額を当然知る(復号できる)。
