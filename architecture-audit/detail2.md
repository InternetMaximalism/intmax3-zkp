# detail2 — abstract2.md の詳細実装仕様(データ構造・ファイル構成・数値)

本書は [abstract2.md](./abstract2.md)(v2 = Lattice/Regev 秘匿版の最小仕様)を**必要条件**として、
現実装(enshrined-paymentchannel ブランチ)の**更新版仕様**を、データ構造体・ファイル構成・数値定数の
レベルで記述するものである。abstract2.md が「何を満たすべきか」を定め、本書が「現実装の型と
ファイルでどう満たすか」を定める。

**規範性**: abstract2.md と本書が矛盾する場合、§A(意図的差分)に列挙した項目を除き abstract2.md が優先する。

## A. abstract2.md からの意図的差分(2 点)

### A-1. SIS commitment → Regev 暗号化(形式変更)

現実装の lattice 層(`src/lattice/proof_adapter.rs`)は **SIS commitment**
(Q = 8,380,417、M = 128、N = 256、`LatticeCommitment` + `LatticeOpening`)である。
本仕様はこれを **Regev(Ring-LWE)暗号化**に置換する。

- 移植元: `/Users/plasma/repos/SIS-lattice-paymentchannel`(リポジトリ名に反して
  中身は Regev/Ring-LWE 実装。`crates/regev-adapter`, `crates/channel-types`,
  `crates/channel-state`, `regev_plonky3`)。
- **形式上の最大の変更**: SIS では受取人が opening(amount + randomness)を受け取らないと
  金額を検証できず、移植元実装も `ReceiverWitnessShare`(暗号化乱数 `r`, `e1u/e1v/e2u/e2v` の
  フルシェア)を送信していた。Regev で**受取人の `RegevPk` 宛てに暗号化**すれば、受取人は
  **自分の秘密鍵で復号するだけ**で金額を検証できる。**乱数シェア構造は廃止**する
  (`ReceiverWitnessShare` 相当の型は持ち込まない)。暗号化乱数は送信者だけが保持する
  **STARK の private witness** となる。
- 第三者(受取人でも送信者でもない co-member)は復号できないため、検証は
  `channelTxZKP` / `channelUpdateZKP`(§E)に依存する — これは abstract2.md §3.1 の設計どおり。

### A-2. 小ブロックモデル: 1 channel = 1 small block = 1 tx

abstract2.md §2.3 は「BP が**複数の送信者(channel)から tx を集めて** `TxV2Tree` を作り、その
root(`tx_tree_root`)に束縛する」モデルである。現実装は異なり、**本仕様はこの点で abstract2.md に
合わせない**(ユーザー決定):

- **1 つの small block は 1 channel が専有し、実質 1 tx を運ぶ**(1 block = 1 user / 1 tx)。
- BP は posting round ごとに channel 別の `SubBlock` の**列**を連結して L1 に投稿する
  (`IntmaxRollup.postBlockAndSubmit`、`SubBlock[]`)。「複数 channel の tx を 1 つの木に集める」
  のではなく、「channel ごとの小ブロックをハッシュチェーンで連結する」。
- 帰結 1: abstract2 の `tx_tree_root` は、本仕様では**自 channel の small block の
  `tx_tree_root`**(`SmallBlockRootMessage.tx_tree_root`)に対応する。中身は実質 1 leaf であり、
  `TxV2MerkleProof`(包含証明)は **1-leaf 木に対する自明な証明**(`MerkleInclusionProof` を
  形式上保持)。
- 帰結 2: `H2`(送金種別タグ)には abstract2 の「ブロック全体の tx_tree_root」ではなく
  **自 channel small block の `tx_tree_root`** が入る。アトミック性(認可と減算の単一署名)の
  議論は変わらない(§D-3)。
- 帰結 3: ITS(intmax-tx-sender)役は、現実装では **`bp_member_slot` で指名された member**
  (`ChannelRecord.bp_member_slot ∈ {0,1,2}`、その slot の `member_sphincs_pubkey_hashes[bp_member_slot]`
  が BP 担当鍵)が担う。役の識別は鍵ハッシュではなく **member slot** で行う(配列添字)。

この差分は安全性質(abstract2.md §4 の 5 性質)を弱めない: 集約木がないぶん包含証明は退化するが、
署名対象 `hash(H1, H2)` の構造・chain 束縛・cap 強制はすべて保たれる。

---

## B. 暗号プリミティブとパラメータ

### B-1. Regev(Ring-LWE)パラメータ

移植元 `SIS-lattice-paymentchannel/crates/regev-adapter` の `channel_params` に従う:

| パラメータ | 値 | 説明 |
|---|---|---|
| `q`(剰余体) | BabyBear `2^31 − 2^27 + 1 = 2,013,265,921` | Plonky3 STARK のネイティブ体と一致 |
| `n`(環次数) | **128**(2 冪、≥ 64 を要求) | 1 多項式の係数数 |
| `eta`(ノイズ) | 2 | CBD(centered binomial)パラメータ |
| `plain_bits` | 8 | 係数あたり平文ビット数 |
| 金額型 | `u64` | 8 bits × 8 係数にエンコード(残り係数は 0) |

### B-2. 型とサイズ

```rust
/// 各 member の Regev 公開鍵(channel 内で公開、channel 作成時に確定)
pub struct RegevPk {
    pub a: Vec<u32>,   // n 係数(mod q)
    pub b: Vec<u32>,   // n 係数; b = a·s + e
}
/// Regev 暗号文(abstract2.md の `LatticeCt`)
pub struct RegevCiphertext {
    pub c1: Vec<u32>,  // n 係数(mod q)
    pub c2: Vec<u32>,  // n 係数(mod q)
}
```

| 物 | サイズ(n = 128) |
|---|---|
| `RegevPk` | 2 × 128 × 4 = **1,024 bytes** |
| `RegevCiphertext` | 2 × 128 × 4 = **1,024 bytes** |
| `encBalances`(3 member 分) | **3,072 bytes** |
| 復号鍵 `RegevSk { s: Vec<i8> }` | 128 bytes(本人のみ保持。どの構造体にも現れない) |

`RegevCiphertext::digest() = hash_words([REGEV_CT_DOMAIN, c1.len() as u32, c1…, c2…]) → Bytes32`
(keccak256。state や PI に入るのは常にこの digest)。

### B-3. 準同型加算とノイズ予算(A5)

- `ct_a + ct_b`(成分ごと mod q 加算)は平文加算に対応する。受取側残高への delta 適用
  (abstract2.md §3.2 step 3「受取人の ct に `encAmount` を加算」)はこれを使う。
- **送信者の自残高更新は準同型ではなく fresh re-encryption**: 送信者は更新後残高を
  **新しく暗号化し直し**、`channelTxZKP` / `channelUpdateZKP` が
  「旧 ct の平文 = 新 ct の平文 + delta 平文」を証明する(移植元の transfer STARK と同形)。
  これにより送信者側 ct のノイズは蓄積しない。
- 受取側 ct は準同型加算でノイズが蓄積する。**`MAX_HOMO_ADDS_BEFORE_REFRESH` 回の加算ごとに、
  受取人自身が次に state を著作する版で fresh re-encryption(refresh)を行う**ことを必須とする。
  refresh の正当性も `channelTxZKP` と同じ「平文等値」STARK で証明する(delta = 0 の特例)。
- ノイズ条件(復号正当性): 蓄積ノイズの ∞-ノルムが `q / 2^(plain_bits+1)` 未満であること。
  CBD(eta=2) の 1 ct あたりノイズ上界から `MAX_HOMO_ADDS_BEFORE_REFRESH` を導出する。
  > **SECURITY(要承認)**: 本書は暫定値 `MAX_HOMO_ADDS_BEFORE_REFRESH = 64` を置くが、
  > これは未検証のセキュリティパラメータである。実装前に eta=2 / n=128 / q=BabyBear での
  > 厳密なノイズ解析(decryption failure rate を含む)を行い、ユーザー承認を得ること。
  > 黙って変更しない(CLAUDE.md 一般則)。

### B-4. ZK 証明系

| 証明 | バックエンド | 移植元 / 既存 |
|---|---|---|
| `channelTxZKP` / `channelUpdateZKP` / refresh 証明 | **Plonky3 STARK**(BabyBear) | `SIS-lattice-paymentchannel` の transfer STARK(`before = after + delta` を n-bit 整数として証明 + 3 ct の well-formedness)。**桁borrow が立たない ripple-carry 制約により range proof が内蔵**され、underflow(負残高)は構成的に不可能 |
| `withdrawClaimZKP` | Plonky3 STARK | 同上の縮退形(「自分の ct の平文 = 公開出金額」) |
| `balanceProof` / `validityProof` | Plonky2(既存) | `src/circuits/balance/`, `src/circuits/validity/`(変更点は §F) |
| close / claim 系 PI 束縛 | Plonky2(既存) | `src/circuits/channel/close_circuit.rs` ほか |
| 署名 | SPHINCS+(Poseidon) | 既存(`SpxSigWitness`)。変更なし |

`ChannelProofEnvelope { role, backend, proof }`(`state_update_verifier.rs:20-24`)は維持し、
`ProofBackend::Plonky3` を lattice 系 STARK の搬送に使う(既存設計どおり)。

---

## C. データ構造(更新版)

凡例: **[新]** = 新規型 / **[変]** = 既存型の変更 / **[維]** = 既存のまま / **[廃]** = 廃止。

### C-1. [廃] SIS 系

- `LatticeCommitment`(`src/common/channel.rs:293-305`)→ `RegevCiphertext` に置換。
- `LatticeOpening`(`channel.rs:309-313`)→ **廃止**。amount/randomness を相手に渡す構造は
  Regev では不要(§A-1)。検証は (a) 受取人の復号、(b) STARK 証明、の 2 経路のみ。
- `LatticeBindingVerifier` trait / `LatticeProofPurpose`(`state_update_verifier.rs:88-102`)→
  `RegevProofVerifier` trait に改名・改型(§E-4)。

### C-2. [新] BalanceState(abstract2.md §2.1 の中核)

```rust
/// abstract2.md: BalanceState { encBalances, settledTxChain, stateVersion }
pub struct BalanceState {
    pub channel_id: ChannelId,
    pub enc_balances: [RegevCiphertext; CHANNEL_MEMBERS],   // member index 順
    pub settled_tx_chain: Bytes32,                          // genesis = 0x00…00
    pub state_version: u64,                                 // チャネル内・間の両更新で +1
}
impl BalanceState {
    /// H1 = hash(BalanceState)。proof オブジェクトを含まない(署名時点で全成分既知)
    pub fn h1(&self) -> Bytes32 {
        // 順序: [BALANCE_STATE_DOMAIN, channel_id,
        //        enc_balances[0].digest(), enc_balances[1].digest(), enc_balances[2].digest(),
        //        settled_tx_chain, split_u64(state_version)] → keccak256
    }
}
/// 合意・署名対象(abstract2.md: balanceStateHash = hash(H1, H2))
pub fn balance_state_hash(h1: Bytes32, h2: Bytes32) -> Bytes32 {
    // [BALANCE_STATE_HASH_DOMAIN, h1, h2] → keccak256
}
```

- `CHANNEL_MEMBERS = 3`(固定、§G)。member は **slot 0/1/2** で `enc_balances` /
  `pending_adds`(D3)の配列添字として参照される。**member の identity は SPHINCS+ 公開鍵ハッシュ
  (`Bytes32`)**であり(DA)、slot はあくまで配列位置にすぎない。`ChannelRecord::validate()` は
  `member_sphincs_pubkey_hashes` が **3 つの相異なる非ゼロハッシュ**であること、および
  `bp_member_slot < CHANNEL_MEMBERS` を要求する。channel→member の束縛木は新 `MemberTree`
  (`src/common/trees/key_tree.rs`、高さ `MEMBER_TREE_HEIGHT = 2`)であり、その root が
  `ChannelLeaf.member_pubkeys_root`(§G、DB)。
- `H2` の値域: `0x00…00`(チャネル内)/ 自 small block の `tx_tree_root`(チャネル間、§A-2)。
  **`H2 = 0` の予約**: チャネル間経路で `tx_tree_root == 0` は検証で拒否する(空木 root が 0 に
  ならないことを keccak ベースの木で保証。v2 監査所見 4 への実装回答)。

### C-3. [変] ChannelState

`src/common/channel.rs:431-470` の `ChannelState` を次のとおり変更:

| フィールド | 処置 |
|---|---|
| `channel_id, epoch, small_block_number, close_freeze_nonce` | [維] |
| `channel_fund: ChannelFund` | [維](`withdrawCap` の源泉) |
| `channel_balance_root: Bytes32` | [変] **`balance_state: BalanceState` に置換**(root ではなく本体を保持。L1 提出時は `h1()` を使う) |
| `shared_native_nullifier_root, unallocated_confirmed_incoming, prev_digest, digest` | [維] |
| `member_signatures: Vec<MemberSignature>` | [変] 署名対象が変わる(下記)+ `MemberSignature` を改型: `{ member_slot: u8, sphincs_pubkey_hash: Bytes32, signature }`(旧 `key_id`/`user_id`/`key_condition_proof` を廃止、DA/DC)。N-of-N(3/3): `signatures[i].member_slot == i` かつ `signatures[i].sphincs_pubkey_hash == record.member_sphincs_pubkey_hashes[i]` |
| **(新)`h2_tag: Bytes32`** | この版の確定に使われたタグ。チャネル内更新 = 0 |

`ChannelState::signing_digest()`(domain `0x494d4348` "IMCH")の preimage を変更:
`channel_balance_root` の位置に **`balance_state.h1()`** を入れ、末尾に **`h2_tag`** と
**`split_u64(balance_state.state_version)`** を追加する。これにより
**`signing_digest()` 自体が `hash(H1, H2)` を内包**し、`member_signatures` が
abstract2.md §3.1 の「`hash(H1, H2)` への 3 人全員署名」を実現する。

- `state_version` は **epoch・small_block_number と独立な単調カウンタ**(チャネル内送金は
  small block を作らないため、`small_block_number` では版が数えられない)。
- 不変条件: `state_version` は厳密増加、1 version 1 state(challenge 順序は §H-4)。

### C-4. [変] ChannelBalance

```rust
pub struct ChannelBalance {
    pub channel_id: ChannelId,
    pub sphincs_pubkey_hash: Bytes32,          // 旧: user_id: UserId(DA: member 識別 = 公開鍵ハッシュ)
    pub balance_ciphertext: RegevCiphertext,   // 旧: balance_commitment: LatticeCommitment
}
```

### C-5. [変] Pay → ChannelTx(チャネル内送金、abstract2.md §2.2)

既存 `Pay`(`channel.rs:501-529`)を改型:

```rust
pub struct ChannelTx {
    pub recipient_sphincs_pubkey_hash: Bytes32,  // 旧: recipient_user_id: UserId(DA)
    pub enc_amount: RegevCiphertext,        // 受取人の RegevPk で暗号化(送信額)
    pub nonce: Bytes32,                     // ワンタイムランダム値
    pub channel_tx_zkp: ChannelProofEnvelope,  // 必須(無ければ co-sign 拒否)
    pub sender_sphincs_pubkey_hash: Bytes32,     // 旧: sender_user_id: UserId(DA)
    pub sender_signature: SignatureBytes,
}
```

- `signing_digest`(domain `PAY_DOMAIN = 0x494d5041` 維持): preimage を
  `[domain, channel_id, prev_state_digest, enc_amount.digest(), nonce, sender_sphincs_pubkey_hash(8), recipient_sphincs_pubkey_hash(8)]`
  に変更(member 部は各 2→8 limbs)。
- 旧 `Pay.amount: LatticeCommitment`(平文添付 opening 前提)は廃止。金額は受取人だけが復号で知る。

### C-6. [変] InterChannelTx(チャネル間送金、abstract2.md §2.3 `TxAux` 対応)

既存 `InterChannelTx`(`channel.rs:541-597`)を改型。abstract2 の `TxAux` /
`TxLeafHash` / `channelUpdateZKP` を現実装フィールドに対応させる:

| abstract2.md | 本仕様フィールド | 処置 |
|---|---|---|
| `senderAddr / recipientAddr` | `source_sphincs_pubkey_hash: Bytes32` / `receiver_deltas[i].receiver_sphincs_pubkey_hash: Bytes32` | [変](旧 `UserId` → 公開鍵ハッシュ、DA) |
| `senderChannelId / recipientChannelId` | `source_channel_id / destination_channel_id` | [維] |
| `senderDelta : LatticeCt` | **(新)`sender_delta_ct: RegevCiphertext`**(送信者 `RegevPk` 宛て、負値平文) | 旧 `sender_amount: LatticeCommitment` を置換 |
| `recipientDelta : LatticeCt` | `receiver_deltas: Vec<ReceiverBalanceDelta>` の `amount` を `RegevCiphertext` に改型(受取人 `RegevPk` 宛て、正値平文) | [変] |
| `channelUpdateZKP` | **(新)`channel_update_zkp: ChannelProofEnvelope`**(旧 `sender_balance_update_proof` / `receiver_update_proof` を統合) | [変] |
| `TxV2MerkleProof` | `tx_inclusion_proof: MerkleInclusionProof`(1-leaf 木、§A-2) | [維] |
| (tx_tree_root への束縛) | `signed_small_block: SignedSmallBlock` | [維] |
| `tx_hash` 等 | `seal, tx_hash, intmax_transfer_commitment, recipient_memo, transport_proof` | [維] |

**[新] TxLeafHash**(abstract2.md §2.3。`settledTxChain` の更新単位):

```rust
pub fn tx_leaf_hash(tx: &InterChannelTx) -> Bytes32 {
    // hash( hash(TX_LEAF_DOMAIN, source_sphincs_pubkey_hash(8), sender_delta_ct.digest()),
    //       hash(TX_LEAF_DOMAIN, receiver_sphincs_pubkey_hash(8), receiver_delta_ct.digest()) )
    // → 送信側・受信側の公開鍵ハッシュ(DA)と lattice 残高変化を両翼で束縛(member 部 2→8 limbs)
}
```

`settledTxChain` 更新則(abstract2.md §2.1):
- チャネル間送金(送・受とも): `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain, tx_leaf_hash])`
- deposit 取り込み: `chain' = hash_words([SETTLED_TX_CHAIN_DOMAIN, chain, deposit_hash])`
- チャネル内送金: 不変。
- `TxLeafHash` は署名時点(flowSend1 step 6 = small block 署名時)で既知 — nullifier
  (`SettledTransfer::nullifier()` は `block_number` を含む)はこの用途に**使えない**。
  nullifier は従来どおり base 層の二重 settle 防止専用(abstract2.md §2.1 の注のとおり)。

### C-7. [変] SmallBlockRootMessage(H1/H2 の搬送体)

`channel.rs:324-352`。フィールド集合は維持し、**意味を再定義**する:

| フィールド | 再定義 |
|---|---|
| `tx_tree_root` | **= `H2`**。チャネル間送金 small block では当該 1-tx 木の root(≠ 0)。 |
| `state_commitment_root` | **= `H1'`**(減算後 `BalanceState` の `h1()`)。旧「lattice commitment 群の root」から置換。 |
| 他フィールド | [変] `bp_key_id` → **`bp_member_slot: u8` + `bp_sphincs_pubkey_hash: Bytes32`**(DA、`sphincs_sig.rs` と lockstep)。残り(`channel_id, small_block_number, prev_small_block_root, medium_epoch_hint, close_freeze_nonce`)は [維] |

`signing_digest()`(domain `0x494d5342` "IMSB")の preimage は member 部のみ更新する
(`bp_key_id` → `bp_member_slot`(1)+`bp_sphincs_pubkey_hash`(8))が、`tx_tree_root`(= H2)と
`state_commitment_root`(= H1′)を**両方含む**構造は不変なので、この 1 署名が abstract2.md §3.3.2 の
`hash(H1', H2 = tx_tree_root)` 署名(= `channelStateSig`、構造的アトミック性)を実現する。
**片方だけに署名する署名対象は存在しない**(分離不可能、abstract2.md §3.4 不変則の構造化)。

`SignedSmallBlock`(`channel.rs:365-403`)は [維]。

### C-8. [変] Close 系(abstract2.md §2.4)

| 型 | 処置 |
|---|---|
| `CloseWithdrawal`(`channel.rs:601-626`) | [変] `final_channel_balance_root` → **`final_balance_state_h1: Bytes32`**。`burn_amount = withdrawCap`(abstract2 の `closeBurnTx.amount`)。 |
| `CloseIntent`(`channel.rs:615-`) | [変] 同上の置換 + **(新)`final_state_version: u64`** と **(新)`final_settled_tx_chain: Bytes32`** を追加(L1 照合用)。`signing_digest`(IMCI)preimage に両者を追記。 |
| `WithdrawalClaim`(`channel.rs:727-`) | [変] `user_amount: LatticeCommitment` → `user_amount_ct: RegevCiphertext`。member 識別 `user_id: UserId` → **`member_sphincs_pubkey_hash: Bytes32`**(DA)。`claim_proof` = `withdrawClaimZKP`(§E-3)。nullifier 導出は **`[IMCW, close_intent_digest(8), member_sphincs_pubkey_hash(8)]`**(close_intent_digest が channel_id 内包なので衝突安全、member 部 2→8 limbs)。 |
| `PostCloseIncomingClaim`(`channel.rs:856-`) | [変] `receiver_amount` を `RegevCiphertext` に。member 識別 `receiver_user_id: UserId` → **`receiver_sphincs_pubkey_hash: Bytes32`**(DA)。abstract2.md §3.5.5 `claimLateTx` の実装。`lateBalanceProof` は `claim_proof` 内で検証され、`finalBalanceProof` とは**別変数**(契約 storage 上も `usedSharedNativeNullifiers` 系で分離)で管理。 |
| `SpecialClose` / `CancelClose` | [変] member 識別子のみ pubkey ハッシュ化(`SpecialClose` の検閲 BP 指名 = `offending_bp_member_slot: u8` + `offending_bp_sphincs_pubkey_hash: Bytes32`、DA)。それ以外は [維](abstract2.md の範囲外の追加防御。安全性質を弱めない追加なので存置。§I-3) |

**[新] close PI の `member_set_commitment`(F5 SECURITY、DB)**: full channel-close 回路は
**`member_set_commitment = keccak([CLOSE_MEMBER_SET_DOMAIN, sphincs_pk_hash_0(8), sphincs_pk_hash_1(8),
sphincs_pk_hash_2(8)])`**(`close_member_set_commitment`、ドメイン `CLOSE_MEMBER_SET_DOMAIN = 0x494d434d`
"IMCM")を **close PI の末尾 8 limbs に expose** する。L1(`ChannelSettlementManager`)は登録済みの
`member_sphincs_pubkey_hashes` から同じ keccak を再計算して照合し、**回路内で 3/3 署名検証された鍵が
当該 channel の登録メンバー集合であること**を束縛する(非メンバー鍵による署名すり替えを排除)。
PI 末尾追記なので既存の close-intent 共有ベクタ(77 limbs ぶん)はずれない。

### C-9. [維/廃] base 層型

`Transfer`(`transfer.rs:34-39`、TRANSFER_LEN = 9)、`SettledTransfer`(nullifier 含む)、
`Block`、`PublicState`、`ValidityPublicInputs`、`ChannelId` — すべて変更なし。

- **[廃]** `KeyId` / `UserId` / `KeyRecord`(と `KEY_RECORD_DOMAIN`)は **削除された**(DA/DC、§D5)。
  これらは旧 2 層 identity(multisig/threshold)の名残であり、abstract2.md §1(「1 人 1 key 1 account,
  address == pubkey」)に不整合だった。member 識別子は全層で **SPHINCS+ 公開鍵ハッシュ `Bytes32`** に統一。
- **[変]** `ChannelRecord` / `MemberSignature` は §C-3・§H-1 のとおり pubkey ハッシュ化(変更なしではない)。
- **`Block.key_ids`**: フィールド名は維持するが、意味を **「active member slots(0/1/2)」**に再解釈する
  (block hash の preimage に残る)。multisig の鍵 identity ではなく、当該ブロックで署名した member の
  slot 集合を表す。

---

## D. 署名対象の統一(abstract2.md §3.1 / §3.3.2)

| 更新種別 | 署名対象 | H2 | 実装上の署名 digest |
|---|---|---|---|
| チャネル内送金(`ChannelTx`) | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()`(h2_tag = 0、§C-3) |
| チャネル間送金(送信側) | `hash(H1', tx_tree_root)` | small block の `tx_tree_root` | `SmallBlockRootMessage::signing_digest()`(§C-7) |
| チャネル間受金(受信側) | `hash(H1', 0)` | `0x00…00` | `ChannelState::signing_digest()`(受信側は small block を作らない) |
| deposit / closeBurnTx | **署名不要**(abstract2.md §3.3.2b) | — | validity / close 回路内で受理 |

- **D-3(アトミック性)**: チャネル間送金で「送金は認可するが減算は拒否する」署名は、署名対象に
  `H1'`(減算後 state)と `H2`(tx_tree_root)が単一 preimage で同居するため**定義上存在しない**。
  validity / confirmation 回路はこの署名を tx_tree_root への署名の**代替**として検証する
  (`H2` 成分 = 投稿された small block の `tx_tree_root` であることを制約。§F-2)。

---

## E. lattice 系 ZKP(新規回路、Plonky3)

### E-1. channelTxZKP(チャネル内、abstract2.md §2.2 / 監査所見 5)

**証明文**(public: `prev_sender_ct.digest()`, `next_sender_ct.digest()`, `enc_amount.digest()`,
sender / recipient の `RegevPk` digest。private: 平文残高・金額・暗号化乱数):
1. `enc_amount` は受取人 `RegevPk` への正しい暗号文で、平文 `amount ≥ 0`。
2. `prev_sender_ct` の平文 = `next_sender_ct` の平文 + `amount`、かつ各平文は n-bit 非負整数
   (**ripple-carry 制約で underflow 不可能 → 更新後送信者残高 ≥ 0 が内蔵**)。
3. `next_sender_ct` は送信者 `RegevPk` への fresh encryption として well-formed。

### E-2. channelUpdateZKP(チャネル間、abstract2.md §2.3)

**証明文**(public: `sender_delta_ct.digest()`, `receiver_delta_ct.digest()`,
`prev/next_sender_ct.digest()`, 両 `RegevPk` digest, `amount`(base 層では平文)):
1. `sender_delta_ct` と `receiver_delta_ct` の平文絶対値がともに `amount`(等量・符号逆)。
2. 送信者残高の更新(E-1 と同じ ripple-carry、`残高 ≥ amount`)。
3. 両 delta がそれぞれの `RegevPk` への正しい暗号文。

`rangeProof`(abstract2.md §3.3.1)= この ZKP の**検証**(ITS = `bp_member_slot` で指名された member が BP に渡す前に実施)。

### E-3. withdrawClaimZKP(close 後出金、abstract2.md §2.4)

**証明文**(public: `final_balance_state_h1` 内の自成分 `user_amount_ct.digest()`,
出金額 `amount`(平文・公開), 自分の `RegevPk` digest):
「`user_amount_ct` の平文 = `amount`」。復号鍵は private witness。他 member の協力不要
(exit-liveness、abstract2.md §4.4)。

### E-4. 検証 trait(`state_update_verifier.rs` 改修)

```rust
pub enum RegevProofPurpose {
    ChannelTx,        // E-1
    ChannelUpdate,    // E-2
    WithdrawClaim,    // E-3
    BalanceRefresh,   // §B-3 refresh(delta = 0 特例)
}
pub trait RegevProofVerifier {
    fn verify(&self, envelope: &ChannelProofEnvelope, purpose: RegevProofPurpose,
              public_inputs: &[u32]) -> Result<(), ChannelStateUpdateError>;
}
```

旧 `LatticeBindingVerifier` / `LatticeProofPurpose::{TransferAmount, BalanceOpening}` と、
`ReceiverDeltaApplicationWitness` / `InChannelTransferUpdateWitness` 内の
`LatticeOpening` フィールド群(opening 受け渡し前提)は廃止。
外部ヘルパープロセス(`tools/lattice-proof-helper`)も廃止し、Plonky3 STARK を in-process で検証する。

---

## F. balance / validity 回路の変更

### F-1. BalancePublicInputs(`src/circuits/balance/balance_pis.rs:47-63`)

```rust
pub struct BalancePublicInputs {
    pub channel_id: ChannelId,                 // [維]
    pub public_state: PublicState,             // [維]
    pub block_r: BlockNumber,                  // [維]
    pub private_commitment: PoseidonHashOut,   // [維]
    pub settled_tx_chain: Bytes32,             // [新] 回路が取り込んだ settle 履歴の chain
}
// BALANCE_PUBLIC_INPUTS_LEN += 8(Bytes32 分)
```

balance 回路は、settle(transfer / deposit)を 1 件取り込むたびに
`chain' = hash(chain, TxLeafHash or deposit_hash)` を**回路内で**計算し、最終値を公開入力に
expose する(abstract2.md §2.1 の新規要件)。`H1` は proof オブジェクトを含まないため、
state↔proof の対応は「`balanceProof.PI.settled_tx_chain == BalanceState.settled_tx_chain`」の
**一致照合**で機械的に検証できる(署名時 proof 未生成の循環 = 監査所見 3 の解消)。

### F-2. validity / confirmation 回路(abstract2.md §3.3.5)

- small block 署名(`channelStateSig` 相当 = `SignedSmallBlock.signatures`)の検証に、
  **「署名 preimage の `tx_tree_root` 成分 = 当該 small block の `tx_tree_root`」かつ
  「チャネル間経路では `tx_tree_root ≠ 0`」**の制約を追加。署名検証は **`update_channel_tree`
  (UpdateUserTree)の per-slot ループで in-circuit に行う**(旧 `signature_aggregation/` パイプラインは
  live validity パスに非接続の死蔵コードであり削除、DC・§D5)。同ループは署名 pubkey が channel の
  Poseidon `member_pubkeys_root` 配下の slot に包含されることも証明する(§F-3 のソ-ンドネス束縛)。
- `PublicState.account_tree_root` の `ChannelLeaf.prev` 更新(取り込みブロック番号、二重支払い防止)は [維]。

### F-3. ChannelClosePublicInputs(`close_pis.rs`)

追加フィールド: `final_state_version: u64`(2 limbs)、`final_settled_tx_chain: Bytes32`(8 limbs)、
**`member_set_commitment: Bytes32`(8 limbs、§C-8、末尾に追記)**。
`final_channel_balance_root` は `final_balance_state_h1` に改名。
**`CHANNEL_CLOSE_PUBLIC_INPUTS_LEN = 77 → 85`**(`member_set_commitment` を末尾 8 limbs に追加。
77 limbs ぶんの既存レイアウトは不変なので close-intent 共有ベクタを温存)。

他の close 系 PI(DA に伴う member 識別子の 2→8 limbs 拡張):

| 回路 | PI 長 | 変更 |
|---|---|---|
| close(`close_pis.rs`) | **77 → 85** | `member_set_commitment`(8)を末尾追記 |
| withdrawal claim(`withdrawal_claim_pis.rs`) | **42 → 48** | `user_id`(2)→ `member_sphincs_pubkey_hash`(8) |
| post-close claim(`post_close_claim_pis.rs`) | **34 → 40** | `receiver_user_id`(2)→ `receiver_pubkey_hash`(8) |
| cancel close(`cancel_close_pis.rs`) | **41**(不変) | PI は channel_id のみ。witness 側の `UserId`/`KeyId` 除去のみ |

**ソ-ンドネス束縛**: validity(`update_channel_tree`)が **署名 pubkey ∈ channel の Poseidon
`member_pubkeys_root`**(`account_tree_root` 配下の `ChannelLeaf` に束縛)であることを slot 包含証明で
証明する(DB)。close は `member_set_commitment` を expose し、L1 が登録メンバー集合と keccak 照合する
(§C-8)。これにより回路内(Poseidon)と L1 境界(keccak)の双方で「署名鍵 = 登録メンバー」が束縛される。

---

## G. 数値定数一覧

### G-1. 新設

| 定数 | 値 | 根拠 |
|---|---|---|
| `CHANNEL_MEMBERS` | **3** | abstract2.md §2.1(3 人固定) |
| `MEMBER_TREE_HEIGHT` | **2** | 新 `MemberTree`(4 葉 ≥ 3 slot)の Poseidon Merkle 高さ(DB)。旧 `KEY_TREE_HEIGHT` / `KEY_SET_TREE_HEIGHT` / `MEMBER_KEY_TREE_HEIGHT` / `KEY_ID_BITS` を**置換・削除** |
| `SIGN_TIMEOUT_SECS` | **180** | abstract2.md §2.5(3 min)。旧 `SMALL_BLOCK_SIGNATURE_TIMEOUT_SECS = 60` を置換 |
| `GRACE_BEFORE_PROCESS_SECS` | **600** | abstract2.md §2.5(10 min)。§H-2 |
| `CHALLENGE_PERIOD_SECS` | **86,400** | abstract2.md §2.5(1 day)。`ChannelSettlementManager` の immutable `challengePeriod` に設定 |
| `MAX_HOMO_ADDS_BEFORE_REFRESH` | **64(暫定・要承認)** | §B-3 |
| `REGEV_N` / `REGEV_ETA` / `REGEV_PLAIN_BITS` | 128 / 2 / 8 | §B-1 |

### G-2. 新設ドメイン定数(既存 IMxx と非衝突を確認済み)

| 定数 | 値 | ASCII |
|---|---|---|
| `BALANCE_STATE_DOMAIN` | `0x494d4253` | "IMBS" |
| `BALANCE_STATE_HASH_DOMAIN` | `0x494d4248` | "IMBH" |
| `TX_LEAF_DOMAIN` | `0x494d544c` | "IMTL" |
| `SETTLED_TX_CHAIN_DOMAIN` | `0x494d5443` | "IMTC" |
| `REGEV_CT_DOMAIN` | `0x494d5243` | "IMRC" |
| `CHANNEL_TX_ZKP_DOMAIN` | `0x494d435a` | "IMCZ" |
| `CHANNEL_UPDATE_ZKP_DOMAIN` | `0x494d555a` | "IMUZ" |
| `CLOSE_MEMBER_SET_DOMAIN` | `0x494d434d` | "IMCM"(keccak、§C-8 close PI `member_set_commitment`。L1 照合) |
| `MEMBER_LEAF_DOMAIN` | `0x4d424c46` | "MBLF"(**Poseidon**。`MemberTree` の葉ドメイン分離、`key_tree.rs`、DB) |
| `REGEV_PK_POSEIDON_DOMAIN` | `0x494d5250` | "IMRP"(**Poseidon**。member 木の葉の `regev_pk_digest = Poseidon([IMRP, n, a…, b…])`、`regev/keys.rs`) |

> 注: `MEMBER_LEAF_DOMAIN` / `REGEV_PK_POSEIDON_DOMAIN` は**回路内 Poseidon**のドメイン(member 木束縛、DB)。
> `CLOSE_MEMBER_SET_DOMAIN` は **L1 keccak** のドメイン(close PI 照合)。回路内(Poseidon)/ L1 境界(keccak)の
> 二系統で同一メンバー集合を表すのが DB の設計。`regev_pk_root`(keccak "IMRR" `0x494d5252`)は §H-1 の L1 アンカー用。

### G-3. 既存(変更なし、参照)

ドメイン: IMCH / IMPA / IMSB / IMSS / IMIT / IMCL / IMCI / IMSC / IMCN / IMCP / IMCW / IMUF /
IMCR / IMLD。木: `CHANNEL_TREE_HEIGHT = 32`,
`TRANSFER_TREE_HEIGHT = 6`, `TX_TREE_HEIGHT = 32`, `BLOCK_NUMBER_BITS = 63`。
`MAX_CLOSE_TRANSFERS = 16`, `SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW = 5`。
**削除**: `KEY_ID_BITS` / `KEY_TREE_HEIGHT` / `KEY_SET_TREE_HEIGHT` / `MEMBER_KEY_TREE_HEIGHT`、
および `IMKR`(`KEY_RECORD_DOMAIN`)と threshold / num_keys 系の定数(DA/DC、§D5)。

---

## H. フロー対応(abstract2.md §3 → 実装)

### H-1. 平常時

| abstract2.md | 実装(更新版) |
|---|---|
| §3.0 `publishRegevPk` | channel 作成時、`registerChannel` で channel ごとに `[(sphincs_pubkey_hash, regev_pk, l1_recipient); 3]` を確定(per-key_id の threshold / key-set 登録は廃止、DA/DC)。`memberKeys[channel_id]` は abstract2 §1 の `Map<ChannelId,[(Address,RegevPk);3]>`。L1 アンカー: `ChannelRecord` の `member_sphincs_pubkey_hashes` + `member_pubkeys_root` + `regev_pk_root`(keccak "IMRR")を IMCR `signing_digest` に取り込む。回路内束縛は同一メンバーから組む Poseidon `MemberTree`(DB) |
| §3.1 `agreeBalanceState` | `ChannelState::signing_digest()`(= hash(H1,H2) 内包)への 3 member 署名収集。検証項目は abstract2 §3.1 のとおり(version+1 / chain 整合 / 自成分復号検証 / `channelTxZKP` / `channelUpdateZKP` + 包含証明) |
| §3.2 `channelTransfer` | `ChannelTx` 構築(§C-5)→ `channelTxZKP` 生成(§E-1)→ 伝播 → co-sign。`ChannelTransition::InChannelTransfer` |
| §3.3.1 `rangeProof` | `bp_member_slot` で指名された member が `channelUpdateZKP` を `RegevProofVerifier` で検証 |
| §3.3.2 `signChannelState` | `SmallBlockRootMessage` 署名(§C-7)。包含確認は 1-leaf 木に対する `tx_inclusion_proof`(§A-2) |
| §3.3.3–3.3.4 `produceBlock` / `postBlock` | BP が posting round の `SubBlock[]` を構成し `IntmaxRollup.postBlockAndSubmit`(`IntmaxRollup.sol:433-445`)。1 SubBlock = 1 channel |
| §3.3.5 `generateValidityProof` | 既存 validity 系 + §F-2 制約 |
| §3.3.6 `generateBalanceProof` | 既存 balance 系 + §F-1 chain expose |
| §3.4 flowSend1/2, flowReceive3 | `InterChannelTx`(§C-6)で実装。step 5 の `chain'` は `TxLeafHash` から署名前に計算。受信側は `ChannelTransition::ReceiverBundleApply` |

### H-2. close ゲーム(abstract2.md §3.5 → `ChannelSettlementManager.sol`)

| abstract2.md | 実装(更新版) | 変更 |
|---|---|---|
| §3.5.1 `requestClose` | **[新] `requestClose()`**: `channelStatus` を即 `ClosePending` 化し `closeRequestedAt = block.timestamp` を記録(署名停止の合図。`isNativeSendAllowed` が false になる) | 現契約は request/startProcess が未分離のため**関数追加** |
| §3.5.2 `startProcess` | `submitCloseIntent(CloseIntent, proof)`(`ChannelSettlementManager.sol:331-387`)に **`require(block.timestamp ≥ closeRequestedAt + GRACE_BEFORE_PROCESS_SECS)`** を追加。L1 検証に **(新)「`finalBalanceProof` の PI `settled_tx_chain` == `CloseIntent.final_settled_tx_chain`」「全 member 署名が `hash(H1,H2)` 系 digest 上にある」**を追加 | chain 照合の追加が v2 の核心 |
| §3.5.3 `challenge` | 既存「challenge 期間内のより新しい close intent による置換」(`331-387` 内の ClosePending 分岐)。置換順序を `(final_epoch, closeNonce)` から **`(final_epoch, final_state_version)`** に変更。提出物ごとに chain 照合を実施 | `final_state_version` 比較へ |
| §3.5.4 `closeAndWithdraw` | `finalizeClose()`(`498-524`)→ 各 member `submitWithdrawalClaim`(`526-569`、claim_proof = withdrawClaimZKP §E-3)→ `claimWithdrawalCredit()`(`610-615`)。**Σ(出金) ≤ withdrawCap** は既存 `totalWithdrawn + amount ≤ finalizedChannelFundAmount` で強制。`closeBurnTx` は `burn_tx_hash` として L1 提出 + L2 burn 処理(署名不要、§D 表 4 行目) | claim_proof の中身が Regev 化 |
| §3.5.5 `claimLateTx` | `submitPostCloseClaim`(`571-608`)。`lateBalanceProof` は claim_proof 内で検証、`usedSharedNativeNullifiers` で二重受領防止 | [維] |

### H-3. 実装独自の追加防御(abstract2.md の範囲外、存置)

- `submitSpecialClose`(BP 検閲スラッシュ、`SPECIAL_CLOSE_MEDIUM_BLOCK_WINDOW = 5`)
- `cancelClose`(復活 tx による close 取り消し)
- `submitLateOutgoingDebitCorrection`
これらは abstract2 の 5 性質に対し**追加的**(exit-liveness を強める方向)であり、矛盾しない。

### H-4. challenge 順序の不変条件

L1 の置換規則は「`final_epoch` が大きい、同点なら `final_state_version` が大きい」。
善良 member の規律(A3): 1 version に 1 state のみ署名(`OneStatePerVersion`)。
これにより「最高 version の全員署名 state が一意に確定」する(ChannelSafety2.lean
`challenge_latest_wins2` の前提と一致)。

---

## I. ファイル構成(変更マップ)

### I-1. 新規

| パス | 内容 |
|---|---|
| `src/regev/mod.rs` | モジュール宣言 |
| `src/regev/params.rs` | §B-1 パラメータ(`channel_params` 移植) |
| `src/regev/keys.rs` | `RegevPk` / `RegevSk` / keygen(移植元 `regev-adapter/src/lib.rs:110-123`) |
| `src/regev/encrypt.rs` | encrypt / decrypt / 準同型加算 / 金額エンコード(`encode_value_message` 移植) |
| `src/regev/transfer_stark.rs` | E-1/E-2/E-3/refresh の Plonky3 AIR(移植元 transfer STARK を 4 purpose に拡張) |
| `src/common/balance_state.rs` | `BalanceState` / `balance_state_hash` / `tx_leaf_hash` / chain 更新(§C-2, C-6) |

### I-2. 変更

| パス | 変更 |
|---|---|
| `src/common/channel.rs` | §C-1〜C-8 の型変更一式。`LatticeCommitment` / `LatticeOpening` 削除 |
| `src/lattice/proof_adapter.rs` | **削除**(SIS 系)。`tools/lattice-proof-helper` も削除 |
| `src/circuits/channel/state_update_verifier.rs` | `RegevProofVerifier` 化(§E-4)。witness 構造から `LatticeOpening` 排除 |
| `src/circuits/balance/balance_pis.rs` / `balance_circuit.rs` | `settled_tx_chain` expose(§F-1) |
| `src/circuits/validity/…`(confirmation 系) | §F-2 の H2 制約 |
| `src/circuits/channel/close_pis.rs` / `close_circuit.rs` | §F-3 |
| `src/circuits/channel/withdrawal_claim_pis.rs` | `user_amount_digest` の意味を `RegevCiphertext::digest()` に |
| `contracts/src/ChannelSettlementManager.sol` | `requestClose()` 追加・GRACE 強制・chain 照合・`final_state_version` 比較(§H-2) |
| `contracts/src/ChannelSettlementVerifier.sol` | close 系 PI hash に `final_state_version` / `final_settled_tx_chain` を追加 |
| `src/constants.rs` | §G の定数追加、`CHANNEL_MEMBERS = 3` |
| `src/circuits/channel/e2e_flow.rs` | E2E を Regev 化(opening 受け渡し撤去、ZKP 必須化) |

### I-3. 不変

`src/common/transfer.rs`(`Transfer` / `SettledTransfer` / nullifier)、`src/common/block.rs`、
`src/common/public_state.rs`、`src/utils/hash_chain/`、SPHINCS+ 系
(`sphincs_sig.rs`)、`IntmaxRollup.sol` の postBlock / deposit / finalize パイプライン、
MLE/WHIR ラッパ。

---

## J. abstract2.md 必要条件チェックリスト

| abstract2.md 要件 | 本仕様での充足 | 状態 |
|---|---|---|
| §1 `RegevPk` / `LatticeCt` | §B-2(`RegevPk` / `RegevCiphertext`) | 新規 |
| §2.1 `BalanceState { encBalances, settledTxChain, stateVersion }` | §C-2 | 新規 |
| §2.1 `H1` に proof を含めない | §C-2 `h1()`(digest のみ) | 新規 |
| §2.1 `BalancePublicInputs` に chain expose | §F-1 | 変更 |
| §2.2 `ChannelTx` + `channelTxZKP` 必須 | §C-5 + §E-1 | 新規 |
| §2.3 `TxAux` / `TxLeafHash` / `channelUpdateZKP` | §C-6 + §E-2 | 変更 |
| §2.3 `channelStateSig`(hash(H1', H2) 署名) | §C-7 / §D | 変更(再定義) |
| §2.4 `finalBalanceProof` の chain 照合 | §H-2 startProcess/challenge | 変更 |
| §2.4 `withdrawClaimZKP` / `lateBalanceProof` | §E-3 / §H-2 | 変更 |
| §2.5 タイムアウト 3 定数 | §G-1 | 変更(60s→180s ほか) |
| §3.2 / §3.4 フロー | §H-1 | 変更 |
| §3.3.2b 署名不要特例(deposit / closeBurnTx) | §D 表 | 既存整合 |
| §3.5 close ゲーム(request → 10min → start → 1day → close) | §H-2(`requestClose` 追加) | 変更 |
| §4.2 Σ(出金) ≤ withdrawCap | 既存 `totalWithdrawn` 強制 | 既存 |
| §4.5 秘匿境界(amount は base 層平文、総残高は PI 可視) | §E-2 public `amount` / balanceProof PI | 整合 |
| (差分)`TxV2Tree` 集約 | **充足しない**(§A-2、ユーザー決定) | 意図的差分 |

## K. 残課題(abstract3 / 実装時要解決)

1. **M7(signed-but-unsettled race)**: flowSend1 step 6 の全員署名 state が L1 取り込み前に
   存在する窓。abstract2.md でも未解決(lean-safety-proof2.md)。実装対策候補:
   `.txRoot` タグ付き state(`h2_tag ≠ 0` の `ChannelState`)を close に採用する際、
   L1 が当該 small block の包含証明を要求する — `CancelClose` / 確認証明
   (`SignedSmallBlock.confirmation_proof`)の既存機構を流用できる見込み。仕様確定は abstract3 で。
2. **retry / version 再割当の意味論**(監査所見 12): 送金不成立時の version 消費規則の明文化。
3. **ノイズ予算の厳密解析**(§B-3 の要承認パラメータ)。
4. **`RegevPk` の真正性**: `publishRegevPk` の鍵すり替え攻撃面。`ChannelRecord` への
   `regev_pk_root` 取り込み(§H-1)で L1 アンカーするが、登録時検証(自分の鍵で暗号化された
   テスト ct の復号確認等)の手順は実装時に設計する。
5. **Lean モデルの追随**: `final_state_version` 比較・1 block = 1 tx 退化・refresh 演算を
   ChannelSafety2.lean の v3 改訂(`Apply` の署名パラメータ化)に反映する。
6. **登録メカニズム(member 木の genesis 取り込み)**(DA/DB、§D5): 回路内束縛
   (`update_channel_tree` が `member_pubkeys_root` 配下の slot 包含を証明)は**実装済み・ユニットテスト済み**
   だが、その束縛が照合する**根(`member_pubkeys_root`)を genesis / account tree に投入する登録経路**は
   未整備(balance 回路の genesis は `switch_board.rs:230` で空 account tree をハードコード)。
   現状は **registration soundness = genesis-trust**(channel ごと、`intmax3-channel-mvp.md` の前提)であり、
   登録済み genesis との整合は follow-up。これに伴い **close の full-stack e2e は registration ブロックで
   赤**(束縛自体の負例テストは緑、§D5 参照)。
