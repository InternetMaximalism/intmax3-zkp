## 0. Types & Terms

```rust
type Bytes = Vec<u8>;
type Bytes32 = [u8; 32];
type U256 = [u8; 32];
type Address = [u8; 20];
```

- **MerkleProof**

```rust
struct MerkleProof {
    siblings: Vec<Bytes32>
}
```

`merkle_proof.verify(index, leaf, root) -> bool`
Verifies that the leaf at position `index` from the left is included in `root`.

## 1. Common Structures

### 1.1 Transfer, Deposit, Tx

```rust
struct Transfer {
    recipient: Bytes32,   // withdrawal: an Ethereum address padded with left-aligned zeros
                          // non-withdrawal: hash(receiver_id, transfer_salt)
    token_index: u32,
    amount: U256,
    aux_data: Bytes32 // hash(memo) or any random value if no memo
}
```

```rust
struct Deposit {
    depositor: Address,
    recipient: Bytes32, // hash(global_receiver_id, transfer_salt)
    token_index: u32,
    amount: U256,
    block_number: u64,
    aux_data: Bytes32
}
```

where `aux_data=keccak256(timestamp, is_eligible)` (`is_eligible` is flag for mining, `timestamp` is also used for mining)

```rust
struct Tx {
    transfer_merkle_root: Bytes32,
    nonce: u32
}
```

- `transfer_merkle_root` is the Merkle root of the `Transfer`s contained in this Tx.
  - Restricted to 64 transfers (height = 6)

### 1.3 Block

```rust
struct Block {
    aggregatorID: u32,
    userIDs: [u32; MAX_USER_IDs],
    tx_tree_root: Bytes32,
    deposit_hash_chain: Bytes32
}
```

On-chain acceptance rules:

- `userIDs` is a fixed-length byte array.
- `userIDs` contains no duplicate `userID` values.
- `aggregatorIDs[msg.sender] == aggregatorID`.

### 1.4 History Root and Deposit Root

History root is updated by the following rule.
`deposit_root <- hash(deposit_root, deposit)`
`history_root <- hash(history_root, deposit_root, block)

## 2. Public State

### 2.1 Send Tree

The send tree is a Merkle tree that stores the block numbers and tx_tree_root of the blocks in which that the specific user’s transactions were included.

```rust
struct SendLeaf {
    prev: u64, // The block number where that user’s Tx was previously included (0 if none)
    cur:  u64  // The latest block number where it was included (first time: that block)
    tx_tree_root: Bytes32 // The tx tree root which the user send at that block
}
```

- If the first tx inclusion is at block=100:
  ```rust
  { prev: 0, cur: 100, tx_tree_root :tx_tree_root1 }
  ```
- If later included at block=150, add the next leaf as:
  ```rust
  { prev: 100, cur: 150, tx_tree_root: tx_tree_root2 }
  ```

### 2.2 Account Tree

The Account Tree is a Merkle tree whose leaf at index `user_id` stores the root of that user’s the root of the send tree, and some other information.

```rust
struct AccountLeaf {
    index: u32 // The index of the next empty leaf.
    prev: u64 // The value of `send_leaf.cur` of the latest inserted send leaf.
    send_tree_root:  Bytes32 // The current root of the send tree.
}
```

### 2.3 PublicState and its Commitment

```rust
struct PublicState {
    block_number: u64,
    account_tree_root: Bytes32,
    deposit_tree_root: Bytes32,
    prev_public_state_root: Bytes32
}
```

- `deposit_tree_root`: A ZK-friendly Merkle tree commitment to the sequence of `deposits`, anchored to `deposit_root` (and thus to `history_root`).
- `prev_public_state_root: Bytes32` is a Merkle tree commitment to the sequence of prior `PublicState`s (an array ordered by block number) up to the immediately previous one.

## 3. Balance Proof

### 3.1 Public Inputs

```rust
struct BalancePublicInputs {
    user_id: u64, // [aggregator_id, local_id]
    public_state: PublicState, // The public sate that can be used for querying tx/deposits.
    block_r: u64, // The user can incorporate deposits/receiving transfers less than `block_r`
    private_state_commitment: Bytes32 // hash(private_state)
}
```

Update rule of `block_r`:

- `block_r` can be updated to `block_r'` if there is no outgoing transaction from `block_r + 1` to `block_r'`
- `block_r` can be updated to the nearest block number that the user send a transaction, after reducing the corresponding balances from `private_state_commitment`.

### 3.2 Private State

```rust
struct PrivateState {
    asset_tree_root: Bytes32,
    nullifier_tree_root: Bytes32,
    nonce: u32,
    salt: Bytes32
}
```

## 4. Spent Proof (verifying sender’s solvency and nonce)

Prove that even if the target Tx is included on-chain as intended, the sender’s assets remain sufficient and the nonce condition is satisfied.

**Public Inputs**

```rust
struct SpentPublicInputs {
    tx: Tx,
    is_valid: bool,                         // prev_private_state.nonce == tx.nonce
    prev_private_state_commitment: Bytes32,
    new_private_state_commitment: Bytes32
}
```

**Private Inputs**

- `transfers: Vec<Transfer>`
  - The set of transfers sent by the Tx sender. Hard limit of 64.

**Verification (circuit constraints)**

1. Open `prev_private_state_commitment` to obtain `asset_tree`, `nonce`, etc.
2. Commit `transfers` to compute `transfer_tree_root`.
3. Compute `new_asset_root = apply_outgoing_transfers(asset_tree, transfers)` (reflecting per-token debits).
4. Compute `is_valid := (tx.nonce == private_state.nonce)`.
   - Only when `is_valid == true`, update `nonce` to `nonce + 1`.
5. If `is_valid == true`, hash `{asset_root = new_asset_root, nonce = incremented, salt = fresh}` to produce `new_private_state_commitment`
   - If `is_valid == false`, then `new_private_state_commitment = prev_private_state_commitment`.

## 5. Public State Update Witness

A proof that an old `PublicState` is consistent with the latest `public_state_root`.

```rust
struct PublicStateUpdateWitness {
    new: PublicState,
    old: PublicState,
    merkle_proof: MerkleProof
}
```

**Verification `w.verify()`**

1. If `w.new==w.old`, return true.
2. Otherwise, verify `w.merkle_proof.verify(w.old, w.old.block_number, w.new.prev_public_tree_root)`

## 5. AccountWitness

Attests the state of the account

```rust
struct AccountWitness {
    pub account_leaf: AccountLeaf,
    pub account_merkle_proof
    pub send_index: u32,
    pub send_leaf: SendLeaf,
    pub send_merkle_proof: SendMerkleProof
}
```

**Verification:** `w.verify(user_id, account_tree_root)->bool`

1. Verify `w.send_merkle_proof.verify(w.send_index, w.send_leaf, w.account_leaf.send_tree_root)`
2. Verify `w.account_merkle_proof.verify(user_id, w.account_leaf, account_tree_root)`.

## 6. TransferWitness

```rust
struct TransferWitness {
    pub transfer: Transfer,
    pub transfer_salt: Bytes32,
    pub transfer_index: u32,
    pub transfer_merkle_proof: MerkleProof
}
```

**Verification:** `w.verify(user_id, transfer_tree_root)->bool`

1. Verify `w.transfer_merkle_proof.verify(w.transfer_index, w.transfer, transfer_tree_root)`
2. Verify `w.transfer.recipient == hash(user_id, transfer_salt)`

## 7. DepositWitness

```rust
struct DepositWitness {
    pub deposit: Deposit,
    pub deposit_salt: Bytes32,
    pub deposit_index: u32,
    pub deposit_merkle_proof: MerkleProof
}
```

**Verification:** `w.verify(user_id, deposit_tree_root)->bool`

1. Verify `w.transfer_merkle_proof.verify(w.deposit_index, w.deposit, deposit_tree_root)`
2. Verify `w.deposit.recipient == hash(user_id, deposit_salt)`

## 8. Tx Settlement Witness (on-chain inclusion proof)

`TxSettlementWitness` proves that the `tx` of the user give by `user_id` is included in the block.

```rust
struct TxSettlementWitness {
    user_id: u64,
    tx: Tx,
    public_state: PublicState,        // The latest public state
    tx_merkle_proof: MerkleProof,       // Inclusion proof of Tx under send_leaf.tx_tree_root
    account_witness: AccountWitness, // Proves the state of the account.
    spent_proof: ProofWithPublicInputs  // The proof in §4 (including its public inputs)
}
```

**Verification `w.verify() -> bool`**

1. `w.tx_merkle_proof.verify(w.user_id.local(), tx, w.send_leaf.tx_tree_root)`.
2. `w.account_witness.verify(w.user_id, w.public_state.account_tree_root)`
3. Check the public inputs of `w.spent_proof`:
   - `w.spent_proof.tx == w.tx`

**Methods**

1. `w.send_block_number_before_tx()`: returns `w.account_witness.send_leaf.prev`.
2. `w.tx_block_number()`: returns `w.account_witness.send_leaf.cur`.

## 9. Sender Circuit

**Inputs**

- The sender’s `sender_balance_proof` immediately before sending.
- `tx_settlement_witness` of the transaction
- `public_state_update_witness` that updates `sender_balance_proof.public_state` to the `tx_settlement_witness.public_state`

**Outputs**

- `new_balance_proof`

**Constraints**

1. Run `sender_balance_proof.verify()`, `tx_settlement_witness.verify()`, and `public_state_update_witness.verify()`.
2. Assert that `sender_balance_proof.public_state == public_state_update_witness.old`, `tx_settlement_witness.public_state == public_state_update_witness.new`, and `sender_balance_proof.user_id == tx_settlement_witness.user_id`.
3. Require  
   `tx_settlement_witness.send_block_number_before_tx() <= sender_balance_proof.block_r` and `tx_settlement_witness.spent_proof.prev_private_state_commitment == sender_balance_proof.private_state_commitment`.
4. Update`sender_balance_proof.public_state <-   public_state_update_witness.new`.  
   Additionally, only when `tx_settlement_witness.spent_proof.is_valid == true`,  
   update `sender_balance_proof.private_state_commitment <- tx_settlement_witness.spent_proof.new_private_state_commitment` and `sender_balance_proof.block_r <- tx_settlement_witness.tx_block_number()`.

## 10. Receiver Circuit

**Inputs**

- The sender’s `sender_balance_proof` immediately before sending
- `sender_public_state_update_witness` that updates `sender_balance_proof.public_state` to the latest
- The receiver’s `receiver_balance_proof` before receiving
- `receiver_public_state_update_witness` that anchors `receiver_balance_proof.public_state` to the latest
- `new_block_r`
- `account_witness` that proves there is no outgoing tx from `receiver_balance_proof.block_r` to `new_block_r`.
- `tx_settlement_witness`
- `transfer_witness`

**Outputs**

- `new_balance_proof` (receiver)

**Constraints**

1. Verify `sender_balance_proof.verify()`, `sender_public_state_update_witness.verify()`, `receiver_balance_proof.verify()`, `receiver_public_state_update_witness.verify()`, `account_witness.verify(recipient_user_id, public_state)`, `tx_settlement_witness.verify()`, and `transfer_witness.verify(recipient_user_id,tx_settlement_witness.tx.transfer_tree_root)` where `recipient_user_id==receiver_balance_proof.user_id` and `public_state==sender_public_state_update_witness.new==receiver_public_state_update_witness.new==tx_settlement_witness.public_state`.
2. Check `sender_balance_proof.public_state==sender_public_state_update_witness.old` and `receiver_balance_proof.public_state == receiver_public_state_update_witness.public_state`.
3. If `account_witness.account_leaf.prev !=0`, assert that `account_witness.send_leaf.prev <= receiver_balance_proof.block_r` and `new_block_r < account_witness.send_leaf.cur`.
4. Check that `tx_settlement_witness.tx_block_number() <= new_block_r`.
5. Assert that  
   `tx_settlement_witness.spent_proof.prev_private_state_commitment == sender_balance_proof.private_state_commitment`,
   and `spent_proof.is_valid == true`
6. Update `receiver_balance_proof.block_r <- new_block_r`, and incorporate the `transfer` into `receiver_balance_proof.private_state`,  
   update `asset_root` / `nullifier_root`.

## 11. Deposit Receive Circuit

**Private Inputs**

- The receiver’s `receiver_balance_proof` before receiving.
- `public_state_update_witness` that anchors `receiver_balance_proof.public_state_root` to the latest
- `new_block_r`
- `account_witness` that proves there is no outgoing tx from `receiver_balance_proof.block_r` to `new_block_r`.
- `deposit_witness`

**Constraints**

1. Verify `public_state_update_witness.verify()`, `receiver_balance_proof.verify()`, `account_witness.verify(receiver_balance_proof.user_id, public_state.account_root)` and `deposit_witness(receiver_balance_proof.user_id, public_state.deposit_root)` where `public_state==public_state_update_witness.new`.
2. If `account_witness.account_leaf.prev !=0`, assert that `account_witness.send_leaf.prev <= receiver_balance_proof.block_r` and `new_block_r < account_witness.send_leaf.cur`.
3. Check that `deposit_witness.deposit.block_number <= new_block_r`.
4. Update `receiver_balance_proof.block_r <- new_block_r`, and insert the `deposit` to `receiver_balance_proof.private_state`,  
   updating `asset_root` / `nullifier_root` .

## 10. Withdrawal Circuit

A circuit that aggregates multiple withdrawals

**Private Inputs**

- Previous `withdrawal_proof`
- The sender’s `sender_balance_proof` immediately before sending
- `public_state_update_witness` that updates `sender_balance_proof.public_state` to the `withdrawal_proof.public_state`
- `tx_settlement_witness`
- `transfer_witness`

**Outputs**

- `new_withdrawal_proof`

**Constraints**

1. Verify `sender_balance_proof.verify()`, `public_state_update_witness.verify()`, `tx_settlement_witness.verify()`, and `transfer_witness.verify()`.
2. Require  
   `tx_settlement_witness.spent_proof.block_s == sender_balance_proof.block_s` ,
   `tx_settlement_witness.spent_proof.prev_private_state_commitment == sender_balance_proof.private_state_commitment, 
and `spent_proof.is_valid == true`
3. Compute `withdrawal: Withdrawal` from `transfer` where
   ```rust
   struct Withdrawal {
   	recipient: Address
   	token_index: u32
   	amount: U256
   	nullifier: Bytes32 // hash(transfer.transfer_salt, transfer)
   }
   ```
4. Check `transfer.is_withdrawal == true`,  
   compute `withdrawal_hash = hash(withdrawal_proof.withdrawal_hash, withdrawal)`, and  
   produce `new_withdrawal_proof`.

**Onchain Verification**

- **Prover**: Prepare `validity_proof` that has `public_state` and `history_root` as its public inputs. It proves the correctness of `public_state` for given `history_root`.

- **Verifier (contract)**:
  1. Verify `withdrawal_proof` and `validity_proof`.
  2. Verify that `validity_proof.public_state == withdrawal_proof.pulic_state`
  3. Verify that `validity_proof.history_root` is contained by the rollup contract storage.
