## 0. Types and Terminology

This specification uses the following type aliases:

```rust
type Bytes = Vec<u8>;
type Bytes32 = [u8; 32];
type U256 = [u8; 32];
type Address = [u8; 20];
```

**Merkle proofs**

```rust
struct MerkleProof {
    siblings: Vec<Bytes32>
}
```

`merkle_proof.verify(index, leaf, root) -> bool` returns `true` if the leaf at position `index` (counting from the left, zero-based) is included in the Merkle tree with root `root`.

## 1. Core Data Structures

### 1.1 Transfer

```rust
struct Transfer {
    recipient: Bytes32,   // withdrawal: Ethereum address padded with left-aligned zeros
                          // non-withdrawal: hash(receiver_id, transfer_salt)
    token_index: u32,
    amount: U256,
    aux_data: Bytes32     // hash(memo) or a random value when no memo is supplied
}
```

- `recipient` encodes either a withdrawal address or the hashed receiver identifier.
- `aux_data` typically commits to a memo; if unused, supply a random nonce-sized value.

### 1.2 Deposit

```rust
struct Deposit {
    depositor: Address,
    recipient: Bytes32,     // hash(receiver_id, transfer_salt)
    token_index: u32,
    amount: U256,
    block_number: u64,
    aux_data: Bytes32
}
```

`aux_data = keccak256(timestamp, is_eligible)` where `is_eligible` flags mining eligibility and `timestamp` is also used for mining randomness.

### 1.3 Transaction (Tx)

```rust
struct Tx {
    transfer_merkle_root: Bytes32,
    nonce: u32
}
```

- `transfer_merkle_root` commits to the set of `Transfer` objects contained in the transaction.
- Each transaction contains at most 64 transfers (Merkle tree height 6).

### 1.4 Block

```rust
struct Block {
    aggregator_id: u32,
    user_ids: [u32; MAX_USER_IDS],
    tx_tree_root: Bytes32,
    deposit_hash_chain: Bytes32
}
```

On-chain acceptance rules:

- `user_ids` is a fixed-length array.
- `user_ids` contains no duplicate entries.
- `aggregator_ids[msg.sender] == aggregator_id`.

### 1.5 History and Deposit hash chains

History roots update according to:

```
deposit_hash_chain <- hash(deposit_hash_chain, deposit)
history_hash_chain <- hash(history_hash_chain, block)
```

`deposit_hash_chain` and `history_hash_chain` are tracked on-chain, providing inclusions for deposits and block history.

## 2. Public State

### 2.1 Send Tree

The send tree is a Merkle tree that stores the block numbers and transaction tree roots where a particular user’s transactions were included.

```rust
struct SendLeaf {
    prev: u64,        // block number where the user's previous Tx was included (0 if none)
    cur: u64,         // latest block number that included the user's Tx
    tx_tree_root: Bytes32   // transaction Merkle root referenced in that block
}
```

Examples:

```rust
// First inclusion at block 100
{ prev: 0, cur: 100, tx_tree_root: tx_tree_root1 }

// Next inclusion at block 150
{ prev: 100, cur: 150, tx_tree_root: tx_tree_root2 }
```

### 2.2 Account Tree

The account tree is a Merkle tree whose leaf at index `user_id` stores the root of that user’s send tree and related metadata.

```rust
struct AccountLeaf {
    index: u32,         // index of the next empty send leaf
    prev: u64,          // value of send_leaf.cur for the latest inserted send leaf
    send_tree_root: Bytes32
}
```

### 2.3 Public State Structure

```rust
struct PublicState {
    block_number: u64,
    account_tree_root: Bytes32,
    deposit_tree_root: Bytes32,
    prev_public_state_root: Bytes32
}
```

- `deposit_tree_root` is a ZK-friendly Merkle commitment to the sequence of deposits, anchored to `deposit_root` (and therefore to `history_root`).
- `prev_public_state_root` is the root of a Merkle commitment to the sequence of prior `PublicState` snapshots up to the immediately previous block.

## 3. Balance Proof

### 3.1 Public Inputs

```rust
struct BalancePublicInputs {
    user_id: u64,                   // [aggregator_id, local_id]
    public_state: PublicState,      // public state used to query transactions and deposits
    block_r: u64,                   // user may incorporate deposits/transfers with block <= block_r
    private_state_commitment: Bytes32   // hash(private_state)
}
```

`block_r` can be updated to `block_r'` when:

- no outgoing transaction exists for the user in blocks `(block_r, block_r']`, and
- the corresponding private balances are debited before advancing `block_r` to the next block `block_r'` where the user sent a transaction.

### 3.2 Private State

```rust
struct PrivateState {
    asset_tree_root: Bytes32,
    nullifier_tree_root: Bytes32,
    nonce: u32,
    salt: Bytes32
}
```

## 4. Spent Proof (Sender Solvency and Nonce)

The spent proof demonstrates that, even after the transaction is processed on-chain, the sender remains solvent and the nonce is respected.

**Public Inputs**

```rust
struct SpentPublicInputs {
    tx: Tx,
    is_valid: bool,                        // prev_private_state.nonce == tx.nonce
    prev_private_state_commitment: Bytes32,
    new_private_state_commitment: Bytes32
}
```

**Private Inputs**

- `transfers: Vec<Transfer>` — the transfers emitted by the transaction; limited to 64 entries.

**Verification steps**

1. Open `prev_private_state_commitment` to obtain the asset tree, nonce, and other private state elements.
2. Commit to `transfers` to compute `transfer_merkle_root`.
3. Compute `new_asset_root = apply_outgoing_transfers(asset_tree, transfers)` to debit per-token balances.
4. Set `is_valid := (tx.nonce == private_state.nonce)`. When `is_valid` holds, increment the nonce by one.
5. Hash `{asset_root = new_asset_root, nonce = incremented, salt = fresh}` to derive `new_private_state_commitment`.

## 5. Witness Objects

### 5.1 PublicStateUpdateWitness

A witness that links an older `PublicState` to the latest `public_state_root`.

```rust
struct PublicStateUpdateWitness {
    new: PublicState,
    old: PublicState,
    merkle_proof: MerkleProof
}
```

`w.verify()`:

1. If `w.new == w.old`, return `true`.
2. Otherwise, verify `w.merkle_proof.verify(w.old.block_number, w.old, w.new.prev_public_state_root)`.

### 5.2 AccountWitness

Attests to the state of a specific account.

```rust
struct AccountWitness {
    account_leaf: AccountLeaf,
    account_merkle_proof: MerkleProof,
    send_index: u32,
    send_leaf: SendLeaf,
    send_merkle_proof: MerkleProof
}
```

`w.verify(user_id, account_tree_root) -> bool`:

1. Verify `w.send_merkle_proof.verify(w.send_index, w.send_leaf, w.account_leaf.send_tree_root)`.
2. Verify `w.account_merkle_proof.verify(user_id, w.account_leaf, account_tree_root)`.

### 5.3 TransferWitness

```rust
struct TransferWitness {
    transfer: Transfer,
    transfer_index: u32,
    transfer_merkle_proof: MerkleProof
}
```

`w.verify(user_id, transfer_merkle_root) -> bool`:

1. Verify `w.transfer_merkle_proof.verify(w.transfer_index, w.transfer, transfer_merkle_root)`.

### 5.4 DepositWitness

```rust
struct DepositWitness {
    deposit: Deposit,
    deposit_salt: Bytes32,
    deposit_index: u64,
    deposit_merkle_proof: MerkleProof
}
```

`w.verify(user_id, deposit_tree_root) -> bool`:

1. Verify `w.deposit_merkle_proof.verify(w.deposit_index, w.deposit, deposit_tree_root)`.
2. Verify `w.deposit.recipient == hash(user_id, w.deposit_salt)`.

### 5.5 TxSettlementWitness (On-chain Inclusion)

Proves that the `tx` associated with `user_id` was included in a block.

```rust
struct TxSettlementWitness {
    user_id: u64,
    tx: Tx,
    public_state: PublicState,          // latest public state
    tx_merkle_proof: MerkleProof,       // inclusion under send_leaf.tx_tree_root
    account_witness: AccountWitness,    // attests to the account state
    spent_proof: ProofWithPublicInputs  // proof described in §4
}
```

`w.verify() -> bool`:

1. Verify `w.tx_merkle_proof.verify(w.account_witness.send_index, w.tx, w.account_witness.send_leaf.tx_tree_root)`.
2. Verify `w.account_witness.verify(w.user_id, w.public_state.account_tree_root)`.
3. Check that `w.spent_proof.tx == w.tx`.

Helper methods:

- `w.send_block_number_before_tx()` returns `w.account_witness.send_leaf.prev`.
- `w.tx_block_number()` returns `w.account_witness.send_leaf.cur`.

## 6. Circuits

### 6.1 Send Tx Circuit

**Inputs**

- The sender’s `sender_balance_proof` immediately before sending.
- `tx_settlement_witness` for the transaction.
- `public_state_update_witness` that updates `sender_balance_proof.public_state` to `tx_settlement_witness.public_state`.

**Outputs**

- `new_balance_proof`.

**Constraints**

1. Run `sender_balance_proof.verify()`, `tx_settlement_witness.verify()`, and `public_state_update_witness.verify()`.
2. Assert:
   - `sender_balance_proof.public_state == public_state_update_witness.old`,
   - `tx_settlement_witness.public_state == public_state_update_witness.new`, and
   - `sender_balance_proof.user_id == tx_settlement_witness.user_id`.
3. Require:
   - `tx_settlement_witness.send_block_number_before_tx() <= sender_balance_proof.block_r`, and
   - `tx_settlement_witness.spent_proof.prev_private_state_commitment == sender_balance_proof.private_state_commitment`.
4. Update `sender_balance_proof.public_state <- public_state_update_witness.new`. When `tx_settlement_witness.spent_proof.is_valid == true`, also set `sender_balance_proof.private_state_commitment <- tx_settlement_witness.spent_proof.new_private_state_commitment` and `sender_balance_proof.block_r <- tx_settlement_witness.tx_block_number()`.

### 6.2 Receive Transfer Circuit

**Inputs**

- The sender’s `sender_balance_proof` immediately before sending.
- `sender_public_state_update_witness` that updates `sender_balance_proof.public_state` to the latest state.
- The receiver’s `receiver_balance_proof` before receiving.
- `receiver_public_state_update_witness` anchoring `receiver_balance_proof.public_state` to the latest state.
- `new_block_r`.
- `account_witness` proving there is no outgoing transaction from `receiver_balance_proof.block_r` to `new_block_r`.
- `tx_settlement_witness`.
- `transfer_witness`.

**Outputs**

- `new_balance_proof` for the receiver.

**Constraints**

1. Let `public_state := sender_public_state_update_witness.new`. Verify `sender_balance_proof.verify()`, `sender_public_state_update_witness.verify()`, `receiver_balance_proof.verify()`, `receiver_public_state_update_witness.verify()`, `account_witness.verify(recipient_user_id, public_state.account_tree_root)`, `tx_settlement_witness.verify()`, and `transfer_witness.verify(recipient_user_id, tx_settlement_witness.tx.transfer_merkle_root)` where `recipient_user_id == receiver_balance_proof.user_id` and `public_state == receiver_public_state_update_witness.new == tx_settlement_witness.public_state`.
2. Check `sender_balance_proof.public_state == sender_public_state_update_witness.old` and `receiver_balance_proof.public_state == receiver_public_state_update_witness.old`.
3. Check `receiver_balance_proof.block_r <= new_block_r <= public_state.block_number`. Additionally, if `account_witness.account_leaf.prev != 0`, assert `account_witness.send_leaf.prev <= receiver_balance_proof.block_r` and `new_block_r < account_witness.send_leaf.cur`.
4. Check `tx_settlement_witness.tx_block_number() <= new_block_r`.
5. Assert `tx_settlement_witness.spent_proof.prev_private_state_commitment == sender_balance_proof.private_state_commitment` and `tx_settlement_witness.spent_proof.is_valid == true`.
6. Update `receiver_balance_proof.block_r <- new_block_r` and incorporate the transfer into `receiver_balance_proof.private_state`, updating `asset_root` and `nullifier_root`.

### 6.3 Receive Deposit Circuit

**Private Inputs**

- The receiver’s `receiver_balance_proof` before receiving.
- `public_state_update_witness` anchoring `receiver_balance_proof.public_state` to the latest state.
- `new_block_r`.
- `account_witness` proving there is no outgoing transaction from `receiver_balance_proof.block_r` to `new_block_r`.
- `deposit_witness`.

**Constraints**

1. Let `public_state := public_state_update_witness.new`. Verify `public_state_update_witness.verify()`, `receiver_balance_proof.verify()`, `account_witness.verify(receiver_balance_proof.user_id, public_state.account_tree_root)`, and `deposit_witness.verify(receiver_balance_proof.user_id, public_state.deposit_tree_root)`.
3. Check `receiver_balance_proof.block_r <= new_block_r <= public_state.block_number`. Additionally, if `account_witness.account_leaf.prev != 0`, assert `account_witness.send_leaf.prev <= receiver_balance_proof.block_r` and `new_block_r < account_witness.send_leaf.cur`.
3. Check `deposit_witness.deposit.block_number <= new_block_r`.
4. Update `receiver_balance_proof.block_r <- new_block_r` and insert the deposit into `receiver_balance_proof.private_state`, updating `asset_root` and `nullifier_root`.

### 6.4 Withdrawal Circuit

Aggregates multiple withdrawals.

**Private Inputs**

- Previous `withdrawal_proof`.
- The sender’s `sender_balance_proof` immediately before sending.
- `public_state_update_witness` that updates `sender_balance_proof.public_state` to `withdrawal_proof.public_state`.
- `tx_settlement_witness`.
- `transfer_witness`.

**Outputs**

- `new_withdrawal_proof`.

**Constraints**

1. Verify `sender_balance_proof.verify()`, `public_state_update_witness.verify()`, `tx_settlement_witness.verify()`, and `transfer_witness.verify()`.
2. Require `tx_settlement_witness.spent_proof.prev_private_state_commitment == sender_balance_proof.private_state_commitment` and `tx_settlement_witness.spent_proof.is_valid == true`.
3. Derive `withdrawal` from `transfer`:

```rust
struct Withdrawal {
    recipient: Address,
    token_index: u32,
    amount: U256,
    nullifier: Bytes32    // hash(transfer_witness.transfer_salt, transfer)
}
```

4. Check `transfer.is_withdrawal == true`, compute `withdrawal_hash = hash(withdrawal_proof.withdrawal_hash, withdrawal)`, and produce `new_withdrawal_proof`.

#### On-chain verification

- **Prover**: Prepare `validity_proof` with `public_state` and `history_root` as its public inputs, proving the correctness of `public_state` for the given `history_root`.
- **Verifier (contract)**:
  1. Verify `withdrawal_proof` and `validity_proof`.
  2. Check `validity_proof.public_state == withdrawal_proof.public_state`.
  3. Ensure `validity_proof.history_root` is contained in the rollup contract storage.
