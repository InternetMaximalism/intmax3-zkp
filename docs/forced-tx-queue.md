# Forced Transaction Queue

Censorship-resistant mechanism allowing on-chain smart contracts to insert Intmax transactions into blocks without aggregator cooperation.

## Motivation

In a rollup, the aggregator controls which transactions are included in blocks. A malicious or unresponsive aggregator can censor specific users. The Forced TX Queue provides an alternative path: any on-chain contract can register as a "forced tx logic" contract for a user, and anyone can trigger the queue to insert a transaction for that user — bypassing SPHINCS+ signature requirements.

## Architecture

```
                  On-chain (L1)                          Off-chain (ZK Circuits)

 ┌────────────┐   registerForcedTxLogic(userId, logic)
 │ User / DApp│──────────────────────────────────────▶ ┌──────────────────────┐
 └────────────┘                                        │  IntmaxRollup.sol    │
                                                       │                      │
 ┌────────────┐   queueForcedTx(userId)                │  forcedTxLogic[uid]  │
 │  Anyone    │──────────────────────────────────────▶ │  forcedTxAccumulator │
 └────────────┘         │                              │  forcedTxAccAt[block]│
                        │  calls logic.insertIntmaxTx()│                      │
                        ▼  (100k gas limit)            └──────────┬───────────┘
                  ┌─────────────┐                                 │
                  │IForcedTxLogic│                                │
                  │.insertIntmaxTx()│──▶ txHash                  │
                  └─────────────┘                                 │
                                                                  │ postBlockAndSubmit()
                                                     ┌────────────▼────────────┐
                                                     │  Slot Maturation        │
                                                     │  Round R: queued        │
                                                     │  Round R+2: eligible    │
                                                     └────────────┬────────────┘
                                                                  │
                                                     ┌────────────▼────────────┐
                                                     │  ForcedTxChain Circuit  │
                                                     │  (Plonky2 cyclic)       │
                                                     │                         │
                                                     │  For each forced tx:    │
                                                     │  1. Verify hash chain   │
                                                     │  2. Update account tree │
                                                     │     (add SendLeaf)      │
                                                     │  3. NO SPHINCS+ sig     │
                                                     └────────────┬────────────┘
                                                                  │
                                                     ┌────────────▼────────────┐
                                                     │  BlockStep Circuit      │
                                                     │                         │
                                                     │  Processing order:      │
                                                     │  1. UpdateAccountTree   │
                                                     │     (regular block)     │
                                                     │  2. ForcedTxChain       │
                                                     │     (forced txs after)  │
                                                     └────────────────────────┘
```

## Solidity Interface

### IForcedTxLogic

```solidity
/// @title IForcedTxLogic
/// @notice Interface for external contracts that supply forced Intmax transactions.
///         Each user may register one logic contract at ID registration time.
///         When insertIntmaxTx() is called, the contract returns the hash of an
///         Intmax transaction to be forcibly included, or bytes32(0) to signal
///         that no transaction should be inserted.
interface IForcedTxLogic {
    /// @return txHash  The Intmax transaction hash to insert, or bytes32(0) for none.
    function insertIntmaxTx() external returns (bytes32 txHash);
}
```

### IntmaxRollup Contract

**State storage:**

```solidity
mapping(uint64 => address) public forcedTxLogicContracts;
bytes32 public forcedTxAccumulator;

/// Snapshot at each posting round (not per sub-block).
/// Maturation: 2-round delay (~10 minutes).
mapping(uint64 => bytes32) public forcedTxAccumulatorAtRound;

uint64 public postingRound;
uint64 public forcedTxCount;
uint256 internal constant FORCED_TX_GAS_LIMIT = 100_000;
```

**Key functions:**

```solidity
function registerForcedTxLogic(uint64 userId, address logicContract) external;
function queueForcedTx(uint64 userId) external;
```

**Slot maturation in postBlockAndSubmit() (per posting round):**

```solidity
postingRound++;
forcedTxAccumulatorAtRound[currentRound] = forcedTxAccumulator;

// Mature: queued before round R, eligible at round R+2
bytes32 batchForcedTxHashChain = bytes32(0);
if (currentRound >= 3) {
    batchForcedTxHashChain = forcedTxAccumulatorAtRound[currentRound - 2];
}
// Applied to the LAST sub-block in the batch only
```

## ZK Circuit Pipeline

### Data Structure (Rust)

```rust
/// A forced transaction: a transaction inserted via on-chain logic
/// bypassing normal SPHINCS+ signature requirement.
pub struct ForcedTx {
    pub user_id: UserId,   // aggregator_id << 32 | local_id
    pub tx_hash: Bytes32,  // hash of the Intmax transaction
}

/// Hash chain: keccak256(prev_hash || user_id || tx_hash)
/// Matches Solidity accumulator computation exactly.
```

### Circuit Modules

| Module | Purpose |
|--------|---------|
| `forced_tx_chain_pis` | Public inputs: tracks `forced_tx_hash_chain`, `account_tree_root`, `block_number`, counts |
| `forced_tx_step` | Single step: verify hash chain + update account tree (add SendLeaf) |
| `forced_tx_hash_chain_circuit` | Cyclic wrapper (same pattern as deposit chain) |
| `forced_tx_chain_processor` | Orchestrator: builds chain proofs from a list of forced txs |

### Processing in BlockStep

The BlockStep circuit processes forced txs **after** regular account updates:

```
Input: (block data, SPHINCS+ signatures, forced txs)
  │
  ├─▶ UpdateAccountTree  ─── account_tree_root_1
  │   (regular block: verify SPHINCS+ sigs, update send trees)
  │
  └─▶ ForcedTxChain      ─── account_tree_root_2 (final)
      (forced txs: update send trees WITHOUT sig verification)
```

This ordering ensures forced txs see the latest account state from regular processing.

## Design Decisions

1. **No SPHINCS+ signature required** — forced txs are authorized by the on-chain logic contract, not by the user's post-quantum key
2. **2-round maturation delay** — prevents front-running; forced txs queued before round R are eligible at round R+2 (~10 minutes)
3. **Separate `queueForcedTx()` from `postBlockAndSubmit()`** — avoids gas griefing where a malicious logic contract could consume excessive gas during block posting
4. **100k gas limit** on `insertIntmaxTx()` calls — bounds the cost of external contract calls
5. **Processing order: regular → forced** — forced txs see the updated account tree from regular block processing
6. **Deposits and forced txs only at posting-round boundaries** — 5-second fast blocks carry only user txs; deposits and forced txs are processed in the last sub-block of each batch

## Impact on Block Proof Performance

Adding `forced_tx_chain_vd` to the BlockStep circuit increased its `degree_bits` from 14 to 15 (2x gate count), causing ~30-47% slowdown in block proof generation. This is an inherent cost of supporting the forced tx verification path within the block circuit.
