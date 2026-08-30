'use strict';
// Delegate-owned L1 close initiation. The settlement manager authenticates a delegate through a
// fixed-depth Merkle proof of (slot, pkG, recipient); this module derives that proof from the
// already WASM-verified signed snapshot and submits it with the recipient's own EVM key.

const {
  Contract,
  JsonRpcProvider,
  Wallet: EthersWallet,
  ZeroHash,
  getAddress,
  isHexString,
  solidityPackedKeccak256,
} = require('ethers');

const PARTICIPANT_TREE_DEPTH = 10;
const MAX_PARTICIPANTS = 1 << PARTICIPANT_TREE_DEPTH;
const PARTICIPANT_LEAF_DOMAIN = '0x494d5052'; // "IMPR"
const PARTICIPANT_NODE_DOMAIN = '0x494d504e'; // "IMPN"
const MANAGER_PARTICIPANT_ABI = [
  'function participantRoot() view returns (bytes32)',
  'function activeParticipantCount() view returns (uint16)',
  'function requestCloseAsParticipant(uint16 slot, bytes32 pkG, bytes32[10] siblings)',
];

function aliased(object, camel, snake, label) {
  if (!object || typeof object !== 'object') throw new Error(`snapshot missing ${label}`);
  const a = object[camel];
  const b = object[snake];
  if (a !== undefined && b !== undefined && JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`snapshot has conflicting ${camel}/${snake}`);
  }
  const value = a !== undefined ? a : b;
  if (value === undefined) throw new Error(`snapshot missing ${label}`);
  return value;
}

function boundedCount(value, label) {
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_PARTICIPANTS) {
    throw new Error(`invalid ${label} ${value}`);
  }
  return count;
}

function participantLeaf(slot, pkG, recipient) {
  return solidityPackedKeccak256(
    ['bytes4', 'uint16', 'bytes32', 'address'],
    [PARTICIPANT_LEAF_DOMAIN, slot, pkG, recipient],
  );
}

function participantNode(left, right) {
  return solidityPackedKeccak256(
    ['bytes4', 'bytes32', 'bytes32'],
    [PARTICIPANT_NODE_DOMAIN, left, right],
  );
}

function buildParticipantCloseProof(snapshot, configuredSlot, configuredRecipient) {
  const state = snapshot && snapshot.state;
  const record = snapshot && snapshot.record;
  const balance = state && aliased(state, 'balanceState', 'balance_state', 'state.balanceState');
  const slot = boundedCount(configuredSlot, 'delegate slot');
  if (slot >= MAX_PARTICIPANTS) throw new Error(`delegate slot ${slot} exceeds participant tree`);

  const recordMembers = boundedCount(aliased(record, 'memberCount', 'member_count', 'record.memberCount'), 'record memberCount');
  const recordDelegates = boundedCount(aliased(record, 'delegateCount', 'delegate_count', 'record.delegateCount'), 'record delegateCount');
  const balanceMembers = boundedCount(aliased(balance, 'memberCount', 'member_count', 'balanceState.memberCount'), 'balance memberCount');
  const balanceDelegates = boundedCount(aliased(balance, 'delegateCount', 'delegate_count', 'balanceState.delegateCount'), 'balance delegateCount');
  if (recordMembers !== balanceMembers || recordDelegates !== balanceDelegates) {
    throw new Error('signed record/balance participant counts disagree');
  }
  const activeParticipantCount = recordMembers + recordDelegates;
  if (activeParticipantCount < 2 || activeParticipantCount > MAX_PARTICIPANTS) {
    throw new Error(`invalid active participant count ${activeParticipantCount}`);
  }
  if (slot >= activeParticipantCount) {
    throw new Error(`delegate slot ${slot} is outside active participant prefix ${activeParticipantCount}`);
  }

  const pkGs = aliased(record, 'memberPkGs', 'member_pk_gs', 'record.memberPkGs');
  const recipients = aliased(balance, 'recipients', 'recipients', 'balanceState.recipients');
  if (!Array.isArray(pkGs) || pkGs.length < activeParticipantCount) {
    throw new Error('signed record does not carry every active participant pkG');
  }
  if (!Array.isArray(recipients) || recipients.length < activeParticipantCount) {
    throw new Error('signed balance state does not carry every active participant recipient');
  }

  const expectedRecipient = getAddress(configuredRecipient);
  const nodes = Array(MAX_PARTICIPANTS).fill(ZeroHash);
  for (let i = 0; i < activeParticipantCount; i += 1) {
    const pkG = String(pkGs[i]);
    if (!isHexString(pkG, 32) || pkG.toLowerCase() === ZeroHash) {
      throw new Error(`invalid active participant pkG at slot ${i}`);
    }
    const recipient = getAddress(recipients[i]);
    if (recipient === getAddress('0x0000000000000000000000000000000000000000')) {
      throw new Error(`zero active participant recipient at slot ${i}`);
    }
    nodes[i] = participantLeaf(i, pkG, recipient);
  }
  const recipient = getAddress(recipients[slot]);
  if (recipient !== expectedRecipient) {
    throw new Error(`configured recipient ${expectedRecipient} differs from signed slot ${slot} recipient ${recipient}`);
  }

  const pkG = String(pkGs[slot]).toLowerCase();
  const siblings = [];
  let index = slot;
  let width = MAX_PARTICIPANTS;
  while (width > 1) {
    siblings.push(nodes[index ^ 1]);
    for (let i = 0; i < width; i += 2) nodes[i >> 1] = participantNode(nodes[i], nodes[i + 1]);
    index >>= 1;
    width >>= 1;
  }
  if (siblings.length !== PARTICIPANT_TREE_DEPTH) throw new Error('participant proof depth mismatch');
  return {
    slot,
    pkG,
    recipient,
    siblings,
    participantRoot: nodes[0],
    activeParticipantCount,
    stateDigest: state && state.digest,
  };
}

function makeParticipantCloser({ rpcUrl, chainId, recipient, privateKey }) {
  if (!privateKey) return null;
  const provider = new JsonRpcProvider(rpcUrl);
  const signer = new EthersWallet(privateKey, provider);
  const expectedRecipient = getAddress(recipient);
  if (getAddress(signer.address) !== expectedRecipient) {
    throw new Error(
      `INTMAX_DELEGATE_L1_PRIVATE_KEY controls ${signer.address}, not configured recipient ${expectedRecipient}`,
    );
  }
  const expectedChainId = BigInt(chainId);
  return {
    signerAddress: signer.address,
    async requestClose(managerAddress, proof) {
      const network = await provider.getNetwork();
      if (network.chainId !== expectedChainId) {
        throw new Error(`delegate L1 RPC chain id ${network.chainId} differs from configured ${expectedChainId}`);
      }
      const manager = new Contract(getAddress(managerAddress), MANAGER_PARTICIPANT_ABI, signer);
      const [onChainRoot, onChainCount] = await Promise.all([
        manager.participantRoot(),
        manager.activeParticipantCount(),
      ]);
      if (String(onChainRoot).toLowerCase() !== String(proof.participantRoot).toLowerCase()) {
        throw new Error('signed snapshot participant root differs from settlement manager');
      }
      if (Number(onChainCount) !== proof.activeParticipantCount) {
        throw new Error('signed snapshot participant count differs from settlement manager');
      }
      await manager.requestCloseAsParticipant.staticCall(proof.slot, proof.pkG, proof.siblings);
      const tx = await manager.requestCloseAsParticipant(proof.slot, proof.pkG, proof.siblings);
      return { txHash: tx.hash };
    },
    async transactionStatus(txHash) {
      if (!isHexString(txHash, 32)) return 'missing';
      const receipt = await provider.getTransactionReceipt(txHash);
      if (receipt) return Number(receipt.status) === 1 ? 'mined' : 'failed';
      return (await provider.getTransaction(txHash)) ? 'pending' : 'missing';
    },
  };
}

module.exports = {
  PARTICIPANT_TREE_DEPTH,
  MAX_PARTICIPANTS,
  buildParticipantCloseProof,
  makeParticipantCloser,
  participantLeaf,
  participantNode,
};
