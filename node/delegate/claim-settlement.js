'use strict';
// Direct delegate-owned settlement path. The browser/Node WASM produces the public withdrawal
// claim and MLE proof while retaining the Regev secret; this module verifies the exported public
// inputs and sends them to the configured manager with the signed leaf recipient's EVM key.

const {
  Contract,
  JsonRpcProvider,
  Wallet: EthersWallet,
  ZeroHash,
  getAddress,
  isHexString,
} = require('ethers');

const sumcheckComponents = () => [{
  name: 'roundPolys', type: 'tuple[]', components: [{ name: 'evals', type: 'uint256[]' }],
}];
const ext3 = (name) => ({
  name, type: 'tuple', components: [
    { name: 'c0', type: 'uint64' },
    { name: 'c1', type: 'uint64' },
    { name: 'c2', type: 'uint64' },
  ],
});
const sumcheck = (name) => ({ name, type: 'tuple', components: sumcheckComponents() });

const MLE_PROOF_COMPONENTS = [
  { name: 'circuitDigest', type: 'uint256[]' },
  { name: 'whirTranscript', type: 'bytes' },
  { name: 'whirHints', type: 'bytes' },
  { name: 'preprocessedRoot', type: 'bytes32' },
  { name: 'witnessRoot', type: 'bytes32' },
  { name: 'auxCommitmentRoot', type: 'bytes32' },
  { name: 'preprocessedEvalValue', type: 'uint256' },
  { name: 'preprocessedBatchR', type: 'uint256' },
  { name: 'preprocessedIndividualEvals', type: 'uint256[]' },
  { name: 'witnessEvalValue', type: 'uint256' },
  { name: 'witnessBatchR', type: 'uint256' },
  { name: 'witnessIndividualEvals', type: 'uint256[]' },
  { name: 'auxBatchR', type: 'uint256' },
  { name: 'auxConstraintEval', type: 'uint256' },
  { name: 'auxPermEval', type: 'uint256' },
  { name: 'auxEvalValue', type: 'uint256' },
  sumcheck('combinedProof'),
  { name: 'publicInputs', type: 'uint256[]' },
  { name: 'alpha', type: 'uint256' },
  { name: 'beta', type: 'uint256' },
  { name: 'gamma', type: 'uint256' },
  { name: 'mu', type: 'uint256' },
  ext3('preprocessedWhirEval'),
  ext3('witnessWhirEval'),
  ext3('auxWhirEval'),
  { name: 'inverseHelpersCommitmentRoot', type: 'bytes32' },
  { name: 'inverseHelpersBatchR', type: 'uint256' },
  sumcheck('invSumcheckProof'),
  sumcheck('hSumcheckProof'),
  { name: 'lambdaInv', type: 'uint256' },
  { name: 'muInv', type: 'uint256' },
  { name: 'lambdaH', type: 'uint256' },
  { name: 'witnessIndividualEvalsAtRInv', type: 'uint256[]' },
  { name: 'preprocessedIndividualEvalsAtRInv', type: 'uint256[]' },
  { name: 'inverseHelpersEvalsAtRInv', type: 'uint256[]' },
  { name: 'inverseHelpersEvalsAtRH', type: 'uint256[]' },
  { name: 'gSubEvalAtRInv', type: 'uint256' },
  { name: 'witnessEvalValueAtRInv', type: 'uint256' },
  { name: 'preprocessedEvalValueAtRInv', type: 'uint256' },
  ext3('inverseHelpersWhirEvalAtRGate'),
  ext3('preprocessedWhirEvalAtRInv'),
  ext3('witnessWhirEvalAtRInv'),
  ext3('auxWhirEvalAtRInv'),
  ext3('inverseHelpersWhirEvalAtRInv'),
  ext3('preprocessedWhirEvalAtRH'),
  ext3('witnessWhirEvalAtRH'),
  ext3('auxWhirEvalAtRH'),
  ext3('inverseHelpersWhirEvalAtRH'),
  { name: 'extChallenge', type: 'uint256' },
  sumcheck('gateSumcheckProof'),
  { name: 'witnessIndividualEvalsAtRGateV2', type: 'uint256[]' },
  { name: 'preprocessedIndividualEvalsAtRGateV2', type: 'uint256[]' },
  { name: 'witnessEvalValueAtRGateV2', type: 'uint256' },
  { name: 'preprocessedEvalValueAtRGateV2', type: 'uint256' },
  ext3('preprocessedWhirEvalAtRGateV2'),
  ext3('witnessWhirEvalAtRGateV2'),
  ext3('auxWhirEvalAtRGateV2'),
  ext3('inverseHelpersWhirEvalAtRGateV2'),
  { name: 'quotientDegreeFactor', type: 'uint256' },
  { name: 'numSelectors', type: 'uint256' },
  { name: 'numGateConstraints', type: 'uint256' },
  {
    name: 'gates', type: 'tuple[]', components: [
      { name: 'gateId', type: 'uint8' },
      { name: 'selectorIndex', type: 'uint8' },
      { name: 'groupStart', type: 'uint8' },
      { name: 'groupEnd', type: 'uint8' },
      { name: 'gateRowIndex', type: 'uint8' },
      { name: 'numConstraints', type: 'uint16' },
      { name: 'numOrConsts', type: 'uint16' },
      { name: 'param2', type: 'uint16' },
      { name: 'param3', type: 'uint16' },
    ],
  },
  { name: 'publicInputsHash', type: 'uint256[4]' },
];

const CLAIM_COMPONENTS = [
  { name: 'closeIntentDigest', type: 'bytes32' },
  { name: 'memberPkG', type: 'bytes32' },
  { name: 'recipient', type: 'address' },
  { name: 'userAmountDigest', type: 'bytes32' },
  { name: 'amount', type: 'uint64' },
  { name: 'tokenSlot', type: 'uint8' },
  { name: 'tokenIndex', type: 'uint32' },
  { name: 'withdrawalNullifier', type: 'bytes32' },
];

const MANAGER_CLAIM_ABI = [
  { type: 'function', name: 'channelId', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint32' }] },
  { type: 'function', name: 'channelStatus', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'finalizedCloseIntentDigest', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'finalizedChannelStateDigest', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'finalizedBalanceStateH1', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'finalizedTokenCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'finalizedTokenRegistry', stateMutability: 'view', inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint32' }] },
  { type: 'function', name: 'usedWithdrawalNullifiers', stateMutability: 'view', inputs: [{ type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'withdrawalCredits', stateMutability: 'view', inputs: [{ type: 'uint32' }, { type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'receivedChannelFunds', stateMutability: 'view', inputs: [{ type: 'uint32' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'totalCreditedOut', stateMutability: 'view', inputs: [{ type: 'uint32' }], outputs: [{ type: 'uint256' }] },
  {
    type: 'function', name: 'submitWithdrawalClaim', stateMutability: 'nonpayable', outputs: [],
    inputs: [
      { name: 'claim', type: 'tuple', components: CLAIM_COMPONENTS },
      { name: 'proof', type: 'tuple', components: MLE_PROOF_COMPONENTS },
    ],
  },
  { type: 'function', name: 'pullChannelFunds', stateMutability: 'nonpayable', inputs: [], outputs: [{ name: 'pulled', type: 'uint256' }] },
  { type: 'function', name: 'pullChannelTokenFunds', stateMutability: 'nonpayable', inputs: [{ name: 'tokenIndex', type: 'uint32' }], outputs: [{ name: 'pulled', type: 'uint256' }] },
  { type: 'function', name: 'claimWithdrawalCredit', stateMutability: 'nonpayable', inputs: [{ name: 'tokenIndex', type: 'uint32' }], outputs: [{ name: 'amount', type: 'uint256' }] },
];

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function uintString(value, label, max = null) {
  let n;
  try {
    if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw new Error();
    n = BigInt(value);
  } catch (_) {
    throw new Error(`${label} must be a canonical unsigned integer`);
  }
  if (n < 0n || (max !== null && n > max)) throw new Error(`${label} is out of range`);
  return n.toString();
}

function bytes(value, label, length) {
  if (!isHexString(value, length)) throw new Error(`${label} must be ${length == null ? 'hex bytes' : `${length} bytes`}`);
  return String(value).toLowerCase();
}

function normalizeArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((v, i) => uintString(v, `${label}[${i}]`));
}

function normalizeSumcheck(value, label) {
  const proof = requireObject(value, label);
  if (!Array.isArray(proof.roundPolys)) throw new Error(`${label}.roundPolys must be an array`);
  return {
    roundPolys: proof.roundPolys.map((round, i) => ({
      evals: normalizeArray(Array.isArray(round) ? round : round && round.evals, `${label}.roundPolys[${i}]`),
    })),
  };
}

function normalizeExt3(value, label) {
  const v = requireObject(value, label);
  return {
    c0: uintString(v.c0, `${label}.c0`, (1n << 64n) - 1n),
    c1: uintString(v.c1, `${label}.c1`, (1n << 64n) - 1n),
    c2: uintString(v.c2, `${label}.c2`, (1n << 64n) - 1n),
  };
}

const ARRAY_FIELDS = MLE_PROOF_COMPONENTS
  .filter((c) => c.type === 'uint256[]' || c.type === 'uint256[4]')
  .map((c) => c.name);
const SCALAR_FIELDS = MLE_PROOF_COMPONENTS
  .filter((c) => c.type === 'uint256')
  .map((c) => c.name);
const EXT3_FIELDS = MLE_PROOF_COMPONENTS
  .filter((c) => c.type === 'tuple' && c.components && c.components[0] && c.components[0].name === 'c0')
  .map((c) => c.name);

function normalizeMleProof(rawProof) {
  const raw = requireObject(rawProof, 'mleProof');
  const out = {
    whirTranscript: bytes(raw.whirTranscript, 'mleProof.whirTranscript'),
    whirHints: bytes(raw.whirHints, 'mleProof.whirHints'),
    preprocessedRoot: bytes(raw.preprocessedRoot || raw.preprocessedCommitmentRoot, 'mleProof.preprocessedRoot', 32),
    witnessRoot: bytes(raw.witnessRoot || raw.witnessCommitmentRoot, 'mleProof.witnessRoot', 32),
    auxCommitmentRoot: bytes(raw.auxCommitmentRoot, 'mleProof.auxCommitmentRoot', 32),
    inverseHelpersCommitmentRoot: bytes(raw.inverseHelpersCommitmentRoot, 'mleProof.inverseHelpersCommitmentRoot', 32),
    combinedProof: normalizeSumcheck(raw.combinedProof, 'mleProof.combinedProof'),
    invSumcheckProof: normalizeSumcheck(raw.invSumcheckProof, 'mleProof.invSumcheckProof'),
    hSumcheckProof: normalizeSumcheck(raw.hSumcheckProof, 'mleProof.hSumcheckProof'),
    gateSumcheckProof: normalizeSumcheck(raw.gateSumcheckProof, 'mleProof.gateSumcheckProof'),
  };
  for (const field of ARRAY_FIELDS) out[field] = normalizeArray(raw[field], `mleProof.${field}`);
  for (const field of SCALAR_FIELDS) out[field] = uintString(raw[field], `mleProof.${field}`);
  for (const field of EXT3_FIELDS) out[field] = normalizeExt3(raw[field], `mleProof.${field}`);
  if (!Array.isArray(raw.gates)) throw new Error('mleProof.gates must be an array');
  out.gates = raw.gates.map((gate, i) => {
    const g = requireObject(gate, `mleProof.gates[${i}]`);
    return {
      gateId: uintString(g.gateId, `mleProof.gates[${i}].gateId`, 255n),
      selectorIndex: uintString(g.selectorIndex, `mleProof.gates[${i}].selectorIndex`, 255n),
      groupStart: uintString(g.groupStart, `mleProof.gates[${i}].groupStart`, 255n),
      groupEnd: uintString(g.groupEnd, `mleProof.gates[${i}].groupEnd`, 255n),
      gateRowIndex: uintString(g.gateRowIndex, `mleProof.gates[${i}].gateRowIndex`, 255n),
      numConstraints: uintString(g.numConstraints, `mleProof.gates[${i}].numConstraints`, 65535n),
      numOrConsts: uintString(g.numOrConsts, `mleProof.gates[${i}].numOrConsts`, 65535n),
      param2: uintString(g.param2, `mleProof.gates[${i}].param2`, 65535n),
      param3: uintString(g.param3, `mleProof.gates[${i}].param3`, 65535n),
    };
  });
  if (out.publicInputsHash.length !== 4) throw new Error('mleProof.publicInputsHash must have length 4');
  return out;
}

function limbsHex(publicInputs, start, count, label) {
  return `0x${publicInputs.slice(start, start + count).map((value, i) => {
    const limb = BigInt(uintString(value, `${label}[${i}]`, 0xffffffffn));
    return limb.toString(16).padStart(8, '0');
  }).join('')}`;
}

function validateClaimArtifact(artifact, finalized, expectedRecipient, expectedTokenSlot) {
  const body = requireObject(artifact, 'withdrawal claim artifact');
  const c = requireObject(body.claim, 'withdrawal claim artifact.claim');
  const proof = normalizeMleProof(body.mleProof);
  if (proof.publicInputs.length !== 50) throw new Error('withdrawal MLE proof must carry exactly 50 public inputs');
  const pis = proof.publicInputs;
  const amount = ((BigInt(pis[46]) << 32n) | BigInt(pis[47])).toString();
  const claim = {
    closeIntentDigest: bytes(c.closeIntentDigest, 'claim.closeIntentDigest', 32),
    memberPkG: bytes(c.memberPkG, 'claim.memberPkG', 32),
    recipient: getAddress(c.recipient),
    userAmountDigest: bytes(c.userAmountDigest, 'claim.userAmountDigest', 32),
    amount: uintString(c.amount, 'claim.amount', (1n << 64n) - 1n),
    tokenSlot: uintString(c.tokenSlot, 'claim.tokenSlot', 9n),
    tokenIndex: uintString(c.tokenIndex, 'claim.tokenIndex', 0xffffffffn),
    withdrawalNullifier: bytes(c.withdrawalNullifier, 'claim.withdrawalNullifier', 32),
  };
  const context = requireObject(finalized, 'finalized context');
  const comparisons = [
    [limbsHex(pis, 0, 8, 'closeIntentDigest PI'), claim.closeIntentDigest, 'claim close digest'],
    [limbsHex(pis, 9, 8, 'finalBalanceStateH1 PI'), String(context.finalBalanceStateH1).toLowerCase(), 'finalized balance H1'],
    [limbsHex(pis, 17, 8, 'memberPkG PI'), claim.memberPkG, 'member pkG'],
    [limbsHex(pis, 25, 5, 'recipient PI'), claim.recipient.toLowerCase(), 'recipient'],
    [limbsHex(pis, 30, 8, 'userAmountDigest PI'), claim.userAmountDigest, 'amount digest'],
    [limbsHex(pis, 38, 8, 'withdrawalNullifier PI'), claim.withdrawalNullifier, 'nullifier'],
    [amount, claim.amount, 'amount'],
    [String(pis[48]), claim.tokenSlot, 'token slot'],
    [String(pis[49]), claim.tokenIndex, 'token index'],
    [String(pis[8]), String(context.channelId), 'channel id'],
    [claim.closeIntentDigest, String(context.closeIntentDigest).toLowerCase(), 'finalized close digest'],
    [claim.recipient.toLowerCase(), getAddress(expectedRecipient).toLowerCase(), 'configured recipient'],
    [claim.tokenSlot, String(expectedTokenSlot), 'requested token slot'],
  ];
  for (const [got, want, label] of comparisons) {
    if (got !== want) throw new Error(`withdrawal artifact ${label} mismatch`);
  }
  const slot = Number(claim.tokenSlot);
  if (slot >= Number(context.tokenCount) || String(context.tokenRegistry[slot]) !== claim.tokenIndex) {
    throw new Error('withdrawal artifact token is not the finalized registry entry');
  }
  return { claim, proof };
}

function makeClaimSettlement({ rpcUrl, chainId, recipient, privateKey, confirmations = 1 }) {
  if (!privateKey) return null;
  const txConfirmations = Number(confirmations);
  if (!Number.isSafeInteger(txConfirmations) || txConfirmations < 1 || txConfirmations > 64) {
    throw new Error('l1TxConfirmations must be an integer in 1..64');
  }
  const provider = new JsonRpcProvider(rpcUrl);
  const signer = new EthersWallet(privateKey, provider);
  const expectedRecipient = getAddress(recipient);
  if (getAddress(signer.address) !== expectedRecipient) {
    throw new Error(`INTMAX_DELEGATE_L1_PRIVATE_KEY controls ${signer.address}, not configured recipient ${expectedRecipient}`);
  }
  const expectedChainId = BigInt(chainId);

  async function checkedManager(managerAddress) {
    const network = await provider.getNetwork();
    if (network.chainId !== expectedChainId) {
      throw new Error(`delegate L1 RPC chain id ${network.chainId} differs from configured ${expectedChainId}`);
    }
    return new Contract(getAddress(managerAddress), MANAGER_CLAIM_ABI, signer);
  }

  return {
    signerAddress: signer.address,
    async readFinalizedContext(managerAddress, blockTag = 'finalized') {
      const manager = await checkedManager(managerAddress);
      const overrides = { blockTag };
      const [channelId, status, closeIntentDigest, finalChannelStateDigest, finalBalanceStateH1, tokenCountRaw] = await Promise.all([
        manager.channelId(overrides),
        manager.channelStatus(overrides),
        manager.finalizedCloseIntentDigest(overrides),
        manager.finalizedChannelStateDigest(overrides),
        manager.finalizedBalanceStateH1(overrides),
        manager.finalizedTokenCount(overrides),
      ]);
      if (Number(status) !== 2) throw new Error('settlement manager is not Closed at the authenticated block');
      if (String(closeIntentDigest).toLowerCase() === ZeroHash
          || String(finalChannelStateDigest).toLowerCase() === ZeroHash
          || String(finalBalanceStateH1).toLowerCase() === ZeroHash) {
        throw new Error('settlement manager finalized close context is incomplete');
      }
      const tokenCount = Number(tokenCountRaw);
      if (!Number.isSafeInteger(tokenCount) || tokenCount < 1 || tokenCount > 10) {
        throw new Error(`invalid finalized token count ${tokenCountRaw}`);
      }
      const tokenRegistry = await Promise.all(
        Array.from({ length: tokenCount }, (_, i) => manager.finalizedTokenRegistry(i, overrides))
      );
      const normalizedRegistry = tokenRegistry.map((v) => Number(v));
      if (new Set(normalizedRegistry).size !== normalizedRegistry.length) {
        throw new Error('finalized token registry contains a duplicate base-token index');
      }
      return {
        channelId: Number(channelId),
        closeIntentDigest: String(closeIntentDigest).toLowerCase(),
        finalChannelStateDigest: String(finalChannelStateDigest).toLowerCase(),
        finalBalanceStateH1: String(finalBalanceStateH1).toLowerCase(),
        tokenCount,
        tokenRegistry: normalizedRegistry,
      };
    },

    async submitClaim(managerAddress, artifact, finalized, tokenSlot, onBroadcast = null) {
      const manager = await checkedManager(managerAddress);
      const { claim, proof } = validateClaimArtifact(artifact, finalized, expectedRecipient, tokenSlot);
      if (await manager.usedWithdrawalNullifiers(claim.withdrawalNullifier)) {
        return { alreadySubmitted: true, tokenIndex: Number(claim.tokenIndex), nullifier: claim.withdrawalNullifier };
      }
      await manager.submitWithdrawalClaim.staticCall(claim, proof);
      const tx = await manager.submitWithdrawalClaim(claim, proof);
      // Persist at the caller before waiting. A process death after broadcast but before a receipt
      // must resume from this hash instead of blindly spending the next account nonce.
      if (typeof onBroadcast === 'function') onBroadcast(tx.hash);
      const receipt = await tx.wait(txConfirmations);
      if (!receipt || Number(receipt.status) !== 1) throw new Error(`withdrawal claim transaction ${tx.hash} failed`);
      return { txHash: tx.hash, tokenIndex: Number(claim.tokenIndex), nullifier: claim.withdrawalNullifier };
    },

    async claimStatus(managerAddress, nullifier, txHash = null) {
      const manager = await checkedManager(managerAddress);
      if (await manager.usedWithdrawalNullifiers(bytes(nullifier, 'withdrawal nullifier', 32))) {
        return 'accepted';
      }
      if (!txHash) return 'missing';
      const receipt = await provider.getTransactionReceipt(txHash);
      if (receipt) return Number(receipt.status) === 1 ? 'mined' : 'failed';
      return (await provider.getTransaction(txHash)) ? 'pending' : 'missing';
    },

    async pullCredit(managerAddress, tokenIndex, onBroadcast = null) {
      const manager = await checkedManager(managerAddress);
      const index = Number(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
      const credit = await manager.withdrawalCredits(index, expectedRecipient);
      if (credit === 0n) return { noCredit: true, tokenIndex: index };

      // Once a live withdrawal producer has created this manager's rollup backing, both fund-pull
      // functions are permissionless and always pay this manager. They do NOT create
      // pendingWithdrawals[manager] / pendingTokenWithdrawals themselves: if production backing is
      // absent, the zero pull or cap check below fails closed and recovery remains retryable.
      const [receivedBefore, paidBefore] = await Promise.all([
        manager.receivedChannelFunds(index),
        manager.totalCreditedOut(index),
      ]);
      if (paidBefore > receivedBefore) throw new Error('manager per-token payout accounting is inconsistent');
      if (receivedBefore - paidBefore < credit) {
        const fundTx = index === 0
          ? await manager.pullChannelFunds()
          : await manager.pullChannelTokenFunds(index);
        if (typeof onBroadcast === 'function') {
          onBroadcast({ phase: 'channel-funds', txHash: fundTx.hash });
        }
        const fundReceipt = await fundTx.wait(txConfirmations);
        if (!fundReceipt || Number(fundReceipt.status) !== 1) {
          throw new Error(`channel fund pull transaction ${fundTx.hash} failed`);
        }
        const [receivedAfter, paidAfter] = await Promise.all([
          manager.receivedChannelFunds(index),
          manager.totalCreditedOut(index),
        ]);
        if (paidAfter > receivedAfter || receivedAfter - paidAfter < credit) {
          throw new Error('manager has not received enough production withdrawal backing for this payout');
        }
      }
      await manager['claimWithdrawalCredit(uint32)'].staticCall(index);
      const tx = await manager['claimWithdrawalCredit(uint32)'](index);
      if (typeof onBroadcast === 'function') {
        onBroadcast({ phase: 'credit', txHash: tx.hash, amount: credit.toString() });
      }
      const receipt = await tx.wait(txConfirmations);
      if (!receipt || Number(receipt.status) !== 1) throw new Error(`withdrawal credit transaction ${tx.hash} failed`);
      return { txHash: tx.hash, tokenIndex: index, amount: credit.toString() };
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
  CLAIM_COMPONENTS,
  MANAGER_CLAIM_ABI,
  MLE_PROOF_COMPONENTS,
  makeClaimSettlement,
  normalizeMleProof,
  validateClaimArtifact,
};
