'use strict';
// Direct delegate-owned settlement path. The browser/Node WASM produces the public withdrawal
// claim and MLE proof while retaining the Regev secret; this module verifies the exported public
// inputs and sends them to the configured manager with the signed leaf recipient's EVM key.

const {
  Contract,
  Interface,
  JsonRpcProvider,
  Wallet: EthersWallet,
  ZeroHash,
  getAddress,
  isHexString,
} = require('ethers');
const { SignedTransactionOutbox } = require('./signed-transaction-outbox');

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

const MLE_PROOF_V1_COMPONENTS = [
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
const MLE_PROOF_V2_REMOVED_FIELDS = new Set([
  'preprocessedWhirEval',
  'witnessWhirEval',
  'auxWhirEval',
  'lambdaH',
  'inverseHelpersWhirEvalAtRGate',
  'preprocessedWhirEvalAtRInv',
  'witnessWhirEvalAtRInv',
  'auxWhirEvalAtRInv',
  'inverseHelpersWhirEvalAtRInv',
  'preprocessedWhirEvalAtRH',
  'witnessWhirEvalAtRH',
  'auxWhirEvalAtRH',
  'inverseHelpersWhirEvalAtRH',
  'preprocessedWhirEvalAtRGateV2',
  'witnessWhirEvalAtRGateV2',
  'auxWhirEvalAtRGateV2',
  'inverseHelpersWhirEvalAtRGateV2',
]);
const MLE_PROOF_V2_COMPONENTS = [
  { name: 'protocolVersion', type: 'uint256' },
  { name: 'constituentWidth', type: 'uint256' },
  ...MLE_PROOF_V1_COMPONENTS.filter(({ name }) => !MLE_PROOF_V2_REMOVED_FIELDS.has(name)),
];
// The checked-in submodule pin uses the v1 tuple. Keep this alias for callers/tests that inspect
// that release ABI; v2 is selected only by an artifact carrying both explicit schema fields.
const MLE_PROOF_COMPONENTS = MLE_PROOF_V1_COMPONENTS;

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

const submitWithdrawalClaimFragment = (components) => ({
  type: 'function', name: 'submitWithdrawalClaim', stateMutability: 'nonpayable', outputs: [],
  inputs: [
    { name: 'claim', type: 'tuple', components: CLAIM_COMPONENTS },
    { name: 'proof', type: 'tuple', components },
  ],
});
const SUBMIT_WITHDRAWAL_CLAIM_V1_FRAGMENT = submitWithdrawalClaimFragment(MLE_PROOF_V1_COMPONENTS);
const SUBMIT_WITHDRAWAL_CLAIM_V2_FRAGMENT = submitWithdrawalClaimFragment(MLE_PROOF_V2_COMPONENTS);

const MANAGER_CLAIM_ABI = [
  {
    type: 'event', name: 'WithdrawalClaimAccepted', anonymous: false,
    inputs: [
      { name: 'closeIntentDigest', type: 'bytes32', indexed: true },
      { name: 'withdrawalNullifier', type: 'bytes32', indexed: true },
      { name: 'memberPkG', type: 'bytes32', indexed: true },
      { name: 'recipient', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'tokenIndex', type: 'uint32', indexed: false },
    ],
  },
  {
    type: 'event', name: 'ChannelFundsPulled', anonymous: false,
    inputs: [
      { name: 'tokenIndex', type: 'uint32', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'totalReceived', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'event', name: 'WithdrawalClaimed', anonymous: false,
    inputs: [
      { name: 'withdrawalNullifier', type: 'bytes32', indexed: true },
      { name: 'recipient', type: 'address', indexed: true },
      { name: 'tokenIndex', type: 'uint32', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
    ],
  },
  { type: 'function', name: 'channelId', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint32' }] },
  { type: 'function', name: 'channelStatus', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'finalizedCloseIntentDigest', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'finalizedChannelStateDigest', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'finalizedBalanceStateH1', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'finalizedTokenCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'finalizedTokenRegistry', stateMutability: 'view', inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint32' }] },
  { type: 'function', name: 'usedWithdrawalNullifiers', stateMutability: 'view', inputs: [{ type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  {
    type: 'function', name: 'withdrawalPayouts', stateMutability: 'view',
    inputs: [{ name: 'withdrawalNullifier', type: 'bytes32' }],
    outputs: [
      { name: 'recipient', type: 'address' },
      { name: 'tokenIndex', type: 'uint32' },
      { name: 'amount', type: 'uint256' },
    ],
  },
  { type: 'function', name: 'withdrawalCredits', stateMutability: 'view', inputs: [{ type: 'uint32' }, { type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'receivedChannelFunds', stateMutability: 'view', inputs: [{ type: 'uint32' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'finalizedChannelFundAmount', stateMutability: 'view', inputs: [{ type: 'uint32' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'totalCreditedOut', stateMutability: 'view', inputs: [{ type: 'uint32' }], outputs: [{ type: 'uint256' }] },
  SUBMIT_WITHDRAWAL_CLAIM_V1_FRAGMENT,
  SUBMIT_WITHDRAWAL_CLAIM_V2_FRAGMENT,
  { type: 'function', name: 'pullChannelFunds', stateMutability: 'nonpayable', inputs: [], outputs: [{ name: 'pulled', type: 'uint256' }] },
  { type: 'function', name: 'pullChannelTokenFunds', stateMutability: 'nonpayable', inputs: [{ name: 'tokenIndex', type: 'uint32' }], outputs: [{ name: 'pulled', type: 'uint256' }] },
  { type: 'function', name: 'claimWithdrawalCredit', stateMutability: 'nonpayable', inputs: [{ name: 'withdrawalNullifier', type: 'bytes32' }], outputs: [{ name: 'amount', type: 'uint256' }] },
];

const SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR = new Interface([SUBMIT_WITHDRAWAL_CLAIM_V1_FRAGMENT])
  .getFunction('submitWithdrawalClaim').selector;
const SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR = new Interface([SUBMIT_WITHDRAWAL_CLAIM_V2_FRAGMENT])
  .getFunction('submitWithdrawalClaim').selector;
if (SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR !== '0x70f89118'
    || SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR !== '0x6d3e503a') {
  throw new Error('withdrawal claim ABI selector drifted without an explicit protocol migration');
}

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

function mleProofAbiVersion(rawProof) {
  const raw = requireObject(rawProof, 'mleProof');
  const hasProtocolVersion = Object.prototype.hasOwnProperty.call(raw, 'protocolVersion');
  const hasConstituentWidth = Object.prototype.hasOwnProperty.call(raw, 'constituentWidth');
  if (hasProtocolVersion !== hasConstituentWidth) {
    throw new Error('mleProof must carry both protocolVersion and constituentWidth or neither');
  }
  return hasProtocolVersion ? 2 : 1;
}

function normalizeMleProof(rawProof, { allowLegacyMle = true } = {}) {
  const raw = requireObject(rawProof, 'mleProof');
  const abiVersion = mleProofAbiVersion(raw);
  if (abiVersion === 1 && !allowLegacyMle) {
    throw new Error('legacy MLE proof ABI is disabled outside the local development release gate');
  }
  const components = abiVersion === 2 ? MLE_PROOF_V2_COMPONENTS : MLE_PROOF_V1_COMPONENTS;
  const arrayFields = components
    .filter((c) => c.type === 'uint256[]' || c.type === 'uint256[4]')
    .map((c) => c.name);
  const scalarFields = components.filter((c) => c.type === 'uint256').map((c) => c.name);
  const ext3Fields = components
    .filter((c) => c.type === 'tuple' && c.components && c.components[0] && c.components[0].name === 'c0')
    .map((c) => c.name);
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
  for (const field of arrayFields) out[field] = normalizeArray(raw[field], `mleProof.${field}`);
  for (const field of scalarFields) out[field] = uintString(raw[field], `mleProof.${field}`);
  for (const field of ext3Fields) out[field] = normalizeExt3(raw[field], `mleProof.${field}`);
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
  if (abiVersion === 2) {
    if (out.protocolVersion !== '1') {
      throw new Error('mleProof.protocolVersion must be the supported PCS protocol version 1');
    }
    const constituentWidth = Math.max(
      out.preprocessedIndividualEvals.length,
      out.witnessIndividualEvals.length,
      out.inverseHelpersEvalsAtRInv.length,
      out.inverseHelpersEvalsAtRH.length,
      out.preprocessedIndividualEvalsAtRGateV2.length,
      out.witnessIndividualEvalsAtRGateV2.length,
      2,
    );
    if (BigInt(out.constituentWidth) !== BigInt(constituentWidth)) {
      throw new Error(`mleProof.constituentWidth must equal its canonical constituent vector width ${constituentWidth}`);
    }
  }
  if (out.publicInputsHash.length !== 4) throw new Error('mleProof.publicInputsHash must have length 4');
  return out;
}

function limbsHex(publicInputs, start, count, label) {
  return `0x${publicInputs.slice(start, start + count).map((value, i) => {
    const limb = BigInt(uintString(value, `${label}[${i}]`, 0xffffffffn));
    return limb.toString(16).padStart(8, '0');
  }).join('')}`;
}

function validateClaimArtifact(
  artifact,
  finalized,
  expectedRecipient,
  expectedTokenSlot,
  { allowLegacyMle = false } = {},
) {
  const body = requireObject(artifact, 'withdrawal claim artifact');
  const c = requireObject(body.claim, 'withdrawal claim artifact.claim');
  const mleAbiVersion = mleProofAbiVersion(body.mleProof);
  const proof = normalizeMleProof(body.mleProof, { allowLegacyMle });
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
  return {
    claim,
    proof,
    mleAbiVersion,
    submitWithdrawalClaimSelector: mleAbiVersion === 2
      ? SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR
      : SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
  };
}

function validateWithdrawalClaimReceipt(
  managerAddress,
  iface,
  receipt,
  txHash,
  withdrawalNullifier,
  recipient,
  tokenIndex,
  amount,
  expectedLogIndex = null,
) {
  if (!receipt || !isHexString(txHash, 32)) throw new Error('withdrawal credit receipt is incomplete');
  const receiptHash = receipt.hash || receipt.transactionHash;
  if (!isHexString(receiptHash, 32) || receiptHash.toLowerCase() !== txHash.toLowerCase()) {
    throw new Error('withdrawal credit receipt transaction hash mismatch');
  }
  const expectedManager = getAddress(managerAddress).toLowerCase();
  const expectedNullifier = bytes(withdrawalNullifier, 'withdrawal nullifier', 32);
  const expectedRecipient = getAddress(recipient).toLowerCase();
  const expectedTokenIndex = BigInt(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
  const expectedAmount = BigInt(uintString(amount, 'withdrawal credit amount'));
  const matches = [];
  for (const log of Array.isArray(receipt.logs) ? receipt.logs : []) {
    let logAddress;
    try { logAddress = getAddress(log.address).toLowerCase(); } catch (_) { continue; }
    if (logAddress !== expectedManager) continue;
    if (!isHexString(log.transactionHash, 32) || log.transactionHash.toLowerCase() !== txHash.toLowerCase()) {
      throw new Error('WithdrawalClaimed event transaction hash mismatch');
    }
    let parsed;
    try { parsed = iface.parseLog({ topics: log.topics, data: log.data }); } catch (_) { continue; }
    const index = log.index == null ? log.logIndex : log.index;
    if (parsed && parsed.name === 'WithdrawalClaimed'
        && (expectedLogIndex == null || Number(index) === Number(expectedLogIndex))) {
      matches.push(parsed);
    }
  }
  if (matches.length !== 1) throw new Error('withdrawal credit receipt must contain exactly one manager WithdrawalClaimed event');
  const args = matches[0].args;
  if (String(args.withdrawalNullifier).toLowerCase() !== expectedNullifier
      || getAddress(args.recipient).toLowerCase() !== expectedRecipient
      || BigInt(args.tokenIndex) !== expectedTokenIndex
      || BigInt(args.amount) !== expectedAmount) {
    throw new Error('WithdrawalClaimed event does not match the journaled payout');
  }
}

function exactReceiptEvent(managerAddress, iface, receipt, txHash, eventName, expectedLogIndex = null) {
  if (!receipt || !isHexString(txHash, 32)) return null;
  const receiptHash = receipt.hash || receipt.transactionHash;
  if (!isHexString(receiptHash, 32) || receiptHash.toLowerCase() !== txHash.toLowerCase()) return null;
  const expectedManager = getAddress(managerAddress).toLowerCase();
  const matches = [];
  for (const log of Array.isArray(receipt.logs) ? receipt.logs : []) {
    let address;
    try { address = getAddress(log.address).toLowerCase(); } catch (_) { continue; }
    if (address !== expectedManager || !isHexString(log.transactionHash, 32)
        || log.transactionHash.toLowerCase() !== txHash.toLowerCase()) continue;
    let parsed;
    try { parsed = iface.parseLog({ topics: log.topics, data: log.data }); } catch (_) { continue; }
    const index = log.index == null ? log.logIndex : log.index;
    if (parsed && parsed.name === eventName
        && (expectedLogIndex == null || Number(index) === Number(expectedLogIndex))) {
      matches.push(parsed);
    }
  }
  return matches.length === 1 ? matches[0] : null;
}

function makeClaimSettlement({
  rpcUrl,
  chainId,
  recipient,
  privateKey,
  confirmations = 1,
  provider: injectedProvider = null,
  signer: injectedSigner = null,
  outbox: injectedOutbox = null,
  outboxDirectory = null,
  signerLockRoot = null,
  allowUnfinalizedDevnet = false,
  channelId = null,
  participantSlot = null,
}) {
  if (!privateKey && !injectedSigner && !injectedOutbox) return null;
  const txConfirmations = Number(confirmations);
  if (!Number.isSafeInteger(txConfirmations) || txConfirmations < 1 || txConfirmations > 64) {
    throw new Error('l1TxConfirmations must be an integer in 1..64');
  }
  const provider = injectedProvider || (injectedOutbox && injectedOutbox.provider) || new JsonRpcProvider(rpcUrl);
  // Keep the key offline. Contract instances below are read/encode-only; every write is signed and
  // persisted by the shared raw-transaction outbox before any JSON-RPC broadcast.
  const signer = injectedSigner || (privateKey ? new EthersWallet(privateKey) : null);
  const signerAddress = injectedOutbox ? injectedOutbox.signerAddress : signer && signer.address;
  const expectedRecipient = getAddress(recipient);
  if (!signerAddress || getAddress(signerAddress) !== expectedRecipient) {
    throw new Error(`INTMAX_DELEGATE_L1_PRIVATE_KEY controls ${signerAddress || 'no address'}, not configured recipient ${expectedRecipient}`);
  }
  const expectedChainId = BigInt(chainId);
  const outbox = injectedOutbox || new SignedTransactionOutbox({
    directory: outboxDirectory,
    lockRoot: signerLockRoot,
    chainId: expectedChainId,
    signer,
    provider,
    confirmations: txConfirmations,
    allowUnfinalizedDevnet,
  });
  if (getAddress(outbox.signerAddress) !== expectedRecipient) {
    throw new Error('delegate transaction outbox signer differs from the configured recipient');
  }

  async function checkedManager(managerAddress) {
    const network = await provider.getNetwork();
    if (network.chainId !== expectedChainId) {
      throw new Error(`delegate L1 RPC chain id ${network.chainId} differs from configured ${expectedChainId}`);
    }
    return new Contract(getAddress(managerAddress), MANAGER_CLAIM_ABI, provider);
  }

  function claimActionId(managerAddress, tokenSlot) {
    if (channelId != null && participantSlot != null) {
      return `claim:${channelId}:${participantSlot}:${tokenSlot}`;
    }
    return `claim:${getAddress(managerAddress).toLowerCase()}:${tokenSlot}`;
  }

  function creditActionId(managerAddress, nullifier) {
    const channel = channelId == null ? getAddress(managerAddress).toLowerCase() : String(channelId);
    return `credit-pull:${channel}:${String(nullifier).toLowerCase()}`;
  }

  function fundsActionId(managerAddress, nullifier) {
    return `${creditActionId(managerAddress, nullifier)}:channel-funds`;
  }

  function normalizedObservation(event) {
    return {
      transactionHash: event && (event.transactionHash || event.txHash),
      blockNumber: event && event.blockNumber,
      blockHash: event && event.blockHash,
      logIndex: event && event.logIndex,
    };
  }

  async function rememberBroadcast(result, callback, value) {
    if (typeof callback !== 'function') return;
    try {
      await callback(value);
    } catch (error) {
      if (error && typeof error === 'object' && !error.transactionHash) {
        error.transactionHash = result.transactionHash;
      }
      throw error;
    }
  }

  async function rememberPrepared(callback, value) {
    if (typeof callback === 'function') await callback(value);
  }

  function signerSettlementRequired(actionId, resumed) {
    const error = new Error(
      `durable outbox action ${actionId} must settle its exact signer nonce before semantic short-circuit`,
    );
    error.code = 'OUTBOX_SIGNER_SETTLEMENT_REQUIRED';
    if (resumed && resumed.transactionHash) error.transactionHash = resumed.transactionHash;
    return error;
  }

  async function send(actionId, transaction, replacement = null) {
    try {
      return await outbox.send({
        actionId,
        to: transaction.to,
        data: transaction.data,
        value: transaction.value == null ? 0n : transaction.value,
        replacement,
      });
    } catch (error) {
      const saved = outbox.status(actionId);
      if (saved && error && typeof error === 'object' && !error.transactionHash) {
        error.transactionHash = saved.transactionHash;
      }
      throw error;
    }
  }

  return {
    signerAddress,
    durableOutbox: true,
    outbox,
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

    async submitClaim(managerAddress, artifact, finalized, tokenSlot, onBroadcast = null, txOptions = {}) {
      const manager = await checkedManager(managerAddress);
      const { claim, proof, submitWithdrawalClaimSelector } = validateClaimArtifact(
        artifact,
        finalized,
        expectedRecipient,
        tokenSlot,
        { allowLegacyMle: expectedChainId === 31337n },
      );
      const actionId = txOptions.actionId || claimActionId(managerAddress, tokenSlot);
      // Recover an intent-only crash or rebroadcast the exact journaled raw before consulting the
      // permissionless nullifier. A foreign submit is semantic success, not proof that this
      // recipient signer's reserved nonce was consumed.
      const resumed = await outbox.resumeExact(actionId);
      const prior = outbox.status(actionId);
      if (await manager.usedWithdrawalNullifiers(claim.withdrawalNullifier)) {
        if (!['absent', 'terminal'].includes(resumed.phase)) {
          throw signerSettlementRequired(actionId, resumed);
        }
        return {
          alreadySubmitted: true,
          txHash: prior && prior.transactionHash,
          outboxActionId: actionId,
          tokenIndex: Number(claim.tokenIndex),
          nullifier: claim.withdrawalNullifier,
        };
      }
      const submitWithdrawalClaim = manager.getFunction(submitWithdrawalClaimSelector);
      const transaction = await submitWithdrawalClaim.populateTransaction(claim, proof);
      if (!prior) await submitWithdrawalClaim.staticCall(claim, proof);
      await rememberPrepared(txOptions.onPrepared, {
        phase: 'claim',
        actionId,
        nullifier: claim.withdrawalNullifier,
        memberPkG: claim.memberPkG,
        tokenIndex: Number(claim.tokenIndex),
        amount: String(claim.amount),
      });
      const submitted = await send(actionId, transaction, txOptions.replacement || null);
      await rememberBroadcast(submitted, onBroadcast, submitted.transactionHash);
      const receipt = await outbox.waitForReceipt(actionId, txConfirmations);
      if (!receipt || Number(receipt.status) !== 1) {
        throw new Error(`withdrawal claim transaction ${submitted.transactionHash} has no successful receipt`);
      }
      return {
        txHash: submitted.transactionHash,
        outboxActionId: actionId,
        tokenIndex: Number(claim.tokenIndex),
        nullifier: claim.withdrawalNullifier,
      };
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

    async pullCredit(
      managerAddress,
      withdrawalNullifier,
      tokenIndex,
      exactAmount,
      onBroadcast = null,
      txOptions = {},
    ) {
      const manager = await checkedManager(managerAddress);
      const nullifier = bytes(withdrawalNullifier, 'withdrawal nullifier', 32);
      const index = Number(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
      const exact = BigInt(uintString(exactAmount, 'exactAmount', (1n << 64n) - 1n));
      if (exact === 0n) throw new Error('exactAmount must be positive');
      const actionId = txOptions.actionId || creditActionId(managerAddress, nullifier);
      const fundAction = txOptions.fundsActionId || fundsActionId(managerAddress, nullifier);

      // These deterministic actions may have reached the raw WAL before the caller's broadcast
      // callback. Resume them before any getter-based early return or later sibling transaction.
      const resumedFunds = await outbox.resumeExact(fundAction);
      if (!['absent', 'terminal'].includes(resumedFunds.phase)) {
        throw signerSettlementRequired(fundAction, resumedFunds);
      }
      const resumedCredit = await outbox.resumeExact(actionId);
      if (!['absent', 'terminal'].includes(resumedCredit.phase)) {
        throw signerSettlementRequired(actionId, resumedCredit);
      }

      const payout = await manager.withdrawalPayouts(nullifier);
      const payoutRecipient = getAddress(payout.recipient == null ? payout[0] : payout.recipient);
      const payoutTokenIndex = BigInt(payout.tokenIndex == null ? payout[1] : payout.tokenIndex);
      const payoutAmount = BigInt(payout.amount == null ? payout[2] : payout.amount);
      if (payoutAmount === 0n) return { noCredit: true, tokenIndex: index, nullifier };
      if (payoutRecipient !== expectedRecipient
          || payoutTokenIndex !== BigInt(index)
          || payoutAmount !== exact) {
        throw new Error('manager nullifier payout does not match the accepted claim');
      }

      const credit = await manager.withdrawalCredits(index, expectedRecipient);
      if (credit < exact) throw new Error('manager withdrawal credit is below the accepted claim amount');

      // Once a live withdrawal producer has created this manager's rollup backing, both fund-pull
      // functions are permissionless and always pay this manager. They do NOT create
      // pendingWithdrawals[manager] / pendingTokenWithdrawals themselves: if production backing is
      // absent, the zero pull or cap check below fails closed and recovery remains retryable.
      const [receivedBefore, paidBefore] = await Promise.all([
        manager.receivedChannelFunds(index),
        manager.totalCreditedOut(index),
      ]);
      if (paidBefore > receivedBefore) throw new Error('manager per-token payout accounting is inconsistent');
      if (receivedBefore - paidBefore < exact) {
        const fundFunction = index === 0
          ? manager.pullChannelFunds
          : manager.pullChannelTokenFunds;
        const fundArgs = index === 0 ? [] : [index];
        if (!outbox.status(fundAction)) {
          await fundFunction.staticCall(...fundArgs);
        }
        const fundTransaction = await fundFunction.populateTransaction(...fundArgs);
        await rememberPrepared(txOptions.onPrepared, {
          phase: 'channel-funds',
          actionId: fundAction,
          nullifier,
          tokenIndex: index,
          amount: exact.toString(),
        });
        const fundSubmitted = await send(
          fundAction,
          fundTransaction,
          txOptions.fundsReplacement || null,
        );
        await rememberBroadcast(fundSubmitted, onBroadcast, {
          phase: 'channel-funds',
          txHash: fundSubmitted.transactionHash,
          outboxActionId: fundAction,
        });
        const fundReceipt = await outbox.waitForReceipt(fundAction, txConfirmations);
        if (!fundReceipt || Number(fundReceipt.status) !== 1) {
          throw new Error(`channel fund pull transaction ${fundSubmitted.transactionHash} has no successful receipt`);
        }
        const [receivedAfter, paidAfter] = await Promise.all([
          manager.receivedChannelFunds(index, { blockTag: fundReceipt.blockNumber }),
          manager.totalCreditedOut(index, { blockTag: fundReceipt.blockNumber }),
        ]);
        if (paidAfter > receivedAfter || receivedAfter - paidAfter < exact) {
          throw new Error('manager has not received enough production withdrawal backing for this payout');
        }
      }
      const claimCredit = manager['claimWithdrawalCredit(bytes32)'];
      if (!outbox.status(actionId)) {
        await claimCredit.staticCall(nullifier);
      }
      const transaction = await claimCredit.populateTransaction(nullifier);
      await rememberPrepared(txOptions.onPrepared, {
        phase: 'credit',
        actionId,
        nullifier,
        tokenIndex: index,
        amount: exact.toString(),
      });
      const submitted = await send(actionId, transaction, txOptions.replacement || null);
      await rememberBroadcast(submitted, onBroadcast, {
        phase: 'credit',
        txHash: submitted.transactionHash,
        outboxActionId: actionId,
        nullifier,
        amount: exact.toString(),
      });
      const receipt = await outbox.waitForReceipt(actionId, txConfirmations);
      if (!receipt || Number(receipt.status) !== 1) {
        throw new Error(`withdrawal credit transaction ${submitted.transactionHash} has no successful receipt`);
      }
      validateWithdrawalClaimReceipt(
        managerAddress,
        manager.interface,
        receipt,
        submitted.transactionHash,
        nullifier,
        expectedRecipient,
        index,
        exact,
      );
      return {
        txHash: submitted.transactionHash,
        outboxActionId: actionId,
        tokenIndex: index,
        nullifier,
        amount: exact.toString(),
      };
    },

    async markClaimFinalized(managerAddress, tokenSlot, expected, event) {
      const manager = await checkedManager(managerAddress);
      const actionId = expected.actionId || claimActionId(managerAddress, tokenSlot);
      const nullifier = bytes(expected.nullifier, 'withdrawal nullifier', 32);
      const tokenIndex = BigInt(uintString(expected.tokenIndex, 'tokenIndex', 0xffffffffn));
      const amount = BigInt(uintString(expected.amount, 'amount', (1n << 64n) - 1n));
      const closeIntentDigest = bytes(expected.closeIntentDigest, 'close intent digest', 32);
      const memberPkG = bytes(expected.memberPkG, 'claim member public-key digest', 32);
      return outbox.markFinalized(actionId, normalizedObservation(event), async ({ blockTag, receipt, transactionHash }) => {
        if (await manager.usedWithdrawalNullifiers(nullifier, { blockTag }) !== true) return false;
        const matches = [];
        for (const entry of Array.isArray(receipt.logs) ? receipt.logs : []) {
          let parsed;
          try {
            if (getAddress(entry.address) !== getAddress(managerAddress)
                || String(entry.transactionHash).toLowerCase() !== transactionHash) continue;
            parsed = manager.interface.parseLog({ topics: entry.topics, data: entry.data });
          } catch (_) { continue; }
          if (parsed && parsed.name === 'WithdrawalClaimAccepted') matches.push(parsed);
        }
        if (matches.length !== 1) return false;
        const args = matches[0].args;
        return String(args.closeIntentDigest).toLowerCase() === closeIntentDigest
          && String(args.withdrawalNullifier).toLowerCase() === nullifier
          && String(args.memberPkG).toLowerCase() === memberPkG
          && getAddress(args.recipient) === expectedRecipient
          && BigInt(args.tokenIndex) === tokenIndex
          && BigInt(args.amount) === amount;
      });
    },

    async markFundsFinalized(
      managerAddress,
      withdrawalNullifier,
      tokenIndex,
      exactAmount,
      event,
      explicitActionId = null,
    ) {
      const manager = await checkedManager(managerAddress);
      const nullifier = bytes(withdrawalNullifier, 'withdrawal nullifier', 32);
      const index = Number(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
      const exact = BigInt(uintString(exactAmount, 'amount', (1n << 64n) - 1n));
      const actionId = explicitActionId || fundsActionId(managerAddress, nullifier);
      return outbox.markFinalized(actionId, normalizedObservation(event), async ({ blockTag, receipt, transactionHash }) => {
        const [received, paid, cap] = await Promise.all([
          manager.receivedChannelFunds(index, { blockTag }),
          manager.totalCreditedOut(index, { blockTag }),
          manager.finalizedChannelFundAmount(index, { blockTag }),
        ]);
        if (paid > received || received < exact || received !== cap) return false;
        const parsed = exactReceiptEvent(
          managerAddress,
          manager.interface,
          receipt,
          transactionHash,
          'ChannelFundsPulled',
        );
        return parsed !== null
          && Number(parsed.args.tokenIndex) === index
          && BigInt(parsed.args.amount) > 0n
          && BigInt(parsed.args.totalReceived) === received;
      });
    },

    async markCreditFinalized(
      managerAddress,
      withdrawalNullifier,
      tokenIndex,
      exactAmount,
      event,
      explicitActionId = null,
    ) {
      const manager = await checkedManager(managerAddress);
      const nullifier = bytes(withdrawalNullifier, 'withdrawal nullifier', 32);
      const index = Number(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
      const exact = BigInt(uintString(exactAmount, 'amount', (1n << 64n) - 1n));
      const actionId = explicitActionId || creditActionId(managerAddress, nullifier);
      return outbox.markFinalized(actionId, normalizedObservation(event), async ({ blockTag, receipt, transactionHash }) => {
        validateWithdrawalClaimReceipt(
          managerAddress,
          manager.interface,
          receipt,
          transactionHash,
          nullifier,
          expectedRecipient,
          index,
          exact,
        );
        const payout = await manager.withdrawalPayouts(nullifier, { blockTag });
        return await manager.usedWithdrawalNullifiers(nullifier, { blockTag }) === true
          && BigInt(payout.amount == null ? payout[2] : payout.amount) === 0n;
      });
    },

    async reconcileClaim(managerAddress, tokenSlot, expected, semanticObservation) {
      const manager = await checkedManager(managerAddress);
      const actionId = expected.actionId || claimActionId(managerAddress, tokenSlot);
      const nullifier = bytes(expected.nullifier, 'withdrawal nullifier', 32);
      const tokenIndex = BigInt(uintString(expected.tokenIndex, 'tokenIndex', 0xffffffffn));
      const amount = BigInt(uintString(expected.amount, 'amount', (1n << 64n) - 1n));
      const closeIntentDigest = bytes(expected.closeIntentDigest, 'close intent digest', 32);
      const memberPkG = bytes(expected.memberPkG, 'claim member public-key digest', 32);
      return outbox.settleSuperseded(
        actionId,
        normalizedObservation(semanticObservation),
        async ({ blockTag, receipt, transactionHash }) => {
          if (await manager.usedWithdrawalNullifiers(nullifier, { blockTag }) !== true) return false;
          const matches = [];
          for (const entry of Array.isArray(receipt.logs) ? receipt.logs : []) {
            let parsed;
            try {
              if (getAddress(entry.address) !== getAddress(managerAddress)
                  || String(entry.transactionHash).toLowerCase() !== transactionHash) continue;
              parsed = manager.interface.parseLog({ topics: entry.topics, data: entry.data });
            } catch (_) { continue; }
            if (parsed && parsed.name === 'WithdrawalClaimAccepted') matches.push(parsed);
          }
          if (matches.length !== 1) return false;
          const args = matches[0].args;
          return String(args.closeIntentDigest).toLowerCase() === closeIntentDigest
            && String(args.withdrawalNullifier).toLowerCase() === nullifier
            && String(args.memberPkG).toLowerCase() === memberPkG
            && getAddress(args.recipient) === expectedRecipient
            && BigInt(args.tokenIndex) === tokenIndex
            && BigInt(args.amount) === amount;
        },
        async ({ blockTag, receipt, transactionHash, logIndex }) => {
          if (!semanticObservation || semanticObservation.kind !== 'WithdrawalClaimAccepted') {
            return false;
          }
          const parsed = exactReceiptEvent(
            managerAddress,
            manager.interface,
            receipt,
            transactionHash,
            'WithdrawalClaimAccepted',
            logIndex,
          );
          if (!parsed) return false;
          const args = parsed.args;
          if (String(args.closeIntentDigest).toLowerCase() !== closeIntentDigest
              || String(args.withdrawalNullifier).toLowerCase() !== nullifier
              || String(args.memberPkG).toLowerCase() !== memberPkG
              || getAddress(args.recipient) !== expectedRecipient
              || BigInt(args.tokenIndex) !== tokenIndex
              || BigInt(args.amount) !== amount
              || String(semanticObservation.closeIntentDigest).toLowerCase() !== closeIntentDigest
              || String(semanticObservation.withdrawalNullifier).toLowerCase() !== nullifier
              || String(semanticObservation.memberPkG).toLowerCase() !== memberPkG
              || getAddress(semanticObservation.recipient) !== expectedRecipient
              || BigInt(semanticObservation.tokenIndex) !== tokenIndex
              || BigInt(semanticObservation.amount) !== amount) return false;
          if (await manager.usedWithdrawalNullifiers(nullifier, { blockTag }) !== true) return false;
          return true;
        },
      );
    },

    async reconcileFunds(
      managerAddress,
      withdrawalNullifier,
      tokenIndex,
      exactAmount,
      semanticObservation,
      explicitActionId = null,
    ) {
      const manager = await checkedManager(managerAddress);
      const nullifier = bytes(withdrawalNullifier, 'withdrawal nullifier', 32);
      const index = Number(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
      const exact = BigInt(uintString(exactAmount, 'amount', (1n << 64n) - 1n));
      const actionId = explicitActionId || fundsActionId(managerAddress, nullifier);
      return outbox.settleSuperseded(
        actionId,
        normalizedObservation(semanticObservation),
        async ({ blockTag, receipt, transactionHash }) => {
          const [received, paid, cap] = await Promise.all([
            manager.receivedChannelFunds(index, { blockTag }),
            manager.totalCreditedOut(index, { blockTag }),
            manager.finalizedChannelFundAmount(index, { blockTag }),
          ]);
          if (paid > received || received < exact || received !== cap) return false;
          const parsed = exactReceiptEvent(
            managerAddress,
            manager.interface,
            receipt,
            transactionHash,
            'ChannelFundsPulled',
          );
          return parsed !== null
            && Number(parsed.args.tokenIndex) === index
            && BigInt(parsed.args.amount) > 0n
            && BigInt(parsed.args.totalReceived) === received;
        },
        async ({ blockTag, receipt, transactionHash, logIndex }) => {
          if (!semanticObservation || semanticObservation.kind !== 'ChannelFundsPulled') return false;
          const parsed = exactReceiptEvent(
            managerAddress,
            manager.interface,
            receipt,
            transactionHash,
            'ChannelFundsPulled',
            logIndex,
          );
          if (!parsed || Number(parsed.args.tokenIndex) !== index
              || BigInt(parsed.args.amount) !== BigInt(semanticObservation.amount)
              || BigInt(parsed.args.totalReceived) !== BigInt(semanticObservation.totalReceived)
              || Number(semanticObservation.tokenIndex) !== index) return false;
          const [received, paid, cap] = await Promise.all([
            manager.receivedChannelFunds(index, { blockTag }),
            manager.totalCreditedOut(index, { blockTag }),
            manager.finalizedChannelFundAmount(index, { blockTag }),
          ]);
          return paid <= received
            && received === cap
            && BigInt(parsed.args.totalReceived) === cap
            && cap >= exact
            && BigInt(parsed.args.amount) > 0n;
        },
      );
    },

    async reconcileCredit(
      managerAddress,
      withdrawalNullifier,
      tokenIndex,
      exactAmount,
      semanticObservation,
      explicitActionId = null,
    ) {
      const manager = await checkedManager(managerAddress);
      const nullifier = bytes(withdrawalNullifier, 'withdrawal nullifier', 32);
      const index = Number(uintString(tokenIndex, 'tokenIndex', 0xffffffffn));
      const exact = BigInt(uintString(exactAmount, 'amount', (1n << 64n) - 1n));
      const actionId = explicitActionId || creditActionId(managerAddress, nullifier);
      return outbox.settleSuperseded(
        actionId,
        normalizedObservation(semanticObservation),
        async ({ blockTag, receipt, transactionHash }) => {
          validateWithdrawalClaimReceipt(
            managerAddress,
            manager.interface,
            receipt,
            transactionHash,
            nullifier,
            expectedRecipient,
            index,
            exact,
          );
          const payout = await manager.withdrawalPayouts(nullifier, { blockTag });
          return await manager.usedWithdrawalNullifiers(nullifier, { blockTag }) === true
            && BigInt(payout.amount == null ? payout[2] : payout.amount) === 0n;
        },
        async ({ blockTag, receipt, transactionHash, logIndex }) => {
          if (!semanticObservation || semanticObservation.kind !== 'WithdrawalClaimed') return false;
          try {
            validateWithdrawalClaimReceipt(
              managerAddress,
              manager.interface,
              receipt,
              transactionHash,
              nullifier,
              expectedRecipient,
              index,
              exact,
              logIndex,
            );
          } catch (_) {
            return false;
          }
          if (String(semanticObservation.withdrawalNullifier).toLowerCase() !== nullifier
              || getAddress(semanticObservation.recipient) !== expectedRecipient
              || Number(semanticObservation.tokenIndex) !== index
              || BigInt(semanticObservation.amount) !== exact) return false;
          const payout = await manager.withdrawalPayouts(nullifier, { blockTag });
          return await manager.usedWithdrawalNullifiers(nullifier, { blockTag }) === true
            && BigInt(payout.amount == null ? payout[2] : payout.amount) === 0n;
        },
      );
    },

    async transactionStatus(txHash) {
      return outbox.transactionStatus(txHash);
    },
    ownsTransaction(actionId, txHash) {
      return outbox.hasAttempt(actionId, txHash);
    },
  };
}

module.exports = {
  CLAIM_COMPONENTS,
  MANAGER_CLAIM_ABI,
  MLE_PROOF_COMPONENTS,
  MLE_PROOF_V1_COMPONENTS,
  MLE_PROOF_V2_COMPONENTS,
  SUBMIT_WITHDRAWAL_CLAIM_V1_SELECTOR,
  SUBMIT_WITHDRAWAL_CLAIM_V2_SELECTOR,
  makeClaimSettlement,
  mleProofAbiVersion,
  normalizeMleProof,
  validateClaimArtifact,
  validateWithdrawalClaimReceipt,
};
