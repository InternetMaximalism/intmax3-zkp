'use strict';
const { Interface, getAddress } = require('ethers');
const abi = new Interface(['function withdraw(uint256)', 'function withdrawToken(uint32,uint256)']);
function pullTransaction(auth, rollup) {
  const amount = auth.withdrawal_amount;
  if (typeof amount === 'number' && !Number.isSafeInteger(amount)) throw new Error('inexact withdrawal amount');
  if (!/^[1-9][0-9]*$/.test(String(amount))) throw new Error('invalid withdrawal amount');
  const tokenIndex = Number(auth.withdrawal_token_index);
  if (!Number.isSafeInteger(tokenIndex) || tokenIndex < 0 || tokenIndex > 0xffffffff) throw new Error('invalid withdrawal token');
  return { to: getAddress(rollup), recipient: getAddress(auth.withdrawal_recipient), amount: String(amount), tokenIndex,
    data: tokenIndex === 0 ? abi.encodeFunctionData('withdraw',[amount]) : abi.encodeFunctionData('withdrawToken',[tokenIndex,amount]), value: '0x0' };
}
function verifyPull(claim, tx, receipt, block) {
  const same = (a,b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
  if (!tx || !receipt || !block || receipt.status !== '0x1' || !same(tx.hash,receipt.transactionHash)
    || !same(tx.from,claim.recipient) || !same(tx.to,claim.to) || !same(tx.input,claim.data)
    || BigInt(tx.value) !== 0n || !same(receipt.blockHash,block.hash)
    || !same(tx.blockHash,receipt.blockHash) || BigInt(receipt.blockNumber) < BigInt(claim.afterBlock)) {
    throw new Error('wallet withdrawal receipt does not match this settled payout');
  }
}
module.exports = { pullTransaction, verifyPull };
