'use strict';
// Public snapshot identities only. Never infer a channel secret from an L1 wallet address.
// `deploying`: this channel's settlement deployment is in flight (PREPARED). Delegates join freely
// before and after a deployment; only while one is in flight is a NEW key refused, because the
// deployment registers exactly the participant snapshot it was prepared for. (The sig-cluster —
// the cosigners — is a different set with a different rule: it never changes after deployment.)
function assertJoinIdentity(snapshot, contribution, deploying) {
  if (!snapshot) return;
  const lower = value => String(value || '').toLowerCase();
  const members = snapshot.members || [];
  const recipients = snapshot.state.balanceState.recipients;
  const existing = members.find(member => lower(member.pkG) === lower(contribution.pkG));
  const channel = snapshot.record.channelId;
  const fail = (code, message) => { throw Object.assign(new Error(message), {status:409, code}); };
  if (existing) {
    const bound = recipients[existing.slot];
    if (lower(bound) !== lower(contribution.recipient)) {
      fail('WALLET_ACCOUNT_MISMATCH', `Channel ${channel} belongs to MetaMask ${bound}. The connected account is ${contribution.recipient}. Switch the connected MetaMask account before continuing.`);
    }
    return;
  }
  if (!deploying) return;
  const delegates = members.filter(member => member.slot >= snapshot.record.memberCount);
  const sameAddress = delegates.find(member => lower(recipients[member.slot]) === lower(contribution.recipient));
  if (sameAddress) {
    fail('CHANNEL_KEY_MISMATCH', `This MetaMask address is already joined to channel ${channel}, but this browser has a different channel key. Open the browser and exact URL used for the first Join. MetaMask alone cannot restore the channel key. Keep the saved keys; do not Clear.`);
  }
  fail('SETTLEMENT_DEPLOYING', `Channel ${channel} is registering its settlement contract on L1 right now, so new members are paused until it finishes. Retry Join in a few minutes; nothing was changed.`);
}
module.exports = { assertJoinIdentity };
