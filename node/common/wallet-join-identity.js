'use strict';
// Public snapshot identities only. Never infer a channel secret from an L1 wallet address.
function assertJoinIdentity(snapshot, contribution, frozen) {
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
  if (!frozen) return;
  const delegates = members.filter(member => member.slot >= snapshot.record.memberCount);
  const sameAddress = delegates.find(member => lower(recipients[member.slot]) === lower(contribution.recipient));
  if (sameAddress) {
    fail('CHANNEL_KEY_MISMATCH', `This MetaMask address is already joined to channel ${channel}, but this browser has a different channel key. Open the browser and exact URL used for the first Join. MetaMask alone cannot restore the channel key. Keep the saved keys; do not Clear.`);
  }
  const bound = delegates.map(member => recipients[member.slot]).slice(0,3).join(', ');
  fail('CHANNEL_MEMBERSHIP_FROZEN', `Channel ${channel} is already registered${bound ? ' for ' + bound : ''}. The connected MetaMask account is ${contribution.recipient}, and this channel key is not a member. Use the original browser and connected account; a new Join cannot replace the existing account.`);
}
module.exports = { assertJoinIdentity };
