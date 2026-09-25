(function (root) {
  'use strict';
  class WalletTransactions {
    constructor(storage, prefix = 'intmax-wallet-tx:') { this.storage = storage; this.prefix = prefix; }
    read(key) {
      const raw = this.storage.getItem(this.prefix + key);
      if (!raw) return null;
      const record = JSON.parse(raw);
      if (record.version !== 1 || !record.request || !record.context) throw new Error('Invalid saved wallet transaction; refusing another payment.');
      return record;
    }
    save(key, record) { this.storage.setItem(this.prefix + key, JSON.stringify(record)); }
    clear(key) { this.storage.removeItem(this.prefix + key); }
    async recover(provider, key, context) {
      const record = this.read(key);
      if (!record) return null;
      if (JSON.stringify(record.context) !== JSON.stringify(context)) throw new Error('A saved transaction belongs to another wallet or deployment. Switch back to resume it.');
      if (record.txHash) return record;
      // A wallet can broadcast successfully and then lose its RPC response. Pin the nonce before
      // asking for approval and look for that exact transaction; never send another payment here.
      const latest = Number(BigInt(await provider.request({method:'eth_blockNumber'})));
      const end = Math.min(latest, record.nextBlock + 63);
      for (let n = record.nextBlock; n <= end; n++) {
        const block = await provider.request({method:'eth_getBlockByNumber', params:['0x'+n.toString(16), true]});
        if (!block || !Array.isArray(block.transactions)) throw new Error('Could not check the saved wallet transaction. Retry the same action.');
        for (const tx of block.transactions) {
          if (String(tx.from).toLowerCase() !== record.request.from.toLowerCase() || BigInt(tx.nonce) !== BigInt(record.request.nonce)) continue;
          if (String(tx.to).toLowerCase() !== record.request.to.toLowerCase()
              || String(tx.input || tx.data || '0x').toLowerCase() !== (record.request.data || '0x').toLowerCase()
              || BigInt(tx.value) !== BigInt(record.request.value || '0x0')) {
            throw new Error('The saved nonce was used by a different wallet transaction. No new payment was sent.');
          }
          record.txHash = tx.hash; this.save(key, record); return record;
        }
        record.nextBlock = n + 1;
      }
      this.save(key, record);
      throw new Error('Waiting to locate the wallet transaction. Check MetaMask, then retry this same action; no second payment will be sent.');
    }
    async send(provider, key, request, context, details) {
      if (typeof navigator !== 'undefined' && navigator.locks) {
        return navigator.locks.request(this.prefix + key, () => this.sendUnlocked(provider,key,request,context,details));
      }
      return this.sendUnlocked(provider,key,request,context,details);
    }
    async sendUnlocked(provider, key, request, context, details) {
      if (this.read(key)) return this.recover(provider, key, context);
      const nonce = await provider.request({method:'eth_getTransactionCount', params:[request.from,'pending']});
      const block = Number(BigInt(await provider.request({method:'eth_blockNumber'})));
      const record = {version:1,context,request:{...request,nonce},details,nextBlock:block};
      this.save(key,record); // Storage failure must happen BEFORE the wallet can spend funds.
      let hash;
      try { hash = await provider.request({method:'eth_sendTransaction',params:[record.request]}); }
      catch (error) { if (Number(error && error.code) === 4001) this.clear(key); throw error; }
      if (!/^0x[0-9a-f]{64}$/i.test(String(hash))) throw new Error('Wallet response was incomplete. Retry this action to locate its transaction.');
      record.txHash=hash;this.save(key,record);return record;
    }
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {WalletTransactions};
  else root.WalletTransactions = WalletTransactions;
})(typeof window !== 'undefined' ? window : globalThis);
