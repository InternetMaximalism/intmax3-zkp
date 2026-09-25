(function(root) {
  'use strict';
  // Proof payloads exceed localStorage quotas. Resolve writes only after the IndexedDB
  // transaction commits, so the browser always retains the exact request before transmission.
  class WalletOutbox {
    async access(mode, run) {
      const db = await new Promise((resolve,reject) => {
        const r=indexedDB.open('intmax-wallet-outbox-v1',1);
        r.onupgradeneeded=()=>r.result.createObjectStore('requests');
        r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
      });
      try { return await new Promise((resolve,reject) => {
        const tx=db.transaction('requests',mode), request=run(tx.objectStore('requests'));
        tx.oncomplete=()=>resolve(request.result);
        tx.onabort=()=>reject(tx.error || new Error('Could not save the pending transfer.'));
        tx.onerror=()=>reject(tx.error);
      }); } finally { db.close(); }
    }
    read(key) { return this.access('readonly',s=>s.get(key)); }
    save(key,value) { return this.access('readwrite',s=>s.add(value,key)); }
    clear(key) { return this.access('readwrite',s=>s.delete(key)); }
  }
  root.WalletOutbox=WalletOutbox;
})(typeof window !== 'undefined' ? window : globalThis);
