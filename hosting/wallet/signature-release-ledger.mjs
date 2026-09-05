// Member channel-state signatures are not public until their predecessor decision is durable.
// This is a release fence, not a replacement for the WASM transition/exit-kit checks. Transaction
// authorizations on ordinary unsigned delegate send proposals do not use this database.
const DB_NAME = 'intmax-member-signature-ledger-v1';
const STORE = 'decisions';
const ZERO = `0x${'00'.repeat(32)}`;

function hex32(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`signature release requires a valid ${label}`);
  }
  return value.toLowerCase();
}

function field(value, camel, snake) {
  if (!value || typeof value !== 'object') return undefined;
  if (value[camel] !== undefined && value[snake] !== undefined
      && JSON.stringify(value[camel]) !== JSON.stringify(value[snake])) {
    throw new Error('signature release refuses conflicting wire aliases');
  }
  return value[camel] !== undefined ? value[camel] : value[snake];
}

function channelId(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('signature release requires an exact channelId');
  }
  return value;
}

function signatureFor(signature, signerPkG) {
  const slot = field(signature, 'memberSlot', 'member_slot');
  if (!Number.isInteger(slot) || slot < 0 || slot > 7
      || hex32(field(signature, 'pkG', 'pk_g'), 'signature identity') !== signerPkG
      || signature.signature == null) throw new Error('signature release identity/slot is inconsistent');
  return slot;
}

export function signatureDecision(candidate, existing) {
  if (!existing) return candidate;
  if (existing.schemaVersion !== 1 || existing.key !== candidate.key
      || existing.signerPkG !== candidate.signerPkG || existing.channelId !== candidate.channelId
      || existing.prevDigest !== candidate.prevDigest || existing.memberSlot !== candidate.memberSlot) {
    throw new Error('durable member-signature decision is inconsistent');
  }
  if (existing.successorDigest !== candidate.successorDigest) {
    throw new Error('a different successor of this predecessor was already signed; recover that exact state');
  }
  if (signatureFor(existing.signature, candidate.signerPkG) !== candidate.memberSlot) {
    throw new Error('durable member-signature slot is inconsistent');
  }
  // Falcon signatures may be randomized. Replay the exact previously released bytes, not a fresh
  // signature, even when a retry recomputes the same valid state.
  return existing;
}

export function createIndexedDbSignatureLedger(indexedDB) {
  let database = null;
  async function open() {
    // Access can itself throw on storage-disabled origins. Keep it lazy so unsigned delegate
    // operations remain usable even when this browser cannot act as a durable member signer.
    if (indexedDB === undefined) indexedDB = globalThis.indexedDB;
    if (!indexedDB || typeof indexedDB.open !== 'function') {
      throw new Error('durable member signing requires IndexedDB; no signature was released');
    }
    if (!database) {
      database = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE, { keyPath: 'key' });
        };
        request.onerror = () => reject(new Error('member signature database could not be opened'));
        request.onblocked = () => reject(new Error('member signature database upgrade is blocked'));
        request.onsuccess = () => {
          const db = request.result;
          db.onversionchange = () => { db.close(); database = null; };
          resolve(db);
        };
      }).catch(error => { database = null; throw error; });
    }
    return database;
  }
  return {
    async remember(candidate) {
      const db = await open();
      return new Promise((resolve, reject) => {
        let transaction;
        let saved;
        let failure;
        try {
          // readwrite transactions on one store serialize the read/decision/write across workers
          // and tabs. Require actual strict durability; do not silently accept an ignored option.
          transaction = db.transaction(STORE, 'readwrite', { durability: 'strict' });
          if (transaction.durability !== 'strict') {
            transaction.abort();
            throw new Error('this browser does not provide strict durable member signing');
          }
          transaction.oncomplete = () => resolve(saved);
          transaction.onabort = () => reject(failure || new Error('member signature storage aborted; no signature was released'));
          transaction.onerror = () => { failure ||= new Error('member signature storage failed; no signature was released'); };
          const store = transaction.objectStore(STORE);
          const read = store.get(candidate.key);
          read.onsuccess = () => {
            try {
              saved = signatureDecision(candidate, read.result);
              if (!read.result) store.add(saved);
            } catch (error) {
              failure = error;
              transaction.abort();
            }
          };
        } catch (error) {
          reject(error);
        }
      });
    },
  };
}

function assertUnsignedProposal(action, result) {
  if (!['send', 'refresh', 'sendInterChannel', 'burnSend'].includes(action)) return;
  // This string is the trusted WASM serde output, not caller JSON. Check its fixed serialized
  // signature-vector keys without reparsing/copying large ZK proof arrays. slimWire merely encodes
  // an already-public input and returns bytes; it cannot generate a new state signature.
  if (typeof result !== 'string'
      || /"(?:memberSignatures|member_signatures)"\s*:(?!\s*\[\s*\])/.test(result)) {
    throw new Error('wallet proposal unexpectedly contains channel-state signatures; rebuild the audited WASM bundle');
  }
}

export function createSignatureReleaseGate(backend = createIndexedDbSignatureLedger()) {
  return {
    async release({ action, input, result, signerPkG }) {
      if (!['signState', 'cosign'].includes(action)) {
        assertUnsignedProposal(action, result);
        return result;
      }
      const identity = hex32(signerPkG, 'session signer identity');
      if (typeof result !== 'string') throw new Error('signed WASM result must retain its exact serialized wire');
      const output = JSON.parse(result);
      const state = action === 'signState'
        ? (typeof input.stateJson === 'string' ? JSON.parse(input.stateJson) : input.stateJson) : output;
      const prevDigest = hex32(field(state, 'prevDigest', 'prev_digest'), 'predecessor digest');
      if (action === 'signState' && prevDigest !== ZERO) throw new Error('genesis signature requires the zero predecessor');
      const signatures = action === 'signState' ? [output] : field(output, 'memberSignatures', 'member_signatures');
      if (!Array.isArray(signatures)) throw new Error('co-sign result has no member-signature vector');
      const own = signatures.filter(signature => hex32(field(signature, 'pkG', 'pk_g'), 'signature identity') === identity);
      if (own.length !== 1) throw new Error('co-sign result must contain exactly one own signature');
      const memberSlot = signatureFor(own[0], identity);
      if (action === 'signState' && memberSlot !== input.slot) throw new Error('genesis signature slot differs from the request');
      const candidate = { schemaVersion: 1, signerPkG: identity,
        channelId: channelId(field(state, 'channelId', 'channel_id')), prevDigest,
        successorDigest: hex32(state.digest, 'successor digest'), memberSlot, signature: own[0] };
      candidate.key = JSON.stringify([identity, candidate.channelId, prevDigest]);
      const persisted = await backend.remember(candidate);
      if (!persisted) throw new Error('member signature storage did not acknowledge a durable decision');
      const saved = signatureDecision(candidate, persisted);
      if (action === 'signState') return JSON.stringify(saved.signature);
      // Preserve the original state text: epoch/version/nonces are raw u64 JSON numbers, so
      // reserializing a parsed ChannelState would round values above 2^53. A MemberSignature is
      // only a small slot, hex public key and Vec<u8>, whose canonical serde JSON is lossless here.
      const originalSignature = JSON.stringify(own[0]);
      const start = result.indexOf(originalSignature);
      if (start < 0 || result.indexOf(originalSignature, start + originalSignature.length) !== -1) {
        throw new Error('signed WASM signature wire is not canonical and unambiguous');
      }
      return result.slice(0, start) + JSON.stringify(saved.signature)
        + result.slice(start + originalSignature.length);
    },
  };
}
