import { openDB } from 'idb';
import type { DBSchema, IDBPDatabase } from 'idb';
import { argon2id } from 'hash-wasm';

interface SecureChatDB extends DBSchema {
  identity: {
    key: string;
    value: {
      id: string;
      encryptedData: ArrayBuffer;
      iv: Uint8Array;
    };
  };
  sessions: {
    key: string;
    value: {
      address: string;
      encryptedRecord: ArrayBuffer;
      iv: Uint8Array;
    };
  };
  prekeys: {
    key: string;
    value: {
      id: number;
      encryptedRecord: ArrayBuffer;
      iv: Uint8Array;
    };
  };
  knownKeys: {
    key: string;
    value: {
      address: string;
      encryptedRecord: ArrayBuffer;
      iv: Uint8Array;
    };
  };
}

let dbPromise: Promise<IDBPDatabase<SecureChatDB>>;

export function initDB() {
  dbPromise = openDB<SecureChatDB>('securechat-db', 2, {
    upgrade(db, oldVersion) {
      if (oldVersion < 1) {
        db.createObjectStore('identity', { keyPath: 'id' });
        db.createObjectStore('sessions', { keyPath: 'address' });
        db.createObjectStore('prekeys', { keyPath: 'id' });
      }
      if (oldVersion < 2) {
        db.createObjectStore('knownKeys', { keyPath: 'address' });
      }
    },
  });
}

// The master key wraps all per-store ciphertexts in IndexedDB.
// Stored unprotected in localStorage — protects from casual access on shared devices only.
// Export passphrase protection uses Argon2id independently.
let masterKey: CryptoKey | null = null;

export async function getMasterKey(): Promise<CryptoKey> {
  if (masterKey) return masterKey;

  const storageKey = 'shhh_local_device_key';
  let rawB64 = localStorage.getItem(storageKey);
  let rawBytes: Uint8Array;

  if (!rawB64) {
    rawBytes = window.crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(storageKey, btoa(String.fromCharCode(...rawBytes)));
  } else {
    try {
      const binStr = atob(rawB64);
      rawBytes = new Uint8Array(binStr.length);
      for (let i = 0; i < binStr.length; i++) {
        rawBytes[i] = binStr.charCodeAt(i);
      }
    } catch {
      rawBytes = window.crypto.getRandomValues(new Uint8Array(32));
      localStorage.setItem(storageKey, btoa(String.fromCharCode(...rawBytes)));
    }
  }

  masterKey = await window.crypto.subtle.importKey(
    'raw',
    rawBytes as any,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
  return masterKey;
}

export async function saveEncrypted(storeName: 'identity' | 'sessions' | 'prekeys' | 'knownKeys', item: any, idKey: string | number) {
  if (!dbPromise) initDB();
  const key = await getMasterKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(item));
  
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  const db = await dbPromise;
  await db.put(storeName, {
    [storeName === 'identity' ? 'id' : storeName === 'sessions' ? 'address' : 'id']: idKey,
    encryptedData: storeName === 'identity' ? encrypted : undefined,
    encryptedRecord: storeName !== 'identity' ? encrypted : undefined,
    iv
  } as any);
}

export async function loadEncrypted(storeName: 'identity' | 'sessions' | 'prekeys' | 'knownKeys', idKey: string | number): Promise<any | null> {
  if (!dbPromise) initDB();
  const db = await dbPromise;
  const record = await db.get(storeName, idKey as any);
  if (!record) return null;

  const key = await getMasterKey();
  const encryptedBuffer = (record as any).encryptedData || (record as any).encryptedRecord;
  
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.iv as any },
      key,
      encryptedBuffer
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch (e) {
    console.warn(`Local record in ${storeName} could not be decrypted. Resetting obsolete record.`);
    try {
      await db.delete(storeName, idKey as any);
    } catch {
      // ignore
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Identity Export / Import  (Option A: Argon2id-wrapped JWK bundle)
//
// Export file format (JSON):
//   { v: 1, salt: "<hex>", iv: "<hex>", ct: "<hex>" }
//
// Plaintext (before encryption):
//   { handle, routing_token, identity, seenNonces, knownKeys[] }
//
// Argon2id tuning (target ~1 s on a 500 MHz / low-end device):
//   iterations=3, memory=65536 KiB (64 MiB), parallelism=1, hashLength=32
//
// LIMITATION: The seen-nonce set captured at export time is a point-in-time snapshot.
// Messages delivered after export but before the next session close will NOT be in the
// snapshot. After an import-based restore, the server can re-deliver nonces from the
// 7-day queue window that are newer than the snapshot. Document this honestly to users.
// ---------------------------------------------------------------------------

const ARGON2_PARAMS = { iterations: 3, memorySize: 65536, parallelism: 1, hashLength: 32 };

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function deriveKeyFromPassphrase(passphrase: string, saltHex: string): Promise<CryptoKey> {
  const saltBytes = new Uint8Array(saltHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
  const keyHex: string = await argon2id({
    password: passphrase,
    salt: saltBytes,
    ...ARGON2_PARAMS,
    outputType: 'hex',
  });
  const keyBytes = new Uint8Array(keyHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
  return window.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Export identity bundle to an Argon2id-encrypted JSON string.
 * Bundles: handle, routing_token, identity keys (JWK), seen nonces, knownKeys store.
 *
 * FOR TOR USERS: Tor Browser wipes IndexedDB on window close. This export is
 * mandatory to keep your identity across sessions. Store the passphrase and
 * file safely — loss of either means permanent identity loss.
 */
export async function exportIdentity(
  handle: string,
  routingToken: string,
  passphrase: string,
  receiveSecret?: string,
): Promise<string> {
  if (!dbPromise) initDB();

  const identity = await loadEncrypted('identity', 'me');
  const seenNonces = await loadEncrypted('identity', 'seen_nonces') ?? {};
  const secret = receiveSecret || (await loadEncrypted('identity', 'receive_secret'))?.receiveSecret;

  // Walk the knownKeys store (contact trust anchors for key-change detection)
  const db = await dbPromise;
  const knownKeysOut: Array<{ address: string; keyB64: string }> = [];
  const masterK = await getMasterKey();
  let cursor = await db.transaction('knownKeys').store.openCursor();
  while (cursor) {
    try {
      const rec = cursor.value as any;
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: rec.iv },
        masterK,
        rec.encryptedRecord,
      );
      knownKeysOut.push(JSON.parse(new TextDecoder().decode(decrypted)));
    } catch { /* skip corrupt record */ }
    cursor = await cursor.continue();
  }

  const plaintext = JSON.stringify({
    handle,
    inbox_id: routingToken,
    routing_token: routingToken,
    receive_secret: secret,
    identity,
    seenNonces,
    knownKeys: knownKeysOut,
  });
  const saltHex = bytesToHex(window.crypto.getRandomValues(new Uint8Array(16)));
  const ivBytes = window.crypto.getRandomValues(new Uint8Array(12));
  const encKey = await deriveKeyFromPassphrase(passphrase, saltHex);
  const ctBuf = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes }, encKey, new TextEncoder().encode(plaintext));

  return JSON.stringify({ v: 1, salt: saltHex, iv: bytesToHex(ivBytes), ct: bytesToHex(new Uint8Array(ctBuf)) }, null, 2);
}

/**
 * Import an Argon2id-encrypted identity backup.
 * Restores identity keys, receive_secret, nonce set, and knownKeys into IndexedDB.
 * Returns { handle, routing_token, inbox_id, receive_secret } on success.
 */
export async function importIdentity(fileContent: string, passphrase: string): Promise<{ handle: string; routing_token: string; inbox_id: string; receive_secret?: string }> {
  if (!dbPromise) initDB();

  const exportObj = JSON.parse(fileContent);
  if (exportObj.v !== 1) throw new Error('Unknown identity backup format version.');

  const encKey = await deriveKeyFromPassphrase(passphrase, exportObj.salt);
  const ivBytes = new Uint8Array((exportObj.iv as string).match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));
  const ctBytes = new Uint8Array((exportObj.ct as string).match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));

  let data: any;
  try {
    const ptBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, encKey, ctBytes);
    data = JSON.parse(new TextDecoder().decode(ptBuf));
  } catch {
    throw new Error('Incorrect passphrase or corrupted backup file.');
  }

  const inboxId = data.inbox_id || data.routing_token;
  if (!data.identity || !data.handle || !inboxId) {
    throw new Error('Backup file is missing required fields.');
  }

  await saveEncrypted('identity', data.identity, 'me');
  if (data.receive_secret) {
    await saveEncrypted('identity', { receiveSecret: data.receive_secret }, 'receive_secret');
  }
  await saveEncrypted('identity', { routingToken: inboxId, inboxId, handle: data.handle }, 'routing_token');

  if (data.seenNonces && Object.keys(data.seenNonces).length > 0) {
    await saveEncrypted('identity', data.seenNonces, 'seen_nonces');
  }
  if (Array.isArray(data.knownKeys)) {
    for (const kk of data.knownKeys) {
      if (kk.address && kk.keyB64) await saveEncrypted('knownKeys', kk, kk.address);
    }
  }

  return { handle: data.handle, routing_token: inboxId, inbox_id: inboxId, receive_secret: data.receive_secret };
}

