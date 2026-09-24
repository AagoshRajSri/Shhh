import { openDB } from 'idb';
import type { DBSchema, IDBPDatabase } from 'idb';

interface SecureChatDB extends DBSchema {
  identity: {
    key: string;
    value: {
      id: string;
      encryptedData: ArrayBuffer; // AES-GCM encrypted IdentityKeyPair + RegistrationId
      iv: Uint8Array;
    };
  };
  sessions: {
    key: string;
    value: {
      address: string; // e.g., handle
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
}

let dbPromise: Promise<IDBPDatabase<SecureChatDB>>;

export function initDB() {
  dbPromise = openDB<SecureChatDB>('securechat-db', 1, {
    upgrade(db) {
      db.createObjectStore('identity', { keyPath: 'id' });
      db.createObjectStore('sessions', { keyPath: 'address' });
      db.createObjectStore('prekeys', { keyPath: 'id' });
    },
  });
}

// In a real implementation, this key is derived from a user passphrase or local biometric vault.
// For this scaffolding, we generate an ephemeral WebCrypto key to demonstrate the structure.
let masterKey: CryptoKey | null = null;

export async function getMasterKey(): Promise<CryptoKey> {
  if (masterKey) return masterKey;
  masterKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return masterKey;
}

export async function saveEncrypted(storeName: 'identity' | 'sessions' | 'prekeys', item: any, idKey: string | number) {
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

export async function loadEncrypted(storeName: 'identity' | 'sessions' | 'prekeys', idKey: string | number): Promise<any | null> {
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
    console.error('Failed to decrypt local DB record', e);
    return null;
  }
}
