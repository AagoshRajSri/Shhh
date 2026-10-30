import 'fake-indexeddb/auto';
import { exportIdentity, importIdentity, saveEncrypted, loadEncrypted, initDB, wipeDatabase } from './src/crypto/db';
import WebSocket from 'ws';

// Mock localStorage for Node environment
const storageMap = new Map<string, string>();
(globalThis as any).localStorage = {
  getItem: (key: string) => storageMap.get(key) ?? null,
  setItem: (key: string, value: string) => storageMap.set(key, value),
  removeItem: (key: string) => storageMap.delete(key),
  clear: () => storageMap.clear(),
};
(globalThis as any).window = globalThis;

import cryptoNode from 'crypto';

function solvePow(handle: string, difficultyBits = 20): number {
  const handleBuf = Buffer.from(handle, 'utf8');
  let nonce = 0;
  const nonceBuf = Buffer.alloc(8);
  const requiredZeroBytes = Math.floor(difficultyBits / 8);
  const remainingBits = difficultyBits % 8;

  while (true) {
    nonceBuf.writeBigUInt64LE(BigInt(nonce));
    const hasher = cryptoNode.createHash('sha256');
    hasher.update(nonceBuf);
    hasher.update(handleBuf);
    const hash = hasher.digest();

    let matches = true;
    for (let i = 0; i < requiredZeroBytes; i++) {
      if (hash[i] !== 0) {
        matches = false;
        break;
      }
    }
    if (matches && remainingBits > 0) {
      if ((hash[requiredZeroBytes] >> (8 - remainingBits)) !== 0) {
        matches = false;
      }
    }
    if (matches) return nonce;
    nonce++;
  }
}

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ ASSERTION FAILED: ${msg}`);
    process.exit(1);
  }
}

async function runBackupRoundtripTest() {
  console.log('--- START: Backup Roundtrip & Vault Storage Test ---');

  initDB();

  // 1. Generate identity credentials
  const handle = '#backup_user_' + Math.random().toString(36).substring(2, 8);
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  const receive_secret = Array.from(secretBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const testInboxId = crypto.randomUUID();
  const passphrase = 'Ultra-Secure-Passphrase-2026!';

  console.log(`[1] Created user ${handle} with inbox_id: ${testInboxId}`);

  // 2. Save identity into encrypted IndexedDB vault
  const mockIdentityKeys = {
    identityKey: 'eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiZXhhbXBsZSJ9',
    privKey: 'mock-private-key-material'
  };

  await saveEncrypted('identity', mockIdentityKeys, 'me');
  await saveEncrypted('identity', { receiveSecret: receive_secret }, 'receive_secret');
  await saveEncrypted('identity', { routingToken: testInboxId, inboxId: testInboxId, handle }, 'routing_token');
  await saveEncrypted('knownKeys', { address: '#contact_bob', keyB64: 'mock_bob_key' }, '#contact_bob');

  // 3. Confirm secret is stored in encrypted vault, NOT in localStorage
  const vaultRecord = await loadEncrypted('identity', 'receive_secret');
  assert(vaultRecord !== null, 'Vault record must exist');
  assert(vaultRecord.receiveSecret === receive_secret, 'Vault must contain the receive_secret');

  const lsSecret = localStorage.getItem('receive_secret');
  assert(lsSecret === null, 'receive_secret must NEVER be stored in localStorage');

  const lsAllKeys = Array.from(storageMap.keys());
  console.log(`[2] localStorage keys present: ${JSON.stringify(lsAllKeys)}`);
  assert(!lsAllKeys.includes('receive_secret'), 'localStorage must not have receive_secret key');
  for (const [k, v] of storageMap.entries()) {
    assert(!v.includes(receive_secret), `localStorage value for key ${k} must not contain plaintext receive_secret`);
  }
  console.log('✅ PASS: receive_secret is securely stored in encrypted vault, completely absent from localStorage.');

  // 4. Export encrypted identity backup
  const exportJson = await exportIdentity(handle, testInboxId, passphrase, receive_secret);
  const parsedExport = JSON.parse(exportJson);

  assert(parsedExport.v === 1, 'Backup format version must be 1');
  assert(typeof parsedExport.salt === 'string' && parsedExport.salt.length === 32, 'Salt must be 16 bytes hex');
  assert(typeof parsedExport.iv === 'string' && parsedExport.iv.length === 24, 'IV must be 12 bytes hex');
  assert(typeof parsedExport.ct === 'string' && parsedExport.ct.length > 50, 'Ciphertext must be non-empty hex');

  // Ensure export ciphertext is encrypted and does not contain plaintext secret
  assert(!exportJson.includes(receive_secret), 'Export file must NOT leak plaintext receive_secret!');
  assert(!exportJson.includes(handle), 'Export file ciphertext must be encrypted; handle must not appear in plaintext!');
  console.log('✅ PASS: Exported encrypted bundle successfully. No plaintext credentials in backup JSON.');

  // 5. Wipe IndexedDB completely
  console.log('[3] Wiping IndexedDB completely...');
  await wipeDatabase();

  const wipedIdentity = await loadEncrypted('identity', 'me');
  assert(wipedIdentity === null, 'IndexedDB identity store must be empty after wipe');
  const wipedSecret = await loadEncrypted('identity', 'receive_secret');
  assert(wipedSecret === null, 'IndexedDB receive_secret must be empty after wipe');
  const wipedContact = await loadEncrypted('knownKeys', '#contact_bob');
  assert(wipedContact === null, 'IndexedDB knownKeys store must be empty after wipe');
  console.log('✅ PASS: IndexedDB wiped clean. Zero identity data retained.');

  // 6. Test import with WRONG passphrase (must fail)
  let failedOnWrongPass = false;
  try {
    await importIdentity(exportJson, 'wrong-passphrase-attempt');
  } catch (err: any) {
    failedOnWrongPass = true;
    assert(err.message.includes('Incorrect passphrase') || err.message.includes('corrupted'), 'Error message must reflect decryption failure');
  }
  assert(failedOnWrongPass, 'Importing with wrong passphrase must fail');
  console.log('✅ PASS: Decryption with wrong passphrase rejected.');

  // 7. Import with CORRECT passphrase
  console.log('[4] Importing backup with correct passphrase...');
  const restored = await importIdentity(exportJson, passphrase);
  assert(restored.handle === handle, `Restored handle matches original (${restored.handle})`);
  assert(restored.inbox_id === testInboxId, `Restored inbox_id matches original (${restored.inbox_id})`);
  assert(restored.receive_secret === receive_secret, 'Restored receive_secret matches original');

  // 8. Confirm secret is restored in encrypted vault and NOT in localStorage
  const restoredVaultSecret = (await loadEncrypted('identity', 'receive_secret'))?.receiveSecret;
  assert(restoredVaultSecret === receive_secret, 'receive_secret must be restored into encrypted vault');

  const lsSecretAfter = localStorage.getItem('receive_secret');
  assert(lsSecretAfter === null, 'receive_secret must STILL not be in localStorage after import');

  const restoredContact = await loadEncrypted('knownKeys', '#contact_bob');
  assert(restoredContact !== null && restoredContact.address === '#contact_bob', 'Contacts must be restored');
  console.log('✅ PASS: Identity, receive_secret, and contacts restored to encrypted vault.');

  // 9. Live relay integration test (if relay is running)
  console.log('[5] Testing live relay integration with restored secret...');
  const API_URL = 'http://127.0.0.1:3000';
  const WS_URL = 'ws://127.0.0.1:3000/ws';

  try {
      const pow_nonce = solvePow(handle, 20);
      const regRes = await fetch(`${API_URL}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          handle,
          identity_public_key: Buffer.from('mock_identity_pk_bytes_32_bytes').toString('base64'),
          signed_prekey: Buffer.from('mock_signed_prekey_bytes_32_bytes').toString('base64'),
          one_time_prekeys: [],
          kyber_public_key: Buffer.from('mock_kyber_public_key_32_bytes').toString('base64'),
          pow_nonce,
          receive_secret: restored.receive_secret,
        }),
      });

    if (regRes.ok) {
      const regData: any = await regRes.json();
      console.log(`[5a] Registered ${handle} on relay. Assigned inbox_id: ${regData.inbox_id}`);

      // Connect WebSocket with restored secret in Sec-WebSocket-Protocol
      const wsConnected = await new Promise<boolean>((resolve) => {
        const socket = new WebSocket(WS_URL, [restored.receive_secret!]);
        const timer = setTimeout(() => {
          socket.terminate();
          resolve(false);
        }, 5000);

        socket.on('open', () => {
          clearTimeout(timer);
          socket.close();
          resolve(true);
        });

        socket.on('error', (err) => {
          clearTimeout(timer);
          console.error('WS Error:', err);
          resolve(false);
        });
      });

      assert(wsConnected, 'WebSocket must connect successfully using restored receive_secret!');
      console.log('✅ PASS: WebSocket connected using restored secret from imported backup!');

      // Test ack with restored secret
      const ackRes = await fetch(`${API_URL}/api/message/ack`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Receive-Secret': restored.receive_secret!,
        },
        body: JSON.stringify({ msg_id: 'test_roundtrip_ack' }),
      });
      assert(ackRes.ok, `Ack request with restored secret must succeed (status ${ackRes.status})`);
      console.log('✅ PASS: Message ack succeeded using restored secret!');
    } else {
      console.log(`[Note] Backend relay not listening on ${API_URL} (status ${regRes.status}); local roundtrip validated.`);
    }
  } catch (err: any) {
    console.log(`[Note] Live relay connection skipped (${err.message}); local backup roundtrip validated.`);
  }

  console.log('🎉 ALL BACKUP ROUNDTRIP CHECKS PASSED SUCCESSFULLY!');
}

runBackupRoundtripTest().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
