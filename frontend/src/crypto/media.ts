import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { createSHA256 } from 'hash-wasm';

// Chunk size for multipart uploads (5MB)
export const CHUNK_SIZE = 5 * 1024 * 1024; 

/**
 * Computes a SHA-256 hash incrementally via streaming WebAssembly.
 * Returns the hash as a hex string and raw bytes.
 */
export async function computeFileHash(file: File | Blob): Promise<{ hex: string; bytes: Uint8Array }> {
  const hasher = await createSHA256();
  hasher.init();

  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBuffer = await file.slice(start, end).arrayBuffer();
    hasher.update(new Uint8Array(chunkBuffer));
  }

  const hex = hasher.digest('hex');
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  return { hex, bytes };
}

/**
 * Encrypts a File using Convergent Encryption (key = SHA-256(plaintext)).
 * This allows deduplication on the server without the server knowing the plaintext.
 * We encrypt the file in chunks to support resumable/chunked uploads for large files.
 */
export async function encryptMediaChunked(file: File): Promise<{
  chunks: Blob[];
  key: Uint8Array;
  contentHash: string; // The hash of the ciphertext (used for addressing in MinIO)
}> {
  // 1. Convergent Encryption: Key is derived from the plaintext hash
  const { bytes: key } = await computeFileHash(file);
  
  const chunks: Blob[] = [];
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  
  const ciphertextHasher = await createSHA256();
  ciphertextHasher.init();

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBuffer = await file.slice(start, end).arrayBuffer();
    
    // Construct nonce for this chunk: chunk index in last 4 bytes (little endian)
    const chunkNonce = new Uint8Array(12);
    const view = new DataView(chunkNonce.buffer);
    view.setUint32(8, i, true);

    const cipher = chacha20poly1305(key, chunkNonce);
    const encryptedChunk = cipher.encrypt(new Uint8Array(chunkBuffer));
    
    ciphertextHasher.update(encryptedChunk);
    chunks.push(new Blob([encryptedChunk]));
  }

  const contentHashHex = ciphertextHasher.digest('hex');

  return {
    chunks,
    key,
    contentHash: contentHashHex
  };
}

/**
 * Decrypts a File encrypted via encryptMediaChunked.
 */
export async function decryptMediaChunked(ciphertextBlob: Blob, key: Uint8Array, mimeType: string): Promise<Blob> {
  // Each encrypted chunk is CHUNK_SIZE + 16 (Poly1305 tag)
  const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 16;
  const totalChunks = Math.ceil(ciphertextBlob.size / ENCRYPTED_CHUNK_SIZE);
  
  const decryptedChunks: Blob[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * ENCRYPTED_CHUNK_SIZE;
    const end = Math.min(start + ENCRYPTED_CHUNK_SIZE, ciphertextBlob.size);
    const chunkBuffer = await ciphertextBlob.slice(start, end).arrayBuffer();
    
    const chunkNonce = new Uint8Array(12);
    const view = new DataView(chunkNonce.buffer);
    view.setUint32(8, i, true);

    const cipher = chacha20poly1305(key, chunkNonce);
    const decryptedChunk = cipher.decrypt(new Uint8Array(chunkBuffer));
    
    decryptedChunks.push(new Blob([decryptedChunk]));
  }

  return new Blob(decryptedChunks, { type: mimeType });
}
