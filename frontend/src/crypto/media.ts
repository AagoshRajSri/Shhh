import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

// Chunk size for multipart uploads (5MB)
export const CHUNK_SIZE = 5 * 1024 * 1024; 

/**
 * Computes a SHA-256 hash incrementally or via ArrayBuffer if streaming isn't natively supported.
 * Returns the hash as a hex string and raw bytes.
 */
export async function computeFileHash(file: File | Blob): Promise<{ hex: string; bytes: Uint8Array }> {
  // For simplicity and compatibility, we read the whole file. 
  // In a production app with very large files, we'd use a streaming WebAssembly hash.
  const buffer = await file.arrayBuffer();
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
  const bytes = new Uint8Array(hashBuffer);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
  let ciphertextLength = 0;
  
  // We need to hash the ciphertext to get the contentHash
  // We'll collect all encrypted chunks to hash them at the end.
  const encryptedBuffers: Uint8Array[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBlob = file.slice(start, end);
    const chunkBuffer = await chunkBlob.arrayBuffer();
    
    // Construct nonce for this chunk: baseNonce + chunk index in last 4 bytes
    const chunkNonce = new Uint8Array(12);
    const view = new DataView(chunkNonce.buffer);
    view.setUint32(8, i, true); // Little endian

    const cipher = chacha20poly1305(key, chunkNonce);
    const encryptedChunk = cipher.encrypt(new Uint8Array(chunkBuffer));
    
    // Prefix with chunk index + length for robust decryption, or just rely on sequence.
    // For simplicity, we just store the encrypted bytes. The Poly1305 tag is appended by the cipher.
    chunks.push(new Blob([encryptedChunk]));
    encryptedBuffers.push(encryptedChunk);
    ciphertextLength += encryptedChunk.length;
  }

  // Hash the concatenated ciphertext to get the content address
  const fullCiphertext = new Uint8Array(ciphertextLength);
  let offset = 0;
  for (const buf of encryptedBuffers) {
    fullCiphertext.set(buf, offset);
    offset += buf.length;
  }
  
  const contentHashBuffer = await window.crypto.subtle.digest('SHA-256', fullCiphertext);
  const contentHashHex = Array.from(new Uint8Array(contentHashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

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
    const chunkBlob = ciphertextBlob.slice(start, end);
    const chunkBuffer = await chunkBlob.arrayBuffer();
    
    const chunkNonce = new Uint8Array(12);
    const view = new DataView(chunkNonce.buffer);
    view.setUint32(8, i, true);

    const cipher = chacha20poly1305(key, chunkNonce);
    const decryptedChunk = cipher.decrypt(new Uint8Array(chunkBuffer));
    
    decryptedChunks.push(new Blob([decryptedChunk]));
  }

  return new Blob(decryptedChunks, { type: mimeType });
}
