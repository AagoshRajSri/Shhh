import { createSHA256 } from 'hash-wasm';

/**
 * Computes a proof-of-work nonce for the given handle.
 * Matches backend verify_pow: SHA-256(nonce_le || handle_utf8) must start
 * with `difficulty` leading zero bits.
 */
export async function solvePoW(
  handle: string,
  difficulty: number = 20,
  onProgress?: (attempts: number) => void
): Promise<number> {
  const hasher = await createSHA256();
  const handleBytes = new TextEncoder().encode(handle);
  const inputBuffer = new Uint8Array(8 + handleBytes.length);
  inputBuffer.set(handleBytes, 8);
  const view = new DataView(inputBuffer.buffer);

  const reqZeroBytes = Math.floor(difficulty / 8);
  const remBits = difficulty % 8;

  let nonce = 0;
  while (true) {
    view.setUint32(0, nonce & 0xffffffff, true);
    view.setUint32(4, Math.floor(nonce / 0x100000000), true);

    hasher.init();
    hasher.update(inputBuffer);
    const digest = hasher.digest('binary');

    let valid = true;
    for (let i = 0; i < reqZeroBytes; i++) {
      if (digest[i] !== 0) {
        valid = false;
        break;
      }
    }
    if (valid && remBits > 0) {
      if ((digest[reqZeroBytes] >> (8 - remBits)) !== 0) {
        valid = false;
      }
    }

    if (valid) {
      return nonce;
    }

    nonce++;
    if (nonce % 25000 === 0) {
      if (onProgress) onProgress(nonce);
      // Yield to UI loop
      await new Promise(r => setTimeout(r, 0));
    }
  }
}
