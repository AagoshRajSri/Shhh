export async function encryptFile(file: File): Promise<{
    ciphertext: Blob;
    key: CryptoKey;
    iv: Uint8Array;
    hash: string;
    mimeType: string;
    size: number;
  }> {
    // Generate one-time symmetric key
    const key = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const buffer = await file.arrayBuffer();
    
    // Calculate content hash for MinIO object addressing
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
    // Encrypt file content
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      buffer
    );
  
    return {
      ciphertext: new Blob([encrypted]),
      key,
      iv,
      hash: hashHex,
      mimeType: file.type,
      size: file.size
    };
  }
  
  export async function decryptFile(
    ciphertext: Blob,
    key: CryptoKey,
    iv: Uint8Array,
    mimeType: string
  ): Promise<File> {
    const buffer = await ciphertext.arrayBuffer();
    
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as any },
      key,
      buffer
    );
  
    return new File([decrypted], "decrypted", { type: mimeType });
  }
  
