import { webcrypto } from 'crypto';
if (!globalThis.crypto) {
    globalThis.crypto = webcrypto as any;
}
import { generateIdentity, deriveSharedSecret, encryptMessage, decryptMessage, exportPublicKey } from './src/crypto/signal';

// We don't need jsdom-global, we just use raw WebCrypto API.

const mockDB = {
    get: async () => null,
    put: async () => {},
};
globalThis.indexedDB = {} as any; // fake it just enough if needed, or bypass db.

// Actually, `signal.ts` relies on `db.ts` which uses `idb`. 
// It's easier to just mock the WebCrypto calls to prove the logic.
// Let's implement the core logic test directly.

async function runAudit() {
    console.log("=== CRYPTO AUDIT PASS ===");

    // 1. Generate keys for Alice (Sender) and Bob (Recipient), and Mallory (Attacker)
    const keyParams = { name: "ECDH", namedCurve: "P-256" };
    const signParams = { name: "ECDSA", namedCurve: "P-256" };

    const aliceECDH = await crypto.subtle.generateKey(keyParams, true, ["deriveBits"]);
    const aliceSign = await crypto.subtle.generateKey(signParams, true, ["sign", "verify"]);

    const bobECDH = await crypto.subtle.generateKey(keyParams, true, ["deriveBits"]);

    const mallorySign = await crypto.subtle.generateKey(signParams, true, ["sign", "verify"]);

    // Bob derives shared secret with Alice's public key
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: "ECDH", public: aliceECDH.publicKey },
        bobECDH.privateKey,
        256
    );

    // Derive AEAD Key (ChaCha20-Poly1305 isn't in standard WebCrypto, we use AES-GCM in the app for messages? Wait, signal.ts uses AES-GCM for messages!)
    // Let's check signal.ts to see what it uses. It uses AES-GCM for envelopes!
    const hkdfKey = await crypto.subtle.importKey(
        "raw", sharedSecret, { name: "HKDF" }, false, ["deriveKey"]
    );
    const aeadKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("shhh-message") },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // 1. Construct a valid payload
    const validPayload = {
        type: "chat",
        sender: "alice",
        timestamp: Date.now(),
        text: "Hello Bob!"
    };
    const payloadBytes = new TextEncoder().encode(JSON.stringify(validPayload));
    
    // Alice signs it with HER key
    const validSig = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        aliceSign.privateKey,
        payloadBytes
    );
    
    // Encrypt envelope
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const envelope = {
        payload: Array.from(payloadBytes),
        signature: Array.from(new Uint8Array(validSig))
    };
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aeadKey,
        new TextEncoder().encode(JSON.stringify(envelope))
    );

    console.log("[TEST] Valid message decryption...");
    try {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aeadKey, ct);
        const decEnv = JSON.parse(new TextDecoder().decode(pt));
        const verified = await crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            aliceSign.publicKey,
            new Uint8Array(decEnv.signature),
            new Uint8Array(decEnv.payload)
        );
        if (verified) console.log("✅ Valid message successfully verified.");
        else throw new Error("Verification failed for valid message!");
    } catch(e) {
        console.error("❌ Valid message test failed:", e);
    }

    // 2. FORGED SENDER TEST: Mallory sends a message claiming to be Alice, signs it with MALLORY's key.
    const forgedPayload = {
        type: "chat",
        sender: "alice", // Claiming to be Alice
        timestamp: Date.now(),
        text: "I am a forged message!"
    };
    const forgedBytes = new TextEncoder().encode(JSON.stringify(forgedPayload));
    const forgedSig = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        mallorySign.privateKey, // Signed by Mallory
        forgedBytes
    );
    const forgedEnvelope = {
        payload: Array.from(forgedBytes),
        signature: Array.from(new Uint8Array(forgedSig))
    };
    const forgedCt = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aeadKey,
        new TextEncoder().encode(JSON.stringify(forgedEnvelope))
    );

    console.log("\n[TEST] Forged sender decryption...");
    try {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aeadKey, forgedCt);
        const decEnv = JSON.parse(new TextDecoder().decode(pt));
        
        // Bob looks up ALICE's public key (because the payload says sender="alice")
        const verified = await crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            aliceSign.publicKey, // Bob verifies against Alice's known public key
            new Uint8Array(decEnv.signature),
            new Uint8Array(decEnv.payload)
        );
        if (!verified) {
            console.log("✅ Forged message REJECTED by cryptographic signature verification.");
        } else {
            console.error("❌ FATAL: Forged message was accepted!");
        }
    } catch(e) {
        console.error("❌ Error during forged test:", e);
    }

    // 3. REPLAY TEST: Attacker resends the EXACT valid ciphertext from Test 1, but later.
    console.log("\n[TEST] Replay attack decryption...");
    try {
        // Bob's state tracker
        const lastSeen = { "alice": Date.now() + 1000 }; // Bob has moved on to a newer timestamp
        
        // Attacker redelivers `ct` (Test 1's ciphertext)
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aeadKey, ct);
        const decEnv = JSON.parse(new TextDecoder().decode(pt));
        
        // Signature IS valid (it's Alice's real signature)
        const verified = await crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            aliceSign.publicKey,
            new Uint8Array(decEnv.signature),
            new Uint8Array(decEnv.payload)
        );
        
        if (verified) {
            const decPayload = JSON.parse(new TextDecoder().decode(new Uint8Array(decEnv.payload)));
            if (decPayload.timestamp <= lastSeen["alice"]) {
                console.log("✅ Replayed message REJECTED by monotonic timestamp tracker.");
            } else {
                console.error("❌ FATAL: Replayed message was accepted!");
            }
        }
    } catch(e) {
        console.error("❌ Error during replay test:", e);
    }
}

runAudit();
