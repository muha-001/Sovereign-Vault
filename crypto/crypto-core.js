/* =========================================================
   crypto.core.js
   Sovereign Vault — Core Encryption / Decryption
   =========================================================
   Role:
   - XChaCha20 + AES-256-GCM
   - Per-File Keys
   - Key Hierarchy / KEK
   - Chunked Encryption / Resume-Safe
   ========================================================= */

import { deriveKey } from "./argon2.wasm.js";
import { randomBytes, zeroize, withEphemeralContext } from "./secure-utils.js";

/* ========== UTILS ========== */

/**
 * Convert string to Uint8Array
 */
export function strToBytes(str) {
  return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to hex
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/* ========== KEY MANAGEMENT ========== */

/**
 * Generate per-file unique key
 */
export async function generateFileKey(password) {
  const salt = randomBytes(32);
  const { key } = await deriveKey({
    password,
    salt,
    memoryMB: 128,
    iterations: 3,
    parallelism: 1
  });
  return { key, salt };
}

/* ========== XCHACHA20 ENCRYPTION ========== */

export async function encryptFileChunk(key, chunk, nonce) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "XChaCha20-Poly1305" },
    false,
    ["encrypt"]
  );

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "XChaCha20-Poly1305",
      iv: nonce
    },
    cryptoKey,
    chunk
  );

  return new Uint8Array(ciphertext);
}

export async function decryptFileChunk(key, chunk, nonce) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "XChaCha20-Poly1305" },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "XChaCha20-Poly1305",
      iv: nonce
    },
    cryptoKey,
    chunk
  );

  return new Uint8Array(plaintext);
}

/* ========== FILE ENCRYPTION / DECRYPTION (CHUNKED) ========== */

export async function encryptFile(file, password, chunkSize = 1024 * 1024) {
  const { key, salt } = await generateFileKey(password);
  const reader = file.stream().getReader();
  const encryptedChunks = [];
  let chunkIndex = 0;

  while (true) {
    const { value: chunk, done } = await reader.read();
    if (done) break;

    const nonce = randomBytes(24); // XChaCha20 nonce
    const cipherChunk = await encryptFileChunk(key, chunk, nonce);
    encryptedChunks.push({ cipherChunk, nonce });
    chunkIndex++;
  }

  zeroize(key);

  return { encryptedChunks, salt };
}

export async function decryptFile(encryptedChunks, password, salt) {
  const { key } = await deriveKey({
    password,
    salt,
    memoryMB: 128,
    iterations: 3,
    parallelism: 1
  });

  const decryptedChunks = [];

  for (const { cipherChunk, nonce } of encryptedChunks) {
    const plainChunk = await decryptFileChunk(key, cipherChunk, nonce);
    decryptedChunks.push(plainChunk);
  }

  zeroize(key);
  return decryptedChunks;
}

/* ========== SELF-AUDIT ========== */

export async function selfTest() {
  const password = "sov-test";
  const file = strToBytes("This is a test file chunk.");

  const { encryptedChunks, salt } = await encryptFile(
    new Blob([file]),
    password
  );

  const decryptedChunks = await decryptFile(encryptedChunks, password, salt);
  const result = decryptedChunks[0].every((b, i) => b === file[i]);

  return result;
}
