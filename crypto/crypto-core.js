/* =========================================================
   Sovereign Vault — Crypto Core
   Argon2id + XChaCha20-Poly1305
   Client-Only | Zero-Knowledge
   ========================================================= */

import { argon2id } from "./argon2.wasm.js";
import { wipeBuffer, randomBytes } from "./secure-utils.js";

/* =======================
   CONSTANTS
   ======================= */
const VAULT_MAGIC = "SVLT1";
const HEADER_VERSION = 1;

/* =======================
   KEY DERIVATION
   ======================= */
export async function deriveMasterKey(password, salt) {
  const pwdBytes = new TextEncoder().encode(password);

  const key = await argon2id({
    password: pwdBytes,
    salt,
    parallelism: 4,
    iterations: 5,
    memorySize: 65536, // 64MB
    hashLength: 32,
    outputType: "binary"
  });

  wipeBuffer(pwdBytes);
  return key;
}

/* =======================
   FILE HEADER
   ======================= */
function createHeader(salt, nonce) {
  const encoder = new TextEncoder();
  return new Blob([
    encoder.encode(VAULT_MAGIC),
    new Uint8Array([HEADER_VERSION]),
    salt,
    nonce
  ]);
}

function parseHeader(buffer) {
  const magic = new TextDecoder().decode(buffer.slice(0, 5));
  if (magic !== VAULT_MAGIC) {
    throw new Error("Invalid vault file");
  }

  return {
    version: buffer[5],
    salt: buffer.slice(6, 38),
    nonce: buffer.slice(38, 62),
    offset: 62
  };
}

/* =======================
   ENCRYPT FILE
   ======================= */
export async function encryptFile(arrayBuffer, password) {
  const salt = randomBytes(32);
  const nonce = randomBytes(24);

  const masterKey = await deriveMasterKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "XChaCha20-Poly1305",
      iv: nonce
    },
    await crypto.subtle.importKey(
      "raw",
      masterKey,
      "XChaCha20-Poly1305",
      false,
      ["encrypt"]
    ),
    arrayBuffer
  );

  wipeBuffer(masterKey);

  return new Blob([
    createHeader(salt, nonce),
    new Uint8Array(encrypted)
  ]);
}

/* =======================
   DECRYPT FILE
   ======================= */
export async function decryptFile(arrayBuffer, password) {
  const header = parseHeader(arrayBuffer);

  const encryptedData = arrayBuffer.slice(header.offset);
  const masterKey = await deriveMasterKey(password, header.salt);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "XChaCha20-Poly1305",
      iv: header.nonce
    },
    await crypto.subtle.importKey(
      "raw",
      masterKey,
      "XChaCha20-Poly1305",
      false,
      ["decrypt"]
    ),
    encryptedData
  );

  wipeBuffer(masterKey);
  return decrypted;
}
