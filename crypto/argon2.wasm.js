/* =========================================================
   argon2.wasm.js
   Sovereign Vault — Argon2id WASM Loader
   =========================================================
   Role:
   - PBKDF2 Pre-Hardening
   - Argon2id Key Derivation
   - Memory-Hard Enforcement
   - No State / No Storage
   ========================================================= */

let _argon2Instance = null;

/* ========== INTERNAL UTILS ========== */

/**
 * Secure random bytes
 * Uses WebCrypto only
 */
function secureRandom(length) {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

/**
 * Constant-time buffer compare
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/* ========== WASM LOADER ========== */

/**
 * Loads Argon2 WASM module
 * @param {string} wasmPath
 */
export async function loadArgon2Wasm(wasmPath = "./argon2.wasm") {
  if (_argon2Instance) return _argon2Instance;

  const response = await fetch(wasmPath);
  if (!response.ok) {
    throw new Error("Failed to load Argon2 WASM");
  }

  const wasmBytes = await response.arrayBuffer();

  const wasmModule = await WebAssembly.instantiate(wasmBytes, {
    env: {
      abort: () => {
        throw new Error("Argon2 WASM aborted");
      }
    }
  });

  _argon2Instance = wasmModule.instance.exports;
  return _argon2Instance;
}

/* ========== PBKDF2 PRE-HARDENING ========== */

/**
 * PBKDF2-HMAC-SHA-512 pre-hardening
 */
async function pbkdf2PreHash(passwordBytes, saltBytes, iterations = 2_000_000) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-512",
      salt: saltBytes,
      iterations
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

/* ========== ARGON2ID DERIVATION ========== */

/**
 * Derive master key using PBKDF2 + Argon2id
 */
export async function deriveKey({
  password,
  salt = secureRandom(32),
  memoryMB = 64,
  iterations = 3,
  parallelism = 1,
  outputLength = 32,
  wasmPath
}) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password must be a non-empty string");
  }

  const passwordBytes = new TextEncoder().encode(password);

  /* ---- PBKDF2 Pre-Hardening ---- */
  const hardened = await pbkdf2PreHash(passwordBytes, salt);

  /* ---- Load Argon2 WASM ---- */
  const argon2 = await loadArgon2Wasm(wasmPath);

  /* ---- Allocate WASM Memory ---- */
  const pwdPtr = argon2._malloc(hardened.length);
  const saltPtr = argon2._malloc(salt.length);
  const outPtr = argon2._malloc(outputLength);

  argon2.HEAPU8.set(hardened, pwdPtr);
  argon2.HEAPU8.set(salt, saltPtr);

  /* ---- Argon2id Execution ---- */
  const result = argon2._argon2id_hash_raw(
    iterations,
    memoryMB * 1024,
    parallelism,
    pwdPtr,
    hardened.length,
    saltPtr,
    salt.length,
    outPtr,
    outputLength
  );

  if (result !== 0) {
    throw new Error("Argon2id derivation failed");
  }

  const derivedKey = argon2.HEAPU8.slice(outPtr, outPtr + outputLength);

  /* ---- Memory Zeroization ---- */
  argon2.HEAPU8.fill(0, pwdPtr, pwdPtr + hardened.length);
  argon2.HEAPU8.fill(0, saltPtr, saltPtr + salt.length);
  argon2.HEAPU8.fill(0, outPtr, outPtr + outputLength);

  argon2._free(pwdPtr);
  argon2._free(saltPtr);
  argon2._free(outPtr);

  passwordBytes.fill(0);
  hardened.fill(0);

  return {
    key: derivedKey,
    salt
  };
}

/* ========== SELF-TEST ========== */

/**
 * Internal self-audit
 */
export async function selfTest() {
  const pwd = "self-test-password";
  const salt = secureRandom(32);

  const a = await deriveKey({ password: pwd, salt });
  const b = await deriveKey({ password: pwd, salt });

  return constantTimeEqual(a.key, b.key);
}
