/* =========================================================
   secure-utils.js
   Sovereign Vault — Secure Utility Core
   =========================================================
   Role:
   - CSPRNG
   - Memory Zeroization
   - Side-Channel Mitigation
   - Entropy Injection
   - Ephemeral Security Helpers
   ========================================================= */

/* ========== CSPRNG ========== */

/**
 * Cryptographically secure random bytes
 * WebCrypto only
 */
export function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("Invalid random length");
  }
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

/* ========== ENTROPY MIXING ========== */

/**
 * Mix multiple entropy sources
 * (System RNG + Timing Noise)
 */
export function mixEntropy(primary) {
  const timing = new Uint32Array(1);
  timing[0] = performance.now() * 1000000;

  const mixed = new Uint8Array(primary.length);
  for (let i = 0; i < primary.length; i++) {
    mixed[i] = primary[i] ^ (timing[0] >> (i % 24));
  }

  timing.fill(0);
  return mixed;
}

/* ========== MEMORY ZEROIZATION ========== */

/**
 * Securely wipe a buffer
 */
export function zeroize(buffer) {
  if (!(buffer instanceof Uint8Array)) return;
  buffer.fill(0);
}

/**
 * Securely wipe multiple buffers
 */
export function zeroizeAll(...buffers) {
  for (const buf of buffers) {
    zeroize(buf);
  }
}

/* ========== CONSTANT-TIME HELPERS ========== */

/**
 * Constant-time equality check
 */
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    return false;
  }
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/* ========== BUFFER COMPARTMENTALIZATION ========== */

/**
 * Create an ephemeral isolated copy
 */
export function isolateBuffer(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new Error("Buffer must be Uint8Array");
  }
  const isolated = new Uint8Array(buffer.length);
  isolated.set(buffer);
  return isolated;
}

/* ========== TIMING NOISE ========== */

/**
 * Introduce minimal jitter to reduce timing patterns
 */
export async function timingNoise(min = 1, max = 4) {
  const delay =
    Math.floor(Math.random() * (max - min + 1)) + min;
  return new Promise(resolve => setTimeout(resolve, delay));
}

/* ========== EPHEMERAL CONTEXT ========== */

/**
 * Run a sensitive operation in an ephemeral context
 */
export async function withEphemeralContext(fn) {
  try {
    return await fn();
  } finally {
    await timingNoise();
  }
}

/* ========== SELF-AUDIT ========== */

/**
 * Internal security self-test
 */
export function selfTest() {
  const a = randomBytes(32);
  const b = isolateBuffer(a);

  const equalBefore = constantTimeEqual(a, b);
  zeroize(a);
  const equalAfter = constantTimeEqual(a, b);

  zeroize(b);

  return equalBefore === true && equalAfter === false;
}
