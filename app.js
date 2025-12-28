/* =========================================================
   app.js
   Sovereign Vault — Core Orchestrator
   =========================================================
   Role:
   - UI Binding
   - Security Orchestration
   - Layer Status Engine
   - Self-Audit Controller
   ========================================================= */

import { deriveKey, selfTest as argonSelfTest } from "./crypto/argon2.wasm.js";
import {
  randomBytes,
  mixEntropy,
  zeroize,
  withEphemeralContext,
  selfTest as utilSelfTest
} from "./crypto/secure-utils.js";

/* ========== UI ELEMENTS ========== */

const logPanel = document.getElementById("logPanel");
const auditBtn = document.getElementById("auditBtn");
const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const passwordInput = document.getElementById("password");

const layerElements = document.querySelectorAll(".layer");

/* ========== LOGGING (NON-SENSITIVE) ========== */

function log(message) {
  const div = document.createElement("div");
  div.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logPanel.appendChild(div);
  logPanel.scrollTop = logPanel.scrollHeight;
}

/* ========== LAYER STATUS ENGINE ========== */

function activateLayer(index, success = true) {
  const layer = layerElements[index];
  if (!layer) return;
  layer.classList.remove("active");
  if (success) layer.classList.add("active");
}

/* ========== INITIAL SECURITY BOOTSTRAP ========== */

async function bootstrapSecurity() {
  log("Bootstrapping Zero-Trust Environment…");

  try {
    // Layer 1–2: Zero-Trust / Zero-Knowledge
    activateLayer(0);
    activateLayer(1);

    // Layer: Secure RNG
    const entropy = mixEntropy(randomBytes(32));
    activateLayer(2);

    zeroize(entropy);

    log("Secure entropy initialized");

  } catch (err) {
    log("Security bootstrap failed");
    console.error(err);
  }
}

/* ========== SELF-AUDIT ========== */

async function runSelfAudit() {
  log("Running internal self-audit…");

  const utilOK = utilSelfTest();
  activateLayer(3, utilOK);

  const argonOK = await argonSelfTest();
  activateLayer(4, argonOK);

  if (utilOK && argonOK) {
    log("Self-audit passed ✔");
  } else {
    log("Self-audit failed ✖");
  }
}

/* ========== PASSWORD TEST (NO STORAGE) ========== */

async function testDerivation() {
  const password = passwordInput.value;
  if (!password) {
    log("Password required for key derivation test");
    return;
  }

  await withEphemeralContext(async () => {
    log("Deriving ephemeral master key…");

    const salt = randomBytes(32);

    const { key } = await deriveKey({
      password,
      salt,
      memoryMB: 64,
      iterations: 3,
      parallelism: 1
    });

    activateLayer(5);

    zeroize(key);
    zeroize(salt);

    log("Ephemeral key derived and destroyed");
  });
}

/* ========== UI EVENTS ========== */

auditBtn.addEventListener("click", runSelfAudit);

encryptBtn.addEventListener("click", async () => {
  log("Encryption pipeline not yet active (Phase 5)");
  await testDerivation();
});

decryptBtn.addEventListener("click", () => {
  log("Decryption pipeline not yet active (Phase 5)");
});

/* ========== BOOT ========== */

bootstrapSecurity();
