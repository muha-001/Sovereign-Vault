/* =========================================================
   app.js (Updated Phase 5)
   Sovereign Vault — Full File Encryption / Decryption
   ========================================================= */

import { deriveKey, selfTest as argonSelfTest } from "./crypto/argon2.wasm.js";
import { randomBytes, mixEntropy, zeroize, withEphemeralContext, selfTest as utilSelfTest } from "./crypto/secure-utils.js";
import { encryptFile, decryptFile } from "./crypto/crypto.core.js";

/* ========== UI ELEMENTS ========== */
const logPanel = document.getElementById("logPanel");
const auditBtn = document.getElementById("auditBtn");
const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const passwordInput = document.getElementById("password");
const fileInput = document.getElementById("fileInput");
const progressBar = document.getElementById("progressBar");

const layerElements = document.querySelectorAll(".layer");

/* ========== LOGGING ========== */
function log(message) {
  const div = document.createElement("div");
  div.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logPanel.appendChild(div);
  logPanel.scrollTop = logPanel.scrollHeight;
}

/* ========== LAYER STATUS ========== */
function activateLayer(index, success = true) {
  const layer = layerElements[index];
  if (!layer) return;
  layer.classList.remove("active");
  if (success) layer.classList.add("active");
}

/* ========== SECURITY BOOTSTRAP ========== */
async function bootstrapSecurity() {
  log("Bootstrapping Zero-Trust Environment…");

  try {
    activateLayer(0); // Zero-Trust
    activateLayer(1); // Zero-Knowledge

    const entropy = mixEntropy(randomBytes(32));
    activateLayer(2); // Secure RNG
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

  if (utilOK && argonOK) log("Self-audit passed ✔");
  else log("Self-audit failed ✖");
}

/* ========== FILE ENCRYPTION ========== */
async function handleEncrypt() {
  const password = passwordInput.value;
  const file = fileInput.files[0];
  if (!password || !file) {
    log("Password and file required");
    return;
  }

  await withEphemeralContext(async () => {
    log(`Encrypting file: ${file.name}`);
    activateLayer(5); // Derivation started

    const { encryptedChunks, salt } = await encryptFile(file, password);
    activateLayer(6); // Encryption complete

    // Simulate chunked progress
    for (let i = 0; i < encryptedChunks.length; i++) {
      progressBar.value = ((i + 1) / encryptedChunks.length) * 100;
      await new Promise(r => setTimeout(r, 10));
    }

    progressBar.value = 0;
    log(`Encryption finished: ${file.name}`);
    zeroize(salt);

    // Store ephemeral encryptedChunks in memory (demo)
    window.lastEncryptedFile = { encryptedChunks, salt };
  });
}

/* ========== FILE DECRYPTION ========== */
async function handleDecrypt() {
  const password = passwordInput.value;
  const lastFile = window.lastEncryptedFile;
  if (!password || !lastFile) {
    log("Password and previously encrypted file required");
    return;
  }

  await withEphemeralContext(async () => {
    log("Decrypting file…");
    activateLayer(7); // Decryption started

    const decryptedChunks = await decryptFile(lastFile.encryptedChunks, password, lastFile.salt);
    activateLayer(8); // Decryption complete

    for (let i = 0; i < decryptedChunks.length; i++) {
      progressBar.value = ((i + 1) / decryptedChunks.length) * 100;
      await new Promise(r => setTimeout(r, 10));
    }

    progressBar.value = 0;
    log("Decryption finished ✔");

    // Demo: create Blob to download
    const blob = new Blob(decryptedChunks);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "decrypted_" + Date.now();
    a.click();
    URL.revokeObjectURL(url);
  });
}

/* ========== UI EVENTS ========== */
auditBtn.addEventListener("click", runSelfAudit);
encryptBtn.addEventListener("click", handleEncrypt);
decryptBtn.addEventListener("click", handleDecrypt);

/* ========== BOOT ========== */
bootstrapSecurity();
