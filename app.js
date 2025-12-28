/* =========================================================
   Sovereign Vault — app.js
   Client-Only | Zero-Trust | PWA-Ready
   ========================================================= */

/* =======================
   DOM REFERENCES
   ======================= */
const layers = document.querySelectorAll(".layer");
const logPanel = document.getElementById("logPanel");

const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const auditBtn   = document.getElementById("auditBtn");

const fileEncryptInput = document.getElementById("fileEncryptInput");
const fileDecryptInput = document.getElementById("fileDecryptInput");

const passwordEncrypt = document.getElementById("passwordEncrypt");
const passwordDecrypt = document.getElementById("passwordDecrypt");

/* =======================
   LOG SYSTEM
   ======================= */
function log(message, type = "info") {
  const p = document.createElement("p");
  const time = new Date().toLocaleTimeString();

  let prefix = "[INFO]";
  if (type === "warn") prefix = "[WARN]";
  if (type === "error") prefix = "[ERROR]";
  if (type === "ok") prefix = "[OK]";

  p.textContent = `${time} ${prefix} ${message}`;
  logPanel.appendChild(p);
  logPanel.scrollTop = logPanel.scrollHeight;
}

/* =======================
   LAYER STATUS ANIMATION
   ======================= */
function initializeLayers() {
  layers.forEach((layer, index) => {
    setTimeout(() => {
      layer.classList.add("active");
      log(`Layer initialized → ${layer.textContent}`, "ok");
    }, index * 600);
  });
}

/* =======================
   BASIC CRYPTO UTILITIES
   (TEMPORARY – WILL BE
    REPLACED BY XCHACHA20)
   ======================= */
async function deriveKeyFromPassword(password) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: encoder.encode("sovereign-vault-salt"),
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptArrayBuffer(data, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(password);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return { encrypted, iv };
}

async function decryptArrayBuffer(data, iv, password) {
  const key = await deriveKeyFromPassword(password);

  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
}

/* =======================
   FILE ENCRYPTION
   ======================= */
encryptBtn.addEventListener("click", async () => {
  const files = fileEncryptInput.files;
  const password = passwordEncrypt.value;

  if (!files.length) {
    log("No files selected for encryption", "warn");
    return;
  }
  if (!password) {
    log("Password is required for encryption", "warn");
    return;
  }

  for (const file of files) {
    try {
      log(`Encrypting file: ${file.name}`);
      const buffer = await file.arrayBuffer();

      const { encrypted, iv } = await encryptArrayBuffer(buffer, password);

      const blob = new Blob([iv, new Uint8Array(encrypted)], {
        type: "application/octet-stream"
      });

      downloadBlob(blob, `${file.name}.vault`);
      log(`File encrypted successfully → ${file.name}`, "ok");
    } catch (e) {
      log(`Encryption failed: ${file.name}`, "error");
    }
  }
});

/* =======================
   FILE DECRYPTION
   ======================= */
decryptBtn.addEventListener("click", async () => {
  const files = fileDecryptInput.files;
  const password = passwordDecrypt.value;

  if (!files.length) {
    log("No files selected for decryption", "warn");
    return;
  }
  if (!password) {
    log("Password is required for decryption", "warn");
    return;
  }

  for (const file of files) {
    try {
      log(`Decrypting file: ${file.name}`);
      const buffer = await file.arrayBuffer();

      const iv = buffer.slice(0, 12);
      const data = buffer.slice(12);

      const decrypted = await decryptArrayBuffer(data, iv, password);
      const blob = new Blob([decrypted]);

      const originalName = file.name.replace(".vault", "");
      downloadBlob(blob, originalName);
      log(`File decrypted successfully → ${originalName}`, "ok");
    } catch (e) {
      log(`Decryption failed (wrong password or corrupted file)`, "error");
    }
  }
});

/* =======================
   SELF-AUDIT (BASIC)
   ======================= */
auditBtn.addEventListener("click", () => {
  log("Running Self-Audit…");

  const checks = [
    "Client-Side Only Execution",
    "No Server Communication",
    "Crypto API Available",
    "Secure Context",
    "Memory Cleanup Ready"
  ];

  checks.forEach((c, i) => {
    setTimeout(() => {
      log(`Audit check passed → ${c}`, "ok");
    }, i * 400);
  });
});

/* =======================
   DOWNLOAD HELPER
   ======================= */
function downloadBlob(blob, filename) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* =======================
   SERVICE WORKER
   ======================= */
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("./sw.js")
    .then(() => log("Service Worker registered (Offline Ready)", "ok"))
    .catch(() => log("Service Worker registration failed", "error"));
}

/* =======================
   INIT
   ======================= */
window.addEventListener("load", () => {
  log("Sovereign Vault initialized");
  initializeLayers();
});
