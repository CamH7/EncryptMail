// public/app.js

// Helper to wrap fetch with credentials
function apiFetch(path, opts = {}) {
  return fetch(path, {
    credentials: "include",
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });
}

// --- RSA KEY FUNCTIONS ---
async function generateKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportPublicKey(key) {
  const spki = await crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(spki);
}
async function exportPrivateKey(key) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(pkcs8);
}

async function importPublicKey(b64) {
  const buf = base64ToArrayBuffer(b64);
  return crypto.subtle.importKey(
    "spki",
    buf,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}
async function importPrivateKey(b64) {
  const buf = base64ToArrayBuffer(b64);
  return crypto.subtle.importKey(
    "pkcs8",
    buf,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

function arrayBufferToBase64(buf) {
  let bin = "";
  const bytes = new Uint8Array(buf);
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes.buffer;
}

async function decryptMessage(b64) {
  try {
    const buf = base64ToArrayBuffer(b64);
    const decrypted = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      window.privateKey,
      buf
    );
    return new TextDecoder().decode(decrypted);
  } catch {
    return "(Unable to decrypt message)";
  }
}

// --- DOM Elements ---
const avatarBtn = document.getElementById("avatarBtn");
const acctDropdown = document.getElementById("acctDropdown");
const contentArea = document.getElementById("contentArea");
let currentTab = "inbox";

function openModal(id) {
  document.getElementById(id).classList.add("active");
}
function closeModal(id) {
  document.getElementById(id).classList.remove("active");
}
function populateDropdown() {
  document.getElementById("dd-user").innerText =
    sessionStorage.getItem("user") || "";
  document.getElementById("dd-pass").innerText =
    sessionStorage.getItem("pass") || "";
}

// Avatar dropdown -------------------------------------------------
avatarBtn.onclick = () => {
  acctDropdown.classList.toggle("active");
  populateDropdown();
};
document.getElementById("dd-logout").onclick = async () => {
  await apiFetch("/api/logout");
  location.href = "/login.html";
};
document.getElementById("dd-delete").onclick = () =>
  openModal("confirmDeleteModal");
document.getElementById("deleteNo").onclick = () =>
  closeModal("confirmDeleteModal");
document.getElementById("deleteYes").onclick = async () => {
  await apiFetch("/api/account", { method: "DELETE" });
  location.href = "/login.html";
};

// Tabs -------------------------------------------------------------
["inbox", "sent", "drafts"].forEach((tab) => {
  document.getElementById("tab-" + tab).onclick = () => {
    currentTab = tab;
    renderTabs();
    loadTab(tab);
  };
});
function renderTabs() {
  ["inbox", "sent", "drafts"].forEach((tab) => {
    document
      .getElementById("tab-" + tab)
      .classList.toggle("active", tab === currentTab);
  });
}

// Compose modal -----------------------------------------------------
document.getElementById("composeBtn").onclick = () => {
  clearCompose();
  openModal("composeModal");
};
document.getElementById("closeCompose").onclick = () =>
  closeModal("composeModal");
function clearCompose() {
  document.getElementById("to").value = "";
  document.getElementById("subject").value = "";
  document.getElementById("body").value = "";
}

// Save draft (plaintext)
document.getElementById("saveDraft").onclick = async () => {
  const to = document.getElementById("to").value;
  const subject = document.getElementById("subject").value;
  const body = document.getElementById("body").value;
  const encoder = new TextEncoder();

  // encrypt subject & body for yourself only
  const subjBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    window.publicKey, // ← your own public key
    encoder.encode(subject)
  );
  const bodyBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    window.publicKey,
    encoder.encode(body)
  );

  // send JUST these two encrypted fields (plus `to`)
  const res = await apiFetch("/api/drafts", {
    method: "POST",
    body: JSON.stringify({
      to,
      subjectEncrypted: arrayBufferToBase64(subjBuf),
      bodyEncrypted: arrayBufferToBase64(bodyBuf),
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    return alert("Failed to save draft: " + (err.error || res.status));
  }

  closeModal("composeModal");
  if (currentTab === "drafts") loadTab("drafts");
};

// Send Message (double-encrypted) -------------------------------
document.getElementById("send").onclick = async () => {
  const to = document.getElementById("to").value;
  const subject = document.getElementById("subject").value;
  const body = document.getElementById("body").value;

  // fetch recipient's public key
  const res = await apiFetch(`/api/publicKey/${to}`);
  if (!res.ok) return alert("Recipient's public key not found");
  const { publicKey: pubB64 } = await res.json();
  const recipientKey = await importPublicKey(pubB64);

  const encoder = new TextEncoder();

  // encrypt for recipient
  const subjRecBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientKey,
    encoder.encode(subject)
  );
  const bodyRecBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientKey,
    encoder.encode(body)
  );

  // encrypt for yourself
  const subjSelfBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    window.publicKey,
    encoder.encode(subject)
  );
  const bodySelfBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    window.publicKey,
    encoder.encode(body)
  );

  // send all four
  await apiFetch("/api/messages", {
    method: "POST",
    body: JSON.stringify({
      to,
      subjectForRecipient: arrayBufferToBase64(subjRecBuf),
      bodyForRecipient: arrayBufferToBase64(bodyRecBuf),
      subjectForSelf: arrayBufferToBase64(subjSelfBuf),
      bodyForSelf: arrayBufferToBase64(bodySelfBuf),
    }),
  });

  closeModal("composeModal");
  loadTab(currentTab);
};


// Load the Tabs -----------------------------------------------
async function loadTab(tab) {
  renderTabs();
  let data = [];

  if (tab === "inbox") {
    const r = await apiFetch("/api/messages");
    if (r.status === 401) return (location.href = "/login.html");
    data = await r.json();
  } else if (tab === "sent") {
    data = await (await apiFetch("/api/sent")).json();
  } else {
    data = await (await apiFetch("/api/drafts")).json();
  }

  if (!data.length) {
    contentArea.innerHTML = `<p>(no ${tab})</p>`;
    return;
  }

  // Decrypt previews for inbox, sent, and drafts -------------------
  for (const m of data) {
    if (tab === "drafts") {
      m.decryptedSubject = await decryptMessage(m.subjectEncrypted);
      m.decryptedBody = await decryptMessage(m.bodyEncrypted);
    } else if (tab === "inbox") {
      m.decryptedSubject = await decryptMessage(m.subjectForRecipient);
      m.decryptedBody = await decryptMessage(m.bodyForRecipient);
    } else {
      m.decryptedSubject = await decryptMessage(m.subjectForSelf);
      m.decryptedBody = await decryptMessage(m.bodyForSelf);
    }
  }

  // Build the list -----------------------------------------------------------
  contentArea.innerHTML = `<ul class="email-list">
${data
  .map(
    (m, i) => `
  <li data-index="${i}">
    <span class="from">${
      tab === "sent" ? "To: " + m.to : "From: " + m.from
    }</span>
    <span class="subject">
      ${(m.decryptedSubject || "(decrypting…)").slice(0, 100)}
    </span>
    <span class="body-preview">
      ${(m.decryptedBody || "(decrypting…)").slice(0, 100)}
    </span>
    <div class="actions-time">
      ${
        tab === "drafts"
          ? `<button class="edit-btn" data-id="${i}">✏️</button>`
          : ""
      }
      <button class="del-btn" data-id="${i}">🗑️</button>
      <span class="time">${new Date(m.timestamp).toLocaleTimeString()}</span>
    </div>
  </li>`
  )
  .join("")}
</ul>`;

  // Attach buttons and click handlers --------------------------------------------------
  if (tab === "drafts") {
    contentArea.querySelectorAll(".edit-btn").forEach((btn) => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const d = data[btn.dataset.id];
        document.getElementById("to").value = d.to;
        document.getElementById("subject").value = d.subject;
        document.getElementById("body").value = d.body;
        openModal("composeModal");
      };
    });
  }
  contentArea.querySelectorAll(".del-btn").forEach((btn) => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const url =
        tab === "drafts"
          ? `/api/drafts/${btn.dataset.id}`
          : `/api/messages/${btn.dataset.id}`;
      await apiFetch(url, { method: "DELETE" });
      loadTab(tab);
    };
  });
  contentArea.querySelectorAll("li").forEach((li) => {
    li.onclick = async () => {
      const m = data[li.dataset.index];
      let decryptedSubject = m.subject;
      let decryptedBody = m.body;
      if (tab !== "drafts") {
        if (tab === "inbox") {
          decryptedSubject = await decryptMessage(m.subjectForRecipient);
          decryptedBody = await decryptMessage(m.bodyForRecipient);
        } else {
          decryptedSubject = await decryptMessage(m.subjectForSelf);
          decryptedBody = await decryptMessage(m.bodyForSelf);
        }
      }
      contentArea.innerHTML = `
        <div class="message-view">
          <div class="nav">
            <button id="backBtn">🔙</button>
            <button id="viewDel" class="del-btn">🗑️</button>
          </div>
          <p class="meta">From: ${m.from}</p>
          <p class="meta">To: ${m.to || sessionStorage.getItem("user")}</p>
          <h3>${decryptedSubject}</h3>
          <div class="body">${decryptedBody}</div>
        </div>`;
      document.getElementById("backBtn").onclick = () => loadTab(tab);
      document.getElementById("viewDel").onclick = async () => {
        const url =
          tab === "drafts"
            ? `/api/drafts/${li.dataset.index}`
            : `/api/messages/${li.dataset.index}`;
        await apiFetch(url, { method: "DELETE" });
        loadTab(tab);
      };
    };
  });
}

// Initialize ------------------------------------------------------------------
window.onload = async () => {
  const user = sessionStorage.getItem("user");
  if (!user) return (location.href = "/login.html");
  avatarBtn.innerText = user.charAt(0).toUpperCase();

  let priv = localStorage.getItem("privateKey");
  let pub = localStorage.getItem("publicKey");
  if (!priv || !pub) {
    const kp = await generateKeyPair();
    pub = await exportPublicKey(kp.publicKey);
    priv = await exportPrivateKey(kp.privateKey);
    localStorage.setItem("publicKey", pub);
    localStorage.setItem("privateKey", priv);
    await apiFetch("/api/publicKey", {
      method: "POST",
      body: JSON.stringify({ publicKey: pub }),
    });
  }
  window.privateKey = await importPrivateKey(priv);
  window.publicKey = await importPublicKey(pub);

  loadTab(currentTab);
};
