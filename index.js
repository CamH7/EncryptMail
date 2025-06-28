// index.js


const express = require("express");
const session = require("express-session");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { body, validationResult } = require("express-validator");

// Paths to JSON data ---------------------------------------
const DATA_PATH = path.join(__dirname, "data.json");
const DRAFTS_PATH = path.join(__dirname, "drafts.json");
const AUDIT_PATH = path.join(__dirname, "audit.json");

function readJSON(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function writeJSON(p, d) {
  fs.writeFileSync(p, JSON.stringify(d, null, 2), "utf8");
}

const app = express();

// Log
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} → ${req.method} ${req.path}`);
  next();
});

// JSON parser
app.use(express.json());

// CORS & session
app.use(cors({ origin: true, credentials: true }));
app.use(
  session({
    secret: "devbox-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Auth helper
function requireLogin(req, res, next) {
  if (req.session.user) return next();
  res.status(401).json({ error: "Not authenticated" });
}

// Audit log
function logEvent(type, entry) {
  const audit = readJSON(AUDIT_PATH);
  audit[type].push(entry);
  writeJSON(AUDIT_PATH, audit);
}

// Password regex
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

// Api routes --------------------------------------------------------------------------------

// Create account
app.post(
  "/api/create",
  [
    body("username")
      .trim()
      .isLength({ min: 3, max: 20 })
      .withMessage("Username 3–20 chars")
      .isAlphanumeric()
      .withMessage("Letters & numbers only"),
    body("password")
      .matches(PASSWORD_REGEX)
      .withMessage("Password needs ≥8 chars, upper, lower, digit & symbol"),
    body("publicKey").isBase64().withMessage("publicKey must be Base64"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }
    const { username, password, publicKey } = req.body;
    logEvent("accountCreations", {
      time: new Date().toISOString(),
      ip: req.ip,
      username,
    });
    const data = readJSON(DATA_PATH);
    if (data.users.some((u) => u.username === username)) {
      return res.status(400).json({ error: "User exists" });
    }
    data.users.push({ username, password, publicKey });
    writeJSON(DATA_PATH, data);
    res.json({ success: true });
  }
);

// Login limiter -------------------------------------------------------
const rateLimit = require("express-rate-limit");
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip + "|" + (req.body.username || ""),
  handler: (req, res) =>
    res
      .status(429)
      .json({ error: "Too many login attempts; try again later." }),
});

// Login --------------------------------------------------------------
app.post("/api/login", loginLimiter, (req, res) => {
  const { username, password, remember } = req.body;
  logEvent("loginAttempts", {
    time: new Date().toISOString(),
    ip: req.ip,
    username,
  });
  const data = readJSON(DATA_PATH);
  const u = data.users.find(
    (u) => u.username === username && u.password === password
  );
  if (!u) return res.status(400).json({ error: "Invalid credentials" });
  req.session.user = username;
  if (remember) req.session.cookie.maxAge = 7 * 24 * 3600 * 1000;
  res.json({ success: true });
});

// Logout ------------------------------------------------------------------
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Public key endpoints ----------------------------------------------------
app.post("/api/publicKey", requireLogin, (req, res) => {
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error: "No publicKey" });
  const data = readJSON(DATA_PATH);
  const u = data.users.find((u) => u.username === req.session.user);
  if (!u) return res.status(404).json({ error: "User not found" });
  u.publicKey = publicKey;
  writeJSON(DATA_PATH, data);
  res.json({ success: true });
});
app.get("/api/publicKey/:username", requireLogin, (req, res) => {
  const data = readJSON(DATA_PATH);
  const u = data.users.find((u) => u.username === req.params.username);
  if (!u || !u.publicKey) return res.status(404).json({ error: "Not found" });
  res.json({ publicKey: u.publicKey });
});

// Messages & drafts ---------------------------------------------------------------

// Inbox
app.get("/api/messages", requireLogin, (req, res) => {
  const data = readJSON(DATA_PATH);
  // return full objects with recipient/self blobs
  res.json(
    data.messages
      .filter((m) => m.to === req.session.user)
      .map((m) => ({
        from: m.from,
        to: m.to,
        subjectForRecipient: m.subjectForRecipient,
        bodyForRecipient: m.bodyForRecipient,
        timestamp: m.timestamp,
      }))
  );
});

// Send message (now expects four ciphertext fields)
app.post("/api/messages", requireLogin, (req, res) => {
  const {
    to,
    subjectForRecipient,
    bodyForRecipient,
    subjectForSelf,
    bodyForSelf,
  } = req.body;
  logEvent("messagesSent", {
    time: new Date().toISOString(),
    ip: req.ip,
    sender: req.session.user,
    recipients: to,
  });
  const data = readJSON(DATA_PATH);
  if (!data.users.some((u) => u.username === to))
    return res.status(400).json({ error: "Recipient not found" });

  data.messages.push({
    from: req.session.user,
    to,
    subjectForRecipient,
    bodyForRecipient,
    subjectForSelf,
    bodyForSelf,
    timestamp: new Date().toISOString(),
  });
  writeJSON(DATA_PATH, data);
  res.json({ success: true });
});

// Sent
app.get("/api/sent", requireLogin, (req, res) => {
  const data = readJSON(DATA_PATH);
  res.json(
    data.messages
      .filter((m) => m.from === req.session.user)
      .map((m) => ({
        from: m.from,
        to: m.to,
        subjectForSelf: m.subjectForSelf,
        bodyForSelf: m.bodyForSelf,
        timestamp: m.timestamp,
      }))
  );
});

// Delete message
app.delete("/api/messages/:id", requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const data = readJSON(DATA_PATH);
  data.messages = data.messages.filter((_, i) => i !== id);
  writeJSON(DATA_PATH, data);
  res.json({ success: true });
});

// Drafts --------------------------------------------------------------------------

// GET /api/drafts
// — Return only the encrypted blobs for the logged‑in user
app.get("/api/drafts", requireLogin, (req, res) => {
  const all = readJSON(DRAFTS_PATH).drafts;
  // filter to this usre then strip out the owner field
  const mine = all
    .filter((d) => d.owner === req.session.user)
    .map(({ owner, ...rest }) => rest);
  res.json(mine);
});

// POST /api/drafts
// Expect { to, subjectEncrypted, bodyEncrypted }
app.post("/api/drafts", requireLogin, (req, res) => {
  const { to, subjectEncrypted, bodyEncrypted } = req.body;
  if (!subjectEncrypted || !bodyEncrypted) {
    return res
      .status(400)
      .json({ error: "Missing subjectEncrypted or bodyEncrypted" });
  }

  // Append to drafts.json
  const d = readJSON(DRAFTS_PATH);
  d.drafts.push({
    owner: req.session.user,
    to,
    subjectEncrypted,
    bodyEncrypted,
    timestamp: new Date().toISOString(),
  });
  writeJSON(DRAFTS_PATH, d);
  res.json({ success: true });
});

// DELETE /api/drafts/:id
// deletes by index in the filtered array
app.delete("/api/drafts/:id", requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const d = readJSON(DRAFTS_PATH);
  d.drafts = d.drafts.filter((_, i) => i !== id);
  writeJSON(DRAFTS_PATH, d);
  res.json({ success: true });
});

// Delete account ------------------------------------------------------------------
app.delete("/api/account", requireLogin, (req, res) => {
  const me = req.session.user;
  const data = readJSON(DATA_PATH);
  data.users = data.users.filter((u) => u.username !== me);
  data.messages = data.messages.filter((m) => m.from !== me && m.to !== me);
  writeJSON(DATA_PATH, data);
  req.session.destroy(() => res.json({ success: true }));
});

app.use(express.static("public"));
// Using port 3000
app.listen(3000, () => console.log("Server running on port 3000"));
