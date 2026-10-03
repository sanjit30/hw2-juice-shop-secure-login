// ---------------------------------------------------------------------------
// Secure login server.
//   - Serves the static front-end form from /public
//   - Validates input again on the server (client checks can be bypassed)
//   - Looks up users with a PARAMETERIZED query  => immune to SQL injection
//   - Stores passwords as bcrypt hashes          => never in plain text
// ---------------------------------------------------------------------------

const path = require("path");
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

// Don't advertise the framework (fingerprinting).
app.disable("x-powered-by");

// Security headers. The CSP only allows scripts/styles from our own origin,
// so even an injected <script> or inline onerror= handler will not run.
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// --- In-memory demo database ------------------------------------------------
const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL   -- bcrypt hash, NOT the raw password
  );
`);

// Seed one account. bcrypt.hashSync(plain, costFactor=12).
// Demo credentials:  admin@juice.sh  /  Password123
const seedHash = bcrypt.hashSync("Password123", 12);
db.prepare("INSERT INTO users (email, password) VALUES (?, ?)")
  .run("admin@juice.sh", seedHash);

// A real hash used when the email doesn't exist, so a failed lookup costs the
// same bcrypt work as a real one (stops timing-based account enumeration).
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 12);

// --- Rate limiting: max 5 failed logins per IP+email per 15 minutes ---------
const MAX_FAILS = 5;
const WINDOW_MS = 15 * 60 * 1000;
const failures = new Map(); // key -> { count, first }

function isLocked(key) {
  const entry = failures.get(key);
  if (!entry) return false;
  if (Date.now() - entry.first > WINDOW_MS) {
    failures.delete(key);
    return false;
  }
  return entry.count >= MAX_FAILS;
}

function recordFailure(key) {
  const entry = failures.get(key);
  if (!entry || Date.now() - entry.first > WINDOW_MS) {
    failures.set(key, { count: 1, first: Date.now() });
  } else {
    entry.count++;
  }
}

// --- Server-side validation (defence in depth) ------------------------------
function validate(email, password) {
  if (typeof email !== "string" || typeof password !== "string") {
    return "Invalid input.";
  }
  if (!email || !password) return "Both fields are required.";
  if (!email.includes("@")) return "Email must contain '@'.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null;
}

// --- Login endpoint ---------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};

  const error = validate(email, password);
  if (error) return res.status(400).json({ success: false, message: error });

  const key = `${req.ip}|${email.toLowerCase()}`;
  if (isLocked(key)) {
    return res.status(429).json({
      success: false,
      message: "Too many failed attempts. Try again in 15 minutes.",
    });
  }

  // SAFE: the `?` placeholder is bound as DATA, never parsed as SQL.
  // A value like  ' OR '1'='1  is treated as a literal email string,
  // so it simply matches no row.
  const row = db
    .prepare("SELECT id, email, password FROM users WHERE email = ?")
    .get(email);

  // ---------------------------------------------------------------------
  // VULNERABLE version (DO NOT USE) — shown only to contrast in the report:
  //   const q = `SELECT * FROM users WHERE email = '${email}'`;
  //   const row = db.prepare(q).get();
  // With that, input  ' OR 1=1 --  would return the first user and bypass auth.
  // ---------------------------------------------------------------------

  // Compare against the bcrypt hash. Always run a compare (even when no row)
  // to reduce timing differences, and return a single generic message.
  const hash = row ? row.password : DUMMY_HASH;
  const ok = bcrypt.compareSync(password, hash);

  if (row && ok) {
    failures.delete(key);
    return res.json({ success: true, user: { email: row.email } });
  }
  recordFailure(key);
  return res.status(401).json({ success: false, message: "Invalid email or password." });
});

// Generic error handler: never send stack traces or file paths to the client
// (e.g. on malformed JSON bodies). Details stay in the server log.
app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({ success: false, message: status === 400 ? "Bad request." : "Server error." });
});

app.listen(PORT, () => {
  console.log(`Secure login server running at http://localhost:${PORT}`);
});
