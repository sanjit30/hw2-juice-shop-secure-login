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

app.use(express.json());
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
  const hash = row ? row.password : "$2a$12$invalidinvalidinvalidinvalidinv";
  const ok = bcrypt.compareSync(password, hash);

  if (row && ok) {
    return res.json({ success: true, user: { email: row.email } });
  }
  return res.status(401).json({ success: false, message: "Invalid email or password." });
});

app.listen(PORT, () => {
  console.log(`Secure login server running at http://localhost:${PORT}`);
});
