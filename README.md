# 🧃 Juice Shop – Secure Login Form

A small login page inspired by [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
built for a web-security assignment. It demonstrates **defense-in-depth** against the
two attacks Juice Shop is famous for — **SQL Injection** and **Cross-Site Scripting (XSS)** —
plus brute force and information leaks, using these measures:

| Measure | Where | Protects against |
|---|---|---|
| Client-side validation | `public/script.js` | Empty / malformed submissions (UX) |
| Server-side validation | `server.js` → `validate()` | Bypassed client checks |
| Parameterized SQL (`?` placeholders) | `server.js` → login query | SQL Injection |
| bcrypt password hashing (cost 12) | `server.js` → seed + `compareSync` | Credential theft from DB |
| `textContent` output (never `innerHTML`) | `public/script.js` | Reflected / DOM XSS |
| Content-Security-Policy header | `server.js` | Injected scripts running |
| Login rate limiting | `server.js` | Password brute force |

## What it does

A user submits an email + password. The browser checks the input is non-empty,
that the email contains `@`, and that the password is at least 8 characters.
The same checks run again on the server, which then looks the user up with a
**parameterized query** and verifies the password against a **bcrypt hash**.
On success it returns the user's email; otherwise a single generic error.

## Project structure

```
juice-shop-secure-login/
├── public/
│   ├── index.html     # the login form
│   ├── style.css       # styling
│   └── script.js       # client-side validation + fetch to the API
├── server.js           # Express server, validation, SQL, bcrypt
├── package.json
└── README.md
```

## How to run

> Requires Node.js 18+.

```bash
# 1. install dependencies
npm install

# 2. start the server
npm start

# 3. open the app
#    http://localhost:3000
```

### Demo credentials

```
Email:    admin@juice.sh
Password: Password123
```

## Try to break it (Part 3)

With the server running, these attacks are expected to **fail**:

- **SQL Injection** — log in with email `' OR '1'='1` and any 8+ char password.
  The `?` placeholder treats the input as a literal string, so no row matches →
  `Invalid email or password.`
- **XSS** — submit email `<img src=x onerror=alert(1)>`. It fails email
  validation, and even if echoed back it is written with `textContent`, so it
  renders as plain text and never executes.

## Weaknesses found in v1 and fixed in v2

Testing the first version (commit `1e6c060`) found four weaknesses, all fixed in `server.js`:

| # | Weakness in v1 | Fix in v2 |
|---|---|---|
| 1 | **Timing-based account enumeration**: real email took ~200 ms, unknown email ~1 ms | Compare against a real precomputed dummy bcrypt hash, so both take ~200 ms |
| 2 | **Unlimited brute force**: no limit on failed logins | 5 failed attempts per IP+email per 15 min, then `429 Too Many Requests` |
| 3 | **Stack-trace disclosure**: malformed JSON returned a stack trace with server file paths | Generic JSON error handler; details logged server-side only |
| 4 | **Missing security headers**: `X-Powered-By: Express`, no CSP | `X-Powered-By` disabled; CSP, `nosniff`, `X-Frame-Options` added |

## Security notes

- Passwords are **never** stored or logged in plain text (bcrypt, cost 12).
- The login response is intentionally generic so it does not reveal whether the
  email or the password was wrong (prevents account enumeration).
- For production you would also add HTTPS, CSRF protection, secure session
  cookies, and a shared rate-limit store (e.g. Redis), because the in-memory
  limiter resets when the server restarts.
