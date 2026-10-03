// ---------------------------------------------------------------------------
// Client-side validation.
// This is a UX convenience ONLY. It can be bypassed (DevTools, curl, Postman),
// so the server repeats every check. Never trust the client.
// ---------------------------------------------------------------------------

const form = document.getElementById("loginForm");
const emailEl = document.getElementById("email");
const passwordEl = document.getElementById("password");
const messageEl = document.getElementById("message");

function showMessage(text, type) {
  // textContent (not innerHTML) => any HTML/JS in `text` is rendered as
  // plain text, so a reflected XSS payload cannot execute here.
  messageEl.textContent = text;
  messageEl.className = type || "";
}

function validate(email, password) {
  if (!email || !password) return "Please fill in both fields.";
  if (!email.includes("@")) return "Email must contain '@'.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null; // valid
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = emailEl.value.trim();
  const password = passwordEl.value;

  const error = validate(email, password);
  if (error) {
    showMessage(error, "error");
    return;
  }

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showMessage(`Welcome back, ${data.user.email}!`, "ok");
    } else {
      // Generic message: do not reveal whether email or password was wrong.
      showMessage(data.message || "Invalid email or password.", "error");
    }
  } catch (err) {
    showMessage("Network error. Please try again.", "error");
  }
});
