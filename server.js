require("dotenv").config();

const express = require("express");
const path = require("path");
const { analyzePrompt } = require("./src/detector");
const { createAuth } = require("./src/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const auth = createAuth({
  userId: process.env.AUTH_USER_ID || "pratham2425",
  email: process.env.AUTH_EMAIL || "guptadivyravindra@gmail.com",
  password: process.env.AUTH_PASSWORD || "demo-password-123"
});

app.use(express.json({ limit: "100kb" }));
app.use(auth.attachSession);

app.get("/", (req, res) => {
  if (!req.session) return res.redirect("/login");
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/index.html", (req, res) => {
  if (!req.session) return res.redirect("/login");
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get(["/login", "/login.html"], (req, res) => {
  if (req.session) return res.redirect("/");
  return res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.get("/api/auth/session", (req, res) => {
  if (!req.session) return res.status(401).json({ error: "Authentication required." });
  return res.json({ userId: auth.userId, email: auth.email });
});

app.post("/api/auth/login", async (req, res) => {
  const identifier = req.body?.identifier;
  const password = req.body?.password;

  if (typeof identifier !== "string" || typeof password !== "string" || !identifier.trim() || !password
    || identifier.length > 254 || Buffer.byteLength(password, "utf8") > 1024) {
    return res.status(400).json({ error: "Enter your user ID or email and password." });
  }

  const result = await auth.login(identifier, password, req.ip);
  if (!result.ok) {
    const status = result.limited ? 429 : 401;
    return res.status(status).json({
      error: result.limited ? "Too many failed attempts. Try again later." : "Invalid user ID, email, or password."
    });
  }

  res.cookie(auth.cookieName, result.token, auth.cookieOptions);
  return res.json({ userId: auth.userId, email: auth.email });
});

app.post("/api/auth/logout", (req, res) => {
  auth.logout(req);
  res.clearCookie(auth.cookieName, { path: "/", sameSite: "lax", httpOnly: true, secure: auth.cookieOptions.secure });
  return res.status(204).end();
});

app.post("/api/analyze", (req, res) => {
  if (!req.session) return res.status(401).json({ error: "Please log in to analyze prompts." });

  const prompt = req.body?.prompt;

  if (typeof prompt !== "string" || !prompt.trim()) {
    return res.status(400).json({ error: "Please provide a non-empty prompt." });
  }

  if (prompt.length > 20000) {
    return res.status(413).json({ error: "Prompt is too long (maximum 20,000 characters)." });
  }

  return res.json(analyzePrompt(prompt));
});

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: "An unexpected server error occurred." });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Prompt Injection Detector running at http://localhost:${PORT}`);
  });
}

module.exports = app;